// recorder.zig — env-gated per-slot read/write event recorder for iter-6 carrier
// localization. Records WHICH storage layer returned WHICH value for every
// account read AND WHICH slot wrote WHICH value into unflushed_cache.
//
// Gates (independent — set one or both):
//   VEX_RECORD_READS=1         enables Phase A read tap
//   VEX_RECORD_WRITES=1        enables Phase B write tap
//   VEX_RECORD_SLOTS=N         record first N replayed slots after boot (default 10)
//   VEX_RECORD_UNTIL_SLOT=S    additionally stop after seeing slot >= S (0=off)
//
// Output layout:
//   /mnt/ramdisk/vex-record-<unix-ts>/slot-<N>.reads.jsonl   (one file per slot)
//   /mnt/ramdisk/vex-record-<unix-ts>/slot-<N>.writes.jsonl
//
// Why this exists: Phase 1D's mock-test → deploy → discover-mock-was-wrong loop
// cost a session. The recorder captures the REAL read+write paths so the
// storage layer that returned a polluted value AND the slot/pubkey that wrote
// the bad value are identifiable directly from production logs.
//
// Iter-6 pollution signature with Phase A+B combined:
//   - reads.jsonl shows  slot=S layer=unflushed_cache csm=M  (where M ∉ S.ancestors)
//   - writes.jsonl shows slot=M pk=X overwrote prev_csm=L    (where L was canonical)
//
// Thread-safety: `current_slot` is threadlocal — every thread that calls into
// `_getRooted` / `getAccountInSlot` / `promoteToUnflushedCache` during replay
// must set its own value at entry to the per-slot work unit. In current vex-fd
// the ONLY thread that does this is `replayWorker` (replay_stage.zig:3247) via
// `onSlotCompleted` at line 1494. `parallelWorkerFn` exists but is dead code
// (svm_pool removed; see replay_stage.zig:253,259). If a future change
// re-introduces a worker pool, each worker entry must also set `current_slot`.
//
// Bootstrap suppression: `enabled` flips true only after main.zig calls
// `boot()` (post-snapshot-load, pre-mainloop). The 3 _getRooted calls inside
// bootstrap.zig and the FeatureSet loader fire before that and are no-op'd.

const std = @import("std");

pub const Layer = enum(u8) {
    sig_overlay = 0,
    unflushed_cache = 1,
    bulk_buffer = 2,
    cache = 3,
    index_storage = 4,
    miss = 5,
};

const Kind = enum(u8) { reads, writes, meta, vote_mismatches, dead_events, tx_results, lthash_contribs, freeze_state };

/// Set by replay_stage.onSlotCompleted on entry, cleared (=0) on return.
/// 0 = "not currently inside per-slot replay" → emit functions drop the event.
pub threadlocal var current_slot: u64 = 0;

/// Boot-time configured caps. Mutated only by `boot()`.
var max_slots: u64 = 0;
var until_slot: u64 = 0;

/// Independent kind gates. Set in `boot()` based on env vars.
var read_gate: bool = false;
var write_gate: bool = false;

/// PR-5o instrumentation gate (2026-05-19): when set via `VEX_PR5O_INSTRUMENT=1`,
/// `getAccountInSlot` emits a record into a separate JSONL file for each read
/// where `cache_slot_map[pk]` falls OUTSIDE the read's ancestor set (i.e., a
/// future read-site filter would fire). The record carries both what the
/// buggy unflushed_cache would return AND what the fall-through (cache/index/
/// storage) WOULD return — counterfactual data used to verify that the
/// upcoming Option A filter is safe. Independent of read_gate/write_gate;
/// bounded by VEX_PR5O_MAX_RECORDS (default 100000) to cap disk usage.
var pr5o_gate: bool = false;
var pr5o_max: u64 = 100000;
var pr5o_records = std.atomic.Value(u64).init(0);
var pr5o_file: ?std.fs.File = null;
var pr5o_file_mutex: std.Thread.Mutex = .{};

/// PR-5p BPF outcome instrumentation gate (2026-05-19): when set via
/// `VEX_PR5P_BPF_OUTCOME=1`, the V2 BPF dispatch path in `replay_stage.zig`
/// emits one record per BPF program invocation capturing the OUTCOME class
/// (ok / Wave6_M4_RunFailed → silent empty / M9_NoFallback / OtherError / ...).
/// Used to localize the at-tip carrier where a "successful" tx leaves
/// CPI-created accounts un-materialized — see HANDOFF v2.1 §1.C +
/// [[project_bpf_cpi_carrier_2026_05_19]]. Lifecycle matches PR-5o:
/// decoupled from the per-slot recorder's max_slots bound; bounded by
/// `VEX_PR5P_MAX_RECORDS` (default 100000).
var pr5p_gate: bool = false;
var pr5p_max: u64 = 100000;
var pr5p_records = std.atomic.Value(u64).init(0);
var pr5p_file: ?std.fs.File = null;
var pr5p_file_mutex: std.Thread.Mutex = .{};

/// PROMOTE-DIAG gate (2026-05-28): when set via `VEX_PROMOTE_DIAG=1`, the
/// AccountsDb promote/purge/advance path + getAccountInSlot fall-through emit
/// std.log.warn lines to localize the slot-564 catchup-root-lag write-loss
/// carrier (ROLLOVER 2026-05-28). Pure logging, no behavior change, bounded by
/// VEX_PROMOTE_DIAG_MAX (default 1M lines). Independent of the file recorder.
var promote_diag_gate: bool = false;
var promote_diag_max: u64 = 1000000;
var promote_diag_count = std.atomic.Value(u64).init(0);

/// True if VEX_PROMOTE_DIAG=1. Cheap hot-path check (no counter touch).
pub fn promoteDiagOn() bool {
    return promote_diag_gate;
}

/// FC-REROOT gate (Phase 1, 2026-06-06): when set via `VEX_FC_REROOT=1`, the
/// tower-BFT root advance in replay_stage.zig:submitVote calls
/// ForkChoice.setTreeRoot to bound the live fork-choice tree to the rooted
/// subtree (it is otherwise unbounded — setTreeRoot was dead/uncalled). DEFAULTS
/// OFF so this lands as a dark deploy: the ONLY behavioral side effect is that
/// bestOverallSlot is then computed over the pruned subtree, which feeds the
/// is_same_fork vote gate — so it must soak (voting continues, re-root counter
/// nonzero, nodeCount plateaus) before being defaulted ON. Cheap hot-path check.
var fc_reroot_gate: bool = false;

/// True if VEX_FC_REROOT=1. Cheap hot-path check (no counter touch).
pub fn fcReRootOn() bool {
    return fc_reroot_gate;
}

/// Returns true while the line budget remains; increments the counter. Callers
/// gate each emitted log line on this so a runaway catchup can't flood the log.
pub fn promoteDiagTick() bool {
    if (!promote_diag_gate) return false;
    return promote_diag_count.fetchAdd(1, .monotonic) < promote_diag_max;
}

/// DURABLE-CAM gate (FIX #95, 2026-05-31): when set via `VEX_DURABLE_CAM=1`, the
/// AccountsDb DURABLE-filing paths (advanceRoot eviction + flushCacheToDisk) emit
/// one std.log.warn line per durable AppendVec write: the content lamports, the
/// value's TRUE write-slot (`cache_slot_map[pk]`), the slot LABEL it is filed
/// under (`rooted_slot`/flush slot), and whether the unflushed_cache lookup HIT.
/// This is the "filing-cabinet camera" that discriminates the FIX #95 carrier
/// mode: Mode 1 (a stale older-write-slot value wins a durable slot at a higher
/// label) vs Mode 2 (cache-miss during eviction → durable write SKIPPED → a stale
/// older value is retained). Pure logging, NO behavior change, bounded by
/// VEX_DURABLE_CAM_MAX (default 5M lines). VEX_DURABLE_CAM_GAP (default 0) only
/// emits filings where (label - write_slot) >= GAP, to focus on late/stale
/// filings and cut volume during a catchup. Independent of the file recorder.
var durable_cam_gate: bool = false;
var durable_cam_max: u64 = 5000000;
var durable_cam_gap: u64 = 0;
var durable_cam_count = std.atomic.Value(u64).init(0);

/// True if VEX_DURABLE_CAM=1. Cheap hot-path check (no counter touch).
pub fn durableCamOn() bool {
    return durable_cam_gate;
}

/// Minimum (label - write_slot) gap for a durable filing to be logged (0 = all).
pub fn durableCamGap() u64 {
    return durable_cam_gap;
}

/// Returns true while the line budget remains; increments the counter. Callers
/// gate each emitted line on this so a runaway catchup can't flood the log.
pub fn durableCamTick() bool {
    if (!durable_cam_gate) return false;
    return durable_cam_count.fetchAdd(1, .monotonic) < durable_cam_max;
}

/// Set by the dispatchBpfExecution call site so emitPr5pBpfOutcome can attach
/// (tx_idx, ix_idx) without a signature change. Threadlocal so the DAG-path
/// parallelism (if/when it re-enables) is safe. 0 sentinel = "not currently
/// inside a BPF dispatch frame," which suppresses emission.
pub threadlocal var current_tx_idx: u32 = 0;
pub threadlocal var current_ix_idx: u16 = 0;
/// 1 means current_ix_idx is set (we need a separate flag because ix_idx=0 is
/// a legitimate value — the first instruction in a tx).
pub threadlocal var current_ix_present: bool = false;

/// PR-5p outcome class for one V2 BPF dispatch frame. The variants partition
/// the 7 exit points of `v2DispatchInternal` in `replay_stage.zig`:
///   ok_top                — top-level v2dispatch.v2DispatchInternal returned muts (success)
///   ok_wave6              — Wave 6 v2DispatchBpfProgram returned muts (success via fallback path)
///   wave6_m4_run_failed   — Wave 6 path caught M4_RunFailed → returned EMPTY mutations (silent #1)
///   wave6_other_fail      — Wave 6 path caught other error → returned null (silent #2)
///   m9_no_fallback        — Top-level caught M9_NoFallback → returned null (silent #3)
///   other_error           — Top-level caught other error → propagated to caller (logged)
///   skipped               — Early return (e.g., program_id_index out of range)
pub const BpfOutcome = enum(u8) {
    ok_top = 0,
    ok_wave6 = 1,
    wave6_m4_run_failed = 2,
    wave6_other_fail = 3,
    m9_no_fallback = 4,
    other_error = 5,
    skipped = 6,
};

/// Set on first emit so we can derive the upper bound (first + max_slots).
var first_slot_seen = std.atomic.Value(u64).init(0);

/// Output directory chosen at boot (for per-slot file path construction).
/// Length-tracked so we can compose paths without re-formatting the timestamp.
var output_dir: [256]u8 = undefined;
var output_dir_len: usize = 0;

/// Drives the hot-path early-out. Flipped true by `boot()`, flipped false on
/// bound-reached. Single flag — when off, every emit returns immediately.
pub var enabled = std.atomic.Value(bool).init(false);

/// Per-slot output files. One map per kind. Lazy-opened on first emit.
/// `files_mutex` guards all maps + the write paths.
var read_files: std.AutoHashMap(u64, std.fs.File) = undefined;
var write_files: std.AutoHashMap(u64, std.fs.File) = undefined;
var meta_files: std.AutoHashMap(u64, std.fs.File) = undefined;
var vote_mismatch_files: std.AutoHashMap(u64, std.fs.File) = undefined;
var dead_event_files: std.AutoHashMap(u64, std.fs.File) = undefined;
var tx_result_files: std.AutoHashMap(u64, std.fs.File) = undefined;
var lthash_contrib_files: std.AutoHashMap(u64, std.fs.File) = undefined;
var freeze_state_files: std.AutoHashMap(u64, std.fs.File) = undefined;
var files_initialized: bool = false;
var files_mutex: std.Thread.Mutex = .{};

fn parseEnvU64(name: []const u8, default_val: u64) u64 {
    const v = std.posix.getenv(name) orelse return default_val;
    return std.fmt.parseInt(u64, v, 10) catch default_val;
}

fn parseEnvBool(name: []const u8) bool {
    const v = std.posix.getenv(name) orelse return false;
    return std.mem.eql(u8, v, "1");
}

/// FREEZE-DUMP gate (FIX#95 byte-diff, 2026-06-01): when `VEX_FREEZE_DUMP_SLOT=<slot>`
/// is set, dump the FULL final freeze-state (base64 data + lamports + owner +
/// executable) for every account modified at that ONE slot, for a direct memcmp
/// against agave-ledger-tool `--record-slots-config accounts` canonical output.
/// Gated to a single slot so the output is bounded (~1144 accounts at slot 439).
var freeze_dump_gate: bool = false;
var freeze_dump_slot: u64 = 0;
// RANGE dump (2026-06-26): dump VEX_FREEZE_DUMP_COUNT consecutive slots starting at
// freeze_dump_slot (default 1 = single slot). Lets us capture a window when the carrier
// first diverges a few slots before the detected slot.
var freeze_dump_count: u64 = 1;

/// STAKE-DUMP gate (Core-BPF stake live-flip verification, 2026-06-16): when
/// `VEX_STAKE_DUMP=1`, auto-capture the FULL freeze-state (same per-account
/// base64+lamports+owner+executable as the FIX#95 freeze-dump) for ANY slot in
/// which the Core-BPF stake ON-path fired. The seam (replay_stage stake ON-branch)
/// calls `markStakeSlot(slot)`; `emitFreezeAccount` then dumps every modified
/// account at those slots. Timing-independent (no preset slot, no parity-window
/// race) so the dump can be byte-diffed vs agave-ledger-tool canonical for the
/// exact slots a stake instruction executed via the .so. Purely additive
/// observability — no consensus/state effect.
var stake_dump_gate: bool = false;
var stake_slots_mu: std.Thread.Mutex = .{};
var stake_slots: [512]u64 = [_]u64{0} ** 512; // ring of recently-fired stake slots
var stake_slots_n: usize = 0;

/// Mark a slot as having executed a stake instruction via the Core-BPF ON-path.
/// Called from the replay-stage stake seam. Cheap dedup against the ring.
pub fn markStakeSlot(slot: u64) void {
    if (!stake_dump_gate) return;
    stake_slots_mu.lock();
    defer stake_slots_mu.unlock();
    for (stake_slots) |s| {
        if (s == slot) return; // already marked
    }
    stake_slots[stake_slots_n % stake_slots.len] = slot;
    stake_slots_n += 1;
}

fn isStakeSlot(slot: u64) bool {
    if (!stake_dump_gate) return false;
    stake_slots_mu.lock();
    defer stake_slots_mu.unlock();
    for (stake_slots) |s| {
        if (s == slot) return true;
    }
    return false;
}

/// Called from main.zig once after snapshot load is complete. Idempotent.
pub fn boot() void {
    if (enabled.load(.monotonic)) return;

    read_gate = parseEnvBool("VEX_RECORD_READS");
    write_gate = parseEnvBool("VEX_RECORD_WRITES");
    pr5o_gate = parseEnvBool("VEX_PR5O_INSTRUMENT");
    pr5o_max = parseEnvU64("VEX_PR5O_MAX_RECORDS", 100000);
    pr5p_gate = parseEnvBool("VEX_PR5P_BPF_OUTCOME");
    pr5p_max = parseEnvU64("VEX_PR5P_MAX_RECORDS", 100000);
    promote_diag_gate = parseEnvBool("VEX_PROMOTE_DIAG");
    promote_diag_max = parseEnvU64("VEX_PROMOTE_DIAG_MAX", 1000000);
    // Phase 1 setTreeRoot wiring gate. Parsed HERE (before the early-return
    // below) so VEX_FC_REROOT is honored even when no file-recorder gate is set;
    // deliberately NOT added to the early-return condition so VEX_FC_REROOT alone
    // does NOT spin up the per-slot file recorder.
    fc_reroot_gate = parseEnvBool("VEX_FC_REROOT");
    durable_cam_gate = parseEnvBool("VEX_DURABLE_CAM");
    durable_cam_max = parseEnvU64("VEX_DURABLE_CAM_MAX", 5000000);
    durable_cam_gap = parseEnvU64("VEX_DURABLE_CAM_GAP", 0);
    freeze_dump_slot = parseEnvU64("VEX_FREEZE_DUMP_SLOT", 0);
    freeze_dump_gate = (freeze_dump_slot != 0);
    freeze_dump_count = parseEnvU64("VEX_FREEZE_DUMP_COUNT", 1);
    if (freeze_dump_count == 0) freeze_dump_count = 1;
    stake_dump_gate = parseEnvBool("VEX_STAKE_DUMP");
    if (!read_gate and !write_gate and !pr5o_gate and !pr5p_gate and !promote_diag_gate and !durable_cam_gate and !freeze_dump_gate and !stake_dump_gate) return;

    max_slots = parseEnvU64("VEX_RECORD_SLOTS", 10);
    until_slot = parseEnvU64("VEX_RECORD_UNTIL_SLOT", 0);

    // PR-5o: lazy-open a single JSONL file in the recorder output dir if
    // pr5o_gate is set. Note: NOT bounded by VEX_RECORD_SLOTS — the PR-5o
    // run is bounded by VEX_PR5O_MAX_RECORDS independently (see
    // `isPr5oEnabled` / `emitPr5oInstrument`).
    if (pr5o_gate) {
        // File path constructed after output_dir is set below (so include
        // the boot ts for run isolation).
    }

    const ts = std.time.timestamp();
    const dir = std.fmt.bufPrint(&output_dir, "/mnt/ramdisk/vex-record-{d}", .{ts}) catch return;
    output_dir_len = dir.len;

    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            std.log.warn("[RECORDER] mkdir failed for {s}: {any}", .{ dir, err });
            return;
        },
    };

    read_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
    write_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
    meta_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
    vote_mismatch_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
    dead_event_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
    tx_result_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
    lthash_contrib_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
    freeze_state_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
    files_initialized = true;

    enabled.store(true, .monotonic);

    // Tier-2 (2026-05-17): emit a run-metadata sidecar so the oracle can
    // index runs across iterations and compute deltas. Captures: boot
    // timestamp, binary md5 (read from /proc/self/exe), git commit (from
    // VEX_GIT_COMMIT env var if set by deploy.sh), env-var snapshot for
    // the env-gated probes, and the configured caps. Single JSON file at
    // <dir>/run_metadata.json so it's trivial to read with `jq`.
    writeRunMetadata(dir) catch |e| {
        std.log.warn("[RECORDER] run_metadata write failed: {any}", .{e});
    };

    // PR-5o: open the instrumentation output file now that output_dir is set.
    if (pr5o_gate) {
        var pr5o_path_buf: [320]u8 = undefined;
        const pr5o_path = std.fmt.bufPrint(&pr5o_path_buf, "{s}/pr5o-instrument.jsonl", .{dir}) catch null;
        if (pr5o_path) |p| {
            pr5o_file = std.fs.createFileAbsolute(p, .{ .truncate = true }) catch |err| blk: {
                std.log.warn("[RECORDER] PR-5o open failed for {s}: {any}", .{ p, err });
                pr5o_gate = false;
                break :blk null;
            };
        } else {
            pr5o_gate = false;
        }
    }

    // PR-5p: open the BPF-outcome output file now that output_dir is set.
    if (pr5p_gate) {
        var pr5p_path_buf: [320]u8 = undefined;
        const pr5p_path = std.fmt.bufPrint(&pr5p_path_buf, "{s}/pr5p-bpf-outcome.jsonl", .{dir}) catch null;
        if (pr5p_path) |p| {
            pr5p_file = std.fs.createFileAbsolute(p, .{ .truncate = true }) catch |err| blk: {
                std.log.warn("[RECORDER] PR-5p open failed for {s}: {any}", .{ p, err });
                pr5p_gate = false;
                break :blk null;
            };
        } else {
            pr5p_gate = false;
        }
    }

    std.log.warn(
        "[RECORDER] enabled: dir={s} max_slots={d} until_slot={d} reads={s} writes={s} pr5o={s} pr5o_max={d} pr5p={s} pr5p_max={d}",
        .{ dir, max_slots, until_slot, if (read_gate) "ON" else "off", if (write_gate) "ON" else "off", if (pr5o_gate) "ON" else "off", pr5o_max, if (pr5p_gate) "ON" else "off", pr5p_max },
    );
}

fn writeRunMetadata(dir: []const u8) !void {
    var path_buf: [320]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/run_metadata.json", .{dir});
    var f = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer f.close();

    // Read /proc/self/exe → md5 candidate. Cheap: we just record the path
    // and let the oracle md5sum it (avoids pulling crypto into recorder).
    var exe_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = std.fs.readLinkAbsolute("/proc/self/exe", &exe_path_buf) catch "unknown";

    // Hostname, useful when iterating across hosts.
    var host_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const host = std.posix.gethostname(&host_buf) catch "unknown";

    // Optional env vars deploy.sh / CI can set for richer metadata.
    const git_commit = std.posix.getenv("VEX_GIT_COMMIT") orelse "unset";
    const fork_iso = std.posix.getenv("VEX_FORK_ISOLATION") orelse "0";

    var line_buf: [2048]u8 = undefined;
    const line = try std.fmt.bufPrint(
        &line_buf,
        "{{\"boot_ts\":{d},\"exe_path\":\"{s}\",\"host\":\"{s}\",\"git_commit\":\"{s}\",\"max_slots\":{d},\"until_slot\":{d},\"reads_gate\":{d},\"writes_gate\":{d},\"fork_isolation\":\"{s}\"}}\n",
        .{
            std.time.timestamp(),
            exe_path,
            host,
            git_commit,
            max_slots,
            until_slot,
            @intFromBool(read_gate),
            @intFromBool(write_gate),
            fork_iso,
        },
    );
    _ = try f.writeAll(line);
}

/// Cheap pre-checks used by callers so they can skip building event values
/// when the recorder is off. Inlinable into hot read/write paths.
pub inline fn isEnabled() bool {
    return enabled.load(.monotonic);
}
pub inline fn isReadEnabled() bool {
    return read_gate and enabled.load(.monotonic);
}
pub inline fn isWriteEnabled() bool {
    return write_gate and enabled.load(.monotonic);
}
/// PR-5o instrumentation gate (2026-05-19). True when:
///   - VEX_PR5O_INSTRUMENT=1 was set at boot, AND
///   - emitted record count is below VEX_PR5O_MAX_RECORDS.
/// Independent of read_gate/write_gate AND of the per-slot recorder's
/// max_slots/until_slot bound — pr5o samples fork-divergence events for
/// far longer than the per-slot streams retain data for, so it must keep
/// emitting after `shutdown()` closes the per-slot files.
pub inline fn isPr5oEnabled() bool {
    return pr5o_gate and pr5o_records.load(.monotonic) < pr5o_max;
}

/// PR-5p instrumentation gate (2026-05-19). Same lifecycle rules as
/// `isPr5oEnabled` — independent of all other gates, decoupled from
/// `shutdown()`. True when VEX_PR5P_BPF_OUTCOME=1 AND emitted count is
/// below VEX_PR5P_MAX_RECORDS. The hot path in `v2DispatchInternal` checks
/// this inline before allocating the JSON line.
pub inline fn isPr5pEnabled() bool {
    return pr5p_gate and pr5p_records.load(.monotonic) < pr5p_max;
}

/// Compute the 8-byte SHA-256 prefix of the FULL `data` (2026-06-01: was
/// first-64-only — the Task#100 trap that masked past-byte-64 divergence in
/// the write-tap/lthash backstop. Upgraded to full-data per advisor so a
/// data-only stale read is catchable in the recorder diff, not just lamports).
/// Returns 0 if data is empty/null. Called inline before any lock release so
/// mmap-backed slices stay valid (a known pitfall here: mmap-backed data must be copied out before use).
fn sha8Of(data: ?[]const u8) u64 {
    const d = data orelse return 0;
    if (d.len == 0) return 0;
    var sha_buf: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(d, &sha_buf, .{});
    return std.mem.readInt(u64, sha_buf[0..8], .big);
}

/// Get-or-open the per-slot file for `kind`. Caller must hold `files_mutex`.
fn getOrOpenFile(slot: u64, kind: Kind) ?std.fs.File {
    const map: *std.AutoHashMap(u64, std.fs.File) = switch (kind) {
        .reads => &read_files,
        .writes => &write_files,
        .meta => &meta_files,
        .vote_mismatches => &vote_mismatch_files,
        .dead_events => &dead_event_files,
        .tx_results => &tx_result_files,
        .lthash_contribs => &lthash_contrib_files,
        .freeze_state => &freeze_state_files,
    };
    if (map.get(slot)) |f| return f;

    var path_buf: [320]u8 = undefined;
    const dir = output_dir[0..output_dir_len];
    const suffix: []const u8 = switch (kind) {
        .reads => "reads",
        .writes => "writes",
        .meta => "meta",
        .vote_mismatches => "vote_mismatches",
        .dead_events => "dead_events",
        .tx_results => "tx_results",
        .lthash_contribs => "lthash_contribs",
        .freeze_state => "freeze_state",
    };
    const path = std.fmt.bufPrint(&path_buf, "{s}/slot-{d}.{s}.jsonl", .{ dir, slot, suffix }) catch return null;
    const f = std.fs.createFileAbsolute(path, .{ .truncate = true }) catch |err| {
        std.log.warn("[RECORDER] open failed for {s}: {any}", .{ path, err });
        return null;
    };
    map.put(slot, f) catch {
        f.close();
        return null;
    };
    return f;
}

/// Close all open files and disable. Called when bound is reached.
fn shutdown(reason: []const u8) void {
    if (!enabled.swap(false, .monotonic)) return;
    files_mutex.lock();
    defer files_mutex.unlock();
    if (files_initialized) {
        var rit = read_files.iterator();
        while (rit.next()) |e| {
            e.value_ptr.sync() catch {};
            e.value_ptr.close();
        }
        read_files.deinit();
        var wit = write_files.iterator();
        while (wit.next()) |e| {
            e.value_ptr.sync() catch {};
            e.value_ptr.close();
        }
        write_files.deinit();
        var mit = meta_files.iterator();
        while (mit.next()) |e| {
            e.value_ptr.sync() catch {};
            e.value_ptr.close();
        }
        meta_files.deinit();
        var vmit = vote_mismatch_files.iterator();
        while (vmit.next()) |e| {
            e.value_ptr.sync() catch {};
            e.value_ptr.close();
        }
        vote_mismatch_files.deinit();
        var deit = dead_event_files.iterator();
        while (deit.next()) |e| {
            e.value_ptr.sync() catch {};
            e.value_ptr.close();
        }
        dead_event_files.deinit();
        var txit = tx_result_files.iterator();
        while (txit.next()) |e| {
            e.value_ptr.sync() catch {};
            e.value_ptr.close();
        }
        tx_result_files.deinit();
        var ltit = lthash_contrib_files.iterator();
        while (ltit.next()) |e| {
            e.value_ptr.sync() catch {};
            e.value_ptr.close();
        }
        lthash_contrib_files.deinit();
        files_initialized = false;
    }
    // PR-5o / PR-5p instrumentation files are NOT closed here. Their
    // lifecycles are decoupled from the per-slot recorder's max_slots/
    // until_slot bound so that we can sample carrier events for far longer
    // than the per-slot streams retain data for. Each file closes when:
    //   (a) its own per-record cap is reached (closeOncePr*CapReached), or
    //   (b) process exit (OS reaps the fd).
    std.log.warn("[RECORDER] shutdown: {s} (per-slot streams closed; pr5o_records_so_far={d} pr5p_records_so_far={d})", .{ reason, pr5o_records.load(.monotonic), pr5p_records.load(.monotonic) });
}

/// Close + sync the pr5o file ONCE, when the pr5o cap is reached. Idempotent
/// under concurrent calls (only the first thread to observe pr5o_file != null
/// performs the close; subsequent callers see null and return).
fn closeOncePr5oCapReached() void {
    pr5o_file_mutex.lock();
    defer pr5o_file_mutex.unlock();
    if (pr5o_file) |f| {
        f.sync() catch {};
        f.close();
        pr5o_file = null;
        std.log.warn("[RECORDER] pr5o cap reached: pr5o_records_emitted={d}", .{pr5o_records.load(.monotonic)});
    }
}

/// Close + sync the pr5p file ONCE, when the pr5p cap is reached. Same
/// idempotent shape as closeOncePr5oCapReached.
fn closeOncePr5pCapReached() void {
    pr5p_file_mutex.lock();
    defer pr5p_file_mutex.unlock();
    if (pr5p_file) |f| {
        f.sync() catch {};
        f.close();
        pr5p_file = null;
        std.log.warn("[RECORDER] pr5p cap reached: pr5p_records_emitted={d}", .{pr5p_records.load(.monotonic)});
    }
}

/// Update first_slot_seen and check bounds. Returns true if event should be
/// dropped. Used by both emit functions.
fn boundCheck() bool {
    if (current_slot == 0) return true;
    if (first_slot_seen.load(.monotonic) == 0) {
        _ = first_slot_seen.cmpxchgStrong(0, current_slot, .monotonic, .monotonic);
    }
    const first = first_slot_seen.load(.monotonic);
    if (max_slots > 0 and current_slot >= first + max_slots) {
        shutdown("bound reached (max_slots)");
        return true;
    }
    if (until_slot > 0 and current_slot > until_slot) {
        shutdown("passed until_slot");
        return true;
    }
    return false;
}

/// Emit one record for a `getAccountInSlot` / `_getRooted` return.
///
/// `data_len` and `data` may be null on a miss. `csm` is the value of
/// `cache_slot_map[pk]` at read time (null if absent). `anc_first`/`anc_last`
/// bracket the ancestors window (null for direct `_getRooted` callers that
/// don't have one).
pub fn emitRead(
    pk: *const [32]u8,
    layer: Layer,
    lamports: ?u64,
    data: ?[]const u8,
    data_len: ?usize,
    csm: ?u64,
    anc_first: ?u64,
    anc_last: ?u64,
    sig_ov_slots: ?[]const u64,
) void {
    if (!read_gate or !enabled.load(.monotonic)) return;
    if (boundCheck()) return;

    const sha8 = sha8Of(data);
    const dlen: u64 = if (data_len) |dl| @as(u64, @intCast(dl)) else 0;
    const lam: u64 = if (lamports) |l| l else 0;
    const lam_present: u8 = if (lamports != null) 1 else 0;
    const csm_val: u64 = if (csm) |c| c else 0;
    const csm_present: u8 = if (csm != null) 1 else 0;
    const af: u64 = if (anc_first) |a| a else 0;
    const al: u64 = if (anc_last) |a| a else 0;
    const anc_present: u8 = if (anc_first != null) 1 else 0;

    const pk_hex = std.fmt.bytesToHex(pk.*, .lower);

    var line_buf: [2048]u8 = undefined;
    var w = std.io.fixedBufferStream(&line_buf);
    const writer = w.writer();
    writer.print(
        "{{\"slot\":{d},\"pk\":\"{s}\",\"layer\":\"{s}\",\"lam_p\":{d},\"lam\":{d},\"sha8\":{d},\"dlen\":{d},\"csm_p\":{d},\"csm\":{d},\"anc_p\":{d},\"af\":{d},\"al\":{d}",
        .{ current_slot, &pk_hex, @tagName(layer), lam_present, lam, sha8, dlen, csm_present, csm_val, anc_present, af, al },
    ) catch return;
    if (sig_ov_slots) |slots| {
        writer.writeAll(",\"sigov\":[") catch return;
        for (slots, 0..) |s, i| {
            if (i > 0) writer.writeByte(',') catch return;
            writer.print("{d}", .{s}) catch return;
        }
        writer.writeByte(']') catch return;
    }
    writer.writeAll("}\n") catch return;
    const line = w.getWritten();

    files_mutex.lock();
    defer files_mutex.unlock();
    if (!files_initialized) return;
    const f = getOrOpenFile(current_slot, .reads) orelse return;
    _ = f.writeAll(line) catch {};
}

/// Emit one record per slot at onSlotCompleted entry. Captures the catchup-state
/// of ancestors + rooted_slot so we can correlate read pollution events with the
/// fork-tree depth available at that moment. Critical for diagnosing Phase 1D/1E's
/// bounded-ancestors-window regression: when ancestors_len is tiny during catchup,
/// the filter false-flags legitimate canonical writes.
pub fn emitSlotMeta(
    slot: u64,
    parent_slot: ?u64,
    ancestors: []const u64,
    rooted_slot: u64,
) void {
    if (!enabled.load(.monotonic)) return;
    // Slot-meta is unconditional when recorder is on (regardless of read/write gate)
    // — it's the index by which all other records are interpreted.

    var line_buf: [2048]u8 = undefined;
    var w = std.io.fixedBufferStream(&line_buf);
    const writer = w.writer();
    const ps_val: u64 = if (parent_slot) |p| p else 0;
    const ps_present: u8 = if (parent_slot != null) 1 else 0;
    writer.print(
        "{{\"slot\":{d},\"parent_p\":{d},\"parent\":{d},\"rooted\":{d},\"anc_len\":{d},\"anc\":[",
        .{ slot, ps_present, ps_val, rooted_slot, ancestors.len },
    ) catch return;
    const cap = @min(ancestors.len, 128);
    for (ancestors[0..cap], 0..) |a, i| {
        if (i > 0) writer.writeByte(',') catch return;
        writer.print("{d}", .{a}) catch return;
    }
    writer.writeAll("]}\n") catch return;
    const line = w.getWritten();

    files_mutex.lock();
    defer files_mutex.unlock();
    if (!files_initialized) return;
    const f = getOrOpenFile(slot, .meta) orelse return;
    _ = f.writeAll(line) catch {};
}

/// Emit one record for a `promoteToUnflushedCache` per-write iteration.
///
/// `prev_csm` is `cache_slot_map[pk]` BEFORE this write (i.e. which slot
/// previously owned this pk in unflushed_cache). If `prev_csm != current_slot`
/// AND `prev_csm` is on a sibling fork, this write is overwriting a value
/// from a different fork — the iter-6 pollution event.
///
/// `prev_lam` and `prev_sha8` are the previous unflushed_cache entry's values
/// (null if no prior entry). The new values are `new_lam` / `new_data`.
/// `owner` is the writing account's owner pubkey.
pub fn emitWrite(
    pk: *const [32]u8,
    owner: *const [32]u8,
    new_lam: u64,
    new_data: []const u8,
    prev_csm: ?u64,
    prev_lam: ?u64,
    prev_data: ?[]const u8,
) void {
    if (!write_gate or !enabled.load(.monotonic)) return;
    if (boundCheck()) return;

    const new_sha8 = sha8Of(new_data);
    const prev_sha8 = sha8Of(prev_data);
    const prev_lam_val: u64 = if (prev_lam) |l| l else 0;
    const prev_lam_present: u8 = if (prev_lam != null) 1 else 0;
    const prev_csm_val: u64 = if (prev_csm) |c| c else 0;
    const prev_csm_present: u8 = if (prev_csm != null) 1 else 0;

    const pk_hex = std.fmt.bytesToHex(pk.*, .lower);
    const ow_hex = std.fmt.bytesToHex(owner.*, .lower);

    var line_buf: [1024]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "{{\"slot\":{d},\"pk\":\"{s}\",\"owner\":\"{s}\",\"new_lam\":{d},\"new_sha8\":{d},\"new_dlen\":{d},\"prev_csm_p\":{d},\"prev_csm\":{d},\"prev_lam_p\":{d},\"prev_lam\":{d},\"prev_sha8\":{d}}}\n",
        .{ current_slot, &pk_hex, &ow_hex, new_lam, new_sha8, new_data.len, prev_csm_present, prev_csm_val, prev_lam_present, prev_lam_val, prev_sha8 },
    ) catch return;

    files_mutex.lock();
    defer files_mutex.unlock();
    if (!files_initialized) return;
    const f = getOrOpenFile(current_slot, .writes) orelse return;
    _ = f.writeAll(line) catch {};
}

/// PR-5o (2026-05-19): emit one instrumentation record at a `getAccountInSlot`
/// read where the filter would fire (csm_slot is NOT in the lookup ancestor
/// set). Captures both the buggy value (`unflushed_*`) and the counterfactual
/// fall-through value (`fallthrough_*`) so a post-run analysis can confirm
/// "if filter fires AND fall-through is sane in 100% of cases, Option A is
/// safe to land" — see HANDOFF §5.6 step 3 + the carrier #2 reproducer tests
/// in accounts.zig.
///
/// Pre-condition: caller has verified `isPr5oEnabled()` is true AND
/// `csm_slot ∉ lookup`. This function does the bound check + serialize +
/// disk write. Thread-safe via `pr5o_file_mutex`.
pub fn emitPr5oInstrument(
    pk: *const [32]u8,
    csm_slot: u64,
    lookup: []const u64,
    unflushed_lam: ?u64,
    unflushed_data: ?[]const u8,
    fallthrough_lam: ?u64,
    fallthrough_data: ?[]const u8,
    fallthrough_layer: ?Layer,
) void {
    if (!pr5o_gate) return;
    if (current_slot == 0) return;
    // Atomic bump-and-cap. Use cmpxchg loop to avoid emitting beyond the cap
    // when many threads race. When the cap is reached, close the pr5o file
    // once so its tail is durably synced (the per-slot recorder's shutdown
    // no longer does this — pr5o is decoupled from max_slots).
    while (true) {
        const cur = pr5o_records.load(.monotonic);
        if (cur >= pr5o_max) {
            closeOncePr5oCapReached();
            return;
        }
        if (pr5o_records.cmpxchgWeak(cur, cur + 1, .monotonic, .monotonic) == null) break;
    }

    const pk_hex = std.fmt.bytesToHex(pk.*, .lower);
    const u_lam_p: u8 = if (unflushed_lam != null) 1 else 0;
    const u_lam: u64 = if (unflushed_lam) |l| l else 0;
    const u_dlen: u64 = if (unflushed_data) |d| @as(u64, @intCast(d.len)) else 0;
    const u_sha8: u64 = sha8Of(unflushed_data);
    const ft_lam_p: u8 = if (fallthrough_lam != null) 1 else 0;
    const ft_lam: u64 = if (fallthrough_lam) |l| l else 0;
    const ft_dlen: u64 = if (fallthrough_data) |d| @as(u64, @intCast(d.len)) else 0;
    const ft_sha8: u64 = sha8Of(fallthrough_data);
    const ft_layer_str: []const u8 = if (fallthrough_layer) |l| @tagName(l) else "null";

    var line_buf: [2048]u8 = undefined;
    var w = std.io.fixedBufferStream(&line_buf);
    const writer = w.writer();
    writer.print(
        "{{\"slot\":{d},\"pk\":\"{s}\",\"csm\":{d},\"u_lam_p\":{d},\"u_lam\":{d},\"u_dlen\":{d},\"u_sha8\":{d},\"ft_lam_p\":{d},\"ft_lam\":{d},\"ft_dlen\":{d},\"ft_sha8\":{d},\"ft_layer\":\"{s}\",\"anc\":[",
        .{ current_slot, &pk_hex, csm_slot, u_lam_p, u_lam, u_dlen, u_sha8, ft_lam_p, ft_lam, ft_dlen, ft_sha8, ft_layer_str },
    ) catch return;
    // Truncate to first 8 ancestors — analysis only needs to see the top
    // entries to confirm csm_slot ∉ anc. Avoids drowning the log.
    const anc_cap = @min(lookup.len, 8);
    for (lookup[0..anc_cap], 0..) |a, i| {
        if (i > 0) writer.writeByte(',') catch return;
        writer.print("{d}", .{a}) catch return;
    }
    writer.print("],\"anc_len\":{d}}}\n", .{lookup.len}) catch return;
    const line = w.getWritten();

    pr5o_file_mutex.lock();
    defer pr5o_file_mutex.unlock();
    const f = pr5o_file orelse return;
    _ = f.writeAll(line) catch {};
}

/// PR-5p (2026-05-19): emit one record per V2 BPF dispatch frame. Called from
/// every return point of `replay_stage.zig:v2DispatchInternal` so the analysis
/// can attribute every BPF outer-instruction to one of 7 outcome classes
/// (see `BpfOutcome` enum). Carries:
///   - slot (from current_slot threadlocal)
///   - tx_idx / ix_idx (from current_tx_idx / current_ix_idx threadlocals,
///     set by the caller at the dispatchBpfExecution call site)
///   - program_id (32-byte hex)
///   - elf_version (0/1/2/3, or 255 = unknown / not resolved)
///   - outcome (BpfOutcome enum tag-name string)
///   - err_name (optional, the raw @errorName) when outcome is an error class
///   - muts_count (success outcomes carry the produced mutation list length;
///     silent-failure outcomes are 0 by definition)
///
/// Pre-condition: caller verified `isPr5pEnabled()` true. This function does
/// the bound check + serialize + disk write. Thread-safe via `pr5p_file_mutex`.
pub fn emitPr5pBpfOutcome(
    program_id: *const [32]u8,
    elf_version: u8,
    outcome: BpfOutcome,
    err_name: ?[]const u8,
    muts_count: u32,
) void {
    if (!pr5p_gate) return;
    if (current_slot == 0) return;
    // Atomic bump-and-cap (same pattern as emitPr5oInstrument).
    while (true) {
        const cur = pr5p_records.load(.monotonic);
        if (cur >= pr5p_max) {
            closeOncePr5pCapReached();
            return;
        }
        if (pr5p_records.cmpxchgWeak(cur, cur + 1, .monotonic, .monotonic) == null) break;
    }

    const pid_hex = std.fmt.bytesToHex(program_id.*, .lower);
    const err_str: []const u8 = if (err_name) |e| e else "";
    const err_str_capped: []const u8 = if (err_str.len > 64) err_str[0..64] else err_str;
    const ix_present_u8: u8 = if (current_ix_present) 1 else 0;

    var line_buf: [1024]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "{{\"slot\":{d},\"tx\":{d},\"ix_p\":{d},\"ix\":{d},\"pid\":\"{s}\",\"elf\":{d},\"outcome\":\"{s}\",\"err\":\"{s}\",\"muts\":{d}}}\n",
        .{
            current_slot,
            current_tx_idx,
            ix_present_u8,
            current_ix_idx,
            &pid_hex,
            elf_version,
            @tagName(outcome),
            err_str_capped,
            muts_count,
        },
    ) catch return;

    pr5p_file_mutex.lock();
    defer pr5p_file_mutex.unlock();
    const f = pr5p_file orelse return;
    _ = f.writeAll(line) catch {};
}

/// Outcome tag for a vote SlotHashMismatch event.
pub const VoteMismatchOutcome = enum(u8) {
    /// Local SlotHashes lacks the (slot, hash) entry — but cluster fallback
    /// accepted. Phase G-2 firing → vote-state mutated using cluster's view.
    accepted_via_cluster_fallback = 0,
    /// Local missed AND cluster fallback (also missed | unavailable). Vote
    /// rejected as SlotHashMismatch.
    rejected = 1,
};

/// Emit one record per vote SlotHashMismatch event (Phase G-2 instrumentation).
///
/// Captures the gap between voter-signed (proposed_slot, proposed_hash) and
/// our local view, plus whether the cluster's curl-cached SlotHashes had a
/// matching entry. Used to characterize WHY the 99.83% mutate_fail rate
/// happens — is our local view 1-slot off, wildly different, or transient
/// catchup race — and whether Phase G-2's fallback recovers the vote.
///
/// `proposed_hash` and `local_hash`/`cluster_hash` are first-8-bytes prefixes.
/// Pass 0 for `local_hash` when our SlotHashes had no entry for proposed_slot.
/// Pass 0 for `cluster_hash` when no cluster fallback data was available.
pub fn emitVoteMismatch(
    voter_pk: *const [32]u8,
    proposed_slot: u64,
    proposed_hash_prefix: u64,
    local_hash_prefix: u64,
    cluster_hash_prefix: u64,
    outcome: VoteMismatchOutcome,
) void {
    if (!enabled.load(.monotonic)) return;
    if (boundCheck()) return;

    const voter_hex = std.fmt.bytesToHex(voter_pk.*, .lower);

    var line_buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "{{\"slot\":{d},\"voter\":\"{s}\",\"proposed_slot\":{d},\"proposed_hash\":{d},\"local_hash\":{d},\"cluster_hash\":{d},\"slot_delta\":{d},\"outcome\":\"{s}\"}}\n",
        .{
            current_slot,
            &voter_hex,
            proposed_slot,
            proposed_hash_prefix,
            local_hash_prefix,
            cluster_hash_prefix,
            @as(i64, @intCast(current_slot)) - @as(i64, @intCast(proposed_slot)),
            @tagName(outcome),
        },
    ) catch return;

    files_mutex.lock();
    defer files_mutex.unlock();
    if (!files_initialized) return;
    const f = getOrOpenFile(current_slot, .vote_mismatches) orelse return;
    _ = f.writeAll(line) catch {};
}

/// Emit one record per markSlotDead call (Phase I / Phase J / cascade trace).
///
/// `slot` is the dying slot. `reason` is the human-readable tag passed to
/// markSlotDead ("leader-skip-from-canonical-parent_off",
/// "orphan-not-in-cluster-slothashes", "cascade_orphan_of_dead_parent", etc.).
/// `target_parent` is set when reason is a cascade event — points at the
/// already-dead parent that triggered this descendant's death. Pass null
/// for non-cascade reasons.
///
/// Note: emit happens on the THREAD that calls markSlotDead — that thread's
/// `current_slot` may differ from the slot being marked dead. We use the
/// `slot` parameter for routing, not `current_slot`, so cascade events from
/// any thread land in the right file.
pub fn emitDeadSlot(
    slot: u64,
    reason: []const u8,
    target_parent: ?u64,
) void {
    if (!enabled.load(.monotonic)) return;
    // No boundCheck — dead events route by `slot`, not current_slot. Apply
    // an explicit window check against first_slot_seen + max_slots so this
    // stays bounded.
    const first = first_slot_seen.load(.monotonic);
    if (first == 0) return;
    if (max_slots > 0 and slot >= first + max_slots) return;
    if (slot < first) return;

    const tp_val: u64 = if (target_parent) |t| t else 0;
    const tp_present: u8 = if (target_parent != null) 1 else 0;

    var line_buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "{{\"slot\":{d},\"reason\":\"{s}\",\"target_parent_p\":{d},\"target_parent\":{d}}}\n",
        .{ slot, reason, tp_present, tp_val },
    ) catch return;

    files_mutex.lock();
    defer files_mutex.unlock();
    if (!files_initialized) return;
    const f = getOrOpenFile(slot, .dead_events) orelse return;
    _ = f.writeAll(line) catch {};
}

/// Tier-1 (2026-05-17): per-tx outcome record. Emitted at the end of every
/// transaction's execution. Lets the oracle diff Vexor's per-tx outcomes
/// against cluster's getBlock(slot, transactionDetails:full) response to
/// identify "tx N succeeded on Vexor but failed on cluster" or vice versa
/// without grepping stdlog. Schema: slot, tx_idx, sig_prefix (first 8 of
/// signature), success, error_code (Custom errors are surfaced as integer;
/// 0 = success), fee, compute_consumed.
pub fn emitTxResult(
    tx_idx: u32,
    sig_prefix: u64,
    success: bool,
    error_code: i64,
    fee_lamports: u64,
    compute_consumed: u64,
) void {
    if (!enabled.load(.monotonic)) return;
    if (boundCheck()) return;

    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "{{\"slot\":{d},\"tx_idx\":{d},\"sig\":{d},\"success\":{d},\"err\":{d},\"fee\":{d},\"compute\":{d}}}\n",
        .{ current_slot, tx_idx, sig_prefix, @intFromBool(success), error_code, fee_lamports, compute_consumed },
    ) catch return;

    files_mutex.lock();
    defer files_mutex.unlock();
    if (!files_initialized) return;
    const f = getOrOpenFile(current_slot, .tx_results) orelse return;
    _ = f.writeAll(line) catch {};
}

/// Tier-2 (2026-05-17): per-account lthash contribution. Emitted from
/// bank.zig:freeze() as each pubkey's accountLtHash() is mixed into the
/// slot's accumulator. The 4.1% of vote-state mismatches in the wider
/// recorder window are genuine bank_hash divergence — for those, comparing
/// per-account contributions vs oracle-node's bank_hash_details JSON points at
/// the EXACT pubkey whose hash drifted (out of 86M loaded accounts).
///
/// Schema: slot, pk (full hex32), lthash_delta_prefix (first 8 bytes of
/// the 32-byte LtHash contribution for this account, big-endian u64),
/// op (0=add, 1=remove — LtHash supports both for credit/debit composition).
pub fn emitLtHashContribution(
    pk: *const [32]u8,
    lthash_prefix: u64,
    op: u8,
) void {
    if (!enabled.load(.monotonic)) return;
    if (boundCheck()) return;

    const pk_hex = std.fmt.bytesToHex(pk.*, .lower);
    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "{{\"slot\":{d},\"pk\":\"{s}\",\"lt\":{d},\"op\":{d}}}\n",
        .{ current_slot, &pk_hex, lthash_prefix, op },
    ) catch return;

    files_mutex.lock();
    defer files_mutex.unlock();
    if (!files_initialized) return;
    const f = getOrOpenFile(current_slot, .lthash_contribs) orelse return;
    _ = f.writeAll(line) catch {};
}

/// FIX#95 (2026-06-01): dump full final freeze-state for ONE modified account
/// at the gated slot (VEX_FREEZE_DUMP_SLOT) — base64(data) + lamports + owner +
/// executable — for a direct memcmp vs agave-ledger-tool `--record-slots-config
/// accounts` canonical output. Bounded to a single slot (~1144 accounts).
/// Purely additive observability: no consensus/state effect.
pub fn emitFreezeAccount(
    slot: u64,
    pk: *const [32]u8,
    lamports: u64,
    owner: *const [32]u8,
    executable: bool,
    data: []const u8,
) void {
    // Dump if this is the single FIX#95 gated slot OR a Core-BPF stake ON-path
    // slot (VEX_STAKE_DUMP). Either gate alone is sufficient.
    const dump_this = (freeze_dump_gate and slot >= freeze_dump_slot and slot < freeze_dump_slot + freeze_dump_count) or isStakeSlot(slot);
    if (!dump_this) return;
    if (!enabled.load(.monotonic)) return;

    // DIAG (2026-06-26): name the exact account + slice shape BEFORE any data deref,
    // so the last line before a crash identifies the dangling-slice culprit. Reads only
    // the fat-pointer fields (len + address) — never the pointed-to bytes. Remove once
    // the lifetime root cause is fixed.
    {
        const diag_pk = std.fmt.bytesToHex(pk.*, .lower);
        std.log.warn("[FREEZE-DUMP-DIAG] slot={d} pk={s} dlen={d} dptr=0x{x} lam={d} exec={d}", .{ slot, &diag_pk, data.len, @intFromPtr(data.ptr), lamports, @intFromBool(executable) });
    }
    // Guard against a corrupt / dangling account-data slice: no real Solana account
    // exceeds 10 MiB, so an absurd len means the slice is bad — base64-encoding it
    // would read unmapped memory and CRASH the whole freeze dump (this exact panic
    // blocked carrier #81's per-account analysis on 2026-06-26). Skip + log it (the
    // log names the offending account so it can be investigated) instead of dying.
    const MAX_ACCT_DATA: usize = 16 * 1024 * 1024;
    if (data.len > MAX_ACCT_DATA) {
        const pk_hex_skip = std.fmt.bytesToHex(pk.*, .lower);
        std.log.warn("[FREEZE-DUMP] slot={d} pk={s} SKIP — implausible data.len={d} (>16MiB, likely a stale slice)", .{ slot, &pk_hex_skip, data.len });
        return;
    }
    const enc = std.base64.standard.Encoder;
    const out_len = enc.calcSize(data.len);
    // +16 byte slack: Zig 0.15.2's encode fast path writes in 16-byte blocks; the
    // extra headroom keeps any block-boundary write strictly in-bounds. The valid
    // output is the first out_len bytes.
    const b64 = std.heap.page_allocator.alloc(u8, out_len + 16) catch return;
    defer std.heap.page_allocator.free(b64);
    _ = enc.encode(b64[0 .. out_len + 16], data);

    const pk_hex = std.fmt.bytesToHex(pk.*, .lower);
    const ow_hex = std.fmt.bytesToHex(owner.*, .lower);
    var hdr: [512]u8 = undefined;
    const hl = std.fmt.bufPrint(
        &hdr,
        "{{\"slot\":{d},\"pk\":\"{s}\",\"owner\":\"{s}\",\"lamports\":{d},\"executable\":{d},\"dlen\":{d},\"data64\":\"",
        .{ slot, &pk_hex, &ow_hex, lamports, @intFromBool(executable), data.len },
    ) catch return;

    files_mutex.lock();
    defer files_mutex.unlock();
    if (!files_initialized) return;
    const f = getOrOpenFile(slot, .freeze_state) orelse return;
    _ = f.writeAll(hl) catch {};
    _ = f.writeAll(b64[0..out_len]) catch {};
    _ = f.writeAll("\"}\n") catch {};
}

// ─── Smoke tests ──────────────────────────────────────────────────────────
//
// Test-only entrypoint that bypasses the env-var gate. NOT for production.

fn testForceEnable(tmp_dir: []const u8, reads_on: bool, writes_on: bool) !void {
    @memcpy(output_dir[0..tmp_dir.len], tmp_dir);
    output_dir_len = tmp_dir.len;
    max_slots = 1000;
    until_slot = 0;
    read_gate = reads_on;
    write_gate = writes_on;
    if (!files_initialized) {
        read_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
        write_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
        meta_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
        vote_mismatch_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
        dead_event_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
        tx_result_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
        lthash_contrib_files = std.AutoHashMap(u64, std.fs.File).init(std.heap.page_allocator);
        files_initialized = true;
    }
    enabled.store(true, .monotonic);
}

fn testReset() void {
    if (enabled.swap(false, .monotonic)) {
        files_mutex.lock();
        defer files_mutex.unlock();
        if (files_initialized) {
            var rit = read_files.iterator();
            while (rit.next()) |e| e.value_ptr.close();
            read_files.deinit();
            var wit = write_files.iterator();
            while (wit.next()) |e| e.value_ptr.close();
            write_files.deinit();
            var mit = meta_files.iterator();
            while (mit.next()) |e| e.value_ptr.close();
            meta_files.deinit();
            var vmit = vote_mismatch_files.iterator();
            while (vmit.next()) |e| e.value_ptr.close();
            vote_mismatch_files.deinit();
            var deit = dead_event_files.iterator();
            while (deit.next()) |e| e.value_ptr.close();
            dead_event_files.deinit();
            var txit = tx_result_files.iterator();
            while (txit.next()) |e| e.value_ptr.close();
            tx_result_files.deinit();
            var ltit = lthash_contrib_files.iterator();
            while (ltit.next()) |e| e.value_ptr.close();
            lthash_contrib_files.deinit();
            files_initialized = false;
        }
    }
    first_slot_seen.store(0, .monotonic);
    current_slot = 0;
    read_gate = false;
    write_gate = false;
}

test "emitRead writes well-formed JSON lines per slot" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buf: [256]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &dir_path_buf);
    try testForceEnable(dir_path, true, false);
    defer testReset();

    const pk_a: [32]u8 = [_]u8{0xAA} ** 32;
    const pk_b: [32]u8 = [_]u8{0xBB} ** 32;
    const data1 = "hello-world-from-account-data";
    const data2 = "second-pubkey-bytes-here";

    current_slot = 100;
    const sigov_slots = [_]u64{ 95, 99 };
    emitRead(&pk_a, .unflushed_cache, 5000, data1, data1.len, 99, null, null, sigov_slots[0..]);
    emitRead(&pk_b, .sig_overlay, 10000, data2, data2.len, null, 95, 100, null);

    current_slot = 101;
    emitRead(&pk_a, .miss, null, null, null, 99, null, null, null);

    var path_buf: [320]u8 = undefined;
    const path_100 = try std.fmt.bufPrint(&path_buf, "{s}/slot-100.reads.jsonl", .{dir_path});
    const data_100 = try std.fs.cwd().readFileAlloc(testing.allocator, path_100, 1 << 20);
    defer testing.allocator.free(data_100);

    var line_count: usize = 0;
    var it = std.mem.splitScalar(u8, data_100, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try testing.expectEqual(@as(i64, 100), obj.get("slot").?.integer);
        line_count += 1;
    }
    try testing.expectEqual(@as(usize, 2), line_count);

    const path_101 = try std.fmt.bufPrint(&path_buf, "{s}/slot-101.reads.jsonl", .{dir_path});
    const data_101 = try std.fs.cwd().readFileAlloc(testing.allocator, path_101, 1 << 20);
    defer testing.allocator.free(data_101);

    var line_count_101: usize = 0;
    var it2 = std.mem.splitScalar(u8, data_101, '\n');
    while (it2.next()) |line| {
        if (line.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try testing.expectEqual(@as(i64, 101), obj.get("slot").?.integer);
        try testing.expectEqualStrings("miss", obj.get("layer").?.string);
        try testing.expectEqual(@as(i64, 0), obj.get("lam_p").?.integer);
        line_count_101 += 1;
    }
    try testing.expectEqual(@as(usize, 1), line_count_101);
}

test "emitWrite writes well-formed JSON lines per slot" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_path_buf: [256]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &dir_path_buf);
    try testForceEnable(dir_path, false, true);
    defer testReset();

    const pk: [32]u8 = [_]u8{0xDD} ** 32;
    const owner: [32]u8 = [_]u8{0xEE} ** 32;
    const new_data = "new-account-bytes-here";
    const prev_data = "previous-bytes-overwritten";

    current_slot = 200;
    emitWrite(&pk, &owner, 12345, new_data, 199, 67890, prev_data);
    emitWrite(&pk, &owner, 22222, "", null, null, null);

    var path_buf: [320]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/slot-200.writes.jsonl", .{dir_path});
    const data = try std.fs.cwd().readFileAlloc(testing.allocator, path, 1 << 20);
    defer testing.allocator.free(data);

    var line_count: usize = 0;
    var it = std.mem.splitScalar(u8, data, '\n');
    var first_obj_lam: i64 = 0;
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try testing.expectEqual(@as(i64, 200), obj.get("slot").?.integer);
        if (line_count == 0) first_obj_lam = obj.get("new_lam").?.integer;
        line_count += 1;
    }
    try testing.expectEqual(@as(usize, 2), line_count);
    try testing.expectEqual(@as(i64, 12345), first_obj_lam);
}

test "current_slot=0 drops events" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path_buf: [256]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &dir_path_buf);
    try testForceEnable(dir_path, true, true);
    defer testReset();

    const pk: [32]u8 = [_]u8{0xCC} ** 32;
    const owner: [32]u8 = [_]u8{0xFF} ** 32;
    current_slot = 0;
    emitRead(&pk, .cache, 7777, "x", 1, null, null, null, null);
    emitWrite(&pk, &owner, 8888, "y", null, null, null);

    var path_buf: [320]u8 = undefined;
    const path_r = try std.fmt.bufPrint(&path_buf, "{s}/slot-0.reads.jsonl", .{dir_path});
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(path_r, .{}));
    const path_w = try std.fmt.bufPrint(&path_buf, "{s}/slot-0.writes.jsonl", .{dir_path});
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(path_w, .{}));
}

test "write gate off blocks emitWrite even when read gate on" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path_buf: [256]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &dir_path_buf);
    try testForceEnable(dir_path, true, false); // reads ON, writes OFF
    defer testReset();

    const pk: [32]u8 = [_]u8{0x11} ** 32;
    const owner: [32]u8 = [_]u8{0x22} ** 32;
    current_slot = 300;
    emitWrite(&pk, &owner, 100, "data", 299, 50, "old");

    var path_buf: [320]u8 = undefined;
    const path_w = try std.fmt.bufPrint(&path_buf, "{s}/slot-300.writes.jsonl", .{dir_path});
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(path_w, .{}));
}
