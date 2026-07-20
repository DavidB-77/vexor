//! Vexor Replay Stage
//!
//! The replay stage is responsible for:
//! - Receiving shreds from TVU
//! - Reconstructing blocks
//! - Replaying transactions to build bank state
//! - Voting on completed slots
//! - Producing blocks when we're the leader
//!
//! Migrated from Vexor 0.14.1 → vex-fd Zig 0.15.2.
//! Changes applied:
//!   - std.ArrayList → std.ArrayListUnmanaged with per-call allocator
//!   - dropped_banks: ArrayList → ArrayListUnmanaged
//!   - batch / local_writes: ArrayList → ArrayListUnmanaged
//!   - toOwnedSlice() → toOwnedSlice(allocator)
//! Module remaps:
//!   - core → @import("core")
//!   - vex_svm bank → @import("bank.zig")
//!   - storage/network/consensus stubs kept with TODO markers

const std = @import("std");
const core = @import("core");
const vex_store = @import("vex_store");
const vex_ledger_mod = @import("vex_ledger"); // P5#1 flight-recorder freeze-tap (VEX_LEDGER_FLIGHT; comptime build_options.vex_ledger). std-only; type only when flag off.
const bank_mod = @import("bank.zig");
const types = @import("types.zig");
const pending_wake = @import("pending_wake.zig"); // orphan-repair (2026-05-30): pure WAKE-decision predicate extracted from checkPendingChain
const pending_chain_gc = @import("pending_chain_gc.zig"); // pure GC-DROP predicate (FIX #2 revert recoverability invariant, KAT-tested)
const orphan_target = @import("orphan_target.zig"); // orphan-repair (2026-05-30): pure orphan-root selection for the Orphan(10) trigger
const chain_wake_fallback = @import("chain_wake_fallback.zig"); // fix/chain-defer-tip-guard: pure CHAIN-WAKE fallback decision (self-heal an evicted continuation)
const verify_ticks_mod = @import("verify_ticks.zig"); // @prov:replay.tick-verify — canonical block tick-validity; pure + KAT-shared
const wave_pool_mod = @import("wave_pool.zig"); // Stage B (parallel-exec) B2c: persistent worker pool for wave-barrier parallel execution
const vex_crypto = @import("vex_crypto");
const build_options = @import("build_options");
const vex_topo = @import("vex_topo"); // Phase 9: declarative tile→core topology table

// Native program execution
const vote_program = @import("native/vote_program.zig");
const vote_state_serde = @import("native/vote_state_serde.zig");
const stake_state = @import("native/stake_state.zig");
const stake_program = @import("native/stake_program.zig");
const bpf_loader_program = @import("native/bpf_loader_program.zig");
const system_v2 = @import("native/system_v2.zig");
const address_lookup_table = @import("native/address_lookup_table.zig");
const compute_budget = @import("compute_budget"); // task #13: dedicated shared module (build.zig)
const banking_stage_mod = @import("banking_stage"); // task #13: dedicated shared module (build.zig)
const tx_ingest_mod = @import("tx_ingest"); // SB-2 (2026-06-17): shared TPU wire parser, for RPC-store tx capture
const produce_ring_mod = @import("produce_ring.zig"); // 2026-06-16: block-production tile isolation rings
const bpf_mod = @import("vex_bpf");
// Wave 4: runtime dispatch flag + V2 umbrella. V2 is dormant by default;
// `--bpf-stack=v2|shadow` engages the new path, gated on selfTest.smoke.
const vex_bpf2 = @import("vex_bpf2");
const v2dispatch = @import("v2_dispatch.zig"); // Wave 5: V2 dispatch + diff
const executor_mod = @import("executor.zig"); // carrier 419957920: transactionCheck (rent-state + balance)
const runtime_mod = @import("runtime.zig"); // carrier 419957920: INCINERATOR_ID for the rent-check skip
// FIX #105: root_partition.zig moved to vex_store/ so AccountsDb owns the durable
// parent map + computeRootPartition; replay_stage now calls db.computeRootPartition.
const shadow_capture = @import("shadow_capture.zig"); // Phase 4: live fixture capture
const bank_sysvar_adapter = @import("bank_sysvar_adapter.zig"); // Wave 6 final: Bank → SysvarCache populate
const bank_prune = @import("bank_prune.zig"); // F3 (C8d backport): clamp pruneOldBanks against current frame's bank
const elf_version = @import("elf_version.zig"); // F8i: per-ELF sBPF version sniff for V3 routing
const v2_pc_mod = vex_bpf2.v2_program_cache; // Wave 6 final: V2 program cache

// Precompile verification (runs before instruction execution)
const precompiles_mod = @import("native/precompiles.zig");
const features_mod = @import("features.zig");
const feature_watch = @import("feature_watch.zig");
const instructions_sysvar_mod = @import("native/instructions_sysvar.zig");

// Sysvar owner pubkey (`Sysvar1111111111111111111111111111111111111`).
// Bytes from base58 decode (verified). Pre-`instructions_sysvar_owned_by_sysvar`
// feature gate, the instructions sysvar's owner was the System program; on
// the testnet snapshot at slot 406443197 that feature is active so the owner
// is the Sysvar program. Used as the .owner field for the synthesized
// Sysvar1nstructions blob.
pub const SYSVAR_OWNER_FOR_INSTRUCTIONS: [32]u8 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0x75, 0xf7, 0x29,
    0xc7, 0x3d, 0x93, 0x40, 0x8f, 0x21, 0x61, 0x20,
    0x06, 0x7e, 0xd8, 0x8c, 0x76, 0xe0, 0x8c, 0x28,
    0x7f, 0xc1, 0x94, 0x60, 0x00, 0x00, 0x00, 0x00,
};

/// Convert the executing tx's instruction list into the per-tx
/// Sysvar1Instructions blob. Sets the trailing `current_instruction_index`
/// to `current_ix_idx`. Caller frees with the same allocator.
pub fn buildInstructionsSysvarBlob(
    alloc: std.mem.Allocator,
    ptx: *const ParsedTx,
    current_ix_idx: u16,
) ![]u8 {
    // Build per-IX inputs; allocate a small per-IX accounts array on the same
    // arena allocator so everything is freed together at end of dispatch.
    const ix_inputs = try alloc.alloc(instructions_sysvar_mod.InstructionInput, ptx.num_instructions);
    defer alloc.free(ix_inputs);

    // Track each per-ix accounts slice; freed via arena cleanup.
    for (ptx.instructions[0..ptx.num_instructions], 0..) |pi, i| {
        const accs = try alloc.alloc(instructions_sysvar_mod.AccountFlag, pi.account_indices.len);
        for (pi.account_indices, 0..) |aidx, j| {
            const idx_u16: u16 = @intCast(aidx);
            const is_signer = idx_u16 < ptx.num_required_sigs;
            const is_writable = ptx.isWritable(idx_u16);
            accs[j] = .{
                .pubkey = &ptx.account_keys[aidx],
                .is_signer = is_signer,
                .is_writable = is_writable,
            };
        }
        ix_inputs[i] = .{
            .program_id = &ptx.account_keys[pi.program_id_index],
            .accounts = accs,
            .data = pi.data,
        };
    }

    const blob = try instructions_sysvar_mod.constructInstructionsData(alloc, ix_inputs);
    instructions_sysvar_mod.storeCurrentIndex(blob, current_ix_idx);
    return blob;
}

// @prov:replay.dag-dispatch — DAG transaction dispatcher
const tx_dispatcher_mod = @import("tx_dispatcher.zig");

const Bank = bank_mod.Bank;

// ── Re-used types ─────────────────────────────────────────────────────────────

pub const Slot = core.Slot;
pub const Pubkey = core.Pubkey;
pub const Hash = @import("types.zig").Hash;

// Part 4b root-guards — pure decision predicate lives in a small, independently
// testable leaf (src/vex_svm/root_guards.zig). doRootAdvance collects the inputs
// via `rootGuardInputs` and dispatches on `evalRootGuards`.
const root_guards = @import("root_guards.zig");
const RootGuardInputs = root_guards.RootGuardInputs;
const evalRootGuards = root_guards.evalRootGuards;

// Switch-proof Part 2, M1 — [REVIVE-WOULD-FIRE] detection tap + the offline
// SlotHashes-injection parser, pure logic lives in a small, independently
// testable leaf (src/vex_svm/revive_detect.zig), same pattern as root_guards.zig
// immediately above (replay_stage.zig's own inline `test` blocks never run under
// any build target — see that file's header + build.zig's test-root-guards step
// comment). sweepPendingTickGateSlots / fetchSlotHashesRemote below are thin
// callers into this leaf's pure functions.
const revive_detect = @import("revive_detect.zig");
// Switch-proof Part 2, M2 — Shape-A dead-slot revive DECISION core (pure leaf,
// unit-KAT'd via `zig build test-revive-repair`). Same extract-the-decision
// pattern as revive_detect.zig / root_guards.zig: this file's sweep-path caller
// does ALL mutation (banks.remove, dead_slots.remove, clearCompletedSlot, the
// requestHighestWindowIndex kick); revive_repair.zig only decides WHAT to do.
const revive_repair = @import("revive_repair.zig");

// Tx-bearing block production, Milestone 3 — auto-safe-off tripwire pure
// predicate + tracked-state bundle, same extraction discipline as
// revive_detect.zig immediately above (own file, unit-KAT'd via
// `zig build test-txbearing-tripwire`). See that file's header for the full
// signal-choice / threshold / latch reasoning.
const txbearing_tripwire = @import("txbearing_tripwire.zig");

// ── CPU pinning helper ───────────────────────────────────────────────────────

fn pinToCore(core_id: u32) void {
    var cpu_set = [_]usize{0} ** 16;
    const idx = core_id / @bitSizeOf(usize);
    const bit: u6 = @intCast(core_id % @bitSizeOf(usize));
    cpu_set[idx] = @as(usize, 1) << bit;
    _ = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
    std.log.debug("[PIN] Thread pinned to core {d}\n", .{core_id});
}

// ── vex-048b: parallel SVM worker affinity state ────────────────────────────
//
// Each pool thread self-pins to one of cores 20-23 on its first task.
// threadlocal guards the pin so subsequent tasks on the same thread are no-ops.
// `next_svm_core` distributes cores monotonically; modulo wraps if n_jobs > 4.
threadlocal var pinned_core: ?u32 = null;

/// d22c (2026-05-11): catchup-RPC parent_slot override. When non-null, signals
/// to getOrCreateBank that target_parent comes from the AUTHORITATIVE RPC
/// `getBlock.parentSlot` field (which correctly reflects skipped slots), not
/// from the inferred slot-1 default. catchUpReplay sets this before each
/// onSlotCompleted call and clears it after. TVU path (replayWorker thread)
/// never touches this — they have shred wire-format parent which is also
/// authoritative. @prov:replay.parent-slot-source
pub threadlocal var catchup_parent_override: ?u64 = null;
/// d27hh (2026-05-11): per-BlockComponent boundary offsets in the current
/// slot's assembled data buffer. Set by replayWorker for the duration of
/// one onSlotCompleted call, cleared on return. When non-empty, replayBlock
/// uses these to jump from the end of one component (which may be padded
/// with zeros inside its last shred) to the start of the next, instead of
/// the byte-by-byte scan-forward heuristic. @prov:replay.completed-data-ranges
pub threadlocal var component_boundaries_override: []const usize = &.{};

/// Phase G-2 (2026-05-17): cluster's curl-cached SlotHashes published from
/// ReplayStage.fetchSlotHashes for use by free-function callers (e.g.
/// executeVoteInstruction) that don't have `self` access. Used as a FALLBACK
/// in vote validation: if our local SlotHashes doesn't contain the proposed
/// (slot, hash), check cluster's; only reject if BOTH miss. Closes the
/// vote-state SlotHashMismatch carrier (Phase F counter was 99.83%) without
/// Phase G's bug (Phase G replaced our SlotHashes ENTIRELY with cluster's,
/// which broke catchup because cluster's 512-slot window doesn't cover old
/// slots).
var g_cluster_slot_hashes: ?[]const u8 = null;
var g_cluster_slot_hashes_lock: std.Thread.Mutex = .{};

/// Snapshot the cluster SlotHashes pointer for fallback validation. Caller
/// must NOT free the returned slice. The underlying buffer is owned by
/// ReplayStage and may be reallocated on the next fetchSlotHashes refresh —
/// callers should only use the snapshot within a single vote check.
pub fn clusterSlotHashesSnapshot() ?[]const u8 {
    g_cluster_slot_hashes_lock.lock();
    defer g_cluster_slot_hashes_lock.unlock();
    return g_cluster_slot_hashes;
}

var next_svm_core: std.atomic.Value(u32) = std.atomic.Value(u32).init(20);
const SVM_CORES_FIRST: u32 = 20;

/// One-shot arm for the VEX_DUMP_ENTRY staging KAT capture (replayEntries). True until the first
/// tx-bearing slot's entry buffer is written to /tmp/vex_entry_<slot>.bin, then flipped off.
var entry_dump_armed: std.atomic.Value(bool) = std.atomic.Value(bool).init(true);
const SVM_CORES_COUNT: u32 = 4;

// ── vex-048b: WorkerCtx — per-color-group parallel SVM worker context ───────
//
// One WorkerCtx is allocated per color group dispatched through svm_pool.
// The executor functions (executeSystemInstruction / executeVoteInstruction /
// executeStakeInstruction / executeBpfProgram) each write to bank.pending_writes
// directly on the current HEAD; vex-048c must redirect those writes into
// ctx.writes before concurrent dispatch is safe. ctx.writes is scaffolded here
// for structural parity with 3a2165a (commit SHA that introduced the pattern)
// but is never populated by vex-048b. FLAG: concurrent bank.pending_writes
// access would be a data race — vex-048c MUST add the writes-redirect before
// wiring this path into replayEntriesInternal.
pub const WorkerCtx = struct {
    bank: *Bank,
    db: *AccountsDb,
    ptxs: []const ParsedTx,
    tx_indices: []const u16,
    alloc: std.mem.Allocator,
    writes: std.ArrayListUnmanaged(bank_mod.AccountWrite) = .{},
    wg: *std.Thread.WaitGroup,
    // Classification counters (accumulated by parallelWorkerFn)
    sys: u64 = 0,
    vote: u64 = 0,
    stake: u64 = 0,
    compute: u64 = 0,
    bpf: u64 = 0,
    // Test-only: if non-null, parallelWorkerFn writes pinned_core here after pin.
    // Production callers leave this null.
    pinned_core_out: ?*std.atomic.Value(u32) = null,
    // Test-only barrier: if non-null, tasks increment after pinning and spin until
    // all n_jobs tasks have pinned, guaranteeing distinct cores in the test.
    start_barrier: ?*std.atomic.Value(u32) = null,
    start_barrier_n: u32 = 4,
    // live feature_set pointer (null-safe: vote executor tolerates null)
    feature_set: ?*const features_mod.FeatureSet = null,
};

// ── vex-048b: parallelWorkerFn ───────────────────────────────────────────────
//
// Task body executed by std.Thread.Pool workers. Consumes ctx.tx_indices, routes
// each transaction's instructions through the native-program classifier, and
// bumps the matching per-ctx counter (sys/vote/stake/compute/bpf).
//
// SELF-PINNING: On the first task a given pool thread picks up, claims the next
// core from next_svm_core (mod SVM_CORES_COUNT) and pins self via pinToCore().
// Subsequent tasks on the same thread are no-ops (threadlocal pinned_core set).
//
// WRITES NOTE (vex-048c): executors now route AccountWrite appends through
// `Bank.collectWrite`, which consults `bank_mod.worker_writes_override`. This
// worker sets that threadlocal to `&ctx.writes` before dispatching executors
// and clears it after. With enable_parallel_svm=false the worker is not
// invoked at all (serial path unchanged). Concurrent dispatch + ordered
// barrier-merge of ctx.writes back into bank.pending_writes is vex-048d scope.
pub fn parallelWorkerFn(ctx: *WorkerCtx) void {
    defer ctx.wg.finish();

    // --- Self-pin: first task per pool thread claims a core 20-23 ---
    if (pinned_core == null) {
        const raw = next_svm_core.fetchAdd(1, .monotonic);
        const offset_from_first = (raw -% SVM_CORES_FIRST) % SVM_CORES_COUNT;
        const core_id = SVM_CORES_FIRST + offset_from_first;
        pinToCore(core_id);
        pinned_core = core_id;
        std.log.debug("[VEX-048B-PIN] pool thread self-pinned to core {d}\n", .{core_id});
    }

    // Write back pinned core for test verification
    if (ctx.pinned_core_out) |out| {
        out.store(pinned_core.?, .release);
    }

    // Test barrier: wait until all tasks have self-pinned before any returns.
    // Guarantees each task ran on a distinct pool thread, so pin assertions hold.
    if (ctx.start_barrier) |barrier| {
        _ = barrier.fetchAdd(1, .acq_rel);
        const deadline_ns = std.time.nanoTimestamp() + 5_000_000_000; // 5 second timeout
        while (barrier.load(.acquire) < ctx.start_barrier_n) {
            if (std.time.nanoTimestamp() > deadline_ns) break; // safety escape
            std.atomic.spinLoopHint();
        }
    }

    // --- vex-048c: redirect Bank.collectWrite() into ctx.writes ---
    // Threadlocal set here, cleared on exit. Nested calls from executors that
    // re-enter collectWrite will observe this override and land in ctx.writes
    // instead of bank.pending_writes.
    const prior_override = bank_mod.worker_writes_override;
    bank_mod.worker_writes_override = &ctx.writes;
    defer bank_mod.worker_writes_override = prior_override;

    // --- Classify + dispatch each transaction index ---
    for (ctx.tx_indices) |tx_idx| {
        if (tx_idx >= ctx.ptxs.len) continue;
        const ptx = &ctx.ptxs[tx_idx];

        for (ptx.instructions[0..ptx.num_instructions]) |ix| {
            if (ix.program_id_index >= ptx.static_key_count) continue;
            const program_id = &ptx.account_keys[ix.program_id_index];

            if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.SYSTEM)) {
                ctx.sys += 1;
                // Day-2: parallel worker path is dead code (svm_pool removed). Pass
                // empty ancestor_slots = legacy flat-read behavior. If this path
                // is revived, populate WorkerCtx.ancestor_slots from the bank.
                executeSystemInstruction(ix, ptx, ctx.bank, ctx.db, ctx.alloc, &[_]u64{}) catch {};
            } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.VOTE)) {
                ctx.vote += 1;
                if (bank_mod.TvTrace.on()) _ = ctx.bank.tvt2_site_worker.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
                // Day-2: dead-code parallel worker path. Pass empty ancestor_slots
                // (feature_set arg was stale anyway — was never in fn signature).
                executeVoteInstruction(ix, ptx, ctx.bank, ctx.db, ctx.alloc, &[_]u64{}) catch {};
            } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.STAKE)) {
                ctx.stake += 1;
                // Phase-1: dead worker path (svm_pool removed) — no live
                // FeatureSet here; pass null → native path (byte-identical).
                executeStakeInstruction(ix, ptx, ctx.bank, ctx.db, ctx.alloc, @as(?*const features_mod.FeatureSet, null)) catch {};
            } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.COMPUTE_BUDGET)) {
                ctx.compute += 1;
            } else if (std.mem.eql(u8, program_id, &BPF_LOADER_UPGRADEABLE)) {
                // BPFLoaderUpgradeable is a NATIVE program (no ELF body): it
                // must run our handler, not the BPF-ELF executor. See
                // native/bpf_loader_program.zig for the lt_hash-carrier root.
                ctx.bpf += 1;
                // Day-2 dead worker path (svm_pool removed); no live FeatureSet
                // available here → pass null (Phase-2 arms treat SIMD-0431 as
                // inactive, which this dead path never exercises anyway).
                bpf_loader_program.execute(ix, ptx, ctx.bank, ctx.db, ctx.alloc, @as(?*const features_mod.FeatureSet, null)) catch {};
            } else {
                ctx.bpf += 1;
                executeBpfProgram(ix, ptx, ctx.bank, ctx.db, ctx.alloc) catch {};
            }
        }
    }
}

/// vex-048c: orderly barrier-merge of per-worker ctx.writes into
/// bank.pending_writes. Call this on the orchestrator thread AFTER the
/// dispatch barrier (`pool.waitAndWork`) returns, NEVER while workers may
/// still be appending. Writes are merged in the order the workers appear in
/// `ctxs`; concurrent dispatch ordering guarantees are vex-048d scope.
///
/// Uses `bank.allocator` for storage so the merged entries retain the same
/// ownership contract as direct `self.pending_writes.append(self.allocator, …)`
/// (per vault/bugs/pending-writes-lifetime.md: AccountWrite.data slices are
/// allocated with bank.allocator inside executors and must outlive the frame
/// they're merged into).
pub fn mergeWorkerWrites(bank: *Bank, ctxs: []const *WorkerCtx) !void {
    for (ctxs) |c| {
        if (c.writes.items.len == 0) continue;
        try bank.pending_writes.appendSlice(bank.allocator, c.writes.items);
        c.writes.clearRetainingCapacity();
    }
}

/// Vote sender worker thread. Drains VoteSendQueue and sends via sendVoteFn.
/// Runs on a dedicated OPS-LANE core to isolate network I/O from replay.
///
/// throughput-fix (2026-06-11): was pinToCore(17) — but core 17 is INSIDE the
/// replay tiling range (validator owns 4-27; ops lane is 28-31). The blocking
/// curl/TLS in sendViaRpc (every 5th vote) spiked core 17 to ~80%, contending
/// with replay work and showing up as one of the 3 "hot" cores in mpstat. The
/// comment's stated intent ("isolate network I/O from replay") was not actually
/// met. Pin to ops-lane core 28 so the worker AND the curl child it forks
/// (which inherits this thread's affinity) run entirely off the replay cores.
/// vex-fd-pin.sh leaves this thread alone (its lifetime-avg CPU is below the
/// 25% repin threshold), so the ops-lane pin sticks.
pub fn voteSenderWorker(
    queue: *VoteSendQueue,
    sendFn: *const fn ([]const u8) void,
    shutdown: *std.atomic.Value(bool),
) void {
    // Phase 9: default = vex_topo table (.txsend == core 28, byte-identical);
    // VEX_LEGACY_PINS / -Dlegacy_pins reverts to the inline pinToCore(28).
    if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) {
        pinToCore(28);
    } else {
        _ = vex_topo.pinTile(vex_topo.LIVE, .txsend, 0);
    }
    std.log.debug("[VOTE-SENDER] Worker started on ops-lane core 28\n", .{});

    var sent: u64 = 0;
    while (!shutdown.load(.acquire)) {
        if (queue.pop()) |data| {
            sendFn(data);
            sent += 1;
            queue.allocator.free(data);

            if (sent <= 3 or sent % 200 == 0) {
                std.log.debug("[VOTE-SENDER] Sent #{d}\n", .{sent});
            }
        } else {
            // No votes pending -- sleep 10ms (votes arrive ~every 400ms)
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    // Drain remaining on shutdown
    while (queue.pop()) |data| {
        sendFn(data);
        queue.allocator.free(data);
        sent += 1;
    }

    std.log.debug("[VOTE-SENDER] Worker stopped after {d} votes\n", .{sent});
}

/// Replay stage statistics (thread-safe)
pub const ReplayStats = struct {
    shreds_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    invalid_shreds: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    slots_replayed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    successful_txs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    failed_txs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    votes_sent: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    blocks_produced: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// 2026-05-28 FIX #77 — slot_queue push-fail counter. Incremented when
    /// the MPSC SlotQueue is full and a producer (TVU rx, CHAIN-WAKE, catchup,
    /// etc.) drops the slot instead of spinning. @prov:replay.slot-queue-drop-policy
    /// Sustained drops > ~10/sec indicate the consumer (replayWorker) is
    /// throughput-starved relative to producer (cluster shred-rate ~150
    /// slots/sec); short bursts are normal.
    slot_queue_drops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // @prov:replay.tps-window-metrics — rolling-window TPS (60-slot ring buffer)
    window_txns: [60]u64 = [_]u64{0} ** 60,
    window_ns: [60]u64 = [_]u64{0} ** 60,
    window_head: usize = 0,
    window_filled: usize = 0,

    lifetime_start_ns: u64 = 0,
    last_report_slot: u64 = 0,

    pub const WINDOW_SLOTS: usize = 60;

    pub fn inc(stat: *std.atomic.Value(u64)) void {
        _ = stat.fetchAdd(1, .seq_cst);
    }

    pub fn get(stat: *const std.atomic.Value(u64)) u64 {
        return stat.load(.seq_cst);
    }

    /// Record one slot's worth of transactions and elapsed nanoseconds.
    pub fn recordSlot(self: *@This(), slot: u64, tx_count: u64, elapsed_ns: u64) void {
        const idx = self.window_head % WINDOW_SLOTS;
        self.window_txns[idx] = tx_count;
        self.window_ns[idx] = elapsed_ns;
        self.window_head += 1;
        if (self.window_filled < WINDOW_SLOTS) self.window_filled += 1;

        if (self.window_head % WINDOW_SLOTS == 0) {
            self.logTps(slot);
        }
    }

    pub fn logTps(self: *const @This(), current_slot: u64) void {
        var total_txns: u64 = 0;
        var total_ns: u64 = 0;
        const samples = self.window_filled;
        if (samples == 0) return;

        for (0..samples) |i| total_txns += self.window_txns[i];
        for (0..samples) |i| total_ns += self.window_ns[i];

        const replay_tps: u64 = if (total_ns > 0)
            (total_txns * 1_000_000_000) / total_ns
        else
            0;

        const avg_txns_per_slot = total_txns / samples;
        const network_tps_est = avg_txns_per_slot * 10 / 4;

        const lifetime_txns = get(&self.successful_txs) + get(&self.failed_txs);
        const lifetime_slots = get(&self.slots_replayed);

        std.log.info(
            "[METRICS] slot={d} | " ++
                "replay_TPS={d} tx/s (last {d} slots, {d} txns) | " ++
                "net_est={d} tx/s | " ++
                "lifetime: {d} txns across {d} slots | " ++
                "votes={d} blocks={d} bad_shreds={d} | " ++
                "slot_queue_drops={d} (FIX #77)",
            .{
                current_slot,
                replay_tps,
                samples,
                total_txns,
                network_tps_est,
                lifetime_txns,
                lifetime_slots,
                get(&self.votes_sent),
                get(&self.blocks_produced),
                get(&self.invalid_shreds),
                get(&self.slot_queue_drops),
            },
        );
    }
};

/// SVM parallel execution statistics
pub const SvmStats = struct {
    total_batches: u64 = 0,
    total_txs_scheduled: u64 = 0,
    total_groups: u64 = 0,
    parallel_batches: u64 = 0,
    serial_fallbacks: u64 = 0,
};

/// Lock-free SPSC queue for serialized vote transaction bytes.
/// Producer: replay thread. Consumer: vote sender thread.
pub const VoteSendQueue = struct {
    // throughput-fix (2026-06-11): 64→256. During a catch-up vote burst the
    // worker can momentarily lag (one RPC curl per 5 sends blocks ~200-500ms);
    // a deeper ring keeps votes flowing through the off-replay worker instead of
    // overflowing into the inline fallback path (submitVote:3499), which would
    // otherwise spawn the blocking curl ON the replay thread and stall replay.
    const CAPACITY = 256;

    buf: [CAPACITY]?[]u8 = [_]?[]u8{null} ** CAPACITY,
    head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // write position (producer)
    tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // read position (consumer)
    allocator: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) VoteSendQueue {
        return .{ .allocator = alloc };
    }

    /// Push serialized tx bytes. Returns true if enqueued, false if full.
    /// Transfers ownership: caller must NOT free the bytes after a successful push.
    pub fn push(self: *VoteSendQueue, data: []u8) bool {
        const h = self.head.load(.acquire);
        const t = self.tail.load(.acquire);
        if (h -% t >= CAPACITY) return false; // full
        self.buf[h % CAPACITY] = data;
        self.head.store(h +% 1, .release);
        return true;
    }

    /// Pop serialized tx bytes. Returns null if empty.
    /// Caller owns the returned slice and MUST free it with self.allocator.
    pub fn pop(self: *VoteSendQueue) ?[]u8 {
        const t = self.tail.load(.acquire);
        const h = self.head.load(.acquire);
        if (t == h) return null; // empty
        const data = self.buf[t % CAPACITY];
        self.buf[t % CAPACITY] = null;
        self.tail.store(t +% 1, .release);
        return data;
    }
};

/// Slot status
pub const SlotStatus = enum {
    processing,
    complete,
    confirmed,
    finalized,
    skipped,
};

/// Bootstrap result produced after full startup sequence.
pub const BootstrapResult = struct {
    root_bank: *Bank,
    start_slot: Slot,
    accounts_loaded: u64,
    total_lamports: u64,
};

/// Minimal replay stage for vex-fd.
///
/// This is the ported Vexor replay pipeline. It maintains the slot→Bank map,
/// the SPSC replay queue, and the parallel SVM execution engine.
///
/// TODO (when storage/network modules are wired):
///   - Wire accounts_db and ledger_db via vex_store module
///   - Wire consensus_engine via vex_consensus module
///   - Wire leader_cache and TPU/TVU clients via vex_network module
///   - Replace shadow_db stub with full ShadowAccountDb
/// PR-5z (2026-05-19) — entry tracking a SHADOW-detected chained_block_id
/// mismatch awaiting deferred cluster oracle confirmation.
pub const ShadowEntry = struct {
    slot: u64,
    parent_slot: u64,
    flagged_at_ms: i64,
};

/// PR-5ae (2026-05-19) — entry tracking a TICK-GATE-SHADOW (d28dd) fire.
/// Slot had `tick_count_seen < EXPECTED_TICKS_PER_SLOT` at completion. We
/// don't mark dead immediately (cluster's SH cache may be stale at-tip).
/// `sweepPendingTickGateSlots` re-checks `getNetworkBankHash(slot) != null`
/// on each fetchSlotHashes refresh; positive → markSlotDead retroactively;
/// 30s timeout → drop as canonical (current SHADOW-only behavior).
pub const TickGateEntry = struct {
    slot: u64,
    ticks_seen: u64,
    flagged_at_ms: i64,
};

/// PR-5ai (2026-05-20) — entry tracking a FEC-GATE-SHADOW (d27mm) fire.
/// Sibling of TickGateEntry / Carrier K. Slot was frozen with an incomplete
/// final FEC set (32-byte chained_merkle_root not derivable). Cluster's SH
/// may confirm the slot as canonical later → retroactive markSlotDead +
/// purge_unrooted via sweepPendingFecGateSlots, mirroring PR-5ae.
pub const FecGateEntry = struct {
    slot: u64,
    reason_tag: []const u8, // @tagName(r) — static enum-name slice, no alloc
    flagged_at_ms: i64,
};

// ── VOTE-COVERAGE CENSUS (permanent telemetry; logged only under VEX_PROP_DIAG) ──
// Hoisted to file scope (2026-07-10, metrics-reporter task) from a submitVote-local
// declaration so a read-only accessor (getVoteCensusSnapshot below) can reach it from
// outside the method. Same atomics, same increment call-sites (submitVote), same single
// static instance either way — Zig container-level `var` storage is not re-created per
// call regardless of lexical nesting, so this is a pure visibility change, zero behavior
// delta for the existing counters. See submitVote for the field semantics.
pub const VoteCensus = struct {
    var eligible: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
    var cast: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
    var fallback_decided: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
    var fallback_cast: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
    var silent_withhold: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
};

/// Point-in-time snapshot of the vote-coverage census counters (5 independent
/// .monotonic loads — NOT atomically consistent as a group, matches every other
/// metrics-reporter sample in this codebase). Read-only; never mutates. Safe to
/// call from any thread at any cadence — no locks, no hot-path cost (the counters
/// are already incremented on the replay path regardless of whether anyone reads
/// them; this just exposes them).
pub fn getVoteCensusSnapshot() struct {
    eligible: u64,
    cast: u64,
    fallback_decided: u64,
    fallback_cast: u64,
    silent_withhold: u64,
} {
    return .{
        .eligible = VoteCensus.eligible.load(.monotonic),
        .cast = VoteCensus.cast.load(.monotonic),
        .fallback_decided = VoteCensus.fallback_decided.load(.monotonic),
        .fallback_cast = VoteCensus.fallback_cast.load(.monotonic),
        .silent_withhold = VoteCensus.silent_withhold.load(.monotonic),
    };
}

pub const ReplayStage = struct {
    allocator: std.mem.Allocator,

    /// Our identity pubkey
    identity: Pubkey,

    /// Active banks by slot (protected by banks_lock)
    banks: std.AutoHashMap(Slot, *Bank),
    /// Banks dropped from `banks` map — deferred destruction to avoid lifetime races.
    /// Zig 0.15.2: ArrayListUnmanaged (no embedded allocator)
    dropped_banks: std.ArrayListUnmanaged(*Bank),
    /// d27f (2026-05-11): freelist of recycled banks. replayWorker is the
    /// SOLE producer/consumer per d17 invariant, so no lock needed here.
    /// Each entry was previously returned by releaseBank with its
    /// pending_writes already cleared and stake_reward_partitions freed.
    /// acquireBank pops + resets fields; falls back to Bank.init when empty.
    /// Eliminates ~200ms `allocator.create(Self)` cost observed via
    /// [BANK-INIT-SLOW] (probe d27e, 2026-05-11) — root cause was either
    /// libc malloc/jemalloc pathology under this validator's heap footprint
    /// or a per-call hidden cost we couldn't pin down. Pool sidesteps it.
    bank_pool: std.ArrayListUnmanaged(*Bank),
    /// Guards concurrent access to `banks`.
    banks_lock: std.Thread.RwLock,

    /// PR-5av Phase 1 (2026-05-22): sentinel-node bank maps.
    /// @prov:replay.sentinel-bank-maps Populated starting Phase 2 when
    /// `getOrCreateBank` learns to mint sentinel banks for slots whose
    /// parent isn't yet known. Until then, both maps stay empty — the
    /// field declaration just locks in struct shape so the multi-phase
    /// port can land incrementally.
    ///
    /// `subtrees`: heads of disconnected bank subtrees — i.e. sentinel
    /// banks whose parent_slot is null but a chain_confirmed/block_id
    /// is available from cluster tower confirmation.
    /// `orphaned`: descendants of a sentinel head — banks that chain to
    /// a subtree but not (yet) back to root.
    /// Lock order (when both held): subtrees BEFORE orphaned; both
    /// AFTER banks_lock if also held.
    subtrees: std.AutoHashMap(Slot, *Bank),
    subtrees_lock: std.Thread.Mutex = .{},
    orphaned: std.AutoHashMap(Slot, *Bank),
    orphaned_lock: std.Thread.Mutex = .{},

    /// Root bank (finalized state) — atomic for lock-free swap.
    root_bank: std.atomic.Value(?*Bank),

    /// AccountsDb reference for loading accounts during tx execution.
    /// Set after bootstrap via setAccountsDb().
    accounts_db: ?*@import("vex_store").accounts.AccountsDb,

    /// P5#1 FLIGHT RECORDER (forensic moat). VexLedger handle for the freeze-tap, set via
    /// setVexLedgerFlight() from main.zig ONLY under -Dvex_ledger + VEX_LEDGER. The tap at the freeze
    /// emit is comptime-gated (build_options.vex_ledger) AND env-gated (flight_record_enabled =
    /// VEX_LEDGER_FLIGHT), so the default build/run is byte-identical + dormant. Journals the bank_hash
    /// INPUT decomposition (parent/poh/sigs/lt_hash) per frozen slot so a future divergence carrier is
    /// diagnosable from the ledger alone. Lock-serialized with the tile writer (VexLedger RwLock);
    /// appendRecord is a buffered write (no fsync) so the tap never stalls the replay thread.
    vex_ledger_flight: ?*vex_ledger_mod.VexLedger = null,
    flight_record_enabled: bool = false,

    /// P5 MOAT #2 (M2): the LIVE divergence-alarm handle. Set via setDivergeAlarm() from
    /// main.zig ONLY under -Dvex_ledger + VEX_DIVERGE_ALARM (which hard-depends on
    /// VEX_LEDGER_FLIGHT). The freeze-tap enqueues {slot, bank_hash} onto the alarm's
    /// non-blocking drop-oldest SPSC ring; a dedicated off-consensus thread drains it, polls
    /// the public-testnet-RPC oracle, and classifies. Comptime-dead unless -Dvex_ledger and
    /// runtime-dormant unless the handle is set → default build/run is byte-identical.
    diverge_alarm: ?*vex_ledger_mod.divergence_alarm_rt.DivergeAlarm = null,
    diverge_alarm_enabled: bool = false,

    /// SB-2 RPC block/transaction-history stores (2026-06-17). Set via setRpcStores() ONLY when the
    /// -Drpc_store comptime flag AND VEX_RPC_STORE env are both on (main.zig). The population call
    /// site is comptime-gated on build_options.rpc_store, so when the flag is OFF these stay null AND
    /// no population codegen exists on the replay path → consensus path byte-identical. OFF-consensus.
    rpc_block_store: ?*@import("vex_store").BlockStore = null,
    rpc_tx_status_store: ?*@import("vex_store").TxStatusStore = null,

    /// Live FeatureSet loaded from AccountsDb at bootstrap — owned by main().
    /// Set via setLiveFeatureSet(); consulted by precompile / runtime gates.
    live_feature_set: ?*features_mod.FeatureSet = null,

    /// Vote submission: identity secret key + vote account pubkey.
    /// Set via setVoteConfig() after bootstrap.
    identity_secret: ?[64]u8,
    vote_account: ?Pubkey,
    /// Block production (leader_mode, all default-null so init is untouched). produce_broadcast_fn
    /// shreds + transmits the produced entry bytes (wired in main.zig — the vex_network side, to avoid
    /// a circular vex_svm↔vex_network module dep). self_produced = slots WE produced → we do NOT
    /// self-vote them (G1: voting an own un-cluster-confirmed slot = tower-lockout wedge; the cluster's
    /// own votes carry consensus on our broadcast block). shred_version_bp = the live shred_version.
    produce_broadcast_ctx: ?*anyopaque = null,
    produce_broadcast_fn: ?*const fn (ctx: *anyopaque, slot: u64, parent_slot: u64, entry_bytes: []const u8, chained_root: [32]u8, secret: [64]u8, shred_version: u16) void = null,
    /// Switch-proof Part 2, M2 — replay→repair kick (the missing reverse link).
    /// replay_stage has NO handle to the TVU repair subsystem: the replay↔tvu link
    /// is one-way (main.zig `tvu_svc.setSlotSink(replay.slotSink())` pushes completed
    /// slots INTO replay; there is no reverse path). The dead-slot revive DUMP's
    /// mandatory follow-on (re-request the slot's shreds so a dumped slot refills)
    /// is therefore wired here as a nullable callback, set in main.zig
    /// (`setRepairKick`) to `TvuService.requestHighestWindowIndex` — same opaque-ctx
    /// circular-dep-avoidance as produce_broadcast_fn. INERT until the
    /// VEX_REVIVE_DEAD_SLOTS-armed dump path invokes it; when unwired (null) the
    /// armed dump path SKIPS the dump entirely (a dump without a kick is strictly
    /// worse than the stall — a dumped slot never refills).
    repair_kick_ctx: ?*anyopaque = null,
    repair_kick_fn: ?*const fn (ctx: *anyopaque, slot: u64, shred_idx: u64) void = null,
    /// Geyser streaming sink (Stage 1a). Opaque ctx + fn-ptr to avoid a vex_svm↔vex_network module
    /// cycle — main.zig wires the typed GeyserService. `status` is the SlotStatus u8 (processed=0,
    /// rooted=2, dead=3). comptime-gated: the call sites (emitGeyserSlot) are dead unless
    /// build_options.geyser, so the default build is byte-identical. Observation-only, NON-consensus.
    geyser_ctx: ?*anyopaque = null,
    geyser_slot_fn: ?*const fn (ctx: *anyopaque, slot: u64, parent: u64, has_parent: bool, status: u8) void = null,
    /// 2026-06-19 (multi-slot leader-window chaining): computes the produced block's last-FEC merkle
    /// root (= next slot's chained_root) WITHOUT transmitting — wired in main.zig to the vex_network
    /// side (block_broadcast.shredsFromEntryBytes), same circular-dep-avoidance as produce_broadcast_fn.
    /// Writes the root into `out` and returns true on success; false (or unwired) ⇒ no stash ⇒ slot N+1
    /// skips, as before. Called REGARDLESS of broadcast so loopback chains too. Non-consensus.
    produce_blockid_fn: ?*const fn (ctx: *anyopaque, entry_bytes: []const u8, slot: u64, parent_slot: u64, chained_root: [32]u8, secret: [64]u8, shred_version: u16, out: *[32]u8) bool = null,
    self_produced: std.AutoHashMapUnmanaged(u64, void) = .{},
    /// Parallel to self_produced: slot → our OWN produced last-FEC merkle root, fed forward as that
    /// slot's bank.block_id at freeze so the next slot of our leader window can chain (see
    /// produce_blockid_fn). Replay-worker-owned only (tile never touches it); fetchRemove'd on consume.
    self_produced_block_id: std.AutoHashMapUnmanaged(u64, [32]u8) = .{},
    /// M3 auto-safe-off tripwire (2026-07-17): parallel to self_produced — the
    /// SUBSET of self-produced slots that actually packed drained txs (as
    /// opposed to an empty tick-only block). Set on the inline path when
    /// `pack_tx_bearing` is decided (replay-thread-owned) and on the tile path
    /// from `SlotDoneRecord.tx_bearing` when Ring B is drained (also
    /// replay-thread-owned — the tile never touches this map, same discipline
    /// as self_produced itself). Consulted (read-only) at freeze completion to
    /// decide whether a frozen self-produced slot is in-scope for the tripwire
    /// counter at all (an empty self-produced slot is neither a failure nor a
    /// clean reset — see txbearing_tripwire.zig).
    self_produced_tx_bearing: std.AutoHashMapUnmanaged(u64, void) = .{},
    /// M3: slots for which the EXISTING [PRODUCE-PARITY-FAIL] self-check
    /// (below, ~:9202) fired at least once during this block's loopback
    /// replay. Populated on the replay thread at the same point that log line
    /// fires (same thread that processes bank.slot's txs); consulted at freeze
    /// completion alongside self_produced_tx_bearing to feed
    /// `txbearing_tripwire.recordSlotOutcome`.
    produce_parity_fail_slots: std.AutoHashMapUnmanaged(u64, void) = .{},
    /// M3 auto-safe-off tripwire state. See txbearing_tripwire.zig for the
    /// full design; `.tripped` is the only cross-thread-read field (the
    /// produce tile consults it via `effectiveArmed`), mirroring the existing
    /// `produce_tile_active` atomic-bool pattern.
    txbearing_tripwire_state: txbearing_tripwire.TripwireState = .{},
    shred_version_bp: u16 = 0,
    /// task #13 LOOPBACK: the TPU mempool (owned by main.zig, outlives replay). When set AND
    /// VEX_TPU_INGEST is on, produceAndBroadcastEmptySlot packs drained txs into the produced block
    /// (produceSlotBytes); else it falls back to the empty (tick-only) path. Default null → no-op.
    banking_stage: ?*banking_stage_mod.BankingStage = null,
    /// 2026-06-16 BLOCK-PRODUCTION TILE ISOLATION. @prov:replay.tile-isolation
    /// When the produce tile is spawned (VEX_TPU_INGEST set, leader_mode on), block production
    /// runs on a dedicated thread pinned to core 20 instead of inline on the replay tile (core 16),
    /// so drain+pack+PoH+shred+broadcast NEVER steal replay cycles (the delinquency cause).
    /// `produce_tile_active` is the RUNTIME gate consulted at the isLeader detection: when true,
    /// replay snapshots build inputs + pushes Ring A + returns; when false (tile not spawned),
    /// replay falls back to the EXISTING inline produceAndBroadcastEmptySlot. All default-null/false
    /// → with -Dleader_mode off this is comptime-pruned and with leader_mode-on-but-tile-not-spawned
    /// the inline path is byte-identical to today.
    produce_ring_a: ?*produce_ring_mod.BecomeLeaderRing = null, // replay→produce (become-leader)
    produce_ring_b: ?*produce_ring_mod.SlotDoneRing = null, // produce→replay (slot-done/loopback)
    produce_tile_active: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// task #26: cross-block AlreadyProcessed recent-signature cache for tx-bearing block production.
    /// Populated (gated) on the replay commit path with every committed tx's signature, queried by the
    /// producer gate. bank-hash-NEUTRAL (pure dedup state). DORMANT unless -Dstatus_cache + VEXOR_STATUS_CACHE.
    recent_sig_cache: @import("block_produce").RecentSigCache = .{},
    /// Lazily-cached VEXOR_STATUS_CACHE env check (avoids a per-tx getenv). null = not yet checked.
    sc_active_cached: ?bool = null,
    /// Function pointer for sending vote transactions (wired from main.zig)
    sendVoteFn: ?*const fn ([]const u8) void,
    /// SPSC queue for offloading vote sends to a dedicated thread.
    /// When set, submitVote() enqueues serialized bytes instead of calling sendVoteFn directly.
    vote_send_queue: ?*VoteSendQueue = null,

    /// Tower BFT state — tracks lockout stack for proper consensus voting.
    tower: ?@import("vex_consensus").tower.TowerBft,

    /// Cached recent blockhash from RPC for vote transaction envelopes.
    /// Refreshed every ~10 seconds. Network accepts blockhashes from last ~150 slots (~60s).
    cached_blockhash: ?Hash = null,
    cached_blockhash_time: i64 = 0,

    /// VOTE-REFRESH (#87 / vote-transport, 2026-06-26). @prov:replay.vote-refresh-parity
    /// When submitVote does NOT cast a new vote (locked out / lag / shouldVote-false), re-broadcast
    /// the LAST cast vote with a fresh blockhash so it keeps landing through short no-cast windows
    /// (the cross-fork-lockout keep-alive + the tx-blockhash-aging gap). Env-gated VEX_VOTE_REFRESH,
    /// dormant unless set. SLASHING-SAFE: refresh re-sends &t.vote_state UNCHANGED — never recordVote,
    /// never adds a slot (only bumps timestamp). last_voted_bank_hash MUST be
    /// the hash actually EMITTED at the cast site (net_hash when used, else bank.bank_hash) — re-sending
    /// a different bank_hash field = a different vote.
    last_voted_bank_hash: ?core.Hash = null, // the vote_hash actually emitted on the cast path
    last_refresh_time_ms: i64 = 0, // wall-ms of last refresh send (5s MAX_VOTE_REFRESH_INTERVAL gate)
    last_refresh_tx_blockhash: ?Hash = null, // suppress identical re-send until blockhash rotates
    last_cast_time_ms: i64 = 0, // wall-ms of last NEW vote cast — Tier-2 fires refresh only after a
    //                              genuine >5s no-cast window (proxy for Agave's "vote hasn't landed";
    //                              keeps the tick-level call dormant during healthy every-slot voting)

    /// throughput-fix #2 (2026-06-11): async sysvar-RPC refresher.
    ///
    /// PRE-FIX: getRecentBlockhash (6s TTL) and fetchSlotHashes (5s TTL) each
    /// fork-exec'd a BLOCKING curl (-m 3) ON THE REPLAY/VOTE THREAD whenever
    /// their cache expired — observed pinned to replay core 16, stealing
    /// 100-300ms from a slot every ~5-6s (a chunk of the heavy-slot tail in
    /// [SLOT-PROFILE]). Agave refreshes vote blockhash / cluster info on
    /// background services and never blocks replay.
    ///
    /// FIX SHAPE — fetch/install SPLIT (not a full move): sysvarRefreshWorker
    /// (ops-lane core 29) does ONLY the network fetch + parse into the
    /// `pending_*` slots under `sysvar_fetch_lock`. The replay thread INSTALLS
    /// pending results inside getRecentBlockhash/getNetworkBankHash — keeping
    /// the install side-effects (g_cluster_slot_hashes publish + the three
    /// PR-5z/5ae/5ai sweeps, which touch replay-stage state and are NOT
    /// thread-safe) on the replay thread exactly as before. Cold boot keeps a
    /// one-shot synchronous prime so first-vote behavior is unchanged.
    sysvar_fetch_lock: std.Thread.Mutex = .{},
    pending_blockhash: ?Hash = null,
    pending_blockhash_time: i64 = 0,
    pending_slot_hashes: ?[]u8 = null,
    pending_slot_hashes_time: i64 = 0,
    sysvar_refresh_thread: ?std.Thread = null,

    /// Leader lookup function — returns the slot leader pubkey.
    /// Set by main.zig to use the LeaderScheduleCache.
    getSlotLeader: ?*const fn (u64) ?core.Pubkey,

    /// Block producer — active during leader slots.
    block_producer: ?@import("block_producer.zig").BlockProducer,

    /// Snapshot service — periodic snapshot generation.
    snapshot_service: ?@import("snapshot_service.zig").SnapshotService,

    /// GHOST fork choice — tracks stake-weighted fork tree for vote safety.
    fork_choice: ?@import("vex_consensus").fork_choice.ForkChoice,

    /// #93 propagation-confirmation (leader-window LATCH). @prov:replay.propagation-latch
    /// Replaces the #92 per-slot non-latching prop-gate proxy that withheld at the
    /// epoch-981/SIMD-0449 boundary. Replay-thread-only (submitVote);
    /// no lock. Init in the struct literal; pruned on root advance; deinit below.
    propagation_map: @import("vex_consensus").propagation.PropagationMap = undefined,

    /// GOSSIP-FED PROP_RETARGET (2026-07-01, VEX_GOSSIP_PROP): real-time gossip
    /// votes feeding the confirmation gate so the vote target tracks the tip
    /// (kills the landed-lag stall) while the heaviest-sibling guard keeps
    /// orphan-safety. `gossip_votes_lock` is a LEAF lock: held ONLY around the
    /// gossip stake sum and RELEASED before any banks_lock (order gossip→never→
    /// banks). Written by the gossip thread (onGossipVote), read by replay.
    latest_gossip_votes: @import("gossip_votes.zig").LatestGossipVotes = undefined,
    gossip_votes_lock: std.Thread.Mutex = .{},
    last_gossip_vote_ms: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    gossip_voter_count_seen: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Cached SlotHashes sysvar data from RPC (for network bank hash lookup).
    cached_slot_hashes: ?[]u8 = null,

    /// PR-5z (2026-05-19) — pending-shadow slots awaiting deferred ENFORCE
    /// decision. When the SHADOW gate at line ~1910 detects a chained_block_id
    /// mismatch but cluster's oracle is too stale to confirm (at-tip slots
    /// newer than cluster's cached SlotHashes tip), we queue the (slot,
    /// parent_slot, flagged_at_ms) here. Every successful `fetchSlotHashes`
    /// refresh runs `sweepPendingShadowSlots` which re-checks each entry.
    /// If cluster's NEW view confirms the parent as orphan → markSlotDead the
    /// CHILD retroactively + purgeUnrootedSlot. If 30s elapses without
    /// confirmation → assume canonical (current behavior, no action).
    pending_shadow_slots: std.ArrayListUnmanaged(ShadowEntry) = .{},

    /// PR-5ae (2026-05-19) — pending-tick-gate slots awaiting deferred ENFORCE
    /// check. When d28dd-SHADOW fires (tick_count < expected), we queue here
    /// instead of marking dead. `sweepPendingTickGateSlots` checks
    /// `getNetworkBankHash(slot) != null` on next refresh — positive →
    /// retroactive markSlotDead + purgeUnrootedSlot; 30s timeout → drop.
    pending_tick_gate_slots: std.ArrayListUnmanaged(TickGateEntry) = .{},

    /// PR-5ai (2026-05-20) — pending FEC-GATE-SHADOW slots awaiting deferred
    /// ENFORCE check. Same shape as pending_tick_gate_slots. Mirrored sweep
    /// at sweepPendingFecGateSlots. Closes Carrier L (sibling to Carrier K).
    pending_fec_gate_slots: std.ArrayListUnmanaged(FecGateEntry) = .{},
    cached_slot_hashes_time: i64 = 0,

    /// ── G0 FIRST-ROOT POSITIVE-ATTESTATION LATCH (incident 423083743, 2026-07-19) ──
    /// Per-process latch: false until one candidate root POSITIVELY matches a
    /// cluster-attested bank_hash (or is duplicate-confirmed). While false (and
    /// VEX_FIRST_ROOT_LATCH not disabled, and not in offline replay), a
    /// HASH-SILENT root advance additionally requires fetchProducedSlots to
    /// confirm the slot was cluster-produced — the exact refusal that would have
    /// blocked rooting cluster-SKIPPED slot 423083742. Replay-thread-only
    /// (doRootAdvance runs on the replay thread for both its callers); no lock.
    first_root_attested: bool = false,
    /// Per-candidate cache for the G0 produced-slot probe (the candidate root
    /// repeats on every vote while refused; without this each retry would fork a
    /// curl). produced-ness of a historical slot is immutable, so a definitive
    /// true/false is cached until the candidate changes; a failed probe (null)
    /// is retried at most once per 2s. Replay-thread-only; no lock.
    first_root_probe_slot: Slot = 0,
    first_root_probe_result: ?bool = null,
    first_root_probe_at_ms: i64 = 0,

    /// ── VOTE-THRESHOLD depth-8 stake wiring (423083743 companion fix) ──
    /// Per-epoch cache of total epoch stake for the threshold check (the same
    /// epoch_stakes walk the PROP-GATE/switch-proof sites do inline, cached here
    /// because this runs on EVERY vote decision). Replay-thread-only (submitVote);
    /// no lock, no cross-thread sync (TVU hot-path standing rule).
    thr_total_stake_epoch: u64 = std.math.maxInt(u64),
    thr_total_stake_cached: u64 = 0,

    /// Statistics
    stats: ReplayStats,

    /// Parallel SVM statistics
    svm_stats: SvmStats,

    // svm_pool removed — was initialized but never dispatched to (zero spawn calls).
    // 8 idle threads were contending with TVU on core 4 for cache.
    // Restore when parallel execute workers are wired (vex-010+).

    /// Lock-free SPSC slot queue (TVU producer → replay consumer)
    /// Capacity: 1024 slots ≈ ~7 minutes of buffer at 400ms/slot.
    slot_queue: *SlotQueue,

    /// Worker thread running the replay consumer loop
    worker_thread: ?std.Thread,

    /// Atomic flag to signal the worker to shut down
    is_running: std.atomic.Value(bool),

    /// Fast catch-up mode: skip signature verification for historical slots
    fast_catchup: bool = false,

    /// Genesis mode: RPC URL for lazy account fetching on AccountsDb miss.
    /// Set by bootstrap when genesis_mode=true (localnet only). null = disabled.
    /// This is a testing crutch — every account miss hits RPC. Not for production.
    genesis_rpc_fallback: ?[]const u8 = null,

    /// r44 fix (2026-04-27): authoritative parent_slot lookup for repair-replay race.
    /// Wired by tvu.setReplayStage; null on catchup-RPC path → falls back to slot-1 heuristic.
    shred_assembler: ?*@import("vex_network").shred_pub.ShredAssembler = null,

    /// DAG dispatch: reorder non-conflicting transactions within an entry.
    /// Default: disabled (serial execution). Enable to test DAG ordering.
    ///
    /// 2026-05-13: forced false. D28AA-FEE-DAG probe at slot 408211451 captured
    /// 7 of ~15 distinct fee_payers each charged TWICE within one slot
    /// (duplicate dispatch). Cluster charged target payer 2×, Vexor charged 4×,
    /// matching the -10000 per-payer cascade fingerprint. Serial path doesn't
    /// have the duplicate-dispatch bug. Discriminator: confirm vote success
    /// returns to ≥99% with this off → DAG bug owned, fix the dispatcher
    /// before re-enabling.
    dag_dispatch_enabled: bool = false,

    /// Lazily-initialized DAG transaction dispatcher. @prov:replay.dag-dispatch
    /// Created on first use in replayEntriesInternal when dag_dispatch_enabled=true.
    dag_dispatcher: ?tx_dispatcher_mod.TxnDispatcher = null,

    // ── Stage B (parallel-exec) B2c — wave-barrier parallel execution ──────────
    // ALL gated behind `comptime build_options.parallel_exec` (default OFF →
    // comptime-dead, these fields inert) AND the `VEX_PARALLEL_EXEC` env (sets
    // parallel_exec_armed in main.zig). When not armed the wave path never runs and
    // the serial-DAG drain is byte-identical (advisor: prove via the at-tip gate).
    /// Set true only if VEX_PARALLEL_EXEC env is present AND build_options.parallel_exec.
    parallel_exec_armed: bool = false,
    /// Persistent worker pool, pinned to wave_cores. Lazily created on first armed
    /// use in replayEntriesInternal (mirrors dag_dispatcher). null when not armed.
    wave_pool: ?*wave_pool_mod.WavePool = null,
    /// Per-worker write-staging buffers (len == wave_pool.n_workers). Eligible txs in
    /// a wave stage their AccountWrites here via worker_writes_override; merged into
    /// bank.pending_writes in worker-index order post-barrier, then cleared. Buffer
    /// STORAGE is on self.allocator; AccountWrite.data payloads live on the worker
    /// ARENA until the per-call flush deep-copies them (see resetArenas timing).
    wave_bufs: []std.ArrayListUnmanaged(bank_mod.AccountWrite) = &.{},
    /// Configured worker cores (from VEX_PARALLEL_EXEC_CORES; default a safe non-CCX0
    /// set). CCX0 (0-3) is OS-reserved — never pin here. Inline buffer (no heap):
    /// WavePool.init dupes the slice. Read as wave_cores_buf[0..wave_cores_len].
    wave_cores_buf: [16]u32 = [_]u32{0} ** 16,
    wave_cores_len: u8 = 0,

    /// [WAVE-WIDTH-BLOCK] measurement-only scratch DAG (gated VEX_WAVE_WIDTH_BLOCK). Accumulates a WHOLE
    /// slot's txs into ONE conflict graph (vs the live per-entry DAG), then dry-drains it (no execution)
    /// to size the BLOCK-LEVEL parallelism ceiling — what merging the ~330 tiny per-entry DAGs into one
    /// would expose. NULL/unused unless the env gate is set (zero live cost). BW_DEPTH ≥ observed max
    /// slot tx count (6906). bw_wavebuf reused per wave; bw_overflow flags a slot that exceeded BW_DEPTH.
    bw_disp: ?tx_dispatcher_mod.TxnDispatcher = null,
    bw_wavebuf: []u32 = &.{},
    bw_overflow: bool = false,

    /// Shred version for this validator (set by setKeypair)
    shred_version: u16 = 0,

    /// d21 (2026-05-11) — chain-connectivity defer map. @prov:replay.chain-connectivity-defer
    /// When getOrCreateBank can't resolve a proper frozen ancestor at
    /// target_parent, we DEFER the slot here (allocator-owned data copy +
    /// target_parent) instead of falling back to root_bank_ptr. After each
    /// successful freeze, checkPendingChain scans for slots whose
    /// target_parent is the just-frozen slot and re-pushes them to slot_queue.
    pending_chain: std.AutoHashMap(u64, PendingChainEntry) = undefined,
    pending_chain_lock: std.Thread.Mutex = .{},
    /// FIX #18a-A (2026-06-12, carrier #18 @414926973): slots that have ALREADY
    /// frozen, surviving bank eviction. The bank-prune slot-based safety valve
    /// (slot−512 when root stalls) evicts banks that are still above the stuck
    /// consensus root; when repair later RE-DELIVERS such a slot (the shred
    /// assembler's rooted-cadence cleanup forgot it), nothing recognized it as
    /// already-replayed → re-replay attempt → unresolvable parent → defer loop.
    /// @prov:replay.frozen-history-dedup — independent of bank_forks retention. Guarded by
    /// pending_chain_lock (write at freeze via checkPendingChain; read at
    /// deferUnconnectedSlotWithBoundaries entry). Pruned below the consensus
    /// root on root advance (entries ≥ root retained — a frozen slot above root
    /// must keep deduping while the root is stuck).
    frozen_history: std.AutoHashMap(u64, void) = undefined,
    /// fix/chain-defer-tip-guard (wedge @422050470): slots the CHAIN-DEFER GC
    /// BACKSTOP evicted while still ABOVE the consensus root (i.e. a genuine
    /// eviction of a not-yet-obsolete, potentially-continuation slot — NOT a
    /// root-advance drop). On each freeze, checkPendingChain's CHAIN-WAKE
    /// fallback consults this set: if the just-frozen slot is the PARENT of an
    /// evicted slot, that child is re-derived from the assembler and re-enqueued
    /// (self-heal), or repair-requested if its bytes are gone. Keying the
    /// fallback on THIS set (not on "did a child wake?") makes it cost-free in
    /// healthy operation (the set is empty) and precise (only slots we actually
    /// evicted are ever re-checked). Guarded by pending_chain_lock; pruned below
    /// the consensus root alongside frozen_history.
    backstop_evicted: std.AutoHashMap(u64, void) = undefined,
    /// fix/chain-defer-tip-guard: single-slot lock-free hand-off to tvu's repair
    /// cycle. Set (release) by the CHAIN-WAKE fallback when an evicted child's
    /// bytes are no longer re-derivable in-process; tvu reads (acquire) it in its
    /// repair loop, issues a window-repair for that slot, and clears it back to
    /// 0. 0 = nothing pending. A plain atomic word (same discipline as
    /// max_slot_seen) — no cross-thread locking on any hot path.
    continuation_repair_needed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Orphan-repair observability (2026-05-30, advisor pre-deploy gate #1):
    /// the set of GAP-PARENT slots we've emitted Orphan(10) requests to
    /// discover (the target_parent of each selected orphan-root). When one of
    /// these later FREEZES, checkPendingChain logs [ORPHAN-CLOSED] — the
    /// end-to-end proof that an Orphan response discovered a true zero-shred
    /// gap, window repair filled it, and it replayed (vs "requests into the
    /// void"). Guarded by pending_chain_lock (NEVER held with banks_lock).
    /// GC'd against root in collectOrphanTargets so it stays bounded.
    orphan_chasing: std.AutoHashMap(u64, void) = undefined,
    orphan_gaps_closed_total: u64 = 0,

    /// d27mm-followup (2026-05-11): Set of slots marked dead by canonical
    /// gates (currently: check_last_fec_set IncompleteFinalFecSet). Children of
    /// dead slots are orphaned. @prov:replay.generate-new-bank-forks
    /// We mirror that here by cascading markSlotDead through the pending_chain
    /// so deferred entries don't wait forever for a dead parent. Chain
    /// re-extends when a slot arrives whose leader-encoded parent_offset walks
    /// back to a frozen or root ancestor (typical: 1-3 slots later, when a
    /// leader who knew about the dead slot produces with skip-aware parent_slot).
    dead_slots: std.AutoHashMap(u64, void) = undefined,
    dead_slots_lock: std.Thread.Mutex = .{},

    /// Switch-proof Part 2, M1 (2026-07-16) — dedup latch for the read-only
    /// `[REVIVE-WOULD-FIRE]` detection tap in `sweepPendingTickGateSlots`.
    /// `cached_slot_hashes` can hold a positive entry for a dead slot across
    /// many consecutive sweep passes (M1 does not remove anything from
    /// `dead_slots`), so without this the tap would log once per sweep
    /// forever. Guarded by `dead_slots_lock` (same critical section as the
    /// `dead_slots` read it accompanies — no new lock, no new ordering).
    /// Purely observational: never consulted by any decision path.
    /// See SWITCHPROOF-PART2-IMPLEMENTATION-PLAN-2026-07-16.md §2 M1.
    revive_would_fire_logged: std.AutoHashMap(u64, void) = undefined,

    /// Switch-proof Part 2, M2 — bounded-retry attempt counter per revived slot.
    /// Persists ACROSS a dump (deliberately NOT cleared on dump) so a repaired-but-
    /// still-truncated slot that re-fails the tick-gate and is re-marked dead is
    /// eventually driven to give_up_exhausted at MAX_REVIVE_ATTEMPTS — the
    /// termination guarantee (never an unbounded dump→re-fail→dump loop). Only
    /// touched under VEX_REVIVE_DEAD_SLOTS on the replay/sweep thread. See
    /// revive_repair.recordAttempt (saturating).
    revive_attempts: std.AutoHashMap(u64, u8) = undefined,
    /// Switch-proof Part 2, M2 — permanent give-up latch: slots whose bounded
    /// retry is exhausted. Kept dead forever; the M2 sweep skips them so no further
    /// dump/repair is ever issued. Same lock/lifetime discipline as
    /// revive_would_fire_logged (freed alongside dead_slots in deinit).
    revive_gave_up: std.AutoHashMap(u64, void) = undefined,

    /// OFFLINE-ONLY diag single-shot latch for the VEX_FORCE_DEAD_SLOT synthetic
    /// Shape-A kill (build_options.force_dead_slot; comptime-dead in prod). The
    /// injector must fire EXACTLY ONCE per target slot: after it kills the slot
    /// pre-freeze and the revive dump re-feeds the (complete) shreds, the slot
    /// MUST replay+freeze normally so the offline gate can observe last_vote
    /// advancing past it — a re-fire would loop straight to give_up_exhausted and
    /// the gate could never pass. `swap(true)` on first hit gates all re-hits.
    force_dead_fired: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// verify_ticks canonical (feat/verify-ticks-canonical-zig-2026-06-19):
    /// EFFECTIVE PoH cadence read from the snapshot manifest, set ONCE at
    /// bootstrap via `setPohParams`. Stamped onto each newly-acquired Bank
    /// (acquireBank) so `replayEntriesInternal`'s gated tick-validity check has
    /// the params in scope. @prov:replay.hashes-per-tick — 0 = hashing disabled
    /// (skip the hash-count checks). Defaults (0 / 64) make a default
    /// (verify_ticks .off) build byte-identical: setPohParams is only invoked
    /// from bootstrap, and even when invoked the values are only READ behind
    /// the comptime gate.
    poh_hashes_per_tick: u64 = 0,
    poh_ticks_per_slot: u64 = 64,

    const Self = @This();

    /// Switch-proof Part 2, M2 — bounded-retry ceiling for Shape-A dead-slot revive.
    /// At attempt_count >= this the decision is give_up_exhausted (slot stays dead,
    /// guardian escalation). 3 = repair gets a few chances to refill the truncated
    /// slot before we conclude the cluster version is genuinely unavailable.
    const MAX_REVIVE_ATTEMPTS: u8 = 3;

    // posix_spawn extern (perf, 2026-07-08): spawn curl WITHOUT fork()'s
    // ~30GB account-heap page-table COW copy. Zig's std.process.Child.spawn
    // calls raw posix.fork()+execve → copy_page_range on the validator's huge
    // RSS (perf showed ~9% live CPU). posix_spawn uses glibc clone(CLONE_VM|
    // CLONE_VFORK): the child shares the address space until exec → NO
    // page-table copy. SAME extern already proven live in main.zig sendViaRpc.
    // Zig 0.15.2 stdlib binds posix_spawn only for darwin; declare for Linux
    // glibc (libc IS linked). Used by fetchRecentBlockhashRemote +
    // fetchSlotHashesRemote below (curl writes the response body to /dev/shm
    // tmpfs via -o, read back after waitpid — no pipe/fork needed).
    extern "c" fn posix_spawn(
        pid_out: *std.c.pid_t,
        path: [*:0]const u8,
        file_actions: ?*const anyopaque,
        attrp: ?*const anyopaque,
        argv_p: [*:null]const ?[*:0]const u8,
        envp_p: [*:null]const ?[*:0]const u8,
    ) c_int;

    pub const PendingChainEntry = struct {
        data: []u8,
        target_parent: u64,
        added_ms: i64,
        /// d28bb (2026-05-12): preserve batch_complete boundaries across
        /// chain-defer → chain-wake so the replay parser can iterate per
        /// BlockComponent. @prov:replay.completed-data-ranges Pre-fix: boundaries were
        /// dropped when slots were deferred, so 100% of post-CHAIN-WAKE
        /// slots had boundaries_len=0, sending the parser into scan-forward
        /// heuristics that mis-parsed at FEC-set boundaries and dropped
        /// significant tx counts. Owned by pending_chain — freed on GC or
        /// transferred to SlotMessage on wake.
        boundaries: []const usize = &.{},
    };
    /// GC threshold: pending entries are dropped by root-based criterion
    /// (slot < root_bank.slot) rather than wall-time TTL. FIX #53 removed
    /// TTL-based GC; this constant is retained only for external readers
    /// who may reference the prior value. Effective GC backstop is now
    /// PENDING_CHAIN_BACKSTOP_TTL_MS = 60 min, applied only when over cap.
    pub const PENDING_CHAIN_TTL_MS: i64 = 5 * 60 * 1000;

    // ── SPSC queue capacity ───────────────────────────────────────────────────
    pub const QUEUE_CAPACITY: usize = 1024;

    /// SPSC queue message: (slot, assembled_data)
    pub const SlotMessage = struct {
        slot: Slot,
        data: []u8,
        /// d24 (2026-05-11): authoritative parent slot, set by catchup when
        /// the payload was fetched via RPC `getBlock.parentSlot`. The replay
        /// worker thread surfaces this into `catchup_parent_override` (a
        /// threadlocal) for the duration of one onSlotCompleted call so
        /// getOrCreateBank uses the RPC-authoritative parent instead of the
        /// shred-assembler view. TVU pushes leave this null — the existing
        /// shred_assembler.getParentSlot path remains authoritative for them.
        parent_override: ?u64 = null,
        /// d27hh (2026-05-11): per-BlockComponent byte boundaries from the
        /// shred assembler. boundaries[i] is the byte offset in `data`
        /// immediately after the i-th component ends; the i+1-th component
        /// starts there. Used by replayBlock to jump directly past intra-
        /// shred zero padding to the next real component. @prov:replay.completed-data-ranges
        /// Empty slice = no boundary info (catchup-RPC path) → parser falls
        /// back to legacy scan-forward.
        boundaries: []const usize = &.{},
    };

    /// Multi-producer single-consumer ring buffer.
    /// Producer side serialized by `producer_lock` (TVU main thread + N verify-tile
    /// workers can all push); consumer is the replayWorker thread (sole pop()er).
    /// Pre-fix this was SPSC and TVU paths bypassed the queue entirely by calling
    /// `onSlotCompleted` directly from multiple threads — driving the AccountsDb /
    /// Bank / batch_arena heap corruption that surfaced as variable ~10-min panics
    /// (arena_allocator / Mutex.unlock / assert).
    pub const SlotQueue = struct {
        buf: [QUEUE_CAPACITY]SlotMessage = undefined,
        head: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        tail: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        producer_lock: std.Thread.Mutex = .{},

        pub fn init() SlotQueue {
            return .{};
        }

        pub fn push(self: *SlotQueue, msg: SlotMessage) bool {
            self.producer_lock.lock();
            defer self.producer_lock.unlock();
            const tail = self.tail.load(.acquire);
            const next_tail = (tail + 1) % QUEUE_CAPACITY;
            if (next_tail == self.head.load(.acquire)) return false; // full
            self.buf[tail] = msg;
            self.tail.store(next_tail, .release);
            return true;
        }

        pub fn pop(self: *SlotQueue) ?SlotMessage {
            const head = self.head.load(.acquire);
            if (head == self.tail.load(.acquire)) return null; // empty
            const msg = self.buf[head];
            self.head.store((head + 1) % QUEUE_CAPACITY, .release);
            return msg;
        }

        pub fn count(self: *const SlotQueue) usize {
            const tail = self.tail.load(.acquire);
            const head = self.head.load(.acquire);
            if (tail >= head) return tail - head;
            return QUEUE_CAPACITY - head + tail;
        }
    };

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    pub fn init(
        allocator: std.mem.Allocator,
        identity: Pubkey,
    ) !*Self {
        const stage = try allocator.create(Self);
        errdefer allocator.destroy(stage);

        // Zig 0.15.2: ArrayListUnmanaged needs no allocator at declaration
        stage.* = .{
            .allocator = allocator,
            .identity = identity,
            .banks = std.AutoHashMap(Slot, *Bank).init(allocator),
            .dropped_banks = .{}, // std.ArrayListUnmanaged(*Bank){}
            .bank_pool = .{}, // d27f Bank freelist
            .banks_lock = .{},
            // PR-5av Phase 1: sentinel-node maps. Empty until Phase 2.
            .subtrees = std.AutoHashMap(Slot, *Bank).init(allocator),
            .subtrees_lock = .{},
            .orphaned = std.AutoHashMap(Slot, *Bank).init(allocator),
            .orphaned_lock = .{},
            .root_bank = std.atomic.Value(?*Bank).init(null),
            .accounts_db = null,
            .identity_secret = null,
            .vote_account = null,
            .sendVoteFn = null,
            .vote_send_queue = null,
            .tower = null,
            .getSlotLeader = null,
            .block_producer = null,
            .snapshot_service = @import("snapshot_service.zig").SnapshotService.init(allocator, .{}),
            .fork_choice = @import("vex_consensus").fork_choice.ForkChoice.init(allocator),
            .propagation_map = @import("vex_consensus").propagation.PropagationMap.init(allocator),
            .latest_gossip_votes = @import("gossip_votes.zig").LatestGossipVotes.init(allocator),
            .stats = .{},
            .svm_stats = .{},
            // svm_pool removed (dead code)
            .slot_queue = undefined, // allocated below
            .worker_thread = null,
            .is_running = std.atomic.Value(bool).init(false),
            .pending_chain = std.AutoHashMap(u64, PendingChainEntry).init(allocator),
            .frozen_history = std.AutoHashMap(u64, void).init(allocator),
            .backstop_evicted = std.AutoHashMap(u64, void).init(allocator),
            .continuation_repair_needed = std.atomic.Value(u64).init(0),
            .pending_chain_lock = .{},
            .orphan_chasing = std.AutoHashMap(u64, void).init(allocator),
            .dead_slots = std.AutoHashMap(u64, void).init(allocator),
            .dead_slots_lock = .{},
            .revive_would_fire_logged = std.AutoHashMap(u64, void).init(allocator),
            .revive_attempts = std.AutoHashMap(u64, u8).init(allocator),
            .revive_gave_up = std.AutoHashMap(u64, void).init(allocator),
        };

        // svm_pool removed — was dead code (zero spawn calls), 8 idle threads on core 4

        // d27g (2026-05-11): pre-warm Bank pool. During catchup the
        // pruneOldBanks guard (min(slot-1, root_bank.slot)) pins the cutoff
        // at the snapshot-start slot because root_bank doesn't advance until
        // catchup completes — so no bank is ever pruned, and every onSlotCompleted
        // pays the ~200ms allocator.create cost. Pre-warming with 1024 banks
        // covers the catchup-to-tip gap (cluster's ~600-slot retransmit window)
        // and keeps acquireBank on the fast path through bootstrap.
        // Banks pushed here have uninitialized fields; acquireBank pops + reset()
        // overwrites everything via struct-literal init. Safe by construction.
        const PRE_WARM_BANKS: usize = 1024;
        stage.bank_pool.ensureUnusedCapacity(allocator, PRE_WARM_BANKS) catch {};
        {
            var i: usize = 0;
            while (i < PRE_WARM_BANKS) : (i += 1) {
                const pw_bank = allocator.create(Bank) catch break;
                // d27h-fix: reset() preserves bank.allocator (so Bank.deinit
                // can destroy via the right allocator later). Pre-warmed
                // banks have garbage in every field — set allocator BEFORE
                // pushing so the first acquireBank.reset() preserves a valid
                // allocator. Initializing pending_writes/recent_blockhashes
                // to their empty defaults isn't required (reset overwrites
                // them via struct-literal init), but the allocator field is
                // load-bearing.
                pw_bank.allocator = allocator;
                stage.bank_pool.appendAssumeCapacity(pw_bank);
            }
            std.log.warn("[BANK-POOL] Pre-warmed {d} banks", .{stage.bank_pool.items.len});
        }

        // Allocate SPSC queue on heap (large struct, must not live on stack)
        const queue = try allocator.create(SlotQueue);
        queue.* = SlotQueue.init();
        stage.slot_queue = queue;

        // Spawn background replay worker thread
        stage.is_running.store(true, .release);
        stage.worker_thread = std.Thread.spawn(.{}, replayWorker, .{stage}) catch |err| blk: {
            std.log.warn("[REPLAY-TILE] Worker thread spawn failed: {any} — falling back to synchronous replay", .{err});
            break :blk null;
        };
        if (stage.worker_thread != null) {
            std.log.info("[REPLAY-TILE] Background replay worker spawned (queue capacity: {d})", .{QUEUE_CAPACITY});
        }

        // throughput-fix #2: async sysvar-RPC refresher (ops-lane core 29).
        // Non-fatal on spawn failure — the cold-boot prime + install paths
        // degrade to the pre-fix synchronous behavior.
        stage.sysvar_refresh_thread = std.Thread.spawn(.{}, sysvarRefreshWorker, .{stage}) catch |err| blk: {
            std.log.warn("[SYSVAR-REFRESH] spawn failed: {any} — falling back to synchronous sysvar refresh", .{err});
            break :blk null;
        };

        return stage;
    }

    pub fn deinit(self: *Self) void {
        // Signal worker to stop and join
        self.is_running.store(false, .release);
        if (self.worker_thread) |thread| {
            thread.join();
            self.worker_thread = null;
        }
        if (self.sysvar_refresh_thread) |thread| {
            thread.join();
            self.sysvar_refresh_thread = null;
        }

        // Drain remaining queued messages and free their data
        while (self.slot_queue.pop()) |msg| {
            if (msg.data.len > 0) self.allocator.free(msg.data);
            if (msg.boundaries.len > 0) self.allocator.free(msg.boundaries);
        }
        self.allocator.destroy(self.slot_queue);

        // d21: free deferred chain-pending entries
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            var it = self.pending_chain.valueIterator();
            while (it.next()) |entry| {
                if (entry.data.len > 0) self.allocator.free(entry.data);
                if (entry.boundaries.len > 0) self.allocator.free(entry.boundaries);
            }
            self.pending_chain.deinit();
            self.frozen_history.deinit();
            self.backstop_evicted.deinit();
        }
        self.propagation_map.deinit(); // #93
        self.latest_gossip_votes.deinit();
        self.orphan_chasing.deinit();

        // d27mm-followup: free dead_slots tracker
        {
            self.dead_slots_lock.lock();
            defer self.dead_slots_lock.unlock();
            self.dead_slots.deinit();
            // Switch-proof Part 2, M1: free the REVIVE-WOULD-FIRE dedup latch
            // alongside dead_slots (same lock, same lifetime).
            self.revive_would_fire_logged.deinit();
            // Switch-proof Part 2, M2: free the revive bounded-retry + give-up maps.
            self.revive_attempts.deinit();
            self.revive_gave_up.deinit();
        }

        // PR-5z: free pending-shadow tracker
        self.pending_shadow_slots.deinit(self.allocator);

        // leader_mode: free the multi-slot-window block_id stash + self-produced set.
        self.self_produced_block_id.deinit(self.allocator);
        self.self_produced.deinit(self.allocator);
        // M3 tripwire: free its two tracking sets alongside self_produced (same lifetime).
        self.self_produced_tx_bearing.deinit(self.allocator);
        self.produce_parity_fail_slots.deinit(self.allocator);

        // PR-5ae: free pending-tick-gate tracker
        self.pending_tick_gate_slots.deinit(self.allocator);

        // PR-5ai: free pending-fec-gate tracker
        self.pending_fec_gate_slots.deinit(self.allocator);

        // svm_pool.deinit() removed (pool no longer initialized)

        // Destroy DAG dispatcher if initialized
        if (self.dag_dispatcher) |*disp| disp.deinit();

        // Stage B (parallel-exec) B2c: tear down the wave pool + its buffers/cores.
        // comptime-dead unless built with -Dparallel_exec; runtime-null unless armed.
        if (comptime build_options.parallel_exec) {
            if (self.wave_pool) |wp| wp.deinit();
            for (self.wave_bufs) |*b| b.deinit(self.allocator);
            if (self.wave_bufs.len > 0) self.allocator.free(self.wave_bufs);
        }

        // Destroy all active banks
        self.banks_lock.lock();
        var bank_iter = self.banks.valueIterator();
        while (bank_iter.next()) |bank| bank.*.deinit();
        self.banks.deinit();
        self.banks_lock.unlock();

        // PR-5av Phase 1: tear down sentinel-node maps. Sentinel banks
        // are tracked in subtrees/orphaned but ALSO inserted into the
        // main `banks` map, so their `Bank` payloads were already
        // destroyed by the loop above. Here we just release the map
        // index storage.
        {
            self.subtrees_lock.lock();
            defer self.subtrees_lock.unlock();
            self.subtrees.deinit();
        }
        {
            self.orphaned_lock.lock();
            defer self.orphaned_lock.unlock();
            self.orphaned.deinit();
        }

        // Destroy deferred-dropped banks
        // Zig 0.15.2: deinit takes allocator
        for (self.dropped_banks.items) |bank| bank.deinit();
        self.dropped_banks.deinit(self.allocator);

        // d27f: tear down the bank pool — these were released, not destroyed.
        for (self.bank_pool.items) |bank| bank.deinit();
        self.bank_pool.deinit(self.allocator);

        // Wave 6C-1: drop the V2 program cache (process-scoped global).
        // Idempotent — safe even if no V2 BPF program ever ran this session.
        deinitV2ProgramCache();

        self.allocator.destroy(self);
    }

    // ── Public interface ──────────────────────────────────────────────────────

    /// Push an assembled slot into the async replay queue.
    /// Ownership of `data` transfers on success — caller must NOT free it.
    /// Returns false if queue is full (caller retains ownership and must free).
    /// GOSSIP-VOTE ingest (called from the gossip thread via onGossipVoteThunk).
    /// Parses the embedded vote tx (never panics — null on malformed) and records
    /// the latest gossip vote per voter. Holds only the leaf lock. Byte-inert to
    /// consensus: writes only the gossip tracker + liveness stamps read by the
    /// gossip-fed gate (which is itself off unless VEX_GOSSIP_PROP is set).
    pub fn onGossipVote(self: *Self, tx_bytes: []const u8) void {
        const gv = @import("gossip_votes.zig").parseGossipVote(tx_bytes) orelse return;
        self.gossip_votes_lock.lock();
        defer self.gossip_votes_lock.unlock();
        const updated = self.latest_gossip_votes.checkAddVote(gv.vote_pubkey, gv.voted_slot, gv.voted_hash) catch return;
        if (updated) {
            self.last_gossip_vote_ms.store(std.time.milliTimestamp(), .monotonic);
            self.gossip_voter_count_seen.store(@intCast(self.latest_gossip_votes.count()), .monotonic);
        }
    }

    /// Type-erased trampoline for gossip.GossipVoteSink (main.zig wires ctx=*ReplayStage).
    pub fn onGossipVoteThunk(ctx: *anyopaque, tx: []const u8) void {
        onGossipVote(@ptrCast(@alignCast(ctx)), tx);
    }

    /// Wire a live FeatureSet (loaded from AccountsDb at bootstrap).
    /// Pointer lifetime must outlive the ReplayStage.
    pub fn setLiveFeatureSet(self: *Self, fs: *features_mod.FeatureSet) void {
        self.live_feature_set = fs;
        // 1b.2 M3: also publish to the module-scope pointer so the FREE-function
        // vote path (executeVoteInstruction → executeVoteViaVoteforge) can thread
        // real per-feature activation slots into voteforge's ExecContext feature
        // gates instead of hardcoded values. Set once at bootstrap before replay
        // starts; read-only thereafter (same lifetime contract as live_feature_set).
        instruction_dispatch.g_vote_live_features = fs;
        std.debug.print("[REPLAY] Live FeatureSet connected ({d} entries, {d} active)\n", .{
            fs.count(), fs.activeCount(),
        });

        // Boot-time cluster feature-status audit (READ-ONLY, logging-only;
        // zero bank_hash impact). Warns with lead time about any feature that
        // is PENDING on-chain but NOT behaviorally wired in Vexor — the
        // proactive defense against the "feature activates → we diverge" class.
        // Runs here because both accounts_db and the root bank are wired at
        // this point (main.zig calls setAccountsDb then setLiveFeatureSet at
        // bootstrap). loadFromAccountsDb just read all 280 feature accounts at
        // this exact point, so re-reading via getAccountInSlot is provably safe.
        if (self.accounts_db) |db| {
            if (self.root_bank.load(.acquire)) |rb| {
                feature_watch.auditPendingFeatures(db, rb.slot, rb.epoch_schedule.getEpoch(rb.slot), rb.ancestors());
            }
        }
    }

    /// verify_ticks canonical: install the EFFECTIVE PoH cadence from the
    /// snapshot manifest. Called ONCE from bootstrap after the manifest parse.
    /// @prov:replay.hashes-per-tick (null manifest → pass 0 → hash-count
    /// checks skipped). No-op effect when verify_ticks is .off (the
    /// values are only read behind the comptime gate).
    pub fn setPohParams(self: *Self, hashes_per_tick: u64, ticks_per_slot: u64) void {
        self.poh_hashes_per_tick = hashes_per_tick;
        self.poh_ticks_per_slot = if (ticks_per_slot > 0) ticks_per_slot else 64;
        std.log.warn("[REPLAY] verify_ticks PoH params: hashes_per_tick={d} ticks_per_slot={d} (verify_ticks={s})", .{
            self.poh_hashes_per_tick, self.poh_ticks_per_slot, @tagName(build_options.verify_ticks),
        });
    }

    /// P5#1: wire the VexLedger handle for the flight-recorder freeze-tap + read VEX_LEDGER_FLIGHT
    /// ONCE (not a per-slot getenv). Called from main.zig only under -Dvex_ledger + VEX_LEDGER. When
    /// VEX_LEDGER_FLIGHT is unset the tap stays dormant (handle set, flight_record_enabled=false).
    pub fn setVexLedgerFlight(self: *Self, vl: *vex_ledger_mod.VexLedger) void {
        self.vex_ledger_flight = vl;
        self.flight_record_enabled = (std.posix.getenv("VEX_LEDGER_FLIGHT") != null);
        if (self.flight_record_enabled)
            std.log.warn("[VEX-LEDGER-FLIGHT] P5#1 flight recorder ENABLED — journaling bank_hash inputs per frozen slot", .{});
    }

    /// P5 MOAT #2 (M2): wire the LIVE divergence-alarm handle (built + thread-started in
    /// main.zig). Setting it arms the freeze-tap enqueue. main.zig only calls this when
    /// VEX_DIVERGE_ALARM=1 AND VEX_LEDGER_FLIGHT=1 (the alarm reads the FlightRecord).
    pub fn setDivergeAlarm(self: *Self, alarm: *vex_ledger_mod.divergence_alarm_rt.DivergeAlarm) void {
        self.diverge_alarm = alarm;
        self.diverge_alarm_enabled = true;
        std.log.warn("[DIVERGENCE-ALARM] freeze-tap ARMED (M2) — enqueuing {{slot,bank_hash}} per frozen slot", .{});
    }

    pub fn setAccountsDb(self: *Self, db: *@import("vex_store").accounts.AccountsDb) void {
        self.accounts_db = db;
        std.log.debug("[REPLAY] AccountsDb connected\n", .{});
        // Quick verify: try looking up the system program (all zeros — always exists)
        const system_pk = core.Pubkey{ .data = [_]u8{0} ** 32 };
        const sys_result = db._getRooted(&system_pk);
        std.log.debug("[DB-VERIFY] System program (0000..0000): {s}\n", .{
            if (sys_result != null) "FOUND" else "NULL",
        });
        // Try native loader
        const native_pk = core.Pubkey{ .data = .{
            0x01, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
            0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
            0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
            0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        } };
        const nat_result = db._getRooted(&native_pk);
        std.log.debug("[DB-VERIFY] NativeLoader: {s}\n", .{
            if (nat_result != null) "FOUND" else "NULL",
        });
    }

    /// r44 fix (2026-04-27): wire shred_assembler for authoritative parent_slot lookup.
    /// Called by tvu.setReplayStage at startup. Eliminates wrong-parent races in repair-replay
    /// where slot N enters getOrCreateBank before slot N-1's bank is in self.banks.
    pub fn setShredAssembler(self: *Self, sa: *@import("vex_network").shred_pub.ShredAssembler) void {
        self.shred_assembler = sa;
        std.log.debug("[REPLAY] ShredAssembler connected (r44 parent-bank lookup armed)\n", .{});
    }

    /// Configure vote submission (call after bootstrap with loaded keypairs)
    pub fn setVoteConfig(self: *Self, identity_secret: [64]u8, vote_account: Pubkey) void {
        self.identity_secret = identity_secret;
        self.vote_account = vote_account;

        // Initialize tower if not already set
        if (self.tower == null) {
            const vex_consensus = @import("vex_consensus");
            self.tower = vex_consensus.tower.TowerBft.init(self.allocator, self.identity) catch null;

            // Try loading tower state from disk — except in OFFLINE REPLAY.
            // HERMETICITY (#27 gate wedge @419131458, 2026-07-02): the isolate
            // harness runs every leg with cwd=$LEDGER, and this relative-path
            // load picks up whatever tower the PREVIOUS leg (or a frozen
            // capture) left there. A leaked high-lastVote tower refuses every
            // replayed vote (no tower rooting) AND its high root drives
            // computePruneCutoff to slot−1 → pruneOldBanks collapses the banks
            // map to ~3 entries → any fork-child whose parent predates the
            // last %64 prune defers as [CHAIN-GAP] forever (no repair offline)
            // → freeze-timeout wedge. Offline replays therefore ALWAYS start
            // with a fresh tower: deterministic + hermetic across legs.
            if (self.tower) |*t| {
                if (std.posix.getenv("VEX_LEDGER_REPLAY") == null) {
                    t.loadFromDisk("tower-state.bin") catch {};
                } else {
                    std.log.warn("[TOWER] offline replay (VEX_LEDGER_REPLAY): tower-state.bin load SKIPPED — fresh hermetic tower", .{});
                }
            }
        }

        // Initialize block producer
        if (self.block_producer == null) {
            const bp_mod = @import("block_producer.zig");
            self.block_producer = bp_mod.BlockProducer.init(self.allocator, self.identity.data, .{});
        }

        std.log.debug("[REPLAY] Vote submission configured for vote account {x:0>2}{x:0>2}..{x:0>2}{x:0>2}\n", .{
            vote_account.data[0], vote_account.data[1], vote_account.data[30], vote_account.data[31],
        });
    }

    /// leader_mode: wire the produce→broadcast callback (shred+transmit, vex_network side) + the live
    /// shred_version. Call from main.zig after TVU exists. No-op effect unless -Dleader_mode.
    pub fn setProduceBroadcast(
        self: *Self,
        ctx: *anyopaque,
        f: *const fn (ctx: *anyopaque, slot: u64, parent_slot: u64, entry_bytes: []const u8, chained_root: [32]u8, secret: [64]u8, shred_version: u16) void,
        shred_version: u16,
    ) void {
        self.produce_broadcast_ctx = ctx;
        self.produce_broadcast_fn = f;
        self.shred_version_bp = shred_version;
    }

    /// Switch-proof Part 2, M2 — wire the replay→repair kick
    /// (TvuService.requestHighestWindowIndex). Call from main.zig after TVU exists,
    /// mirroring setProduceBroadcast's opaque-ctx pattern. Enables the dead-slot
    /// revive dump to re-request a dumped slot's shreds from peers so the slot
    /// refills. Purely wires the callback; INERT until the VEX_REVIVE_DEAD_SLOTS
    /// revive path is armed (nothing invokes repair_kick_fn otherwise).
    pub fn setRepairKick(
        self: *Self,
        ctx: *anyopaque,
        f: *const fn (ctx: *anyopaque, slot: u64, shred_idx: u64) void,
    ) void {
        self.repair_kick_ctx = ctx;
        self.repair_kick_fn = f;
    }

    /// leader_mode (2026-06-19, multi-slot leader-window chaining): wire the compute-block_id callback
    /// (vex_network side, no transmit) so a produced slot's last-FEC merkle root is fed forward as the
    /// next slot's chained_root. Reuses produce_broadcast_ctx. Call from main.zig after TVU exists.
    pub fn setProduceBlockId(
        self: *Self,
        f: *const fn (ctx: *anyopaque, entry_bytes: []const u8, slot: u64, parent_slot: u64, chained_root: [32]u8, secret: [64]u8, shred_version: u16, out: *[32]u8) bool,
    ) void {
        self.produce_blockid_fn = f;
    }

    /// task #13 LOOPBACK: wire the TPU mempool so produced blocks can pack real txs. Call from
    /// main.zig with the same &banking the QUIC ingest adapter feeds. No-op effect unless
    /// VEX_TPU_INGEST is set (the gate is checked in produceAndBroadcastEmptySlot).
    pub fn setBankingStage(self: *Self, banking: *banking_stage_mod.BankingStage) void {
        self.banking_stage = banking;
    }

    /// SB-2 (2026-06-17): wire the RPC block/transaction-history stores so replay populates them as
    /// blocks freeze. Called by main.zig ONLY under -Drpc_store + VEX_RPC_STORE. OFF-consensus.
    pub fn setRpcStores(self: *Self, bs: *@import("vex_store").BlockStore, ts: *@import("vex_store").TxStatusStore) void {
        self.rpc_block_store = bs;
        self.rpc_tx_status_store = ts;
        std.log.debug("[RPC-STORE] replay-path population wired (BlockStore + TxStatusStore)\n", .{});
    }

    /// SB-2 population FLUSH (2026-06-17): drain the per-slot `bank.rpc_tx_capture` (filled IN-LOOP by
    /// the executor, in block transaction order, with correct tx framing) into the RPC BlockStore +
    /// TxStatusStore so getBlock / getTransaction / getSignaturesForAddress return real data. Runs once
    /// per replayed slot, after `replayEntriesInternal` (so `bank.poh_hash` is set from the last entry).
    ///
    /// WHY a flush of an in-loop capture (NOT a post-hoc re-parse of `data`): the live entry buffer is
    /// component-boundary-anchored multi-batch bincode (see replayEntriesInternal's framing comment); a
    /// second independent parser would drift from the executor's framing and re-introduce the 1-byte
    /// carrier class (413149072). The executor already frames every tx correctly, so we capture there
    /// (Bank.captureRpcTx) and merely persist here.
    ///
    /// CONSENSUS SAFETY: the SOLE call site (in `replayEntries`) is wrapped in
    /// `if (comptime build_options.rpc_store)`; with the flag OFF neither this fn nor the capture exist
    /// on the replay path → consensus path byte-identical. With the flag ON it only READS `bank` fields
    /// + the capture list and WRITES to the standalone RPC stores — never accounts_db / bank state /
    /// lthash / sigverify / voting.
    ///
    /// HONEST-PARTIAL (documented): captures signature + fee-payer + raw wire (+ success status). Per-tx
    /// err / fee / pre-post balances are NOT threaded out of the dual-path executor; empty balance
    /// slices + fee=0 + err=null are valid per the block_store contract. Richer meta is additive.
    fn flushRpcStore(self: *Self, bank: *Bank) void {
        const bs = self.rpc_block_store orelse return;
        const ts = self.rpc_tx_status_store orelse return;
        const block_store = @import("vex_store").block_store;
        const alloc = self.allocator;

        // Idempotent: if this slot was already stored (re-delivery), skip (capture is cleared below).
        if (bs.hasBlock(bank.slot)) {
            for (bank.rpc_tx_capture.items) |c| {
                alloc.free(c.wire);
                if (c.account_keys.len != 0) alloc.free(c.account_keys);
                if (c.pre_balances.len != 0) alloc.free(c.pre_balances);
                if (c.post_balances.len != 0) alloc.free(c.post_balances);
            }
            bank.rpc_tx_capture.clearRetainingCapacity();
            return;
        }

        var txs = std.ArrayListUnmanaged(block_store.StoredTx){};
        defer txs.deinit(alloc); // putBlock deep-copies; our StoredTx.wire entries are NOT owned here
        for (bank.rpc_tx_capture.items) |c| {
            txs.append(alloc, .{
                .signature = c.signature,
                .wire = c.wire, // borrowed view into the capture; putBlock dupes it
                // SB-2 getBlock-meta enrichment (2026-06-21): populated post-execution by the serial
                // executor (setLastRpcTxMeta). err = genuine per-tx failure (InstructionError /
                // precompile) or null; compute_units_consumed = always null (not threaded out of the
                // dispatch path yet); pre/post_balances = fee-payer-only (account[0]) length-1 views or
                // empty. putBlock deep-copies all of these — the capture's owned slices are freed below.
                .err = c.err,
                .fee = c.fee, // base fee (5000 × sig count); see captureRpcTx
                .compute_units_consumed = c.compute_units_consumed,
                .pre_balances = c.pre_balances, // borrowed; putBlock dupes it
                .post_balances = c.post_balances, // borrowed; putBlock dupes it
            }) catch break;
        }

        const stored = block_store.StoredBlock{
            .slot = bank.slot,
            .parent_slot = bank.parent_slot orelse (bank.slot -| 1),
            .blockhash = bank.poh_hash.data, // last-entry PoH hash = the block's blockhash
            .previous_blockhash = bank.parent_hash.data,
            .block_height = null,
            .block_time = std.time.timestamp(),
            .transactions = txs.items,
            .rewards = &[_]block_store.StoredReward{},
        };
        bs.putBlock(stored) catch {
            std.log.debug("[RPC-STORE] putBlock failed for slot {d}\n", .{bank.slot});
        };

        // Index each captured tx: signature → (slot, index) and fee-payer → signature.
        for (bank.rpc_tx_capture.items, 0..) |c, i| {
            ts.put(c.signature, bank.slot, @intCast(i), null) catch {};
            ts.indexAddress(.{ .data = c.fee_payer }, bank.slot, c.signature) catch {};
        }

        // Capture list consumed; free its owned wire + account_keys + balance copies + reset for reuse.
        for (bank.rpc_tx_capture.items) |c| {
            alloc.free(c.wire);
            if (c.account_keys.len != 0) alloc.free(c.account_keys);
            if (c.pre_balances.len != 0) alloc.free(c.pre_balances);
            if (c.post_balances.len != 0) alloc.free(c.post_balances);
        }
        bank.rpc_tx_capture.clearRetainingCapacity();

        // Prune both stores below (root - 1024) so they stay bounded (RSS discipline).
        if (self.accounts_db) |db| {
            const root = db.rooted_slot;
            if (root > 1024) {
                _ = bs.purgeBelow(root - 1024);
                _ = ts.purgeBelow(root - 1024);
            }
        }
    }

    /// Q2 content-path FLUSH (2026-06-25): drain this slot's `bank.rpc_tx_capture` (filled in block order
    /// by the serial executor when VEX_LEDGER_CONTENT is set) into the VexLedger content CFs that back
    /// getTransaction / getBlock / getSignaturesForAddress. COMPTIME no-op unless -Dvex_ledger; runtime
    /// no-op unless self.vex_ledger_flight is set AND Bank.contentCaptureActive() (strict VEX_LEDGER_CONTENT).
    ///
    /// CONSENSUS SAFETY: reads ONLY the bank's RPC capture list (already-observed values) and writes ONLY
    /// to the standalone VexLedger — never accounts_db / bank state / lthash / sigverify / voting → bank_hash
    /// unaffected. Every write is best-effort (`catch {}`), NEVER fatal to replay. Does NOT free the capture
    /// list — the caller (replayBlock flush region) owns the free (see the ownership comment there).
    ///
    /// per-tx writes (rc.1 CFs): transaction (wire) + slot_signatures(slot,tx_index→sig) +
    /// transaction_status (proto-encoded TransactionStatusMeta) + address_signatures(pubkey→sig) for each
    /// touched static key.
    ///
    /// HONEST-PARTIAL (flagged): account_keys/pre/post are STATIC-KEY-COMPLETE (ALT-loaded addresses are
    /// NOT resolved at the capture site → loaded_writable/readonly_addresses omitted; num_loaded_writable=0).
    /// compute_units_consumed is always null (the dispatch path returns !void; the meter is not threaded out).
    /// err code 255 (synthetic precompile-fail sentinel) is NOT a real Agave TransactionError discriminant,
    /// so its err field is OMITTED rather than encoded as a bogus variant; code 8 (InstructionError) is
    /// encoded faithfully (ix_index → GenericError inner; exact inner-variant mapping is a follow-up).
    fn flushVexLedgerContent(self: *Self, bank: *Bank) void {
        if (comptime !build_options.vex_ledger) return;
        const vl = self.vex_ledger_flight orelse return;
        if (!Bank.contentCaptureActive()) return;
        const proto = vex_ledger_mod.agave_proto;
        const slot = bank.slot;

        for (bank.rpc_tx_capture.items, 0..) |c, i| {
            const tx_index: u32 = @intCast(i);
            // CapturedTx.signature is [64]u8 — the tx id (first signature).
            const sig: [64]u8 = c.signature;

            // transaction (wire) + slot_signatures(slot, tx_index → sig). ⚠️ putTransactionWire /
            // putSlotSignature land via LEDG's rpc-slotsig-index staged diff (slotsig-module.diff);
            // signatures coded to the documented contract: putTransactionWire(sig, slot, wire) and
            // putSlotSignature(slot, tx_index, sig). FLAGGED in the report (verify after the diff lands).
            vl.putTransactionWire(sig, slot, c.wire) catch {};
            vl.putSlotSignature(slot, tx_index, sig) catch {};

            // transaction_status: encode CapturedTx → proto TransactionStatusMeta, then store.
            // err mapping: code 8 → InstructionError(ix_index, GenericError); else (incl synthetic 255) omit.
            var err_proto: ?[]u8 = null;
            if (c.err) |e| {
                if (e.code == 8) {
                    const te = proto.TransactionError{
                        .instruction_error = .{
                            .ix_index = e.instruction_index orelse 0,
                            // inner InstructionError discriminant not decoded here → GenericError (index 0).
                            .err = .{ .unit = e.instruction_error orelse 0 },
                        },
                    };
                    err_proto = te.encodeProtoErrField(self.allocator) catch null;
                }
                // code 255 (and any other non-8) → leave err_proto null (omit) per the honesty flag.
            }
            defer if (err_proto) |ep| self.allocator.free(ep);

            const meta = proto.TransactionStatusMeta{
                .err_proto = err_proto,
                .fee = c.fee,
                .pre_balances = c.pre_balances,
                .post_balances = c.post_balances,
                // We never capture inner-instructions / log-messages, so set BOTH none-flags TRUE → the
                // proto-read path renders innerInstructions:null + logMessages:null (the honest not-captured
                // value), NOT [] (rc.1 convert.rs:568/578 + LIVE-RC1-META-GOLDEN-2026-06-25). LEDG's encoder
                // defaults these false, so this MUST be explicit (LEDG confirmed agave_proto tags 10/11).
                .inner_instructions_none = true,
                .log_messages_none = true,
                // loaded_writable/readonly_addresses omitted (ALT not resolved — static-key-complete).
                .compute_units_consumed = c.compute_units_consumed, // always null today (flagged).
            };
            if (meta.encode(self.allocator)) |meta_bytes| {
                defer self.allocator.free(meta_bytes);
                vl.putTransactionStatus(sig, slot, meta_bytes) catch {};
            } else |_| {}

            // address_signatures: index every TOUCHED static account key → this signature. writable per
            // @prov:replay.static-key-writable-rule (header counts): a signer j (<num_required_sigs) is
            // writable iff j < num_required_sigs - num_readonly_signed; a non-signer j is writable iff
            // j < num_keys - num_readonly_unsigned. tx_index lets the enumeration list block order.
            const n_keys: u32 = @intCast(c.account_keys.len);
            const nrs: u32 = c.num_required_signatures;
            const nro_s: u32 = c.num_readonly_signed_accounts;
            const nro_u: u32 = c.num_readonly_unsigned_accounts;
            for (c.account_keys, 0..) |key, kidx| {
                const j: u32 = @intCast(kidx);
                const writable: bool = if (j < nrs)
                    (j < (nrs -| nro_s))
                else
                    (j < (n_keys -| nro_u));
                vl.putAddressSignature(key, slot, tx_index, sig, writable) catch {};
            }
        }
    }

    /// Per-tx inclusion PRE-FILTER for tx-bearing block production (task #25). `ctx` is the producing
    /// (parent) *Bank. Returns true iff `tx_wire` passes the per-tx load/validate checks the cluster
    /// enforces on replay (@prov:replay.pre-filter-validate-fee-payer) EVALUATED AGAINST THE
    /// FROZEN PARENT IN ISOLATION: a valid ed25519 signature, a recent (≤150-age) blockhash, and a
    /// fee-payer that exists, is system-program-owned, and can pay. Each per-tx check is conservative
    /// (a borderline tx is dropped, a safe throughput loss). ⚠️ This is a PRE-FILTER, NOT a complete
    /// broadcast-safety boundary: the cluster executes the block SEQUENTIALLY, so a tx draining/closing
    /// a fee-payer earlier in the SAME block can still make a later tx fatal — which this isolated
    /// parent-state check cannot see. The complete boundary is execution-based and is a FLIP-BLOCKER;
    /// a replay_stage SAFETY INTERLOCK forbids tx-bearing broadcast until it lands (see block_produce
    /// banner). NOT checked here: cost-model block-CU limit, CROSS-block AlreadyProcessed (TxnCache
    /// unwired). This predicate derefs the LIVE bank, so it is inline-path-only (the tile needs a
    /// thread-safe snapshot — flip-blocker).
    /// task #26: cross-block AlreadyProcessed status cache gate. Comptime-pruned to `false` when
    /// -Dstatus_cache is off (byte-identical); else lazily reads VEXOR_STATUS_CACHE once and caches it.
    fn statusCacheActive(self: *Self) bool {
        if (comptime !build_options.status_cache) return false;
        if (self.sc_active_cached) |v| return v;
        const v = std.posix.getenv("VEXOR_STATUS_CACHE") != null;
        self.sc_active_cached = v;
        return v;
    }

    /// Stateful gate context for the SEQUENTIAL producer pre-filter (task #25/26). `state` carries the
    /// per-block running fee-payer balances; the producing (parent) `bank` supplies the parent-state
    /// lookups. `recent_sigs`/`producing_slot` drive the cross-block AlreadyProcessed dedup (null when
    /// the status cache is dormant). Built fresh per produced block on the replay thread (inline-path only).
    const ProduceGateCtx = struct {
        bank: *Bank,
        state: *@import("block_produce").SeqGateState,
        allocator: std.mem.Allocator,
        recent_sigs: ?*const @import("block_produce").RecentSigCache,
        producing_slot: u64,
    };

    fn bankAdmitTxForBroadcast(ctx: *anyopaque, tx_wire: []const u8) bool {
        const block_produce = @import("block_produce");
        const gctx: *ProduceGateCtx = @ptrCast(@alignCast(ctx));
        const bank = gctx.bank;
        var ssig: [tx_ingest_mod.MAX_SIGNATURES][64]u8 = undefined;
        var skey: [tx_ingest_mod.MAX_SIGNATURES][32]u8 = undefined;
        const parsed = tx_ingest_mod.parse(tx_wire, &ssig, &skey) catch return false;

        // Extract the producing bank's recent (≤150) blockhash set into a stack buffer.
        var bh_buf: [150][32]u8 = undefined;
        const entries = bank.recent_blockhashes.constSlice();
        for (entries, 0..) |e, i| bh_buf[i] = e.blockhash.data;
        const bh_set = bh_buf[0..entries.len];

        // Extract the fee-payer account view (signer_keys[0]) from accounts_db at the parent's slot.
        // @prov:replay.fee-payer-account-lookup No DB ⇒
        // cannot validate ⇒ treat as absent (drops every tx → empty block, the safe fallback). This is
        // the PARENT-state balance; admitTxSeq seeds its running balance from it and tracks subsequent
        // fee debits by the same payer this block (the sequential fee-stacking drain).
        var fpv: ?block_produce.FeePayerView = null;
        if (bank.accounts_db) |adb| {
            const fee_payer_pk = core.Pubkey{ .data = parsed.signer_keys[0] };
            if (adb.getAccountInSlot(&fee_payer_pk, bank.slot, bank.ancestors())) |acct| {
                fpv = .{ .lamports = acct.lamports, .owner = acct.owner.data, .data_len = acct.data.len };
            }
        }

        // Delegate to the single test-rootable composed decision: cross-block AlreadyProcessed dedup
        // (gctx.recent_sigs, null when the status cache is dormant) THEN the sequential load/fee gate.
        // Centralizing the dedup in block_produce.admitTxSeqBroadcast is what makes it offline-KAT-
        // provable; the (rare) extra accounts_db lookup above on a duplicate tx is negligible.
        return block_produce.admitTxSeqBroadcast(gctx.allocator, gctx.state, parsed, tx_wire, bh_set, fpv, gctx.recent_sigs, gctx.producing_slot);
    }

    // ── PASS 3 (durable execute-once-and-record) LIVE adapters ────────────────────────────────────────
    // Feed block_produce.InclusionGate.execute a REAL accounts_db-backed executor so produceSlotBytes
    // packs a tx IFF it truly was_processed against live parent state (inclusion == execution), closing
    // the drain-chain + third-party-mover dead-block residuals the static whitelist path leaves open.
    // Wired ONLY on the inline/loopback produce path (the tile has no accounts_db reach — see :5353).
    // INERT while VEX_TPU_INGEST is unset (the tx-bearing pack branch is never entered).

    /// Load-on-demand backing for the produce-time BlockExecutor: fetch a touched account read-only from
    /// the producing (parent) bank's accounts_db at its slot — the SAME proven-safe read
    /// bankAdmitTxForBroadcast uses. `ctx` = *Bank (parent_bank). Returns null when the account is absent
    /// (no DB, or getAccountInSlot null on lamports==0) ⇒ the executor treats it as NotLoaded. `data` is
    /// intentionally EMPTY: the executor's System Transfer/CreateAccount(space=0) path never reads account
    /// data, so we avoid borrowing an AccountView.data slice whose lifetime we don't own. ISOLATION: this
    /// is read-only — the executor commits ONLY into its private overlay, never back to accounts_db.
    fn bankLoadAccountForBroadcast(ctx: ?*anyopaque, pubkey: [32]u8) ?@import("block_executor.zig").Account {
        const bank: *Bank = @ptrCast(@alignCast(ctx.?));
        const adb = bank.accounts_db orelse return null;
        const pk = core.Pubkey{ .data = pubkey };
        const acct = adb.getAccountInSlot(&pk, bank.slot, bank.ancestors()) orelse return null;
        return .{ .lamports = acct.lamports, .owner = acct.owner.data, .executable = acct.executable, .data = &.{} };
    }

    /// InclusionGate.execute adapter: execute-and-commit one candidate against the per-block overlay and
    /// return Agave was_processed() (the pack decision). `ctx` = *block_executor.BlockExecutor (per block).
    fn bankExecuteForBroadcast(ctx: *anyopaque, tx_wire: []const u8) bool {
        const block_executor = @import("block_executor.zig");
        const ex: *block_executor.BlockExecutor = @ptrCast(@alignCast(ctx));
        var ssig: [tx_ingest_mod.MAX_SIGNATURES][64]u8 = undefined;
        var skey: [tx_ingest_mod.MAX_SIGNATURES][32]u8 = undefined;
        const parsed = tx_ingest_mod.parse(tx_wire, &ssig, &skey) catch return false;
        return ex.executeAndCommit(parsed, tx_wire).wasProcessed();
    }

    /// leader_mode: produce an EMPTY (tick-only) block for our leader slot `next_slot`, broadcast it as
    /// shreds (via the wired callback), and loop the entry bytes back through replay so OUR OWN bank
    /// freezes. We mark the slot self-produced so onSlotFrozen does NOT submitVote it (G1: voting an own
    /// un-cluster-confirmed slot wedges the tower; the cluster's votes carry consensus on our block).
    /// Reuses the KAT-green block_produce; the broadcast callback uses the KAT-green block_broadcast.
    fn produceAndBroadcastEmptySlot(self: *Self, next_slot: u64, parent_slot: u64, parent_bank: *Bank) void {
        // Need the parent's SIMD-0340 block_id as the first FEC set's chained merkle root. If absent
        // (snapshot anchor), we cannot build a cluster-acceptable block → skip (slot stays skipped,
        // same as today; no orphan, no wasted broadcast).
        const chained: [32]u8 = parent_bank.block_id orelse {
            std.log.warn("[LEADER-PRODUCE] slot={d} skipped: parent block_id null (no chained root)", .{next_slot});
            return;
        };
        const sec = self.identity_secret orelse return;

        const block_produce = @import("block_produce");
        const seed = parent_bank.poh_hash.data;
        const broadcast_enabled = core.envFlagValueArmed(std.posix.getenv("VEX_LEADER_BROADCAST"));
        const tpu_ingest_on = std.posix.getenv("VEX_TPU_INGEST") != null;

        // task #25 SAFETY INTERLOCK (safe-by-construction, NOT env-discipline): tx-bearing packing is
        // permitted ONLY when broadcast is OFF (loopback validation). The per-tx admit predicate is a
        // PRE-FILTER, not a complete broadcast-safety boundary — the cluster executes a block
        // SEQUENTIALLY, so a tx that drains/closes a fee-payer earlier in the SAME block can make a
        // later tx InsufficientFundsForFee → NotLoaded → the cluster marks our whole block dead. The
        // complete boundary is execution-based (execute-during-pack OR loopback-replay-then-broadcast-
        // -only-if-not-dead) and is a FLIP-BLOCKER (task #25). Until it lands, broadcasting tx-bearing
        // bytes is forbidden: if both env flags are set we produce an EMPTY block (cluster-proven
        // accepted) + a loud error, so no tx-bearing shred can ever leave the host by accident.
        const want_tx_bearing = tpu_ingest_on and self.banking_stage != null;
        // task #26 FLIP (operator-authorized 2026-06-22): broadcast tx-bearing blocks on the INLINE path
        // when the explicit VEX_TXBEARING_BROADCAST gate is set. The inline gate is COMPLETE for honest
        // traffic — sigverify + blockhash-age + SEQUENTIAL fee-payer running-balance + in-block dedup +
        // cross-block AlreadyProcessed (RecentSigCache) + the cost-model block-CU ceiling
        // (produceSlotBytes CostTracker) — covering every BLOCK-FATAL replay class. RESIDUAL accepted by
        // operator: adversarial SAME-payer transfer-drain (an earlier tx in the SAME block transfers the
        // fee-payer's lamports away → a later tx is InsufficientFundsForFee → NotLoaded). It self-heals —
        // the cluster skips that ONE block and our own loopback flags it ([PRODUCE-PARITY-FAIL]); never
        // persistent. WITHOUT the explicit gate the original safe interlock holds (force EMPTY). Requires
        // the inline producer (VEX_FORCE_INLINE_PRODUCE); the produce TILE keeps its own force-empty
        // interlock (it has no live-bank deref for the gate; see :4163).
        // M3 (2026-07-17): the effective arm state is the operator's env flag AND NOT the auto-safe-off
        // tripwire (txbearing_tripwire.zig) — see that file for the full signal/threshold/latch design.
        // When the tripwire is tripped this collapses to the SAME force-EMPTY interlock as the flag
        // simply being unset, so a tripped process behaves byte-identically to a never-armed one from
        // this point on (until an operator restarts with the flags re-set).
        const txbearing_broadcast_env = std.posix.getenv("VEX_TXBEARING_BROADCAST") != null;
        const txbearing_broadcast = self.txbearing_tripwire_state.effectiveArmed(txbearing_broadcast_env);
        if (want_tx_bearing and broadcast_enabled and !txbearing_broadcast) {
            if (txbearing_broadcast_env) {
                std.log.err("[LEADER-PRODUCE] slot={d} tx-bearing+broadcast SUPPRESSED — M3 tripwire is TRIPPED (tripped_at_slot={d}) — producing EMPTY block instead. Re-arm requires an operator restart.", .{ next_slot, self.txbearing_tripwire_state.tripped_at_slot });
            } else {
                std.log.err("[LEADER-PRODUCE] slot={d} tx-bearing+broadcast BLOCKED (set VEX_TXBEARING_BROADCAST=1 to flip) — producing EMPTY block instead", .{next_slot});
            }
        }
        const pack_tx_bearing = want_tx_bearing and (!broadcast_enabled or txbearing_broadcast);
        // M3: track which self-produced slots actually packed drained txs (as opposed to an empty
        // tick-only block) — the tripwire's consecutive-fail counter only considers these (see
        // self_produced_tx_bearing's doc comment / txbearing_tripwire.zig's threshold reasoning).
        if (pack_tx_bearing) self.self_produced_tx_bearing.put(self.allocator, next_slot, {}) catch {};
        if (pack_tx_bearing and broadcast_enabled)
            std.log.warn("[LEADER-PRODUCE] slot={d} TX-BEARING BROADCAST ARMED — inline gate (pre-filter+cost); transfer-drain residual monitored via [PRODUCE-PARITY-FAIL] + M3 auto-safe-off tripwire", .{next_slot});
        const bytes = if (pack_tx_bearing) blk: {
            // Loopback-only tx-bearing path: pack drained txs through the SEQUENTIAL pre-filter
            // (sigverify + blockhash-age + fee-payer-can-pay using a RUNNING per-block balance, so the
            // sequential fee-stacking drain is caught) + in-block dedup. The block only loops back to
            // OUR bank (broadcast is off here), so an imperfect pre-filter can at worst waste our own
            // loopback slot — never a cluster-visible dead block. seq_state holds the running balances;
            // freed when this block's production completes.
            var seq_state = block_produce.SeqGateState{};
            defer seq_state.deinit(self.allocator);
            const sc: ?*const block_produce.RecentSigCache = if (self.statusCacheActive()) &self.recent_sig_cache else null;
            var gctx = ProduceGateCtx{ .bank = parent_bank, .state = &seq_state, .allocator = self.allocator, .recent_sigs = sc, .producing_slot = next_slot };
            // PASS 3 durable executor: a per-block execute-once-and-record overlay over parent_bank's
            // accounts_db (load-on-demand, read-only → isolation). When `.execute` is set, produceSlotBytes
            // packs a tx IFF was_processed after REAL execution (bypassing the static whitelist/admit),
            // closing the drain-chain + third-party-mover dead-block residuals. `admit` is retained as the
            // (unused-while-execute≠null) fallback shape. bh_buf/block_exec live through produceSlotBytes
            // below; block_exec.deinit frees the overlay when this block's production completes.
            const block_executor = @import("block_executor.zig");
            var block_exec = block_executor.BlockExecutor.init(self.allocator);
            defer block_exec.deinit();
            block_exec.load_ctx = parent_bank;
            block_exec.load_fn = bankLoadAccountForBroadcast;
            block_exec.recent_sigs = sc;
            block_exec.producing_slot = next_slot;
            // Arm blockhash-age validation from the producing bank's recent (≤150) blockhashes (a
            // stale-blockhash tx the cluster rejects would otherwise be packed → dead block).
            var bh_buf: [150][32]u8 = undefined;
            const bh_entries = parent_bank.recent_blockhashes.constSlice();
            for (bh_entries, 0..) |e, i| bh_buf[i] = e.blockhash.data;
            block_exec.known_blockhashes = bh_buf[0..bh_entries.len];
            const gate = block_produce.InclusionGate{
                .ctx = &gctx,
                .admit = bankAdmitTxForBroadcast,
                .exec_ctx = &block_exec,
                .execute = bankExecuteForBroadcast,
            };
            break :blk block_produce.produceSlotBytes(
                self.allocator,
                seed,
                block_produce.TESTNET_HASHES_PER_TICK,
                block_produce.TICKS_PER_SLOT,
                self.banking_stage.?,
                null,
                gate,
                block_produce.MAX_BLOCK_UNITS, // SIMD-0256 60M block-CU ceiling (cost-model pack stop)
            ) catch |e| {
                std.log.warn("[LEADER-PRODUCE] slot={d} produceSlotBytes failed: {any}", .{ next_slot, e });
                return;
            };
        } else block_produce.produceEmptySlotBytes(
            self.allocator,
            seed,
            block_produce.TESTNET_HASHES_PER_TICK,
            block_produce.TICKS_PER_SLOT,
            null,
        ) catch |e| {
            std.log.warn("[LEADER-PRODUCE] slot={d} produce failed: {any}", .{ next_slot, e });
            return;
        };
        defer self.allocator.free(bytes);

        // Mark self-produced BEFORE the loopback so the freeze handler skips self-voting it.
        self.self_produced.put(self.allocator, next_slot, {}) catch {};

        // Multi-slot leader-window chaining (2026-06-19): stash OUR produced last-FEC merkle root so
        // the NEXT slot of our window can chain to it (applied as this slot's bank.block_id at freeze,
        // replay_stage.zig freeze path). Computed REGARDLESS of broadcast (loopback needs it too).
        // Compute failure / unwired callback ⇒ no stash ⇒ slot N+1 skips, exactly as before.
        if (self.produce_blockid_fn) |bidf| {
            if (self.produce_broadcast_ctx) |ctx| {
                var bid: [32]u8 = undefined;
                if (bidf(ctx, bytes, next_slot, parent_slot, chained, sec, self.shred_version_bp, &bid))
                    self.self_produced_block_id.put(self.allocator, next_slot, bid) catch {};
            }
        }

        // STAGED ROLLOUT: the cluster-facing broadcast is the one irreversible step. Gate it behind
        // VEX_LEADER_BROADCAST (default OFF). When unset we still produce + loopback-freeze our own
        // block (validates the full produce → shred-able → self-replay-accept path with ZERO cluster
        // impact: no shreds leave the host). Operator flips VEX_LEADER_BROADCAST=1 only after a real
        // leader window confirms our parent block_id tracks the cluster (no CHAINED-BLOCK-ID-SHADOW
        // on the leader-parent slot ⇒ our chained_root is cluster-acceptable).
        if (broadcast_enabled) {
            if (self.produce_broadcast_fn) |f| {
                if (self.produce_broadcast_ctx) |ctx| {
                    f(ctx, next_slot, parent_slot, bytes, chained, sec, self.shred_version_bp);
                }
            }
        }

        // Loopback the SAME bytes so our own bank freezes (parent_override = parent_slot).
        const loop_copy = self.allocator.dupe(u8, bytes) catch return;
        if (!self.pushSlotForReplayWithParent(next_slot, loop_copy, parent_slot)) self.allocator.free(loop_copy);
        std.log.warn("[LEADER-PRODUCE] slot={d} parent={d} produced {d}B → {s} + loopback (no self-vote)", .{ next_slot, parent_slot, bytes.len, if (broadcast_enabled) "BROADCAST" else "loopback-only(no-bcast)" });
    }

    /// Fetch a recent blockhash from RPC for vote transaction envelopes.
    /// Caches for 6 seconds. @prov:replay.blockhash-cache-ttl
    /// d27ii (2026-05-11): reduced from 30s → 6s. Stale blockhash → cluster rejects
    /// vote with VoteTooOld (Custom=0).
    fn getRecentBlockhash(self: *Self) Hash {
        // throughput-fix #2: READ-ONLY on the replay/vote thread. Install any
        // pending result from the async refresher; never spawn curl here
        // except the one-shot cold-boot prime (cache empty AND no pending —
        // preserves first-vote behavior from before the split).
        {
            self.sysvar_fetch_lock.lock();
            defer self.sysvar_fetch_lock.unlock();
            if (self.pending_blockhash) |ph| {
                self.cached_blockhash = ph;
                self.cached_blockhash_time = self.pending_blockhash_time;
                self.pending_blockhash = null;
            }
        }
        if (self.cached_blockhash) |h| return h;
        // Cold-boot prime (once): synchronous fetch, same as pre-fix behavior.
        if (self.fetchRecentBlockhashRemote()) |hash| {
            self.cached_blockhash = hash;
            self.cached_blockhash_time = @as(i64, @intCast(std.time.timestamp()));
            return hash;
        }
        return Hash.ZERO;
    }

    /// Network half of the blockhash refresh — fork-exec curl + parse. NO
    /// cache writes; safe to call from any thread. Blocking (-m 3); intended
    /// for sysvarRefreshWorker (ops-lane) + the one-shot cold-boot prime.
    fn fetchRecentBlockhashRemote(self: *Self) ?Hash {
        const rpc_bh = self.genesis_rpc_fallback orelse "https://api.testnet.solana.com";
        // perf (2026-07-08): posix_spawn transport (no fork COW). curl writes
        // the response body to tmpfs (-o) instead of a pipe; the RPC request
        // bytes (-d body, URL, -m 3) are IDENTICAL to the prior fork+exec path.
        const out_path = "/dev/shm/vex-bh.json";
        const argv = [_][]const u8{
            "/usr/bin/curl", "-s",                             "-o", out_path,                                                           "-m",   "3", "-X", "POST",
            "-H",            "Content-Type: application/json", "-d", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getLatestBlockhash\"}", rpc_bh,
        };
        // Null-terminate each arg (runtime rpc_bh included) into a c_argv; free
        // the z-copies after waitpid. Any failure (dupe/spawn/curl-exit/read) →
        // return null, so the caller keeps its last cached value — exactly as
        // the fork+exec version degraded.
        var c_argv: [argv.len + 1]?[*:0]const u8 = undefined;
        var dupes: [argv.len][:0]u8 = undefined;
        var ndup: usize = 0;
        defer {
            for (dupes[0..ndup]) |s| self.allocator.free(s);
        }
        for (argv, 0..) |a, i| {
            const z = self.allocator.dupeZ(u8, a) catch return null;
            dupes[ndup] = z;
            ndup += 1;
            c_argv[i] = z.ptr;
        }
        c_argv[argv.len] = null;
        var empty_env = [_]?[*:0]const u8{null};
        var pid: std.c.pid_t = 0;
        const rc = posix_spawn(&pid, "/usr/bin/curl", null, null, @ptrCast(&c_argv), @ptrCast(&empty_env));
        if (rc != 0) return null;
        const wr = std.posix.waitpid(pid, 0);
        if (!std.posix.W.IFEXITED(wr.status) or std.posix.W.EXITSTATUS(wr.status) != 0) return null;

        // Read curl's response body back from tmpfs into the same-size buffer
        // the pipe read used; the parse below is UNCHANGED.
        var response_buf: [2048]u8 = undefined;
        const n = blk: {
            const f = std.fs.cwd().openFile(out_path, .{}) catch break :blk 0;
            defer f.close();
            break :blk f.readAll(&response_buf) catch 0;
        };
        if (n == 0) return null;
        const response = response_buf[0..n];

        // Parse blockhash from JSON: "blockhash":"<base58>"
        if (std.mem.indexOf(u8, response, "\"blockhash\":\"")) |idx| {
            const start = idx + 13; // len of "blockhash":"
            if (std.mem.indexOfPos(u8, response, start, "\"")) |end| {
                const b58 = response[start..end];
                if (b58.len >= 32 and b58.len <= 44) {
                    var decoded_buf: [32]u8 = undefined;
                    core.base58.decodeToBuf(b58, &decoded_buf) catch return null;
                    var hash: Hash = undefined;
                    @memcpy(&hash.data, &decoded_buf);
                    return hash;
                }
            }
        }
        return null;
    }

    /// Fetch the network's bank hash for a slot from the SlotHashes sysvar.
    /// The SlotHashes sysvar stores (slot, bank_hash) pairs for recent slots.
    /// Used for vote submissions until native parity is achieved.
    ///
    /// pub for the live-path regression gate (kat_revive_would_fire.zig,
    /// switch-proof Part 2 M1) — same "pub for KAT" rationale as
    /// sweepPendingTickGateSlots/verifyTicksKill elsewhere in this file: this
    /// is a real (if incidental, from the vote path) caller of the
    /// fetchSlotHashesRemote -> installSlotHashes -> sweepPendingTickGateSlots
    /// chain, letting the KAT drive VEX_SLOT_HASH_INJECT_FILE end-to-end
    /// through the REAL production call path rather than only the pure leaf.
    pub fn getNetworkBankHash(self: *Self, slot: Slot) ?Hash {
        const now = @as(i64, @intCast(std.time.timestamp()));

        // Refresh cache every 10 seconds (tightened to 5s per Phase G-2
        // attribution finding 2026-05-17: cluster's curl-cached SlotHashes
        // staleness was rejecting ~95% of votes; 5s TTL drops avg staleness
        // from ~75 slots to ~12 slots at 2.5 slots/sec cluster rate).
        //
        // throughput-fix #2: the network fetch moved to sysvarRefreshWorker
        // (ops lane); here we only INSTALL a pending buffer — which keeps the
        // install side-effects (free old, g_cluster publish, PR-5z/5ae/5ai
        // sweeps over replay-stage state) on the replay thread exactly as
        // before the split. Cold boot keeps the one-shot synchronous prime.
        const pending: ?[]u8 = blk: {
            self.sysvar_fetch_lock.lock();
            defer self.sysvar_fetch_lock.unlock();
            const p = self.pending_slot_hashes;
            self.pending_slot_hashes = null;
            break :blk p;
        };
        if (pending) |buf| {
            self.installSlotHashes(buf);
        } else if (self.cached_slot_hashes == null) {
            // Cold-boot prime (once): synchronous fetch+install, pre-fix shape.
            if (self.fetchSlotHashesRemote()) |buf| self.installSlotHashes(buf);
        }
        _ = now;

        return self.scanCachedSlotHash(slot);
    }

    /// Scan the *already-cached* cluster SlotHashes for `slot`'s bank_hash
    /// without triggering a refresh. SlotHashes maps slot → that slot's
    /// bank_hash, so a hit is the cluster's canonical bank_hash for the slot.
    /// Split out of getNetworkBankHash so markSlotDead's canonical-match guard
    /// (PR-5ah) can consult the cache without re-entering fetchSlotHashes
    /// (which itself can drive sweeps → markSlotDead → recursion).
    fn scanCachedSlotHash(self: *Self, slot: Slot) ?Hash {
        const data = self.cached_slot_hashes orelse return null;
        if (data.len < 8) return null;

        const count = std.mem.readInt(u64, data[0..8], .little);
        const max_entries = @min(count, (data.len - 8) / 40);

        // Search for our slot (entries are newest-first)
        for (0..max_entries) |i| {
            const off = 8 + i * 40;
            if (off + 40 > data.len) break;
            const entry_slot = std.mem.readInt(u64, data[off..][0..8], .little);
            if (entry_slot == slot) {
                var hash: Hash = undefined;
                @memcpy(&hash.data, data[off + 8 ..][0..32]);
                return hash;
            }
        }
        return null;
    }

    /// SELF-CONTAINED, THREAD-SAFE cluster-oracle "which slots were PRODUCED?"
    /// probe for the TVU repair thread (VEX_REPAIR_SKIP_ABANDONED). Returns the
    /// array of PRODUCED (non-skipped, rooted/confirmed) slots the CLUSTER reports
    /// in the inclusive range [lo, hi], or `null` if the query FAILED (curl/parse
    /// error). Caller OWNS + frees the returned buffer. An EMPTY (len==0) slice is
    /// a valid success meaning "no produced slots in that range" — distinct from a
    /// null failure.
    ///
    /// WHY getBlocks (the HISTORICAL is_skipped oracle, replacing the 512-slot
    /// SlotHashes window): a catch-up wedge stalls on a slot FAR behind the cluster
    /// tip (the real 419581196 wedge was ~4,500 slots back), OUTSIDE the cluster's
    /// cached SlotHashes window — so the old SlotHashes presence probe returned
    /// false for the wedge's neighbors and the fix never fired on its exact target.
    /// `getBlocks(lo, hi)` (Agave RPC) works for ANY historical range and is the
    /// direct analog of Agave `Blockstore::is_skipped` (ledger/src/blockstore.rs:4820,
    /// rc.1 == 4.1.0-rc.1): "lowest_root < slot < max_root AND slot has no root
    /// entry". A slot ABSENT from getBlocks' returned list (while the range is
    /// bounded by produced slots on both sides) is exactly a cluster-confirmed skip.
    ///
    /// SELF-CONTAINED: reads ONLY `self.genesis_rpc_fallback` (set once at
    /// bootstrap, immutable during run) and fork-execs curl — it touches NO
    /// mutable replay-stage state, so it is safe to call from the TVU repair
    /// thread with no lock. Mirrors the fetchSlotHashesRemote curl pattern.
    ///
    /// OFFLINE/GATE INJECTION: if the env `VEX_SKIP_CANON_FILE` is set, the
    /// produced-slot list is read from that STATIC file (one slot per line or CSV;
    /// blank lines / non-numeric tokens ignored) instead of curling live RPC. A
    /// 12h-old wedge slot is no longer in live getBlocks retention, so the
    /// offline-replay gate supplies the oracle-node-derived produced list here to make
    /// the abandon decision deterministic. When the env is UNSET, the live curl is
    /// used. The file is filtered to [lo, hi] so the caller's coverage logic is
    /// identical to the live path.
    ///
    /// RULE #1: the live RPC endpoint is `self.genesis_rpc_fallback orelse
    /// "https://api.testnet.solana.com"` — the PUBLIC testnet RPC ONLY, NEVER
    /// oracle-node (38.92.24.174). Identical to fetchSlotHashesRemote.
    pub fn fetchProducedSlots(self: *Self, lo: u64, hi: u64) ?[]u64 {
        if (hi < lo) return null;

        // ── OFFLINE/GATE PATH: static canon-slots file (VEX_SKIP_CANON_FILE) ──
        if (std.posix.getenv("VEX_SKIP_CANON_FILE")) |path| {
            const file = std.fs.cwd().openFile(path, .{}) catch return null;
            defer file.close();
            // Canon files are tiny (a neighborhood list); cap at 1 MiB.
            const contents = file.readToEndAlloc(self.allocator, 1 << 20) catch return null;
            defer self.allocator.free(contents);
            var out = std.ArrayListUnmanaged(u64){};
            errdefer out.deinit(self.allocator);
            // Tokenize on any non-digit separator (newline, comma, space, tab).
            var it = std.mem.tokenizeAny(u8, contents, " \t\r\n,");
            while (it.next()) |tok| {
                const v = std.fmt.parseInt(u64, tok, 10) catch continue;
                if (v >= lo and v <= hi) out.append(self.allocator, v) catch return null;
            }
            return out.toOwnedSlice(self.allocator) catch null;
        }

        // ── LIVE PATH: getBlocks RPC via curl (public testnet only) ──
        const rpc = self.genesis_rpc_fallback orelse "https://api.testnet.solana.com";
        var body_buf: [128]u8 = undefined;
        const body = std.fmt.bufPrint(
            &body_buf,
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlocks\",\"params\":[{d},{d}]}}",
            .{ lo, hi },
        ) catch return null;
        const argv = [_][]const u8{
            "/usr/bin/curl", "-s",                             "-m", "3",  "-X", "POST",
            "-H",            "Content-Type: application/json", "-d", body, rpc,
        };
        var child = std.process.Child.init(&argv, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch return null;

        var resp = std.ArrayListUnmanaged(u8){};
        defer resp.deinit(self.allocator);
        var read_buf: [16384]u8 = undefined;
        if (child.stdout) |*stdout| {
            while (true) {
                const n = stdout.read(&read_buf) catch break;
                if (n == 0) break;
                resp.appendSlice(self.allocator, read_buf[0..n]) catch {
                    _ = child.wait() catch {};
                    return null;
                };
            }
        }
        _ = child.wait() catch {};
        if (resp.items.len == 0) return null;

        // Parse the JSON `"result":[<u64>,...]` integer array. A `result` that is
        // null/absent/non-array (RPC error) → null (FAIL CLOSED).
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp.items, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const result = parsed.value.object.get("result") orelse return null;
        if (result != .array) return null;
        const arr = result.array;
        const out = self.allocator.alloc(u64, arr.items.len) catch return null;
        var i: usize = 0;
        for (arr.items) |item| {
            if (item != .integer) {
                self.allocator.free(out);
                return null;
            }
            out[i] = @intCast(item.integer);
            i += 1;
        }
        return out;
    }

    /// OFFLINE/GATE INJECTION helper for `VEX_SLOT_HASH_INJECT_FILE` (switch-proof
    /// Part 2, M1, 2026-07-16 — see SWITCHPROOF-PART2-IMPLEMENTATION-PLAN-2026-07-16.md
    /// §2 M1 gate note: "feed the offline SlotHashes cache ... if the replay driver
    /// doesn't organically populate it"). Both M1 gate incidents are days-old slots,
    /// outside the live ~512-slot SlotHashes sysvar window and replayed from a local
    /// ledger with no network reachable — this lets an offline gate run deterministically
    /// supply the cluster's bank_hash for a dead slot. Mirrors the existing
    /// `VEX_SKIP_CANON_FILE` offline-injection pattern in `fetchProducedSlots` above
    /// (same file, same "static file replaces the curl" shape).
    ///
    /// Parses "slot=<u64> hash=<base58>" tokens out of `path`, one slot per line;
    /// any other whitespace-delimited tokens on the line (e.g. the
    /// `signature_count=`/`total_data_len=` fields the forensics
    /// CANONICAL-HASHES.txt capture format already carries) are ignored, so that
    /// exact forensics file is consumable directly with no conversion step. Returns
    /// a buffer in the SAME wire shape `installSlotHashes` expects from the live RPC
    /// path (8-byte LE entry count + count * (8-byte LE slot, 32-byte hash)), or
    /// `null` on any read/parse/empty-result failure — the caller degrades exactly
    /// like a failed curl (keeps its last cached value). Read-only: touches no
    /// replay-stage state, allocates only the returned buffer + a scratch list it
    /// frees itself.
    ///
    /// Thin caller: file I/O only. The pure parse+encode logic lives in
    /// `revive_detect.zig` (independently KAT'd — see that file's tests).
    fn parseSlotHashInjectFile(self: *Self, path: []const u8) ?[]u8 {
        const file = std.fs.cwd().openFile(path, .{}) catch return null;
        defer file.close();
        // Forensics capture files are small (a handful to a few hundred lines);
        // cap at 1 MiB same as VEX_SKIP_CANON_FILE.
        const contents = file.readToEndAlloc(self.allocator, 1 << 20) catch return null;
        defer self.allocator.free(contents);

        const entries = revive_detect.parseSlotHashInjectContent(self.allocator, contents) catch return null;
        defer self.allocator.free(entries);

        return (revive_detect.encodeSlotHashBlob(self.allocator, entries) catch return null) orelse null;
    }

    /// Network half of the SlotHashes refresh — fork-exec curl + base64
    /// decode into a fresh owned buffer. NO cache writes, NO sweeps; safe to
    /// call from any thread (used by sysvarRefreshWorker + cold-boot prime).
    fn fetchSlotHashesRemote(self: *Self) ?[]u8 {
        // ── OFFLINE/GATE INJECTION (switch-proof Part 2, M1) — see
        // parseSlotHashInjectFile's doc comment above. When VEX_SLOT_HASH_INJECT_FILE
        // is unset (always true in production; not part of the deploy recipe), this
        // is a no-op and the live curl path below runs unchanged. Comptime-gated
        // with the rest of the M1 tap this scaffolding exists to gate.
        //
        // HARD-GATED to offline replay mode, unlike VEX_SKIP_CANON_FILE's precedent
        // (fetchProducedSlots above, value-gated only): cached_slot_hashes is wider
        // blast radius than the produced-slots list — it also feeds markSlotDead's
        // PR-5ah canonical-match guard, root-guard G2, and vote-hash selection, not
        // just this tap. Requiring VEX_LEDGER_REPLAY or VEX_SNAPSHOT_OFFLINE (the
        // SAME offline-mode detector main.zig itself uses, e.g. main.zig:228) means
        // a stray VEX_SLOT_HASH_INJECT_FILE set in a live/prod environment by
        // mistake is inert, not a live consensus-state override.
        if (comptime build_options.verify_ticks != .off) {
            const offline_mode = std.posix.getenv("VEX_LEDGER_REPLAY") != null or
                std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null;
            if (offline_mode) {
                if (std.posix.getenv("VEX_SLOT_HASH_INJECT_FILE")) |path| {
                    return self.parseSlotHashInjectFile(path);
                }
            }
        }

        // SysvarS1otHashes111111111111111111111111111
        const req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"SysvarS1otHashes111111111111111111111111111\",{\"encoding\":\"base64\",\"commitment\":\"processed\"}]}";
        const rpc_sh = self.genesis_rpc_fallback orelse "https://api.testnet.solana.com";
        // perf (2026-07-08): posix_spawn transport (no fork COW). curl writes
        // the response body to tmpfs (-o) instead of a pipe; the RPC request
        // bytes (-d req, URL, -m 3) are IDENTICAL to the prior fork+exec path.
        const out_path = "/dev/shm/vex-sh.json";
        const argv = [_][]const u8{
            "/usr/bin/curl", "-s",                             "-o", out_path, "-m",   "3", "-X", "POST",
            "-H",            "Content-Type: application/json", "-d", req,      rpc_sh,
        };
        // Null-terminate each arg (runtime rpc_sh included) into a c_argv; free
        // the z-copies after waitpid. Any failure (dupe/spawn/curl-exit/read) →
        // return null, so the caller keeps its last cached value — exactly as
        // the fork+exec version degraded.
        var c_argv: [argv.len + 1]?[*:0]const u8 = undefined;
        var dupes: [argv.len][:0]u8 = undefined;
        var ndup: usize = 0;
        defer {
            for (dupes[0..ndup]) |s| self.allocator.free(s);
        }
        for (argv, 0..) |a, i| {
            const z = self.allocator.dupeZ(u8, a) catch return null;
            dupes[ndup] = z;
            ndup += 1;
            c_argv[i] = z.ptr;
        }
        c_argv[argv.len] = null;
        var empty_env = [_]?[*:0]const u8{null};
        var pid: std.c.pid_t = 0;
        const rc = posix_spawn(&pid, "/usr/bin/curl", null, null, @ptrCast(&c_argv), @ptrCast(&empty_env));
        if (rc != 0) return null;
        const wr = std.posix.waitpid(pid, 0);
        if (!std.posix.W.IFEXITED(wr.status) or std.posix.W.EXITSTATUS(wr.status) != 0) return null;

        // SlotHashes can be up to ~20KB (512 entries × 40 bytes). Read curl's
        // response body back from tmpfs into the same-size buffer the pipe read
        // used; the base64 parse below is UNCHANGED.
        var resp_buf: [32768]u8 = undefined;
        const n = blk: {
            const f = std.fs.cwd().openFile(out_path, .{}) catch break :blk 0;
            defer f.close();
            break :blk f.readAll(&resp_buf) catch 0;
        };
        if (n == 0) return null;

        const resp = resp_buf[0..n];

        // Parse base64 data from JSON response: "data":["<base64>","base64"]
        if (std.mem.indexOf(u8, resp, "\"data\":[\"")) |idx| {
            const start = idx + 9;
            if (std.mem.indexOfPos(u8, resp, start, "\"")) |end| {
                const b64_data = resp[start..end];
                const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64_data) catch return null;
                const decoded = self.allocator.alloc(u8, decoded_len) catch return null;
                std.base64.standard.Decoder.decode(decoded, b64_data) catch {
                    self.allocator.free(decoded);
                    return null;
                };
                return decoded;
            }
        }
        return null;
    }

    /// Install half of the SlotHashes refresh — MUST run on the replay
    /// thread (frees the buffer scanCachedSlotHash reads, publishes the
    /// g_cluster fallback, and runs the PR-5z/5ae/5ai sweeps over
    /// replay-stage state). Takes ownership of `decoded`.
    fn installSlotHashes(self: *Self, decoded: []u8) void {
        if (self.cached_slot_hashes) |old| self.allocator.free(old);
        self.cached_slot_hashes = decoded;
        self.cached_slot_hashes_time = @intCast(std.time.timestamp());
        // Phase G-2 (2026-05-17): also publish into the module-level
        // global so executeVoteInstruction (a free fn without `self`
        // access) can use cluster's SlotHashes as a FALLBACK in
        // vote validation. This is the safer Phase G shape — Phase G
        // used cluster's view as PRIMARY which regressed during
        // catchup (cluster's 512-slot window doesn't cover old
        // slots). Fallback only kicks in when local check fails.
        {
            g_cluster_slot_hashes_lock.lock();
            defer g_cluster_slot_hashes_lock.unlock();
            g_cluster_slot_hashes = decoded;
        }
        // PR-5z: now that cluster's SlotHashes is fresh, sweep
        // SHADOW-pending slots for retroactive orphan confirmation.
        self.sweepPendingShadowSlots();
        // PR-5ae (2026-05-19): also sweep TICK-GATE-pending slots
        // for retroactive TooFewTicks confirmation via positive
        // canonical oracle (getNetworkBankHash).
        self.sweepPendingTickGateSlots();
        // PR-5ai (2026-05-20): sweep FEC-GATE-pending slots for
        // retroactive incomplete-final-FEC-set confirmation.
        self.sweepPendingFecGateSlots();
    }

    /// throughput-fix #2 worker: refreshes the blockhash (5s cadence) and
    /// SlotHashes (4s cadence) caches OFF the replay path, on the ops lane.
    /// Results land in pending_* under sysvar_fetch_lock; the replay thread
    /// installs them at its next getRecentBlockhash/getNetworkBankHash call.
    /// Lifecycle: spawned at stage start, joined in deinit via is_running.
    fn sysvarRefreshWorker(self: *Self) void {
        // Phase 9: default = vex_topo table (.sysvar == core 29, byte-identical);
        // VEX_LEGACY_PINS / -Dlegacy_pins reverts to the inline pinToCore(29).
        if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) {
            pinToCore(29);
        } else {
            _ = vex_topo.pinTile(vex_topo.LIVE, .sysvar, 0);
        }
        std.log.warn("[SYSVAR-REFRESH] worker started on ops-lane core 29\n", .{});
        var last_bh: i64 = 0;
        var last_sh: i64 = 0;
        while (self.is_running.load(.acquire)) {
            const now = @as(i64, @intCast(std.time.timestamp()));
            if (now - last_bh >= 5) {
                if (self.fetchRecentBlockhashRemote()) |hash| {
                    self.sysvar_fetch_lock.lock();
                    self.pending_blockhash = hash;
                    self.pending_blockhash_time = now;
                    self.sysvar_fetch_lock.unlock();
                }
                last_bh = now;
            }
            if (now - last_sh >= 4) {
                if (self.fetchSlotHashesRemote()) |buf| {
                    self.sysvar_fetch_lock.lock();
                    // Replace any unconsumed pending buffer (replay thread
                    // hasn't installed it yet) — free the stale one here;
                    // it was never visible outside the lock.
                    if (self.pending_slot_hashes) |stale| self.allocator.free(stale);
                    self.pending_slot_hashes = buf;
                    self.pending_slot_hashes_time = now;
                    self.sysvar_fetch_lock.unlock();
                }
                last_sh = now;
            }
            std.Thread.sleep(500 * std.time.ns_per_ms);
        }
        std.log.warn("[SYSVAR-REFRESH] worker stopped\n", .{});
    }

    /// PR-5z (2026-05-19, simplified 2026-05-27 Task #26): timeout sweep of
    /// SHADOW-flagged slots. The retroactive orphan-confirm path is gone
    /// (isKnownOrphanSlot removed — Agave-canonical doesn't query cluster
    /// SlotHashes for orphan confirmation). All pending entries are dropped
    /// after a 30s timeout (assume canonical, false-negative-preferred).
    ///
    /// Why retroactive (instead of pre-freeze defer): pre-freeze defer would
    /// block catchup whenever a SHADOW fires (~1 per ~200 slots in our soak),
    /// stalling progress. Retroactive lets the chain advance and only kills
    /// fork-orphan branches AFTER cluster confirms — at worst, we burn a
    /// few extra slots of work but the canonical chain stays alive.
    ///
    /// Closes the at-tip phantom-fork carrier where cluster's oracle is too
    /// stale at freeze time to confirm orphan (PR-5y handles only the case
    /// where cluster's cache HAPPENS to already have the entry).
    fn sweepPendingShadowSlots(self: *Self) void {
        const now = std.time.milliTimestamp();
        var i: usize = 0;
        while (i < self.pending_shadow_slots.items.len) {
            const entry = self.pending_shadow_slots.items[i];
            const age_ms = now - entry.flagged_at_ms;
            // Task #26 (2026-05-27): Agave-canonical removal. The
            // isKnownOrphanSlot retroactive-enforce branch is gone — Agave's
            // blockstore_processor.rs:2398 path never re-queries cluster's
            // SlotHashes to confirm orphan; it relies on fork-choice + replay
            // to converge naturally. Vexor's WIDEN-PROBE counter showed 0
            // events over 1183+ banks (Task #28 design threshold = 1000),
            // confirming the widen is dead weight. Keep only the 30s timeout
            // cleanup so pending entries don't accumulate; treat all entries
            // as "assume canonical" (false-negative-preferred). The shadow
            // queue itself is preserved because addPendingShadowSlot is still
            // called from the chained_block_id mismatch path (no behavior
            // change there yet — future cleanup can remove the queue entirely).
            if (age_ms > 30_000) {
                _ = self.pending_shadow_slots.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// PR-5ae (2026-05-19) — retroactive ENFORCE sweep for d28dd-flagged
    /// TICK-GATE slots. Called from `fetchSlotHashes` after each successful
    /// cluster SlotHashes refresh. For each pending entry:
    /// - If `getNetworkBankHash(slot) != null` (cluster's SH has a positive
    ///   entry for this slot → cluster considers it canonical with a complete
    ///   block) → markSlotDead retroactively + purgeUnrootedSlot (Vexor's
    ///   incomplete-tick freeze diverges from cluster's canonical block).
    /// - 30s timeout → drop (assume canonical, false-negative risk preferred
    ///   over false-positive mark-dead risk).
    ///
    /// Closes Carrier K (slot 409591733 in 2026-05-19 PR-5ad-probe boot):
    /// Vexor saw 61 ticks vs expected 64; froze 430 TXs vs cluster's 584;
    /// POH matched (shred-assembler POH) but lthash diverged → bank_hash
    /// divergence cascade. Cluster's SH should have positive entry for the
    /// canonical slot 1733, allowing retroactive kill within 30s window.
    ///
    /// pub for the live-path regression gate (kat_revive_would_fire.zig,
    /// switch-proof Part 2 M1) — same rationale as verifyTicksKill's own "pub
    /// for the live-path regression gate" doc comment elsewhere in this file:
    /// exercises the REAL driving path (this function, including the
    /// [REVIVE-WOULD-FIRE] tap added 2026-07-16) rather than only the pure
    /// predicate in revive_detect.zig.
    pub fn sweepPendingTickGateSlots(self: *Self) void {
        const now = std.time.milliTimestamp();
        var i: usize = 0;
        while (i < self.pending_tick_gate_slots.items.len) {
            const entry = self.pending_tick_gate_slots.items[i];
            const age_ms = now - entry.flagged_at_ms;
            // Re-check positive canonical oracle: slot IS in cluster's SH →
            // cluster has a complete canonical block at this slot → Vexor's
            // incomplete-tick freeze was wrong.
            if (self.getNetworkBankHash(entry.slot) != null) {
                std.log.warn(
                    "[TICK-GATE-RETROACTIVE-ENFORCE] slot={d} ticks_seen={d} cluster_confirms_canonical (age={d}ms) — markSlotDead (PR-5ah canonical-guard refuses if local hash matches)",
                    .{ entry.slot, entry.ticks_seen, age_ms },
                );
                self.markSlotDead(entry.slot, "TooFewTicks retroactive cluster confirmation");
                _ = self.pending_tick_gate_slots.swapRemove(i);
            } else if (age_ms > 30_000) {
                // Timeout: cluster's SH never showed positive entry within
                // 30s. Assume canonical (current SHADOW behavior). False-
                // negative risk: a truly-incomplete slot that cluster also
                // misses → both diverge but Vexor doesn't catch it. We
                // accept this risk to avoid FP-mark-dead.
                std.log.debug(
                    "[TICK-GATE-TIMEOUT-DROPPED] slot={d} ticks_seen={d} age={d}ms — assumed canonical",
                    .{ entry.slot, entry.ticks_seen, age_ms },
                );
                _ = self.pending_tick_gate_slots.swapRemove(i);
            } else {
                // Within 30s window, oracle hasn't confirmed yet. Keep.
                i += 1;
            }
        }

        // ── SWITCH-PROOF PART 2, M1 (2026-07-16) — READ-ONLY Shape-A revive
        // detection tap. SWITCHPROOF-PART2-IMPLEMENTATION-PLAN-2026-07-16.md
        // §1.1/§2 M1: reuses this same mandatory seam (this function already
        // runs on every cluster SlotHashes refresh, via installSlotHashes) as
        // the SECOND consumer of the cluster-oracle cache — the first being
        // the retroactive-ENFORCE loop just above. Predicate: a slot already
        // in the TERMINAL `dead_slots` set (markSlotDeadOne) for which
        // `scanCachedSlotHash` now resolves a cluster bank_hash. This is a
        // presence check, not a hash-mismatch check — a dead slot has no
        // local bank_hash to compare (the local bank never froze, §0 of the
        // plan). Logs `[REVIVE-WOULD-FIRE]` once per slot (dedup latch below)
        // and does NOTHING else: no dump, no repair request, no dead_slots
        // mutation, no assembler mutation, no fork-choice mutation. Byte-
        // identical binary behavior modulo this log line. Comptime-gated with
        // the SAME flag family as the dead_slots terminal guard itself
        // (replay onSlotCompleted, ~:3817) so a hypothetical verify_ticks
        // .off build stays byte-identical (net_opts hardcodes .zerohash
        // today, so this tap is always compiled in for every current build —
        // matching the dead_slots guard it mirrors).
        if (comptime build_options.verify_ticks != .off) {
            self.dead_slots_lock.lock();
            defer self.dead_slots_lock.unlock();
            var dead_it = self.dead_slots.keyIterator();
            while (dead_it.next()) |slot_ptr| {
                const dead_slot = slot_ptr.*;
                // Latch check FIRST, before the scan: scanCachedSlotHash is a
                // linear scan of up to 512 SlotHashes entries, and M1 never
                // removes anything from dead_slots — once a slot is logged,
                // re-scanning for it on every subsequent sweep (forever, for
                // as long as the slot stays dead) is pure waste on the
                // replay/sweep thread, under dead_slots_lock. On a real
                // incident with thousands of cascade-dead descendants (e.g.
                // 422359406's ~9.5k), that waste compounds every SlotHashes
                // refresh. Cheap map lookup short-circuits the scan.
                if (self.revive_would_fire_logged.contains(dead_slot)) continue;
                const cluster_hash = self.scanCachedSlotHash(dead_slot);
                // Pure decision (src/vex_svm/revive_detect.zig) — read-only;
                // the ONLY mutation below is the dedup-latch insert, which is
                // observational bookkeeping, not a decision path.
                const fire_hash = revive_detect.checkReviveWouldFire(
                    if (cluster_hash) |h| h.data else null,
                    false, // already checked above; kept explicit for the pure fn's own contract
                ) orelse continue;
                std.log.warn(
                    "[REVIVE-WOULD-FIRE] slot={d} cluster_hash={s} reason=dead-slot-terminal — Shape-A revive would fire here (M1 dark tap: detection only, no mutation)",
                    .{ dead_slot, &std.fmt.bytesToHex(fire_hash, .lower) },
                );
                self.revive_would_fire_logged.put(dead_slot, {}) catch {};
            }
        }

        // ── SWITCH-PROOF PART 2, M2 (2026-07-19) — ARMED Shape-A dead-slot REVIVE.
        // Consumes revive_repair.decideRevive at this same mandatory seam (the M1
        // dark tap above is detection-only). Gated by VEX_REVIVE_DEAD_SLOTS: when
        // OFF, reviveEnabled()==false → this whole block is skipped → the binary is
        // behavior-identical to M1 and the M1 KAT's zero-mutation invariant holds.
        //
        // Two PHASES, to avoid (a) mutating dead_slots under its own keyIterator and
        // (b) a reentrant dead_slots_lock (Mutex, non-reentrant → the dump's
        // dead_slots.remove under the same held lock would deadlock):
        //   PHASE A (collect): under dead_slots_lock, snapshot candidate (slot,
        //     resolved cluster hash) pairs. No mutation; lock released after.
        //   PHASE B (decide+act): OUTSIDE dead_slots_lock, read each slot's local
        //     bank (banks_lock.lockShared), run the PURE decision, and dispatch.
        //     reviveDeadSlotDump re-acquires banks_lock exclusive + dead_slots_lock
        //     FRESH (no nesting) — same collect-then-mutate discipline as the
        //     markSlotDeadOne cascade.
        if ((comptime build_options.verify_ticks != .off) and self.reviveEnabled()) {
            const Cand = struct { slot: u64, cluster_hash: ?[32]u8 };
            var candidates = std.ArrayList(Cand){};
            defer candidates.deinit(self.allocator);
            {
                self.dead_slots_lock.lock();
                defer self.dead_slots_lock.unlock();
                var dead_it = self.dead_slots.keyIterator();
                while (dead_it.next()) |slot_ptr| {
                    const ds = slot_ptr.*;
                    if (self.revive_gave_up.contains(ds)) continue; // permanently latched
                    const ch: ?[32]u8 = if (self.scanCachedSlotHash(ds)) |h| h.data else null;
                    candidates.append(self.allocator, .{ .slot = ds, .cluster_hash = ch }) catch continue;
                }
            }
            for (candidates.items) |cand| {
                const slot = cand.slot;
                // Read local bank state → LocalBank (banks_lock shared: mirrors
                // onSlotCompleted's lockShared read; the dump re-locks exclusive).
                const local: revive_repair.LocalBank = blk: {
                    self.banks_lock.lockShared();
                    defer self.banks_lock.unlockShared();
                    if (self.banks.get(slot)) |b| {
                        if (b.is_frozen) break :blk .{ .frozen = b.bank_hash.data };
                        break :blk .unfrozen;
                    }
                    break :blk .absent;
                };
                const attempts: u8 = self.revive_attempts.get(slot) orelse 0;
                const decision = revive_repair.decideRevive(.{
                    .flag_enabled = true,
                    .is_dead = true,
                    .cluster_hash = cand.cluster_hash,
                    .local = local,
                    .attempt_count = attempts,
                    .max_attempts = MAX_REVIVE_ATTEMPTS,
                });
                switch (decision) {
                    .proceed_dump_repair => {
                        // Structurally enforce "never dump without a wired kick":
                        // a dumped slot that can't be re-requested never refills, so
                        // an unwired kick makes the dump strictly worse than the stall.
                        const kick_fn = self.repair_kick_fn;
                        const kick_ctx = self.repair_kick_ctx;
                        if (kick_fn == null or kick_ctx == null) {
                            std.log.warn("[REVIVE-SKIP-NO-KICK] slot={d} — repair kick unwired; refusing dump (dump without kick is worse than the stall)", .{slot});
                            continue;
                        }
                        std.log.warn("[REVIVE-DUMP] slot={d} attempt={d}/{d} — Shape-A dump (banks.remove+clearCompletedSlot+dead_slots.remove) + requestHighestWindowIndex kick", .{ slot, attempts, MAX_REVIVE_ATTEMPTS });
                        self.reviveDeadSlotDump(slot);
                        kick_fn.?(kick_ctx.?, slot, 0);
                        self.revive_attempts.put(slot, revive_repair.recordAttempt(attempts)) catch {};
                    },
                    .give_up_exhausted => {
                        self.revive_gave_up.put(slot, {}) catch {};
                        std.log.warn("[REVIVE-GAVE-UP] slot={d} attempts={d}/{d} — bounded-retry exhausted; slot stays dead (guardian escalation)", .{ slot, attempts, MAX_REVIVE_ATTEMPTS });
                    },
                    .matches_cluster_no_repair => {
                        // Escape hatch (Agave DuplicateConfirmedSlotMatchesCluster):
                        // frozen local hash already == cluster → mark-dead was wrongly
                        // conservative. M2 = log only (un-dead is a fork-choice touch
                        // deferred with Shape B). Latch into revive_gave_up to suppress
                        // per-sweep re-logging (M2 will never act on it either way).
                        self.revive_gave_up.put(slot, {}) catch {};
                        std.log.warn("[REVIVE-MATCHES-CLUSTER] slot={d} — frozen local hash == cluster; M2 log-only (un-dead deferred with Shape B)", .{slot});
                    },
                    .refuse_not_shape_a => {
                        // Frozen local hash != cluster = genuine Shape B (equivocation /
                        // wrong-version), OUT of M2 scope. Refuse (never dump a frozen
                        // bank). Latch to suppress per-sweep re-logging; Shape-B recovery
                        // is the deferred Part 2b line.
                        self.revive_gave_up.put(slot, {}) catch {};
                        std.log.warn("[REVIVE-REFUSE-NOT-SHAPE-A] slot={d} — frozen local hash != cluster (Shape B); M2 refuses (no dump of frozen bank)", .{slot});
                    },
                    .no_action => {},
                }
            }
        }
    }

    /// PR-5ai (2026-05-20) — retroactive ENFORCE sweep for d27mm FEC-GATE
    /// SHADOW-flagged slots. Mirrors sweepPendingTickGateSlots exactly:
    /// `getNetworkBankHash(slot) != null` (positive cluster oracle) confirms
    /// the slot has a complete canonical block; Vexor's incomplete-final-FEC
    /// freeze is therefore lthash-divergent → retroactive markSlotDead + purge.
    /// 30s timeout drops without action (sibling slot we both miss is benign).
    /// Closes Carrier L (7 events in 2026-05-19 PR-5ad-probe boot).
    fn sweepPendingFecGateSlots(self: *Self) void {
        const now = std.time.milliTimestamp();
        var i: usize = 0;
        while (i < self.pending_fec_gate_slots.items.len) {
            const entry = self.pending_fec_gate_slots.items[i];
            const age_ms = now - entry.flagged_at_ms;
            if (self.getNetworkBankHash(entry.slot) != null) {
                std.log.warn(
                    "[FEC-GATE-RETROACTIVE-ENFORCE] slot={d} reason={s} cluster_confirms_canonical (age={d}ms) — markSlotDead (PR-5ah canonical-guard refuses if local hash matches)",
                    .{ entry.slot, entry.reason_tag, age_ms },
                );
                self.markSlotDead(entry.slot, "FEC-GATE retroactive cluster confirmation");
                _ = self.pending_fec_gate_slots.swapRemove(i);
            } else if (age_ms > 30_000) {
                std.log.debug(
                    "[FEC-GATE-TIMEOUT-DROPPED] slot={d} reason={s} age={d}ms — assumed canonical",
                    .{ entry.slot, entry.reason_tag, age_ms },
                );
                _ = self.pending_fec_gate_slots.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Check if we are the leader for a given slot.
    pub fn isLeader(self: *Self, slot: Slot) bool {
        if (self.getSlotLeader) |getLeader| {
            if (getLeader(slot)) |leader| {
                return std.mem.eql(u8, &leader.data, &self.identity.data);
            }
        }
        return false;
    }

    /// Enqueue a completed slot for the replay worker. Blocks (1ms back-off
    /// retry) when the SlotQueue is full — slot DROPS would break the chain
    /// (parent_bank_hash references), so back-pressure is mandatory. Returns
    /// false only on validator shutdown (is_running cleared) so the producer
    /// can free its buffer and exit.
    /// d24-filter (2026-05-11) — drop TVU pushes whose slot is more than
    /// `FAR_AHEAD_THRESHOLD` slots ahead of the current frozen tip. Such
    /// slots cannot connect (their parents won't be in `self.banks` until
    /// catchup or repair bridges the intermediate range), and pushing
    /// them floods the MPSC with future-slot defers, starving the queue
    /// of catchup's chain-extending slots. Dropped slots are eventually
    /// refetched via gossip retransmit (~600-slot cluster window) or
    /// repair-on-demand once the chain reaches them. Catchup's
    /// `pushSlotForReplayWithParent` bypasses this filter because catchup
    /// knows the authoritative parent and is by definition operating
    /// near the frozen tip.
    const FAR_AHEAD_THRESHOLD: u64 = 200;

    pub fn pushSlotForReplay(self: *Self, slot: Slot, data: []u8) bool {
        // d27mm-REVERTED: orphan-cascade removed (caused 351 dead-slot
        // cascades on a single torn-tail-FEC slot). dead_slots map is
        // kept but unused; markSlotDead is now a no-op gate.

        // 2026-05-27 FIX #46.2 — Agave-canonical drop check.
        // Compare against `accounts_db.rooted_slot` (tower-supermajority root,
        // updated only via db.advanceRoot at line 2745 when tower.vote_state.root_slot
        // advances) with STRICT `<`. This matches Agave `replay_stage.rs:4643`:
        //
        //     if slot < root { continue; }
        //
        // where `root = bank_forks.root()` is the consensus root, not the freeze tip.
        //
        // Previous bug (2026-05-27 wedge): the check used `self.root_bank.slot`,
        // which Vexor advances on EVERY freeze (line 2440) — making it the
        // working_bank (freeze tip) NOT the root_bank (consensus). When fork-choice
        // accepted a sibling-fork slot that advanced freeze tip past a canonical
        // slot we hadn't replayed yet, the canonical slot was dropped as "obsolete".
        //
        // db.rooted_slot starts at 0 (snapshot anchor); strict `<` means slot=0
        // can pass too. The whole check is bypassed if accounts_db isn't wired.
        // Byte-extractor cites: agave-4.0.0/runtime/src/bank_forks.rs:431
        // (BankForks::root advanced only in do_set_root, via tower) + replay_stage.rs:4643
        // (strict `<`) + ledger/src/blockstore.rs:5096 (verify_shred_slots).
        if (self.accounts_db) |db| {
            if (slot < db.rooted_slot) {
                const Dbg = struct {
                    var count: u32 = 0;
                };
                const n = Dbg.count;
                if (n < 50 or @mod(n, 1000) == 0) {
                    std.log.warn("[REPLAY-PUSH-DROP-BELOW-ROOT] slot={d} rooted_slot={d} count={d} (Agave-canonical: strict < consensus root)", .{ slot, db.rooted_slot, n });
                }
                Dbg.count = n + 1;
                if (data.len > 0) self.allocator.free(data);
                return true; // pretend success — buffer freed, caller continues
            }
        }

        if (self.root_bank.load(.acquire)) |rb| {
            if (slot > rb.slot + FAR_AHEAD_THRESHOLD) {
                // d27aa (2026-05-11): instead of dropping, defer to
                // pending_chain so the slot's assembled data is preserved
                // and the d27z chain-defer drain wakes it when chain
                // catches up to within the threshold. This closes the
                // bug observed after d27z: slot N completed early in the
                // run, FAR-AHEAD-DROP discarded the assembled buffer,
                // and when root_bank later advanced to N-1 the slot was
                // never re-pushed (shred_assembler still had the shreds
                // but nothing triggered a re-extraction). Per user "match
                // Agave canonical": Agave's blockstore accepts all shreds
                // regardless of root distance and `generate_new_bank_forks`
                // polls every replay iteration, so there's no equivalent
                // drop — the data just lives until the parent becomes
                // available. pending_chain mirrors that with a 5-min TTL
                // bound on memory.
                self.deferUnconnectedSlot(slot, data) catch |err| {
                    std.log.warn("[FAR-AHEAD-DEFER-FAIL] slot={d} err={any} — falling back to drop", .{ slot, err });
                };
                if (data.len > 0) self.allocator.free(data);
                const DropDbg = struct {
                    var count: u64 = 0;
                };
                DropDbg.count += 1;
                if (DropDbg.count <= 10 or DropDbg.count % 100 == 0) {
                    std.log.warn("[FAR-AHEAD-DEFER] slot={d} (frozen_tip={d}, gap={d}, threshold={d}) — deferred to pending_chain. count={d}", .{
                        slot, rb.slot, slot - rb.slot, FAR_AHEAD_THRESHOLD, DropDbg.count,
                    });
                }
                return true;
            }
        }
        return self.pushSlotForReplayWithParent(slot, data, null);
    }

    /// d24 (2026-05-11): like pushSlotForReplay but carries an authoritative
    /// parent_slot through to the replay worker (which sets the
    /// `catchup_parent_override` threadlocal before calling onSlotCompleted).
    /// Used by the background catchup thread so it can route through the
    /// same MPSC SlotQueue that TVU uses, preserving d17's invariant that
    /// replayWorker is the sole onSlotCompleted caller — no longer racing
    /// catchup's direct onSlotCompleted call against replayWorker's
    /// (which caused d17's heap corruption when both ran concurrently).
    /// Also bypasses the d24-filter FAR_AHEAD_THRESHOLD check — catchup
    /// is by definition operating sequentially just ahead of the frozen
    /// tip with an authoritative parent, so it should always be pushed.
    /// d27hh: convenience wrapper — TVU path that has per-component boundaries
    /// from the shred assembler should call this variant. Catchup-RPC path
    /// continues to use pushSlotForReplay/WithParent (boundaries empty → parser
    /// falls back to scan-forward).
    pub fn pushSlotForReplayWithBoundaries(self: *Self, slot: Slot, data: []u8, boundaries: []const usize) bool {
        // 2026-05-27 FIX #46.2 — Agave-canonical drop check (see pushSlotForReplay).
        // Strict `<` against tower-supermajority root `accounts_db.rooted_slot`.
        if (self.accounts_db) |db| {
            if (slot < db.rooted_slot) {
                const Dbg = struct {
                    var count: u32 = 0;
                };
                const n = Dbg.count;
                if (n < 50 or @mod(n, 1000) == 0) {
                    std.log.warn("[REPLAY-PUSH-BND-DROP-BELOW-ROOT] slot={d} rooted_slot={d} count={d} (Agave-canonical: strict < consensus root)", .{ slot, db.rooted_slot, n });
                }
                Dbg.count = n + 1;
                if (data.len > 0) self.allocator.free(data);
                if (boundaries.len > 0) self.allocator.free(boundaries);
                return true;
            }
        }
        if (self.root_bank.load(.acquire)) |rb| {
            if (slot > rb.slot + FAR_AHEAD_THRESHOLD) {
                // d28bb: preserve boundaries through deferral so they're
                // available when CHAIN-WAKE re-pushes.
                self.deferUnconnectedSlotWithBoundaries(slot, data, boundaries) catch |err| {
                    std.log.warn("[FAR-AHEAD-DEFER-FAIL] slot={d} err={any} — falling back to drop", .{ slot, err });
                };
                if (data.len > 0) self.allocator.free(data);
                if (boundaries.len > 0) self.allocator.free(boundaries);
                return true;
            }
        }
        const msg = SlotMessage{ .slot = slot, .data = data, .parent_override = null, .boundaries = boundaries };
        // 2026-05-28 FIX #77 — Drop-and-continue (FD-canonical). The prior
        // 64ms spin (PR-5ba) still blocked the TVU rx thread, which under
        // sustained back-pressure starved the AF_XDP fill ring (~28K
        // rx_xsk_buff_alloc_err/sec measured 2026-05-28 on FIX #72 binary).
        // @prov:replay.slot-queue-drop-policy Re-emission backstop:
        //   • TVU paths — shred_assembler retains assembly state; turbine
        //     retransmit + repair scheduler re-deliver shreds.
        //   • CATCHUP paths — outer driver retries on `failed += 1`.
        //   • CHAIN-WAKE/FAST-WAKE — repair scheduler refetches once the
        //     chain reaches the slot (rare collision because these paths
        //     fire sporadically, not at packet rate).
        // Sustained drops > ~10/sec = consumer throughput regression; short
        // bursts are normal. Drop counter at `stats.slot_queue_drops`.
        if (self.slot_queue.push(msg)) return true;
        const drops = self.stats.slot_queue_drops.fetchAdd(1, .monotonic) + 1;
        if (drops <= 50 or @mod(drops, 1000) == 0) {
            std.log.warn("[SLOT-QUEUE-DROP-BND] slot={d} drops_total={d} depth={d} bnd_len={d} (FIX #77 — FD-canonical drop)", .{
                slot, drops, self.slot_queue.count(), boundaries.len,
            });
        }
        return false;
    }

    /// Has `slot` been frozen by the replay worker? Polls `frozen_history`, the
    /// single canonical freeze-record point (populated in checkPendingChain AFTER
    /// bank.freeze() emits its [BANK-FROZEN] line, under pending_chain_lock). Used
    /// by the offline VexLedger read-driver (main.zig, -Dvex_ledger +
    /// VEX_LEDGER_REPLAY) to wait per-slot before feeding the next slot's shreds.
    /// Read-only, lock-guarded; safe to call from another thread. NOTE: entries
    /// below the consensus root are pruned by pruneOldBanks — fine for the driver,
    /// which polls a slot moments after dispatch (long before any root advance).
    pub fn slotFrozen(self: *Self, slot: Slot) bool {
        self.pending_chain_lock.lock();
        defer self.pending_chain_lock.unlock();
        return self.frozen_history.contains(slot);
    }

    /// True iff `slot` is currently in the dead_slots set. pub for the offline
    /// self-recovery gate (main.zig's VEX_LEDGER_REPLAY drive loop): after a
    /// force-dead kill the slot enters dead_slots, and the armed revive sweep's
    /// reviveDeadSlotDump removes it (its LAST of three dump steps, after
    /// banks.remove + clearCompletedSlot). The drive loop uses the
    /// dead→not-dead transition as the "dumped, safe to re-feed" signal. Same
    /// dead_slots_lock the sweep/dump use — no new synchronization.
    pub fn slotDead(self: *Self, slot: Slot) bool {
        self.dead_slots_lock.lock();
        defer self.dead_slots_lock.unlock();
        return self.dead_slots.contains(slot);
    }

    /// Build a SlotSink (Phase B.2 seam, 2026-07-08) — the narrow type-erased
    /// interface tvu holds instead of a raw *ReplayStage. See vex_network.SlotSink.
    /// Behavior-identical to the direct pointer; lets Phase C relocate the fields
    /// tvu reads (root_bank / accounts_db) without touching the network layer.
    pub fn slotSink(self: *Self) @import("vex_network").SlotSink {
        return .{ .ctx = self, .vtable = &slot_sink_vtable };
    }

    inline fn sinkCast(ctx: *anyopaque) *Self {
        return @ptrCast(@alignCast(ctx));
    }

    const slot_sink_vtable = @import("vex_network").SlotSink.VTable{
        .pushSlotForReplayWithBoundaries = struct {
            fn f(ctx: *anyopaque, slot: Slot, data: []u8, boundaries: []const usize) bool {
                return sinkCast(ctx).pushSlotForReplayWithBoundaries(slot, data, boundaries);
            }
        }.f,
        .collectOrphanTargets = struct {
            fn f(ctx: *anyopaque, allocator: std.mem.Allocator, max: usize) anyerror![]u64 {
                return sinkCast(ctx).collectOrphanTargets(allocator, max);
            }
        }.f,
        .fetchProducedSlots = struct {
            fn f(ctx: *anyopaque, lo: u64, hi: u64) ?[]u64 {
                return sinkCast(ctx).fetchProducedSlots(lo, hi);
            }
        }.f,
        .setShredAssembler = struct {
            fn f(ctx: *anyopaque, sa: *@import("vex_network").shred_pub.ShredAssembler) void {
                sinkCast(ctx).setShredAssembler(sa);
            }
        }.f,
        .rootBank = struct {
            fn f(ctx: *anyopaque) ?*Bank {
                return sinkCast(ctx).root_bank.load(.acquire);
            }
        }.f,
        .accountsDb = struct {
            fn f(ctx: *anyopaque) ?*@import("vex_store").accounts.AccountsDb {
                return sinkCast(ctx).accounts_db;
            }
        }.f,
        .takeContinuationRepair = struct {
            fn f(ctx: *anyopaque) ?Slot {
                return sinkCast(ctx).takeContinuationRepair();
            }
        }.f,
    };

    /// fix/chain-defer-tip-guard: atomically take (and clear) a continuation slot
    /// the CHAIN-WAKE fallback flagged for repair (its evicted bytes were gone).
    /// tvu's repair cycle drains this and issues a window re-fetch. Lock-free
    /// swap; 0 ⇒ nothing pending.
    pub fn takeContinuationRepair(self: *Self) ?Slot {
        const s = self.continuation_repair_needed.swap(0, .acq_rel);
        return if (s == 0) null else s;
    }

    pub fn pushSlotForReplayWithParent(self: *Self, slot: Slot, data: []u8, parent_override: ?u64) bool {
        const msg = SlotMessage{ .slot = slot, .data = data, .parent_override = parent_override };
        // 2026-05-28 FIX #77 — Drop-and-continue. @prov:replay.slot-queue-drop-policy
        // Prior unbounded spin held the TVU rx thread + catchup driver indefinitely
        // on full queue; in catchup, the driver itself can stall and freeze the
        // AF_XDP fill-ring refill. Callers (`tvu.zig`, `replay_stage` CHAIN-WAKE /
        // FAST-WAKE, catchup parallel + sequential) all free buffer on `false`.
        if (self.slot_queue.push(msg)) {
            std.log.debug("[REPLAY-TILE] Queued slot {d} ({d} bytes, queue depth ~{d})\n", .{
                slot, data.len, self.slot_queue.count(),
            });
            return true;
        }
        const drops = self.stats.slot_queue_drops.fetchAdd(1, .monotonic) + 1;
        if (drops <= 50 or @mod(drops, 1000) == 0) {
            std.log.warn("[SLOT-QUEUE-DROP-PARENT] slot={d} drops_total={d} depth={d} parent_override={?d} (FIX #77 — FD-canonical drop)", .{
                slot, drops, self.slot_queue.count(), parent_override,
            });
        }
        return false;
    }

    /// verify_ticks canonical (feat/verify-ticks-canonical-zig-2026-06-19):
    /// kill a slot that failed the block tick-validity check. The caller MUST
    /// `return error.BadBlockTickValidity` right after, which propagates up
    /// through `replayEntries` (:4759) to `onSlotCompleted`'s catch at the
    /// `self.replayEntries(...) catch { return; }` site (~:2920) — that `return`
    /// is taken BEFORE `bank.freeze()` (~:3287), so the slot is NEVER frozen,
    /// never gets a real bank_hash, and is never voted.
    ///
    /// WHY THIS REACHES FORK CHOICE (the audit point): the vote-prevention is
    /// "abort-before-freeze + dead_slots membership", NOT fork_choice
    /// invalidation. `markSlotDead` on an unfrozen slot is a near-no-op for the
    /// fork_choice update (it builds SlotHashKey{slot, bank_hash=0} which matches
    /// no real fork_info entry), but the slot is recorded in `dead_slots`, and
    /// onSlotCompleted's verify_ticks guard returns early for any dead slot on
    /// re-delivery — so the slot can never be replayed/frozen/voted later either.
    /// The bank also stays in `self.banks` unfrozen, so the existing
    /// `banks.get(slot)` early-return also blocks re-entry. The slot's children
    /// orphan naturally (no frozen parent → getOrCreateBank UnconnectedSlot
    /// defer). @prov:replay.bank-tree-invariant
    ///
    /// `markSlotDead`'s canonical-match guard (:2011) is correctly bypassed here:
    /// the bank is unfrozen so its bank_hash is still zero and can never equal the
    /// cluster's nonzero SlotHash → the guard falls through to the real kill. This
    /// also means `full` mode has NO false-positive safety net at reject time —
    /// which is exactly why `zerohash` (provably cannot false-reject a valid
    /// block) is the safe production default and `full` is parity-soaked first.
    /// verify_ticks Alpenglow scaffold (feat/verify-ticks-canonical-zig-2026-06-19).
    /// @prov:replay.alpenglow-tick-scaffold — alpenglow blocks use the AlpenTick /
    /// BlockFooterV1 structure, not classic PoH ticks, so the classic
    /// tick-validity checks do not apply. No canonical Firedancer port exists
    /// (FD does not implement Alpenglow); Vexor has no migration-state machinery yet, so when
    /// `-Dalpenglow=false` (default) this is hard-stubbed to ALWAYS false — i.e.
    /// no block is ever treated as alpenglow, so verify_ticks runs for every slot
    /// exactly as today. When `-Dalpenglow=true` the function still returns false
    /// (a compile-checked scaffold) with a TODO for the real migration-state
    /// lookup. Comptime-gated so a default (verify_ticks .off) build is unaffected.
    fn isAlpenglowBlock(self: *Self, slot: Slot) bool {
        _ = self;
        _ = slot;
        if (comptime build_options.alpenglow) {
            // TODO(alpenglow migration): replace with the real migration-state
            // lookup — return true iff the migration has succeeded AND
            // slot > genesis_cert slot. @prov:replay.alpenglow-tick-scaffold
            // Until that machinery exists, no block
            // is alpenglow, so verify_ticks runs for every slot (safe default).
            return false;
        }
        return false;
    }

    /// OFFLINE-ONLY diag (build_options.force_dead_slot; comptime-dead in prod):
    /// parse VEX_FORCE_DEAD_SLOT once (cached) into the target slot to synthetically
    /// mark dead+truncated (Shape A) so the switch-proof Part-2 offline self-recovery
    /// gate is runnable on a CLEAN slot without a fresh live incident. When the build
    /// flag is off this is comptime `return null` and the sole caller's `if (comptime
    /// build_options.force_dead_slot)` guard makes the whole hook comptime-dead — the
    /// deploy binary never carries the slot-killer. Same cached-parse shape as
    /// switchProofVoterDiagEnabled; unset/blank/unparseable → null (no injection).
    fn forceDeadSlotTarget(self: *Self) ?u64 {
        _ = self;
        if (comptime !build_options.force_dead_slot) return null;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var target: ?u64 = null;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_FORCE_DEAD_SLOT")) |s| {
                const trimmed = std.mem.trim(u8, s, " \t\r\n");
                Cache.target = std.fmt.parseInt(u64, trimmed, 10) catch null;
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.target;
    }

    /// pub for the live-path regression gate (kat_mark_dead_cascade.zig):
    /// exercises the REAL verify_ticks driving path (verifyTicksKill →
    /// markSlotDead → cascade) on an unfrozen slot, not just the pure Verifier.
    pub fn verifyTicksKill(self: *Self, bank: *Bank, reason: []const u8) void {
        std.log.warn(
            "[VERIFY-TICKS-DEAD] slot={d} parent={?d} hashes_per_tick={d} ticks_per_slot={d} reason={s} — canonical block tick-validity reject (FD verify_ticks)",
            .{ bank.slot, bank.parent_slot, bank.hashes_per_tick, bank.ticks_per_slot, reason },
        );
        self.markSlotDead(bank.slot, reason);
    }

    /// Switch-proof Part 2, M2 — the 3-action Shape-A dead-slot DUMP (plan §1.2;
    /// armed VEX_REVIVE_DEAD_SLOTS path only). The caller has already confirmed
    /// decideRevive == .proceed_dump_repair (so the local bank is unfrozen-or-absent,
    /// never frozen) AND that a repair kick is wired (a dump without a kick is
    /// strictly worse than the stall). Runs on the replay/sweep thread. Three
    /// removals:
    ///   1. banks.remove under EXCLUSIVE banks_lock — must not race
    ///      onSlotCompleted's banks_lock.lockShared read. The removed *Bank is
    ///      intentionally NOT returned to the pool / destroyed: an aborted unfrozen
    ///      bank is cheap, this path is rare + bounded (<= MAX_REVIVE_ATTEMPTS), and
    ///      reusing/freeing a bank that a since-released reader saw is riskier than
    ///      the small leak. (Under the exclusive lock no reader holds it now.)
    ///   2. assembler.clearCompletedSlot — drops the truncated assembly state so
    ///      repair re-collects fresh (internally mutexed; thread-agnostic).
    ///   3. dead_slots.remove under dead_slots_lock.
    /// These three removals ARE the single-shot re-arm: onSlotCompleted's
    /// banks.get + dead_slots.contains terminal guards both pass again on
    /// re-delivery, so the repaired slot re-replays through the UNMODIFIED Part-1
    /// tick-gate/contiguity gates. revive_attempts is NOT touched here (the caller
    /// bumps it) so a repaired-but-still-truncated re-fail is bounded toward give-up.
    fn reviveDeadSlotDump(self: *Self, slot: Slot) void {
        {
            self.banks_lock.lock();
            defer self.banks_lock.unlock();
            _ = self.banks.remove(slot);
        }
        if (self.shred_assembler) |sa| sa.clearCompletedSlot(slot);
        {
            self.dead_slots_lock.lock();
            defer self.dead_slots_lock.unlock();
            _ = self.dead_slots.remove(slot);
        }
    }

    /// d21: defer a slot whose parent isn't connected yet.
    /// d27mm-followup (2026-05-11): Mark a slot dead. @prov:replay.mark-dead-slot-cascade
    /// Records into dead_slots,
    /// removes any pending_chain entry for this slot, and cascades the orphan:
    /// any pending entry whose target_parent == this slot is also marked dead
    /// (because its parent is unreachable). The cascade is ITERATIVE (worklist,
    /// see the 2026-06-19 fix below) so its cost is bounded by the number of
    /// currently-pending entries but its STACK depth is O(1).
    ///
    /// Mark a slot dead and CASCADE to every pending orphan whose ancestry is
    /// now unreachable.
    ///
    /// 2026-06-19 (feat/verify-ticks-canonical-zig) STACK-OVERFLOW FIX: the
    /// cascade was previously a genuine recursion (`self.markSlotDead(child)`
    /// per orphan). On a long LINEAR orphan chain in `pending_chain` (normal
    /// during catchup), recursion depth == chain length, each level carrying
    /// markSlotDead's full frame. The verify_ticks `zerohash` kill is the only
    /// mark-dead caller that fires from DEEP inside `replayEntriesInternal`
    /// (verifyTicksKill at :5345/:6238), so the cascade stacked on top of that
    /// giant frame and overflowed the replay-worker stack → SIGSEGV (confirmed
    /// by `test-mark-dead-cascade`: gdb showed `zig_probe_stack`→`??? 0x0`, the
    /// guard-page fault, on a single thread). FIX = drive the cascade with an
    /// EXPLICIT FIFO worklist (O(1) stack depth) instead of recursion. The
    /// per-slot side-effects (dead_slots insert, purgeUnrootedSlot, fork_choice
    /// mark-invalid, own pending_chain removal, recorder) are UNCHANGED and
    /// still fire exactly once per dead slot — only the traversal shape changed
    /// (depth-first recursion → breadth-first worklist, behaviorally equivalent
    /// because each slot's effects are independent + the dead_slots set
    /// dedupes).
    /// One unit of cascade work: a slot to mark dead + the reason string. The
    /// reason is always a static literal (callers + the cascade constant), so
    /// storing the slice is lifetime-safe across the worklist's lifetime.
    pub const DeadWorkItem = struct { slot: Slot, reason: []const u8 };

    /// Geyser Stage 1a slot-status emit. comptime-dead unless build_options.geyser; wait-free (the
    /// callback does a single SPSC push, drop-on-full). status: processed=0, rooted=2, dead=3.
    /// NON-consensus (observation-only) — never touches bank state.
    inline fn emitGeyserSlot(self: *Self, slot: u64, parent: ?u64, status: u8) void {
        if (comptime build_options.geyser) {
            if (self.geyser_slot_fn) |f| {
                const ctx = self.geyser_ctx orelse return;
                f(ctx, slot, parent orelse 0, parent != null, status);
            }
        }
    }

    pub fn markSlotDead(self: *Self, slot: Slot, reason: []const u8) void {
        self.emitGeyserSlot(slot, null, 3); // geyser: SlotStatus.dead
        // Explicit cascade worklist (replaces the prior recursion). FIFO of
        // DeadWorkItem.
        var worklist = std.ArrayList(DeadWorkItem){};
        defer worklist.deinit(self.allocator);
        // Seed; if the initial append OOMs, fall back to a single in-place mark
        // (no cascade) so we never silently skip the primary dead slot.
        worklist.append(self.allocator, .{ .slot = slot, .reason = reason }) catch {
            _ = self.markSlotDeadOne(slot, reason, null);
            return;
        };

        var wi: usize = 0;
        while (wi < worklist.items.len) : (wi += 1) {
            const item = worklist.items[wi];
            // markSlotDeadOne does ALL the per-slot work and appends this slot's
            // orphan children (target_parent == item.slot) to `worklist` for
            // iterative processing — no recursion, so stack depth is bounded by 1
            // regardless of the orphan-chain length.
            _ = self.markSlotDeadOne(item.slot, item.reason, &worklist);
        }
    }

    /// Per-slot half of markSlotDead: performs ALL side-effects for ONE dead
    /// slot and (if `out_worklist` is non-null) appends its pending orphans for
    /// the caller's iterative cascade. Returns true if the slot was newly marked
    /// dead (false if it was the canonical-guard no-op or already-dead). This is
    /// the EXACT body of the old recursive markSlotDead minus the recursive tail.
    fn markSlotDeadOne(
        self: *Self,
        slot: Slot,
        reason: []const u8,
        out_worklist: ?*std.ArrayList(DeadWorkItem),
    ) bool {
        // PR-5ah (2026-05-24) — Canonical-match guard. NEVER purge a slot whose
        // locally-replayed bank_hash equals the cluster's canonical bank_hash
        // (SlotHashes maps slot → bank_hash). If they match, this slot IS the
        // cluster's block and killing it would orphan a canonical slot and seed
        // bank_hash divergence — the boot-2 (`leader-skip-from-canonical-parent_off`)
        // and boot-3 (`FEC-GATE retroactive`) carriers both did exactly this to
        // canonical slots that Vexor had already replayed correctly. The mark-dead
        // sites use "cluster HAS the slot" as their kill trigger, but cluster
        // having the slot is normal for every canonical slot — the missing test
        // is whether OUR replay actually diverged. Only frozen slots present in
        // the cached cluster SlotHashes are guarded; unfrozen/skipped slots (no
        // local bank, or absent from cluster SH = genuinely skipped) and slots
        // whose local hash truly diverges fall through to the real kill path.
        // Cache-only lookup (no fetch) to avoid re-entering fetchSlotHashes →
        // sweeps → markSlotDead recursion.
        if (self.banks.get(slot)) |local_bank| {
            if (self.scanCachedSlotHash(slot)) |cluster_hash| {
                if (std.mem.eql(u8, &local_bank.bank_hash.data, &cluster_hash.data)) {
                    std.log.warn(
                        "[DEAD-SLOT-CANONICAL-GUARD] slot={d} reason={s} — local bank_hash matches cluster canonical SlotHashes; refusing mark-dead (false-positive avoided)",
                        .{ slot, reason },
                    );
                    return false;
                }
            }
        }

        // Insert into dead_slots
        {
            self.dead_slots_lock.lock();
            defer self.dead_slots_lock.unlock();
            const gop = self.dead_slots.getOrPut(slot) catch return false;
            if (gop.found_existing) return false; // already marked, avoid cascade re-entry
        }
        std.log.warn("[REPLAY-DEAD-SLOT] slot={d} reason={s} — Agave canonical mark-dead", .{ slot, reason });
        // Recorder-extension 2026-05-17: emit structured dead-slot event so
        // the oracle can correlate Phase J/I fires + cascade chains with
        // first-divergent slots without grepping stdlog. `target_parent`
        // is null here — cascade events are emitted at the cascade site
        // below with the dying parent slot filled in.
        vex_store.recorder.emitDeadSlot(slot, reason, null);

        // Fork-isolation: purge this slot's writes from accounts_db unrooted
        // overlay so the canonical fork never reads its (likely-orphan) pre-state.
        // No-op when VEX_FORK_ISOLATION is disabled.
        if (self.accounts_db) |db| db.purgeUnrootedSlot(slot);

        // 2026-05-28 FIX #87 — Wire fork-choice mark-fork-invalid.
        //
        // @prov:replay.fork-choice-mark-invalid — without this update, fork-choice
        // retains the dead subtree at full weight and bestOverallSlot keeps
        // selecting the dead branch as canonical → validator wedges.
        //
        // Wedge observed 2026-05-28 ~05:00 UTC: slot 411405258 phantom-frozen,
        // markSlotDead added it to dead_slots set but fork-choice didn't update
        // → fork-choice still pointed at the dead branch → gap widened 2.5
        // slots/sec until manual intervention.
        //
        // We look up the local bank's bank_hash to construct SlotHashKey
        // (slot, hash). If the bank doesn't exist (slot was never frozen),
        // we skip — fork-choice has no entry for an unfrozen slot anyway.
        if (self.fork_choice) |*fc| {
            // 2026-06-19 (verify_ticks): guard on `is_frozen`, not just bank
            // presence. The verify_ticks `zerohash`/`full` kill targets an
            // UNFROZEN bank mid-replay — it IS present in `self.banks` but its
            // bank_hash is still all-zeros (not yet computed). fork_choice only
            // ever holds an entry for a FROZEN slot (addForkCompat runs at
            // freeze with the real hash), so an unfrozen kill's
            // markForkInvalidCandidate({slot, hash=0}) is a guaranteed no-op
            // (key absent → early return). Skipping it explicitly avoids the
            // pointless call + warn-log spam and documents that the unfrozen
            // kill path (verify_ticks-exclusive) intentionally does NOT touch
            // fork_choice. Frozen-slot kills (all other callers) are unchanged.
            if (self.banks.get(slot)) |local_bank| {
                if (local_bank.is_frozen) {
                    const fc_mod = @import("vex_consensus").fork_choice;
                    const key = fc_mod.SlotHashKey{
                        .slot = slot,
                        .hash = local_bank.bank_hash,
                    };
                    fc.markForkInvalidCandidate(key);
                } else {
                    // Unfrozen (e.g. verify_ticks kill before freeze): no
                    // fork_info entry exists (bank_hash==0); skip.
                    std.log.debug(
                        "[markSlotDead] slot={d} present but UNFROZEN (bank_hash=0); skipping fork_choice update",
                        .{slot},
                    );
                }
            } else {
                // Slot was never frozen — no fork_info entry exists.
                // No-op; fork-choice already excludes the slot from selection.
                std.log.debug(
                    "[markSlotDead] slot={d} not in banks (never frozen); skipping fork_choice update",
                    .{slot},
                );
            }
        }

        // Remove this slot's own pending_chain entry if present (it's now dead, not pending)
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            if (self.pending_chain.fetchRemove(slot)) |kv| {
                if (kv.value.data.len > 0) self.allocator.free(kv.value.data);
            }
        }

        // Cascade: collect all pending entries whose target_parent == slot.
        // Do collection under lock, then ENQUEUE each onto the caller's
        // worklist OUTSIDE the lock (no recursion — the worklist driver in
        // markSlotDead processes them iteratively, so we never hold the
        // pending_chain_lock across a nested mark and never grow the stack).
        var orphans = std.ArrayList(u64){};
        defer orphans.deinit(self.allocator);
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            var it = self.pending_chain.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.target_parent == slot) {
                    orphans.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }
        }
        for (orphans.items) |child| {
            // Phase J-2 (2026-05-17): trace each cascade for diagnosing
            // future stalls. dead_parent is the slot just marked dead;
            // child's pending_chain entry pointed at it via target_parent.
            std.log.warn("[CASCADE] killing slot={d} (target_parent={d} just died: {s})", .{ child, slot, reason });
            // Recorder: also emit with target_parent set so structured
            // analysis can follow the cascade chain back to its root cause.
            vex_store.recorder.emitDeadSlot(child, "cascade_orphan_of_dead_parent", slot);
            // ITERATIVE cascade (2026-06-19 stack-overflow fix): enqueue the
            // orphan onto the worklist instead of `self.markSlotDead(child)`.
            // If there is no worklist (the OOM single-mark fallback path) the
            // cascade is intentionally skipped — the primary slot is still
            // marked, and orphans GC out of pending_chain on the root advance.
            if (out_worklist) |wl| {
                wl.append(self.allocator, .{ .slot = child, .reason = "cascade_orphan_of_dead_parent" }) catch {
                    // On OOM we cannot enqueue further cascade; the orphan stays
                    // in pending_chain and is reaped by the GC backstop. Better
                    // than recursing (the bug we are fixing).
                };
            }
        }
        return true;
    }

    /// Copies the assembled data into pending_chain so it survives the caller's
    /// free. checkPendingChain re-pushes when parent freezes.
    fn deferUnconnectedSlot(self: *Self, slot: Slot, assembled_data: []const u8) !void {
        return self.deferUnconnectedSlotWithBoundaries(slot, assembled_data, &.{});
    }

    /// d28bb (2026-05-12): same as deferUnconnectedSlot but also preserves
    /// the per-component byte boundaries. Caller transfers ownership of
    /// `boundaries` to pending_chain (we take a copy so caller can free).
    fn deferUnconnectedSlotWithBoundaries(self: *Self, slot: Slot, assembled_data: []const u8, boundaries: []const usize) !void {
        // 2026-05-25 LIVELOCK FIX (forensically diagnosed from 410911969 wedge):
        // ENTRY-LEVEL DROP-BELOW-ROOT GUARD — without this, the PR-5ak FAST-WAKE
        // path keeps re-pushing slots whose root has already advanced past them.
        // Sequence that wedges: slot completes → defer called → FAST-WAKE fires
        // (target_parent <= root) → push to slot_queue → onSlotCompleted →
        // getOrCreateBank gets CHAIN-GAP (root >= slot) → error.UnconnectedSlot →
        // caller calls deferUnconnectedSlot → FAST-WAKE fires again → infinite
        // loop until log fills (104M+ mentions observed in one wedge).
        //
        // Counterpart: getOrCreateBank's "root>=slot" path returns
        // error.UnconnectedSlot but onSlotCompleted's catch path calls THIS
        // function. The drop here breaks the cycle.
        //
        // Adapted from commit c550539 chain-defer livelock guard (Fix #1).
        // FIX #112 (2026-05-30): drop ONLY below the monotonic CONSENSUS root
        // (db.rooted_slot), NOT root_bank.slot (= last-frozen bank). root_bank is
        // non-monotonic (observed 869→870→874→876→872); keying the drop on it let
        // an out-of-order minority freeze (876) discard the canonical bridge slots
        // 873/875 that were above the true root (872). Canonical: Agave
        // bank_forks.get_non_rooted prunes on set_root (root advancement) only.
        const rooted_slot_top: u64 = if (self.accounts_db) |db| db.rooted_slot else 0;
        // FIX #18a-A (2026-06-12, carrier #18 @414926973): a RE-DELIVERED slot
        // that already FROZE once (bank since evicted by the slot−512 prune
        // safety valve) must be DROPPED, not deferred — its outputs were already
        // consumed; re-replay is never legitimate (no duplicate-block support).
        // Without this, the live wedge looped defer→fast-wake→defer on slot
        // 414926973 for 3.4h (memcpy of the 2.5MB payload per lap → RSS 115GB,
        // replay starved). Agave analog: blockstore's "slot is full" check,
        // independent of bank_forks retention.
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            if (self.frozen_history.contains(slot)) {
                const DedupDbg = struct {
                    var count: u64 = 0;
                };
                DedupDbg.count += 1;
                if (DedupDbg.count <= 20 or DedupDbg.count % 1000 == 0) {
                    std.log.warn("[REPLAY-DEDUP-FROZEN] slot={d} re-delivery of already-frozen slot DROPPED (count={d}, FIX #18a-A)", .{ slot, DedupDbg.count });
                }
                return;
            }
        }
        if (pending_wake.shouldDropBelowRoot(slot, rooted_slot_top)) {
            const Dbg = struct {
                var count: u32 = 0;
            };
            const n = Dbg.count;
            if (n < 50 or @mod(n, 1000) == 0) {
                std.log.warn("[CHAIN-DEFER-DROP-BELOW-ROOT] slot={d} rooted_slot={d} count={d} (FIX#112: consensus root, not last-frozen)", .{ slot, rooted_slot_top, n });
            }
            Dbg.count = n + 1;
            return;
        }

        // GC pending entries: canonical root-based criterion, unified across
        // sentinel_node ON/OFF.
        //
        // FIX #53 (2026-05-27): catchup-mode wedge root-cause + fix.
        // Empirical wedge at slot 411160841: child arrived at log line 1971,
        // parent slot 411160840 didn't freeze until line 67889 (~64k log lines
        // later — minutes-to-hours of repair delay during cold-boot catchup).
        // The prior TTL-based GC (5 min, gated on sentinel_node=OFF) fired at
        // line 31627, freed the child's data, and the assembler is one-shot —
        // unrecoverable wedge. Forward chain progress past 411160840 = 0.
        //
        // Root-based criterion (drop slot when slot < root_bank.slot) is
        // canonical-safe regardless of sentinel_node: root_bank is the
        // lockout-confirmed cluster anchor, slots below it are already
        // rooted on some fork and cannot help forward progress. The PR-5au
        // regression concern (divergent fork advancement without sentinel
        // anchors) was about FORK ACCEPTANCE, not GC RETENTION — keeping
        // stuck entries beyond root cannot cause divergence.
        //
        // Backstop: PENDING_CHAIN_HARD_CAP (4096) + PENDING_CHAIN_BACKSTOP_TTL_MS
        // (60 min) prevent unbounded growth if root stalls. Drop ONLY when
        // BOTH conditions met (over cap AND entry older than backstop TTL),
        // so normal catchup is not affected.
        //
        // ──────────────────────────────────────────────────────────────────
        // pending_chain GC (RSS bound). Two drop predicates, BOTH recoverable:
        //   (1) root-advance: drop a slot once the CONSENSUS root has provably
        //       advanced past it (slot < db.rooted_slot) — it's obsolete.
        //   (2) backstop: drop only when over PENDING_CHAIN_HARD_CAP (4096) AND
        //       the entry is older than the 60-min TTL — a last-resort bound if
        //       the root genuinely stalls for >1h.
        // No entry that is still ABOVE the consensus root and younger than the
        // backstop TTL is ever dropped, so every retained pending entry stays
        // wakeable via checkPendingChain and re-requestable via orphan repair /
        // seedCatchupRepairs. That recoverability invariant is the whole point.
        //
        // ── REVERTED 2026-06-14: FIX #2 "immediate furthest-from-root eviction"
        // (an extra cap at 2048 that dropped the HIGHEST-keyed entries down to
        // the cap) is DELETED. It was a DECISIVE SILENT-CONSENSUS-HOLE bug, not a
        // valid memory bound. A slot enters pending_chain ONLY after it is
        // is_complete in the shred assembler; the wake path (checkPendingChain)
        // and orphan repair (collectOrphanTargets/selectOrphanTargets) BOTH key
        // exclusively on live pending_chain entries. Evicting an entry removed it
        // from BOTH:
        //   • checkPendingChain can no longer wake it (no entry, no owned data).
        //   • orphan repair can no longer select it OR anything pointing at it
        //     (its children are higher-keyed → evicted FIRST → nothing keeps it
        //     as a target_parent).
        //   • getInProgressSlots/getMissingIndices skip is_complete slots, so the
        //     per-slot WindowIndex loop never re-requests it either.
        // The ONLY path that re-requests an ABSENT sub-tip slot is
        // seedCatchupRepairs' HWI burst — but that is anchored on the consensus
        // root and capped at SEED_CAP=2048, so the UPPER HALF of an evicted set
        // (which sits at ~root+2048..root+4096 in the exact root-stuck wedge that
        // trips a 2048 cap) is BEYOND its ceiling → genuinely unrecoverable. And
        // any evicted slot that IS within range re-completes → re-defers → is
        // immediately re-evicted (wedge still over cap) → livelock, ~2.5MB churn
        // per cycle, zero forward progress. So FIX #2 made recovery STRICTLY
        // WORSE than the status quo. clearCompletedSlot(victim) does NOT fix this:
        // it only removes the assembler entry (fetchRemove — does NOT flip
        // is_complete=false), so getInProgressSlots still won't surface it, and it
        // ALSO frees the assembled bytes — same two failure modes plus more data
        // loss. The clean fix is to NOT evict: rely on the root-advance + 60-min
        // backstop drops above (both recoverable), the FIX #53 one-shot-assembler
        // retention rationale, and FIX #3's fail-stop floor for the single-stuck-
        // slot phantom wedge (it fail-stops at ~5 min ≈ ~750 entries, BELOW 4096,
        // so the acute wedge that motivated FIX #2 is already bounded WITHOUT it).
        // The historical 115GB blowup was a defer→fast-wake→defer LIVELOCK
        // (memcpy of one 2.5MB payload per lap), independently closed by the
        // FIX #18a-A frozen_history dedup guard above — NOT a distinct-entry
        // accretion that eviction was needed to bound.
        // OPERATOR NOTE: the residual RSS bound is the pre-FIX-#2 baseline —
        // 4096 × ~2.5MB ≈ ~10GB only after a >60-min root stall. If a future
        // wedge is found where FIX #3 never fires yet pending_chain exceeds the
        // hard cap WITHIN the 60-min window, the correct response is a RECOVERABLE
        // bound (e.g. re-keying dedup so re-fetch re-surfaces, or a lower
        // backstop TTL), never a silent highest-keyed drop.
        // ──────────────────────────────────────────────────────────────────
        const now_ms = std.time.milliTimestamp();
        // FIX #112: GC pending entries below the CONSENSUS root (db.rooted_slot),
        // NOT root_bank.slot (last-frozen, non-monotonic — see drop guard above).
        const root_slot_for_gc: u64 = if (self.accounts_db) |db| db.rooted_slot else 0;
        // fix/chain-defer-tip-guard (wedge @422050470): the freeze TIP is the
        // last-frozen bank — the point replay is advancing FROM. The protected
        // band is measured around it so the imminently-resolvable continuation
        // (tip+1 .. tip+band) is never GC'd. This is deliberately the freeze-tip
        // (root_bank.slot), NOT the consensus root: we protect the REPLAY
        // frontier, which is exactly where the fatal severance happened.
        const freeze_tip_for_gc: u64 = if (self.root_bank.load(.acquire)) |rb| rb.slot else 0;
        const PENDING_CHAIN_HARD_CAP: usize = pending_chain_gc.PENDING_CHAIN_HARD_CAP;
        const PENDING_CHAIN_BACKSTOP_TTL_MS: i64 = pending_chain_gc.PENDING_CHAIN_BACKSTOP_TTL_MS;
        const PROTECT_BAND: u64 = pending_chain_gc.PENDING_CHAIN_PROTECT_BAND;
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();

            var to_drop = std.ArrayList(u64){};
            defer to_drop.deinit(self.allocator);

            const cur_count = self.pending_chain.count();

            // ── Clause (1): ROOT-ADVANCE drops (unconditional, recoverable). Any
            // entry below the consensus root is obsolete (children wake via the
            // root-floor). Shared predicate — single source of truth.
            {
                var it = self.pending_chain.iterator();
                while (it.next()) |entry| {
                    if (pending_wake.shouldDropBelowRoot(entry.key_ptr.*, root_slot_for_gc)) {
                        to_drop.append(self.allocator, entry.key_ptr.*) catch continue;
                    }
                }
            }

            // ── Clause (2): TIP-AWARE BACKSTOP (fix/chain-defer-tip-guard). Only
            // when STILL over the hard cap after root-drops, evict FURTHEST-from-
            // tip first (highest slot; every deferred slot is above the tip),
            // NEVER within the protected band above the freeze tip, and ONLY down
            // to the cap. The near-tip continuation — the one the @422050470 wedge
            // self-decapitated on — is the LAST thing dropped, never the first.
            const remaining_after_root = cur_count - to_drop.items.len;
            if (remaining_after_root > PENDING_CHAIN_HARD_CAP) {
                var eligible = std.ArrayList(u64){};
                defer eligible.deinit(self.allocator);
                var it = self.pending_chain.iterator();
                while (it.next()) |entry| {
                    if (pending_chain_gc.backstopEligible(
                        entry.key_ptr.*,
                        freeze_tip_for_gc,
                        now_ms - entry.value_ptr.added_ms,
                        PROTECT_BAND,
                        PENDING_CHAIN_BACKSTOP_TTL_MS,
                    )) {
                        eligible.append(self.allocator, entry.key_ptr.*) catch continue;
                    }
                }
                // Furthest-from-tip first = highest slot first (descending).
                std.mem.sort(u64, eligible.items, {}, comptime std.sort.desc(u64));
                const need = remaining_after_root - PENDING_CHAIN_HARD_CAP;
                const drop_n = @min(need, eligible.items.len);
                for (eligible.items[0..drop_n]) |s| {
                    to_drop.append(self.allocator, s) catch break;
                }
            }

            for (to_drop.items) |s| {
                if (self.pending_chain.fetchRemove(s)) |kv| {
                    if (kv.value.data.len > 0) self.allocator.free(kv.value.data);
                    if (kv.value.boundaries.len > 0) self.allocator.free(kv.value.boundaries);
                    if (root_slot_for_gc > 0 and s < root_slot_for_gc) {
                        std.log.warn("[CHAIN-DEFER-GC-ROOT] dropped slot {d} (root advanced past, slot < {d})", .{ s, root_slot_for_gc });
                    } else {
                        // RCA instrumentation: log the gap from the dropped slot to
                        // the freeze tip. A SMALL gap here would have been the fatal
                        // signal in the wedge; the protected band now makes it
                        // impossible to drop within `band` of the tip.
                        const tip_gap: i64 = @as(i64, @intCast(s)) - @as(i64, @intCast(freeze_tip_for_gc));
                        std.log.warn("[CHAIN-DEFER-GC-BACKSTOP] dropped slot {d} (furthest-from-tip, over cap {d}, > 60min old; freeze_tip={d} tip_gap={d} band={d})", .{ s, PENDING_CHAIN_HARD_CAP, freeze_tip_for_gc, tip_gap, PROTECT_BAND });
                        // fix/chain-defer-tip-guard: record this eviction so that if
                        // this slot's parent later freezes, the CHAIN-WAKE fallback
                        // re-derives + re-enqueues it (self-heal) rather than
                        // orphaning replay. Only backstop drops (above root, genuine
                        // eviction) are recorded — root-advance drops are obsolete.
                        self.backstop_evicted.put(s, {}) catch {};
                    }
                }
            }
        }

        // Don't double-defer
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            if (self.pending_chain.contains(slot)) return; // already deferred
        }

        // Determine target_parent for wake-up keying
        const target_parent: u64 = blk: {
            if (self.shred_assembler) |sa| {
                if (sa.getParentSlot(slot)) |p| break :blk p;
            }
            break :blk if (slot > 0) slot - 1 else 0;
        };

        // d27mm-REVERTED: dead-parent check removed (caused cascade-orphan).

        const data_copy = try self.allocator.alloc(u8, assembled_data.len);
        @memcpy(data_copy, assembled_data);

        // d28bb: copy boundaries so the pending entry owns its own slice
        // independent of the caller's lifetime.
        var boundaries_copy: []usize = &.{};
        if (boundaries.len > 0) {
            boundaries_copy = self.allocator.alloc(usize, boundaries.len) catch |err| {
                self.allocator.free(data_copy);
                return err;
            };
            @memcpy(boundaries_copy, boundaries);
        }

        // PR-5ak (2026-05-20): Carrier H closer — before deferring, check if
        // target_parent is ALREADY frozen (the common cold-boot race where
        // slot N+1's shreds arrive after slot N has frozen). If yes, skip
        // the defer and push directly to slot_queue so replay can proceed.
        // Without this, the entry would sit in pending_chain until another
        // (unrelated) freeze triggers checkPendingChain's sweep.
        const parent_already_frozen = blk: {
            const parent_frozen = pf: {
                self.banks_lock.lockShared();
                defer self.banks_lock.unlockShared();
                if (self.banks.get(target_parent)) |bank| break :pf bank.is_frozen;
                break :pf false;
            };
            // FIX #112 (2026-05-30): the root-fallback ("parent at/below root is a
            // ready boundary parent") must key on the monotonic CONSENSUS root
            // (db.rooted_slot), NOT root_bank.slot (last-frozen, non-monotonic).
            // Keying on root_bank let a transient out-of-order minority freeze make
            // a canonical child look "ready" → fast-wake-push → getOrCreateBank
            // reject (root_bank>=slot) → defer → re-push: a 104M-line livelock.
            // Throughput preserved: the common in-order case wakes via parent_frozen.
            // FIX #18a-B (2026-06-12, carrier #18 @414926973): pass the freeze-tip
            // and child slot so the predicate mirrors resolveParent's d28mm guard —
            // fast-wake must never claim ready for a build resolve will refuse
            // (that disagreement was the 3.4h defer→push→defer livelock, RSS 115GB).
            const rooted: Slot = if (self.accounts_db) |db| db.rooted_slot else 0;
            const freeze_tip: Slot = if (self.root_bank.load(.acquire)) |rb| rb.slot else 0;
            break :blk pending_wake.parentReadyForFastWake(parent_frozen, target_parent, rooted, freeze_tip, slot);
        };
        if (parent_already_frozen) {
            std.log.warn("[CHAIN-DEFER-FAST-WAKE] slot={d} target_parent={d} already frozen — push to slot_queue directly (PR-5ak)", .{ slot, target_parent });
            const ok = if (boundaries_copy.len > 0)
                self.pushSlotForReplayWithBoundaries(slot, data_copy, boundaries_copy)
            else
                self.pushSlotForReplay(slot, data_copy);
            if (!ok) {
                if (data_copy.len > 0) self.allocator.free(data_copy);
                if (boundaries_copy.len > 0) self.allocator.free(boundaries_copy);
            }
            return;
        }

        // PR-5av Phase 3/4 (combined per advisor pivot 2026-05-22): mint
        // a sentinel for this slot before stashing bytes in pending_chain.
        // @prov:replay.sentinel-vs-tower-confirm — the
        // shred assembler IS our "we now know this slot exists" signal,
        // so creation triggers on shred-defer. Sentinel lives in subtrees
        // so Phase 6's relaxed death sentence can consult it. Errors are
        // soft — sentinel creation is structural-only here; bytes still
        // defer correctly even if minting fails or flag is off.
        _ = self.createSentinelBank(slot, null) catch |sentinel_err| switch (sentinel_err) {
            error.SentinelDisabled, error.SlotAlreadyExists => {},
            error.OutOfMemory => std.log.warn("[SENTINEL-CREATE-FAIL] slot={d} err=OutOfMemory", .{slot}),
        };

        self.pending_chain_lock.lock();
        defer self.pending_chain_lock.unlock();
        self.pending_chain.put(slot, .{
            .data = data_copy,
            .target_parent = target_parent,
            .added_ms = now_ms,
            .boundaries = boundaries_copy,
        }) catch |err| {
            self.allocator.free(data_copy);
            if (boundaries_copy.len > 0) self.allocator.free(boundaries_copy);
            return err;
        };
        std.log.warn("[CHAIN-DEFER] slot={d} target_parent={d} (waiting for parent via repair, pending={d})", .{ slot, target_parent, self.pending_chain.count() });
    }

    /// d21: when slot S freezes, wake any deferred slot whose
    /// target_parent == S. Removes from pending_chain and re-pushes to slot_queue.
    /// Cascades: when the woken slot freezes, this fires again for ITS children.
    ///
    /// d27z (2026-05-11): "any frozen bank >= root can be parent".
    /// @prov:replay.generate-new-bank-forks — no "wait for THIS exact slot to
    /// freeze" requirement; any frozen ancestor at or above root suffices.
    ///
    /// Vexor port: in addition to waking on exact `target_parent == frozen_slot`
    /// match, wake any pending entry whose target_parent <= root_bank.slot.
    /// @prov:replay.chain-connectivity-defer Without this,
    /// pending entries whose target_parent never freezes (cluster-skipped slot,
    /// or root_bank advanced past it via a different path) stay stuck forever
    /// even though they could replay against root_bank.
    fn checkPendingChain(self: *Self, frozen_slot: Slot) void {
        // FIX #18a-A: durably record this freeze in frozen_history (survives
        // bank eviction; consulted by deferUnconnectedSlotWithBoundaries to
        // drop re-delivered already-replayed slots). Both freeze sites funnel
        // through checkPendingChain, so this is the single canonical record
        // point. Pruned below the consensus root in pruneOldBanks' cadence.
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            self.frozen_history.put(frozen_slot, {}) catch {};
        }
        var to_wake_slots = std.ArrayList(u64){};
        var to_wake_data = std.ArrayList([]u8){};
        // d28bb (2026-05-12): preserve batch_complete boundaries through
        // chain-defer → chain-wake. Without this, woken slots replay with
        // boundaries_len=0 → linear-scan parser mis-aligns at FEC-set
        // boundaries → measure_fail → bank_hash divergence.
        var to_wake_boundaries = std.ArrayList([]const usize){};
        defer to_wake_slots.deinit(self.allocator);
        defer to_wake_data.deinit(self.allocator);
        defer to_wake_boundaries.deinit(self.allocator);

        const root_slot: Slot = if (self.root_bank.load(.acquire)) |rb| rb.slot else 0;

        // PR-S5 (2026-05-15): @prov:replay.generate-new-bank-forks port.
        // Snapshot the set of frozen slots so we can wake any pending entry
        // whose target_parent is in the set, not just the slot whose freeze
        // event triggered this call. Closes the defer-after-freeze race where
        // checkPendingChain(N) ran BEFORE slot N+1's shreds arrived; previously
        // N+1's target_parent=N never woke because no future freeze event for
        // N would fire (N already frozen) and N > root_slot.
        // Lock order: banks_lock (shared) BEFORE pending_chain_lock.
        var frozen_set = std.AutoHashMap(u64, void).init(self.allocator);
        defer frozen_set.deinit();
        {
            self.banks_lock.lockShared();
            defer self.banks_lock.unlockShared();
            var bit = self.banks.iterator();
            while (bit.next()) |be| {
                if (be.value_ptr.*.is_frozen) {
                    frozen_set.put(be.key_ptr.*, {}) catch continue;
                }
            }
        }
        // PR-S5 probe: log frozen_set + pending_chain size every 200 invocations
        // to verify the poll path executes. Self-throttling counter.
        const PrS5Dbg = struct {
            var calls: u64 = 0;
        };
        PrS5Dbg.calls += 1;
        if (PrS5Dbg.calls % 200 == 1) {
            self.pending_chain_lock.lock();
            const pchain_count = self.pending_chain.count();
            const chasing_count = self.orphan_chasing.count();
            const closed_total = self.orphan_gaps_closed_total;
            self.pending_chain_lock.unlock();
            // FIX #112 observability: surface the TRUE consensus root
            // (db.rooted_slot) next to root_slot (= root_bank.slot, last-frozen).
            // These diverging is the wedge signature; this confirms which root the
            // GC/drop now keys on, and whether the consensus root tracks the
            // frontier or sits at the snapshot during catchup.
            const consensus_root: u64 = if (self.accounts_db) |db| db.rooted_slot else 0;
            std.log.warn("[PR-S5-PROBE] call#{d} frozen_set_size={d} pending_chain_count={d} frozen_slot_arg={d} root_slot={d} consensus_root={d} orphan_chasing={d} orphan_closed={d}", .{ PrS5Dbg.calls, frozen_set.count(), pchain_count, frozen_slot, root_slot, consensus_root, chasing_count, closed_total });
        }

        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();

            // Orphan-repair observability (2026-05-30, advisor gate #1): if the
            // slot that just froze is a gap-parent we emitted Orphan(10) to
            // discover, the two-stage loop closed end-to-end (Orphan response →
            // ancestor discovered → window repair filled it → it replayed →
            // froze). Log it so a soak can distinguish "loop closing" from
            // "requests into the void." Children waiting on this parent wake in
            // the loop just below (same lock hold).
            if (self.orphan_chasing.fetchRemove(frozen_slot)) |_| {
                self.orphan_gaps_closed_total += 1;
                std.log.warn("[ORPHAN-CLOSED] gap_parent={d} froze (was Orphan-requested) — orphan loop closed (total_closed={d})", .{ frozen_slot, self.orphan_gaps_closed_total });
            }

            // 2026-06-05 FIX (carrier 413389395): the wake's root-fallback (b)
            // must key on the monotonic CONSENSUS root (db.rooted_slot), NOT the
            // freeze-tip `root_slot` (self.root_bank.slot). Passing the freeze-tip
            // would wake a child whose tp is in the (consensus_root, freeze_tip]
            // band even though tp is NOT frozen — getOrCreateBank (now keyed on
            // the consensus root too) then re-defers it → wake↔defer livelock on
            // every freeze (the exact 413389395 churn band). Keyed on the
            // consensus root, such a child rests in pending_chain and wakes the
            // instant its true parent freezes (via shouldWakePending (a)/(c)).
            // Matches FIX#112's parentReadyForFastWake / shouldDropBelowRoot.
            const wake_root: u64 = if (self.accounts_db) |db| db.rooted_slot else 0;
            var it = self.pending_chain.iterator();
            while (it.next()) |entry| {
                const tp = entry.value_ptr.target_parent;
                // WAKE predicate extracted to pending_wake.zig (orphan-repair
                // 2026-05-30) so it is unit-proven, not reasoned-correct in place.
                // (a) tp just froze, (b) tp <= consensus root (rooted boundary),
                // (c) tp anywhere in the frozen set.
                if (pending_wake.shouldWakePending(tp, frozen_slot, wake_root, &frozen_set)) {
                    to_wake_slots.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }
            for (to_wake_slots.items) |s| {
                if (self.pending_chain.fetchRemove(s)) |kv| {
                    to_wake_data.append(self.allocator, kv.value.data) catch {
                        // Out of memory for the wake list — free the data and skip
                        if (kv.value.data.len > 0) self.allocator.free(kv.value.data);
                        if (kv.value.boundaries.len > 0) self.allocator.free(kv.value.boundaries);
                        continue;
                    };
                    to_wake_boundaries.append(self.allocator, kv.value.boundaries) catch {
                        // Lost the boundaries slot — free it; data already appended
                        if (kv.value.boundaries.len > 0) self.allocator.free(kv.value.boundaries);
                        to_wake_boundaries.append(self.allocator, &.{}) catch {};
                    };
                }
            }
        }

        for (to_wake_slots.items, 0..) |s, i| {
            if (i >= to_wake_data.items.len) break;
            const data = to_wake_data.items[i];
            const bnds: []const usize = if (i < to_wake_boundaries.items.len) to_wake_boundaries.items[i] else &.{};
            const ok = if (bnds.len > 0)
                self.pushSlotForReplayWithBoundaries(s, data, bnds)
            else
                self.pushSlotForReplay(s, data);
            if (!ok) {
                // Shutdown — free the buffer
                if (data.len > 0) self.allocator.free(data);
                if (bnds.len > 0) self.allocator.free(bnds);
            } else {
                std.log.warn("[CHAIN-WAKE] slot={d} woken (frozen_parent={d} root={d} boundaries={d})", .{ s, frozen_slot, root_slot, bnds.len });
            }
        }

        // ── fix/chain-defer-tip-guard: CHAIN-WAKE FALLBACK (self-heal an evicted
        // continuation). The tip-aware backstop PREVENTS near-tip eviction; this
        // is the independent safety net that heals the orphaning class regardless
        // of eviction-policy bugs. Cost-free in healthy operation: backstop_evicted
        // is empty, so we take the lock once, see count()==0, and fall through.
        // Only after a genuine backstop eviction do we check whether the slot that
        // just froze is the PARENT of an evicted slot and, if so, re-derive its
        // still-held bytes from the assembler and re-enqueue (or repair-request).
        self.chainWakeFallback(frozen_slot);
    }

    /// fix/chain-defer-tip-guard (wedge @422050470): re-attach any CHAIN-DEFER
    /// continuation that the GC backstop evicted before its parent froze. Called
    /// at the tail of checkPendingChain (holds NO locks on entry). See
    /// chain_wake_fallback.zig for the pure decision; RCA in
    /// forensics/incident-wedge-422050470/RCA-DATA.md.
    fn chainWakeFallback(self: *Self, frozen_slot: Slot) void {
        // Snapshot the evicted set under the lock (empty ⇒ nothing to do — the
        // common, healthy case, one uncontended lock/count()/unlock).
        var evicted_children = std.ArrayList(u64){};
        defer evicted_children.deinit(self.allocator);
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            if (self.backstop_evicted.count() == 0) return;
            var eit = self.backstop_evicted.keyIterator();
            while (eit.next()) |k| evicted_children.append(self.allocator, k.*) catch break;
        }

        for (evicted_children.items) |child| {
            // Only act on evicted slots whose parent is the slot that just froze —
            // i.e. THIS freeze is what would have woken them. Parent is read from
            // the child's own shreds (still held in the assembler). If the child's
            // assembly was ALSO evicted (getParentSlot == null → bytes gone), we
            // can't read its parent; fall back to the IMMEDIATE contiguous
            // continuation (child == frozen_slot+1) so the "both-evicted" child is
            // still repair-requested rather than orphaned. This closes the repair
            // hole where getInProgressSlots/getMissingIndices skip is_complete
            // (and absent) slots — the direct window-repair below re-fetches it,
            // bounded to the immediate continuation gap only.
            const parent: ?u64 = if (self.shred_assembler) |sa| sa.getParentSlot(child) else null;
            const is_continuation = (parent != null and parent.? == frozen_slot) or
                (parent == null and child == frozen_slot +| 1);
            if (!is_continuation) continue;

            // Did the child already recover on its own? (frozen, or back in the map)
            const frozen_or_deferred = blk: {
                self.pending_chain_lock.lock();
                defer self.pending_chain_lock.unlock();
                break :blk self.frozen_history.contains(child) or self.pending_chain.contains(child);
            };
            const completed = if (self.shred_assembler) |sa| sa.isSlotComplete(child) else false;

            switch (chain_wake_fallback.decide(frozen_or_deferred, completed)) {
                .recovered => {},
                .reenqueue => {
                    // Re-derive the still-held block and push it for replay; its
                    // parent just froze so it is immediately replayable. Same
                    // assembler-data→push handoff the normal ingest path uses
                    // (tvu.zig:977). Idempotent-safe: onSlotCompleted early-returns
                    // if a bank for `child` already exists.
                    const sa = self.shred_assembler.?;
                    if (sa.getAssembledDataWithBoundaries(child)) |ar| {
                        const ok = if (ar.boundaries.len > 0)
                            self.pushSlotForReplayWithBoundaries(child, ar.data, ar.boundaries)
                        else
                            self.pushSlotForReplay(child, ar.data);
                        if (ok) {
                            std.log.warn("[CHAIN-WAKE-FALLBACK] slot={d} re-enqueued from assembler (parent {d} froze; evicted-continuation self-heal)", .{ child, frozen_slot });
                        } else {
                            if (ar.data.len > 0) self.allocator.free(ar.data);
                            if (ar.boundaries.len > 0) self.allocator.free(ar.boundaries);
                        }
                    } else |e| {
                        std.log.warn("[CHAIN-WAKE-FALLBACK] slot={d} re-derive failed ({any}) — requesting repair (parent {d} froze)", .{ child, e, frozen_slot });
                        self.continuation_repair_needed.store(child, .release);
                    }
                },
                .repair => {
                    // Bytes are gone (assembly swept) — hand the slot to tvu's
                    // repair cycle for a normal window re-fetch.
                    self.continuation_repair_needed.store(child, .release);
                    std.log.warn("[CHAIN-WAKE-FALLBACK] slot={d} not re-derivable — requesting repair (parent {d} froze)", .{ child, frozen_slot });
                },
            }
            // Consume the eviction record either way (recovered/healed/handed off).
            self.pending_chain_lock.lock();
            _ = self.backstop_evicted.remove(child);
            self.pending_chain_lock.unlock();
        }
    }

    /// Orphan-repair (2026-05-30): collect the CHAIN-DEFER "orphan roots" to
    /// emit Orphan(10) repair requests for — deferred slots whose target_parent
    /// is a true zero-shred gap (above root, not frozen, not itself another
    /// deferred slot). Called from tvu's repair cycle (it holds the
    /// replay_stage ref). Returns up to `max` slots, nearest-root-first; the
    /// CALLER FREES the returned slice. Selection is the unit-tested
    /// orphan_target.selectOrphanTargets; this method just snapshots the live
    /// pending_chain + frozen-bank state under the proper locks.
    ///
    /// Lock order matches checkPendingChain: banks_lock (shared) is taken and
    /// RELEASED before pending_chain_lock (never held simultaneously).
    pub fn collectOrphanTargets(self: *Self, allocator: std.mem.Allocator, max: usize) ![]u64 {
        // FIX #112 (5th/final site, 2026-06-06 wedge 413481786): the orphan-root
        // gate MUST key on the monotonic CONSENSUS root (db.rooted_slot), NOT the
        // non-monotonic freeze-tip (self.root_bank.slot). The freeze-tip advances
        // on EVERY freeze and can be a minority-fork orphan (in the wedge it was
        // 786, parent 782, a slot the cluster SKIPPED). selectOrphanTargets at
        // orphan_target.zig:51 excludes any deferred slot whose target_parent <=
        // root as "wakes via root-floor." Keyed on the freeze-tip 786, the
        // keystone-bottom 785 (target_parent=784, the true zero-shred gap) was
        // excluded because 784 <= 786 — but 784 is NOT rooted (consensus_root=746),
        // NOT frozen, and has zero shreds (never window-discoverable), so it NEVER
        // wakes via root-floor and the chain stalls forever. Keyed on the consensus
        // root 746, 784 > 746 → 785 IS selected → requestOrphan(785) discovers 784.
        // This is the exact freeze-tip→consensus-root bug class FIX #112 already
        // migrated at shouldDropBelowRoot, parentReadyForFastWake, resolveParent,
        // and checkPendingChain's wake_root (replay_stage.zig:2011). collectOrphan-
        // Targets was the un-migrated straggler. Sibling pattern: lines 1980, 2011.
        const root_slot: Slot = if (self.accounts_db) |db| db.rooted_slot else 0;

        var frozen_set = std.AutoHashMap(u64, void).init(allocator);
        defer frozen_set.deinit();
        {
            self.banks_lock.lockShared();
            defer self.banks_lock.unlockShared();
            var bit = self.banks.iterator();
            while (bit.next()) |be| {
                if (be.value_ptr.*.is_frozen) frozen_set.put(be.key_ptr.*, {}) catch continue;
            }
        }

        // Per-slot DEFER_REPAIR_THRESHOLD. @prov:replay.defer-repair-threshold
        // (advisor pre-deploy gate #3, 2026-05-30): only orphan-request a
        // deferred slot whose parent has been missing for >=250ms. A slot
        // deferred <250ms ago may still have its parent arrive via turbine, so
        // emitting an Orphan request for it would race the normal receive path.
        // This is the per-slot age gate that the 500ms global tvu throttle
        // (which bounds total Orphan emission rate) does NOT provide.
        const now_ms = std.time.milliTimestamp();
        const DEFER_REPAIR_THRESHOLD_MS: i64 = 250;

        var deferred = std.ArrayList(orphan_target.DeferredEntry){};
        defer deferred.deinit(allocator);
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            var it = self.pending_chain.iterator();
            while (it.next()) |entry| {
                if (now_ms - entry.value_ptr.added_ms < DEFER_REPAIR_THRESHOLD_MS) continue;
                deferred.append(allocator, .{
                    .slot = entry.key_ptr.*,
                    .target_parent = entry.value_ptr.target_parent,
                }) catch continue;
            }
        }

        const targets = try orphan_target.selectOrphanTargets(allocator, deferred.items, &frozen_set, root_slot, max);

        // Observability (advisor pre-deploy gate #1, 2026-05-30): record the
        // GAP-PARENT we're chasing for each selected orphan-root, and GC any
        // chased gap that has fallen to/below root (moot — its children wake
        // via checkPendingChain's root-floor, not via repair). When a chased
        // gap-parent later freezes, checkPendingChain emits [ORPHAN-CLOSED],
        // proving the two-stage Orphan loop closed. `targets` is already
        // allocated; the puts/appends below are best-effort (catch {}) so a
        // transient OOM here never leaks or fails the returned slice.
        {
            self.pending_chain_lock.lock();
            defer self.pending_chain_lock.unlock();
            // GC stale chased gaps (<= consensus root). `root_slot` now holds the
            // monotonic CONSENSUS root (db.rooted_slot), so a chased gap is only
            // GC'd once genuinely rooted (its children wake via checkPendingChain's
            // root-floor). Previously this keyed on the freeze-tip, which would
            // have evicted the keystone gap 784 (784 <= freeze-tip 786) before its
            // Orphan loop could close — observability only (re-selected next cycle),
            // but corrected here for the same FIX #112 reason as the selection root.
            // Collect-then-remove: removing during keyIterator() iteration is UB.
            var stale = std.ArrayList(u64){};
            defer stale.deinit(allocator);
            var cit = self.orphan_chasing.keyIterator();
            while (cit.next()) |k| {
                if (root_slot > 0 and k.* <= root_slot) stale.append(allocator, k.*) catch {};
            }
            for (stale.items) |k| _ = self.orphan_chasing.remove(k);
            // Record the gap-parent (target_parent) for each newly-selected
            // orphan-root. `targets` ⊆ deferred slots, so the lookup is exact.
            for (targets) |s| {
                for (deferred.items) |e| {
                    if (e.slot == s) {
                        self.orphan_chasing.put(e.target_parent, {}) catch {};
                        break;
                    }
                }
            }
        }

        return targets;
    }

    /// Set fast catch-up mode (skip sig verification for historical replay)
    pub fn setFastCatchup(self: *Self, enabled: bool) void {
        self.fast_catchup = enabled;
        if (enabled) std.log.info("[REPLAY] Fast catch-up mode ENABLED — skipping sig verification", .{});
    }

    /// Get current root slot (lock-free atomic read)
    pub fn rootSlot(self: *const Self) ?Slot {
        if (self.root_bank.load(.acquire)) |rb| return rb.slot;
        return null;
    }

    /// Print statistics
    pub fn printStats(self: *const Self) void {
        std.log.debug(
            \\
            \\=== Replay Stage Stats ===
            \\Shreds received:   {d}
            \\Invalid shreds:    {d}
            \\Slots replayed:    {d}
            \\Successful TXs:    {d}
            \\Failed TXs:        {d}
            \\Votes sent:        {d}
            \\Blocks produced:   {d}
            \\==========================
            \\
        , .{
            ReplayStats.get(&self.stats.shreds_received),
            ReplayStats.get(&self.stats.invalid_shreds),
            ReplayStats.get(&self.stats.slots_replayed),
            ReplayStats.get(&self.stats.successful_txs),
            ReplayStats.get(&self.stats.failed_txs),
            ReplayStats.get(&self.stats.votes_sent),
            ReplayStats.get(&self.stats.blocks_produced),
        });
    }

    // ── Process a completed slot ──────────────────────────────────────────────

    /// Process a completed slot directly (called from TVU when slot is assembled).
    /// Replays all entries, freezes the bank, and updates root_bank.
    /// Solana Foundation Delegation Program requirement:
    /// Replay must complete in < 400ms per slot to keep up with the network tip.
    /// Budget breakdown. @prov:replay.slot-budget-breakdown
    ///   TX execution (BPF/SBF):   60-75% (~240-300ms)
    ///   Account loading:          10-25% (~40-100ms)
    ///   Signature verification:   ~20ms (parallelized)
    ///   Bank hash computation:    ~5-15ms
    const SLOT_BUDGET_MS: i64 = 400;

    pub fn onSlotCompleted(self: *Self, slot: Slot, assembled_data: []const u8) !void {
        const t0 = std.time.milliTimestamp();

        // Phase A recorder: set threadlocal current_slot so every _getRooted /
        // getAccountInSlot call inside this slot's replay is attributed to it.
        // Cleared on function return; threadlocal so concurrent worker threads
        // don't collide. Cheap unconditional write (8 bytes).
        vex_store.recorder.current_slot = slot;
        defer vex_store.recorder.current_slot = 0;

        // Verify we haven't already processed this slot.
        // PR-5av Phase 3/4 fix (2026-05-22): sentinels live in `self.banks`
        // but are placeholders awaiting promotion — they do NOT count as
        // "already processed." Returning early here when a sentinel exists
        // is the bug that pinned chain advancement under -Dsentinel_node:
        // CHAIN-WAKE re-pushed deferred slots correctly, but this gate
        // blocked them from reaching getOrCreateBank's teardown+promote
        // path, so SENTINEL-PROMOTE never fired (verified empirically in
        // Phase 7 stuck log: 1107 SENTINEL-CREATE / 0 SENTINEL-PROMOTE).
        {
            self.banks_lock.lockShared();
            defer self.banks_lock.unlockShared();
            if (self.banks.get(slot)) |existing| {
                if (!existing.is_sentinel) return;
            }
        }

        // verify_ticks canonical (feat/verify-ticks-canonical-zig-2026-06-19):
        // a slot killed by the tick-validity gate must NEVER be re-replayed /
        // re-frozen on re-delivery — that is what makes the kill "reach fork
        // choice" rather than being a transient parse-abort. The unfrozen aborted
        // bank already stays in self.banks (non-sentinel → the early-return
        // above), but we add an explicit dead_slots membership guard for
        // robustness and to mirror Agave/FD's "dead slot is terminal". Comptime-
        // gated so the default (.off) build is byte-identical.
        if (comptime build_options.verify_ticks != .off) {
            self.dead_slots_lock.lock();
            const is_dead = self.dead_slots.contains(slot);
            self.dead_slots_lock.unlock();
            if (is_dead) {
                std.log.debug("[VERIFY-TICKS] slot={d} already dead — skipping re-replay", .{slot});
                return;
            }
        }

        if (assembled_data.len < 16) {
            std.log.debug("[REPLAY] Slot {d}: assembled data too short ({d} bytes)\n", .{ slot, assembled_data.len });
            return;
        }

        // Phase I (2026-05-17): pre-replay orphan-slot detection — REMOVED 2026-05-26
        // (Task #26 byte-extractor Phase 1: callsite 2). This guard consulted
        // cluster's cached SlotHashes to pre-emptively `markSlotDead` slots
        // that cluster claimed were orphan. Agave has NO equivalent — Agave's
        // `generate_new_bank_forks` (replay_stage.rs:4575-4593) only creates
        // banks for slots whose parent is already frozen, so orphan slots
        // simply never get banks. Vexor's `getOrCreateBank(slot)` below
        // already enforces the same invariant (UnconnectedSlot → CHAIN-DEFER),
        // making this guard structurally REDUNDANT against the bank-tree
        // invariant. The current binary has fired 5 [REPLAY-ORPHAN-DETECT]
        // events with the conservative gate intact — without the gate, those
        // slots route through getOrCreateBank → either UnconnectedSlot (defer)
        // or SIMD-0340 ENFORCE at freeze (Agave-canonical kill). Either
        // outcome is byte-equivalent to Agave's behavior.
        // See: agave-4.0.0/core/src/replay_stage.rs:4575-4593 generate_new_bank_forks
        //      project-wedge-411024170-bmtree32-needed-2026-05-26
        //      Task #26 Phase 2 (2026-05-27): isKnownOrphanSlot removed +
        //      WIDEN-PROBE removed — empirical evidence from 1183-bank soak
        //      on binary 169ac58a showed 0 probe events; widen safe to drop.

        // d27-debug (2026-05-11): finer-grained timing around getOrCreateBank
        // to localize where bank_create_ms=~180ms is coming from after d27
        // removed the 200ms wait + backward-walk.
        const t0a = std.time.milliTimestamp();
        const bank = self.getOrCreateBank(slot) catch |err| {
            if (err == error.UnconnectedSlot) {
                // d21: parent isn't in the bank tree yet. @prov:replay.chain-connectivity-defer
                // this slot — when its parent gets frozen, checkPendingChain
                // will re-push it to slot_queue. Repair fills the gap meanwhile.
                //
                // d28bb (2026-05-12): preserve component_boundaries_override
                // (set by replayWorker from msg.boundaries) through deferral.
                // Without this, the threadlocal is cleared on function return
                // and CHAIN-WAKE re-replays with boundaries_len=0, sending the
                // parser into scan-forward heuristics that mis-align at FEC-set
                // boundaries → measure_fail → bank_hash divergence.
                const tl_bnds = component_boundaries_override;
                self.deferUnconnectedSlotWithBoundaries(slot, assembled_data, tl_bnds) catch |defer_err| {
                    std.log.warn("[CHAIN-DEFER] slot={d}: defer failed ({any}), dropping", .{ slot, defer_err });
                };
                return;
            }
            std.log.debug("[REPLAY] Failed to create bank for slot {d}: {any}\n", .{ slot, err });
            return;
        };

        // Phase J (2026-05-17): leader-skip detection from bank.parent_slot.
        // bank.parent_slot is derived from the leader-signed shred header's
        // parent_offset. If parent_slot is more than 1 below slot, the leader
        // of `slot` declared that slots (parent_slot+1 .. slot-1) were
        // skipped.
        //
        // Phase J-2 (2026-05-17 ~12:30 MDT): cluster-SlotHashes cross-check
        // before mark-dead, after observing a false-positive cascade.
        // PID 2354465 hit a case where `slot=409052956`'s first-arrived
        // shred claimed parent_off=5 (skip of 952-955), but cluster's
        // canonical chain actually goes 951→952→953→…→956. cluster getBlock
        // confirmed 952-955 are all canonical. Phase J fired on the forked
        // shred's claim, marked 952 dead, and the cascade killed 30 canonical
        // descendants → replay stalled.
        //
        // Defense: before marking a slot dead via parent_off claim, consult
        // cluster's cached SlotHashes (the same data Phase I uses). If the
        // slot IS in cluster's authoritative view, the parent_off claim
        // is from a forked validator's shred — abort the mark-dead.
        // Phase I already filters by cluster view (only marks dead if NOT
        // in cluster); Phase J needs the same defense at its own fire site.
        // Phase J (2026-05-17): leader-skip detection from bank.parent_slot — REMOVED
        // 2026-05-26 (Task #26 byte-extractor callsite 3, Agave-canonical).
        //
        // Phase J's original intent was to mark dead any slots in
        // `(parent_slot, slot)` that the leader's parent_off claim said were
        // skipped — i.e. speculatively kill intervening slots from a forked
        // shred's header. Agave has NO equivalent: its `generate_new_bank_forks`
        // (agave-4.0.0/core/src/replay_stage.rs:4575-4593) simply does not
        // create banks for slots without a frozen parent, so "intervening
        // skipped slots" never enter the bank tree to begin with. There is no
        // Agave call to `set_dead_slot` for leader-skip claims; the absence
        // of a bank IS the death signal.
        //
        // Empirical history (preserved for context):
        //   - PR-5y v1 (pre-2026-05-19): the unguarded leader-skip kill marked
        //     three canonical cluster slots (slot 409528840/841/842) dead based
        //     on a forked validator's parent_off shred. Bank hash divergence
        //     cascaded from there.
        //   - PR-5y v2 (2026-05-19): added cluster-SH orphan-confirm gate
        //     before the kill. Empirical fire count in binary 6cc7d8a:
        //     0 PHASE-J-FALSE-POSITIVE-AVOIDED events.
        //   - Task #26 callsite 3 removal (2026-05-26, this commit): drop the
        //     entire leader-skip kill block. Agave's bank-tree invariant
        //     (parent must be frozen — see `replay_stage.zig:3188 getOrCreateBank`)
        //     enforces the canonical behavior structurally. No regression to
        //     PR-5y v1's bug because we no longer attempt the kill at all.
        //
        // See: agave-4.0.0/core/src/replay_stage.rs:4575-4593 generate_new_bank_forks
        //      Byte-extractor Section C #3 verdict: "REDUNDANT and non-canonical"

        // Phase 1: Parse and replay entries (TX execution + account loading)
        const t1 = std.time.milliTimestamp();
        const goc_ms: i64 = t1 - t0a; // getOrCreateBank wall-clock
        if ((self.stats.slots_replayed.load(.monotonic) <= 30 or self.stats.slots_replayed.load(.monotonic) % 50 == 0) and goc_ms > 50) {
            std.log.warn("[GOC-SLOW] slot={d} getOrCreateBank={d}ms", .{ slot, goc_ms });
        }
        self.replayEntries(bank, assembled_data) catch |err| {
            std.log.debug("[REPLAY] Failed to replay slot {d}: {any} (data_len={d})\n", .{ slot, err, assembled_data.len });
            return;
        };
        const t2 = std.time.milliTimestamp();

        // Set collector_id (slot leader) before freeze so fee distribution works.
        // AGAVE-BRIDGE: fetched from RPC. TODO: compute natively from stake weights.
        if (self.getSlotLeader) |leaderFn| {
            if (leaderFn(slot)) |leader| {
                bank.collector_id = .{ .data = leader.data };
            }
        }

        // Phase 2: Freeze — compute accounts delta hash + bank hash
        // Capture watermark: freeze() appends sysvar writes to pending_writes.
        // We must flush ONLY those new entries (indices >= pre_freeze_len) to AccountsDb.
        // The replay-path entries (indices < pre_freeze_len) were already flushed in
        // replayEntriesInternal and their .data may point to freed batch_arena memory.
        const pre_freeze_len = bank.pending_writes.items.len;

        // d27mm-ENFORCE (2026-05-12): Agave-canonical port of
        // agave-4.0/core/src/replay_stage.rs:3518-3553. Verify the last
        // DATA_SHREDS_PER_FEC_BLOCK=32 data shreds share one merkle root
        // BEFORE freezing. If not, mark dead and skip freeze (no cascade —
        // children orphan naturally via pending_chain 5-min TTL).
        //
        // History:
        //   d27mm-v1 (2026-05-11): shipped with cascade-orphan + buggy merkleRoot
        //     layout → 351 cascade orphans on a SINGLE false positive at slot
        //     407,801,882 (slot was actually ALIVE in cluster). Reverted.
        //   d27mm-FIX (2026-05-12): Corrected merkleRoot() chained-shred layout
        //     (chained_merkle_root is BEFORE proof, INSIDE leaf scope — was
        //     wrongly placed AFTER proof in `suffix_size` calc). Shadow-mode
        //     verified 132 slots with 0 false positives. See shred.zig:184.
        //   d27mm-ENFORCE (current): gate re-enabled, cascade still removed.
        //     With merkleRoot correct, real dead slots are RARE — natural
        //     pending_chain TTL handles child orphan without explicit cascade.
        //
        // Agave reference: agave-4.0/ledger/src/blockstore.rs:3822-3924 +
        //                  agave-4.0/ledger/src/shred/merkle_tree.rs:108
        // d28ll (2026-05-12): port of SIMD-0340 validate_chained_block_id from
        // Agave RC0/RC1 blockstore_processor.rs:2398 `check_chained_block_id`.
        //
        // Two-part check on the slot's shred set:
        //   (1) Last DATA_SHREDS_PER_FEC_BLOCK=32 data shreds share ONE
        //       merkle root → use as this slot's block_id. [d27mm content]
        //   (2) THIS slot's first shred chained_merkle_root == PARENT bank's
        //       block_id. Mismatch = orphaned fork — Agave marks dead. [d28ll]
        //
        // Both are SHADOW (warn-only) for the first deployment per d27mm
        // lesson: re-enabling enforce after 380 false-positive-free slots
        // still surfaced a fresh FP under production traffic (0.2% rate,
        // enough to halt the chain). Need ≥1000 cluster-verified slots with
        // 0 FPs before promoting to ENFORCE. Feature `vcmrbYbiMVK…` (SIMD-0340)
        // is ACTIVE on testnet since slot 406,604,256 — cluster Agave validators
        // are already enforcing this check, which is why Vexor's `dead-slot
        // acceptance` carrier (see project_d28hh_REAL_CARRIER_dead_slot_…
        // memory) exists in the first place.
        if (self.shred_assembler) |sa| {
            sa.mutex.lock();
            const slot_asm_opt = sa.slots.get(slot);
            // FIX 2026-06-02 — FEC-GATE canonical alignment to Agave v4.1.
            // block_id = merkle root of the SINGLE last data shred, exactly as
            // Agave v4.1 `get_block_id` → `get_last_shred_merkle_root`
            // (blockstore.rs:3250/3230, TowerBFT path). Agave v4.1 DELETED the
            // 4.0 `check_last_fec_set` 32-shred completeness gate (zero hits in
            // 4.1 src) and Firedancer never had a replay-time gate. The old
            // `checkLastFecSet32()` gate false-fired on legal blocks whose final
            // FEC set has <32 data shreds → `incomplete_final_fec_set` → those
            // cluster-canonical slots were marked DEAD (PR-5ai retroactive
            // enforce) → FORK-INFO-INVALID-ANCESTOR cascade → the tower could not
            // vote past the last clean slot → permanent delinquency. We no longer
            // gate freeze on FEC-set structure. Slot integrity remains guaranteed
            // by bank_hash verification + the SIMD-0340 chained-block-id check
            // immediately below (which now receives a CORRECT block_id even when
            // the final FEC set is <32 — previously it fell back to a seed).
            const block_id_32: ?[32]u8 = if (slot_asm_opt) |sa_ptr|
                sa_ptr.lastShredMerkleRoot32()
            else
                null;
            // d28ll: chained_merkle_root from this slot's first data shred
            // (Agave's `get_parent_chained_block_id` — the value the leader
            // claims for the parent slot's block_id).
            const child_chained_root: ?[32]u8 = if (slot_asm_opt) |sa_ptr|
                sa_ptr.firstShredChainedMerkleRoot()
            else
                null;
            sa.mutex.unlock();

            if (block_id_32) |mr| {
                bank.block_id = mr;
                bank.block_id_source = .replayed_last_fec;
            } else if (comptime build_options.leader_mode) {
                // Multi-slot leader-window chaining (2026-06-19): a slot WE produced has no received
                // shreds in the ShredAssembler (block_id_32 null), so feed forward OUR produced last-FEC
                // merkle root (stashed at produce time, self_produced_block_id) as this slot's block_id →
                // the NEXT slot of our leader window can chain to it. fetchRemove keeps the stash bounded.
                // Non-consensus (block_id is the chained-root source, not a bank_hash input).
                if (self.self_produced_block_id.fetchRemove(slot)) |kv| {
                    bank.block_id = kv.value;
                    bank.block_id_source = .self_produced;
                }
            }

            // d28ll-SHADOW: SIMD-0340 chained_block_id check. Compares THIS
            // slot's first-shred chained_merkle_root against the parent bank's
            // block_id. Mismatch ⇒ orphaned fork — cluster considers parent
            // dead but Vexor's TVU accepted child shreds anyway.
            //
            // Agave canonical (blockstore_processor.rs:2398-2434):
            //   - Feature gate Inactive ⇒ Pass (skip check)
            //   - Parent chained_block_id Unavailable (shred 0 missing) ⇒ Pass
            //   - Parent's last shred merkle root unavailable (e.g. snapshot
            //     anchor — Err(_)) ⇒ Pass
            //   - Otherwise compare; Mismatch ⇒ set_dead_slot + return
            //
            // Vexor SHADOW emission first — no mark-dead until validated.
            if (child_chained_root) |child_root| {
                const parent_slot = bank.parent_slot orelse 0;
                if (parent_slot != 0) {
                    self.banks_lock.lockShared();
                    const parent_bank_opt = self.banks.get(parent_slot);
                    const parent_block_id_opt: ?[32]u8 = if (parent_bank_opt) |pb| pb.block_id else null;
                    const parent_block_id_source: bank_mod.BlockIdSource =
                        if (parent_bank_opt) |pb| pb.block_id_source else .none;
                    // PR-5av Phase 5 (2026-05-22): capture sentinel state under
                    // the same lock to avoid races. Sentinels carry zero-hash
                    // block_id placeholders that would always mismatch and
                    // pollute the SHADOW enforce queue (or, worse, trigger
                    // markSlotDead if cluster-orphan check coincidentally
                    // matched). Always-false when -Dsentinel_node is OFF
                    // because no code sets is_sentinel=true in that build.
                    const parent_is_sentinel: bool = if (parent_bank_opt) |pb| pb.is_sentinel else false;
                    self.banks_lock.unlockShared();

                    if (parent_is_sentinel) {
                        // Parent is a sentinel — its block_id is a zero-hash
                        // placeholder (or whatever createSentinelBank seeded).
                        // Chain-verify against it is meaningless. Skip silently.
                        // Phase 5 design: chain_confirmed remains false until
                        // the sentinel is torn down and the slot replays normally.
                    } else if (parent_block_id_opt) |parent_root| {
                        if (!std.mem.eql(u8, &child_root, &parent_root)) {
                            const sct = @import("vex_network").slot_chain_tracker;
                            // PR-5g v3 (2026-05-15): NARROW back to .manifest-only.
                            // v2 widened to .replayed_last_fec per d28-ccc bmtree-32
                            // memo, but EMPIRICALLY at slot 408484888 v2 fired a
                            // FALSE POSITIVE: parent slot 408484887 byte-matched
                            // cluster's bank_hash but Vexor's locally-computed
                            // last-FEC merkle root (block_id=adc2c7a2..) DIFFERED
                            // from what slot 888's leader claimed for parent
                            // (39bc7f32..). Vexor's bmtree-32 still produces a
                            // different root than leaders compute. Marking slot
                            // 888 dead cascaded the entire pending_chain (572+
                            // deferred slots), stalling the validator.
                            // .manifest source IS still trusted (snapshot tail
                            // is canonical cluster-rooted). Re-widen only after
                            // verifying bmtree-32 against live testnet shreds.
                            // PR-5y (2026-05-19): widen ENFORCE to also fire when
                            // parent_block_id_source == .replayed_last_fec AND the cluster
                            // SlotHashes oracle CONFIRMS the parent slot is orphaned.
                            //
                            // Why the previous gate (.manifest only) was insufficient:
                            // After cold-boot from a snapshot WITHOUT block_id (older format),
                            // parent_block_id_source for every replayed slot becomes
                            // .replayed_last_fec (derived at freeze time from the slot's own
                            // last-FEC bmtree-32 root). The .manifest-only gate skipped ENFORCE
                            // for ALL such slots → forked-leader slots passed the shadow gate
                            // unchallenged → Vexor froze phantom slots like 409528842 with
                            // parent=409528838 (cluster says 842 was SKIPPED entirely).
                            //
                            // Why we can't blindly widen to .replayed_last_fec:
                            // PR-5g v2 tried this and caused a 572-slot cascade at slot
                            // 408484888 because Vexor's bmtree-32 produces different last-FEC
                            // roots than leaders even on the canonical fork (subtle
                            // last-shred discrimination bug at the bmtree-32 layer).
                            //
                            // Task #26 Phase 2 (2026-05-27): Agave-canonical widen.
                            // Previously `safe_to_enforce` required either
                            // .manifest source OR (.replayed_last_fec AND
                            // cluster_says_parent_orphan). The cluster-orphan
                            // gate was a Vexor-only invention; Agave's
                            // blockstore_processor.rs:2398 path applies
                            // check_chained_block_id unconditionally. The
                            // WIDEN-PROBE counter ran for 1183+ banks on
                            // binary 169ac58a (2026-05-27 00:30 UTC soak) with
                            // ZERO events — empirical evidence the cluster-
                            // orphan gate never differed from "enforce" on
                            // testnet. Remove the gate, the probe log, and
                            // the isKnownOrphanSlot call site (the function
                            // itself is deleted at line ~1133). PR-5ah
                            // canonical-match guard at markSlotDead still
                            // refuses to kill slots whose local bank_hash
                            // matches cluster's SH, so the residual safety
                            // net for bmtree-32 false-positives is preserved.
                            // TOURNIQUET 2026-06-03 (revert the 2026-05-27 Task #26
                            // unconditional widen): enforce mark-dead ONLY when the
                            // parent block_id came from the snapshot MANIFEST (canonical,
                            // cluster-rooted). For .replayed_last_fec the block_id is
                            // derived from Vexor's bmtree-32 last-shred merkle root, which
                            // is KNOWN to differ from the leader's merkle root even on the
                            // canonical fork (documented above @408484888; reproduced live
                            // @412802919 2026-06-03: child_chained_root=5d075655 !=
                            // parent_block_id=604095a5, src=replayed_last_fec, killing a
                            // slot getBlock confirms is canonical → 128-slot cascade wedge).
                            // The 5/27 widen was gated on "verify bmtree-32 against live
                            // testnet shreds" — never done. Until the shred merkle-root
                            // computation is ported canonically (Agave ledger/src/shred/
                            // merkle.rs + FD fd_shred) so bmtree-32 matches leaders byte-
                            // for-byte, enforcing on .replayed_last_fec false-positives.
                            // .replayed_last_fec falls through to SHADOW (log, no kill);
                            // integrity stays guaranteed by bank_hash-vs-cluster.
                            // FEC-RECOVERY ZERO-ROOT GUARD (2026-06-03): the
                            // snapshot-manifest base/block_id fix re-arms
                            // .manifest enforcement at the snapshot anchor→child
                            // (the anchor's block_id is now correctly extracted,
                            // src=.manifest). A child that arrived via FEC
                            // recovery leaves its chained_root @memset 0 — Vexor's
                            // fec_resolver reconstructs erasure DATA but does not
                            // re-attach the chained_root (the canonical bmtree-32/
                            // chained_root port is task #8). An all-zero child_root
                            // is "couldn't extract", NOT a genuine fork-orphan, so
                            // enforcing mark-dead on it would false-kill a canonical
                            // slot — the SESSION-14 wedge shape. A REAL fork-orphan
                            // always carries the forked leader's non-zero merkle
                            // root, so this guard suppresses ONLY the recovery
                            // artifact and preserves all legitimate enforcement.
                            var child_root_nonzero = false;
                            for (child_root) |b| {
                                if (b != 0) {
                                    child_root_nonzero = true;
                                    break;
                                }
                            }
                            const safe_to_enforce = (parent_block_id_source == .manifest) and child_root_nonzero;
                            if (sct.SIMD_0340_ENFORCE_MARK_DEAD and safe_to_enforce) {
                                // Carrier: at slot 408475681 (PR-5f boot, anchor+1386)
                                // 568 fee-payers each over-charged by 5000 lamports
                                // due to accumulated orphan-slot pollution from
                                // suppressed CHAINED-BLOCK-ID-SHADOW events. ENFORCE
                                // here calls markSlotDead which triggers
                                // purgeUnrootedSlot — closing the pollution path
                                // Agave canonical blockstore_processor.rs:2398
                                // handles via set_dead_slot + return.
                                std.log.warn(
                                    "[CHAINED-BLOCK-ID-ENFORCE] slot={d} parent={d} child_chained_root={x} parent_block_id={x} src={s} — SIMD-0340 fork-orphan, marking dead",
                                    .{ slot, parent_slot, child_root[0..8].*, parent_root[0..8].*, @tagName(parent_block_id_source) },
                                );
                                // 2026-05-28 FIX #86/#87 (cherry-picked onto FIX #77 baseline).
                                //
                                // Canonical decision: mark ONLY the child dead. Both Agave
                                // (blockstore_processor.rs:2461 + replay_stage.rs:2495-2573)
                                // and Firedancer (fd_reasm.c:849-851) do exactly this on
                                // chained_block_id mismatch — neither "up-cascades" to also
                                // mark the parent dead. A prior Vexor experiment (FIX #82,
                                // never landed on this branch — it lived in commit 60111b6
                                // which was reverted with the FIX #79 boot regression) did
                                // up-cascade and proved incorrect: it killed both the phantom
                                // parent AND the canonical child, leaving fork-choice with
                                // no viable path (2026-05-28 ~05:00 UTC wedge at PID 268026,
                                // slot 411405258 SKIPPED on canonical chain).
                                //
                                // The companion FIX #87 below (in markSlotDead) calls
                                // markForkInvalidCandidate so fork-choice downweights the
                                // dead subtree and naturally picks alternate forks via
                                // vote-weight — matching Agave's mark_dead_slot →
                                // mark_fork_invalid_candidate flow.
                                //
                                // Result: child marked dead (canonical), fork-choice updates
                                // weights, parent fork (phantom-frozen but unreferenced) wins
                                // by default OR fork-choice finds a sibling. No up-cascade.
                                self.markSlotDead(slot, "SIMD-0340 chained_block_id inter-slot mismatch");
                                return;
                            }
                            std.log.warn(
                                "[CHAINED-BLOCK-ID-SHADOW] slot={d} parent={d} child_chained_root={x} parent_block_id={x} src={s} — Agave would mark dead (SIMD-0340 fork-orphan); suppressed",
                                .{ slot, parent_slot, child_root[0..8].*, parent_root[0..8].*, @tagName(parent_block_id_source) },
                            );
                            // PR-5z (2026-05-19), simplified 2026-05-27 Task #26:
                            // queue this slot in pending_shadow_slots so the 30s
                            // timeout sweep eventually drops it. The retroactive
                            // orphan-confirm sweep was removed (isKnownOrphanSlot
                            // gone — Agave-canonical doesn't re-query cluster's
                            // SlotHashes for orphan confirmation). The pending
                            // queue is preserved only to bound memory; future
                            // cleanup can remove it entirely.
                            self.pending_shadow_slots.append(self.allocator, .{
                                .slot = slot,
                                .parent_slot = parent_slot,
                                .flagged_at_ms = std.time.milliTimestamp(),
                            }) catch {};
                        } else {
                            // PR-5av Phase 5 (2026-05-22): single-step chain
                            // verify SUCCESS — child's chained_merkle_root
                            // matches parent's block_id, so this bank chains
                            // to a confirmed ancestor. Set chain_confirmed so
                            // Phase 6's relaxed death sentence can treat this
                            // slot as canonical. Per-FEC walk-back skipped:
                            // shred assembler already validates within-slot
                            // chains via SlotChainTracker; full backward chain
                            // check is duplicative absent a specific gap.
                            bank.chain_confirmed = true;
                            std.log.warn(
                                "[CHAIN-VERIFY-OK] slot={d} parent={d} chained_root={x} parent_src={s}",
                                .{ slot, parent_slot, child_root[0..8].*, @tagName(parent_block_id_source) },
                            );
                        }
                    } else if (parent_bank_opt) |pb| {
                        // d28oo (2026-05-12): snapshot anchor block_id seeding.
                        // Parent bank exists but its block_id is null (typical
                        // for the snapshot anchor — we didn't run shred-replay
                        // for it so we never derived its last-shred merkle
                        // root). Adopt THIS child's chained_merkle_root claim
                        // as the parent's block_id. The leader of the child
                        // slot claims this is what the parent's block_id was;
                        // if the leader is canonical, this is correct; if the
                        // leader is forked, we'd silently adopt a wrong root —
                        // but that's no worse than today (block_id=null means
                        // we currently silently pass everything). With seed,
                        // ALL subsequent slots whose parent IS this one can be
                        // validated against a real reference.
                        //
                        // Thread-safety: `block_id` is a single `?[32]u8` field.
                        // Concurrent writers of the SAME value (multiple shreds
                        // from the same leader = same chained_root) race
                        // benignly. Different-leader fork scenarios race to
                        // first-write-wins; that's an architectural property
                        // (no worse than null-pass current behavior).
                        //
                        // We could use lockExclusive here but the cost would
                        // serialize the whole bank tree on every slot freeze.
                        // Single-field assignment is the right trade-off.
                        pb.block_id = child_root;
                        pb.block_id_source = .d28oo_first_shred;
                        std.log.warn(
                            "[CHAINED-BLOCK-ID-SEED] slot={d} parent={d} seeded parent.block_id={x} from this slot's first chained_root (snapshot anchor handoff)",
                            .{ slot, parent_slot, child_root[0..8].* },
                        );
                    }
                    // parent_bank null:
                    // mirror Agave's `Err(_) ⇒ Pass` — parent is genuinely
                    // missing from blockstore (likely pruned below root).
                    // No comparison possible; do nothing.
                }
            }

            // d28ll (vex-037 revival): also check the TVU-side SlotChainTracker
            // for any violations observed at SHRED INSERT time. Catches BOTH
            // (a) intra-slot chain violations (FEC sets within this slot whose
            //     chained_merkle_root didn't match the prior FEC set's root),
            // (b) inter-slot violations where the parent was on a fork.
            // The TVU detection runs milliseconds after each FEC completes —
            // far earlier than this freeze-time gate. Both gates share SHADOW
            // semantics until ≥1000-slot FP-free verification window.
            sa.mutex.lock();
            const violation_opt = sa.chain_tracker.observedViolation(slot);
            sa.mutex.unlock();
            if (violation_opt) |v| {
                const exp_hex = std.fmt.bytesToHex(v.expected_root, .lower);
                const obs_hex = std.fmt.bytesToHex(v.observed_root, .lower);
                const sct = @import("vex_network").slot_chain_tracker;
                if (sct.SIMD_0340_ENFORCE_MARK_DEAD) {
                    std.log.warn(
                        "[CHAIN-TRACKER-ENFORCE] slot={d} fec={d} kind={s} expected={s} observed={s} — marking dead per SIMD-0340",
                        .{ slot, v.fec_set_index, @tagName(v.kind), &exp_hex, &obs_hex },
                    );
                    self.markSlotDead(slot, "SIMD-0340 chained_merkle_root violation");
                    return;
                }
                std.log.warn(
                    "[CHAIN-TRACKER-SHADOW] slot={d} fec={d} kind={s} expected={s} observed={s} — Agave would mark dead; suppressed",
                    .{ slot, v.fec_set_index, @tagName(v.kind), &exp_hex, &obs_hex },
                );
            }
        }

        const stub_rent = struct {
            fn f(_: usize) u64 {
                return 890_880;
            }
        };
        bank.freeze(stub_rent.f) catch |err| {
            // d23-diag (2026-05-11): upgraded debug→warn to surface silent
            // freeze failures that cascade through chain-defer (root cause
            // of d22 "tail-chase" — first catchup slot's freeze throws,
            // bank stays unfrozen, every subsequent slot times out at
            // getOrCreateBank's wait-for-parent-frozen loop and gets
            // deferred. Revert to debug once the failing freeze step is
            // identified and fixed.)
            std.log.warn("[REPLAY-TRACE] slot={d} freeze FAILED: {any}", .{ slot, err });
            return;
        };
        self.emitGeyserSlot(slot, bank.parent_slot, 0); // geyser: SlotStatus.processed (bank frozen)

        // P5#1 FLIGHT-RECORDER freeze-tap (forensic moat). Comptime-dead unless -Dvex_ledger;
        // runtime-dormant unless VEX_LEDGER_FLIGHT. Best-effort, NEVER fatal to replay. Reads the
        // bank_hash INPUT decomposition off the just-frozen bank (do NOT re-derive — mirrors the
        // [BANK-FROZEN] emit at bank.zig:4449-4459) and journals it next to the shreds. @prov:replay.flight-recorder-bank-hashes-cf
        // (gated together — its 37B emitter golden is still unconfirmed,
        // is_duplicate_confirmed=false at freeze time; promote to always-on after the golden lands).
        if (comptime build_options.vex_ledger) {
            if (self.flight_record_enabled) {
                if (self.vex_ledger_flight) |vl| {
                    const rec = vex_ledger_mod.FlightRecord{
                        .bank_hash = bank.bank_hash.data,
                        .parent_hash = bank.parent_hash.data,
                        .signature_count = bank.signature_count,
                        .poh_hash = bank.poh_hash.data,
                        .accounts_lt_hash = bank.accounts_lthash.asBytes().*,
                    };
                    vl.putFlightRecord(slot, rec) catch {};
                    vl.putBankHash(slot, bank.bank_hash.data, false) catch {};
                }
            }
            // P5 MOAT #2 (M2) FREEZE-TAP: single non-blocking 40-byte SPSC push {slot,bank_hash}.
            // Runtime-dormant unless VEX_DIVERGE_ALARM armed the handle. enqueue() is infallible
            // (drop-oldest ring) — it can NEVER block or fail, so it can NEVER perturb bank_hash or
            // consensus timing. The alarm thread does ALL the RPC/replay off-path. @prov:replay.diverge-alarm-tap
            if (self.diverge_alarm_enabled) {
                if (self.diverge_alarm) |da| da.enqueue(slot, bank.bank_hash.data);
            }
        }

        // Q2 getBlock blockhash sourcing: store the slot's blockhash (= bank.poh_hash, the PoH last_blockhash
        // — the SAME value FlightRecord.poh_hash holds) when content capture is on, so getBlock can emit
        // blockhash + previousBlockhash (PoH, NOT in the tx wire). Gated VEX_LEDGER_CONTENT (independent of
        // the flight tap), reusing the same vl handle. putBlockhash lands via LEDG's KIND_BLOCKHASH drop —
        // coded to putBlockhash(slot, [32]u8); best-effort + dormant by default. getBlock reads
        // getBlockhash(slot) + getBlockhash(parent_slot).
        if (comptime build_options.vex_ledger) {
            if (self.vex_ledger_flight) |vl| {
                if (Bank.contentCaptureActive()) {
                    vl.putBlockhash(slot, bank.poh_hash.data) catch {};
                }
            }
        }

        // Fix A: Flush post-freeze sysvar writes to AccountsDb.
        // Uses watermark to avoid re-reading dangling arena pointers from replay entries.
        if (self.accounts_db) |db| {
            if (bank.pending_writes.items.len > pre_freeze_len) {
                flushPendingWritesFromIndex(bank, db, pre_freeze_len);
            }
        }

        // [LTHASH-VERIFY] Decisive byte-vs-accumulation test (env VEX_VERIFY_LTHASH_SLOT).
        // Placed HERE — after BOTH the in-replay main-tx flush (flushPendingWritesToDb)
        // AND the post-freeze sysvar flush (flushPendingWritesFromIndex above) — so the
        // full writeset for this slot is committed into the read path (unrooted_ring).
        // The recompute re-sums accountLtHash over every account's COMMITTED state at
        // bank.slot and compares to the incremental bank.accounts_lthash:
        //   MATCH    ⇒ accumulator correct for Vexor's states ⇒ divergence is BYTE-class.
        //   MISMATCH ⇒ ACCUMULATION-class carrier (dropped/doubled/mis-based contribution).
        // Single-slot, env-gated; production deploys pay zero cost (one getenv + slot compare).
        if (self.accounts_db) |db| {
            if (std.posix.getenv("VEX_VERIFY_LTHASH_SLOT")) |env_slot_str| {
                if (std.fmt.parseInt(u64, std.mem.trim(u8, env_slot_str, " \t\r\n"), 10)) |target_slot| {
                    if (target_slot == bank.slot) {
                        db.recomputeAndVerifyLtHash(bank);
                    }
                } else |_| {}
            }
        }

        // [LT-WRITE-LOCALIZER] Writeset-sized accumulation-carrier localizer (env
        // VEX_VERIFY_LTHASH_WRITES, optional lower-bound VEX_VERIFY_LTHASH_SLOT).
        // Runs at replay speed: for each changed pubkey this slot, compares the
        // EXACT lthash contribution freeze() applied (captured in bank.lt_write_capture
        // during Pass C) against accountLtHash(getAccountInSlot committed readback).
        // A DIFFER names the carrier account+slot — the account whose accumulator
        // delta was computed from different bytes than committed to storage (the
        // DM-lamport / store-rotation ACCUMULATION class). Placed HERE, after the
        // same full-writeset flush the recompute relies on, so the readback is the
        // committed final state. Env-gated; production deploys pay zero cost.
        if (self.accounts_db) |db| {
            if (std.posix.getenv("VEX_VERIFY_LTHASH_WRITES") != null) {
                var run = true;
                if (std.posix.getenv("VEX_VERIFY_LTHASH_SLOT")) |lb_str| {
                    if (std.fmt.parseInt(u64, std.mem.trim(u8, lb_str, " \t\r\n"), 10)) |bound| {
                        run = bank.slot >= bound;
                    } else |_| {}
                }
                if (run) db.verifyLtHashWrites(bank);
            }
        }

        const t3 = std.time.milliTimestamp();

        // Update root_bank if the bank has a valid poh hash
        const zero_hash = [_]u8{0} ** 32;
        if (!std.mem.eql(u8, &bank.poh_hash.data, &zero_hash)) {
            self.root_bank.store(bank, .release);
            // Cache poh_hash as tx_blockhash — deterministic from PoH entries.
            // @prov:replay.cached-blockhash-poh Curl fallback for bootstrap.
            self.cached_blockhash = bank.poh_hash;
            self.cached_blockhash_time = @as(i64, @intCast(std.time.timestamp()));
        }

        // Register this slot in GHOST fork tree.
        // PHASE-1 (2026-05-26): now uses (Slot, Hash) keying via addForkCompat,
        // which seeds the tree's root from the first bank's parent and inserts
        // each subsequent bank as a child of (parent_slot, parent_hash).
        // The hash-aware keying is the structural prerequisite for representing
        // equivocating sibling slots — without it, fork choice cannot
        // distinguish two blocks at the same slot with different bank_hashes.
        if (self.fork_choice) |*fc| {
            const fc_mod = @import("vex_consensus").fork_choice;
            fc_mod.addForkCompat(fc, slot, bank.parent_slot, bank.bank_hash, bank.parent_hash) catch {};

            // PHASE-2 (2026-05-26): feed cluster votes into fork_choice's
            // latest_votes map so bestSlot() can weight forks by real stake.
            //
            // REDESIGN (2026-05-26, supersedes original delta-over-pending_writes):
            // The original path walked bank.pending_writes directly to extract
            // vote-program writes. This crashed in production (SIGSEGV at
            // vote_state_serde.zig:1422) because vote-tx .data slices are
            // allocated with arena_alloc (per-tx batch_arena) which is freed
            // by `defer batch_arena.deinit()` at replay_stage.zig:3460 BEFORE
            // this onSlotCompleted hook runs. See
            // project-phase2-segfault-rootcause-2026-05-26 for the full trace.
            //
            // @prov:replay.fork-choice-vote-feed — a stable per-bank view of
            // vote accounts, NOT a delta.
            //
            // REDESIGN-2 (2026-06-03): the 2026-05-26 redesign read
            // `db.unflushed_cache`, but that is a write-back DELTA drained
            // independently by `flushCacheToDisk` — at the tip the flush keeps
            // up, the cache empties of vote accounts, and the feed returned
            // `vote_accounts=0 emitted=0` → no stake weight → no vote
            // (delinquent-at-tip while replaying cleanly; intermittent because
            // catch-up's flush lag masked it). The correct stable analog is
            // `db.top_votes`: snapshot-seeded, upserted on every
            // vote commit, survives the flush and root advance.
            // `fork_choice_feed.buildVoteAccountBatch` iterates it under
            // `top_votes_lock` (pass 1), taking each voter's tower top, and feeds
            // the PubkeyVote batch to `fc.addVotes`.
            //
            // PROPERTIES:
            //   - Re-emits ALL known voters every bank (mirrors Agave), so a
            //     voter previously `no_bank_hash` gets re-evaluated next bank;
            //     inactive voters fall out naturally when `bank_hash_ctx.lookup`
            //     of their stale vote slot returns null.
            //   - No lifetime hazard — `top_votes_lock` held during pass 1
            //     (scan only, no .data deref); `bank_hash_ctx.lookup` runs in
            //     pass 2 outside the lock to avoid any interaction with
            //     `banks_lock`.
            //
            // Stake comes from accounts_db.epoch_stakes — same snapshot-frozen
            // source the leader schedule uses (proven correct via
            // leader_schedule.zig populateAgaveCanonical). Wrapped in
            // EpochStakeLookup which walks to the right epoch on each
            // lookup (handles epoch boundaries transparently).
            //
            // Allocator: self.allocator (long-lived) — batch slice is tiny
            // (~100 voters × ~50 bytes = ~5KB) and freed immediately after
            // addVotes. Not on bank.allocator because the batch lifetime
            // is decoupled from the bank's arena lifecycle.
            //
            phase2_delta: {
                const db_ptr = self.accounts_db orelse break :phase2_delta;
                if (db_ptr.epoch_stakes.len == 0) break :phase2_delta;

                // bank_hash_ctx adapter — looks up frozen bank_hash from
                // self.banks under banks_lock (shared). Built inline since
                // it captures self by reference.
                //
                // PATCH-1 (2026-05-26, byte-extractor finding): @prov:replay.frozen-bank-hash-lookup-guard
                // Returns Some(hash) only when the bank is
                // POST-freeze (bank.zig:3094 computes bank_hash, line 3195
                // sets is_frozen=true AFTER). Without this guard, sentinels
                // and in-flight sibling banks present in self.banks return
                // their zero-initialized bank_hash (bank.zig:469
                // .bank_hash = Hash.default()), polluting latest_votes with
                // (voter, slot, [0;32]) entries that subsequently BLOCK any
                // future vote from the same voter for the same slot —
                // strict-newer filter at fork_choice.zig:699-705 sees
                // prev_hash=[0;32] < new_hash=real and returns continue.
                const BankHashCtx = struct {
                    rs: *Self,
                    pub fn lookup(ctx: @This(), s: u64) ?core.Hash {
                        ctx.rs.banks_lock.lockShared();
                        defer ctx.rs.banks_lock.unlockShared();
                        const b = ctx.rs.banks.get(s) orelse return null;
                        if (!b.is_frozen) return null; // @prov:replay.frozen-bank-hash-lookup-guard
                        return b.bank_hash;
                    }
                };
                const bh_ctx = BankHashCtx{ .rs = self };

                // FIX (switch-proof gossip-arming wedge, live specimen slot 422521275,
                // 2026-07-17, fix/switchproof-gossip-arming-2026-07-17): switched from
                // `buildVoteAccountBatch` (sourced `db.top_votes`, a side cache upserted
                // only by AccountsDb.refreshTopVoteForWrite from the flush chokepoints)
                // to `buildVoteAccountBatchFresh` (reads EVERY staked voter's
                // vote-account state directly off `db`, fork-aware, at THIS bank —
                // no persistent cache in the path to go stale). See
                // fork_choice_feed.zig `buildVoteAccountBatchFresh` doc for the full
                // root-cause writeup + Agave citation (consensus.rs:407
                // collect_vote_lockouts / replay_stage.rs:4391 compute_bank_stats) and
                // the in-repo precedent (bank.zig:1308 carrier #15, the Clock estimator
                // hit the identical top_votes-staleness bug class and was fixed the
                // same way).
                const current_epoch = bank.epoch_schedule.getEpoch(bank.slot);
                const ffeed = @import("fork_choice_feed.zig");
                const out = ffeed.buildVoteAccountBatchFresh(
                    self.allocator,
                    db_ptr,
                    db_ptr.epoch_stakes,
                    current_epoch,
                    bank.slot,
                    bank.ancestors(),
                    bh_ctx,
                ) catch break :phase2_delta;
                defer self.allocator.free(out.votes);

                if (out.votes.len > 0) {
                    const Lookup = ffeed.EpochStakeLookup(@TypeOf(db_ptr.epoch_stakes));
                    const stake_lookup = Lookup{
                        .epoch_stakes = db_ptr.epoch_stakes,
                        // FIX-2 (2026-06-10): thread the REAL schedule from
                        // the frozen bank (clock.epoch source of truth).
                        .epoch_schedule = bank.epoch_schedule,
                    };
                    _ = fc.addVotes(out.votes, stake_lookup) catch |e| {
                        std.log.warn(
                            "[FORK-CHOICE-DELTA] addVotes failed at slot {d}: {any} " ++
                                "(votes={d} candidates={d} no_account={d} no_lv={d} no_bh={d})",
                            .{
                                slot,                   e,                    out.votes.len,
                                out.stats.candidates,   out.stats.no_account, out.stats.no_last_vote,
                                out.stats.no_bank_hash,
                            },
                        );
                        break :phase2_delta;
                    };
                }

                // Diag log gated to first 50 banks + every 25th afterward
                // (same cadence as [SLOT-PROFILE] above). Bounds log volume
                // while still confirming the feed fired.
                const tr = self.stats.slots_replayed.load(.monotonic);
                if (tr <= 50 or tr % 25 == 0 or out.stats.no_bank_hash > 0) {
                    std.log.warn(
                        "[FORK-CHOICE-DELTA] slot={d} candidates={d} emitted={d} " ++
                            "no_account={d} no_lv={d} no_bh={d} parse_fail={d}",
                        .{
                            slot,                 out.stats.candidates,   out.stats.emitted,
                            out.stats.no_account, out.stats.no_last_vote, out.stats.no_bank_hash,
                            out.stats.parse_fail,
                        },
                    );
                }
            }
        }

        ReplayStats.inc(&self.stats.slots_replayed);
        const total_replayed = self.stats.slots_replayed.load(.monotonic);

        // r76-profile (2026-05-11): per-slot timing breakdown for catchup
        // tail-chase investigation. Identifies which phase dominates the
        // ~1.4 slots/sec apply rate (vs cluster's 2.5 slots/sec). Phases:
        //   bank_create = t1 - t0   (getOrCreateBank + chain check)
        //   replay      = t2 - t1   (replayEntries: tx parse + native/BPF dispatch)
        //   freeze      = t3 - t2   (bank.freeze + post-freeze flush)
        //   total       = t3 - t0
        // Pure observability — no behavior change. Emit gated to first 50
        // slots + every 25th afterward to bound log volume.
        if (total_replayed <= 50 or total_replayed % 25 == 0) {
            std.log.warn(
                "[SLOT-PROFILE] slot={d} total_ms={d} bank_create_ms={d} replay_ms={d} freeze_ms={d} n_replayed={d}",
                .{ slot, t3 - t0, t1 - t0, t2 - t1, t3 - t2, total_replayed },
            );
        }

        // d21: now that this slot is frozen, wake any deferred
        // child slots (slots whose target_parent == slot) so they can replay.
        // @prov:replay.chain-connectivity-defer This is the chain-build mechanism:
        // as repair fills the gap (s+1, s+2, ...), each freeze cascades into
        // waking the next pending child.
        self.checkPendingChain(slot);

        // Aggressive cache-to-disk flush (every 100 slots, 5000 entries)
        // Prevents RSS bloat that degrades throughput (2.77→2.05/s over 15 min without this)
        //
        // STEP 5/8 (two_tier): DISABLED. flushCacheToDisk promotes the FORK-BLIND
        // unflushed_cache into the index FILED UNDER THE CURRENT SLOT (not the
        // account's true write slot). Under two_tier the index's higher-slot-wins
        // guard then lets that fake-high-slot stale value CLOBBER the correct
        // fork-aware value that advanceRoot's STEP-5 ring promotion filed under the
        // true rooted slot — the exact reason the 413408129 read stayed stale. The
        // ring promotion in advanceRoot is now the SOLE index writer; advanceRoot
        // also drains rooted cache entries, so RSS stays bounded.
        if (!build_options.two_tier and slot % 100 == 0 and slot > 0) {
            if (self.accounts_db) |db| {
                _ = db.flushCacheToDisk(slot, 5000) catch {};
            }
        }

        // Bank pruning: free old banks below tower root (every 64 slots).
        // Safety valve: if root stalls, fall back to slot-based cutoff (slot - 512)
        // to prevent unbounded bank accumulation. @prov:replay.bank-prune-cutoff
        //
        // F3 (C8d backport): the raw cutoff is CLAMPED via bank_prune.computePruneCutoff
        // so pruneOldBanks can never free a bank the current frame still holds a
        // pointer to. Without the clamp, a catchup-mode tower with root_slot ahead
        // of the replay cursor would push cutoff past the current slot, freeing
        // `bank` here. Subsequent reads of bank.pending_writes.items.len in the
        // [REPLAY] print observed ReleaseSafe-poisoned memory (writes=0xAAAAAAAAAAAAAAAA),
        // then `tx_total = tx_diag_success + tx_diag_parse_fail` panics on integer
        // overflow. Clamp preserves both the current bank AND self.root_bank.
        if (slot % 64 == 0 and slot > 0) {
            const tower_root: ?u64 = if (self.tower) |*t| t.vote_state.root_slot else null;
            const rb_slot: ?u64 = if (self.root_bank.load(.acquire)) |rb| rb.slot else null;
            const cutoff = bank_prune.computePruneCutoff(tower_root, slot, rb_slot);
            if (cutoff > 0) {
                self.pruneOldBanks(cutoff);
            }
            // Wave 6C-1: prune V2 program cache entries older than the
            // retention window so long-running sessions don't accumulate
            // stale loaded programs in memory.
            pruneV2ProgramCache(slot);
            // FIX #18a-A: prune frozen_history below the consensus root.
            // Entries ≥ root are RETAINED (a frozen slot above a stuck root
            // must keep deduping re-deliveries — that IS the carrier case).
            // Growth while stuck is ~2.5 entries/s × 16B — negligible.
            {
                const fh_root: u64 = if (self.accounts_db) |db| db.rooted_slot else 0;
                if (fh_root > 0) {
                    self.pending_chain_lock.lock();
                    defer self.pending_chain_lock.unlock();
                    var fh_it = self.frozen_history.keyIterator();
                    var fh_drop = std.ArrayList(u64){};
                    defer fh_drop.deinit(self.allocator);
                    while (fh_it.next()) |k| {
                        if (k.* < fh_root) fh_drop.append(self.allocator, k.*) catch break;
                    }
                    for (fh_drop.items) |k| _ = self.frozen_history.remove(k);
                    // fix/chain-defer-tip-guard: prune backstop_evicted below root
                    // too (a below-root evicted slot is obsolete — its children
                    // wake via the root-floor). Same lock already held.
                    var be_it = self.backstop_evicted.keyIterator();
                    var be_drop = std.ArrayList(u64){};
                    defer be_drop.deinit(self.allocator);
                    while (be_it.next()) |k| {
                        if (k.* < fh_root) be_drop.append(self.allocator, k.*) catch break;
                    }
                    for (be_drop.items) |k| _ = self.backstop_evicted.remove(k);
                }
            }
            // Task #71 L3 leak fix (2026-06-11): free shred assemblies below
            // the same safe prune cutoff. Rooted slots are final; their
            // SlotAssembly (+copied payloads, ~2.5 MB/slot) was NEVER freed
            // (sweeper skips is_complete; clearCompletedSlot had no callers)
            // = the ~25 GB/h at-tip RSS slope (jeprof 97.3%).
            if (cutoff > 0) {
                if (self.shred_assembler) |sa| {
                    _ = sa.clearRootedSlots(cutoff);
                }
            }
        }

        // ── Task #71 [MEM-BREAKDOWN] (2026-06-10): once-a-minute memory-class
        // telemetry for the RSS-leak diagnosis (28-30 GB/h anon growth at-tip,
        // pinned to never-reclaimed rooted AppendVec heap stores). Cheap atomic/
        // len reads only; the /proc/self/status read is 1 small file per minute.
        {
            const MemDiag = struct {
                var last_ms: i64 = 0;
            };
            const md_now = std.time.milliTimestamp();
            if (md_now - MemDiag.last_ms >= 60_000) {
                MemDiag.last_ms = md_now;
                self.emitMemBreakdown(slot);
                dumpMallocInfo(slot); // VEX_MALLOC_INFO=1 → all-arena XML (residual forensic)
            }

            // ── Task #71 store-reclaim tick (2026-06-10, v2 backlog-paced):
            // drive AppendVec shrink + retired-store reaping from the replay
            // loop (same thread as advanceRoot/promotions — writers and shrink
            // serialize on storage.lock; this keeps GC cursor state
            // single-threaded). @prov:replay.accounts-gc-tick
            //
            // v1 BUG (2026-06-10 delinquency forensic): the tick was throttled
            // to 1 call / 2s × batch=2 = ~1 store/s reclaim. At the TIP that
            // outpaces creation (~1 store/16s), but once the node falls BEHIND
            // and replays fast to catch up, store creation hits ~1/10s while
            // reclaim stayed pinned at ~1/s and the 30s cursor reset kept
            // re-walking the head of the list — so av_heap spiraled 8.6G→20G
            // and RSS pressure deepened the lag (a feedback loop → delinquency).
            //
            // v2 FIX: fire EVERY freeze (no wall-clock throttle) so reclaim
            // frequency self-scales with the freeze rate (faster during
            // catch-up, exactly when creation is faster), and scale the per-
            // tick batch by the live-heap-store backlog so a burst can be
            // drained instead of trickled. Each shrink walk is cheap (mostly-
            // dead 64MB stores copy few live records). Target ~48 live heap
            // stores ≈ 3GB working set.
            if (self.accounts_db) |adb| {
                const heap_stores = vex_store.accounts.g_av_heap_count.load(.monotonic);
                const target: u64 = 48;
                adb.accounts_gc_batch = if (heap_stores > target)
                    @intCast(@min(@as(u64, 64), heap_stores - target + 2))
                else
                    2;
                adb.tickAccountsGc(adb.rooted_slot, @intCast(md_now));
            }
        }

        // Timing breakdown
        const total_ms = t3 - t0;

        // Record for TPS tracking
        self.stats.recordSlot(slot, bank.signature_count, @intCast(@max(1, total_ms) * std.time.ns_per_ms));

        // ── Vote submission ──────────────────────────────────────────────
        // After successful freeze, submit a vote for this slot.
        // Requires: identity_secret, vote_account, and bank_hash.
        // r55-fix: dropped `bank.has_entries` gate (forward-ported from
        // vex-nova c9aeaa0, 2026-04-13). The gate suppressed votes on
        // tick-only slots, dropping the vote rate to ~1% (we measured 5
        // [VOTE-SEND] across 461 frozen slots on r53). @prov:replay.vote-every-frozen-bank
        // Throwaway
        // keys + --no-voting still in place; this only affects vote-send
        // diagnostics until staked keys are wired in (gated separately).
        // G1 (leader_mode): NEVER self-vote a slot WE produced. An own produced slot the cluster has
        // not yet confirmed is an own-only orphan; voting it makes fork-choice lock onto it (tower
        // lockout) and wedges us. The cluster's own votes carry consensus on our broadcast block. When
        // -Dleader_mode is off, `is_own_produced` is comptime-false → the vote path is byte-identical.
        const is_own_produced = if (comptime build_options.leader_mode) self.self_produced.contains(slot) else false;
        if (self.identity_secret != null and self.vote_account != null and !is_own_produced) {
            self.submitVote(bank) catch |err| {
                const VoteErrDbg = struct {
                    var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
                };
                const vc = VoteErrDbg.count.fetchAdd(1, .monotonic);
                if (vc < 5) {
                    std.log.debug("[VOTE-SUBMIT] slot={d} FAILED: {any}\n", .{ slot, err });
                }
            };
            ReplayStats.inc(&self.stats.votes_sent);
        }

        // ── M3 auto-safe-off tripwire evaluation (2026-07-17) ────────────────
        // Latch-first (mirrors revive_detect's "check the latch BEFORE the [there:
        // expensive scan; here: the two extra map lookups] work" discipline): once
        // tripped, skip re-evaluating forever. Only self-produced TX-BEARING slots
        // are in scope (self_produced_tx_bearing) — an empty self-produced slot has
        // nothing to fail on and deliberately does not touch the counter (see
        // txbearing_tripwire.zig's threshold-reasoning doc). NOTE: skipping empty
        // slots entirely (rather than treating them as a "clean" reset) means the
        // tripwire's "2" is really "2 fails with no SUCCESSFUL tx-bearing slot in
        // between", which can span many empty leader slots — see txbearing_tripwire.
        // zig's "HONEST NAMING" note for why this (safe-direction) looseness is
        // deliberate, not a bug.
        if (comptime build_options.leader_mode) {
            if (!self.txbearing_tripwire_state.tripped.load(.acquire) and is_own_produced and
                self.self_produced_tx_bearing.contains(slot))
            {
                const had_fail = self.produce_parity_fail_slots.contains(slot);
                const env_armed = std.posix.getenv("VEX_TXBEARING_BROADCAST") != null;
                if (self.txbearing_tripwire_state.recordSlotOutcome(slot, had_fail)) {
                    if (env_armed) {
                        // REAL trip: broadcast was actually armed, so this slot (and the ONE before
                        // it, per TRIP_THRESHOLD=2) were genuinely at risk of being broadcast dead
                        // blocks. From the NEXT self-produced slot onward, effectiveArmed() forces
                        // empty-block production in-process — no restart.
                        std.log.err(
                            "[TXBEARING-TRIPWIRE-FIRED] slot={d} consecutive_produce_parity_fails={d} >= threshold={d} — AUTO-SAFE-OFF: tx-bearing broadcast DISABLED in-process (falling back to empty-block production, the known-good mode). This process will NOT auto-re-arm; an operator restart with the flags re-set is required to try again after investigating.",
                            .{ slot, txbearing_tripwire.TRIP_THRESHOLD, txbearing_tripwire.TRIP_THRESHOLD },
                        );
                    } else {
                        // Dark tap (mirrors [REVIVE-WOULD-FIRE]): VEX_TXBEARING_BROADCAST is unset, so
                        // nothing was actually being broadcast (either today's live default, or a
                        // deliberate loopback-only soak per plan §4 M1 item 3) — detection-only, no
                        // production-behavior consequence (effectiveArmed(false) is false either way,
                        // tripped or not). The internal latch still sets for consistency with the
                        // real-trip branch (one code path, one state machine) — in practice this has no
                        // separate observable effect, since arming the flag requires a process restart
                        // (see the ROLLBACK section of the runbook), which always starts a fresh
                        // TripwireState anyway.
                        std.log.warn(
                            "[TXBEARING-WOULD-TRIP] slot={d} consecutive_produce_parity_fails={d} >= threshold={d} — dark tap: VEX_TXBEARING_BROADCAST is unset (nothing was actually broadcasting), but the tripwire WOULD have fired here if it had been armed",
                            .{ slot, txbearing_tripwire.TRIP_THRESHOLD, txbearing_tripwire.TRIP_THRESHOLD },
                        );
                    }
                }
            }
        }

        // ── Snapshot generation ──────────────────────────────────────────
        if (self.snapshot_service) |*ss| {
            const snap_mod = @import("snapshot_service.zig");
            ss.onSlotFrozen(snap_mod.SnapshotMeta{
                .slot = slot,
                .bank_hash = bank.bank_hash.data,
                .parent_slot = bank.parent_slot orelse 0,
                .epoch = bank.epoch_schedule.getEpoch(slot),
                .lamports_total = 0, // TODO: track from pending_writes
                .accounts_count = bank.pending_writes.items.len,
                .timestamp = @intCast(std.time.timestamp()),
            });
        }

        // ── Leader slot detection + block production (leader_mode) ──────────
        // comptime-gated: with -Dleader_mode off this whole block is pruned → the voting binary is
        // byte-identical. With it on, we produce+broadcast an empty block ONLY on our own leader slots
        // (isLeader gate); every non-leader slot's replay/vote path is unchanged.
        if (comptime build_options.leader_mode) {
            const next_slot = slot + 1;
            if (self.isLeader(next_slot)) {
                // 2026-06-16 TILE ISOLATION: when the produce tile is spawned, snapshot the build
                // inputs (reading the SAME bank fields at the SAME point the inline path reads them
                // so the snapshot is byte-identical) and PUSH Ring A — then RETURN immediately. The
                // produce tile does drain+pack+PoH+shred+broadcast on core 20; this thread (replay,
                // core 16) does NO production work. When the tile is NOT active, fall back to the
                // existing inline path (byte-identical to today; covers leader_mode-on/TPU-off).
                if (self.produce_tile_active.load(.acquire)) {
                    self.dispatchLeaderToProduceTile(next_slot, slot, bank);
                } else {
                    self.produceAndBroadcastEmptySlot(next_slot, slot, bank);
                }
            }
        }
    }

    /// Scratch collector for `dispatchLeaderToProduceTile`'s mempool peek (M2b). Populated entirely
    /// INSIDE `banking_stage.peekEach`'s lock (parsing is cheap/pure — no nested lock acquisition,
    /// per that method's contract); `payer_pubkeys`/`sigs` are VALUE copies, safe to read after
    /// `peekEach` returns and the lock is released. Bounded by `produce_ring_mod.FEE_SNAPSHOT_CAP`.
    const FeeSnapshotCollector = struct {
        payer_pubkeys: [produce_ring_mod.FEE_SNAPSHOT_CAP][32]u8 = undefined,
        payer_count: usize = 0,
        sigs: [produce_ring_mod.FEE_SNAPSHOT_CAP][64]u8 = undefined,
        sig_count: usize = 0,

        fn addPayer(self: *@This(), pk: [32]u8) void {
            for (self.payer_pubkeys[0..self.payer_count]) |existing| {
                if (std.mem.eql(u8, &existing, &pk)) return; // already have it
            }
            if (self.payer_count < self.payer_pubkeys.len) {
                self.payer_pubkeys[self.payer_count] = pk;
                self.payer_count += 1;
            }
        }

        fn cb(ctx: *anyopaque, tx_wire: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            var ssig: [tx_ingest_mod.MAX_SIGNATURES][64]u8 = undefined;
            var skey: [tx_ingest_mod.MAX_SIGNATURES][32]u8 = undefined;
            const parsed = tx_ingest_mod.parse(tx_wire, &ssig, &skey) catch return; // malformed — skip
            if (self.sig_count < self.sigs.len) {
                self.sigs[self.sig_count] = parsed.signatures[0];
                self.sig_count += 1;
            }
            self.addPayer(parsed.signer_keys[0]);
        }
    };

    /// 2026-06-16 TILE ISOLATION (replay side, "become-leader" emit). Runs on the REPLAY thread.
    /// Snapshots every build input as a VALUE (no *Bank / no self.identity_secret deref happens on
    /// the produce tile — identity_secret is nulled/restored on THIS thread by the suspend-voting
    /// path :6308-6459, so a tile reading it live would be a torn read) and pushes Ring A. Reads the
    /// same fields the inline produceAndBroadcastEmptySlot reads at :1225-1264, so the produced bytes
    /// are identical to the inline path — just built on the other thread. self_produced is NOT
    /// marked here; the G1 self-vote guard stays replay-owned and is marked when Ring B drains (so
    /// it is set before the looped-back slot can freeze, preserving the inline mark-before-loopback
    /// ordering). Skip semantics mirror the inline path (null block_id / null secret → no push).
    ///
    /// 2026-07-17 (M2b): ALSO snapshots the tile's inclusion-gate inputs here, on the replay thread,
    /// exactly where every other tile input is already snapshotted — see produce_ring.zig's
    /// BecomeLeaderRecord doc for why this is a wider application of the SAME "values only" principle,
    /// not a new one:
    ///   1. `banking_stage.peekEach` (non-destructive) walks the mempool AS IT STANDS RIGHT NOW under
    ///      its own lock, extracting (fee-payer pubkey, first signature) VALUE pairs — this is the
    ///      ONE new cross-thread synchronization this milestone adds: the replay thread briefly takes
    ///      `banking_stage.lock` (today only the tile does, via `drainBatch`). It is bounded (guarded
    ///      by `isLeader`, so it runs once per OUR leader slot, not per replayed slot), short-held
    ///      (parsing only — no nested accounts_db lookup inside the lock, see FeeSnapshotCollector.cb),
    ///      and is NOT the accounts_db/replay-commit write-path lock chain that actually caused the
    ///      prior delinquency (produce_ring.zig banner) — a different, already-cross-thread-by-design
    ///      lock class (the QUIC-pump thread already writes through it).
    ///   2. For each DISTINCT fee-payer pubkey observed, look up its frozen-parent balance via
    ///      `accounts_db.getAccountInSlot` — the EXACT SAME call `bankAdmitTxForBroadcast` makes below,
    ///      just run here (still replay-thread-owned, zero new access pattern) instead of per-tx at
    ///      broadcast time.
    ///   3. Value-copy `parent_bank.recent_blockhashes` (bounded, ≤150×32B) — a plain frozen-bank
    ///      struct field read, the same category as `block_id`/`poh_hash` just above.
    ///   4. When the status cache is active, check each peeked signature against
    ///      `self.recent_sig_cache` (replay-owned; no lock needed — only this thread ever touches it)
    ///      and carry forward the ones flagged AlreadyProcessed.
    /// Coverage is bounded (`FEE_SNAPSHOT_CAP`) and necessarily a SNAPSHOT (a tx arriving in the gap
    /// between this dispatch and the tile's later `drainBatch` won't have a fee-payer entry) — the
    /// tile-side gate's fallback for "not in the snapshot" is the SAME conservative "cannot verify ⇒
    /// treat as absent ⇒ drop" policy `bankAdmitTxForBroadcast` already uses for a genuinely-absent
    /// account (see `tileAdmitTxForBroadcast`), so this can only under-include, never wrongly admit.
    fn dispatchLeaderToProduceTile(self: *Self, next_slot: u64, parent_slot: u64, parent_bank: *Bank) void {
        const ring_a = self.produce_ring_a orelse return;
        const sec = self.identity_secret orelse return;
        // SIMD-0340 parent block_id (= first FEC chained merkle root). Inline path skips when null;
        // encode validity so the tile skips identically (no orphan, no wasted broadcast).
        const block_id = parent_bank.block_id;
        const tpu_ingest_on = std.posix.getenv("VEX_TPU_INGEST") != null;

        var rec = produce_ring_mod.BecomeLeaderRecord{
            .slot = next_slot,
            .parent_slot = parent_slot,
            .chained_root = block_id orelse [_]u8{0} ** 32,
            .chained_root_valid = block_id != null,
            .seed = parent_bank.poh_hash.data,
            .secret = sec,
            .shred_version = self.shred_version_bp,
            .tpu_ingest_on = tpu_ingest_on,
        };

        // M2b gate-input snapshot — only meaningful (and only worth the work) when the tile would
        // actually pack drained txs; skip entirely for the tick-only branch (byte-identical to today
        // when tpu_ingest_on is false — should not happen given dispatch is only reachable under
        // VEX_TPU_INGEST anyway, but keep the check as documentation + a cheap belt-and-braces guard).
        if (tpu_ingest_on and self.banking_stage != null) {
            // recent_blockhashes — plain frozen-bank field read (same category as block_id/poh_hash).
            const entries = parent_bank.recent_blockhashes.constSlice();
            rec.recent_blockhashes_len = @intCast(@min(entries.len, rec.recent_blockhashes.len));
            for (entries[0..rec.recent_blockhashes_len], 0..) |e, i| rec.recent_blockhashes[i] = e.blockhash.data;

            // Phase A: non-destructive mempool peek, lock-held parsing only (no accounts_db here).
            var collector = FeeSnapshotCollector{};
            self.banking_stage.?.peekEach(produce_ring_mod.FEE_SNAPSHOT_CAP, &collector, FeeSnapshotCollector.cb);

            // Phase B: lock released — accounts_db lookups (replay-thread-owned, same call
            // bankAdmitTxForBroadcast makes) + RecentSigCache checks (also replay-owned, no lock).
            if (parent_bank.accounts_db) |adb| {
                for (collector.payer_pubkeys[0..collector.payer_count]) |pk_bytes| {
                    const pk = core.Pubkey{ .data = pk_bytes };
                    if (adb.getAccountInSlot(&pk, parent_bank.slot, parent_bank.ancestors())) |acct| {
                        if (rec.fee_snapshot_len < rec.fee_snapshot.len) {
                            rec.fee_snapshot[rec.fee_snapshot_len] = .{
                                .pubkey = pk_bytes,
                                .lamports = acct.lamports,
                                .owner = acct.owner.data,
                                .data_len = @intCast(acct.data.len),
                            };
                            rec.fee_snapshot_len += 1;
                        }
                    }
                }
            }

            rec.status_cache_checked = self.statusCacheActive();
            if (rec.status_cache_checked) {
                for (collector.sigs[0..collector.sig_count]) |sig| {
                    if (self.recent_sig_cache.isRecent(&sig, next_slot)) {
                        if (rec.already_processed_len < rec.already_processed_sigs.len) {
                            rec.already_processed_sigs[rec.already_processed_len] = sig;
                            rec.already_processed_len += 1;
                        }
                    }
                }
            }
        }

        if (!ring_a.tryPush(rec)) {
            // Ring A full = produce tile fell behind (should never happen at cap 64 with one
            // in-flight slot). Skip this slot, same outcome as the inline path skipping a slot it
            // cannot build — no inline production here (that would re-introduce the cycle theft).
            std.log.warn("[PRODUCE-TILE] Ring A full, slot={d} skipped (tile behind)", .{next_slot});
        }
    }

    /// 2026-07-17 (M2b). Tile-side mirror of `bankAdmitTxForBroadcast` (:1818): the SAME per-tx
    /// pre-filter, sourced from the VALUE-copied `BecomeLeaderRecord` snapshot instead of a live
    /// `*Bank`/`accounts_db` — the tile still dereferences ZERO shared mutable state (produce_ring.zig
    /// banner), only the record it already owns. `state`/`allocator` behave identically to the inline
    /// gate (fresh `SeqGateState` per produced block); `admitTxSeq` itself is UNCHANGED — the only
    /// difference from the inline gate is WHERE `fee_payer`/`recent_blockhashes`/cross-block-dedup come
    /// from. A fee-payer pubkey not present in `rec.fee_snapshot` (never looked up, or looked up and
    /// found absent — both cases already collapse to `fpv = null` on the inline path too, see
    /// `bankAdmitTxForBroadcast`) is treated as absent, same conservative drop.
    const TileGateCtx = struct {
        rec: *const produce_ring_mod.BecomeLeaderRecord,
        state: *@import("block_produce").SeqGateState,
        allocator: std.mem.Allocator,
    };

    fn tileAdmitTxForBroadcast(ctx: *anyopaque, tx_wire: []const u8) bool {
        const block_produce = @import("block_produce");
        const gctx: *TileGateCtx = @ptrCast(@alignCast(ctx));
        var ssig: [tx_ingest_mod.MAX_SIGNATURES][64]u8 = undefined;
        var skey: [tx_ingest_mod.MAX_SIGNATURES][32]u8 = undefined;
        const parsed = tx_ingest_mod.parse(tx_wire, &ssig, &skey) catch return false;

        // Cross-block AlreadyProcessed, snapshot-sourced (see BecomeLeaderRecord doc). Only entries
        // the dispatch-time peek actually observed are checked; a tx that arrived after the snapshot
        // gets no cross-block dedup here (same "not yet wired for this tx" gap the inline path has
        // whenever the status cache itself is dormant — not a new asymmetry, just a narrower window).
        if (gctx.rec.status_cache_checked) {
            for (gctx.rec.already_processed_sigs[0..gctx.rec.already_processed_len]) |flagged| {
                if (std.mem.eql(u8, &flagged, &parsed.signatures[0])) return false;
            }
        }

        const bh_set = gctx.rec.recent_blockhashes[0..gctx.rec.recent_blockhashes_len];

        var fpv: ?block_produce.FeePayerView = null;
        for (gctx.rec.fee_snapshot[0..gctx.rec.fee_snapshot_len]) |snap| {
            if (std.mem.eql(u8, &snap.pubkey, &parsed.signer_keys[0])) {
                fpv = .{ .lamports = snap.lamports, .owner = snap.owner, .data_len = snap.data_len };
                break;
            }
        }

        return block_produce.admitTxSeq(gctx.allocator, gctx.state, parsed, tx_wire, bh_set, fpv);
    }

    /// 2026-06-16 TILE ISOLATION (replay side, "slot-done" consume). Runs on the REPLAY thread at
    /// the top of replayWorker every iteration. Drains Ring B (blocks the produce tile finished) and
    /// runs the EXISTING loopback self-replay + G1 self-vote guard — both replay-thread-owned.
    /// Ownership: an `ok` record TRANSFERS owned block_bytes; we mark self_produced (replay-owned
    /// hashmap, never touched by the tile) BEFORE handing the bytes to pushSlotForReplayWithParent,
    /// preserving the inline mark-before-loopback ordering. We free the bytes iff the loopback push
    /// declines them (returns false) — mirrors the inline dupe/free contract at :1286-1287.
    fn drainProduceTileRingB(self: *Self) void {
        const ring_b = self.produce_ring_b orelse return;
        var rec: produce_ring_mod.SlotDoneRecord = undefined;
        while (ring_b.tryPop(&rec)) {
            switch (rec.status) {
                .skipped => {
                    // Tile could not build; nothing to loop back, nothing to free.
                    std.log.warn("[PRODUCE-TILE] slot={d} skipped by tile (no block)", .{rec.slot});
                },
                .ok => {
                    // G1: mark self-produced BEFORE the loopback so onSlotFrozen skips self-voting
                    // it (replay-owned write; the tile never touches self_produced).
                    self.self_produced.put(self.allocator, rec.slot, {}) catch {};
                    // M3 auto-safe-off tripwire: mirror the inline path's self_produced_tx_bearing
                    // marking — rec.tx_bearing was computed on the TILE thread (produceTileLoop) and
                    // carried across Ring B as a plain value; this write is replay-thread-owned, same
                    // discipline as self_produced itself.
                    if (rec.tx_bearing) self.self_produced_tx_bearing.put(self.allocator, rec.slot, {}) catch {};
                    // Multi-slot leader-window chaining: stash OUR produced block_id (computed on the
                    // tile) so the next slot of our window chains (applied at this slot's freeze).
                    if (rec.has_block_id) self.self_produced_block_id.put(self.allocator, rec.slot, rec.block_id) catch {};
                    if (!self.pushSlotForReplayWithParent(rec.slot, rec.block_bytes, rec.parent_slot)) {
                        self.allocator.free(rec.block_bytes);
                    }
                },
            }
        }
    }

    /// 2026-06-16 TILE ISOLATION (produce side). The body of the dedicated produce tile thread,
    /// pinned to core 20. Drains Ring A (become-leader), builds the block off the SNAPSHOTTED inputs
    /// (zero shared-Bank deref), broadcasts it (when VEX_LEADER_BROADCAST is set — the same gate the
    /// inline path uses), and pushes the loopback bytes back via Ring B. Uses self.allocator which
    /// is std.heap.c_allocator (thread-safe libc malloc — confirmed main.zig:240), so allocating
    /// here concurrently with replay's allocations on core 16 is safe. The block bytes come from the
    /// same block_produce.zig as the inline path → no consensus-byte change, just a thread move.
    pub fn produceTileLoop(self: *Self) void {
        // Phase 9: default = vex_topo table (.produce == core 20, byte-identical);
        // VEX_LEGACY_PINS / -Dlegacy_pins reverts to the inline pinToCore(20).
        if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) {
            pinToCore(20);
        } else {
            _ = vex_topo.pinTile(vex_topo.LIVE, .produce, 0);
        }
        std.log.warn("[PRODUCE-TILE] started on core 20 (block production isolated off replay)", .{});
        const ring_a = self.produce_ring_a orelse return;
        const ring_b = self.produce_ring_b orelse return;
        const block_produce = @import("block_produce");
        var rec: produce_ring_mod.BecomeLeaderRecord = undefined;
        while (self.is_running.load(.acquire)) {
            if (!ring_a.tryPop(&rec)) {
                std.Thread.sleep(200 * std.time.ns_per_us); // idle — no leader work pending
                continue;
            }

            // Skip exactly as the inline path skips: a null parent block_id has no chained merkle
            // root → an unbuildable (cluster-unacceptable) block. Signal slot-done(skipped).
            if (!rec.chained_root_valid) {
                std.log.warn("[PRODUCE-TILE] slot={d} skipped: parent block_id null (no chained root)", .{rec.slot});
                _ = ring_b.tryPush(.{ .slot = rec.slot, .parent_slot = rec.parent_slot, .block_bytes = &.{}, .status = .skipped });
                continue;
            }

            // Build the slot bytes — same branch the inline path takes (:1242): pack drained txs when
            // VEX_TPU_INGEST is on AND a mempool is wired, else the empty tick-only path. BankingStage
            // is mutex-protected; the QUIC pump (core 6) is the sole producer, this tile the sole
            // consumer (drainBatch) — one-producer/one-consumer under the mutex is safe.
            // block_produce's `seed: Hash` is `entry.Hash` = a bare [32]u8 (the inline path passes
            // `parent_bank.poh_hash.data`, also [32]u8). rec.seed IS that snapshotted [32]u8.
            // 2026-07-17 (M2b, task #25's tile flip-blocker CLOSED): the produce tile is still "zero
            // shared-Bank deref" by design (replay recycles banks in a pool on core 16) — it cannot and
            // does not call the live-bank admit predicate the inline path uses. Instead it runs
            // `tileAdmitTxForBroadcast`, the SAME `admitTxSeq` gate sourced from the VALUE-copied
            // `rec.fee_snapshot`/`rec.recent_blockhashes`/`rec.already_processed_sigs` dispatch built on
            // the replay thread (see `dispatchLeaderToProduceTile`). That gate is a PRE-FILTER, not a
            // complete broadcast-safety boundary — identically to the inline path (block_produce.zig
            // banner) — so the SAME explicit-override interlock applies here as there
            // (`VEX_TXBEARING_BROADCAST`, replay_stage.zig's inline interlock comment): without it,
            // tx-bearing + broadcast forces the EMPTY (cluster-proven-accepted) path + a loud error;
            // with it, tx-bearing bytes may broadcast through the gate, same residual (adversarial
            // same-payer transfer-drain beyond M2's covered instruction classes) the inline path accepts.
            // tx-bearing packing WITHOUT broadcast (loopback-only) is unconditionally allowed, same as
            // always — an imperfect pack there can at worst waste our own loopback slot.
            const broadcast_enabled = core.envFlagValueArmed(std.posix.getenv("VEX_LEADER_BROADCAST"));
            const tile_want_tx_bearing = rec.tpu_ingest_on and self.banking_stage != null;
            // M3 (2026-07-17): same effectiveArmed() gate the inline path uses. Safe to call from THIS
            // (tile) thread — effectiveArmed only touches the atomic `tripped` field (see
            // txbearing_tripwire.zig's TripwireState doc: this is the ONE field the tile is allowed to
            // read cross-thread, mirroring the existing produce_tile_active atomic-bool pattern).
            const tile_txbearing_broadcast_env = std.posix.getenv("VEX_TXBEARING_BROADCAST") != null;
            const tile_txbearing_broadcast = self.txbearing_tripwire_state.effectiveArmed(tile_txbearing_broadcast_env);
            if (tile_want_tx_bearing and broadcast_enabled and !tile_txbearing_broadcast) {
                if (tile_txbearing_broadcast_env) {
                    std.log.err("[PRODUCE-TILE] slot={d} tx-bearing+broadcast SUPPRESSED — M3 tripwire is TRIPPED — producing EMPTY block instead. Re-arm requires an operator restart.", .{rec.slot});
                } else {
                    std.log.err("[PRODUCE-TILE] slot={d} tx-bearing+broadcast BLOCKED (set VEX_TXBEARING_BROADCAST=1 to flip) — producing EMPTY block instead", .{rec.slot});
                }
            }
            const tile_pack_tx_bearing = tile_want_tx_bearing and (!broadcast_enabled or tile_txbearing_broadcast);
            var tile_seq_state = block_produce.SeqGateState{};
            defer tile_seq_state.deinit(self.allocator);
            var tile_gctx = TileGateCtx{ .rec = &rec, .state = &tile_seq_state, .allocator = self.allocator };
            const tile_gate = block_produce.InclusionGate{ .ctx = &tile_gctx, .admit = tileAdmitTxForBroadcast };
            const bytes = if (tile_pack_tx_bearing)
                block_produce.produceSlotBytes(
                    self.allocator,
                    rec.seed,
                    block_produce.TESTNET_HASHES_PER_TICK,
                    block_produce.TICKS_PER_SLOT,
                    self.banking_stage.?,
                    null,
                    tile_gate,
                    block_produce.MAX_BLOCK_UNITS, // SIMD-0256 60M block-CU ceiling (cost-model pack stop)
                ) catch |e| {
                    std.log.warn("[PRODUCE-TILE] slot={d} produceSlotBytes failed: {any}", .{ rec.slot, e });
                    _ = ring_b.tryPush(.{ .slot = rec.slot, .parent_slot = rec.parent_slot, .block_bytes = &.{}, .status = .skipped });
                    continue;
                }
            else
                block_produce.produceEmptySlotBytes(
                    self.allocator,
                    rec.seed,
                    block_produce.TESTNET_HASHES_PER_TICK,
                    block_produce.TICKS_PER_SLOT,
                    null,
                ) catch |e| {
                    std.log.warn("[PRODUCE-TILE] slot={d} produce failed: {any}", .{ rec.slot, e });
                    _ = ring_b.tryPush(.{ .slot = rec.slot, .parent_slot = rec.parent_slot, .block_bytes = &.{}, .status = .skipped });
                    continue;
                };
            defer self.allocator.free(bytes);

            // Multi-slot leader-window chaining (2026-06-19): compute OUR produced last-FEC merkle root
            // HERE on the tile (off the replay thread) and carry it on the SlotDoneRecord;
            // drainProduceTileRingB stashes slot→block_id so the next slot of our window chains.
            // Regardless of broadcast. Compute failure / unwired ⇒ has_block_id=false ⇒ slot N+1 skips.
            var tile_bid: [32]u8 = [_]u8{0} ** 32;
            var tile_has_bid = false;
            if (self.produce_blockid_fn) |bidf| {
                if (self.produce_broadcast_ctx) |ctx| {
                    tile_has_bid = bidf(ctx, bytes, rec.slot, rec.parent_slot, rec.chained_root, rec.secret, rec.shred_version, &tile_bid);
                }
            }

            // STAGED ROLLOUT: cluster-facing broadcast gated behind VEX_LEADER_BROADCAST (default
            // OFF), exactly as the inline path (:1276). When unset we still produce + loopback-freeze
            // our own block (NO shred leaves the host). The broadcast callback (shred+transmit) holds
            // no replay-thread-local state, so running it on this tile is safe. (broadcast_enabled is
            // read once above, at the tx-bearing safety interlock.)
            if (broadcast_enabled) {
                if (self.produce_broadcast_fn) |f| {
                    if (self.produce_broadcast_ctx) |ctx| {
                        f(ctx, rec.slot, rec.parent_slot, bytes, rec.chained_root, rec.secret, rec.shred_version);
                    }
                }
            }

            // Hand a fresh OWNED copy of the bytes to replay for the loopback self-replay (replay
            // frees it iff its push declines). `bytes` itself is freed by the defer above.
            const loop_copy = self.allocator.dupe(u8, bytes) catch {
                _ = ring_b.tryPush(.{ .slot = rec.slot, .parent_slot = rec.parent_slot, .block_bytes = &.{}, .status = .skipped });
                continue;
            };
            if (!ring_b.tryPush(.{ .slot = rec.slot, .parent_slot = rec.parent_slot, .block_bytes = loop_copy, .status = .ok, .block_id = tile_bid, .has_block_id = tile_has_bid, .tx_bearing = tile_pack_tx_bearing })) {
                // Ring B full (should never happen at cap 64) — free our copy to avoid a leak.
                self.allocator.free(loop_copy);
                std.log.warn("[PRODUCE-TILE] Ring B full, slot={d} loopback dropped", .{rec.slot});
                continue;
            }
            std.log.warn("[PRODUCE-TILE] slot={d} parent={d} produced {d}B → {s} + loopback (no self-vote)", .{ rec.slot, rec.parent_slot, bytes.len, if (broadcast_enabled) "BROADCAST" else "loopback-only(no-bcast)" });
        }
        std.log.warn("[PRODUCE-TILE] shutting down", .{});
    }

    /// task #32: liveness WATCHDOG (gated -Dwatchdog; spawned from main.zig). Reads the ReplayStats
    /// liveness atomics (slots_replayed, votes_sent) lock-free and alerts if the node stops advancing
    /// for STUCK_SECS. Observation-only by default; if VEX_WATCHDOG_RESTART is set it exits(1) on a
    /// confirmed wedge so the process supervisor restarts us. READ-ONLY — no consensus impact; the
    /// whole thread is comptime-excluded from the default build (byte-identical).
    pub fn watchdogLoop(self: *Self) void {
        const CHECK_SECS: u64 = 15;
        const STUCK_SECS: u64 = 90; // no slot replayed AND no vote sent for this long ⇒ wedged
        const restart_on_wedge = core.envFlagValueArmed(std.posix.getenv("VEX_WATCHDOG_RESTART"));
        std.log.warn("[WATCHDOG] started (stuck_threshold={d}s, restart_on_wedge={any})", .{ STUCK_SECS, restart_on_wedge });
        var last_slots: u64 = ReplayStats.get(&self.stats.slots_replayed);
        var last_votes: u64 = ReplayStats.get(&self.stats.votes_sent);
        var stale_secs: u64 = 0;
        while (self.is_running.load(.acquire)) {
            std.Thread.sleep(CHECK_SECS * std.time.ns_per_s);
            const slots = ReplayStats.get(&self.stats.slots_replayed);
            const votes = ReplayStats.get(&self.stats.votes_sent);
            if (slots != last_slots or votes != last_votes) {
                stale_secs = 0;
                last_slots = slots;
                last_votes = votes;
                continue;
            }
            stale_secs += CHECK_SECS;
            std.log.warn("[WATCHDOG] no progress for {d}s (slots_replayed={d} votes_sent={d})", .{ stale_secs, slots, votes });
            if (stale_secs >= STUCK_SECS) {
                std.log.err("[HEALTH-ALERT] node WEDGED: no slot replayed or vote sent in {d}s (slots={d} votes={d})", .{ stale_secs, slots, votes });
                if (restart_on_wedge) {
                    std.log.err("[WATCHDOG] VEX_WATCHDOG_RESTART set — exiting(1) for supervisor restart", .{});
                    std.posix.exit(1);
                }
                stale_secs = 0; // re-arm; keep observing (avoid log spam)
            }
        }
        std.log.warn("[WATCHDOG] shutting down", .{});
    }

    /// 2026-06-16 TILE ISOLATION: allocate the two SPSC rings, mark the tile active, and return the
    /// ReplayStage so main.zig can spawn the produce tile thread (produceTileLoop). Idempotent-safe:
    /// only allocates once. Called from main.zig under the VEX_TPU_INGEST gate (leader_mode on).
    /// When this is NEVER called (the default OFF path), produce_tile_active stays false and the
    /// isLeader dispatch takes the inline path → byte-identical to today.
    pub fn enableProduceTile(self: *Self) !void {
        if (self.produce_ring_a != null) return; // already enabled
        self.produce_ring_a = try produce_ring_mod.BecomeLeaderRing.init(self.allocator, produce_ring_mod.PRODUCE_RING_CAPACITY);
        self.produce_ring_b = try produce_ring_mod.SlotDoneRing.init(self.allocator, produce_ring_mod.PRODUCE_RING_CAPACITY);
        self.produce_tile_active.store(true, .release);
    }

    /// CARRIER #20 (2026-06-13): build a candidate bank's ancestor chain
    /// (newest-first, exclusive of `root`) from the LIVE banks map — the
    /// authoritative in-memory parent links. @prov:replay.ancestor-chain-bankforks
    /// Falls back to the durable `slot_parents` map
    /// only when a bank has been pruned. This replaces the
    /// `AccountsDb.unrootedAncestorChain` walk in the tower lockout guard,
    /// which used slot_parents ALONE and truncated on any gap (sentinel/wake
    /// freeze paths don't always record a link), producing a false cross-fork
    /// lockout that wedged voting (delinquency 2026-06-13 @415008611).
    ///
    /// SAFETY: walks TRUE parent links, so it can only find GENUINE ancestors.
    /// It never invents a false ancestor, so the carrier-7 protection (refuse a
    /// vote that violates an abandoned-fork lockout) is preserved — a real
    /// abandoned-fork vote is still absent from the true parent chain.
    /// No lock is held across the two maps (banks_lock released before
    /// slot_parents_lock) to avoid a lock-order inversion with the freeze path.
    ///
    /// Made `pub` (2026-07-17, switch-proof-gossip-arming session) for
    /// `src/kat_ancestor_walk_unrooted_depth.zig` — same rationale as
    /// `sweepPendingTickGateSlots`/`getNetworkBankHash` above: the fix for the
    /// live 422521275 wedge (d2c2f59) is entirely in the CALLER's buffer
    /// sizing (fixed `[4096]Slot` -> heap-sized-to-actual-unrooted-depth), not
    /// in this function's own walk logic, so the KAT drives this REAL function
    /// with both buffer shapes directly rather than a reimplementation.
    pub fn ancestorChainComplete(self: *Self, start_parent: Slot, root: Slot, out: []Slot) []const Slot {
        var n: usize = 0;
        var p = start_parent;
        while (n < out.len and p > root) {
            out[n] = p;
            n += 1;
            const next: ?Slot = blk: {
                self.banks_lock.lockShared();
                if (self.banks.get(p)) |b| {
                    const pp = b.parent_slot;
                    self.banks_lock.unlockShared();
                    break :blk pp;
                }
                self.banks_lock.unlockShared();
                // Bank pruned (below tower root) — fall back to the durable link.
                if (self.accounts_db) |db| {
                    db.slot_parents_lock.lockShared();
                    defer db.slot_parents_lock.unlockShared();
                    break :blk db.slot_parents.get(p);
                }
                break :blk null;
            };
            p = next orelse break;
        }
        return out[0..n];
    }

    /// Submit a vote for a completed slot.
    /// Builds a CompactUpdateVoteState transaction and sends via TPU client.
    /// VOTE-REFRESH. @prov:replay.vote-refresh-parity
    /// Called on the no-cast return paths of submitVote: re-broadcast the LAST cast vote with a
    /// fresh blockhash so it keeps landing through short no-cast windows (cross-fork-lockout
    /// keep-alive + tx-blockhash-aging). Env-gated VEX_VOTE_REFRESH (dormant unless set).
    ///
    /// ⚠ SLASHING-SAFE BY CONSTRUCTION: this re-sends &t.vote_state UNCHANGED — it never calls
    /// recordVote(), never touches t.last_vote_slot, never appends a lockout. Adding a slot here
    /// would be a NEW, potentially CONFLICTING vote = slashing-class. @prov:replay.vote-refresh-parity
    /// — only swaps recent_blockhash+timestamp. The re-sent tower
    /// body (root/lockouts/bank_hash) is byte-identical to the original vote.
    /// ⚠ Uses last_voted_bank_hash = the hash ACTUALLY EMITTED on the cast path (net_hash when used,
    /// else bank.bank_hash) — re-sending a different bank_hash field would be a different vote.
    /// #87 Tier-3 switch-proof activation mode, parsed once from VEX_SWITCH_PROOF:
    ///   unset / unknown → .off    (DORMANT — legacy conservative cross-fork refusal)
    ///   "shadow"        → .shadow (COMPUTE + log would-switch, but do NOT change votes)
    ///   "1"/"armed"/"on"→ .armed  (ACT on the proof — only after shadow validation)
    const SwitchProofMode = enum { off, shadow, armed };
    fn switchProofMode(self: *Self) SwitchProofMode {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var mode: SwitchProofMode = .off;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_SWITCH_PROOF")) |s| {
                if (std.mem.eql(u8, s, "shadow")) {
                    Cache.mode = .shadow;
                } else if (std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "armed") or std.mem.eql(u8, s, "on")) {
                    Cache.mode = .armed;
                } else {
                    Cache.mode = .off;
                }
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.mode;
    }

    /// PROPAGATION-CONFIRMATION gate mode, parsed once from VEX_PROP_GATE (mirrors switchProofMode):
    ///   unset / unknown → .off    (DORMANT — current behavior; no propagation check)
    ///   "shadow"        → .shadow (COMPUTE + log would-refuse, but do NOT change votes)
    ///   "1"/"armed"/"on"→ .armed  (ACT — refuse to vote a fork that is not propagation-confirmed)
    fn propGateMode(self: *Self) SwitchProofMode {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var mode: SwitchProofMode = .off;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_PROP_GATE")) |s| {
                if (std.mem.eql(u8, s, "shadow")) {
                    Cache.mode = .shadow;
                } else if (std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "armed") or std.mem.eql(u8, s, "on")) {
                    Cache.mode = .armed;
                } else {
                    Cache.mode = .off;
                }
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.mode;
    }

    /// GOSSIP-FED PROP_RETARGET mode, parsed once from VEX_GOSSIP_PROP (mirrors propGateMode).
    /// INDEPENDENT of VEX_PROP_GATE so it can shadow alone while the landed gate stays armed.
    ///   unset/unknown → .off    (DORMANT — no gossip-fed retarget)
    ///   "shadow"      → .shadow (COMPUTE gossip-fed target + heaviest-sibling guard, LOG only)
    ///   "1"/"armed"/"on" → .armed (ACT — override the vote target with the gossip-fed heaviest-sibling pick)
    /// NOTE: arming REQUIRES VEX_PROP_GATE stays armed as the fallback (unhealthy-feed/no-target →
    /// fall through to the landed armed target; without it, the fallthrough votes the tip = orphan risk).
    fn gossipPropMode(self: *Self) SwitchProofMode {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var mode: SwitchProofMode = .off;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_GOSSIP_PROP")) |s| {
                if (std.mem.eql(u8, s, "shadow")) {
                    Cache.mode = .shadow;
                } else if (std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "armed") or std.mem.eql(u8, s, "on")) {
                    Cache.mode = .armed;
                } else {
                    Cache.mode = .off;
                }
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.mode;
    }

    /// #93: VEX_PROP_LATCH selects the canonical leader-window PROPAGATION-LATCH target selection over the
    /// #92 per-slot subtree-stake proxy. unset/"0"/"off" → proxy (legacy); anything else → latch. Parsed once.
    fn propLatchEnabled(self: *Self) bool {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var on: bool = false;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_PROP_LATCH")) |s| {
                Cache.on = !(s.len == 0 or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "off"));
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.on;
    }

    /// TASK #3 SHADOW (observe-only): VEX_HEAVIEST_SHADOW enables a LOG-ONLY comparison of our ACTUAL
    /// vote target against @prov:replay.heaviest-subtree-leaf-target (`fork_choice.bestOverallSlot()`).
    /// It NEVER changes the vote (no behavioral effect, cannot affect consensus
    /// or liveness) — it only emits `[HEAVIEST-SHADOW]` lines so we can measure, BEFORE building the
    /// armed path, how far behind the heaviest leaf our PROP-retarget vote lands (the ~1-credit gap) and
    /// whether the heaviest leaf is a SAFE same-fork extension. Parsed once; unset/"0"/"off"/"" → off.
    fn heaviestShadowEnabled(self: *Self) bool {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var on: bool = false;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_HEAVIEST_SHADOW")) |s| {
                Cache.on = !(s.len == 0 or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "off"));
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.on;
    }

    /// VOTE-COVERAGE mechanism telemetry (VEX_PROP_DIAG; default OFF). When set, submitVote emits
    /// [PROP-DIAG] lines at the canVote gate quantifying the non-advancing-retarget skip: (a) the
    /// selected target A is non-advancing (canVote(A)=false ⇒ A ≤ last_vote) with A / tip / last_vote,
    /// and (b) whether the vote was SILENTLY withheld vs recovered by the tip fallback. Permanent,
    /// env-gated telemetry for the vote-credit-gap-coverage mechanism (2026-07-10). Parsed once;
    /// unset/"0"/"off"/"" → off. Mirrors propLatchEnabled's cached-bool pattern.
    fn propDiagEnabled(self: *Self) bool {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var on: bool = false;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_PROP_DIAG")) |s| {
                Cache.on = !(s.len == 0 or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "off"));
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.on;
    }

    /// SWITCH-PROOF PER-VOTER DIAGNOSTIC (VEX_SWITCH_PROOF_VOTER_DIAG; default OFF).
    /// When set, every [SWITCH-PROOF]/[SWITCH-SHADOW] evaluation (i.e. every cross-fork
    /// switch-proof check — already a rare path, gated behind VEX_SWITCH_PROOF being
    /// shadow/armed AND is_same_fork=false) additionally runs
    /// `fork_choice.switchThresholdVoterBreakdown` (fork_choice.zig) and emits
    /// [SWITCH-PROOF-VOTER] lines for the top contributing (pubkey-prefix, cand_slot,
    /// stake, source) entries plus a [SWITCH-PROOF-BREAKDOWN] summary of exclusion
    /// counts per predicate. Added 2026-07-17 after the 422600922 sibling-race event
    /// logged only an unattributed aggregate ("locked_out=.../... (38.18%)
    /// gossip_cnt=0/0") with no way to tell which voters/slots supplied the stake —
    /// this turns the next such event into a fully attributable trace. Diagnostic-only:
    /// never changes the vote decision, never touches consensus state. Parsed once;
    /// unset/"0"/"off"/"" → off (mirrors propDiagEnabled's cached-bool pattern).
    fn switchProofVoterDiagEnabled(self: *Self) bool {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var on: bool = false;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_SWITCH_PROOF_VOTER_DIAG")) |s| {
                Cache.on = !(s.len == 0 or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "off"));
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.on;
    }

    /// Switch-proof Part 2, M2 revive arming (VEX_REVIVE_DEAD_SLOTS; default OFF).
    /// When OFF, decideRevive is passed flag_enabled=false → every dead slot is
    /// .no_action → the sweep's M2 block is fully dormant and the binary is
    /// behavior-identical to M1 (preserving test-revive-would-fire's zero-mutation
    /// invariant, which runs with this env unset). Parsed once (cached);
    /// unset/"0"/"off"/"" → off. Same cached-bool pattern as switchProofVoterDiagEnabled.
    ///
    /// pub for the offline self-recovery gate: main.zig's VEX_LEDGER_REPLAY drive
    /// loop reads this to decide whether to arm ledger-driven re-delivery of a
    /// force-dead+dumped slot (single source of truth for the arming env parse).
    pub fn reviveEnabled(self: *Self) bool {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var on: bool = false;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_REVIVE_DEAD_SLOTS")) |s| {
                Cache.on = !(s.len == 0 or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "off"));
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.on;
    }

    /// VOTE-THRESHOLD depth-8 gate mode (VEX_VOTE_THRESHOLD; incident 423083743
    /// companion fix, 2026-07-19). The Agave/FD invariant "cluster signals gate
    /// VOTING, own-tower depth gates ROOTING" — their depth-8 threshold check
    /// runs with REAL observed stake, which is what structurally prevents their
    /// towers from ever filling 31-deep on a fork the cluster abandoned. Vexor's
    /// check (tower.zig shouldVote) existed but was called with (0,0) = dead.
    ///   unset / "shadow" / unknown → .shadow (DEFAULT: compute real stakes +
    ///                                log would-be verdict; vote decisions
    ///                                byte-identical — (0,0) still passed)
    ///   "1"/"armed"/"on"           → .armed  (pass real stakes — ENFORCING;
    ///                                only after shadow-soak validation)
    ///   "0"/"off"/""               → .off    (fully dormant, no computation)
    /// Parsed once (cached); mirrors switchProofMode. Deliberately NOT in
    /// bakeProdEnvDefaults — the shadow default lives here in code.
    fn voteThresholdMode(self: *Self) @import("vex_consensus").tower.TowerBft.ThresholdMode {
        _ = self;
        const Mode = @import("vex_consensus").tower.TowerBft.ThresholdMode;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var mode: Mode = .shadow;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_VOTE_THRESHOLD")) |s| {
                if (s.len == 0 or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "off")) {
                    Cache.mode = .off;
                } else if (std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "armed") or std.mem.eql(u8, s, "on")) {
                    Cache.mode = .armed;
                } else {
                    Cache.mode = .shadow;
                }
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.mode;
    }

    /// VOTE-THRESHOLD total-stake numerator's denominator: TOTAL stake of the
    /// bank's epoch (same walk the PROP-GATE and switch-proof sites do inline;
    /// cached per epoch here because this runs on EVERY vote decision).
    /// Replay-thread-only; reuses already-loaded db.epoch_stakes — no new
    /// cross-thread sync (TVU hot-path standing rule).
    fn epochTotalStake(self: *Self, bank: *Bank) u64 {
        const db = self.accounts_db orelse return 0;
        const ep = bank.epoch_schedule.getEpoch(bank.slot);
        if (self.thr_total_stake_epoch == ep) return self.thr_total_stake_cached;
        var total: u64 = 0;
        for (db.epoch_stakes) |es| {
            if (es.epoch == ep) {
                for (es.vote_account_stakes) |vs| total +%= vs.stake;
                break;
            }
        }
        self.thr_total_stake_epoch = ep;
        self.thr_total_stake_cached = total;
        return total;
    }

    /// VOTE-THRESHOLD numerator: cluster stake observed voting AT-OR-BEYOND
    /// `depth_slot` on OUR fork = fork-choice `stake_voted_subtree` of the
    /// depth-slot node on the candidate bank's ancestry. This is the Vexor
    /// analog of Agave's `voted_stakes[threshold_slot]` (consensus.rs
    /// populate_ancestor_voted_stakes): both equal the stake of voters whose
    /// LATEST vote lands in the subtree rooted at the slot. The feed is
    /// `buildVoteAccountBatchFresh` → `fc.addVotes` in onSlotCompleted — votes
    /// landed in REPLAYED banks (Agave collect_vote_lockouts analog), live even
    /// during boot catch-up with zero gossip; it runs on the replay thread,
    /// same thread as submitVote → no new cross-thread sync.
    /// Key resolution mirrors rootGuardInputs: prefer the node on the ANCHOR
    /// (candidate vote target) bank's ancestry — disambiguates equivocating
    /// same-slot siblings — falling back to any node at the slot; absent
    /// (pruned/unknown) → 0 (in shadow that logs WOULD-REFUSE; never a crash).
    /// pub for src/kat_vote_threshold_shadow.zig (drives the REAL fork-choice
    /// walk against a constructed tree).
    pub fn clusterVotedStakeAtDepthSlot(self: *Self, depth_slot: Slot, anchor_slot: Slot, anchor_hash: Hash) u64 {
        const fc = if (self.fork_choice) |*p| p else return 0;
        const fc_mod = @import("vex_consensus").fork_choice;
        var key: ?fc_mod.SlotHashKey = null;
        const ak = fc_mod.SlotHashKey{ .slot = anchor_slot, .hash = anchor_hash };
        if (anchor_slot == depth_slot) {
            key = ak;
        } else if (fc.containsBlock(ak)) {
            var it = fc.ancestorIterator(ak);
            while (it.next()) |a| {
                if (a.slot == depth_slot) {
                    key = a;
                    break;
                }
                if (a.slot < depth_slot) break; // walked past — not on this ancestry
            }
        }
        if (key == null) key = fc.firstKeyAtSlot(depth_slot);
        const k = key orelse return 0;
        return fc.stakeVotedSubtree(k) orelse 0;
    }

    /// TASK #3 ARMED canonical vote-selection (VEX_CANONICAL_VOTE). @prov:vote.select-reset
    /// When set, submitVote selects the
    /// @prov:replay.select-vote-reset-forks target (heaviest-subtree leaf, or heaviest-on-same-voted-fork
    /// when a switch fails) INSTEAD of prop_retarget's backward ≥1/3 walk. REQUIRES VEX_SWITCH_PROOF
    /// armed (a cross-fork canonical target needs the switch authorization downstream). DORMANT by
    /// default; only armed after the offline gate (freeze-418669047.2: advances past the stall AND
    /// refuses the orphan via self-heal). Parsed once; unset/"0"/"off"/"" → off.
    fn canonicalVoteEnabled(self: *Self) bool {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var on: bool = false;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_CANONICAL_VOTE")) |s| {
                Cache.on = !(s.len == 0 or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "off"));
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.on;
    }

    fn maybeRefreshLastVote(self: *Self) void {
        if (!core.envFlagValueArmed(std.posix.getenv("VEX_VOTE_REFRESH"))) return; // dormant unless armed
        const vex_consensus = @import("vex_consensus");
        const t = if (self.tower) |*tw| tw else return;
        if (t.last_vote_slot == 0) return; // never cast a vote (@prov:replay.vote-refresh-parity)
        const vh = self.last_voted_bank_hash orelse return; // need the emitted vote_hash
        const secret = self.identity_secret orelse return;
        const vote_acct = self.vote_account orelse return;
        const fresh_bh = self.cached_blockhash orelse return;

        // MAX_VOTE_REFRESH_INTERVAL_MILLIS = 5000. @prov:replay.vote-refresh-parity
        const now_ms = std.time.milliTimestamp();
        // Tier-2 gate: only refresh after a genuine >5s NO-CAST window. When healthy we cast a vote
        // every ~0.4s → last_cast_time_ms is always recent → this returns → the tick-level call
        // (replayWorker) stays dormant during normal voting.
        if (now_ms - self.last_cast_time_ms < 5000) return;
        if (now_ms - self.last_refresh_time_ms < 5000) return;
        // Tier-1 proxy for the 16-block age gate: only re-send once the envelope
        // blockhash has rotated since our last refresh — avoids spamming byte-near-identical txs.
        if (self.last_refresh_tx_blockhash) |prev| {
            if (std.mem.eql(u8, &prev.data, &fresh_bh.data)) return;
        }

        var builder = vex_consensus.vote_tx.VoteTransactionBuilder.init(
            self.allocator,
            self.identity,
            .{ .data = vote_acct.data },
        );
        builder.setIdentitySecret(secret);
        var tx = builder.buildTowerSync(&t.vote_state, vh, fresh_bh, null) catch return; // SAME tower, fresh bh
        defer tx.deinit();
        const serialized = builder.signAndSerialize(&tx) catch return;

        var enqueued = false;
        if (self.vote_send_queue) |q| enqueued = q.push(serialized);
        if (!enqueued) {
            defer self.allocator.free(serialized);
            if (self.sendVoteFn) |sendFn| sendFn(serialized);
        }
        self.last_refresh_time_ms = now_ms;
        self.last_refresh_tx_blockhash = fresh_bh;
        const RefreshDbg = struct {
            var count: u64 = 0;
        };
        RefreshDbg.count += 1;
        if (RefreshDbg.count <= 3 or RefreshDbg.count % 50 == 0) {
            std.log.info("[VOTE-REFRESH] re-sent last vote slot={d} (blockhash rotated; tower unchanged) [#{d}]", .{ t.last_vote_slot, RefreshDbg.count });
        }
    }

    /// Part 4b root-guard input collector. Resolves the candidate root's fork-
    /// choice (slot,hash) key and reads the two predicate inputs off it plus the
    /// cluster oracle, returning them for the pure `evalRootGuards`. Returns null
    /// only when there is no fork-choice tree at all (nothing to guard against).
    /// SAFETY: uses `scanCachedSlotHash` (read-only SlotHashes cache), NEVER
    /// `getNetworkBankHash` — the latter installs pending buffers and drives the
    /// retroactive tick-gate/FEC sweeps (→ markSlotDead recursion). This mirrors
    /// the PR-5ah canonical-guard, which reads the same cache for the same reason.
    fn rootGuardInputs(self: *Self, root: Slot, anchor_slot: Slot) ?RootGuardInputs {
        const fc = if (self.fork_choice) |*p| p else return null;
        const fc_mod = @import("vex_consensus").fork_choice;

        // Resolve the candidate root's (slot,hash) key. Prefer the node on the
        // ANCHOR bank's ancestry (disambiguates equivocating same-slot siblings —
        // the root we are about to commit is the one on the just-voted/just-frozen
        // bank's ancestry, exactly as the FC-REROOT walk at doRootAdvance's tail
        // derives it). Fall back to any node at the slot; if the tree has no entry
        // for `root` at all (offline / bootstrap), leave the key null → fail open.
        var root_key: ?fc_mod.SlotHashKey = null;
        if (self.banks.get(anchor_slot)) |ab| {
            if (ab.is_frozen) {
                const ak = fc_mod.SlotHashKey{ .slot = anchor_slot, .hash = ab.bank_hash };
                if (anchor_slot == root) {
                    root_key = ak;
                } else if (fc.containsBlock(ak)) {
                    var it = fc.ancestorIterator(ak);
                    while (it.next()) |a| {
                        if (a.slot == root) {
                            root_key = a;
                            break;
                        }
                        if (a.slot < root) break; // walked past — root not an ancestor
                    }
                }
            }
        }
        if (root_key == null) root_key = fc.firstKeyAtSlot(root);

        const cluster = self.scanCachedSlotHash(root);
        return RootGuardInputs{
            .latest_invalid_ancestor = if (root_key) |rk| fc.latestInvalidAncestor(rk) else null,
            .is_duplicate_confirmed = if (root_key) |rk| (fc.isDuplicateConfirmed(rk) orelse false) else false,
            .our_root_hash = if (root_key) |rk| rk.hash.data else null,
            .cluster_canonical_hash = if (cluster) |c| c.data else null,
        };
    }

    /// G0 first-root latch arming (VEX_FIRST_ROOT_LATCH; DEFAULT ON — deliberately
    /// NOT in bakeProdEnvDefaults, the default lives here in code; the env exists
    /// only as a kill-switch: explicit "0"/"off"/"" disables). Hard-disabled in
    /// offline replay / golden-gate mode (VEX_LEDGER_REPLAY / VEX_SNAPSHOT_OFFLINE,
    /// the same detection bakeProdEnvDefaults uses): offline has no cluster to
    /// attest, so the latch must be inert there or DIFF987 canonical replay would
    /// refuse every first root. Parsed once (cached); same pattern as
    /// switchProofVoterDiagEnabled.
    fn firstRootLatchEnabled(self: *Self) bool {
        _ = self;
        const Cache = struct {
            var parsed = std.atomic.Value(u8).init(0);
            var on: bool = true;
        };
        if (Cache.parsed.load(.monotonic) == 0) {
            if (std.posix.getenv("VEX_LEDGER_REPLAY") != null or
                std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null)
            {
                Cache.on = false;
                std.log.warn("[ROOT-GUARD] offline replay mode — G0 first-root latch INERT (no cluster to attest)", .{});
            } else if (std.posix.getenv("VEX_FIRST_ROOT_LATCH")) |s| {
                Cache.on = !(s.len == 0 or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "off"));
                if (!Cache.on) std.log.warn("[ROOT-GUARD] G0 first-root latch DISABLED by VEX_FIRST_ROOT_LATCH={s}", .{s});
            }
            Cache.parsed.store(1, .monotonic);
        }
        return Cache.on;
    }

    /// G0 produced-slot probe: was `slot` cluster-PRODUCED? Wraps the existing
    /// historical oracle `fetchProducedSlots(slot, slot)` (getBlocks — the Agave
    /// Blockstore::is_skipped analog; offline-fakeable via VEX_SKIP_CANON_FILE)
    /// behind the per-candidate cache documented at the fields. Returns
    /// true/false = definitive cluster verdict, null = oracle unreachable
    /// (rate-limited retry). Called ONLY pre-latch on a hash-silent candidate —
    /// i.e. never post-boot-window and never offline — so the ≤3s curl (-m 3)
    /// this can block the replay thread for is confined to exactly the boot
    /// catch-up window it protects.
    fn probeClusterProduced(self: *Self, slot: Slot) ?bool {
        if (self.first_root_probe_slot == slot) {
            if (self.first_root_probe_result) |r| return r;
            // Prior probe for this same candidate FAILED — rate-limit retries.
            if (std.time.milliTimestamp() - self.first_root_probe_at_ms < 2000) return null;
        }
        self.first_root_probe_slot = slot;
        self.first_root_probe_result = null;
        self.first_root_probe_at_ms = std.time.milliTimestamp();
        const produced_list = self.fetchProducedSlots(slot, slot) orelse return null;
        defer self.allocator.free(produced_list);
        var produced = false;
        for (produced_list) |s| {
            if (s == slot) {
                produced = true;
                break;
            }
        }
        self.first_root_probe_result = produced;
        return produced;
    }

    /// The full ROOT-GUARDS decision for one candidate root advance: input
    /// collection (rootGuardInputs) + G0 first-root-latch state + the pre-latch
    /// produced-slot probe + the pure predicate (evalRootGuards) + latch
    /// transition on positive attestation. Returns null when there is no
    /// fork-choice tree at all (nothing to guard against — offline/unit
    /// bootstrap, unchanged from the pre-G0 code). Split out of doRootAdvance
    /// (and made pub) so the live-path KAT (src/kat_first_root_latch.zig) can
    /// drive the REAL glue — scanCachedSlotHash, fetchProducedSlots'
    /// VEX_SKIP_CANON_FILE path, the probe cache, and the latch field — without
    /// needing a full AccountsDb; doRootAdvance is its only production caller.
    pub fn rootGuardDecisionForAdvance(self: *Self, root: Slot, anchor_slot: Slot) ?root_guards.RootGuardDecision {
        var gin = self.rootGuardInputs(root, anchor_slot) orelse return null;
        gin.first_root_pending = self.firstRootLatchEnabled() and !self.first_root_attested;
        if (gin.first_root_pending and gin.cluster_canonical_hash == null and !gin.is_duplicate_confirmed) {
            gin.cluster_produced = self.probeClusterProduced(root);
        }
        const dec = evalRootGuards(gin);
        if (dec == .allow_attested and !self.first_root_attested) {
            self.first_root_attested = true;
            if (self.firstRootLatchEnabled()) {
                std.log.warn(
                    "[ROOT-GUARD] first-root positive attestation LATCHED slot={d} (cluster-attested bank_hash match) — G0 boot gate satisfied, steady-state guard semantics from here",
                    .{root},
                );
            }
        }
        return dec;
    }

    /// #27 (2026-07-02): root-advance body SHARED by the LIVE vote path
    /// (submitVote) and the OFFLINE force-root path (forceAdvanceRootTo,
    /// VEX_REPLAY_FORCE_ROOT_DEPTH). Extracted VERBATIM from submitVote so the
    /// two callers can never drift: ancestry guard (carrier #7 LAYER 2) →
    /// partition promote/purge → db.advanceRoot → geyser rooted
    /// emit → db.purgeRootedSlot. Returns prev_root (read BEFORE advanceRoot)
    /// when the advance ran; null when the ancestry guard REFUSED it (prev
    /// root kept). anchor_slot/anchor_parent = the just-voted (live) /
    /// just-frozen (offline) slot the candidate root must be an ancestor of.
    fn doRootAdvance(self: *Self, db: *AccountsDb, root: Slot, anchor_slot: Slot, anchor_parent: ?Slot) ?Slot {
        // Phase 2c-B (2026-05-15): capture prev_root for sibling-slot
        // sig_overlay purge. db.rooted_slot is updated inside
        // advanceRoot — read it BEFORE the call.
        const prev_root: Slot = db.rooted_slot;

        // CARRIER #7 LAYER 2 (2026-06-10) — root-advance ancestry
        // guard (belt-and-suspenders under the LAYER-1 fork-aware
        // lockout; this guard ALONE would have prevented carrier
        // #7). The candidate root comes from raw tower slot math;
        // @414406146 it was an ABANDONED FORK block (cluster-
        // skipped) — the partition below then promoted the fork
        // chain {141,142,146} and PURGED canonical {143,144,145},
        // poisoning the rooted store (epoch_credits −34 @188).
        // Verify the candidate root lies on the just-voted bank's
        // ancestry (durable slot_parents walk — the same map the
        // partition trusts). If not: REFUSE the whole advance
        // (promote/purge/advanceRoot/FC-reroot all skipped, prev
        // root kept), log loudly, count. The tower retries on the
        // next vote; under LAYER 1 the tower root is always on the
        // voted fork, so any fire here = a tower bug surfaced
        // loudly instead of a consensus-poisoned store. Mirrors
        // Agave BankForks::set_root rooting a bank on the working
        // fork's ancestry, never a bare slot number.
        if (root > prev_root and !db.isRootOnVotedAncestry(root, anchor_slot)) {
            const RootRejectDbg = struct {
                var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
            };
            const rc = RootRejectDbg.count.fetchAdd(1, .monotonic) + 1;
            std.log.err(
                "[ROOT-ANCESTRY-REJECT] candidate root={d} NOT on voted-bank ancestry (bank={d} parent={?d} prev_root={d} rejects={d}) — root advance REFUSED, prev root kept (carrier #7 guard)",
                .{ root, anchor_slot, anchor_parent, prev_root, rc },
            );
            return null;
        }

        // ═══ ROOT-GUARDS (Part 4b, 2026-07-15) — switch-proof / self-recovery
        // root-fix. Two REFUSE-ONLY guards that prevent the single worst outcome
        // of the 421935259 incident class: rooting a divergent / cluster-
        // unconfirmed fork PAST consensus (in the incident root advanced
        // 248→266→289→326 while the cluster lagged ~289), which made recovery
        // impossible without a fresh snapshot. Both guards ONLY ever REFUSE the
        // advance (return null, keep prev root) — strictly safe, cannot corrupt
        // state; a fire degrades any future recurrence from "unrecoverable" to a
        // "recoverable stall" that VOTE-REJECT-ALARM catches in ~30s. Design:
        // vexor-research/design-docs/SWITCHPROOF-SELFRECOVERY-ROOTFIX-DESIGN-2026-07-15 §4b.
        //   G1 — never root a fork whose ancestry includes an INVALID slot
        //        (fork_info.latest_invalid_ancestor != null).
        //   G2 — never root a slot the CLUSTER has diverged from: refuse when the
        //        cluster's SlotHashes holds a KNOWN-DIFFERENT canonical bank_hash
        //        for the candidate root slot (positive-divergence). ALLOW when
        //        the candidate is duplicate-confirmed (future-proof: today only
        //        the genesis root is, until Part 2 wires the cluster dup-confirm
        //        feed), or when the cluster oracle is silent / agrees (fail-open
        //        — a no-op at bootstrap / offline, exactly as the design requires).
        //   NOTE: the design's literal G2 ("refuse UNLESS duplicate-confirmed")
        //   is inert-armed in this tree — is_duplicate_confirmed is set only for
        //   the genesis root (fork_choice.zig:754 parent_key==null) and never
        //   propagates to a non-root slot without Part 2's cluster dup-confirm
        //   feed, so an "unless-confirmed" refuse would reject EVERY advance. The
        //   positive-divergence form is the safe, faithful realization of the
        //   same protective intent given the signals that exist today; it
        //   auto-strengthens once Part 2 sets is_duplicate_confirmed for real.
        // Both no-op unless this is a real advance (root > prev_root, checked
        // above by the ancestry guard's precondition and here) and the fork-choice
        // tree carries the candidate root — offline replay and bootstrap (empty
        // tree / no cluster oracle) fail open, so canonical replay is byte-
        // identical with ZERO fires.
        //   G0 — FIRST-ROOT POSITIVE-ATTESTATION LATCH (incident 423083743,
        //        2026-07-19): until one candidate root positively matches a
        //        cluster-attested bank_hash, a HASH-SILENT candidate (the G2
        //        fail-open case — exactly how cluster-SKIPPED 423083742 rooted)
        //        additionally requires fetchProducedSlots to confirm the slot
        //        was cluster-produced. Post-latch: byte-identical to pre-G0.
        //        Kill-switch VEX_FIRST_ROOT_LATCH=0; INERT offline (see
        //        firstRootLatchEnabled). Refuse-only, like G1/G2.
        if (root > prev_root) {
            if (self.rootGuardDecisionForAdvance(root, anchor_slot)) |gdec| {
                switch (gdec) {
                    .allow, .allow_attested => {},
                    .refuse_g0 => |why| {
                        const G0Dbg = struct {
                            var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                        };
                        const rc = G0Dbg.count.fetchAdd(1, .monotonic) + 1;
                        std.log.err(
                            "[ROOT-GUARD] slot={d} reason=G0-first-root-unattested consensus_root={d} why={s} (bank={d} prev_root={d} fires={d}) — candidate root is HASH-SILENT (no cluster-attested bank_hash) and {s}; pre-latch root advance REFUSED, prev root kept (423083743 guard)",
                            .{
                                root,
                                prev_root,
                                switch (why) {
                                    .not_produced => @as([]const u8, "not-produced-confirmed"),
                                    .oracle_unreachable => "oracle-unreachable",
                                },
                                anchor_slot,
                                prev_root,
                                rc,
                                switch (why) {
                                    .not_produced => @as([]const u8, "the cluster oracle reports the slot was NOT produced (cluster-skipped)"),
                                    .oracle_unreachable => "the produced-slot oracle is unreachable (fail-closed only pre-latch)",
                                },
                            },
                        );
                        return null;
                    },
                    .refuse_g1 => |lia| {
                        const G1Dbg = struct {
                            var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                        };
                        const rc = G1Dbg.count.fetchAdd(1, .monotonic) + 1;
                        std.log.err(
                            "[ROOT-GUARD] slot={d} reason=G1-invalid-ancestor consensus_root={d} invalid_ancestor={d} (bank={d} prev_root={d} fires={d}) — root advance REFUSED, prev root kept",
                            .{ root, prev_root, lia, anchor_slot, prev_root, rc },
                        );
                        return null;
                    },
                    .refuse_g2 => {
                        const G2Dbg = struct {
                            var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                        };
                        const rc = G2Dbg.count.fetchAdd(1, .monotonic) + 1;
                        std.log.err(
                            "[ROOT-GUARD] slot={d} reason=G2-cluster-divergent consensus_root={d} invalid_ancestor=none (bank={d} prev_root={d} fires={d}) — candidate root's cluster-canonical bank_hash differs from ours; root advance REFUSED, prev root kept",
                            .{ root, prev_root, anchor_slot, prev_root, rc },
                        );
                        return null;
                    },
                }
            }
        }

        // FIX #105: captured from the partition below to gate
        // purgeRootedSlot's range purge (skip when chain incomplete).
        var partition_complete = false;

        // FIX #105 (Option A, Step 1b): write-side fork isolation at the
        // root boundary. BEFORE advanceRoot evicts the fork-blind
        // unflushed_cache → AppendVec, PROMOTE the newly-rooted ANCESTOR
        // chain's fork-aware sig_overlay values into the flat cache
        // (overwriting any sibling-fork pollution — the slot 411,456,733
        // / CRnk carrier), then PURGE proven abandoned siblings so their
        // writes never reach AppendVec. Mirrors Firedancer funk publish +
        // cancel-siblings and Agave defer-durable-write + prune_non_rooted.
        //
        // SAFETY (ROLLOVER blocker #2): ancestry is proven via a parent-
        // pointer walk (NOT bank.ancestors_buf, which is 64-capped and
        // could misclassify a real ancestor as a sibling → destroy rooted
        // data). If the walk cannot reach prev_root (a pruned bank breaks
        // the chain) we promote only what we proved and purge NOTHING —
        // conservative: accept residual pollution, never destroy rooted
        // state.
        if (root > prev_root) {
            // FIX #105 (Option A): ancestry from the DURABLE slot→parent
            // map (db.computeRootPartition), NOT the live bank tree — banks
            // pruned during catch-up severed the parent walk and dropped the
            // carrier's rooted writes from the chain (the slot-564 carrier).
            // The durable map retains every unrooted slot's parent link, so
            // the walk reaches prev_root and the chain is complete. The pure
            // partition is unit-tested (vex_store/root_partition.zig). If the
            // map still can't reach prev_root the chain is incomplete →
            // promote what we proved, purge NOTHING (conservative).
            var part = db.computeRootPartition(self.allocator, prev_root, root);
            if (part) |*p| {
                defer p.deinit(self.allocator);
                partition_complete = p.chain_complete;
                // Promote ASCENDING so the highest ancestor slot wins
                // per-pubkey (Agave latest_slot) — overwrites sibling-fork
                // pollution (the slot 411,456,733 / CRnk carrier).
                db.promoteRootedChain(p.chain.items);
                // PROMOTE-DIAG (2026-05-28): purgeRootedSlot below will
                // purge sig_overlay for the WHOLE (prev_root..root] range,
                // but promoteRootedChain only promoted `p.chain.items`. Any
                // slot purged-but-not-promoted-nor-sibling is a rooted write
                // LOST to the flat cache — the H2 carrier. Flag each one
                // (bounded range to avoid the boot prev=0 megajump).
                if (vex_store.recorder.promoteDiagOn() and root > prev_root and (root - prev_root) < 4096) {
                    var ds: Slot = prev_root + 1;
                    while (ds <= root) : (ds += 1) {
                        var covered = false;
                        for (p.chain.items) |cs| {
                            if (cs == ds) {
                                covered = true;
                                break;
                            }
                        }
                        if (!covered) {
                            for (p.siblings.items) |ss| {
                                if (ss == ds) {
                                    covered = true;
                                    break;
                                }
                            }
                        }
                        if (!covered) {
                            // Self-discriminate: a purged slot with sig_overlay
                            // entries>0 = REAL canonical writes lost (carrier);
                            // entries=0 = benign skipped/empty-slot purge.
                            const ov_entries = db.sig_overlay.entryCountForSlot(ds);
                            if (vex_store.recorder.promoteDiagTick()) {
                                std.log.warn("[PROMOTE-DIAG][PURGE-NO-PROMOTE] slot={d} entries={d} prev_root={d} root={d} chain_len={d} complete={} {s}", .{ ds, ov_entries, prev_root, root, p.chain.items.len, p.chain_complete, if (ov_entries > 0) "*** DANGEROUS: REAL writes purged-no-promote ***" else "(benign skip/empty)" });
                            }
                        }
                    }
                }
                // Purge PROVEN abandoned siblings ONLY when the chain is
                // complete. MUST run BEFORE purgeRootedSlot drops their
                // sig_overlay buckets (purgeUnrootedSlot reads sig_overlay
                // to find which flat-cache pubkeys to clean).
                if (p.chain_complete) {
                    for (p.siblings.items) |s| db.purgeUnrootedSlot(s);
                }
                // Live analog of the unit test: a skip-advance (root
                // jumped over ≥1 slot → chain_len>1) or any sibling purge
                // is exactly the slot-733 carrier shape. Log it so we can
                // grep for the fix firing on a real fork event and confirm
                // parity holds through the descendant slots. A plain +1
                // advance (chain_len==1, no siblings) is silent (per-slot,
                // would be noise). Pairs with purgeUnrootedSlot's
                // [FORK-ISO] per-sibling line.
                if (p.chain.items.len > 1 or p.siblings.items.len > 0 or (vex_store.recorder.promoteDiagOn() and vex_store.recorder.promoteDiagTick())) {
                    std.log.warn("[ROOT-PROMOTE] advance root={d} prev={d} chain_len={d} siblings={d} complete={}", .{ root, prev_root, p.chain.items.len, p.siblings.items.len, p.chain_complete });
                }
            } else {
                // RULE #0: partition unavailable (alloc failure) — promote
                // and purge are skipped; the flat cache keeps whatever it
                // holds this advance. Surface it so we know if it ever fires.
                std.log.warn("[ROOT-PROMOTE] partition unavailable root={d} prev={d} — promote+purge SKIPPED (fork-blind cache unguarded this advance)", .{ root, prev_root });
            }
        }

        db.advanceRoot(root);
        self.emitGeyserSlot(root, null, 2); // geyser: SlotStatus.rooted
        // After advanceRoot evicts unflushed_cache → AppendVec for
        // accounts last-written ≤ root, purge the sig_overlay buckets
        // for the newly-rooted slot AND any sibling/skipped slots in
        // (prev_root..root). This closes the structural fork-iso
        // gap: orphan slots' writes never see canonical reads.
        db.purgeRootedSlot(root, prev_root, partition_complete);
        return prev_root;
    }

    /// #27 VEX_REPLAY_FORCE_ROOT_DEPTH — offline-replay force-root. The offline
    /// driver (main.zig VEX_LEDGER_REPLAY loop) calls this after slotFrozen(K)
    /// with root = K − depth. Without it a no-vote replay never roots →
    /// unrooted_ring grows unboundedly → getWithModifiedSlotPlusSelf goes
    /// O(slots²) (perf-proven 63% CPU by slot ~1600 of the 2026-07-01
    /// 21.7k-slot attempt). Runs the FULL shared root-advance via doRootAdvance
    /// — NEVER bare db.advanceRoot: skipping the partition promote/purge or the
    /// sig_overlay purge would silently falsify replayed bank_hashes (the H2
    /// purge-no-promote carrier shape, offline).
    /// OFFLINE-ONLY: main.zig wires this exclusively inside its
    /// VEX_LEDGER_REPLAY branch; there is no live-path caller by construction.
    pub fn forceAdvanceRootTo(self: *Self, root: Slot, anchor_slot: Slot) void {
        const db = self.accounts_db orelse return;
        if (root <= db.rooted_slot) return;
        const Dbg = struct {
            var advances: u64 = 0;
        };
        if (self.doRootAdvance(db, root, anchor_slot, null)) |prev| {
            Dbg.advances += 1;
            if (Dbg.advances == 1 or Dbg.advances % 500 == 0) {
                std.log.warn("[FORCE-ROOT] advanced root {d} -> {d} (anchor={d} advances={d})", .{ prev, root, anchor_slot, Dbg.advances });
            }
        }
    }

    fn submitVote(self: *Self, bank_in: *Bank) !void {
        const vex_consensus = @import("vex_consensus");
        const secret = self.identity_secret orelse return;
        const vote_acct = self.vote_account orelse return;

        // ── VOTE-COVERAGE CENSUS (permanent telemetry; logged only under VEX_PROP_DIAG) ──
        // Static counters for the vote-credit-gap-coverage mechanism (2026-07-10):
        //   eligible         = submitVote invocations (one per frozen non-own-produced tip we decide on)
        //   cast             = invocations that reached recordVote (an actual own vote; target + tip)
        //   fallback_decided = non-advancing retarget where we CHOSE to vote the frozen tip (this fix) —
        //                      these are EXACTLY the slots the un-fixed binary SILENTLY skipped
        //   fallback_cast    = of those, the ones that then passed isLockedOut/shouldVote and cast
        //   silent_withhold  = non-advancing retarget AND tip also not votable → withheld (unchanged by fix)
        // Un-fixed coverage is derivable from one fixed-binary run: cast_UNFIXED = cast − fallback_cast
        // (the casts that did NOT come from the tip fallback — OLD silently withheld all fallback slots).
        // VoteCensus itself is now file-scope (hoisted above `pub const ReplayStage`, 2026-07-10
        // metrics-reporter task) so getVoteCensusSnapshot() can read it from outside this method.
        // Whether THIS invocation chose the tip-fallback (set below); drives fallback_cast at recordVote.
        var voted_via_fallback = false;
        const census_elig = VoteCensus.eligible.fetchAdd(1, .monotonic) + 1;
        if (self.propDiagEnabled() and census_elig % 100 == 0) {
            const c = VoteCensus.cast.load(.monotonic);
            const fd = VoteCensus.fallback_decided.load(.monotonic);
            const fc = VoteCensus.fallback_cast.load(.monotonic);
            const w = VoteCensus.silent_withhold.load(.monotonic);
            // Un-fixed coverage = casts that did NOT come from the tip-fallback (OLD silently withheld those).
            const cast_unfixed = c - fc; // underflow-safe: fallback_cast ⊆ cast
            std.log.warn(
                "[PROP-DIAG-CENSUS] eligible={d} cast={d} ({d}%) fallback_decided={d} fallback_cast={d} silent_withhold={d} | derived cast_UNFIXED={d} ({d}%)",
                .{ census_elig, c, c * 100 / census_elig, fd, fc, w, cast_unfixed, cast_unfixed * 100 / census_elig },
            );
        }

        // ── PROPAGATION-CONFIRMATION retarget (@prov:replay.select-vote-reset-forks → heaviest_bank) ──
        // ROOT CAUSE of the orphan-vote delinquency (on-chain proven 2026-06-27): Vexor votes the just-frozen
        // TIP eagerly. In a freeze race it votes a cluster-SKIPPED orphan tip BEFORE its canonical sibling
        // freezes → poisons the TowerSync (orphan slot ∉ SlotHashes → vote program SlotsMismatch) → on-chain
        // lastVote frozen while replay stays bank-exact → delinquent (voted 418214636 parent 631 / 418215978).
        // Agave votes the HIGHEST PROPAGATED bank (~1-2 behind tip): the highest ancestor whose fork carries
        // ≥ SUPERMINORITY (1/3) cluster-vote stake (ForkInfo.stake_voted_subtree). The tip leaf is structurally
        // 0 (validators vote ~1-2 behind) — a tip gate cannot work (proven by VEX_PROP_GATE=shadow attempt 1);
        // we must RETARGET to the highest propagated ancestor. An orphan tip has 0 subtree stake and walks back
        // only to its shared canonical fork-point (≤ last_vote ⇒ not votable) → orphan SKIPPED; canonical
        // settles ~2 behind. DORMANT default; VEX_PROP_GATE=shadow logs the would-be target; =armed retargets.
        // SLASHING-SAFE: only ever votes a real frozen ancestor on bank_in's OWN fork, or withholds.
        var bank: *Bank = bank_in;
        prop_retarget: {
            const mode = self.propGateMode();
            if (mode == .off) break :prop_retarget;
            const fc = if (self.fork_choice) |*p| p else break :prop_retarget;
            const db = self.accounts_db orelse break :prop_retarget;
            const pg_mod = @import("vex_consensus").fork_choice;
            var total_stake: u64 = 0;
            const pg_ep = bank_in.epoch_schedule.getEpoch(bank_in.slot);
            for (db.epoch_stakes) |es| {
                if (es.epoch == pg_ep) {
                    for (es.vote_account_stakes) |vs| total_stake +%= vs.stake;
                    break;
                }
            }
            if (total_stake == 0) break :prop_retarget; // no epoch-stake view (bootstrap) → fail-open
            const threshold = total_stake / 3; // SUPERMINORITY (1/3) of bank_in's epoch (for logs)
            var target_slot: ?Slot = null;
            const start_key = pg_mod.SlotHashKey{ .slot = bank_in.slot, .hash = bank_in.bank_hash };
            if (self.propLatchEnabled()) {
                // #93 CANONICAL: vote the highest ancestor whose LEADER WINDOW is latched-propagated.
                // @prov:replay.propagation-latch Walk tip+ancestry; observe each
                // leader-window-START node (latch once subtree voter-stake > 1/3, boundary-correct per-epoch
                // total); pick the highest ancestor whose window is propagated. The LATCH + leader-window
                // indirection make this epoch-boundary-robust (the #92 per-slot proxy was not).
                const prop = @import("vex_consensus").propagation;
                self.propagation_map.pruneBelow(db.rooted_slot); // bound memory (rooted windows implicitly propagated)
                var first = true;
                var it = fc.ancestorIterator(start_key);
                while (true) {
                    const nkey = if (first) start_key else (it.next() orelse break);
                    first = false;
                    const s = nkey.slot;
                    const s_ep = bank_in.epoch_schedule.getEpoch(s);
                    const s_first = bank_in.epoch_schedule.getFirstSlotInEpoch(s_ep);
                    const ws = prop.leaderWindowStart(s, s_first);
                    if (s == ws) { // this node IS its window-start → observe/latch from its subtree stake
                        var s_total: u64 = total_stake;
                        if (s_ep != pg_ep) { // ancestor in a different epoch (near boundary): its own total
                            s_total = 0;
                            for (db.epoch_stakes) |es| {
                                if (es.epoch == s_ep) {
                                    for (es.vote_account_stakes) |vs| s_total +%= vs.stake;
                                    break;
                                }
                            }
                        }
                        self.propagation_map.observe(ws, fc.stakeVotedSubtree(nkey) orelse 0, s_total) catch {};
                    }
                    if (target_slot == null and self.propagation_map.isPropagated(ws)) target_slot = s;
                }
            } else {
                // #92 LEGACY proxy: highest ancestor with ≥1/3 subtree stake (per-slot, NON-latching →
                // withholds at epoch boundary; kept for A/B until the latch is offline-gated + armed).
                if ((fc.stakeVotedSubtree(start_key) orelse 0) >= threshold) {
                    target_slot = bank_in.slot;
                } else {
                    var it = fc.ancestorIterator(start_key);
                    while (it.next()) |akey| {
                        if ((fc.stakeVotedSubtree(akey) orelse 0) >= threshold) {
                            target_slot = akey.slot;
                            break;
                        }
                    }
                }
            }
            if (mode == .shadow) {
                const PropDbg = struct {
                    var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                };
                const n = PropDbg.count.fetchAdd(1, .monotonic) + 1;
                if (target_slot == null or n % 50 == 0) {
                    std.log.warn(
                        "[PROP-RETARGET-SHADOW] tip={d} would_vote_target={?d} (highest ≥1/3-propagated ancestor; thr={d}/{d}) — OBSERVE ONLY, vote unchanged",
                        .{ bank_in.slot, target_slot, threshold, total_stake },
                    );
                }
                break :prop_retarget; // shadow never changes the vote target
            }
            // armed: vote the highest propagated ancestor. FAIL-OPEN if none is ≥1/3-propagated
            // (epoch boundary / vote-ingest lag / catch-up): fall through and vote the tip rather than
            // withhold — a withhold-wedge is fatal (froze the vote at the epoch-981/SIMD-0449 boundary
            // slot 418268256, 2026-06-27), whereas voting the tip is at worst a rare self-healing orphan
            // vote. Orphan prevention still holds the ~99% of slots where a propagated ancestor exists.
            const ArmDbg = struct {
                var act: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                var fo: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
            };
            const ts = target_slot orelse {
                const f = ArmDbg.fo.fetchAdd(1, .monotonic) + 1;
                if (f <= 3 or f % 100 == 0)
                    std.log.warn("[PROP-RETARGET] tip={d} FAIL-OPEN — no ≥1/3-propagated ancestor (boundary/lag), vote tip [#{d}]", .{ bank_in.slot, f });
                break :prop_retarget;
            };
            if (ts != bank_in.slot) {
                self.banks_lock.lockShared();
                const tb = self.banks.get(ts);
                self.banks_lock.unlockShared();
                if (tb) |tbank| {
                    if (tbank.is_frozen) {
                        bank = tbank;
                        const n = ArmDbg.act.fetchAdd(1, .monotonic) + 1;
                        if (n <= 3 or n % 200 == 0)
                            std.log.warn("[PROP-RETARGET] tip={d} → vote propagated ancestor {d} (≥1/3 cluster stake) [#{d}]", .{ bank_in.slot, ts, n });
                    }
                }
            }
        }

        // ── GOSSIP-FED PROP_RETARGET (VEX_GOSSIP_PROP; default OFF) ──────────────────────────────────
        // Fixes the recurring landed-lag STALL (the ≥1/3 landed gate freezes at a stale ancestor because
        // landed votes lag) by feeding REAL-TIME gossip votes into a COMBINED stake (landed subtree +|
        // hash-aware gossip). Orphan-safety is preserved by a HEAVIEST-SIBLING guard, NOT the ≥1/3 floor
        // alone (an absolute floor still confirms a ~40% near-even-loser orphan — advisor 2026-07-01):
        // walk our tip's ancestry and accumulate `chain_clean` ROOT→TIP (chain_clean(node) =
        // chain_clean(parent) AND our child strictly beats every sibling by combined stake). gv_safe =
        // the highest (nearest-tip) node still chain_clean AND combined>1/3. In a freeze-race the losing
        // fork's fork-point is contested (canonical sibling ≥ us) → chain_clean goes false there → gv_safe
        // walks back to the shared fork-point P (≤ last_vote → downstream tower gate makes it VoteTooOld →
        // WITHHOLD, recover-on-canonical-sibling). Independent env from VEX_PROP_GATE. ARMED REQUIRES
        // VEX_PROP_GATE stays armed: unhealthy-feed / no-target falls through to the landed armed target
        // (the fallback); with the landed gate off, that fallthrough would vote the tip = orphan risk.
        // Adopting gv_safe + downstream tower validation is the SAME mechanism the landed armed path uses.
        gossip_prop: {
            const gmode = self.gossipPropMode();
            if (gmode == .off) break :gossip_prop;
            // (Throttle removed: the walk is now single-pass O(voters×depth) via gossip_precompute,
            // cheap enough to run per-vote in both shadow and armed — validated live by the gap staying
            // low without the throttle. This also lets shadow sample per-vote for dense stall capture.)
            const fc = if (self.fork_choice) |*p| p else break :gossip_prop;
            const db = self.accounts_db orelse break :gossip_prop;
            const gp_mod = @import("vex_consensus").fork_choice;

            var total_stake: u64 = 0;
            var n_validators: usize = 0;
            const gp_ep = bank_in.epoch_schedule.getEpoch(bank_in.slot);
            for (db.epoch_stakes) |es| {
                if (es.epoch == gp_ep) {
                    for (es.vote_account_stakes) |vs| {
                        total_stake +%= vs.stake;
                        n_validators += 1;
                    }
                    break;
                }
            }
            if (total_stake == 0) break :gossip_prop; // no epoch-stake view (bootstrap) → fall through
            const threshold = total_stake / 3;
            const majority = total_stake / 2;
            const start_key = gp_mod.SlotHashKey{ .slot = bank_in.slot, .hash = bank_in.bank_hash };

            // Injected ctx (duck-typed for gossip_votes.stakeForSlotAncestryKey): epochStake bound to the
            // VOTER's voted-slot epoch; isAncestorKey hash-aware + INCLUSIVE via fork_choice.
            const GCtx = struct {
                fc: *const @import("vex_consensus").fork_choice.ForkChoice,
                db_es: @TypeOf(db.epoch_stakes),
                sched: @TypeOf(bank_in.epoch_schedule),
                lv: *const @import("gossip_votes.zig").LatestGossipVotes,
                pub fn epochStake(self2: *const @This(), vp: [32]u8) u64 {
                    const rec = self2.lv.get(vp) orelse return 0;
                    const ep = self2.sched.getEpoch(rec.slot);
                    for (self2.db_es) |es| {
                        if (es.epoch == ep) {
                            for (es.vote_account_stakes) |vs| {
                                if (std.mem.eql(u8, &vs.vote_pubkey, &vp)) return vs.stake;
                            }
                            return 0;
                        }
                    }
                    return 0;
                }
                pub fn isAncestorKey(self2: *const @This(), cs: u64, ch: [32]u8, vs: u64, vh: [32]u8) bool {
                    const m = @import("vex_consensus").fork_choice;
                    const ck = m.SlotHashKey{ .slot = cs, .hash = .{ .data = ch } };
                    const vk = m.SlotHashKey{ .slot = vs, .hash = .{ .data = vh } };
                    if (m.SlotHashKey.eql(ck, vk)) return true; // inclusive: candidate IS the voted bank
                    return self2.fc.isStrictAncestor(ck, vk);
                }
            };
            const gctx = GCtx{ .fc = fc, .db_es = db.epoch_stakes, .sched = bank_in.epoch_schedule, .lv = &self.latest_gossip_votes };

            // SINGLE-PASS gossip-stake precompute (O(voters×depth) total, was O(voters×depth) PER
            // ancestry node → O(voters×depth²) per vote — the reason the shadow had to be throttled and
            // arming was blocked). Precompute the hash-aware gossip stake for EVERY node on our tip's
            // ancestry in one pass; result is BYTE-IDENTICAL to stakeForSlotAncestryKey (gated by
            // test-gossip-precompute vs the trusted reference). Held under gossip_votes_lock for the whole
            // build (it reads latest_gossip_votes.map AND gctx.epochStake reads it too); no banks_lock →
            // order (gossip→never→banks) preserved. On OOM → null → SCtx falls back to the on-demand
            // reference for every key (correct, just the old cost). Deinit on scope exit.
            var ancestry_gossip: ?@import("gossip_precompute.zig").AncestryGossip = null;
            defer if (ancestry_gossip) |*agp| agp.deinit();
            {
                self.gossip_votes_lock.lock();
                defer self.gossip_votes_lock.unlock();
                ancestry_gossip = @import("gossip_precompute.zig").precompute(self.allocator, fc, start_key, &self.latest_gossip_votes, &gctx) catch null;
            }
            const ag_ptr: ?*const @import("gossip_precompute.zig").AncestryGossip =
                if (ancestry_gossip) |*agp| agp else null;

            // Prod stake-context for the SHARED gossip_retarget walk (same code the KATs gate):
            // combined = landed subtree +| hash-aware gossip; gossip_votes_lock (leaf) held ONLY around
            // the gossip sum, released before any banks_lock (order gossip→never→banks). landed = baseline.
            const SCtx = struct {
                rs: *Self,
                gctx: *const GCtx,
                fc: *const gp_mod.ForkChoice,
                ag: ?*const @import("gossip_precompute.zig").AncestryGossip,
                pub fn combined(sc: *const @This(), key: gp_mod.SlotHashKey) u64 {
                    const landed_s = sc.fc.stakeVotedSubtree(key) orelse 0;
                    // Ancestry node → O(1) precomputed gossip stake (byte-identical to the reference).
                    if (sc.ag) |agp| {
                        if (agp.get(key)) |g| return landed_s +| g;
                    }
                    // Sibling / off-ancestry node (few — only at contested fork points), or precompute
                    // unavailable → on-demand hash-aware sum, gossip_votes_lock (leaf) held around it.
                    sc.rs.gossip_votes_lock.lock();
                    const gossip_s = sc.rs.latest_gossip_votes.stakeForSlotAncestryKey(key.slot, key.hash.data, sc.gctx);
                    sc.rs.gossip_votes_lock.unlock();
                    return landed_s +| gossip_s;
                }
                pub fn landed(sc: *const @This(), key: gp_mod.SlotHashKey) u64 {
                    return sc.fc.stakeVotedSubtree(key) orelse 0;
                }
            };
            const sctx = SCtx{ .rs = self, .gctx = &gctx, .fc = fc, .ag = ag_ptr };
            const gr = @import("gossip_retarget.zig").walk(fc, start_key, threshold, majority, &sctx);
            const gv_safe = gr.gv_safe; // highest chain_clean ∧ combined>1/3 (THE armed target)
            const gv_floor = gr.gv_floor; // highest combined>1/3, NO guard (unsafe probe, log only)
            const gv_majority = gr.gv_majority; // >1/2 variant (plurality probe, log only)
            const landed_tgt = gr.landed_tgt; // landed-only baseline (log only)
            const contested_at = gr.contested_at; // first (root-ward) contested fork point

            // Orphan probe + feed health for the shadow log.
            self.gossip_votes_lock.lock();
            const tip_gossip = self.latest_gossip_votes.stakeForSlotAncestryKey(start_key.slot, start_key.hash.data, &gctx);
            self.gossip_votes_lock.unlock();
            const tip_combined = (fc.stakeVotedSubtree(start_key) orelse 0) +| tip_gossip;
            const now_ms = std.time.milliTimestamp();
            const feed_age_ms = now_ms - self.last_gossip_vote_ms.load(.monotonic);
            const voters = self.gossip_voter_count_seen.load(.monotonic);
            const min_voters: u32 = @intCast(@max(1, n_validators / 3));
            // 20s window (tuned from live shadow: feed_age p50=7.2s p90=13.7s). A 7-15s-fresh gossip
            // feed is still 10-100x fresher than a minutes-long landed stall, so it remains useful for
            // advancing the target during a stall; 5s was too tight (marked healthy=false 61% of the time).
            const feed_healthy = feed_age_ms >= 0 and feed_age_ms < 20000 and voters >= min_voters;

            if (gmode == .shadow) {
                const GpDbg = struct {
                    var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                };
                const c = GpDbg.count.fetchAdd(1, .monotonic) + 1;
                // Log densely on the STALL SIGNATURE (landed target lagging the tip) so a natural
                // landing-stall (~2-4 min) is fully captured, plus every contested fork point + a
                // periodic baseline. The walk is now O(voters×depth) (single-pass precompute), so
                // per-vote sampling is cheap — the throttle is gone.
                const landed_lag: u64 = if (landed_tgt) |lt| (if (bank_in.slot > lt.slot) bank_in.slot - lt.slot else 0) else 0;
                if (contested_at != null or landed_lag > 4 or c % 20 == 0) {
                    std.log.warn("[GOSSIP-PROP-SHADOW] tip={d} landed_tgt={?d} gv_floor={?d} gv_safe={?d} gv_majority={?d} contested_at={?d} tip_combined={d} tip_gossip={d} thr={d}/{d}/{d} voters={d} feed_age_ms={d} healthy={} — OBSERVE ONLY", .{
                        bank_in.slot,
                        if (landed_tgt) |k| k.slot else null,
                        if (gv_floor) |k| k.slot else null,
                        if (gv_safe) |k| k.slot else null,
                        if (gv_majority) |k| k.slot else null,
                        contested_at,
                        tip_combined,
                        tip_gossip,
                        threshold,
                        majority,
                        total_stake,
                        voters,
                        feed_age_ms,
                        feed_healthy,
                    });
                }
                break :gossip_prop; // shadow never changes the vote target
            }

            // armed: override with the gossip-fed heaviest-sibling target when the feed is healthy.
            // Unhealthy feed OR no gv_safe → fall through (landed armed target stands = the fallback).
            if (!feed_healthy) break :gossip_prop;
            const tkey = gv_safe orelse break :gossip_prop;
            if (!(tkey.slot == start_key.slot and std.mem.eql(u8, &tkey.hash.data, &start_key.hash.data))) {
                // hash-carrying adoption: only adopt a frozen bank whose bank_hash IS tkey.hash.
                self.banks_lock.lockShared();
                const tb = self.banks.get(tkey.slot);
                self.banks_lock.unlockShared();
                if (tb) |tbank| {
                    if (tbank.is_frozen and std.mem.eql(u8, &tbank.bank_hash.data, &tkey.hash.data)) {
                        bank = tbank;
                        const GpArm = struct {
                            var act: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                        };
                        const n = GpArm.act.fetchAdd(1, .monotonic) + 1;
                        if (n <= 3 or n % 200 == 0)
                            std.log.warn("[GOSSIP-PROP] tip={d} → gossip-fed heaviest-sibling target {d} (combined; contested_at={?d}) [#{d}]", .{ bank_in.slot, tkey.slot, contested_at, n });
                    }
                }
            }
            // gv_safe == tip → bank stays bank_in (tip is heaviest+propagated). gv_safe ≤ last_vote →
            // adopted ancestor is VoteTooOld downstream → WITHHOLD (orphan-safe).
        }

        // ── TASK #3 ARMED canonical vote-selection (VEX_CANONICAL_VOTE; default OFF) ─────────────────
        // Replaces prop_retarget's backward ≥1/3 walk. @prov:replay.select-vote-reset-forks —
        // vote bestOverallSlot() (heaviest-subtree leaf) when it is a same-fork extension of
        // our last vote OR a valid switch; else fall back to the heaviest bank on our OWN
        // voted fork (deepestSlotOf(last_vote), the Figure-1 anti-halt reset).
        // This only SELECTS `bank`; the downstream tower gates (isLockedOut + the switch_proof block) do
        // the final validation, so a cross-fork target still needs VEX_SWITCH_PROOF authorization and a
        // lockout-violating target is still refused. SLASHING-SAFE: only ever votes a real frozen bank.
        // OFFLINE-GATED on freeze-418669047.2 (must advance past the stall AND refuse/self-heal the orphan)
        // before being armed live. When OFF, behavior is byte-identical to the prop_retarget path above.
        if (self.canonicalVoteEnabled()) canonical_vote: {
            const fc = if (self.fork_choice) |*p| p else break :canonical_vote;
            const t0 = if (self.tower) |*p| p else break :canonical_vote;
            const db = self.accounts_db orelse break :canonical_vote;
            const fcm = @import("vex_consensus").fork_choice;
            const best = fcm.bestSlotCompat(fc) orelse break :canonical_vote;
            var target_slot: Slot = best;
            if (t0.vote_state.lastVotedSlot()) |last_voted| {
                var total_stake: u64 = 0;
                const ep = bank_in.epoch_schedule.getEpoch(bank_in.slot);
                for (db.epoch_stakes) |es| {
                    if (es.epoch == ep) {
                        for (es.vote_account_stakes) |vs| total_stake +%= vs.stake;
                        break;
                    }
                }
                const ffeed = @import("fork_choice_feed.zig");
                const SLT = ffeed.EpochStakeLookup(@TypeOf(db.epoch_stakes));
                const sl = SLT{ .epoch_stakes = db.epoch_stakes, .epoch_schedule = bank_in.epoch_schedule };
                const dec = fc.checkSwitchThreshold(last_voted, best, total_stake, sl);
                if (!(dec.same_fork or dec.would_switch)) {
                    // FailedSwitch ⇒ heaviest bank on our OWN voted fork (stay on our fork; Figure-1).
                    self.banks_lock.lockShared();
                    const lvb = self.banks.get(last_voted);
                    self.banks_lock.unlockShared();
                    if (lvb) |b| {
                        const lvk = fcm.SlotHashKey{ .slot = last_voted, .hash = b.bank_hash };
                        // @prov:replay.heaviest-bank-same-voted-fork — is_candidate ? best : deepest.
                        // Was unconditional deepest = the Some(false) branch only, non-canonical
                        // when last vote is still a candidate.
                        if (fc.heaviestSlotOnSameVotedFork(lvk)) |d| target_slot = d.slot;
                    }
                }
            }
            self.banks_lock.lockShared();
            const tb = self.banks.get(target_slot);
            self.banks_lock.unlockShared();
            if (tb) |tbank| {
                if (tbank.is_frozen) {
                    bank = tbank;
                    const CanonDbg = struct {
                        var c: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                    };
                    const n = CanonDbg.c.fetchAdd(1, .monotonic) + 1;
                    if (n <= 3 or n % 200 == 0)
                        std.log.warn("[CANONICAL-VOTE] tip={d} → canonical target {d} (heaviest-leaf/switch/same-fork-fallback) [#{d}]", .{ bank_in.slot, target_slot, n });
                }
            }
        }

        // ── TASK #3 SHADOW (observe-only; VEX_HEAVIEST_SHADOW; default OFF) ──────────────────────────
        // Logs how our ACTUAL vote target (`bank.slot` = the eager tip AFTER the PROP-retarget above)
        // compares to @prov:replay.heaviest-subtree-leaf-target — this is the measurement that prices the
        // ~1-credit landing-latency gap: Agave/FD vote the heaviest leaf (typically the fresh tip →
        // latency 1), whereas our PROP-gate retargets ~1 slot behind. ZERO behavioral effect — it never
        // mutates `bank`; pure logging, so it cannot affect consensus, liveness, or slashing-safety.
        // Verified byte-faithful to Agave 4.1.0-rc.1 (audit 2026-06-28 + main-loop spot-check).
        //
        // INTERPRETATION CAVEATS — do NOT read `best_minus_actual` as "credits we'd gain":
        //   1. SAME-FORK BUCKETING: Agave votes best_overall ONLY when it is a same-fork extension
        //      of the last vote (or a switch proof passes); cross-fork it votes
        //      heaviest_slot_on_same_voted_fork or abstains. A cross-fork `best` is therefore NOT
        //      "what Agave would vote" — every sample is tagged `same_fork=` so cross-fork rows are
        //      bucketed out when reading the data.
        //   2. Our fork-choice tree is fed from votes LANDED in replayed blocks (not gossip-frozen
        //      votes), so `best` trails the true cluster heaviest by our own vote-landing latency.
        //      Directionally conservative; the measured gap conflates fork-choice lag with landing lag.
        // ARMING is a LATER, separate phase (NOT enabled here): it additionally requires
        // heaviest_slot_on_same_voted_fork + switch-threshold compose + last_vote_able_to_land refresh
        // + duplicate-invalid marking. This block only OBSERVES.
        heaviest_shadow: {
            if (!self.heaviestShadowEnabled()) break :heaviest_shadow;
            const fc = if (self.fork_choice) |*p| p else break :heaviest_shadow;
            const fc_mod = @import("vex_consensus").fork_choice;
            const best = fc_mod.bestSlotCompat(fc) orelse break :heaviest_shadow; // heaviest-subtree leaf slot
            const actual = bank.slot; // our real vote target (eager tip, post PROP-retarget)
            const tip = bank_in.slot; // the eager frozen tip we were handed
            // `best` is a SAFE same-fork extension iff it shares a fork with our actual target: either
            // best == actual, or actual is an ancestor of best (we'd extend our own fork forward to it),
            // or best is an ancestor of actual (we are already ahead of it). isAncestorBySlot(a,b) =
            // "is a an ancestor of b" — the SAME API the tower's is_same_fork uses (:4938).
            const same_fork = (best == actual) or fc.isAncestorBySlot(actual, best) or fc.isAncestorBySlot(best, actual);

            // ── GATE-AWARE canonical decision (Task #3 stage 1, 2026-06-30; OBSERVE-ONLY) ───────────
            // Compute what @prov:replay.select-vote-reset-forks WOULD
            // vote if the target were the heaviest-subtree leaf `best`: the switch decision (SameFork vs
            // SwitchProof vs FailedSwitch via checkSwitchThreshold) and the resulting candidate (vote
            // `best` iff SameFork|SwitchProof, else fall back to the heaviest bank on our own voted fork
            // = deepestSlotOf(last_vote)). This prices the canonical fix and — load-bearing — surfaces the
            // ORPHAN freeze-race signal (`best` cross-fork from last_vote with NO switch proof) in live
            // logs BEFORE arming, so the orphan-safety question is answered from real traffic + offline
            // replay, not theory (advisor 2026-06-30). ZERO behavioral effect: never mutates `bank`/vote.
            var sw_same: bool = true; // no prior vote ⇒ Agave SameFork
            var sw_switch: bool = false;
            var canon_target: Slot = best;
            if (self.tower) |*t| {
                if (t.vote_state.lastVotedSlot()) |last_voted| {
                    // STARVATION FIX (2026-07-06, task #32): the same-fork fast path below is
                    // EXACTLY checkSwitchThreshold's own early-return (fork_choice.zig:510) —
                    // one ancestry walk instead of the full per-voter loop. Only a TRUE
                    // cross-fork-from-last-vote (the rare orphan-relevant event) pays the full
                    // (now slot-memoized) switch-threshold walk. Before this, fork churn made
                    // EVERY vote pay an O(voters × tree) walk on the submit path → the
                    // 04:36Z/12:22Z vote-landing delinquencies.
                    const cheap_same = (best == last_voted) or fc.isAncestorBySlot(best, last_voted);
                    if (cheap_same) {
                        sw_same = true;
                        sw_switch = true; // == the early-return's would_switch
                    } else if (self.accounts_db) |db| {
                        // Total epoch stake is CONSTANT within an epoch — cache it instead of
                        // re-summing ~15.5k vote-account stakes on every vote (task #32).
                        const EpochStakeCache = struct {
                            var epoch: u64 = std.math.maxInt(u64);
                            var total: u64 = 0;
                        };
                        const ep = bank.epoch_schedule.getEpoch(bank.slot);
                        if (EpochStakeCache.epoch != ep) {
                            var tot: u64 = 0;
                            for (db.epoch_stakes) |es| {
                                if (es.epoch == ep) {
                                    for (es.vote_account_stakes) |vs| tot +%= vs.stake;
                                    break;
                                }
                            }
                            EpochStakeCache.total = tot;
                            EpochStakeCache.epoch = ep;
                        }
                        const total_stake = EpochStakeCache.total;
                        const ffeed = @import("fork_choice_feed.zig");
                        const StakeLookupT = ffeed.EpochStakeLookup(@TypeOf(db.epoch_stakes));
                        const stake_lookup = StakeLookupT{ .epoch_stakes = db.epoch_stakes, .epoch_schedule = bank.epoch_schedule };
                        const dec = fc.checkSwitchThreshold(last_voted, best, total_stake, stake_lookup);
                        sw_same = dec.same_fork;
                        sw_switch = dec.would_switch;
                        if (!(dec.same_fork or dec.would_switch)) {
                            // FailedSwitch ⇒ @prov:replay.heaviest-bank-same-voted-fork (stay on own
                            // fork; Figure-1 anti-halt) = the deepest descendant of our last vote.
                            self.banks_lock.lockShared();
                            const lv_bank = self.banks.get(last_voted);
                            self.banks_lock.unlockShared();
                            if (lv_bank) |lvb| {
                                const lv_key = fc_mod.SlotHashKey{ .slot = last_voted, .hash = lvb.bank_hash };
                                if (fc.deepestSlotOf(lv_key)) |d| canon_target = d.slot;
                            }
                        }
                    }
                }
            }
            const ShadowDbg = struct {
                var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
            };
            const n = ShadowDbg.count.fetchAdd(1, .monotonic) + 1;
            // Log periodic samples AND every cross-fork case (best is neither same-fork nor a valid
            // switch = the orphan-relevant signal) so freeze-race events are never sampled out.
            const cross_fork_best = !sw_same and !sw_switch;
            if (n <= 5 or n % 100 == 0 or cross_fork_best) {
                std.log.warn(
                    "[HEAVIEST-SHADOW] actual_vote={d} best_overall={d} canon_target={d} tip={d} best_minus_actual={d} best_is_tip={} same_fork={} sw_same={} sw_switch={} cross_fork_best={} — OBSERVE ONLY, vote unchanged [#{d}]",
                    .{ actual, best, canon_target, tip, @as(i64, @intCast(best)) - @as(i64, @intCast(actual)), best == tip, same_fork, sw_same, sw_switch, cross_fork_best, n },
                );
            }
        }

        // Record vote in tower state (handles lockout expiry + confirmation doubling)
        if (self.tower) |*t| {
            // ── VOTE-COVERAGE target resolution (2026-07-10, vote-credit-gap-coverage mechanism) ──
            // resolveVoteTarget is the SLOT-gate decision (tower.zig): .target when the retargeted
            // slot strictly advances (canVote), .tip when the retarget is NON-ADVANCING (canVote=false
            // ⇒ ≤ last_vote) but the frozen own-fork TIP still advances, else .withhold. The .tip
            // FALLBACK fixes the silent skip — the un-fixed code SILENTLY returned here, casting ZERO
            // votes on ~29% of slots (86% at leader-window position 1). Voting the tip mirrors the
            // FAIL-OPEN branch in the retarget block (vote the tip when NO ≥1/3-propagated ancestor
            // exists). The tip is a real frozen bank on our OWN fork → slashing-safe by construction;
            // the chosen slot still passes canVote (inside resolveVoteTarget) + isLockedOut + shouldVote
            // below — those gates are UNTOUCHED.
            const choice = t.vote_state.resolveVoteTarget(bank.slot, bank_in.slot, bank_in.is_frozen);
            if (choice != .target) {
                if (self.propDiagEnabled()) {
                    const PropDiag = struct {
                        var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                    };
                    const dn = PropDiag.count.fetchAdd(1, .monotonic) + 1;
                    std.log.warn(
                        "[PROP-DIAG] non-advancing target A={d} (canVote=false) last_vote={?d} tip={d} tip_frozen={} action={s} [#{d}]",
                        .{ bank.slot, t.vote_state.lastVotedSlot(), bank_in.slot, bank_in.is_frozen, if (choice == .tip) "fallback=tip" else "SILENT-WITHHOLD", dn },
                    );
                }
                switch (choice) {
                    .tip => {
                        // FIX (2026-07-17, switch-proof sibling-race divergence — live
                        // event @422600922): `bank_in` ("the tip") is whichever bank
                        // onSlotCompleted's queue just finished freezing — driven by
                        // shred-assembly-completion order across ALL forks, NOT
                        // validated against fork-choice. The "own-fork tip" name/doc
                        // comment above (and the "slashing-safe by construction"
                        // claim) assumes bank_in extends OUR OWN tower forward, which
                        // is only true when `target` (fork-choice's own pick,
                        // resolved by prop_retarget/canonical_vote above) merely
                        // trails a genuinely-advancing same-fork tip. It is FALSE
                        // when `target` == last_voted_slot itself (fork-choice found
                        // NOTHING heavier than what we already voted) and bank_in is
                        // instead a fresh SIBLING from a freeze race (same parent,
                        // different child) — confirmed live: 422600919 (our last
                        // vote, already canonical) vs. sibling 422600922, which froze
                        // moments later and fell straight into this branch
                        // ("[PROP-RETARGET] fallback=tip target=422600919<=last_vote
                        // =422600919 → vote own-fork tip=422600922"). Blindly setting
                        // `bank = bank_in` here feeds an UNVALIDATED cross-fork slot
                        // into the switch-proof block below as `switch_slot`, asking
                        // "should I switch to bank_in" even though fork-choice's own
                        // heaviest-bank selection (`best`, computed above) never
                        // nominated it — a category error: Agave only ever evaluates
                        // check_switch_threshold against heaviest_bank.slot(), the
                        // fork-choice-selected candidate, never an arbitrary
                        // just-replayed sibling (core/src/consensus/fork_choice.rs:
                        // 434-445; see AGAVE-SWITCHPROOF-CANONICAL-SPEC-2026-07-17.md
                        // §1.4). That mis-fed switch-proof authorized a vote onto
                        // 422600922, which then got orphaned (2 TOWER-LOCKOUT
                        // refusals + 3-slot excursion before CANONICAL-VOTE
                        // recovered onto 422600925).
                        //
                        // Restrict the fallback to its actually-safe case: bank_in
                        // must be a genuine descendant of last_voted_slot (or equal
                        // to it) — i.e. really "our own fork's tip", not a sibling.
                        // A cross-fork bank_in is exactly the scenario the
                        // switch-proof mechanism exists to gate via fork-choice's
                        // OWN heaviest pick, on a LATER tick once fork-choice itself
                        // (not shred-arrival order) prefers it — never here.
                        const last_voted = t.vote_state.lastVotedSlot() orelse bank_in.slot;
                        const tip_is_own_fork = if (self.fork_choice) |*fc_ck|
                            fc_ck.isAncestorBySlot(bank_in.slot, last_voted)
                        else
                            true; // no fork-choice data (bootstrap/unit harness) → legacy permissive behavior
                        if (!tip_is_own_fork) {
                            _ = VoteCensus.silent_withhold.fetchAdd(1, .monotonic);
                            const SibDbg = struct {
                                var n: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                            };
                            const sn = SibDbg.n.fetchAdd(1, .monotonic) + 1;
                            if (sn <= 3 or sn % 200 == 0)
                                std.log.warn(
                                    "[PROP-RETARGET] fallback=tip REFUSED — tip={d} is NOT a descendant of last_vote={d} (cross-fork sibling, not own-fork tip) — withholding, letting switch-proof gate on fork-choice's own pick instead [#{d}]",
                                    .{ bank_in.slot, last_voted, sn },
                                );
                            self.maybeRefreshLastVote();
                            return;
                        }
                        // FIX (2026-07-20, cross-fork lockout wedge @423281048): the gate
                        // above proves the TIP extends our own tower, but says nothing
                        // about the TARGET — fork-choice's actual pick. When the target is
                        // NOT an ancestor of the tip, fork-choice has selected a DIFFERENT
                        // fork (the cluster disagrees with the fork we're standing on) and
                        // it is merely non-advancing by slot number. Voting our own tip
                        // then is the opposite of Agave's FailedSwitchThreshold semantics
                        // (no vote, reset to own fork, wait): each fallback vote doubles
                        // our own lockouts on the losing fork. Live @423281048-063 this
                        // loop cast 10 extra own-fork votes against canonical target
                        // 423281051 → ~1024-slot lockout → delinquency, where withholding
                        // leaves lockouts 8/4/2 and the node re-joins canonical within a
                        // few slots (as 5 sibling episodes that night did). The fallback's
                        // ONLY intended case is a same-fork target that trails a
                        // genuinely-advancing own-fork tip (propagation lag), so require
                        // target ∈ ancestors(tip). isAncestorBySlot is false on unknown
                        // ancestry → conservative direction (withhold, never dig).
                        const target_on_own_fork = if (self.fork_choice) |*fc_ck|
                            fc_ck.isAncestorBySlot(bank_in.slot, bank.slot)
                        else
                            true; // no fork-choice data (bootstrap/unit harness) → legacy permissive behavior
                        if (!target_on_own_fork) {
                            _ = VoteCensus.silent_withhold.fetchAdd(1, .monotonic);
                            const XfDbg = struct {
                                var n: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                            };
                            const xn = XfDbg.n.fetchAdd(1, .monotonic) + 1;
                            if (xn <= 3 or xn % 200 == 0)
                                std.log.warn(
                                    "[PROP-RETARGET] fallback=tip REFUSED — target={d} is NOT an ancestor of tip={d} (fork-choice prefers a different fork) — withholding instead of deepening own-fork lockout [#{d}]",
                                    .{ bank.slot, bank_in.slot, xn },
                                );
                            self.maybeRefreshLastVote();
                            return;
                        }
                        const fc_n = VoteCensus.fallback_decided.fetchAdd(1, .monotonic) + 1;
                        if (fc_n <= 3 or fc_n % 200 == 0)
                            std.log.warn(
                                "[PROP-RETARGET] fallback=tip target={d}<=last_vote={?d} → vote own-fork tip={d} (non-advancing retarget) [#{d}]",
                                .{ bank.slot, t.vote_state.lastVotedSlot(), bank_in.slot, fc_n },
                            );
                        bank = bank_in; // vote the frozen own-fork tip instead of silently withholding
                        voted_via_fallback = true;
                    },
                    .withhold => {
                        _ = VoteCensus.silent_withhold.fetchAdd(1, .monotonic);
                        self.maybeRefreshLastVote(); // keep the last vote landing during the slot-lag window
                        return;
                    },
                    .target => unreachable,
                }
            }

            // CARRIER #7 LAYER 1 (2026-06-10): fork-aware lockout — Agave
            // Tower::is_locked_out / Sig isLockedOut. canVote above is
            // slot-number-only (fork-BLIND): @414406146 it admitted a vote on
            // canonical 147 ONE slot after voting abandoned-fork 146 (lockout
            // active until 148) — a slashable-class lockout violation — and
            // the un-expired fork vote then marched to tower depth 31, became
            // the AccountsDb root, and the root-advance promote/purge poisoned
            // the rooted store (epoch_credits −34 @414406188).
            //
            // Ancestry of the candidate bank = the DURABLE slot_parents walk
            // from bank.parent down to rooted_slot (unrootedAncestorChain, the
            // same source computeRootPartition trusts) + the rooted prefix
            // (every slot ≤ rooted_slot is an ancestor — the rooted chain is
            // linear). If the walk is truncated (missing parent link) a prior
            // vote may be misclassified as non-ancestor → we REFUSE the vote:
            // conservative direction (liveness pause, never a lockout
            // violation).
            // FIX (2026-07-17, switch-proof-gossip-arming session — the ACTUAL
            // blocker behind live wedge 422521275): the fallback walk below used
            // to write into a FIXED `[4096]Slot` stack buffer. Once unrooted depth
            // (candidate.slot − db.rooted_slot) exceeds ~4096 — which a stuck root
            // guarantees will keep growing, forever, one slot at a time — the walk
            // silently TRUNCATES before reaching a last_voted_slot that sits close
            // to root (this wedge: last_voted_slot was only 73 slots above root;
            // the walk started at the CANDIDATE TIP and could only cover the
            // nearest 4096 slots of an unrooted region that had grown past 14,000).
            // `isLockedOut` (tower.zig:145-149) cannot distinguish "walked to root,
            // confirmed absent" from "buffer exhausted before reaching root" —
            // `ancestors.containsSlot(lockout.slot)` is false either way, and a
            // false `containsSlot` unconditionally returns locked-out=true. Once
            // that fires, this function returns at line ~6385 — BEFORE the
            // switch-proof block (§below) is ever reached. Confirmed on the live
            // log: [SWITCH-PROOF] lines stop for good at slot 422525389 (unrooted
            // depth 4187 — within ~2% of the 4096 bound) while [TOWER-LOCKOUT]
            // refusals keep climbing (10,700+) for the next 10,800+ slots. This is
            // a Vexor-only bound: Agave's `ancestors: HashMap<Slot, HashSet<Slot>>`
            // is re-derived fresh from BankForks every replay tick (no fixed cap);
            // Firedancer's tower ancestry is a live parent-pointer walk with no
            // fixed cap either. Fix: size the fallback buffer to the ACTUAL
            // unrooted distance (heap-allocated, freed at the end of this scope)
            // instead of a fixed cap — the walk can then always reach root,
            // regardless of how deep an ongoing wedge has grown. This changes ONLY
            // the completeness of the ancestor SET fed to `isLockedOut`; the
            // function's own lockout logic is untouched, and per its existing
            // documented invariant ("walks TRUE parent links... can only find
            // GENUINE ancestors... can never invent a false ancestor") this can
            // only REMOVE false-positive lockouts, never introduce a false
            // negative — one-directional, same safety class as CARRIER #20/#7.
            var anc_buf_dyn: []Slot = &.{};
            defer if (anc_buf_dyn.len > 0) self.allocator.free(anc_buf_dyn);
            // OOM-only fallback storage — declared here (not nested inside the
            // `catch` below) so its stack lifetime unambiguously spans the
            // `.chain` assignment that may reference it. Same 4096 cap + same
            // may-truncate/over-refuse-never-under-refuse behavior as the
            // pre-fix code; only reached if allocating `anc_buf_dyn` fails.
            var anc_buf_fallback: [4096]Slot = undefined;
            const ancestors: vex_consensus.tower.TowerBft.SliceAncestors = if (self.accounts_db) |db| .{
                .rooted_slot = db.rooted_slot,
                // CARRIER #20 (2026-06-13): build the ancestor chain from the LIVE
                // banks map (authoritative in-memory parent links = Agave BankForks
                // ancestors) down to root, NOT the durable slot_parents map alone.
                // slot_parents can have gaps mid-catch-up (sentinel/wake freeze
                // paths) → unrootedAncestorChain TRUNCATED → a true ancestor
                // (last_vote, above root on the canonical fork — parity MATCHES)
                // was misclassified non-ancestor → false cross-fork lockout →
                // ALL votes REFUSED → delinquency (@415008611, db.rooted_slot raced
                // ahead). Walking TRUE parent links only ADDS true ancestors (fixes
                // the false-negative); it can never invent a false ancestor, so the
                // carrier-7 cross-fork protection is fully preserved.
                // CARRIER #7 FIX (2026-06-23): consume the bank's COMPLETE INHERITED
                // proper-ancestor set (built in getOrCreateBank, Agave bank.rs:1420
                // parity) — it never truncates, unlike the ancestorChainComplete walk
                // below which broke at a live sentinel bank (parent_slot=null) →
                // last_vote misclassified non-ancestor → false cross-fork lockout →
                // sustained delinquency (@417317107, 2026-06-23). The inherited set is
                // built only from verified true ancestors, so carrier-7 cross-fork
                // protection is preserved (it can never invent a false ancestor). Fall
                // back to the legacy walk ONLY on the rare overflow (>512 unrooted
                // depth = deep catch-up) — sized to the ACTUAL unrooted distance
                // (see 2026-07-17 fix note above), never truncated.
                .chain = if (!bank.proper_ancestors_overflow)
                    bank.proper_ancestors[0..bank.proper_ancestors_len]
                else chain_blk: {
                    const parent = bank.parent_slot orelse 0;
                    const need: usize = if (parent > db.rooted_slot) parent - db.rooted_slot else 0;
                    anc_buf_dyn = self.allocator.alloc(Slot, need) catch {
                        // OOM on a multi-thousand-slot wedge's ancestor buffer:
                        // fall back to the bounded walk (conservative — may
                        // truncate and over-refuse, exactly today's behavior,
                        // never under-refuses) rather than crash the replay loop.
                        break :chain_blk self.ancestorChainComplete(parent, db.rooted_slot, &anc_buf_fallback);
                    };
                    break :chain_blk self.ancestorChainComplete(parent, db.rooted_slot, anc_buf_dyn);
                },
            } else .{
                // No accounts_db (unit/bootstrap harness): no ancestry source.
                // Treat every slot as an ancestor — degrades to the legacy
                // slot-only lockout (canVote above), never blocks bootstrap.
                .rooted_slot = std.math.maxInt(u64),
                .chain = &.{},
            };
            if (t.vote_state.isLockedOut(bank.slot, ancestors)) {
                const LockoutDbg = struct {
                    var count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                };
                const lc = LockoutDbg.count.fetchAdd(1, .monotonic) + 1;
                std.log.warn(
                    "[TOWER-LOCKOUT] vote REFUSED slot={d} parent={?d} last_vote={?d} rooted={d} — cross-fork lockout active (carrier #7 guard, refusals={d})",
                    .{ bank.slot, bank.parent_slot, t.vote_state.lastVotedSlot(), if (self.accounts_db) |db| db.rooted_slot else 0, lc },
                );
                self.maybeRefreshLastVote(); // cross-fork-lockout keep-alive: re-send last vote so it keeps landing (#87)
                return;
            }

            // d28nn (2026-05-12): proper ancestor walk via ForkChoice.isAncestor
            // (added to vex_consensus/fork_choice.zig in this commit). Prior
            // heuristic at this line accepted `best > bank.slot` as "same fork"
            // — which is WRONG for reorgs: the GHOST heaviest subtree could
            // legitimately be on a different fork that simply contains higher
            // slot numbers. Tower would then permit votes on a non-canonical
            // fork. Convergent finding from 2 parallel sub-agents 2026-05-12.
            //
            // Correct semantics: we are "on the same fork" iff the current
            // bank's slot is in the ancestry chain of the GHOST best slot
            // (or trivially equal to it). Walks bank.parent → … → root via
            // ForkNode.parent pointers; O(depth), early-exit on match.
            //
            // Bootstrap fallthrough (no fork_choice / no best slot yet):
            // permit vote — Vexor needs to land its first tower vote to
            // make any cluster progress observable.
            // PHASE-1 (2026-05-26): bestSlotCompat returns just the slot (drops
            // hash) for is_same_fork comparison; isAncestorBySlot accepts slot-
            // only args because the caller doesn't have parent_hash available
            // at this site. Internally walks parent chain via the (Slot, Hash)
            // tree. Returns true when any node at bank.slot is an ancestor of
            // any node at the best slot.
            const fc_mod = @import("vex_consensus").fork_choice;
            const is_same_fork = if (self.fork_choice) |*fc|
                if (fc_mod.bestSlotCompat(fc)) |best| fc.isAncestorBySlot(best, bank.slot) else true
            else
                true; // No GHOST data yet — assume same fork (bootstrap)

            // ── VOTE-THRESHOLD depth-8 stake wiring (incident 423083743 companion fix) ──
            // The threshold check inside shouldVote was structurally DEAD: both live
            // call sites passed (0,0) and tower.zig skips the check when total_stake==0.
            // That hollow gate is how the 2026-07-19 boot voted 32× onto cluster-SKIPPED
            // 423083742 and rooted it — Agave/FD are immune because their depth-8 check
            // runs with REAL stake from votes landed in replayed blocks and stops the
            // tower fill ~24 votes before a root could form. Compute the real
            // (cluster_voted_stake@depth8, total_epoch_stake) here from already-
            // maintained replay-thread aggregates (fork-choice stake_voted_subtree fed
            // by buildVoteAccountBatchFresh in onSlotCompleted + per-epoch total cache)
            // — no new cross-thread sync. thresholdStakesForMode is the single seam
            // deciding what reaches shouldVote: SHADOW (default) forwards (0,0) so vote
            // decisions stay byte-identical while [VOTE-THRESHOLD-SHADOW] logs the
            // would-be verdict; VEX_VOTE_THRESHOLD=1 arms enforcement (after soak).
            const thr_mode = self.voteThresholdMode();
            var thr_voted: u64 = 0;
            var thr_total: u64 = 0;
            if (thr_mode != .off) {
                if (t.vote_state.thresholdDepthSlot(bank.slot)) |d8| {
                    thr_voted = self.clusterVotedStakeAtDepthSlot(d8, bank.slot, bank.bank_hash);
                    thr_total = self.epochTotalStake(bank);
                }
                // Simulated tower shallower than depth 8 → (0,0) stays: the check is
                // skipped, matching Agave's trivial-pass for a not-deep-enough tower.
            }
            const thr = vex_consensus.tower.TowerBft.thresholdStakesForMode(thr_mode, thr_voted, thr_total);

            // Full vote decision: lockout (slot + fork-aware) + threshold + fork safety.
            // shouldVote is side-effect-free (canVote + isLockedOut + threshold +
            // the conservative cross-fork stub), so it is safe to evaluate twice.
            const legacy_ok = t.shouldVote(bank.slot, is_same_fork, ancestors, thr.voted, thr.total);
            var allow_vote = legacy_ok;

            // SHADOW: would the REAL-stake verdict differ from the (0,0) verdict the
            // vote decision actually used? Only the threshold clause can differ (the
            // other gates saw identical inputs), and it only ever REFUSES — so a
            // difference is exactly "legacy passed, real stake would refuse".
            if (thr_mode == .shadow and thr_total > 0) {
                const ThrDbg = struct {
                    var evals: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                };
                const n = ThrDbg.evals.fetchAdd(1, .monotonic) + 1;
                const real_ok = t.shouldVote(bank.slot, is_same_fork, ancestors, thr_voted, thr_total);
                if (real_ok != legacy_ok) {
                    std.log.warn(
                        "[VOTE-THRESHOLD-SHADOW] slot={d} depth=8 depth8_slot={?d} voted_stake={d} total={d} verdict=WOULD-REFUSE — cluster stake at depth-8 below {d}% (OBSERVE ONLY, vote unchanged)",
                        .{ bank.slot, t.vote_state.thresholdDepthSlot(bank.slot), thr_voted, thr_total, vex_consensus.tower.TowerBft.THRESHOLD_PCT },
                    );
                } else if (n == 1 or n % 512 == 0) {
                    std.log.info(
                        "[VOTE-THRESHOLD-SHADOW] slot={d} depth=8 voted_stake={d} total={d} verdict=PASS (sample #{d})",
                        .{ bank.slot, thr_voted, thr_total, n },
                    );
                }
            }

            // ── #87 Tier-3: canonical switch-threshold proof (gated off/shadow/armed) ──
            // DORMANT by default (VEX_SWITCH_PROOF unset): behavior is byte-identical
            // to the legacy conservative stub (cross-fork votes refused). The switch
            // proof is an ADDITIONAL liveness gate, NEVER a lockout override — it is
            // consulted ONLY when the validator is already lockout-clear (enforced at
            // the LAYER-1 guard above AND inside shouldVote). @prov:replay.switch-proof-composition
            // Given lockout-clear, even a wrong proof cannot cast a slashable vote.
            switch_proof: {
                const mode = self.switchProofMode();
                if (mode == .off) break :switch_proof;
                if (legacy_ok) break :switch_proof; // already voting (same fork) — nothing to add
                // Confirm the ONLY failing gate was the cross-fork stub: re-run
                // shouldVote forcing is_same_fork=true. If that is ALSO false, the
                // refusal was for a real reason (lockout/threshold) — never override.
                // VOTE-THRESHOLD wiring (423083743 companion fix): same `thr` seam as
                // the main call site above — (0,0) in shadow/off (byte-identical),
                // real stakes when armed (a threshold-failing tower then correctly
                // blocks the switch-proof liveness override too).
                if (!t.shouldVote(bank.slot, true, ancestors, thr.voted, thr.total)) break :switch_proof;
                if (thr_mode == .shadow and thr_total > 0 and
                    !t.shouldVote(bank.slot, true, ancestors, thr_voted, thr_total))
                {
                    std.log.warn(
                        "[VOTE-THRESHOLD-SHADOW] site=switch-proof slot={d} depth=8 voted_stake={d} total={d} verdict=WOULD-REFUSE — armed mode would block the switch-proof path here (OBSERVE ONLY)",
                        .{ bank.slot, thr_voted, thr_total },
                    );
                }
                const fc = if (self.fork_choice) |*p| p else break :switch_proof;
                const db = self.accounts_db orelse break :switch_proof;
                const last_voted = t.vote_state.lastVotedSlot() orelse {
                    // No prior vote → Agave SameFork → safe (lockout-clear).
                    allow_vote = true;
                    break :switch_proof;
                };
                // Denominator = TOTAL epoch stake (NOT voted stake). @prov:replay.switch-proof-stake-denominator
                var total_stake: u64 = 0;
                const ep = bank.epoch_schedule.getEpoch(bank.slot);
                for (db.epoch_stakes) |es| {
                    if (es.epoch == ep) {
                        for (es.vote_account_stakes) |vs| total_stake +%= vs.stake;
                        break;
                    }
                }
                const ffeed = @import("fork_choice_feed.zig");
                const StakeLookupT = ffeed.EpochStakeLookup(@TypeOf(db.epoch_stakes));
                const stake_lookup = StakeLookupT{
                    .epoch_stakes = db.epoch_stakes,
                    .epoch_schedule = bank.epoch_schedule,
                };
                // ── GOSSIP OBSERVATIONS (P0 root fix, wedge 421109451 2026-07-10) ──
                // Agave's switch proof counts max_gossip_frozen_votes — REAL-TIME
                // gossip votes — in ADDITION to landed votes (consensus.rs:1222).
                // The landed feed alone is structurally blind here: when our tower
                // is on a losing fork, every cluster voter's landed vote-state in
                // OUR banks is <= our own last vote (the landed feed lags the tip;
                // we vote AT the tip) → all filtered by the canonical strictly-
                // newer predicate → locked_out=0/325M observed live → no escape →
                // delinquency. Snapshot the CRDS tag-1 tracker (wired 2026-07-01,
                // always populated) under its LEAF lock; pre-filter to strictly-
                // newer entries so the copy stays tiny. OOM → partial/empty slice
                // (conservative: undercount only, never a false proof — exactly
                // the pre-fix behavior at worst).
                const PkVote = fc_mod.HeaviestSubtreeForkChoice.PubkeyVote;
                var glist = std.ArrayListUnmanaged(PkVote){};
                defer glist.deinit(self.allocator);
                {
                    self.gossip_votes_lock.lock();
                    defer self.gossip_votes_lock.unlock();
                    var git = self.latest_gossip_votes.map.iterator();
                    while (git.next()) |ge| {
                        if (ge.value_ptr.slot <= last_voted) continue; // strictly-newer pre-filter
                        glist.append(self.allocator, .{
                            .pubkey = .{ .data = ge.key_ptr.* },
                            .slot_hash = .{ .slot = ge.value_ptr.slot, .hash = .{ .data = ge.value_ptr.hash } },
                        }) catch break; // OOM → evaluate the partial snapshot
                    }
                }
                const gossip_obs: []const PkVote = glist.items;
                const dec = fc.checkSwitchThresholdGossip(last_voted, bank.slot, total_stake, stake_lookup, gossip_obs);
                const pct: f64 = if (total_stake > 0)
                    @as(f64, @floatFromInt(dec.locked_out_stake)) / @as(f64, @floatFromInt(total_stake)) * 100.0
                else
                    0.0;
                // `dec.same_fork`: GHOST flagged a different fork, but the Agave
                // SameFork test (candidate descends from our last vote) says same
                // fork → a lockout-clear no-proof vote is canonical (§3a). A valid
                // switch proof (`would_switch`) authorizes a genuine cross-fork vote.
                const authorize = dec.same_fork or dec.would_switch;
                // PER-VOTER BREAKDOWN (2026-07-17, wedge 422521275 / sibling-race
                // 422600922 follow-up — see switchProofVoterDiagEnabled doc above).
                // Opt-in (VEX_SWITCH_PROOF_VOTER_DIAG); this evaluation site is
                // already the rare cross-fork path (is_same_fork=false, legacy_ok
                // false), so the extra O(voters) walk here is not a hot-path
                // concern — it never runs on the common same-fork tick.
                if (self.switchProofVoterDiagEnabled()) {
                    var breakdown = fc_mod.HeaviestSubtreeForkChoice.SwitchThresholdBreakdown{};
                    fc.switchThresholdVoterBreakdown(last_voted, bank.slot, stake_lookup, gossip_obs, &breakdown);
                    for (breakdown.top[0..breakdown.top_len]) |c| {
                        std.log.warn(
                            "[SWITCH-PROOF-VOTER] pubkey_prefix={x:0>8} cand_slot={d} stake={d} source={s}",
                            .{ std.mem.readInt(u32, c.pubkey.data[0..4], .big), c.cand_slot, c.stake, @tagName(c.source) },
                        );
                    }
                    std.log.warn(
                        "[SWITCH-PROOF-BREAKDOWN] landed: seen={d} excl_root={d} excl_no_gca={d} counted={d} stake={d} | gossip: seen={d} excl_not_newer={d} excl_dup={d} excl_not_frozen={d} excl_no_gca={d} counted={d} stake={d}",
                        .{
                            breakdown.landed_seen,                breakdown.landed_excluded_root,   breakdown.landed_excluded_no_gca,    breakdown.landed_counted,
                            breakdown.landed_stake,               breakdown.gossip_seen,            breakdown.gossip_excluded_not_newer, breakdown.gossip_excluded_dup,
                            breakdown.gossip_excluded_not_frozen, breakdown.gossip_excluded_no_gca, breakdown.gossip_counted,            breakdown.gossip_stake,
                        },
                    );
                }
                switch (mode) {
                    // SHADOW: COMPUTE + log only — NEVER changes the vote decision.
                    .shadow => std.log.warn(
                        "[SWITCH-SHADOW] slot={d} last_vote={d} same_fork={} would_switch={} locked_out={d}/{d} ({d:.2}%) gossip_seen={d} gossip_cnt={d}/{d} — OBSERVE ONLY, vote unchanged",
                        .{ bank.slot, last_voted, dec.same_fork, dec.would_switch, dec.locked_out_stake, total_stake, pct, gossip_obs.len, dec.gossip_counted, dec.gossip_considered },
                    ),
                    // ARMED: act on the proof (only after shadow validation).
                    .armed => {
                        if (authorize) allow_vote = true;
                        std.log.warn(
                            "[SWITCH-PROOF] slot={d} last_vote={d} authorize={} (same_fork={} would_switch={}) locked_out={d}/{d} ({d:.2}%) thr=38% gossip_seen={d} gossip_cnt={d}/{d}",
                            .{ bank.slot, last_voted, authorize, dec.same_fork, dec.would_switch, dec.locked_out_stake, total_stake, pct, gossip_obs.len, dec.gossip_counted, dec.gossip_considered },
                        );
                    },
                    .off => unreachable,
                }
            }

            if (!allow_vote) {
                self.maybeRefreshLastVote(); // threshold/fork-safety no-cast: keep last vote alive
                return;
            }

            t.vote_state.recordVote(bank.slot);
            t.last_vote_slot = bank.slot;
            _ = VoteCensus.cast.fetchAdd(1, .monotonic); // vote-coverage census: an own vote was cast
            if (voted_via_fallback) _ = VoteCensus.fallback_cast.fetchAdd(1, .monotonic);
            // Advance accounts DB root when tower root advances
            if (t.vote_state.root_slot) |root| {
                if (self.accounts_db) |db| {
                    // Root-advance body extracted VERBATIM to doRootAdvance
                    // (#27, 2026-07-02) — SHARED with the offline force-root
                    // path (forceAdvanceRootTo). Edit THERE, never inline here.
                    // Returns prev_root; null = ancestry guard refused.
                    if (self.doRootAdvance(db, root, bank.slot, bank.parent_slot)) |prev_root| {

                        // PHASE 1 (2026-06-06): bound the live fork-choice tree to
                        // the rooted subtree. The tree is otherwise UNBOUNDED —
                        // setTreeRoot exists but was dead/uncalled, so fork_infos
                        // grows monotonically from boot. @prov:replay.fc-reroot-ordering
                        // we re-root AFTER db.advanceRoot + db.purgeRootedSlot.
                        //
                        // Gated default-OFF (VEX_FC_REROOT) for a dark deploy. The
                        // ONLY behavioral side effect when ON is that bestOverallSlot
                        // is then computed over the PRUNED subtree, which feeds the
                        // is_same_fork vote gate at ~3050 — see safety note below.
                        //
                        // Root-key source is load-bearing: derive it by walking
                        // fc.ancestorIterator from the just-voted bank's IN-TREE key
                        // down to the node at slot==root. NEVER self.banks.get(root)
                        // (consensus root lags freeze-tip → likely pruned → silent
                        // no-op → tree stays unbounded) and NEVER self.root_bank
                        // (freeze-tip = a different slot → wrong key). The bank key
                        // was inserted by addForkCompat (line 2761) in this same
                        // onSlotCompleted flow before submitVote (line 2979), and
                        // root is an ancestor of bank.slot by tower construction.
                        if (vex_store.recorder.fcReRootOn() and root > prev_root) {
                            if (self.fork_choice) |*fc| {
                                const ReRootDbg = struct {
                                    var fired: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                                    var skipped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                                };
                                const bank_key = fc_mod.SlotHashKey{ .slot = bank.slot, .hash = bank.bank_hash };
                                if (!fc.containsBlock(bank_key)) {
                                    const sk = ReRootDbg.skipped.fetchAdd(1, .monotonic) + 1;
                                    std.log.warn("[FC-REROOT] skip: voted bank not in tree slot={d} root={d} skipped={d}", .{ bank.slot, root, sk });
                                } else {
                                    // Walk ancestors to the node at slot==root.
                                    // ancestorIterator yields PARENT-first (never
                                    // self), so handle root==bank.slot explicitly.
                                    var root_key: ?fc_mod.SlotHashKey = if (bank.slot == root) bank_key else null;
                                    if (root_key == null) {
                                        var it = fc.ancestorIterator(bank_key);
                                        while (it.next()) |a| {
                                            if (a.slot == root) {
                                                root_key = a;
                                                break;
                                            }
                                            if (a.slot < root) break; // walked past — root not an ancestor
                                        }
                                    }
                                    if (root_key) |rk| {
                                        const before = fc.nodeCount();
                                        // setTreeRoot failure (OOM) MUST never
                                        // propagate into the replay loop — log + skip.
                                        if (fc.setTreeRoot(rk)) |_| {
                                            const fr = ReRootDbg.fired.fetchAdd(1, .monotonic) + 1;
                                            std.log.warn("[FC-REROOT] re-rooted root={d} prev={d} nodes {d}->{d} fired={d}", .{ root, prev_root, before, fc.nodeCount(), fr });
                                        } else |e| {
                                            std.log.warn("[FC-REROOT] setTreeRoot failed root={d} err={any}", .{ root, e });
                                        }
                                    } else {
                                        // root not yet an ancestor of bank.slot —
                                        // defer one advance (safe: tree stays one
                                        // re-root larger, retried next root advance).
                                        const sk = ReRootDbg.skipped.fetchAdd(1, .monotonic) + 1;
                                        std.log.warn("[FC-REROOT] skip: root not an ancestor of voted bank root={d} bank_slot={d} skipped={d}", .{ root, bank.slot, sk });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Persist tower state after every vote — except in OFFLINE REPLAY
            // (VEX_LEDGER_REPLAY): the save would land in the shared cwd and
            // contaminate the NEXT leg's tower (see hermeticity note at the
            // load site in init).
            if (std.posix.getenv("VEX_LEDGER_REPLAY") == null) {
                t.saveToDisk("tower-state.bin") catch |err| {
                    std.log.debug("[TOWER] Save failed: {any}\n", .{err});
                };
            }
        }

        // Build CompactTowerSync (instruction 16) with full tower state
        var builder = vex_consensus.vote_tx.VoteTransactionBuilder.init(
            self.allocator,
            self.identity,
            .{ .data = vote_acct.data },
        );
        builder.setIdentitySecret(secret);

        const tower_state = if (self.tower) |*t| &t.vote_state else null;

        // Use cached poh_hash as tx envelope blockhash. @prov:replay.cached-blockhash-poh
        // poh_hash is PoH-deterministic from entry data — not account-state-dependent.
        // Falls back to curl only on bootstrap (before first freeze).
        // Council ruling: 14/14 unanimous approval (2026-04-14).
        const tx_blockhash = self.cached_blockhash orelse self.getRecentBlockhash();

        // Use network's bank hash for the vote (curl #2 — still needed).
        // P1 removal caused votes to stop landing after ~1200 slots due to hash drift.
        // getNetworkBankHash returns null most of the time but occasionally corrects drift.
        // TODO: Fix C after sustained 1000+ slots of 100% native parity.
        // NOTE: keep CALLING getNetworkBankHash unconditionally — it has a load-bearing
        // side effect (installs/refreshes the cluster SlotHashes cache that markSlotDead's
        // PR-5ah canonical-match guard consults). The VEX_DISABLE_NETHASH experiment only
        // suppresses USING its result for the vote `hash` field, so we vote purely on our
        // own locally-computed bank_hash (removes the net_hash bandaid). Env unset =
        // byte-identical to prior behavior. Reversible by restart without the env.
        const net_hash = self.getNetworkBankHash(bank.slot);
        // net_hash band-aid toggle — VALUE-based (operator directive 2026-06-14:
        // keep the mechanism but leave it in the OFF position, and make the switch
        // PREDICTABLE). "0" => band-aid ON (vote the cluster's RPC-fetched bank_hash);
        // anything else, or unset => OFF (vote our own locally-computed bank_hash).
        // Default (unset) = OFF. NOTE the prior `!= null` PRESENCE check meant
        // exporting the var as "0" (deploy.sh does) silently DISABLED the band-aid,
        // so a "flip back to 0 to re-enable" was a no-op. Value-based makes 0 actually
        // turn it ON, matching the comment + a deploy.sh default of 1 (OFF).
        const disable_nethash = if (std.posix.getenv("VEX_DISABLE_NETHASH")) |v|
            !std.mem.eql(u8, v, "0")
        else
            true;
        const use_net = !disable_nethash and net_hash != null;
        const vote_hash = if (use_net) net_hash.? else core.Hash{ .data = bank.bank_hash.data };
        // VOTE-REFRESH: cache the hash ACTUALLY emitted so a later refresh re-sends the identical
        // tower body (different bank_hash field would be a different vote). Cast path only.
        self.last_voted_bank_hash = vote_hash;
        self.last_cast_time_ms = std.time.milliTimestamp(); // mark a fresh cast → suppress refresh for 5s

        var tx = if (tower_state) |ts|
            try builder.buildTowerSync(
                ts,
                vote_hash,
                tx_blockhash,
                null, // block_id — will wire from shred merkle root later
            )
        else blk: {
            // Fallback to legacy if no tower (shouldn't happen in practice)
            const VoteType = vex_consensus.vote.Vote;
            const v = VoteType{
                .slot = bank.slot,
                .hash = .{ .data = bank.bank_hash.data },
                .timestamp = @intCast(std.time.timestamp()),
                .signature = .{ .data = [_]u8{0} ** 64 },
            };
            const votes = [_]VoteType{v};
            break :blk try builder.buildVoteTransaction(&votes, tx_blockhash);
        };
        defer tx.deinit();

        const serialized = try builder.signAndSerialize(&tx);

        // Enqueue for async send if vote sender thread is wired.
        // Ownership transfers to queue -- sender thread frees after send.
        var enqueued = false;
        if (self.vote_send_queue) |q| {
            enqueued = q.push(serialized);
        }

        if (!enqueued) {
            // Fallback: inline send + free (queue not wired or full)
            defer self.allocator.free(serialized);
            if (self.sendVoteFn) |sendFn| {
                sendFn(serialized);
            }
        }

        // Log periodically
        const VoteDbgSubmit = struct {
            var count: u64 = 0;
        };
        VoteDbgSubmit.count += 1;
        if (VoteDbgSubmit.count <= 5 or VoteDbgSubmit.count % 100 == 0) {
            const lockout_depth: usize = if (self.tower) |*t| t.vote_state.len else 0;
            const root = if (self.tower) |*t| t.vote_state.root_slot else null;
            std.log.debug("[VOTE-SUBMIT] slot={d} hash={x:0>8}.. tower_depth={d} root={?d} sent={s} [#{d}]\n", .{
                bank.slot,
                std.mem.readInt(u32, bank.bank_hash.data[0..4], .big),
                lockout_depth,
                root,
                if (self.sendVoteFn != null) "YES" else "BUILD-ONLY",
                VoteDbgSubmit.count,
            });
        }
    }

    // ── Bank management ───────────────────────────────────────────────────────

    /// d27f Bank pool — pop a recycled bank or fall back to allocator.create.
    /// replayWorker is sole caller per d17 invariant; no lock needed.
    fn acquireBank(
        self: *Self,
        slot: Slot,
        parent_slot: ?u64,
        parent_hash: vex_crypto.Hash,
        parent_lthash: vex_crypto.LtHash,
        parent_poh_hash: vex_crypto.Hash,
    ) !*Bank {
        if (self.bank_pool.pop()) |bank| {
            bank.reset(slot, parent_slot, parent_hash, parent_lthash, parent_poh_hash);
            // verify_ticks: stamp the manifest PoH cadence onto the recycled bank
            // (reset() cleared it to defaults). Comptime-gated so the default
            // (.off) build does not codegen this and stays byte-identical.
            if (comptime build_options.verify_ticks != .off) {
                bank.hashes_per_tick = self.poh_hashes_per_tick;
                bank.ticks_per_slot = self.poh_ticks_per_slot;
            }
            return bank;
        }
        const bank = try Bank.init(self.allocator, slot, parent_slot, parent_hash, parent_lthash, parent_poh_hash);
        if (comptime build_options.verify_ticks != .off) {
            bank.hashes_per_tick = self.poh_hashes_per_tick;
            bank.ticks_per_slot = self.poh_ticks_per_slot;
        }
        return bank;
    }

    /// d27f Bank pool — return a bank to the freelist for reuse. Performs
    /// the same per-slot cleanup `bank.deinit()` does for owned resources
    /// (pending_writes + stake_reward_partitions), but keeps the heap
    /// allocation for the Bank struct itself.
    const BANK_POOL_CAP: usize = 1024;
    fn releaseBank(self: *Self, bank: *Bank) void {
        bank.pending_writes.deinit(bank.allocator);
        bank.freeStakeRewardPartitions();
        if (self.bank_pool.items.len < BANK_POOL_CAP) {
            self.bank_pool.append(self.allocator, bank) catch {
                bank.allocator.destroy(bank);
            };
        } else {
            bank.allocator.destroy(bank);
        }
    }

    /// PR-5av Phase 2 (2026-05-22): mint a sentinel bank for a slot whose
    /// parent isn't yet known. @prov:replay.sentinel-bank-fd-forest A sentinel:
    ///   - has `parent_slot = null` (the marker for "not yet linked")
    ///   - has `block_id` set to the cluster-confirmed canonical id
    ///   - has `block_id_source = .cluster_tower_confirmed`
    ///   - is inserted into both `banks` (so lookups find it) AND
    ///     `subtrees` (so iterators can find it as an orphan-subtree head)
    ///   - is NOT frozen and NOT chain_confirmed yet — replay can't
    ///     touch it until shreds arrive and Phase 4's parent-promotion
    ///     wires it into the main fork tree.
    ///
    /// Gated by `build_options.sentinel_node` (default OFF). When the
    /// flag is off, returns `error.SentinelDisabled` — callers MUST fall
    /// back to the existing UnconnectedSlot defer path.
    ///
    /// `block_id` is optional (PR-5av Phase 2.1 advisor revision): the
    /// shred-driven creation path (Phase 3/4) usually doesn't have a
    /// cluster-canonical block_id yet — that comes later from either the
    /// shred assembler's chained merkle root or a tower-confirm signal.
    /// When null, the bank's block_id is zero-initialised and source is
    /// .none; callers MAY mutate bank.block_id later if they acquire one.
    /// When non-null, source is set to .cluster_tower_confirmed
    /// (caller's contract: they have a real cluster signal).
    ///
    /// Lock discipline: takes `banks_lock` (write) and `subtrees_lock`
    /// internally. Caller must NOT hold either lock when calling.
    ///
    /// Explicit error set so callers can switch cleanly regardless of
    /// whether `build_options.sentinel_node` short-circuits the body.
    const SentinelError = error{
        SentinelDisabled,
        SlotAlreadyExists,
        OutOfMemory,
    };
    fn createSentinelBank(self: *Self, slot: Slot, block_id: ?[32]u8) SentinelError!*Bank {
        if (!build_options.sentinel_node) return error.SentinelDisabled;

        // Refuse to mint a sentinel for a slot we already track. The
        // existing entry may be a real bank with shred state we'd lose.
        {
            self.banks_lock.lockShared();
            defer self.banks_lock.unlockShared();
            if (self.banks.contains(slot)) return error.SlotAlreadyExists;
        }

        // Identity LtHash (zero accumulator) — placeholder until shreds
        // arrive and we can fold the real account writes in. @prov:replay.sentinel-bank-fd-forest
        // — these fields remain "unknown" until parent resolution.
        const bank = try self.acquireBank(
            slot,
            null, // parent_slot = null → sentinel marker
            vex_crypto.Hash.default(),
            vex_crypto.LtHash.init(),
            vex_crypto.Hash.default(),
        );
        bank.accounts_db = self.accounts_db;
        bank.is_sentinel = true;
        const bid = block_id orelse [_]u8{0} ** 32;
        bank.block_id = bid;
        bank.block_id_source = if (block_id != null) .cluster_tower_confirmed else .none;

        // Lock order: banks_lock BEFORE subtrees_lock (per the struct
        // field doc convention).
        self.banks_lock.lock();
        self.banks.put(slot, bank) catch |err| {
            self.banks_lock.unlock();
            self.releaseBank(bank);
            return err;
        };
        self.banks_lock.unlock();

        // FIX #105: record the durable slot→parent link (survives bank pruning) so
        // the root-advance ancestry walk never breaks mid-catch-up. Sentinel banks
        // (parent_slot == null) carry no link and are skipped.
        if (bank.parent_slot) |ps| {
            if (self.accounts_db) |db| db.recordSlotParent(slot, ps);
        }

        self.subtrees_lock.lock();
        self.subtrees.put(slot, bank) catch |err| {
            self.subtrees_lock.unlock();
            // Roll back the banks.put — leave releaseBank to Phase 6's
            // markSlotDead path or to deinit.
            self.banks_lock.lock();
            _ = self.banks.remove(slot);
            self.banks_lock.unlock();
            self.releaseBank(bank);
            return err;
        };
        self.subtrees_lock.unlock();

        std.log.warn(
            "[SENTINEL-CREATE] slot={d} block_id={x}{x}{x}{x}{x}{x}{x}{x}.. source={s}",
            .{ slot, bid[0], bid[1], bid[2], bid[3], bid[4], bid[5], bid[6], bid[7], @tagName(bank.block_id_source) },
        );
        return bank;
    }

    fn getOrCreateBank(self: *Self, slot: Slot) !*Bank {
        const goc_t0 = std.time.milliTimestamp();
        // Fast path under shared lock
        {
            self.banks_lock.lockShared();
            defer self.banks_lock.unlockShared();
            if (self.banks.get(slot)) |existing| {
                // PR-5av Phase 3/4: skip sentinels in fast path. A sentinel
                // has parent_slot=null and identity LtHash — returning it
                // here would short-circuit normal bank creation and feed
                // corrupted state into replay. Slow path tears the sentinel
                // down and constructs a real bank in its place.
                if (!existing.is_sentinel) return existing;
            }
        }
        const goc_t1 = std.time.milliTimestamp();

        // PR-5av Phase 3/4: tear down any sentinel for this slot BEFORE
        // entering the slow-path construction. The sentinel was minted
        // during shred-defer when parent was unconnected; now that we have
        // a chance to build a real bank, the placeholder must vacate.
        if (build_options.sentinel_node) {
            self.banks_lock.lock();
            const sentinel_to_release: ?*Bank = blk: {
                if (self.banks.get(slot)) |existing| {
                    if (existing.is_sentinel) {
                        _ = self.banks.remove(slot);
                        break :blk existing;
                    }
                }
                break :blk null;
            };
            self.banks_lock.unlock();
            if (sentinel_to_release) |bank| {
                self.subtrees_lock.lock();
                _ = self.subtrees.remove(slot);
                self.subtrees_lock.unlock();
                std.log.warn("[SENTINEL-PROMOTE] slot={d} torn down sentinel — building real bank", .{slot});
                self.releaseBank(bank);
            }
        }

        const root_bank_ptr = self.root_bank.load(.acquire) orelse return error.NoRootBank;

        // r44 fix (2026-04-27): authoritative parent_slot from shred wire-format.
        // Pre-r44, this function walked backward from slot-1 accepting ANY bank in self.banks,
        // with no frozen-check and no "parent must exist" guard. When slot N entered before
        // slot N-1's bank was added to self.banks (race in repair-replay / parallel paths),
        // the search silently fell back to N-2 → wrong parent baked in for slot N's lifetime.
        // 4.2% of repair-replay slots and 1.8% of non-repair slots triggered this; each event
        // inflated cap by ~+1.4M lamports and corrupted accounts_lt_hash. r43 located in
        // vault/sessions/2026-04-27-r43-anomaly-discriminator.md.
        // d22c (2026-05-11): target_parent sources, in priority order:
        //   1. catchup_parent_override (threadlocal) — from RPC getBlock.parentSlot,
        //      authoritative (cluster's own view of who its parent is).
        //   2. shred_assembler.getParentSlot — from shred wire-format,
        //      authoritative (leader's own signed parent_offset).
        //   3. Default slot-1 — INFERRED (used when neither above is available;
        //      e.g. very old paths where shred_assembler isn't wired).
        // The authoritative cases (1 + 2) require strict ancestor match.
        // The inferred case still requires strict match since we have no
        // signal that skipping is happening (worse to bake wrong parent than
        // to defer; defer + repair will eventually surface the right parent
        // via the assembler).
        const target_parent: u64 = blk: {
            if (catchup_parent_override) |p| break :blk p;
            if (self.shred_assembler) |sa| {
                if (sa.getParentSlot(slot)) |p| break :blk p;
            }
            break :blk if (slot > 0) slot - 1 else 0;
        };
        const goc_t2 = std.time.milliTimestamp();

        // d27 (2026-05-11): single-shot parent-frozen check, no wait loop.
        //
        // Pre-d27 this loop waited up to 200ms (100 × 2ms spin-sleeps) for
        // banks[target_parent] to become frozen. That window was justified
        // in the pre-d17 era when onSlotCompleted was called concurrently
        // from N TVU threads + replayWorker — a race could have target_parent
        // be in-flight on another thread. Post-d17 (MPSC SlotQueue) +
        // post-d24 (catchup also queue-routed), replayWorker is the SOLE
        // onSlotCompleted caller. Therefore target_parent is either:
        //   (a) already frozen in self.banks (sequential prior pop), OR
        //   (b) not in self.banks at all (gap; needs catchup/repair)
        // Waiting 200ms accomplishes nothing in case (b) and was empirically
        // burning ~200ms PER CHAIN-RESOLVE SLOT — measured via [SLOT-PROFILE]
        // showing total_ms=240 with replay_ms=20 + freeze_ms=8 → 212ms
        // bank_create_ms. Removing the wait cuts per-slot wall-clock from
        // ~240ms p50 to ~40ms p50, lifting replayWorker drain capacity from
        // ~4 slots/sec to ~25 slots/sec — well above cluster's 2.5 slots/sec.
        var ancestor: *Bank = root_bank_ptr;
        // Consensus root (monotonic tower root = db.rooted_slot), NOT the
        // freeze-tip (root_bank.slot, advanced on every freeze). The parent
        // root-fallback keys on THIS — see pending_wake.resolveParent and the
        // 413389395 wrong-parent carrier. 0 when accounts_db unwired / pre-root.
        const consensus_root: u64 = if (self.accounts_db) |db| db.rooted_slot else 0;
        var parent_frozen = false;
        {
            self.banks_lock.lockShared();
            const found = self.banks.get(target_parent);
            if (found) |b| {
                if (b.is_frozen) {
                    ancestor = b;
                    parent_frozen = true;
                }
            }
            self.banks_lock.unlockShared();
        }
        const goc_t3 = std.time.milliTimestamp();

        // d27 (2026-05-11): backward-walk fallback removed. d21's strict
        // chain-connectivity check below requires `ancestor.slot ==
        // target_parent` EXACTLY for the CONNECTED branch; any backward-walk
        // result with ancestor.slot < target_parent falls through to
        // `error.UnconnectedSlot`. So the walk's result is discarded —
        // pure overhead. For unconnected slots, eliminating the walk
        // saves ~slot_distance × lock_acquire_us per defer (empirically
        // ~150-200ms per slot when target_parent is hundreds of slots
        // ahead of root_bank). The `target_parent <= root_bank_ptr.slot`
        // boundary case below still uses root_bank directly, no walk
        // needed.

        // r45-A probe (2026-04-27). @prov:replay.sig-structural-invariant-probe
        // We retrofit as logged + counted (NOT crash) until we know the firing rate. If the residual
        // 1.9% wrong-parent + bootstrap-RBH-unseeded + dedup-bug carriers fire here, this surfaces them.
        // Slot/parent/category are emitted so we can correlate with oracle-node bank-frozen logs.

        // d21 (2026-05-11) — chain-connectivity check. @prov:replay.chain-connectivity-defer
        // ReplayStage only iterates `bank_forks.active_bank_slots()` — slots
        // whose parent is already in the bank tree. New banks aren't created
        // until their parent exists. We port that semantic: REFUSE to create
        // bank if no frozen ancestor at target_parent specifically. Caller
        // (onSlotCompleted) catches error.UnconnectedSlot and DEFERS the slot
        // in pending_chain until parent arrives via repair (checkPendingChain).
        // Without this, the fallback to root_bank_ptr baked in wrong
        // parent_bank_hash → permanent chain divergence from gov on every
        // bootstrap-to-tip transition or repair gap.
        // Parent-ancestor decision — UNIT-PROVEN in pending_wake.resolveParent
        // (CALL it, never duplicate, so production and the test cannot drift).
        // 2026-06-05 FIX (carrier slot 413389395 — wrong-parent at catch-up→tip):
        // the root-fallback now keys on the monotonic CONSENSUS root, not the
        // freeze-tip (self.root_bank.slot, advanced on every freeze). The old
        // `target_parent <= root_bank.slot` let an orphan sibling that froze
        // first masquerade as "root": cluster canonical chain 392→393→395 (394
        // SKIPPED); Vexor built orphan 394 (froze first → freeze-tip=394); 395's
        // true parent 393 satisfied `393 <= 394` → 395 was built on the orphan
        // → wrong SlotHashes → all votes (for 393) rejected → vote-account writes
        // dropped from accounts_lt_hash → bank_hash divergence → delinquency.
        // Now 393 (above consensus root, below freeze-tip, unfrozen) DEFERS, and
        // CHAIN-WAKE links 395→393 once 393 freezes on its real parent 392. Same
        // principle FIX#112 applied to the drop + fast-wake paths; this completes
        // it for getOrCreateBank's resolve + the freeze-sweep wake (line ~2012).
        switch (pending_wake.resolveParent(
            target_parent,
            parent_frozen,
            root_bank_ptr.slot,
            root_bank_ptr.is_frozen,
            consensus_root,
            slot,
        )) {
            .connected => {
                // ancestor is banks[target_parent] when parent_frozen; otherwise
                // the (always-frozen) freeze-tip boundary (target_parent==root.slot).
                if (!parent_frozen) ancestor = root_bank_ptr;
            },
            .use_root_fallback => ancestor = root_bank_ptr,
            .defer_unconnected => {
                // onSlotCompleted catches error.UnconnectedSlot and defers into
                // pending_chain (d21: @prov:replay.chain-connectivity-defer). Covers both the gap case and
                // the d28mm "root raced past slot" case.
                const gap = if (slot > root_bank_ptr.slot + 1) slot - root_bank_ptr.slot - 1 else 0;
                std.log.warn(
                    "[CHAIN-GAP] slot={d} target_parent={d} root.slot={d} consensus_root={d} gap={d} → DEFER (canonical parent not yet replayable)",
                    .{ slot, target_parent, root_bank_ptr.slot, consensus_root, gap },
                );
                return error.UnconnectedSlot;
            },
        }

        const goc_t4 = std.time.milliTimestamp();
        // d27f: pull from bank pool (or fallback-allocate). Avoids per-slot
        // ~200ms allocator.create(Bank) cost observed via [BANK-INIT-SLOW].
        const bank = try self.acquireBank(slot, ancestor.slot, ancestor.bank_hash, ancestor.accounts_lthash, ancestor.poh_hash);
        const goc_t4b = std.time.milliTimestamp();
        bank.accounts_db = self.accounts_db;
        const goc_t5 = std.time.milliTimestamp();

        // BUG-5 fix: inherit all fields from ancestor that must persist across slots.
        // Without this, non-root banks have capitalization=0 and epoch_rewards_active=false,
        // causing near-zero inflation rewards and distributePartitionedRewards() no-ops.
        bank.capitalization = ancestor.capitalization;
        bank.block_height = ancestor.block_height + 1;
        bank.epoch_schedule = ancestor.epoch_schedule;

        // Partitioned reward state (spans multiple slots during distribution window)
        bank.epoch_rewards_active = ancestor.epoch_rewards_active;
        bank.stake_reward_partitions = ancestor.stake_reward_partitions;
        // Note: child does NOT own the partitions — only the epoch-boundary bank owns them.
        bank.owns_stake_reward_partitions = false;
        bank.distribution_starting_block_height = ancestor.distribution_starting_block_height;
        bank.num_reward_partitions = ancestor.num_reward_partitions;

        // r38 fix (helm-fresh 2026-04-27): inherit RecentBlockhashes queue. Pre-r38 the
        // queue was reset to .{} empty per Bank.init (bank.zig:423), so each
        // updateRecentBlockhashes call pushed 1 entry → count=1 forever instead of the
        // canonical rolling 150-entry window. This caused ~6008 bytes/slot of RBH sysvar
        // byte-divergence vs Agave (prior forensics narrowed: coverage perfect +
        // algorithm parity → carrier had to be sysvar bytes; r37-diag probed all 5
        // per-slot sysvars and confirmed RBH was the dominant carrier). RBH queue
        // is plain-old-data (BoundedArray of [150]BlockhashEntry + len), so a value-copy
        // is safe — no allocation tracking. After ~150 slots of catchup advance, Vexor's
        // queue self-fills to count=150 from this inheritance.
        bank.recent_blockhashes = ancestor.recent_blockhashes;
        // CONSENSUS-CRITICAL (epoch-979 tip carrier): derive THIS slot's fee-rate
        // governor from the PARENT's governor + the PARENT's accumulated
        // signature_count. @prov:replay.fee-rate-governor-derive The derived
        // `fee_rate_governor.lamports_per_signature` is what gets written into
        // the RecentBlockhashes sysvar at freeze (bank.zig updateRecentBlockhashes),
        // replacing the old hardcoded 5000 that diverged at the slot-848 spike.
        // Carried/derived here — adjacent to the recent_blockhashes inheritance —
        // because the FULL parent bank (needed for ancestor.signature_count) is
        // in scope only at this site; acquireBank receives scalars only.
        bank.fee_rate_governor = @import("blockhash_queue.zig").FeeRateGovernor.newDerived(
            ancestor.fee_rate_governor,
            ancestor.signature_count,
        );
        bank.total_stake_rewards = ancestor.total_stake_rewards;
        bank.distributed_rewards = ancestor.distributed_rewards;
        bank.vote_rewards_distributed = ancestor.vote_rewards_distributed;
        bank.epoch_reward_parent_blockhash = ancestor.epoch_reward_parent_blockhash;
        bank.epoch_reward_total_points = ancestor.epoch_reward_total_points;
        // RESIDUAL FIX (2026-07-02, epoch-983 gate 0/15 @419132257): this field
        // was the ONLY sysvar input missing from this inherit list. Every child
        // bank's updateEpochRewardsDistributed/deactivateEpochRewardsSysvar
        // rebuilt the EpochRewards sysvar with total_rewards=0 (field default)
        // → one 8-byte diff vs cluster in EVERY distribution-window slot →
        // wrong lt_hash → wrong bank_hash. Byte-proven: lt(sysvar bytes with
        // total_rewards=0 + the CORRECT distributed accumulation) == the
        // recorded op=1 lt-contrib at 419132257 EXACTLY.
        bank.epoch_reward_total_rewards = ancestor.epoch_reward_total_rewards;

        // CARRIER #7 FIX (2026-06-23): build the COMPLETE inherited proper-ancestor
        // set (Agave bank.rs:1420-1425 parity: child.ancestors = {parent.slot} ∪
        // parent.proper_ancestors, filtered > rooted_slot). The tower lockout check
        // consumes this complete set instead of the gap-fragile
        // `ancestorChainComplete` walk, which truncated at a live sentinel bank
        // (parent_slot=null) → false cross-fork lockout → delinquency. `ancestor`
        // here is ALWAYS a frozen real bank or the root bank (the .defer_unconnected
        // arm returned error.UnconnectedSlot above), so the set is built only from
        // verified true ancestors — it can never invent a false ancestor (carrier-7
        // safety preserved by construction). On overflow (>512 unrooted depth, deep
        // catch-up where we don't vote) the vote site falls back to the legacy walk.
        {
            const proot: u64 = if (self.accounts_db) |db| db.rooted_slot else 0;
            const cap: u16 = bank.proper_ancestors.len;
            var pa_n: u16 = 0;
            var pa_overflow: bool = ancestor.proper_ancestors_overflow;
            if (ancestor.slot > proot) {
                if (pa_n < cap) {
                    bank.proper_ancestors[pa_n] = ancestor.slot;
                    pa_n += 1;
                } else pa_overflow = true;
            }
            for (ancestor.proper_ancestors[0..ancestor.proper_ancestors_len]) |a| {
                if (a > proot) {
                    if (pa_n < cap) {
                        bank.proper_ancestors[pa_n] = a;
                        pa_n += 1;
                    } else {
                        pa_overflow = true;
                        break;
                    }
                }
            }
            bank.proper_ancestors_len = pa_n;
            bank.proper_ancestors_overflow = pa_overflow;
        }

        const goc_t6 = std.time.milliTimestamp();
        self.banks_lock.lock();
        const goc_t7 = std.time.milliTimestamp();
        defer self.banks_lock.unlock();
        try self.banks.put(slot, bank);
        // FIX #105: durable slot→parent link (see recordSlotParent).
        if (bank.parent_slot) |ps| {
            if (self.accounts_db) |db| db.recordSlotParent(slot, ps);
        }
        const goc_t8 = std.time.milliTimestamp();

        // d27c-debug stage probe — fires when GOC takes >50ms (matches GOC-SLOW threshold)
        const goc_total = goc_t8 - goc_t0;
        if (goc_total > 50 and (self.stats.slots_replayed.load(.monotonic) <= 30 or self.stats.slots_replayed.load(.monotonic) % 100 == 0)) {
            std.log.warn(
                "[GOC-STAGE] slot={d} total={d}ms fast={d} target={d} pcheck={d} t34={d} bankinit={d} adb={d} t56={d} acq={d} put={d}",
                .{
                    slot,
                    goc_total,
                    goc_t1 - goc_t0, // fast-path lookup
                    goc_t2 - goc_t1, // target_parent resolution (incl getParentSlot)
                    goc_t3 - goc_t2, // parent-check shared lock
                    goc_t4 - goc_t3, // probe + chain-connectivity branch
                    goc_t4b - goc_t4, // Bank.init pure (allocator.create + struct literal)
                    goc_t5 - goc_t4b, // bank.accounts_db assignment
                    goc_t6 - goc_t5, // field inheritance assignments
                    goc_t7 - goc_t6, // banks_lock.lock acquire wall-clock
                    goc_t8 - goc_t7, // banks.put
                },
            );
        }

        return bank;
    }

    // ── Entry replay ──────────────────────────────────────────────────────────

    /// Replay all entries in `data` into `bank`.
    fn replayEntries(self: *Self, bank: *Bank, data: []const u8) !void {
        // STAGING/KAT one-shot: capture a real slot's deshredded entry buffer for the
        // entry.zig integration KAT (chain nextHash → blockhash; serialize→real-parser).
        // Gated by VEX_DUMP_ENTRY=1; dumps the first tx-bearing slot (len>=3000) ONCE.
        // Zero effect on consensus — read-only copy of `data` to /tmp. Diagnostic only.
        if (data.len >= 3000 and std.posix.getenv("VEX_DUMP_ENTRY") != null) {
            if (entry_dump_armed.cmpxchgStrong(true, false, .seq_cst, .seq_cst) == null) {
                var path_buf: [128]u8 = undefined;
                const path = std.fmt.bufPrint(&path_buf, "/tmp/vex_entry_{d}.bin", .{bank.slot}) catch "vex_entry.bin";
                if (std.fs.cwd().createFile(path, .{})) |f| {
                    defer f.close();
                    f.writeAll(data) catch {};
                } else |_| {}
                // Sidecar: the component boundaries (byte offsets) the replay parser uses to frame
                // each bincode Vec<Entry>, so the offline KAT harness frames identically. u64 LE each.
                var bnd_buf: [128]u8 = undefined;
                const bnd_path = std.fmt.bufPrint(&bnd_buf, "/tmp/vex_entry_{d}.bnd", .{bank.slot}) catch "vex_entry.bnd";
                if (std.fs.cwd().createFile(bnd_path, .{})) |bf| {
                    defer bf.close();
                    for (component_boundaries_override) |b| {
                        var tmp: [8]u8 = undefined;
                        std.mem.writeInt(u64, &tmp, @intCast(b), .little);
                        bf.writeAll(&tmp) catch {};
                    }
                } else |_| {}
                std.log.warn("[ENTRY-DUMP] slot={d} len={d} boundaries={d} -> {s} (parent_slot={d})", .{ bank.slot, data.len, component_boundaries_override.len, path, bank.parent_slot orelse 0 });
            }
        }
        self.replayEntriesInternal(bank, data) catch |err| {
            std.log.err("[REPLAY] Failed to replay slot {d}: {s} (data_len={d})", .{
                bank.slot, @errorName(err), data.len,
            });

            // Dump failed slot data for offline analysis
            var path_buf: [128]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "/tmp/vex_slot_{d}_fail.bin", .{bank.slot}) catch "failed_slot.bin";
            const file = std.fs.cwd().createFile(path, .{}) catch |e| blk: {
                std.log.err("[REPLAY] Failed to create dump file: {any}", .{e});
                break :blk null;
            };
            if (file) |f| {
                defer f.close();
                f.writeAll(data) catch {};
                std.log.err("[REPLAY] Dumped failed slot data to {s}", .{path});
            }

            // incident-422359406 follow-up (2026-07-16): also dump the raw
            // per-shred records with FEC-recovery provenance + the component
            // boundaries this replay used — the post-assembly buffer above
            // tells you WHAT the parser saw; this tells you WHICH shreds
            // produced it and whether any were FEC-recovered. Closes the
            // "our corrupted raw shred set was never preserved" gap from
            // this incident's own postmortem. Best-effort / non-blocking —
            // dumpSlotShredsWithProvenance swallows its own I/O errors and
            // never affects the `return err` below either way.
            if (self.shred_assembler) |sa| {
                sa.dumpSlotShredsWithProvenance(bank.slot, component_boundaries_override);
            }

            return err;
        };

        // SB-2 (2026-06-17) + Q2 (2026-06-25): persist this slot's captured transactions into the RPC
        // history stores AND the VexLedger content CFs. COMPTIME-gated → with both -Drpc_store and
        // -Dvex_ledger OFF nothing here is codegen'd (consensus path byte-identical). poh_hash is set by
        // now (last entry). OFF-consensus: only reads bank + writes the standalone RPC/VexLedger stores.
        //
        // OWNERSHIP of `bank.rpc_tx_capture` free/clear (critical — capture now fires for the vex_ledger
        // content path too, so SOMEONE must always drain it or it leaks + grows across slots):
        //   - flushVexLedgerContent reads the capture (block order) → VexLedger; it does NOT free.
        //   - flushRpcStore frees+clears when rpc_block_store != null (the existing SB-2 owner).
        //   - else (vex_ledger-only / rpc_block_store null) the explicit drain below owns the free.
        if (comptime build_options.rpc_store or build_options.vex_ledger) {
            if (comptime build_options.vex_ledger) self.flushVexLedgerContent(bank);
            const rpc_owns_free = (comptime build_options.rpc_store) and self.rpc_block_store != null;
            if (comptime build_options.rpc_store) self.flushRpcStore(bank);
            if (!rpc_owns_free) {
                for (bank.rpc_tx_capture.items) |c| {
                    self.allocator.free(c.wire);
                    if (c.account_keys.len != 0) self.allocator.free(c.account_keys);
                    if (c.pre_balances.len != 0) self.allocator.free(c.pre_balances);
                    if (c.post_balances.len != 0) self.allocator.free(c.post_balances);
                }
                bank.rpc_tx_capture.clearRetainingCapacity();
            }
        }
    }

    /// Stage B B2c — execute ONE transaction's instructions (the per-tx body extracted
    /// from the DAG Phase-2 drain so BOTH the serial drain AND a wave worker can run it).
    /// Does the precompile check, the per-instruction native/BPF dispatch, and per-tx
    /// rollback. Does NOT touch the cost gate — the caller sequences
    /// estimate/recordTransactionCost on the MAIN thread (seam #7: block_compute_units is
    /// single-threaded). Writes land via `bank.collectWrite`, which routes to the
    /// thread-local `worker_writes_override` (worker buffer) when set, else
    /// `bank.pending_writes`. Per-tx rollback truncates whichever sink is active
    /// (rollbackFailedTxSink). `arena` is the active scratch allocator (worker arena in
    /// the wave path, batch_arena in the serial path) — also where executors allocate
    /// AccountWrite.data payloads (they survive to the per-call flush, NOT bank.allocator).
    ///
    /// SERIAL CALLER (override==null): byte-identical to the pre-B2c inline body EXCEPT
    /// the per-program `native_*` diagnostic counters (write-only/never-read — dropped to
    /// keep this function thread-safe; the serial non-DAG branch still maintains its own).
    /// WAVE CALLER: only ELIGIBLE (all-native) txs reach here on a worker; the BPF/loader/
    /// ZK branches (which touch the recorder threadlocals) are reached ONLY by INELIGIBLE
    /// txs, which run on the main thread — so the recorder is never touched concurrently.
    fn executeDagTx(
        self: *Self,
        bank: *Bank,
        db: *AccountsDb,
        arena: std.mem.Allocator,
        ancestor_slots: []const u64,
        ptx: *const ParsedTx,
        info_idx: usize,
        info: *const DagTxInfo,
    ) void {
        // ── FEE UNIT (2026-07-09, Stage 1 fees-in-execution) ──────────────────
        // Per-tx fee validation + debit, moved out of DAG Phase-1 into this
        // DAG-ordered execution unit so each tx's fee sees the running balance of
        // every earlier tx. @prov:replay.fee-unit-sequential-order The
        // fee payer is a declared writable key ⇒ the conflict DAG serializes
        // fee-payer dependencies in block order, so this runs in exactly Agave's
        // order. Runs BEFORE tx_mark (below) so the fee debit sits below the
        // rollback mark — a fees-only failed tx KEEPS its fee (RollbackAccounts::
        // fee_payer) — and BEFORE verifyTxPrecompiles so a precompile-fail tx
        // still pays (mirrors the old Phase-1-debits-all-then-Phase-2-executes
        // model). Counters are ATOMIC: wave workers run this unit concurrently.
        // Skipped when the tx was too short / had no parseable fee payer.
        if (info.has_fee) {
            // execution_fees accrues UNCONDITIONALLY once the fee is parsed
            // (matches the old `bank.execution_fees += base_fee_dag` OUTSIDE the
            // fee-payer guard). ATOMIC — wave workers accumulate concurrently.
            _ = @atomicRmw(u64, &bank.execution_fees, .Add, info.base_fee, .monotonic);

            const total_debit: u64 = info.base_fee + info.priority_fee;
            // Override-aware newest-first payer read: worker override buffer (if
            // this runs on a wave worker) → bank.pending_writes newest-first →
            // AccountsDb (ancestor-filtered, fork-isolation iter-6 carrier
            // defense). Serial (override==null) is byte-identical to the old raw
            // pending_writes scan (bank.overlayNewest doc @bank.zig:898).
            var fp_lamports: u64 = 0;
            var fp_owner: [32]u8 = undefined;
            var fp_exec = false;
            var fp_rent: u64 = std.math.maxInt(u64);
            var fp_data: []const u8 = &[_]u8{};
            var fp_found = false;
            if (bank.overlayNewest(&info.fee_payer)) |w| {
                fp_lamports = w.lamports;
                fp_owner = w.owner.data;
                fp_exec = w.executable;
                fp_rent = w.rent_epoch;
                fp_data = w.data;
                fp_found = true;
            } else {
                const fp_pk = core.Pubkey{ .data = info.fee_payer };
                if (db.getAccountInSlot(&fp_pk, bank.slot, bank.ancestors())) |acct| {
                    fp_lamports = acct.lamports;
                    fp_owner = acct.owner.data;
                    fp_exec = acct.executable;
                    fp_rent = acct.rent_epoch;
                    fp_data = acct.data;
                    fp_found = true;
                }
            }
            if (fp_found and fp_lamports >= total_debit) {
                // PR-5al (2026-05-20): @prov:replay.tx-processed-signature-count — count its
                // message-header signatures (NOT precompile sigs). r40.6 pairing:
                // accumulate priority_fees ONLY when the fee_payer debit succeeds
                // (settleFees credits leader by priority_fees + (execution_fees -
                // burn) per bank.zig:1252). Both ATOMIC — wave workers.
                _ = @atomicRmw(u64, &bank.signature_count, .Add, @as(u64, info.fee_sig_count), .monotonic);
                _ = @atomicRmw(u64, &bank.priority_fees, .Add, info.priority_fee, .monotonic);
                const old_lt = bank_mod.Bank.accountLtHash(
                    &info.fee_payer,
                    &fp_owner,
                    fp_lamports,
                    fp_exec,
                    fp_data,
                );
                const new_lamports = fp_lamports - total_debit;
                const new_lt = bank_mod.Bank.accountLtHash(
                    &info.fee_payer,
                    &fp_owner,
                    new_lamports,
                    fp_exec,
                    fp_data,
                );
                bank.collectWrite(.{
                    .pubkey = .{ .data = info.fee_payer },
                    .lamports = new_lamports,
                    .owner = .{ .data = fp_owner },
                    .executable = fp_exec,
                    .rent_epoch = fp_rent,
                    .data = fp_data,
                    .old_lt = old_lt,
                    .new_lt = new_lt,
                }) catch {};

                // Tier-1 (2026-05-17): emit per-tx outcome to the recorder. Fee
                // debit succeeded = tx accepted for execution. Sig prefix is the
                // first 8 bytes of the first signature in tx_data (Solana txs
                // always start with signatures, prefixed by a compact-u16 count).
                // (Recorder is forensic-only + disabled on the wave path, so this
                // never fires concurrently — ensureWavePool refuses to arm it.)
                if (vex_store.recorder.isEnabled() and info.tx_data.len >= 64) {
                    const sig_prefix = std.mem.readInt(u64, info.tx_data[1..9], .big);
                    vex_store.recorder.emitTxResult(
                        @intCast(info_idx),
                        sig_prefix,
                        true, // success (fee debit ok)
                        0, // error_code (none)
                        total_debit, // fee
                        0, // compute_consumed (not tracked here)
                    );
                }
            } else if (vex_store.recorder.isEnabled() and info.tx_data.len >= 64) {
                // Fee debit FAILED — tx rejected.
                const sig_prefix = std.mem.readInt(u64, info.tx_data[1..9], .big);
                vex_store.recorder.emitTxResult(
                    @intCast(info_idx),
                    sig_prefix,
                    false, // success=false
                    1, // error_code 1 = insufficient_funds
                    0, // fee (not paid)
                    0, // compute
                );
            }
        }

        // fix/failed-tx-rollback (carrier #6 @414386920): tx-scoped write mark on the
        // ACTIVE sink (worker buffer if override set, else pending_writes). The fee
        // debit above sits BELOW this mark and therefore survives rollback.
        const tx_mark = if (bank_mod.worker_writes_override) |ov| ov.items.len else bank.pending_writes.items.len;

        // Verify precompile instructions BEFORE executing any instructions.
        // @prov:replay.precompile-verify-order
        if (!verifyTxPrecompiles(arena, ptx, bank.slot, self.live_feature_set)) {
            ReplayStats.inc(&self.stats.failed_txs);
            return;
        }

        var tx_fail: ?TxFailInfo = null;
        // fix/cu-parity-batch2 fix 3 (2026-07-12): loaded_accounts_data_size
        // gate. @prov:replay.loaded-accounts-precheck-order — an exceeded tx never reaches ix0 (fees-only, same as the
        // builtin_cus-exhaustion path just below). Checked once, up front —
        // the loop-top guard right below turns it into "no ix ever runs".
        if (loadedAccountsDataSizeCheck(ptx, bank, db)) |lads_err| {
            tx_fail = .{ .ix_idx = 0, .err = lads_err };
        }
        // Carrier 419957920: post-fee pre-execution snapshot for the canonical
        // tx-level rent-state/balance check (verified after the ix loop).
        const rent_states = rentCheckSnapshot(arena, ptx, bank, db);
        // CU-METER (2026-07-05): ONE shared per-tx compute meter — exact
        // mirror of the serial-loop counterpart (see the doc block there).
        var tx_cus_remaining: u64 = compute_budget.executionLimit(compute_budget.parseInstructions(
            ptx.instructions[0..ptx.num_instructions],
            ptx.account_keys[0..ptx.num_accounts],
        ));
        for (ptx.instructions[0..ptx.num_instructions], 0..) |ix, ix_idx| {
            if (tx_fail != null) break; // loaded-accounts-data-size pre-check already failed this tx
            if (ix.program_id_index >= ptx.static_key_count) continue;
            const program_id = &ptx.account_keys[ix.program_id_index];

            // CU-METER builtin draw — mirror of the serial-loop counterpart.
            // fix/cu-parity-batch2: loaderEntryCus() covers BPF_LOADER_UPGRADEABLE/
            // V2/DEPRECATED direct-invocation. @prov:replay.loader-v2-deprecated-invocation
            const builtin_cus: u64 = if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.SYSTEM))
                150
            else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.VOTE))
                2100
            else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.COMPUTE_BUDGET))
                150
            else
                loaderEntryCus(program_id);
            if (builtin_cus > tx_cus_remaining) {
                tx_cus_remaining = 0;
                tx_fail = .{ .ix_idx = ix_idx, .err = error.ComputationalBudgetExceeded };
                break;
            }
            tx_cus_remaining -= builtin_cus;

            if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.SYSTEM)) {
                executeSystemInstruction(ix, ptx, bank, db, arena, ancestor_slots) catch |e| {
                    tx_fail = .{ .ix_idx = ix_idx, .err = e };
                };
            } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.VOTE)) {
                if (bank_mod.TvTrace.on()) _ = bank.tvt2_site_dag.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
                executeVoteInstruction(ix, ptx, bank, db, arena, ancestor_slots) catch |e| {
                    // [TOPVOTES-TRACE] TEMPORARY per-slot one-shot: name the exact vote error.
                    if (bank_mod.TvTrace.on() and bank.tvt2_errprobe_done.cmpxchgStrong(0, 1, .monotonic, .monotonic) == null) {
                        std.log.warn("[TOPVOTES-TRACE] voteerr slot={d} err={s}", .{ bank.slot, @errorName(e) });
                    }
                    tx_fail = .{ .ix_idx = ix_idx, .err = e };
                };
            } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.STAKE)) {
                executeStakeInstruction(ix, ptx, bank, db, arena, self.live_feature_set) catch |e| {
                    tx_fail = .{ .ix_idx = ix_idx, .err = e };
                };
            } else if (std.mem.eql(u8, program_id, &address_lookup_table.PROGRAM_ID)) {
                // ALT migrated to Core BPF (SIMD-0128): run the proven native
                // handler instead of letting it silent-eat the migrated ELF.
                executeAltInstruction(ix, ptx, bank, db, arena, ancestor_slots) catch |e| {
                    tx_fail = .{ .ix_idx = ix_idx, .err = e };
                };
            } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.COMPUTE_BUDGET)) {
                // ComputeBudget: parsed in Phase-1 (fee/priority); no execute-time side effect.
            } else if (std.mem.eql(u8, program_id, &BPF_LOADER_UPGRADEABLE)) {
                // BPFLoaderUpgradeable: NATIVE handler (lt_hash carrier root). INELIGIBLE for
                // parallel (not in the native-eligible set) → only reached on the main thread.
                bpf_loader_program.execute(ix, ptx, bank, db, arena, self.live_feature_set) catch |e| {
                    tx_fail = .{ .ix_idx = ix_idx, .err = e };
                };
            } else if (vex_bpf2.builtins.zk_elgamal_proof_program.HANDLER_ENABLED and
                std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.ZK_ELGAMAL))
            {
                dispatchZkElGamalBuiltin(ix, ptx, bank, db, arena, self.live_feature_set) catch |e| {
                    tx_fail = .{ .ix_idx = ix_idx, .err = e };
                };
            } else if (std.mem.eql(u8, program_id, &BPF_LOADER_V2) or std.mem.eql(u8, program_id, &BPF_LOADER_DEPRECATED)) {
                // fix/cu-parity-batch2: direct invocation of bpf_loader/bpf_loader_deprecated
                // as the top-level program_id ALWAYS fails. @prov:replay.loader-v2-deprecated-invocation
                // — after the entry CU above lands.
                // Must be intercepted here, before the generic-BPF branch would try (and fail
                // differently) to find these loader IDs in the program cache.
                tx_fail = .{ .ix_idx = ix_idx, .err = error.UnsupportedProgramId };
            } else {
                // Generic BPF program. INELIGIBLE for parallel → main thread only, so the
                // recorder threadlocals below are never touched concurrently.
                vex_store.recorder.current_tx_idx = @intCast(info_idx);
                vex_store.recorder.current_ix_idx = @intCast(ix_idx);
                vex_store.recorder.current_ix_present = true;
                defer vex_store.recorder.current_ix_present = false;
                const c17_arm = ix.program_id_index < ptx.account_keys.len and std.mem.eql(u8, ptx.account_keys[ix.program_id_index][0..8], &[_]u8{ 0x0d, 0x45, 0x99, 0x5b, 0x19, 0xa4, 0x53, 0xff });
                if (c17_arm) vex_bpf2.syscalls.c17_probe = true;
                defer if (c17_arm) {
                    vex_bpf2.syscalls.c17_probe = false;
                };
                dispatchBpfExecution(ix, ptx, bank, db, arena, self.live_feature_set, &tx_cus_remaining) catch |e| {
                    if (c17_arm) std.log.warn("[C17-IXERR] err={s}", .{@errorName(e)});
                    // ONLY M4_RunFailed / V1_ProgramFailed / M4_BpfElfResolutionFailed are
                    // genuine execution failures; other DispatchError values are Vexor
                    // plumbing/fallback (requirement #3). M4_BpfElfResolutionFailed
                    // (fix/small-parity-batch-2026-07-17) mirrors Agave's
                    // InstructionError::UnsupportedProgramId for a BPF-loader-owned
                    // executable whose ELF failed to resolve (instruction_dispatch.zig).
                    if (e == error.M4_RunFailed or e == error.V1_ProgramFailed or e == error.M4_BpfElfResolutionFailed) {
                        tx_fail = .{ .ix_idx = ix_idx, .err = e };
                    } else if (e == error.M9_NoFallback or e == error.M5_BankBackedBpfNotPlumbed) {
                        // Structural fail-loud (2026-07-01): a Core-BPF-migrated builtin with
                        // no native handler would SILENTLY drop its writes here (success + 0
                        // mutations) → latent bank_hash carrier (the Config/ALT/FeatureGate
                        // migration class). Hash-neutral: we do NOT set tx_fail (canonical
                        // SUCCEEDS — forcing failure would just diverge differently). We make
                        // it LOUD so forensics catches it immediately instead of days later.
                        // Mirrors 5c480d7 (stake .so plumbing → no silent success-no-writes).
                        std.log.warn("[MIGRATED-BUILTIN-SILENT-EAT] slot={d} err={s} — unhandled builtin dropped writes (would carrier); add its native handler", .{ bank.slot, @errorName(e) });
                    }
                };
            }
            // @prov:replay.stop-at-first-failed-ix
            if (tx_fail != null) break;
        }
        // Carrier 419957920: canonical post-execution tx-level check — ONLY
        // when the ix loop succeeded. @prov:replay.post-execution-verify-changes-order
        // A violation is a TransactionError:
        // the whole tx becomes fees-only failed (writes rolled back below,
        // fee + durable-nonce advance kept — both sit below tx_mark).
        // ix_idx = num_instructions marks "post-execution" (no single ix).
        if (tx_fail == null) {
            if (rent_states) |states| {
                rentCheckVerify(states, bank, db) catch |e| {
                    tx_fail = .{ .ix_idx = ptx.num_instructions, .err = e };
                };
            }
        }
        if (tx_fail) |tf| {
            rollbackFailedTxSink(bank, ptx, tx_mark, tf);
            ReplayStats.inc(&self.stats.failed_txs);
        }
    }

    /// Stage B B2c — lazily create the persistent WavePool + per-worker write buffers on
    /// first armed use (mirrors the dag_dispatcher lazy-init). Returns true if the pool is
    /// ready, false (and DISARMS parallel_exec) on any failure → caller falls back to the
    /// serial drain. Refuses to arm if the recorder is enabled (seam #8: the recorder is a
    /// shared append sink; eligible native executors must not emit to it concurrently).
    /// comptime-dead unless built with -Dparallel_exec.
    fn ensureWavePool(self: *Self) bool {
        if (comptime !build_options.parallel_exec) return false;
        // B3-CLEAR FIX C2 (2026-06-22, ARCH shared-state audit BLOCKER C2): the wave path's
        // original hazard was the legacy vote_state_serde acceptance path reading
        // clusterSlotHashesSnapshot() — a curl-mutated global that feeds bank_hash, unsafe
        // to read concurrently from workers. That path was retired 2026-07-12: voteforge
        // (`executeVoteViaVoteforge`) is now the sole vote executor and reads canonical
        // LOCAL SlotHashes from the bank sysvar, never the curl-global, so the wave path is
        // sound under the production build. (The old -Dsig_vote=true compile gate that
        // enforced this is gone with the flag.)
        if (self.wave_pool != null) return true;
        if (vex_store.recorder.isEnabled()) {
            std.log.err("[PARALLEL-EXEC] recorder is ENABLED — refusing to arm wave path (seam #8); staying SERIAL", .{});
            self.parallel_exec_armed = false;
            return false;
        }
        const cores = self.wave_cores_buf[0..self.wave_cores_len];
        const wp = wave_pool_mod.WavePool.init(self.allocator, cores) catch |e| {
            std.log.err("[PARALLEL-EXEC] WavePool.init failed ({s}) — staying SERIAL", .{@errorName(e)});
            self.parallel_exec_armed = false;
            return false;
        };
        const bufs = self.allocator.alloc(std.ArrayListUnmanaged(bank_mod.AccountWrite), wp.n_workers) catch {
            wp.deinit();
            std.log.err("[PARALLEL-EXEC] worker-buffer alloc failed — staying SERIAL", .{});
            self.parallel_exec_armed = false;
            return false;
        };
        for (bufs) |*b| b.* = .{};
        self.wave_pool = wp;
        self.wave_bufs = bufs;
        std.log.warn("[PARALLEL-EXEC] WavePool LIVE: {d} workers on cores {any}", .{ wp.n_workers, cores });
        return true;
    }

    /// Stage B B2c — wave-barrier parallel execution of the DAG ready set. Replaces the
    /// serial `while (disp.getNextReady())` drain when armed. Per wave:
    ///   1. drain the WHOLE current ready set (all in_degree==0 = mutually conflict-free);
    ///   2. cost-gate IN DRAIN ORDER on the MAIN thread (block_compute_units single-thread,
    ///      seam #7) — record admitted cost; cost-skipped txs are NOT executed (mirrors the
    ///      serial path; skip branch is dead on under-cap testnet); partition admitted into
    ///      ELIGIBLE (all-native) vs INELIGIBLE, running ineligible SERIALLY now (override
    ///      null → pending_writes), BEFORE any worker touches pending_writes;
    ///   3. dispatchWave the eligible txs across workers (each sets worker_writes_override to
    ///      its own buffer; reads see frozen pending_writes + its own buffer — the DAG's W→R
    ///      exclusion guarantees no cross-worker buffer read);
    ///   4. BARRIER, then merge worker buffers into pending_writes in worker-index order
    ///      (disjoint write sets ⇒ order-independent for lthash, but deterministic);
    ///   5. completeTxn EVERY wave tx (admitted+skipped+eligible+ineligible) to release the
    ///      next wave's dependents.
    /// Returns the number of completed txns (for the abandon/endBlock decision). OOM on a
    /// committed-write merge is a fail-stop @panic (cannot silently drop a committed write —
    /// same rule as flushPendingWritesToDb).
    fn runWaveDrain(
        self: *Self,
        wp: *wave_pool_mod.WavePool,
        disp: *tx_dispatcher_mod.TxnDispatcher,
        bank: *Bank,
        dag_tx_infos: []const DagTxInfo,
        dag_idx_map: []const u32,
        arena: std.mem.Allocator,
        ancestor_slots: []const u64,
    ) usize {
        const db = self.accounts_db orelse return 0;
        var dag_executed: usize = 0;
        // [WAVE-WIDTH] parallelism-ceiling accumulators (byte-neutral; only touched when the gate is on).
        const measure_width = WaveWidth.on();
        var ww_waves: u64 = 0; // drain rounds = DAG critical-path depth
        var ww_txs: u64 = 0; // total ready txs across waves (= parallelizable population)
        var ww_max_width: u64 = 0; // widest single dependency level
        var ww_singleton_waves: u64 = 0; // waves of width 1 (forced-serial levels)
        // [WAVE-TIMING] block-scoped accumulators (byte-neutral; only touched when the gate is on).
        const measure_timing = WaveTiming.on();
        var wt_dispatch_ns: u64 = 0;
        var wt_ineligible_ns: u64 = 0;
        var wt_n_dispatches: u64 = 0;
        // [WAVE-INLINE] fix #1 (2026-07-19): singleton-wave barrier-bypass accumulators —
        // tracked separately from wt_dispatch_ns/wt_n_dispatches so the summary line still
        // shows how many waves ran (inline vs dispatched) instead of the bypassed waves
        // silently vanishing from the counters.
        var wt_inline_ns: u64 = 0;
        var wt_n_inline: u64 = 0;
        const wt_eligible_ns_start: u64 = if (measure_timing) WaveTiming.eligible_ns.load(.monotonic) else 0;
        var wave_idxs: std.ArrayListUnmanaged(u32) = .{}; // arena-backed (freed at call end)
        var eligible: std.ArrayListUnmanaged(u32) = .{}; // info_idx of eligible admitted txs
        var ctx: WaveCtx = .{
            .self = self,
            .bank = bank,
            .db = db,
            .ancestor_slots = ancestor_slots,
            .dag_tx_infos = dag_tx_infos,
            .eligible = &.{},
            .bufs = self.wave_bufs,
        };

        while (true) {
            wave_idxs.clearRetainingCapacity();
            while (disp.getNextReady()) |txn_idx| {
                wave_idxs.append(arena, txn_idx) catch @panic("OOM: runWaveDrain wave_idxs — cannot drop a ready tx");
            }
            if (wave_idxs.items.len == 0) break;

            if (measure_width) {
                const w: u64 = wave_idxs.items.len;
                ww_waves += 1;
                ww_txs += w;
                if (w > ww_max_width) ww_max_width = w;
                if (w == 1) ww_singleton_waves += 1;
            }

            eligible.clearRetainingCapacity();
            // Cost-gate pass IN DRAIN ORDER (main thread) + partition + run ineligible serially.
            for (wave_idxs.items) |txn_idx| {
                const info_idx = dag_idx_map[txn_idx];
                const info = &dag_tx_infos[info_idx];
                if (info.parsed == null) continue;
                const ptx = info.parsed.?;
                // FIX #95 PROPAGATION (#43, 2026-06-22): record the cost as a STAT in drain order,
                // but PARTITION + EXECUTE every tx UNCONDITIONALLY. @prov:replay.cost-gate-no-skip
                // The OLD code wrapped the partition in `if (dagTxCost)`, so a cost-null tx was
                // dropped from BOTH the worker pool (eligible) AND main-thread exec (ineligible) →
                // dropped mutations on heavy-but-valid slots the cluster accepts → divergence (412486968).
                if (dagTxCost(bank, &ptx)) |cost| {
                    bank.recordTransactionCost(cost);
                } else {
                    CostNoSkip.note(bank.slot, "wave");
                }
                if (info.eligible) {
                    eligible.append(arena, info_idx) catch @panic("OOM: runWaveDrain eligible list");
                } else {
                    // Ineligible (BPF/loader/zk): SERIAL on the main thread, override null
                    // → pending_writes, BEFORE dispatchWave so no concurrent pending_writes
                    // access. Disjointness (DAG) makes the ineligible/eligible order
                    // irrelevant to bank_hash.
                    if (bank_mod.TvTrace.on()) _ = bank.tvt2_dag_from_shadow.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
                    if (measure_timing) {
                        var wt_timer = std.time.Timer.start() catch unreachable;
                        self.executeDagTx(bank, db, arena, ancestor_slots, &ptx, info_idx, info);
                        wt_ineligible_ns += wt_timer.read();
                    } else {
                        self.executeDagTx(bank, db, arena, ancestor_slots, &ptx, info_idx, info);
                    }
                }
            }

            // [WAVE-CONFLICT] D1 (gated VEX_WAVE_CONFLICT_DETECT): do any two ELIGIBLE (concurrently-
            // executed) wave txs share a WRITABLE account per isWritable? If so the DAG failed to
            // serialize them — the parallel-exec race. Read-only diagnostic.
            if (eligible.items.len > 1 and WaveConflictDetect.on()) {
                var wmap = std.AutoHashMap([32]u8, usize).init(arena);
                defer wmap.deinit();
                for (eligible.items) |einfo| {
                    const eptx = dag_tx_infos[einfo].parsed orelse continue;
                    for (0..@as(usize, eptx.num_accounts)) |ai| {
                        if (!eptx.isWritable(@intCast(ai))) continue;
                        const pk = eptx.account_keys[ai];
                        const gop = wmap.getOrPut(pk) catch continue;
                        if (gop.found_existing) {
                            if (gop.value_ptr.* != einfo) {
                                WaveConflictDetect.hits += 1;
                                std.log.warn("[WAVE-CONFLICT] slot={d} kind=DAG-miss pubkey={s} tx_a={d} tx_b={d} hits={d} — two concurrent wave txs share a WRITABLE account; the DAG did NOT serialize them (parallel-exec race)", .{ bank.slot, std.fmt.bytesToHex(pk, .lower), gop.value_ptr.*, einfo, WaveConflictDetect.hits });
                            }
                        } else {
                            gop.value_ptr.* = einfo;
                        }
                    }
                }
            }

            if (WaveTrace.on()) {
                std.log.warn("[WAVE-TRACE] slot={d} wave ready={d} eligible={d} ineligible-serial={d}", .{ bank.slot, wave_idxs.items.len, eligible.items.len, wave_idxs.items.len - eligible.items.len });
            }

            // Dispatch the eligible (all-native) txs across the worker pool.
            if (eligible.items.len == 1 and !WaveShadowVerify.on()) {
                // [WAVE-INLINE] Fix #1 (wave-formation P1, 2026-07-19 profiling —
                // forensics/wave-formation-profile-2026-07-19.md §ANALYSIS):
                // 96.1% of waves have exactly one eligible tx. Routing a single tx through
                // wp.dispatchWave() pays a measured ~90µs/wave mutex/broadcast/wake-2-workers-
                // to-service-1-item barrier for zero parallelism benefit. Execute it INLINE on
                // this (main/replay) thread instead: worker_writes_override is unset here
                // (identical sink to the ineligible branch above), so executeDagTx's writes
                // land directly in bank.pending_writes — byte-identical to the single worker's
                // buffer being merged in afterward (same tx, same order, same state), just
                // without the cross-thread round-trip. Skipped when VEX_WAVE_SHADOW_VERIFY is
                // armed so that comparator keeps exercising the real dispatch path unmodified.
                const sinfo_idx = eligible.items[0];
                const sinfo = &dag_tx_infos[sinfo_idx];
                const sptx = sinfo.parsed.?; // admitted into `eligible` above ⇒ parsed != null
                if (measure_timing) {
                    var wt_timer = std.time.Timer.start() catch unreachable;
                    self.executeDagTx(bank, db, arena, ancestor_slots, &sptx, sinfo_idx, sinfo);
                    wt_inline_ns += wt_timer.read();
                    wt_n_inline += 1;
                } else {
                    self.executeDagTx(bank, db, arena, ancestor_slots, &sptx, sinfo_idx, sinfo);
                }
            } else if (eligible.items.len > 0) {
                ctx.eligible = eligible.items;
                if (WaveShadowVerify.on()) {
                    // ── SHADOW-VERIFY MODE (gated VEX_WAVE_SHADOW_VERIFY) ─────────────────────────────
                    // Run this wave's eligible txs TWICE from the SAME frozen pre-wave state:
                    //   (1) PARALLEL into the worker buffers — comparison only, DISCARDED (NOT merged).
                    //   (2) SERIAL in ascending block index into pending_writes — COMMITTED (canonical).
                    // The parallel pass writes ONLY to worker buffers, so pending_writes is untouched and
                    // the serial pass reads the IDENTICAL pre-state. Diff (1) vs (2) by VALUE per pubkey →
                    // [WAVE-DIVERGE] names any account the parallel path got wrong. Committing the SERIAL
                    // result keeps the bank bank-exact → safe on the live voting node. completeTxn for the
                    // wave still runs exactly once, later (the loop after this block).
                    wp.dispatchWave(@ptrCast(&ctx), eligible.items.len, waveCb);
                    // (1) snapshot the parallel result per-pubkey (last write wins), then discard buffers.
                    var par_map = std.AutoHashMap([32]u8, ShadowVal).init(arena);
                    for (self.wave_bufs) |*buf| {
                        for (buf.items) |*wr| {
                            par_map.put(wr.pubkey.data, shadowValOf(wr)) catch {};
                        }
                        buf.clearRetainingCapacity();
                    }
                    // (2) serial pass in ASCENDING info_idx (canonical block order, NOT raw drain order),
                    // override=null on the main thread → writes land in pending_writes (committed).
                    const ser_order = arena.dupe(u32, eligible.items) catch eligible.items;
                    std.sort.pdq(u32, ser_order, {}, comptime std.sort.asc(u32));
                    const ser_mark = bank.pending_writes.items.len;
                    for (ser_order) |sinfo_idx| {
                        const sptx = dag_tx_infos[sinfo_idx].parsed orelse continue;
                        if (bank_mod.TvTrace.on()) _ = bank.tvt2_dag_from_shadow.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
                        self.executeDagTx(bank, db, arena, ancestor_slots, &sptx, sinfo_idx, &dag_tx_infos[sinfo_idx]);
                    }
                    // (3) snapshot the serial result per-pubkey (last write wins) from new pending_writes.
                    var ser_map = std.AutoHashMap([32]u8, ShadowVal).init(arena);
                    for (bank.pending_writes.items[ser_mark..]) |*wr| {
                        ser_map.put(wr.pubkey.data, shadowValOf(wr)) catch {};
                    }
                    // (4) diff by value. Any difference = the parallel-exec divergence, account named.
                    var pit = par_map.iterator();
                    while (pit.next()) |e| {
                        if (ser_map.get(e.key_ptr.*)) |sv| {
                            if (!shadowEql(e.value_ptr.*, sv)) {
                                WaveShadowVerify.report(bank.slot, e.key_ptr.*, e.value_ptr.*, sv);
                                logWaveDivergeTxs(bank.slot, e.key_ptr.*, wave_idxs.items, dag_idx_map, dag_tx_infos);
                            }
                        } else {
                            WaveShadowVerify.reportMissing(bank.slot, e.key_ptr.*, "in-parallel-only");
                            logWaveDivergeTxs(bank.slot, e.key_ptr.*, wave_idxs.items, dag_idx_map, dag_tx_infos);
                        }
                    }
                    var sit = ser_map.iterator();
                    while (sit.next()) |e| {
                        if (!par_map.contains(e.key_ptr.*)) {
                            WaveShadowVerify.reportMissing(bank.slot, e.key_ptr.*, "in-serial-only");
                            logWaveDivergeTxs(bank.slot, e.key_ptr.*, wave_idxs.items, dag_idx_map, dag_tx_infos);
                        }
                    }
                    par_map.deinit();
                    ser_map.deinit();
                    // pending_writes now holds the SERIAL (canonical) result → bank stays exact.
                } else {
                    if (measure_timing) {
                        var wt_timer = std.time.Timer.start() catch unreachable;
                        wp.dispatchWave(@ptrCast(&ctx), eligible.items.len, waveCb);
                        wt_dispatch_ns += wt_timer.read();
                        wt_n_dispatches += 1;
                    } else {
                        wp.dispatchWave(@ptrCast(&ctx), eligible.items.len, waveCb);
                    }
                    // BARRIER returned (full happens-before from every worker). Merge each
                    // worker's buffer into pending_writes in worker-index order, then clear it.

                    // [WAVE-CONFLICT] D2 (gated VEX_WAVE_CONFLICT_DETECT): did the SAME pubkey land in two
                    // DIFFERENT worker buffers this wave? That means two txs actually WROTE the same account
                    // (catches an isWritable-vs-handler-writes mismatch the DAG couldn't see). Read-only,
                    // BEFORE the merge so the per-worker attribution is still intact.
                    if (WaveConflictDetect.on()) {
                        var pmap = std.AutoHashMap([32]u8, usize).init(arena);
                        defer pmap.deinit();
                        for (self.wave_bufs, 0..) |*buf, w| {
                            for (buf.items) |*wr| {
                                const gop = pmap.getOrPut(wr.pubkey.data) catch continue;
                                if (gop.found_existing) {
                                    if (gop.value_ptr.* != w) {
                                        WaveConflictDetect.hits += 1;
                                        std.log.warn("[WAVE-CONFLICT] slot={d} kind=cross-worker-write pubkey={s} worker_a={d} worker_b={d} hits={d} — same account written by two workers in one wave (isWritable/DAG vs actual writes mismatch = parallel-exec race)", .{ bank.slot, std.fmt.bytesToHex(wr.pubkey.data, .lower), gop.value_ptr.*, w, WaveConflictDetect.hits });
                                    }
                                } else {
                                    gop.value_ptr.* = w;
                                }
                            }
                        }
                    }

                    for (self.wave_bufs) |*buf| {
                        if (buf.items.len == 0) continue;
                        bank.pending_writes.appendSlice(bank.allocator, buf.items) catch @panic("OOM: runWaveDrain merge worker buffer — cannot drop a committed write");
                        buf.clearRetainingCapacity();
                    }
                }
            }

            // Release the next wave's dependents: completeTxn EVERY tx in this wave.
            for (wave_idxs.items) |txn_idx| {
                disp.completeTxn(txn_idx);
                dag_executed += 1;
            }
        }
        if (measure_width and ww_waves > 0) {
            // ceiling = mean wave width = txs / waves; emitted ×100 as an integer (no float fmt).
            const ceiling_x100: u64 = ww_txs * 100 / ww_waves;
            std.log.warn("[WAVE-WIDTH] slot={d} txs={d} waves={d} ceiling_x100={d} max_width={d} singleton_waves={d}", .{
                bank.slot, ww_txs, ww_waves, ceiling_x100, ww_max_width, ww_singleton_waves,
            });
        }
        if (measure_timing and (wt_n_dispatches > 0 or wt_n_inline > 0)) {
            const wt_eligible_ns_end = WaveTiming.eligible_ns.load(.monotonic);
            const wt_eligible_ns = wt_eligible_ns_end - wt_eligible_ns_start;
            // overhead = dispatch wall-time minus the worker-side useful-work time it contained;
            // see WaveTiming doc comment for the n_items==1 exactness / n_items>1 conservative-bound note.
            // Only meaningful over actually-dispatched waves — [WAVE-INLINE] bypass waves (fix #1)
            // never call dispatchWave, so they're excluded from this ratio and reported separately
            // via inline_dispatches/inline_ns (their overhead is ~0 by construction: no barrier).
            const overhead_ns: i64 = @as(i64, @intCast(wt_dispatch_ns)) - @as(i64, @intCast(wt_eligible_ns));
            const overhead_ns_per_wave: i64 = if (wt_n_dispatches > 0) @divTrunc(overhead_ns, @as(i64, @intCast(wt_n_dispatches))) else 0;
            std.log.warn("[WAVE-TIMING] slot={d} dispatches={d} dispatch_ns={d} eligible_ns={d} ineligible_ns={d} overhead_ns_total={d} overhead_ns_per_wave={d} inline_dispatches={d} inline_ns={d}", .{
                bank.slot, wt_n_dispatches, wt_dispatch_ns, wt_eligible_ns, wt_ineligible_ns, overhead_ns, overhead_ns_per_wave, wt_n_inline, wt_inline_ns,
            });
        }
        return dag_executed;
    }

    /// Core entry parsing and transaction execution loop.
    ///
    /// Format: multiple batches of bincode Vec<Entry>
    ///   Each batch: [count:u64][entry0][entry1]...[entryN]
    ///   Entry: [num_hashes:u64][hash:32][num_txs:u64][tx_wire_bytes...]
    ///
    /// Zig 0.15.2 changes:
    ///   - batch: std.ArrayListUnmanaged(Transaction){} + append(alloc, ...)
    ///   - local_writes: ArrayListUnmanaged + deinit(alloc)
    ///   - task_writes: ArrayListUnmanaged per worker task
    fn replayEntriesInternal(self: *Self, bank: *Bank, data: []const u8) !void {
        // PR-5ac (2026-05-19) — setAncestors moved BEFORE pre-execute sysvar
        // updates (was at end of slot-start sysvar block). Reason: `updateClockSysvar`
        // and `updateLastRestartSlot` both call `db.getAccountInSlot(pk, self.slot,
        // self.ancestors())` to read the prior sysvar bytes. With ancestors=[]
        // (the pre-PR-5ac timing) these reads fall through to the fork-blind
        // `_getRooted → unflushed_cache` path, picking up SIBLING-FORK writes
        // when a parent_offset>1 leader-block exists (e.g., orphan slot 211
        // writes Clock; canonical slot 212's parent=210 child reads slot 211's
        // bytes instead of slot 210's). Empirical carrier: testnet slot 409566212
        // (Carrier G) — Vexor and oracle-node agree on parent_off=2 fork at slot 212
        // (sigs=0, POH match) but diverge on lthash because Vexor's Clock at
        // slot 212 subtracted `lt(slot_211_clock)` while oracle-node subtracted
        // `lt(slot_210_clock)`. Bug delta one-shot, lthash chain contaminated
        // for 1100+ cascade slots.
        //
        // PR-5aa already plumbed parent_sh_sysvar to updateSlotHashesSysvar
        // (per-bank pending_writes read; fork-aware by construction). PR-5ac
        // extends fork-aware reads to Clock + LastRestartSlot by populating
        // `bank.ancestors_buf` BEFORE those updates run — `getAccountInSlot`
        // now sees the canonical ancestor chain and excludes sibling slots.
        //
        // PR-S1.5 (2026-05-15): collect this slot's ancestor chain ONCE here,
        // copy into bank.ancestors_buf via setAncestors. Every fork-aware
        // AccountsDb read from now on uses `bank.ancestors()`. Walks `self.banks`
        // under a shared lock; capped at 64 (covers >2× typical tower depth).
        var ancestor_slots_buf: [bank_mod.ANCESTORS_CAP]u64 = undefined;
        const ancestor_slots: []const u64 = blk: {
            const db = self.accounts_db orelse break :blk &[_]u64{};
            const parent = bank.parent_slot orelse break :blk &[_]u64{};
            if (build_options.two_tier) {
                // STEP 3 window-uncap: walk the DURABLE slot_parents chain
                // (FIX #105) for the FULL unrooted ancestor window up to
                // RING_CAPACITY. Unlike the legacy `self.banks` walk below, this
                // survives bank pruning during catch-up, so the fork-aware read
                // can reach an on-fork write >64 slots back — closing the
                // 64-cap stale-read carrier (413408129: write 138 slots back).
                break :blk db.unrootedAncestorChain(parent, &ancestor_slots_buf);
            }
            // Legacy: 64-capped walk over the in-memory bank map (fork-iso-gated).
            if (!db.fork_isolation_enabled) break :blk &[_]u64{};
            var n: usize = 0;
            var p = parent;
            self.banks_lock.lockShared();
            defer self.banks_lock.unlockShared();
            while (n < 64) {
                ancestor_slots_buf[n] = p;
                n += 1;
                const parent_bank = self.banks.get(p) orelse break;
                p = parent_bank.parent_slot orelse break;
            }
            break :blk ancestor_slots_buf[0..n];
        };
        bank.setAncestors(ancestor_slots);

        // Pre-execute sysvar updates: Clock + SlotHashes + LastRestartSlot.
        // @prov:replay.pre-execute-sysvar-order
        // These MUST be updated BEFORE any transaction executes so that programs reading
        // these sysvars see current-slot data. They append to pending_writes (not cleared
        // by flush) — freeze()'s LtHash walk still includes them in bank_hash.
        //
        // PR-5{aa} (2026-05-19): fetch parent bank's SH from its pending_writes
        // (fork-aware, per-bank) and pass to updateSlotHashesSysvar so the new
        // SH blob is derived from canonical-ancestor state instead of the
        // fork-blind accounts_db._getRooted → unflushed_cache (where a sibling-
        // fork's write at higher-numbered slot can overwrite the canonical
        // entry and leak across forks). Carrier: testnet slot 409543729 read
        // sibling-fork slot 730's SH → produced SH missing slot 727 → 6 vote
        // rejections → 571-rejection cascade.
        const SH_PUBKEY_BYTES: [32]u8 = .{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf,
            0xc6, 0xf2, 0x65, 0xe3, 0xfb, 0x77, 0xcc, 0x7a,
            0xda, 0x82, 0xc5, 0x29, 0xd0, 0xbe, 0x3b, 0x13,
            0x6e, 0x2d, 0x00, 0x55, 0x20, 0x00, 0x00, 0x00,
        };
        const parent_sh_sysvar: ?Bank.SysvarFromParent = blk: {
            const ps = bank.parent_slot orelse break :blk null;
            const pb = self.banks.get(ps) orelse break :blk null;
            break :blk pb.getSysvarFromPendingWrites(&SH_PUBKEY_BYTES);
        };
        try bank.updateClockSysvar();
        try bank.updateSlotHashesSysvar(parent_sh_sysvar);
        // r35-fix: r35-A [SYSVAR-WRITES] probe
        // confirmed LastRestartSlot was never being written (0/10 slots).
        // @prov:replay.pre-execute-sysvar-order Wire the missing writer.
        try bank.updateLastRestartSlot();

        // Flush sysvar writes to AccountsDb so transactions can read current-slot values.
        if (self.accounts_db) |db| {
            flushPendingWritesToDb(bank, db);
        }

        // BUG-1 fix: process epoch boundary BEFORE transaction execution.
        // @prov:replay.epoch-boundary-pre-execute-order Transactions in the epoch-boundary slot must execute
        // against updated epoch state (new epoch, features, Clock, rewards state).
        {
            const current_epoch = bank.epoch_schedule.getEpoch(bank.slot);
            const parent_epoch = if (bank.parent_slot) |ps| bank.epoch_schedule.getEpoch(ps) else 0;
            if (parent_epoch < current_epoch and bank.slot > 0) {
                std.log.debug("[EPOCH] Pre-execute boundary: slot={d} epoch {d}→{d}\n", .{
                    bank.slot, parent_epoch, current_epoch,
                });
                // Task: apply_feature_activations port. @prov:replay.feature-activation-epoch-boundary
                // every PENDING feature account (activated_at == None) is activated at the first
                // bank of the new epoch — its account bytes are REWRITTEN
                // (discriminant 0→1 + activation slot), which feeds the
                // boundary slot's accounts_lt_hash. Without this, Vexor
                // diverges at EVERY boundary that activates a feature (first
                // live case: SIMD-0512 s512oDwg… at epoch 973). Must run
                // BEFORE processEpochBoundary.
                // Epoch-boundary cluster feature-status audit (READ-ONLY,
                // logging-only; zero bank_hash impact). Called BEFORE
                // applyNewFeatureActivations so it reports what is pending AND
                // about to activate. Pending features seen here flip only when
                // the cluster sets activated_at, i.e. at the NEXT boundary —
                // giving ~1 epoch (~2 day) lead time to wire any unwired one.
                if (self.accounts_db) |db| {
                    feature_watch.auditPendingFeatures(db, bank.slot, current_epoch, bank.ancestors());
                }
                try self.applyNewFeatureActivations(bank);
                try bank.processEpochBoundary(current_epoch);
            }
        }

        // Phase D recorder: emit per-slot metadata AFTER setAncestors so the
        // recorded ancestors slice matches what the read path will see during
        // replayEntries below. Critical for diagnosing Phase 1D/1E's bounded-
        // ancestors-window regression — when ancestors_len is tiny during
        // catchup, the iter-6 filter false-flags legitimate canonical writes.
        if (vex_store.recorder.isEnabled()) {
            const rs: u64 = if (self.accounts_db) |db| db.rooted_slot else 0;
            vex_store.recorder.emitSlotMeta(bank.slot, bank.parent_slot, bank.ancestors(), rs);
        }

        var offset: usize = 0;
        var last_entry_hash: Hash = Hash{ .data = [_]u8{0} ** 32 };
        var entry_count: usize = 0;
        // d28dd-SHADOW (2026-05-12): count tick entries (num_txs == 0) so we
        // can detect TooFewTicks dead-slot condition. @prov:replay.too-few-ticks-shadow
        // Shadow-log only — promotion to ENFORCE requires ≥1000-slot FP-free
        // shadow soak per d27mm false-positive lesson.
        var tick_count_seen: u64 = 0;

        // ════════════════════════════════════════════════════════════════════
        // verify_ticks canonical (feat/verify-ticks-canonical-zig-2026-06-19):
        // a single incremental Verifier (src/vex_svm/verify_ticks.zig) drives ALL
        // tick-validity checks (zerohash + full eager + final). The live replay
        // path and the KAT (verify_ticks_kat.zig) exercise this exact code — not
        // two copies. Comptime-gated: in a default (.off) build the struct is
        // `undefined`, `vt_active` is false, and no Verifier method is ever called
        // (no codegen on the consensus path; byte-identical to today).
        //
        // Alpenglow scaffold (gated -Dalpenglow): when this slot is an alpenglow
        // block. @prov:replay.alpenglow-tick-scaffold
        // — we skip ALL tick-validity checks by leaving `vt_active = false` (so
        // the Verifier is never advanced). Stubbed always-false at
        // -Dalpenglow=false (no block is ever treated as alpenglow).
        var vt_verifier: verify_ticks_mod.Verifier = undefined;
        var vt_active: bool = false;
        if (comptime build_options.verify_ticks != .off) {
            const vt_level: verify_ticks_mod.Level = comptime switch (build_options.verify_ticks) {
                .off => .off,
                .zerohash => .zerohash,
                .full => .full,
            };
            vt_active = !self.isAlpenglowBlock(bank.slot);
            if (vt_active) {
                vt_verifier = verify_ticks_mod.Verifier.init(
                    vt_level,
                    bank.hashes_per_tick, // @prov:replay.hashes-per-tick
                    bank.parent_slot orelse bank.slot,
                    bank.slot,
                    bank.ticks_per_slot,
                );
            }
        }

        var tx_diag_success: u64 = 0;
        const tx_diag_blockhash: u64 = 0;
        const tx_diag_sigfail: u64 = 0;
        const tx_diag_funds: u64 = 0;
        const tx_diag_acct: u64 = 0;
        const tx_diag_other: u64 = 0;
        var tx_diag_parse_fail: u64 = 0;
        var fee_writes: u64 = 0;
        var native_system: u64 = 0;
        var native_vote: u64 = 0;
        var native_stake: u64 = 0;
        var native_compute: u64 = 0;
        var native_bpf: u64 = 0;

        // Batch arena: all transaction memory for this slot lives here.
        // Eliminates UAF where tx.deinit() freed data that bank_tx still pointed to.
        var batch_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer batch_arena.deinit();
        const arena_alloc = batch_arena.allocator();

        var batch_num: usize = 0;

        // ── Boundary-anchored component framing (2026-06-04 carrier fix) ──────
        // @prov:replay.completed-data-ranges — each completed-data-range is ONE
        // BlockComponent (a bincode Vec<Entry>) STRICTLY within [range_start,
        // range_end). Vexor concatenates every shred into one
        // buffer, so we reproduce that per-range framing using the batch_complete-
        // derived boundaries (ShredAssembler sets them from the 0x40 flag). When
        // boundaries are present we anchor each outer iteration to ONE component:
        // read the Vec<Entry> count at comp_start, bound the entry loop by comp_end,
        // then advance to the next boundary — IGNORING the sub-byte tail-padding the
        // leader leaves in the final shred of a component.
        //
        // This eliminates the 1-byte-misalignment carrier (slot 413,149,072):
        // comp3's 154 entries ended at offset 215,711, exactly 1 byte before the
        // true FEC boundary 215,712; the old per-batch loop then read the next
        // Vec<Entry> count from offset 215,711 (a byte early) → decoded a phantom
        // 39,424-entry batch that swallowed the entire next component (-153 votes /
        // -1 tick → wrong signature_count + accounts_lt_hash → divergent bank_hash,
        // chained to every descendant slot). Proven on the captured buffer: the
        // anchored framing recovers tx_ok=4094 ticks=64 (exact cluster match) vs
        // the per-batch loop's 3941/63.
        //
        // When boundaries are EMPTY (catchup-RPC path, no batch_complete flags) we
        // fall back to the legacy per-batch scan-forward heuristics, unchanged.
        // ── Boundary-anchored framing + under-count-robust tail (2026-06-05) ──────
        // @prov:replay.completed-data-ranges — each completed-data-range — one
        // per DATA_COMPLETE (0x40) flag — is a bincode Vec<Entry>. Vexor concatenates all shred payloads into one buffer and
        // rebuilds the ranges from the per-shred 0x40 flags (getAssembledDataWith-
        // Boundaries). We parse within [.., cur_comp_end); when a range is consumed
        // we SNAP offset to its end (skipping the leader's sub-shred tail padding) —
        // this is what kills the 1-byte-early carrier (413149072 / 413219562 /
        // 413253683 class: whole buffer consumed yet ticks short, because the legacy
        // loop read the next Vec<Entry> count a byte before the FEC boundary).
        // Two robustness rules beyond pure-anchored framing (9cea430):
        //   (1) parse MULTIPLE Vec<Entry> batches WITHIN a range until cur_comp_end
        //       (offset is NOT reset each outer iteration) — covers a range holding
        //       several entry batches because intermediate 0x40 flags are missing;
        //   (2) when the boundary array is UNDER-COUNTED (fewer 0x40 flags than the
        //       block's entry batches — seen live at the tip, e.g. boundaries=1 on a
        //       200KB/64-tick block) parse the remaining tail [last_boundary,
        //       data.len) with LEGACY scan-forward instead of dropping it (the
        //       9cea430 regression that false-TooFewTicks'd 700+ slots → delinquency).
        // FEC recovery preserves byte 85 (erasure region starts at byte 64), so a
        // COMPLETE slot keeps its final 0x40 ⇒ last boundary == data.len ⇒ the tail
        // never engages on a complete slot ⇒ no phantom-entry risk. Leader zero-fills
        // the last shred ⇒ end padding reads prefix_val==0 ⇒ snap (never a phantom).
        // Empty boundaries (catchup-RPC path) ⇒ anchored=false ⇒ pure legacy.
        var anchored = component_boundaries_override.len > 0;
        var comp_bi: usize = 0;
        var cur_comp_end: usize = if (anchored) component_boundaries_override[0] else data.len;

        // [WAVE-WIDTH-BLOCK] slot-scoped scratch DAG: lazy-init once, reset per slot. Accumulates every
        // entry's txs into one block-wide conflict graph; dry-drained + logged after the batch loop.
        if (BlockWidth.on()) {
            if (self.bw_disp == null) {
                self.bw_disp = tx_dispatcher_mod.TxnDispatcher.init(self.allocator, BlockWidth.DEPTH) catch null;
                if (self.bw_disp != null) {
                    self.bw_wavebuf = self.allocator.alloc(u32, BlockWidth.DEPTH) catch &.{};
                }
            }
            if (self.bw_disp) |*bw| bw.beginBlock();
            self.bw_overflow = false;
        }

        // [BLOCK-DAG] slot-scoped state for the deferred-execution probe. The infos list + idx map are
        // arena-backed (batch_arena lives for the whole replayEntriesInternal call = the whole slot, and
        // parsed txs/tx_data reference `data`/arena memory with the same lifetime). blkdag_begun ensures
        // disp.beginBlock() runs ONCE per slot (per-entry beginBlock would reset the cross-entry edge
        // chains/counters mid-slot). All dead when the gate is off.
        var blkdag_infos: std.ArrayListUnmanaged(DagTxInfo) = .{};
        var blkdag_idx_map: []u32 = &.{};
        var blkdag_begun = false;
        var blkdag_added: usize = 0;

        batch_loop: while (offset + 8 <= data.len) {
            // comp_end bounds the entry loop to the current range (or the whole
            // buffer in legacy / tail mode).
            var comp_end: usize = if (anchored) cur_comp_end else data.len;
            if (anchored and offset + 8 > comp_end) {
                // Current completed-data-range consumed → snap to its end (the exact
                // boundary, skipping any sub-shred tail padding ⇒ carrier-immune) and
                // advance to the next range.
                offset = cur_comp_end;
                comp_bi += 1;
                if (comp_bi < component_boundaries_override.len) {
                    cur_comp_end = component_boundaries_override[comp_bi];
                    comp_end = cur_comp_end;
                    if (offset + 8 > comp_end) continue; // degenerate (empty) range
                } else {
                    // Known boundaries exhausted. Complete slot: last boundary ==
                    // data.len ⇒ nothing left. Under-counted slot: a real tail remains
                    // ⇒ drop to legacy scan-forward (robust to the missing 0x40 flags).
                    if (offset + 8 > data.len) break;
                    anchored = false;
                    comp_end = data.len;
                }
            }

            const prefix_val = std.mem.readInt(u64, data[offset..][0..8], .little);

            // Anchored: an invalid count at `offset` — 0 (leader's zero tail-padding)
            // or >1M (misalignment). Scan forward for the next valid Vec<Entry>
            // header BOUNDED by this range's end (cur_comp_end); if none, the range
            // is consumed → snap to its boundary (the top-of-loop advance then moves
            // to the next range). Bounding the scan by cur_comp_end is what prevents
            // a within-range recovery from ever reading across a true 0x40 boundary
            // (the carrier). The legacy (un-anchored) prefix branches below handle
            // the boundary-less catchup-RPC path unchanged.
            if (anchored and (prefix_val == 0 or prefix_val > 1_000_000)) {
                var scan_o: usize = offset + 1;
                var scan_found = false;
                while (scan_o + 56 <= cur_comp_end) : (scan_o += 1) {
                    const pc = std.mem.readInt(u64, data[scan_o..][0..8], .little);
                    const ph = std.mem.readInt(u64, data[scan_o + 8 ..][0..8], .little);
                    const pt = std.mem.readInt(u64, data[scan_o + 48 ..][0..8], .little);
                    if (pc > 0 and pc < 10000 and ph > 0 and ph < 5_000_000 and pt <= 10_000) {
                        offset = scan_o;
                        scan_found = true;
                        break;
                    }
                }
                if (!scan_found) offset = cur_comp_end; // range consumed → snap; top advances
                continue :batch_loop;
            }

            // GATE 1: entry count must be reasonable.
            //
            // d28bb (2026-05-12): when prefix_val > 1M, this is NOT a valid
            // Vec<Entry> count — but it's also not necessarily "garbage" or
            // end-of-data. Each BlockComponent gets its OWN
            // deshredded buffer, deserialized independently. @prov:replay.completed-data-ranges
            // Vexor concatenates all shreds into
            // one buffer so we must skip from one component's tail to the
            // next component's head using batch_complete-derived boundaries
            // (set by ShredAssembler.getAssembledDataWithBoundaries via the
            // 0x40 flag bit).
            //
            // The carrier: slot 407,817,717 read u64=670014898176 (bytes
            // `00 00 00 00 9c 00 00 00`) at offset 92,444 of 273,248 bytes.
            // Pre-fix this broke out of batch_loop dropping 67% of txs.
            // Post-fix: identical boundary-jump as prefix_val==0 — skip to
            // the next batch_complete-marked component start.
            if (prefix_val > 1_000_000) {
                // Anchored: this component's count prefix is not a valid Vec<Entry>
                // length — abandon the component and advance to the next boundary
                // (comp_bi already incremented at the top of the iteration).
                if (anchored) continue :batch_loop;
                const boundaries = component_boundaries_override;
                if (boundaries.len > 0) {
                    var jumped = false;
                    for (boundaries) |b| {
                        if (b > offset) {
                            offset = b;
                            jumped = true;
                            break;
                        }
                    }
                    if (jumped) continue;
                }
                break;
            }

            // Empty batch: padding between shred batches — scan forward for next valid batch.
            // (Pre-d27ee behavior — d27ee BlockMarker-V1 port was reverted after testnet
            // verification showed marker_version=0 dominant, indicating the current cluster
            // either hasn't migrated to BlockComponent or our discriminator was wrong.
            // Keeping legacy scan-forward to preserve 98.5% d27dd match rate while we
            // gather more evidence about the actual carrier.)
            //
            // Empty batch: end of current BlockComponent.
            //
            // d27hh: when per-component boundaries are available (TVU path),
            // jump directly to the next component start. @prov:replay.completed-data-ranges
            // Trailing bytes inside a component (which Vexor sees as zero padding
            // because the leader fills the last shred) are ignored.
            //
            // When boundaries are empty (catchup-RPC path or no batch_complete
            // flags observed) fall back to the legacy scan-forward heuristic.
            if (prefix_val == 0) {
                // Anchored: an empty/zero-count component — nothing to parse here;
                // advance to the next boundary (comp_bi already incremented).
                if (anchored) continue :batch_loop;
                const boundaries = component_boundaries_override;
                if (boundaries.len > 0) {
                    var jumped = false;
                    for (boundaries) |b| {
                        if (b > offset) {
                            offset = b;
                            jumped = true;
                            break;
                        }
                    }
                    if (jumped) continue;
                    break; // No more components past current offset.
                }
                // Legacy fallback (catchup-RPC path)
                var found = false;
                var scan_offset = offset + 1;
                while (scan_offset + 56 <= data.len) : (scan_offset += 1) {
                    const probe_count = std.mem.readInt(u64, data[scan_offset..][0..8], .little);
                    const probe_hashes = std.mem.readInt(u64, data[scan_offset + 8 ..][0..8], .little);
                    const probe_txs = std.mem.readInt(u64, data[scan_offset + 48 ..][0..8], .little);
                    if (probe_count > 0 and probe_count < 10000 and
                        probe_hashes > 0 and probe_hashes < 5_000_000 and
                        probe_txs <= 10_000)
                    {
                        offset = scan_offset;
                        found = true;
                        break;
                    }
                }
                if (found) continue;
                break;
            }

            // GATE 2: first entry's num_hashes
            // Anchored mode skips this peek-gate: the count is read at a trusted
            // component start and entries are bounded by comp_end, so the legacy
            // "drifted into garbage" heuristic does not apply.
            if (!anchored and offset + 16 <= data.len) {
                const peek_num_hashes = std.mem.readInt(u64, data[offset + 8 ..][0..8], .little);
                if (peek_num_hashes == 0 or peek_num_hashes > 5_000_000) {
                    if (offset > 0) {
                        break;
                    }
                }
            }

            // GATE 3: first entry's num_txs.
            // 2026-05-06 (post-c07030f): raised 2000 → 10_000 to match the
            // inner-entry rejection threshold at GATE 4 (line ~1605). The
            // 2000 cap was tripping legit cluster blocks during leader-handoff
            // vote-backlog flushes — testnet slot 406443788 had 2526 vote txs
            // (cluster RPC confirmed) packed into one entry, the gate rejected
            // the entire batch → bank frozen with sysvars only → bank_hash
            // cascade-diverged from oracle-node for 211 subsequent slots until the
            // chain recovered. Solana's per-block size is bounded by CU (48M)
            // and shred count, not by a fixed tx count; 10k is a sane parser-
            // sanity ceiling that matches the inner gate.
            if (!anchored and offset + 56 <= data.len) {
                const peek_num_txs = std.mem.readInt(u64, data[offset + 48 ..][0..8], .little);
                if (peek_num_txs > 10_000) {
                    break;
                }
            }

            offset += 8; // skip the Vec<Entry> count prefix
            batch_num += 1;
            const batch_max: usize = @intCast(prefix_val);

            var batch_entry_count: usize = 0;

            while (offset + 48 <= comp_end and batch_entry_count < batch_max) {
                batch_entry_count += 1;
                entry_count += 1;

                const num_hashes = std.mem.readInt(u64, data[offset..][0..8], .little);
                offset += 8;

                if (num_hashes > 5_000_000) {
                    // Diag enhancement (2026-05-05): capture slot + source path + raw bytes
                    // around the bad field so we can decide whether this is catchup-RPC
                    // payload corruption (transient) vs live-TVU shred misalignment
                    // (potential parser bug). Only fires on threshold trip — not hot path.
                    const ctx_start = if (offset >= 16) offset - 16 else 0;
                    const ctx_end = @min(offset + 16, data.len);
                    const source: []const u8 = if (self.fast_catchup) "catchup-rpc" else "live-tvu";
                    std.log.warn("[REPLAY] Entry {d}: suspicious num_hashes={d}, slot={d}, source={s}, raw_ctx_bytes[{d}..{d}]={x}, stopping", .{
                        entry_count, num_hashes, bank.slot, source, ctx_start, ctx_end, data[ctx_start..ctx_end],
                    });
                    // Anchored: abandon only this component, not every later one.
                    if (anchored) continue :batch_loop;
                    break :batch_loop;
                }

                // PoH verification: just read the entry hash; defer full PoH chain
                // verification to bank.freeze() which has the proper error path.
                // Removed the inline `for (0..num_hashes)` partial-verify loop
                // (was at this site) — under malformed-entry conditions it could
                // hit Zig stdlib runtime asserts and panic the process.
                // @prov:replay.per-slot-abort-pattern See vault doc 2026-05-03.
                var entry_hash: [32]u8 = undefined;
                @memcpy(&entry_hash, data[offset..][0..32]);
                offset += 32;
                // Deferred: only update last_entry_hash after full tx parse (Bug 5 fix)

                const num_txs = std.mem.readInt(u64, data[offset..][0..8], .little);
                offset += 8;

                if (num_txs > 10_000) {
                    std.log.debug("[REPLAY-REJECT] Entry {d}: corrupt num_txs={d}, aborting slot\n", .{ entry_count, num_txs });
                    // Anchored: abandon only this component, not every later one.
                    if (anchored) continue :batch_loop;
                    break :batch_loop;
                }

                // d28dd-SHADOW: count tick entries (no transactions = tick).
                // @prov:replay.too-few-ticks-shadow
                if (num_txs == 0) tick_count_seen += 1;

                // ════════════════════════════════════════════════════════════
                // verify_ticks canonical (feat/verify-ticks-canonical-zig-2026-06-19)
                // EAGER, on-the-fly tick-validity. @prov:replay.tick-verify
                // Comptime-gated: NO codegen in the default (.off) build.
                // ════════════════════════════════════════════════════════════
                if ((comptime build_options.verify_ticks != .off) and vt_active) {
                    // Drive the shared canonical Verifier with this entry. All
                    // checks (zerohash + full eager) live in verify_ticks.zig.
                    const vt_verdict = vt_verifier.onEntry(num_hashes, num_txs == 0);
                    if (vt_verdict.isDead()) {
                        self.verifyTicksKill(bank, @tagName(vt_verdict));
                        return error.BadBlockTickValidity;
                    }
                }

                // ── Transaction processing: Serial or DAG dispatch ──────
                var entry_complete = true;

                // Determine whether to use DAG path for this entry.
                // Falls back to serial if dispatcher init fails.
                var use_dag = self.dag_dispatch_enabled and num_txs > 0;

                // Q2 content-capture (task #67, 2026-06-25): when VEX_LEDGER_CONTENT is ON, force
                // the SERIAL executor for this slot so the proven serial capture path fills
                // bank.rpc_tx_capture (account_keys + header counts + FULL per-static-key pre/post
                // balance vectors, gathered at the END of each tx's iteration when the newest
                // pending_writes entry for a key IS that tx's write). The DAG path CANNOT reproduce
                // canonical block-order pre/post: it (a) executes in dependency order, not block
                // order, and (b) defers program execution to Phase 2, so a per-tx POST scan of
                // pending_writes after Phase 2 only ever sees each key's FINAL value — the
                // intermediate per-tx balance for a key touched by multiple txs is unrecoverable
                // (and on the wave path workers write to per-worker override buffers merged only at
                // the barrier, so an in-flight per-tx scan is unsafe). Forcing serial routes to the
                // byte-faithful capture instead of fabricating wrong balances.
                //
                // CONSENSUS-NEUTRAL: the DAG path is a bank-EXACT reorder of the serial path (#43
                // proof: execute-regardless + order-invariant cost stat) — forcing serial is the
                // MORE conservative choice and can never change bank_hash. DORMANT: comptime-gated
                // on -Dvex_ledger AND runtime-gated on the cached VEX_LEDGER_CONTENT env, so with
                // content OFF (the live voting deploy) `use_dag` is untouched → DAG/wave dispatch
                // and perf are exactly as before, zero extra work. `dag_dispatch_enabled` is left
                // TRUE — only this slot's local is forced — and since the env is cached/constant,
                // content-on means the dispatcher never even inits.
                if (comptime build_options.vex_ledger) {
                    if (Bank.contentCaptureActive()) use_dag = false;
                }
                if (use_dag and self.dag_dispatcher == null) {
                    // [BLOCK-DAG] a slot-wide DAG must hold the whole block (observed max 6906 txs/slot);
                    // per-entry keeps the live default 4096. Env is cached → constant per process.
                    const dag_depth: u32 = if (BlockDag.on()) BlockDag.DEPTH else 4096;
                    if (tx_dispatcher_mod.TxnDispatcher.init(self.allocator, dag_depth)) |d| {
                        self.dag_dispatcher = d;
                        std.log.debug("[DAG] Dispatcher initialized (depth={d})\n", .{dag_depth});
                    } else |_| {
                        std.log.err("[DAG] Failed to init dispatcher, falling back to serial", .{});
                        self.dag_dispatch_enabled = false;
                        use_dag = false;
                    }
                }

                if (use_dag) {
                    // ═══════════════════════════════════════════════════════════
                    // DAG DISPATCH PATH (Phase 1 — single-threaded reordering)
                    // ═══════════════════════════════════════════════════════════

                    var disp = &self.dag_dispatcher.?;
                    if (!BlockDag.on()) {
                        disp.beginBlock();
                    } else if (!blkdag_begun) {
                        // [BLOCK-DAG] one beginBlock per SLOT: cross-entry account-conflict chains must
                        // survive entry boundaries (that is the whole point). Allocate the slot-wide
                        // txn_idx→infos map lazily here (needs disp.pool.len).
                        disp.beginBlock();
                        blkdag_begun = true;
                        blkdag_idx_map = try arena_alloc.alloc(u32, disp.pool.len);
                        @memset(blkdag_idx_map, 0);
                    }

                    // Temporary storage: map from txn_idx → parse-order index.
                    // DagTxInfo is module-scope (hoisted for Stage B B2c so runWaveDrain
                    // can take a slice of it).

                    // Pre-allocate temp arrays from batch arena
                    const num_txs_usize: usize = @intCast(num_txs);
                    const dag_tx_infos = try arena_alloc.alloc(DagTxInfo, num_txs_usize);
                    // Map from pool txn_idx → index into dag_tx_infos
                    const dag_idx_map = try arena_alloc.alloc(u32, disp.pool.len);
                    @memset(dag_idx_map, 0);

                    var dag_parsed: usize = 0;
                    var dag_added: usize = 0;
                    var dag_ready_immediate: usize = 0;

                    // ── DAG Phase 1: Parse all txns, add to dispatcher ──────
                    for (0..num_txs) |tx_i| {
                        if (offset >= comp_end) {
                            entry_complete = false;
                            break;
                        }

                        const tx_start = offset;
                        const tx_size = measureTransaction(data, tx_start) catch {
                            tx_diag_parse_fail += 1;
                            entry_complete = false;
                            break;
                        };

                        if (tx_size == 0 or tx_start + tx_size > comp_end) {
                            tx_diag_parse_fail += 1;
                            entry_complete = false;
                            break;
                        }

                        offset = tx_start + tx_size;
                        tx_diag_success += 1;

                        const tx_data_slice = data[tx_start .. tx_start + tx_size];

                        // SB-2 (2026-06-17): capture this tx for the RPC history stores, in DAG PARSE
                        // order (= block transaction order; the DAG only reorders EXECUTION, not the
                        // wire order). Mirrors the serial-path capture. COMPTIME no-op when -Drpc_store
                        // is OFF → consensus path byte-identical.
                        if (comptime build_options.rpc_store) {
                            if (self.rpc_block_store != null) {
                                var rpc_ss2: [tx_ingest_mod.MAX_SIGNATURES][64]u8 = undefined;
                                var rpc_sk2: [tx_ingest_mod.MAX_SIGNATURES][32]u8 = undefined;
                                if (tx_ingest_mod.parse(tx_data_slice, &rpc_ss2, &rpc_sk2)) |rpc_parsed2| {
                                    const fp2: [32]u8 = if (rpc_parsed2.num_keys > 0) rpc_sk2[0] else [_]u8{0} ** 32;
                                    var rpc_fee_pos2: usize = 0;
                                    const rpc_nsigs2 = readCompactU16(tx_data_slice, &rpc_fee_pos2) catch 0;
                                    // DAG path is comptime-dead (dag_dispatch_enabled=false) and does NOT
                                    // enrich getBlock meta post-execution (err/CU/balances stay at their
                                    // CapturedTx defaults: null/null/empty). Discard the capture index.
                                    _ = bank.captureRpcTx(rpc_parsed2.id().*, fp2, 5000 * @as(u64, rpc_nsigs2), tx_data_slice);
                                } else |_| {}
                            }
                        }

                        // Fee PARSE during Phase 1 (wire-only). Stage 1 fees-in-execution
                        // (2026-07-09): the actual fee validation + debit + counter increments
                        // are DEFERRED to executeDagTx (the DAG-ordered execution unit) so each
                        // tx's fee sees the running balance of every earlier tx in block order;
                        // here we only PARSE the wire and STASH the result into DagTxInfo.
                        var sig_count: u16 = 1;
                        var fee_has_dag = false;
                        var fee_payer_dag: [32]u8 = [_]u8{0} ** 32;
                        var fee_base_dag: u64 = 0;
                        var fee_prio_dag: u64 = 0;
                        if (tx_data_slice.len > 100) {
                            var fee_pos_dag: usize = 0;
                            // PR-5al (2026-05-20): @prov:replay.tx-processed-signature-count
                            // Bug pre-PR-5al: counted on every header parse → over-count by K (failed
                            // sanitization/lock/fee-payer txs) → bank_hash SHA256 input diverges
                            // from cluster → cluster rejects votes with Custom=2 SlotHashMismatch.
                            // Fix: defer the increment until INSIDE the fee_payer-debit guard.
                            const num_sigs_dag = readCompactU16(tx_data_slice, &fee_pos_dag) catch {
                                dag_tx_infos[tx_i] = .{ .tx_data = tx_data_slice, .num_sigs = 1, .parsed = null };
                                dag_parsed += 1;
                                continue;
                            };
                            sig_count = num_sigs_dag;
                            if (sig_count == 0) sig_count = 1;
                            if (num_sigs_dag == 0) {
                                dag_tx_infos[tx_i] = .{ .tx_data = tx_data_slice, .num_sigs = 1, .parsed = null };
                                dag_parsed += 1;
                                continue;
                            }
                            fee_pos_dag += @as(usize, num_sigs_dag) * 64;
                            if (fee_pos_dag < tx_data_slice.len) {
                                if (tx_data_slice[fee_pos_dag] & 0x80 != 0) fee_pos_dag += 1;
                                fee_pos_dag += 3;
                                const num_keys_dag = readCompactU16(tx_data_slice, &fee_pos_dag) catch 0;
                                if (num_keys_dag > 0 and fee_pos_dag + 32 <= tx_data_slice.len) {
                                    var fee_payer_key_dag: [32]u8 = undefined;
                                    @memcpy(&fee_payer_key_dag, tx_data_slice[fee_pos_dag..][0..32]);

                                    // r75-bug-class-d11 (2026-05-07): include precompile sigs in
                                    // base_fee. @prov:replay.precompile-sig-base-fee
                                    const ix_start_dag = fee_pos_dag + @as(usize, num_keys_dag) * 32 + 32;
                                    const precompile_sigs_dag = compute_budget.parsePrecompileSigCountFromWire(
                                        tx_data_slice,
                                        fee_pos_dag,
                                        num_keys_dag,
                                        ix_start_dag,
                                    );
                                    const total_sigs_dag: u64 = @as(u64, num_sigs_dag) + @as(u64, precompile_sigs_dag);
                                    const base_fee_dag: u64 = 5000 * total_sigs_dag;

                                    // r40.6: parse compute_budget instructions for priority fee.
                                    const priority_fee_dag = compute_budget.parsePriorityFeeFromWire(
                                        tx_data_slice,
                                        fee_pos_dag,
                                        num_keys_dag,
                                        ix_start_dag,
                                    );

                                    // Stage 1 fees-in-execution (2026-07-09): STASH the parsed fee
                                    // unit into DagTxInfo instead of debiting here. executeDagTx's
                                    // fee unit (before instruction dispatch) does the payer read +
                                    // sufficiency guard + debit + the three counter increments
                                    // (execution_fees unconditionally, signature_count/priority_fees
                                    // under the guard) in DAG order. @prov:replay.fee-unit-sequential-order
                                    fee_payer_dag = fee_payer_key_dag;
                                    fee_base_dag = base_fee_dag;
                                    fee_prio_dag = priority_fee_dag;
                                    fee_has_dag = true;
                                }
                            }
                        }
                        // PR-5al (2026-05-20): tx_data_slice.len <= 100 = too-small tx,
                        // not a real Solana transaction. Don't count it. @prov:replay.tx-processed-signature-count

                        // Parse to get account keys and writability
                        const parsed_opt = if (tx_data_slice.len > 100) blk_dag_parse: {
                            break :blk_dag_parse parseTxFromBytes(tx_data_slice, arena_alloc, self.accounts_db, bank) catch {
                                break :blk_dag_parse null;
                            };
                        } else null;

                        dag_tx_infos[tx_i] = .{
                            .tx_data = tx_data_slice,
                            .num_sigs = sig_count,
                            .parsed = parsed_opt,
                            // Stage B B2c: precompute native-only parallel eligibility once
                            // here (cheap, on the parse thread). comptime-dead-ish — only the
                            // wave path reads it; serial-DAG ignores it.
                            .eligible = if (parsed_opt) |p| txIsNativeEligible(&p) else false,
                            // Stage 1 fees-in-execution: the fee unit stashed above (applied in
                            // executeDagTx). fee_has_dag=false for short/parse-fail txs → the
                            // fee unit is skipped (mirrors the old short-tx behavior).
                            .fee_payer = fee_payer_dag,
                            .base_fee = fee_base_dag,
                            .priority_fee = fee_prio_dag,
                            .fee_sig_count = sig_count,
                            .has_fee = fee_has_dag,
                        };
                        dag_parsed += 1;

                        // Build writable-first ordered account arrays for addTxn
                        if (parsed_opt) |ptx| {
                            // Compute writability per Solana convention:
                            //   Writable signers: [0, num_required_sigs - num_readonly_signed)
                            //   Readonly signers: [num_required_sigs - num_readonly_signed, num_required_sigs)
                            //   Writable non-signers: [num_required_sigs, num_accounts - num_readonly_unsigned)
                            //   Readonly non-signers: [num_accounts - num_readonly_unsigned, num_accounts)
                            const n_accts: usize = @as(usize, ptx.num_accounts);

                            // Zone-based writability (handles both legacy and v0+ALT)
                            var n_writable: usize = 0;
                            for (0..n_accts) |ai| {
                                if (ptx.isWritable(@intCast(ai))) {
                                    n_writable += 1;
                                }
                            }

                            if (n_accts > 0 and n_accts <= tx_dispatcher_mod.MAX_ACCT_PER_TXN) {
                                // Build reordered arrays (writables first)
                                var ordered_keys: [tx_dispatcher_mod.MAX_ACCT_PER_TXN][32]u8 = undefined;
                                var ordered_writable: [tx_dispatcher_mod.MAX_ACCT_PER_TXN]bool = undefined;
                                var wi: usize = 0;
                                var ri: usize = n_writable;

                                for (0..n_accts) |ai| {
                                    const is_w = ptx.isWritable(@intCast(ai));
                                    if (is_w) {
                                        ordered_keys[wi] = ptx.account_keys[ai];
                                        ordered_writable[wi] = true;
                                        wi += 1;
                                    } else {
                                        ordered_keys[ri] = ptx.account_keys[ai];
                                        ordered_writable[ri] = false;
                                        ri += 1;
                                    }
                                }

                                const txn_idx = disp.addTxn(
                                    ordered_keys[0..n_accts],
                                    ordered_writable[0..n_accts],
                                ) catch {
                                    if (WaveTrace.on()) std.log.warn("[WAVE-TRACE] slot={d} DAG-DROP tx_i={d} reason=addTxn-pool-exhausted (executed by NEITHER serial-DAG nor wave path)", .{ bank.slot, tx_i });
                                    continue;
                                };

                                dag_idx_map[txn_idx] = @intCast(tx_i);
                                dag_added += 1;

                                // [BLOCK-DAG] slot-wide accumulation: remember this tx's info (copy is
                                // cheap; parsed/tx_data reference slot-lifetime memory) and map its pool
                                // txn_idx for the slot-end drain. dag_tx_infos[tx_i] was fully written
                                // (incl. .eligible) just above, before addTxn.
                                if (BlockDag.on()) {
                                    blkdag_infos.append(arena_alloc, dag_tx_infos[tx_i]) catch @panic("OOM: block-DAG infos — cannot silently drop a queued tx");
                                    blkdag_idx_map[txn_idx] = @intCast(blkdag_infos.items.len - 1);
                                    blkdag_added += 1;
                                }

                                // [WAVE-WIDTH-BLOCK] mirror this tx into the slot-wide scratch DAG (same
                                // writable-first ordered keys). Measurement-only; failure = slot exceeded
                                // BW_DEPTH → flag overflow (never silently truncate).
                                if (self.bw_disp) |*bw| {
                                    _ = bw.addTxn(ordered_keys[0..n_accts], ordered_writable[0..n_accts]) catch {
                                        self.bw_overflow = true;
                                    };
                                }

                                // Check if immediately ready (no deps)
                                if (disp.pool[txn_idx].in_degree == 0) {
                                    dag_ready_immediate += 1;
                                }
                            } else if (n_accts > tx_dispatcher_mod.MAX_ACCT_PER_TXN and WaveTrace.on()) {
                                std.log.warn("[WAVE-TRACE] slot={d} DAG-DROP tx_i={d} reason=n_accts={d}>{d} (executed by NEITHER serial-DAG nor wave path)", .{ bank.slot, tx_i, n_accts, tx_dispatcher_mod.MAX_ACCT_PER_TXN });
                            }
                        }
                    }

                    // ── DAG Phase 2: Execute in DAG order ────────────────────
                    // Fee deduction already happened in Phase 1. Only native program
                    // execution is reordered by the DAG.
                    //
                    // Stage B B2c (parallel-exec): when ARMED (-Dparallel_exec build +
                    // VEX_PARALLEL_EXEC env), execution runs over a persistent worker pool
                    // in conflict-free WAVES (runWaveDrain). Default/unarmed (incl. the
                    // entire comptime-off build): the original single-threaded serial drain
                    // below, byte-identical to pre-B2c — the wave block is comptime-dead. The
                    // per-tx execute body is now executeDagTx (shared by both paths). The
                    // cost gate stays on the MAIN thread in both paths (block_compute_units
                    // single-threaded, seam #7); the serial drain records cost AFTER execute
                    // (unchanged position), runWaveDrain records at admission (cost is not in
                    // bank_hash and the sum is order-invariant, so this is parity-neutral).
                    var dag_executed: usize = 0;
                    const used_wave = blk_wave: {
                        // [BLOCK-DAG] probe armed: Phase 2 is DEFERRED to the slot-end drain — this
                        // entry's txs stay queued in the slot-wide dispatcher. `true` here just means
                        // "skip the per-entry serial drain below".
                        if (BlockDag.on()) break :blk_wave true;
                        if (comptime build_options.parallel_exec) {
                            if (self.parallel_exec_armed and self.ensureWavePool()) {
                                dag_executed = self.runWaveDrain(self.wave_pool.?, disp, bank, dag_tx_infos, dag_idx_map, arena_alloc, ancestor_slots);
                                break :blk_wave true;
                            }
                        }
                        break :blk_wave false;
                    };
                    if (!used_wave) {
                        while (disp.getNextReady()) |txn_idx| {
                            const info_idx = dag_idx_map[txn_idx];
                            const info = &dag_tx_infos[info_idx];

                            // Native program execution in DAG order.
                            if (self.accounts_db != null and info.parsed != null) {
                                const ptx = info.parsed.?;
                                // FIX #95 PROPAGATION (#43, 2026-06-22): execute UNCONDITIONALLY.
                                // @prov:replay.cost-gate-no-skip The old `if (dagTxCost) { execute }` SKIPPED
                                // execution once Vexor's ESTIMATE crossed 60M — dropping mutations on
                                // heavy-but-VALID slots the cluster accepts (the estimate over-counts
                                // vs actual CU) → accounts_lt_hash corruption → bank_hash divergence
                                // (carrier 412486968). Record the cost only while under the cap (stat
                                // only; mirrors the serial path's 6700/6828).
                                const dag_tx_cost = dagTxCost(bank, &ptx);
                                if (bank_mod.TvTrace.on()) _ = bank.tvt2_dag_from_serial_drain.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
                                self.executeDagTx(bank, self.accounts_db.?, arena_alloc, ancestor_slots, &ptx, info_idx, info);
                                if (dag_tx_cost) |c| {
                                    bank.recordTransactionCost(c);
                                } else {
                                    CostNoSkip.note(bank.slot, "dag");
                                }
                            }

                            disp.completeTxn(txn_idx);
                            dag_executed += 1;
                        }
                    }

                    // Safety: if not all txns completed (parse failure), abandon
                    if (BlockDag.on()) {
                        // [BLOCK-DAG] nothing executed per-entry — end/abandon accounting happens once
                        // at the slot-end drain.
                    } else if (!entry_complete or dag_executed < dag_added) {
                        disp.abandonBlock();
                    } else {
                        disp.endBlock();
                    }
                } else {
                    // ═══════════════════════════════════════════════════════════
                    // SERIAL PATH (original, unchanged)
                    // ═══════════════════════════════════════════════════════════
                    var tx_idx: usize = 0;
                    for (0..num_txs) |tx_i_serial| {
                        tx_idx += 1;
                        _ = tx_i_serial;
                        if (offset >= comp_end) {
                            entry_complete = false;
                            break;
                        }

                        const tx_start = offset;
                        const tx_size = measureTransaction(data, tx_start) catch {
                            tx_diag_parse_fail += 1;
                            entry_complete = false;
                            break; // can't determine tx boundary — stop entry
                        };

                        if (tx_size == 0 or tx_start + tx_size > comp_end) {
                            tx_diag_parse_fail += 1;
                            entry_complete = false;
                            break;
                        }

                        // Successfully measured transaction — advance offset
                        offset = tx_start + tx_size;
                        tx_diag_success += 1;

                        // Fee deduction: extract fee payer and deduct base fee (5000 lamports)
                        const tx_data = data[tx_start .. tx_start + tx_size];

                        // SB-2 getBlock-meta enrichment (2026-06-21): per-iteration cosmetic capture state.
                        // `rpc_cap_idx` = index of THIS tx in bank.rpc_tx_capture (null = not captured this
                        // iteration → never enrich, avoids clobbering the prior tx). `rpc_pre`/`rpc_post` =
                        // fee-payer (account[0]) lamports before/after; `rpc_err` = post-execution outcome.
                        // ALL comptime-dead when -Drpc_store is OFF. Pure OBSERVATION — written to the RPC
                        // capture list only, never to bank/accounts state, so bank_hash is unaffected.
                        var rpc_cap_idx: ?usize = null;
                        var rpc_pre: ?u64 = null;
                        var rpc_post: ?u64 = null;
                        var rpc_err: ?@import("vex_store").block_store.TxError = null;

                        // Q2 content-path (2026-06-25): full STATIC account-key + header-count + balance
                        // state for THIS tx, gathered alongside the fee-payer-only SB-2 capture above when
                        // VEX_LEDGER_CONTENT is on. STATIC-KEY-COMPLETE: covers ALL static message keys
                        // (account_keys[0..rpc_sk_len]) for every legacy + vote + non-ALT-v0 tx. ALT-loaded
                        // (v0 address_table_lookups) addresses are NOT resolved here — flagged TODO; the
                        // executor does not expose a resolved combined-key list at this site, so we emit a
                        // self-consistent static-only vector (account_keys / pre / post all rpc_sk_len long,
                        // num_loaded_writable=0) rather than fabricate loaded addresses. ALL comptime-dead
                        // unless -Drpc_store OR -Dvex_ledger; all runtime-dormant unless the gate env is set.
                        var rpc_skeys: [tx_ingest_mod.MAX_SIGNATURES][32]u8 = undefined; // static keys (block order)
                        var rpc_sk_len: u32 = 0; // # static message keys captured
                        var rpc_nrs: u8 = 0; // num_required_signatures
                        var rpc_nro_signed: u8 = 0; // num_readonly_signed_accounts
                        var rpc_nro_unsigned: u8 = 0; // num_readonly_unsigned_accounts
                        var rpc_pre_vec: [tx_ingest_mod.MAX_SIGNATURES]u64 = undefined; // per-static-key pre-balances
                        var rpc_post_vec: [tx_ingest_mod.MAX_SIGNATURES]u64 = undefined; // per-static-key post-balances
                        var rpc_pre_gathered = false; // pre-vector filled (before execute) for this tx

                        // SB-2 (2026-06-17): capture this tx (signature + fee-payer + wire) for the RPC
                        // history stores, in block order, with the executor's CORRECT framing. COMPTIME
                        // no-op when neither -Drpc_store NOR -Dvex_ledger is set (the whole block is
                        // comptime-dead → consensus path byte-identical). captureRpcTx deep-copies the wire
                        // (arena-independent) and itself runtime-gates on rpcCaptureActive() (VEX_RPC_STORE
                        // or VEX_LEDGER_CONTENT). Q2 (2026-06-25): the capture also fires for the vex_ledger
                        // content path (self.vex_ledger_flight) — identical rpc_store behavior preserved.
                        if (comptime build_options.rpc_store or build_options.vex_ledger) {
                            // DORMANCY (LIVE audit): enter the capture block (which runs an extra tx parse)
                            // ONLY when a sink is actually active — rpc_store wired, OR vex_ledger content
                            // explicitly on (VEX_LEDGER_CONTENT via Bank.contentCaptureActive()). vex_ledger_flight
                            // alone is NOT sufficient: it is non-null whenever VEX_LEDGER=1 (set for the freeze
                            // tap), so gating on it would run a per-tx parse on the live deploy with content OFF.
                            // This keeps the live (content-off) replay path zero-extra-work.
                            if (self.rpc_block_store != null or (self.vex_ledger_flight != null and Bank.contentCaptureActive())) {
                                var rpc_ss: [tx_ingest_mod.MAX_SIGNATURES][64]u8 = undefined;
                                var rpc_sk: [tx_ingest_mod.MAX_SIGNATURES][32]u8 = undefined;
                                if (tx_ingest_mod.parse(tx_data, &rpc_ss, &rpc_sk)) |rpc_parsed| {
                                    const fp: [32]u8 = if (rpc_parsed.num_keys > 0) rpc_sk[0] else [_]u8{0} ** 32;
                                    // getBlock meta: base fee = 5000 × signature count. Read the
                                    // leading compact-u16 sig count independently (cosmetic, never
                                    // touches the consensus fee-debit at ~6275). Priority/precompile
                                    // fees are an enrichment follow-up.
                                    var rpc_fee_pos: usize = 0;
                                    const rpc_nsigs = readCompactU16(tx_data, &rpc_fee_pos) catch 0;
                                    const rpc_fee: u64 = 5000 * @as(u64, rpc_nsigs);
                                    rpc_cap_idx = bank.captureRpcTx(rpc_parsed.id().*, fp, rpc_fee, tx_data);
                                    // Q2: copy ALL static message keys (parse only copies signer keys, so
                                    // read straight from the wire at keys_offset) + the two readonly header
                                    // counts (parse skips them). Bounds-clamped to MAX_SIGNATURES.
                                    if (rpc_cap_idx != null) {
                                        const n_keys: u32 = @min(@as(u32, rpc_parsed.num_keys), @as(u32, tx_ingest_mod.MAX_SIGNATURES));
                                        const ko = rpc_parsed.keys_offset;
                                        if (ko + @as(usize, n_keys) * 32 <= tx_data.len) {
                                            var ki: u32 = 0;
                                            while (ki < n_keys) : (ki += 1) {
                                                @memcpy(&rpc_skeys[ki], tx_data[ko + ki * 32 ..][0..32]);
                                            }
                                            rpc_sk_len = n_keys;
                                            rpc_nrs = rpc_parsed.num_required_sigs;
                                            // header: [ver?][num_required][num_ro_signed][num_ro_unsigned]...
                                            // keys_offset points at the first key, which is right after the
                                            // compact-u16 key count, which follows the 3 header count bytes.
                                            // Recompute the two readonly counts directly from the wire: they
                                            // sit at message_start(+1 if versioned)+1 and +2.
                                            const msg_off: usize = tx_data.len - rpc_parsed.message.len;
                                            const hdr0: usize = msg_off + (if (rpc_parsed.is_versioned) @as(usize, 1) else 0);
                                            if (hdr0 + 3 <= tx_data.len) {
                                                rpc_nro_signed = tx_data[hdr0 + 1];
                                                rpc_nro_unsigned = tx_data[hdr0 + 2];
                                            }
                                        }
                                    }
                                } else |_| {}
                            }
                        }
                        if (tx_data.len > 100) {
                            var fee_pos: usize = 0;
                            // PR-5al (2026-05-20): defer signature_count increment until
                            // INSIDE the fee_payer-debit guard. See DAG-path block above.
                            // @prov:replay.tx-processed-signature-count
                            const num_sigs_fee = readCompactU16(tx_data, &fee_pos) catch {
                                continue;
                            };
                            if (num_sigs_fee == 0) continue;
                            const first_sig_off = fee_pos; // first signature begins right after the count
                            fee_pos += @as(usize, num_sigs_fee) * 64;
                            if (fee_pos >= tx_data.len) continue;
                            if (tx_data[fee_pos] & 0x80 != 0) fee_pos += 1;
                            fee_pos += 3;
                            const num_keys = readCompactU16(tx_data, &fee_pos) catch continue;
                            if (num_keys == 0 or fee_pos + 32 > tx_data.len) continue;

                            var fee_payer_key: [32]u8 = undefined;
                            @memcpy(&fee_payer_key, tx_data[fee_pos..][0..32]);

                            // r75-bug-class-d11 (2026-05-07): include precompile sigs in base_fee.
                            const ix_start_nondag = fee_pos + @as(usize, num_keys) * 32 + 32;
                            const precompile_sigs_nondag = compute_budget.parsePrecompileSigCountFromWire(
                                tx_data,
                                fee_pos,
                                num_keys,
                                ix_start_nondag,
                            );
                            const total_sigs_nondag: u64 = @as(u64, num_sigs_fee) + @as(u64, precompile_sigs_nondag);
                            const base_fee: u64 = 5000 * total_sigs_nondag;
                            bank.execution_fees += base_fee;

                            // r40.6 mirror of DAG-path plumbing: parse priority_fee + total_debit;
                            // accumulator moved INSIDE fee_payer-debit guard below for atomic pairing.
                            const priority_fee_nondag = compute_budget.parsePriorityFeeFromWire(
                                tx_data,
                                fee_pos,
                                num_keys,
                                ix_start_nondag,
                            );
                            const total_debit_nondag: u64 = base_fee + priority_fee_nondag;

                            if (self.accounts_db) |db| {
                                const fp_pk = @import("core").Pubkey{ .data = fee_payer_key };
                                // Use running balance from pending_writes for multi-tx fee payers.
                                var fp_lam: u64 = 0;
                                var fp_own: [32]u8 = undefined;
                                var fp_exe = false;
                                var fp_re: u64 = std.math.maxInt(u64);
                                var fp_dat: []const u8 = &[_]u8{};
                                var fp_ok = false;
                                {
                                    var ri2: usize = bank.pending_writes.items.len;
                                    while (ri2 > 0) {
                                        ri2 -= 1;
                                        if (std.mem.eql(u8, &bank.pending_writes.items[ri2].pubkey.data, &fee_payer_key)) {
                                            fp_lam = bank.pending_writes.items[ri2].lamports;
                                            fp_own = bank.pending_writes.items[ri2].owner.data;
                                            fp_exe = bank.pending_writes.items[ri2].executable;
                                            fp_re = bank.pending_writes.items[ri2].rent_epoch;
                                            fp_dat = bank.pending_writes.items[ri2].data;
                                            fp_ok = true;
                                            break;
                                        }
                                    }
                                }
                                // M1 diagnostic enrichment (TXBEARING-BLOCK-PRODUCTION-PLAN-2026-07-16
                                // §4 M1 item 2): true iff this fee-payer was ALREADY in pending_writes,
                                // i.e. written by an EARLIER tx in THIS SAME block (a prior transfer/fee
                                // debit) — the exact same-block-earlier-writer question the
                                // [PRODUCE-PARITY-FAIL] log below needs to distinguish the documented
                                // transfer-drain residual (block_produce.zig:487-488) from any other
                                // NotLoaded sub-class. Pure new local; reads fp_ok BEFORE the AccountsDb
                                // (parent-state) fallback below can flip it — zero behavior change to
                                // fp_ok/fp_lam/etc, which continue exactly as before.
                                const same_block_earlier_writer = fp_ok;
                                if (!fp_ok) {
                                    // Fork-isolation: ancestor-filtered read. See DAG-path comment above.
                                    if (db.getAccountInSlot(&fp_pk, bank.slot, bank.ancestors())) |acct| {
                                        fp_lam = acct.lamports;
                                        fp_own = acct.owner.data;
                                        fp_exe = acct.executable;
                                        fp_re = acct.rent_epoch;
                                        fp_dat = acct.data;
                                        fp_ok = true;
                                    }
                                }
                                if (fp_ok and fp_lam >= total_debit_nondag) {
                                    // PR-5al (2026-05-20): @prov:replay.tx-processed-signature-count
                                    bank.signature_count += num_sigs_fee;
                                    // SB-2 getBlock-meta: pre-tx fee-payer (account[0]) balance =
                                    // fp_lam, read BEFORE the fee debit below. Observation only.
                                    if (comptime build_options.rpc_store or build_options.vex_ledger) rpc_pre = fp_lam;
                                    // Q2 content-path (2026-06-25): gather the FULL per-static-key pre-balance
                                    // vector HERE (BEFORE the fee debit + execute mutate pending_writes), so
                                    // pre_balances[i] is the lamports of account_keys[i] as of pre-execution.
                                    // Per key: newest pending_writes entry (this slot's running balance),
                                    // else fork-isolated AccountsDb read, else 0 (account created this tx).
                                    // Pure OBSERVATION — reads pending_writes / accounts_db, writes neither.
                                    if (comptime build_options.rpc_store or build_options.vex_ledger) {
                                        if (rpc_sk_len > 0) {
                                            var ai: u32 = 0;
                                            while (ai < rpc_sk_len) : (ai += 1) {
                                                const akey = rpc_skeys[ai];
                                                var lam: u64 = 0;
                                                var found = false;
                                                var rwi: usize = bank.pending_writes.items.len;
                                                while (rwi > 0) {
                                                    rwi -= 1;
                                                    if (std.mem.eql(u8, &bank.pending_writes.items[rwi].pubkey.data, &akey)) {
                                                        lam = bank.pending_writes.items[rwi].lamports;
                                                        found = true;
                                                        break;
                                                    }
                                                }
                                                if (!found) {
                                                    const apk = @import("core").Pubkey{ .data = akey };
                                                    if (db.getAccountInSlot(&apk, bank.slot, bank.ancestors())) |acct| {
                                                        lam = acct.lamports;
                                                    }
                                                }
                                                rpc_pre_vec[ai] = lam;
                                            }
                                            rpc_pre_gathered = true;
                                        }
                                    }
                                    // r40.6 pairing: accumulate priority_fees ONLY when guard passes.
                                    bank.priority_fees += priority_fee_nondag;
                                    const old_lt = bank_mod.Bank.accountLtHash(
                                        &fee_payer_key,
                                        &fp_own,
                                        fp_lam,
                                        fp_exe,
                                        fp_dat,
                                    );
                                    const new_lamports = fp_lam - total_debit_nondag;
                                    const new_lt = bank_mod.Bank.accountLtHash(
                                        &fee_payer_key,
                                        &fp_own,
                                        new_lamports,
                                        fp_exe,
                                        fp_dat,
                                    );
                                    bank.collectWrite(.{
                                        .pubkey = .{ .data = fee_payer_key },
                                        .lamports = new_lamports,
                                        .owner = .{ .data = fp_own },
                                        .executable = fp_exe,
                                        .rent_epoch = fp_re,
                                        .data = fp_dat,
                                        .old_lt = old_lt,
                                        .new_lt = new_lt,
                                    }) catch {};
                                    fee_writes += 1;

                                    // task #26: record this COMMITTED tx's signature for cross-block
                                    // AlreadyProcessed dedup in our own block production. Gated +
                                    // bank-hash-neutral (pure dedup state). prune() self-throttles per
                                    // slot (idempotent), so calling it here is one prune per slot.
                                    if (comptime build_options.status_cache) {
                                        if (self.statusCacheActive() and first_sig_off + 64 <= tx_data.len) {
                                            self.recent_sig_cache.record(self.allocator, tx_data[first_sig_off..][0..64], bank.slot);
                                            self.recent_sig_cache.prune(self.allocator, bank.slot);
                                        }
                                    }

                                    // Recorder Tier-1: per-tx outcome (SERIAL path, which is the
                                    // default — dag_dispatch_enabled defaults to false). Fee
                                    // debit succeeded = tx accepted for execution.
                                    if (vex_store.recorder.isEnabled() and tx_data.len >= 9) {
                                        const sig_prefix = std.mem.readInt(u64, tx_data[1..9], .big);
                                        vex_store.recorder.emitTxResult(
                                            @intCast(tx_idx - 1), // tx_idx was already incremented at loop top
                                            sig_prefix,
                                            true,
                                            0,
                                            total_debit_nondag,
                                            0,
                                        );
                                    }
                                } else {
                                    // task #26 PRODUCE-PARITY self-check (increment 2): a fee-fail tx in
                                    // OUR OWN loopback-replayed block is a gate MISS — the cluster would
                                    // mark this block DEAD (AlreadyProcessed/InsufficientFundsForFee). This
                                    // is precisely where the adversarial transfer-drain residual surfaces:
                                    // the inclusion gate admitted the tx against PARENT state, but replay
                                    // sees the fee-payer drained by an earlier tx's transfer. Loud + rate-
                                    // limited; loopback-only ⇒ purely observational (bank-hash-neutral, and
                                    // inert in the default config: no tx-bearing production ⇒ no self-
                                    // produced fee-fails). The REAL-execution parity verification.
                                    if (self.self_produced.contains(bank.slot)) {
                                        const PP = struct {
                                            var last: u64 = std.math.maxInt(u64);
                                            var n: u64 = 0;
                                        };
                                        if (PP.last != bank.slot) {
                                            PP.last = bank.slot;
                                            PP.n = 0;
                                        }
                                        PP.n += 1;
                                        // M3 auto-safe-off tripwire (2026-07-17): record that THIS slot had
                                        // >=1 parity-fail, unconditionally (not rate-limited by the PP.n<=3
                                        // log cap below — the tripwire needs to know a fail happened, not
                                        // how many). Consulted (read-only) at freeze completion; see
                                        // self.produce_parity_fail_slots' doc comment + txbearing_tripwire.zig.
                                        self.produce_parity_fail_slots.put(self.allocator, bank.slot, {}) catch {};
                                        if (PP.n <= 3) {
                                            // M1 diagnostic enrichment (plan §4 M1 item 2): sig prefix +
                                            // fee-payer pubkey (first 8 bytes, hex-friendly via {x}) +
                                            // the same-block-earlier-writer flag captured above — so a
                                            // FUTURE occurrence (live or offline) self-diagnoses which
                                            // NotLoaded sub-class fired without needing a repeat live
                                            // incident. Comptime-free (self.self_produced is empty unless
                                            // tx-bearing production actually ran, so this branch is dead
                                            // weight — not extra cost — in the default VEX_TPU_INGEST=off
                                            // config; no separate build_options gate needed).
                                            const sig_prefix: u64 = if (tx_data.len >= first_sig_off + 8)
                                                std.mem.readInt(u64, tx_data[first_sig_off..][0..8], .big)
                                            else
                                                0;
                                            // std.fmt.fmtSliceHexLower is NOT exported in Zig 0.15.2's
                                            // stdlib (see vex_bpf2/trace.zig:134) — use bytesToHex (the
                                            // pattern every other hex-logging call site in this file uses,
                                            // e.g. :7685/:7776/:11107) instead.
                                            var fp8: [8]u8 = undefined;
                                            @memcpy(&fp8, fee_payer_key[0..8]);
                                            const fp_hex = std.fmt.bytesToHex(fp8, .lower);
                                            std.log.err("[PRODUCE-PARITY-FAIL] slot={d} self-produced block has a NotLoaded tx (fee-payer can't pay / drained) — cluster would mark this block DEAD (gate miss; likely transfer-drain residual). count={d} sig_prefix={x} fee_payer={s} same_block_earlier_writer={}", .{ bank.slot, PP.n, sig_prefix, fp_hex, same_block_earlier_writer });
                                        }
                                    }
                                    if (vex_store.recorder.isEnabled() and tx_data.len >= 9) {
                                        // Fee debit FAILED — tx rejected.
                                        const sig_prefix = std.mem.readInt(u64, tx_data[1..9], .big);
                                        vex_store.recorder.emitTxResult(
                                            @intCast(tx_idx - 1),
                                            sig_prefix,
                                            false,
                                            1, // insufficient_funds
                                            0,
                                            0,
                                        );
                                    }
                                }
                            }
                        }
                        // PR-5al (2026-05-20): tx_data.len <= 100 = too-small tx, not a real
                        // Solana transaction. Don't count it. @prov:replay.tx-processed-signature-count

                        // Execute native programs
                        if (self.accounts_db != null and tx_data.len > 100) {
                            const parsed = parseTxFromBytes(tx_data, arena_alloc, self.accounts_db, bank) catch blk_parse: {
                                break :blk_parse null;
                            };
                            if (parsed) |ptx| {
                                // Block compute unit check — skip if block is full.
                                // num_write_locks = total_accounts - readonly_signed - readonly_unsigned
                                var num_write_locks: u64 = 0;
                                for (0..@as(usize, ptx.num_accounts)) |wai2| {
                                    if (ptx.isWritable(@intCast(wai2))) num_write_locks += 1;
                                }
                                var total_ix_data_len: u64 = 0;
                                for (ptx.instructions[0..ptx.num_instructions]) |ix_cu| {
                                    total_ix_data_len += @intCast(ix_cu.data.len);
                                }
                                const is_vote_tx = blk_vote: {
                                    for (ptx.instructions[0..ptx.num_instructions]) |ix_cv| {
                                        if (ix_cv.program_id_index < ptx.static_key_count) {
                                            if (std.mem.eql(u8, &ptx.account_keys[ix_cv.program_id_index], &NATIVE_PROGRAM_IDS.VOTE)) {
                                                break :blk_vote true;
                                            }
                                        }
                                    }
                                    break :blk_vote false;
                                };
                                const cu_limit: u64 = if (is_vote_tx) 2100 else 200_000;
                                // FIX #95 WEDGE2 (2026-06-01): the block compute-unit limit is a
                                // block-PRODUCTION admission control, NOT a replay execution gate.
                                // The cluster already formed this block within the real limit, so
                                // replay MUST execute every transaction in it. @prov:replay.cost-gate-no-skip
                                // The old
                                // `if (estimateTransactionCost(...)) |tx_cost|` SKIPPED the entire
                                // instruction loop below once block_compute_units exceeded the cap
                                // (estimate returns null), WHILE THE FEE WAS ALREADY DEBITED above —
                                // silently dropping System-Transfer mutations for ~6200/7056 txs at
                                // heavy slot 412486968 → accounts_lt_hash corruption → bank_hash
                                // divergence → vote slot-hash mismatch → delinquency. Decoupled here:
                                // compute the cost for stats, but execute regardless.
                                const tx_cost_opt = bank.estimateTransactionCost(
                                    @intCast(ptx.num_required_sigs),
                                    num_write_locks,
                                    total_ix_data_len,
                                    cu_limit,
                                    is_vote_tx,
                                );
                                if (tx_cost_opt == null) {
                                    // Old behavior would SKIP this tx's instructions here. Count +
                                    // rate-limited log so the carrier stays observable; execute anyway.
                                    const NoSkipLog = struct {
                                        var count: u64 = 0;
                                        var last_slot: u64 = std.math.maxInt(u64);
                                    };
                                    if (NoSkipLog.last_slot != bank.slot) {
                                        NoSkipLog.last_slot = bank.slot;
                                        NoSkipLog.count = 0;
                                    }
                                    NoSkipLog.count +|= 1;
                                    if (NoSkipLog.count <= 5 or NoSkipLog.count % 500 == 0)
                                        std.log.warn("[COST-GATE-NOSKIP] slot={d} tx_idx={d} count={d} — executing anyway (Agave-canonical replay)\n", .{ bank.slot, tx_idx, NoSkipLog.count });
                                }
                                // Verify precompile instructions BEFORE executing any instructions.
                                // @prov:replay.precompile-verify-order
                                // On failure: abort this transaction (skip instruction execution).
                                if (!verifyTxPrecompiles(arena_alloc, &ptx, bank.slot, self.live_feature_set)) {
                                    ReplayStats.inc(&self.stats.failed_txs);
                                    // SB-2 getBlock-meta: precompile verification failed → a non-Instruction
                                    // TransactionError. @prov:replay.tx-error-discriminant-mapping
                                    // emit a generic non-zero code (renders as {"Code":N}); honest non-null
                                    // err. Observation only. Exact variant mapping is a follow-up.
                                    if (comptime build_options.rpc_store or build_options.vex_ledger) rpc_err = .{ .code = 255, .instruction_index = null, .instruction_error = null };
                                } else {
                                    // fix/failed-tx-rollback (2026-06-10, carrier #6 @414386920):
                                    // tx-scoped write mark + first-genuine-error capture. The fee
                                    // debit for THIS tx was appended in the fee block ABOVE, so it
                                    // sits below tx_mark_serial and survives rollback.
                                    // @prov:replay.fee-payer-rollback-survival Mirrors the DAG path exactly.
                                    const tx_mark_serial = bank.pending_writes.items.len;
                                    var tx_fail_serial: ?TxFailInfo = null;
                                    // fix/cu-parity-batch2 fix 3 (2026-07-12): loaded_accounts_data_size
                                    // gate — see DAG twin's doc block for the full citation.
                                    if (loadedAccountsDataSizeCheck(&ptx, bank, self.accounts_db.?)) |lads_err| {
                                        tx_fail_serial = .{ .ix_idx = 0, .err = lads_err };
                                    }
                                    // Carrier 419957920: post-fee pre-execution snapshot for the
                                    // canonical tx-level rent-state/balance check (see DAG twin).
                                    const rent_states_serial = rentCheckSnapshot(arena_alloc, &ptx, bank, self.accounts_db.?);
                                    // CU-METER (2026-07-05, carrier 419786142 tx#289): ONE shared
                                    // per-tx compute meter. @prov:replay.per-tx-cu-meter-drawdown
                                    // Limit = explicit SetComputeUnitLimit (capped
                                    // 1.4M) else the canonical default rule; SAME parse the fee
                                    // path uses. Pre-fix every top-level BPF ix got a fresh
                                    // hardcoded 1.4M → ix4 of tx#289 completed on 33,254 CU the
                                    // cluster refused → committed writes the cluster rolled back
                                    // → bank_hash diverged.
                                    var tx_cus_remaining: u64 = compute_budget.executionLimit(compute_budget.parseInstructions(
                                        ptx.instructions[0..ptx.num_instructions],
                                        ptx.account_keys[0..ptx.num_accounts],
                                    ));
                                    for (ptx.instructions[0..ptx.num_instructions], 0..) |ix, ix_idx_serial| {
                                        if (tx_fail_serial != null) break; // loaded-accounts-data-size pre-check already failed this tx
                                        if (ix.program_id_index >= ptx.static_key_count) continue;
                                        const program_id = &ptx.account_keys[ix.program_id_index];

                                        // CU-METER builtin draw. @prov:replay.per-tx-cu-meter-drawdown
                                        // System=150, Vote=2100, ComputeBudget=150. Stake/ALT/Config
                                        // are Core-BPF migrated on this cluster (real VM CUs) — their
                                        // native-handler consumption is a follow-up parity item (0 here).
                                        // fix/cu-parity-batch2: loaderEntryCus() covers
                                        // BPF_LOADER_UPGRADEABLE/V2/DEPRECATED direct-invocation.
                                        // @prov:replay.loader-v2-deprecated-invocation
                                        const builtin_cus: u64 = if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.SYSTEM))
                                            150
                                        else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.VOTE))
                                            2100
                                        else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.COMPUTE_BUDGET))
                                            150
                                        else
                                            loaderEntryCus(program_id);
                                        if (builtin_cus > tx_cus_remaining) {
                                            tx_cus_remaining = 0;
                                            tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = error.ComputationalBudgetExceeded };
                                            break;
                                        }
                                        tx_cus_remaining -= builtin_cus;

                                        if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.SYSTEM)) {
                                            native_system += 1;
                                            executeSystemInstruction(ix, &ptx, bank, self.accounts_db.?, arena_alloc, ancestor_slots) catch |e| {
                                                // Canonical system_v2 InstrError escape (Unimplemented
                                                // plumbing filtered inside) → genuine tx failure.
                                                tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = e };
                                            };
                                        } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.VOTE)) {
                                            native_vote += 1;
                                            if (bank_mod.TvTrace.on()) _ = bank.tvt2_site_serial.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
                                            executeVoteInstruction(ix, &ptx, bank, self.accounts_db.?, arena_alloc, ancestor_slots) catch |e| {
                                                // FIX-1b: genuine vote InstructionError (plumbing
                                                // filtered inside the seam) → tx failure. See DAG
                                                // path counterpart.
                                                tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = e };
                                            };
                                        } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.STAKE)) {
                                            native_stake += 1;
                                            executeStakeInstruction(ix, &ptx, bank, self.accounts_db.?, arena_alloc, self.live_feature_set) catch |e| {
                                                // FIX-1c: dispatch-level stake parse errors only
                                                // (genuine, deterministic). See DAG path counterpart.
                                                tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = e };
                                            };
                                        } else if (std.mem.eql(u8, program_id, &address_lookup_table.PROGRAM_ID)) {
                                            // ALT migrated to Core BPF (SIMD-0128): run the proven
                                            // native handler instead of silent-eating the migrated
                                            // ELF. See DAG path counterpart in executeDagTx.
                                            executeAltInstruction(ix, &ptx, bank, self.accounts_db.?, arena_alloc, ancestor_slots) catch |e| {
                                                tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = e };
                                            };
                                        } else if (std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.COMPUTE_BUDGET)) {
                                            native_compute += 1;
                                        } else if (std.mem.eql(u8, program_id, &BPF_LOADER_UPGRADEABLE)) {
                                            // BPFLoaderUpgradeable: NATIVE handler (lt_hash carrier root,
                                            // see native/bpf_loader_program.zig) — must NOT fall to the
                                            // BPF-ELF executor, which no-ops for a bodyless native program.
                                            native_bpf += 1;
                                            if (self.accounts_db != null) {
                                                // Phase-2 arms propagate a genuine InstructionError
                                                // (deploy ELF verify fail) → tx rollback. See DAG counterpart.
                                                bpf_loader_program.execute(ix, &ptx, bank, self.accounts_db.?, arena_alloc, self.live_feature_set) catch |e| {
                                                    tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = e };
                                                };
                                            }
                                        } else if (vex_bpf2.builtins.zk_elgamal_proof_program.HANDLER_ENABLED and
                                            std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.ZK_ELGAMAL))
                                        {
                                            // task #11 (DARK: comptime-false => dead code; zk ix fall to the
                                            // else BPF branch exactly as today). ENABLED => verify + write ctx-state.
                                            native_bpf += 1;
                                            if (self.accounts_db != null) {
                                                dispatchZkElGamalBuiltin(ix, &ptx, bank, self.accounts_db.?, arena_alloc, self.live_feature_set) catch |e| {
                                                    tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = e };
                                                };
                                            }
                                        } else if (std.mem.eql(u8, program_id, &BPF_LOADER_V2) or std.mem.eql(u8, program_id, &BPF_LOADER_DEPRECATED)) {
                                            // fix/cu-parity-batch2: direct invocation of bpf_loader/
                                            // bpf_loader_deprecated as the top-level program_id ALWAYS
                                            // fails after the entry CU above lands. See DAG path counterpart.
                                            // @prov:replay.loader-v2-deprecated-invocation
                                            tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = error.UnsupportedProgramId };
                                        } else {
                                            native_bpf += 1;
                                            if (self.accounts_db != null) {
                                                // PR-5p (2026-05-19): see DAG path counterpart at ~line 3127.
                                                vex_store.recorder.current_tx_idx = @intCast(tx_idx);
                                                vex_store.recorder.current_ix_idx = @intCast(ix_idx_serial);
                                                vex_store.recorder.current_ix_present = true;
                                                defer vex_store.recorder.current_ix_present = false;
                                                // carrier #17 one-shot: arm program-log capture for HistoryJT ix.
                                                const c17_arm = ix.program_id_index < ptx.account_keys.len and std.mem.eql(u8, ptx.account_keys[ix.program_id_index][0..8], &[_]u8{ 0x0d, 0x45, 0x99, 0x5b, 0x19, 0xa4, 0x53, 0xff });
                                                if (c17_arm) vex_bpf2.syscalls.c17_probe = true;
                                                defer if (c17_arm) {
                                                    vex_bpf2.syscalls.c17_probe = false;
                                                };
                                                dispatchBpfExecution(ix, &ptx, bank, self.accounts_db.?, arena_alloc, self.live_feature_set, &tx_cus_remaining) catch |e| {
                                                    if (c17_arm) std.log.warn("[C17-IXERR] err={s}", .{@errorName(e)});
                                                    // ONLY M4_RunFailed, V1_ProgramFailed, and
                                                    // M4_BpfElfResolutionFailed (fix/small-parity-batch-
                                                    // 2026-07-17, mirrors the serial-path counterpart) are
                                                    // genuine (see DAG path + taxonomy doc block above
                                                    // rollbackFailedTx).
                                                    if (e == error.M4_RunFailed or e == error.V1_ProgramFailed or e == error.M4_BpfElfResolutionFailed) {
                                                        tx_fail_serial = .{ .ix_idx = ix_idx_serial, .err = e };
                                                    } else if (e == error.M9_NoFallback or e == error.M5_BankBackedBpfNotPlumbed) {
                                                        // Structural fail-loud (2026-07-01): see the serial-path
                                                        // counterpart above. Hash-neutral loud marker for a
                                                        // Core-BPF-migrated builtin with no native handler
                                                        // (would silent-eat its writes → latent carrier).
                                                        std.log.warn("[MIGRATED-BUILTIN-SILENT-EAT] slot={d} err={s} — unhandled builtin dropped writes (would carrier); add its native handler", .{ bank.slot, @errorName(e) });
                                                    }
                                                };
                                            }
                                        }
                                        // @prov:replay.stop-at-first-failed-ix
                                        if (tx_fail_serial != null) break;
                                    }
                                    // Carrier 419957920: canonical post-execution tx-level check —
                                    // mirror of the DAG twin (see executeDagTx tail for the doc).
                                    if (tx_fail_serial == null) {
                                        if (rent_states_serial) |states| {
                                            rentCheckVerify(states, bank, self.accounts_db.?) catch |e| {
                                                tx_fail_serial = .{ .ix_idx = ptx.num_instructions, .err = e };
                                            };
                                        }
                                    }
                                    if (tx_fail_serial) |tf| {
                                        rollbackFailedTx(bank, &ptx, tx_mark_serial, tf);
                                        ReplayStats.inc(&self.stats.failed_txs);
                                        // SB-2 getBlock-meta: genuine per-tx failure → InstructionError.
                                        // @prov:replay.tx-error-discriminant-mapping
                                        // instruction_error stays null → the renderer emits the valid
                                        // "GenericError" inner. Observation only (no state touched). Exact
                                        // inner-variant mapping (Custom/named) is a follow-up.
                                        if (comptime build_options.rpc_store or build_options.vex_ledger)
                                            rpc_err = .{ .code = 8, .instruction_index = @truncate(tf.ix_idx), .instruction_error = null };
                                    }
                                } // end else (precompile passed)
                                // Record cost for stats only when it fit the budget (null = block
                                // full; we still executed above). @prov:replay.cost-gate-no-skip
                                if (tx_cost_opt) |tx_cost| bank.recordTransactionCost(tx_cost);
                            }
                        }

                        // SB-2 getBlock-meta enrichment (2026-06-21) + Q2 content-path (2026-06-25): attach
                        // the now-known post-execution meta to THIS tx's capture entry. Runs at the END of
                        // the iteration, after the fee debit AND the execute block AND any rollbackFailedTx,
                        // so post-balances reflect the FINAL account state (not the post-fee-debit-only
                        // balance — critical for non-vote transfers where the fee payer also moves lamports).
                        // The backward scans over pending_writes find each key's tail write fast (just
                        // appended) and are bank-state OBSERVATION only (read pending_writes, write nothing →
                        // bank_hash unaffected). All comptime-dead unless -Drpc_store OR -Dvex_ledger.
                        if (comptime build_options.rpc_store or build_options.vex_ledger) {
                            if (rpc_cap_idx) |cap_i| {
                                // post = fee-payer's latest pending_writes entry, if any (else null →
                                // no post captured; pre may also be null on the load-fail path).
                                if (rpc_pre != null) {
                                    const fp_key = bank.rpc_tx_capture.items[cap_i].fee_payer;
                                    var ri3: usize = bank.pending_writes.items.len;
                                    while (ri3 > 0) {
                                        ri3 -= 1;
                                        if (std.mem.eql(u8, &bank.pending_writes.items[ri3].pubkey.data, &fp_key)) {
                                            rpc_post = bank.pending_writes.items[ri3].lamports;
                                            break;
                                        }
                                    }
                                }

                                // Q2: gather the FULL per-static-key post-balance vector (parallel to the
                                // pre-vector gathered before execute). Per key: newest pending_writes entry
                                // (its final state this slot), else fall back to the pre-balance (unchanged).
                                if (rpc_pre_gathered) {
                                    var ai: u32 = 0;
                                    while (ai < rpc_sk_len) : (ai += 1) {
                                        const akey = rpc_skeys[ai];
                                        var lam: u64 = rpc_pre_vec[ai]; // default: unchanged
                                        var ri4: usize = bank.pending_writes.items.len;
                                        while (ri4 > 0) {
                                            ri4 -= 1;
                                            if (std.mem.eql(u8, &bank.pending_writes.items[ri4].pubkey.data, &akey)) {
                                                lam = bank.pending_writes.items[ri4].lamports;
                                                break;
                                            }
                                        }
                                        rpc_post_vec[ai] = lam;
                                    }
                                }

                                // Q2: full key-parallel population fires ONLY on the vex_ledger content
                                // path (self.vex_ledger_flight != null). The rpc_store-only path (no flight)
                                // falls through to the length-1 fee-payer fallback below → byte-IDENTICAL to
                                // the prior SB-2 flushRpcStore output (task constraint: rpc_store unchanged).
                                if (self.vex_ledger_flight != null and rpc_pre_gathered and rpc_sk_len > 0) {
                                    // STATIC-KEY-COMPLETE: full account_keys + parallel pre/post balance
                                    // vectors + header counts. num_loaded_writable=0 (ALT addresses not
                                    // resolved here — see TODO at the capture site). setRpcTxAccounts owns
                                    // the FINAL pre/post balances (called LAST), so we pass empty balances
                                    // to setLastRpcTxMeta below to avoid a redundant length-1 overwrite.
                                    bank.setLastRpcTxMeta(cap_i, rpc_err, null, &[_]u64{}, &[_]u64{});
                                    bank.setRpcTxAccounts(
                                        cap_i,
                                        rpc_skeys[0..rpc_sk_len],
                                        rpc_sk_len,
                                        0, // num_loaded_writable — ALT-loaded TODO
                                        rpc_nrs,
                                        rpc_nro_signed,
                                        rpc_nro_unsigned,
                                        rpc_pre_vec[0..rpc_sk_len],
                                        rpc_post_vec[0..rpc_sk_len],
                                    );
                                } else {
                                    // Fallback (parse/keys out of bounds or load-fail): fee-payer-only
                                    // length-1 balance views (account[0]) — the prior SB-2 behavior.
                                    var pre_buf: [1]u64 = undefined;
                                    var post_buf: [1]u64 = undefined;
                                    const pre_slice: []const u64 = if (rpc_pre) |p| blk: {
                                        pre_buf[0] = p;
                                        break :blk pre_buf[0..1];
                                    } else &[_]u64{};
                                    const post_slice: []const u64 = if (rpc_post) |p| blk: {
                                        post_buf[0] = p;
                                        break :blk post_buf[0..1];
                                    } else &[_]u64{};
                                    bank.setLastRpcTxMeta(cap_i, rpc_err, null, pre_slice, post_slice);
                                }
                            }
                        }
                    }
                }

                // ALWAYS update poh hash — entry_hash is from leader's signed data,
                // authoritative regardless of our parse success (Opus Council decision).
                last_entry_hash = .{ .data = entry_hash };

                // d28bb-FOLLOWUP (2026-05-12): on inner-loop tx-parse failure
                // (entry_complete=false), try the SAME boundary-jump recovery
                // we use for prefix_oob. Carrier slot 407,821,292 had
                // tx_fail=1 at tx_start=277,399 with byte0=0x00 (num_sigs=0);
                // Agave parsed 615 txs vs Vexor 605 → misaligned ~1-4 bytes.
                // Linear break loses remaining txs in the slot AND propagates
                // wrong bank_hash. Jumping to next batch_complete boundary
                // resyncs to a valid component start and may recover.
                if (!entry_complete) {
                    // Anchored: a tx-parse failure means this component is corrupt
                    // past this entry — abandon the rest of the component and snap
                    // to the next boundary (comp_bi already incremented). The
                    // boundary itself is trusted, so we never re-scan for a
                    // resync point inside the same component (that re-scan was the
                    // legacy heuristic that mis-anchored the carrier).
                    if (anchored) continue :batch_loop;
                    const boundaries = component_boundaries_override;
                    var jumped = false;
                    if (boundaries.len > 0) {
                        for (boundaries) |b| {
                            if (b > offset) {
                                offset = b;
                                jumped = true;
                                break;
                            }
                        }
                    }
                    if (jumped) continue :batch_loop;
                    break :batch_loop;
                }

                // Suppress unused-variable warnings for stubs pending full wiring
                _ = tx_diag_blockhash;
                _ = tx_diag_sigfail;
                _ = tx_diag_funds;
                _ = tx_diag_acct;
                _ = tx_diag_other;
            } // end inner while (batch entries)

            // Anchored mode consumes exactly one component per outer iteration:
            // the Vec<Entry> for this component is now fully parsed (or was
            // truncated by a malformed entry above), so advance to the next
            // boundary (comp_bi already incremented at the top of the iteration).
            if (anchored) continue :batch_loop;
        } // end outer while (batches)

        // OFFLINE-ONLY diag injection (build_options.force_dead_slot; comptime-dead
        // in prod). Synthetic Shape-A kill: if this slot == VEX_FORCE_DEAD_SLOT and
        // the latch has not fired, markSlotDead PRE-FREEZE exactly as the real
        // TooFewTicks gate below does — leaving a dead+UNFROZEN bank in self.banks
        // (Shape A) — so the switch-proof Part-2 revive path can be exercised on a
        // clean slot offline. SINGLE-SHOT (force_dead_fired.swap): after revive
        // dumps + re-feeds the complete shreds, the re-replay MUST freeze normally
        // for the gate to observe last_vote advancing past the revived slot. Placed
        // here (post-batch, pre-freeze) so it fires regardless of tick count — the
        // target slot is otherwise clean (64 ticks) and would freeze.
        if (comptime build_options.force_dead_slot) {
            if (self.forceDeadSlotTarget()) |target| {
                if (bank.slot == target and !self.force_dead_fired.swap(true, .monotonic)) {
                    std.log.warn(
                        "[FORCE-DEAD-SLOT] slot={d} — VEX_FORCE_DEAD_SLOT synthetic Shape-A kill (offline diag, single-shot); markSlotDead PRE-FREEZE",
                        .{bank.slot},
                    );
                    self.verifyTicksKill(bank, "VEX_FORCE_DEAD_SLOT synthetic Shape-A kill (offline diag)");
                    return error.BadBlockTickValidity;
                }
            }
        }

        // d28dd-SHADOW (2026-05-12): TooFewTicks dead-slot gate. @prov:replay.too-few-ticks-shadow
        // Caller (onSlotCompleted) only invokes us after shred_assembler signals
        // SLOT-COMPLETED, so slot_full is implicitly true. Expected ticks per
        // slot = DEFAULT_TICKS_PER_SLOT (64 on testnet/mainnet; SIMD-326 may
        // bump for Alpenglow but not yet active).
        //
        // PR-5ae (2026-05-19): promoted from log-only SHADOW to deferred ENFORCE
        // via PR-5z pattern. Queue (slot, ticks_seen, flagged_at_ms) here;
        // on next `fetchSlotHashes` refresh, `sweepPendingTickGateSlots` re-
        // checks `getNetworkBankHash(slot) != null` (positive canonical oracle
        // — slot IS in cluster's SH → cluster considers this slot canonical
        // with a complete block). If confirmed → markSlotDead retroactively
        // (Vexor's incomplete-tick freeze was wrong). 30s timeout → drop
        // (assume canonical, current SHADOW behavior — false-negative risk
        // is preferred over FP-mark-dead risk). Carrier K (slot 409591733
        // in 2026-05-19 boot): 1 fire, TRUE positive (cluster has 584 sigs
        // for that slot; Vexor froze with 430 → incomplete-block carrier).
        // ── PHASE 3: `full` canonical TOO_FEW_TICKS. @prov:replay.tick-verify
        //    onSlotCompleted is only invoked after the shred
        //    assembler signals SLOT-COMPLETED, so this IS the fec_eos / slot-full
        //    point. Canonical: tick_cnt + tick_height < max_tick_height. Unlike
        //    the flat `< 64` deferred gate below, this is CORRECT across skipped
        //    parents (a gap-k block legitimately needs k*ticks_per_slot ticks).
        //    Marks dead EAGERLY (no deferred cluster-confirm) — this removes the
        //    flat gate's false-positive safety net, which is precisely what the
        //    `full` parity-soak measures. `full` SUPERSEDES the flat deferred
        //    gate (the flat gate is skipped in a full build to avoid a redundant
        //    + weaker second check).
        if ((comptime build_options.verify_ticks == .full) and vt_active) {
            const vt_final = vt_verifier.onSlotEnd();
            if (vt_final.isDead()) {
                self.verifyTicksKill(bank, @tagName(vt_final));
                return error.BadBlockTickValidity;
            }
        }

        // d28dd → PR-5ag-BLOCK (2026-07-14, incident 421935259): TooFewTicks
        // completeness gate, promoted from deferred-shadow to BLOCKING pre-freeze.
        //
        // WHY BLOCKING (the incident): 421935259 froze+voted on a TRUNCATED block
        // (ticks_seen=30, expected=64) because the deferred-shadow gate merely
        // QUEUED the deficit and enforced 727ms AFTER the vote shipped. Agave marks
        // an incomplete slot dead at replay (blockstore is_full / TooFewTicks)
        // BEFORE freeze/vote; repair then re-fetches the complete version and the
        // node self-recovers. We now mirror that: verifyTicksKill (markSlotDead) +
        // `return error.BadBlockTickValidity` — which propagates through
        // replayEntries to onSlotCompleted's catch (:3743) and RETURNS before
        // bank.freeze() (:4123), so the slot NEVER freezes and is NEVER voted. The
        // dead-slot machinery + repair then re-fetch canonical 259 (same path the
        // retroactive gate used, only now pre-freeze). Identical kill mechanism to
        // the .full eager path (:7842) and the final .full onSlotEnd check (:8957).
        //
        // CLAIMED-COMPLETE, not still-streaming: replayEntriesInternal is invoked
        // ONLY from onSlotCompleted, which the shred_assembler drives ONLY after it
        // signals SLOT-COMPLETED (:8927,:8944). So the slot is already CLAIMED
        // COMPLETE here; ticks_seen<expected therefore means TRUNCATED (a partial
        // FEC set falsely declared complete — the 421935259 `[SLOT-COMPLETED via
        // idx=345]` fire), never "still arriving". A still-streaming slot never
        // reaches this gate (the assembler has not yet declared it complete).
        //
        // FALSE-POSITIVE SAFETY (why the flat `< 64` threshold, not the canonical
        // window): the flat `< 64` gate is a STRICT SUBSET of the canonical FD/Agave
        // TOO_FEW_TICKS check (verify_ticks.zig onSlotEnd:
        // `tick_count + tick_height < max_tick_height`). Since (slot - parent_slot)
        // >= 1, the canonical threshold (slot-parent)*64 >= 64, so
        //   ticks_seen < 64  ⟹  ticks_seen < (slot-parent)*64  ⟹  canonical DEAD.
        // The flat gate therefore NEVER marks dead a slot Agave/FD would keep — it
        // can only UNDER-fire on gap-k deficits (still caught by .full builds, and
        // not the incident shape), never over-fire onto a canonical slot. It is also
        // parent_slot-INDEPENDENT (robust when catchup leaves parent linkage stale)
        // and is the exact predicate the FP-free d28dd shadow soak validated.
        // Superseded by the eager canonical TOO_FEW above when verify_ticks==.full.
        const EXPECTED_TICKS_PER_SLOT: u64 = 64;
        if ((comptime build_options.verify_ticks != .full) and tick_count_seen < EXPECTED_TICKS_PER_SLOT) {
            std.log.warn(
                "[TICK-GATE-BLOCK] slot={d} ticks_seen={d} expected={d} entries={d} data_len={d} offset={d} batches={d} tx_ok={d} — TooFewTicks: markSlotDead PRE-FREEZE (Agave parity; incident 421935259)",
                .{
                    bank.slot,   tick_count_seen, EXPECTED_TICKS_PER_SLOT,
                    entry_count, data.len,        offset,
                    batch_num,   tx_diag_success,
                },
            );
            self.verifyTicksKill(bank, "TooFewTicks pre-freeze completeness gate");
            return error.BadBlockTickValidity;
        }

        // Debug: test AccountsDb lookup from replay stage
        if (entry_count > 0 and tx_diag_success > 0 and self.stats.slots_replayed.load(.monotonic) < 3) {
            if (self.accounts_db) |db| {
                const test_pk = core.Pubkey{ .data = .{
                    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9,
                    0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
                    0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c,
                    0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
                } }; // Clock sysvar
                const result = db.getAccountInSlot(&test_pk, bank.slot, bank.ancestors());
                std.log.debug("[DB-TEST] slot={d} Clock lookup: {s}\n", .{
                    bank.slot, if (result != null) "FOUND" else "NULL",
                });
            }
        }

        // [BLOCK-DAG] SLOT-END DEFERRED DRAIN (gated VEX_BLOCK_DAG): execute the slot-wide DAG serially
        // in dependency order. Mirrors the per-entry serial Phase-2 drain verbatim (execute-unconditionally
        // per FIX #95; cost recorded after execute, stat-only). Conflicting txs keep block order (addTxn
        // order = parse order across entries; FIFO tie-break), so the ONLY behavioral change vs per-entry
        // is the fee/execution interleave across entries — exactly what the golden gate must judge.
        if (BlockDag.on() and blkdag_begun) {
            if (self.dag_dispatcher) |*bdisp| {
                var blk_executed: usize = 0;
                while (bdisp.getNextReady()) |txn_idx| {
                    const info = &blkdag_infos.items[blkdag_idx_map[txn_idx]];
                    if (self.accounts_db != null and info.parsed != null) {
                        const ptx = info.parsed.?;
                        const dag_tx_cost = dagTxCost(bank, &ptx);
                        if (bank_mod.TvTrace.on()) _ = bank.tvt2_dag_from_blockdag.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
                        self.executeDagTx(bank, self.accounts_db.?, arena_alloc, ancestor_slots, &ptx, blkdag_idx_map[txn_idx], info);
                        if (dag_tx_cost) |c| {
                            bank.recordTransactionCost(c);
                        } else {
                            CostNoSkip.note(bank.slot, "blockdag");
                        }
                    }
                    bdisp.completeTxn(txn_idx);
                    blk_executed += 1;
                }
                std.log.warn("[BLOCK-DAG] slot={d} deferred-drain executed={d} added={d}{s}", .{
                    bank.slot, blk_executed, blkdag_added, if (blk_executed < blkdag_added) " INCOMPLETE-ABANDON" else "",
                });
                if (blk_executed < blkdag_added) bdisp.abandonBlock() else bdisp.endBlock();
            }
        }

        if (entry_count > 0) {
            bank.has_entries = true;
            std.log.debug("[REPLAY] Parsed {d} entries from {d} bytes", .{ entry_count, data.len });
        }

        // [WAVE-WIDTH-BLOCK] dry-drain the slot-wide scratch DAG (NO execution) → block-level ceiling.
        // Each round drains the WHOLE current ready set (one dependency level) then completes it, exactly
        // like runWaveDrain's wave structure but over ALL entries at once. Fully drains → pool returns to
        // free for the next slot's beginBlock. Pure measurement; touches no bank state.
        if (self.bw_disp) |*bw| {
            if (self.bw_wavebuf.len > 0) {
                var bw_waves: u64 = 0;
                var bw_txs: u64 = 0;
                var bw_maxw: u64 = 0;
                while (true) {
                    var n: usize = 0;
                    while (bw.getNextReady()) |idx| {
                        if (n >= self.bw_wavebuf.len) break;
                        self.bw_wavebuf[n] = idx;
                        n += 1;
                    }
                    if (n == 0) break;
                    bw_waves += 1;
                    bw_txs += n;
                    if (n > bw_maxw) bw_maxw = n;
                    for (self.bw_wavebuf[0..n]) |idx| bw.completeTxn(idx);
                }
                if (bw_waves > 0) {
                    const bw_ceiling_x100: u64 = bw_txs * 100 / bw_waves;
                    std.log.warn("[WAVE-WIDTH-BLOCK] slot={d} txs={d} waves={d} ceiling_x100={d} max_width={d} overflow={d}", .{
                        bank.slot, bw_txs, bw_waves, bw_ceiling_x100, bw_maxw, @intFromBool(self.bw_overflow),
                    });
                }
            }
        }

        // Update lifetime counters for METRICS reporting
        _ = self.stats.successful_txs.fetchAdd(tx_diag_success, .monotonic);
        _ = self.stats.failed_txs.fetchAdd(tx_diag_parse_fail, .monotonic);

        // Update bank blockhash with last entry hash
        const zero_hash_2 = [_]u8{0} ** 32;
        if (!std.mem.eql(u8, &last_entry_hash.data, &zero_hash_2)) {
            bank.poh_hash = last_entry_hash;
        }

        // CRITICAL: Flush pending_writes to AccountsDb BEFORE batch_arena.deinit()
        // Vote account mutable_data is allocated from batch_arena — must be deep-copied
        // to AccountsDb's cache_arena before the arena is freed.
        if (self.accounts_db) |db| {
            flushPendingWritesToDb(bank, db);
        }

        // Stage B B2c: reset the worker arenas now that the flush has deep-copied every
        // committed write. CORRECTED LIFETIME (advisor #4): wave-executed AccountWrite.data
        // payloads are allocated from the WORKER ARENA (executors use the passed allocator,
        // NOT bank.allocator), exactly like batch_arena above — so the arenas can only be
        // dropped AFTER the flush, and only once per call (NEVER between entries within a
        // call, where prior entries' writes still sit in pending_writes). Mirrors
        // batch_arena.deinit timing. comptime-dead unless built with -Dparallel_exec.
        if (comptime build_options.parallel_exec) {
            if (self.wave_pool) |wp| wp.resetArenas();
        }
    }

    // ── Background replay worker ──────────────────────────────────────────────

    /// Background replay worker thread entry point. @prov:replay.worker-tile-name
    fn replayWorker(self: *Self) void {
        // Pin replay worker to core 16 (CCD-aware layout).
        // Phase 9: default = vex_topo table (.replay == core 16, byte-identical);
        // VEX_LEGACY_PINS / -Dlegacy_pins reverts to the inline pinToCore(16).
        if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) {
            pinToCore(16);
        } else {
            _ = vex_topo.pinTile(vex_topo.LIVE, .replay, 0);
        }
        std.log.debug("[REPLAY-WORKER] Worker thread started\n", .{});

        var slots_replayed: u64 = 0;
        var last_log_time = std.time.milliTimestamp();
        var last_pending_scan_ms: i64 = 0;

        while (self.is_running.load(.acquire)) {
            // 2026-06-16 TILE ISOLATION: drain Ring B (blocks the produce tile finished on core 20)
            // every loop iteration → run the existing loopback self-replay + G1 self-vote guard on
            // THIS (replay) thread. No-op (single null-check) when the tile isn't active → the OFF
            // path is unaffected. comptime-gated so -Dleader_mode-off prunes it entirely.
            if (comptime build_options.leader_mode) {
                if (self.produce_tile_active.load(.acquire)) self.drainProduceTileRingB();
            }

            // d27z: periodic pending-chain drain. @prov:replay.generate-new-bank-forks
            // Runs every replay iteration to discover slots whose parent
            // is now frozen / at-or-below root. Without this, slots that landed
            // in pending_chain *before* the parent-resolution condition became
            // satisfied via a non-direct path (e.g. root_bank advanced via a
            // sibling cascade) stay stuck forever. Throttled to once per 200ms
            // to bound the scan cost; pending_chain is small (~hundreds at
            // worst).
            const now_ms_scan = std.time.milliTimestamp();
            if (now_ms_scan - last_pending_scan_ms > 200) {
                last_pending_scan_ms = now_ms_scan;
                // Pass root_bank.slot as "frozen_slot" so any pending entry
                // with target_parent <= root_slot gets woken (via the new
                // <=-root branch added to checkPendingChain).
                if (self.root_bank.load(.acquire)) |rb| {
                    self.checkPendingChain(rb.slot);
                }

                // VOTE-REFRESH Tier-2 (#87, 2026-06-26): tick-level keep-alive. submitVote's refresh
                // (Tier-1) only fires when a bank freezes; during a FULL replay stall no banks freeze,
                // so the last vote would age out → delinquent. This call runs on the SAME replay thread
                // as submitVote (no tower data race) every ~200ms, and self-gates (VEX_VOTE_REFRESH +
                // 5s-no-cast + 5s-interval + blockhash-rotated) so it's dormant unless we genuinely
                // haven't cast in >5s. @prov:replay.vote-refresh-parity — runs every replay tick,
                // not only post-freeze.
                self.maybeRefreshLastVote();

                // PR-5aq (2026-05-20): proactive cluster SlotHashes refresh.
                //
                // Without this, the module-global `g_cluster_slot_hashes`
                // (PR-5ab Phase G-2 cluster fallback) stays null until
                // `getNetworkBankHash` is triggered — which only happens on
                // SHADOW/TICK-GATE/CHAINED-BLOCK-ID events. Empirically
                // (`slot-409807599.vote_mismatches.jsonl` post PR-5ap deploy):
                // 395 slots after boot all had `cluster_hash=0` → ALL 575
                // Vote writes per slot silently dropped via SH-mismatch
                // rejection. Once `fetchSlotHashes` finally fired (slot
                // 409807995), 583 votes accepted via
                // `accepted_via_cluster_fallback`, proving the fallback
                // mechanism works once warm — it just wasn't being warmed.
                //
                // Refresh gated by 5s TTL (matches getNetworkBankHash refresh
                // at line ~1126). RPC cost ~100ms; runs once every 200ms
                // drain tick → ~once per 25 ticks at steady state.
                // throughput-fix #2: the warm-keeping is now an INSTALL of the
                // async refresher's pending buffer (no blocking curl on this
                // thread); cold boot keeps the synchronous one-shot prime.
                const pending_sh: ?[]u8 = blk: {
                    self.sysvar_fetch_lock.lock();
                    defer self.sysvar_fetch_lock.unlock();
                    const p = self.pending_slot_hashes;
                    self.pending_slot_hashes = null;
                    break :blk p;
                };
                if (pending_sh) |buf| {
                    self.installSlotHashes(buf);
                } else if (self.cached_slot_hashes == null) {
                    if (self.fetchSlotHashesRemote()) |buf| self.installSlotHashes(buf);
                }
            }

            if (self.slot_queue.pop()) |msg| {
                // d24 (2026-05-11): if the producer attached an authoritative
                // parent_slot (catchup's RPC getBlock.parentSlot), surface it
                // through the threadlocal for the duration of this call so
                // getOrCreateBank can use it. Clear before returning even on
                // error so a stale value doesn't leak into the next slot.
                if (msg.parent_override) |p| catchup_parent_override = p;
                defer catchup_parent_override = null;
                // d27hh: surface per-component boundaries to replayBlock via
                // threadlocal. onSlotCompleted reads it; cleared on return.
                if (msg.boundaries.len > 0) component_boundaries_override = msg.boundaries;
                defer component_boundaries_override = &.{};

                self.onSlotCompleted(msg.slot, msg.data) catch |err| {
                    // 2026-05-25: surface silent error path — baseline had `catch {}`
                    // which hid the wedge cause for ~30min-CURRENT-then-stuck failures.
                    // Log first 20 errors per slot to identify which path fails.
                    const ScDbg = struct {
                        var n: u32 = 0;
                    };
                    if (ScDbg.n < 20) {
                        ScDbg.n += 1;
                        std.log.warn("[REPLAY-WORKER-ERR] slot={d} err={any}", .{ msg.slot, err });
                    }
                };

                // Consumer owns the buffer — free after processing
                if (msg.data.len > 0) self.allocator.free(msg.data);
                if (msg.boundaries.len > 0) self.allocator.free(msg.boundaries);

                slots_replayed += 1;

                const now = std.time.milliTimestamp();
                if (now - last_log_time > 10_000) {
                    std.log.debug("[REPLAY-WORKER] Status: {d} slots replayed, queue depth ~{d}\n", .{
                        slots_replayed, self.slot_queue.count(),
                    });
                    last_log_time = now;
                }
            } else {
                // Queue empty — sleep 1ms to avoid busy-waiting
                std.Thread.sleep(1_000_000); // 1ms
            }
        }

        std.log.debug("[REPLAY-WORKER] Worker thread shutting down ({d} slots replayed)\n", .{slots_replayed});
    }

    /// Task #71 [MEM-BREAKDOWN] (2026-06-10): once-a-minute per-subsystem memory
    /// telemetry. Reads ONLY cheap atomics / hashmap-count fields (racy unlocked
    /// reads, diagnostic-tolerant) — never walks big structures and never takes
    /// replay-path locks. Output units: MB for byte gauges, raw counts otherwise.
    ///
    /// Leak-class legend (from the 2026-06-10 live diagnosis of PID 3016250):
    ///   av_heap   = rooted AppendVec heap stores (THE leak: 64MB c_allocator
    ///               buffers, ~4MB appended/slot, never reclaimed → 28-30 GB/h)
    ///   av_app    = lifetime bytes appended (expected dirty-RSS slope of av_heap)
    ///   av_mmap   = snapshot-mmap stores (bounded, file-backed)
    ///   reclaimed = stores/bytes freed by the reclamation candidate (0 = dormant)
    /// glibc mallinfo2 (since glibc 2.33) — lets [MEM-BREAKDOWN] split malloc
    /// RSS into IN-USE (true leak candidates) vs FREE-RETAINED (arena
    /// fragmentation/retention). Fields are size_t on 64-bit.
    const MallInfo2 = extern struct {
        arena: usize, // non-mmapped space allocated (bytes)
        ordblks: usize,
        smblks: usize,
        hblks: usize, // number of mmapped regions
        hblkhd: usize, // bytes in mmapped regions (the AppendVec 64MB buffers)
        usmblks: usize,
        fsmblks: usize,
        uordblks: usize, // total allocated (in-use) bytes
        fordblks: usize, // total free (retained, not returned to OS) bytes
        keepcost: usize,
    };
    extern "c" fn mallinfo2() MallInfo2;

    // Task #71 residual-leak forensic (2026-06-10): mallinfo2 reports ONLY the
    // glibc MAIN arena — in this multithreaded process the per-thread arenas
    // are invisible to it, so `malloc_inuse` under-counts. `malloc_info(0, fp)`
    // dumps an XML breakdown of ALL arenas with per-size-class histograms.
    // Diffing two dumps fingerprints WHICH size class (→ which allocator) is
    // growing — the decisive tool for attributing the ~14 GB/hr residual that
    // no count-lens explains. Env-gated (VEX_MALLOC_INFO=1), appended to
    // /tmp/vex-malloc-info-<pid>.xml once per [MEM-BREAKDOWN] tick.
    extern "c" fn malloc_info(options: c_int, stream: *anyopaque) c_int;
    extern "c" fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
    extern "c" fn fclose(stream: *anyopaque) c_int;
    extern "c" fn fputs(s: [*:0]const u8, stream: *anyopaque) c_int;

    // Task #71 L3 split (2026-06-11): jemalloc is DT_NEEDED-linked, so its
    // mallctl is directly callable. stats.allocated = live malloc bytes;
    // stats.resident = ALL pages jemalloc holds resident (incl. dirty/frag);
    // stats.retained = virtual-only (not in RSS). The decisive number is
    // RssAnon − stats.resident = anon memory OUTSIDE jemalloc entirely
    // (Zig page_allocator raw mmaps, thread stacks) — the class the heap
    // profiler cannot see. Logged each MEM-BREAKDOWN tick.
    extern "c" fn mallctl(name: [*:0]const u8, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;

    fn jemallocStats() struct { allocated: u64, resident: u64, retained: u64 } {
        var epoch: u64 = 1;
        var sz: usize = @sizeOf(u64);
        _ = mallctl("epoch", &epoch, &sz, &epoch, @sizeOf(u64)); // refresh stats
        var allocated: usize = 0;
        var resident: usize = 0;
        var retained: usize = 0;
        sz = @sizeOf(usize);
        _ = mallctl("stats.allocated", &allocated, &sz, null, 0);
        sz = @sizeOf(usize);
        _ = mallctl("stats.resident", &resident, &sz, null, 0);
        sz = @sizeOf(usize);
        _ = mallctl("stats.retained", &retained, &sz, null, 0);
        return .{ .allocated = allocated, .resident = resident, .retained = retained };
    }

    fn dumpMallocInfo(slot: u64) void {
        if (std.posix.getenv("VEX_MALLOC_INFO") == null) return;
        var pathbuf: [128]u8 = undefined;
        const pid = std.os.linux.getpid();
        const path = std.fmt.bufPrintZ(&pathbuf, "/tmp/vex-malloc-info-{d}.xml", .{pid}) catch return;
        const fp = fopen(path.ptr, "a") orelse return;
        defer _ = fclose(fp);
        var hdr: [96]u8 = undefined;
        const h = std.fmt.bufPrintZ(&hdr, "<!-- MALLOC-INFO slot={d} -->\n", .{slot}) catch return;
        _ = fputs(h.ptr, fp);
        _ = malloc_info(0, fp);
    }

    /// apply_feature_activations port. @prov:replay.feature-activation-epoch-boundary
    /// At the FIRST bank of a new epoch, every feature account
    /// that exists and parses as PENDING (bincode Feature{activated_at: None},
    /// i.e. data[0]==0) is activated:
    ///   1. account bytes rewritten: data[0]=1, data[1..9]=bank.slot LE
    ///      (feature::to_account; lamports/owner/rent_epoch/len unchanged) —
    ///      committed through collectWrite with real old_lt/new_lt so the
    ///      boundary slot's accounts_lt_hash matches the cluster's;
    ///   2. the LIVE FeatureSet gate flips (activated at bank.slot) so
    ///      runtime/syscall gates (e.g. SIMD-0512 sol_sha512 at epoch 973)
    ///      take effect mid-run without a restart.
    /// Scope note: reserved-keys refresh + SIMD-0437 rent gates from the
    /// same upstream function are separate ports (tasks #68/#69) — not pending
    /// on testnet at the next boundary.
    ///
    /// ⚠ SIMD-0437 HELD (task #69, watch-item, NOT wired here — see
    /// src/vex_svm/native/kat_simd0437_rent.zig + SIMD-0437-RC1-PORT-SPEC).
    /// When any of features.SET_LAMPORTS_PER_BYTE_TO_{6333,5080,2575,1322,696} is
    /// scheduled to activate, this function must (a) detect which of those 5 gates
    /// activate THIS boundary, (b) set rent.lamports_per_byte to the array-selected
    /// value (iterate [6333,5080,2575,1322,696], lowest-active wins), and (c)
    /// re-serialize the SysvarRent111 account back to AccountsDb via collectWrite
    /// (the NEW mechanism Vexor lacks). PREREQUISITE: SIMD-0194 threshold
    /// deprecation must apply FIRST (threshold→1.0, byte data[8..16]=0x3FF0…),
    /// else the boundary slot diverges. The KAT pins the 17-byte format + selection
    /// rule; the boundary write only proves out at a real activation (offline-replay).
    fn applyNewFeatureActivations(self: *Self, bank: *Bank) !void {
        const db = self.accounts_db orelse return;
        const fs = self.live_feature_set orelse return;

        for (features_mod.KNOWN_FEATURES) |kf| {
            const key = Pubkey{ .data = kf.pubkey };
            const view = db.getAccountInSlot(&key, bank.slot, bank.ancestors()) orelse continue;
            switch (features_mod.parseFeatureAccount(view.data, view.owner.data)) {
                .pending => {},
                else => continue,
            }

            // Rewrite the account bytes exactly like feature::to_account:
            // discriminant 0→1, slot LE; everything else preserved (incl. any
            // tail beyond the 9 canonical bytes — bincode keeps account len).
            const new_data = bank.allocator.alloc(u8, view.data.len) catch return;
            @memcpy(new_data, view.data);
            new_data[0] = 1;
            std.mem.writeInt(u64, new_data[1..9], bank.slot, .little);

            const old_lt = Bank.accountLtHash(&kf.pubkey, &view.owner.data, view.lamports, view.executable, view.data);
            const new_lt = Bank.accountLtHash(&kf.pubkey, &view.owner.data, view.lamports, view.executable, new_data);
            try bank.collectWrite(.{
                .pubkey = key,
                .lamports = view.lamports,
                .owner = view.owner,
                .executable = view.executable,
                .rent_epoch = view.rent_epoch,
                .data = new_data,
                .old_lt = old_lt,
                .new_lt = new_lt,
            });

            // Flip the LIVE gate. EVERY known feature is pre-seeded into the map
            // at boot (FeatureSet.seedKnownFeaturesDisabled, called from
            // loadFromAccountsDb), so getPtr ALWAYS hits here for a KNOWN_FEATURES
            // entry → in-place value overwrite, no allocation/rehash (the map's
            // backing allocator belongs to main()). This is the path that lets a
            // feature whose ACCOUNT was created after boot (e.g. SIMD-0449) flip
            // its runtime gate mid-run without a restart.
            if (fs.slots.getPtr(kf.pubkey)) |v| {
                v.* = bank.slot;
            } else {
                // Defensive/unreachable for KNOWN_FEATURES (all pre-seeded). Would
                // only trigger if a feature account on-chain is NOT in
                // KNOWN_FEATURES — in which case the gate has no consumer anyway.
                // Account bytes above stay canonical (hash parity holds).
                std.log.warn("[FEATURE-ACTIVATE] {s} activated at slot={d} but NOT in boot map — in-memory gate stale until restart", .{ kf.name, bank.slot });
            }
            std.log.warn("[FEATURE-ACTIVATE] {s} activated at slot={d} (epoch boundary, account rewritten)", .{ kf.name, bank.slot });
        }
    }

    fn emitMemBreakdown(self: *Self, slot: u64) void {
        const acc = vex_store.accounts;
        const mb = 1024 * 1024;

        // /proc/self/status: VmRSS / RssAnon / RssFile (kB). Best-effort.
        var rss_kb: u64 = 0;
        var anon_kb: u64 = 0;
        var file_kb: u64 = 0;
        if (std.fs.cwd().openFile("/proc/self/status", .{})) |f| {
            defer f.close();
            var sbuf: [4096]u8 = undefined;
            const n = f.readAll(&sbuf) catch 0;
            var lines = std.mem.tokenizeScalar(u8, sbuf[0..n], '\n');
            while (lines.next()) |line| {
                inline for (.{ .{ "VmRSS:", &rss_kb }, .{ "RssAnon:", &anon_kb }, .{ "RssFile:", &file_kb } }) |pair| {
                    if (std.mem.startsWith(u8, line, pair[0])) {
                        var toks = std.mem.tokenizeAny(u8, line[pair[0].len..], " \tkB");
                        if (toks.next()) |t| pair[1].* = std.fmt.parseInt(u64, t, 10) catch 0;
                    }
                }
            }
        } else |_| {}

        // Bank lifecycle gauges (unlocked count reads — tolerable for diag).
        const banks_n = self.banks.count();
        const pool_n = self.bank_pool.items.len;
        const dropped_n = self.dropped_banks.items.len;

        // malloc-level split: in-use vs free-retained. Walks arena bins —
        // sub-ms, fine once per minute. (mallinfo2 reads ~0 under jemalloc;
        // kept for glibc fallback builds.)
        const mi = mallinfo2();

        // jemalloc-native stats + THE L3 SPLIT: nonje_mb = RssAnon minus
        // jemalloc-resident = anon outside jemalloc (page_allocator/stacks).
        const je = jemallocStats();
        const nonje_mb: u64 = (anon_kb * 1024 -| je.resident) / mb;

        if (self.accounts_db) |db| {
            std.log.warn(
                "[MEM-BREAKDOWN] slot={d} rss_mb={d} anon_mb={d} file_mb={d} | je_alloc_mb={d} je_resident_mb={d} je_retained_mb={d} NONJE_mb={d} | malloc_inuse_mb={d} malloc_free_mb={d} malloc_mmap_mb={d} | av_heap={d}cnt/{d}MB app={d}MB reclaimed={d}cnt/{d}MB av_mmap={d}cnt/{d}MB stores={d} s2s={d} | unflushed={d} csm={d} index={d} sigov={d} ring={d} topv={d} | banks={d} pool={d} dropped={d}",
                .{
                    slot,
                    rss_kb / 1024,
                    anon_kb / 1024,
                    file_kb / 1024,
                    je.allocated / mb,
                    je.resident / mb,
                    je.retained / mb,
                    nonje_mb,
                    mi.uordblks / mb,
                    mi.fordblks / mb,
                    mi.hblkhd / mb,
                    acc.g_av_heap_count.load(.monotonic),
                    acc.g_av_heap_cap_bytes.load(.monotonic) / mb,
                    acc.g_av_appended_bytes.load(.monotonic) / mb,
                    acc.g_av_reclaimed_count.load(.monotonic),
                    acc.g_av_reclaimed_bytes.load(.monotonic) / mb,
                    acc.g_av_mmap_count.load(.monotonic),
                    acc.g_av_mmap_bytes.load(.monotonic) / mb,
                    db.storage.stores.count(),
                    db.storage.slot_to_store.count(),
                    db.unflushed_cache.count(),
                    db.cache_slot_map.count(),
                    db.index.totalCount(),
                    db.sig_overlay.approxEntries(),
                    db.unrooted_ring.approxEntries(),
                    db.top_votes.count(),
                    banks_n,
                    pool_n,
                    dropped_n,
                },
            );
        } else {
            std.log.warn(
                "[MEM-BREAKDOWN] slot={d} rss_mb={d} anon_mb={d} file_mb={d} | av_heap={d}cnt/{d}MB app={d}MB | banks={d} pool={d} dropped={d} (db unwired)",
                .{
                    slot,
                    rss_kb / 1024,
                    anon_kb / 1024,
                    file_kb / 1024,
                    acc.g_av_heap_count.load(.monotonic),
                    acc.g_av_heap_cap_bytes.load(.monotonic) / mb,
                    acc.g_av_appended_bytes.load(.monotonic) / mb,
                    banks_n,
                    pool_n,
                    dropped_n,
                },
            );
        }
    }

    fn pruneOldBanks(self: *Self, cutoff_slot: u64) void {
        var to_drop = std.ArrayListUnmanaged(*Bank){};
        defer to_drop.deinit(self.allocator);

        {
            self.banks_lock.lock();
            defer self.banks_lock.unlock();

            // Task #14 UAF guard (2026-06-16): never free an epoch-boundary bank that
            // OWNS its stake_reward_partitions slice while the multi-slot distribution
            // window is still live relative to the advancing root — a tail child bank
            // (owns=false, inherited pointer) may still be iterating that slice inside
            // distributePartitionedRewards()→freeze(). Deferring keeps the owner bank in
            // the map ~num_reward_partitions slots longer (the benign, less-aggressive
            // direction w.r.t. the F3 over-prune class); once the root's block_height
            // passes window_end, the owner is re-selected here next prune cycle and
            // released normally (single owner-free, fork-safe). If the root bank is
            // unknown, defer (never free on an unknown root).
            const tip_block_height: ?u64 =
                if (self.root_bank.load(.acquire)) |rb| rb.block_height else null;
            var it = self.banks.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* < cutoff_slot) {
                    const bank = entry.value_ptr.*;
                    if (bank.owns_stake_reward_partitions) {
                        if (tip_block_height) |tbh| {
                            if (bank.rewardDistributionWindowLive(tbh)) continue;
                        } else {
                            continue; // unknown root → defer the owner bank
                        }
                    }
                    to_drop.append(self.allocator, bank) catch continue;
                }
            }
            for (to_drop.items) |bank| {
                _ = self.banks.remove(bank.slot);
            }
        }

        // d27f: recycle pruned banks into the pool instead of destroying.
        for (to_drop.items) |bank| {
            self.releaseBank(bank);
        }

        if (to_drop.items.len > 0) {
            std.log.debug("[BANK-PRUNE] Pruned {d} banks older than slot {d}, remaining={d}\n", .{
                to_drop.items.len,
                cutoff_slot,
                self.banks.count(),
            });
        }
    }

    // ── Catch-up replay ───────────────────────────────────────────────────────

    /// Replay all confirmed slots from [from_slot, to_slot] using RPC getBlock.
    ///
    /// This bridges the gap between the snapshot slot and the live tip.
    /// Without this, the first live slot has:
    ///   - Wrong parent_hash (snapshot's bank_hash instead of tip-1's bank_hash)
    ///   - Wrong LtHash (snapshot's accumulator instead of tip-1's accumulator)
    ///
    /// Both are SHA256 inputs → avalanche effect → every live slot's bank_hash
    /// is completely uncorrelated with the network's.
    ///
    /// Algorithm:
    ///   1. getBlocks(from_slot, to_slot) → confirmed slot list (skipped slots excluded)
    ///   2. For each confirmed slot, getBlock(slot, base64) → wire-format transactions
    ///   3. Assemble entry payload and call onSlotCompleted (full TX execution path)
    ///   4. After all slots, root_bank has correct parent_hash + LtHash for live replay
    // ── Parallel catchup-fetch infrastructure ────────────────────────────────
    // GATED OFF (USE_PARALLEL_CATCHUP=false) on 2026-05-05 after both 5a5e6b87
    // (8 workers) and 91d4e636 (2 workers) wedged with the same fingerprint:
    // low voluntary_ctxt_switches, high nonvoluntary_ctxt_switches, silent log,
    // active CPU, post-catchup. Diagnostic gold from 91d4e636's enhanced
    // num_hashes warning showed the wedge fires on `source=live-tvu` (NOT
    // catchup-rpc) at slots 406269631 + 406269641 — meaning the wedge is in the
    // post-catchup TVU shred-ingestion path, NOT in the parallel fetch itself.
    // Hypothesis: the parallel-fetch coordination state (FetchCtx mutex/condvar)
    // leaves the validator in a subtly-different post-catchup state than
    // sequential, which prevents recovery when TVU later hits a transient
    // bad-shred condition that 3492d55f's sequential path recovers from cleanly.
    //
    // Infrastructure PRESERVED below (FetchCtx, parallelFetchWorker) so the
    // work isn't lost — flip USE_PARALLEL_CATCHUP=true to re-enable once we've
    // root-caused the post-catchup-state difference. See vault/diag/91d4e636_
    // wedge_2026_05_05/ for the diagnostic capture + slot decode work.
    // r75-bug-class-d13 (2026-05-09): re-enable parallel catchup with 6 workers
    // for diagnostic-only run (we need probe to fire at slot 448,662; the
    // post-catchup TVU wedge gated this off in 2026-05-05 doesn't affect probe
    // capture). 60s curl timeout to handle public testnet RPC latency.
    // d18-revert (2026-05-11): the d13 diagnostic flip was never reverted; live
    // soaks since 2026-05-09 inherited the wedge-prone parallel path → 574-slot
    // catchup-to-tip transition gap → broken parent_bank_hash chain → permanent
    // divergence. Restoring the 2026-05-05 anchor (bf8bdc98) — sequential only.
    // Per vault/feedback_anchor_bf8bdc98_shelve_catchup_2026_05_05.md +
    // vault/FAST_CATCHUP_IS_SLOW_CATCHUP_2026_05_05.md: snapshot+TVU+repair on
    // modern hw fills the gap faster than serialized RPC catchup. Don't iterate
    // on parallel catchup without [SLOT-PROFILE] always-on timing instrumentation.
    // d26-revert (2026-05-11): tried USE_PARALLEL_CATCHUP=true after d24+d25
    // (hypothesis: d19's wedge premise doesn't apply with queue isolation).
    // EMPIRICAL RESULT: per-slot replay times jumped from d25's p50=44ms
    // (replay=30ms, freeze=10ms) to 1800-4100ms (replay=900-3200ms,
    // freeze=16-2700ms) — 30-100x slowdown in replayWorker. Not a hard wedge
    // but a severe contention degradation. Cause not pinpointed in this
    // session — candidates: 6 curl-fork subprocesses hammering allocator,
    // shared HTTP client state, accountsdb cache contention. The d19 revert
    // was correct. KEEP THIS FALSE until the contention is root-caused
    // (probably needs a dedicated per-worker arena allocator and
    // per-worker HTTP client).
    const USE_PARALLEL_CATCHUP: bool = false;
    const FETCH_WORKERS: usize = 6;
    const MAX_INFLIGHT: usize = FETCH_WORKERS * 3;

    const FetchSlot = union(enum) {
        pending,
        ok: FetchedBlock, // owned payload + parent_slot (caller frees payload)
        err: anyerror,
    };

    const FetchCtx = struct {
        allocator: std.mem.Allocator,
        rpc_url: []const u8,
        slots: []const u64,
        results: []FetchSlot,
        next_to_fetch: usize, // mutex-guarded — index of next slot to claim
        next_to_consume: usize, // mutex-guarded — index of next slot main thread will apply
        mutex: std.Thread.Mutex,
        cond_work: std.Thread.Condition,
        cond_result: std.Thread.Condition,
        shutdown: std.atomic.Value(bool),
    };

    fn parallelFetchWorker(ctx: *FetchCtx) void {
        // Phase-1 topo rework (2026-06-22): DORMANT pin for revival-correctness.
        // This worker is dead today (USE_PARALLEL_CATCHUP=false → never spawned).
        // If re-enabled, these bursty I/O (curl/RPC fetch) workers must NOT float
        // onto the hot pipeline (replay 16 / verify 8-15 / produce 20); pin to cold
        // CCX0 (vex_topo.COLD_CCX0_RELIEF, core 1) which is OFF the hot pipeline and
        // inside the widened taskset. Pin never executes live (dead path); it only
        // ensures a future revival inherits a collision-free home, not a float.
        pinToCore(vex_topo.COLD_CCX0_RELIEF[0]);
        while (true) {
            ctx.mutex.lock();
            const my_idx = blk: {
                while (true) {
                    if (ctx.shutdown.load(.acquire)) {
                        ctx.mutex.unlock();
                        return;
                    }
                    if (ctx.next_to_fetch >= ctx.slots.len) {
                        ctx.mutex.unlock();
                        return; // all work claimed
                    }
                    // Backpressure: pause if we'd run too far ahead of the consumer
                    const inflight = ctx.next_to_fetch - ctx.next_to_consume;
                    if (inflight < MAX_INFLIGHT) break :blk ctx.next_to_fetch;
                    ctx.cond_work.wait(&ctx.mutex);
                }
            };
            ctx.next_to_fetch = my_idx + 1;
            const my_slot = ctx.slots[my_idx];
            ctx.mutex.unlock();

            // Fetch outside the lock.
            const result: FetchSlot = blk: {
                const fetched = catchUpFetchBlock(ctx.allocator, undefined, ctx.rpc_url, my_slot) catch |err| {
                    break :blk FetchSlot{ .err = err };
                };
                break :blk FetchSlot{ .ok = fetched };
            };

            ctx.mutex.lock();
            ctx.results[my_idx] = result;
            ctx.cond_result.broadcast();
            ctx.mutex.unlock();
        }
    }

    pub fn catchUpReplay(self: *Self, rpc_url: []const u8, from_slot: u64, to_slot: u64) !u64 {
        if (from_slot > to_slot) return 0;

        std.log.warn("[CATCHUP] Starting catch-up replay: slots {d}..{d} ({d} slots max)", .{
            from_slot, to_slot, to_slot - from_slot + 1,
        });

        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();

        // Step 1: Get list of confirmed (non-skipped) slots in range.
        // getBlocks returns only slots that had blocks produced.
        const confirmed_slots = try catchUpFetchConfirmedSlots(self.allocator, &http_client, rpc_url, from_slot, to_slot);
        defer self.allocator.free(confirmed_slots);

        std.log.warn("[CATCHUP] {d} confirmed slots out of {d} in range — sequential fetch (parallel disabled per 91d4e636 wedge investigation)", .{
            confirmed_slots.len, to_slot - from_slot + 1,
        });

        if (confirmed_slots.len == 0) return 0;

        // Throttle progress logs at high slot counts to avoid stderr saturation.
        const progress_interval: usize = if (confirmed_slots.len > 5000) 500 else 50;

        // Suppress vote submission during catch-up — historical slots are rejected by network.
        const saved_secret = self.identity_secret;
        const saved_vote_account = self.vote_account;
        self.identity_secret = null; // suspend voting
        self.fast_catchup = true;

        var replayed: u64 = 0;
        var failed: u64 = 0;

        if (USE_PARALLEL_CATCHUP) {
            // ── PARALLEL PATH (currently disabled) ──────────────────────────
            // Preserved infrastructure — re-enable by flipping USE_PARALLEL_CATCHUP=true
            // ONLY after root-causing the post-catchup TVU wedge documented in
            // vault/diag/91d4e636_wedge_2026_05_05/.
            const results = try self.allocator.alloc(FetchSlot, confirmed_slots.len);
            defer self.allocator.free(results);
            @memset(results, FetchSlot{ .pending = {} });

            var ctx = FetchCtx{
                .allocator = self.allocator,
                .rpc_url = rpc_url,
                .slots = confirmed_slots,
                .results = results,
                .next_to_fetch = 0,
                .next_to_consume = 0,
                .mutex = .{},
                .cond_work = .{},
                .cond_result = .{},
                .shutdown = std.atomic.Value(bool).init(false),
            };

            var workers: [FETCH_WORKERS]std.Thread = undefined;
            var spawned: usize = 0;
            for (&workers) |*w| {
                w.* = std.Thread.spawn(.{}, parallelFetchWorker, .{&ctx}) catch break;
                spawned += 1;
            }
            if (spawned == 0) return error.NoWorkersSpawned;

            defer {
                ctx.shutdown.store(true, .release);
                ctx.mutex.lock();
                ctx.cond_work.broadcast();
                ctx.mutex.unlock();
                for (workers[0..spawned]) |w| w.join();
                for (results) |r| switch (r) {
                    .ok => |fb| self.allocator.free(fb.payload),
                    else => {},
                };
            }

            for (confirmed_slots, 0..) |slot, idx| {
                if (idx % progress_interval == 0 or idx == confirmed_slots.len - 1) {
                    std.log.warn("[CATCHUP] Progress: {d}/{d} slots (last replayed: {d})", .{
                        idx, confirmed_slots.len, slot,
                    });
                }

                ctx.mutex.lock();
                while (ctx.results[idx] == .pending) {
                    ctx.cond_result.wait(&ctx.mutex);
                }
                const result = ctx.results[idx];
                ctx.results[idx] = .pending;
                ctx.next_to_consume = idx + 1;
                ctx.cond_work.broadcast();
                ctx.mutex.unlock();

                switch (result) {
                    .err => |e| {
                        std.log.debug("[CATCHUP] Failed to fetch slot {d}: {any} — skipping\n", .{ slot, e });
                        failed += 1;
                    },
                    .ok => |fb| {
                        // d24 (2026-05-11): route via SlotQueue MPSC so the
                        // background catchup thread doesn't race replayWorker
                        // on onSlotCompleted (d17 invariant: replayWorker is
                        // sole onSlotCompleted caller). parent_override
                        // carries d22c's RPC parentSlot through to
                        // getOrCreateBank via the threadlocal that
                        // replayWorker sets per-message.
                        if (!self.pushSlotForReplayWithParent(slot, fb.payload, fb.parent_slot)) {
                            // shutdown — buffer never landed in queue; free
                            if (fb.payload.len > 0) self.allocator.free(fb.payload);
                            std.log.debug("[CATCHUP] Push failed for slot {d} (shutdown?) — skipping\n", .{slot});
                            failed += 1;
                            continue;
                        }
                        // ownership transferred to queue; replayWorker frees
                        replayed += 1;
                    },
                    .pending => unreachable,
                }
            }
        } else {
            // ── SEQUENTIAL PATH (3492d55f's proven-good shape) ──────────────
            // Restored 2026-05-05 after parallel-fetch wedge investigation.
            // Slower per-slot (~1.3 sec each via curl-subprocess + RPC), but
            // recovers cleanly from transient [REPLAY] suspicious entries that
            // wedged 5a5e6b87 + 91d4e636. Per-iteration apply runs immediately
            // after fetch, no coordination state to leak into post-catchup TVU.
            // d27j (2026-05-11): fetch_ms probe — measure RPC fetch time per
            // slot vs replay time to confirm whether the bottleneck is
            // RPC-bound (fetch_ms >> replay_ms) or coordination-bound
            // (fetch_ms small but queue drains between fetches).
            var fetch_ms_sum: i64 = 0;
            var fetch_ms_max: i64 = 0;
            var fetch_ms_count: u64 = 0;
            for (confirmed_slots, 0..) |slot, idx| {
                if (idx % progress_interval == 0 or idx == confirmed_slots.len - 1) {
                    const avg_fetch: i64 = if (fetch_ms_count > 0) @divTrunc(fetch_ms_sum, @as(i64, @intCast(fetch_ms_count))) else 0;
                    std.log.warn("[CATCHUP] Progress: {d}/{d} slots (last replayed: {d}) fetch_ms avg={d} max={d}", .{
                        idx, confirmed_slots.len, slot, avg_fetch, fetch_ms_max,
                    });
                    // Reset rolling window so each progress line reflects recent slots
                    fetch_ms_sum = 0;
                    fetch_ms_max = 0;
                    fetch_ms_count = 0;
                }

                const fetch_t0 = std.time.milliTimestamp();
                const fetched = catchUpFetchBlock(self.allocator, &http_client, rpc_url, slot) catch |err| {
                    std.log.debug("[CATCHUP] Failed to fetch slot {d}: {any} — skipping\n", .{ slot, err });
                    failed += 1;
                    continue;
                };
                const fetch_ms: i64 = std.time.milliTimestamp() - fetch_t0;
                fetch_ms_sum += fetch_ms;
                if (fetch_ms > fetch_ms_max) fetch_ms_max = fetch_ms;
                fetch_ms_count += 1;

                // d24 (2026-05-11): route catchup-fetched slots through the
                // SlotQueue MPSC instead of calling onSlotCompleted directly.
                // This lets the catchup function run in a background thread
                // without racing replayWorker on shared per-bank state
                // (d17 invariant: replayWorker is sole onSlotCompleted caller).
                // parent_override threads d22c's authoritative RPC parentSlot
                // through to getOrCreateBank via the per-message threadlocal
                // that replayWorker sets/clears around each onSlotCompleted.
                if (!self.pushSlotForReplayWithParent(slot, fetched.payload, fetched.parent_slot)) {
                    // shutdown — buffer never landed in queue; free
                    if (fetched.payload.len > 0) self.allocator.free(fetched.payload);
                    std.log.debug("[CATCHUP] Push failed for slot {d} (shutdown?) — skipping\n", .{slot});
                    failed += 1;
                    continue;
                }
                // ownership transferred to queue; replayWorker frees
                replayed += 1;
            }
        }

        // Restore voting
        self.identity_secret = saved_secret;
        self.vote_account = saved_vote_account;
        self.fast_catchup = false;

        const root_slot = if (self.root_bank.load(.acquire)) |rb| rb.slot else 0;
        std.log.warn("[CATCHUP] Complete: {d} replayed, {d} failed. Root bank now at slot {d}", .{
            replayed, failed, root_slot,
        });

        return replayed;
    }

    /// curl-subprocess JSON-RPC POST. Used in place of std.http.Client.fetch
    /// because Zig 0.15.2's flate.Decompress hits unreachable when paired with
    /// std.Io.Writer.Allocating, and api.testnet.solana.com gzips responses
    /// regardless of Accept-Encoding: identity. curl handles streaming bodies
    /// of arbitrary size and never invokes the broken decoder.
    /// Caller frees the returned buffer.
    fn curlRpcPost(allocator: std.mem.Allocator, rpc_url: []const u8, body: []const u8) ![]u8 {
        const argv = [_][]const u8{
            "/usr/bin/curl", "-s",                             "-m", "60", "-X",    "POST",
            "-H",            "Content-Type: application/json", "-d", body, rpc_url,
        };
        var child = std.process.Child.init(&argv, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        try child.spawn();

        var resp = std.ArrayListUnmanaged(u8){};
        errdefer resp.deinit(allocator);
        var buf: [16384]u8 = undefined;
        while (true) {
            const n = child.stdout.?.read(&buf) catch break;
            if (n == 0) break;
            try resp.appendSlice(allocator, buf[0..n]);
        }
        _ = child.wait() catch {};
        return resp.toOwnedSlice(allocator);
    }

    /// Fetch confirmed slot list via getBlocks RPC.
    /// Returns a heap-allocated slice (caller frees).
    fn catchUpFetchConfirmedSlots(
        allocator: std.mem.Allocator,
        http_client: *std.http.Client,
        rpc_url: []const u8,
        from_slot: u64,
        to_slot: u64,
    ) ![]u64 {
        _ = http_client;

        // r75-bug-class-d13 (2026-05-09): chunk getBlocks into 500-slot windows.
        // Empirical test: testnet RPC times out (30s) on 5000-slot range with
        // empty body, but happily serves 100-500 slot ranges. Tighter chunks
        // also unblock retries: a single failed chunk costs ~1.5s instead of
        // 90s+. With 100 chunks for 50k slots and ~1s/chunk we expect ~2 min
        // to complete the slot-list fetch.
        const CHUNK: u64 = 500;
        const MAX_RETRIES: u8 = 3;

        var all_slots = std.ArrayListUnmanaged(u64){};
        errdefer all_slots.deinit(allocator);

        var chunk_start = from_slot;
        while (chunk_start <= to_slot) : (chunk_start += CHUNK) {
            const chunk_end = @min(chunk_start + CHUNK - 1, to_slot);

            var attempt: u8 = 0;
            const slots_chunk: []u64 = while (attempt < MAX_RETRIES) : (attempt += 1) {
                const body = try std.fmt.allocPrint(allocator,
                    \\{{"jsonrpc":"2.0","id":1,"method":"getBlocks","params":[{d},{d}]}}
                , .{ chunk_start, chunk_end });
                defer allocator.free(body);

                const response = curlRpcPost(allocator, rpc_url, body) catch |e| {
                    std.log.warn("[CATCHUP] getBlocks {d}..{d} curl error {any} (retry {d}/{d})", .{ chunk_start, chunk_end, e, attempt + 1, MAX_RETRIES });
                    continue;
                };
                defer allocator.free(response);

                const parsed = std.json.parseFromSlice(std.json.Value, allocator, response, .{}) catch |e| {
                    std.log.warn("[CATCHUP] getBlocks {d}..{d} json parse error {any} (resp_len={d}, retry {d}/{d})", .{ chunk_start, chunk_end, e, response.len, attempt + 1, MAX_RETRIES });
                    continue;
                };
                defer parsed.deinit();

                const result = parsed.value.object.get("result") orelse {
                    std.log.warn("[CATCHUP] getBlocks {d}..{d} no result field (retry {d}/{d})", .{ chunk_start, chunk_end, attempt + 1, MAX_RETRIES });
                    continue;
                };
                if (result != .array) continue;
                const arr = result.array;

                const out = try allocator.alloc(u64, arr.items.len);
                for (arr.items, 0..) |item, i| {
                    out[i] = @intCast(item.integer);
                }
                break out;
            } else {
                std.log.warn("[CATCHUP] getBlocks {d}..{d} EXHAUSTED retries — continuing with empty chunk", .{ chunk_start, chunk_end });
                continue;
            };
            defer allocator.free(slots_chunk);

            try all_slots.appendSlice(allocator, slots_chunk);
        }

        return all_slots.toOwnedSlice(allocator);
    }

    /// Fetch a single block from RPC and assemble an entry payload for onSlotCompleted.
    ///
    /// Entry payload format (matches replayEntriesInternal parser):
    ///   [count:u64LE][num_hashes:u64LE][blockhash:32bytes][num_txs:u64LE][tx0...txN]
    ///
    /// The blockhash field is the slot's last entry hash. @prov:replay.cached-blockhash-poh
    /// This is what sets bank.poh_hash in replayEntriesInternal.
    ///
    /// Returns a heap-allocated payload (caller frees).
    /// d22c (2026-05-11): catchup fetch result includes RPC's authoritative
    /// `parentSlot` field so getOrCreateBank can chain banks correctly across
    /// cluster-skipped slots (e.g. when slot N's actual parent is N-2 because
    /// slot N-1 was never produced by its leader).
    pub const FetchedBlock = struct {
        payload: []u8,
        parent_slot: u64,
    };

    fn catchUpFetchBlock(
        allocator: std.mem.Allocator,
        http_client: *std.http.Client,
        rpc_url: []const u8,
        slot: u64,
    ) !FetchedBlock {
        _ = http_client;
        const body = try std.fmt.allocPrint(allocator,
            \\{{"jsonrpc":"2.0","id":1,"method":"getBlock","params":[{d},{{"encoding":"base64","transactionDetails":"full","rewards":false,"maxSupportedTransactionVersion":0}}]}}
        , .{slot});
        defer allocator.free(body);

        const response = try curlRpcPost(allocator, rpc_url, body);
        defer allocator.free(response);

        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response, .{});
        defer parsed.deinit();

        // Check for RPC error
        if (parsed.value.object.get("error")) |err_val| {
            _ = err_val;
            return error.RpcBlockError;
        }

        const result = parsed.value.object.get("result") orelse return error.RpcMissingResult;
        if (result == .null) return error.RpcSkippedSlot;

        // d22c: extract authoritative parent_slot. @prov:replay.parent-slot-source Falls
        // back to slot-1 only if RPC response somehow missing the field
        // (shouldn't happen, but defensive).
        const parent_slot: u64 = if (result.object.get("parentSlot")) |ps_val|
            @intCast(ps_val.integer)
        else
            (if (slot > 0) slot - 1 else 0);

        // Extract blockhash (last_blockhash = poh_hash)
        var blockhash_bytes: [32]u8 = [_]u8{0} ** 32;
        if (result.object.get("blockhash")) |bh_val| {
            const bh_str = bh_val.string;
            // Decode base58 blockhash
            catchUpDecodeBase58(bh_str, &blockhash_bytes) catch {
                // On decode failure, leave as zero — replayEntriesInternal skips zero poh_hash
                std.log.debug("[CATCHUP] Warning: Failed to decode blockhash for slot {d}\n", .{slot});
            };
        }

        // Collect all raw transaction bytes from base64-encoded wire format
        const transactions_val = result.object.get("transactions") orelse {
            // No transactions: empty block. Still need the poh_hash entry.
            const empty_payload = try catchUpBuildPayload(allocator, &blockhash_bytes, &[_][]u8{});
            return FetchedBlock{ .payload = empty_payload, .parent_slot = parent_slot };
        };

        var tx_bufs = std.ArrayListUnmanaged([]u8){};
        defer {
            for (tx_bufs.items) |buf| allocator.free(buf);
            tx_bufs.deinit(allocator);
        }

        for (transactions_val.array.items) |tx_item| {
            // transaction field: array where [0] is base64 tx bytes, [1] is encoding string
            const tx_field = tx_item.object.get("transaction") orelse continue;
            const b64_str = tx_field.array.items[0].string;

            const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64_str) catch continue;
            const decoded = allocator.alloc(u8, decoded_len) catch continue;
            std.base64.standard.Decoder.decode(decoded, b64_str) catch {
                allocator.free(decoded);
                continue;
            };
            try tx_bufs.append(allocator, decoded);
        }

        const built = try catchUpBuildPayload(allocator, &blockhash_bytes, tx_bufs.items);
        return FetchedBlock{ .payload = built, .parent_slot = parent_slot };
    }

    /// Build entry payload for onSlotCompleted from decoded transaction bytes.
    fn catchUpBuildPayload(
        allocator: std.mem.Allocator,
        blockhash: *const [32]u8,
        txs: []const []u8,
    ) ![]u8 {
        // Calculate total size:
        // [batch_count:8] [num_hashes:8] [hash:32] [num_txs:8] [tx0...txN]
        var total_tx_size: usize = 0;
        for (txs) |tx| total_tx_size += tx.len;

        const payload_size = 8 + 8 + 32 + 8 + total_tx_size;
        const payload = try allocator.alloc(u8, payload_size);

        var pos: usize = 0;

        // batch_count = 1 (one batch with one entry)
        std.mem.writeInt(u64, payload[pos..][0..8], 1, .little);
        pos += 8;

        // Entry: num_hashes = 1 (arbitrary, poh hash chain; we set it to 1 as placeholder)
        std.mem.writeInt(u64, payload[pos..][0..8], 1, .little);
        pos += 8;

        // Entry: hash = blockhash (this becomes bank.poh_hash)
        @memcpy(payload[pos..][0..32], blockhash);
        pos += 32;

        // Entry: num_txs
        std.mem.writeInt(u64, payload[pos..][0..8], @intCast(txs.len), .little);
        pos += 8;

        // Transactions (concatenated wire bytes)
        for (txs) |tx| {
            @memcpy(payload[pos..][0..tx.len], tx);
            pos += tx.len;
        }

        return payload;
    }
};

/// Decode a base58 string into a 32-byte array.
/// Uses the Bitcoin/Solana base58 alphabet.
fn catchUpDecodeBase58(b58: []const u8, out: *[32]u8) !void {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Build lookup table
    var lookup: [256]u8 = [_]u8{255} ** 256;
    for (alphabet, 0..) |c, i| lookup[c] = @intCast(i);

    // Count leading '1's (leading zero bytes)
    var leading_zeros: usize = 0;
    for (b58) |c| {
        if (c != '1') break;
        leading_zeros += 1;
    }

    // Decode into big-endian bytes
    var num: [64]u8 = [_]u8{0} ** 64;
    const num_len: usize = 64;

    for (b58) |c| {
        const digit = lookup[c];
        if (digit == 255) return error.InvalidBase58Char;

        var carry: u32 = digit;
        var i: usize = num_len;
        while (i > 0) {
            i -= 1;
            carry += @as(u32, num[i]) * 58;
            num[i] = @intCast(carry & 0xff);
            carry >>= 8;
        }
        if (carry != 0) return error.Base58Overflow;
    }

    // Find start of result (skip leading zeros)
    var start: usize = 0;
    while (start < num_len and num[start] == 0) start += 1;

    const result_len = num_len - start;
    if (result_len + leading_zeros != 32) return error.Base58WrongLength;

    @memset(out[0..leading_zeros], 0);
    @memcpy(out[leading_zeros..32], num[start..num_len]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "replay stats" {
    var stats = ReplayStats{};
    stats.shreds_received.store(100, .seq_cst);
    try std.testing.expectEqual(@as(u64, 100), stats.shreds_received.load(.seq_cst));
}

test "slot queue push pop" {
    var q = ReplayStage.SlotQueue.init();
    var data = [_]u8{ 1, 2, 3 };
    const msg = ReplayStage.SlotMessage{ .slot = 42, .data = &data };
    try std.testing.expect(q.push(msg));
    const got = q.pop();
    try std.testing.expect(got != null);
    try std.testing.expectEqual(@as(Slot, 42), got.?.slot);
    try std.testing.expect(q.pop() == null);
}

// fix/cu-parity-batch2 (2026-07-12): loader-entry CU cost KAT.
// @prov:replay.loader-entry-cu-cost — direct invocation of one of
// the three native loaders themselves (not merely a program owned by one)
// charges a flat entry cost before (for upgradeable) running the
// Deploy/Upgrade/etc. dispatcher, or (for the other two) immediately
// failing UnsupportedProgramId.
test "loaderEntryCus: BPF_LOADER_UPGRADEABLE=2370, BPF_LOADER_2=570, BPF_LOADER_DEPRECATED=1140, other=0" {
    try std.testing.expectEqual(@as(u64, 2370), loaderEntryCus(&BPF_LOADER_UPGRADEABLE));
    try std.testing.expectEqual(@as(u64, 570), loaderEntryCus(&BPF_LOADER_V2));
    try std.testing.expectEqual(@as(u64, 1140), loaderEntryCus(&BPF_LOADER_DEPRECATED));
    const some_other_program: [32]u8 = [_]u8{0xab} ** 32;
    try std.testing.expectEqual(@as(u64, 0), loaderEntryCus(&some_other_program));
}

test "loaderEntryCus: matches Agave DEFAULT/DEPRECATED/UPGRADEABLE_LOADER_COMPUTE_UNITS constants" {
    try std.testing.expectEqual(@as(u64, DEFAULT_LOADER_COMPUTE_UNITS), loaderEntryCus(&BPF_LOADER_V2));
    try std.testing.expectEqual(@as(u64, DEPRECATED_LOADER_COMPUTE_UNITS), loaderEntryCus(&BPF_LOADER_DEPRECATED));
    try std.testing.expectEqual(@as(u64, UPGRADEABLE_LOADER_COMPUTE_UNITS), loaderEntryCus(&BPF_LOADER_UPGRADEABLE));
}

// PR-5n regression: chain-through walks pending_writes backward to find the
// most-recent in-slot write for a pubkey. The Withdraw branch at lines 6687-6760
// MUST use the value found by this walk (current_data, current_lamports, etc.),
// not the pre-slot snapshot from getAccountInSlot, otherwise a Vote+Withdraw
// pair on the same vote account in one slot loses the Vote's mutation.
// Carrier: slot 409335950, pubkey 5351b3df... — see PR-5n commit body.
test "PR-5n: pending_writes backward-walk returns most-recent in-slot write" {
    const alloc = std.testing.allocator;
    var pending: std.ArrayListUnmanaged(bank_mod.AccountWrite) = .{};
    defer pending.deinit(alloc);

    const target_key = [_]u8{0xAB} ** 32;
    const other_key = [_]u8{0xCD} ** 32;
    const vote_owner = [_]u8{0x07} ++ [_]u8{0x61} ++ [_]u8{0} ** 30;

    // Simulate prior slot's persisted state visible through getAccountInSlot:
    // data = X3, lamports = 77_209_457_590 (matches the recorder for 5351b3df at slot 949).
    const data_x3 = [_]u8{0x03} ** 3762; // pre-vote snapshot bytes
    const lam_pre: u64 = 77_209_457_590;

    // In-slot history (oldest -> newest):
    // 1. An unrelated write for other_key (the loop must skip it).
    try pending.append(alloc, .{
        .pubkey = .{ .data = other_key },
        .lamports = 1,
        .owner = .{ .data = vote_owner },
        .executable = false,
        .rent_epoch = 0,
        .data = "",
    });
    // 2. The Vote tx for target_key — mutates X3 -> X3v (lockouts rolled forward),
    //    lamports unchanged from snapshot at this point in the slot.
    const data_x3v = [_]u8{0x3F} ** 3762; // post-vote bytes (different from X3)
    try pending.append(alloc, .{
        .pubkey = .{ .data = target_key },
        .lamports = lam_pre,
        .owner = .{ .data = vote_owner },
        .executable = false,
        .rent_epoch = 0,
        .data = &data_x3v,
    });

    // Backward walk that mirrors the chain-through loop at replay_stage.zig
    // ~lines 6611-6624. The Withdraw branch at line 6687-6760 must consult the
    // result of this walk (PR-5n), not the pre-slot snapshot.
    var current_data: []const u8 = &data_x3;
    var current_lamports: u64 = lam_pre;
    {
        var j: usize = pending.items.len;
        while (j > 0) {
            j -= 1;
            const pw = &pending.items[j];
            if (std.mem.eql(u8, &pw.pubkey.data, &target_key)) {
                current_data = pw.data;
                current_lamports = pw.lamports;
                break;
            }
        }
    }

    // Without PR-5n, the Withdraw would have used the snapshot bytes (X3).
    // With PR-5n, it uses the chained-through bytes (X3v).
    try std.testing.expectEqual(@as(usize, 3762), current_data.len);
    try std.testing.expect(std.mem.eql(u8, current_data, &data_x3v));
    try std.testing.expect(!std.mem.eql(u8, current_data, &data_x3));
    try std.testing.expectEqual(lam_pre, current_lamports);

    // Subsequent Withdraw computes its post-state from current_*:
    const withdraw_lamports: u64 = 72_209_457_590;
    const vote_new_lamports = current_lamports - withdraw_lamports;
    try std.testing.expectEqual(@as(u64, 5_000_000_000), vote_new_lamports);

    // Append the Withdraw's resulting write — data MUST carry the chained value,
    // not the snapshot. This is the exact post-state shape Vexor emits at line
    // 6752-6760 after PR-5n.
    try pending.append(alloc, .{
        .pubkey = .{ .data = target_key },
        .lamports = vote_new_lamports,
        .owner = .{ .data = vote_owner },
        .executable = false,
        .rent_epoch = 0,
        .data = current_data,
    });

    const final = pending.items[pending.items.len - 1];
    try std.testing.expectEqual(vote_new_lamports, final.lamports);
    try std.testing.expect(std.mem.eql(u8, final.data, &data_x3v));
    // Regression guard: had the Withdraw used the snapshot (pre-PR-5n bug),
    // final.data would have equalled data_x3, losing the Vote's lockout shift.
    try std.testing.expect(!std.mem.eql(u8, final.data, &data_x3));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Transaction parsing (wire format → structured data for native program dispatch)
// ═══════════════════════════════════════════════════════════════════════════════

/// A parsed instruction from a Solana transaction (zero-copy slices into tx_data)
pub const ParsedInstruction = struct {
    program_id_index: u8,
    account_indices: []const u8,
    data: []const u8,
};

/// Parsed transaction with zero-copy references into the original wire data.
/// Account keys and instructions reference the original tx_data slice.
pub const ParsedTx = struct {
    num_sigs: u16,
    num_required_sigs: u8,
    num_readonly_signed: u8,
    num_readonly_unsigned: u8,
    account_keys: []const [32]u8, // pointer into tx_data (cast from raw bytes), or allocated for v0+ALT
    num_accounts: u16,
    blockhash: *const [32]u8,
    instructions: []ParsedInstruction, // allocated by caller
    num_instructions: u16,
    fee_payer: [32]u8,
    /// First signature (the canonical tx ID). Zero-copy pointer into tx_data.
    /// Set by parseTxFromBytes; nullable because some test paths construct
    /// ParsedTx without a real signatures section. When set, this is the
    /// 64-byte ed25519 signature shadow_capture can serialize for oracle-node
    /// `getTransaction <base58(signature)>` arbitration.
    first_signature: ?*const [64]u8 = null,
    /// Number of static (non-ALT) account keys. For legacy txns, equals num_accounts.
    /// For v0 with ALTs, the combined array is: [0..static_key_count) static,
    /// [static_key_count..static_key_count+alt_writable_count) ALT writable,
    /// [static_key_count+alt_writable_count..num_accounts) ALT readonly.
    static_key_count: u16 = 0,
    alt_writable_count: u16 = 0,
    /// fix/cu-parity-batch2 (2026-07-12): count of ALT tables THIS tx's
    /// address_table_lookups section referenced (v0 txs only; 0 for legacy).
    /// @prov:replay.alt-lookup-table-base-size — this is the TABLE count,
    /// distinct from alt_writable_count (a RESOLVED-KEY count).
    num_lookup_tables: u16 = 0,

    /// Zone-based writability check that handles both legacy and v0+ALT transactions.
    /// For legacy: falls back to header-field formula.
    /// For v0+ALT: uses zone boundaries (static header | ALT writable | ALT readonly).
    pub fn isWritable(self: *const ParsedTx, index: u16) bool {
        if (index >= self.num_accounts) return false;
        if (index < self.static_key_count) {
            // Static key — use original header-based writability
            const nrs = self.num_required_sigs;
            const ros = self.num_readonly_signed;
            const rou = self.num_readonly_unsigned;
            const sk = self.static_key_count;
            // Writable signed: [0, nrs - ros)
            if (index < nrs -| ros) return true;
            // Readonly signed: [nrs - ros, nrs) → not writable
            if (index < nrs) return false;
            // Writable unsigned: [nrs, sk - rou)
            if (index < sk -| rou) return true;
            // Readonly unsigned: [sk - rou, sk) → not writable
            return false;
        }
        // ALT zone: writable then readonly
        return index < self.static_key_count + self.alt_writable_count;
    }
};

/// Per-tx scratch the DAG path carries from Phase-1 parse into Phase-2 execute.
/// Hoisted to module scope for Stage B B2c so `runWaveDrain` can take a slice of it.
/// `eligible` = Stage B native-only parallel eligibility (every instruction's program
/// ∈ {System,Vote,ComputeBudget}); ineligible txs (incl. ALL Stake — see B3-CLEAR C1 on
/// txIsNativeEligible — and BPF/loader/ZK) run SERIALLY within their wave on the main thread.
pub const DagTxInfo = struct {
    tx_data: []const u8,
    num_sigs: u16,
    parsed: ?ParsedTx,
    eligible: bool = false,
    // Stage 1 fees-in-execution (2026-07-09): the per-tx fee unit is COMPUTED at
    // parse (Phase 1, wire-only) and APPLIED at execution (executeDagTx), so each
    // tx's fee validation+debit sees the running balance of every earlier tx in
    // DAG order. @prov:replay.fee-unit-sequential-order Phase 1 stashes these; the fee unit reads them.
    fee_payer: [32]u8 = [_]u8{0} ** 32,
    base_fee: u64 = 0, // 5000 * (header sigs + precompile sigs)
    priority_fee: u64 = 0,
    fee_sig_count: u16 = 0, // header sigs only (signature_count semantics)
    has_fee: bool = false, // false => tx_data too short / parse failed => no fee unit
};

/// Stage B B2c — parallel eligibility predicate (native-only first cut, plan SCOPE
/// DECISION). A tx is eligible iff EVERY instruction's program_id ∈ {System, Vote,
/// ComputeBudget}. Any other program ⇒ INELIGIBLE (runs serially within its wave on
/// the main thread). An instruction whose program_id_index is out-of-range
/// (>= static_key_count, e.g. an ALT-resolved program — never canonical for a native
/// program) is treated as ineligible (conservative). Empty-instruction txs are
/// eligible (they touch nothing).
///
/// B3-CLEAR FIX C1 (2026-06-22, ARCH shared-state audit BLOCKER C1): STAKE is
/// DELIBERATELY EXCLUDED. With VEX_STAKE_BPF=1 (the LIVE deploy default) and the
/// migrate_stake_program_to_core_bpf feature active, executeStakeInstruction DIVERTS
/// into the BPF VM, whose commit path (commitV2Mutations, ~replay_stage.zig:10084)
/// does a RAW `bank.pending_writes.append` that BYPASSES collectWrite (does not honor
/// worker_writes_override). On a worker thread that = wrong sink (lands in shared
/// pending_writes mid-wave instead of the worker buffer) + a data race ⇒ bank_hash
/// DIVERGENCE. Excluding STAKE from the eligible set makes stake txs run SERIALLY
/// in-wave (the ineligible path, main thread) where commitV2Mutations is safe — exactly
/// like the BPF programs. Votes dominate testnet load, so the parallel win is preserved.
/// (The executeDagTx STAKE branch is unchanged — it still serves the serial/ineligible
/// path.) BPF-loader / upgradeable-loader / ZK were already excluded.
pub fn txIsNativeEligible(ptx: *const ParsedTx) bool {
    for (ptx.instructions[0..ptx.num_instructions]) |ix| {
        if (ix.program_id_index >= ptx.static_key_count) return false;
        const pid = &ptx.account_keys[ix.program_id_index];
        const ok = std.mem.eql(u8, pid, &NATIVE_PROGRAM_IDS.SYSTEM) or
            std.mem.eql(u8, pid, &NATIVE_PROGRAM_IDS.VOTE) or
            std.mem.eql(u8, pid, &NATIVE_PROGRAM_IDS.COMPUTE_BUDGET);
        if (!ok) return false;
    }
    return true;
}

/// Stage B B2c — compute a tx's cost inputs and run the block CU cost gate. Extracted
/// from the DAG Phase-2 drain so the serial drain AND runWaveDrain's cost-gate pass share
/// ONE implementation (byte-identical inputs: write-lock count, instruction-data bytes,
/// vote sub-limit detection, vote 2100 / non-vote 200_000 CU limit). Returns the cost on
/// admission, null when the block (or vote) CU cap would be exceeded. Pure read of
/// bank.block_compute_units (recordTransactionCost is the caller's job, main thread — seam #7).
/// FIX #95 PROPAGATION (#43, 2026-06-22): a null return NO LONGER skips execution.
/// @prov:replay.cost-gate-no-skip Callers now execute regardless and note CostNoSkip on a null.
/// [WAVE-CONFLICT] parallel-exec race detector (gated VEX_WAVE_CONFLICT_DETECT, default OFF → zero cost
/// + byte-identical to baseline; the only off-cost is one cached-bool check per wave). Read-only: it
/// ONLY logs, never alters consensus state. Two complementary checks on the eligible (concurrently-
/// executed) wave set:
///   D1 (pre-dispatch): two eligible txs share a WRITABLE account per isWritable ⇒ the DAG failed to
///       serialize them. Fires deterministically every wave a miss occurs.
///   D2 (post-barrier): the SAME pubkey lands in two different worker buffers ⇒ two txs actually wrote
///       the same account (catches an isWritable-vs-handler-writes mismatch the DAG couldn't see).
/// Either firing NAMES the exact account + txs = the nondeterministic parallel-exec divergence, no
/// guesswork. If it never fires under a parallel soak, the divergence is NOT a wave write-conflict.
const WaveConflictDetect = struct {
    var enabled: bool = false;
    var inited: bool = false;
    var hits: u64 = 0;
    fn on() bool {
        if (!inited) {
            inited = true;
            enabled = std.posix.getenv("VEX_WAVE_CONFLICT_DETECT") != null;
            // One-time visible confirmation so a repro never has to GUESS whether the
            // detector is live (the env reaches the child via deploy.sh's `env`-inherit path).
            std.log.warn("[WAVE-CONFLICT] detector {s} (VEX_WAVE_CONFLICT_DETECT {s})", .{
                if (enabled) "ARMED — will log any same-account cross-tx write in a wave" else "OFF",
                if (enabled) "set" else "unset",
            });
        }
        return enabled;
    }
};

/// [WAVE-TRACE] parallel-exec execution tracer (gated VEX_WAVE_TRACE, default OFF → one cached-bool
/// check). Read-only narration of the wave pipeline A→B: per-wave partition (ready/eligible/ineligible)
/// and the DAG drop sites (a tx with >MAX_ACCT_PER_TXN accounts, or an addTxn pool-exhaustion, is
/// dropped from the conflict-DAG and executed by NEITHER the serial-DAG nor the wave path — surfaced
/// here so a silent skip is never invisible). Helps SEE how a wave goes from parse → DAG → partition →
/// workers → merge.
const WaveTrace = struct {
    var enabled: bool = false;
    var inited: bool = false;
    fn on() bool {
        if (!inited) {
            inited = true;
            enabled = std.posix.getenv("VEX_WAVE_TRACE") != null;
            std.log.warn("[WAVE-TRACE] tracer {s} (VEX_WAVE_TRACE {s})", .{
                if (enabled) "ARMED — logs per-wave partition + DAG drops" else "OFF",
                if (enabled) "set" else "unset",
            });
        }
        return enabled;
    }
};

/// [WAVE-WIDTH] parallelism-ceiling measurement (gated VEX_WAVE_WIDTH, default OFF → one cached-bool
/// check). PURE OBSERVATION, byte-neutral: it reads the DAG wave structure runWaveDrain already produces
/// and emits ONE line per block. The point is the go/no-go for the whole parallel-BPF track — does a real
/// block expose conflict-free lanes at all? Each outer runWaveDrain iteration is one dependency LEVEL
/// (getNextReady drains every in_degree==0 tx = a mutually conflict-free set). So:
///   waves        = number of drain rounds = DAG critical-path DEPTH (min serial length, ∞ workers)
///   tx_count/waves = mean wave WIDTH = the parallelism CEILING (independent of eligibility — eligibility
///                   only picks worker-vs-mainthread; the wave STRUCTURE is pure DAG dependency)
///   max_width    = the widest single level (best-case burst parallelism)
/// ceiling≈1 → block is contention-bound (hot-account serial chain); parallel BPF + STM both buy ~nothing.
/// ceiling≥3-4 → real lanes exist; the override-fix is worth it. Runs offline over the golden 1848 real
/// testnet slots (no node-down, no consensus risk) to answer the question BEFORE any parallel-exec design.
const WaveWidth = struct {
    var enabled: bool = false;
    var inited: bool = false;
    fn on() bool {
        if (!inited) {
            inited = true;
            enabled = std.posix.getenv("VEX_WAVE_WIDTH") != null;
            std.log.warn("[WAVE-WIDTH] measure {s} (VEX_WAVE_WIDTH {s})", .{
                if (enabled) "ARMED — one parallelism-ceiling line per block" else "OFF",
                if (enabled) "set" else "unset",
            });
        }
        return enabled;
    }
};

/// [WAVE-WIDTH-BLOCK] block-level parallelism-ceiling measurement (gated VEX_WAVE_WIDTH_BLOCK, default OFF).
/// Complements [WAVE-WIDTH] (per-entry): that showed the median block ceiling ≈1.3 because the DAG is built
/// PER ENTRY over ~330 tiny (median 1-tx, vote-dominated) entries. This measures what a SINGLE block-wide
/// conflict DAG would expose — the upside of merging entries. Pure observation: a separate scratch dispatcher
/// accumulates the slot's txs and is dry-drained (getNextReady/completeTxn, NO execution) → waves =
/// block-level critical-path depth, txs/waves = block-level ceiling. Off in the live deploy (one cached bool).
const BlockWidth = struct {
    /// Scratch-DAG depth. ≥ observed max slot tx count (6906). ~30MB pool (offline-only, one-time).
    pub const DEPTH: u32 = 8192;
    var enabled: bool = false;
    var inited: bool = false;
    fn on() bool {
        if (!inited) {
            inited = true;
            enabled = std.posix.getenv("VEX_WAVE_WIDTH_BLOCK") != null;
            std.log.warn("[WAVE-WIDTH-BLOCK] measure {s} (VEX_WAVE_WIDTH_BLOCK {s})", .{
                if (enabled) "ARMED — one block-level ceiling line per slot (scratch DAG, no execution)" else "OFF",
                if (enabled) "set" else "unset",
            });
        }
        return enabled;
    }
};

/// [BLOCK-DAG] block-level DAG batching CORRECTNESS PROBE (gated VEX_BLOCK_DAG, default OFF → one cached
/// bool). The [WAVE-WIDTH-BLOCK] measurement proved a slot-wide conflict DAG exposes a median 232×
/// parallelism ceiling vs 1.32× per-entry — but both parity runs still EXECUTED per-entry. This gate is
/// the first executed increment: Phase 1 (parse + fee deduction) stays per-entry in parse order exactly
/// as today, but the conflict DAG accumulates across ALL of the slot's entries and Phase 2 execution is
/// DEFERRED to one serial slot-end drain in DAG order. SERIAL on purpose — it isolates the one open
/// byte-identity question (fees-in-parse-order vs deferred cross-entry execution reordering: a tx that
/// credits a later entry's fee payer, or reads an account another entry's fee debit touched) from any
/// parallelism concern. Gate: golden 1848/1848 byte-identical. Offline probe only — NOT for the live
/// deploy until it has passed the gate and been promoted deliberately.
const BlockDag = struct {
    /// Dispatcher depth when the probe is armed. Default live depth is 4096 (per-entry never nears it),
    /// but a slot-wide DAG must hold the whole block — observed max 6906 txs/slot (2026-07-09 sweep).
    pub const DEPTH: u32 = 8192;
    var enabled: bool = false;
    var inited: bool = false;
    fn on() bool {
        if (!inited) {
            inited = true;
            enabled = std.posix.getenv("VEX_BLOCK_DAG") != null;
            std.log.warn("[BLOCK-DAG] probe {s} (VEX_BLOCK_DAG {s})", .{
                if (enabled) "ARMED — slot-wide DAG, execution deferred to serial slot-end drain" else "OFF",
                if (enabled) "set" else "unset",
            });
        }
        return enabled;
    }
};

/// [WAVE-TIMING] wall-clock per-wave overhead measurement (gated VEX_WAVE_TIMING, default OFF → one
/// cached-bool check; when armed, a handful of std.time.Timer.read() calls per wave — vDSO clock,
/// ~25ns each). MEASUREMENT-ONLY: never alters dispatch order, tx outcome, or consensus state.
/// Profiling-map action #3 (wave-formation P1): isolates
///   dispatch_ns   = wall time of the wp.dispatchWave() call as observed from the main thread — wake +
///                   barrier + ALL eligible-tx execution across workers for that wave (the full cost of
///                   routing this wave through the worker pool).
///   eligible_ns   = sum of PER-TX worker-side execution time (Timer wrapped around the executeDagTx
///                   call inside waveCb), atomic-accumulated since multiple workers write it concurrently.
///   ineligible_ns = sum of main-thread serial executeDagTx time (BPF/loader/zk/stake — the ineligible
///                   path, unaffected by the worker pool).
/// overhead_ns_per_wave ≈ (dispatch_ns_total - eligible_ns_total) / n_dispatches is the wake+barrier+
/// scheduling cost NOT spent on useful work — exact when n_items==1 (the documented common case: one
/// worker executes, nothing to subtract for fan-out), an upper bound when n_items>1 (eligible_ns then
/// overlaps in wall time across workers, so the subtraction is conservative, not negative-capable in
/// practice since dispatch_ns bounds the wall-clock envelope the eligible work executed inside).
/// ONE summary line per BLOCK (mirrors WaveWidth at :8576) — never per-wave, so this stays log-neutral
/// even on a 60k-wave block.
const WaveTiming = struct {
    var enabled: bool = false;
    var inited: bool = false;
    var eligible_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0); // worker-side; cross-thread, atomic
    fn on() bool {
        if (!inited) {
            inited = true;
            enabled = std.posix.getenv("VEX_WAVE_TIMING") != null;
            std.log.warn("[WAVE-TIMING] {s} (VEX_WAVE_TIMING {s})", .{
                if (enabled) "ARMED — one dispatch/eligible/ineligible ns summary per block" else "OFF",
                if (enabled) "set" else "unset",
            });
        }
        return enabled;
    }
};

/// Value snapshot of an AccountWrite for the shadow comparator — the consensus-relevant fields only
/// (the lt_hash fields are derived). Slices reference arena-stable memory live through one runWaveDrain.
const ShadowVal = struct {
    lamports: u64,
    owner: [32]u8,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};
fn shadowValOf(wr: *const bank_mod.AccountWrite) ShadowVal {
    return .{ .lamports = wr.lamports, .owner = wr.owner.data, .executable = wr.executable, .rent_epoch = wr.rent_epoch, .data = wr.data };
}
fn shadowEql(a: ShadowVal, b: ShadowVal) bool {
    return a.lamports == b.lamports and std.mem.eql(u8, &a.owner, &b.owner) and a.executable == b.executable and a.rent_epoch == b.rent_epoch and std.mem.eql(u8, a.data, b.data);
}

/// [WAVE-VERIFY] parallel-vs-serial shadow comparator (gated VEX_WAVE_SHADOW_VERIFY, default OFF → zero
/// cost + byte-identical to baseline). When ARMED, each wave's eligible txs are executed TWICE from the
/// SAME frozen pre-wave state: (1) PARALLEL into the worker buffers (comparison only, DISCARDED), and
/// (2) SERIAL in ascending block index into pending_writes (COMMITTED — the canonical result, so the
/// node stays bank-exact and keeps voting). The two are diffed by VALUE per pubkey; any difference IS
/// the parallel-exec divergence and is logged with the exact account ([WAVE-DIVERGE]). Because the
/// SERIAL result is what commits, this can run on the LIVE voting node safely — a comparator bug only
/// mis-logs, it never alters committed state. It pins the hidden cross-tx dependency the conflict-DAG
/// fails to capture: a W→R hazard where the reader holds the account read-only is invisible to the
/// [WAVE-CONFLICT] detectors (D1 needs both writable, D2 needs both to write) but is caught here because
/// it diffs the actual written bytes. The serial pass uses ASCENDING info_idx (block order) so a
/// hidden-dependent pair commits the way the cluster ordered it (raw drain order could be wrong); the
/// empirical proof of canonical order is that the node stays CURRENT with the comparator on.
const WaveShadowVerify = struct {
    var enabled: bool = false;
    var inited: bool = false;
    var hits: u64 = 0;
    fn on() bool {
        if (!inited) {
            inited = true;
            enabled = std.posix.getenv("VEX_WAVE_SHADOW_VERIFY") != null;
            std.log.warn("[WAVE-VERIFY] shadow comparator {s} (VEX_WAVE_SHADOW_VERIFY {s})", .{
                if (enabled) "ARMED — parallel-vs-serial-commit per wave; [WAVE-DIVERGE] names any diff" else "OFF",
                if (enabled) "set" else "unset",
            });
        }
        return enabled;
    }
    fn report(slot: u64, pk: [32]u8, par: ShadowVal, ser: ShadowVal) void {
        hits +|= 1;
        std.log.warn("[WAVE-DIVERGE] slot={d} pubkey={s} hits={d} — PARALLEL!=SERIAL lamports={d}/{d} owner={s}/{s} exec={}/{} rent={d}/{d} datalen={d}/{d}", .{
            slot,                                  std.fmt.bytesToHex(pk, .lower), hits,
            par.lamports,                          ser.lamports,                   std.fmt.bytesToHex(par.owner, .lower),
            std.fmt.bytesToHex(ser.owner, .lower), par.executable,                 ser.executable,
            par.rent_epoch,                        ser.rent_epoch,                 par.data.len,
            ser.data.len,
        });
    }
    fn reportMissing(slot: u64, pk: [32]u8, which: []const u8) void {
        hits +|= 1;
        std.log.warn("[WAVE-DIVERGE] slot={d} pubkey={s} hits={d} — account written {s} (one execution mode wrote it, the other did not)", .{
            slot, std.fmt.bytesToHex(pk, .lower), hits, which,
        });
    }
};

/// On a [WAVE-DIVERGE], scan EVERY tx in this wave (eligible workers + ineligible main-thread) and log
/// each one that DECLARES the diverging account, with its eligible/ineligible flag, its writability for
/// that account, and its first instruction's program-id prefix. This answers the discriminating question
/// in one read: is the account in BOTH txs' declared metas (a conflict the DAG should have serialized but
/// the wave ran against a stale snapshot — incl. an eligible<->ineligible miss) or in NEITHER (a
/// non-declared-account channel)? The scan runs only on a (rare) divergence, so it costs nothing in steady
/// state.
fn logWaveDivergeTxs(slot: u64, pk: [32]u8, wave_idxs: []const u32, dag_idx_map: []const u32, dag_tx_infos: []const DagTxInfo) void {
    var declarers: usize = 0;
    for (wave_idxs) |txn_idx| {
        const info_idx = dag_idx_map[txn_idx];
        const info = &dag_tx_infos[info_idx];
        const ptx = info.parsed orelse continue;
        var writable: ?bool = null;
        for (0..@as(usize, ptx.num_accounts)) |ai| {
            if (std.mem.eql(u8, &ptx.account_keys[ai], &pk)) {
                writable = ptx.isWritable(@intCast(ai));
                break;
            }
        }
        const w = writable orelse continue; // tx does not reference this account
        declarers += 1;
        var prog: [4]u8 = .{ 0, 0, 0, 0 };
        if (ptx.num_instructions > 0) {
            const pidx = ptx.instructions[0].program_id_index;
            if (pidx < ptx.account_keys.len) prog = ptx.account_keys[pidx][0..4].*;
        }
        std.log.warn("[WAVE-DIVERGE]   contributor slot={d} pubkey={s} info_idx={d} eligible={} writable={} prog4={s}", .{
            slot, std.fmt.bytesToHex(pk, .lower), info_idx, info.eligible, w, std.fmt.bytesToHex(prog, .lower),
        });
    }
    std.log.warn("[WAVE-DIVERGE]   ^ slot={d} pubkey={s} declarers={d} (in_both_metas=>DAG-should-serialize; in_none=>non-declared channel)", .{
        slot, std.fmt.bytesToHex(pk, .lower), declarers,
    });
}

const CostNoSkip = struct {
    var count: u64 = 0;
    var last_slot: u64 = std.math.maxInt(u64);
    fn note(slot: u64, path: []const u8) void {
        if (last_slot != slot) {
            last_slot = slot;
            count = 0;
        }
        count +|= 1;
        if (count <= 5 or count % 500 == 0)
            std.log.warn("[COST-GATE-NOSKIP] slot={d} path={s} count={d} — executing anyway (Agave/FD-canonical replay)\n", .{ slot, path, count });
    }
};

fn dagTxCost(bank: *Bank, ptx: *const ParsedTx) ?Bank.TransactionCost {
    var wl: u64 = 0;
    for (0..@as(usize, ptx.num_accounts)) |ai| {
        if (ptx.isWritable(@intCast(ai))) wl += 1;
    }
    var ix_data: u64 = 0;
    for (ptx.instructions[0..ptx.num_instructions]) |ixd| {
        ix_data += @intCast(ixd.data.len);
    }
    const is_vote = blk: {
        for (ptx.instructions[0..ptx.num_instructions]) |ixv| {
            if (ixv.program_id_index < ptx.static_key_count) {
                if (std.mem.eql(u8, &ptx.account_keys[ixv.program_id_index], &NATIVE_PROGRAM_IDS.VOTE)) break :blk true;
            }
        }
        break :blk false;
    };
    const cu_lim: u64 = if (is_vote) 2100 else 200_000;
    return bank.estimateTransactionCost(@intCast(ptx.num_required_sigs), wl, ix_data, cu_lim, is_vote);
}

/// Stage B B2c — per-wave context passed to the worker callback (waveCb). Borrowed for the
/// duration of one dispatchWave call. `eligible` is the list of dag_tx_infos indices for
/// the eligible (all-native) admitted txs of THIS wave; `bufs` are the per-worker write
/// buffers (worker i stages into bufs[i] via worker_writes_override).
const WaveCtx = struct {
    self: *ReplayStage,
    bank: *Bank,
    db: *AccountsDb,
    ancestor_slots: []const u64,
    dag_tx_infos: []const DagTxInfo,
    eligible: []const u32,
    bufs: []std.ArrayListUnmanaged(bank_mod.AccountWrite),
};

/// Stage B B2c — wave worker callback (wave_pool.WorkFn). Runs ONE eligible tx on a worker:
/// redirects collectWrite into this worker's buffer, executes, restores. The DAG's W→R
/// exclusion (tx_dispatcher addEdges Case-3 + Step-4) guarantees this tx reads only
/// committed pending_writes (frozen during the wave) + its OWN buffer (intra-tx RAW) —
/// never another worker's buffer. `arena` is this worker's private allocator.
fn waveCb(ctx_ptr: *anyopaque, worker_idx: usize, arena: std.mem.Allocator, item_idx: usize) void {
    const ctx: *WaveCtx = @ptrCast(@alignCast(ctx_ptr));
    const info_idx = ctx.eligible[item_idx];
    const ptx = ctx.dag_tx_infos[info_idx].parsed.?; // local copy on the worker stack (read-only slices into batch_arena)
    const prior = bank_mod.worker_writes_override;
    bank_mod.worker_writes_override = &ctx.bufs[worker_idx];
    defer bank_mod.worker_writes_override = prior;
    if (bank_mod.TvTrace.on()) _ = ctx.bank.tvt2_dag_from_wave.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
    if (WaveTiming.on()) {
        var wt_timer = std.time.Timer.start() catch unreachable;
        ctx.self.executeDagTx(ctx.bank, ctx.db, arena, ctx.ancestor_slots, &ptx, info_idx, &ctx.dag_tx_infos[info_idx]);
        _ = WaveTiming.eligible_ns.fetchAdd(wt_timer.read(), .monotonic);
    } else {
        ctx.self.executeDagTx(ctx.bank, ctx.db, arena, ctx.ancestor_slots, &ptx, info_idx, &ctx.dag_tx_infos[info_idx]);
    }
}

/// One entry from the address_table_lookups section of a v0 transaction.
const RawAltLookup = struct {
    table_key: [32]u8,
    writable_indexes: []const u8, // zero-copy into tx_data
    readonly_indexes: []const u8, // zero-copy into tx_data
};

/// Parse a transaction from wire bytes. Instructions are allocated from the provided allocator.
/// Account keys are zero-copy slices into tx_data (legacy) or allocated (v0 with ALTs).
/// accounts_db is needed to resolve v0 address lookup tables.
///
/// PR-S2 Phase 2a (2026-05-15): `bank` threaded in so ALT-table reads route
/// through the ancestor-aware AccountsDb path (`getAccountInSlot`) rather than
/// the flat rooted read. Empty sig_overlay in 2a means this is byte-identical
/// to the prior `getAccount` flow; the threading sets up 2b/2c when real
/// per-slot ALT writes (if any) need to be visible mid-slot.
fn parseTxFromBytes(tx_data: []const u8, alloc: std.mem.Allocator, accounts_db: ?*AccountsDb, bank: ?*const Bank) !ParsedTx {
    var pos: usize = 0;

    // 1. Signatures
    const num_sigs = readCompactU16(tx_data, &pos) catch return error.TooShort;
    // d27dd (2026-05-11): @prov:replay.txn-sig-max-127
    // Vexor had 19, which silently rejects multisig-wallet / DEX / Jito-bundle txs with
    // 20+ sigs; on rejection the caller's tx parse loop breaks and drops ALL subsequent
    // txs in the same entry, causing slot-level sig-count divergence (carrier slot 407744900:
    // Vexor 763 vs cluster 774, -11 txs).
    if (num_sigs == 0 or num_sigs > 127) return error.TooShort;
    // Capture the first signature (canonical tx ID) before stepping past.
    if (pos + 64 > tx_data.len) return error.TooShort;
    const first_signature_ptr: *const [64]u8 = @ptrCast(tx_data[pos..][0..64]);
    pos += @as(usize, num_sigs) * 64; // skip signatures
    if (pos >= tx_data.len) return error.TooShort;

    // 2. Version detection
    const is_v0 = (tx_data[pos] & 0x80) != 0;
    if (is_v0) pos += 1;

    // 3. Header
    if (pos + 3 > tx_data.len) return error.TooShort;
    const num_required_sigs = tx_data[pos];
    const num_readonly_signed = tx_data[pos + 1];
    const num_readonly_unsigned = tx_data[pos + 2];
    pos += 3;

    // 4. Account keys (zero-copy)
    const num_accounts = readCompactU16(tx_data, &pos) catch return error.TooShort;
    // d27dd: @prov:replay.txn-accounts-max-256
    // Static account-keys can be up to 256 (ALT lookups counted separately).
    if (num_accounts == 0 or num_accounts > 256) return error.TooShort;
    const keys_start = pos;
    const keys_end = keys_start + @as(usize, num_accounts) * 32;
    if (keys_end > tx_data.len) return error.TooShort;
    const account_keys: []const [32]u8 = @as([*]const [32]u8, @ptrCast(@alignCast(tx_data.ptr + keys_start)))[0..num_accounts];
    pos = keys_end;

    // 5. Blockhash
    if (pos + 32 > tx_data.len) return error.TooShort;
    const blockhash: *const [32]u8 = @ptrCast(tx_data[pos..][0..32]);
    pos += 32;

    // 6. Instructions — d27ll: @prov:replay.txn-instructions-max-255
    // See replay_stage.zig:6762 sibling site for full rationale. Carrier slot 407,787,569.
    const num_instructions = readCompactU16(tx_data, &pos) catch return error.TooShort;
    if (num_instructions > 255) return error.TooShort;
    const instructions = try alloc.alloc(ParsedInstruction, num_instructions);

    for (instructions, 0..) |*ix, idx| {
        _ = idx;
        if (pos >= tx_data.len) return error.TooShort;
        ix.program_id_index = tx_data[pos];
        pos += 1;

        const num_ix_accounts = readCompactU16(tx_data, &pos) catch return error.TooShort;
        if (pos + num_ix_accounts > tx_data.len) return error.TooShort;
        ix.account_indices = tx_data[pos..][0..num_ix_accounts];
        pos += num_ix_accounts;

        const ix_data_len = readCompactU16(tx_data, &pos) catch return error.TooShort;
        if (pos + ix_data_len > tx_data.len) return error.TooShort;
        ix.data = tx_data[pos..][0..ix_data_len];
        pos += ix_data_len;
    }

    // 7. ALT resolution (v0 only)
    // Spec order: static keys | ALT writable (table order, index order) | ALT readonly
    var final_keys = account_keys;
    var final_num_accounts = num_accounts;
    var alt_writable_count: u16 = 0;
    var num_lookup_tables: u16 = 0; // fix/cu-parity-batch2: ALT TABLE count (not resolved-key count)
    const static_key_count = num_accounts;

    if (is_v0) alt_blk: {
        const db = accounts_db orelse break :alt_blk;

        const num_lookups = readCompactU16(tx_data, &pos) catch break :alt_blk;
        if (num_lookups == 0) break :alt_blk;
        // d27dd: @prov:replay.txn-addr-table-lookup-max-127
        if (num_lookups > 127) return error.TooShort;

        var raw_lookups: [32]RawAltLookup = undefined;
        var total_writable: usize = 0;
        var total_readonly: usize = 0;

        for (raw_lookups[0..num_lookups]) |*rl| {
            if (pos + 32 > tx_data.len) return error.TooShort;
            @memcpy(&rl.table_key, tx_data[pos..][0..32]);
            pos += 32;

            const nw = readCompactU16(tx_data, &pos) catch return error.TooShort;
            if (pos + nw > tx_data.len) return error.TooShort;
            rl.writable_indexes = tx_data[pos..][0..nw];
            pos += nw;

            const nr = readCompactU16(tx_data, &pos) catch return error.TooShort;
            if (pos + nr > tx_data.len) return error.TooShort;
            rl.readonly_indexes = tx_data[pos..][0..nr];
            pos += nr;

            total_writable += nw;
            total_readonly += nr;
        }

        const total_keys = @as(usize, num_accounts) + total_writable + total_readonly;
        if (total_keys > 256) return error.TooShort;

        // Allocate combined array (arena-backed, freed per-slot)
        const combined = try alloc.alloc([32]u8, total_keys);
        @memcpy(combined[0..num_accounts], account_keys);

        var w_cursor: usize = num_accounts;
        var r_cursor: usize = num_accounts + total_writable;

        for (raw_lookups[0..num_lookups]) |rl| {
            const table_pk = core.Pubkey{ .data = rl.table_key };
            const acct_view = if (bank) |b|
                db.getAccountInSlot(&table_pk, b.slot, b.ancestors()) orelse return error.TooShort
            else
                db._getRooted(&table_pk) orelse return error.TooShort;

            // ALT layout: 56-byte header + packed [32]u8 addresses
            if (acct_view.data.len < address_lookup_table.LOOKUP_TABLE_META_SIZE) return error.TooShort;
            const addr_bytes = acct_view.data[address_lookup_table.LOOKUP_TABLE_META_SIZE..];
            if (addr_bytes.len % 32 != 0) return error.TooShort;
            const addr_count = addr_bytes.len / 32;
            const addresses: [*]const [32]u8 = @ptrCast(@alignCast(addr_bytes.ptr));

            for (rl.writable_indexes) |idx| {
                if (@as(usize, idx) >= addr_count) return error.TooShort;
                combined[w_cursor] = addresses[idx];
                w_cursor += 1;
            }
            for (rl.readonly_indexes) |idx| {
                if (@as(usize, idx) >= addr_count) return error.TooShort;
                combined[r_cursor] = addresses[idx];
                r_cursor += 1;
            }
        }

        final_keys = combined;
        final_num_accounts = @intCast(total_keys);
        alt_writable_count = @intCast(total_writable);
        num_lookup_tables = num_lookups;
    }

    // Fee payer is always the first account key
    var fee_payer: [32]u8 = undefined;
    @memcpy(&fee_payer, &final_keys[0]);

    return ParsedTx{
        .num_sigs = num_sigs,
        .num_required_sigs = num_required_sigs,
        .num_readonly_signed = num_readonly_signed,
        .num_readonly_unsigned = num_readonly_unsigned,
        .account_keys = final_keys,
        .num_accounts = final_num_accounts,
        .blockhash = blockhash,
        .instructions = instructions,
        .num_instructions = num_instructions,
        .fee_payer = fee_payer,
        .static_key_count = static_key_count,
        .alt_writable_count = alt_writable_count,
        .num_lookup_tables = num_lookup_tables,
        .first_signature = first_signature_ptr,
    };
}

/// Flush bank's pending_writes to AccountsDb unflushed_cache.
/// Deduplicates (last write per pubkey wins) and deep-copies account data.
/// Uses page_allocator for data copies and frees old data on overwrite
/// to prevent unbounded memory growth (production-critical).
const AccountsDb = @import("vex_store").accounts.AccountsDb;

/// TOPVOTES-DIAG (2026-06-03): per-slot attribution of top_votes refresh
/// attempts, broken down by call site + outcome. Pins WHY the fork-choice feed's
/// `emitted` collapses to 1 at steady tip despite the refresh "should fire once
/// per vote". The replay worker is the sole caller of every refresh site (d17
/// invariant), so plain globals are race-free. Emits one summary line per slot.
/// Temporary diagnostic — strip once the suppression is understood.
///
/// CONSOLIDATION (2026-06-04): the actual top_votes upsert/remove now lives in ONE
/// canonical chokepoint — `AccountsDb.refreshTopVoteForWrite` — called once at
/// every real db landing (flushPendingWritesToDb, flushPendingWritesFromIndex,
/// promoteRootedChain). The chokepoint bumps cumulative counters on AccountsDb
/// (`tv_upsert_ok` / `tv_remove_ok` / `tv_deser_fail` / `tv_readback_stale`).
/// This struct SNAPSHOTS those cumulative counters at each slot boundary and
/// reports the per-slot DELTA, so the "upsert_ok ~1050 at the tip" signal the
/// consolidation must preserve is reported from the single source of truth — and
/// it now captures the promoteRootedChain landing too (the tip-active site the old
/// per-call `refreshTopVotes` instrumentation could not see). `site1`/`site2` are
/// per-flush call hints bumped at the flush sites; the upsert/remove totals are
/// path-agnostic deltas. Replay worker is the sole writer (d17), so plain globals
/// are race-free. Temporary diagnostic — strip once the suppression is understood.
const TopVotesDiag = struct {
    var cur_slot: u64 = std.math.maxInt(u64);
    var site1: u32 = 0; // flushPendingWritesToDb vote-write hint (post-tx replay flush)
    var site2: u32 = 0; // flushPendingWritesFromIndex vote-write hint (post-freeze flush)
    // Cumulative-counter snapshots taken at the last roll(); per-slot delta = now - snap.
    var snap_upsert: u64 = 0;
    var snap_remove: u64 = 0;
    var snap_deser_fail: u64 = 0;
    var snap_readback_stale: u64 = 0;

    /// Count a vote-account write seen at a named flush site (diagnostic hint only;
    /// the authoritative upsert happens in AccountsDb.refreshTopVoteForWrite).
    fn bump(site: u8) void {
        switch (site) {
            1 => site1 += 1,
            else => site2 += 1,
        }
    }

    /// Emit the prior slot's per-slot deltas (from the cumulative AccountsDb
    /// counters, which cover ALL three db landings including promoteRootedChain),
    /// then re-snapshot for the new slot. Driven from the per-slot flush anchor
    /// with the CURRENT replay slot — never a rooted/older slot — so the counters
    /// are not reset mid-slot by the root-advance re-promotion path.
    fn roll(db: *AccountsDb, slot: u64) void {
        if (slot == cur_slot) return;
        const upsert_ok = db.tv_upsert_ok - snap_upsert;
        const remove_ok = db.tv_remove_ok - snap_remove;
        const deser_fail = db.tv_deser_fail - snap_deser_fail;
        const readback_stale = db.tv_readback_stale - snap_readback_stale;
        if (cur_slot != std.math.maxInt(u64) and (upsert_ok + remove_ok + site1 + site2) > 0) {
            std.log.warn(
                "[TOPVOTES-DIAG] slot={d} site1={d} site2={d} upsert_ok={d} remove_ok={d} deser_fail={d} readback_stale={d}",
                .{ cur_slot, site1, site2, upsert_ok, remove_ok, deser_fail, readback_stale },
            );
        }
        cur_slot = slot;
        site1 = 0;
        site2 = 0;
        snap_upsert = db.tv_upsert_ok;
        snap_remove = db.tv_remove_ok;
        snap_deser_fail = db.tv_deser_fail;
        snap_readback_stale = db.tv_readback_stale;
    }
};

pub fn flushPendingWritesToDb(bank: *Bank, db: *AccountsDb) void {
    // TOPVOTES-DIAG: emit the prior slot's per-slot top_votes deltas and snapshot
    // for this slot. Driven here (the per-slot post-tx flush anchor) with the
    // CURRENT bank.slot — NOT a rooted slot — so promoteRootedChain's older-slot
    // landings never roll/reset the per-slot window. Runs before the early-return
    // so even a zero-write slot flushes the prior slot's line.
    TopVotesDiag.roll(db, bank.slot);

    // [TOPVOTES-TRACE] TEMPORARY measurement (see bank.zig TvTrace) — snapshot
    // the buffer THIS flush call sees: total len, vote-owned entries, and how
    // many of those .data blobs still deserialize as vote state. .data is LIVE
    // here for the post-tx flush (flush precedes batch_arena.deinit, :8981) and
    // for the pre-exec sysvar flush (nothing freed yet). Placed BEFORE the
    // empty early-return so zero-write flush calls are still counted.
    if (bank_mod.TvTrace.on()) {
        bank.tvt_flush_calls += 1;
        var tvt_vote: u32 = 0;
        var tvt_parse_ok: u32 = 0;
        for (bank.pending_writes.items) |*w| {
            if (!std.mem.eql(u8, &w.owner.data, &bank_mod.TvTrace.VOTE_OWNER)) continue;
            tvt_vote += 1;
            if (vote_state_serde.deserializeVoteState(w.data) != null) tvt_parse_ok += 1;
        }
        std.log.warn("[TOPVOTES-TRACE] flush slot={d} call={d} len={d} vote={d} parse_ok={d}", .{
            bank.slot, bank.tvt_flush_calls, bank.pending_writes.items.len, tvt_vote, tvt_parse_ok,
        });
    }

    if (bank.pending_writes.items.len == 0) return;

    // Deduplicate: last write per pubkey wins (walk reverse)
    var seen = std.AutoHashMap([32]u8, void).init(bank.allocator);
    defer seen.deinit();

    var flushed: u64 = 0;
    var freed: u64 = 0;

    // Use page_allocator for deep copies — supports individual free() unlike ArenaAllocator.
    // This is critical: on mainnet at 2.5 slots/sec with ~1200 accounts/slot,
    // ArenaAllocator would grow at ~12.5 MB/sec = 45 GB/hour → OOM.
    const data_alloc = std.heap.page_allocator;

    db.unflushed_cache_lock.lock();
    defer db.unflushed_cache_lock.unlock();

    // Pre-size to avoid HashMap resize during batch insert
    const current = db.unflushed_cache.count();
    const additional = @min(bank.pending_writes.items.len, 10000);
    if (current + additional < std.math.maxInt(u32)) {
        db.unflushed_cache.ensureTotalCapacity(@intCast(current + additional)) catch {};
    }

    // Phase B recorder: read gate once outside the hot loop.
    const rec_writes_on = vex_store.recorder.isWriteEnabled();

    var i: usize = bank.pending_writes.items.len;
    while (i > 0) {
        i -= 1;
        const w = &bank.pending_writes.items[i];
        if (seen.contains(w.pubkey.data)) continue;
        // OOM here must fail-stop: skipping the NEWEST write while an older
        // pending write for the same pubkey remains eligible = silent
        // bank_hash divergence. A crash is consensus-safe; a dropped write
        // is not. (A5, 2026-06-11)
        seen.put(w.pubkey.data, {}) catch @panic("OOM: flushPendingWritesToDb seen.put — cannot skip a committed account write");

        // Deep-copy data using page_allocator (supports free)
        const owned_data = if (w.data.len > 0) blk: {
            const copy = data_alloc.alloc(u8, w.data.len) catch @panic("OOM: flushPendingWritesToDb data copy — cannot drop a committed account write");
            @memcpy(copy, w.data);
            break :blk copy;
        } else &[_]u8{};

        // Phase B recorder: capture pre-state BEFORE the put-and-free below
        // overwrites unflushed_cache[pk] and cache_slot_map[pk]. SHA happens
        // inline inside emitWrite so prev_data slice stays valid.
        const pk = core.Pubkey{ .data = w.pubkey.data };
        const prev_csm: ?u64 = if (rec_writes_on) db.cache_slot_map.get(pk) else null;
        const prev_unflushed = if (rec_writes_on) db.unflushed_cache.get(pk) else null;
        const prev_lam: ?u64 = if (prev_unflushed) |a| a.lamports else null;
        const prev_data: ?[]const u8 = if (prev_unflushed) |a| a.data else null;
        if (rec_writes_on) {
            vex_store.recorder.emitWrite(
                &w.pubkey.data,
                &w.owner.data,
                w.lamports,
                w.data,
                prev_csm,
                prev_lam,
                prev_data,
            );
        }

        // Free old data if overwriting an existing entry
        if (db.unflushed_cache.get(pk)) |old_acct| {
            if (old_acct.data.len > 0) {
                data_alloc.free(@constCast(old_acct.data));
                freed += 1;
            }
        }

        // Write to unflushed_cache (lock already held).
        // OOM fail-stop (A5, 2026-06-11): the old `put_ok=false → continue`
        // shape silently DROPPED a committed write (divergence) and leaked
        // owned_data; for an existing key it would also have left the map
        // holding the data freed above (dangling). Crash instead.
        db.unflushed_cache.put(pk, .{
            .lamports = w.lamports,
            .owner = core.Pubkey{ .data = w.owner.data },
            .executable = w.executable,
            .rent_epoch = w.rent_epoch,
            .data = owned_data,
        }) catch @panic("OOM: flushPendingWritesToDb unflushed_cache.put — cannot drop a committed account write");
        // A missing cache_slot_map entry mis-slots the account at flush time
        // (stale-read class) — same fail-stop rule.
        db.cache_slot_map.put(pk, bank.slot) catch @panic("OOM: flushPendingWritesToDb cache_slot_map.put");
        // r75-bug-class-b-cache-invalidate (2026-05-06): defense-in-depth.
        // The read-cache `db.cache` may hold stale snapshot bytes for `pk`.
        // Even though `getAccount` checks unflushed_cache (L1) BEFORE cache (L3),
        // the L1 entry can later be evicted by `flushCacheToDisk` (every 100 slots)
        // — at which point the stale L3 entry surfaces. Invalidate at the WRITE
        // point so the cache layer is consistent end-to-end.
        db.cache.invalidate(&pk);
        flushed += 1;

        // Phase E (2026-05-17): RE-ENABLED sig_overlay.put. Phase 2c-B
        // disabled this when (a) db.allocator was non-thread-safe and
        // (b) parallelWorkerFn was a live multi-thread caller. Both
        // hazards are gone today:
        //   - db.allocator is c_allocator (libc malloc + jemalloc, thread-safe)
        //   - parallelWorkerFn is dead code (svm_pool removed; see lines 253,259)
        // Phase D recorder diagnosis (2026-05-17) proved this disable is
        // the iter-6 carrier: with sig_overlay empty, getAccountInSlot's
        // fork-aware read path returns null for every pubkey and falls
        // through to the flat fork-blind unflushed_cache — 7,297 polluted
        // reads / 2,000 slots all attributable to this gap.
        // sig_overlay clones data internally with the passed allocator and
        // frees on overwrite, so allocate a c_allocator copy here. The
        // unflushed_cache path uses a separate page_allocator copy above —
        // the two stores own independent data.
        {
            // OOM fail-stop (A5, 2026-06-11): the old fallback stored EMPTY
            // data for an account that HAS data — read-layer corruption.
            const sig_data = if (owned_data.len > 0) blk: {
                const copy = db.allocator.alloc(u8, owned_data.len) catch @panic("OOM: sig_overlay data copy — cannot corrupt a committed account write");
                @memcpy(copy, owned_data);
                break :blk @as([]const u8, copy);
            } else @as([]const u8, &[_]u8{});
            db.sig_overlay.put(db.allocator, bank.slot, pk, .{
                .lamports = w.lamports,
                .owner = core.Pubkey{ .data = w.owner.data },
                .executable = w.executable,
                .rent_epoch = w.rent_epoch,
                .data = sig_data,
            }) catch @panic("OOM: sig_overlay.put — cannot drop a committed account write");
        }

        // 2026-05-18: mirror into UnrootedRing too (fork-aware per-slot
        // cache). Ring stores writes keyed by slot so a later slot-K reader
        // cannot see this bank.slot's value unless K's ancestor chain
        // includes bank.slot. Separate page_allocator dupe matches the
        // ring's deinit free path.
        {
            // OOM fail-stop (A5, 2026-06-11): empty-data fallback = ring would
            // serve a corrupted (data-less) version on this fork.
            const ring_data = if (owned_data.len > 0) blk: {
                const copy = std.heap.page_allocator.alloc(u8, owned_data.len) catch @panic("OOM: unrooted_ring data copy — cannot corrupt a committed account write");
                @memcpy(copy, owned_data);
                break :blk @as([]const u8, copy);
            } else @as([]const u8, &[_]u8{});
            db.unrooted_ring.put(bank.slot, pk, .{
                .lamports = w.lamports,
                .owner = core.Pubkey{ .data = w.owner.data },
                .executable = w.executable,
                .rent_epoch = w.rent_epoch,
                .data = ring_data,
            }) catch @panic("OOM: unrooted_ring.put — cannot drop a committed account write (fork-aware read layer)");
        }

        // top_votes refresh via the single canonical chokepoint
        // (AccountsDb.refreshTopVoteForWrite) at THIS db landing — the post-tx
        // replay flush where vote-account writes from executed vote txs land.
        // The chokepoint encodes the full check_and_store contract (remove on
        // zero-lamports, fork-aware upsert by write_slot). bump() is a diagnostic
        // hint only. unflushed_cache_lock is held here; the chokepoint takes only
        // top_votes_lock nested inside it (same lock order, no inversion).
        if (std.mem.eql(u8, &w.owner.data, &vote_program.VOTE_PROGRAM_ID)) TopVotesDiag.bump(1);
        db.refreshTopVoteForWrite(w.pubkey.data, w.owner.data, owned_data, w.lamports, bank.slot);
    }

    // Print BEFORE we release the lock (while data is still valid)
    const FlushDbg = struct {
        var count: u32 = 0;
    };
    FlushDbg.count += 1;
    if (FlushDbg.count <= 10 or FlushDbg.count % 100 == 0) {
        std.log.debug("[FLUSH] slot={d} pending={d} deduped={d} flushed={d} freed={d} cache={d}\n", .{
            bank.slot, bank.pending_writes.items.len, seen.count(), flushed, freed, db.unflushed_cache.count(),
        });
    }
}

/// Flush a RANGE of bank's pending_writes to AccountsDb unflushed_cache.
/// Only processes entries at indices [start_idx, pending_writes.len).
/// Used for post-freeze sysvar flushes: replay entries (0..start_idx) were already
/// flushed and their .data may point to freed arena memory — must not be touched.
fn flushPendingWritesFromIndex(bank: *Bank, db: *AccountsDb, start_idx: usize) void {
    if (bank.pending_writes.items.len <= start_idx) return;

    // Deduplicate within the range: last write per pubkey wins (walk reverse)
    var seen = std.AutoHashMap([32]u8, void).init(bank.allocator);
    defer seen.deinit();

    var flushed: u64 = 0;
    var freed: u64 = 0;

    const data_alloc = std.heap.page_allocator;

    db.unflushed_cache_lock.lock();
    defer db.unflushed_cache_lock.unlock();

    const additional = bank.pending_writes.items.len - start_idx;
    const current = db.unflushed_cache.count();
    if (current + additional < std.math.maxInt(u32)) {
        db.unflushed_cache.ensureTotalCapacity(@intCast(current + additional)) catch {};
    }

    // Phase B recorder: read gate once outside the hot loop.
    const rec_writes_on = vex_store.recorder.isWriteEnabled();

    var i: usize = bank.pending_writes.items.len;
    while (i > start_idx) {
        i -= 1;
        const w = &bank.pending_writes.items[i];
        if (seen.contains(w.pubkey.data)) continue;
        // OOM fail-stop (A5, 2026-06-11): same rule as flushPendingWritesToDb —
        // a skipped/dropped committed write is silent divergence; crash instead.
        seen.put(w.pubkey.data, {}) catch @panic("OOM: post-freeze flush seen.put — cannot skip a committed account write");

        // Deep-copy data using page_allocator (supports free)
        const owned_data = if (w.data.len > 0) blk: {
            const copy = data_alloc.alloc(u8, w.data.len) catch @panic("OOM: post-freeze flush data copy — cannot drop a committed account write");
            @memcpy(copy, w.data);
            break :blk copy;
        } else &[_]u8{};

        // Phase B recorder: capture pre-state BEFORE the put-and-free below.
        const pk = core.Pubkey{ .data = w.pubkey.data };
        const prev_csm: ?u64 = if (rec_writes_on) db.cache_slot_map.get(pk) else null;
        const prev_unflushed = if (rec_writes_on) db.unflushed_cache.get(pk) else null;
        const prev_lam: ?u64 = if (prev_unflushed) |a| a.lamports else null;
        const prev_data: ?[]const u8 = if (prev_unflushed) |a| a.data else null;
        if (rec_writes_on) {
            vex_store.recorder.emitWrite(
                &w.pubkey.data,
                &w.owner.data,
                w.lamports,
                w.data,
                prev_csm,
                prev_lam,
                prev_data,
            );
        }

        // Free old data if overwriting an existing entry
        if (db.unflushed_cache.get(pk)) |old_acct| {
            if (old_acct.data.len > 0) {
                data_alloc.free(@constCast(old_acct.data));
                freed += 1;
            }
        }

        // Write to unflushed_cache (lock already held).
        // OOM fail-stop (A5, 2026-06-11): see flushPendingWritesToDb companion
        // site — old shape dropped the write + leaked owned_data on put-fail.
        db.unflushed_cache.put(pk, .{
            .lamports = w.lamports,
            .owner = core.Pubkey{ .data = w.owner.data },
            .executable = w.executable,
            .rent_epoch = w.rent_epoch,
            .data = owned_data,
        }) catch @panic("OOM: post-freeze flush unflushed_cache.put — cannot drop a committed account write");
        db.cache_slot_map.put(pk, bank.slot) catch @panic("OOM: post-freeze flush cache_slot_map.put");
        // r75-bug-class-b-cache-invalidate (2026-05-06): defense-in-depth.
        // The read-cache `db.cache` may hold stale snapshot bytes for `pk`.
        // Even though `getAccount` checks unflushed_cache (L1) BEFORE cache (L3),
        // the L1 entry can later be evicted by `flushCacheToDisk` (every 100 slots)
        // — at which point the stale L3 entry surfaces. Invalidate at the WRITE
        // point so the cache layer is consistent end-to-end.
        db.cache.invalidate(&pk);
        flushed += 1;

        // Phase E (2026-05-17): RE-ENABLED sig_overlay.put. Same rationale
        // as the flushPendingWritesToDb companion site (line 4319): Phase 2c-B
        // hazards are gone (allocator + parallelWorkerFn). Phase D recorder
        // proved this disable is the iter-6 carrier.
        {
            // OOM fail-stop (A5, 2026-06-11): the old fallback stored EMPTY
            // data for an account that HAS data — read-layer corruption.
            const sig_data = if (owned_data.len > 0) blk: {
                const copy = db.allocator.alloc(u8, owned_data.len) catch @panic("OOM: sig_overlay data copy — cannot corrupt a committed account write");
                @memcpy(copy, owned_data);
                break :blk @as([]const u8, copy);
            } else @as([]const u8, &[_]u8{});
            db.sig_overlay.put(db.allocator, bank.slot, pk, .{
                .lamports = w.lamports,
                .owner = core.Pubkey{ .data = w.owner.data },
                .executable = w.executable,
                .rent_epoch = w.rent_epoch,
                .data = sig_data,
            }) catch @panic("OOM: sig_overlay.put — cannot drop a committed account write");
        }

        // 2026-05-18: mirror into UnrootedRing (fork-aware per-slot cache).
        // Same rationale as sig_overlay companion above — ring stores writes
        // keyed by slot to prevent iter-6 fork pollution at read time.
        {
            // OOM fail-stop (A5, 2026-06-11): empty-data fallback = ring would
            // serve a corrupted (data-less) version on this fork.
            const ring_data = if (owned_data.len > 0) blk: {
                const copy = std.heap.page_allocator.alloc(u8, owned_data.len) catch @panic("OOM: unrooted_ring data copy — cannot corrupt a committed account write");
                @memcpy(copy, owned_data);
                break :blk @as([]const u8, copy);
            } else @as([]const u8, &[_]u8{});
            db.unrooted_ring.put(bank.slot, pk, .{
                .lamports = w.lamports,
                .owner = core.Pubkey{ .data = w.owner.data },
                .executable = w.executable,
                .rent_epoch = w.rent_epoch,
                .data = ring_data,
            }) catch @panic("OOM: unrooted_ring.put — cannot drop a committed account write (fork-aware read layer)");
        }

        // top_votes refresh via the single canonical chokepoint
        // (AccountsDb.refreshTopVoteForWrite) at THIS db landing — the post-freeze
        // sysvar flush. Votes essentially never land here (committed pre-freeze by
        // flushPendingWritesToDb), but every db.unflushed_cache.put route stays on
        // the one canonical updater. unflushed_cache_lock held; chokepoint nests
        // top_votes_lock. The roll()/snapshot for this slot already happened in
        // flushPendingWritesToDb, so these deltas attribute to the current slot.
        if (std.mem.eql(u8, &w.owner.data, &vote_program.VOTE_PROGRAM_ID)) TopVotesDiag.bump(2);
        db.refreshTopVoteForWrite(w.pubkey.data, w.owner.data, owned_data, w.lamports, bank.slot);
    }
}

/// Native program IDs (verified from base58 decode, not hand-typed)
pub const NATIVE_PROGRAM_IDS = struct {
    pub const SYSTEM = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    pub const VOTE = [_]u8{ 0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3, 0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00 };
    pub const STAKE = [_]u8{ 0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a, 0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2, 0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b, 0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00 };
    pub const COMPUTE_BUDGET = [_]u8{ 0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7, 0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00 };
    // ZkE1Gama1Proof11111111111111111111111111111 (zk-elgamal-proof native builtin).
    // task #11: gated dark via vex_bpf2.builtins.zk_elgamal_proof_program.HANDLER_ENABLED.
    pub const ZK_ELGAMAL = [_]u8{ 0x08, 0x63, 0x75, 0xac, 0xe2, 0xae, 0xea, 0x28, 0x1a, 0x6b, 0x37, 0x4d, 0x68, 0x1b, 0xa7, 0x6a, 0x53, 0xcc, 0xf6, 0x38, 0xc0, 0x74, 0x55, 0x93, 0x6c, 0x05, 0xd0, 0x65, 0x40, 0x00, 0x00, 0x00 };
};

/// BPF Loader Upgradeable program ID (BPFLoaderUpgradeab1e11111111111111111111111)
pub const BPF_LOADER_UPGRADEABLE = [_]u8{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0,
    0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2,
    0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
};

/// BPF Loader v2 (non-upgradeable) program ID (BPFLoader2111111111111111111111111111111111).
/// ELF lives directly in the program account's data (no programdata indirection).
pub const BPF_LOADER_V2 = [_]u8{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6e,
    0x39, 0x5a, 0xe1, 0x28, 0x94, 0x8f, 0xfa, 0x69,
    0x56, 0x93, 0x37, 0x68, 0x18, 0xdd, 0x47, 0x43,
    0x52, 0x21, 0xf3, 0xc6, 0x00, 0x00, 0x00, 0x00,
};

/// BPF Loader (deprecated) program ID (BPFLoader1111111111111111111111111111111111).
/// ELF lives directly in the program account's data (no programdata indirection).
pub const BPF_LOADER_DEPRECATED = [_]u8{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6b,
    0xbd, 0x23, 0x95, 0x85, 0x5f, 0x64, 0x04, 0xd9,
    0xb4, 0xf4, 0x56, 0xb7, 0x82, 0x1b, 0xb0, 0x14,
    0x57, 0x49, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00,
};

// fix/cu-parity-batch2 loader-entry-costs (2026-07-12).
// @prov:replay.loader-entry-cu-cost — native-loader entry costs charged
// BEFORE process_instruction_inner's match runs, ONLY for a "Program
// Management Instruction" (an ix whose program_id IS the loader itself).
// NOT charged for the "Program Invocation" path -- invoking a deployed
// program merely OWNED by one of these loaders costs 0 loader-entry CU;
// only the ELF's own VM-metered execution applies there (see loaderEntryCus()
// doc below). bpf_loader (570) and bpf_loader_deprecated (1140)
// direct-invocation ALWAYS then fails UnsupportedProgramId after the charge
// lands -- the tx still rolls back to fee-only, same as if the charge had
// exceeded budget. loader_v4: verified ABSENT from this Agave 4.2.0-beta.0
// snapshot's bank builtins (cost-tracking placeholder only, not
// dispatchable). Not implemented here for that reason -- adding an entry
// cost for a program_id Agave itself cannot invoke would be pure
// speculation, not a parity fix.
const UPGRADEABLE_LOADER_COMPUTE_UNITS: u64 = 2370;
const DEFAULT_LOADER_COMPUTE_UNITS: u64 = 570;
const DEPRECATED_LOADER_COMPUTE_UNITS: u64 = 1140;

/// Loader-entry CU cost for a top-level ix whose program_id is one of the
/// three native loaders themselves (0 for anything else, including a
/// program merely owned by one of them — see comment block above).
fn loaderEntryCus(program_id: *const [32]u8) u64 {
    if (std.mem.eql(u8, program_id, &BPF_LOADER_UPGRADEABLE)) return UPGRADEABLE_LOADER_COMPUTE_UNITS;
    if (std.mem.eql(u8, program_id, &BPF_LOADER_V2)) return DEFAULT_LOADER_COMPUTE_UNITS;
    if (std.mem.eql(u8, program_id, &BPF_LOADER_DEPRECATED)) return DEPRECATED_LOADER_COMPUTE_UNITS;
    return 0;
}

/// FIX #95 (2026-06-01): pre-warm one CPI-callee program into the V2 cache.
/// See the call site just before `v2DispatchBpfProgram`. @prov:replay.cpi-callee-prewarm
/// Vexor's resolver is lookup-only, so a CPI into a program not yet dispatched
/// top-level THIS run missed → M7_RecursiveLoadFailed → the inner instruction
/// was silently dropped (tx still err=0), corrupting bank_hash. Measured
/// carrier: slot 412458795 BiSoN→SPL-Token CloseAccount (3 closes + a
/// 19,218,520 credit dropped → vote-drop cascade → delinquent).
///
/// `cand_*` come from an already-read AccountSnapshot (snaps[] or cpi_extras),
/// so the warm path costs only a hashmap lookup; the programdata account (cold
/// upgradeable callee only) is the single extra db read. Failure is non-fatal:
/// the existing M7 miss-path then handles it exactly as before (no regression).
/// Upgrade-detection for CPI-callee-only programs matches the existing resolver
/// (none); the cache is bounded by invalidateBeforeSlot at slot rollover.
pub fn prewarmCalleeProgram(
    cache: *v2_pc_mod.V2ProgramCache,
    db: *AccountsDb,
    bank: *Bank,
    top_level_program: *const [32]u8,
    cand_key: [32]u8,
    cand_owner: [32]u8,
    cand_data: []const u8,
    cand_executable: bool,
) void {
    if (!cand_executable) return;
    if (std.mem.eql(u8, &cand_key, top_level_program)) return; // dispatch loads this
    const is_loader = std.mem.eql(u8, &cand_owner, &BPF_LOADER_UPGRADEABLE) or
        std.mem.eql(u8, &cand_owner, &BPF_LOADER_V2) or
        std.mem.eql(u8, &cand_owner, &BPF_LOADER_DEPRECATED);
    if (!is_loader) return; // builtins (NativeLoader) dispatch in-place; not ELFs
    if (cache.get(cand_key) != null) return; // already warm (cheap exit)

    // Resolve ELF identically to the top-level resolver (replay_stage.zig
    // ~6595): upgradeable → programdata account (skip 45-byte header); else
    // (loader v2 / deprecated) → the program account data IS the ELF.
    var pd_slot: u64 = 0;
    const elf_bytes: []const u8 = blk: {
        if (std.mem.eql(u8, &cand_owner, &BPF_LOADER_UPGRADEABLE) and cand_data.len >= 36) {
            const state = std.mem.readInt(u32, cand_data[0..4], .little);
            if (state == 2) {
                var pd_key = core.Pubkey{ .data = undefined };
                @memcpy(&pd_key.data, cand_data[4..36]);
                if (db.getAccountInSlot(&pd_key, bank.slot, bank.ancestors())) |pd_acct| {
                    if (pd_acct.data.len >= 45) {
                        pd_slot = std.mem.readInt(u64, pd_acct.data[4..12], .little);
                        break :blk pd_acct.data[45..];
                    }
                }
            }
        }
        break :blk cand_data;
    };
    if (elf_bytes.len < 16) return;

    v2dispatch.ensureProgramCached(cache, cand_key, elf_bytes, bank.slot, pd_slot) catch |pe| {
        logV2DispatchFallback(@errorName(pe));
    };
}

// ── Wave 6 final: V2 program cache (lazy, replay-thread-local) ─────────────
//
// Replay is single-threaded per ReplayStage; this module-level cache is
// borrowed by `v2DispatchBpfProgram` which OWNS-on-insert. Lazy-init via
// `getOrInitV2ProgramCache` so unit tests that never enter the BPF gap path
// don't allocate the map.
var g_v2_program_cache: ?v2_pc_mod.V2ProgramCache = null;

/// Process-lifetime allocator for the V2 program cache. The cache is shared
/// across every replay dispatch and outlives any per-dispatch arena. Callers
/// previously passed their per-dispatch `v2_alloc` (an `ArenaAllocator`),
/// which dangled the cache's `.allocator` and its map metadata once the
/// arena deinit'd at end-of-dispatch — the next `cache.get()` SEGV'd in
/// `hash_map.getIndex` reading freed metadata. Use `page_allocator` so the
/// cache is genuinely process-scoped, matching the v2_program_cache header
/// contract ("process-scoped, one global, accessed exclusively from the
/// replay thread").
pub fn getOrInitV2ProgramCache(_: std.mem.Allocator) *v2_pc_mod.V2ProgramCache {
    if (g_v2_program_cache == null) {
        g_v2_program_cache = v2_pc_mod.V2ProgramCache.init(std.heap.page_allocator);
    }
    return &g_v2_program_cache.?;
}

/// Wave 6C-1: drop V2 program cache entries inserted before `min_keep_slot`.
/// Called from `onSlotCompleted` on the existing 64-slot rhythm so the cache
/// stays bounded across long-running sessions. Retention window matches the
/// 432-slot Solana slot-history horizon (≈ 3 minutes), which is wide enough
/// that any program touched in the recent past stays cached, narrow enough
/// that long-cold programs evict eventually.
pub const V2_PROGRAM_CACHE_RETENTION_SLOTS: u64 = 432;

fn pruneV2ProgramCache(current_slot: u64) void {
    const cache = &(g_v2_program_cache orelse return);
    const cutoff = current_slot -| V2_PROGRAM_CACHE_RETENTION_SLOTS;
    if (cutoff == 0) return;
    cache.invalidateBeforeSlot(cutoff);
}

/// Wave 6C-1: shutdown hook. Called from `ReplayStage.deinit` (and from
/// `main.zig`'s defer chain when ReplayStage isn't constructed). Idempotent
/// so it's safe to call from multiple shutdown paths.
pub fn deinitV2ProgramCache() void {
    if (g_v2_program_cache) |*cache| {
        cache.deinit();
        g_v2_program_cache = null;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// fix/failed-tx-rollback (2026-06-10, carrier #6 @414386920): tx-scoped
// rollback of instruction writes on the first GENUINE instruction error.
//
// @prov:replay.tx-rollback-canonical-law — the instruction loop STOPS at the
// first failing instruction; a successful tx stores ALL writable accounts,
// a FAILED tx stores ONLY the RollbackAccounts (FeePayerOnly /
// SameNonceAndFeePayer / SeparateNonceAndFeePayer shapes); the durable-nonce
// advance happens at VALIDATION and therefore SURVIVES tx failure.
//
// Vexor shape (B′ — least-regression-risk canonical equivalent): instruction
// writes continue to land EAGERLY in bank.pending_writes (this preserves the
// carrier-#4 intra-tx visibility contract: later instructions of the same tx
// read earlier writes through the r75 pending_writes overlay). On the first
// genuine error the appended range [tx_mark..len) is TRUNCATED
// (shrinkRetainingCapacity — same established pattern as the W6B trampoline
// at :7455-7488), keeping only the durable-nonce advance write when the
// message is a durable-nonce tx (ix0 = System AdvanceNonceAccount) and the
// failure happened AFTER ix0. Because the lt mixin (bank.zig:3243 freeze
// per-pubkey aggregation), the db landing AND the recorder emission
// (flushPendingWritesToDb :6197+) all consume pending_writes AFTER the tx
// loop, a truncated write is byte-UNTOUCHED everywhere — no lt mixin, no
// recorder line, no db write. The fee debit was appended BEFORE tx_mark
// (serial path: fee block above the instruction loop; DAG path: the fee unit
// at the top of executeDagTx, above this mark) and is never rolled back —
// matching RollbackAccounts::fee_payer exactly.
//
// ERROR TAXONOMY is enforced PER CALL SITE (Zig error values are global —
// names collide across handlers, so classify-by-name at a central chokepoint
// would mistake e.g. a stake-plumbing InvalidInstructionData for a genuine
// System failure):
//   • dispatchBpfExecution sites: ONLY error.M4_RunFailed is genuine (BPF VM
//     abort or r0!=0 program error, v2_dispatch.zig:1150-1231 — the carrier
//     path). Every other DispatchError (M5_*, M9_*, M1/M2/M3/M6/M8, OOM) is
//     Vexor plumbing/fallback and must NOT fail the tx.
//   • executeSystemInstruction: propagates the canonical system_v2 InstrError
//     set (faithful FD port of InstructionError); error.Unimplemented
//     (NonceEnv-not-wired plumbing) is filtered INSIDE the handler. Any
//     escaping error is genuine.
//   • vote / stake / bpf_loader sites: unchanged `catch {}` — their canonical
//     failures silent-return internally; what escapes is alloc/plumbing.
//     (Documented residual: a failed top-level vote/stake/v1-ELF instruction
//     after an earlier writing instruction still leaks — pre-existing class,
//     see AUTOPILOT-WORKLOG 2026-06-10 risk table.)
// ════════════════════════════════════════════════════════════════════════════

/// First-genuine-failure record for one transaction's instruction loop.
pub const TxFailInfo = struct {
    ix_idx: usize,
    err: anyerror,
};

// ─────────────────────────────────────────────────────────────────────────────
// Post-execution tx-level check (rent-state transitions + lamports conservation)
// — carrier 419957920 (2026-07-05). @prov:replay.rent-state-check
// executor.transactionCheck existed as a faithful, unit-tested FD port with
// ZERO production callers — the cluster failed tx#196/#205 at 419957920 with
// InsufficientFundsForRent (fees-only, writes rolled back) while Vexor
// committed them → bank_hash diverged → delinquency.
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot per-writable-account (lamports, data_len) BEFORE the instruction
/// loop. The fee debit sits BELOW tx_mark, so overlayNewest at this point is
/// the POST-FEE starting state. @prov:replay.rent-state-check Read path = overlayNewest (worker-override-aware)
/// + db — the same substrate the native handlers execute against.
/// Returns null when the tx has no writable accounts.
fn rentCheckSnapshot(
    alloc: std.mem.Allocator,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
) ?[]executor_mod.WritableAccountState {
    var n: usize = 0;
    for (0..ptx.num_accounts) |i| {
        if (ptx.isWritable(@intCast(i))) n += 1;
    }
    if (n == 0) return null;
    // A5 policy (precedent f1f53fe/F4): a crash is consensus-safe; silently
    // SKIPPING a consensus check is not.
    const arr = alloc.alloc(executor_mod.WritableAccountState, n) catch
        @panic("OOM: rentCheckSnapshot alloc — cannot silently skip a consensus check (A5)");
    var j: usize = 0;
    for (0..ptx.num_accounts) |i| {
        if (!ptx.isWritable(@intCast(i))) continue;
        const pk: [32]u8 = ptx.account_keys[i];
        var lam: u64 = 0;
        var dlen: usize = 0;
        if (bank.overlayNewest(&pk)) |w| {
            lam = w.lamports;
            dlen = w.data.len;
        } else {
            const pk_c = core.Pubkey{ .data = pk };
            if (db.getAccountInSlot(&pk_c, bank.slot, bank.ancestors())) |acct| {
                lam = acct.lamports;
                dlen = acct.data.len;
            }
            // else: account does not exist → (0, 0) = Uninitialized (canonical).
        }
        arr[j] = .{
            .pubkey = pk,
            .starting_lamports = lam,
            .starting_data_len = dlen,
            .ending_lamports = lam,
            .ending_data_len = dlen,
            .is_incinerator = std.mem.eql(u8, &pk, &runtime_mod.INCINERATOR_ID),
            .starting_lamports_h = 0,
            .starting_lamports_l = 0,
            .ending_lamports_h = 0,
            .ending_lamports_l = 0,
        };
        j += 1;
    }
    return arr;
}

/// Re-read each snapshotted account AFTER the instruction loop succeeded and
/// run the canonical tx-level check. An account the tx never wrote resolves to
/// the same source as the snapshot → ending == starting → trivially allowed.
/// On violation the caller fails the WHOLE tx (fees + durable-nonce advance
/// kept, execution writes rolled back to tx_mark). @prov:replay.rent-state-check
fn rentCheckVerify(
    states: []executor_mod.WritableAccountState,
    bank: *Bank,
    db: *AccountsDb,
) executor_mod.TxnError!void {
    for (states) |*s| {
        if (bank.overlayNewest(&s.pubkey)) |w| {
            s.ending_lamports = w.lamports;
            s.ending_data_len = w.data.len;
        } else {
            const pk_c = core.Pubkey{ .data = s.pubkey };
            if (db.getAccountInSlot(&pk_c, bank.slot, bank.ancestors())) |acct| {
                s.ending_lamports = acct.lamports;
                s.ending_data_len = acct.data.len;
            } else {
                s.ending_lamports = 0;
                s.ending_data_len = 0;
            }
        }
    }
    return executor_mod.transactionCheck(states, &rentExemptMinimumBalanceDefault);
}

/// fix/cu-parity-batch2 loaded-accounts-data-size-1/2 (2026-07-12).
/// @prov:replay.loaded-accounts-data-size-check — runs ONCE per tx, BEFORE
/// any instruction executes, over each account's pre-tx on-chain state.
/// Accumulates TRANSACTION_ACCOUNT_BASE_SIZE(64)+data.len for every
/// account_key, ADDRESS_LOOKUP_TABLE_BASE_SIZE(8248) per ALT table
/// referenced, and — for a bpf_loader_upgradeable account in "Program" state
/// whose ProgramData isn't already elsewhere in account_keys — the same
/// base+data.len for that ProgramData account too. That last term matters:
/// account_keys lists the (tiny) Program account, not its ProgramData (which
/// holds the actual ELF and is commonly hundreds of KB) — omitting it would
/// systematically UNDER-count almost every tx that invokes a modern
/// upgradeable BPF program, the unsafe direction (Vexor would accept what
/// Agave rejects).
///
/// On exceeding the tx's limit (explicit SetLoadedAccountsDataSizeLimit else
/// MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES=67,108,864): Agave commits the tx
/// fees-only (fee charged + rollback_accounts kept, execution never starts).
/// That is EXACTLY the shape of Vexor's existing pre-ix-loop tx_fail path
/// (fee sits below tx_mark; rollbackFailedTxSink discards writes above it) —
/// so this check runs BEFORE the ix loop, same timing as the builtin_cus
/// pre-check, and on failure skips the loop entirely (not "fails at ix 0";
/// no instruction runs, matching Agave never reaching execution).
///
/// Returns null (within budget) or the failure error.
fn loadedAccountsDataSizeCheck(ptx: *const ParsedTx, bank: *Bank, db: *AccountsDb) ?anyerror {
    const limit = compute_budget.loadedAccountsDataSizeLimit(compute_budget.parseInstructions(
        ptx.instructions[0..ptx.num_instructions],
        ptx.account_keys[0..ptx.num_accounts],
    )) catch return error.InvalidLoadedAccountsDataSizeLimit;

    var total: u64 = @as(u64, ptx.num_lookup_tables) * compute_budget.ADDRESS_LOOKUP_TABLE_BASE_SIZE;

    // parseTxFromBytes caps total_keys at 256 (`if (total_keys > 256) return
    // error.TooShort`), so a fixed 256-slot scratch array for "already-
    // counted ProgramData" dedup is safe without an allocator on this
    // hot path.
    var extra_pd: [256][32]u8 = undefined;
    var extra_pd_n: usize = 0;

    for (0..ptx.num_accounts) |i| {
        const pk: [32]u8 = ptx.account_keys[i];
        var dlen: usize = 0;
        var owner: [32]u8 = [_]u8{0} ** 32;
        var data: []const u8 = &.{};
        if (bank.overlayNewest(&pk)) |w| {
            dlen = w.data.len;
            owner = w.owner.data;
            data = w.data;
        } else {
            const pk_c = core.Pubkey{ .data = pk };
            if (db.getAccountInSlot(&pk_c, bank.slot, bank.ancestors())) |acct| {
                dlen = acct.data.len;
                owner = acct.owner.data;
                data = acct.data;
            }
            // else: account doesn't exist -> loads as fresh/empty, 0 bytes.
            // @prov:replay.loaded-accounts-data-size-check
        }
        total += compute_budget.TRANSACTION_ACCOUNT_BASE_SIZE + dlen;

        // ProgramData special-case: only for bpf_loader_upgradeable-owned
        // accounts in "Program" state — tag(u32 LE)=2 (STATE_PROGRAM,
        // loader-v3-interface state.rs) + 32-byte programdata_address, 36
        // bytes total (native/bpf_loader_program.zig PROGRAM_SIZE=36 confirms
        // this exact layout independently). @prov:replay.loaded-accounts-data-size-check
        if (std.mem.eql(u8, &owner, &BPF_LOADER_UPGRADEABLE) and data.len >= 36) {
            const tag = std.mem.readInt(u32, data[0..4], .little);
            if (tag == 2) {
                var pd_addr: [32]u8 = undefined;
                @memcpy(&pd_addr, data[4..36]);
                var already = false;
                for (ptx.account_keys[0..ptx.num_accounts]) |k| {
                    if (std.mem.eql(u8, &k, &pd_addr)) {
                        already = true;
                        break;
                    }
                }
                if (!already) {
                    for (extra_pd[0..extra_pd_n]) |k| {
                        if (std.mem.eql(u8, &k, &pd_addr)) {
                            already = true;
                            break;
                        }
                    }
                }
                if (!already) {
                    var pd_dlen: ?usize = null;
                    if (bank.overlayNewest(&pd_addr)) |w2| {
                        pd_dlen = w2.data.len;
                    } else {
                        const pd_c = core.Pubkey{ .data = pd_addr };
                        if (db.getAccountInSlot(&pd_c, bank.slot, bank.ancestors())) |pd_acct| {
                            pd_dlen = pd_acct.data.len;
                        }
                    }
                    if (pd_dlen) |pdl| {
                        total += compute_budget.TRANSACTION_ACCOUNT_BASE_SIZE + pdl;
                        if (extra_pd_n < extra_pd.len) {
                            extra_pd[extra_pd_n] = pd_addr;
                            extra_pd_n += 1;
                        }
                    }
                    // else: programdata account doesn't exist -> contributes 0.
                    // @prov:replay.loaded-accounts-data-size-check
                }
            }
        }
    }

    if (total > limit) return error.MaxLoadedAccountsDataSizeExceeded;
    return null;
}

/// Loud accounting (requirement: NEVER silent). Non-atomic statics are fine —
/// both instruction loops run on the single replay thread (VoteDbg precedent).
pub const TxRollbackStats = struct {
    pub var txs_failed_rolled_back: u64 = 0;
    pub var accounts_rolled_back: u64 = 0;
    pub var nonce_writes_kept: u64 = 0;
    var log_slot: u64 = std.math.maxInt(u64);
    var logs_this_slot: u32 = 0;
};

/// @prov:replay.durable-nonce-rollback — the message's FIRST instruction must
/// be System::AdvanceNonceAccount (discriminant 4); the nonce account is that
/// instruction's account[0]. Only this shape makes the tx a durable-nonce tx —
/// an AdvanceNonceAccount at ix>0 gets NO rollback protection (FeePayerOnly).
pub fn txDurableNoncePk(ptx: *const ParsedTx) ?[32]u8 {
    if (ptx.num_instructions == 0) return null;
    const ix0 = ptx.instructions[0];
    if (ix0.program_id_index >= ptx.static_key_count) return null;
    if (ix0.program_id_index >= ptx.account_keys.len) return null;
    if (!std.mem.eql(u8, &ptx.account_keys[ix0.program_id_index], &NATIVE_PROGRAM_IDS.SYSTEM)) return null;
    if (ix0.data.len < 4) return null;
    if (std.mem.readInt(u32, ix0.data[0..4], .little) != 4) return null; // AdvanceNonceAccount
    if (ix0.account_indices.len == 0) return null;
    const ai = ix0.account_indices[0];
    if (ai >= ptx.num_accounts) return null;
    // @prov:replay.durable-nonce-rollback — nonce account must be writable for rollback capture.
    if (!ptx.isWritable(ai)) return null;
    return ptx.account_keys[ai];
}

pub const RollbackResult = struct { rolled: usize, nonce_kept: bool };

/// Truncate this tx's appended writes [mark..len), optionally keeping the
/// FIRST write whose pubkey == nonce_keep (the ix0 AdvanceNonceAccount write).
/// @prov:replay.durable-nonce-rollback Dropped
/// AccountWrite.data slices are NOT freed here — identical lifecycle to the
/// W6B trampoline truncation (:7488): data is arena/bank.allocator-owned and
/// reclaimed at slot teardown; flushPendingWritesToDb deep-copies what it
/// keeps, so no dangling reference can escape.
pub fn rollbackFailedTxWrites(bank: *Bank, mark: usize, nonce_keep: ?[32]u8) RollbackResult {
    const items = bank.pending_writes.items;
    if (items.len <= mark) return .{ .rolled = 0, .nonce_kept = false };

    // [TOPVOTES-TRACE] TEMPORARY measurement — vote-owned writes about to be
    // dropped by failed-tx rollback (candidate drain for the site1=0 paradox).
    // The optionally-kept nonce write is never vote-owned, so counting the whole
    // [mark..] range is exact for vote entries.
    if (bank_mod.TvTrace.on()) {
        var tvt_n: u32 = 0;
        for (items[mark..]) |*w| {
            if (std.mem.eql(u8, &w.owner.data, &bank_mod.TvTrace.VOTE_OWNER)) tvt_n += 1;
        }
        bank.tvt_vote_rolled_fail += tvt_n;
    }
    var kept: usize = 0;
    if (nonce_keep) |npk| {
        var i: usize = mark;
        while (i < items.len) : (i += 1) {
            if (std.mem.eql(u8, &items[i].pubkey.data, &npk)) {
                // Keep ONLY the FIRST nonce write (= the ix0 advance). Any
                // LATER same-tx mutation of the nonce account is discarded.
                // @prov:replay.durable-nonce-rollback
                if (i != mark) items[mark] = items[i];
                kept = 1;
                break;
            }
        }
    }
    const rolled = items.len - mark - kept;
    bank.pending_writes.shrinkRetainingCapacity(mark + kept);
    return .{ .rolled = rolled, .nonce_kept = kept == 1 };
}

/// Full failed-tx handling for both instruction loops (DAG + serial): durable
/// nonce detection, rollback, counters, rate-limited [TX-ROLLBACK] log
/// (first 4 per slot + every 100th overall — loud but bounded).
pub fn rollbackFailedTx(bank: *Bank, ptx: *const ParsedTx, mark: usize, fail: TxFailInfo) void {
    // Nonce advance survives ONLY when the failure happened after ix0 — if
    // ix0 (the advance itself) failed, no advance write exists.
    // @prov:replay.durable-nonce-rollback (documented deferred residual)
    const nonce_keep: ?[32]u8 = if (fail.ix_idx > 0) txDurableNoncePk(ptx) else null;
    const res = rollbackFailedTxWrites(bank, mark, nonce_keep);
    TxRollbackStats.txs_failed_rolled_back += 1;
    TxRollbackStats.accounts_rolled_back += res.rolled;
    if (res.nonce_kept) TxRollbackStats.nonce_writes_kept += 1;
    if (TxRollbackStats.log_slot != bank.slot) {
        TxRollbackStats.log_slot = bank.slot;
        TxRollbackStats.logs_this_slot = 0;
    }
    TxRollbackStats.logs_this_slot +|= 1;
    if (TxRollbackStats.logs_this_slot <= 4 or TxRollbackStats.txs_failed_rolled_back % 100 == 0) {
        std.log.warn(
            "[TX-ROLLBACK] slot={d} failed_ix={d} err={s} rolled_back={d} nonce_kept={} totals: txs={d} accts={d} nonce={d}",
            .{
                bank.slot,
                fail.ix_idx,
                @errorName(fail.err),
                res.rolled,
                res.nonce_kept,
                TxRollbackStats.txs_failed_rolled_back,
                TxRollbackStats.accounts_rolled_back,
                TxRollbackStats.nonce_writes_kept,
            },
        );
    }
}

/// Stage B B2c — sink-aware per-tx rollback. Serial path (override==null): delegates to
/// rollbackFailedTx, byte-identical to pre-B2c (full truncation + durable-nonce keep +
/// TxRollbackStats + rate-limited log). Worker path (override set): truncates the WORKER's
/// OWN buffer [mark..), keeping the ix0 durable-nonce advance write (same rule as
/// rollbackFailedTxWrites — durable-nonce txs contain a System AdvanceNonceAccount and can
/// be native-eligible). TxRollbackStats are NON-atomic (single-replay-thread assumption),
/// so they are NOT updated on the worker path (diagnostic only, never in bank_hash); the
/// truncation — the consensus-relevant part — IS applied.
fn rollbackFailedTxSink(bank: *Bank, ptx: *const ParsedTx, mark: usize, fail: TxFailInfo) void {
    if (bank_mod.worker_writes_override) |sink| {
        const nonce_keep: ?[32]u8 = if (fail.ix_idx > 0) txDurableNoncePk(ptx) else null;
        const items = sink.items;
        if (items.len <= mark) return;
        var kept: usize = 0;
        if (nonce_keep) |npk| {
            var i: usize = mark;
            while (i < items.len) : (i += 1) {
                if (std.mem.eql(u8, &items[i].pubkey.data, &npk)) {
                    if (i != mark) items[mark] = items[i];
                    kept = 1;
                    break;
                }
            }
        }
        sink.shrinkRetainingCapacity(mark + kept);
    } else {
        rollbackFailedTx(bank, ptx, mark, fail);
    }
}

// ── Wave 4: BPF stack dispatch ──────────────────────────────────────────────
//
// `dispatchBpfExecution` is the single chokepoint for BPF program execution
// from replay. The runtime mode (`vex_bpf2.dispatch_mode.current()`) is
// resolved at boot from `--bpf-stack=v1|v2|shadow` (default v1) and locked
// before replay threads spawn, so it's safe to read here without atomics.
//
// Modes:
//   .v1     — call `executeBpfProgram` (legacy `src/vex_bpf` path). This
//             is byte-identical to the pre-Wave-4 binary.
//   .v2     — V2 dispatch entry. Real V2 dispatch wiring (M1+M3+M2+M6+M8+M4
//             over a real Bank/SysvarCache + AccountMutation translation
//             layer) is the follow-up task in Wave 4.5/Wave 5. For now V2
//             logs a one-time notice and falls through to V1 — this keeps
//             V2 dormant against unintended runtime engagement until the
//             dispatch internals are validated end-to-end. The smoke gate
//             at boot guarantees the V2 modules themselves are sound; the
//             remaining work is the Bank ↔ M8 InvokeContext adapter +
//             AccountMutation `new_owner` translation + per-program M9
//             fallback table to V1's native handlers (Vote/Stake/ALT/Zk
//             skeleton-pending variants).
//   .shadow — V1 owns commit; V2 runs alongside (currently a no-op stub
//             that emits a synthetic Stage-D log line per BPF instruction
//             to validate the log path + format). When real V2 dispatch
//             lands, this slot runs the actual V2 pipeline and diffs.
//
// IMPORTANT: callers (the two replay sites) wrap this in `catch {}`, so any
// error from this function is benign at the dispatch boundary. We exploit
// that to keep V2/shadow free to surface any issue without affecting V1.
// --- Phase C cut C1 (2026-07-08): executor-bridge layer moved to instruction_dispatch.zig.
//     Forwarding aliases keep every replay_stage.X / cross-module caller resolving unchanged.
const instruction_dispatch = @import("instruction_dispatch.zig");
pub const StakeTaxonomyUnknownStats = instruction_dispatch.StakeTaxonomyUnknownStats;
pub const V1TaxonomyUnknownStats = instruction_dispatch.V1TaxonomyUnknownStats;
pub const VoteTaxonomyUnknownStats = instruction_dispatch.VoteTaxonomyUnknownStats;
pub const captureShadowFixture = instruction_dispatch.captureShadowFixture;
pub const commitV2Mutations = instruction_dispatch.commitV2Mutations;
pub const convertVoteLockouts = instruction_dispatch.convertVoteLockouts;
pub const dispatchBpfExecution = instruction_dispatch.dispatchBpfExecution;
pub const dispatchV3ViaV2Producer = instruction_dispatch.dispatchV3ViaV2Producer;
pub const dispatchZkElGamalBuiltin = instruction_dispatch.dispatchZkElGamalBuiltin;
pub const emitShadowErrLine = instruction_dispatch.emitShadowErrLine;
pub const executeAltInstruction = instruction_dispatch.executeAltInstruction;
pub const executeBpfProgram = instruction_dispatch.executeBpfProgram;
pub const executeBpfProgramCore = instruction_dispatch.executeBpfProgramCore;
pub const executeStakeInstruction = instruction_dispatch.executeStakeInstruction;
pub const executeSystemInstruction = instruction_dispatch.executeSystemInstruction;
pub const executeVoteInstruction = instruction_dispatch.executeVoteInstruction;
pub const executeVoteViaVoteforge = instruction_dispatch.executeVoteViaVoteforge;
pub const gatherVoteCollector = instruction_dispatch.gatherVoteCollector;
pub const logV2DispatchFallback = instruction_dispatch.logV2DispatchFallback;
pub const rentExemptMinimumBalanceDefault = instruction_dispatch.rentExemptMinimumBalanceDefault;
pub const shadowDispatch = instruction_dispatch.shadowDispatch;
pub const v2DispatchInternal = instruction_dispatch.v2DispatchInternal;
pub const warnOncePerSlot = instruction_dispatch.warnOncePerSlot;
pub const wave6b = instruction_dispatch.wave6b;
/// HARDEN-3 (2026-06-16): StakeHistory well-formedness guard for the Core-BPF
/// Stake ON-path. Returns a deterministic error.InvalidStakeHistory when the
/// StakeHistory sysvar buffer the v5 .so will consume is malformed, so the tx
/// fails CLEANLY instead of the .so's order-dependent positional accessor
/// panicking and aborting the replay thread.
///
/// @prov:replay.stake-history-layout — u64 len ‖ len × { epoch:u64,
/// effective:u64, activating:u64, deactivating:u64 }. Production feeds the
/// full 16392B account (8 + 512*32). We accept the canonical full-size
/// buffer and any shorter well-formed buffer (a freshly bootstrapped /
/// low-epoch cluster has fewer entries), but require:
///   • bytes present (sysvar account exists),
///   • size == 16392 OR (>= 8 AND 8 + len*32 <= total len)  — len fits,
///   • newest-first anchor: entries are stored in DESCENDING epoch order;
///     the positional accessor relies on entry[0] being the newest, so a
///     non-descending head is malformed.
/// A null buffer (sysvar missing) is also a clean failure — the .so cannot run
/// stake activation math without it.
pub fn validateStakeHistoryWellFormed(bytes_opt: ?[]const u8, slot: u64) !void {
    const bytes = bytes_opt orelse {
        std.log.warn("[STAKE-BPF-SH-GUARD] slot={d} StakeHistory sysvar MISSING — failing tx cleanly", .{slot});
        return error.InvalidStakeHistory;
    };
    const ENTRY_SIZE: usize = 32;
    const FULL_SIZE: usize = 8 + 512 * ENTRY_SIZE; // 16392
    if (bytes.len < 8) {
        std.log.warn("[STAKE-BPF-SH-GUARD] slot={d} StakeHistory len={d} < 8 (no length prefix) — failing tx", .{ slot, bytes.len });
        return error.InvalidStakeHistory;
    }
    const len = std.mem.readInt(u64, bytes[0..8], .little);
    // Canonical production buffer is exactly 16392B; otherwise the declared
    // entry count must fit in the available bytes (no positional OOB read).
    const max_entries = (bytes.len - 8) / ENTRY_SIZE;
    if (bytes.len != FULL_SIZE and len > max_entries) {
        std.log.warn("[STAKE-BPF-SH-GUARD] slot={d} StakeHistory len={d} declares more entries than {d} bytes hold (max {d}) — failing tx", .{ slot, len, bytes.len, max_entries });
        return error.InvalidStakeHistory;
    }
    if (len > 512) {
        std.log.warn("[STAKE-BPF-SH-GUARD] slot={d} StakeHistory len={d} > 512 cap — failing tx", .{ slot, len });
        return error.InvalidStakeHistory;
    }
    // Newest-first anchor: epochs must be strictly descending from the front.
    // @prov:replay.stake-history-layout — the positional accessor the .so
    // uses assumes this ordering; a violation means the buffer was tampered.
    const usable = @min(len, max_entries);
    if (usable >= 2) {
        var prev = std.mem.readInt(u64, bytes[8..16], .little);
        var i: usize = 1;
        while (i < usable) : (i += 1) {
            const off = 8 + i * ENTRY_SIZE;
            const epoch = std.mem.readInt(u64, bytes[off..][0..8], .little);
            if (epoch >= prev) {
                std.log.warn("[STAKE-BPF-SH-GUARD] slot={d} StakeHistory not newest-first at idx={d} (epoch={d} >= prev={d}) — failing tx", .{ slot, i, epoch, prev });
                return error.InvalidStakeHistory;
            }
            prev = epoch;
        }
    }
}

fn isNativeProgram(program_id: *const [32]u8) bool {
    return std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.SYSTEM) or
        std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.VOTE) or
        std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.STAKE) or
        std.mem.eql(u8, program_id, &NATIVE_PROGRAM_IDS.COMPUTE_BUDGET);
}

/// Verify all precompile instructions in a parsed transaction.
///
/// Builds a TxForPrecompiles from the parsed tx and calls verifyPrecompiles.
/// Returns true if ALL precompile checks pass (or there are no precompile instructions).
/// Returns false if any precompile verification fails — the caller should skip
/// instruction execution for the entire transaction.
///
/// @prov:replay.precompile-verify-order
fn verifyTxPrecompiles(
    allocator: std.mem.Allocator,
    ptx: *const ParsedTx,
    slot: u64,
    feature_set: ?*const features_mod.FeatureSet,
) bool {
    // Build TxInstruction slice for precompile dispatcher
    const instrs = allocator.alloc(precompiles_mod.TxInstruction, ptx.num_instructions) catch return true;
    defer allocator.free(instrs);

    for (ptx.instructions[0..ptx.num_instructions], 0..) |ix, i| {
        instrs[i] = .{
            .program_index = ix.program_id_index,
            .data = ix.data,
        };
    }

    const tx_for_pre = precompiles_mod.TxForPrecompiles{
        .account_keys = ptx.account_keys,
        .instructions = instrs,
    };

    // Use the live FeatureSet when wired; otherwise fall back to an empty
    // set (every gate reads inactive) so pre-bootstrap callers still work.
    var empty_fs = features_mod.FeatureSet.init();
    defer empty_fs.deinit(allocator);
    const fs_ptr: *const features_mod.FeatureSet = feature_set orelse &empty_fs;

    const result = precompiles_mod.verifyPrecompiles(
        allocator,
        &tx_for_pre,
        fs_ptr,
        slot,
    ) catch return true; // OOM: be permissive

    if (result) |failure| {
        std.log.warn("[PRECOMPILE] slot={d} tx failed precompile check: instr_idx={d} custom_err={d}", .{
            slot, failure.instruction_index, failure.custom_error,
        });
        return false;
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Transaction wire format measurement
// Ported from old Vexor src/runtime/transaction.zig:577
// ═══════════════════════════════════════════════════════════════════════════════

// 2026-05-24: per-reject-reason counters for measureTransaction.
// Diagnostic-only; identifies which wire-parse cap or bounds-check is dropping
// transactions at the entry batch_loop call sites (replay_stage.zig:3487, 3829).
// Both call sites do `entry_complete=false; break;` on TooShort, silently
// dropping ALL remaining txs in the entry. A single mis-cap can cascade into
// many missing txs per slot. Counters are non-atomic globals (matches VoteDbg
// pattern) — race-induced undercount is acceptable for a diagnostic.
pub const ParseRejStats = struct {
    pub var total_calls: u64 = 0;
    pub var total_ok: u64 = 0;
    pub var sigs_len_short: u64 = 0; // compact-u16 read fail for num_sigs
    pub var sigs_zero: u64 = 0; // num_sigs == 0
    pub var sigs_over_127: u64 = 0; // num_sigs > 127 (@prov:replay.txn-sig-max-127)
    pub var sigs_oob: u64 = 0; // sigs_end > data.len
    pub var no_version_byte: u64 = 0; // pos >= data.len at version-detect
    pub var versioned_v_nonzero: u64 = 0; // versioned but version byte != 0
    pub var header_short: u64 = 0; // pos + 3 > data.len for message header
    pub var accounts_len_short: u64 = 0; // compact-u16 read fail for num_accounts
    pub var accounts_zero: u64 = 0; // num_accounts == 0
    pub var accounts_over_256: u64 = 0; // num_accounts > 256 (@prov:replay.txn-accounts-max-256)
    pub var accounts_oob: u64 = 0; // accts_end > data.len
    pub var rbh_short: u64 = 0; // pos + 32 > data.len for recent_blockhash
    pub var ix_count_short: u64 = 0; // compact-u16 read fail for num_instructions
    pub var ix_count_over_255: u64 = 0; // num_instructions > 255 (SIMD-160 cap)
    pub var ix_pid_short: u64 = 0; // pos >= data.len for program_id_index
    pub var ix_accts_count_short: u64 = 0; // compact-u16 read fail for num_ix_accounts
    pub var ix_accts_oob: u64 = 0; // pos + num_ix_accounts > data.len
    pub var ix_data_len_short: u64 = 0; // compact-u16 read fail for ix_data_len
    pub var ix_data_oob: u64 = 0; // pos + ix_data_len > data.len
    pub var alt_count_short: u64 = 0; // compact-u16 read fail for num_lookups
    pub var alt_count_over_127: u64 = 0; // num_lookups > 127 (@prov:replay.txn-addr-table-lookup-max-127)
    pub var alt_key_short: u64 = 0; // pos + 32 > data.len for lookup table key
    pub var alt_nw_short: u64 = 0; // compact-u16 read fail for writable_count
    pub var alt_nw_oob: u64 = 0; // pos + nw > data.len
    pub var alt_nr_short: u64 = 0; // compact-u16 read fail for readonly_count
    pub var alt_nr_oob: u64 = 0; // pos + nr > data.len
};

/// Measure the size of a Solana transaction in wire format without fully parsing it.
/// Returns the number of bytes consumed (pos - start).
/// Handles both legacy and versioned (v0) transactions with ALTs.
pub fn measureTransaction(data: []const u8, start: usize) error{TooShort}!usize {
    ParseRejStats.total_calls += 1;
    var pos = start;

    // 1. Signatures — real TXs have 1-19 signatures
    const num_sigs = readCompactU16(data, &pos) catch {
        ParseRejStats.sigs_len_short += 1;
        return error.TooShort;
    };
    // d27dd (2026-05-11): @prov:replay.txn-sig-max-127
    // Vexor had 19, which silently rejects multisig-wallet / DEX / Jito-bundle txs with
    // 20+ sigs; on rejection the caller's tx parse loop breaks and drops ALL subsequent
    // txs in the same entry, causing slot-level sig-count divergence (carrier slot 407744900:
    // Vexor 763 vs cluster 774, -11 txs).
    if (num_sigs == 0) {
        ParseRejStats.sigs_zero += 1;
        return error.TooShort;
    }
    if (num_sigs > 127) {
        ParseRejStats.sigs_over_127 += 1;
        return error.TooShort;
    }
    const sigs_end = pos + @as(usize, num_sigs) * 64;
    if (sigs_end > data.len) {
        ParseRejStats.sigs_oob += 1;
        return error.TooShort;
    }
    pos = sigs_end;

    // 2. Versioned detection
    if (pos >= data.len) {
        ParseRejStats.no_version_byte += 1;
        return error.TooShort;
    }
    const is_versioned = (data[pos] & 0x80) != 0;
    if (is_versioned) {
        const version = data[pos] & 0x7F;
        if (version != 0) {
            ParseRejStats.versioned_v_nonzero += 1;
            return error.TooShort;
        }
        pos += 1;
    }

    // 3. Header (3 bytes)
    if (pos + 3 > data.len) {
        ParseRejStats.header_short += 1;
        return error.TooShort;
    }
    _ = data[pos]; // num_required_sigs — read but not validated here.
    // Removed strict num_req_sigs == num_sigs check.
    // Solana allows num_required_signatures <= num_signatures when transactions
    // have read-only signers. Agave's sanitize() enforces equality, but rejecting
    // here causes a cascade: break aborts the entry loop, silently dropping all
    // subsequent transactions in the entry. The network executes those transactions,
    // causing bank hash divergence. Accept the transaction and let parseTxFromBytes
    // handle validation.
    pos += 3;

    // 4. Account keys
    const num_accounts = readCompactU16(data, &pos) catch {
        ParseRejStats.accounts_len_short += 1;
        return error.TooShort;
    };
    // d27dd: @prov:replay.txn-accounts-max-256
    // Static account-keys can be up to 256 (ALT lookups counted separately).
    if (num_accounts == 0) {
        ParseRejStats.accounts_zero += 1;
        return error.TooShort;
    }
    if (num_accounts > 256) {
        ParseRejStats.accounts_over_256 += 1;
        return error.TooShort;
    }
    const accts_end = pos + @as(usize, num_accounts) * 32;
    if (accts_end > data.len) {
        ParseRejStats.accounts_oob += 1;
        return error.TooShort;
    }
    pos = accts_end;

    // 5. Recent blockhash
    if (pos + 32 > data.len) {
        ParseRejStats.rbh_short += 1;
        return error.TooShort;
    }
    pos += 32;

    // 6. Instructions
    // d27ll (2026-05-11): @prov:replay.txn-instructions-max-255
    // The 64-cap that was here is `MAX_INSTRUCTION_TRACE_LENGTH` from
    // transaction-context/src/lib.rs:26 — a trace-buffer SIZE constant, NOT a wire-
    // parse limit. Misusing it as a parse cap rejected real txs with 65-255 ixs;
    // caller's `entry_complete=false; break :batch_loop` then silently dropped all
    // remaining txs in the slot. Same class as d27dd num_sigs 19→127 fix.
    // Carrier slot: 407,787,569 (Δ=-425 vote txs, -425 system txs = -850 accounts).
    const num_instructions = readCompactU16(data, &pos) catch {
        ParseRejStats.ix_count_short += 1;
        return error.TooShort;
    };
    if (num_instructions > 255) {
        ParseRejStats.ix_count_over_255 += 1;
        return error.TooShort;
    }
    for (0..num_instructions) |_| {
        if (pos >= data.len) {
            ParseRejStats.ix_pid_short += 1;
            return error.TooShort;
        }
        pos += 1; // program_id_index

        const num_ix_accounts = readCompactU16(data, &pos) catch {
            ParseRejStats.ix_accts_count_short += 1;
            return error.TooShort;
        };
        if (pos + num_ix_accounts > data.len) {
            ParseRejStats.ix_accts_oob += 1;
            return error.TooShort;
        }
        pos += num_ix_accounts;

        const ix_data_len = readCompactU16(data, &pos) catch {
            ParseRejStats.ix_data_len_short += 1;
            return error.TooShort;
        };
        if (pos + ix_data_len > data.len) {
            ParseRejStats.ix_data_oob += 1;
            return error.TooShort;
        }
        pos += ix_data_len;
    }

    // 7. ALTs (versioned v0 only)
    if (is_versioned) {
        const num_lookups = readCompactU16(data, &pos) catch {
            ParseRejStats.alt_count_short += 1;
            return error.TooShort;
        };
        // d27dd: @prov:replay.txn-addr-table-lookup-max-127
        if (num_lookups > 127) {
            ParseRejStats.alt_count_over_127 += 1;
            return error.TooShort;
        }
        for (0..num_lookups) |_| {
            if (pos + 32 > data.len) {
                ParseRejStats.alt_key_short += 1;
                return error.TooShort;
            }
            pos += 32; // lookup table key

            const nw = readCompactU16(data, &pos) catch {
                ParseRejStats.alt_nw_short += 1;
                return error.TooShort;
            };
            if (pos + nw > data.len) {
                ParseRejStats.alt_nw_oob += 1;
                return error.TooShort;
            }
            pos += nw;

            const nr = readCompactU16(data, &pos) catch {
                ParseRejStats.alt_nr_short += 1;
                return error.TooShort;
            };
            if (pos + nr > data.len) {
                ParseRejStats.alt_nr_oob += 1;
                return error.TooShort;
            }
            pos += nr;
        }
    }

    ParseRejStats.total_ok += 1;
    return pos - start;
}

/// Read a compact-u16 (Solana's LEB128 variant). Advances pos.
fn readCompactU16(data: []const u8, pos: *usize) !u16 {
    if (pos.* >= data.len) return error.TooShort;
    var value: u32 = 0;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (pos.* + i >= data.len) return error.TooShort;
        const byte = data[pos.* + i];
        value |= @as(u32, byte & 0x7F) << @as(u5, @intCast(i * 7));
        if (byte & 0x80 == 0) {
            pos.* += i + 1;
            if (value > 65535) return error.TooShort;
            return @intCast(value);
        }
    }
    return error.TooShort;
}

// ═══════════════════════════════════════════════════════════════════════════════
// vex-048b synthetic regression test
// Verifies: 4 pool threads self-pin to distinct cores in {20,21,22,23};
// WaitGroup barrier returns without deadlock; counters accessible.
//
// NOTE: tx_indices = empty slices — no real bank/db required. The test
// exercises the pin + barrier + WaitGroup mechanics only. The classification
// dispatch body compiles against real executor signatures but never fires.
//
// THREADLOCAL GOTCHA: Zig runs tests in the same process. If a prior test or
// run left pinned_core set on a thread that the new pool reuses, that thread
// would skip re-pinning. Since `std.Thread.Pool` spawns FRESH OS threads at
// init(), each fresh thread's `pinned_core` starts null (threadlocals are
// zero-initialized per-thread). We also reset `next_svm_core` to 20 at test
// start so core assignments are deterministic across repeated runs.
// ═══════════════════════════════════════════════════════════════════════════════

test "vex-048b parallel worker self-pinning + counter accumulation" {
    const testing = std.testing;
    const alloc = testing.allocator;

    // Reset atomic counter so cores start at 20 deterministically.
    next_svm_core.store(SVM_CORES_FIRST, .seq_cst);

    const N: u32 = 4;

    // Shared barrier: tasks increment after pinning and spin until all N ready.
    var barrier = std.atomic.Value(u32).init(0);

    // Per-task pinned-core output slots.
    var core_out: [N]std.atomic.Value(u32) = undefined;
    for (&core_out) |*v| v.* = std.atomic.Value(u32).init(0);

    // WaitGroup for all N tasks.
    var wg = std.Thread.WaitGroup{};

    // WorkerCtx array — one per task.
    // bank/db/ptxs are undefined because tx_indices is empty (no dispatch happens).
    var ctxs: [N]WorkerCtx = undefined;
    for (0..N) |i| {
        ctxs[i] = WorkerCtx{
            .bank = undefined,
            .db = undefined,
            .ptxs = &[_]ParsedTx{},
            .tx_indices = &[_]u16{},
            .alloc = alloc,
            .wg = &wg,
            .pinned_core_out = &core_out[i],
            .start_barrier = &barrier,
            .start_barrier_n = N,
        };
    }

    // Spawn fresh pool with exactly N workers — matches production n_jobs=4.
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = alloc, .n_jobs = N });
    defer pool.deinit();

    // Enqueue N tasks.
    const t_start = std.time.milliTimestamp();
    for (0..N) |i| {
        wg.start();
        try pool.spawn(parallelWorkerFn, .{&ctxs[i]});
    }

    pool.waitAndWork(&wg);
    const elapsed_ms = std.time.milliTimestamp() - t_start;

    // 1. No deadlock: must complete within 2 seconds.
    try testing.expect(elapsed_ms < 2000);

    // 2. Collect the 4 pinned cores and verify they cover {20,21,22,23} exactly once each.
    var core_seen = [_]bool{false} ** N; // index 0 = core 20, ..., 3 = core 23
    for (0..N) |i| {
        const c = core_out[i].load(.acquire);
        // Each core must be in [SVM_CORES_FIRST, SVM_CORES_FIRST + SVM_CORES_COUNT)
        try testing.expect(c >= SVM_CORES_FIRST);
        try testing.expect(c < SVM_CORES_FIRST + SVM_CORES_COUNT);
        const slot = c - SVM_CORES_FIRST;
        core_seen[slot] = true;
    }
    // All 4 cores covered (no two tasks pinned to the same core).
    for (core_seen) |seen| {
        try testing.expect(seen);
    }

    // 3. Counters all zero (empty tx_indices — no dispatch fired).
    for (0..N) |i| {
        try testing.expectEqual(@as(u64, 0), ctxs[i].sys);
        try testing.expectEqual(@as(u64, 0), ctxs[i].vote);
        try testing.expectEqual(@as(u64, 0), ctxs[i].stake);
        try testing.expectEqual(@as(u64, 0), ctxs[i].compute);
        try testing.expectEqual(@as(u64, 0), ctxs[i].bpf);
    }

    // 4. vex-048c: parallelWorkerFn swapped worker_writes_override back to its
    //    prior value before returning. Orchestrator sees null after the barrier.
    try testing.expect(bank_mod.worker_writes_override == null);
}

// ═══════════════════════════════════════════════════════════════════════════════
// vex-048c writes-redirect regression test
//
// Exercises the `worker_writes_override` threadlocal + merge semantics WITHOUT
// needing a live Bank/AccountsDb. This test validates:
//
//   (1) `bank_mod.worker_writes_override` can be set to a per-worker
//       ArrayListUnmanaged and routes subsequent `AccountWrite` appends there.
//   (2) Switching the override mid-flow does not contaminate the prior buffer.
//   (3) Clearing the override (null) restores the original destination.
//   (4) An orderly concat of worker buffers preserves insertion order per
//       worker (simulating `mergeWorkerWrites` without needing a real Bank).
//
// Count-equivalence to the serial baseline is what vex-048c ships; byte-identical
// ordering across workers is vex-048d's problem (it depends on dispatch order
// through the svm_pool, which vex-048c does not wire).
// ═══════════════════════════════════════════════════════════════════════════════

test "vex-048c writes-redirect: threadlocal override + orderly merge" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const mkWrite = struct {
        fn call(tag: u8) bank_mod.AccountWrite {
            return bank_mod.AccountWrite{
                .pubkey = .{ .data = [_]u8{tag} ** 32 },
                .lamports = @as(u64, tag),
                .owner = .{ .data = [_]u8{0} ** 32 },
                .executable = false,
                .rent_epoch = 0,
                .data = &[_]u8{},
            };
        }
    }.call;

    // Ensure we start with null override (in case a prior test left it set).
    bank_mod.worker_writes_override = null;

    const K: usize = 25;
    const N: usize = 4;

    var buffers: [N]std.ArrayListUnmanaged(bank_mod.AccountWrite) = undefined;
    for (&buffers) |*b| b.* = .{};
    defer for (&buffers) |*b| b.deinit(alloc);

    // 1. For each of N "workers", point the override at its buffer + append K
    //    entries. Simulates what `Bank.collectWrite` would do under override.
    for (0..N) |w| {
        const prior = bank_mod.worker_writes_override;
        bank_mod.worker_writes_override = &buffers[w];
        defer bank_mod.worker_writes_override = prior;

        for (0..K) |s| {
            // Run through the exact same path `Bank.collectWrite` uses: check the
            // threadlocal + append. No Bank instance needed for this plumbing test.
            const dest = bank_mod.worker_writes_override orelse unreachable;
            try dest.append(alloc, mkWrite(@intCast((w * K) + s)));
        }
    }

    // 2. Override restored to null after the last `defer`.
    try testing.expect(bank_mod.worker_writes_override == null);

    // 3. Each buffer has exactly K writes (per-worker isolation preserved).
    for (0..N) |w| {
        try testing.expectEqual(K, buffers[w].items.len);
        // First element's lamports encodes worker index (w*K), last is (w*K + K-1).
        try testing.expectEqual(@as(u64, @intCast(w * K)), buffers[w].items[0].lamports);
        try testing.expectEqual(@as(u64, @intCast(w * K + K - 1)), buffers[w].items[K - 1].lamports);
    }

    // 4. Orderly merge: simulate mergeWorkerWrites by concatenating in worker
    //    order. Verify total count = N*K and per-worker ordering is preserved.
    var merged: std.ArrayListUnmanaged(bank_mod.AccountWrite) = .{};
    defer merged.deinit(alloc);
    for (&buffers) |*b| try merged.appendSlice(alloc, b.items);

    try testing.expectEqual(N * K, merged.items.len);
    for (0..N * K) |i| {
        try testing.expectEqual(@as(u64, @intCast(i)), merged.items[i].lamports);
    }
}
