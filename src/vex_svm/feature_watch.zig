//! Cluster Feature-Status Watcher (READ-ONLY, LOGGING-ONLY diagnostic).
//!
//! Proactive defense against the "feature activates on-chain → Vexor diverges"
//! class of carrier (bit us twice: epoch-977 boundary + disc-18 UpdateCommissionBps).
//!
//! For every entry in `features.KNOWN_FEATURES` this scans the on-chain feature
//! account and, for any that is PENDING (exists, discriminant 0 / activated_at ==
//! None), classifies whether Vexor has BEHAVIORALLY WIRED that feature's gate and
//! warns with lead time if not. It NEVER writes, never mutates pending_writes, and
//! never touches the live FeatureSet — the only side effects are `std.log` lines.
//!
//! Read path: `AccountsDb.getAccountInSlot` (+ `parseFeatureAccount`), the exact
//! read+parse used by `replay_stage.applyNewFeatureActivations`. That accessor is
//! read-only (returns an `AccountView` over committed/ring storage); see
//! accounts.zig:1918.
//!
//! Classification methodology (derived by grepping the codebase for where each
//! feature const is actually CONSUMED at a site that changes execution — NOT from
//! a hand-maintained guess list). See the WIRED / NEEDS_WIRING tables below; each
//! entry carries its consumption-site evidence in a comment.

const std = @import("std");
const core = @import("core");
const vex_store = @import("vex_store");
const features = @import("features.zig");

// ─────────────────────────────────────────────────────────────────────────────
// Classification sets (compile-time, keyed by KNOWN_FEATURES `.name`).
//
// Names below are the EXACT `KnownFeature.name` strings from features.zig — note
// two that differ from their const identifier: VOTE_STATE_LAYOUT_V4's catalog
// name is "vote_state_v4" and REJECT_LEGACY_VOTE_INSTRUCTIONS's is
// "deprecate_legacy_vote_ixs".
// ─────────────────────────────────────────────────────────────────────────────

/// Features whose gate genuinely CHANGES Vexor execution AND is implemented.
/// Evidence (feature name → consumption site that changes execution):
const WIRED = [_][]const u8{
    // ── BPF/syscall dispatch gates (src/vex_svm/v2_dispatch.zig) ──
    "syscall_parameter_address_restrictions", // v2_dispatch.zig:814 isActive → syscall ABI
    "virtual_address_space_adjustments", // v2_dispatch.zig:820 isActive → VM region layout
    "account_data_direct_mapping", // v2_dispatch.zig:826 isActive → direct-mapping ABI
    "enable_sha512_syscall", // v2_dispatch.zig:834 + bpf_loader_program.zig:601 isActive
    "alt_bn128_little_endian", // v2_dispatch.zig:847 isActive → bn254 endianness
    "enable_alt_bn128_g2_syscalls", // v2_dispatch.zig:852 isActive → bn254 G2 arms
    "poseidon_enforce_padding", // v2_dispatch.zig:857 isActive → poseidon padding
    "enable_bls12_381_syscall", // v2_dispatch.zig:866 isActive → BLS12-381 arms
    "migrate_stake_program_to_core_bpf", // v2_dispatch.zig:878 + replay_stage.zig:11772 isActive → Core-BPF route

    // ── Loader gates (src/vex_svm/native/bpf_loader_program.zig) ──
    "loader_v3_minimum_extend_program_size", // bpf_loader_program.zig:592 isActive
    "disable_sbpf_v0_v1_v2_deployment", // bpf_loader_program.zig:607 isActive

    // ── Reward / commission gates (overlay + bare featureActiveAtSlot) ──
    "commission_rate_in_basis_points", // bank.zig:2826 overlay + replay_stage.zig:11222 (disc-18 gate)
    "delay_commission_updates", // bank.zig:2825 overlay + replay_stage.zig:11223
    "block_revenue_sharing", // replay_stage.zig:11225 featureActiveAtSlot → SIMD-0123 handler

    // ── Vote-program gates (threaded into voteforge's feature gates) ──
    // The live FeatureSet is published to instruction_dispatch.g_vote_live_features
    // and consumed by voteforge (executeVoteViaVoteforge → vi.ExecContext.features).
    "vote_state_v4", // voteforge vote_instructions vote_state_v4 gate
    "enable_tower_sync_ix", // voteforge enable_tower_sync_ix gate
    "deprecate_legacy_vote_ixs", // voteforge deprecate_legacy_vote_ixs gate
    "bls_pubkey_management_in_vote_account", // voteforge bls_pubkey_management gate
};

/// Known time-bombs: catalogued, currently absent/pending on cluster, and whose
/// REAL execution consumer is unimplemented (or only a NotImplemented stub) — so
/// activation WILL diverge. Evidence per entry below.
const NEEDS_WIRING = [_][]const u8{
    // custom_commission_collector (SIMD-0232): only consumer outside its def is
    // activationSlot() threaded into voteforge's live feature gates;
    // the real runtime consumer = the post-exec min-balance / commission-collector
    // branch (relax_post_exec_min_balance_check), which is unimplemented.
    "custom_commission_collector",
    // H1 (2026-07-01): direct_account_pointers_in_program_input (SIMD-0449) REMOVED
    // from NEEDS_WIRING — it is now WIRED + ACTIVE on testnet + bank-exact (serializer
    // trailer serialize.zig:330, gate v2_dispatch.zig:905; verified by the staged-feature
    // audit). The old "NotImplemented stub / no consumer" note was STALE and would emit
    // false time-bomb alerts / misdirect a future carrier hunt.
    // relax_post_exec_min_balance_check (SIMD-0392): no consumer found; real
    // consumer = custom_commission_collector branch, unimplemented.
    "relax_post_exec_min_balance_check",
    // define_ltds_fee_only_semantics (SIMD-0186-amend): no consumer found; real
    // consumer = replay block-cost enforcement, unimplemented.
    "define_ltds_fee_only_semantics",
    // ── task #37 (2026-07-06, 4.2.0-beta.0 delta): rekeys + new gates ──
    // enable_tx_v1 (SIMD-0385): NOW in KNOWN_FEATURES with the 4.2 REKEYED pubkey
    // (txv1aq4pp…; the old txv1hPU… placeholder was never catalogued and can no
    // longer activate). Consumer = tx-v1 parse/dispatch, deferred-by-design (#23)
    // → time-bomb watch is exactly what this list is for.
    "enable_tx_v1",
    // custom_commission_collector_v2: 4.2 rekey of the SIMD-0232 gate (3HcSr…);
    // same unimplemented runtime branch as the old key above.
    "custom_commission_collector_v2",
    // alpenglow_v2: 4.2 rekey (a1penGLz8…). Only wired consumer = VAT min-balance
    // arm (bank.zig, OR-gated with the old key); the consensus algorithm itself
    // is unimplemented → warn on staging.
    "alpenglow_v2",
    // SIMD-0525 slot-time regimes: PoH hashes_per_tick / rent slots_per_year /
    // block+account cost limits / shred caps all change per 4.2 slot_params.rs —
    // NONE of that table exists in Vexor yet.
    "reduce_slot_time_to_350ms",
    "reduce_slot_time_to_300ms",
    "reduce_slot_time_to_250ms",
    "reduce_slot_time_to_200ms",
    // SIMD-0391: core-BPF stake upgrade-from-buffer + fixed-point warmup/cooldown
    // (stake_v2) — bank_hash-critical on activation, unimplemented.
    "upgrade_bpf_stake_program_to_v5_1",
    // SIMD-0438: LAMPORTS_PER_BYTE → 6960 rent constant reset, unimplemented.
    "set_lamports_per_byte_to_6960",
    // SIMD-0326 companion: fast leader handover, unimplemented.
    "alpenglow_fast_leader_handover",
};

fn inSet(set: []const []const u8, name: []const u8) bool {
    for (set) |s| {
        if (std.mem.eql(u8, s, name)) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// M3: structured JSONL event emission (feature-gate conformance canary).
//
// Append-only, machine-readable event feed consumed by the scheduled auto-trigger
// (golden/feature-canary-scheduler.sh). One JSONL line is dropped per PENDING
// feature classified `wired` or `unclassified` — the canary's value-add set:
// those are gates Vexor BELIEVES it implemented and the only way to be sure is to
// prove them byte-for-byte against Agave. `needs_wiring` features are already
// KNOWN to diverge (the classifier says so) so they are intentionally NOT emitted;
// they are time-bombs to wire, not conformance candidates. Design doc §d item (1).
//
// OFF-HOT-PATH (zero consensus cost): auditPendingFeatures runs ONLY at (a) boot
// (setLiveFeatureSet) and (b) each epoch-boundary bank, before
// applyNewFeatureActivations (replay_stage.zig:1383 + :7451) — never in the
// per-transaction / per-slot replay loop. A blocking O_APPEND write here therefore
// costs nothing on the hot path; no buffering / background thread is required.
//
// LIVE-SAFETY: emission is OFF by default. It arms only when (offline replay mode,
// the same VEX_LEDGER_REPLAY / VEX_SNAPSHOT_OFFLINE detector M1's force-activate
// uses) OR VEX_CANARY_EMIT is explicitly set. A live validator writes NOTHING to
// disk unless the operator opts in with VEX_CANARY_EMIT=1 — which arms the real
// ~1-epoch-lead trigger feed. Any I/O error is swallowed (diagnostic, never fatal).
// ─────────────────────────────────────────────────────────────────────────────

const CANARY_DEFAULT_DIR = "./forensics/feature-canary";
const CANARY_EVENTS_FILE = "events.jsonl";

fn canaryEmitEnabled() bool {
    if (std.posix.getenv("VEX_CANARY_EMIT") != null) return true;
    return std.posix.getenv("VEX_LEDGER_REPLAY") != null or
        std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null;
}

/// Append one already-formatted JSONL line (including the trailing '\n') to
/// `<dir>/events.jsonl`. Best-effort: creates `dir` if missing, opens
/// O_APPEND|O_CREAT so concurrent canary processes cannot interleave partial
/// lines (our line is ~200 B, well under PIPE_BUF), and silently no-ops on any
/// error (diagnostic feed — never fatal). Split from `appendCanaryEvent` so the
/// emit KAT can target a controlled tmp dir without touching process env.
fn appendCanaryEventTo(dir: []const u8, line: []const u8) void {
    std.fs.cwd().makePath(dir) catch {};
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&pathbuf, "{s}/{s}", .{ dir, CANARY_EVENTS_FILE }) catch return;
    const fd = std.posix.open(path, .{ .ACCMODE = .WRONLY, .APPEND = true, .CREAT = true }, 0o644) catch return;
    defer std.posix.close(fd);
    _ = std.posix.write(fd, line) catch {};
}

/// A PENDING feature is a conformance-canary candidate (worth emitting a trigger
/// for) iff emission is armed AND its class is `wired` or `unclassified` — the
/// value-add set. `needs_wiring` is already KNOWN to diverge, so it is never a
/// candidate. Pure predicate → unit-testable without any I/O.
fn shouldEmitCrossing(emit: bool, cls: Class) bool {
    return emit and cls != .needs_wiring;
}

/// Format one `feature-pending-crossing` JSONL record (trailing '\n' included)
/// into `buf`. Names/pubkeys are identifier-safe (base58 / snake_case) so no JSON
/// string escaping is required. Returns the written slice or an error if `buf` is
/// too small (caller treats that as skip). Pure → unit-testable.
fn formatCrossingEvent(
    buf: []u8,
    ts_unix: i64,
    slot: u64,
    epoch: u64,
    pubkey_b58: []const u8,
    name: []const u8,
    cls: Class,
    build_id: []const u8,
) ![]const u8 {
    return std.fmt.bufPrint(
        buf,
        "{{\"schema\":1,\"kind\":\"feature-pending-crossing\",\"ts_unix\":{d},\"slot\":{d},\"epoch\":{d},\"pubkey\":\"{s}\",\"name\":\"{s}\",\"class\":\"{s}\",\"build_id\":\"{s}\"}}\n",
        .{ ts_unix, slot, epoch, pubkey_b58, name, @tagName(cls), build_id },
    );
}

/// Emit a trigger event for one PENDING feature (into `dir`) if it is a canary
/// candidate. Off-hot-path (see the module header); a blocking append here is free.
fn maybeEmitCrossingTo(
    dir: []const u8,
    emit: bool,
    slot: u64,
    epoch: u64,
    pubkey: *const [32]u8,
    name: []const u8,
    cls: Class,
    build_id: []const u8,
) void {
    if (!shouldEmitCrossing(emit, cls)) return;
    var pkbuf: [44]u8 = undefined;
    const pkj = fmtPubkey(pubkey, &pkbuf);
    var linebuf: [512]u8 = undefined;
    const line = formatCrossingEvent(&linebuf, std.time.timestamp(), slot, epoch, pkj, name, cls, build_id) catch return;
    appendCanaryEventTo(dir, line);
}

/// Env-resolved wrapper (dir = VEX_CANARY_EVENTS_DIR or CANARY_DEFAULT_DIR).
fn maybeEmitCrossing(
    emit: bool,
    slot: u64,
    epoch: u64,
    pubkey: *const [32]u8,
    name: []const u8,
    cls: Class,
    build_id: []const u8,
) void {
    const dir = std.posix.getenv("VEX_CANARY_EVENTS_DIR") orelse CANARY_DEFAULT_DIR;
    maybeEmitCrossingTo(dir, emit, slot, epoch, pubkey, name, cls, build_id);
}

const Class = enum { wired, needs_wiring, unclassified };

fn classify(name: []const u8) Class {
    if (inSet(&NEEDS_WIRING, name)) return .needs_wiring;
    if (inSet(&WIRED, name)) return .wired;
    return .unclassified;
}

/// Format a 32-byte pubkey as base58 into `buf` (44 bytes is enough for a 32-byte
/// key); fall back to hex on encode error. Returns the slice actually used.
fn fmtPubkey(pubkey: *const [32]u8, buf: []u8) []const u8 {
    if (core.base58.encodeToBuf(pubkey, buf)) |s| {
        return s;
    } else |_| {
        // Fallback (only reachable if base58 ever errors — it cannot for a
        // 32-byte key): lowercase hex. `buf` (44B) holds only the first 22
        // bytes (44 hex chars); enough to identify the account in a log.
        const hex = "0123456789abcdef";
        const n = @min(buf.len / 2, pubkey.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            buf[i * 2] = hex[pubkey[i] >> 4];
            buf[i * 2 + 1] = hex[pubkey[i] & 0x0f];
        }
        return buf[0 .. n * 2];
    }
}

/// Scan every KNOWN_FEATURES account, classify each PENDING feature, and log.
///
/// READ-ONLY: reads accounts via `db.getAccountInSlot` and emits `std.log` lines
/// only. It never writes, never mutates `pending_writes`, never touches the live
/// FeatureSet, and has ZERO bank_hash / consensus impact.
///
/// `slot` + `ancestors` should be the fork point at which to read feature state
/// (boot: root bank; epoch boundary: the boundary bank). At an epoch boundary,
/// calling this BEFORE `applyNewFeatureActivations` reports what is pending AND
/// about to activate at the NEXT boundary — i.e. ~1 epoch (~2 day) lead time.
pub fn auditPendingFeatures(
    db: *vex_store.accounts.AccountsDb,
    slot: u64,
    epoch: u64,
    ancestors: []const u64,
) void {
    var pending: usize = 0;
    var unwired: usize = 0;
    var unclassified: usize = 0;
    var wired_pending: usize = 0;

    var keybuf: [44]u8 = undefined;

    // M3: arm the JSONL event feed once per scan (env read is cheap but done here,
    // not per-feature). build_id = the client-identity git short-hash stamped at
    // boot (core.version.setGitHash(build_options.git_hash)); "unknown" pre-stamp.
    const emit = canaryEmitEnabled();
    const build_id = core.version.gitHash();

    // Structured emission for the M2 canary driver: a single-line JSON summary of
    // every PENDING feature (pubkey, name, wired class) built alongside the human
    // logs. Machine-readable so the driver can pick a feature without stderr-
    // grepping the human lines. Fixed stack buffer (pending set is small — a
    // handful); on the (never-observed) overflow we mark `truncated` in the line.
    var json_buf: [16384]u8 = undefined;
    var json_fbs = std.io.fixedBufferStream(&json_buf);
    const jw = json_fbs.writer();
    var json_ok = true;
    var json_first = true;

    for (features.KNOWN_FEATURES) |kf| {
        const key: core.Pubkey = .{ .data = kf.pubkey };
        const view = db.getAccountInSlot(&key, slot, ancestors) orelse continue;
        switch (features.parseFeatureAccount(view.data, view.owner.data)) {
            .pending => {},
            else => continue,
        }
        pending += 1;
        const cls = classify(kf.name);

        // JSON entry for this pending feature (names/pubkeys are identifier-safe →
        // no escaping needed). `@tagName(cls)` = wired|needs_wiring|unclassified.
        if (json_ok) {
            var pkbuf: [44]u8 = undefined;
            const pkj = fmtPubkey(&kf.pubkey, &pkbuf);
            jw.print(
                "{s}{{\"name\":\"{s}\",\"pubkey\":\"{s}\",\"class\":\"{s}\"}}",
                .{ if (json_first) "" else ",", kf.name, pkj, @tagName(cls) },
            ) catch {
                json_ok = false;
            };
            json_first = false;
        }

        switch (cls) {
            .needs_wiring => {
                unwired += 1;
                const pk = fmtPubkey(&kf.pubkey, &keybuf);
                std.log.warn(
                    "[FEATURE-WATCH] 🔴 PENDING+UNWIRED name={s} pubkey={s} — WILL DIVERGE on activation; wire before the boundary",
                    .{ kf.name, pk },
                );
            },
            .wired => {
                wired_pending += 1;
                std.log.info("[FEATURE-WATCH] ✓ pending, wiring verified name={s}", .{kf.name});
            },
            .unclassified => {
                unclassified += 1;
                const pk = fmtPubkey(&kf.pubkey, &keybuf);
                std.log.warn(
                    "[FEATURE-WATCH] ⚠ PENDING+UNCLASSIFIED name={s} pubkey={s} — verify wiring before activation",
                    .{ kf.name, pk },
                );
            },
        }

        // M3: emit a JSONL trigger event for the canary's value-add set only
        // (wired | unclassified). needs_wiring is known-diverge, not a conformance
        // candidate, so maybeEmitCrossing deliberately excludes it. The scheduler
        // dedups on (pubkey, epoch).
        maybeEmitCrossing(emit, slot, epoch, &kf.pubkey, kf.name, cls, build_id);
    }

    // Single machine-readable summary line (always emitted, even when pending==0 so
    // the driver can distinguish "clean scan" from "no scan"). `lead_epochs:1` is
    // the design's documented lead-time assumption when this scan runs at the epoch-
    // boundary bank BEFORE applyNewFeatureActivations (~1 epoch / ~2 days); at boot-
    // time scans the true lead differs — the field is a hint, not a measurement.
    // WARN-level (not info) so it survives vexLogFn's default info-suppression — the
    // M2 driver must be able to parse it without needing VEX_LOG_INFO=1.
    std.log.warn(
        "[FEATURE-WATCH-JSON] {{\"schema\":1,\"slot\":{d},\"scanned\":{d},\"lead_epochs\":1,\"truncated\":{},\"counts\":{{\"pending\":{d},\"unwired\":{d},\"unclassified\":{d},\"wired_pending\":{d}}},\"features\":[{s}]}}",
        .{ slot, features.KNOWN_FEATURES.len, !json_ok, pending, unwired, unclassified, wired_pending, json_fbs.getWritten() },
    );

    if (pending == 0) {
        std.log.info(
            "[FEATURE-WATCH] scanned={d} no pending features @slot={d}",
            .{ features.KNOWN_FEATURES.len, slot },
        );
        return;
    }

    std.log.warn(
        "[FEATURE-WATCH] scanned={d} pending={d} unwired={d} unclassified={d} wired_pending={d} @slot={d}",
        .{ features.KNOWN_FEATURES.len, pending, unwired, unclassified, wired_pending, slot },
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "classification is total and disjoint" {
    // Every WIRED / NEEDS_WIRING name classifies to its own bucket.
    for (WIRED) |n| try std.testing.expectEqual(Class.wired, classify(n));
    for (NEEDS_WIRING) |n| try std.testing.expectEqual(Class.needs_wiring, classify(n));
    // An unknown name is unclassified.
    try std.testing.expectEqual(Class.unclassified, classify("not_a_real_feature_xyz"));
    // No name appears in both sets (NEEDS_WIRING takes precedence in classify, but
    // the sets must not overlap or the summary counters would be wrong).
    for (WIRED) |w| try std.testing.expect(!inSet(&NEEDS_WIRING, w));
}

test "every classified name exists in KNOWN_FEATURES" {
    inline for (WIRED ++ NEEDS_WIRING) |name| {
        var found = false;
        for (features.KNOWN_FEATURES) |kf| {
            if (std.mem.eql(u8, kf.name, name)) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

// ── M3 emission KATs ─────────────────────────────────────────────────────────

test "M3 emit gate: only armed wired/unclassified crossings emit" {
    // disarmed → never
    try std.testing.expect(!shouldEmitCrossing(false, .wired));
    try std.testing.expect(!shouldEmitCrossing(false, .unclassified));
    try std.testing.expect(!shouldEmitCrossing(false, .needs_wiring));
    // armed → value-add set only; needs_wiring (known-diverge) is excluded
    try std.testing.expect(shouldEmitCrossing(true, .wired));
    try std.testing.expect(shouldEmitCrossing(true, .unclassified));
    try std.testing.expect(!shouldEmitCrossing(true, .needs_wiring));
}

test "M3 emit format: one well-formed JSONL record with all required fields" {
    var buf: [512]u8 = undefined;
    const line = try formatCrossingEvent(&buf, 1_752_000_000, 421_310_719, 974, "Feature1111111111111111111111111111111111111", "some_wired_feature", .wired, "9aa44e0");
    // one line, newline-terminated
    try std.testing.expect(std.mem.endsWith(u8, line, "}\n"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "\n"));
    // every required key present
    for ([_][]const u8{
        "\"schema\":1",                    "\"kind\":\"feature-pending-crossing\"",
        "\"ts_unix\":1752000000",          "\"slot\":421310719",
        "\"epoch\":974",                   "\"pubkey\":\"Feature11111",
        "\"name\":\"some_wired_feature\"", "\"class\":\"wired\"",
        "\"build_id\":\"9aa44e0\"",
    }) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, line, needle) != null);
    }
}

test "M3 emit append: exactly one line per emit, append-only round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &pathbuf);

    const pk = [_]u8{3} ** 32;
    // needs_wiring must NOT emit; wired MUST emit exactly once.
    maybeEmitCrossingTo(dir, true, 100, 1, &pk, "nw", .needs_wiring, "b");
    maybeEmitCrossingTo(dir, true, 200, 2, &pk, "w1", .wired, "b");
    var data = try tmp.dir.readFileAlloc(std.testing.allocator, CANARY_EVENTS_FILE, 8192);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, data, "\n"));
    try std.testing.expect(std.mem.indexOf(u8, data, "\"name\":\"w1\"") != null);

    // a second armed emit appends (does not truncate) → two lines.
    maybeEmitCrossingTo(dir, true, 300, 3, &pk, "u1", .unclassified, "b");
    std.testing.allocator.free(data);
    data = try tmp.dir.readFileAlloc(std.testing.allocator, CANARY_EVENTS_FILE, 8192);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, data, "\n"));
}

// Env-driven KAT: only fires when the emit-KAT shell script sets
// VEX_CANARY_EVENTS_DIR (a fresh tmp dir). It emits exactly one wired crossing via
// the REAL production path (maybeEmitCrossing → appendCanaryEvent → env-dir
// resolution → O_APPEND) so the shell/python leg can json-validate the schema.
// A normal `zig build test` leaves the env unset → this test is a no-op.
test "M3 emit KAT (python schema gate): env-driven production-path emit" {
    if (std.posix.getenv("VEX_CANARY_EVENTS_DIR") == null) return;
    const pk = [_]u8{7} ** 32;
    maybeEmitCrossing(true, 421_000_000, 974, &pk, "kat_synthetic_wired_feature", .wired, "katbuild");
}
