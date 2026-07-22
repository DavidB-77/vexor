//! Switch-proof Part 2, M1 — live-path regression gate for the
//! [REVIVE-WOULD-FIRE] detection tap.
//!
//! src/vex_svm/revive_detect.zig KATs (zig build test-revive-detect) prove the
//! PURE decision logic in isolation. This file proves the REAL glue in
//! replay_stage.zig around it — the actual dead_slots iteration, the actual
//! scanCachedSlotHash call, the actual revive_would_fire_logged dedup-latch
//! mutation, and (in the second test) the actual VEX_SLOT_HASH_INJECT_FILE
//! offline-injection env-var path in fetchSlotHashesRemote — by driving the
//! REAL `ReplayStage.sweepPendingTickGateSlots` (made pub for exactly this
//! purpose, see its doc comment) against a REAL ReplayStage instance. Mirrors
//! kat_mark_dead_cascade.zig's established pattern for this struct (arena
//! allocator; auto-spawned worker + sysvar-refresh threads stopped AND JOINED
//! — see `stopAndJoinWorkers` below — before any manual state manipulation,
//! since a still-live sysvar_refresh_thread races this test's direct field
//! writes / real calls into the same single-writer-assumed cache fields).
//!
//! Design: switch-proof self-recovery, Part 2 M1 (dead-slot revive-would-fire
//! detection tap — see src/vex_svm/revive_detect.zig for the pure predicate).
//!
//! Build/run: zig build test-revive-would-fire

const std = @import("std");
const vex_svm = @import("vex_svm");
const core = @import("core");

const ReplayStage = vex_svm.replay_stage.ReplayStage;
const Pubkey = core.Pubkey;

/// ReplayStage.init unconditionally spawns worker_thread + sysvar_refresh_thread
/// (real background threads — this is production init, not a test-only stub).
/// `cached_slot_hashes`/`pending_slot_hashes` are single-writer-assumed fields
/// (installSlotHashes frees+reassigns with no lock) — a still-live
/// sysvar_refresh_thread OR worker_thread racing this test's manual field
/// writes / real calls is a genuine use-after-free. `ReplayStage.deinit()`
/// already documents the correct fix (stop + JOIN both threads); this mirrors
/// that, without the rest of deinit's teardown (the arena reclaims everything
/// else on test exit).
///
/// CORRECTION (2026-07-17): this comment previously claimed a bare
/// `is_running.store(false, .release)` (kat_mark_dead_cascade.zig's pre-fix
/// pattern) was safe for that file "because it never exercises the
/// sysvar-refresh chain." That was wrong — replayWorker (worker_thread) has
/// its OWN independent periodic call into fetchSlotHashesRemote ->
/// installSlotHashes (the "PR-5aq proactive cluster SlotHashes refresh"
/// block, replay_stage.zig ~:9683-9694), entirely separate from
/// sysvar_refresh_thread, and a bare store(false) does not stop a worker
/// already mid-iteration (e.g. blocked in fetchSlotHashesRemote's `waitpid`
/// for up to curl's -m 3 = 3s). Reproduced as a real SIGSEGV (gdb-confirmed:
/// self.allocator.free at replay_stage.zig:2336, called from replayWorker at
/// :9693, on an orphaned never-joined thread from an earlier test) under
/// deliberate CPU starvation; kat_mark_dead_cascade.zig now calls this same
/// `stopAndJoinWorkers` pattern too. See its 2026-07-17 CI-SIGSEGV FIX
/// header comment for the full writeup.
fn stopAndJoinWorkers(stage: *ReplayStage) void {
    stage.is_running.store(false, .release);
    if (stage.worker_thread) |t| {
        t.join();
        stage.worker_thread = null;
    }
    if (stage.sysvar_refresh_thread) |t| {
        t.join();
        stage.sysvar_refresh_thread = null;
    }
}

/// Builds a `cached_slot_hashes`-shaped blob (8-byte LE count + count*(8-byte
/// LE slot, 32-byte hash) — the SysvarS1otHashes111... account's own on-chain
/// layout, same shape `installSlotHashes` expects from the live RPC path) for
/// exactly one (slot, hash) pair, for direct field injection.
fn makeSingleSlotHashBlob(allocator: std.mem.Allocator, slot: u64, hash: [32]u8) ![]u8 {
    const out = try allocator.alloc(u8, 8 + 40);
    std.mem.writeInt(u64, out[0..8], 1, .little);
    std.mem.writeInt(u64, out[8..][0..8], slot, .little);
    @memcpy(out[16..][0..32], &hash);
    return out;
}

test "live-path: REVIVE-WOULD-FIRE fires exactly once for a dead slot once cluster hash resolves, zero mutation of dead_slots/banks" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage); // eliminate the race BEFORE any manual state manipulation

    const DEAD_SLOT: u64 = 555_555;
    const cluster_hash = [_]u8{0xAB} ** 32;

    // Simulate markSlotDeadOne's terminal effect directly (the ONLY state the
    // tap's predicate reads): DEAD_SLOT is in dead_slots, nothing else touched.
    stage.dead_slots.put(DEAD_SLOT, {}) catch unreachable;
    try std.testing.expectEqual(@as(u32, 1), stage.dead_slots.count());
    try std.testing.expectEqual(@as(u32, 0), stage.banks.count());

    // Cluster's cached SlotHashes now confirms a hash for DEAD_SLOT.
    stage.cached_slot_hashes = try makeSingleSlotHashBlob(allocator, DEAD_SLOT, cluster_hash);

    stage.sweepPendingTickGateSlots(); // the REAL function, not a copy

    // Fired: dedup latch recorded exactly this slot.
    try std.testing.expectEqual(@as(u32, 1), stage.revive_would_fire_logged.count());
    try std.testing.expect(stage.revive_would_fire_logged.contains(DEAD_SLOT));

    // ZERO mutation of dead_slots/banks (the M1 hard scope limit).
    try std.testing.expectEqual(@as(u32, 1), stage.dead_slots.count());
    try std.testing.expect(stage.dead_slots.contains(DEAD_SLOT));
    try std.testing.expectEqual(@as(u32, 0), stage.banks.count());

    // Second sweep pass (e.g. a subsequent SlotHashes refresh): dedup latch
    // must suppress a second fire — count stays at 1, not 2.
    stage.sweepPendingTickGateSlots();
    try std.testing.expectEqual(@as(u32, 1), stage.revive_would_fire_logged.count());
}

test "live-path: no cluster-confirmed hash yet -> does not fire; dead slot stays dead unchanged" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    const DEAD_SLOT: u64 = 777_777;
    stage.dead_slots.put(DEAD_SLOT, {}) catch unreachable;
    // cached_slot_hashes stays null (cluster hasn't confirmed / cache is stale).

    stage.sweepPendingTickGateSlots();

    try std.testing.expectEqual(@as(u32, 0), stage.revive_would_fire_logged.count());
    try std.testing.expect(stage.dead_slots.contains(DEAD_SLOT));
}

test "live-path: VEX_SLOT_HASH_INJECT_FILE drives fetchSlotHashesRemote -> installSlotHashes -> sweepPendingTickGateSlots end-to-end" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    const DEAD_SLOT: u64 = 421_935_259;
    stage.dead_slots.put(DEAD_SLOT, {}) catch unreachable;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &pathbuf);
    var file_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try std.fmt.bufPrintZ(&file_path_buf, "{s}/inject.txt", .{dir});
    {
        const f = try tmp.dir.createFile("inject.txt", .{});
        defer f.close();
        // Slot 421935259's real canonical base58 blockhash (== the slot's
        // bank_hash), captured from the live testnet incident this KAT
        // regression-guards; hex 222355518d051e1f...f09bbe.
        var line_buf: [128]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buf, "slot={d} hash=3JG7REXRN7QAYJhj7j9nFPeVq3okjBFMHhSnXBzpuFxZ\n", .{DEAD_SLOT});
        try f.writeAll(line);
    }

    // VEX_SLOT_HASH_INJECT_FILE is hard-gated to offline replay mode (requires
    // VEX_LEDGER_REPLAY or VEX_SNAPSHOT_OFFLINE too — see fetchSlotHashesRemote's
    // doc comment); set the offline marker so the injection actually takes.
    _ = setenv("VEX_SNAPSHOT_OFFLINE", "1", 1);
    defer _ = unsetenv("VEX_SNAPSHOT_OFFLINE");
    _ = setenv("VEX_SLOT_HASH_INJECT_FILE", file_path.ptr, 1);
    defer _ = unsetenv("VEX_SLOT_HASH_INJECT_FILE");

    // Force getNetworkBankHash down its cold-prime path (synchronous
    // fetchSlotHashesRemote -> installSlotHashes -> sweep). ReplayStage.init
    // spawns sysvar_refresh_thread, which can complete a REAL network fetch and
    // populate cached_slot_hashes BEFORE stopAndJoinWorkers joins it (join waits
    // for the in-flight fetch, it does not prevent it). A non-null cache makes
    // getNetworkBankHash skip the inject fetch, so scanCachedSlotHash misses the
    // injected slot — the "expected 1, found 0" race. Clearing here (workers are
    // already joined and dead, so nothing repopulates it) makes the inject path
    // deterministic. arena-backed; no free needed.
    stage.pending_slot_hashes = null;
    stage.cached_slot_hashes = null;

    // fetchSlotHashesRemote/installSlotHashes are private (file-scope); this
    // test reaches the REAL chain via getNetworkBankHash (made pub for this
    // KAT — see its doc comment), a genuine production caller (vote path)
    // that, on a cold/empty cache, synchronously calls
    // fetchSlotHashesRemote -> installSlotHashes -> sweepPendingTickGateSlots
    // — the exact same chain the sysvar-refresh worker drives periodically in
    // production, just reached from a different real call site.
    const got = stage.getNetworkBankHash(DEAD_SLOT);
    _ = got; // may be null (PR-5ah guard has no local bank to compare) — irrelevant here

    try std.testing.expectEqual(@as(u32, 1), stage.revive_would_fire_logged.count());
    try std.testing.expect(stage.revive_would_fire_logged.contains(DEAD_SLOT));
    try std.testing.expect(stage.dead_slots.contains(DEAD_SLOT));
}

// Test-only libc externs (mirrors main.zig:210's identical setenv declaration
// — std.posix has no portable setenv/unsetenv on this target).
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;
