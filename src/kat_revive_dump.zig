//! Switch-proof Part 2, M2 — ARMED live-path regression gate for the Shape-A
//! dead-slot revive DISPATCH (the STAGE-3 god-file wiring in
//! `ReplayStage.sweepPendingTickGateSlots`).
//!
//! SCOPE — what this proves and what it does NOT:
//!   PROVES (non-tautological): with VEX_REVIVE_DEAD_SLOTS armed, the REAL sweep
//!     routes each revive_repair.decideRevive outcome to the correct god-file
//!     action — proceed → (dump removes dead_slots membership) + (repair kick
//!     invoked with the slot) + (attempt counter bumped); the "never dump without
//!     a wired kick" guard (unwired kick ⇒ NO dump, slot stays dead); the
//!     bounded-retry give_up latch (exhausted ⇒ slot stays dead, latched into
//!     revive_gave_up, NO kick). These are the control-flow branches STAGE 3 adds.
//!   DOES NOT PROVE: that the dump actually RELEASES the stall (re-replay →
//!     re-freeze → last_vote advances past the revived slot). That requires the
//!     offline self-recovery boot (needs a re-feed mechanism + populated
//!     cached_slot_hashes) and is out of a unit KAT's reach — see the PART2-WIRING
//!     report section. This file deliberately covers ONLY the dispatch, which is
//!     exactly the new god-file risk surface.
//!
//! Mirrors kat_revive_would_fire.zig's real-ReplayStage pattern (arena; workers
//! stopped+joined before manual state manipulation). Separate binary from
//! kat_revive_would_fire so VEX_REVIVE_DEAD_SLOTS can be armed process-wide
//! WITHOUT breaking that file's flag-OFF zero-mutation invariant (reviveEnabled()
//! caches the env parse process-globally on first call).
//!
//! Build/run: zig build test-revive-dump

const std = @import("std");
const vex_svm = @import("vex_svm");
const core = @import("core");

const ReplayStage = vex_svm.replay_stage.ReplayStage;
const Pubkey = core.Pubkey;

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

fn makeSingleSlotHashBlob(allocator: std.mem.Allocator, slot: u64, hash: [32]u8) ![]u8 {
    const out = try allocator.alloc(u8, 8 + 40);
    std.mem.writeInt(u64, out[0..8], 1, .little);
    std.mem.writeInt(u64, out[8..][0..8], slot, .little);
    @memcpy(out[16..][0..32], &hash);
    return out;
}

/// Repair-kick capture stub. Static so the fn-ptr has no closure; reset per test.
const KickRec = struct {
    var count: u32 = 0;
    var last_slot: u64 = 0;
    fn reset() void {
        count = 0;
        last_slot = 0;
    }
    fn f(ctx: *anyopaque, slot: u64, shred_idx: u64) void {
        _ = ctx;
        _ = shred_idx;
        count += 1;
        last_slot = slot;
    }
};

// std.posix has no portable setenv on this target (mirrors main.zig:210).
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

test "ARMED proceed_dump_repair: dump removes dead_slots membership + invokes repair kick + bumps attempt" {
    _ = setenv("VEX_REVIVE_DEAD_SLOTS", "1", 1);
    KickRec.reset();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);
    stage.setRepairKick(@ptrCast(stage), KickRec.f);

    const DEAD_SLOT: u64 = 900_001;
    const cluster_hash = [_]u8{0xCD} ** 32;
    // Shape A: dead + ABSENT local bank (banks empty) + cluster hash resolves.
    stage.dead_slots.put(DEAD_SLOT, {}) catch unreachable;
    stage.cached_slot_hashes = try makeSingleSlotHashBlob(allocator, DEAD_SLOT, cluster_hash);

    stage.sweepPendingTickGateSlots(); // the REAL sweep, armed

    // Dump fired: dead_slots membership removed (the single-shot re-arm).
    try std.testing.expect(!stage.dead_slots.contains(DEAD_SLOT));
    // Repair kick invoked exactly once, for this slot.
    try std.testing.expectEqual(@as(u32, 1), KickRec.count);
    try std.testing.expectEqual(DEAD_SLOT, KickRec.last_slot);
    // Attempt counter bumped (persists across dump for the give-up bound).
    try std.testing.expectEqual(@as(u8, 1), stage.revive_attempts.get(DEAD_SLOT).?);
    // Not latched as gave-up (attempts remain).
    try std.testing.expect(!stage.revive_gave_up.contains(DEAD_SLOT));
}

test "ARMED no-kick guard: proceed decision but repair kick UNWIRED -> NO dump, slot stays dead" {
    _ = setenv("VEX_REVIVE_DEAD_SLOTS", "1", 1);
    KickRec.reset();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);
    // Deliberately DO NOT wire setRepairKick (repair_kick_fn stays null).

    const DEAD_SLOT: u64 = 900_002;
    const cluster_hash = [_]u8{0xCD} ** 32;
    stage.dead_slots.put(DEAD_SLOT, {}) catch unreachable;
    stage.cached_slot_hashes = try makeSingleSlotHashBlob(allocator, DEAD_SLOT, cluster_hash);

    stage.sweepPendingTickGateSlots();

    // A dump without a kick is worse than the stall — the guard must SKIP the dump.
    try std.testing.expect(stage.dead_slots.contains(DEAD_SLOT)); // still dead
    try std.testing.expectEqual(@as(u32, 0), KickRec.count); // no kick
    try std.testing.expect(stage.revive_attempts.get(DEAD_SLOT) == null); // no attempt bumped
}

test "ARMED give_up_exhausted: attempts at ceiling -> slot stays dead, latched, NO kick" {
    _ = setenv("VEX_REVIVE_DEAD_SLOTS", "1", 1);
    KickRec.reset();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);
    stage.setRepairKick(@ptrCast(stage), KickRec.f);

    const DEAD_SLOT: u64 = 900_003;
    const cluster_hash = [_]u8{0xCD} ** 32;
    stage.dead_slots.put(DEAD_SLOT, {}) catch unreachable;
    stage.cached_slot_hashes = try makeSingleSlotHashBlob(allocator, DEAD_SLOT, cluster_hash);
    // Pre-exhaust the bounded retry (MAX_REVIVE_ATTEMPTS is 3 in replay_stage.zig).
    stage.revive_attempts.put(DEAD_SLOT, 3) catch unreachable;

    stage.sweepPendingTickGateSlots();

    // Give-up: slot stays dead, latched permanently, no further dump/kick.
    try std.testing.expect(stage.dead_slots.contains(DEAD_SLOT));
    try std.testing.expect(stage.revive_gave_up.contains(DEAD_SLOT));
    try std.testing.expectEqual(@as(u32, 0), KickRec.count);

    // Second sweep: the gave-up latch means it is skipped entirely (still no kick).
    stage.sweepPendingTickGateSlots();
    try std.testing.expectEqual(@as(u32, 0), KickRec.count);
}
