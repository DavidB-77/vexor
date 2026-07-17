//! KAT — repair-peer stake-weighting accessor (commit 34bce76,
//! feat/repair-peer-stakeweight-2026-06-19).
//!
//! Standalone test target for `LeaderScheduleCache.fillStakesForSlot`, the
//! locked copy-out accessor that the gated `-Drepair_stake_weighting`
//! tvu.getRepairPeers branch reads to weight repair candidates by cached epoch
//! stake (NON-CONSENSUS liveness; never feeds bank_hash/vote/consensus).
//!
//! `fillStakesForSlot` is `pub` and `epoch_stakes` is a public field of
//! `LeaderScheduleCache`, so this external test file can construct the cache,
//! populate `epoch_stakes` directly for the epoch containing a chosen slot, and
//! assert the copy-out semantics WITHOUT touching the live AccountsDb /
//! populateAgaveCanonical path. Mirrors the in-repo small test-target pattern
//! (test-tower / test-fork-choice) but lives in its own file because the 3
//! committed source files must not be edited.
//!
//! Generator defaults exercised (LeaderScheduleGenerator.init):
//!   slots_per_epoch   = 432000
//!   first_normal_slot = 524256
//!   first_normal_epoch= 14
//! ⇒ for a normal-range slot, getEpoch(slot) = 14 + (slot-524256)/432000.
//!
//! Run: zig build test-leader-schedule-repair

const std = @import("std");
const ls = @import("leader_schedule.zig");

const testing = std.testing;

// Helper: build a [32]u8 node identity from a single distinguishing byte.
fn node(b: u8) [32]u8 {
    var k = [_]u8{0} ** 32;
    k[0] = b;
    return k;
}

// Helper: insert a (node→stake) entry into the cache's per-epoch stake map for
// the epoch that CONTAINS `slot`. This is the public `epoch_stakes` field — the
// same map populateAgaveCanonical fills from `stakes_buf` on the live path.
fn putStake(cache: *ls.LeaderScheduleCache, slot: u64, nk: [32]u8, stake: u64) !void {
    const epoch = cache.generator.getEpoch(slot);
    const gop = try cache.epoch_stakes.getOrPut(epoch);
    if (!gop.found_existing) gop.value_ptr.* = .{};
    try gop.value_ptr.put(cache.allocator, nk, stake);
}

test "fillStakesForSlot: known node -> its stake, unknown node -> 0 (cached epoch)" {
    const a = testing.allocator;
    var cache = ls.LeaderScheduleCache.init(a);
    defer cache.deinit();

    // Slot inside epoch 20 (normal range): 524256 + (20-14)*432000 = 3_116_256.
    const slot = cache.generator.getFirstSlotInEpoch(20);
    try testing.expectEqual(@as(u64, 3_116_256), slot);
    try testing.expectEqual(@as(u64, 20), cache.generator.getEpoch(slot));

    const known_a = node(0xAA);
    const known_b = node(0xBB);
    const unknown = node(0xCC);

    try putStake(&cache, slot, known_a, 1_000_000);
    try putStake(&cache, slot, known_b, 42);

    // Query for a different slot in the SAME epoch (epoch 20) to prove the lookup
    // is epoch-keyed, not slot-keyed.
    const query_slot = slot + 12_345;
    try testing.expectEqual(@as(u64, 20), cache.generator.getEpoch(query_slot));

    const nodes = [_][32]u8{ known_a, unknown, known_b };
    var weights = [_]u64{ 7, 7, 7 }; // pre-fill non-zero to prove @memset clears.
    cache.fillStakesForSlot(query_slot, &nodes, &weights);

    try testing.expectEqual(@as(u64, 1_000_000), weights[0]); // known_a
    try testing.expectEqual(@as(u64, 0), weights[1]); // unknown -> 0
    try testing.expectEqual(@as(u64, 42), weights[2]); // known_b
}

test "fillStakesForSlot: uncached epoch -> all zero" {
    const a = testing.allocator;
    var cache = ls.LeaderScheduleCache.init(a);
    defer cache.deinit();

    // Populate epoch 20 only.
    const slot20 = cache.generator.getFirstSlotInEpoch(20);
    const known_a = node(0xAA);
    try putStake(&cache, slot20, known_a, 1_000_000);

    // Query the FIRST slot of epoch 21 — a different, UNcached epoch.
    const slot21 = cache.generator.getFirstSlotInEpoch(21);
    try testing.expectEqual(@as(u64, 21), cache.generator.getEpoch(slot21));
    try testing.expect(cache.generator.getEpoch(slot21) != cache.generator.getEpoch(slot20));

    // Even the node that IS staked in epoch 20 must read 0 in epoch 21.
    const nodes = [_][32]u8{ known_a, node(0xDD) };
    var weights = [_]u64{ 5, 9 };
    cache.fillStakesForSlot(slot21, &nodes, &weights);

    try testing.expectEqual(@as(u64, 0), weights[0]);
    try testing.expectEqual(@as(u64, 0), weights[1]);
}

test "fillStakesForSlot: empty nodes is a no-op (no crash)" {
    const a = testing.allocator;
    var cache = ls.LeaderScheduleCache.init(a);
    defer cache.deinit();

    const slot = cache.generator.getFirstSlotInEpoch(20);
    try putStake(&cache, slot, node(0xAA), 100);

    const nodes = [_][32]u8{};
    var weights = [_]u64{};
    cache.fillStakesForSlot(slot, &nodes, &weights); // assert(len==len) holds (0==0)
}

test "fillStakesForSlot: summed-per-node stake is read back verbatim" {
    // populateAgaveCanonical SUMS multiple vote accounts of one node identity
    // into a single epoch_stakes entry; fillStakesForSlot must return that exact
    // summed value. We emulate the post-sum state directly.
    const a = testing.allocator;
    var cache = ls.LeaderScheduleCache.init(a);
    defer cache.deinit();

    const slot = cache.generator.getFirstSlotInEpoch(15);
    const big = node(0x11);
    try putStake(&cache, slot, big, 3 + 5 + 8); // summed across 3 vote accounts

    const nodes = [_][32]u8{big};
    var weights = [_]u64{0};
    cache.fillStakesForSlot(slot, &nodes, &weights);
    try testing.expectEqual(@as(u64, 16), weights[0]);
}
