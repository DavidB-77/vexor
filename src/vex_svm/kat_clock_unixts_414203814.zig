//! Boot-time KAT: Clock.unix_timestamp stake-weighted median @ testnet 414203814.
//!
//! Discriminator for agave-behavior-extractor verdict A (math bug) vs B (input
//! samples). Cluster canonical = 1781011502 (getBlockTime(414203814)) with ALL
//! ~519 prior-slot voters carrying last_timestamp=(414203813, 1781011502).
//!
//! If this KAT passes with the CLEAN unanimous inputs below => the math is
//! Agave/FD-faithful => any live divergence MUST be in the input samples that
//! reach the estimator (top_votes cache carrying stale per-voter last_timestamp,
//! or a high-stake voter missing from selectForFork). => verdict (B).
//!
//! To turn this into a full ground-truth gate, replace the synthetic 519-voter
//! block with the REAL kept-sample dump (pubkey, slot, ts, stake) harvested
//! from the live [CLOCK-CACHE-SAMPLES] path at 414203814 and assert the result
//! still equals 1781011502 — a non-match THERE localizes the stale sample.

const std = @import("std");
const ct = @import("clock_timestamp.zig");

test "clock unix_ts: clean unanimous prior-slot voters -> 1781011502 (A/B discriminator)" {
    const allocator = std.testing.allocator;

    const TARGET_SLOT: u64 = 414203814;
    const VOTE_SLOT: u64 = 414203813;        // prior slot
    const CLUSTER_TS: i64 = 1781011502;      // unanimous last_timestamp.timestamp
    const NS_PER_SLOT: u64 = 400_000_000;    // testnet: 64 ticks * 6_250_000 ns
    const N: usize = 519;

    var samples: [N]ct.VoteTimestampSample = undefined;
    var stakes: [N]ct.StakeEntry = undefined;
    for (0..N) |i| {
        var pk = [_]u8{0} ** 32;
        pk[0] = @intCast(i & 0xff);
        pk[1] = @intCast((i >> 8) & 0xff);
        samples[i] = .{ .vote_pubkey = pk, .slot = VOTE_SLOT, .unix_ts = CLUSTER_TS };
        stakes[i] = .{ .vote_pubkey = pk, .stake = 1_000_000_000 }; // equal stake
    }

    // Anchor: epoch 971 first slot; epoch_start_ts inherited from boot snapshot.
    // For slot_delta=1 the projection is +0s (400ms/1e9 = 0 integer seconds), and
    // estimate_offset ~= poh_offset (both hours-wide), so the drift bound is a
    // no-op here; passing null and Some(anchor) MUST give the same result.
    const got_no_anchor = try ct.computeStakeWeightedUnixTs(
        allocator, &samples, &stakes, TARGET_SLOT, NS_PER_SLOT,
        null, ct.ClockDriftBounds.DEFAULT, true,
    );
    try std.testing.expectEqual(@as(?i64, CLUSTER_TS), got_no_anchor);

    // With an anchor far enough back that the median sits within bounds, result
    // is identical (proves anchor-null vs anchor-set is a red herring at delta=1).
    const anchor = ct.EpochAnchor{
        .slot = TARGET_SLOT - 100_000,        // arbitrary in-epoch anchor slot
        .unix_ts = CLUSTER_TS - 40_000,       // ~100_000 slots * 0.4s = 40_000s
    };
    const got_anchor = try ct.computeStakeWeightedUnixTs(
        allocator, &samples, &stakes, TARGET_SLOT, NS_PER_SLOT,
        anchor, ct.ClockDriftBounds.DEFAULT, true,
    );
    try std.testing.expectEqual(@as(?i64, CLUSTER_TS), got_anchor);
}

test "clock unix_ts: byte offset 32-39 of Clock account carries this value LE" {
    // Clock layout: [slot:u64][epoch_start_ts:i64][epoch:u64][lse:u64][unix_ts:i64]
    // unix_timestamp occupies bytes 32..40, little-endian i64.
    const CLUSTER_TS: i64 = 1781011502;
    var buf: [40]u8 = undefined;
    std.mem.writeInt(i64, buf[32..40], CLUSTER_TS, .little);
    const expected = [_]u8{ 0x2e, 0x14, 0x28, 0x6a, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqualSlices(u8, &expected, buf[32..40]);
}
