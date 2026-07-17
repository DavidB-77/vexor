//! Vexor Clock.unix_ts computation (SIMD-0001 stake-weighted median).
//!
//! This module computes a cluster-agreed Unix timestamp for the Clock sysvar.
//! Running validators submit a timestamp with every vote transaction; the
//! cluster's notion of "now" is the stake-weighted median of those timestamps,
//! then bounded against an epoch-anchored PoH drift estimate so runaway votes
//! (forward or backward) cannot pull the clock arbitrarily far.
//!
//! Wall-clock time is unusable here: on a catching-up validator, wall-clock is
//! "right now" while the slot being replayed was produced minutes or hours in
//! the past. Only the vote timestamps stored IN the slot's txs reflect the
//! real production time, so the median must come from those.
//!
//! @prov:clock.timestamp-reference
//! All structural names and the module layout are Vexor-native by design.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Fractional bounds (in percent) that cap how far the stake-weighted median
/// may drift from the PoH-projected slot timestamp within the current epoch.
/// A "fast" clock (median earlier than PoH expects) is capped at `fast_pct`;
/// a "slow" clock (median later than PoH expects) at `slow_pct`.
///
/// @prov:clock.drift-bounds — the constants the cluster has been running under
/// since `warp_timestamp_again` activated are `25` / `150`. They are exposed here
/// for testability; production callers should use `DEFAULT`.
pub const ClockDriftBounds = struct {
    fast_pct: u32,
    slow_pct: u32,

    pub const DEFAULT: ClockDriftBounds = .{ .fast_pct = 25, .slow_pct = 150 };
};

/// First-slot-of-epoch anchor pair. `unix_ts` is the Clock value when the
/// epoch began; `slot` is that epoch's first slot. Used to compute the PoH
/// drift reference against which the stake-weighted median is bounded.
pub const EpochAnchor = struct {
    slot: u64,
    unix_ts: i64,
};

/// One validator's latest-published timestamp. Collected from each vote
/// account's `last_timestamp` field.
pub const VoteTimestampSample = struct {
    /// Vote account pubkey. Keys stake lookup in the `stakes` table below.
    vote_pubkey: [32]u8,
    /// The slot at which this timestamp was attached by the voter.
    slot: u64,
    /// Unix seconds claimed by the voter for `slot`.
    unix_ts: i64,
};

/// Compact { vote_pubkey → stake_lamports } entry. Caller supplies a slice of
/// these sorted/unsorted; we look up by linear scan since epoch staker counts
/// on mainnet/testnet are ~1-2k entries and a map allocation per call would
/// dwarf the scan cost.
pub const StakeEntry = struct {
    vote_pubkey: [32]u8,
    stake: u64,
};

/// Compute the Clock.unix_ts estimate for `slot` given the set of recent
/// validator timestamps and the per-pubkey stake table.
///
/// Returns `null` if no sample is attributable to any stake (e.g. fresh
/// bootstrap with no collected votes yet) — callers should treat that as
/// "no estimate available, keep previous unix_ts".
///
/// Algorithm:
///   1. Project every sample forward to `slot` by adding `(slot -
///      sample.slot) * ns_per_slot` seconds. This approximates what the
///      voter's wall-clock would read now if their cadence were exact.
///   2. Sum the stake assigned to each projected timestamp (many voters
///      may land on the same integer-second estimate after projection).
///   3. Walk the projected-timestamp table in ascending order; the first
///      bucket whose cumulative stake exceeds half of the total is the
///      stake-weighted median.
///   4. If an epoch anchor is provided, bound the median such that its
///      offset from `anchor.unix_ts` lies within [-fast_pct, +slow_pct] %
///      of the PoH-projected offset `(slot - anchor.slot) * ns_per_slot`.
///      Over-shoot slams to anchor+slow; under-shoot slams to anchor-fast.
pub fn computeStakeWeightedUnixTs(
    allocator: Allocator,
    samples: []const VoteTimestampSample,
    stakes: []const StakeEntry,
    slot: u64,
    ns_per_slot: u64,
    anchor: ?EpochAnchor,
    bounds: ClockDriftBounds,
    fix_estimate_into_u64: bool,
) Allocator.Error!?i64 {
    // Use a SortedArrayHashMap analogue: a simple sorted-by-key pair list.
    // Stake counts per estimated timestamp bucket.
    var buckets = std.array_list.Managed(struct { ts: i64, stake: u128 }).init(allocator);
    defer buckets.deinit();

    var total_stake: u128 = 0;

    for (samples) |s| {
        // Project forward to `slot`. saturating-sub so samples from future
        // slots (shouldn't happen but be safe) just contribute at their own
        // timestamp with zero offset.
        const slot_delta = std.math.sub(u64, slot, s.slot) catch 0;
        const offset_ns: u64 = std.math.mul(u64, ns_per_slot, slot_delta) catch std.math.maxInt(u64);
        const offset_s: i64 = @intCast(offset_ns / 1_000_000_000);
        const estimate = std.math.add(i64, s.unix_ts, offset_s) catch s.unix_ts;

        const stake: u128 = lookupStake(stakes, &s.vote_pubkey);
        total_stake = std.math.add(u128, total_stake, stake) catch total_stake;

        // Insertion sort into buckets by `ts`, merging same-`ts` entries.
        var inserted = false;
        for (buckets.items, 0..) |*entry, i| {
            if (entry.ts == estimate) {
                entry.stake = std.math.add(u128, entry.stake, stake) catch entry.stake;
                inserted = true;
                break;
            }
            if (entry.ts > estimate) {
                try buckets.insert(i, .{ .ts = estimate, .stake = stake });
                inserted = true;
                break;
            }
        }
        if (!inserted) try buckets.append(.{ .ts = estimate, .stake = stake });
    }

    if (total_stake == 0) return null;

    // Walk buckets in ascending timestamp order; first bucket past the
    // half-stake mark is the stake-weighted median.
    var acc: u128 = 0;
    var estimate_s: i64 = 0;
    for (buckets.items) |entry| {
        acc = std.math.add(u128, acc, entry.stake) catch acc;
        if (acc > total_stake / 2) {
            estimate_s = entry.ts;
            break;
        }
    }

    // Apply epoch-anchored drift bounds, if an anchor is provided.
    if (anchor) |a| {
        const slot_since_anchor: u64 = std.math.sub(u64, slot, a.slot) catch 0;
        const poh_offset_ns: u64 = std.math.mul(u64, ns_per_slot, slot_since_anchor) catch std.math.maxInt(u64);

        // @prov:clock.fix-estimate-into-u64 — `warp_timestamp_again`
        // feature-gate: when active, negative (estimate < anchor) deltas
        // saturate to zero instead of underflowing to a huge u64.
        const estimate_offset_s: u64 = if (fix_estimate_into_u64) blk: {
            const est_u: u64 = if (estimate_s < 0) 0 else @intCast(estimate_s);
            const anchor_u: u64 = if (a.unix_ts < 0) 0 else @intCast(a.unix_ts);
            break :blk if (est_u >= anchor_u) est_u - anchor_u else 0;
        } else blk: {
            const delta: i64 = estimate_s -| a.unix_ts;
            break :blk @bitCast(delta);
        };
        const estimate_offset_ns: u64 = std.math.mul(u64, estimate_offset_s, 1_000_000_000) catch std.math.maxInt(u64);

        const fast_bound_ns: u64 = poh_offset_ns * bounds.fast_pct / 100;
        const slow_bound_ns: u64 = poh_offset_ns * bounds.slow_pct / 100;

        if (estimate_offset_ns > poh_offset_ns and
            estimate_offset_ns - poh_offset_ns > slow_bound_ns)
        {
            // Clock ran too slow (median far later than PoH expected) — clamp up.
            estimate_s = a.unix_ts +|
                @as(i64, @intCast(poh_offset_ns / 1_000_000_000)) +|
                @as(i64, @intCast(slow_bound_ns / 1_000_000_000));
        } else if (estimate_offset_ns < poh_offset_ns and
            poh_offset_ns - estimate_offset_ns > fast_bound_ns)
        {
            // Clock ran too fast (median earlier than PoH expected) — clamp down.
            estimate_s = a.unix_ts +|
                @as(i64, @intCast(poh_offset_ns / 1_000_000_000)) -|
                @as(i64, @intCast(fast_bound_ns / 1_000_000_000));
        }
    }

    return estimate_s;
}

fn lookupStake(stakes: []const StakeEntry, pk: *const [32]u8) u128 {
    for (stakes) |s| {
        if (std.mem.eql(u8, &s.vote_pubkey, pk)) return s.stake;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
// @prov:clock.test-vectors — sourced from the reference test suite's expected
// outputs so we know Vexor matches the cluster on identical inputs. Test names
// and structure are Vexor's own.

test "stake-weighted median ignores low-staked outliers" {
    const allocator = std.testing.allocator;
    const ref_ts: i64 = 1_578_909_061;
    const slot: u64 = 5;
    const ns_per_slot: u64 = 400_000_000;

    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

    var pk0 = [_]u8{0} ** 32;
    pk0[0] = 0;
    var pk1 = [_]u8{0} ** 32;
    pk1[0] = 1;
    var pk2 = [_]u8{0} ** 32;
    pk2[0] = 2;
    var pk3 = [_]u8{0} ** 32;
    pk3[0] = 3;
    var pk4 = [_]u8{0} ** 32;
    pk4[0] = 4;

    const stakes = [_]StakeEntry{
        .{ .vote_pubkey = pk0, .stake = 1 * LAMPORTS_PER_SOL },
        .{ .vote_pubkey = pk1, .stake = 1 * LAMPORTS_PER_SOL },
        .{ .vote_pubkey = pk2, .stake = 1_000_000 * LAMPORTS_PER_SOL },
        .{ .vote_pubkey = pk3, .stake = 1_000_000 * LAMPORTS_PER_SOL },
        .{ .vote_pubkey = pk4, .stake = 1_000_000 * LAMPORTS_PER_SOL },
    };

    // Two outliers vote timestamp 0; three high-stake voters vote ref_ts.
    const samples = [_]VoteTimestampSample{
        .{ .vote_pubkey = pk0, .slot = slot, .unix_ts = 0 },
        .{ .vote_pubkey = pk1, .slot = slot, .unix_ts = 0 },
        .{ .vote_pubkey = pk2, .slot = slot, .unix_ts = ref_ts },
        .{ .vote_pubkey = pk3, .slot = slot, .unix_ts = ref_ts },
        .{ .vote_pubkey = pk4, .slot = slot, .unix_ts = ref_ts },
    };

    const got = try computeStakeWeightedUnixTs(
        allocator,
        &samples,
        &stakes,
        slot,
        ns_per_slot,
        null,
        .{ .fast_pct = 25, .slow_pct = 25 },
        false,
    );
    try std.testing.expectEqual(@as(?i64, ref_ts), got);
}

test "returns null when total stake is zero" {
    const allocator = std.testing.allocator;
    const got = try computeStakeWeightedUnixTs(
        allocator,
        &[_]VoteTimestampSample{},
        &[_]StakeEntry{},
        100,
        400_000_000,
        null,
        ClockDriftBounds.DEFAULT,
        false,
    );
    try std.testing.expectEqual(@as(?i64, null), got);
}

test "slow clock is clamped at anchor + slow_bound" {
    const allocator = std.testing.allocator;
    const anchor_slot: u64 = 0;
    const anchor_ts: i64 = 1_000_000_000;
    const slot: u64 = 10_000;
    const ns_per_slot: u64 = 400_000_000;
    // poh_offset = 10_000 * 400ms = 4000s; slow 150% = 6000s cap from anchor.

    var pk = [_]u8{0} ** 32;
    pk[0] = 1;
    const samples = [_]VoteTimestampSample{
        // Massively slow — voter claims 20_000s past anchor, which is way
        // beyond the 4000+6000 = 10_000s slow ceiling.
        .{ .vote_pubkey = pk, .slot = slot, .unix_ts = anchor_ts + 20_000 },
    };
    const stakes = [_]StakeEntry{
        .{ .vote_pubkey = pk, .stake = 1_000_000 },
    };

    const got = try computeStakeWeightedUnixTs(
        allocator,
        &samples,
        &stakes,
        slot,
        ns_per_slot,
        .{ .slot = anchor_slot, .unix_ts = anchor_ts },
        ClockDriftBounds.DEFAULT,
        true, // warp_timestamp_again active
    );

    // Expect: anchor + poh_offset_s + slow_bound_s = 1_000_000_000 + 4000 + 6000
    try std.testing.expectEqual(@as(?i64, anchor_ts + 4000 + 6000), got);
}

test "fast clock is clamped at anchor + poh_offset - fast_bound" {
    const allocator = std.testing.allocator;
    const anchor_slot: u64 = 0;
    const anchor_ts: i64 = 1_000_000_000;
    const slot: u64 = 10_000;
    const ns_per_slot: u64 = 400_000_000;
    // poh_offset = 4000s; fast 25% = 1000s floor below poh.

    var pk = [_]u8{0} ** 32;
    pk[0] = 1;
    const samples = [_]VoteTimestampSample{
        // Voter claims only anchor_ts+100s — way earlier than poh expects.
        .{ .vote_pubkey = pk, .slot = slot, .unix_ts = anchor_ts + 100 },
    };
    const stakes = [_]StakeEntry{
        .{ .vote_pubkey = pk, .stake = 1_000_000 },
    };

    const got = try computeStakeWeightedUnixTs(
        allocator,
        &samples,
        &stakes,
        slot,
        ns_per_slot,
        .{ .slot = anchor_slot, .unix_ts = anchor_ts },
        ClockDriftBounds.DEFAULT,
        true,
    );

    // Expect: anchor + poh_offset - fast_bound = 1_000_000_000 + 4000 - 1000
    try std.testing.expectEqual(@as(?i64, anchor_ts + 4000 - 1000), got);
}

test "sig_clock: per-voter forward projection then stake-weighted median (deliverable #3)" {
    // This is the SIMD-0001 sample-source contract the -Dsig_clock path feeds:
    // each live voter contributes (vote_pubkey, last_timestamp.slot,
    // last_timestamp.ts) at DISTINCT lag from the reading slot, so the per-voter
    // forward projection `(slot - vote_slot) * ns_per_slot` is exercised (the
    // existing tests all use vote_slot == slot → zero projection). The estimate
    // must equal the HAND-COMPUTED stake-weighted median of the PROJECTED
    // timestamps. @prov:clock.stake-weighted-median-projection — on the same inputs.
    const allocator = std.testing.allocator;
    const slot: u64 = 1000;
    const ns_per_slot: u64 = 400_000_000; // 0.4 s/slot — the canonical constant.

    var pkA = [_]u8{0} ** 32;
    pkA[0] = 0xA;
    var pkB = [_]u8{0} ** 32;
    pkB[0] = 0xB;
    var pkC = [_]u8{0} ** 32;
    pkC[0] = 0xC;

    // Stakes: B is the majority block. A+C alone (200) cannot cross half (250).
    const stakes = [_]StakeEntry{
        .{ .vote_pubkey = pkA, .stake = 100 },
        .{ .vote_pubkey = pkB, .stake = 300 },
        .{ .vote_pubkey = pkC, .stake = 100 },
    };
    const total_stake: u128 = 500;
    _ = total_stake;

    // Each voter's last_timestamp is anchored at a different slot, so the forward
    // projection to `slot` differs per voter:
    //   A: delta = 1000-900 = 100 slots -> +40s  -> 50000 + 40  = 50040
    //   B: delta = 1000-950 =  50 slots -> +20s  -> 50020 + 20  = 50040
    //   C: delta = 1000-990 =  10 slots -> + 4s  -> 50100 +  4  = 50104
    const samples = [_]VoteTimestampSample{
        .{ .vote_pubkey = pkA, .slot = 900, .unix_ts = 50_000 },
        .{ .vote_pubkey = pkB, .slot = 950, .unix_ts = 50_020 },
        .{ .vote_pubkey = pkC, .slot = 990, .unix_ts = 50_100 },
    };

    // Buckets after projection (ascending ts):
    //   50040 -> stake A+B = 100 + 300 = 400
    //   50104 -> stake C   = 100
    // total = 500, half = 250. Walking ascending, acc=400 > 250 at 50040.
    // => stake-weighted median = 50040.
    const expected: i64 = 50_040;

    const got = try computeStakeWeightedUnixTs(
        allocator,
        &samples,
        &stakes,
        slot,
        ns_per_slot,
        null, // no anchor → no drift clamp; isolate the projection+median.
        ClockDriftBounds.DEFAULT,
        true, // warp_timestamp_again active for every slot Vexor boots.
    );
    try std.testing.expectEqual(@as(?i64, expected), got);

    // Cross-check: drop the majority voter B and the median moves to the higher
    // projected bucket (A=100 vs C=100 ties on stake; ascending walk picks the
    // first bucket whose cumulative stake STRICTLY exceeds half=100, i.e. C@50104).
    const samples_no_b = [_]VoteTimestampSample{
        .{ .vote_pubkey = pkA, .slot = 900, .unix_ts = 50_000 }, // -> 50040
        .{ .vote_pubkey = pkC, .slot = 990, .unix_ts = 50_100 }, // -> 50104
    };
    const got2 = try computeStakeWeightedUnixTs(
        allocator,
        &samples_no_b,
        &stakes,
        slot,
        ns_per_slot,
        null,
        ClockDriftBounds.DEFAULT,
        true,
    );
    try std.testing.expectEqual(@as(?i64, 50_104), got2);
}
