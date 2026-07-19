//! Carrier differential KAT: Clock.unix_timestamp @ testnet slot 420860261
//! (epoch-987 boundary+5). Third instance of the SIMD-0001 estimator carrier
//! (after @414203814 and carrier #15 @414723807).
//!
//! GROUND TRUTH (per-account diff of slot 420860261 vs cluster-canonical,
//! oracle-node create-snapshot; SLOTD_FINDINGS 2026-07-09):
//!   Clock@420860261 canonical = { slot 420860261, epoch_start_ts 1783624397,
//!                                  epoch 987, lse 988, unix_timestamp 1783624399 }
//!   Vexor DIVERGED: unix_timestamp = 1783624398  (canon − 1s).
//!   Every other slot-D write (5064 total, incl. all 4133 stake-reward writes)
//!   was byte-identical; a downstream program account stored clock_ts+43200 and
//!   inherited the −1s. The −1s Clock diverged lthash → bank_hash → wedge.
//!
//! ROOT CAUSE (this KAT proves it): the estimator arithmetic is Agave-faithful;
//! the bug was the DRIFT ANCHOR. Agave `update_clock` (runtime/src/bank.rs:
//! 2398-2406) recomputes the anchor every slot as (first_slot_of(parent_epoch),
//! parent_clock.epoch_start_timestamp). At boundary+5 that anchor is the CURRENT
//! epoch's first slot (420860256, ts 1783624397) → poh_estimate_offset = 5 slots
//! = 2s → a ±25% fast band of floor(0.5s)=0s that pins the estimate to the PoH
//! projection epoch_start+2 = 1783624399. The pre-fix Vexor code cached the
//! anchor once at the boundary using the PARENT epoch's first slot, freezing a
//! full-epoch-wide (~43200s) band that never clamps → the stake-weighted median,
//! which floor-projects one second low here, sailed through as 1783624398.
//!
//! ARMS (fed the REAL canonical inputs captured at slot 420860261 via
//! VEX_CLOCK_KAT_DUMP — samples = every staked voter's last_timestamp read from
//! the parent-bank vote state, stakes = epoch-987 epoch_stakes):
//!   * NULL anchor (no drift bound)  → RAW stake-weighted median. This is what
//!     the stale full-epoch-wide band also yields (it never clamps). Expected
//!     1783624398 — reproduces the LIVE −1s bug from canonical inputs, proving
//!     the median floor-projects one second low and the estimator needs the
//!     drift clamp to reach canon.
//!   * TIGHT anchor (420860256, 1783624397) = Agave's per-slot current-epoch
//!     anchor. Expected 1783624399 — matches cluster-canonical, proving the
//!     fixed anchor (and only the anchor) closes the divergence.
//!
//! Skips (pass-trivially) when KAT_CLOCK987_BLOB is unset, so plain
//! `zig build test` stays green without the forensic asset. Capture the blob:
//!   VEX_CLOCK_KAT_DUMP=420860261 VEX_CLOCK_KAT_DUMP_PATH=/path/clock987.blob \
//!     <replay the 987-boundary window>
//! then: KAT_CLOCK987_BLOB=/path/clock987.blob \
//!   zig test src/vex_svm/kat_clock_unixts_420860261.zig

const std = @import("std");
const ct = @import("clock_timestamp.zig");

const TARGET_SLOT: u64 = 420860261;
const NS_PER_SLOT: u64 = 400_000_000;
const EPOCH_987_FIRST_SLOT: u64 = 420_860_256; // 524256 + (987-14)*432000
const EPOCH_987_START_TS: i64 = 1_783_624_397; // canonical Clock@D.epoch_start_timestamp
const RAW_MEDIAN_EXPECTED: i64 = 1_783_624_398; // canon − 1s (null-anchor / stale-band result)
const CLUSTER_TS: i64 = 1_783_624_399; // canonical Clock@D.unix_timestamp

const Loaded = struct {
    samples: []ct.VoteTimestampSample,
    stakes: []ct.StakeEntry,
    slot: u64,
    ns_per_slot: u64,
    dump_anchor_present: bool,
    dump_anchor_slot: u64,
    dump_anchor_ts: i64,
};

fn loadBlob(allocator: std.mem.Allocator) !?Loaded {
    const path = std.process.getEnvVarOwned(allocator, "KAT_CLOCK987_BLOB") catch return null;
    defer allocator.free(path);
    const buf = std.fs.cwd().readFileAlloc(allocator, path, 256 * 1024 * 1024) catch return null;
    defer allocator.free(buf);

    if (buf.len < 4 or !std.mem.eql(u8, buf[0..4], "CKAT")) return null;
    var p: usize = 4;
    const rdU64 = struct {
        fn f(b: []const u8, off: *usize) u64 {
            const v = std.mem.readInt(u64, b[off.*..][0..8], .little);
            off.* += 8;
            return v;
        }
    }.f;
    const rdI64 = struct {
        fn f(b: []const u8, off: *usize) i64 {
            const v = std.mem.readInt(i64, b[off.*..][0..8], .little);
            off.* += 8;
            return v;
        }
    }.f;

    const slot = rdU64(buf, &p);
    const ns = rdU64(buf, &p);
    const anchor_present = buf[p] != 0;
    p += 1;
    const a_slot = rdU64(buf, &p);
    const a_ts = rdI64(buf, &p);

    const n_samples = std.mem.readInt(u32, buf[p..][0..4], .little);
    p += 4;
    var samples = try allocator.alloc(ct.VoteTimestampSample, n_samples);
    for (0..n_samples) |i| {
        samples[i] = .{
            .vote_pubkey = buf[p..][0..32].*,
            .slot = std.mem.readInt(u64, buf[p + 32 ..][0..8], .little),
            .unix_ts = std.mem.readInt(i64, buf[p + 40 ..][0..8], .little),
        };
        p += 48;
    }
    const n_stakes = std.mem.readInt(u32, buf[p..][0..4], .little);
    p += 4;
    var stakes = try allocator.alloc(ct.StakeEntry, n_stakes);
    for (0..n_stakes) |i| {
        stakes[i] = .{
            .vote_pubkey = buf[p..][0..32].*,
            .stake = std.mem.readInt(u64, buf[p + 32 ..][0..8], .little),
        };
        p += 40;
    }

    return .{
        .samples = samples,
        .stakes = stakes,
        .slot = slot,
        .ns_per_slot = ns,
        .dump_anchor_present = anchor_present,
        .dump_anchor_slot = a_slot,
        .dump_anchor_ts = a_ts,
    };
}

test "clock@420860261: RAW median (null anchor) reproduces the live −1s = 1783624398" {
    const allocator = std.testing.allocator;
    const loaded = (try loadBlob(allocator)) orelse return error.SkipZigTest;
    defer allocator.free(loaded.samples);
    defer allocator.free(loaded.stakes);

    try std.testing.expectEqual(@as(u64, TARGET_SLOT), loaded.slot);

    const raw = try ct.computeStakeWeightedUnixTs(
        allocator,
        loaded.samples,
        loaded.stakes,
        loaded.slot,
        loaded.ns_per_slot,
        null, // no drift bound → pure stake-weighted median
        ct.ClockDriftBounds.DEFAULT,
        true,
    );
    std.debug.print(
        "[KAT-987] arm=null-anchor samples={d} stakes={d} dump_anchor={?d}/{d} raw_median={?d} (expect {d})\n",
        .{ loaded.samples.len, loaded.stakes.len, if (loaded.dump_anchor_present) loaded.dump_anchor_slot else null, loaded.dump_anchor_ts, raw, RAW_MEDIAN_EXPECTED },
    );
    try std.testing.expectEqual(@as(?i64, RAW_MEDIAN_EXPECTED), raw);
}

test "clock@420860261: Agave per-slot current-epoch anchor -> 1783624399 (canon)" {
    const allocator = std.testing.allocator;
    const loaded = (try loadBlob(allocator)) orelse return error.SkipZigTest;
    defer allocator.free(loaded.samples);
    defer allocator.free(loaded.stakes);

    const anchor = ct.EpochAnchor{ .slot = EPOCH_987_FIRST_SLOT, .unix_ts = EPOCH_987_START_TS };
    const est = try ct.computeStakeWeightedUnixTs(
        allocator,
        loaded.samples,
        loaded.stakes,
        loaded.slot,
        loaded.ns_per_slot,
        anchor,
        ct.ClockDriftBounds.DEFAULT,
        true,
    );
    std.debug.print(
        "[KAT-987] arm=tight-anchor(slot={d},ts={d}) est={?d} (expect {d}=canon)\n",
        .{ EPOCH_987_FIRST_SLOT, EPOCH_987_START_TS, est, CLUSTER_TS },
    );
    try std.testing.expectEqual(@as(?i64, CLUSTER_TS), est);
}
