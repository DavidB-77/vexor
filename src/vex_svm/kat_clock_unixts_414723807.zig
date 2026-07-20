//! Carrier #15 differential KAT: Clock.unix_timestamp @ testnet slot 414723807.
//!
//! GROUND TRUTH (oracle-node agave-ledger-tool oracle, 2026-06-11):
//!   Clock@414723806 = { slot 414723806, epoch_start_ts 1781078800, epoch 972,
//!                       lse 973, unix_timestamp 1781210359 }   (Vexor MATCHED)
//!   Clock@414723807 = { slot 414723807, epoch_start_ts 1781078800, epoch 972,
//!                       lse 973, unix_timestamp 1781210360 }   (Vexor DIVERGED — held 359)
//!   The sole non-vote tx (HC9oBfF9… "UpdateProperty", feed TYTL-1) persisted
//!   1781210360 into account data → permanent lt_hash divergence (carrier #15).
//!
//! INPUTS (canonical, 100% fidelity):
//!   * vote-accounts blob extracted from `agave-ledger-tool create-snapshot
//!     414723806` (EVERY vote account's bytes as-of-parent-of-onset), parsed
//!     here by Vexor's own vote_state_serde.deserializeVoteState.
//!   * stake table from oracle-node RPC getVoteAccounts during epoch 972
//!     (activatedStake is epoch-frozen).
//!
//! VERDICTS:
//!   * canonical arm == 1781210360 → estimator + canonical inputs reproduce the
//!     cluster ⇒ the LIVE bug is the input feed (top_votes selectForFork serving
//!     different (slot,ts) pairs than parent-bank state).  Fix = sampling feed.
//!   * canonical arm == 1781210359 → estimator/stake/filter bug upstream of the
//!     feed.  Compare the vexor-filter arm to isolate the zero-ts drop.
//!
//! Skips (pass-trivially) when KAT_CLOCK807_BLOB / KAT_CLOCK807_STAKES are not
//! set, so plain `zig build test` stays green without the forensic assets.
//! Run: KAT_CLOCK807_BLOB=forensic-snapshots-carrier15/vote_accounts_806.blob \
//!      KAT_CLOCK807_STAKES=forensic-snapshots-carrier15/stakes_972.bin \
//!      zig build test-clock-kat-414723807

const std = @import("std");
const vex_svm = @import("vex_svm");
const ct = vex_svm.clock_timestamp;
const vss = vex_svm.native.vote_state_serde;

const TARGET_SLOT: u64 = 414723807;
const NS_PER_SLOT: u64 = 400_000_000;
const SLOTS_PER_EPOCH: u64 = 432_000;
const EPOCH_972_FIRST_SLOT: u64 = 414_380_256; // 524256 + (972-14)*432000
const EPOCH_START_TS: i64 = 1_781_078_800; // from canonical Clock@806/807
const ANCESTOR_TS: i64 = 1_781_210_359; // canonical Clock@806 (Vexor matched)
const CLUSTER_TS: i64 = 1_781_210_360; // canonical Clock@807 (Vexor diverged)

const Loaded = struct {
    samples: []ct.VoteTimestampSample,
    stakes: []ct.StakeEntry,
    dropped_zero_ts: usize,
    parse_fail: usize,
};

fn loadInputs(allocator: std.mem.Allocator, drop_zero_ts: bool) !?Loaded {
    const blob_path = std.process.getEnvVarOwned(allocator, "KAT_CLOCK807_BLOB") catch return null;
    defer allocator.free(blob_path);
    const stakes_path = std.process.getEnvVarOwned(allocator, "KAT_CLOCK807_STAKES") catch return null;
    defer allocator.free(stakes_path);

    const blob = std.fs.cwd().readFileAlloc(allocator, blob_path, 256 * 1024 * 1024) catch return null;
    defer allocator.free(blob);
    const stakes_raw = std.fs.cwd().readFileAlloc(allocator, stakes_path, 16 * 1024 * 1024) catch return null;
    defer allocator.free(stakes_raw);

    // stakes file: u32 count | repeat: pubkey[32] stake u64
    if (stakes_raw.len < 4) return null;
    const n_stakes = std.mem.readInt(u32, stakes_raw[0..4], .little);
    var stakes = try allocator.alloc(ct.StakeEntry, n_stakes);
    var sp: usize = 4;
    for (0..n_stakes) |i| {
        if (sp + 40 > stakes_raw.len) return null;
        stakes[i] = .{
            .vote_pubkey = stakes_raw[sp..][0..32].*,
            .stake = std.mem.readInt(u64, stakes_raw[sp + 32 ..][0..8], .little),
        };
        sp += 40;
    }

    // blob: u32 count | repeat: pubkey[32] | u32 data_len | data
    if (blob.len < 4) return null;
    const n_accts = std.mem.readInt(u32, blob[0..4], .little);
    var samples = std.array_list.Managed(ct.VoteTimestampSample).init(allocator);
    defer samples.deinit();
    var dropped_zero: usize = 0;
    var parse_fail: usize = 0;
    var bp: usize = 4;
    for (0..n_accts) |_| {
        if (bp + 36 > blob.len) return null;
        const pk: [32]u8 = blob[bp..][0..32].*;
        const dlen = std.mem.readInt(u32, blob[bp + 32 ..][0..4], .little);
        bp += 36;
        if (bp + dlen > blob.len) return null;
        const data = blob[bp .. bp + dlen];
        bp += dlen;

        const vs = vss.deserializeVoteState(data) orelse {
            parse_fail += 1;
            continue;
        };
        const lt = vs.last_timestamp;
        // Agave bank.rs:2614-2620 sample filter: drop future (checked_sub None)
        // and older than one epoch. (Vexor live ALSO drops ts==0 — bank.zig:939;
        // that arm is toggled by drop_zero_ts to measure its effect.)
        if (drop_zero_ts and lt.timestamp == 0) {
            dropped_zero += 1;
            continue;
        }
        const slot_delta = std.math.sub(u64, TARGET_SLOT, lt.slot) catch continue;
        if (slot_delta > SLOTS_PER_EPOCH) continue;
        try samples.append(.{ .vote_pubkey = pk, .slot = lt.slot, .unix_ts = lt.timestamp });
    }

    return .{
        .samples = try samples.toOwnedSlice(),
        .stakes = stakes,
        .dropped_zero_ts = dropped_zero,
        .parse_fail = parse_fail,
    };
}

fn runArm(allocator: std.mem.Allocator, drop_zero_ts: bool) !?i64 {
    const loaded = (try loadInputs(allocator, drop_zero_ts)) orelse return error.SkipZigTest;
    defer allocator.free(loaded.samples);
    defer allocator.free(loaded.stakes);

    const anchor = ct.EpochAnchor{ .slot = EPOCH_972_FIRST_SLOT, .unix_ts = EPOCH_START_TS };
    const est = try ct.computeStakeWeightedUnixTs(
        allocator,
        loaded.samples,
        loaded.stakes,
        TARGET_SLOT,
        NS_PER_SLOT,
        anchor,
        ct.ClockDriftBounds.DEFAULT,
        true, // warp_timestamp_again active
    );
    std.debug.print(
        "[KAT-807] arm={s} samples={d} stakes={d} parse_fail={d} drop_zero={d} raw_estimate={?d}\n",
        .{
            if (drop_zero_ts) "vexor-live" else "canonical",
            loaded.samples.len, loaded.stakes.len, loaded.parse_fail, loaded.dropped_zero_ts, est,
        },
    );
    // updateClockSysvar monotonic floor (bank.zig:1056 / Agave bank.rs:2294-2299):
    // estimate < ancestor → ancestor.
    if (est) |e| {
        return if (e < ANCESTOR_TS) ANCESTOR_TS else e;
    }
    return ANCESTOR_TS; // estimator None → inherit parent
}

test "carrier #15: canonical samples@806 -> Clock.unix_ts@807 == 1781210360" {
    const allocator = std.testing.allocator;
    const got = try runArm(allocator, false);
    try std.testing.expectEqual(@as(?i64, CLUSTER_TS), got);
}

test "carrier #15: vexor-live zero-ts-drop arm (diagnostic, result printed)" {
    const allocator = std.testing.allocator;
    const got = try runArm(allocator, true);
    // Diagnostic arm: print + compare. If this DIFFERS from the canonical arm,
    // the bank.zig:939 zero-ts drop is consensus-relevant and must be removed.
    std.debug.print("[KAT-807] vexor-live arm result={?d} (cluster={d})\n", .{ got, CLUSTER_TS });
}
