//! voteforge, stage 1 KATs — vote_codec.zig byte-exactness gate
//! (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 1 gate).
//!
//! Two legs:
//!  1. REAL-ACCOUNT round-trip: the CARRIER-419996256 bisect vector
//!     (FjkDgNYLUXQsPtnxFRs84zPbRnbCgvCjM45cW5QVPY3m, real cluster V4 bytes,
//!     3762B, BOTH authorized_voters entries populated — local byte-identical
//!     copy of src/vex_svm/native/kat_fjkdgnyl_v4_419996256.bin, md5
//!     c99dc983cf03bef8a5dd111dafedb44b) must parse -> serialize back
//!     BYTE-EXACT over the serialized prefix with the stale tail untouched.
//!  2. Negative cases: truncation/garbage rejection, Option-flag strictness,
//!     version-tag validation.
//!
//! (The Sig-transplant differential legs — codec-vs-oracle field parity and
//! oracle-minted V3 round-trips — were removed with the transplant 2026-07-12;
//! the real-cluster golden vector above is the surviving byte-exactness anchor,
//! and V3->V4 migration is exercised live via voteforge/kat_vote_instructions.)

const std = @import("std");
const codec = @import("vote_codec.zig");

const FJK = @embedFile("kat_fjkdgnyl_v4_419996256.bin");
/// Real firedancer-io/test-vectors (pinned 31d8aa8a…) instr/fixtures/vote/
/// bb46e6a09b0a7d7c9d2f8677398fa7ea98e40178.fix — account[0] raw data, 1828B,
/// version tag 1 (V1_14_11). Byte-identical to the array embedded in the grind
/// commit bacc392 (extracted from that source). Its recorded expected result is
/// UninitializedAccount because it genuinely decodes to an EMPTY authorized_voters
/// set under Agave's VoteStateVersions::deserialize.
const V1_BB46 = @embedFile("kat_v1_14_11_bb46e6a0.bin");

/// Lay out a minimal-but-valid V1_14_11 wire buffer (bincode fixint/LE) with the
/// given fields. `votes` are bare Lockouts (12B each, NO per-vote latency byte —
/// the V1_14_11 wire difference vs V3/V4). Used to drive the migrate path with a
/// NON-empty authorized_voters set (the real fixture above is empty and only
/// exercises the UninitializedAccount arm).
fn buildV1_14_11(
    buf: []u8,
    node_pubkey: [32]u8,
    withdrawer: [32]u8,
    commission: u8,
    votes: []const codec.Lockout,
    voter_epoch: u64,
    voter_pubkey: [32]u8,
) usize {
    var o: usize = 0;
    const wu32 = struct {
        fn f(b: []u8, off: *usize, v: u32) void {
            std.mem.writeInt(u32, b[off.*..][0..4], v, .little);
            off.* += 4;
        }
    }.f;
    const wu64 = struct {
        fn f(b: []u8, off: *usize, v: u64) void {
            std.mem.writeInt(u64, b[off.*..][0..8], v, .little);
            off.* += 8;
        }
    }.f;
    wu32(buf, &o, codec.VERSION_TAG_V1_14_11);
    @memcpy(buf[o..][0..32], &node_pubkey);
    o += 32;
    @memcpy(buf[o..][0..32], &withdrawer);
    o += 32;
    buf[o] = commission;
    o += 1;
    // votes: VecDeque<Lockout> — len + N*(slot u64, conf u32), no latency byte.
    wu64(buf, &o, @intCast(votes.len));
    for (votes) |v| {
        wu64(buf, &o, v.slot);
        wu32(buf, &o, v.confirmation_count);
    }
    // root_slot: Option<u64> = None.
    buf[o] = 0;
    o += 1;
    // authorized_voters: len + (epoch u64, pubkey 32).
    wu64(buf, &o, 1);
    wu64(buf, &o, voter_epoch);
    @memcpy(buf[o..][0..32], &voter_pubkey);
    o += 32;
    // prior_voters: opaque 1545B CircBuf blob (zeros).
    @memset(buf[o..][0..codec.PRIOR_VOTERS_BLOB_LEN], 0);
    o += codec.PRIOR_VOTERS_BLOB_LEN;
    // epoch_credits: len = 0.
    wu64(buf, &o, 0);
    // last_timestamp: slot u64 + timestamp i64.
    wu64(buf, &o, 0);
    wu64(buf, &o, 0);
    return o;
}

// ── Leg 1: real cluster V4 account ───────────────────────────────────────────

test "STAGE1-KAT: real FjkDgNYL V4 bytes parse with expected field values" {
    const p = try codec.VoteStateV4.parse(FJK);
    const s = p.state;

    try std.testing.expectEqual(@as(u16, 10_000), s.inflation_rewards_commission_bps);
    try std.testing.expectEqual(@as(u16, 10_000), s.block_revenue_commission_bps);
    try std.testing.expectEqual(@as(u64, 0), s.pending_delegator_rewards);
    try std.testing.expect(s.bls_pubkey_compressed != null);
    try std.testing.expectEqual(@as(usize, 31), s.tail.votes_len);
    try std.testing.expectEqual(@as(u64, 420011904), s.tail.votes[0].lockout.slot);
    try std.testing.expectEqual(@as(u32, 31), s.tail.votes[0].lockout.confirmation_count);
    try std.testing.expectEqual(@as(u8, 1), s.tail.votes[0].latency);
    try std.testing.expectEqual(@as(?u64, 420011903), s.tail.root_slot);
    // THE 419996256 carrier invariant: BOTH authorized_voters entries.
    try std.testing.expectEqual(@as(usize, 2), s.tail.authorized_voters_len);
    try std.testing.expectEqual(@as(u64, 984), s.tail.authorized_voters[0].epoch);
    try std.testing.expectEqual(@as(u64, 985), s.tail.authorized_voters[1].epoch);
    try std.testing.expectEqual(@as(usize, 64), s.tail.epoch_credits_len);
    try std.testing.expectEqual(@as(u64, 420011941), s.tail.last_timestamp.slot);
    try std.testing.expectEqual(@as(i64, 1783290894), s.tail.last_timestamp.timestamp);
    try std.testing.expectEqual(@as(usize, 2261), p.consumed);
}

test "STAGE1-KAT: real FjkDgNYL V4 round-trip is byte-exact incl. untouched stale tail" {
    const p = try codec.VoteStateV4.parse(FJK);

    var out: [3762]u8 = undefined;
    @memset(&out, 0xEE); // sentinel: serialize must not touch past `written`
    const written = try p.state.serialize(&out);

    try std.testing.expectEqual(p.consumed, written);
    try std.testing.expectEqualSlices(u8, FJK[0..written], out[0..written]);
    for (out[written..]) |b| try std.testing.expectEqual(@as(u8, 0xEE), b);

    // Full-buffer contract as the seam will use it: copy account, serialize
    // in place, whole 3762B must equal the original (tail preserved).
    var acct: [3762]u8 = undefined;
    @memcpy(&acct, FJK);
    _ = try p.state.serialize(&acct);
    try std.testing.expectEqualSlices(u8, FJK, &acct);
}

// ── Leg 3: migration + negative cases ────────────────────────────────────────

test "STAGE1-KAT: negative — wrong tag, truncation, bad Option flag all reject" {
    // Wrong version tag.
    var bad_tag: [3762]u8 = undefined;
    @memcpy(&bad_tag, FJK);
    bad_tag[0] = 2; // claim V3 while body is V4-shaped
    try std.testing.expectError(error.InvalidAccountData, codec.VoteStateV4.parse(&bad_tag));

    // Truncation mid-votes.
    try std.testing.expectError(error.InvalidAccountData, codec.VoteStateV4.parse(FJK[0..300]));

    // Corrupt Option presence byte (BLS flag @144 must be 0/1).
    var bad_opt: [3762]u8 = undefined;
    @memcpy(&bad_opt, FJK);
    bad_opt[144] = 7;
    try std.testing.expectError(error.InvalidAccountData, codec.VoteStateV4.parse(&bad_opt));

    // Absurd votes count.
    var bad_n: [3762]u8 = undefined;
    @memcpy(&bad_n, FJK);
    std.mem.writeInt(u64, bad_n[193..201], 10_000, .little);
    try std.testing.expectError(error.InvalidAccountData, codec.VoteStateV4.parse(&bad_n));

    try std.testing.expectError(error.InvalidAccountData, codec.versionTag(FJK[0..3]));
    try std.testing.expectEqual(@as(u32, 3), try codec.versionTag(FJK));
}

// ── Leg 4: V1_14_11 (tag 1) legacy codec + migration (bacc392) ───────────────

test "STAGE1-KAT: V1_14_11 real fixture (bb46e6a0) parses as tag 1 to authorized_voters_len==0" {
    try std.testing.expectEqual(@as(u32, codec.VERSION_TAG_V1_14_11), try codec.versionTag(V1_BB46));
    const p = try codec.VoteState1_14_11.parse(V1_BB46);
    // The fixture's whole point: an initialized-looking legacy account that
    // genuinely bincode-decodes to an EMPTY authorized_voters set (→ Agave
    // UninitializedAccount on the mutating path — asserted in kat_vote_instructions).
    try std.testing.expectEqual(@as(usize, 0), p.state.tail.authorized_voters_len);
}

test "STAGE1-KAT: V1_14_11 synthetic (non-empty voters, no-latency votes) migrates to V4 with exact fields" {
    const node = [_]u8{0x11} ** 32;
    const withdrawer = [_]u8{0x22} ** 32;
    const voter = [_]u8{0x33} ** 32;
    const vote_pubkey = [_]u8{0x55} ** 32;
    const votes = [_]codec.Lockout{
        .{ .slot = 100, .confirmation_count = 31 },
        .{ .slot = 101, .confirmation_count = 1 },
    };

    var buf: [3762]u8 = [_]u8{0} ** 3762;
    const len = buildV1_14_11(&buf, node, withdrawer, 7, &votes, 984, voter);

    const p = try codec.VoteState1_14_11.parse(buf[0..len]);
    try std.testing.expectEqual(@as(usize, 2), p.state.tail.votes_len);
    // no-latency wire → LandedVote.latency == 0 for every migrated vote.
    try std.testing.expectEqual(@as(u8, 0), p.state.tail.votes[0].latency);
    try std.testing.expectEqual(@as(u64, 100), p.state.tail.votes[0].lockout.slot);
    try std.testing.expectEqual(@as(u32, 31), p.state.tail.votes[0].lockout.confirmation_count);
    try std.testing.expectEqual(@as(u8, 0), p.state.tail.votes[1].latency);
    try std.testing.expectEqual(@as(u64, 101), p.state.tail.votes[1].lockout.slot);
    try std.testing.expectEqual(@as(usize, 1), p.state.tail.authorized_voters_len);

    const v4 = codec.migrateV1_14_11ToV4(&p.state, vote_pubkey);
    try std.testing.expectEqualSlices(u8, &node, &v4.node_pubkey);
    try std.testing.expectEqualSlices(u8, &withdrawer, &v4.authorized_withdrawer);
    // collectors: inflation → vote account pubkey, block → node pubkey.
    try std.testing.expectEqualSlices(u8, &vote_pubkey, &v4.inflation_rewards_collector);
    try std.testing.expectEqualSlices(u8, &node, &v4.block_revenue_collector);
    try std.testing.expectEqual(@as(u16, 700), v4.inflation_rewards_commission_bps); // 7 * 100
    try std.testing.expectEqual(@as(u16, 10_000), v4.block_revenue_commission_bps);
    try std.testing.expectEqual(@as(u64, 0), v4.pending_delegator_rewards);
    try std.testing.expect(v4.bls_pubkey_compressed == null);
    try std.testing.expectEqual(@as(usize, 2), v4.tail.votes_len);
    try std.testing.expectEqual(@as(usize, 1), v4.tail.authorized_voters_len);
    try std.testing.expectEqual(@as(u64, 984), v4.tail.authorized_voters[0].epoch);
    try std.testing.expectEqualSlices(u8, &voter, &v4.tail.authorized_voters[0].pubkey);
}

test "STAGE1-KAT: V3/V4 NO-REGRESSION — real V4 + a V3 round-trip byte-identical after the codec change" {
    // V4 golden (FJK) is byte-exact through parse→serialize (guards the tag-3
    // path is unchanged by the tag-1 additions).
    {
        var acct: [3762]u8 = undefined;
        @memcpy(&acct, FJK);
        const p = try codec.VoteStateV4.parse(FJK);
        _ = try p.state.serialize(&acct);
        try std.testing.expectEqualSlices(u8, FJK, &acct);
    }
    // Build a V3 buffer, parse→serialize, assert byte-identical prefix (the V3
    // migration body was refactored into migrateLegacyToV4 — this proves the
    // V3 wire codec itself is untouched).
    {
        var s: codec.VoteStateV3 = std.mem.zeroes(codec.VoteStateV3);
        s.node_pubkey = [_]u8{0x44} ** 32;
        s.authorized_withdrawer = [_]u8{0x66} ** 32;
        s.commission = 5;
        s.prior_voters_blob = [_]u8{0} ** codec.PRIOR_VOTERS_BLOB_LEN;
        s.tail = codec.Tail.EMPTY;
        s.tail.authorized_voters_len = 1;
        s.tail.authorized_voters[0] = .{ .epoch = 9, .pubkey = [_]u8{0x77} ** 32 };
        var out1: [3762]u8 = [_]u8{0} ** 3762;
        const w1 = try s.serialize(&out1);
        const p = try codec.VoteStateV3.parse(out1[0..w1]);
        var out2: [3762]u8 = [_]u8{0} ** 3762;
        const w2 = try p.state.serialize(&out2);
        try std.testing.expectEqual(w1, w2);
        try std.testing.expectEqualSlices(u8, out1[0..w1], out2[0..w2]);
        // V3→V4 migration formula unchanged (5*100=500, block=10000).
        const v4 = codec.migrateV3ToV4(&p.state, [_]u8{0x88} ** 32);
        try std.testing.expectEqual(@as(u16, 500), v4.inflation_rewards_commission_bps);
        try std.testing.expectEqual(@as(u16, 10_000), v4.block_revenue_commission_bps);
    }
}

test "STAGE1-KAT: V4 with no BLS key round-trips (offset shift by 48 handled)" {
    const p = try codec.VoteStateV4.parse(FJK);
    var s = p.state;
    s.bls_pubkey_compressed = null;

    var out: [3762]u8 = undefined;
    @memset(&out, 0);
    const written = try s.serialize(&out);
    try std.testing.expectEqual(p.consumed - 48, written);

    const p2 = try codec.VoteStateV4.parse(&out);
    try std.testing.expect(p2.state.bls_pubkey_compressed == null);
    try std.testing.expectEqual(s.tail.votes_len, p2.state.tail.votes_len);
    try std.testing.expectEqual(s.tail.root_slot, p2.state.tail.root_slot);
    try std.testing.expectEqual(s.tail.last_timestamp.timestamp, p2.state.tail.last_timestamp.timestamp);
}
