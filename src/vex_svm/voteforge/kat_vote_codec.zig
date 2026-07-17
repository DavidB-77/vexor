//! VOTEFORGE Stage 1 KATs — vote_codec.zig byte-exactness gate
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
