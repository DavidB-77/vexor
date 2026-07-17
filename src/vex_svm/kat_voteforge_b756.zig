//! VOTEFORGE Stage 1 KAT (supplement) — round-trip the OTHER named real-account
//! fixture from the scope doc's Stage-1 gate: canon-756 (271KPMd vote account,
//! V4 3762B, AV=[967,968], the carrier-@413005757 golden from
//! kat_vote_authorize_canon.zig). Rooted at src/vex_svm/ (not voteforge/)
//! because the canon fixture lives in native/ and Zig module roots cannot
//! import upward — this root reaches both subtrees.

const std = @import("std");
const canon = @import("native/kat_vote_authorize_canon.zig");
const codec = @import("voteforge/vote_codec.zig");

test "STAGE1-KAT: canon-756 real V4 bytes round-trip byte-exact through the new codec" {
    var pre: [3762]u8 = undefined;
    try canon.decodeB64(canon.B756, &pre);

    const p = try codec.VoteStateV4.parse(&pre);
    // Known canon-756 facts (same vector the authorize KATs pin): V4, two
    // authorized-voter entries at epochs 967/968, both -> BwVDYeT9.
    try std.testing.expectEqual(@as(usize, 2), p.state.tail.authorized_voters_len);
    try std.testing.expectEqual(@as(u64, 967), p.state.tail.authorized_voters[0].epoch);
    try std.testing.expectEqual(@as(u64, 968), p.state.tail.authorized_voters[1].epoch);
    try std.testing.expectEqualSlices(u8, &canon.BW_VDYET9, &p.state.tail.authorized_voters[0].pubkey);
    try std.testing.expectEqualSlices(u8, &canon.BW_VDYET9, &p.state.tail.authorized_voters[1].pubkey);

    var acct: [3762]u8 = undefined;
    @memcpy(&acct, &pre);
    const written = try p.state.serialize(&acct);
    try std.testing.expectEqual(p.consumed, written);
    try std.testing.expectEqualSlices(u8, &pre, &acct); // full buffer, stale tail preserved
}
