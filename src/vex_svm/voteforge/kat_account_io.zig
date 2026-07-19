//! voteforge, stage 2 KATs — account_io.zig gate
//! (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 2 gate, item 4).
//!
//! IN-PLACE MUTATION THROUGH THE CODEC: borrow the real CARRIER-419996256
//! V4 fixture mutably, mutate fields via Stage 1's `vote_codec.zig` directly
//! against the borrow's own buffer (zero extra copies), verify the mutation
//! landed and the stale tail stayed untouched — proves the two rewrite layers
//! (account_io + codec) compose the way §F.1 designs them to.
//!
//! (The Sig-transplant differential legs — BorrowedAccount accept/reject parity
//! and the real-sysvar-id checkSysvarId shape KAT — were removed with the
//! transplant 2026-07-12. The borrow/lamport/data/owner/executable rules and
//! checkSysvarId accept/reject are covered by account_io.zig's own self-tests
//! (run under the same test-account-io step) and by the instruction-level
//! voteforge KATs.)

const std = @import("std");
const account_io = @import("account_io.zig");
const codec = @import("vote_codec.zig");

const FJK = @embedFile("kat_fjkdgnyl_v4_419996256.bin");

// ── Leg 1: in-place mutation through the Stage 1 codec ──────────────────────

test "STAGE2-KAT: borrow the real V4 fixture mutably, mutate via codec in place, stale tail untouched" {
    const alloc = std.testing.allocator;
    const buf = try alloc.dupe(u8, FJK);
    defer alloc.free(buf);

    const program_id: [32]u8 = [_]u8{7} ** 32; // vote program stand-in
    var records = [_]account_io.AccountRecord{.{
        .pubkey = [_]u8{1} ** 32,
        .lamports = 1_000_000,
        .owner = program_id,
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = buf,
    }};
    const metas = [_]account_io.AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try account_io.AccountTable.init(program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();

    const mutable_data = try b.dataMut();
    const parsed = try codec.VoteStateV4.parse(mutable_data);
    var state = parsed.state;

    const orig_rewards = state.pending_delegator_rewards;
    state.pending_delegator_rewards = orig_rewards + 4242;
    const orig_conf = state.tail.votes[0].lockout.confirmation_count;
    state.tail.votes[0].lockout.confirmation_count = orig_conf + 1;

    const written = try state.serialize(mutable_data);
    try std.testing.expectEqual(parsed.consumed, written);

    // The buffer IS the borrow's own storage (no copy) — re-reading through
    // the borrow must see the mutation.
    const reparsed = try codec.VoteStateV4.parse(b.dataConst());
    try std.testing.expectEqual(orig_rewards + 4242, reparsed.state.pending_delegator_rewards);
    try std.testing.expectEqual(orig_conf + 1, reparsed.state.tail.votes[0].lockout.confirmation_count);

    // Stale tail (beyond the serialized prefix) is byte-identical to the
    // original fixture — codec never touches it, and account_io never
    // resized the buffer (setDataLength was not called).
    try std.testing.expectEqualSlices(u8, FJK[written..], b.dataConst()[written..]);
    try std.testing.expectEqual(@as(usize, FJK.len), b.dataConst().len);

    // Everything else account_io tracks (lamports/owner/executable/rent_epoch)
    // is untouched by a pure data mutation.
    try std.testing.expectEqual(@as(u64, 1_000_000), b.lamports());
    try std.testing.expectEqualSlices(u8, &program_id, &b.owner());
    try std.testing.expectEqual(std.math.maxInt(u64), b.rentEpoch());
}
