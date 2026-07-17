//! KAT (Known-Answer Test) for SIMD-0291 — UpdateCommissionBps (vote disc 18).
//!
//! Locks the consensus-critical pieces of the epoch-974 commission-rate-in-
//! basis-points handler:
//!   (a) byte encoding: outer disc 18 (u32 LE) ‖ commission_bps (u16 LE) ‖
//!       kind (u32 LE — CommissionKind variant index). The `#[repr(u8)]` on
//!       Agave's CommissionKind is a red herring; bincode (serde derive)
//!       encodes a fieldless enum's index as u32. Empirically confirmed against
//!       solana-vote-interface-5.0.0: {bps=1234, InflationRewards} serializes to
//!       [18,0,0,0, 210,4, 0,0,0,0] and {.., BlockRevenue} to
//!       [18,0,0,0, 210,4, 1,0,0,0]. The golden bytes are asserted below.
//!   (b) kind=BlockRevenue is REJECTED when SIMD-0123 (block_revenue_sharing)
//!       is inactive (the testnet-today / epoch-974 case) → no mutation.
//!   (c) field-set: a successful InflationRewards update writes the RAW u16
//!       basis-point value (NO *100, NO clamp) into inflation_rewards_commission_bps
//!       and the change survives a serialize→deserialize round-trip.
//!
//! Refs: Agave programs/vote/src/vote_processor.rs:362-381 (dispatch+gate),
//! programs/vote/src/vote_state/mod.rs:828-860 (update_commission_bps),
//! solana-improvement-documents/proposals/0291-commission-rate-in-basis-points.md,
//! solana-vote-interface-5.0.0 instruction.rs:25-31, 217-221.

const std = @import("std");
const vote_program = @import("vote_program.zig");
const serde = @import("vote_state_serde.zig");

// ── Golden instruction bytes (from real solana-vote-interface-5.0.0 bincode) ──
// bps = 1234 = 0x04D2 → LE [0xD2, 0x04].
const GOLDEN_INFLATION = [_]u8{ 18, 0, 0, 0, 0xD2, 0x04, 0, 0, 0, 0 };
const GOLDEN_BLOCKREV = [_]u8{ 18, 0, 0, 0, 0xD2, 0x04, 1, 0, 0, 0 };

// ─────────────────────────────────────────────────────────────────────────────
// KAT (a) — DESERIALIZE: disc-18 payload parses to {bps, kind} with exact encoding
// ─────────────────────────────────────────────────────────────────────────────
test "KAT SIMD-0291: disc-18 deserialize InflationRewards bps=1234" {
    const parsed = try vote_program.VoteInstruction.deserialize(&GOLDEN_INFLATION);
    try std.testing.expect(parsed == .UpdateCommissionBps);
    try std.testing.expectEqual(@as(u16, 1234), parsed.UpdateCommissionBps.commission_bps);
    try std.testing.expectEqual(vote_program.CommissionKind.inflation_rewards, parsed.UpdateCommissionBps.kind);

    const parsed_br = try vote_program.VoteInstruction.deserialize(&GOLDEN_BLOCKREV);
    try std.testing.expect(parsed_br == .UpdateCommissionBps);
    try std.testing.expectEqual(@as(u16, 1234), parsed_br.UpdateCommissionBps.commission_bps);
    try std.testing.expectEqual(vote_program.CommissionKind.block_revenue, parsed_br.UpdateCommissionBps.kind);

    // Payload too short (< 6 bytes after the 4-byte disc) → InvalidData, not a
    // silent mis-parse. e.g. only the u16 present, kind missing.
    try std.testing.expectError(error.InvalidData, vote_program.UpdateCommissionBpsData.deserialize(&[_]u8{ 0xD2, 0x04 }));

    // Out-of-range kind discriminant (2) → InvalidData (intToEnum rejects it).
    const bad_kind = [_]u8{ 18, 0, 0, 0, 0xD2, 0x04, 2, 0, 0, 0 };
    try std.testing.expectError(error.InvalidData, vote_program.VoteInstruction.deserialize(&bad_kind));
}

// Helper: build a fresh V4 vote account with a known authorized_withdrawer and
// a starting inflation_rewards_commission_bps. Returns the serialized length.
fn buildV4(buf: *[serde.VOTE_STATE_V3_SZ]u8, withdrawer: [32]u8, start_bps: u16) usize {
    var vs = serde.VoteState.init();
    vs.version = 3; // V4
    vs.node_pubkey = [_]u8{0xAB} ** 32;
    vs.authorized_withdrawer = withdrawer;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0xAB} ** 32 };
    @memset(&vs.inflation_rewards_collector, 0x11);
    @memset(&vs.block_revenue_collector, 0x22);
    vs.inflation_rewards_commission_bps = start_bps;
    vs.block_revenue_commission_bps = 10_000;
    vs.has_bls_pubkey_compressed = false;
    @memset(buf, 0);
    return serde.serializeVoteState(&vs, buf).?;
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT (c) — FIELD-SET: InflationRewards update writes RAW u16 (no *100), persists
// ─────────────────────────────────────────────────────────────────────────────
test "KAT SIMD-0291: InflationRewards sets inflation_rewards_commission_bps=1234 RAW" {
    const withdrawer = [_]u8{0xCD} ** 32;
    var buf: [serde.VOTE_STATE_V3_SZ]u8 = undefined;
    _ = buildV4(&buf, withdrawer, 500); // start at 5.00%

    const args: vote_program.UpdateCommissionBpsData = .{
        .commission_bps = 1234,
        .kind = .inflation_rewards,
    };
    // account[0] = vote account; withdrawer is a signer.
    const vote_key = [_]u8{0xAB} ** 32;
    const account_keys = [_][32]u8{ vote_key, withdrawer };
    const account_indices = [_]u8{ 0, 1 };
    const num_required_sigs: u8 = 2; // both account_keys are within sig range

    const ok = vote_program.handleUpdateCommissionBps(
        &args,
        &account_keys,
        &account_indices,
        num_required_sigs,
        &buf,
        false, // block_revenue_sharing inactive (irrelevant for InflationRewards)
    );
    try std.testing.expect(ok);

    // Re-deserialize and assert the RAW value landed (1234, NOT 123400).
    const post = serde.deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 3), post.version);
    try std.testing.expectEqual(@as(u16, 1234), post.inflation_rewards_commission_bps);
    // block_revenue untouched.
    try std.testing.expectEqual(@as(u16, 10_000), post.block_revenue_commission_bps);
    // withdrawer/identity untouched.
    try std.testing.expectEqualSlices(u8, &withdrawer, &post.authorized_withdrawer);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT (b) — BlockRevenue is REJECTED when SIMD-0123 inactive (no mutation)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT SIMD-0291: BlockRevenue rejected when block_revenue_sharing inactive" {
    const withdrawer = [_]u8{0xCD} ** 32;
    var buf: [serde.VOTE_STATE_V3_SZ]u8 = undefined;
    _ = buildV4(&buf, withdrawer, 500);
    var before: [serde.VOTE_STATE_V3_SZ]u8 = undefined;
    @memcpy(&before, &buf);

    const args: vote_program.UpdateCommissionBpsData = .{
        .commission_bps = 1234,
        .kind = .block_revenue,
    };
    const vote_key = [_]u8{0xAB} ** 32;
    const account_keys = [_][32]u8{ vote_key, withdrawer };
    const account_indices = [_]u8{ 0, 1 };

    const ok = vote_program.handleUpdateCommissionBps(
        &args,
        &account_keys,
        &account_indices,
        2,
        &buf,
        false, // SIMD-0123 INACTIVE → BlockRevenue must reject
    );
    try std.testing.expect(!ok); // rejected
    // No mutation: buffer byte-identical (the early-return fires BEFORE deserialize).
    try std.testing.expectEqualSlices(u8, &before, &buf);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT (b2) — BlockRevenue ACCEPTED when SIMD-0123 active (field-set sanity)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT SIMD-0291: BlockRevenue accepted when block_revenue_sharing active" {
    const withdrawer = [_]u8{0xCD} ** 32;
    var buf: [serde.VOTE_STATE_V3_SZ]u8 = undefined;
    _ = buildV4(&buf, withdrawer, 500);

    const args: vote_program.UpdateCommissionBpsData = .{
        .commission_bps = 4321,
        .kind = .block_revenue,
    };
    const vote_key = [_]u8{0xAB} ** 32;
    const account_keys = [_][32]u8{ vote_key, withdrawer };
    const account_indices = [_]u8{ 0, 1 };

    const ok = vote_program.handleUpdateCommissionBps(
        &args,
        &account_keys,
        &account_indices,
        2,
        &buf,
        true, // SIMD-0123 ACTIVE
    );
    try std.testing.expect(ok);
    const post = serde.deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u16, 4321), post.block_revenue_commission_bps);
    // inflation untouched (still 500).
    try std.testing.expectEqual(@as(u16, 500), post.inflation_rewards_commission_bps);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT (d) — withdrawer-not-signer is REJECTED (no mutation of a valid V4 acct)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT SIMD-0291: InflationRewards rejected when withdrawer did not sign" {
    const withdrawer = [_]u8{0xCD} ** 32;
    var buf: [serde.VOTE_STATE_V3_SZ]u8 = undefined;
    _ = buildV4(&buf, withdrawer, 500);

    const args: vote_program.UpdateCommissionBpsData = .{
        .commission_bps = 1234,
        .kind = .inflation_rewards,
    };
    const vote_key = [_]u8{0xAB} ** 32;
    const other = [_]u8{0xEE} ** 32; // NOT the withdrawer
    const account_keys = [_][32]u8{ vote_key, other };
    const account_indices = [_]u8{ 0, 1 };

    const ok = vote_program.handleUpdateCommissionBps(
        &args,
        &account_keys,
        &account_indices,
        2,
        &buf,
        false,
    );
    try std.testing.expect(!ok);
    // commission unchanged (still 500).
    const post = serde.deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u16, 500), post.inflation_rewards_commission_bps);
}

test {
    std.testing.refAllDecls(@This());
}
