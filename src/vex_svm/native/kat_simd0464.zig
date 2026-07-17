//! KAT (Known-Answer Test) for SIMD-0464 — InitializeAccountV2 (vote disc 16).
//!
//! Locks the consensus-critical pieces of the (dormant, 5-feature-gated)
//! VoteStateV4 InitializeAccountV2 handler against Agave 4.1.0-rc.1 + vote-
//! interface 6.0.0 (NOT Firedancer — fd_vote_codec.c is on the OLD v4.0.0-alpha.0
//! draft that put collectors in the instruction payload; rc.1 puts them in
//! ACCOUNTS idx 2/3). Spec: SIMD-0464-RC1-PORT-SPEC-2026-06-21.md.
//!
//!   (a) instruction-data layout: node@4, authorized_voter@36, bls_pubkey[48]@68,
//!       bls_pop[96]@116, authorized_withdrawer@212 (AFTER bls — the offset trap),
//!       inflation_bps u16@244, block_bps u16@246; payload 244, total 248. The
//!       BLS fixed arrays carry NO bincode length prefix (serde_as([_;N])).
//!   (b) the written VoteStateV4 image is byte-exact at every load-bearing offset
//!       (§6 of the spec). The serializer (vote_state_serde version==3) is the
//!       already-proven SIMD-0185/0449 one; this asserts the handler POPULATES it
//!       correctly (collectors resolved, bps raw, bls=Some, av[0]={clock.epoch,voter}).
//!   (c) collector validate_and_resolve_key (Agave mod.rs:881-903): ==vote_key
//!       short-circuits with no checks; else owner==system / rent-exempt / writable.
//!   (d) BLS proof-of-possession over "ALPENGLOW"||vote_key gates success; a
//!       corrupt PoP fails the handler.

const std = @import("std");
const vote_program = @import("vote_program.zig");
const serde = @import("vote_state_serde.zig");
const bls_pop = @import("bls_pop");

const SZ = serde.VOTE_STATE_V3_SZ; // 3762

// Build the 248-byte InitializeAccountV2 instruction data (disc 16 + 244 payload).
fn buildIxData(
    node: [32]u8,
    voter: [32]u8,
    bls_pk: [48]u8,
    pop: [96]u8,
    withdrawer: [32]u8,
    infl_bps: u16,
    blk_bps: u16,
) [248]u8 {
    var d: [248]u8 = undefined;
    std.mem.writeInt(u32, d[0..4], 16, .little);
    @memcpy(d[4..36], &node);
    @memcpy(d[36..68], &voter);
    @memcpy(d[68..116], &bls_pk);
    @memcpy(d[116..212], &pop);
    @memcpy(d[212..244], &withdrawer);
    std.mem.writeInt(u16, d[244..246], infl_bps, .little);
    std.mem.writeInt(u16, d[246..248], blk_bps, .little);
    return d;
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT (a) — DESERIALIZE: the offset trap (withdrawer@212, AFTER the 144 BLS bytes)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT SIMD-0464: disc-16 deserialize — offsets incl withdrawer@212 trap" {
    const node = [_]u8{0x22} ** 32;
    const voter = [_]u8{0x33} ** 32;
    const bls_pk = [_]u8{0x44} ** 48;
    const pop = [_]u8{0x55} ** 96;
    const withdrawer = [_]u8{0x66} ** 32;
    const ix = buildIxData(node, voter, bls_pk, pop, withdrawer, 800, 10_000);

    const parsed = try vote_program.VoteInstruction.deserialize(&ix);
    try std.testing.expect(parsed == .InitializeAccountV2);
    const v = parsed.InitializeAccountV2;
    try std.testing.expectEqualSlices(u8, &node, &v.node_pubkey);
    try std.testing.expectEqualSlices(u8, &voter, &v.authorized_voter);
    try std.testing.expectEqualSlices(u8, &bls_pk, &v.bls_pubkey);
    try std.testing.expectEqualSlices(u8, &pop, &v.bls_proof_of_possession);
    try std.testing.expectEqualSlices(u8, &withdrawer, &v.authorized_withdrawer); // @212 trap
    try std.testing.expectEqual(@as(u16, 800), v.inflation_rewards_commission_bps);
    try std.testing.expectEqual(@as(u16, 10_000), v.block_revenue_commission_bps);

    // Short payload (< 244) → InvalidData, not a silent mis-parse.
    try std.testing.expectError(error.InvalidData, vote_program.InitializeAccountV2Data.deserialize(ix[4..200]));
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT (c) — resolveCollector (Agave NewCommissionCollector::validate_and_resolve_key)
// ─────────────────────────────────────────────────────────────────────────────
test "KAT SIMD-0464: resolveCollector — short-circuit + owner/rent/writable checks" {
    const vote_key = [_]u8{0x11} ** 32;
    const SYSTEM = [_]u8{0} ** 32;
    const other = [_]u8{0x77} ** 32;

    // == vote_key → short-circuit, NO checks (even with bad owner / 0 lamports).
    {
        const c = vote_program.CollectorAccount{ .key = vote_key, .owner = other, .lamports = 0, .rent_exempt_min = 999, .is_writable = false };
        try std.testing.expectEqualSlices(u8, &vote_key, &(vote_program.resolveCollector(&c, &vote_key).?));
    }
    // != vote_key, system-owned, rent-exempt, writable → resolves to its own key.
    {
        const c = vote_program.CollectorAccount{ .key = other, .owner = SYSTEM, .lamports = 1000, .rent_exempt_min = 1000, .is_writable = true };
        try std.testing.expectEqualSlices(u8, &other, &(vote_program.resolveCollector(&c, &vote_key).?));
    }
    // wrong owner → null (InvalidAccountOwner).
    {
        const c = vote_program.CollectorAccount{ .key = other, .owner = [_]u8{0x99} ** 32, .lamports = 1000, .rent_exempt_min = 1000, .is_writable = true };
        try std.testing.expect(vote_program.resolveCollector(&c, &vote_key) == null);
    }
    // not rent-exempt → null (InsufficientFunds).
    {
        const c = vote_program.CollectorAccount{ .key = other, .owner = SYSTEM, .lamports = 999, .rent_exempt_min = 1000, .is_writable = true };
        try std.testing.expect(vote_program.resolveCollector(&c, &vote_key) == null);
    }
    // not writable → null (InvalidArgument).
    {
        const c = vote_program.CollectorAccount{ .key = other, .owner = SYSTEM, .lamports = 1000, .rent_exempt_min = 1000, .is_writable = false };
        try std.testing.expect(vote_program.resolveCollector(&c, &vote_key) == null);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT (b)+(d) — full handler: valid PoP → byte-exact V4 image; corrupt PoP → fail
// ─────────────────────────────────────────────────────────────────────────────
test "KAT SIMD-0464: handleInitializeAccountV2 writes byte-exact VoteStateV4" {
    const vote_key = [_]u8{0x11} ** 32;
    const node = [_]u8{0x22} ** 32;
    const voter = [_]u8{0x33} ** 32;
    const withdrawer = [_]u8{0x66} ** 32;
    const epoch: u64 = 7;
    const infl_bps: u16 = 800;
    const blk_bps: u16 = 10_000;

    // Deterministic BLS keypair + valid PoP over "ALPENGLOW"||vote_key.
    const ikm = [_]u8{0xC0} ** 32;
    const kp = bls_pop.TestKeypair.fromIkm(&ikm);
    const bls_pk = kp.pubkey_compressed;
    var pop_msg: [bls_pop.POP_PAYLOAD_SIZE]u8 = undefined;
    @memcpy(pop_msg[0..bls_pop.ALPENGLOW_LABEL.len], bls_pop.ALPENGLOW_LABEL);
    @memcpy(pop_msg[bls_pop.ALPENGLOW_LABEL.len..], &vote_key);
    const pop = kp.signPop(&pop_msg);

    const ix = buildIxData(node, voter, bls_pk, pop, withdrawer, infl_bps, blk_bps);
    const parsed = try vote_program.VoteInstruction.deserialize(&ix);
    const args = parsed.InitializeAccountV2;

    // node signs (account_keys[0] = node, num_required_sigs = 1).
    const account_keys = [_][32]u8{ node, vote_key };
    // Collectors == vote_key (short-circuit; no account state needed).
    const infl_c = vote_program.CollectorAccount{ .key = vote_key, .owner = [_]u8{0} ** 32, .lamports = 0, .rent_exempt_min = 0, .is_writable = false };
    const blk_c = infl_c;

    var data = [_]u8{0} ** SZ; // uninitialized (version 0)
    const ok = vote_program.handleInitializeAccountV2(&args, &account_keys, 1, &data, epoch, &vote_key, &infl_c, &blk_c);
    try std.testing.expect(ok);

    // §6 byte-exact assertions.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 3, 0, 0, 0 }, data[0..4]); // V4 tag
    try std.testing.expectEqualSlices(u8, &node, data[4..36]);
    try std.testing.expectEqualSlices(u8, &withdrawer, data[36..68]);
    try std.testing.expectEqualSlices(u8, &vote_key, data[68..100]); // inflation collector (resolved)
    try std.testing.expectEqualSlices(u8, &vote_key, data[100..132]); // block collector (resolved)
    try std.testing.expectEqual(infl_bps, std.mem.readInt(u16, data[132..134], .little));
    try std.testing.expectEqual(blk_bps, std.mem.readInt(u16, data[134..136], .little));
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, data[136..144], .little)); // pending
    try std.testing.expectEqual(@as(u8, 1), data[144]); // bls Some
    try std.testing.expectEqualSlices(u8, &bls_pk, data[145..193]);
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, data[193..201], .little)); // votes=0
    try std.testing.expectEqual(@as(u8, 0), data[201]); // root None
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, data[202..210], .little)); // av=1
    try std.testing.expectEqual(epoch, std.mem.readInt(u64, data[210..218], .little));
    try std.testing.expectEqualSlices(u8, &voter, data[218..250]);
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, data[250..258], .little)); // ec=0
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, data[258..266], .little)); // ts slot
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, data[266..274], .little)); // ts timestamp
    // tail zero-filled
    for (data[274..]) |b| try std.testing.expectEqual(@as(u8, 0), b);

    // Corrupt PoP → handler fails (no write asserted; ok=false is the gate).
    var bad_pop = pop;
    bad_pop[0] ^= 0xFF;
    const ix_bad = buildIxData(node, voter, bls_pk, bad_pop, withdrawer, infl_bps, blk_bps);
    const args_bad = (try vote_program.VoteInstruction.deserialize(&ix_bad)).InitializeAccountV2;
    var data2 = [_]u8{0} ** SZ;
    try std.testing.expect(!vote_program.handleInitializeAccountV2(&args_bad, &account_keys, 1, &data2, epoch, &vote_key, &infl_c, &blk_c));

    // Already-initialized (version tag != 0) → AccountAlreadyInitialized → fail.
    var data3 = [_]u8{0} ** SZ;
    std.mem.writeInt(u32, data3[0..4], 3, .little); // pretend already V4
    try std.testing.expect(!vote_program.handleInitializeAccountV2(&args, &account_keys, 1, &data3, epoch, &vote_key, &infl_c, &blk_c));

    // node not a signer (num_required_sigs = 0) → MissingRequiredSignature → fail.
    var data4 = [_]u8{0} ** SZ;
    try std.testing.expect(!vote_program.handleInitializeAccountV2(&args, &account_keys, 0, &data4, epoch, &vote_key, &infl_c, &blk_c));
}
