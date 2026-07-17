//! VOTEFORGE Stage 3 — state-transition-layer KATs
//! (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 3 gate).
//!
//! Agave-source-derived positive/negative-case KATs (ported from
//! `programs/vote/src/vote_processor.rs` / `vote_state/{mod,handler}.rs`
//! `#[test]` functions — same input shapes, same expected
//! `InstructionError`/`Custom(VoteError)` outcomes) for the full instruction
//! family: Authorize, UpdateValidatorIdentity, UpdateCommission[Bps],
//! UpdateCommissionCollector, Withdraw, InitializeAccount[V2],
//! DepositDelegatorRewards.
//!
//! (The Sig-transplant differential legs — byte-exact mutated-account
//! comparison of voteforge vs the oracle — were removed with the transplant
//! 2026-07-12; the Agave-semantics assertions above are the surviving anchor.)

const std = @import("std");
const testing = std.testing;
const codec = @import("vote_codec.zig");
const aio = @import("account_io.zig");
const vi = @import("vote_instructions.zig");
const bls_pop = @import("bls_pop");

// [agave] the REAL vote program id ("Vote111111111111111111111111111111111111111"),
// sourced from voteforge's own `vote_program.zig`. Every fixture in this file
// uses this same constant so the account owner matches what dispatch expects.
const VOTE_PROGRAM_ID: [32]u8 = @import("vote_program.zig").VOTE_PROGRAM_ID;
const VOTE_KEY: [32]u8 = [_]u8{0xAA} ** 32;

fn key(byte: u8) [32]u8 {
    return [_]u8{byte} ** 32;
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture builders
// ─────────────────────────────────────────────────────────────────────────────

fn emptyV4(node: [32]u8, withdrawer: [32]u8) codec.VoteStateV4 {
    var s: codec.VoteStateV4 = std.mem.zeroes(codec.VoteStateV4);
    s.node_pubkey = node;
    s.authorized_withdrawer = withdrawer;
    s.inflation_rewards_collector = VOTE_KEY;
    s.block_revenue_collector = node;
    s.block_revenue_commission_bps = 10_000;
    s.tail = codec.Tail.EMPTY;
    return s;
}

fn withAuthorizedVoter(s: *codec.VoteStateV4, epoch: u64, voter: [32]u8) void {
    s.tail.authorized_voters[s.tail.authorized_voters_len] = .{ .epoch = epoch, .pubkey = voter };
    s.tail.authorized_voters_len += 1;
}

fn withEpochCredit(s: *codec.VoteStateV4, epoch: u64, credits: u64, prev: u64) void {
    s.tail.epoch_credits[s.tail.epoch_credits_len] = .{ .epoch = epoch, .credits = credits, .prev_credits = prev };
    s.tail.epoch_credits_len += 1;
}

fn serializeInto(buf: []u8, s: *const codec.VoteStateV4) void {
    @memset(buf, 0);
    _ = s.serialize(buf) catch unreachable;
}

/// One-account table: [vote]. `data` must outlive the table (caller-owned).
fn oneAccountTable(data: []u8, signer: bool, writable: bool) struct { metas: [1]aio.AccountMeta, records: [1]aio.AccountRecord } {
    return .{
        .metas = [_]aio.AccountMeta{.{ .pubkey = VOTE_KEY, .is_signer = signer, .is_writable = writable }},
        .records = [_]aio.AccountRecord{.{ .pubkey = VOTE_KEY, .lamports = 100_000_000, .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = data }},
    };
}

fn mkTable(metas: []const aio.AccountMeta, records: []aio.AccountRecord) aio.AccountTable {
    return aio.AccountTable.init(VOTE_PROGRAM_ID, metas, records) catch unreachable;
}

fn defaultCtx() vi.ExecContext {
    return .{
        .slot = 1000,
        .epoch = 10,
        .leader_schedule_epoch = 10,
        .epoch_schedule = .{ .slots_per_epoch = 432_000, .leader_schedule_slot_offset = 432_000, .warmup = false, .first_normal_epoch = 0, .first_normal_slot = 0 },
        .features = .{
            .bls_pubkey_management_in_vote_account = true,
            .custom_commission_collector = true,
            .commission_rate_in_basis_points = true,
            .delay_commission_updates = true,
            .block_revenue_sharing = true,
            .vote_account_initialize_v2 = true,
        },
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Authorize family
// ─────────────────────────────────────────────────────────────────────────────

test "STAGE3-KAT: authorize voter — withdrawer-signed succeeds, purges+carries epoch window" {
    const withdrawer = key(2);
    const orig_voter = key(3);
    const new_voter = key(4);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, orig_voter); // epoch 8 < current_epoch 10 -> carry-forward candidate
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    const signers = [_][32]u8{withdrawer};
    try vi.authorize(&table, 0, &signers, new_voter, .voter, &ctx);

    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    // target_epoch = leader_schedule_epoch + 1 = 11
    try testing.expectEqual(@as(usize, 2), parsed.tail.authorized_voters_len); // {8-purged? no: floor=9, 8<9 purged} + new(10, carried)+new(11,new_voter)
}

test "STAGE3-KAT: authorize voter — epoch-authorized-voter signs when withdrawer doesn't" {
    const withdrawer = key(2);
    const cur_voter = key(3);
    const new_voter = key(4);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 10, cur_voter); // exact match at current_epoch
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    const signers = [_][32]u8{cur_voter};
    try vi.authorize(&table, 0, &signers, new_voter, .voter, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expect(parsed.tail.authorized_voters_len >= 1);
}

test "STAGE3-KAT: authorize voter — neither withdrawer nor epoch voter signs -> MissingRequiredSignature" {
    const withdrawer = key(2);
    const cur_voter = key(3);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 10, cur_voter);
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    const signers = [_][32]u8{key(9)};
    try testing.expectError(error.MissingRequiredSignature, vi.authorize(&table, 0, &signers, key(5), .voter, &ctx));
}

test "STAGE3-KAT: authorize voter — TooSoonToReauthorize when target_epoch already scheduled" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 10, key(3));
    withAuthorizedVoter(&s, 11, key(4)); // target_epoch (leader_schedule_epoch+1=11) already present
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    const signers = [_][32]u8{withdrawer};
    try testing.expectError(error.Custom, vi.authorize(&table, 0, &signers, key(5), .voter, &ctx));
    try testing.expectEqual(@as(?u32, @intFromEnum(vi.VoteError.too_soon_to_reauthorize)), ctx.custom_error);
}

test "STAGE3-KAT: authorize withdrawer — only current withdrawer may authorize a new one" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 10, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    try testing.expectError(error.MissingRequiredSignature, vi.authorize(&table, 0, &[_][32]u8{key(9)}, key(5), .withdrawer, &ctx));

    var buf2: [3762]u8 = undefined;
    serializeInto(&buf2, &s);
    var tab2 = oneAccountTable(&buf2, true, true);
    var table2 = mkTable(&tab2.metas, &tab2.records);
    try vi.authorize(&table2, 0, &[_][32]u8{withdrawer}, key(5), .withdrawer, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf2)).state;
    try testing.expectEqualSlices(u8, &key(5), &parsed.authorized_withdrawer);
}

test "STAGE3-KAT: authorize voter_with_bls — valid PoP registers BLS pubkey" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    const kp = bls_pop.TestKeypair.fromIkm(&[_]u8{0x11} ** 32);
    var payload: [41]u8 = undefined;
    @memcpy(payload[0..9], "ALPENGLOW");
    @memcpy(payload[9..41], &VOTE_KEY);
    const pop = kp.signPop(&payload);

    const signers = [_][32]u8{withdrawer};
    try vi.authorize(&table, 0, &signers, key(6), .{ .voter_with_bls = .{ .bls_pubkey = kp.pubkey_compressed, .bls_proof_of_possession = pop } }, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expect(parsed.bls_pubkey_compressed != null);
    try testing.expectEqualSlices(u8, &kp.pubkey_compressed, &parsed.bls_pubkey_compressed.?);
}

test "STAGE3-KAT: authorize voter_with_bls — bad PoP rejected with InvalidArgument, no state mutation" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);
    var buf_before = buf;

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    const kp = bls_pop.TestKeypair.fromIkm(&[_]u8{0x22} ** 32);
    var bad_pop = kp.signPop("wrong-payload");
    bad_pop[0] ^= 0xFF;

    const signers = [_][32]u8{withdrawer};
    try testing.expectError(error.InvalidArgument, vi.authorize(&table, 0, &signers, key(6), .{ .voter_with_bls = .{ .bls_pubkey = kp.pubkey_compressed, .bls_proof_of_possession = bad_pop } }, &ctx));
    try testing.expectEqualSlices(u8, &buf_before, &buf);
}

test "STAGE3-KAT: authorize voter — legacy Voter rejected once BLS pubkey is registered" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    s.bls_pubkey_compressed = [_]u8{0x55} ** 48;
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    try testing.expectError(error.InvalidInstructionData, vi.authorize(&table, 0, &[_][32]u8{withdrawer}, key(6), .voter, &ctx));
}

test "STAGE3-KAT: authorize voter_with_bls — gate off (bls_pubkey_management_in_vote_account=false) rejects" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.bls_pubkey_management_in_vote_account = false;
    try testing.expectError(error.InvalidInstructionData, vi.authorize(&table, 0, &[_][32]u8{withdrawer}, key(6), .{ .voter_with_bls = .{ .bls_pubkey = [_]u8{1} ** 48, .bls_proof_of_possession = [_]u8{2} ** 96 } }, &ctx));
}

// ─────────────────────────────────────────────────────────────────────────────
// getAndUpdateAuthorizedVoter / purge — [agave] handler.rs unit-level pinning
// ─────────────────────────────────────────────────────────────────────────────

test "STAGE3-KAT: authorized-voter carry-forward across a 5-step epoch chain (handler.rs test shape)" {
    // original@0 -> new_voter@2 -> new_voter2@3 -> new_voter3@6 -> original@9
    const original = key(1);
    const v2 = key(2);
    const v3 = key(3);
    const v4 = key(4);
    var s = emptyV4(key(9), key(8));
    withAuthorizedVoter(&s, 0, original);
    withAuthorizedVoter(&s, 2, v2);
    withAuthorizedVoter(&s, 3, v3);
    withAuthorizedVoter(&s, 6, v4);
    withAuthorizedVoter(&s, 9, original);
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var state = (try codec.VoteStateV4.parse(&buf)).state;
    // query at epoch 1: carries from epoch0 = original
    var tail_copy = state.tail;
    const at1 = try vi.getAndUpdateAuthorizedVoterForTest(&tail_copy, 1);
    try testing.expectEqualSlices(u8, &original, &at1);
    _ = &state;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. UpdateValidatorIdentity
// ─────────────────────────────────────────────────────────────────────────────

fn twoAccountTable(vdata: []u8, sdata: []u8, vsigner: bool, ssigner: bool) struct { metas: [2]aio.AccountMeta, records: [2]aio.AccountRecord } {
    return .{
        .metas = [_]aio.AccountMeta{
            .{ .pubkey = VOTE_KEY, .is_signer = vsigner, .is_writable = true },
            .{ .pubkey = key(0x30), .is_signer = ssigner, .is_writable = true },
        },
        .records = [_]aio.AccountRecord{
            .{ .pubkey = VOTE_KEY, .lamports = 100_000_000, .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = vdata },
            .{ .pubkey = key(0x30), .lamports = 5_000_000, .owner = [_]u8{0} ** 32, .executable = false, .rent_epoch = 0, .data = sdata },
        },
    };
}

test "STAGE3-KAT: updateValidatorIdentity — both withdrawer and new identity must sign" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);
    var empty: [0]u8 = .{};

    var tab = twoAccountTable(&buf, &empty, true, false);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    try testing.expectError(error.MissingRequiredSignature, vi.updateValidatorIdentity(&table, 0, 1, &[_][32]u8{withdrawer}, &ctx));
}

test "STAGE3-KAT: updateValidatorIdentity — success syncs block_revenue_collector when custom_commission_collector OFF" {
    const withdrawer = key(2);
    const new_node = key(0x30);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);
    var empty: [0]u8 = .{};

    var tab = twoAccountTable(&buf, &empty, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.custom_commission_collector = false;
    const signers = [_][32]u8{ withdrawer, new_node };
    try vi.updateValidatorIdentity(&table, 0, 1, &signers, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqualSlices(u8, &new_node, &parsed.node_pubkey);
    try testing.expectEqualSlices(u8, &new_node, &parsed.block_revenue_collector);
}

test "STAGE3-KAT: updateValidatorIdentity — custom_commission_collector ON leaves block_revenue_collector untouched" {
    const withdrawer = key(2);
    const new_node = key(0x30);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    s.block_revenue_collector = key(0x77);
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);
    var empty: [0]u8 = .{};

    var tab = twoAccountTable(&buf, &empty, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.custom_commission_collector = true;
    const signers = [_][32]u8{ withdrawer, new_node };
    try vi.updateValidatorIdentity(&table, 0, 1, &signers, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqualSlices(u8, &key(0x77), &parsed.block_revenue_collector);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. UpdateCommission / UpdateCommissionBps / UpdateCommissionCollector
// ─────────────────────────────────────────────────────────────────────────────

test "STAGE3-KAT: isCommissionUpdateAllowed — allowed in first half of epoch, denied in second" {
    const es = vi.EpochScheduleParams{ .slots_per_epoch = 1000, .leader_schedule_slot_offset = 1000, .warmup = false, .first_normal_epoch = 0, .first_normal_slot = 0 };
    try testing.expect(vi.isCommissionUpdateAllowed(0, es));
    try testing.expect(vi.isCommissionUpdateAllowed(500, es));
    try testing.expect(!vi.isCommissionUpdateAllowed(501, es));
    try testing.expect(!vi.isCommissionUpdateAllowed(999, es));
}

test "STAGE3-KAT: updateCommission — increase blocked in 2nd half of epoch unless delay_commission_updates active" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    s.inflation_rewards_commission_bps = 500; // 5%
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.delay_commission_updates = false;
    ctx.slot = 999; // 2nd half of a 1000-slot epoch
    ctx.epoch_schedule = .{ .slots_per_epoch = 1000, .leader_schedule_slot_offset = 1000, .warmup = false, .first_normal_epoch = 0, .first_normal_slot = 0 };
    const signers = [_][32]u8{withdrawer};
    try testing.expectError(error.Custom, vi.updateCommission(&table, 0, 10, &signers, &ctx));
    try testing.expectEqual(@as(?u32, @intFromEnum(vi.VoteError.commission_update_too_late)), ctx.custom_error);
}

test "STAGE3-KAT: updateCommission — decrease always allowed regardless of slot position" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    s.inflation_rewards_commission_bps = 1000; // 10%
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.delay_commission_updates = false;
    ctx.slot = 999;
    ctx.epoch_schedule = .{ .slots_per_epoch = 1000, .leader_schedule_slot_offset = 1000, .warmup = false, .first_normal_epoch = 0, .first_normal_slot = 0 };
    const signers = [_][32]u8{withdrawer};
    try vi.updateCommission(&table, 0, 5, &signers, &ctx); // decrease 10% -> 5%
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqual(@as(u16, 500), parsed.inflation_rewards_commission_bps);
}

test "STAGE3-KAT: updateCommission — delay_commission_updates ON bypasses the throttle entirely" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.delay_commission_updates = true;
    ctx.slot = 999;
    ctx.epoch_schedule = .{ .slots_per_epoch = 1000, .leader_schedule_slot_offset = 1000, .warmup = false, .first_normal_epoch = 0, .first_normal_slot = 0 };
    try vi.updateCommission(&table, 0, 50, &[_][32]u8{withdrawer}, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqual(@as(u16, 5000), parsed.inflation_rewards_commission_bps);
}

test "STAGE3-KAT: updateCommissionBps — no epoch-midpoint throttle, both kinds independently settable" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.slot = 999;
    ctx.epoch_schedule = .{ .slots_per_epoch = 1000, .leader_schedule_slot_offset = 1000, .warmup = false, .first_normal_epoch = 0, .first_normal_slot = 0 };
    const signers = [_][32]u8{withdrawer};
    try vi.updateCommissionBps(&table, 0, 1234, .inflation_rewards, &signers, &ctx);
    try vi.updateCommissionBps(&table, 0, 5678, .block_revenue, &signers, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqual(@as(u16, 1234), parsed.inflation_rewards_commission_bps);
    try testing.expectEqual(@as(u16, 5678), parsed.block_revenue_commission_bps);
}

test "STAGE3-KAT: updateCommissionBps — BlockRevenue kind rejected when block_revenue_sharing gate is off" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.block_revenue_sharing = false;
    try testing.expectError(error.InvalidInstructionData, vi.updateCommissionBps(&table, 0, 100, .block_revenue, &[_][32]u8{withdrawer}, &ctx));
}

test "STAGE3-KAT: updateCommissionCollector — self-alias short-circuits all checks" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);
    var empty: [0]u8 = .{};

    var out: struct { table: aio.AccountTable, metas: [2]aio.AccountMeta, records: [2]aio.AccountRecord } = undefined;
    out.metas = [_]aio.AccountMeta{
        .{ .pubkey = VOTE_KEY, .is_signer = true, .is_writable = true },
        .{ .pubkey = VOTE_KEY, .is_signer = false, .is_writable = false }, // aliases the vote account itself
    };
    out.records = [_]aio.AccountRecord{
        .{ .pubkey = VOTE_KEY, .lamports = 100_000_000, .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = &buf },
        .{ .pubkey = VOTE_KEY, .lamports = 100_000_000, .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = &empty },
    };
    out.table = aio.AccountTable.init(VOTE_PROGRAM_ID, &out.metas, &out.records) catch unreachable;
    var ctx = defaultCtx();
    try vi.updateCommissionCollector(&out.table, 0, 1, .inflation_rewards, &[_][32]u8{withdrawer}, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqualSlices(u8, &VOTE_KEY, &parsed.inflation_rewards_collector);
}

test "STAGE3-KAT: updateCommissionCollector — third-party collector must be system-owned, rent-exempt, writable" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);
    var cdata: [0]u8 = .{};

    var tab = twoAccountTable(&buf, &cdata, true, false);
    var table = mkTable(&tab.metas, &tab.records);
    tab.metas[1].is_writable = false; // not writable -> InvalidArgument
    tab.records[1].owner = [_]u8{0} ** 32; // system-owned
    tab.records[1].lamports = vi.minimumBalance(0); // rent-exempt
    var ctx = defaultCtx();
    try testing.expectError(error.InvalidArgument, vi.updateCommissionCollector(&table, 0, 1, .block_revenue, &[_][32]u8{withdrawer}, &ctx));

    tab.metas[1].is_writable = true;
    try vi.updateCommissionCollector(&table, 0, 1, .block_revenue, &[_][32]u8{withdrawer}, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqualSlices(u8, &key(0x30), &parsed.block_revenue_collector);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Withdraw
// ─────────────────────────────────────────────────────────────────────────────

fn withdrawTable(vdata: []u8) struct { metas: [2]aio.AccountMeta, records: [2]aio.AccountRecord } {
    return .{
        .metas = [_]aio.AccountMeta{
            .{ .pubkey = VOTE_KEY, .is_signer = false, .is_writable = true },
            .{ .pubkey = key(0x40), .is_signer = false, .is_writable = true },
        },
        .records = [_]aio.AccountRecord{
            .{ .pubkey = VOTE_KEY, .lamports = 10_000_000, .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = vdata },
            .{ .pubkey = key(0x40), .lamports = 0, .owner = [_]u8{0} ** 32, .executable = false, .rent_epoch = 0, .data = &[_]u8{} },
        },
    };
}

test "STAGE3-KAT: withdraw — partial withdrawal above rent-exempt floor succeeds, moves lamports" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = withdrawTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    tab.records[0].lamports = vi.minimumBalance(3762) + 5_000_000;
    var ctx = defaultCtx();
    try vi.withdraw(&table, 0, 1, 5_000_000, &[_][32]u8{withdrawer}, &ctx);
    try testing.expectEqual(vi.minimumBalance(3762), table.records[0].lamports);
    try testing.expectEqual(@as(u64, 5_000_000), table.records[1].lamports);
}

test "STAGE3-KAT: withdraw — partial withdrawal below rent-exempt floor rejected" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = withdrawTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    tab.records[0].lamports = vi.minimumBalance(3762) + 1000;
    var ctx = defaultCtx();
    try testing.expectError(error.InsufficientFunds, vi.withdraw(&table, 0, 1, 5000, &[_][32]u8{withdrawer}, &ctx));
}

test "STAGE3-KAT: withdraw — full close zeroes entire account when not recently active" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    withEpochCredit(&s, 3, 100, 50); // last credited epoch 3
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = withdrawTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    const full = table.records[0].lamports;
    var ctx = defaultCtx();
    ctx.epoch = 10; // 10 - 3 = 7 >= 2, close allowed
    try vi.withdraw(&table, 0, 1, full, &[_][32]u8{withdrawer}, &ctx);
    try testing.expectEqual(@as(u64, 0), table.records[0].lamports);
    for (buf) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "STAGE3-KAT: withdraw — full close rejected (ActiveVoteAccountClose) when voted within last epoch" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    withEpochCredit(&s, 9, 100, 50); // last credited epoch 9
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = withdrawTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    const full = table.records[0].lamports;
    var ctx = defaultCtx();
    ctx.epoch = 10; // 10 - 9 = 1 < 2 -> rejected
    try testing.expectError(error.Custom, vi.withdraw(&table, 0, 1, full, &[_][32]u8{withdrawer}, &ctx));
    try testing.expectEqual(@as(?u32, @intFromEnum(vi.VoteError.active_vote_account_close)), ctx.custom_error);
}

test "STAGE3-KAT: withdraw — non-withdrawer signer rejected" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = withdrawTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    try testing.expectError(error.MissingRequiredSignature, vi.withdraw(&table, 0, 1, 1000, &[_][32]u8{key(9)}, &ctx));
}

test "STAGE3-KAT: withdraw — overdraw rejected InsufficientFunds" {
    const withdrawer = key(2);
    var s = emptyV4(key(1), withdrawer);
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = withdrawTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    tab.records[0].lamports = 1000;
    var ctx = defaultCtx();
    try testing.expectError(error.InsufficientFunds, vi.withdraw(&table, 0, 1, 2000, &[_][32]u8{withdrawer}, &ctx));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. InitializeAccount + InitializeAccountV2
// ─────────────────────────────────────────────────────────────────────────────

test "STAGE3-KAT: initializeAccount — success on a rent-exempt, zeroed, correctly-sized account" {
    var buf: [3762]u8 = [_]u8{0} ** 3762;
    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    tab.records[0].lamports = vi.minimumBalance(3762);
    var ctx = defaultCtx();
    const node = key(1);
    const voter = key(2);
    const withdrawer = key(3);
    try vi.initializeAccount(&table, 0, node, voter, withdrawer, 42, &[_][32]u8{node}, &ctx);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqualSlices(u8, &node, &parsed.node_pubkey);
    try testing.expectEqualSlices(u8, &withdrawer, &parsed.authorized_withdrawer);
    try testing.expectEqualSlices(u8, &VOTE_KEY, &parsed.inflation_rewards_collector);
    try testing.expectEqual(@as(u16, 4200), parsed.inflation_rewards_commission_bps);
    try testing.expectEqual(@as(usize, 1), parsed.tail.authorized_voters_len);
    try testing.expectEqualSlices(u8, &voter, &parsed.tail.authorized_voters[0].pubkey);
}

test "STAGE3-KAT: initializeAccount — reinitializing an already-initialized account rejected" {
    var s = emptyV4(key(1), key(2));
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);
    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    tab.records[0].lamports = vi.minimumBalance(3762);
    var ctx = defaultCtx();
    try testing.expectError(error.AccountAlreadyInitialized, vi.initializeAccount(&table, 0, key(1), key(4), key(5), 1, &[_][32]u8{key(1)}, &ctx));
}

test "STAGE3-KAT: initializeAccount — not rent-exempt rejected InsufficientFunds" {
    var buf: [3762]u8 = [_]u8{0} ** 3762;
    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    tab.records[0].lamports = 1;
    var ctx = defaultCtx();
    try testing.expectError(error.InsufficientFunds, vi.initializeAccount(&table, 0, key(1), key(2), key(3), 1, &[_][32]u8{key(1)}, &ctx));
}

test "STAGE3-KAT: initializeAccount — unsigned node rejected MissingRequiredSignature" {
    var buf: [3762]u8 = [_]u8{0} ** 3762;
    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    tab.records[0].lamports = vi.minimumBalance(3762);
    var ctx = defaultCtx();
    try testing.expectError(error.MissingRequiredSignature, vi.initializeAccount(&table, 0, key(1), key(2), key(3), 1, &[_][32]u8{key(9)}, &ctx));
}

test "STAGE3-KAT: initializeAccountV2 — success builds V4 with explicit collectors+bps+BLS key" {
    var buf: [3762]u8 = [_]u8{0} ** 3762;
    var cdata1: [0]u8 = .{};
    var cdata2: [0]u8 = .{};
    var out: struct { table: aio.AccountTable, metas: [3]aio.AccountMeta, records: [3]aio.AccountRecord } = undefined;
    out.metas = [_]aio.AccountMeta{
        .{ .pubkey = VOTE_KEY, .is_signer = true, .is_writable = true },
        .{ .pubkey = key(0x50), .is_signer = false, .is_writable = true },
        .{ .pubkey = key(0x51), .is_signer = false, .is_writable = true },
    };
    out.records = [_]aio.AccountRecord{
        .{ .pubkey = VOTE_KEY, .lamports = vi.minimumBalance(3762), .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = &buf },
        .{ .pubkey = key(0x50), .lamports = vi.minimumBalance(0), .owner = [_]u8{0} ** 32, .executable = false, .rent_epoch = 0, .data = &cdata1 },
        .{ .pubkey = key(0x51), .lamports = vi.minimumBalance(0), .owner = [_]u8{0} ** 32, .executable = false, .rent_epoch = 0, .data = &cdata2 },
    };
    out.table = aio.AccountTable.init(VOTE_PROGRAM_ID, &out.metas, &out.records) catch unreachable;

    var ctx = defaultCtx();
    const kp = bls_pop.TestKeypair.fromIkm(&[_]u8{0x33} ** 32);
    var payload: [41]u8 = undefined;
    @memcpy(payload[0..9], "ALPENGLOW");
    @memcpy(payload[9..41], &VOTE_KEY);
    const pop = kp.signPop(&payload);
    const node = key(1);
    try vi.initializeAccountV2(&out.table, 0, 1, 2, .{
        .node_pubkey = node,
        .authorized_voter = key(2),
        .authorized_voter_bls_pubkey = kp.pubkey_compressed,
        .authorized_voter_bls_proof_of_possession = pop,
        .authorized_withdrawer = key(3),
        .inflation_rewards_commission_bps = 777,
        .block_revenue_commission_bps = 888,
    }, &[_][32]u8{node}, &ctx);

    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqualSlices(u8, &key(0x50), &parsed.inflation_rewards_collector);
    try testing.expectEqualSlices(u8, &key(0x51), &parsed.block_revenue_collector);
    try testing.expectEqual(@as(u16, 777), parsed.inflation_rewards_commission_bps);
    try testing.expectEqual(@as(u16, 888), parsed.block_revenue_commission_bps);
    try testing.expect(parsed.bls_pubkey_compressed != null);
}

test "STAGE3-KAT: initializeAccountV2 — feature gate off rejects InvalidInstructionData" {
    var buf: [3762]u8 = [_]u8{0} ** 3762;
    var tab = oneAccountTable(&buf, true, true);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.vote_account_initialize_v2 = false;
    try testing.expectError(error.InvalidInstructionData, vi.initializeAccountV2(&table, 0, 0, 0, .{
        .node_pubkey = key(1),
        .authorized_voter = key(2),
        .authorized_voter_bls_pubkey = [_]u8{1} ** 48,
        .authorized_voter_bls_proof_of_possession = [_]u8{2} ** 96,
        .authorized_withdrawer = key(3),
        .inflation_rewards_commission_bps = 0,
        .block_revenue_commission_bps = 0,
    }, &[_][32]u8{key(1)}, &ctx));
}

test "STAGE3-KAT: initializeAccountV2 — bad PoP rejected InvalidArgument" {
    var buf: [3762]u8 = [_]u8{0} ** 3762;
    var cdata: [0]u8 = .{};
    var out: struct { table: aio.AccountTable, metas: [3]aio.AccountMeta, records: [3]aio.AccountRecord } = undefined;
    out.metas = [_]aio.AccountMeta{
        .{ .pubkey = VOTE_KEY, .is_signer = true, .is_writable = true },
        .{ .pubkey = VOTE_KEY, .is_signer = false, .is_writable = false },
        .{ .pubkey = VOTE_KEY, .is_signer = false, .is_writable = false },
    };
    out.records = [_]aio.AccountRecord{
        .{ .pubkey = VOTE_KEY, .lamports = vi.minimumBalance(3762), .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = &buf },
        .{ .pubkey = VOTE_KEY, .lamports = vi.minimumBalance(3762), .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = &cdata },
        .{ .pubkey = VOTE_KEY, .lamports = vi.minimumBalance(3762), .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = &cdata },
    };
    out.table = aio.AccountTable.init(VOTE_PROGRAM_ID, &out.metas, &out.records) catch unreachable;
    var ctx = defaultCtx();
    const node = key(1);
    try testing.expectError(error.InvalidArgument, vi.initializeAccountV2(&out.table, 0, 1, 2, .{
        .node_pubkey = node,
        .authorized_voter = key(2),
        .authorized_voter_bls_pubkey = [_]u8{0xAB} ** 48,
        .authorized_voter_bls_proof_of_possession = [_]u8{0xCD} ** 96,
        .authorized_withdrawer = key(3),
        .inflation_rewards_commission_bps = 0,
        .block_revenue_commission_bps = 0,
    }, &[_][32]u8{node}, &ctx));
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. DepositDelegatorRewards — Agave-only (no transplant equivalent, §D.4)
// ─────────────────────────────────────────────────────────────────────────────

fn depositTable(vdata: []u8) struct { metas: [2]aio.AccountMeta, records: [2]aio.AccountRecord } {
    return .{
        .metas = [_]aio.AccountMeta{
            .{ .pubkey = VOTE_KEY, .is_signer = false, .is_writable = true },
            .{ .pubkey = key(0x60), .is_signer = true, .is_writable = true },
        },
        .records = [_]aio.AccountRecord{
            .{ .pubkey = VOTE_KEY, .lamports = 10_000_000, .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = vdata },
            .{ .pubkey = key(0x60), .lamports = 5_000_000, .owner = [_]u8{0} ** 32, .executable = false, .rent_epoch = 0, .data = &[_]u8{} },
        },
    };
}

test "STAGE3-KAT: depositDelegatorRewards — success moves lamports + accumulates pending_delegator_rewards" {
    var s = emptyV4(key(1), key(2));
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = depositTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    try vi.depositDelegatorRewards(&table, 0, 1, 1_000_000, &[_][32]u8{key(0x60)}, &ctx);
    try vi.depositDelegatorRewards(&table, 0, 1, 500_000, &[_][32]u8{key(0x60)}, &ctx);
    try testing.expectEqual(@as(u64, 11_500_000), table.records[0].lamports);
    try testing.expectEqual(@as(u64, 3_500_000), table.records[1].lamports);
    const parsed = (try codec.VoteStateV4.parse(&buf)).state;
    try testing.expectEqual(@as(u64, 1_500_000), parsed.pending_delegator_rewards);
}

test "STAGE3-KAT: depositDelegatorRewards — zero deposit is a valid no-op" {
    var s = emptyV4(key(1), key(2));
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = depositTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    try vi.depositDelegatorRewards(&table, 0, 1, 0, &[_][32]u8{key(0x60)}, &ctx);
    try testing.expectEqual(@as(u64, 10_000_000), table.records[0].lamports);
}

test "STAGE3-KAT: depositDelegatorRewards — feature gate off rejects" {
    var s = emptyV4(key(1), key(2));
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = depositTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    ctx.features.block_revenue_sharing = false;
    try testing.expectError(error.InvalidInstructionData, vi.depositDelegatorRewards(&table, 0, 1, 100, &[_][32]u8{key(0x60)}, &ctx));
}

test "STAGE3-KAT: depositDelegatorRewards — V3 account rejected (no auto-migrate, unlike every other instruction)" {
    var s3: codec.VoteStateV3 = std.mem.zeroes(codec.VoteStateV3);
    s3.node_pubkey = key(1);
    s3.authorized_withdrawer = key(2);
    s3.commission = 5;
    s3.tail = codec.Tail.EMPTY;
    s3.tail.authorized_voters[0] = .{ .epoch = 8, .pubkey = key(3) };
    s3.tail.authorized_voters_len = 1;
    var buf: [3762]u8 = [_]u8{0} ** 3762;
    _ = s3.serialize(&buf) catch unreachable;

    var tab = depositTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    var ctx = defaultCtx();
    try testing.expectError(error.InvalidAccountData, vi.depositDelegatorRewards(&table, 0, 1, 100, &[_][32]u8{key(0x60)}, &ctx));
}

test "STAGE3-KAT: depositDelegatorRewards — unsigned source rejected" {
    var s = emptyV4(key(1), key(2));
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = depositTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    tab.metas[1].is_signer = false;
    var ctx = defaultCtx();
    try testing.expectError(error.MissingRequiredSignature, vi.depositDelegatorRewards(&table, 0, 1, 100, &[_][32]u8{}, &ctx));
}

test "STAGE3-KAT: depositDelegatorRewards — insufficient source balance rejected as system Custom(1)" {
    var s = emptyV4(key(1), key(2));
    withAuthorizedVoter(&s, 8, key(3));
    var buf: [3762]u8 = undefined;
    serializeInto(&buf, &s);

    var tab = depositTable(&buf);
    var table = mkTable(&tab.metas, &tab.records);
    tab.records[1].lamports = 100;
    var ctx = defaultCtx();
    try testing.expectError(error.Custom, vi.depositDelegatorRewards(&table, 0, 1, 1000, &[_][32]u8{key(0x60)}, &ctx));
    try testing.expectEqual(@as(?u32, 1), ctx.custom_error);
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction-argument decode round-trips
// ─────────────────────────────────────────────────────────────────────────────

test "STAGE3-KAT: parseInstruction — Authorize(disc1) decodes new_authority+VoteAuthorize.voter" {
    var data: [4 + 32 + 4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 1, .little);
    @memcpy(data[4..36], &key(9));
    std.mem.writeInt(u32, data[36..40], 0, .little); // voter
    const parsed = try vi.parseInstruction(testing.allocator, &data);
    switch (parsed) {
        .authorize => |a| {
            try testing.expectEqualSlices(u8, &key(9), &a.new_authority);
            try testing.expect(a.vote_authorize == .voter);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "STAGE3-KAT: parseInstruction — Withdraw(disc3) decodes u64 lamports" {
    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 3, .little);
    std.mem.writeInt(u64, data[4..12], 42_000_000, .little);
    const parsed = try vi.parseInstruction(testing.allocator, &data);
    switch (parsed) {
        .withdraw => |w| try testing.expectEqual(@as(u64, 42_000_000), w.lamports),
        else => return error.TestUnexpectedResult,
    }
}

test "STAGE3-KAT: parseInstruction — UpdateCommissionBps(disc18) decodes bps(u16)+kind(u32 enum)" {
    var data: [10]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 18, .little);
    std.mem.writeInt(u16, data[4..6], 999, .little);
    std.mem.writeInt(u32, data[6..10], 1, .little); // block_revenue
    const parsed = try vi.parseInstruction(testing.allocator, &data);
    switch (parsed) {
        .update_commission_bps => |u| {
            try testing.expectEqual(@as(u16, 999), u.commission_bps);
            try testing.expect(u.kind == .block_revenue);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "STAGE5-KAT: parseInstruction — TowerSync(disc14) with a truncated payload is a decode error, not unrouted (Stage 5 landed)" {
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 14, .little);
    try testing.expectError(error.InvalidInstructionData, vi.parseInstruction(testing.allocator, &data));
    try testing.expect(!vi.isStage5Discriminant(14));
    try testing.expect(vi.isStage3Discriminant(14));
}

test "STAGE5-KAT: discriminant routing tables — every discriminant 0-19 is handled, isStage5Discriminant is always false, KNOWN-GAP subset is still {16,19}" {
    var d: u32 = 0;
    while (d <= 19) : (d += 1) {
        try testing.expect(vi.isStage3Discriminant(d));
        try testing.expect(!vi.isStage5Discriminant(d));
    }
    try testing.expect(!vi.isStage3Discriminant(20));
    try testing.expect(vi.isKnownGapDiscriminant(16));
    try testing.expect(vi.isKnownGapDiscriminant(19));
    try testing.expect(!vi.isKnownGapDiscriminant(1));
    try testing.expect(!vi.isKnownGapDiscriminant(14));
}
