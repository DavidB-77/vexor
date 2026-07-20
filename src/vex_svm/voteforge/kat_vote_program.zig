//! voteforge, stage 4 — `vote_program.zig` (dispatch glue / front door) KATs
//! (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 4 gate).
//!
//! Legs:
//!   1. Decode-layer KATs: malformed/truncated/unknown-discriminant/oversized
//!      instruction data never panics, always resolves to a well-defined
//!      `InstrError` or a successful classify/decode.
//!   2. Dispatch-table completeness: every discriminant 0..19 routes
//!      (`.stage3`) or delegates (`.stage5`), none silently dropped as
//!      `.unrecognized` — the full 20-variant `VoteInstruction` table is
//!      covered, cross-checked against `vote_instructions.zig`'s own
//!      `isStage3Discriminant`/`isStage5Discriminant` partition.
//!   3. Decode-corpus KAT: a fixed fixture corpus of hand-built instruction
//!      bytes with expected accept/reject verdicts, driven through this front
//!      door's zero-alloc discriminant peek + Stage 3's `parseInstruction`.
//!   4. Real execution KATs through the live front door `vp.dispatch()`
//!      (missing-signer TowerSync rejection, disc16 KNOWN-GAP classification).
//!
//! (The Sig-transplant differential legs — decode-agreement and byte-equal
//! execution comparison of voteforge vs the oracle — were removed with the
//! transplant 2026-07-12; the voteforge-side assertions above are the
//! surviving anchor.)

const std = @import("std");
const testing = std.testing;
const vp = @import("vote_program.zig");
const vi = @import("vote_instructions.zig");
const aio = @import("account_io.zig");
const codec = @import("vote_codec.zig");

// ─────────────────────────────────────────────────────────────────────────────
// 1. Decode-layer KATs — never panic, always a well-defined error/success.
// ─────────────────────────────────────────────────────────────────────────────

test "DECODE-KAT: empty instruction data -> InvalidInstructionData, not a crash" {
    try testing.expectError(error.InvalidInstructionData, vp.peekDiscriminant(&[_]u8{}));
}

test "DECODE-KAT: 1/2/3-byte truncated discriminant -> InvalidInstructionData" {
    try testing.expectError(error.InvalidInstructionData, vp.peekDiscriminant(&[_]u8{0x01}));
    try testing.expectError(error.InvalidInstructionData, vp.peekDiscriminant(&[_]u8{ 0x01, 0x00 }));
    try testing.expectError(error.InvalidInstructionData, vp.peekDiscriminant(&[_]u8{ 0x01, 0x00, 0x00 }));
}

test "DECODE-KAT: unknown discriminant (20, 255, u32 max) classifies unrecognized, never errors at the classify step" {
    for ([_]u32{ 20, 255, 1000, std.math.maxInt(u32) }) |d| {
        try testing.expect(vp.classify(d) == .unrecognized);
    }
}

test "DECODE-KAT: Stage-3 discriminant with truncated payload -> InvalidInstructionData from parseInstruction, not a panic" {
    const alloc = testing.allocator;
    // Authorize (disc1) needs 32 (new_authority) + 4 (vote_authorize tag)
    // bytes after the discriminant; supply only 10.
    var data: [14]u8 = [_]u8{0} ** 14;
    std.mem.writeInt(u32, data[0..4], 1, .little);
    try testing.expectError(error.InvalidInstructionData, vi.parseInstruction(alloc, &data));
}

test "DECODE-KAT: Stage-3 discriminant with oversized payload decodes the fixed-size prefix and ignores the tail" {
    const alloc = testing.allocator;
    var data: [200]u8 = [_]u8{0xCD} ** 200;
    std.mem.writeInt(u32, data[0..4], 5, .little); // UpdateCommission
    data[4] = 42;
    const parsed = try vi.parseInstruction(alloc, &data);
    switch (parsed) {
        .update_commission => |u| try testing.expectEqual(@as(u8, 42), u.commission),
        else => return error.TestUnexpectedResult,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Dispatch-table completeness — every discriminant 0..19 routes to exactly
// one of {.stage3, .stage5}, cross-checked against vote_instructions.zig's
// own partition (this is the SAME invariant vote_program.zig's own
// self-test pins; repeated here against the KAT-suite root so it gates
// alongside the differential legs, not just the front-door file in isolation).
// ─────────────────────────────────────────────────────────────────────────────

test "COMPLETENESS-KAT: 0..19 partitions exactly into Stage-3+5 (20) / Stage-5-remaining (0), zero overlap, zero gap — Stage 5 landed" {
    var stage3_count: usize = 0;
    var stage5_count: usize = 0;
    var i: u32 = 0;
    while (i <= 19) : (i += 1) {
        const c = vp.classify(i);
        try testing.expect(c != .unrecognized);
        const is3 = vi.isStage3Discriminant(i);
        const is5 = vi.isStage5Discriminant(i);
        try testing.expect(is3 != is5); // exactly one, never both, never neither
        try testing.expectEqual(if (is3) vp.RouteClass.stage3 else vp.RouteClass.stage5, c);
        if (is3) stage3_count += 1;
        if (is5) stage5_count += 1;
    }
    // Stage 5 landed (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 5): every
    // discriminant 0-19 is now handled directly — `isStage5Discriminant`
    // always returns false (kept for API stability, see vote_instructions.zig).
    try testing.expectEqual(@as(usize, 20), stage3_count);
    try testing.expectEqual(@as(usize, 0), stage5_count);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Decode-corpus KAT — a fixed fixture corpus of instruction bytes with
// expected accept/reject verdicts, driven through the front door's zero-alloc
// discriminant peek + Stage 3's parseInstruction.
// ─────────────────────────────────────────────────────────────────────────────

const Fixture = struct {
    name: []const u8,
    data: []const u8,
    expect_ok: bool,
};

fn mkAuthorize(buf: *[40]u8, disc: u32, new_authority: [32]u8, kind: u32) []const u8 {
    std.mem.writeInt(u32, buf[0..4], disc, .little);
    @memcpy(buf[4..36], &new_authority);
    std.mem.writeInt(u32, buf[36..40], kind, .little);
    return buf;
}

test "DECODE-CORPUS-KAT: fixture corpus — voteforge decode verdict matches expected accept/reject" {
    const alloc = testing.allocator;

    var init_buf: [101]u8 = undefined; // 4(disc) + 32(node) + 32(voter) + 32(withdrawer) + 1(commission)
    std.mem.writeInt(u32, init_buf[0..4], 0, .little);
    @memset(init_buf[4..], 0x11);

    var auth_buf: [40]u8 = undefined;
    _ = mkAuthorize(&auth_buf, 1, [_]u8{0x22} ** 32, 0);

    var withdraw_buf: [12]u8 = undefined;
    std.mem.writeInt(u32, withdraw_buf[0..4], 3, .little);
    std.mem.writeInt(u64, withdraw_buf[4..12], 12345, .little);

    var uvi_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &uvi_buf, 4, .little);

    var commission_buf: [5]u8 = undefined;
    std.mem.writeInt(u32, commission_buf[0..4], 5, .little);
    commission_buf[4] = 7;

    var authchk_buf: [8]u8 = undefined; // AuthorizeChecked(disc7): disc(4) + VoteAuthorize tag(4, voter=0)
    std.mem.writeInt(u32, authchk_buf[0..4], 7, .little);
    std.mem.writeInt(u32, authchk_buf[4..8], 0, .little);

    var bps_buf: [10]u8 = undefined;
    std.mem.writeInt(u32, bps_buf[0..4], 18, .little);
    std.mem.writeInt(u16, bps_buf[4..6], 500, .little);
    std.mem.writeInt(u32, bps_buf[6..10], 0, .little);

    var vote_trunc_buf: [4]u8 = undefined; // Vote (disc2) -- discriminant-only, no payload: truncated
    std.mem.writeInt(u32, &vote_trunc_buf, 2, .little);

    var towersync_trunc_buf: [4]u8 = undefined; // TowerSync (disc14) -- discriminant-only: truncated
    std.mem.writeInt(u32, &towersync_trunc_buf, 14, .little);

    // Vote(2), full valid payload: disc(4) + slots Vec<u64>{len=1,[100]}(8+8) +
    // hash[32] + timestamp Option<i64>::None(1) = 53 bytes.
    var vote_buf: [53]u8 = undefined;
    std.mem.writeInt(u32, vote_buf[0..4], 2, .little);
    std.mem.writeInt(u64, vote_buf[4..12], 1, .little);
    std.mem.writeInt(u64, vote_buf[12..20], 100, .little);
    @memset(vote_buf[20..52], 0);
    vote_buf[52] = 0; // timestamp: None

    // TowerSync(14), full valid compact payload: disc(4) + root=Slot::MAX(8,
    // None) + short_vec<LockoutOffset>{count=1(1B), offset=100(varint,1B),
    // confirmation_count=1(1B)} + hash[32] + timestamp::None(1) + block_id[32]
    // = 4+8+1+1+1+32+1+32 = 80 bytes.
    var towersync_buf: [80]u8 = undefined;
    std.mem.writeInt(u32, towersync_buf[0..4], 14, .little);
    std.mem.writeInt(u64, towersync_buf[4..12], std.math.maxInt(u64), .little);
    towersync_buf[12] = 1; // short_vec count = 1
    towersync_buf[13] = 100; // varint offset = 100 (< 0x80, single byte)
    towersync_buf[14] = 1; // confirmation_count = 1
    @memset(towersync_buf[15..47], 0); // hash
    towersync_buf[47] = 0; // timestamp: None
    @memset(towersync_buf[48..80], 0); // block_id

    var unknown_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &unknown_buf, 20, .little);

    var trunc_authorize: [10]u8 = undefined; // disc1 with only 6 payload bytes (needs 36)
    std.mem.writeInt(u32, trunc_authorize[0..4], 1, .little);

    const fixtures = [_]Fixture{
        .{ .name = "empty", .data = &[_]u8{}, .expect_ok = false },
        .{ .name = "truncated-3B", .data = &[_]u8{ 1, 2, 3 }, .expect_ok = false },
        .{ .name = "InitializeAccount(0)", .data = &init_buf, .expect_ok = true },
        .{ .name = "Authorize(1)", .data = &auth_buf, .expect_ok = true },
        .{ .name = "Authorize(1)-truncated", .data = &trunc_authorize, .expect_ok = false },
        .{ .name = "Withdraw(3)", .data = &withdraw_buf, .expect_ok = true },
        .{ .name = "UpdateValidatorIdentity(4)", .data = &uvi_buf, .expect_ok = true },
        .{ .name = "UpdateCommission(5)", .data = &commission_buf, .expect_ok = true },
        .{ .name = "AuthorizeChecked(7)", .data = &authchk_buf, .expect_ok = true },
        .{ .name = "UpdateCommissionBps(18)", .data = &bps_buf, .expect_ok = true },
        .{ .name = "Vote(2)-truncated", .data = &vote_trunc_buf, .expect_ok = false },
        .{ .name = "TowerSync(14)-truncated", .data = &towersync_trunc_buf, .expect_ok = false },
        .{ .name = "Vote(2)", .data = &vote_buf, .expect_ok = true }, // Stage 5 landed: full real decode, both sides
        .{ .name = "TowerSync(14)", .data = &towersync_buf, .expect_ok = true },
        .{ .name = "unrecognized(20)", .data = &unknown_buf, .expect_ok = false },
    };

    for (fixtures) |fx| {
        // For Stage-3-owned discriminants, exercise voteforge's REAL
        // parseInstruction (the front door's own decode path for that leg).
        // For Stage-5/unrecognized, exercise the front door's zero-alloc
        // peek+classify (voteforge never fully decodes those).
        const disc_or_err = vp.peekDiscriminant(fx.data);
        if (disc_or_err) |disc| {
            const class = vp.classify(disc);
            const our_ok = switch (class) {
                .stage3 => blk: {
                    const parsed = vi.parseInstruction(alloc, fx.data) catch break :blk false;
                    _ = parsed;
                    break :blk true;
                },
                .stage5, .unrecognized => true, // peek succeeded; that's all voteforge claims for these
            };
            if (class == .stage3) {
                try testing.expectEqual(fx.expect_ok, our_ok);
            }
        } else |_| {
            try testing.expect(!fx.expect_ok);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Real execution KATs through the live front door `vp.dispatch()`:
// missing-signer TowerSync rejection and disc16 KNOWN-GAP classification,
// exercising the account-table build + dispatch + all-or-nothing-on-error
// commit contract the way the live seam (`executeVoteViaVoteforge`) does.
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal outcome shape for these KATs — the vote account's post-execution
/// fields plus the error name/custom code, mirroring the live seam's own diff.
const Outcome = struct {
    lamports: u64,
    owner: [32]u8,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
    err_name: ?[]const u8,
    custom_code: ?u32,
};

/// [local] gate-off `vi.ExecContext` — matches `vote_program.zig`'s own
/// (private, test-only) `defaultCtx()` helper byte-for-byte; duplicated here
/// rather than exported across the file boundary, keeping that file's test
/// section self-contained.
fn defaultExecCtx() vi.ExecContext {
    return .{
        .slot = 1000,
        .epoch = 10,
        .leader_schedule_epoch = 10,
        .epoch_schedule = .{ .slots_per_epoch = 432_000, .leader_schedule_slot_offset = 432_000, .warmup = false, .first_normal_epoch = 0, .first_normal_slot = 0 },
        .features = .{},
        .alloc = std.testing.allocator,
    };
}

/// The voteforge (live) side of the same fixture, through the REAL front
/// door `vp.dispatch()` — returns a `vab.Outcome` in the same shape.
fn execVoteforge(alloc: std.mem.Allocator, vote_pubkey: [32]u8, vote_data: []const u8, vote_lamports: u64, is_signer: bool, ix_data: []const u8) !Outcome {
    const data = try alloc.dupe(u8, vote_data);
    defer alloc.free(data); // safe here: this fixture errors pre-write, so the account buffer is never resized.
    var metas = [_]aio.AccountMeta{.{ .pubkey = vote_pubkey, .is_signer = is_signer, .is_writable = true }};
    var records = [_]aio.AccountRecord{.{ .pubkey = vote_pubkey, .lamports = vote_lamports, .owner = vp.VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = data }};
    var table = try aio.AccountTable.init(vp.VOTE_PROGRAM_ID, &metas, &records);
    var ctx = defaultExecCtx();
    const result = try vp.dispatch(alloc, &table, vp.VOTE_PROGRAM_ID, ix_data, if (is_signer) &[_][32]u8{vote_pubkey} else &[_][32]u8{}, &ctx);
    const exec_result: vi.InstrError!void = switch (result) {
        .handled => |h| h,
        .delegate => error.InvalidInstructionData,
    };
    if (exec_result) |_| {
        return .{
            .lamports = table.records[0].lamports,
            .owner = table.records[0].owner,
            .executable = table.records[0].executable,
            .rent_epoch = table.records[0].rent_epoch,
            .data = try alloc.dupe(u8, table.records[0].data),
            .err_name = null,
            .custom_code = null,
        };
    } else |e| {
        return .{
            .lamports = vote_lamports,
            .owner = vp.VOTE_PROGRAM_ID,
            .executable = false,
            .rent_epoch = 0,
            .data = try alloc.dupe(u8, vote_data),
            .err_name = @errorName(e),
            .custom_code = ctx.custom_error,
        };
    }
}

test "STAGE7-EXEC-KAT: TowerSync (disc14) — voteforge rejects the missing-signer fixture with MissingRequiredSignature and does not mutate" {
    // Uses a well-formed, REALISTICALLY INITIALIZED V4 account and withholds
    // the authorized-voter signature — exercising `verifyAuthorizedSigner`/
    // `isPubkeySigner` through the live front door, with the all-or-nothing
    // no-mutation-on-error contract asserted below.
    const alloc = testing.allocator;
    const vote_key = [_]u8{0xAA} ** 32;
    const authorized_voter = [_]u8{0x03} ** 32;
    var s: codec.VoteStateV4 = std.mem.zeroes(codec.VoteStateV4);
    s.node_pubkey = [_]u8{0x01} ** 32;
    s.authorized_withdrawer = [_]u8{0x02} ** 32;
    s.inflation_rewards_collector = [_]u8{0xAA} ** 32;
    s.block_revenue_collector = s.node_pubkey;
    s.block_revenue_commission_bps = 10_000;
    s.tail = codec.Tail.EMPTY;
    s.tail.authorized_voters[0] = .{ .epoch = 8, .pubkey = authorized_voter };
    s.tail.authorized_voters_len = 1;
    var vote_data: [3762]u8 = [_]u8{0} ** 3762;
    _ = try s.serialize(&vote_data);

    // Well-formed compact TowerSync payload — decodes cleanly
    // (same 80-byte shape as the decode-corpus fixture above).
    var ix_data: [80]u8 = undefined;
    std.mem.writeInt(u32, ix_data[0..4], 14, .little);
    std.mem.writeInt(u64, ix_data[4..12], std.math.maxInt(u64), .little);
    ix_data[12] = 1;
    ix_data[13] = 5;
    ix_data[14] = 1;
    @memset(ix_data[15..47], 0);
    ix_data[47] = 0;
    @memset(ix_data[48..80], 0);

    // is_signer=false on the vote account itself, and no OTHER signer is
    // threaded (`authorized_voter` never appears in the signer set) — voteforge
    // must reject with MissingRequiredSignature.
    const live = try execVoteforge(alloc, vote_key, &vote_data, 1000, false, &ix_data);
    defer alloc.free(live.data);

    try testing.expectEqualStrings("MissingRequiredSignature", live.err_name.?);
    // all-or-nothing on error: the account is unmutated.
    try testing.expectEqual(@as(u64, 1000), live.lamports);
    try testing.expectEqualSlices(u8, &vp.VOTE_PROGRAM_ID, &live.owner);
    try testing.expectEqualSlices(u8, &vote_data, live.data);
}

test "STAGE7-EXEC-KAT: InitializeAccountV2 (disc16) — classified KNOWN-GAP; voteforge's gate-off execution rejects" {
    const alloc = testing.allocator;
    const vote_key = [_]u8{0xAA} ** 32;
    const vote_data = [_]u8{0} ** 3762; // uninitialized

    // disc16 payload; feature gates are gate-OFF (default `vi.FeatureFlags{}`)
    // so voteforge's REAL `initializeAccountV2` rejects here via its own
    // feature check. The load-bearing assertion is the classifier routing
    // disc16 to KNOWN-GAP (see `vi.isKnownGapDiscriminant`'s own doc).
    var ix_data: [4 + 32 + 32 + 48 + 96 + 32 + 2 + 2]u8 = undefined;
    std.mem.writeInt(u32, ix_data[0..4], 16, .little);
    @memset(ix_data[4..], 0);

    try testing.expect(vi.isKnownGapDiscriminant(16));

    const live = try execVoteforge(alloc, vote_key, &vote_data, 100_000_000, true, &ix_data);
    defer alloc.free(live.data);
    try testing.expect(live.err_name != null);
}
