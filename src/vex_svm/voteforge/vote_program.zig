//! VOTEFORGE Stage 4 — instruction dispatch glue / FRONT DOOR
//! (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 4, §F.1 layer 4).
//!
//! [FD] `fd_vote_program.c:1655-1699` (`fd_vote_program_execute`) is the
//! canonical shape this file mirrors: borrow account 0, check its owner ==
//! the vote program id (`InvalidAccountOwner` else — `:1658-1661`), collect
//! signers, THEN one stack-allocated instruction-struct deserialize
//! (`fd_vote_instruction_deserialize` into `fd_vote_instruction_t
//! instruction[1]`, a fixed local, `:1696-1699`) BEFORE the discriminant
//! switch — not a per-arm incremental parse. This file's `dispatch()`
//! follows the same shape, adapted to what's actually cheap to do zero-alloc
//! in Zig: a 4-byte discriminant PEEK (no allocation, no struct materialized)
//! classifies Stage-3-routed vs Stage-5-delegate BEFORE paying for
//! `vote_instructions.parseInstruction`'s full decode — Stage-5 (TowerSync
//! family) instructions never allocate here at all, and never touch the
//! (Stage-3-only) `ArgReader` machinery.
//!
//! [agave] `vote_processor.rs:60-74` — account-0 owner check precedes target-
//! version resolution, which precedes the discriminant match. Per
//! `vote_instructions.zig`'s own header note, Agave 4.2 has exactly ONE
//! target version (V4, hardcoded, `handler.rs:35-38`) — this file carries no
//! `target_version` field or branch; that's not an omission, it's the
//! ground-truth correction already established at Stage 3.
//!
//! Per the scope doc: "Should be thin by construction (all real logic lives
//! in Stage 1-3's layers)... a literal, auditable mirror of
//! `vote_processor.rs:131-409`'s match arms." This file owns exactly THREE
//! things: (1) the account-0 owner check every arm needs upfront (agave
//! `vote_processor.rs:64-67`), (2) discriminant classification (Stage-3-
//! routed / Stage-5-delegate / unrecognized-delegate), (3) the single call-
//! out to `vote_instructions.execute` for routed families. It does NOT
//! implement TowerSync itself (Stage 5) — for those discriminants (and any
//! discriminant this rewrite does not yet recognize), `dispatch()` returns
//! `.delegate`, signaling the caller to log/count the discriminant. In
//! practice Stage 5 has landed (every discriminant 0-19 is handled directly),
//! so `.delegate` is a defensive path the live seam
//! (`instruction_dispatch.executeVoteViaVoteforge`) treats as a decode error.
//!
//! Layering (per scope doc §F.1, matching `vote_instructions.zig`'s own
//! discipline): imports ONLY `account_io.zig` (Stage 2) and
//! `vote_instructions.zig` (Stage 3) — zero import of `sigvote`, zero import
//! of anything outside `voteforge/`. `VOTE_PROGRAM_ID` below is therefore an
//! independently-declared byte-identical COPY of `native/vote_program.zig`'s
//! constant of the same name, not an import of it — `kat_vote_program.zig`
//! pins the two equal directly (a decode/id divergence between the live
//! native path and this front door would otherwise be invisible until an
//! actual mismatch on live traffic).
//!
//! **Decode-perf note** (scope doc deliverable): the discriminant peek below
//! is a single `readInt` off the caller's existing `ix_data` slice — no
//! allocation, no copy, no struct materialization. The ONLY allocation this
//! file ever causes is `vote_instructions.parseInstruction`'s own (Stage 3,
//! already gated to `.stage3`-classified discriminants only, and even then
//! only the two `*_with_seed` families' variable-length seed actually heap-
//! allocates — every other Stage-3 payload is fixed-size and copied straight
//! off the stack-parsed `ArgReader`). Concretely: for the 8 Stage-5
//! discriminants (~90%+ of live vote-ix volume, since `Vote`/`TowerSync` are
//! the traffic-dominant families), `dispatch()` performs ONE stack read and
//! ZERO heap traffic before returning `.delegate` — the FD-cited "stack-
//! allocated, fixed-size" lever applies maximally to exactly the instructions
//! that dominate the live wire.

const std = @import("std");
const aio = @import("account_io.zig");
const vi = @import("vote_instructions.zig");

/// [agave]/[FD]/[native] `Vote111111111111111111111111111111111111111`,
/// byte-identical to `native/vote_program.zig:32` (independently declared,
/// not imported — see file header). `kat_vote_program.zig` pins equality.
pub const VOTE_PROGRAM_ID: [32]u8 = .{
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
    0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
    0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
};

pub const DispatchError = vi.InstrError;

/// Which leg of the front door a discriminant resolves to.
pub const RouteClass = enum {
    /// One of Stage 3's 12 fully-ported discriminants (0,1,3,4,5,7,10,11,
    /// 16,17,18,19 — see `vote_instructions.isStage3Discriminant`).
    stage3,
    /// Vote/VoteSwitch/UpdateVoteState(+Switch)/CompactUpdateVoteState
    /// (+Switch)/TowerSync(+Switch) — discriminants 2,6,8,9,12,13,14,15.
    /// Stage 5 has landed: these are now executed directly by voteforge, so
    /// this class is retained only for API/partition stability.
    stage5,
    /// Any discriminant outside the known 0-19 table. A conforming client
    /// never emits one today (`VoteInstruction` has exactly 20 variants),
    /// but the front door must classify it (never panic) — treated the same
    /// as `.stage5` by every caller: delegate, don't execute.
    unrecognized,
};

/// [agave] `solana-vote-interface-6.0.0/src/instruction.rs:35-239` — the
/// full 20-variant discriminant table, partitioned exactly as
/// `vote_instructions.zig`'s own `isStage3Discriminant`/`isStage5Discriminant`
/// already declare it (this function does not duplicate that partition, it
/// composes it — a single source of truth for which 12/8 discriminants are
/// which, see that file's own citation).
pub fn classify(disc: u32) RouteClass {
    if (vi.isStage3Discriminant(disc)) return .stage3;
    if (vi.isStage5Discriminant(disc)) return .stage5;
    return .unrecognized;
}

/// Zero-alloc discriminant peek. [agave] the first 4 bytes of the bincode
/// instruction blob are ALWAYS the LE u32 enum tag (`VoteInstruction`'s
/// declaration-order variant index — see `vote_instructions.zig`'s decoder
/// header for the full bincode-enum-tag citation). Does not validate or
/// consume the rest of the payload; `.stage3`-classified discriminants get a
/// second, full pass via `vote_instructions.parseInstruction` inside
/// `dispatch()` below — this function exists so `.stage5`/`.unrecognized`
/// discriminants never pay for that second pass at all.
pub fn peekDiscriminant(data: []const u8) DispatchError!u32 {
    if (data.len < 4) return error.InvalidInstructionData;
    return std.mem.readInt(u32, data[0..4], .little);
}

pub const DelegateInfo = struct { disc: u32, class: RouteClass };

pub const DispatchResult = union(enum) {
    /// Stage-3 family: fully executed against `table`. `void` on success,
    /// otherwise the escaping `InstrError` (including `error.Custom`, whose
    /// `VoteError` sub-code is staged in `ctx.custom_error` exactly as
    /// `vote_instructions.execute` already documents — this file adds no
    /// second error-code channel).
    handled: DispatchError!void,
    /// Stage-5 family or an unrecognized discriminant: NOT executed here.
    /// Carries the raw discriminant + `RouteClass` so a caller can log/count
    /// which case it was. Since Stage 5 landed this path is not reached on
    /// well-formed input; the live seam treats it as a decode error.
    delegate: DelegateInfo,
};

/// THE front door. [agave]/[FD] account-0 owner check FIRST (`vote_processor.
/// rs:64-67`, `fd_vote_program.c:1658-1661`) — a malformed/foreign-owned
/// account 0 must never reach the discriminant switch. `table.records[0]` is
/// always the vote account by construction: every call site here and in
/// Agave/FD alike treats instruction-account-index 0 as the vote account
/// (matches `vote_instructions.execute`'s own account-index-0 convention,
/// cited per-family in that file).
///
/// `program_id` is caller-supplied rather than defaulted to `VOTE_PROGRAM_ID`
/// above — mirrors `account_io.AccountTable.init`'s own caller-supplied
/// `program_id` (this file never assumes how its caller resolved the id it
/// wants checked against; `kat_vote_program.zig` exercises both the real
/// `VOTE_PROGRAM_ID` and synthetic ids explicitly).
pub fn dispatch(
    alloc: std.mem.Allocator,
    table: *aio.AccountTable,
    program_id: [32]u8,
    ix_data: []const u8,
    signers: []const [32]u8,
    ctx: *vi.ExecContext,
) DispatchError!DispatchResult {
    if (table.records.len == 0) return error.InvalidAccountData;
    if (!std.mem.eql(u8, &table.records[0].owner, &program_id)) return error.InvalidAccountOwner;

    const disc = try peekDiscriminant(ix_data);
    const class = classify(disc);
    switch (class) {
        .stage3 => {
            const parsed = try vi.parseInstruction(alloc, ix_data);
            return .{ .handled = vi.execute(table, parsed, signers, ctx) };
        },
        .stage5, .unrecognized => return .{ .delegate = .{ .disc = disc, .class = class } },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-tests — dispatch-shape correctness independent of any fixture corpus
// (the full decode-corpus + execution KATs live in `kat_vote_program.zig`).
// These pin `classify`/`peekDiscriminant`/the account-0 owner-check ordering
// themselves.
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "classify: every discriminant 0..19 routes to exactly one non-unrecognized class" {
    var i: u32 = 0;
    while (i <= 19) : (i += 1) {
        try testing.expect(classify(i) != .unrecognized);
    }
}

test "classify: discriminant 20+ is unrecognized (never panics)" {
    try testing.expect(classify(20) == .unrecognized);
    try testing.expect(classify(std.math.maxInt(u32)) == .unrecognized);
}

test "peekDiscriminant: truncated data (0-3 bytes) returns InvalidInstructionData, never panics" {
    try testing.expectError(error.InvalidInstructionData, peekDiscriminant(&[_]u8{}));
    try testing.expectError(error.InvalidInstructionData, peekDiscriminant(&[_]u8{1}));
    try testing.expectError(error.InvalidInstructionData, peekDiscriminant(&[_]u8{ 1, 2 }));
    try testing.expectError(error.InvalidInstructionData, peekDiscriminant(&[_]u8{ 1, 2, 3 }));
}

test "peekDiscriminant: exactly 4 bytes decodes, ignores nothing beyond" {
    const d = try peekDiscriminant(&[_]u8{ 7, 0, 0, 0 });
    try testing.expectEqual(@as(u32, 7), d);
}

fn testTable(owner: [32]u8, data: []u8) struct { metas: [1]aio.AccountMeta, records: [1]aio.AccountRecord } {
    return .{
        .metas = [_]aio.AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = false, .is_writable = true }},
        .records = [_]aio.AccountRecord{.{ .pubkey = [_]u8{1} ** 32, .lamports = 100_000_000, .owner = owner, .executable = false, .rent_epoch = 0, .data = data }},
    };
}

fn defaultCtx() vi.ExecContext {
    return .{
        .slot = 1000,
        .epoch = 10,
        .leader_schedule_epoch = 10,
        .epoch_schedule = .{ .slots_per_epoch = 432_000, .leader_schedule_slot_offset = 432_000, .warmup = false, .first_normal_epoch = 0, .first_normal_slot = 0 },
        .features = .{},
    };
}

test "dispatch: account-0 owner mismatch rejected BEFORE any discriminant decode (malformed ix data would otherwise also error, so this proves ORDER)" {
    const alloc = testing.allocator;
    var data = [_]u8{0} ** 3762;
    const wrong_owner = [_]u8{0xEE} ** 32;
    var fx = testTable(wrong_owner, &data);
    var table = try aio.AccountTable.init(VOTE_PROGRAM_ID, &fx.metas, &fx.records);
    var ctx = defaultCtx();
    // Deliberately empty ix_data (would ALSO fail decode) — if the owner
    // check ran after decode, this would surface InvalidInstructionData
    // instead; asserting InvalidAccountOwner proves the owner check is first.
    try testing.expectError(error.InvalidAccountOwner, dispatch(alloc, &table, VOTE_PROGRAM_ID, &[_]u8{}, &[_][32]u8{}, &ctx));
}

test "dispatch: real VOTE_PROGRAM_ID accepted, matches native/vote_program.zig's constant" {
    const alloc = testing.allocator;
    var data = [_]u8{0} ** 3762;
    var fx = testTable(VOTE_PROGRAM_ID, &data);
    var table = try aio.AccountTable.init(VOTE_PROGRAM_ID, &fx.metas, &fx.records);
    var ctx = defaultCtx();
    var ix_data: [4]u8 = undefined;
    std.mem.writeInt(u32, &ix_data, 4, .little); // update_validator_identity — needs 2 accounts, expect MissingAccount not InvalidAccountOwner
    // The owner check + discriminant classify both succeed (that's what this
    // test pins) — the OUTER `DispatchError!DispatchResult` is therefore Ok,
    // wrapping a `.handled` whose INNER `DispatchError!void` carries the
    // MissingAccount from the real dispatch (account index 1 doesn't exist).
    const result = try dispatch(alloc, &table, VOTE_PROGRAM_ID, &ix_data, &[_][32]u8{}, &ctx);
    switch (result) {
        .handled => |h| try testing.expectError(error.MissingAccount, h),
        .delegate => return error.TestUnexpectedResult,
    }
}

test "dispatch: Stage-3 discriminant (Withdraw, disc3) with malformed (truncated) payload returns InvalidInstructionData, not a crash" {
    const alloc = testing.allocator;
    var data = [_]u8{0} ** 3762;
    var fx = testTable(VOTE_PROGRAM_ID, &data);
    var table = try aio.AccountTable.init(VOTE_PROGRAM_ID, &fx.metas, &fx.records);
    var ctx = defaultCtx();
    var ix_data: [6]u8 = undefined; // disc(4) + only 2 of the required 8 lamports bytes
    std.mem.writeInt(u32, ix_data[0..4], 3, .little);
    try testing.expectError(error.InvalidInstructionData, dispatch(alloc, &table, VOTE_PROGRAM_ID, &ix_data, &[_][32]u8{}, &ctx));
}

test "dispatch: Stage-3 discriminant with oversized (trailing-garbage) payload still decodes correctly (extra bytes ignored, mirrors bincode's own prefix-read convention)" {
    const alloc = testing.allocator;
    var data = [_]u8{0} ** 3762;
    var fx = testTable(VOTE_PROGRAM_ID, &data);
    var table = try aio.AccountTable.init(VOTE_PROGRAM_ID, &fx.metas, &fx.records);
    var ctx = defaultCtx();
    // UpdateValidatorIdentity (disc4) has NO payload beyond the 4-byte tag —
    // 60 bytes of trailing garbage must be silently ignored, not misread as
    // part of the (nonexistent) args.
    var ix_data: [64]u8 = [_]u8{0xAB} ** 64;
    std.mem.writeInt(u32, ix_data[0..4], 4, .little);
    const result = try dispatch(alloc, &table, VOTE_PROGRAM_ID, &ix_data, &[_][32]u8{}, &ctx);
    // update_validator_identity needs a second account (index 1, the new
    // identity), which this 1-account table doesn't have — MissingAccount
    // proves the oversized payload decoded fine and reached real dispatch
    // (not an InvalidInstructionData from the trailing garbage).
    switch (result) {
        .handled => |h| try testing.expectError(error.MissingAccount, h),
        .delegate => return error.TestUnexpectedResult,
    }
}

test "dispatch: unknown discriminant (20) delegates, never attempts a decode" {
    const alloc = testing.allocator;
    var data = [_]u8{0} ** 3762;
    var fx = testTable(VOTE_PROGRAM_ID, &data);
    var table = try aio.AccountTable.init(VOTE_PROGRAM_ID, &fx.metas, &fx.records);
    var ctx = defaultCtx();
    var ix_data: [4]u8 = undefined;
    std.mem.writeInt(u32, &ix_data, 20, .little);
    const result = try dispatch(alloc, &table, VOTE_PROGRAM_ID, &ix_data, &[_][32]u8{}, &ctx);
    switch (result) {
        .delegate => |d| {
            try testing.expectEqual(@as(u32, 20), d.disc);
            try testing.expect(d.class == .unrecognized);
        },
        .handled => return error.TestUnexpectedResult,
    }
}

test "dispatch: TowerSync (disc14) is real-executed now (Stage 5 landed) — a truncated payload surfaces InvalidInstructionData via .handled, never .delegate" {
    const alloc = testing.allocator;
    var data = [_]u8{0} ** 3762;
    var fx = testTable(VOTE_PROGRAM_ID, &data);
    var table = try aio.AccountTable.init(VOTE_PROGRAM_ID, &fx.metas, &fx.records);
    var ctx = defaultCtx();
    // A discriminant-only payload (no lockout body) proves dispatch() now
    // routes disc14 all the way into vi.parseInstruction/execute — Stage 4's
    // own RouteClass.stage5 leg is unreachable for disc14 post-Stage-5 (see
    // vote_instructions.zig's isStage5Discriminant/isStage3Discriminant).
    // parseInstruction's own decode failure escapes dispatch() at the OUTER
    // level (same shape as the pre-existing Withdraw-truncated-payload self-
    // test above) — never reaches a `.handled` value to switch on.
    var ix_data: [4]u8 = undefined;
    std.mem.writeInt(u32, &ix_data, 14, .little);
    try testing.expectError(error.InvalidInstructionData, dispatch(alloc, &table, VOTE_PROGRAM_ID, &ix_data, &[_][32]u8{}, &ctx));
}

test "dispatch: Stage-3 discriminant (Authorize, disc1) with valid payload executes and mutates the account" {
    const alloc = testing.allocator;
    var s: vi_codec_VoteStateV4 = std.mem.zeroes(vi_codec_VoteStateV4);
    s.node_pubkey = [_]u8{1} ** 32;
    s.authorized_withdrawer = [_]u8{2} ** 32;
    s.inflation_rewards_collector = [_]u8{0xAA} ** 32;
    s.block_revenue_collector = s.node_pubkey;
    s.block_revenue_commission_bps = 10_000;
    s.tail = vi_codec.Tail.EMPTY;
    s.tail.authorized_voters[0] = .{ .epoch = 8, .pubkey = [_]u8{3} ** 32 };
    s.tail.authorized_voters_len = 1;
    var data: [3762]u8 = [_]u8{0} ** 3762;
    _ = try s.serialize(&data);

    const withdrawer = [_]u8{2} ** 32;
    var metas = [_]aio.AccountMeta{
        .{ .pubkey = [_]u8{1} ** 32, .is_signer = false, .is_writable = true },
    };
    var records = [_]aio.AccountRecord{
        .{ .pubkey = [_]u8{1} ** 32, .lamports = 100_000_000, .owner = VOTE_PROGRAM_ID, .executable = false, .rent_epoch = 0, .data = &data },
    };
    var table = try aio.AccountTable.init(VOTE_PROGRAM_ID, &metas, &records);
    var ctx = defaultCtx();

    var ix_data: [40]u8 = undefined;
    std.mem.writeInt(u32, ix_data[0..4], 1, .little); // Authorize
    @memcpy(ix_data[4..36], &[_]u8{4} ** 32);
    std.mem.writeInt(u32, ix_data[36..40], 0, .little); // voter

    const result = try dispatch(alloc, &table, VOTE_PROGRAM_ID, &ix_data, &[_][32]u8{withdrawer}, &ctx);
    switch (result) {
        .handled => |h| try h,
        .delegate => return error.TestUnexpectedResult,
    }
    const post = (try vi_codec.VoteStateV4.parse(&data)).state;
    try testing.expectEqual(@as(usize, 2), post.tail.authorized_voters_len);
}

const vi_codec = @import("vote_codec.zig");
const vi_codec_VoteStateV4 = vi_codec.VoteStateV4;
