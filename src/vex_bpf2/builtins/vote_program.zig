//! Vexor BPF2 — M9: Vote native builtin program.
//!
//! ── Spec source ───────────────────────────────────────────────────────────
//!   • agave-v4.0.0-beta.7: programs/vote/src/vote_processor.rs +
//!     programs/vote/src/vote_state/{mod.rs,vote_state_versions.rs,...}
//!   • sig: src/runtime/program/vote/{execute.zig,instruction.zig,
//!     state.zig,state_v4.zig}
//!   • Vexor V1 reference (DO NOT MUTATE):
//!     src/vex_svm/native/{vote_program.zig,vote_state_serde.zig,
//!     vote_codec.zig,vote_v2.zig}
//!
//! ── Port status (this session) ────────────────────────────────────────────
//! Instruction parser ports the bincode tag set:
//!     0  InitializeAccount(VoteInit)                             pending
//!     1  Authorize(Pubkey, VoteAuthorize)                        pending
//!     2  Vote(Vote)                                              pending
//!     3  Withdraw(u64)                                           pending
//!     4  UpdateValidatorIdentity                                 pending
//!     5  UpdateCommission(u8)                                    pending
//!     6  VoteSwitch(Vote, Hash)                                  pending
//!     7  AuthorizeChecked(VoteAuthorize)                         pending
//!     8  UpdateVoteState(VoteStateUpdate)                        pending
//!     9  UpdateVoteStateSwitch(VoteStateUpdate, Hash)            pending
//!    10  AuthorizeWithSeed                                       pending
//!    11  AuthorizeCheckedWithSeed                                pending
//!    12  CompactUpdateVoteState(VoteStateUpdate)                 pending
//!    13  CompactUpdateVoteStateSwitch(VoteStateUpdate, Hash)     pending
//!    14  TowerSync(TowerSync)                                    pending
//!    15  TowerSyncSwitch(TowerSync, Hash)                        pending
//!    16  InitializeAccountV2(VoteInitV2)                         pending
//!    17  UpdateCommissionBps                                     pending
//!    18  UpdateCommissionCollector                               pending
//!    19  DepositDelegatorRewards                                 pending
//!
//! Every variant currently returns `M9_Vote_VariantPending_*`. The full
//! port (vote_state_versioned + tower-bft mutation logic) is sized at
//! ~5000 LoC porting from sig/state.zig + state_v4.zig and is a
//! multi-session deliverable. Until then, the running validator's vote
//! handler stays on V1's `src/vex_svm/native/vote_program.zig`. The Wave 4
//! wireup at replay_stage.zig swaps to M9 only after a per-instruction
//! parity table proves byte-identical mutation against V1 over a 10k-vote
//! sample. That guard keeps the running validator on the proven path.
//!
//! ── SIMD inventory ────────────────────────────────────────────────────────
//!   • SIMD-0337 (handover markers + DATA_COMPLETE_SHRED placement) — ACTIVE on
//!     testnet since slot 416972256 (epoch 978 boundary). It does NOT touch the
//!     Vote program: it only adds forward-compat Alpenglow handover markers and
//!     shred placement rules — the DATA_COMPLETE rules ARE enforced on the shred
//!     path via Bank.discardUnexpectedDataCompleteEffective (shred.zig /
//!     verify_tile.zig / tvu.zig), gated on the real epoch-delayed activation. The
//!     Vote program is NOT retired by 0337 and correctly stays on the Tower-BFT
//!     path; the full Alpenglow CONSENSUS protocol (which WOULD retire it) is a
//!     SEPARATE, not-yet-activated feature. (No feature_set gate in execute() — the
//!     program just executes; the earlier "reads feature_set to error" note was
//!     aspirational and never implemented.)
//!   • SIMD-0033 (Timely-Vote-Credit) — already active; affects
//!     credit-earning math inside vote_state, not parser or dispatch.
//!   • SIMD-0138 (Legacy-vote handling) — affects backward-compat parsing
//!     for older Vote variants; honoured inside V1 today, ported when the
//!     state machinery lands.
//!
//! ── fix_ledger anchors ────────────────────────────────────────────────────
//!   • vex-058 — vote handlers MUST read EpochSchedule + Clock via
//!     ctx.sysvar_cache; never hardcode 0. Locked when the full port lands.
//!   • vex-039 (executeBpfProgram-owner-bug) — vote account owner is read
//!     from AccountView.owner, never inferred.
//!
//! ── V1 → V2 behaviour delta (when this file replaces V1) ──────────────────
//! Documented inline at each variant when ported. Major risks:
//!   • V1 has shipped quirks (vex-014 vote rewrite, vex-094/095 stake
//!     vote-path, vex-058 epoch-schedule fix) that the V2 port MUST
//!     preserve. Each is gated by a fix_ledger entry; the V2 port's
//!     parity test loads the V1 binary's witness traces to prove the
//!     shipped fix's invariant survives.
//!   • vex-022 SPL Token inline shim is DROPPED (does not affect Vote).

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const InvokeContext = ic.InvokeContext;
const trace = @import("mod.zig").trace;

pub const COMPUTE_UNITS: u64 = 2_100; // agave-3.x DEFAULT_COMPUTE_UNITS for Vote

pub const Error = error{
    M9_Vote_OutOfCompute,
    M9_Vote_NoActiveFrame,
    M9_Vote_InvalidInstructionData,
    M9_Vote_UnknownInstructionTag,
    M9_Vote_VariantPending_InitializeAccount,
    M9_Vote_VariantPending_Authorize,
    M9_Vote_VariantPending_Vote,
    M9_Vote_VariantPending_Withdraw,
    M9_Vote_VariantPending_UpdateValidatorIdentity,
    M9_Vote_VariantPending_UpdateCommission,
    M9_Vote_VariantPending_VoteSwitch,
    M9_Vote_VariantPending_AuthorizeChecked,
    M9_Vote_VariantPending_UpdateVoteState,
    M9_Vote_VariantPending_UpdateVoteStateSwitch,
    M9_Vote_VariantPending_AuthorizeWithSeed,
    M9_Vote_VariantPending_AuthorizeCheckedWithSeed,
    M9_Vote_VariantPending_CompactUpdateVoteState,
    M9_Vote_VariantPending_CompactUpdateVoteStateSwitch,
    M9_Vote_VariantPending_TowerSync,
    M9_Vote_VariantPending_TowerSyncSwitch,
    M9_Vote_VariantPending_InitializeAccountV2,
    M9_Vote_VariantPending_UpdateCommissionBps,
    M9_Vote_VariantPending_UpdateCommissionCollector,
    M9_Vote_VariantPending_DepositDelegatorRewards,
};

pub fn execute(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    ctx.consumeCompute(COMPUTE_UNITS) catch return error.M9_Vote_OutOfCompute;
    if (ctx.currentFrame() == null) return error.M9_Vote_NoActiveFrame;
    if (ix_data.len < 4) return error.M9_Vote_InvalidInstructionData;
    const tag = std.mem.readInt(u32, ix_data[0..4], .little);
    trace("M9.vote.execute (tag={d})", .{tag});

    return switch (tag) {
        0 => error.M9_Vote_VariantPending_InitializeAccount,
        1 => error.M9_Vote_VariantPending_Authorize,
        2 => error.M9_Vote_VariantPending_Vote,
        3 => error.M9_Vote_VariantPending_Withdraw,
        4 => error.M9_Vote_VariantPending_UpdateValidatorIdentity,
        5 => error.M9_Vote_VariantPending_UpdateCommission,
        6 => error.M9_Vote_VariantPending_VoteSwitch,
        7 => error.M9_Vote_VariantPending_AuthorizeChecked,
        8 => error.M9_Vote_VariantPending_UpdateVoteState,
        9 => error.M9_Vote_VariantPending_UpdateVoteStateSwitch,
        10 => error.M9_Vote_VariantPending_AuthorizeWithSeed,
        11 => error.M9_Vote_VariantPending_AuthorizeCheckedWithSeed,
        12 => error.M9_Vote_VariantPending_CompactUpdateVoteState,
        13 => error.M9_Vote_VariantPending_CompactUpdateVoteStateSwitch,
        14 => error.M9_Vote_VariantPending_TowerSync,
        15 => error.M9_Vote_VariantPending_TowerSyncSwitch,
        16 => error.M9_Vote_VariantPending_InitializeAccountV2,
        17 => error.M9_Vote_VariantPending_UpdateCommissionBps,
        18 => error.M9_Vote_VariantPending_UpdateCommissionCollector,
        19 => error.M9_Vote_VariantPending_DepositDelegatorRewards,
        else => error.M9_Vote_UnknownInstructionTag,
    };
}

pub fn selfTest() bool {
    return COMPUTE_UNITS == 2_100;
}

// ── Tests ─────────────────────────────────────────────────────────────────

const Harness = @import("test_harness.zig").Harness;

test "M9 vote: empty data rejected" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    try t.expectError(error.M9_Vote_InvalidInstructionData, execute(h.ctx, &.{}));
}

test "M9 vote: unknown tag rejected" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 99, .little);
    try t.expectError(error.M9_Vote_UnknownInstructionTag, execute(h.ctx, &data));
}

test "M9 vote: known tag dispatches to VariantPending error" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 2, .little); // Vote
    try t.expectError(error.M9_Vote_VariantPending_Vote, execute(h.ctx, &data));
}

test "M9 vote: OutOfCompute when meter short" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100, &.{});
    defer h.deinit();
    try t.expectError(error.M9_Vote_OutOfCompute, execute(h.ctx, &.{}));
}
