//! Vexor BPF2 — M9: ZkElGamalProof native builtin program.
//!
//! ── Spec source ─────────────────────────────────────────────────────────── @prov:zksdk.module-map
//!   Proof verification math = the byte-faithful Zig port under src/vex_bpf2/zksdk/,
//!   Gap-A validated vs real proof vectors (zksdk/gap_a_kat_test.zig).
//!
//! ── Instruction enum (tag = u8 — single-byte ProofInstruction) ────────────
//!     0  CloseContextState                              1  VerifyZeroCiphertext
//!     2  VerifyCiphertextCiphertextEquality             3  VerifyCiphertextCommitmentEquality
//!     4  VerifyPubkeyValidity                           5  VerifyPercentageWithCap
//!     6  VerifyBatchedRangeProofU64                     7  VerifyBatchedRangeProofU128
//!     8  VerifyBatchedRangeProofU256                    9  VerifyGroupedCiphertext2HandlesValidity
//!    10  VerifyBatchedGroupedCiphertext2HandlesValidity 11 VerifyGroupedCiphertext3HandlesValidity
//!    12  VerifyBatchedGroupedCiphertext3HandlesValidity
//!
//! Each Verify* reads its proof EITHER from ix_data[1..] (data-mode) OR from an
//! account at the u32-LE offset in ix_data[1..5] (account-mode, ix_data.len==5).
//! If >= accessed+2 instruction accounts are present, a ProofContextState account
//! is created (authority‖TYPE‖context).
//!
//! ── DARK LAUNCH ───────────────────────────────────────────────────────────
//! `HANDLER_ENABLED` defaults FALSE: execute() preserves the EXACT prior stub
//! behaviour (charge 100 CU, return VariantPending) so deploying this binary is a
//! behavioural NO-OP vs the currently-voting binary (which already diverges from
//! Agave on zk txs — the latent exposure we are closing). The real verifier
//! (`executeReal`) is ALWAYS COMPILED and is exercised by the Harness e2e tests, so
//! "tests pass" validates the real code even while the deployed binary is dark.
//!
//! FLIP-BLOCKERS (must all land before setting HANDLER_ENABLED=true — see plan doc):
//!   1. Harness e2e test (zk_elgamal_e2e_test.zig) green for ALL paths
//!      (data-mode, account-mode, context-state create, close, corrupt, OutOfCompute).
//!   2. Feature gate `disable_zk_elgamal_proof_program` / `reenable_zk_elgamal_proof_program`
//!      wired through v2_dispatch as a threaded bool (the sha512_syscall_active pattern;
//!      the in-ctx feature_active hook is dead/null) AND the live testnet activation state
//!      of those two feature accounts checked — flipping with the gate unwired matches
//!      today's cluster but silently diverges the moment `disable` activates.
//!   3. M9_* error -> on-chain InstructionError mapping verified byte-faithful (a failed
//!      zk tx commits its InstructionError into the block; wrong code => bank_hash divergence).
//!
//! ── SIMD ──────────────────────────────────────────────────────────────────
//!   • SIMD-0153 (Token-22 confidential transfers) — ACTIVE; relies on these proofs.

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const InvokeContext = ic.InvokeContext;
const Pubkey32 = ic.Pubkey32;
const mod = @import("mod.zig");
const trace = mod.trace;
const SYSTEM_PROGRAM_ID = mod.SYSTEM_PROGRAM_ID;
const ZK_ELGAMAL_PROOF_PROGRAM_ID = mod.ZK_ELGAMAL_PROOF_PROGRAM_ID;

const zksdk = @import("../zksdk/zksdk.zig");
const zkt = @import("../zksdk/zk_elgamal_types.zig");
const ProofType = zkt.ProofType;

/// HANDLER ENABLED (2026-06-19 flip). The latent divergence is now FIXED on the live path:
/// the zk-elgamal builtin verifies proofs + writes ProofContextState instead of silent-no-op.
///
/// Flip-blockers cleared:
///   • B (error mapping) DISSOLVED: bank_hash = SHA256(prev || sig_count || poh) + accounts_lt_hash
///     (bank.zig:826/869). It contains NO tx error code and NO CU consumed, so a FAILED zk tx
///     contributes only its fee deduction to the delta — identical to Agave's failure regardless of
///     the specific InstructionError. "Any error => tx fails => fee-only rollback" is byte-faithful.
///   • C (feature gate) DISSOLVED: disable_zk_elgamal_proof_program AND reenable_* are BOTH active
///     (340508256 / 406604256) and features are monotonic => `disabled = disable && !reenable` is
///     permanently false => permanently ENABLED => "always verify" matches Agave forever.
///   • Direction confirmed ENABLED via read-only RPC (Check 1).
/// Revert = set false + rebuild (the dispatch branch becomes comptime-dead again).
/// Residual: the live dispatch->v2DispatchInternal->commitV2Mutations integration for zk is new
/// (commit path itself is live-proven for V3 ELFs); validated by Gap-A + e2e + at-tip no-regression.
pub const HANDLER_ENABLED: bool = true;

/// Dark-path per-instruction charge — preserved EXACTLY as the prior stub so the dark
/// deploy matches the currently-voting binary. The REAL path (executeReal) does NOT charge
/// this (Agave declare_process_instruction default CU = 0; each arm charges its canonical
/// value only — keeping +100 would make every zk tx cost e.g. 6100 not 6000 => CU divergence).
pub const COMPUTE_UNITS: u64 = 100;

pub const Error = error{
    M9_ZkElGamalProof_OutOfCompute,
    M9_ZkElGamalProof_NoActiveFrame,
    M9_ZkElGamalProof_InvalidInstructionData,
    M9_ZkElGamalProof_UnknownInstructionTag,
    // real-handler account/state errors (mirror Agave InstructionError variants)
    M9_ZkElGamalProof_NotEnoughAccounts,
    M9_ZkElGamalProof_AccountIndexOutOfBounds,
    M9_ZkElGamalProof_InvalidAccountData,
    M9_ZkElGamalProof_InvalidAccountOwner,
    M9_ZkElGamalProof_AccountAlreadyInitialized,
    M9_ZkElGamalProof_AccountNotWritable,
    M9_ZkElGamalProof_MissingRequiredSignature,
    M9_ZkElGamalProof_UninitializedAccount,
    M9_ZkElGamalProof_ProofVerificationFailed,
    M9_ZkElGamalProof_OutOfMemory,
    // dark-path stubs (returned only while HANDLER_ENABLED=false)
    M9_ZkElGamalProof_VariantPending_CloseContextState,
    M9_ZkElGamalProof_VariantPending_VerifyZeroCiphertext,
    M9_ZkElGamalProof_VariantPending_VerifyCiphertextCiphertextEquality,
    M9_ZkElGamalProof_VariantPending_VerifyCiphertextCommitmentEquality,
    M9_ZkElGamalProof_VariantPending_VerifyPubkeyValidity,
    M9_ZkElGamalProof_VariantPending_VerifyPercentageWithCap,
    M9_ZkElGamalProof_VariantPending_VerifyBatchedRangeProofU64,
    M9_ZkElGamalProof_VariantPending_VerifyBatchedRangeProofU128,
    M9_ZkElGamalProof_VariantPending_VerifyBatchedRangeProofU256,
    M9_ZkElGamalProof_VariantPending_VerifyGroupedCiphertext2HandlesValidity,
    M9_ZkElGamalProof_VariantPending_VerifyBatchedGroupedCiphertext2HandlesValidity,
    M9_ZkElGamalProof_VariantPending_VerifyGroupedCiphertext3HandlesValidity,
    M9_ZkElGamalProof_VariantPending_VerifyBatchedGroupedCiphertext3HandlesValidity,
};

// ── ProofContextState account layout (Pod, byte-faithful). @prov:zksdk.module-map ──
// extern structs, all u8-aligned => no padding. ProofType is enum(u8) (non-exhaustive).

pub const ProofContextStateMeta = extern struct {
    context_state_authority: Pubkey32,
    proof_type: ProofType,
};
comptime {
    if (@sizeOf(ProofContextStateMeta) != 33) @compileError("ProofContextStateMeta must be 33 bytes (no padding)");
}

pub fn ProofContextState(comptime Ctx: type) type {
    return extern struct {
        context_state_authority: Pubkey32,
        proof_type: ProofType,
        context: [Ctx.BYTE_LEN]u8,
    };
}

/// Raw Pod read of the 33-byte meta (bytemuck try_from_bytes equiv). Caller bounds-checks len.
fn readMeta(data: []const u8) ProofContextStateMeta {
    var m: ProofContextStateMeta = undefined;
    @memcpy(std.mem.asBytes(&m), data[0..@sizeOf(ProofContextStateMeta)]);
    return m;
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub fn execute(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    if (HANDLER_ENABLED) return executeReal(ctx, ix_data);

    // ── DARK: byte-for-byte the prior stub (no-op vs deployed binary) ──
    ctx.consumeCompute(COMPUTE_UNITS) catch return error.M9_ZkElGamalProof_OutOfCompute;
    if (ctx.currentFrame() == null) return error.M9_ZkElGamalProof_NoActiveFrame;
    if (ix_data.len < 1) return error.M9_ZkElGamalProof_InvalidInstructionData;
    return switch (ix_data[0]) {
        0 => error.M9_ZkElGamalProof_VariantPending_CloseContextState,
        1 => error.M9_ZkElGamalProof_VariantPending_VerifyZeroCiphertext,
        2 => error.M9_ZkElGamalProof_VariantPending_VerifyCiphertextCiphertextEquality,
        3 => error.M9_ZkElGamalProof_VariantPending_VerifyCiphertextCommitmentEquality,
        4 => error.M9_ZkElGamalProof_VariantPending_VerifyPubkeyValidity,
        5 => error.M9_ZkElGamalProof_VariantPending_VerifyPercentageWithCap,
        6 => error.M9_ZkElGamalProof_VariantPending_VerifyBatchedRangeProofU64,
        7 => error.M9_ZkElGamalProof_VariantPending_VerifyBatchedRangeProofU128,
        8 => error.M9_ZkElGamalProof_VariantPending_VerifyBatchedRangeProofU256,
        9 => error.M9_ZkElGamalProof_VariantPending_VerifyGroupedCiphertext2HandlesValidity,
        10 => error.M9_ZkElGamalProof_VariantPending_VerifyBatchedGroupedCiphertext2HandlesValidity,
        11 => error.M9_ZkElGamalProof_VariantPending_VerifyGroupedCiphertext3HandlesValidity,
        12 => error.M9_ZkElGamalProof_VariantPending_VerifyBatchedGroupedCiphertext3HandlesValidity,
        else => error.M9_ZkElGamalProof_UnknownInstructionTag,
    };
}

/// The real verifier (flip target). ALWAYS COMPILED; exercised by Harness e2e tests.
pub fn executeReal(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    if (ctx.currentFrame() == null) return error.M9_ZkElGamalProof_NoActiveFrame;
    if (ix_data.len < 1) return error.M9_ZkElGamalProof_InvalidInstructionData;
    const tag = ix_data[0];
    trace("M9.zk_elgamal_proof.executeReal (tag={d})", .{tag});

    // NB: feature gate (disable/reenable_zk_elgamal_proof_program) is a FLIP-BLOCKER, not
    // wired here — see header. The program is currently ENABLED on the cluster.

    switch (tag) {
        0 => {
            ctx.consumeCompute(zkt.CLOSE_CONTEXT_STATE_COMPUTE_UNITS) catch return error.M9_ZkElGamalProof_OutOfCompute;
            return processCloseContextState(ctx);
        },
        1 => return verifyArm(ctx, ix_data, zksdk.ZeroCiphertextData, zkt.VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS),
        2 => return verifyArm(ctx, ix_data, zksdk.CiphertextCiphertextData, zkt.VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS),
        3 => return verifyArm(ctx, ix_data, zksdk.CiphertextCommitmentData, zkt.VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS),
        4 => return verifyArm(ctx, ix_data, zksdk.PubkeyProofData, zkt.VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS),
        5 => return verifyArm(ctx, ix_data, zksdk.PercentageWithCapData, zkt.VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS),
        6 => return verifyArm(ctx, ix_data, zksdk.RangeProofU64Data, zkt.VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS),
        7 => return verifyArm(ctx, ix_data, zksdk.RangeProofU128Data, zkt.VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS),
        8 => return verifyArm(ctx, ix_data, zksdk.RangeProofU256Data, zkt.VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS),
        9 => return verifyArm(ctx, ix_data, zksdk.GroupedCiphertext2HandlesData, zkt.VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS),
        10 => return verifyArm(ctx, ix_data, zksdk.BatchedGroupedCiphertext2HandlesData, zkt.VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS),
        11 => return verifyArm(ctx, ix_data, zksdk.GroupedCiphertext3HandlesData, zkt.VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS),
        12 => return verifyArm(ctx, ix_data, zksdk.BatchedGroupedCiphertext3HandlesData, zkt.VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS),
        else => return error.M9_ZkElGamalProof_InvalidInstructionData, // intToEnum-fail => InvalidInstructionData
    }
}

fn verifyArm(ctx: *InvokeContext, ix_data: []const u8, comptime Data: type, cu: u64) Error!void {
    ctx.consumeCompute(cu) catch return error.M9_ZkElGamalProof_OutOfCompute;
    return processVerifyProof(ctx, ix_data, Data);
}

fn accountAtFrame(ctx: *InvokeContext, pos: usize) Error!*ic.AccountView {
    const frame = ctx.currentFrame() orelse return error.M9_ZkElGamalProof_NoActiveFrame;
    if (pos >= frame.account_indices.len) return error.M9_ZkElGamalProof_NotEnoughAccounts;
    const idx = frame.account_indices[pos];
    if (idx >= ctx.tx.accounts.len) return error.M9_ZkElGamalProof_AccountIndexOutOfBounds;
    return &ctx.tx.accounts[idx];
}

fn processVerifyProof(ctx: *InvokeContext, ix_data: []const u8, comptime Data: type) Error!void {
    var accessed_accounts: usize = 0;

    // Parse + verify the proof; capture its context bytes.
    const context_bytes: [Data.Context.BYTE_LEN]u8 = blk: {
        if (ix_data.len == 5) {
            // account-mode: proof lives in an account at u32-LE offset ix_data[1..5].
            const acct = try accountAtFrame(ctx, accessed_accounts);
            accessed_accounts += 1;
            const data_len = acct.data.len;
            const start: u32 = std.mem.readInt(u32, ix_data[1..][0..4], .little);
            const end: u64 = @as(u64, start) + Data.BYTE_LEN;
            if (start >= data_len) return error.M9_ZkElGamalProof_InvalidAccountData;
            if (end > data_len) return error.M9_ZkElGamalProof_InvalidAccountData;
            const slice = acct.data[start..@intCast(end)];
            const data = Data.fromBytes(slice) catch return error.M9_ZkElGamalProof_InvalidInstructionData;
            data.verify() catch return error.M9_ZkElGamalProof_ProofVerificationFailed;
            break :blk data.context.toBytes();
        } else {
            // data-mode: proof in ix_data[1..].
            const data = Data.fromBytes(ix_data[1..]) catch return error.M9_ZkElGamalProof_InvalidInstructionData;
            data.verify() catch return error.M9_ZkElGamalProof_ProofVerificationFailed;
            break :blk data.context.toBytes();
        }
    };

    // Create the ProofContextState account iff >= accessed+2 instruction accounts present.
    const frame = ctx.currentFrame().?;
    if (frame.account_indices.len >= accessed_accounts + 2) {
        // authority: READ-ONLY key, no signer check (matches Agave create path).
        const authority_key = (try accountAtFrame(ctx, accessed_accounts + 1)).pubkey;

        const proof_ctx = try accountAtFrame(ctx, accessed_accounts);
        if (!std.mem.eql(u8, &proof_ctx.owner, &ZK_ELGAMAL_PROOF_PROGRAM_ID))
            return error.M9_ZkElGamalProof_InvalidAccountOwner;
        if (proof_ctx.data.len < @sizeOf(ProofContextStateMeta))
            return error.M9_ZkElGamalProof_InvalidAccountData;
        if (readMeta(proof_ctx.data).proof_type != .uninitialized)
            return error.M9_ZkElGamalProof_AccountAlreadyInitialized;

        const State = ProofContextState(Data.Context);
        var state: State = .{
            .context_state_authority = authority_key,
            .proof_type = Data.TYPE,
            .context = context_bytes,
        };
        if (proof_ctx.data.len != @sizeOf(State))
            return error.M9_ZkElGamalProof_InvalidAccountData;
        if (!proof_ctx.is_writable)
            return error.M9_ZkElGamalProof_AccountNotWritable;
        // in-place overwrite (account is pre-sized exactly; do NOT realloc).
        @memcpy(proof_ctx.data, std.mem.asBytes(&state));
    }
}

fn processCloseContextState(ctx: *InvokeContext) Error!void {
    // Mirror Agave check order: owner(2) signer -> ctx(0) -> dest(1) -> ctx!=dest -> owner==id
    // -> meta initialized -> meta.authority==owner -> move lamports -> zero data -> set system owner.
    const owner_acct = try accountAtFrame(ctx, 2);
    if (!owner_acct.is_signer) return error.M9_ZkElGamalProof_MissingRequiredSignature;
    const owner_key = owner_acct.pubkey;

    const proof_ctx = try accountAtFrame(ctx, 0);
    const dest = try accountAtFrame(ctx, 1);
    if (std.mem.eql(u8, &proof_ctx.pubkey, &dest.pubkey))
        return error.M9_ZkElGamalProof_InvalidInstructionData;

    if (!std.mem.eql(u8, &proof_ctx.owner, &ZK_ELGAMAL_PROOF_PROGRAM_ID))
        return error.M9_ZkElGamalProof_InvalidAccountOwner;
    if (proof_ctx.data.len < @sizeOf(ProofContextStateMeta))
        return error.M9_ZkElGamalProof_InvalidAccountData;
    const meta = readMeta(proof_ctx.data);
    if (meta.proof_type == .uninitialized)
        return error.M9_ZkElGamalProof_UninitializedAccount;
    if (!std.mem.eql(u8, &meta.context_state_authority, &owner_key))
        return error.M9_ZkElGamalProof_InvalidAccountOwner;

    if (!proof_ctx.is_writable or !dest.is_writable)
        return error.M9_ZkElGamalProof_AccountNotWritable;

    // move all lamports ctx -> dest (sum preserved => per-instr lamport invariant holds).
    dest.lamports = std.math.add(u64, dest.lamports, proof_ctx.lamports) catch
        return error.M9_ZkElGamalProof_InvalidInstructionData;
    proof_ctx.lamports = 0;
    // shrink data to 0 (mirror system_program resize idiom: alloc+assign).
    proof_ctx.data = ctx.allocator.alloc(u8, 0) catch return error.M9_ZkElGamalProof_OutOfMemory;
    proof_ctx.owner = SYSTEM_PROGRAM_ID;
}

pub fn selfTest() bool {
    return COMPUTE_UNITS == 100;
}

// ── execute() dispatch tests (HANDLER_ENABLED=true => execute() routes to executeReal).
// The full account-mode/data-mode/context-state/close/corrupt coverage lives in the Harness
// e2e KAT (zk_elgamal_e2e_test.zig); these guard the execute() entry + error edges.

const Harness = @import("test_harness.zig").Harness;

test "M9 zk_elgamal: no active frame rejected" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    // no pushFrame => executeReal's currentFrame()==null guard fires first.
    try t.expectError(error.M9_ZkElGamalProof_NoActiveFrame, execute(h.ctx, &[_]u8{1}));
}

test "M9 zk_elgamal: empty data rejected (InvalidInstructionData)" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    try t.expectError(error.M9_ZkElGamalProof_InvalidInstructionData, execute(h.ctx, &.{}));
}

test "M9 zk_elgamal: unknown tag => InvalidInstructionData (intToEnum-fail)" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    try t.expectError(error.M9_ZkElGamalProof_InvalidInstructionData, execute(h.ctx, &[_]u8{99}));
}

test "M9 zk_elgamal: CloseContextState without accounts => NotEnoughAccounts" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    try t.expectError(error.M9_ZkElGamalProof_NotEnoughAccounts, execute(h.ctx, &[_]u8{0}));
}

test "M9 zk_elgamal: OutOfCompute when meter below arm cost" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 50, &.{}); // < 2600 (pubkey-validity)
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    try t.expectError(error.M9_ZkElGamalProof_OutOfCompute, execute(h.ctx, &[_]u8{4}));
}
