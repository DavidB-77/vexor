//! Vexor BPF2 — M9: Feature Gate native builtin (SIMD-0089, Core-BPF migrated).
//!
//! ── Spec source (PRIMARY, read 2026-07-01) ────────────────────────────────
//!   • SIMD-0089 "Programify Feature Gate Program" (feature
//!     4eohviozzEeivk1y9UbrnekbAFMDQyJz5JjA9Y6gyvky) — ACTIVE on testnet.
//!   • Canonical on-chain program: github.com/solana-program/feature-gate
//!       program/src/processor.rs  (process / process_revoke_pending_activation)
//!       program/src/instruction.rs (FeatureGateInstruction::unpack)
//!     + interface crate solana-feature-gate-interface-4.0.0
//!       src/state.rs  (Feature::from_account_info, size_of()==9)
//!       src/error.rs  (FeatureGateError::FeatureAlreadyActivated == Custom(0))
//!       src/instruction.rs (revoke_pending_activation account layout)
//!
//! ── Why a NATIVE handler for a BPF program ─────────────────────────────────
//! Feature Gate migrated native→Core-BPF (SIMD-0089). Vexor has no .so for it,
//! so a tx invoking `Feature111…` fell through to BPF-load, failed, and hit the
//! `[MIGRATED-BUILTIN-SILENT-EAT]` fail-loud guard (replay_stage.zig:6430) —
//! same class as the Config migration carrier (commit 4be6762). This handler
//! reproduces the program's account mutations byte-for-byte so bank_hash tracks
//! the cluster. Registering it in `isBuiltin` routes the tx here and the
//! SILENT-EAT guard goes moot (it only fires on M9_NoFallback /
//! M5_BankBackedBpfNotPlumbed, which no longer occur for this id).
//!
//! ── Behavior (process_revoke_pending_activation, verbatim trace) ───────────
//!   ONE instruction: RevokePendingActivation. Wire = EXACTLY one byte 0x00
//!   (unpack: `input.len() != 1` → InvalidInstructionData; then try_from(tag),
//!   only tag 0 valid → else InvalidInstructionData).
//!
//!   Accounts (3 required — `next_account_info` ×3 → NotEnoughAccountKeys):
//!     [0] feature      (signer, writable)
//!     [1] incinerator  (writable)   ← MUST be `incinerator::id()` — see below
//!     [2] system       (readonly, unused: `_system_program_info`)
//!
//!   Checks (processor order):
//!     1. !feature.is_signer                         → MissingRequiredSignature
//!     2. Feature::from_account_info(feature):
//!          owner != FeatureGate id                  → InvalidAccountOwner
//!          data.len < 9 (Feature::size_of())        → InvalidAccountData
//!          bincode Option<u64> tag (data[0]) > 1    → InvalidAccountData
//!     3. activated_at.is_some() i.e. data[0] == 1   → FeatureAlreadyActivated
//!
//!   Mutations on success (processor: resize → assign → CPI-transfer):
//!     • feature.data → len 0   (resize(0))
//!     • feature.owner → System (assign(system_program::id()))
//!     • feature.lamports → 0    ┐  lamports moved to incinerator via a System
//!     • incinerator.lamports += ┘  CPI `transfer(feature, incinerator::id())`.
//!   Because the transfer DESTINATION is the hard-coded `incinerator::id()`,
//!   the System CPI can only succeed if account[1] IS the incinerator address
//!   (and writable). A mismatched/read-only account[1] makes the CPI fail →
//!   the whole tx errors → ZERO mutations. We reproduce that by REQUIRING
//!   account[1] == INCINERATOR_ID and writable (fail-loud otherwise). The task
//!   brief modeled a blind `account[1] += lamports`; the PRIMARY source instead
//!   burns to the fixed incinerator — omitting the address check would let an
//!   adversarial tx (any writable account[1]) diverge bank_hash (RULE #0).
//!
//! ── Consensus note: 0-lamport delete + lt_hash ─────────────────────────────
//! Setting feature.lamports = 0 makes the commit path DELETE the account:
//! `Bank.accountLtHash` returns `LtHash.init()` (zero contribution) for
//! lamports==0 (bank.zig:990, FD fd_hashes.c:30-32) and the store REMOVEs it.
//! So the feature account's post data/owner are consensus-irrelevant once its
//! lamports hit 0 — but we still empty its data + reassign to System to mirror
//! the program exactly (and for a clean AccountView the KAT can assert).
//!
//! ── extractMutations / arena note (v2_dispatch.zig:384) ────────────────────
//! `execute` reslices `feature.data = feature.data[0..0]` to shrink to len 0.
//! extractMutations diffs post-vs-pre and emits: feature {lamports 0, owner
//! System, data []} + incinerator {lamports +prior}. The production commit path
//! runs from a PER-DISPATCH ArenaAllocator (replay_stage.zig:12011 — "arena
//! drops on dispatch exit; no per-mutation free walk; no leak"), so orphaning
//! the original data buffer via the reslice is free. In the Harness KAT the
//! reslice is likewise safe: the harness tracks + frees `data_bufs[i]` (the
//! full original buffer), independent of AccountView.data. VERIFIED: reslice
//! `buf[0..0]` + `allocator.free` does NOT crash (Zig 0.15.2 DebugAllocator) —
//! it just no-ops the size-class free; a fresh `alloc(0)` reassign would LEAK
//! in the KAT (harness never frees ctx account data), so reslice is correct.

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const InvokeContext = ic.InvokeContext;
const Pubkey32 = ic.Pubkey32;
const trace = @import("mod.zig").trace;
const FEATURE_GATE_PROGRAM_ID = @import("mod.zig").FEATURE_GATE_PROGRAM_ID;
const INCINERATOR_ID = @import("mod.zig").INCINERATOR_ID;
const SYSTEM_PROGRAM_ID = @import("mod.zig").SYSTEM_PROGRAM_ID;

/// Nominal CU. The migrated program is BPF; its real cost is metered by the
/// SBPF VM and is NOT part of bank_hash. We charge a small nominal amount so
/// the meter stays roughly consistent; a valid tx (≥200k CU budget) never
/// fails on it.
pub const COMPUTE_UNITS: u64 = 1_500;

/// Feature::size_of() — 1 bincode Option tag byte + 8 slot bytes.
const FEATURE_STATE_SIZE: usize = 9;

pub const Error = error{
    M9_FeatureGate_OutOfCompute,
    M9_FeatureGate_NoActiveFrame,
    M9_FeatureGate_AccountIndexOutOfBounds,
    /// `next_account_info` ×3 ran out of accounts (Agave NotEnoughAccountKeys).
    M9_FeatureGate_NotEnoughAccountKeys,
    /// unpack: input.len() != 1, or tag byte not a valid instruction
    /// (Agave InvalidInstructionData).
    M9_FeatureGate_InvalidInstructionData,
    /// feature account did not sign (Agave MissingRequiredSignature).
    M9_FeatureGate_MissingRequiredSignature,
    /// feature.owner != Feature Gate program id
    /// (Feature::from_account_info → InvalidAccountOwner).
    M9_FeatureGate_InvalidAccountOwner,
    /// feature.data.len < 9, or bincode Option tag > 1
    /// (Feature::from_account_info → InvalidAccountData).
    M9_FeatureGate_InvalidAccountData,
    /// activated_at.is_some() — feature already activated
    /// (FeatureGateError::FeatureAlreadyActivated == ProgramError::Custom(0)).
    M9_FeatureGate_FeatureAlreadyActivated,
    /// feature or incinerator not writable — the program's resize/assign/CPI
    /// would be rejected by the runtime (readonly-modified) → 0 mutations.
    M9_FeatureGate_AccountNotWritable,
    /// account[1] != incinerator::id(). The System CPI transfer targets the
    /// hard-coded incinerator address; a mismatch makes the CPI fail → the tx
    /// errors → 0 mutations. Reproduced here so a crafted account[1] cannot
    /// divert the burned lamports and diverge bank_hash.
    M9_FeatureGate_IncineratorMismatch,
    /// incinerator.lamports + feature.lamports overflowed u64 (System transfer
    /// checked_add → ArithmeticOverflow). Unreachable for real balances.
    M9_FeatureGate_ArithmeticOverflow,
};

pub fn execute(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    ctx.consumeCompute(COMPUTE_UNITS) catch return error.M9_FeatureGate_OutOfCompute;
    trace("M9.feature_gate.execute (data_len={d})", .{ix_data.len});

    const frame = ctx.currentFrame() orelse return error.M9_FeatureGate_NoActiveFrame;

    // ── unpack(input): strict single-byte 0x00 ────────────────────────────
    // program/src/instruction.rs: `if input.len() != 1 { InvalidInstructionData }`
    // then `try_from(input[0])` — only tag 0 (RevokePendingActivation) exists.
    if (ix_data.len != 1) return error.M9_FeatureGate_InvalidInstructionData;
    if (ix_data[0] != 0) return error.M9_FeatureGate_InvalidInstructionData;

    // ── next_account_info ×3 ──────────────────────────────────────────────
    if (frame.account_indices.len < 3) return error.M9_FeatureGate_NotEnoughAccountKeys;

    const feat_idx = frame.account_indices[0];
    const incin_idx = frame.account_indices[1];
    // [2] = system program, unused (`_system_program_info`).
    if (feat_idx >= ctx.tx.accounts.len or incin_idx >= ctx.tx.accounts.len)
        return error.M9_FeatureGate_AccountIndexOutOfBounds;
    const feature = &ctx.tx.accounts[feat_idx];
    const incinerator = &ctx.tx.accounts[incin_idx];

    // ── 1. signer ─────────────────────────────────────────────────────────
    if (!feature.is_signer) return error.M9_FeatureGate_MissingRequiredSignature;

    // ── 2. Feature::from_account_info(feature) ────────────────────────────
    // owner check ("This will also check the program ID").
    if (!std.mem.eql(u8, &feature.owner, &FEATURE_GATE_PROGRAM_ID))
        return error.M9_FeatureGate_InvalidAccountOwner;
    // data_len < size_of() (9).
    if (feature.data.len < FEATURE_STATE_SIZE) return error.M9_FeatureGate_InvalidAccountData;
    // bincode Option<u64> tag: 0 = None (pending), 1 = Some (activated), >1 =
    // malformed → deserialize error → InvalidAccountData.
    const tag = feature.data[0];
    if (tag > 1) return error.M9_FeatureGate_InvalidAccountData;

    // ── 3. activated_at.is_some() ─────────────────────────────────────────
    if (tag == 1) return error.M9_FeatureGate_FeatureAlreadyActivated;

    // ── Mutation preconditions (reproduce the resize/assign/CPI failures) ──
    // A read-only feature makes resize/assign a readonly-modification → reject.
    if (!feature.is_writable) return error.M9_FeatureGate_AccountNotWritable;
    // The System CPI transfer destination is the hard-coded incinerator id;
    // account[1] must BE it (and writable) or the CPI fails → 0 mutations.
    if (!std.mem.eql(u8, &incinerator.pubkey, &INCINERATOR_ID))
        return error.M9_FeatureGate_IncineratorMismatch;
    if (!incinerator.is_writable) return error.M9_FeatureGate_AccountNotWritable;

    // Pre-compute the credit with checked add (System transfer semantics).
    const prior_lamports = feature.lamports;
    const new_incinerator_lamports = std.math.add(u64, incinerator.lamports, prior_lamports) catch
        return error.M9_FeatureGate_ArithmeticOverflow;

    // ── Apply (all checks passed; no partial-mutation path) ───────────────
    // resize(0): shrink data to length 0. Safe reslice (see header note).
    feature.data = feature.data[0..0];
    // assign(system_program::id()): owner → System (all-zero id).
    feature.owner = SYSTEM_PROGRAM_ID;
    // Burn: move all feature lamports to the incinerator.
    feature.lamports = 0;
    incinerator.lamports = new_incinerator_lamports;
}

pub fn selfTest() bool {
    if (COMPUTE_UNITS != 1_500) return false;
    // Program id must decode to the canonical on-chain bytes (CLAUDE.md
    // pitfall #3: never trust a hand-typed / mis-counted base58).
    const EXPECT_ID = [_]u8{
        0x03, 0xc0, 0xa0, 0xcd, 0xcb, 0x06, 0xd2, 0xda,
        0xef, 0xae, 0x82, 0xd1, 0x6f, 0xee, 0x7a, 0xcf,
        0x61, 0xec, 0x73, 0x7b, 0x23, 0x48, 0x1b, 0x21,
        0x94, 0x6a, 0x76, 0x70, 0x00, 0x00, 0x00, 0x00,
    };
    if (!std.mem.eql(u8, &FEATURE_GATE_PROGRAM_ID, &EXPECT_ID)) return false;
    return true;
}

// Compile-time lock on the program id bytes.
comptime {
    const EXPECT_ID = [_]u8{
        0x03, 0xc0, 0xa0, 0xcd, 0xcb, 0x06, 0xd2, 0xda,
        0xef, 0xae, 0x82, 0xd1, 0x6f, 0xee, 0x7a, 0xcf,
        0x61, 0xec, 0x73, 0x7b, 0x23, 0x48, 0x1b, 0x21,
        0x94, 0x6a, 0x76, 0x70, 0x00, 0x00, 0x00, 0x00,
    };
    if (!std.mem.eql(u8, &FEATURE_GATE_PROGRAM_ID, &EXPECT_ID))
        @compileError("FEATURE_GATE_PROGRAM_ID base58 decode != canonical Feature111… bytes");

    // Incinerator id — consensus-critical (System-CPI transfer destination).
    // Canonical bytes from Firedancer fd_system_ids_pp.h SYSVAR_INCINERATOR_ID.
    const EXPECT_INCIN = [_]u8{
        0x00, 0x33, 0x90, 0x72, 0x8D, 0x34, 0x11, 0x60,
        0x79, 0xBD, 0xC9, 0x11, 0xBF, 0xFF, 0x00, 0xDB,
        0xD4, 0x4D, 0x2E, 0xCD, 0xCC, 0xF7, 0x9C, 0xA6,
        0xE1, 0x00, 0x38, 0xE1, 0x00, 0x00, 0x00, 0x00,
    };
    if (!std.mem.eql(u8, &INCINERATOR_ID, &EXPECT_INCIN))
        @compileError("INCINERATOR_ID base58 decode != canonical incinerator bytes");
}

// ── Tests ─────────────────────────────────────────────────────────────────

const Harness = @import("test_harness.zig");

/// Build the canonical 3-account borrow set: feature[0], incinerator[1],
/// system[2]. `feat_*` describe the feature account; incinerator seeded with
/// `incin_lamports`; system is a readonly placeholder.
fn happySpecs(
    feat_lamports: u64,
    feat_signer: bool,
    feat_writable: bool,
    feat_owner: Pubkey32,
    incin_lamports: u64,
    incin_pubkey: Pubkey32,
    incin_writable: bool,
) [3]Harness.AccountSpec {
    const FEAT_PK = [_]u8{0x11} ** 32;
    return .{
        .{ .pubkey = FEAT_PK, .lamports = feat_lamports, .data_len = FEATURE_STATE_SIZE, .owner = feat_owner, .is_writable = feat_writable, .is_signer = feat_signer },
        .{ .pubkey = incin_pubkey, .lamports = incin_lamports, .data_len = 0, .is_writable = incin_writable, .is_signer = false },
        .{ .pubkey = SYSTEM_PROGRAM_ID, .lamports = 1, .data_len = 0, .is_writable = false, .is_signer = false },
    };
}

test "M9 feature_gate: OutOfCompute when meter is short" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100, &.{});
    defer h.deinit();
    try t.expectError(error.M9_FeatureGate_OutOfCompute, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: KAT — pending feature revoked, lamports burned to incinerator" {
    const t = std.testing;
    var specs = happySpecs(953_520, true, true, FEATURE_GATE_PROGRAM_ID, 1, INCINERATOR_ID, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    // feature.data already zero-filled by the harness → pending (tag 0). Good.
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();

    try execute(h.ctx, &[_]u8{0x00});

    // feature: deleted → lamports 0, data emptied, owner reassigned to System.
    try t.expectEqual(@as(u64, 0), h.accounts[0].lamports);
    try t.expectEqual(@as(usize, 0), h.accounts[0].data.len);
    try t.expectEqualSlices(u8, &SYSTEM_PROGRAM_ID, &h.accounts[0].owner);
    // incinerator: credited prior feature lamports (1 + 953_520).
    try t.expectEqual(@as(u64, 953_521), h.accounts[1].lamports);
}

test "M9 feature_gate: not-signer → MissingRequiredSignature" {
    const t = std.testing;
    var specs = happySpecs(953_520, false, true, FEATURE_GATE_PROGRAM_ID, 1, INCINERATOR_ID, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_MissingRequiredSignature, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: already activated (data[0]==1) → FeatureAlreadyActivated" {
    const t = std.testing;
    var specs = happySpecs(953_520, true, true, FEATURE_GATE_PROGRAM_ID, 1, INCINERATOR_ID, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    h.accounts[0].data[0] = 1; // Some(activated_at)
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_FeatureAlreadyActivated, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: bad bincode tag (data[0]==2) → InvalidAccountData" {
    const t = std.testing;
    var specs = happySpecs(953_520, true, true, FEATURE_GATE_PROGRAM_ID, 1, INCINERATOR_ID, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    h.accounts[0].data[0] = 2; // invalid Option tag
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_InvalidAccountData, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: wrong owner → InvalidAccountOwner" {
    const t = std.testing;
    const WRONG_OWNER = [_]u8{0xAB} ** 32;
    var specs = happySpecs(953_520, true, true, WRONG_OWNER, 1, INCINERATOR_ID, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_InvalidAccountOwner, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: data too short (<9) → InvalidAccountData" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 200_000, &.{
        .{ .pubkey = [_]u8{0x11} ** 32, .lamports = 100, .data_len = 8, .owner = FEATURE_GATE_PROGRAM_ID, .is_writable = true, .is_signer = true },
        .{ .pubkey = INCINERATOR_ID, .lamports = 1, .data_len = 0, .is_writable = true, .is_signer = false },
        .{ .pubkey = SYSTEM_PROGRAM_ID, .lamports = 1, .data_len = 0, .is_writable = false, .is_signer = false },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_InvalidAccountData, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: ix_data variants → InvalidInstructionData" {
    const t = std.testing;
    var specs = happySpecs(953_520, true, true, FEATURE_GATE_PROGRAM_ID, 1, INCINERATOR_ID, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_InvalidInstructionData, execute(h.ctx, &[_]u8{}));
    try t.expectError(error.M9_FeatureGate_InvalidInstructionData, execute(h.ctx, &[_]u8{ 0x00, 0x00 }));
    try t.expectError(error.M9_FeatureGate_InvalidInstructionData, execute(h.ctx, &[_]u8{0x01}));
}

test "M9 feature_gate: fewer than 3 accounts → NotEnoughAccountKeys" {
    const t = std.testing;
    var specs = happySpecs(953_520, true, true, FEATURE_GATE_PROGRAM_ID, 1, INCINERATOR_ID, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1 }); // only 2
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_NotEnoughAccountKeys, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: incinerator not writable → AccountNotWritable" {
    // Consensus-critical: extractMutations SKIPS non-writable accounts, so if
    // account[1] were credited but not writable, the credit would be DROPPED
    // while the feature (writable) is still deleted → lamports destroyed vs the
    // real program's 0-mutation CPI failure. Guarding it here locks lamport
    // conservation.
    const t = std.testing;
    var specs = happySpecs(953_520, true, true, FEATURE_GATE_PROGRAM_ID, 1, INCINERATOR_ID, false);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_AccountNotWritable, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: feature not writable → AccountNotWritable" {
    // Mirror-image conservation guard: a non-writable feature would drop the
    // debit/delete while the incinerator is still credited → lamports created.
    const t = std.testing;
    var specs = happySpecs(953_520, true, false, FEATURE_GATE_PROGRAM_ID, 1, INCINERATOR_ID, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_AccountNotWritable, execute(h.ctx, &[_]u8{0x00}));
}

test "M9 feature_gate: account[1] not the incinerator → IncineratorMismatch" {
    const t = std.testing;
    const NOT_INCIN = [_]u8{0x22} ** 32;
    var specs = happySpecs(953_520, true, true, FEATURE_GATE_PROGRAM_ID, 1, NOT_INCIN, true);
    var h = try Harness.init(t.allocator, 200_000, &specs);
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    try t.expectError(error.M9_FeatureGate_IncineratorMismatch, execute(h.ctx, &[_]u8{0x00}));
}
