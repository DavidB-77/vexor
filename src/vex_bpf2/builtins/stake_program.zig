//! Vexor BPF2 — M9: Stake native builtin program.
//!
//! @prov:stake-builtin.module-map — spec source (Agave legacy stake_state.rs +
//! stake_instruction.rs, Core-BPF v5 under SIMD-0196; Sig lib.zig full port)
//! and full per-instruction upstream line-map in PROVENANCE.md.
//!   • Vexor V1 reference (DO NOT MUTATE):
//!     src/vex_svm/native/{stake_program.zig,stake_state.zig}
//!
//! ── Instruction enum (agave bincode tag = u32 LE) ─────────────────────────
//!     0  Initialize(Authorized, Lockup)
//!     1  Authorize(Pubkey, StakeAuthorize)
//!     2  DelegateStake
//!     3  Split(u64)
//!     4  Withdraw(u64)
//!     5  Deactivate
//!     6  SetLockup(LockupArgs)
//!     7  Merge
//!     8  AuthorizeWithSeed(AuthorizeWithSeedArgs)
//!     9  InitializeChecked
//!    10  AuthorizeChecked(StakeAuthorize)
//!    11  AuthorizeCheckedWithSeed(AuthorizeCheckedWithSeedArgs)
//!    12  SetLockupChecked(LockupCheckedArgs)
//!    13  GetMinimumDelegation
//!    14  DeactivateDelinquent
//!    15  Redelegate (legacy, removed in v4)  — pending parser
//!    16  MoveStake(u64)
//!    17  MoveLamports(u64)
//!
//! ── Port status (this session) ────────────────────────────────────────────
//! Skeleton only: parser dispatches by tag; every variant returns
//! `M9_Stake_VariantPending_<Name>`. The full port (~3500 LoC) is a
//! multi-session deliverable. Until then the running validator's stake
//! handler stays on V1's `src/vex_svm/native/stake_program.zig`. The Wave 4
//! wireup at replay_stage.zig swaps to M9 only after a per-instruction
//! parity table proves byte-identical mutation against V1 on a 10k-stake
//! sample.
//!
//! ── SIMD inventory ────────────────────────────────────────────────────────
//!   • SIMD-0196 (Migrate Stake to Core BPF) — DORMANT. Until activation
//!     this stays builtin. When it activates this entire file becomes a
//!     compatibility shim.
//!   • SIMD-0490 (Upgrade BPF stake program to v5) — DORMANT (testnet AND
//!     mainnet). Stake stays on v4 logic per task scope.
//!   • SIMD-0191 (Loading-fees) — already active; affects fee math, not
//!     stake handler.
//!
//! ── fix_ledger anchors ────────────────────────────────────────────────────
//!   • vex-058 — stake handlers MUST read EpochSchedule + Clock +
//!     StakeHistory via ctx.sysvar_cache; never hardcode 0. Locked when
//!     full port lands.
//!   • vex-039 (executeBpfProgram-owner-bug) — stake account owner read
//!     from AccountView.owner.

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const InvokeContext = ic.InvokeContext;
const sysvar_cache = @import("../sysvar_cache.zig");
const StakeHistoryEntry = sysvar_cache.StakeHistoryEntry;
const trace = @import("mod.zig").trace;

// Canonical StakeStateV2 byte layout (a stable on-chain wire format). These
// mirror vex_svm/native/stake_state.zig — we cannot @import that file here
// because it already belongs to the `vex_svm` module and Zig forbids a single
// file living in two modules. The three offsets below are the canonical fixed
// layout (StakeStateV2: u32 disc @0, Meta @4 [authorized.staker @12], Stake @124
// [deactivation_epoch @172]); the shared KAT vectors keep both paths honest.
const STAKE_STATE_SZ: usize = 200;
const STAKE_OFF_RENT_EXEMPT: usize = 4; // u64 meta.rent_exempt_reserve
const STAKE_OFF_STAKER: usize = 12; // [32]u8 meta.authorized.staker
const STAKE_OFF_WITHDRAWER: usize = 44; // [32]u8 meta.authorized.withdrawer
const STAKE_OFF_LOCKUP_TS: usize = 76; // i64 meta.lockup.unix_timestamp
const STAKE_OFF_LOCKUP_EPOCH: usize = 84; // u64 meta.lockup.epoch
const STAKE_OFF_LOCKUP_CUSTODIAN: usize = 92; // [32]u8 meta.lockup.custodian
const STAKE_OFF_VOTER: usize = 124; // [32]u8 stake.delegation.voter_pubkey
const STAKE_OFF_DELEGATION_STAKE: usize = 156; // u64 stake.delegation.stake
const STAKE_OFF_ACTIVATION_EPOCH: usize = 164; // u64 stake.delegation.activation_epoch
const STAKE_OFF_DEACTIVATION_EPOCH: usize = 172; // u64
const STAKE_OFF_CREDITS_OBSERVED: usize = 188; // u64 stake.credits_observed
const STAKE_OFF_STAKE_FLAGS: usize = 196; // u8 stake_flags
const STAKE_DISC_UNINITIALIZED: u32 = 0; // StakeStateV2::Uninitialized
const STAKE_DISC_INITIALIZED: u32 = 1; // StakeStateV2::Initialized
const STAKE_DISC_STAKE: u32 = 2; // StakeStateV2::Stake

// Stake program id (for the get_stake_account owner check). Pulled from the
// builtins registry so there is a single canonical source.
const STAKE_PROGRAM_ID = @import("mod.zig").STAKE_PROGRAM_ID;
// Vote program id (DelegateStake requires the vote account owner == Vote111…;
// canonical IncorrectProgramId otherwise). Single canonical source = builtins registry.
const VOTE_PROGRAM_ID = @import("mod.zig").VOTE_PROGRAM_ID;

pub const COMPUTE_UNITS: u64 = 750; // @prov:stake-builtin.cu-cost

pub const Error = error{
    M9_Stake_OutOfCompute,
    M9_Stake_NoActiveFrame,
    M9_Stake_InvalidInstructionData,
    M9_Stake_UnknownInstructionTag,
    M9_Stake_VariantPending_Authorize,
    M9_Stake_VariantPending_DelegateStake,
    M9_Stake_VariantPending_Split,
    M9_Stake_VariantPending_Withdraw,
    M9_Stake_VariantPending_Deactivate,
    M9_Stake_VariantPending_SetLockup,
    M9_Stake_VariantPending_Merge,
    M9_Stake_VariantPending_AuthorizeWithSeed,
    M9_Stake_VariantPending_InitializeChecked,
    M9_Stake_VariantPending_AuthorizeChecked,
    M9_Stake_VariantPending_AuthorizeCheckedWithSeed,
    M9_Stake_VariantPending_SetLockupChecked,
    M9_Stake_VariantPending_GetMinimumDelegation,
    M9_Stake_VariantPending_DeactivateDelinquent,
    M9_Stake_VariantPending_Redelegate,
    M9_Stake_VariantPending_MoveStake,
    M9_Stake_VariantPending_MoveLamports,
    // Canonical Deactivate (tag 5) error set — typed to mirror Agave's
    // InstructionError returns (no silent no-ops).
    M9_Stake_NotEnoughAccounts, // NotEnoughAccountKeys
    M9_Stake_AccountIndexOutOfBounds,
    M9_Stake_AccountNotWritable,
    M9_Stake_InvalidAccountData, // not Stake state / malformed
    M9_Stake_MissingRequiredSignature, // staker authority did not sign
    M9_Stake_AlreadyDeactivated, // Agave StakeError::AlreadyDeactivated = Custom(2)
    M9_Stake_ClockUnavailable, // Clock sysvar not populated
    // Canonical Authorize (tag 1) error set. All fold into M7_BuiltinFailed at the
    // CPI boundary (cpi.zig:810) — the specific variant is diagnostic, NOT consensus
    // (a failed tx's only state effect is the fee, identical regardless of code). What
    // IS consensus = the pass/fail boundary, which these typed errors gate.
    M9_Stake_InvalidAccountOwner, // stake owner != stake program (get_stake_account)
    M9_Stake_CustodianMissing, // lockup in force, no custodian account = StakeError::CustodianMissing (Custom 7)
    M9_Stake_CustodianSignatureMissing, // custodian present but did not sign (Custom 8)
    M9_Stake_LockupInForce, // lockup in force, custodian != lockup.custodian (Custom 1)
    M9_Stake_EpochRewardsActive, // SIMD-0118 reward window blocks stake ix (Custom 19)
    // Canonical Merge (tag 7) + Withdraw (tag 4) error set (this session).
    // All fold into M7_BuiltinFailed at cpi.zig:810 — the variant is diagnostic,
    // NOT consensus (a failed tx's only state effect is the fee). What IS consensus
    // is the pass/fail boundary, which these typed errors gate.
    M9_Stake_InsufficientFunds, // Withdraw: lamports+reserve > stake.lamports (InstructionError::InsufficientFunds)
    M9_Stake_MergeMismatch, // metas / voter / deact mismatch (StakeError::MergeMismatch Custom 6)
    M9_Stake_MergeTransientStake, // un-mergeable kind: transient warming/cooling (StakeError::MergeTransientStake Custom 14)
    M9_Stake_ArithmeticOverflow, // checked add overflow / weighted credits > u64 max
    M9_Stake_InvalidArgument, // Merge: dst account index == src account index (InstructionError::InvalidArgument)
    // Canonical Split (tag 3) error set (this session). Fold into M7_BuiltinFailed
    // at cpi.zig:810 — the variant is diagnostic, NOT consensus (only the pass/fail
    // boundary + success bytes are). These mirror Sig v5 Split's typed returns.
    M9_Stake_InsufficientDelegation, // split_stake_amount/remainder < min_delegation (StakeError::InsufficientDelegation Custom 11)
    M9_Stake_InsufficientStake, // remaining_stake_delta > src.delegation.stake (StakeError::InsufficientStake Custom 3)
    // Canonical MoveStake (tag 16) error set (this session). Fold into M7_BuiltinFailed
    // at cpi.zig:810 — the variant is diagnostic, NOT consensus (only the pass/fail
    // boundary + success bytes are). v5-only (SIMD-0148/0490).
    M9_Stake_VoteAddressMismatch, // dest FullyActive but voter != source voter (StakeError::VoteAddressMismatch Custom 21)
    // Canonical DelegateStake (tag 2) error set (this session). Fold into
    // M7_BuiltinFailed at cpi.zig:810 — the variant is diagnostic, NOT consensus
    // (only the pass/fail boundary + success bytes are). Mirrors Sig v5 delegate's
    // typed returns.
    M9_Stake_TooSoonToRedelegate, // re-delegate of an effective stake to a NEW vote (StakeError::TooSoonToRedelegate Custom 23)
    M9_Stake_MalformedVoteState, // vote account data could not be deserialized (InstructionError, NOT credits=0)
    // Canonical DeactivateDelinquent (tag 14) error set (this session). Fold into
    // M7_BuiltinFailed at cpi.zig:810 — the variant is diagnostic, NOT consensus
    // (only the pass/fail boundary + success bytes are). Mirrors Sig v5
    // deactivateDelinquent (lib.zig:1406) typed returns.
    M9_Stake_InsufficientReferenceVotes, // reference vote acct lacks 5 consecutive recent epoch_credits (StakeError::InsufficientReferenceVotes Custom 12)
    M9_Stake_MinimumDelinquentEpochsNotMet, // delinquent voted within last 5 epochs (StakeError::MinimumDelinquentEpochsForDeactivationNotMet Custom 13)
    // Canonical GetMinimumDelegation (tag 13) error set (this session). The handler
    // has no fallible step EXCEPT the return_data alloc; folds into M7_BuiltinFailed
    // at cpi.zig:810 — diagnostic, NOT consensus. (Agave/Sig use a stack BoundedArray
    // and cannot fail here; Vexor's return_data is an ArrayListUnmanaged that can OOM.)
    M9_Stake_OutOfMemory, // return_data alloc failed (folds to M7; non-consensus)
};

// f64 0.25 as raw bits (Delegation.deprecated_warmup_cooldown_rate default). v5
// still serializes this 8-byte field into the 200-byte account; on init→Stake it
// MUST be set to 0.25, on re-delegate it MUST be PRESERVED. See FOOTGUN at offset
// 180 in executeDelegate. = @bitCast(@as(f64, 0.25)).
const STAKE_WARMUP_RATE_DEFAULT_BITS: u64 = 0x3FD0000000000000;
const STAKE_OFF_WARMUP_RATE: usize = 180; // u64 (f64 bits) stake.delegation.deprecated_warmup_cooldown_rate

// SIMD-0490 v5 minimum delegation = 1 SOL. Applies only to Split / MoveStake /
// MoveLamports on the BPF stake program (active testnet).
const MIN_DELEGATION_LAMPORTS: u64 = 1_000_000_000;

pub fn execute(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    ctx.consumeCompute(COMPUTE_UNITS) catch return error.M9_Stake_OutOfCompute;
    if (ctx.currentFrame() == null) return error.M9_Stake_NoActiveFrame;
    if (ix_data.len < 4) return error.M9_Stake_InvalidInstructionData;
    const tag = std.mem.readInt(u32, ix_data[0..4], .little);
    trace("M9.stake.execute (tag={d})", .{tag});

    return switch (tag) {
        0 => return executeInitialize(ctx, ix_data),
        1 => return executeAuthorize(ctx, ix_data),
        2 => return executeDelegate(ctx, ix_data),
        3 => return executeSplit(ctx, ix_data),
        4 => return executeWithdraw(ctx, ix_data),
        5 => return executeDeactivate(ctx),
        6 => return executeSetLockup(ctx, ix_data),
        7 => return executeMerge(ctx),
        8 => return executeAuthorizeWithSeed(ctx, ix_data),
        9 => return executeInitializeChecked(ctx),
        10 => return executeAuthorizeChecked(ctx, ix_data),
        11 => return executeAuthorizeCheckedWithSeed(ctx, ix_data),
        12 => return executeSetLockupChecked(ctx, ix_data),
        13 => return executeGetMinimumDelegation(ctx),
        14 => return executeDeactivateDelinquent(ctx),
        15 => error.M9_Stake_VariantPending_Redelegate,
        16 => return executeMoveStake(ctx, ix_data),
        17 => return executeMoveLamports(ctx, ix_data),
        else => error.M9_Stake_UnknownInstructionTag,
    };
}

// ── Authorize (tag 1) — canonical Agave stake `authorize` ───────────────────
//
// CARRIER FIX (2026-06-16, divergence onset testnet slot 415547068, post-rc.0-
// restart): a BPF program (PDA seed "deposit" — a stake-pool/deposit protocol,
// caller 06814ed4…) CPIs into Stake Authorize. The cluster executes it; Vexor hit
// the `M9_Stake_VariantPending_Authorize` stub → M7_BuiltinFailed → outer tx
// M4_RunFailed (failed_ix=2) → the staker/withdrawer write was dropped →
// accounts_lt_hash poison → bank_hash divergence → cascade. Predicted recurrence
// of the Deactivate(tag5) stub class (memory carrier-stake-cpi-deactivate-stub).
//
// @prov:stake-builtin.authorize — byte-faithful to Agave AND Sig.
// Accounts: [0] stake [WRITE], [1] Clock,
// [2] authority [SIGNER], [3] custodian (OPTIONAL). ix data = u32 tag(1) +
// [32]new_authorized + u32 stake_authorize (0=Staker,1=Withdrawer) = 40 bytes.
//
// ⚠ Do NOT copy the top-level native handleAuthorize — it has 3 consensus bugs
// (index-2-only signer check instead of signer-SET scan; lockup block ordered
// AFTER the withdrawer-signature check instead of before; non-canonical
// isLockupActive). This port follows Agave order exactly, mirroring
// executeDeactivate's set-scan + in-place same-length mutation (NO bank.collectWrite;
// cpi.zig propagates the in-place change to caller memory, replay content-detects it).
fn signerSetContains(ctx: *InvokeContext, frame: anytype, key: []const u8) bool {
    for (frame.account_indices) |aidx| {
        if (aidx >= ctx.tx.accounts.len) continue;
        const a = &ctx.tx.accounts[aidx];
        if (a.is_signer and std.mem.eql(u8, &a.pubkey, key)) return true;
    }
    return false;
}

// ── Initialize (tag 0) — canonical BPF stake v5 (SIMD-0490 active testnet) ───
//
// Transitions a stake account Uninitialized(0) → Initialized(1), writing
// Meta{rent_exempt_reserve, Authorized{staker,withdrawer}, Lockup{ts,epoch,
// custodian}}. NO lamport movement, NO signer requirement.
//
// @prov:stake-builtin.initialize — v4 == v5 for tag 0 (SIMD-0490 does NOT touch Initialize):
//   accounts: [0] stake [WRITE], [1] Rent sysvar.  NO signer required.
//   1. data.len != SIZE(200) → InvalidAccountData  (EXACT !=, not <)
//   2. state != Uninitialized(0) → InvalidAccountData
//   3. lamports < Rent.minimumBalance(200) → InsufficientFunds
//   4. serialize_into(Initialized): writes Meta over the [0..124] region,
//      leaves [124..200] untouched (canonical set_state writes only the
//      serialized bytes — same logic that makes our Withdraw/Merge drain
//      "write disc=0, preserve tail" correct).
//
// ⚠ Do NOT copy the top-level native handleInitialize (vex_svm/native/
// stake_program.zig:229) — it has the silent-swallow bug class:
//   (a) `parse catch return` → malformed/short ix data = silent no-op success
//       (Agave: InvalidInstructionData);
//   (b) `if (disc != 0) return` → already-Initialized/Stake = silent success
//       (Agave: InvalidAccountData);
//   (c) `if (lamports < reserve) return` → underfunded = silent success
//       (Agave: InsufficientFunds);
//   (d) NO data.len==200 check; (e) NO SIMD-0118 EpochRewards gate;
//   (f) @memset(0,200) of a fresh alloc + bank.collectWrite (wrong idiom for the
//       CPI path). This port follows Agave order exactly, mirroring
//       executeAuthorize/executeMerge (typed errors, in-place same-length
//       mutation, NO bank.collectWrite — cpi.zig propagates the in-place change
//       to caller memory, replay content-detects it). The native handler's
//       silent-swallow is a separate LATENT top-level fix — flagged, not fixed here.
fn executeInitialize(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // ix data: u32 tag(0) + Authorized{staker[32],withdrawer[32]} +
    //          Lockup{ts i64, epoch u64, custodian[32]} = 116 bytes.
    if (ix_data.len < 116) return error.M9_Stake_InvalidInstructionData;

    // SIMD-0118 EpochRewardsActive gate: blocks all stake ix (except
    // GetMinimumDelegation) during the partitioned reward window. Guarded —
    // sysvar absent ⇒ no gate (safe).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // Accounts: [0] stake [WRITE], [1] Rent sysvar. NO signer required.
    if (frame.account_indices.len < 2) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    if (stake_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    // get_stake_account: owner must be the stake program (else InvalidAccountOwner).
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;

    // EXACT size: Agave checks data.len != SIZE (NOT < — a 201-byte account must
    // be REJECTED, unlike the Authorize/Withdraw `< STAKE_STATE_SZ` siblings).
    if (stake.data.len != STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    // Must be Uninitialized(0).
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_UNINITIALIZED) return error.M9_Stake_InvalidAccountData;

    // rent_exempt_reserve = Rent.minimumBalance(200). Single arithmetic form,
    // identical to executeMoveStake:869. Default = (128+200)*3480*2.0 = 2,282,880.
    const rent = ctx.sysvar_cache.getRent() catch return error.M9_Stake_ClockUnavailable;
    const reserve: u64 = @intFromFloat(@as(f64, @floatFromInt((128 + STAKE_STATE_SZ) * rent.lamports_per_byte_year)) * rent.exemption_threshold);
    if (stake.lamports < reserve) return error.M9_Stake_InsufficientFunds;

    // In-place same-length write of Meta over the Uninitialized buffer. Write ONLY
    // [0..124] (canonical set_state(Initialized) serialize_into writes the 124
    // serialized bytes and leaves [124..200] untouched). NO @memset. NO lamport move.
    std.mem.writeInt(u32, stake.data[0..4], STAKE_DISC_INITIALIZED, .little); // disc=1 @0
    std.mem.writeInt(u64, stake.data[STAKE_OFF_RENT_EXEMPT..][0..8], reserve, .little); // @4
    @memcpy(stake.data[STAKE_OFF_STAKER..][0..32], ix_data[4..36]); // staker @12
    @memcpy(stake.data[STAKE_OFF_WITHDRAWER..][0..32], ix_data[36..68]); // withdrawer @44
    @memcpy(stake.data[STAKE_OFF_LOCKUP_TS..][0..8], ix_data[68..76]); // lockup.ts @76
    @memcpy(stake.data[STAKE_OFF_LOCKUP_EPOCH..][0..8], ix_data[76..84]); // lockup.epoch @84
    @memcpy(stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32], ix_data[84..116]); // custodian @92
}

// ── InitializeChecked (tag 9) — canonical Agave/BPF stake v5 ─────────────────
//
// CARRIER-CLASS FIX (predicted recurrence of the Authorize(tag1, slot 415547068),
// Deactivate(tag5, slot 415214214), and the rest of the Stake-CPI stub carriers):
// the first time any BPF program CPIs Stake InitializeChecked, the prior
// `M9_Stake_VariantPending_InitializeChecked` stub → M7_BuiltinFailed → outer tx
// M4_RunFailed → dropped Initialized-state write → accounts_lt_hash poison →
// bank_hash divergence → delinquency. Closing the stub pre-empts it.
//
// Identical to Initialize (tag 0) EXCEPT the three "Checked" deltas:
//   • authorities come from the ACCOUNT METAS, not ix data:
//       staker      = accounts[2].pubkey
//       withdrawer  = accounts[3].pubkey
//   • that withdrawer account (index 3) MUST be a signer — canonical INDEX-3
//     `is_signer` check (this is what makes the variant "Checked"; it is NOT a
//     signer-SET scan). The staker (index 2) does NOT need to sign.
//   • lockup is ALWAYS Lockup::DEFAULT (all-zero) — there is no lockup in ix data.
//   • requires >=4 accounts: [0] stake [WRITE], [1] Rent, [2] staker, [3] withdrawer [SIGNER].
// ix data = u32 tag(9) only (4 bytes) — already length-gated in execute().
//
// @prov:stake-builtin.initialize-checked — v4 == v5 for
// tag 9 (SIMD-0490 min-delegation touches only Split/MoveStake/MoveLamports; the
// Initialize family is untouched). SIMD-0118 EpochRewards gate applies (mirrors the
// siblings).
//
// ⚠ The INDEX-3 signer check is the ONE place "NEVER index-N" is itself the canonical
// behavior: checked variants pin the new authority BY POSITION (withdrawer pubkey is
// TAKEN FROM acct[3], so "did acct[3] sign" IS the canonical test) — same as
// executeAuthorizeChecked:429. Do NOT substitute signerSetContains here.
//
// ⚠ Mirrors executeInitialize (tag 0) for the write: serialize_into(Initialized)
// writes ONLY the Meta region [0..124] and STOPS — it does NOT zero-pad [124..200].
// The precondition (disc==Uninitialized = system-created = all-zero) already leaves
// the tail zero, so the bytes match either way; the byte-faithful choice (matching
// the landed executeInitialize + the canonical set_state) is to leave [124..200]
// UNTOUCHED. This is a CREATE, but the lockup region [76..124] IS canonical Meta and
// MUST be zeroed (Lockup::DEFAULT) — that is a write, NOT a "preserve tail" no-op.
//
// ⚠ Do NOT copy the top-level native handleInitialize (vex_svm/native/
// stake_program.zig:229) — it has the silent-swallow bug class (parse catch return,
// no data.len==200 check, hardcoded reserve, no EpochRewards gate, @memset + a
// bank.collectWrite which is the wrong idiom for the CPI path); it also implements
// only tag 0, never tag 9. Take logic from Sig; this handler uses typed errors and
// in-place same-length mutation (cpi.zig propagates the change, replay content-detects it).
fn executeInitializeChecked(ctx: *InvokeContext) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // ix data = u32 tag(9) only (4 bytes); already length-gated in execute(). No payload.

    // SIMD-0118 EpochRewardsActive gate: blocks all stake ix (except GetMinimumDelegation)
    // during the partitioned reward window. Guarded — sysvar absent ⇒ no gate (safe).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // Accounts: [0] stake [WRITE], [1] Rent, [2] staker, [3] withdrawer [SIGNER].
    if (frame.account_indices.len < 4) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    const staker_idx = frame.account_indices[2];
    const wd_idx = frame.account_indices[3];
    if (stake_idx >= ctx.tx.accounts.len or staker_idx >= ctx.tx.accounts.len or
        wd_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    // get_stake_account: owner must be the stake program (FIRST canonical check).
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;

    // CHECKED delta: the withdrawer authority (acct[3]) MUST sign at its OWN position
    // (canonical INDEX-3 is_signer — Sig lib.zig:272-276). The staker (acct[2]) does NOT
    // need to sign. authorities are taken from the account metas, NOT from ix data.
    if (!ctx.tx.accounts[wd_idx].is_signer) return error.M9_Stake_MissingRequiredSignature;
    const new_staker = ctx.tx.accounts[staker_idx].pubkey;
    const new_withdrawer = ctx.tx.accounts[wd_idx].pubkey;

    // EXACT size: Agave checks data.len != SIZE (NOT <) — a non-200 account is REJECTED.
    if (stake.data.len != STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    // Must be Uninitialized(0).
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_UNINITIALIZED) return error.M9_Stake_InvalidAccountData;

    // rent_exempt_reserve = Rent.minimumBalance(200). Single arithmetic form, copied
    // verbatim from executeInitialize:298-299. Default = (128+200)*3480*2.0 = 2,282,880.
    const rent = ctx.sysvar_cache.getRent() catch return error.M9_Stake_ClockUnavailable;
    const reserve: u64 = @intFromFloat(@as(f64, @floatFromInt((128 + STAKE_STATE_SZ) * rent.lamports_per_byte_year)) * rent.exemption_threshold);
    if (stake.lamports < reserve) return error.M9_Stake_InsufficientFunds;

    // In-place same-length write of Meta over the Uninitialized buffer. Write disc=1@0,
    // reserve@4, staker@12, withdrawer@44, and the Lockup::DEFAULT zeros @76/84/92.
    // Leave [124..200] UNTOUCHED (canonical set_state(Initialized) serialize_into writes
    // only the [0..124] Meta bytes; an Uninitialized account is all-zero there already).
    std.mem.writeInt(u32, stake.data[0..4], STAKE_DISC_INITIALIZED, .little); // disc=1 @0
    std.mem.writeInt(u64, stake.data[STAKE_OFF_RENT_EXEMPT..][0..8], reserve, .little); // @4
    @memcpy(stake.data[STAKE_OFF_STAKER..][0..32], &new_staker); // staker @12
    @memcpy(stake.data[STAKE_OFF_WITHDRAWER..][0..32], &new_withdrawer); // withdrawer @44
    // Lockup::DEFAULT = all zero (ts@76, epoch@84, custodian@92) — canonical Meta region.
    @memset(stake.data[STAKE_OFF_LOCKUP_TS..STAKE_OFF_VOTER], 0); // [76..124] ts+epoch+custodian
}

fn executeAuthorize(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // ix data: u32 tag(1) + [32] new_authorized + u32 authorize_type = 40 bytes.
    if (ix_data.len < 40) return error.M9_Stake_InvalidInstructionData;
    const new_authority = ix_data[4..36];
    const authorize_type = std.mem.readInt(u32, ix_data[36..40], .little);
    if (authorize_type > 1) return error.M9_Stake_InvalidInstructionData;

    // SIMD-0118 EpochRewardsActive gate: blocks all stake ix (except GetMinimumDelegation)
    // during the partitioned reward window. Guarded — sysvar absent ⇒ no gate (safe).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // Accounts: [0] stake [WRITE], [1] Clock, [2] authority [SIGNER], [3] custodian (optional).
    if (frame.account_indices.len < 3) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    if (stake_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    // get_stake_account: owner must be the stake program (else InvalidAccountOwner).
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;

    // State must be Initialized(1) or Stake(2) — both touch only Meta.authorized.
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_INITIALIZED and disc != STAKE_DISC_STAKE)
        return error.M9_Stake_InvalidAccountData;

    const staker = stake.data[STAKE_OFF_STAKER..][0..32];
    const withdrawer = stake.data[STAKE_OFF_WITHDRAWER..][0..32];

    if (authorize_type == 0) {
        // StakeAuthorize::Staker — signer set must contain the current staker OR withdrawer.
        if (!signerSetContains(ctx, frame, staker) and !signerSetContains(ctx, frame, withdrawer))
            return error.M9_Stake_MissingRequiredSignature;
        @memcpy(stake.data[STAKE_OFF_STAKER..][0..32], new_authority);
    } else {
        // StakeAuthorize::Withdrawer — lockup block FIRST (Agave order), then withdrawer sig.
        const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
        const lk_ts = std.mem.readInt(i64, stake.data[STAKE_OFF_LOCKUP_TS..][0..8], .little);
        const lk_epoch = std.mem.readInt(u64, stake.data[STAKE_OFF_LOCKUP_EPOCH..][0..8], .little);
        const lk_custodian = stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32];

        // Lockup::is_in_force(clock, None): no custodian bypass.
        if (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch) {
            // custodian = optional pubkey at instruction account index 3 (signer NOT required at fetch).
            if (frame.account_indices.len <= 3) return error.M9_Stake_CustodianMissing;
            const cust_idx = frame.account_indices[3];
            if (cust_idx >= ctx.tx.accounts.len) return error.M9_Stake_CustodianMissing;
            const custodian = &ctx.tx.accounts[cust_idx].pubkey;
            if (!signerSetContains(ctx, frame, custodian))
                return error.M9_Stake_CustodianSignatureMissing;
            // is_in_force(clock, Some(custodian)): bypass iff custodian == lockup.custodian.
            const bypass = std.mem.eql(u8, custodian, lk_custodian);
            if (!bypass and (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch))
                return error.M9_Stake_LockupInForce;
        }
        // check(signers, Withdrawer): signer set must contain the current withdrawer.
        if (!signerSetContains(ctx, frame, withdrawer))
            return error.M9_Stake_MissingRequiredSignature;
        @memcpy(stake.data[STAKE_OFF_WITHDRAWER..][0..32], new_authority);
    }
}

// ── AuthorizeChecked (tag 10) — canonical Agave v5 stake `AuthorizeChecked` ──
//
// CARRIER-CLASS FIX (predicted recurrence of the Authorize(tag1, slot 415547068)
// and Deactivate(tag5, slot 415214214) stub carriers): the first time any BPF
// program CPIs Stake AuthorizeChecked, the `M9_Stake_VariantPending_AuthorizeChecked`
// stub → M7_BuiltinFailed → outer tx M4_RunFailed → dropped staker/withdrawer write
// → accounts_lt_hash poison → bank_hash divergence. Closing the stub pre-empts it.
//
// Identical to Authorize (tag 1) EXCEPT three Checked deltas:
//   • new_authority = accounts[3].pubkey (NOT in ix data),
//   • that account[3] MUST be a signer — canonical INDEX-3 `is_signer` check
//     (this is what makes the variant "Checked"; it is NOT a signer-SET scan),
//   • custodian is at instruction account index 4 (NOT 3),
//   • requires >=4 accounts.
// ix data = u32 tag(10) + u32 authorize_type (0=Staker,1=Withdrawer) = 8 bytes.
//
// @prov:stake-builtin.authorize-checked — byte-identical in Sig; FD = Core-BPF
// by construction (no native FD processor). v4 == v5 for this arm (SIMD-0490
// min-delegation touches only Split/MoveStake; SIMD-0118 EpochRewards gate applies).
// Mirrors executeAuthorize exactly for the shared `authorize()` body: signer-SET
// scan of staker/withdrawer (never index-N), lockup-block FIRST (Agave order),
// in-place same-length mutation (NO bank.collectWrite — cpi.zig propagates the
// change, replay content-detects it).
//
// ⚠ The top-level native handleAuthorizeChecked (vex_svm/native/stake_program.zig
// :1552) is NOT used by this CPI path and has the index-2 OLD-auth eql + emitWrite +
// alloc-copy bugs — do NOT copy it. Its index-3 NEW-auth signer check (line 1566)
// IS canonical and is what this handler does below.
fn executeAuthorizeChecked(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // ix data: u32 tag(10) + u32 authorize_type (0=Staker,1=Withdrawer) = 8 bytes.
    if (ix_data.len < 8) return error.M9_Stake_InvalidInstructionData;
    const authorize_type = std.mem.readInt(u32, ix_data[4..8], .little);
    if (authorize_type > 1) return error.M9_Stake_InvalidInstructionData;

    // SIMD-0118 EpochRewardsActive gate (blocks all stake ix except GetMinimumDelegation
    // during the partitioned reward window). Guarded — sysvar absent ⇒ no gate (safe).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // >=4 accounts: [0] stake[W], [1] Clock, [2] old auth[S], [3] new auth[S], [4] custodian opt.
    if (frame.account_indices.len < 4) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    const new_idx = frame.account_indices[3];
    if (stake_idx >= ctx.tx.accounts.len or new_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;

    // Canonical INDEX-3 signer check on the NEW authority (the "Checked" delta vs tag 1).
    if (!ctx.tx.accounts[new_idx].is_signer) return error.M9_Stake_MissingRequiredSignature;
    const new_authority = &ctx.tx.accounts[new_idx].pubkey;

    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    // get_stake_account: owner must be the stake program (else InvalidAccountOwner).
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    // State must be Initialized(1) or Stake(2) — both touch only Meta.authorized.
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_INITIALIZED and disc != STAKE_DISC_STAKE)
        return error.M9_Stake_InvalidAccountData;

    const staker = stake.data[STAKE_OFF_STAKER..][0..32];
    const withdrawer = stake.data[STAKE_OFF_WITHDRAWER..][0..32];

    if (authorize_type == 0) {
        // StakeAuthorize::Staker — signer set must contain the current staker OR withdrawer.
        if (!signerSetContains(ctx, frame, staker) and !signerSetContains(ctx, frame, withdrawer))
            return error.M9_Stake_MissingRequiredSignature;
        @memcpy(stake.data[STAKE_OFF_STAKER..][0..32], new_authority);
    } else {
        // StakeAuthorize::Withdrawer — lockup block FIRST (Agave order), then withdrawer sig.
        const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
        const lk_ts = std.mem.readInt(i64, stake.data[STAKE_OFF_LOCKUP_TS..][0..8], .little);
        const lk_epoch = std.mem.readInt(u64, stake.data[STAKE_OFF_LOCKUP_EPOCH..][0..8], .little);
        const lk_custodian = stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32];

        // Lockup::is_in_force(clock, None): no custodian bypass.
        if (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch) {
            // custodian = optional pubkey at instruction account index 4 for Checked (NOT 3).
            if (frame.account_indices.len <= 4) return error.M9_Stake_CustodianMissing;
            const cust_idx = frame.account_indices[4];
            if (cust_idx >= ctx.tx.accounts.len) return error.M9_Stake_CustodianMissing;
            const custodian = &ctx.tx.accounts[cust_idx].pubkey;
            if (!signerSetContains(ctx, frame, custodian))
                return error.M9_Stake_CustodianSignatureMissing;
            // is_in_force(clock, Some(custodian)): bypass iff custodian == lockup.custodian.
            const bypass = std.mem.eql(u8, custodian, lk_custodian);
            if (!bypass and (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch))
                return error.M9_Stake_LockupInForce;
        }
        // check(signers, Withdrawer): signer set must contain the current withdrawer.
        if (!signerSetContains(ctx, frame, withdrawer))
            return error.M9_Stake_MissingRequiredSignature;
        @memcpy(stake.data[STAKE_OFF_WITHDRAWER..][0..32], new_authority);
    }
}

// ── AuthorizeWithSeed (tag 8) — canonical Agave v5 stake `AuthorizeWithSeed` ─
//
// CARRIER-CLASS FIX (predicted recurrence of the Authorize(tag1, slot 415547068),
// AuthorizeChecked(tag10) and Deactivate(tag5, slot 415214214) stub carriers): the
// first time any BPF program CPIs Stake AuthorizeWithSeed, the
// `M9_Stake_VariantPending_AuthorizeWithSeed` stub → M7_BuiltinFailed → outer tx
// M4_RunFailed → dropped staker/withdrawer write → accounts_lt_hash poison →
// bank_hash divergence. Closing the stub pre-empts it. (Stake-pool / derived-account
// protocols use AuthorizeWithSeed to rotate a stake authority that is itself a
// create_with_seed address — common on testnet.)
//
// SEMANTIC: derive an authority pubkey D = SHA256(base | seed | owner) from the
// base account at instruction index 1 (ONLY if that account signed), then run the
// EXACT Authorize (tag 1) core with a single-element signer set {D} (empty if base
// did not sign). It is NOT a signer-SET scan over the frame — the signing authority
// is exactly {D}. This is the one tag-8-specific divergence from executeAuthorize.
//
// Accounts: [0] stake [WRITE], [1] base [SIGNER], [2] Clock, [3] custodian (OPTIONAL).
// NB the account layout differs from tag 1 ([stake, Clock@1, authority@2, cust@3]):
// here base is @1, Clock is @2. Vexor reads Clock from the sysvar_cache (not the
// account), so the only index that matters for the custodian is index 3 — SAME as
// tag 1 (Sig getOptionalPubkey(ic, 3, false)).
//
// ix data (bincode, LE): u32 tag(8) + [32] new_authorized_pubkey + u32 stake_authorize
//   (0=Staker,1=Withdrawer) + u64 seed_len + [seed_len] seed + [32] authority_owner.
//   StakeAuthorize is a fieldless Rust enum → bincode u32 (same as tag 1's
//   authorize_type @36, cross-validated). authority_seed uses SEED_FIELD_CONFIG =
//   utf8StringCodec → u64 length prefix. Min length = 48 + 0 + 32 = 80 (empty seed).
//   @prov:stake-builtin.authorize-with-seed — AuthorizeWithSeedArgs field order.
//
// @prov:stake-builtin.authorize-with-seed — createWithSeed = SHA256(base|seed|owner)
// (byte-faithful to Agave; carrier #12 proved this exact derivation @414674115).
// FD = Core-BPF (no native FD processor). v4 == v5 for tag 8
// (SIMD-0490 min-delegation touches only Split/MoveStake; SIMD-0118 EpochRewards
// gate applies).
//
// ⚠ Do NOT copy the top-level native handleAuthorizeWithSeed (vex_svm/native/
// stake_program.zig:1477) — it is a pure STUB (log line only). The derive helper
// below mirrors system_program.zig:519 verifySeedAddress, but RETURNS the hash
// instead of comparing it (single source of truth for the SHA256 path).

const PDA_MARKER = "ProgramDerivedAddress"; // 21 bytes (create_program_address only)

/// Canonical `create_with_seed(base, seed, owner)` = SHA256(base | seed | owner).
/// Returns null on the two reject conditions (caller maps to a typed M9 error that
/// folds to M7 — pass/fail boundary is what matters):
///   • seed.len > 32  → MaxSeedLenExceeded (Custom 0)
///   • owner ends with the 21-byte PDA marker → IllegalOwner (Custom 2)
/// Mirrors system_program.zig:519 verifySeedAddress (carrier #12-proven byte-exact)
/// but returns the derived key rather than comparing it.
///
/// `pub` (2026-07-11, P0-2 fix): reused verbatim by the native top-level
/// AuthorizeWithSeed/AuthorizeCheckedWithSeed handlers
/// (vex_svm/native/stake_program.zig) — single source of truth for the
/// create_with_seed derivation rather than a second hand-copied SHA256 call,
/// per canonical-refactor-over-point-patches.
pub fn deriveWithSeed(base: []const u8, seed: []const u8, owner: []const u8) ?[32]u8 {
    if (seed.len > 32) return null; // MaxSeedLenExceeded
    if (std.mem.eql(u8, owner[11..32], PDA_MARKER)) return null; // IllegalOwner
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(base);
    h.update(seed);
    h.update(owner);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn executeAuthorizeWithSeed(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // Parse the bincode wire layout. @prov:stake-builtin.authorize-with-seed
    // tag(4)+new_auth[32]+u32 type+u64 seed_len+seed+owner[32].
    const IX_OFF_NEW_AUTH: usize = 4; // [32] new_authorized_pubkey
    const IX_OFF_TYPE: usize = 36; // u32 stake_authorize
    const IX_OFF_SEED_LEN: usize = 40; // u64 seed length prefix
    const IX_OFF_SEED: usize = 48; // seed bytes start
    if (ix_data.len < IX_OFF_SEED) return error.M9_Stake_InvalidInstructionData;
    const new_authority = ix_data[IX_OFF_NEW_AUTH..][0..32];
    const authorize_type = std.mem.readInt(u32, ix_data[IX_OFF_TYPE..][0..4], .little);
    if (authorize_type > 1) return error.M9_Stake_InvalidInstructionData;
    const seed_len = std.mem.readInt(u64, ix_data[IX_OFF_SEED_LEN..][0..8], .little);
    if (seed_len > 32) return error.M9_Stake_InvalidInstructionData; // MaxSeedLenExceeded
    const seed_end = IX_OFF_SEED + @as(usize, @intCast(seed_len));
    if (ix_data.len < seed_end + 32) return error.M9_Stake_InvalidInstructionData;
    const seed = ix_data[IX_OFF_SEED..seed_end];
    const authority_owner = ix_data[seed_end..][0..32];

    // SIMD-0118 EpochRewardsActive gate: blocks all stake ix (except GetMinimumDelegation)
    // during the partitioned reward window. Guarded — sysvar absent ⇒ no gate (safe).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // checkNumberOfAccounts(2): [0] stake [W], [1] base [SIGNER], ([2] Clock, [3] custodian).
    if (frame.account_indices.len < 2) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    if (stake_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    // get_stake_account: owner must be the stake program (else InvalidAccountOwner).
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    // State must be Initialized(1) or Stake(2) — both touch only Meta.authorized.
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_INITIALIZED and disc != STAKE_DISC_STAKE)
        return error.M9_Stake_InvalidAccountData;

    // Build the single-element signer set {D}: derive D ONLY if the base account
    // (instruction index 1) signed (Sig lib.zig:568). Otherwise the signer set is
    // EMPTY → every authorize check below fails with MissingRequiredSignature.
    var derived: ?[32]u8 = null;
    const base_idx = frame.account_indices[1];
    if (base_idx < ctx.tx.accounts.len and ctx.tx.accounts[base_idx].is_signer) {
        derived = deriveWithSeed(&ctx.tx.accounts[base_idx].pubkey, seed, authority_owner) orelse
            return error.M9_Stake_InvalidArgument; // MaxSeedLenExceeded / IllegalOwner (Custom; folds M7)
    }
    // dsig = the (only) signer in the set, or null if base did not sign.
    const dsig: ?[]const u8 = if (derived) |*d| d[0..32] else null;

    const staker = stake.data[STAKE_OFF_STAKER..][0..32];
    const withdrawer = stake.data[STAKE_OFF_WITHDRAWER..][0..32];

    if (authorize_type == 0) {
        // StakeAuthorize::Staker — signer set {D} must contain staker OR withdrawer
        // (state.zig:147-152). With a 1-element set this is a direct eql against D.
        const ok = dsig != null and (std.mem.eql(u8, dsig.?, staker) or std.mem.eql(u8, dsig.?, withdrawer));
        if (!ok) return error.M9_Stake_MissingRequiredSignature;
        @memcpy(stake.data[STAKE_OFF_STAKER..][0..32], new_authority);
    } else {
        // StakeAuthorize::Withdrawer — lockup block FIRST (state.zig:156-171), then
        // the withdrawer-signature check (check(signers, Withdrawer)).
        const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
        const lk_ts = std.mem.readInt(i64, stake.data[STAKE_OFF_LOCKUP_TS..][0..8], .little);
        const lk_epoch = std.mem.readInt(u64, stake.data[STAKE_OFF_LOCKUP_EPOCH..][0..8], .little);
        const lk_custodian = stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32];

        // Lockup::is_in_force(clock, None): no custodian bypass.
        if (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch) {
            // custodian = optional pubkey at instruction account index 3 (Sig
            // getOptionalPubkey(ic, 3, false) — signer NOT required at fetch).
            if (frame.account_indices.len <= 3) return error.M9_Stake_CustodianMissing;
            const cust_idx = frame.account_indices[3];
            if (cust_idx >= ctx.tx.accounts.len) return error.M9_Stake_CustodianMissing;
            const custodian = &ctx.tx.accounts[cust_idx].pubkey;
            // has_custodian_signer over signers={D}: custodian counts iff custodian == D
            // (state.zig:163-165). NOT a frame signer-set scan.
            const cust_signed = dsig != null and std.mem.eql(u8, dsig.?, custodian);
            if (!cust_signed) return error.M9_Stake_CustodianSignatureMissing;
            // is_in_force(clock, Some(custodian)): bypass iff custodian == lockup.custodian.
            const bypass = std.mem.eql(u8, custodian, lk_custodian);
            if (!bypass and (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch))
                return error.M9_Stake_LockupInForce;
        }
        // check(signers={D}, Withdrawer): D must equal the current withdrawer.
        const ok = dsig != null and std.mem.eql(u8, dsig.?, withdrawer);
        if (!ok) return error.M9_Stake_MissingRequiredSignature;
        @memcpy(stake.data[STAKE_OFF_WITHDRAWER..][0..32], new_authority);
    }
}

// ── AuthorizeCheckedWithSeed (tag 11) — canonical Agave v5 `AuthorizeCheckedWithSeed`
//
// CARRIER-CLASS FIX (predicted recurrence of the Authorize(tag1, slot 415547068),
// AuthorizeChecked(tag10), AuthorizeWithSeed(tag8) and Deactivate(tag5, slot
// 415214214) stub carriers): the first time any BPF program CPIs Stake
// AuthorizeCheckedWithSeed, the `M9_Stake_VariantPending_AuthorizeCheckedWithSeed`
// stub → M7_BuiltinFailed → outer tx M4_RunFailed → dropped staker/withdrawer write
// → accounts_lt_hash poison → bank_hash divergence. Closing the stub pre-empts it.
//
// This is tag 8 (AuthorizeWithSeed) + the "Checked" delta. Identical seed-derive
// single-element-signer-set semantics; the ONLY differences:
//   • new_authority = accounts[3].pubkey (NOT in ix data — that account MUST sign),
//   • >=4 accounts required (tag 8 = 2),
//   • custodian is at instruction account index 4 (tag 8 = 3),
//   • ix data carries NO new_authorized_pubkey; field order is stake_authorize FIRST.
// Base seed authority stays at instruction index 1 (same as tag 8).
//
// Accounts: [0] stake [WRITE], [1] base [SIGNER→D], [2] Clock, [3] new authority
// [SIGNER], [4] custodian (OPTIONAL). Vexor reads Clock from sysvar_cache (not the
// account); the new-authority signer check is a canonical INDEX-3 `is_signer` (this
// is the "Checked" delta), done BEFORE the old-authority checks. @prov:stake-builtin.authorize-checked-with-seed
//
// ix data (bincode, LE): u32 tag(11) + u32 stake_authorize (0=Staker,1=Withdrawer)
//   + u64 seed_len + [seed_len] seed + [32] authority_owner.
//   AuthorizeCheckedWithSeedArgs field order = {stake_authorize, authority_seed,
//   authority_owner} — stake_authorize FIRST, unlike
//   tag 8's AuthorizeWithSeedArgs which leads with new_authorized_pubkey. seed uses
//   SEED_FIELD_CONFIG = u64 length prefix. Min length = 16 + 0 + 32 = 48 (empty seed).
//
// @prov:stake-builtin.authorize-checked-with-seed — deriveWithSeed = SHA256(base|seed|owner)
// (carrier #12-proven). FD = Core-BPF (no native FD processor). v4 == v5 for tag 11
// (SIMD-0490 min-delegation touches only Split/MoveStake; SIMD-0118 EpochRewards gate
// applies).
//
// ⚠ Do NOT copy the top-level native handleAuthorizeCheckedWithSeed (vex_svm/native/
// stake_program.zig:1617) — it is a pure STUB ("not yet implemented" log, no mutation).
// Mirrors executeAuthorizeWithSeed exactly for the shared seed-derive + authorize body;
// the single load-bearing difference is the new authority + INDEX-3 signer check above.
fn executeAuthorizeCheckedWithSeed(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // Parse the bincode wire layout (field order = stake_authorize FIRST):
    // tag(4)+u32 type+u64 seed_len+seed+owner[32]. @prov:stake-builtin.authorize-checked-with-seed
    const IX_OFF_TYPE: usize = 4; // u32 stake_authorize
    const IX_OFF_SEED_LEN: usize = 8; // u64 seed length prefix
    const IX_OFF_SEED: usize = 16; // seed bytes start
    if (ix_data.len < IX_OFF_SEED) return error.M9_Stake_InvalidInstructionData;
    const authorize_type = std.mem.readInt(u32, ix_data[IX_OFF_TYPE..][0..4], .little);
    if (authorize_type > 1) return error.M9_Stake_InvalidInstructionData;
    const seed_len = std.mem.readInt(u64, ix_data[IX_OFF_SEED_LEN..][0..8], .little);
    if (seed_len > 32) return error.M9_Stake_InvalidInstructionData; // MaxSeedLenExceeded
    const seed_end = IX_OFF_SEED + @as(usize, @intCast(seed_len));
    if (ix_data.len < seed_end + 32) return error.M9_Stake_InvalidInstructionData;
    const seed = ix_data[IX_OFF_SEED..seed_end];
    const authority_owner = ix_data[seed_end..][0..32];

    // SIMD-0118 EpochRewardsActive gate: blocks all stake ix (except GetMinimumDelegation)
    // during the partitioned reward window. Guarded — sysvar absent ⇒ no gate (safe).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // checkNumberOfAccounts(4): [0] stake[W], [1] base[S], [2] Clock, [3] new auth[S], [4] custodian opt.
    if (frame.account_indices.len < 4) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    const new_idx = frame.account_indices[3];
    if (stake_idx >= ctx.tx.accounts.len or new_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;

    // new authority = accounts[3].pubkey; that account MUST sign (the "Checked" delta;
    // canonical INDEX-3 signer check, BEFORE the old-authority checks — Sig lib.zig:327).
    if (!ctx.tx.accounts[new_idx].is_signer) return error.M9_Stake_MissingRequiredSignature;
    const new_authority = &ctx.tx.accounts[new_idx].pubkey;

    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    // get_stake_account: owner must be the stake program (else InvalidAccountOwner).
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    // State must be Initialized(1) or Stake(2) — both touch only Meta.authorized.
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_INITIALIZED and disc != STAKE_DISC_STAKE)
        return error.M9_Stake_InvalidAccountData;

    // Build the single-element signer set {D}: derive D ONLY if the base account
    // (instruction index 1) signed (Sig lib.zig:568). Otherwise the set is EMPTY →
    // every authorize check below fails with MissingRequiredSignature.
    var derived: ?[32]u8 = null;
    const base_idx = frame.account_indices[1];
    if (base_idx < ctx.tx.accounts.len and ctx.tx.accounts[base_idx].is_signer) {
        derived = deriveWithSeed(&ctx.tx.accounts[base_idx].pubkey, seed, authority_owner) orelse
            return error.M9_Stake_InvalidArgument; // MaxSeedLenExceeded / IllegalOwner (Custom; folds M7)
    }
    // dsig = the (only) signer in the set, or null if base did not sign.
    const dsig: ?[]const u8 = if (derived) |*d| d[0..32] else null;

    const staker = stake.data[STAKE_OFF_STAKER..][0..32];
    const withdrawer = stake.data[STAKE_OFF_WITHDRAWER..][0..32];

    if (authorize_type == 0) {
        // StakeAuthorize::Staker — signer set {D} must contain staker OR withdrawer
        // (state.zig:147-152). With a 1-element set this is a direct eql against D.
        const ok = dsig != null and (std.mem.eql(u8, dsig.?, staker) or std.mem.eql(u8, dsig.?, withdrawer));
        if (!ok) return error.M9_Stake_MissingRequiredSignature;
        @memcpy(stake.data[STAKE_OFF_STAKER..][0..32], new_authority);
    } else {
        // StakeAuthorize::Withdrawer — lockup block FIRST (state.zig:156-171), then
        // the withdrawer-signature check (check(signers, Withdrawer)).
        const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
        const lk_ts = std.mem.readInt(i64, stake.data[STAKE_OFF_LOCKUP_TS..][0..8], .little);
        const lk_epoch = std.mem.readInt(u64, stake.data[STAKE_OFF_LOCKUP_EPOCH..][0..8], .little);
        const lk_custodian = stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32];

        // Lockup::is_in_force(clock, None): no custodian bypass.
        if (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch) {
            // custodian = optional pubkey at instruction account index 4 for the Checked
            // variant (Sig getOptionalPubkey(ic, 4, false) — signer NOT required at fetch).
            if (frame.account_indices.len <= 4) return error.M9_Stake_CustodianMissing;
            const cust_idx = frame.account_indices[4];
            if (cust_idx >= ctx.tx.accounts.len) return error.M9_Stake_CustodianMissing;
            const custodian = &ctx.tx.accounts[cust_idx].pubkey;
            // has_custodian_signer over signers={D}: custodian counts iff custodian == D
            // (state.zig:163-165). NOT a frame signer-set scan.
            const cust_signed = dsig != null and std.mem.eql(u8, dsig.?, custodian);
            if (!cust_signed) return error.M9_Stake_CustodianSignatureMissing;
            // is_in_force(clock, Some(custodian)): bypass iff custodian == lockup.custodian.
            const bypass = std.mem.eql(u8, custodian, lk_custodian);
            if (!bypass and (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch))
                return error.M9_Stake_LockupInForce;
        }
        // check(signers={D}, Withdrawer): D must equal the current withdrawer.
        const ok = dsig != null and std.mem.eql(u8, dsig.?, withdrawer);
        if (!ok) return error.M9_Stake_MissingRequiredSignature;
        @memcpy(stake.data[STAKE_OFF_WITHDRAWER..][0..32], new_authority);
    }
}

// ── Deactivate (tag 5) — canonical Agave stake `deactivate` ─────────────────
//
// CARRIER FIX (2026-06-14, divergence onset testnet slot 415214214): a BPF
// program (SPL Stake Pool `RemoveValidatorFromPool`) CPIs into Stake Deactivate.
// The cluster executes it; Vexor hit this stub → M7_BuiltinFailed → the outer tx
// M4_RunFailed → the stake account's deactivation write was dropped →
// accounts_lt_hash poison → bank_hash divergence → delinquency. Latent since the
// M9 builtin skeleton (2026-04-25); only this CPI path was stubbed (the top-level
// native handler vex_svm/native/stake_program.zig:handleDeactivate is real).
//
// @prov:stake-builtin.deactivate — FD has no native stake processor post-SIMD-0490,
// relies on the same Core-BPF behavior, which is byte-preserving for Deactivate:
//   accounts: [0] stake [WRITE], [1] Clock sysvar, [2] stake authority [SIGNER]
//   1. state must be StakeStateV2::Stake → else InvalidAccountData
//   2. Authorized::check(signers, Staker): staker pubkey ∈ instruction signer set
//      → else MissingRequiredSignature
//   3. Stake::deactivate(clock.epoch): deactivation_epoch != u64::MAX →
//      StakeError::AlreadyDeactivated (Custom 2); else deactivation_epoch = epoch
//
// CPI-native (InvokeContext) port, mirroring builtins/system_program.zig: mutate
// `ctx.tx.accounts[stake_idx].data` IN PLACE (same length). NO bank.collectWrite /
// accountLtHash here (those are top-level-native-only and Bank is not in scope in
// the CPI path). The commit chain is proven: cpi.zig propagates the same-length
// change to caller memory, and replay_stage.zig content-detects it (old_datas is
// an alloc.dupe copy; the gate compares bytes, not just length — the durable-nonce
// carrier fix made this exact in-place-same-length shape commit correctly).
fn executeDeactivate(ctx: *InvokeContext) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // Canonical account refs: stake[0], Clock[1], staker[2].
    if (frame.account_indices.len < 3) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    if (stake_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;

    // State must be Stake(2) (a delegated stake) — else InvalidAccountData.
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_STAKE) return error.M9_Stake_InvalidAccountData;

    // Authorized::check — the staker pubkey must be among the instruction's
    // signing accounts (Agave set-scan; not an index hardcode).
    const staker = stake.data[STAKE_OFF_STAKER..][0..32];
    var staker_signed = false;
    for (frame.account_indices) |aidx| {
        if (aidx >= ctx.tx.accounts.len) continue;
        const a = &ctx.tx.accounts[aidx];
        if (a.is_signer and std.mem.eql(u8, &a.pubkey, staker)) {
            staker_signed = true;
            break;
        }
    }
    if (!staker_signed) return error.M9_Stake_MissingRequiredSignature;

    // Already-deactivating guard — Agave StakeError::AlreadyDeactivated (Custom 2).
    const cur_deact = std.mem.readInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
    if (cur_deact != std.math.maxInt(u64)) return error.M9_Stake_AlreadyDeactivated;

    // Set deactivation_epoch = clock.epoch (canonical epoch source = Clock sysvar).
    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
    std.mem.writeInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], clock.epoch, .little);
}

// ── Stake activation/deactivation curve (ported from vex_svm/bank.zig) ──────
//
// MODULE-BOUNDARY NOTE: vex_bpf2 cannot @import vex_svm. This block is a VERBATIM
// port of Bank.getStakeActivationStatus + lookupHistory + warmupCooldownRate
// (vex_svm/bank.zig:2015-2255), proven v5-correct (carrier #16). The float math
// (warmup @intFromFloat, cooldown lossyCast, @max(_,1), saturating sub, base =
// e.effective only) is preserved EXACTLY — any drift here is a silent bank_hash
// carrier. `history` is typed as the bpf2 SysvarCache StakeHistoryEntry (extern
// struct with the same {epoch,effective,activating,deactivating} u64 fields in
// the same order — confirmed sysvar_cache.zig:226), so no second struct/copy.
//
// new_rate_activation_epoch: the native curve passes
// Bank.getNewRateActivationEpoch() = epoch of REDUCE_STAKE_WARMUP_COOLDOWN
// (testnet epoch 586, activated long ago). vex_bpf2 has no accounts_db handle to
// read that feature account, so we pass 0 (the always-9% sentinel). This is
// BYTE-EQUIVALENT for all live txs: warmupCooldownRate(epoch+1, 586) = 0.09 for
// every epoch+1 >= 586, and the current epoch (~974) plus the ~11-epoch cooldown
// window is far past 586, so no live warmup/cooldown loop ever evaluates an epoch
// < 586 → the 0.25 path is unreachable; 0 and 586 produce identical rates. (TODO:
// if ctx ever exposes the activation epoch, swap it in.)
const StakeActivationStatus = struct {
    effective: u64,
    activating: u64,
    deactivating: u64,
};

fn lookupHistory(history: []const StakeHistoryEntry, epoch: u64) ?StakeHistoryEntry {
    for (history) |e| {
        if (e.epoch == epoch) return e;
    }
    return null;
}

fn warmupCooldownRate(current_epoch: u64, new_rate_activation_epoch: u64) f64 {
    return if (new_rate_activation_epoch != 0 and current_epoch < new_rate_activation_epoch) 0.25 else 0.09;
}

fn getStakeActivationStatus(
    activation_epoch: u64,
    deactivation_epoch: u64,
    stake: u64,
    target_epoch: u64,
    history: []const StakeHistoryEntry,
    new_rate_activation_epoch: u64,
) StakeActivationStatus {
    var current_effective: u64 = 0;
    if (activation_epoch == std.math.maxInt(u64)) {
        current_effective = stake;
    } else {
        if (activation_epoch == deactivation_epoch) {
            return .{ .effective = 0, .activating = 0, .deactivating = 0 };
        }
        if (target_epoch < activation_epoch) {
            return .{ .effective = 0, .activating = 0, .deactivating = 0 };
        }
        if (target_epoch == activation_epoch) {
            return .{ .effective = 0, .activating = stake, .deactivating = 0 };
        }

        var epoch = activation_epoch;
        const warmup_end = @min(target_epoch, deactivation_epoch);
        while (epoch < warmup_end) : (epoch += 1) {
            const entry = lookupHistory(history, epoch);
            if (entry) |e| {
                if (e.activating == 0) {
                    current_effective = stake;
                    break;
                }
                const remaining = stake - current_effective;
                const weight: f64 = @as(f64, @floatFromInt(remaining)) /
                    @as(f64, @floatFromInt(e.activating));
                const newly_effective_cluster: f64 = @as(f64, @floatFromInt(e.effective)) * warmupCooldownRate(epoch + 1, new_rate_activation_epoch);
                const newly_effective: u64 = @max(@as(u64, @intFromFloat(weight * newly_effective_cluster)), 1);
                current_effective += newly_effective;
                if (current_effective >= stake) {
                    current_effective = stake;
                    break;
                }
            } else {
                if (epoch == activation_epoch) {
                    current_effective = stake;
                }
                break;
            }
        }
    }
    current_effective = @min(current_effective, stake);

    if (target_epoch < deactivation_epoch) {
        return .{
            .effective = current_effective,
            .activating = stake - current_effective,
            .deactivating = 0,
        };
    }

    if (target_epoch == deactivation_epoch) {
        return .{
            .effective = current_effective,
            .activating = 0,
            .deactivating = current_effective,
        };
    }

    const deact_entry = lookupHistory(history, deactivation_epoch);
    if (deact_entry == null) {
        return .{ .effective = 0, .activating = 0, .deactivating = 0 };
    }

    var remaining_eff = current_effective;
    var cool_epoch = deactivation_epoch;
    while (cool_epoch < target_epoch) : (cool_epoch += 1) {
        const entry = lookupHistory(history, cool_epoch);
        if (entry) |e| {
            if (e.deactivating == 0) {
                remaining_eff = 0;
                break;
            }
            const weight: f64 = @as(f64, @floatFromInt(remaining_eff)) /
                @as(f64, @floatFromInt(e.deactivating));
            const newly_not_effective_cluster: f64 = @as(f64, @floatFromInt(e.effective)) * warmupCooldownRate(cool_epoch + 1, new_rate_activation_epoch);
            const newly_not_effective: u64 = @max(1, std.math.lossyCast(u64, weight * newly_not_effective_cluster));
            remaining_eff -|= newly_not_effective;
            if (remaining_eff == 0) break;
        } else {
            break;
        }
    }

    return .{
        .effective = remaining_eff,
        .activating = 0,
        .deactivating = remaining_eff,
    };
}

/// Fetch the live StakeHistory entries from the sysvar cache; empty slice if the
/// sysvar is absent (mirrors native's `catch &[_]...{}`). In production the
/// bpf2 SysvarCache is populated via bank_sysvar_adapter.getStakeHistoryBytes,
/// which returns the real on-chain StakeHistory account bytes.
fn stakeHistory(ctx: *InvokeContext) []const StakeHistoryEntry {
    const sh = ctx.sysvar_cache.getStakeHistory() catch return &.{};
    return sh.entries;
}

/// Canonical `Lockup::is_in_force(clock, custodian)`:
///   in force iff (lockup.unix_timestamp > clock.unix_timestamp OR
///                 lockup.epoch > clock.epoch), with a custodian bypass iff the
///   supplied (signed) custodian key == lockup.custodian.
fn lockupInForce(data: []const u8, clock: anytype, signed_custodian: ?[]const u8) bool {
    const lk_ts = std.mem.readInt(i64, data[STAKE_OFF_LOCKUP_TS..][0..8], .little);
    const lk_epoch = std.mem.readInt(u64, data[STAKE_OFF_LOCKUP_EPOCH..][0..8], .little);
    if (signed_custodian) |c| {
        const lk_custodian = data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32];
        if (std.mem.eql(u8, c, lk_custodian)) return false; // custodian bypass
    }
    return lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch;
}

/// MergeKind classifier (get_if_mergeable) using the activation curve.
/// Returns 0=Inactive, 1=ActivationEpoch, 2=FullyActive, 0xFF=reject(transient).
/// Initialized(1) → Inactive(0). Uninitialized/other → 0xFE (InvalidAccountData).
fn getMergeKind(data: []const u8, target_epoch: u64, history: []const StakeHistoryEntry) u8 {
    const disc = std.mem.readInt(u32, data[0..4], .little);
    if (disc == STAKE_DISC_INITIALIZED) return 0; // Initialized = inactive
    if (disc != STAKE_DISC_STAKE) return 0xFE; // Uninitialized/RewardsPool → InvalidAccountData

    const activation_epoch = std.mem.readInt(u64, data[STAKE_OFF_ACTIVATION_EPOCH..][0..8], .little);
    const deactivation_epoch = std.mem.readInt(u64, data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
    const delegation_stake = std.mem.readInt(u64, data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);

    const status = getStakeActivationStatus(
        activation_epoch,
        deactivation_epoch,
        delegation_stake,
        target_epoch,
        history,
        0, // new_rate_activation_epoch sentinel — see curve port note
    );

    // (0,0,0) = fully deactivated = inactive
    if (status.effective == 0 and status.activating == 0 and status.deactivating == 0) return 0;
    // (0,_,_) = at activation epoch = activating
    if (status.effective == 0) return 1;
    // (>0,0,0) = fully active
    if (status.activating == 0 and status.deactivating == 0) return 2;
    // transient (partially warming/cooling) = unmergeable
    return 0xFF;
}

/// Weighted average of credits_observed (stake_weighted_credits_observed), u128,
/// ceiling-rounded. EXACT canonical form; returns null on overflow / total==0.
fn weightedCreditsObserved(
    stake_credits: u64,
    stake_amount: u64,
    absorbed_credits: u64,
    absorbed_amount: u64,
) ?u64 {
    if (stake_credits == absorbed_credits) return stake_credits;
    const total_stake: u128 = @as(u128, stake_amount) + @as(u128, absorbed_amount);
    if (total_stake == 0) return null;
    var numerator: u128 = @as(u128, stake_credits) * @as(u128, stake_amount) +
        @as(u128, absorbed_credits) * @as(u128, absorbed_amount);
    numerator += total_stake; // ceiling adjustment
    numerator -= 1;
    const result = numerator / total_stake;
    if (result > std.math.maxInt(u64)) return null;
    return @as(u64, @truncate(result));
}

// ── Merge (tag 7) — canonical BPF stake v5 (SIMD-0490 active testnet) ───────
//
// Accounts: [0] dst [WRITE], [1] src [WRITE], [2] Clock, [3] StakeHistory,
//           [4] staker authority [SIGNER]. ix data = u32 tag(7) only.
//
// Mirrors executeAuthorize/executeDeactivate (typed errors, signer-SET scan,
// in-place same-length mutation, NO bank.collectWrite — cpi.zig propagates the
// in-place lamports+data change to caller memory, replay content-detects it).
//
// v5 LOGIC ported from native handleMerge (vex_svm/native/stake_program.zig:1311)
// with its CPI bugs FIXED: (a) signer = signerSetContains(dst.staker) over ALL
// frame signers, NOT index-4 hardcode; (b) FullyActive arm requires BOTH
// deact==MAX (native:1435 already correct — PRESERVED, contra the task note);
// (c) EpochRewards gate added; (e) source drain writes ONLY u32 disc=0 (offset 0)
// and PRESERVES the tail 4..200 (native's @memset(0,200) is the bug — same class
// as the VoterWithBLS stale-tail carrier).
// ── SetLockup (tag 6) — canonical `Meta::set_lockup` (v4 == v5; pure lockup mutation) ──
//
// @prov:stake-builtin.set-lockup — Sig and Agave agree fully; FD
// post-SIMD-0490 runs the same v5 .so. SetLockup is a pure `Meta.lockup` field
// mutation, UNCHANGED across v4↔v5 — no min-delegation, no SIMD-0490 math.
//
// Accounts: [0] stake [WRITE, owner == Stake program]; [1] authority [SIGNER]
// checked via the signer-SET scan (NEVER index-1). Clock comes from
// ctx.sysvar_cache (NOT an instruction account index). ix data = u32 tag(6) +
// 3 × bincode Option<{i64 ts, u64 epoch, [32] custodian}>. In force →
// custodian ∈ signers; expired → withdrawer ∈ signers (isInForce custodian=null,
// NO bypass — the custodian here is the signer being checked, not a bypass key).
// Apply only the Some fields, in place, same length (byte-equivalent to Agave's
// full serialize_into, which rewrites every non-lockup field byte-identically).
//
// ⚠ Do NOT copy the top-level native handleSetLockup (vex_svm/native/
// stake_program.zig:1176) — it has 6 wrapper bugs: (1) index-1 signer + eql,
// NOT a signer-SET scan; (2) NO SIMD-0118 EpochRewards gate; (3) NO owner ==
// Stake-program check; (4) bespoke non-canonical isLockupActive instead of
// isInForce(_, null); (5) silent `return` on every rejection (swallows the
// pass/fail boundary as tx-success); (6) deep-copy + emitWrite, wrong for the CPI
// path. This port follows Agave/Sig order exactly, mirroring executeAuthorize/
// executeMerge (typed errors, in-place same-length mutation, NO bank.collectWrite —
// cpi.zig propagates the in-place change to caller memory, replay content-detects
// it). The native handler's bugs are a separate LATENT top-level fix — flagged
// (footgun comment at native:1176), not fixed here.
fn executeSetLockup(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;

    // Parse LockupArgs: u32 tag(6) + 3 × Option (u8 present-tag + payload).
    // (Parse FIRST, then gate — matches Agave order limited_deserialize? → gate,
    // and the landed executeAuthorize/executeInitialize idiom.)
    if (ix_data.len < 4) return error.M9_Stake_InvalidInstructionData;
    var off: usize = 4;
    var ts: ?i64 = null;
    var epoch: ?u64 = null;
    var custodian: ?[32]u8 = null;
    // unix_timestamp: Option<i64>
    if (off >= ix_data.len) return error.M9_Stake_InvalidInstructionData;
    const ts_tag = ix_data[off];
    off += 1;
    if (ts_tag == 1) {
        if (off + 8 > ix_data.len) return error.M9_Stake_InvalidInstructionData;
        ts = std.mem.readInt(i64, ix_data[off..][0..8], .little);
        off += 8;
    } else if (ts_tag != 0) return error.M9_Stake_InvalidInstructionData;
    // epoch: Option<u64>
    if (off >= ix_data.len) return error.M9_Stake_InvalidInstructionData;
    const ep_tag = ix_data[off];
    off += 1;
    if (ep_tag == 1) {
        if (off + 8 > ix_data.len) return error.M9_Stake_InvalidInstructionData;
        epoch = std.mem.readInt(u64, ix_data[off..][0..8], .little);
        off += 8;
    } else if (ep_tag != 0) return error.M9_Stake_InvalidInstructionData;
    // custodian: Option<Pubkey>
    if (off >= ix_data.len) return error.M9_Stake_InvalidInstructionData;
    const cu_tag = ix_data[off];
    off += 1;
    if (cu_tag == 1) {
        if (off + 32 > ix_data.len) return error.M9_Stake_InvalidInstructionData;
        custodian = ix_data[off..][0..32].*;
        off += 32;
    } else if (cu_tag != 0) return error.M9_Stake_InvalidInstructionData;

    // SIMD-0118 EpochRewards gate (guarded; absent ⇒ no gate). Placed AFTER the
    // parse to mirror Agave order + the landed executeAuthorize/executeInitialize idiom.
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // Account [0] = stake [WRITE]; owner == Stake program.
    if (frame.account_indices.len < 1) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    if (stake_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_INITIALIZED and disc != STAKE_DISC_STAKE)
        return error.M9_Stake_InvalidAccountData;

    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;

    // Auth: in force → custodian ∈ signers; else → withdrawer ∈ signers.
    // isInForce custodian=null ⇒ NO bypass (the custodian is the key being checked).
    if (lockupInForce(stake.data, clock, null)) {
        const cust = stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32];
        if (!signerSetContains(ctx, frame, cust)) return error.M9_Stake_MissingRequiredSignature;
    } else {
        const withdrawer = stake.data[STAKE_OFF_WITHDRAWER..][0..32];
        if (!signerSetContains(ctx, frame, withdrawer)) return error.M9_Stake_MissingRequiredSignature;
    }

    // Apply only the present options, in place (same length). Gate on the Option
    // being present, NOT on value != 0 — Some(0) is a valid lockup-clear.
    if (ts) |v| std.mem.writeInt(i64, stake.data[STAKE_OFF_LOCKUP_TS..][0..8], v, .little);
    if (epoch) |v| std.mem.writeInt(u64, stake.data[STAKE_OFF_LOCKUP_EPOCH..][0..8], v, .little);
    if (custodian) |c| @memcpy(stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32], &c);
}

// ── SetLockupChecked (tag 12) — canonical `Meta::set_lockup` via the "Checked" idiom ──
//
// CARRIER-CLASS FIX (predicted recurrence of the Authorize(tag1, slot 415547068),
// Deactivate(tag5, slot 415214214), SetLockup(tag6), and the rest of the Stake-CPI
// stub carriers): the first time any BPF program CPIs Stake SetLockupChecked, the
// prior `M9_Stake_VariantPending_SetLockupChecked` stub → M7_BuiltinFailed → outer tx
// M4_RunFailed → dropped lockup write → accounts_lt_hash poison → bank_hash divergence
// → delinquency. Closing the stub pre-empts it. memory carrier-stake-cpi-deactivate-stub.
//
// IDENTICAL to SetLockup (tag 6) EXCEPT two "Checked" deltas:
//   • the ix data has NO custodian Option — only Option<i64 ts> + Option<u64 epoch>.
//     LockupCheckedArgs (instruction.rs) drops the third Option<Pubkey> that
//     LockupArgs (tag 6) carries. Min ix len = 6 bytes (u32 tag + two None tags).
//   • the new custodian is account[2].pubkey (get_optional_pubkey idx=2,
//     should_be_signer=TRUE): if account[2] is present it MUST sign and becomes the
//     new lockup.custodian; if absent (frame has ≤2 accounts) custodian = None (no
//     error). This get_optional_pubkey check runs at the arm (stake_instruction.rs:302),
//     BEFORE Meta::set_lockup's in-force/withdrawer authorization (state.rs:438) — so a
//     present-but-unsigned account[2] is MissingRequiredSignature raised first.
//
// Accounts: [0] stake [WRITE, owner == Stake program]; the authorizing signer
// (current custodian if lockup in force, else withdrawer) is checked via the
// signer-SET scan (NEVER index-N); [2] new custodian (OPTIONAL, must sign). Clock
// comes from ctx.sysvar_cache (NOT an instruction account index). Apply only the
// present fields, in place, same length (byte-equivalent to Agave's full
// serialize_into, which rewrites every non-lockup byte identically).
//
// @prov:stake-builtin.set-lockup-checked — byte-identical in Sig. FD post-SIMD-0490
// runs the same v5 .so. SetLockup(Checked) is a pure Meta.lockup mutation, UNCHANGED
// across v4↔v5 — SIMD-0490 (min-delegation, MoveStake/MoveLamports) does NOT touch it.
//
// ⚠ Do NOT copy the top-level native handleSetLockup (vex_svm/native/
// stake_program.zig:1176) — 4 wrapper bugs (footgun comment flagged there): index-N
// signer (not set-scan); non-canonical isLockupActive (not isInForce(_,null)); no
// account[2]-as-custodian handling (only reads tag-6 ix-data custodian); no SIMD-0118
// EpochRewards gate. Port LOGIC only. This handler mirrors executeSetLockup/
// executeAuthorize (typed errors, in-place same-length mutation, NO bank.collectWrite —
// cpi.zig propagates the in-place change to caller memory, replay content-detects it).
fn executeSetLockupChecked(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;

    // Parse LockupCheckedArgs: u32 tag(12) + Option<i64 ts> + Option<u64 epoch>.
    // NO custodian Option (the tag-6 delta). Min len = 4 + 1 + 1 = 6.
    if (ix_data.len < 6) return error.M9_Stake_InvalidInstructionData;
    var off: usize = 4;
    var ts: ?i64 = null;
    var epoch: ?u64 = null;
    // unix_timestamp: Option<i64>
    if (off >= ix_data.len) return error.M9_Stake_InvalidInstructionData;
    const ts_tag = ix_data[off];
    off += 1;
    if (ts_tag == 1) {
        if (off + 8 > ix_data.len) return error.M9_Stake_InvalidInstructionData;
        ts = std.mem.readInt(i64, ix_data[off..][0..8], .little);
        off += 8;
    } else if (ts_tag != 0) return error.M9_Stake_InvalidInstructionData;
    // epoch: Option<u64>
    if (off >= ix_data.len) return error.M9_Stake_InvalidInstructionData;
    const ep_tag = ix_data[off];
    off += 1;
    if (ep_tag == 1) {
        if (off + 8 > ix_data.len) return error.M9_Stake_InvalidInstructionData;
        epoch = std.mem.readInt(u64, ix_data[off..][0..8], .little);
        off += 8;
    } else if (ep_tag != 0) return error.M9_Stake_InvalidInstructionData;

    // SIMD-0118 EpochRewards gate (guarded; absent ⇒ no gate). Mirrors the landed
    // executeSetLockup/executeAuthorize idiom (parse first, then gate).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // get_stake_account: account [0] = stake [WRITE]; owner == Stake program.
    if (frame.account_indices.len < 1) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    if (stake_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    if (disc != STAKE_DISC_INITIALIZED and disc != STAKE_DISC_STAKE)
        return error.M9_Stake_InvalidAccountData;

    // get_optional_pubkey(idx=2, should_be_signer=TRUE): if account[2] is present it
    // MUST sign (canonical INDEX-2 is_signer — the new custodian is taken BY POSITION,
    // so "did acct[2] sign" IS the canonical test, like executeAuthorizeChecked's
    // index-N rule); if absent (≤2 accounts) custodian stays None (no error). This runs
    // BEFORE the Meta::set_lockup auth check (Agave stake_instruction.rs:302).
    var new_custodian: ?[32]u8 = null;
    if (frame.account_indices.len > 2) {
        const cust_idx = frame.account_indices[2];
        if (cust_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
        const ca = &ctx.tx.accounts[cust_idx];
        if (!ca.is_signer) return error.M9_Stake_MissingRequiredSignature;
        new_custodian = ca.pubkey;
    }

    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;

    // Meta::set_lockup auth: in force → current custodian ∈ signers; else → withdrawer
    // ∈ signers. isInForce(clock, None) ⇒ NO bypass (the custodian here is the key being
    // checked via the signer set, not a bypass key).
    if (lockupInForce(stake.data, clock, null)) {
        const cust = stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32];
        if (!signerSetContains(ctx, frame, cust)) return error.M9_Stake_MissingRequiredSignature;
    } else {
        const withdrawer = stake.data[STAKE_OFF_WITHDRAWER..][0..32];
        if (!signerSetContains(ctx, frame, withdrawer)) return error.M9_Stake_MissingRequiredSignature;
    }

    // Apply only the present fields, in place (same length). Gate on presence, NOT on
    // value != 0 — Some(0) is a valid lockup-clear. new_custodian set iff account[2] present.
    if (ts) |v| std.mem.writeInt(i64, stake.data[STAKE_OFF_LOCKUP_TS..][0..8], v, .little);
    if (epoch) |v| std.mem.writeInt(u64, stake.data[STAKE_OFF_LOCKUP_EPOCH..][0..8], v, .little);
    if (new_custodian) |c| @memcpy(stake.data[STAKE_OFF_LOCKUP_CUSTODIAN..][0..32], &c);
}

fn executeMerge(ctx: *InvokeContext) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;

    // SIMD-0118 EpochRewards gate (guarded; absent ⇒ no gate).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    if (frame.account_indices.len < 5) return error.M9_Stake_NotEnoughAccounts;
    const dst_idx = frame.account_indices[0];
    const src_idx = frame.account_indices[1];
    // dst == src by ix-account INDEX equality → InvalidArgument (Agave).
    if (dst_idx == src_idx) return error.M9_Stake_InvalidArgument;
    if (dst_idx >= ctx.tx.accounts.len or src_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;
    const dst = &ctx.tx.accounts[dst_idx];
    const src = &ctx.tx.accounts[src_idx];
    if (!dst.is_writable or !src.is_writable) return error.M9_Stake_AccountNotWritable;
    // get_stake_account: both owned by the stake program.
    if (!std.mem.eql(u8, &dst.owner, &STAKE_PROGRAM_ID) or
        !std.mem.eql(u8, &src.owner, &STAKE_PROGRAM_ID))
        return error.M9_Stake_InvalidAccountOwner;
    if (dst.data.len < STAKE_STATE_SZ or src.data.len < STAKE_STATE_SZ)
        return error.M9_Stake_InvalidAccountData;

    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;

    // ── metas_can_merge ──
    const dst_staker = dst.data[STAKE_OFF_STAKER..][0..32];
    const dst_withdrawer = dst.data[STAKE_OFF_WITHDRAWER..][0..32];
    const src_staker = src.data[STAKE_OFF_STAKER..][0..32];
    const src_withdrawer = src.data[STAKE_OFF_WITHDRAWER..][0..32];

    // Staker authority of the destination must be in the instruction signer set.
    if (!signerSetContains(ctx, frame, dst_staker)) return error.M9_Stake_MissingRequiredSignature;

    if (!std.mem.eql(u8, dst_staker, src_staker) or
        !std.mem.eql(u8, dst_withdrawer, src_withdrawer))
        return error.M9_Stake_MergeMismatch;
    // Lockups must match byte-for-byte (ts+epoch+custodian = 48 bytes) OR both
    // not-in-force (Lockup::is_in_force(clock, None)). rent_exempt NOT compared.
    const dst_lockup = dst.data[STAKE_OFF_LOCKUP_TS..][0..48];
    const src_lockup = src.data[STAKE_OFF_LOCKUP_TS..][0..48];
    if (!std.mem.eql(u8, dst_lockup, src_lockup)) {
        if (lockupInForce(dst.data, clock, null) or lockupInForce(src.data, clock, null))
            return error.M9_Stake_MergeMismatch;
    }

    // ── classify both via getMergeKind (uses curve) ──
    const history = stakeHistory(ctx);
    const dst_kind = getMergeKind(dst.data, clock.epoch, history);
    const src_kind = getMergeKind(src.data, clock.epoch, history);
    if (dst_kind == 0xFE or src_kind == 0xFE) return error.M9_Stake_InvalidAccountData;
    if (dst_kind == 0xFF or src_kind == 0xFF) return error.M9_Stake_MergeTransientStake;

    // ── pair table (apply to dst.data IN PLACE) ──
    if (dst_kind == 0 and src_kind == 0) {
        // (Inactive,Inactive) → None (no dst-state change)
    } else if (dst_kind == 0 and src_kind == 1) {
        // (Inactive,ActivationEpoch) → None
    } else if (dst_kind == 1 and src_kind == 0) {
        // (ActivationEpoch,Inactive) → dst.delegation.stake += src.lamports; flags=dst|src.
        const dst_stake = std.mem.readInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
        const new_stake = std.math.add(u64, dst_stake, src.lamports) catch return error.M9_Stake_ArithmeticOverflow;
        std.mem.writeInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], new_stake, .little);
        dst.data[STAKE_OFF_STAKE_FLAGS] = dst.data[STAKE_OFF_STAKE_FLAGS] | src.data[STAKE_OFF_STAKE_FLAGS];
    } else if (dst_kind == 1 and src_kind == 1) {
        // (ActivationEpoch,ActivationEpoch) → absorbed = src.lamports [V5!];
        // dst.stake += absorbed; credits = weighted; flags = dst|src.
        if (!std.mem.eql(u8, dst.data[STAKE_OFF_VOTER..][0..32], src.data[STAKE_OFF_VOTER..][0..32]))
            return error.M9_Stake_MergeMismatch;
        // active_delegations_can_merge (canonical merge.rs:113-117): in addition to
        // the voter-pubkey match above, BOTH dst and src deactivation_epoch must be
        // u64::MAX. Mirrors the (FullyActive,FullyActive) arm below — both activating
        // arms get this gate via active_stake().zip(). Pre-existing v5 gap, not a regression.
        const dst_deact = std.mem.readInt(u64, dst.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
        const src_deact = std.mem.readInt(u64, src.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
        if (dst_deact != std.math.maxInt(u64) or src_deact != std.math.maxInt(u64))
            return error.M9_Stake_MergeMismatch;
        const dst_stake = std.mem.readInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
        const dst_credits = std.mem.readInt(u64, dst.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], .little);
        const src_credits = std.mem.readInt(u64, src.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], .little);
        const absorbed = src.lamports;
        const merged = weightedCreditsObserved(dst_credits, dst_stake, src_credits, absorbed) orelse return error.M9_Stake_ArithmeticOverflow;
        const new_stake = std.math.add(u64, dst_stake, absorbed) catch return error.M9_Stake_ArithmeticOverflow;
        std.mem.writeInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], new_stake, .little);
        std.mem.writeInt(u64, dst.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], merged, .little);
        dst.data[STAKE_OFF_STAKE_FLAGS] = dst.data[STAKE_OFF_STAKE_FLAGS] | src.data[STAKE_OFF_STAKE_FLAGS];
    } else if (dst_kind == 2 and src_kind == 2) {
        // (FullyActive,FullyActive) → active_delegations_can_merge:
        // dst.voter==src.voter AND dst.deact==MAX AND src.deact==MAX.
        // absorbed = src.delegation.stake; dst.stake += absorbed; credits=weighted;
        // flags = 0 (EMPTY).
        if (!std.mem.eql(u8, dst.data[STAKE_OFF_VOTER..][0..32], src.data[STAKE_OFF_VOTER..][0..32]))
            return error.M9_Stake_MergeMismatch;
        const dst_deact = std.mem.readInt(u64, dst.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
        const src_deact = std.mem.readInt(u64, src.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
        if (dst_deact != std.math.maxInt(u64) or src_deact != std.math.maxInt(u64))
            return error.M9_Stake_MergeMismatch;
        const dst_stake = std.mem.readInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
        const dst_credits = std.mem.readInt(u64, dst.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], .little);
        const src_stake = std.mem.readInt(u64, src.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
        const src_credits = std.mem.readInt(u64, src.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], .little);
        const absorbed = src_stake;
        const merged = weightedCreditsObserved(dst_credits, dst_stake, src_credits, absorbed) orelse return error.M9_Stake_ArithmeticOverflow;
        const new_stake = std.math.add(u64, dst_stake, absorbed) catch return error.M9_Stake_ArithmeticOverflow;
        std.mem.writeInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], new_stake, .little);
        std.mem.writeInt(u64, dst.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], merged, .little);
        dst.data[STAKE_OFF_STAKE_FLAGS] = 0;
    } else {
        return error.M9_Stake_MergeMismatch;
    }

    // ── byte writes ──
    // dst gains src lamports ALWAYS (even on no-state-change arms).
    dst.lamports = std.math.add(u64, dst.lamports, src.lamports) catch return error.M9_Stake_ArithmeticOverflow;
    // source drained → Uninitialized: write ONLY u32 disc=0 at offset 0; PRESERVE
    // the tail 4..200 (canonical set_state(Uninitialized) bincode-writes 4 bytes).
    std.mem.writeInt(u32, src.data[0..4], STAKE_DISC_UNINITIALIZED, .little);
    src.lamports = 0;
}

// ── GetMinimumDelegation (tag 13) — canonical Core-BPF v5. @prov:stake-builtin.get-minimum-delegation ──
//
// Read-only query. NO accounts, NO signers, NO account-byte mutation, NO lamport
// move. Sole consensus-visible effect: return_data = u64 LE(min_delegation),
// program_id = Stake program id — the 8 bytes a calling BPF program reads back via
// sol_get_return_data (which can branch outer-tx success). The current stub
// (M9_Stake_VariantPending_GetMinimumDelegation → M7_BuiltinFailed → outer
// M4_RunFailed) is the divergence: any state a caller would have written, gated on
// the returned value, is dropped → lt-hash poison → bank_hash diverge. Same carrier
// class as Deactivate(415214214) / Authorize(415547068).
//
// ⚠ CRITICAL DO-NOTs (verified against Sig lib.zig + Agave v5 .so, agave-behavior-
// extractor 2026-06-16):
//   (1) Do NOT add the SIMD-0118 EpochRewards gate. tag 13 is the ONE documented
//       exception (Sig lib.zig:73 `and stake_instruction != .get_minimum_delegation`).
//       Every OTHER landed handler HAS the gate; this one MUST NOT — gating it would
//       falsely fail a tx the cluster passes during a reward window → divergence.
//   (2) Do NOT require accounts or signers (Sig lib.zig:373 reads none).
//   (3) Do NOT copy native/stake_program.zig:1732 "log-only, sets no return_data"
//       incompleteness — wiring return_data IS the fix.
// Compute (COMPUTE_UNITS=750) is already consumed at `execute` entry — do NOT
// re-consume here.
//
// SIMD-0490 v5 ACTIVE on testnet ⇒ min_delegation = 1 SOL. We REUSE
// MIN_DELEGATION_LAMPORTS (the exact constant Split/MoveStake/MoveLamports ENFORCE):
// canonically GetMinimumDelegation returns the same value those handlers gate on
// (Sig calls one getMinimumDelegation for all of them), so reusing the constant is
// the correctness guarantee, not merely DRY. (NB: the file-header comment lines
// 45-46 calling SIMD-0490 "DORMANT / v4" is a STALE doc bug — every landed handler
// treats v5 as active; see commit message.)
fn executeGetMinimumDelegation(ctx: *InvokeContext) Error!void {
    const min_delegation: u64 = MIN_DELEGATION_LAMPORTS; // SIMD-0490 v5 = 1 SOL
    var le: [8]u8 = undefined;
    std.mem.writeInt(u64, &le, min_delegation, .little);
    ctx.tx.return_data.set(ctx.allocator, STAKE_PROGRAM_ID, &le) catch
        return error.M9_Stake_OutOfMemory;
}

// ── Withdraw (tag 4) — canonical BPF stake v5 (SIMD-0490 active testnet) ─────
//
// Accounts: [0] stake [WRITE], [1] recipient [WRITE], [2] Clock, [3] StakeHistory,
//           [4] withdraw authority [SIGNER], [5] custodian (OPTIONAL).
// ix data = u32 tag(4) + u64 lamports = 12 bytes.
//
// v5 LOGIC ported from native handleWithdraw (vex_svm/native/stake_program.zig:598)
// with its CPI bugs FIXED: (a) typed errors not silent `return`; (b) NO zero-amount
// early-return (canonical has none); (c) NO same-account stake==recipient guard
// (canonical does sequential -=/+=; a same-index withdraw nets to a no-op);
// (d) canonical Lockup::is_in_force (not native's >0-conjunct/epoch_schedule form);
// (e) full-withdraw writes ONLY u32 disc=0 (offset 0), PRESERVES tail (not
// @memset(0,200)); (f) add EpochRewards gate. Withdraw authority = signer-SET of
// the withdrawer (Initialized/Stake) or stake.pubkey (Uninitialized) — NOT index-4.
fn executeWithdraw(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // ix data: u32 tag(4) + u64 lamports = 12 bytes.
    if (ix_data.len < 12) return error.M9_Stake_InvalidInstructionData;
    const withdraw_lamports = std.mem.readInt(u64, ix_data[4..12], .little);
    // NOTE: NO zero-amount early return (canonical has none).

    // SIMD-0118 EpochRewards gate (guarded; absent ⇒ no gate).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    if (frame.account_indices.len < 5) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    const recip_idx = frame.account_indices[1];
    if (stake_idx >= ctx.tx.accounts.len or recip_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    const recip = &ctx.tx.accounts[recip_idx];
    if (!stake.is_writable or !recip.is_writable) return error.M9_Stake_AccountNotWritable;
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (stake.data.len < 4) return error.M9_Stake_InvalidAccountData;

    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;

    // ── reserve + is_staked + authority by disc ──
    var reserve: u64 = 0;
    var is_staked = false;
    var has_lockup = false;
    switch (disc) {
        STAKE_DISC_STAKE => {
            if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
            const withdrawer = stake.data[STAKE_OFF_WITHDRAWER..][0..32];
            if (!signerSetContains(ctx, frame, withdrawer)) return error.M9_Stake_MissingRequiredSignature;
            const rent_exempt = std.mem.readInt(u64, stake.data[STAKE_OFF_RENT_EXEMPT..][0..8], .little);
            const deleg = std.mem.readInt(u64, stake.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
            const act = std.mem.readInt(u64, stake.data[STAKE_OFF_ACTIVATION_EPOCH..][0..8], .little);
            const deact = std.mem.readInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
            const staked: u64 = if (clock.epoch >= deact) blk: {
                const history = stakeHistory(ctx);
                const status = getStakeActivationStatus(act, deact, deleg, clock.epoch, history, 0);
                break :blk status.effective;
            } else deleg;
            is_staked = staked != 0;
            reserve = std.math.add(u64, staked, rent_exempt) catch return error.M9_Stake_ArithmeticOverflow;
            has_lockup = true;
        },
        STAKE_DISC_INITIALIZED => {
            if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
            const withdrawer = stake.data[STAKE_OFF_WITHDRAWER..][0..32];
            if (!signerSetContains(ctx, frame, withdrawer)) return error.M9_Stake_MissingRequiredSignature;
            reserve = std.mem.readInt(u64, stake.data[STAKE_OFF_RENT_EXEMPT..][0..8], .little);
            is_staked = false;
            has_lockup = true;
        },
        STAKE_DISC_UNINITIALIZED => {
            // Self-custody: signer set must contain the stake account key itself.
            if (!signerSetContains(ctx, frame, &stake.pubkey)) return error.M9_Stake_MissingRequiredSignature;
            reserve = 0;
            is_staked = false;
            has_lockup = false; // no lockup field on Uninitialized
        },
        else => return error.M9_Stake_InvalidAccountData, // RewardsPool / unknown
    }

    // ── lockup (Initialized & Stake only) — canonical Lockup::is_in_force ──
    if (has_lockup) {
        // Custodian = optional account at index 5; signer-gated at fetch (Agave).
        var signed_custodian: ?[]const u8 = null;
        if (frame.account_indices.len >= 6) {
            const cust_idx = frame.account_indices[5];
            if (cust_idx < ctx.tx.accounts.len and ctx.tx.accounts[cust_idx].is_signer) {
                signed_custodian = &ctx.tx.accounts[cust_idx].pubkey;
            }
        }
        if (lockupInForce(stake.data, clock, signed_custodian)) return error.M9_Stake_LockupInForce;
    }

    // ── limit checks (canonical order) — NO same-account guard ──
    const lamports_and_reserve = std.math.add(u64, withdraw_lamports, reserve) catch return error.M9_Stake_InsufficientFunds;
    if (is_staked and lamports_and_reserve > stake.lamports) return error.M9_Stake_InsufficientFunds;
    if (withdraw_lamports != stake.lamports and lamports_and_reserve > stake.lamports)
        return error.M9_Stake_InsufficientFunds;

    // ── byte writes ──
    // Full withdrawal → reset disc to Uninitialized (4 bytes), PRESERVE tail.
    if (withdraw_lamports == stake.lamports) {
        std.mem.writeInt(u32, stake.data[0..4], STAKE_DISC_UNINITIALIZED, .little);
    }
    // Sequential -= / += (if stake_idx == recip_idx these net to a no-op, matching
    // canonical's sequential lamport moves — touches ONLY lamports, never state).
    stake.lamports -= withdraw_lamports;
    recip.lamports = std.math.add(u64, recip.lamports, withdraw_lamports) catch return error.M9_Stake_ArithmeticOverflow;
}

// ── Split (tag 3) — canonical BPF stake v5 (SIMD-0490 active testnet) ────────
//
// Accounts: [0] source stake [WRITE], [1] destination [WRITE] (must be
//           Uninitialized, owner=stake, EXACTLY 200 bytes). Staker authority is
//           checked over the FULL instruction signer set (Init/Stake); for an
//           Uninitialized source the source account's own pubkey must sign.
// ix data = u32 tag(3) + u64 lamports = 12 bytes.
//
// @prov:stake-builtin.split — byte-faithful to Agave solana-program/stake@program@v5.0.0
// commit 6ed2c60c (the rc.0 .so Firedancer runs). SIMD-0490 ACTIVE ⇒ min_delegation =
// 1 SOL. Mirrors executeMerge/executeWithdraw (typed errors, signer-SET scan,
// in-place same-length mutation, NO bank.collectWrite, EpochRewards gate, close =
// disc=0 ONLY + PRESERVE tail).
//
// ⚠ Do NOT copy native handleSplit (vex_svm/native/stake_program.zig:1046,1093):
// it @memset(src_data[4..],0) on source drain (stale-tail carrier, same class as
// VoterWithBLS) and writes only rent_exempt+delegation on dst (drops voter@124 /
// credits@188 / flags@196). The canonical v5 dst is a FULL StakeStateV2.stake =
// a copy of the source .stake with ONLY rent_exempt_reserve and delegation.stake
// overridden — Stake::split() returns `new = self.*` then sets new.delegation.stake.
// So: memcpy the full 200 bytes from src, then override rent_exempt@4 + delegation@156.
fn executeSplit(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // ix data: u32 tag(3) + u64 lamports = 12 bytes.
    if (ix_data.len < 12) return error.M9_Stake_InvalidInstructionData;
    const lamports = std.mem.readInt(u64, ix_data[4..12], .little);

    // SIMD-0118 EpochRewards gate (guarded; absent ⇒ no gate).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    if (frame.account_indices.len < 2) return error.M9_Stake_NotEnoughAccounts;
    const src_idx = frame.account_indices[0];
    const dst_idx = frame.account_indices[1];
    if (src_idx >= ctx.tx.accounts.len or dst_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;
    const src = &ctx.tx.accounts[src_idx];
    const dst = &ctx.tx.accounts[dst_idx];
    if (!src.is_writable or !dst.is_writable) return error.M9_Stake_AccountNotWritable;

    // ── destination preconditions (canonical: owner, EXACT 200 bytes, Uninitialized) ──
    if (!std.mem.eql(u8, &dst.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (dst.data.len != STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    if (std.mem.readInt(u32, dst.data[0..4], .little) != STAKE_DISC_UNINITIALIZED)
        return error.M9_Stake_InvalidAccountData;
    if (src.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;

    // ── source: lamports > source.lamports → InsufficientFunds (canonical, before switch) ──
    if (lamports > src.lamports) return error.M9_Stake_InsufficientFunds;

    // destination_rent_exempt_reserve = Rent.minimumBalance(200) (canonical computes
    // from the live Rent sysvar; default = (128+200)*3480*2.0 = 2,282,880).
    const rent = ctx.sysvar_cache.getRent() catch return error.M9_Stake_ClockUnavailable;
    const dest_reserve: u64 = @intFromFloat(@as(f64, @floatFromInt((128 + STAKE_STATE_SZ) * rent.lamports_per_byte_year)) * rent.exemption_threshold);
    const min_del: u64 = 1_000_000_000; // SIMD-0490 v5: 1 SOL

    const src_disc = std.mem.readInt(u32, src.data[0..4], .little);
    const src_reserve = std.mem.readInt(u64, src.data[STAKE_OFF_RENT_EXEMPT..][0..8], .little);

    if (src_disc == STAKE_DISC_STAKE) {
        // Authorized::check(signers, .staker).
        const staker = src.data[STAKE_OFF_STAKER..][0..32];
        if (!signerSetContains(ctx, frame, staker)) return error.M9_Stake_MissingRequiredSignature;

        // is_active = getStakeStatus(...).effective > 0 at the current epoch.
        const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
        const deleg = std.mem.readInt(u64, src.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
        const act = std.mem.readInt(u64, src.data[STAKE_OFF_ACTIVATION_EPOCH..][0..8], .little);
        const deact = std.mem.readInt(u64, src.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
        const status = getStakeActivationStatus(act, deact, deleg, clock.epoch, stakeHistory(ctx), 0);
        const is_active = status.effective > 0;

        // validateSplitAmount(additional_required = min_del, source_is_active).
        if (lamports == 0) return error.M9_Stake_InsufficientFunds;
        const source_minimum = src_reserve +| min_del;
        const source_remaining = src.lamports -| lamports;
        if (source_remaining != 0 and source_remaining < source_minimum) return error.M9_Stake_InsufficientFunds;
        if (is_active and source_remaining != 0 and dst.lamports < dest_reserve) return error.M9_Stake_InsufficientFunds;
        const destination_minimum = dest_reserve +| min_del;
        const destination_deficit = destination_minimum -| dst.lamports;
        if (lamports < destination_deficit) return error.M9_Stake_InsufficientFunds;

        // remaining_stake_delta / split_stake_amount.
        var remaining_delta: u64 = undefined;
        var split_amt: u64 = undefined;
        if (source_remaining == 0) {
            remaining_delta = lamports -| src_reserve;
            split_amt = remaining_delta;
        } else {
            if (deleg -| lamports < min_del) return error.M9_Stake_InsufficientDelegation;
            remaining_delta = lamports;
            split_amt = lamports -| (dest_reserve -| dst.lamports);
        }
        if (split_amt < min_del) return error.M9_Stake_InsufficientDelegation;

        // Stake::split — insufficient_stake guard, then src.delegation.stake -= remaining_delta.
        if (remaining_delta > deleg) return error.M9_Stake_InsufficientStake;
        std.mem.writeInt(u64, src.data[STAKE_OFF_DELEGATION_STAKE..][0..8], deleg - remaining_delta, .little);

        // dst = FULL copy of src .stake (new = self.*), override rent_exempt + delegation.stake.
        // (disc stays 2 via the copy; voter/credits/flags/epochs all inherited.)
        // bincode StakeStateV2::Stake serializes disc(4)+Meta(120)+Stake(72)+flags(1) = 197
        // bytes; serializeIntoAccountData writes ONLY those 197 and PRESERVES the tail
        // [197..200] (padding, canonically untouched). Copy through 197 only — never the
        // padding tail (this file's history is tail-byte carriers; stay idiom-faithful).
        @memcpy(dst.data[0 .. STAKE_OFF_STAKE_FLAGS + 1], src.data[0 .. STAKE_OFF_STAKE_FLAGS + 1]);
        std.mem.writeInt(u64, dst.data[STAKE_OFF_RENT_EXEMPT..][0..8], dest_reserve, .little);
        std.mem.writeInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], split_amt, .little);
    } else if (src_disc == STAKE_DISC_INITIALIZED) {
        // Authorized::check(signers, .staker).
        const staker = src.data[STAKE_OFF_STAKER..][0..32];
        if (!signerSetContains(ctx, frame, staker)) return error.M9_Stake_MissingRequiredSignature;

        // validateSplitAmount(additional_required = 0, source_is_active = false).
        if (lamports == 0) return error.M9_Stake_InsufficientFunds;
        const source_remaining = src.lamports -| lamports;
        if (source_remaining != 0 and source_remaining < src_reserve) return error.M9_Stake_InsufficientFunds;
        const destination_deficit = dest_reserve -| dst.lamports;
        if (lamports < destination_deficit) return error.M9_Stake_InsufficientFunds;

        // dst = Initialized(1): disc=1 + full Meta (bytes 4..124), rent_exempt override.
        // bincode StakeStateV2::Initialized serializes disc(4) + Meta(120) = 124 bytes;
        // serializeIntoAccountData writes ONLY those 124 bytes and PRESERVES the tail
        // (124..200) — same "serialize serialized_size, no tail-zero" semantic the landed
        // Merge/Withdraw close-idiom relies on. So DO NOT @memset/zero 124..200; leave the
        // dst's prior bytes untouched (a freshly-created Uninitialized split target is
        // runtime-zeroed there anyway, so the byte image is identical either way, but
        // preserving is the canonical-faithful form — never assume the residue).
        std.mem.writeInt(u32, dst.data[0..4], STAKE_DISC_INITIALIZED, .little);
        @memcpy(dst.data[STAKE_OFF_RENT_EXEMPT..124], src.data[STAKE_OFF_RENT_EXEMPT..124]);
        std.mem.writeInt(u64, dst.data[STAKE_OFF_RENT_EXEMPT..][0..8], dest_reserve, .little);
    } else if (src_disc == STAKE_DISC_UNINITIALIZED) {
        // Source pubkey itself must be in the signer set.
        if (!signerSetContains(ctx, frame, &src.pubkey)) return error.M9_Stake_MissingRequiredSignature;
    } else {
        return error.M9_Stake_InvalidAccountData; // RewardsPool / unknown
    }

    // ── Deinitialize source on full drain (canonical: AFTER the switch, BEFORE lamport
    // moves). Write ONLY u32 disc=0; PRESERVE the tail 4..200 (set_state(Uninitialized)
    // bincode-writes 4 bytes — NEVER @memset). ──
    if (lamports == src.lamports) std.mem.writeInt(u32, src.data[0..4], STAKE_DISC_UNINITIALIZED, .little);

    // dst gains lamports; src loses lamports (canonical sequential add then sub).
    dst.lamports = std.math.add(u64, dst.lamports, lamports) catch return error.M9_Stake_ArithmeticOverflow;
    src.lamports -= lamports;
}

// ── MoveStake (tag 16) — canonical BPF stake v5 (SIMD-0148/0490, v5-only) ────
//
// Accounts: [0] source stake [WRITE], [1] destination stake [WRITE],
//           [2] stake authority [SIGNER]. ix data = u32 tag(16) + u64 lamports
//           = 12 bytes.
//
// @prov:stake-builtin.move-stake — byte-faithful to Sig and to
// solana-program/stake@program@v5.0.0 commit 6ed2c60c (the rc.0 .so
// Firedancer runs). Mirrors executeMerge/executeWithdraw/executeSplit idiom
// (typed errors folding to M7_BuiltinFailed, in-place same-length mutation, NO
// bank.collectWrite, EpochRewards gate). SIMD-0490 ACTIVE ⇒ min_delegation=1 SOL.
//
// ⚠ FOOTGUN: MoveStake/MoveLamports use a ONE-ELEMENT signer set = {pubkey @
// instruction account index 2}, gated on index-2.is_signer — NOT the full-frame
// signerSetContains used by Authorize/Merge/Withdraw/Split. Using signerSetContains
// here accepts a tx where the staker signed at index != 2 → CONSENSUS pass/fail
// divergence (Agave/Sig reject it: Agave stake_state.rs:134-143, Sig lib.zig:1712-1716).
// Source-drain on a FULL move writes disc=1 (Initialized), NOT disc=0 (Uninitialized
// like Merge/Withdraw/Split close). stake_flags@196 is written 0/EMPTY on every Stake
// write (NOT OR-merged like Merge's ActivationEpoch arm). Absorbed amount in the
// FullyActive-dest arm = `lamports` (the ix arg), NOT src.delegation.stake.
fn executeMoveStake(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;

    // SIMD-0118 EpochRewards gate (guarded; absent ⇒ no gate).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // ix data: u32 tag(16) + u64 lamports = 12 bytes.
    if (ix_data.len < 12) return error.M9_Stake_InvalidInstructionData;
    const lamports = std.mem.readInt(u64, ix_data[4..12], .little);

    // Accounts: [0] source [WRITE], [1] destination [WRITE], [2] authority [SIGNER].
    if (frame.account_indices.len < 3) return error.M9_Stake_NotEnoughAccounts;
    const src_idx = frame.account_indices[0];
    const dst_idx = frame.account_indices[1];
    const auth_idx = frame.account_indices[2];
    if (src_idx >= ctx.tx.accounts.len or dst_idx >= ctx.tx.accounts.len or auth_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;
    const src = &ctx.tx.accounts[src_idx];
    const dst = &ctx.tx.accounts[dst_idx];
    const auth = &ctx.tx.accounts[auth_idx];

    // ── move_stake_or_lamports_shared_checks ──
    // ⚠ ONE-ELEMENT signer set: index-2 MUST be a signer (NOT signerSetContains).
    if (!auth.is_signer) return error.M9_Stake_MissingRequiredSignature;
    // owners (Agave IncorrectProgramId).
    if (!std.mem.eql(u8, &src.owner, &STAKE_PROGRAM_ID) or !std.mem.eql(u8, &dst.owner, &STAKE_PROGRAM_ID))
        return error.M9_Stake_InvalidAccountOwner;
    // not the same account (by key, canonical).
    if (std.mem.eql(u8, &src.pubkey, &dst.pubkey)) return error.M9_Stake_InvalidInstructionData;
    // both writable.
    if (!src.is_writable or !dst.is_writable) return error.M9_Stake_InvalidInstructionData;
    // must move something.
    if (lamports == 0) return error.M9_Stake_InvalidArgument;

    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
    const history = stakeHistory(ctx);
    // get_state (>=200 bytes) is required by get_if_mergeable's deserialize.
    if (src.data.len < STAKE_STATE_SZ or dst.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;

    // get_if_mergeable on BOTH (transient → MergeTransientStake; non-stake → InvalidAccountData).
    const src_kind = getMergeKind(src.data, clock.epoch, history);
    const dst_kind = getMergeKind(dst.data, clock.epoch, history);
    if (src_kind == 0xFE or dst_kind == 0xFE) return error.M9_Stake_InvalidAccountData;
    if (src_kind == 0xFF or dst_kind == 0xFF) return error.M9_Stake_MergeTransientStake;

    // authorized.check(signers = {auth.pubkey}, Staker): source.staker == auth.pubkey.
    const src_staker = src.data[STAKE_OFF_STAKER..][0..32];
    if (!std.mem.eql(u8, src_staker, &auth.pubkey)) return error.M9_Stake_MissingRequiredSignature;

    // metas_can_merge(source, dest): authorized (staker + withdrawer) match AND
    // lockups match byte-for-byte OR both not-in-force.
    const dst_staker = dst.data[STAKE_OFF_STAKER..][0..32];
    if (!std.mem.eql(u8, src_staker, dst_staker) or
        !std.mem.eql(u8, src.data[STAKE_OFF_WITHDRAWER..][0..32], dst.data[STAKE_OFF_WITHDRAWER..][0..32]))
        return error.M9_Stake_MergeMismatch;
    if (!std.mem.eql(u8, src.data[STAKE_OFF_LOCKUP_TS..][0..48], dst.data[STAKE_OFF_LOCKUP_TS..][0..48])) {
        if (lockupInForce(src.data, clock, null) or lockupInForce(dst.data, clock, null))
            return error.M9_Stake_MergeMismatch;
    }

    // ── move_stake body ──
    // size guard already enforced above (== StakeStateV2::size_of()).
    // source MUST be FullyActive (else InvalidAccountData).
    if (src_kind != 2) return error.M9_Stake_InvalidAccountData;
    const src_stake = std.mem.readInt(u64, src.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
    // source cannot move more stake than it has.
    const src_final = std.math.sub(u64, src_stake, lamports) catch return error.M9_Stake_InvalidArgument;
    // unless all stake moved, source retains >= min_delegation.
    if (src_final != 0 and src_final < MIN_DELEGATION_LAMPORTS) return error.M9_Stake_InvalidArgument;

    if (dst_kind == 2) {
        // ── FullyActive dest ──
        // same vote account as source (else VoteAddressMismatch).
        if (!std.mem.eql(u8, src.data[STAKE_OFF_VOTER..][0..32], dst.data[STAKE_OFF_VOTER..][0..32]))
            return error.M9_Stake_VoteAddressMismatch;
        const dst_stake = std.mem.readInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
        const dst_final = std.math.add(u64, dst_stake, lamports) catch return error.M9_Stake_ArithmeticOverflow;
        if (dst_final < MIN_DELEGATION_LAMPORTS) return error.M9_Stake_InvalidArgument;
        // merge_delegation_stake_and_credits_observed(dest, absorbed=lamports, source.credits).
        const dst_credits = std.mem.readInt(u64, dst.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], .little);
        const src_credits = std.mem.readInt(u64, src.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], .little);
        const merged = weightedCreditsObserved(dst_credits, dst_stake, src_credits, lamports) orelse return error.M9_Stake_ArithmeticOverflow;
        // write dest = Stake(dest_meta UNCHANGED, dest_stake, EMPTY).
        std.mem.writeInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], dst_final, .little);
        std.mem.writeInt(u64, dst.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], merged, .little);
        dst.data[STAKE_OFF_STAKE_FLAGS] = 0; // StakeFlags::empty()
    } else if (dst_kind == 0) {
        // ── Inactive dest (Initialized disc=1, or fully-deactivated Stake) ──
        if (lamports < MIN_DELEGATION_LAMPORTS) return error.M9_Stake_InvalidArgument;
        // destination_stake = source_stake (FULL delegation+credits body); override
        // .stake = lamports. Agave: `let mut destination_stake = source_stake;
        // destination_stake.delegation.stake = lamports;`. The 72-byte body
        // [124..196] = {delegation(voter,stake,act,deact,warmup), credits_observed}.
        // dst keeps its OWN meta (4..124) — Inactive arm carries destination_meta.
        @memcpy(dst.data[STAKE_OFF_VOTER..STAKE_OFF_STAKE_FLAGS], src.data[STAKE_OFF_VOTER..STAKE_OFF_STAKE_FLAGS]);
        std.mem.writeInt(u64, dst.data[STAKE_OFF_DELEGATION_STAKE..][0..8], lamports, .little);
        dst.data[STAKE_OFF_STAKE_FLAGS] = 0; // StakeFlags::empty()
        std.mem.writeInt(u32, dst.data[0..4], STAKE_DISC_STAKE, .little); // Initialized/Inactive → Stake
    } else {
        // ActivationEpoch dest = the `_` arm = InvalidAccountData.
        return error.M9_Stake_InvalidAccountData;
    }

    // ── source write ──
    if (src_final == 0) {
        // Initialized(source_meta): disc=1, PRESERVE tail (bincode writes 124 bytes;
        // we touch ONLY the 4-byte disc — meta unchanged, delegation tail preserved).
        std.mem.writeInt(u32, src.data[0..4], STAKE_DISC_INITIALIZED, .little);
    } else {
        // Stake(source_meta, src w/ delegation.stake=src_final, EMPTY).
        std.mem.writeInt(u64, src.data[STAKE_OFF_DELEGATION_STAKE..][0..8], src_final, .little);
        src.data[STAKE_OFF_STAKE_FLAGS] = 0; // StakeFlags::empty()
    }

    // ── lamports (by the ix arg) ──
    src.lamports = std.math.sub(u64, src.lamports, lamports) catch return error.M9_Stake_InsufficientFunds;
    dst.lamports = std.math.add(u64, dst.lamports, lamports) catch return error.M9_Stake_ArithmeticOverflow;
    // final reserve guard (meta.rent_exempt_reserve @ offset 4).
    const src_reserve = std.mem.readInt(u64, src.data[STAKE_OFF_RENT_EXEMPT..][0..8], .little);
    const dst_reserve = std.mem.readInt(u64, dst.data[STAKE_OFF_RENT_EXEMPT..][0..8], .little);
    if (src.lamports < src_reserve or dst.lamports < dst_reserve) return error.M9_Stake_InvalidArgument;
}

// ── MoveLamports (tag 17) — canonical BPF stake v5 (SIMD-0148/0490, v5-only) ─
//
// Accounts: [0] source stake [WRITE], [1] destination stake [WRITE],
//           [2] stake authority [SIGNER]. ix data = u32 tag(17) + u64 lamports
//           = 12 bytes.
//
// @prov:stake-builtin.move-lamports — byte-faithful to Sig and to
// solana-program/stake@program@v5.0.0 commit 6ed2c60c (the rc.0 .so Firedancer
// runs). Mirrors executeMoveStake's shared-checks block VERBATIM (one-element
// index-2 signer set, owner/same-account/writable/lamports!=0, get_if_mergeable
// on both, source-staker authorized.check, metas_can_merge), then a much SMALLER body.
//
// ⚠ FOOTGUN: MoveStake/MoveLamports authority is the SINGLE account at index 2,
// gated on index-2.is_signer + source.staker == auth.pubkey — NOT the full-frame
// signerSetContains (correct only for Authorize/Merge/Withdraw/Split). signerSetContains
// would PASS when the staker signs at index != 2 → Vexor moves lamports, the cluster
// (Agave v5.0.0 / Sig / FD) rejects MissingRequiredSignature → bank_hash divergence.
// Reference: agave-behavior-extractor 2026-06-15 + Sig lib.zig:1712-1744 + Agave v5.0.0
// move_stake_or_lamports_shared_checks (commit 6ed2c60c).
//
// ⚠ MoveLamports is NOT MoveStake — four things from executeMoveStake's BODY must
// NOT be copied (each a boundary divergence if it were):
//   (1) NO `src_kind != 2` requirement — source may be Inactive(0) OR FullyActive(2);
//       only ActivationEpoch(1) rejects (the free-lamports switch `else` handles it).
//   (2) NO branching on dst_kind in the body — destination ActivationEpoch is VALID
//       here; dst classification still runs (its 0xFE/0xFF reject + metas_can_merge),
//       but the body does not act on dst_kind.
//   (3) NO state-byte writes on EITHER account — only src.lamports-=n / dst.lamports+=n.
//   (4) NO post-move reserve guard — Agave process_move_lamports has none; the
//       saturating free-lamports calc is the ONLY bound.
// Also: unlike Withdraw, MoveLamports DOES reject lamports==0 (InvalidArgument).
fn executeMoveLamports(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;

    // SIMD-0118 EpochRewards gate (guarded; absent ⇒ no gate).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // ix data: u32 tag(17) + u64 lamports = 12 bytes.
    if (ix_data.len < 12) return error.M9_Stake_InvalidInstructionData;
    const lamports = std.mem.readInt(u64, ix_data[4..12], .little);

    // Accounts: [0] source [WRITE], [1] destination [WRITE], [2] authority [SIGNER].
    if (frame.account_indices.len < 3) return error.M9_Stake_NotEnoughAccounts;
    const src_idx = frame.account_indices[0];
    const dst_idx = frame.account_indices[1];
    const auth_idx = frame.account_indices[2];
    if (src_idx >= ctx.tx.accounts.len or dst_idx >= ctx.tx.accounts.len or auth_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;
    const src = &ctx.tx.accounts[src_idx];
    const dst = &ctx.tx.accounts[dst_idx];
    const auth = &ctx.tx.accounts[auth_idx];

    // ── move_stake_or_lamports_shared_checks (identical to executeMoveStake) ──
    // ⚠ ONE-ELEMENT signer set: index-2 MUST be a signer (NOT signerSetContains).
    if (!auth.is_signer) return error.M9_Stake_MissingRequiredSignature;
    // owners (Agave IncorrectProgramId).
    if (!std.mem.eql(u8, &src.owner, &STAKE_PROGRAM_ID) or !std.mem.eql(u8, &dst.owner, &STAKE_PROGRAM_ID))
        return error.M9_Stake_InvalidAccountOwner;
    // not the same account (by key, canonical).
    if (std.mem.eql(u8, &src.pubkey, &dst.pubkey)) return error.M9_Stake_InvalidInstructionData;
    // both writable.
    if (!src.is_writable or !dst.is_writable) return error.M9_Stake_InvalidInstructionData;
    // must move something (UNLIKE Withdraw, MoveLamports rejects 0 = InvalidArgument).
    if (lamports == 0) return error.M9_Stake_InvalidArgument;

    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
    const history = stakeHistory(ctx);
    // get_state (>=200 bytes) is required by get_if_mergeable's deserialize.
    if (src.data.len < STAKE_STATE_SZ or dst.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;

    // get_if_mergeable on BOTH (transient → MergeTransientStake; non-stake → InvalidAccountData).
    const src_kind = getMergeKind(src.data, clock.epoch, history);
    const dst_kind = getMergeKind(dst.data, clock.epoch, history);
    if (src_kind == 0xFE or dst_kind == 0xFE) return error.M9_Stake_InvalidAccountData;
    if (src_kind == 0xFF or dst_kind == 0xFF) return error.M9_Stake_MergeTransientStake;

    // authorized.check(signers = {auth.pubkey}, Staker): source.staker == auth.pubkey.
    const src_staker = src.data[STAKE_OFF_STAKER..][0..32];
    if (!std.mem.eql(u8, src_staker, &auth.pubkey)) return error.M9_Stake_MissingRequiredSignature;

    // metas_can_merge(source, dest): authorized (staker + withdrawer) match AND
    // lockups match byte-for-byte OR both not-in-force.
    const dst_staker = dst.data[STAKE_OFF_STAKER..][0..32];
    if (!std.mem.eql(u8, src_staker, dst_staker) or
        !std.mem.eql(u8, src.data[STAKE_OFF_WITHDRAWER..][0..32], dst.data[STAKE_OFF_WITHDRAWER..][0..32]))
        return error.M9_Stake_MergeMismatch;
    if (!std.mem.eql(u8, src.data[STAKE_OFF_LOCKUP_TS..][0..48], dst.data[STAKE_OFF_LOCKUP_TS..][0..48])) {
        if (lockupInForce(src.data, clock, null) or lockupInForce(dst.data, clock, null))
            return error.M9_Stake_MergeMismatch;
    }

    // ── move_lamports body (NOT move_stake) ──
    // source_free_lamports by SOURCE kind (saturating subs, canonical):
    //   FullyActive(2): src.lamports -| delegation.stake -| rent_exempt_reserve
    //   Inactive(0):    src.lamports -| rent_exempt_reserve
    //   ActivationEpoch(1) / other: InvalidAccountData (no free-lamports definition)
    // dst_kind is NOT branched on — dest ActivationEpoch is valid; only its
    // 0xFE/0xFF reject above applies.
    const reserve = std.mem.readInt(u64, src.data[STAKE_OFF_RENT_EXEMPT..][0..8], .little);
    const free: u64 = switch (src_kind) {
        2 => blk: {
            const deleg = std.mem.readInt(u64, src.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
            break :blk (src.lamports -| deleg) -| reserve;
        },
        0 => src.lamports -| reserve,
        else => return error.M9_Stake_InvalidAccountData, // ActivationEpoch(1)
    };
    if (lamports > free) return error.M9_Stake_InvalidArgument;

    // ── byte writes: ONLY the two lamports fields. NO state-data writes, NO
    // post-move reserve guard (Agave process_move_lamports has none). n ≤ free ≤
    // src.lamports always (saturating subs only decrease), so the `-=` cannot
    // underflow — same plain-subtract idiom as executeWithdraw. ──
    src.lamports -= lamports;
    dst.lamports = std.math.add(u64, dst.lamports, lamports) catch return error.M9_Stake_ArithmeticOverflow;
}

// ── vote credits walker (inline, fallible) ──────────────────────────────────
//
// Canonical: delegate() does deserialize(VoteStateVersions) → convertToVoteState
// → getCredits(). getCredits() = the LAST epoch_credits entry's `.credits`, or 0
// if the history is empty (Sig vote/state.zig:1664-1669). A MALFORMED vote
// account makes the deserialize ERROR → tx fails; a VALID parse with an empty
// epoch_credits returns 0 → tx succeeds. These are opposite pass/fail outcomes,
// so this walker is FALLIBLE: it returns error.M9_Stake_MalformedVoteState on any
// bounds/format failure and returns 0 ONLY on a clean parse with zero credits.
//
// PORTED BYTE-IDENTICAL to vex_svm/native/vote_state_serde.zig:deserializeVoteState
// (the proven version-aware walk). vex_bpf2 cannot @import vex_svm (module-boundary
// rule, same as the activation-curve port above), so the layout is inlined here.
// The version==3 branch is the LIVE testnet path (SIMD-0185, V4/version-3 vote
// state): node[32] + withdrawer[32] + inflation_rewards_collector[32] +
// block_revenue_collector[32] + inflation_rewards_commission_bps u16 +
// block_revenue_commission_bps u16 + pending_delegator_rewards u64 +
// has_bls_pubkey_compressed u8 + (bls_pubkey_compressed[48] iff has_bls) ; NO
// commission byte ; lockouts use the 13-byte LandedVote ; NO prior_voters. Getting
// the optional BLS 48 bytes or the prior_voters skip wrong shifts credits@188 (a
// silent bank_hash carrier) — this is why it mirrors the proven serde exactly.
const VOTE_MAX_LOCKOUT_HISTORY: u64 = 31;
const VOTE_MAX_AUTHORIZED_VOTERS: u64 = 8;
const VOTE_MAX_EPOCH_CREDITS_HISTORY: u64 = 64;
const VOTE_PRIOR_VOTERS_SIZE: usize = 1545;

fn readU64At(data: []const u8, pos: *usize) Error!u64 {
    if (pos.* + 8 > data.len) return error.M9_Stake_MalformedVoteState;
    const v = std.mem.readInt(u64, data[pos.*..][0..8], .little);
    pos.* += 8;
    return v;
}

// Byte offset + entry count of the epoch_credits array within raw vote-account
// data. The single SHARED version-aware walk for ALL vote-account consumers in this
// module (voteCredits and the DeactivateDelinquent acceptable/eligible checks).
// Returns .{ off, count } where each entry is {u64 epoch, u64 credits, u64 prev}
// (24 bytes) starting at `off`. FALLIBLE: any bounds/format failure (or a malformed
// account that can't be deserialized) → error.M9_Stake_MalformedVoteState; a clean
// parse with zero entries returns count==0 (NOT an error). The malformed≠empty
// distinction is consensus-relevant (a malformed delinquent vote acct must FAIL the
// tx, never be silently treated as empty→eligible). Mirrors
// vex_svm/native/vote_state_serde.zig:deserializeVoteState exactly (see voteCredits
// notes above for the version-3/SIMD-0185 layout & the BLS-48 / prior_voters
// pitfalls that shift the epoch_credits offset).
const EpochCreditsRegion = struct { off: usize, count: usize };

fn voteEpochCreditsRegion(data: []const u8) Error!EpochCreditsRegion {
    var pos: usize = 0;
    // version u32 (1=V0_23_5, 2=V1_14_11/Current, 3=V4/version-3 live)
    if (data.len < 4) return error.M9_Stake_MalformedVoteState;
    const version = std.mem.readInt(u32, data[0..4], .little);
    pos = 4;
    if (version != 1 and version != 2 and version != 3) return error.M9_Stake_MalformedVoteState;

    // node_pubkey[32] + authorized_withdrawer[32]
    if (pos + 64 > data.len) return error.M9_Stake_MalformedVoteState;
    pos += 64;

    if (version == 3) {
        // inflation_rewards_collector[32] + block_revenue_collector[32]
        if (pos + 64 > data.len) return error.M9_Stake_MalformedVoteState;
        pos += 64;
        // inflation_rewards_commission_bps u16 + block_revenue_commission_bps u16
        if (pos + 4 > data.len) return error.M9_Stake_MalformedVoteState;
        pos += 4;
        // pending_delegator_rewards u64
        _ = try readU64At(data, &pos);
        // has_bls_pubkey_compressed u8
        if (pos >= data.len) return error.M9_Stake_MalformedVoteState;
        const has_bls = data[pos] != 0;
        pos += 1;
        if (has_bls) {
            if (pos + 48 > data.len) return error.M9_Stake_MalformedVoteState;
            pos += 48; // bls_pubkey_compressed[48]
        }
    } else {
        // commission u8 (V0_23_5 / Current only)
        if (pos >= data.len) return error.M9_Stake_MalformedVoteState;
        pos += 1;
    }

    // Lockouts: u64 len, then `len` entries.
    const lockout_count = try readU64At(data, &pos);
    if (lockout_count > VOTE_MAX_LOCKOUT_HISTORY) return error.M9_Stake_MalformedVoteState;
    // V1 LandedVote = 12 bytes {slot u64, conf u32}; V2/V3 = 13 bytes {latency u8, slot u64, conf u32}.
    const lockout_size: usize = if (version == 1) 12 else 13;
    const lockouts_bytes = @as(usize, @intCast(lockout_count)) * lockout_size;
    if (pos + lockouts_bytes > data.len) return error.M9_Stake_MalformedVoteState;
    pos += lockouts_bytes;

    // Root slot: Option<u64> = u8 tag (+ u64 iff some).
    if (pos >= data.len) return error.M9_Stake_MalformedVoteState;
    const has_root = data[pos] != 0;
    pos += 1;
    if (has_root) _ = try readU64At(data, &pos);

    // Authorized voters: u64 len, then {u64 epoch, [32]u8 pubkey} entries.
    const av_count = try readU64At(data, &pos);
    if (av_count > VOTE_MAX_AUTHORIZED_VOTERS) return error.M9_Stake_MalformedVoteState;
    const av_bytes = @as(usize, @intCast(av_count)) * 40; // 8 + 32
    if (pos + av_bytes > data.len) return error.M9_Stake_MalformedVoteState;
    pos += av_bytes;

    // Prior voters: fixed-size CircBuf (v1/v2 only; version-3 removed prior_voters).
    if (version != 3) {
        if (pos + VOTE_PRIOR_VOTERS_SIZE > data.len) return error.M9_Stake_MalformedVoteState;
        pos += VOTE_PRIOR_VOTERS_SIZE;
    }

    // Epoch credits: u64 len, then {u64 epoch, u64 credits, u64 prev_credits}.
    const ec_count = try readU64At(data, &pos);
    if (ec_count > VOTE_MAX_EPOCH_CREDITS_HISTORY) return error.M9_Stake_MalformedVoteState;
    const ec_bytes = @as(usize, @intCast(ec_count)) * 24;
    if (pos + ec_bytes > data.len) return error.M9_Stake_MalformedVoteState;
    return .{ .off = pos, .count = @intCast(ec_count) };
}

/// getCredits() over raw vote-account data. Returns the last epoch_credits.credits
/// (0 if empty), or error.M9_Stake_MalformedVoteState on a parse failure.
fn voteCredits(data: []const u8) Error!u64 {
    const region = try voteEpochCreditsRegion(data);
    if (region.count == 0) return 0; // getCredits() on empty history = 0 (clean parse)
    // Walk to the LAST entry; getCredits returns its `.credits` field (the 2nd u64).
    const last_entry_off = region.off + ((region.count - 1) * 24);
    // entry = {epoch u64 @ +0, credits u64 @ +8, prev_credits u64 @ +16}
    return std.mem.readInt(u64, data[last_entry_off + 8 ..][0..8], .little);
}

// ── DelegateStake (tag 2) — canonical BPF stake v5 (SIMD-0490 active testnet) ─
//
// Accounts: [0] stake [WRITE], [1] vote [RO, owner==Vote111], [2] Clock,
//           [3] StakeHistory, [4] (config — legacy, unused). ix data = u32 tag(2)
//           only (4 bytes; no payload). Staker authority is checked over the FULL
//           instruction signer set (signerSetContains, NEVER index-N).
//
// @prov:stake-builtin.delegate — account-count boundary: require >=5 accounts
// (NOT >=6; native's `< 6` is the index-N anti-pattern bug). The signer is found
// by signer-SET scan of meta.authorized.staker@12, NOT by position. Byte-faithful
// to Agave solana-program/stake@program@v5.0.0 commit 6ed2c60c (the rc.0 .so
// Firedancer runs). Mirrors executeMerge/executeWithdraw/executeSplit idiom (typed
// errors folding to M7_BuiltinFailed, signer-SET scan, in-place same-length
// mutation, NO bank.collectWrite, EpochRewards gate). DelegateStake moves NO lamports.
//
// ⚠ FOOTGUN: offset 180 = Delegation.deprecated_warmup_cooldown_rate (u64 = f64
// bits, default 0.25 = 0x3FD0000000000000). It is "deprecated" in v5 but STILL
// serialized into the 200-byte account. On init→Stake it MUST be set to 0.25 (the
// newStake struct-default the v5 serializer writes); on re-delegate/reactivate it
// MUST be PRESERVED (canonical re-serializes the unchanged deserialized field). If
// a handler skips offset 180 on the init path: bytes 180..187 = whatever the
// Initialized tail held → account hash wrong → bank_hash divergence. The native
// top-level handler unconditionally writes 0.25 on re-delegate (harmless since
// value==default, but not canonical-shaped — we PRESERVE).
// Reference: agave-behavior-extractor 2026-06-16 (DelegateStake) + Sig
// state.zig:221 DEFAULT_WARMUP_COOLDOWN_RATE.
//
// ⚠ Do NOT copy native handleDelegateStake (vex_svm/native/stake_program.zig:445):
// it requires `< 6` accounts + authority at index 5 (index-N), gates re-delegate on
// `deact != MAX` (misses the effective-stake 3-way + reactivate), writes flags=0 on
// re-delegate (canonical PRESERVES args.flags), unconditionally writes 0.25 on
// offset 180, lacks the vote-owner check, lacks the EpochRewards gate, and uses
// bank.collectWrite (top-level only). Port the LOGIC, fix the wrappers.
fn executeDelegate(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;
    // ix data: u32 tag(2) only. No payload (already validated len>=4 by execute()).
    if (ix_data.len < 4) return error.M9_Stake_InvalidInstructionData;

    // SIMD-0118 EpochRewards gate (guarded; absent ⇒ no gate).
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // Account-count boundary: canonical requires >=5 (stake, vote, clock, history, config).
    if (frame.account_indices.len < 5) return error.M9_Stake_NotEnoughAccounts;
    const stake_idx = frame.account_indices[0];
    const vote_idx = frame.account_indices[1];
    if (stake_idx >= ctx.tx.accounts.len or vote_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    const vote = &ctx.tx.accounts[vote_idx];
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;
    // get_stake_account: stake owner must be the stake program.
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    // vote account owner must be the vote program (Agave IncorrectProgramId).
    if (!std.mem.eql(u8, &vote.owner, &VOTE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;

    // getCredits() over the vote account — FALLIBLE (malformed ⇒ tx fails; empty ⇒ 0).
    const credits = try voteCredits(vote.data);

    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;
    const disc = std.mem.readInt(u32, stake.data[0..4], .little);
    const staker = stake.data[STAKE_OFF_STAKER..][0..32];
    const rent_exempt = std.mem.readInt(u64, stake.data[STAKE_OFF_RENT_EXEMPT..][0..8], .little);

    switch (disc) {
        STAKE_DISC_INITIALIZED => {
            // Authorized::check(signers, .staker).
            if (!signerSetContains(ctx, frame, staker)) return error.M9_Stake_MissingRequiredSignature;
            // validateDelegatedAmount: stake_amount = lamports -| rent_exempt; >= 1 SOL (SIMD-0490).
            const stake_amount = stake.lamports -| rent_exempt;
            if (stake_amount < MIN_DELEGATION_LAMPORTS) return error.M9_Stake_InsufficientDelegation;
            // newStake → serialize Stake{flags=EMPTY(0)}. The source is Initialized
            // (disc=1), so the FULL Stake body (124..197) is written: voter, stake,
            // activation=epoch, deact=MAX, warmup=0.25, credits, flags=0. Meta (4..124)
            // is preserved (newStake reuses meta.*); tail (197..200) preserved.
            std.mem.writeInt(u32, stake.data[0..4], STAKE_DISC_STAKE, .little);
            @memcpy(stake.data[STAKE_OFF_VOTER..][0..32], &vote.pubkey);
            std.mem.writeInt(u64, stake.data[STAKE_OFF_DELEGATION_STAKE..][0..8], stake_amount, .little);
            std.mem.writeInt(u64, stake.data[STAKE_OFF_ACTIVATION_EPOCH..][0..8], clock.epoch, .little);
            std.mem.writeInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], std.math.maxInt(u64), .little);
            std.mem.writeInt(u64, stake.data[STAKE_OFF_WARMUP_RATE..][0..8], STAKE_WARMUP_RATE_DEFAULT_BITS, .little); // 0.25 ← CRITICAL
            std.mem.writeInt(u64, stake.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], credits, .little);
            stake.data[STAKE_OFF_STAKE_FLAGS] = 0; // StakeFlags::EMPTY
        },
        STAKE_DISC_STAKE => {
            // Authorized::check(signers, .staker).
            if (!signerSetContains(ctx, frame, staker)) return error.M9_Stake_MissingRequiredSignature;
            // validateDelegatedAmount (same min-delegation gate).
            const stake_amount = stake.lamports -| rent_exempt;
            if (stake_amount < MIN_DELEGATION_LAMPORTS) return error.M9_Stake_InsufficientDelegation;

            // redelegateStake: gate on EFFECTIVE stake (not deact!=MAX).
            const cur_voter = stake.data[STAKE_OFF_VOTER..][0..32];
            const cur_stake = std.mem.readInt(u64, stake.data[STAKE_OFF_DELEGATION_STAKE..][0..8], .little);
            const cur_act = std.mem.readInt(u64, stake.data[STAKE_OFF_ACTIVATION_EPOCH..][0..8], .little);
            const cur_deact = std.mem.readInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little);
            const status = getStakeActivationStatus(cur_act, cur_deact, cur_stake, clock.epoch, stakeHistory(ctx), 0);

            if (status.effective != 0) {
                // reactivate iff same voter AND clock.epoch == deactivation_epoch:
                // write ONLY deactivation_epoch = MAX; everything else PRESERVED
                // (voter, stake, activation, warmup@180, credits, flags).
                if (std.mem.eql(u8, cur_voter, &vote.pubkey) and clock.epoch == cur_deact) {
                    std.mem.writeInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], std.math.maxInt(u64), .little);
                } else {
                    return error.M9_Stake_TooSoonToRedelegate;
                }
            } else {
                // full re-delegate: voter, stake, activation=epoch, deact=MAX, credits.
                // PRESERVE warmup@180 (canonical re-serializes the unchanged field) and
                // flags@196 (=args.flags). disc stays Stake(2).
                @memcpy(stake.data[STAKE_OFF_VOTER..][0..32], &vote.pubkey);
                std.mem.writeInt(u64, stake.data[STAKE_OFF_DELEGATION_STAKE..][0..8], stake_amount, .little);
                std.mem.writeInt(u64, stake.data[STAKE_OFF_ACTIVATION_EPOCH..][0..8], clock.epoch, .little);
                std.mem.writeInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], std.math.maxInt(u64), .little);
                std.mem.writeInt(u64, stake.data[STAKE_OFF_CREDITS_OBSERVED..][0..8], credits, .little);
            }
        },
        else => return error.M9_Stake_InvalidAccountData, // Uninitialized / RewardsPool
    }
}

// ── DeactivateDelinquent (tag 14) — canonical BPF stake v5 ──────────────────
//
// Accounts: [0] stake [WRITE], [1] delinquent vote [RO, owner==Vote111],
//           [2] reference vote [RO, owner==Vote111]. ix data = u32 tag(14) only
//           (4 bytes; no payload). NO authority signer — this is the permissionless
//           crank that lets ANYONE deactivate a stake delegated to a vote account
//           that has been delinquent for >=5 epochs, validated against a reference
//           vote account that HAS been voting consecutively for the last 5 epochs.
//
// DeactivateDelinquent is UNCHANGED v4→v5 (no SIMD-0490 min-delegation, no new
// fields). The single success byte-write is identical to executeDeactivate (tag 5):
// u64 deactivation_epoch = clock.epoch at offset 172. No lamport move, no disc
// change, tail (180..200) fully preserved.
//
// @prov:stake-builtin.deactivate-delinquent — byte-faithful to Agave
// solana-program/stake@program@v5.0.0 commit 6ed2c60c (the rc.0 .so Firedancer
// runs). Order (matching dispatch): get_stake_account (owner
// guard) → checkNumberOfAccounts(3) → clock → delinquent owner+parse → reference
// owner+parse → acceptableReference → stake must be Stake(2) → voter==delinquent
// pubkey → eligible → deactivate (deact != MAX else AlreadyDeactivated). Error ORDER
// is non-consensus (all fold to M7); only the boundary CONJUNCTION + success bytes
// are consensus.
//
// ⚠ saturating vs checked: acceptableReference's INNER loop uses saturating `-|`
// (canonical tools.rs:62 / Sig lib.zig:1513) — CORRECT. eligibleDelinquent's
// minimum-epoch computes with CHECKED sub (`std.math.sub catch return false`, Sig
// lib.zig:1557) — at current_epoch<5 it returns false (NOT eligible), NOT a
// saturated-to-0 compare. Do NOT copy native handleDeactivateDelinquent
// (vex_svm/native/stake_program.zig:1760): it uses saturating `-|` in eligible
// (diverges at epoch<5), emitWrite+alloc data_copy (BPF idiom is in-place writeInt),
// has no EpochRewards gate, and silently `return`s instead of typed errors.
// Reference: agave-behavior-extractor 2026-06-16 (DeactivateDelinquent) + Sig
// lib.zig:1406-1564 (read-verified this session) + SIMD-0185/0291 vote V4 layout.
const MIN_DELINQUENT_EPOCHS: u64 = 5;

// acceptable_reference_epoch_credits: the reference vote acct must have voted in
// each of the last MIN_DELINQUENT_EPOCHS epochs ending at current_epoch — i.e. the
// last 5 epoch_credits entries reversed == (current, current-1, ..., current-4).
// checked_sub(len, 5) underflow (len<5) → false (NOT a whole-slice accept).
fn acceptableReference(data: []const u8, current_epoch: u64) Error!bool {
    const region = try voteEpochCreditsRegion(data);
    const start = std.math.sub(usize, region.count, MIN_DELINQUENT_EPOCHS) catch return false;
    var epoch = current_epoch;
    var i: usize = region.count;
    while (i > start) {
        i -= 1;
        const off = region.off + (i * 24); // entry {epoch u64 @+0, credits @+8, prev @+16}
        const vote_epoch = std.mem.readInt(u64, data[off..][0..8], .little);
        if (vote_epoch != epoch) return false;
        epoch -|= 1; // canonical saturating_sub HERE. @prov:stake-builtin.deactivate-delinquent
    }
    return true;
}

// eligible_for_account_delinquent: a delinquent vote acct is eligible iff it has NO
// epoch_credits (never voted → true) OR its last vote epoch <= current_epoch-5
// (checked: current_epoch<5 → false).
fn eligibleDelinquent(data: []const u8, current_epoch: u64) Error!bool {
    const region = try voteEpochCreditsRegion(data);
    if (region.count == 0) return true;
    const last_off = region.off + ((region.count - 1) * 24);
    const last_epoch = std.mem.readInt(u64, data[last_off..][0..8], .little);
    const min_epoch = std.math.sub(u64, current_epoch, MIN_DELINQUENT_EPOCHS) catch return false; // checked, NOT saturating
    return last_epoch <= min_epoch;
}

fn executeDeactivateDelinquent(ctx: *InvokeContext) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_Stake_NoActiveFrame;

    // SIMD-0118 EpochRewards gate: blocks all stake ix (except GetMinimumDelegation)
    // during the rewards window. Mirrors the landed executeDelegate/Merge idiom.
    if (ctx.sysvar_cache.getEpochRewards()) |er| {
        if (er.active) return error.M9_Stake_EpochRewardsActive;
    } else |_| {}

    // get_stake_account: borrow account[0], owner must == stake program.
    // @prov:stake-builtin.deactivate-delinquent — dispatch calls getStakeAccount
    // BEFORE checkNumberOfAccounts(3); both fold to M7 so order is non-consensus,
    // but mirror canonical for clarity.
    const stake_idx = frame.account_indices[0];
    if (stake_idx >= ctx.tx.accounts.len) return error.M9_Stake_AccountIndexOutOfBounds;
    const stake = &ctx.tx.accounts[stake_idx];
    if (!std.mem.eql(u8, &stake.owner, &STAKE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (!stake.is_writable) return error.M9_Stake_AccountNotWritable;

    // checkNumberOfAccounts(3): stake[0], delinquent[1], reference[2].
    if (frame.account_indices.len < 3) return error.M9_Stake_NotEnoughAccounts;
    const delq_idx = frame.account_indices[1];
    const ref_idx = frame.account_indices[2];
    if (delq_idx >= ctx.tx.accounts.len or ref_idx >= ctx.tx.accounts.len)
        return error.M9_Stake_AccountIndexOutOfBounds;
    const delq = &ctx.tx.accounts[delq_idx];
    const ref = &ctx.tx.accounts[ref_idx];

    const clock = ctx.sysvar_cache.getClock() catch return error.M9_Stake_ClockUnavailable;

    // delinquent vote account: owner==Vote111 (IncorrectProgramId), then parse.
    if (!std.mem.eql(u8, &delq.owner, &VOTE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    // Parse the delinquent vote state up front (canonical deserializes both vote
    // states before acceptableReference). A malformed delinquent acct FAILS the tx
    // (MalformedVoteState → M7), it is NEVER silently treated as empty→eligible.
    _ = try voteEpochCreditsRegion(delq.data);

    // reference vote account: owner==Vote111, then acceptableReference.
    if (!std.mem.eql(u8, &ref.owner, &VOTE_PROGRAM_ID)) return error.M9_Stake_InvalidAccountOwner;
    if (!try acceptableReference(ref.data, clock.epoch)) return error.M9_Stake_InsufficientReferenceVotes;

    // stake must be Stake(2) — else InvalidAccountData.
    if (stake.data.len < STAKE_STATE_SZ) return error.M9_Stake_InvalidAccountData;
    if (std.mem.readInt(u32, stake.data[0..4], .little) != STAKE_DISC_STAKE)
        return error.M9_Stake_InvalidAccountData;

    // voter_pubkey == delinquent vote ACCOUNT pubkey (compares
    // stake.delegation.voter_pubkey to delinquent_vote_account_meta.pubkey).
    // @prov:stake-builtin.deactivate-delinquent
    if (!std.mem.eql(u8, stake.data[STAKE_OFF_VOTER..][0..32], &delq.pubkey))
        return error.M9_Stake_VoteAddressMismatch;

    // eligible: delinquent voted >=5 epochs ago (or never).
    if (!try eligibleDelinquent(delq.data, clock.epoch))
        return error.M9_Stake_MinimumDelinquentEpochsNotMet;

    // stake.deactivate(epoch): AlreadyDeactivated if deactivation_epoch != MAX.
    if (std.mem.readInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little) != std.math.maxInt(u64))
        return error.M9_Stake_AlreadyDeactivated;

    // ── success byte: ONLY deactivation_epoch @172 (identical to tag-5). ──
    std.mem.writeInt(u64, stake.data[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], clock.epoch, .little);
}

pub fn selfTest() bool {
    return COMPUTE_UNITS == 750;
}

// ── Tests ─────────────────────────────────────────────────────────────────

const Harness = @import("test_harness.zig").Harness;

test "M9 stake: empty data rejected" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    try t.expectError(error.M9_Stake_InvalidInstructionData, execute(h.ctx, &.{}));
}

test "M9 stake: unknown tag rejected" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 99, .little);
    try t.expectError(error.M9_Stake_UnknownInstructionTag, execute(h.ctx, &data));
}

// tag=2 now dispatches to executeDelegate (NOT a VariantPending stub). With no
// accounts on the frame it must fail the account-count boundary (>=5), proving the
// stub is gone and the canonical handler runs.
test "M9 stake: tag=2 dispatches to executeDelegate (NotEnoughAccounts on empty frame)" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 2, .little);
    try t.expectError(error.M9_Stake_NotEnoughAccounts, execute(h.ctx, &data));
}

test "M9 stake: OutOfCompute when meter short" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100, &.{});
    defer h.deinit();
    try t.expectError(error.M9_Stake_OutOfCompute, execute(h.ctx, &.{}));
}

// CARRIER 415214214 KAT — BPF→CPI Deactivate (tag 5). The exact shape that
// diverged: a Stake(2) account, deactivation_epoch=MAX, staker authority signs.
// Pre-fix: error.M9_Stake_VariantPending_Deactivate (this test FAILS).
// Post-fix: deactivation_epoch byte at offset 172 == clock.epoch, all else intact.
test "M9 stake: Deactivate (tag 5) sets deactivation_epoch — carrier 415214214 shape" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    staker[31] = 0xCD;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .is_writable = true }, // [0] stake account (Stake state)
        .{ .data_len = 0 }, // [1] Clock sysvar (placeholder; epoch from cache)
        .{ .pubkey = staker, .is_signer = true }, // [2] staker authority (signs)
    });
    defer h.deinit();

    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 2, .little); // disc = Stake(2)
    @memcpy(sdata[12..44], &staker); // meta.authorized.staker = staker
    std.mem.writeInt(u64, sdata[172..180], std.math.maxInt(u64), .little); // not yet deactivating

    // Populate Clock sysvar at epoch 974.
    h.cache.clock_view = .{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 974,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();

    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 5, .little); // Deactivate
    try execute(h.ctx, &ix);

    // deactivation_epoch == clock epoch; discriminant unchanged.
    try t.expectEqual(@as(u64, 974), std.mem.readInt(u64, h.accounts[0].data[172..180], .little));
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, h.accounts[0].data[0..4], .little));
}

// Already-deactivating → AlreadyDeactivated (canonical Custom(2)); no write.
test "M9 stake: Deactivate rejects already-deactivating stake" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0x11;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 2, .little);
    @memcpy(sdata[12..44], &staker);
    std.mem.writeInt(u64, sdata[172..180], 500, .little); // already deactivating @ epoch 500
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 5, .little);
    try t.expectError(error.M9_Stake_AlreadyDeactivated, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 500), std.mem.readInt(u64, h.accounts[0].data[172..180], .little)); // unchanged
}

// Staker authority did not sign → MissingRequiredSignature (canonical).
test "M9 stake: Deactivate rejects when staker did not sign" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0x22;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = false }, // present but NOT signing
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 2, .little);
    @memcpy(sdata[12..44], &staker);
    std.mem.writeInt(u64, sdata[172..180], std.math.maxInt(u64), .little);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 5, .little);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, &ix));
}

// ── Authorize (tag 1) KATs — carrier 415547068 shape ────────────────────────

// Staker change (type 0): current staker signs → staker pubkey at offset 12
// becomes new_authority; everything else byte-unchanged. This is the carrier shape
// (a "deposit" PDA reassigning the staker authority via CPI).
test "M9 stake: Authorize Staker (tag 1) sets staker @offset 12 — carrier 415547068 shape" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    staker[31] = 0xA1;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var new_auth: [32]u8 = std.mem.zeroes([32]u8);
    new_auth[0] = 0xCC;
    new_auth[31] = 0xC9;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .data_len = 0 }, // [1] Clock (placeholder)
        .{ .pubkey = staker, .is_signer = true }, // [2] staker authority signs
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 1, .little); // disc = Initialized(1)
    @memcpy(sdata[12..44], &staker);
    @memcpy(sdata[44..76], &withdrawer);

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();

    var ix: [40]u8 = std.mem.zeroes([40]u8);
    std.mem.writeInt(u32, ix[0..4], 1, .little); // Authorize
    @memcpy(ix[4..36], &new_auth);
    std.mem.writeInt(u32, ix[36..40], 0, .little); // Staker
    try execute(h.ctx, &ix);

    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[12..44]); // staker := new
    try t.expectEqualSlices(u8, &withdrawer, h.accounts[0].data[44..76]); // withdrawer unchanged
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // disc unchanged
}

// Withdrawer change (type 1), lockup NOT in force: withdrawer signs → offset 44 := new.
test "M9 stake: Authorize Withdrawer (tag 1) sets withdrawer @offset 44 (no lockup)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    withdrawer[31] = 0xB7;
    var new_auth: [32]u8 = std.mem.zeroes([32]u8);
    new_auth[0] = 0xDD;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = withdrawer, .is_signer = true }, // withdrawer signs
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 2, .little); // disc = Stake(2) — both states work
    @memcpy(sdata[12..44], &staker);
    @memcpy(sdata[44..76], &withdrawer);
    // lockup zeroed → not in force.
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 100, .leader_schedule_epoch = 0, .unix_timestamp = 1_000_000 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();

    var ix: [40]u8 = std.mem.zeroes([40]u8);
    std.mem.writeInt(u32, ix[0..4], 1, .little);
    @memcpy(ix[4..36], &new_auth);
    std.mem.writeInt(u32, ix[36..40], 1, .little); // Withdrawer
    try execute(h.ctx, &ix);

    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[44..76]); // withdrawer := new
    try t.expectEqualSlices(u8, &staker, h.accounts[0].data[12..44]); // staker unchanged
}

// Withdrawer change with lockup IN FORCE + custodian signs but != lockup.custodian
// → LockupInForce (Custom 1); account data must be UNCHANGED on the error path.
test "M9 stake: Authorize Withdrawer rejects when lockup in force (LockupInForce)" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var lk_custodian: [32]u8 = std.mem.zeroes([32]u8);
    lk_custodian[0] = 0xEE;
    var wrong_custodian: [32]u8 = std.mem.zeroes([32]u8);
    wrong_custodian[0] = 0xFF;
    var new_auth: [32]u8 = std.mem.zeroes([32]u8);
    new_auth[0] = 0xDD;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .data_len = 0 }, // [1] Clock
        .{ .pubkey = withdrawer, .is_signer = true }, // [2] withdrawer signs
        .{ .pubkey = wrong_custodian, .is_signer = true }, // [3] custodian signs but wrong key
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 2, .little);
    @memcpy(sdata[44..76], &withdrawer);
    std.mem.writeInt(u64, sdata[84..92], 200, .little); // lockup.epoch = 200 (future)
    @memcpy(sdata[92..124], &lk_custodian); // lockup.custodian = EE
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 100, .leader_schedule_epoch = 0, .unix_timestamp = 0 }; // 100 < 200 → in force

    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();

    var ix: [40]u8 = std.mem.zeroes([40]u8);
    std.mem.writeInt(u32, ix[0..4], 1, .little);
    @memcpy(ix[4..36], &new_auth);
    std.mem.writeInt(u32, ix[36..40], 1, .little); // Withdrawer
    try t.expectError(error.M9_Stake_LockupInForce, execute(h.ctx, &ix));
    try t.expectEqualSlices(u8, &withdrawer, h.accounts[0].data[44..76]); // UNCHANGED on error
}

// Authorize with no valid signer → MissingRequiredSignature (no write).
test "M9 stake: Authorize Staker rejects when neither staker nor withdrawer signed" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var other: [32]u8 = std.mem.zeroes([32]u8);
    other[0] = 0x99;
    var new_auth: [32]u8 = std.mem.zeroes([32]u8);
    new_auth[0] = 0xCC;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = other, .is_signer = true }, // a signer, but NOT staker/withdrawer
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 1, .little);
    @memcpy(sdata[12..44], &staker);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [40]u8 = std.mem.zeroes([40]u8);
    std.mem.writeInt(u32, ix[0..4], 1, .little);
    @memcpy(ix[4..36], &new_auth);
    std.mem.writeInt(u32, ix[36..40], 0, .little);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, &ix));
    try t.expectEqualSlices(u8, &staker, h.accounts[0].data[12..44]); // unchanged
}

// ── AuthorizeChecked (tag 10) KATs — canonical Agave v5 ─────────────────────

// KAT #1 (success, Staker): new authority at acct[3] signs → staker@12 := acct[3].pubkey.
test "M9 stake: AuthorizeChecked Staker (tag 10) sets staker @12 from acct[3]" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    staker[31] = 0xA1;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var new_auth: [32]u8 = std.mem.zeroes([32]u8);
    new_auth[0] = 0xCC;
    new_auth[31] = 0xC9;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .data_len = 0 }, // [1] Clock
        .{ .pubkey = staker, .is_signer = true }, // [2] old auth signs
        .{ .pubkey = new_auth, .is_signer = true }, // [3] new auth signs
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 1, .little); // Initialized
    @memcpy(sdata[12..44], &staker);
    @memcpy(sdata[44..76], &withdrawer);
    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [8]u8 = std.mem.zeroes([8]u8);
    std.mem.writeInt(u32, ix[0..4], 10, .little); // AuthorizeChecked
    std.mem.writeInt(u32, ix[4..8], 0, .little); // Staker
    try execute(h.ctx, &ix);
    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[12..44]);
    try t.expectEqualSlices(u8, &withdrawer, h.accounts[0].data[44..76]);
}

// KAT #2 (DEFINING rejection — the only thing distinguishing Checked from tag 1):
// new authority at acct[3] does NOT sign → MissingRequiredSignature, no write.
test "M9 stake: AuthorizeChecked rejects when new authority (acct[3]) did not sign" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var new_auth: [32]u8 = std.mem.zeroes([32]u8);
    new_auth[0] = 0xCC;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true }, // [2] old auth signs
        .{ .pubkey = new_auth, .is_signer = false }, // [3] new auth does NOT sign
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 1, .little);
    @memcpy(sdata[12..44], &staker);
    @memcpy(sdata[44..76], &withdrawer);
    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [8]u8 = std.mem.zeroes([8]u8);
    std.mem.writeInt(u32, ix[0..4], 10, .little);
    std.mem.writeInt(u32, ix[4..8], 0, .little);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, &ix));
    try t.expectEqualSlices(u8, &staker, h.accounts[0].data[12..44]); // UNCHANGED
}

// KAT #3 (rejection): only 3 accounts (no new-authority slot) → NotEnoughAccounts.
test "M9 stake: AuthorizeChecked rejects with <4 accounts" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [8]u8 = std.mem.zeroes([8]u8);
    std.mem.writeInt(u32, ix[0..4], 10, .little);
    try t.expectError(error.M9_Stake_NotEnoughAccounts, execute(h.ctx, &ix));
}

// KAT #4 (success, Withdrawer, no lockup): new auth signs → withdrawer@44 := acct[3].pubkey.
test "M9 stake: AuthorizeChecked Withdrawer (tag 10) sets withdrawer @44, no lockup" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    withdrawer[31] = 0xB7;
    var new_auth: [32]u8 = std.mem.zeroes([32]u8);
    new_auth[0] = 0xDD;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = withdrawer, .is_signer = true }, // [2] old withdrawer signs
        .{ .pubkey = new_auth, .is_signer = true }, // [3] new auth signs
    });
    defer h.deinit();
    const sdata = h.accounts[0].data;
    std.mem.writeInt(u32, sdata[0..4], 2, .little); // Stake(2)
    @memcpy(sdata[12..44], &staker);
    @memcpy(sdata[44..76], &withdrawer);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 100, .leader_schedule_epoch = 0, .unix_timestamp = 1_000_000 };
    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [8]u8 = std.mem.zeroes([8]u8);
    std.mem.writeInt(u32, ix[0..4], 10, .little);
    std.mem.writeInt(u32, ix[4..8], 1, .little); // Withdrawer
    try execute(h.ctx, &ix);
    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[44..76]);
    try t.expectEqualSlices(u8, &staker, h.accounts[0].data[12..44]);
}

// ── AuthorizeWithSeed (tag 8) KATs — BPF stake v5 (SIMD-0490) ───────────────
//
// Signer set = {D=SHA256(base|seed|owner)} ONLY if base@1 signed. Wire layout:
// tag(4)+new_auth[32]+u32 type+u64 seed_len+seed+owner[32].

// Build tag-8 ix data into `buf`, returns the written length.
fn buildAuthWithSeed(buf: []u8, new_auth: [32]u8, atype: u32, seed: []const u8, owner: [32]u8) usize {
    std.mem.writeInt(u32, buf[0..4], 8, .little);
    @memcpy(buf[4..36], &new_auth);
    std.mem.writeInt(u32, buf[36..40], atype, .little);
    std.mem.writeInt(u64, buf[40..48], seed.len, .little);
    @memcpy(buf[48..][0..seed.len], seed);
    @memcpy(buf[48 + seed.len ..][0..32], &owner);
    return 48 + seed.len + 32;
}

// Compute D = SHA256(base|seed|owner) for the expected derived authority.
fn deriveD(base: [32]u8, seed: []const u8, owner: [32]u8) [32]u8 {
    var hd = std.crypto.hash.sha2.Sha256.init(.{});
    hd.update(&base);
    hd.update(seed);
    hd.update(&owner);
    var d: [32]u8 = undefined;
    hd.final(&d);
    return d;
}

test "M9 stake: AuthorizeWithSeed (tag 8) Staker success — derived D == current staker" {
    const t = std.testing;
    const seed = "deposit";
    const owner = [_]u8{0x09} ** 32; // not the PDA marker
    var base: [32]u8 = undefined;
    @memset(&base, 0x77);
    const D = deriveD(base, seed, owner);
    var new_auth: [32]u8 = undefined;
    @memset(&new_auth, 0x42);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = base, .is_signer = true }, // [1] base SIGNER
        .{ .data_len = 0 }, // [2] Clock placeholder
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little); // Initialized(1)
    @memcpy(sd[12..44], &D); // current staker = derived authority
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthWithSeed(&ix, new_auth, 0, seed, owner);
    try execute(h.ctx, ix[0..n]);

    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[12..44]); // staker updated
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // disc intact
}

test "M9 stake: AuthorizeWithSeed rejects when base did NOT sign" {
    const t = std.testing;
    const seed = "deposit";
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x77);
    const D = deriveD(base, seed, owner);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = base, .is_signer = false }, // [1] base did NOT sign
        .{ .data_len = 0 },
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little);
    @memcpy(sd[12..44], &D);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthWithSeed(&ix, [_]u8{0x42} ** 32, 0, seed, owner);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, ix[0..n]));
    try t.expectEqualSlices(u8, &D, h.accounts[0].data[12..44]); // unchanged on reject
}

test "M9 stake: AuthorizeWithSeed rejects when derived D != current staker" {
    const t = std.testing;
    const seed = "wrong";
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x77);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = base, .is_signer = true },
        .{ .data_len = 0 },
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little);
    @memset(sd[12..44], 0xEE); // current staker is some OTHER key (not D)
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthWithSeed(&ix, [_]u8{0x42} ** 32, 0, seed, owner);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, ix[0..n]));
}

test "M9 stake: AuthorizeWithSeed Withdrawer success (no lockup) — D == withdrawer" {
    const t = std.testing;
    const seed = "withdraw";
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x33);
    const D = deriveD(base, seed, owner);
    var new_auth: [32]u8 = undefined;
    @memset(&new_auth, 0x55);
    var staker: [32]u8 = undefined;
    @memset(&staker, 0xAA);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = base, .is_signer = true },
        .{ .data_len = 0 },
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little);
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &D); // current withdrawer = derived
    // lockup ts/epoch left 0 → not in force.
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 1000 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthWithSeed(&ix, new_auth, 1, seed, owner);
    try execute(h.ctx, ix[0..n]);

    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[44..76]); // withdrawer updated
    try t.expectEqualSlices(u8, &staker, h.accounts[0].data[12..44]); // staker untouched
}

// Withdrawer + lockup IN FORCE, custodian == D (the derived signer) and custodian
// == lockup.custodian → bypass → success. Exercises the tag-8-specific custodian
// path (custodian counts only because it equals D).
test "M9 stake: AuthorizeWithSeed Withdrawer lockup-in-force bypass (custodian == D == lockup.custodian)" {
    const t = std.testing;
    const seed = "lock";
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x44);
    const D = deriveD(base, seed, owner); // D is BOTH the withdrawer AND the lockup custodian
    var new_auth: [32]u8 = undefined;
    @memset(&new_auth, 0x66);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = base, .is_signer = true }, // [1] base SIGNER → D
        .{ .data_len = 0 }, // [2] Clock
        .{ .pubkey = D, .is_signer = false }, // [3] custodian acct = D (signer-not-required at fetch)
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little); // Stake(2)
    @memcpy(sd[44..76], &D); // withdrawer = D
    std.mem.writeInt(u64, sd[84..92], 2000, .little); // lockup.epoch = 2000 (future → in force)
    @memcpy(sd[92..124], &D); // lockup.custodian = D → custodian==D bypasses
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthWithSeed(&ix, new_auth, 1, seed, owner);
    try execute(h.ctx, ix[0..n]);

    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[44..76]); // withdrawer updated despite lockup
}

// ── AuthorizeCheckedWithSeed (tag 11) KATs — BPF stake v5 (SIMD-0490) ────────
//
// tag 8 + Checked: new authority = accounts[3].pubkey (must sign), base@1 derives D,
// custodian@4, >=4 accounts. Wire layout (stake_authorize FIRST): tag(4)+u32 type+
// u64 seed_len+seed+owner[32]. Reuses deriveD() from the tag-8 KAT block.

// Build tag-11 ix data into `buf`, returns the written length.
fn buildAuthCheckedWithSeed(buf: []u8, atype: u32, seed: []const u8, owner: [32]u8) usize {
    std.mem.writeInt(u32, buf[0..4], 11, .little);
    std.mem.writeInt(u32, buf[4..8], atype, .little);
    std.mem.writeInt(u64, buf[8..16], seed.len, .little);
    @memcpy(buf[16..][0..seed.len], seed);
    @memcpy(buf[16 + seed.len ..][0..32], &owner);
    return 16 + seed.len + 32;
}

test "M9 stake: AuthorizeCheckedWithSeed (tag 11) Staker — derived base signs, new auth = acct[3]" {
    const t = std.testing;
    const seed = "stake:authority";
    const owner = [_]u8{0x09} ** 32; // not the PDA marker
    var base: [32]u8 = undefined;
    @memset(&base, 0x11);
    const D = deriveD(base, seed, owner); // D = current staker
    var withdrawer: [32]u8 = undefined;
    @memset(&withdrawer, 0xBB);
    var new_auth: [32]u8 = undefined;
    @memset(&new_auth, 0xCC);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = base, .is_signer = true }, // [1] base/seed authority signs → D
        .{ .data_len = 0 }, // [2] Clock placeholder
        .{ .pubkey = new_auth, .is_signer = true }, // [3] new authority signs (Checked)
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little); // Initialized
    @memcpy(sd[12..44], &D); // staker = derived key
    @memcpy(sd[44..76], &withdrawer);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthCheckedWithSeed(&ix, 0, seed, owner);
    try execute(h.ctx, ix[0..n]);

    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[12..44]); // staker := new
    try t.expectEqualSlices(u8, &withdrawer, h.accounts[0].data[44..76]); // withdrawer unchanged
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // disc intact
}

test "M9 stake: AuthorizeCheckedWithSeed rejects when acct[3] (new auth) did not sign" {
    const t = std.testing;
    const seed = "x";
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x11);
    const D = deriveD(base, seed, owner);
    var new_auth: [32]u8 = undefined;
    @memset(&new_auth, 0xCC);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = base, .is_signer = true }, // [1] base signs
        .{ .data_len = 0 },
        .{ .pubkey = new_auth, .is_signer = false }, // [3] new auth does NOT sign → MissingRequiredSignature
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    @memcpy(h.accounts[0].data[12..44], &D);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthCheckedWithSeed(&ix, 0, seed, owner);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, ix[0..n]));
    try t.expectEqualSlices(u8, &D, h.accounts[0].data[12..44]); // staker unchanged (no partial write)
}

test "M9 stake: AuthorizeCheckedWithSeed rejects wrong seed (derived != staker) → MissingRequiredSignature" {
    const t = std.testing;
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x11);
    var real_staker: [32]u8 = undefined;
    @memset(&real_staker, 0x77); // NOT the derived key
    var new_auth: [32]u8 = undefined;
    @memset(&new_auth, 0xCC);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = base, .is_signer = true },
        .{ .data_len = 0 },
        .{ .pubkey = new_auth, .is_signer = true }, // new auth signs (so we reach the old-auth check)
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    @memcpy(h.accounts[0].data[12..44], &real_staker);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthCheckedWithSeed(&ix, 0, "wrong", owner);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, ix[0..n]));
}

test "M9 stake: AuthorizeCheckedWithSeed rejects when fewer than 4 accounts" {
    const t = std.testing;
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x11);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = base, .is_signer = true },
        .{ .data_len = 0 },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 }); // only 3
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthCheckedWithSeed(&ix, 0, "s", owner);
    try t.expectError(error.M9_Stake_NotEnoughAccounts, execute(h.ctx, ix[0..n]));
}

test "M9 stake: AuthorizeCheckedWithSeed Withdrawer success (no lockup) — D == withdrawer, new auth signs" {
    const t = std.testing;
    const seed = "withdraw";
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x33);
    const D = deriveD(base, seed, owner); // D = current withdrawer
    var staker: [32]u8 = undefined;
    @memset(&staker, 0xAA);
    var new_auth: [32]u8 = undefined;
    @memset(&new_auth, 0x55);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = base, .is_signer = true }, // [1] base → D
        .{ .data_len = 0 }, // [2] Clock
        .{ .pubkey = new_auth, .is_signer = true }, // [3] new auth signs
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little);
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &D); // current withdrawer = derived
    // lockup left 0 → not in force.
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 1000 };

    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthCheckedWithSeed(&ix, 1, seed, owner);
    try execute(h.ctx, ix[0..n]);

    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[44..76]); // withdrawer updated
    try t.expectEqualSlices(u8, &staker, h.accounts[0].data[12..44]); // staker untouched
}

test "M9 stake: AuthorizeCheckedWithSeed Withdrawer lockup-in-force bypass (custodian@4 == D == lockup.custodian)" {
    const t = std.testing;
    const seed = "lock";
    const owner = [_]u8{0x09} ** 32;
    var base: [32]u8 = undefined;
    @memset(&base, 0x44);
    const D = deriveD(base, seed, owner); // D = withdrawer AND lockup custodian
    var new_auth: [32]u8 = undefined;
    @memset(&new_auth, 0x66);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = base, .is_signer = true }, // [1] base → D
        .{ .data_len = 0 }, // [2] Clock
        .{ .pubkey = new_auth, .is_signer = true }, // [3] new auth signs
        .{ .pubkey = D, .is_signer = false }, // [4] custodian acct = D (signer-not-required at fetch)
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little); // Stake(2)
    @memcpy(sd[44..76], &D); // withdrawer = D
    std.mem.writeInt(u64, sd[84..92], 2000, .little); // lockup.epoch = 2000 (future → in force)
    @memcpy(sd[92..124], &D); // lockup.custodian = D → custodian==D bypasses
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildAuthCheckedWithSeed(&ix, 1, seed, owner);
    try execute(h.ctx, ix[0..n]);

    try t.expectEqualSlices(u8, &new_auth, h.accounts[0].data[44..76]); // withdrawer updated despite lockup
}

// ── Merge (tag 7) KATs — BPF stake v5 (SIMD-0490) ───────────────────────────

const MAXU64 = std.math.maxInt(u64);

// Helper: set the Clock view at a given epoch.
fn setClock(h: anytype, epoch: u64, unix_ts: i64) void {
    h.cache.clock_view = .{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = epoch,
        .leader_schedule_epoch = 0,
        .unix_timestamp = unix_ts,
    };
}

// (Inactive,Inactive) → no-op merge: dst data byte-identical, dst gains src
// lamports, src drained to disc=0 with tail preserved. Lamports conservation.
test "M9 stake: Merge (tag 7) Inactive+Inactive — no-op, tail preserved, conservation" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 1000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] dst
        .{ .lamports = 500, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [1] src
        .{ .data_len = 0 }, // [2] Clock
        .{ .data_len = 0 }, // [3] StakeHistory
        .{ .pubkey = staker, .is_signer = true }, // [4] staker authority
    });
    defer h.deinit();
    for ([_]usize{ 0, 1 }) |i| {
        const d = h.accounts[i].data;
        std.mem.writeInt(u32, d[0..4], 1, .little); // Initialized = Inactive
        @memcpy(d[12..44], &staker);
        @memcpy(d[44..76], &withdrawer);
    }
    // give src a recognizable tail
    h.accounts[1].data[150] = 0x77;
    var dst_before: [200]u8 = undefined;
    @memcpy(&dst_before, h.accounts[0].data[0..200]);

    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 7, .little);
    try execute(h.ctx, &ix);

    try t.expectEqualSlices(u8, &dst_before, h.accounts[0].data[0..200]); // dst data unchanged
    try t.expectEqual(@as(u64, 1500), h.accounts[0].lamports); // gained src lamports
    try t.expectEqual(@as(u64, 0), h.accounts[1].lamports); // src drained
    try t.expectEqual(@as(u32, 0), std.mem.readInt(u32, h.accounts[1].data[0..4], .little)); // disc=0
    try t.expectEqual(@as(u8, 0x77), h.accounts[1].data[150]); // src tail preserved
}

// (FullyActive,FullyActive) → credits blend + flags=0. absorbed = src.delegation.stake.
test "M9 stake: Merge FullyActive+FullyActive — credits weighted, flags=0" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 5000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .lamports = 3000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    // Stake(2), activated epoch 10, deact=MAX, history makes both fully effective.
    for ([_]usize{ 0, 1 }) |i| {
        const d = h.accounts[i].data;
        std.mem.writeInt(u32, d[0..4], 2, .little);
        @memcpy(d[12..44], &staker);
        @memcpy(d[44..76], &withdrawer);
        @memcpy(d[124..156], &voter);
        std.mem.writeInt(u64, d[164..172], 10, .little); // activation_epoch
        std.mem.writeInt(u64, d[172..180], MAXU64, .little); // deact = MAX
        d[196] = 0x03; // some flags set
    }
    std.mem.writeInt(u64, h.accounts[0].data[156..164], 2000, .little); // dst delegation.stake
    std.mem.writeInt(u64, h.accounts[0].data[188..196], 100, .little); // dst credits
    std.mem.writeInt(u64, h.accounts[1].data[156..164], 1000, .little); // src delegation.stake
    std.mem.writeInt(u64, h.accounts[1].data[188..196], 200, .little); // src credits

    // history at epoch 11..: effective huge, activating 0 → fully active at epoch 13.
    // NOTE: SysvarCache.deinit frees stake_history_entries, so it MUST be
    // allocator-owned (a comptime slice literal here triggers an invalid free).
    const hist = try t.allocator.alloc(sysvar_cache.StakeHistoryEntry, 2);
    hist[0] = .{ .epoch = 11, .effective = 1_000_000_000, .activating = 0, .deactivating = 0 };
    hist[1] = .{ .epoch = 12, .effective = 1_000_000_000, .activating = 0, .deactivating = 0 };
    h.cache.stake_history_entries = hist;
    setClock(&h, 13, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 7, .little);
    try execute(h.ctx, &ix);

    // absorbed = src delegation.stake (1000); dst.stake 2000 -> 3000.
    try t.expectEqual(@as(u64, 3000), std.mem.readInt(u64, h.accounts[0].data[156..164], .little));
    // weighted credits = ceil((100*2000 + 200*1000)/3000) = ceil(400000/3000)=134.
    const expected_credits = weightedCreditsObserved(100, 2000, 200, 1000).?;
    try t.expectEqual(expected_credits, std.mem.readInt(u64, h.accounts[0].data[188..196], .little));
    try t.expectEqual(@as(u8, 0), h.accounts[0].data[196]); // flags EMPTY
    try t.expectEqual(@as(u64, 8000), h.accounts[0].lamports); // 5000+3000
    try t.expectEqual(@as(u32, 0), std.mem.readInt(u32, h.accounts[1].data[0..4], .little)); // src disc=0
}

// (ActivationEpoch,ActivationEpoch) → v5 absorbed = src.LAMPORTS (not rent+stake).
// The SIMD-0490 #5 differentiator: src has EXCESS lamports.
test "M9 stake: Merge ActivationEpoch+ActivationEpoch — v5 absorbs src.lamports (excess)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;

    // src.lamports = 9000 but delegation+rent = 1000+500 = 1500 → 7500 excess.
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 5000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .lamports = 9000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    for ([_]usize{ 0, 1 }) |i| {
        const d = h.accounts[i].data;
        std.mem.writeInt(u32, d[0..4], 2, .little);
        @memcpy(d[12..44], &staker);
        @memcpy(d[44..76], &withdrawer);
        @memcpy(d[124..156], &voter);
        std.mem.writeInt(u64, d[164..172], 13, .little); // activation_epoch == clock.epoch → ActivationEpoch
        std.mem.writeInt(u64, d[172..180], MAXU64, .little);
        std.mem.writeInt(u64, d[4..12], 500, .little); // rent_exempt
    }
    std.mem.writeInt(u64, h.accounts[0].data[156..164], 2000, .little); // dst delegation
    std.mem.writeInt(u64, h.accounts[0].data[188..196], 50, .little);
    std.mem.writeInt(u64, h.accounts[1].data[156..164], 1000, .little); // src delegation (NOT used by v5)
    std.mem.writeInt(u64, h.accounts[1].data[188..196], 50, .little);

    setClock(&h, 13, 1_000_000); // epoch == activation_epoch → kind 1 (no history needed)
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 7, .little);
    try execute(h.ctx, &ix);

    // v5: dst.stake += src.LAMPORTS (9000), NOT src.delegation(1000) or rent+stake(1500).
    try t.expectEqual(@as(u64, 11000), std.mem.readInt(u64, h.accounts[0].data[156..164], .little));
    try t.expectEqual(@as(u64, 14000), h.accounts[0].lamports); // 5000+9000
}

// (ActivationEpoch,ActivationEpoch) with dst.deactivation_epoch != MAX → MergeMismatch.
// active_delegations_can_merge (merge.rs:113-117) requires BOTH deact==MAX; the v5 gap
// was that the (1,1) arm omitted this gate (the (2,2) arm had it). Discriminator: the
// UNPATCHED code would SUCCEED here (voter matches, no deact gate) and mutate dst —
// so the unchanged-dst assertions only hold BECAUSE of the new gate. deact is set to a
// FUTURE epoch (100 > clock.epoch 13), which does NOT change getMergeKind classification
// (still kind 1 / ActivationEpoch), so we genuinely reach the new check.
test "M9 stake: Merge ActivationEpoch+ActivationEpoch rejects dst deact!=MAX (MergeMismatch), no mutation" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 5000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .lamports = 9000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    for ([_]usize{ 0, 1 }) |i| {
        const d = h.accounts[i].data;
        std.mem.writeInt(u32, d[0..4], 2, .little);
        @memcpy(d[12..44], &staker);
        @memcpy(d[44..76], &withdrawer);
        @memcpy(d[124..156], &voter);
        std.mem.writeInt(u64, d[164..172], 13, .little); // activation_epoch == clock.epoch → ActivationEpoch
        std.mem.writeInt(u64, d[172..180], MAXU64, .little);
        std.mem.writeInt(u64, d[4..12], 500, .little); // rent_exempt
    }
    std.mem.writeInt(u64, h.accounts[0].data[156..164], 2000, .little); // dst delegation
    std.mem.writeInt(u64, h.accounts[0].data[188..196], 50, .little);
    std.mem.writeInt(u64, h.accounts[1].data[156..164], 1000, .little); // src delegation
    std.mem.writeInt(u64, h.accounts[1].data[188..196], 50, .little);
    // dst.deactivation_epoch = 100 (a FUTURE epoch > clock.epoch 13): violates the
    // ==MAX gate but leaves classification at kind 1 (ActivationEpoch).
    std.mem.writeInt(u64, h.accounts[0].data[172..180], 100, .little);

    // Snapshot dst delegation.stake + lamports to prove no mutation on the error path.
    const dst_stake_before = std.mem.readInt(u64, h.accounts[0].data[156..164], .little);
    const dst_lamports_before = h.accounts[0].lamports;

    setClock(&h, 13, 1_000_000); // epoch == activation_epoch → kind 1 (no history needed)
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 7, .little);
    try t.expectError(error.M9_Stake_MergeMismatch, execute(h.ctx, &ix));

    // dst UNCHANGED: delegation.stake still 2000, lamports still 5000, src not drained.
    try t.expectEqual(dst_stake_before, std.mem.readInt(u64, h.accounts[0].data[156..164], .little));
    try t.expectEqual(dst_lamports_before, h.accounts[0].lamports);
    try t.expectEqual(@as(u64, 9000), h.accounts[1].lamports);
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, h.accounts[1].data[0..4], .little)); // src disc still Stake(2)
}

// metas mismatch (withdrawer differs) → MergeMismatch; both accounts unchanged.
test "M9 stake: Merge rejects metas mismatch (MergeMismatch), no mutation" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var w1: [32]u8 = std.mem.zeroes([32]u8);
    w1[0] = 0xB1;
    var w2: [32]u8 = std.mem.zeroes([32]u8);
    w2[0] = 0xB2;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 1000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .lamports = 500, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    @memcpy(h.accounts[0].data[44..76], &w1);
    std.mem.writeInt(u32, h.accounts[1].data[0..4], 1, .little);
    @memcpy(h.accounts[1].data[12..44], &staker);
    @memcpy(h.accounts[1].data[44..76], &w2); // different withdrawer

    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 7, .little);
    try t.expectError(error.M9_Stake_MergeMismatch, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 1000), h.accounts[0].lamports);
    try t.expectEqual(@as(u64, 500), h.accounts[1].lamports);
}

// dst index == src index → InvalidArgument; no mutation.
test "M9 stake: Merge rejects dst==src index (InvalidArgument)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 1000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 0, 1, 2, 3 }); // dst_idx == src_idx == 0
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 7, .little);
    try t.expectError(error.M9_Stake_InvalidArgument, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 1000), h.accounts[0].lamports);
}

// ── Withdraw (tag 4) KATs ───────────────────────────────────────────────────

// Partial withdraw from Initialized: lamports move, stake data byte-identical.
test "M9 stake: Withdraw partial (Initialized) — lamports move, data unchanged" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 10_000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .lamports = 0, .data_len = 0, .is_writable = true }, // [1] recipient
        .{ .data_len = 0 }, // [2] Clock
        .{ .data_len = 0 }, // [3] StakeHistory
        .{ .pubkey = withdrawer, .is_signer = true }, // [4] withdraw authority
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little); // Initialized
    @memcpy(h.accounts[0].data[44..76], &withdrawer);
    std.mem.writeInt(u64, h.accounts[0].data[4..12], 2000, .little); // rent_exempt_reserve
    var stake_before: [200]u8 = undefined;
    @memcpy(&stake_before, h.accounts[0].data[0..200]);

    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 4, .little);
    std.mem.writeInt(u64, ix[4..12], 3000, .little); // withdraw 3000 (10000-2000=8000 avail)
    try execute(h.ctx, &ix);

    try t.expectEqual(@as(u64, 7000), h.accounts[0].lamports);
    try t.expectEqual(@as(u64, 3000), h.accounts[1].lamports);
    try t.expectEqualSlices(u8, &stake_before, h.accounts[0].data[0..200]); // data unchanged
}

// Full withdraw (Initialized): disc reset to 0, tail preserved, lamports drained.
test "M9 stake: Withdraw full (Initialized) — disc=0, tail preserved" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 2000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .lamports = 0, .data_len = 0, .is_writable = true },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = withdrawer, .is_signer = true },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    @memcpy(h.accounts[0].data[44..76], &withdrawer);
    std.mem.writeInt(u64, h.accounts[0].data[4..12], 0, .little); // reserve 0 → full withdraw allowed
    h.accounts[0].data[150] = 0x55; // tail marker

    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 4, .little);
    std.mem.writeInt(u64, ix[4..12], 2000, .little); // == stake.lamports → full
    try execute(h.ctx, &ix);

    try t.expectEqual(@as(u64, 0), h.accounts[0].lamports);
    try t.expectEqual(@as(u64, 2000), h.accounts[1].lamports);
    try t.expectEqual(@as(u32, 0), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // disc=0
    try t.expectEqual(@as(u8, 0x55), h.accounts[0].data[150]); // tail preserved
    // withdrawer bytes (part of tail) still present
    try t.expectEqual(@as(u8, 0xBB), h.accounts[0].data[44]);
}

// Insufficient funds: staked account, withdraw + reserve > lamports → reject, no move.
test "M9 stake: Withdraw rejects insufficient funds (InsufficientFunds)" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 5000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .lamports = 0, .data_len = 0, .is_writable = true },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = withdrawer, .is_signer = true },
    });
    defer h.deinit();
    const d = h.accounts[0].data;
    std.mem.writeInt(u32, d[0..4], 2, .little); // Stake
    @memcpy(d[44..76], &withdrawer);
    @memcpy(d[124..156], &voter);
    std.mem.writeInt(u64, d[4..12], 2000, .little); // rent_exempt
    std.mem.writeInt(u64, d[156..164], 3000, .little); // delegation.stake
    std.mem.writeInt(u64, d[164..172], 5, .little); // activation_epoch
    std.mem.writeInt(u64, d[172..180], MAXU64, .little); // not deactivating → staked = delegation = 3000
    // reserve = 3000 + 2000 = 5000; available = 0. withdraw 1 → reject.

    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 4, .little);
    std.mem.writeInt(u64, ix[4..12], 1, .little);
    try t.expectError(error.M9_Stake_InsufficientFunds, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 5000), h.accounts[0].lamports); // unchanged
    try t.expectEqual(@as(u64, 0), h.accounts[1].lamports);
}

// Lockup in force (no/wrong custodian) → LockupInForce; no move.
test "M9 stake: Withdraw rejects lockup in force (LockupInForce)" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .lamports = 5000, .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .lamports = 0, .data_len = 0, .is_writable = true },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = withdrawer, .is_signer = true },
    });
    defer h.deinit();
    const d = h.accounts[0].data;
    std.mem.writeInt(u32, d[0..4], 1, .little); // Initialized
    @memcpy(d[44..76], &withdrawer);
    std.mem.writeInt(u64, d[4..12], 0, .little); // reserve 0
    std.mem.writeInt(u64, d[84..92], 200, .little); // lockup.epoch = 200 (future)

    setClock(&h, 100, 0); // epoch 100 < 200 → in force
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 4, .little);
    std.mem.writeInt(u64, ix[4..12], 1000, .little);
    try t.expectError(error.M9_Stake_LockupInForce, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 5000), h.accounts[0].lamports); // unchanged
    try t.expectEqual(@as(u64, 0), h.accounts[1].lamports);
}

// ── Split (tag 3) KATs — BPF stake v5 (SIMD-0490) ───────────────────────────

// Helper: set the Rent view to the Agave default (lpb=3480, ex=2.0).
fn setDefaultRent(h: anytype) void {
    h.cache.rent_view = .{ .lamports_per_byte_year = 3480, .exemption_threshold = 2.0, .burn_percent = 50 };
}

// KAT 1 — partial split of an ACTIVE Stake(2). The destination is PRE-FUNDED to
// rent-exemption (2_282_880) as a real split target is — required because the
// canonical active+partial path rejects (InsufficientFunds) if an active source's
// split target is not already rent-exempt. dst_deficit then = 0, so
// split_stake_amount = lamports. Verifies dst is a FULL .stake copy (voter/credits/
// flags/epochs inherited), rent_exempt overridden, delegation = lamports.
test "M9 stake: Split (tag 3) partial Stake split — full meta copy, success bytes" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] src Stake
        .{ .data_len = 200, .lamports = 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [1] dst Uninit, pre-funded
        .{ .pubkey = staker, .is_signer = true }, // [2] staker signs
    });
    defer h.deinit();
    const s = h.accounts[0].data;
    std.mem.writeInt(u32, s[0..4], 2, .little); // Stake(2)
    std.mem.writeInt(u64, s[4..12], 2_282_880, .little); // rent_exempt_reserve
    @memcpy(s[12..44], &staker);
    @memcpy(s[44..76], &withdrawer);
    @memcpy(s[124..156], &voter);
    std.mem.writeInt(u64, s[156..164], 4_997_717_120, .little); // delegation.stake = 5SOL - reserve
    std.mem.writeInt(u64, s[164..172], 0, .little); // activation_epoch
    std.mem.writeInt(u64, s[172..180], std.math.maxInt(u64), .little); // deact=MAX (active)
    std.mem.writeInt(u64, s[188..196], 42, .little); // credits_observed
    s[196] = 0x01; // flags

    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    setDefaultRent(&h);

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 3, .little);
    std.mem.writeInt(u64, ix[4..12], 2_000_000_000, .little); // split 2 SOL
    try execute(h.ctx, &ix);

    // src remaining = 3SOL >= reserve+1SOL ok; src.delegation -= remaining_delta(=lamports=2SOL).
    try t.expectEqual(@as(u64, 3_000_000_000), h.accounts[0].lamports);
    try t.expectEqual(@as(u64, 4_997_717_120 - 2_000_000_000), std.mem.readInt(u64, h.accounts[0].data[156..164], .little));
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // src disc unchanged
    // dst: Stake(2), lamports = 2_282_880 + 2SOL, rent_exempt=2_282_880,
    // delegation = lamports - (dest_reserve - dst_prebalance) = 2SOL - (2_282_880-2_282_880) = 2SOL.
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, h.accounts[1].data[0..4], .little));
    try t.expectEqual(@as(u64, 2_282_880 + 2_000_000_000), h.accounts[1].lamports);
    try t.expectEqual(@as(u64, 2_282_880), std.mem.readInt(u64, h.accounts[1].data[4..12], .little));
    try t.expectEqual(@as(u64, 2_000_000_000), std.mem.readInt(u64, h.accounts[1].data[156..164], .little));
    // dst inherits staker/withdrawer/voter/credits/flags from src (full copy).
    try t.expectEqualSlices(u8, h.accounts[0].data[12..44], h.accounts[1].data[12..44]); // staker
    try t.expectEqualSlices(u8, h.accounts[0].data[44..76], h.accounts[1].data[44..76]); // withdrawer
    try t.expectEqualSlices(u8, &voter, h.accounts[1].data[124..156]); // voter
    try t.expectEqual(@as(u64, 42), std.mem.readInt(u64, h.accounts[1].data[188..196], .little)); // credits
    try t.expectEqual(@as(u8, 0x01), h.accounts[1].data[196]); // flags
}

// KAT 2 — REJECT: staker not in signer set → MissingRequiredSignature; no writes.
test "M9 stake: Split rejects when staker absent from signer set" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 0, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = std.mem.zeroes([32]u8), .is_signer = true }, // wrong signer
    });
    defer h.deinit();
    const s = h.accounts[0].data;
    std.mem.writeInt(u32, s[0..4], 2, .little);
    std.mem.writeInt(u64, s[4..12], 2_282_880, .little);
    @memcpy(s[12..44], &staker);
    std.mem.writeInt(u64, s[156..164], 4_997_717_120, .little);
    std.mem.writeInt(u64, s[172..180], std.math.maxInt(u64), .little);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 3, .little);
    std.mem.writeInt(u64, ix[4..12], 2_000_000_000, .little);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 5_000_000_000), h.accounts[0].lamports); // unchanged
    try t.expectEqual(@as(u64, 0), h.accounts[1].lamports);
}

// KAT 3 — REJECT: destination not Uninitialized → InvalidAccountData.
test "M9 stake: Split rejects non-uninitialized destination" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 0, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 2, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    std.mem.writeInt(u32, h.accounts[1].data[0..4], 1, .little); // dst already Initialized → reject
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 3, .little);
    std.mem.writeInt(u64, ix[4..12], 2_000_000_000, .little);
    try t.expectError(error.M9_Stake_InvalidAccountData, execute(h.ctx, &ix));
}

// KAT 4 — REJECT: partial split leaves src.delegation.stake < 1 SOL → InsufficientDelegation.
// src has plenty of lamports + a pre-funded rent-exempt dst (so the InsufficientFunds
// reserve/deficit checks all pass), and is INACTIVE (deact in the past → effective=0,
// so the active+partial dst-rent-exempt check is skipped); delegation is only 1.5 SOL,
// so splitting 1 SOL leaves 0.5 SOL delegated < min_del → InsufficientDelegation.
test "M9 stake: Split rejects sub-min-delegation remainder" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 10_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // dst pre-funded
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    const s = h.accounts[0].data;
    std.mem.writeInt(u32, s[0..4], 2, .little);
    std.mem.writeInt(u64, s[4..12], 2_282_880, .little);
    @memcpy(s[12..44], &staker);
    std.mem.writeInt(u64, s[156..164], 1_500_000_000, .little); // 1.5 SOL delegated
    std.mem.writeInt(u64, s[164..172], 0, .little); // activation_epoch
    std.mem.writeInt(u64, s[172..180], 500, .little); // deactivated @ epoch 500 (< 974) → effective 0 → inactive
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 3, .little);
    std.mem.writeInt(u64, ix[4..12], 1_000_000_000, .little); // remainder delegation 0.5 SOL < 1 SOL
    try t.expectError(error.M9_Stake_InsufficientDelegation, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 10_000_000_000), h.accounts[0].lamports); // unchanged
}

// KAT 5 — full drain of an Initialized(1) source: src→Uninitialized (disc=0, tail
// PRESERVED), dst→Initialized with full meta copy. Lamports conservation.
test "M9 stake: Split full-drain Initialized — src disc=0 tail preserved, dst Initialized" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 3_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] src Initialized
        .{ .data_len = 200, .lamports = 0, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [1] dst Uninitialized
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    const s = h.accounts[0].data;
    std.mem.writeInt(u32, s[0..4], 1, .little); // Initialized(1)
    std.mem.writeInt(u64, s[4..12], 2_282_880, .little); // rent_exempt
    @memcpy(s[12..44], &staker);
    @memcpy(s[44..76], &withdrawer);
    s[150] = 0x99; // src tail marker (must survive close)
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    setDefaultRent(&h);

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 3, .little);
    std.mem.writeInt(u64, ix[4..12], 3_000_000_000, .little); // == src.lamports → full drain
    try execute(h.ctx, &ix);

    // src drained: lamports 0, disc=0, tail (incl marker) preserved.
    try t.expectEqual(@as(u64, 0), h.accounts[0].lamports);
    try t.expectEqual(@as(u32, 0), std.mem.readInt(u32, h.accounts[0].data[0..4], .little));
    try t.expectEqual(@as(u8, 0x99), h.accounts[0].data[150]); // tail PRESERVED (not memset)
    // dst Initialized(1): disc=1, staker/withdrawer copied, rent_exempt overridden.
    try t.expectEqual(@as(u64, 3_000_000_000), h.accounts[1].lamports);
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, h.accounts[1].data[0..4], .little));
    try t.expectEqual(@as(u64, 2_282_880), std.mem.readInt(u64, h.accounts[1].data[4..12], .little));
    try t.expectEqualSlices(u8, &staker, h.accounts[1].data[12..44]);
    try t.expectEqualSlices(u8, &withdrawer, h.accounts[1].data[44..76]);
}

// KAT 6 — Uninitialized source: the source account's OWN pubkey must be a signer.
// Here it signs → success (no state mutation on src data beyond lamports). dst stays
// Uninitialized (disc 0) but gains the lamports.
test "M9 stake: Split Uninitialized source — self-signs, lamports move only" {
    const t = std.testing;
    var src_key: [32]u8 = std.mem.zeroes([32]u8);
    src_key[0] = 0x5A;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .pubkey = src_key, .data_len = 200, .lamports = 4_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true, .is_signer = true }, // [0] src Uninit, self-signs
        .{ .data_len = 200, .lamports = 0, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [1] dst Uninit
    });
    defer h.deinit();
    // src disc already 0 (Uninitialized) from zero-fill.
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 3, .little);
    std.mem.writeInt(u64, ix[4..12], 1_000_000_000, .little); // partial; Uninit has no reserve/min checks
    try execute(h.ctx, &ix);

    try t.expectEqual(@as(u64, 3_000_000_000), h.accounts[0].lamports);
    try t.expectEqual(@as(u64, 1_000_000_000), h.accounts[1].lamports);
    try t.expectEqual(@as(u32, 0), std.mem.readInt(u32, h.accounts[1].data[0..4], .little)); // dst still Uninit
}

// KAT 7 — REJECT: SIMD-0118 EpochRewards window active → EpochRewardsActive (no writes).
test "M9 stake: Split rejects during EpochRewards window" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    const s = h.accounts[0].data;
    std.mem.writeInt(u32, s[0..4], 2, .little);
    std.mem.writeInt(u64, s[4..12], 2_282_880, .little);
    @memcpy(s[12..44], &staker);
    std.mem.writeInt(u64, s[156..164], 4_997_717_120, .little);
    std.mem.writeInt(u64, s[172..180], std.math.maxInt(u64), .little);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    setDefaultRent(&h);
    h.cache.epoch_rewards_view = .{ .distribution_starting_block_height = 0, .num_partitions = 1, .parent_blockhash = std.mem.zeroes([32]u8), .total_points = 0, .total_rewards = 0, .distributed_rewards = 0, .active = true };
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 3, .little);
    std.mem.writeInt(u64, ix[4..12], 2_000_000_000, .little);
    try t.expectError(error.M9_Stake_EpochRewardsActive, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 5_000_000_000), h.accounts[0].lamports); // unchanged
}

// ── MoveStake (tag 16) KATs — BPF stake v5 (SIMD-0148/0490) ─────────────────

// KAT 1 (SUCCESS, FullyActive→Inactive dest, full move): source drains to
// Initialized(disc=1, tail preserved); dest adopts source's delegation body with
// delegation.stake=lamports, flags=0, disc→2. Lamports conserve by ix arg.
test "M9 stake: MoveStake (tag 16) FullyActive→Inactive dest, full move" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;
    const MOVE: u64 = 5 * 1_000_000_000; // 5 SOL (> 1 SOL min)
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 6_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] src
        .{ .data_len = 200, .lamports = 1_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [1] dst
        .{ .pubkey = staker, .is_signer = true }, // [2] authority == staker
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE; // distinct src key (not-same-account check)
    // src: Stake(2) FullyActive, stake=MOVE, deact=MAX, voter set, credits=100, reserve@4=1 SOL
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    std.mem.writeInt(u64, sd[4..12], 1_000_000_000, .little); // rent_exempt_reserve
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &withdrawer);
    @memcpy(sd[124..156], &voter);
    std.mem.writeInt(u64, sd[156..164], MOVE, .little); // delegation.stake
    std.mem.writeInt(u64, sd[164..172], 10, .little); // activation_epoch
    std.mem.writeInt(u64, sd[172..180], MAXU64, .little); // deact = MAX
    std.mem.writeInt(u64, sd[188..196], 100, .little); // credits
    // dst: Initialized(1) (Inactive), same staker/withdrawer/reserve, lockup zero
    const dd = h.accounts[1].data;
    std.mem.writeInt(u32, dd[0..4], 1, .little);
    std.mem.writeInt(u64, dd[4..12], 1_000_000_000, .little);
    @memcpy(dd[12..44], &staker);
    @memcpy(dd[44..76], &withdrawer);
    // history: src fully active by epoch 13
    const hist = try t.allocator.alloc(sysvar_cache.StakeHistoryEntry, 2);
    hist[0] = .{ .epoch = 11, .effective = 1_000_000_000_000, .activating = 0, .deactivating = 0 };
    hist[1] = .{ .epoch = 12, .effective = 1_000_000_000_000, .activating = 0, .deactivating = 0 };
    h.cache.stake_history_entries = hist;
    setClock(&h, 13, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 16, .little);
    std.mem.writeInt(u64, ix[4..12], MOVE, .little);
    try execute(h.ctx, &ix);
    // src → Initialized(1), tail preserved (voter still set), lamports -= MOVE
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, h.accounts[0].data[0..4], .little));
    try t.expectEqualSlices(u8, &voter, h.accounts[0].data[124..156]); // tail PRESERVED
    try t.expectEqual(@as(u64, 1_000_000_000), h.accounts[0].lamports);
    // dst → Stake(2), stake=MOVE, voter=src voter, credits=src credits, flags=0, lamports += MOVE
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, h.accounts[1].data[0..4], .little));
    try t.expectEqual(MOVE, std.mem.readInt(u64, h.accounts[1].data[156..164], .little));
    try t.expectEqualSlices(u8, &voter, h.accounts[1].data[124..156]);
    try t.expectEqual(@as(u64, 100), std.mem.readInt(u64, h.accounts[1].data[188..196], .little));
    try t.expectEqual(@as(u8, 0), h.accounts[1].data[196]);
    try t.expectEqual(@as(u64, 6_000_000_000), h.accounts[1].lamports);
}

// KAT 2 (REJECT, source not FullyActive): Inactive source → InvalidAccountData.
test "M9 stake: MoveStake rejects non-FullyActive source (InvalidAccountData)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 6_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 1_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE; // distinct src key (not-same-account check)
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little); // src Initialized = Inactive
    @memcpy(h.accounts[0].data[12..44], &staker);
    std.mem.writeInt(u32, h.accounts[1].data[0..4], 1, .little);
    @memcpy(h.accounts[1].data[12..44], &staker);
    setClock(&h, 13, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 16, .little);
    std.mem.writeInt(u64, ix[4..12], 1_000_000_000, .little);
    try t.expectError(error.M9_Stake_InvalidAccountData, execute(h.ctx, &ix));
}

// KAT 3 (REJECT, index-2 not signer): MissingRequiredSignature. Proves the
// index-2-specific signer gate (NOT signerSetContains).
test "M9 stake: MoveStake rejects when authority (idx 2) did not sign" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 6_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 1_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = false }, // NOT a signer
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE; // distinct src key (not-same-account check)
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 2, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    setClock(&h, 13, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 16, .little);
    std.mem.writeInt(u64, ix[4..12], 1_000_000_000, .little);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, &ix));
}

// KAT 4 (REJECT, lamports==0): InvalidArgument. Fires before the FullyActive
// check (shared_checks lamports==0 precedes the move_stake body).
test "M9 stake: MoveStake rejects lamports==0 (InvalidArgument)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 6_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 1_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE; // distinct src key (not-same-account check)
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 2, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    setClock(&h, 13, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 16, .little);
    std.mem.writeInt(u64, ix[4..12], 0, .little);
    try t.expectError(error.M9_Stake_InvalidArgument, execute(h.ctx, &ix));
}

// KAT 5 (SUCCESS, FullyActive→FullyActive dest, partial move): source retains
// >= min_delegation (stays Stake), dest stake += lamports, credits weighted,
// flags=0, voter match required. Conservation.
test "M9 stake: MoveStake FullyActive→FullyActive dest, partial move" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;
    const SRC_STAKE: u64 = 6 * 1_000_000_000;
    const DST_STAKE: u64 = 3 * 1_000_000_000;
    const MOVE: u64 = 2 * 1_000_000_000; // src_final = 4 SOL (>1), dst_final = 5 SOL
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 7_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] src
        .{ .data_len = 200, .lamports = 4_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [1] dst
        .{ .pubkey = staker, .is_signer = true }, // [2] authority
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE; // distinct src key (not-same-account check)
    for ([_]usize{ 0, 1 }) |i| {
        const d = h.accounts[i].data;
        std.mem.writeInt(u32, d[0..4], 2, .little);
        std.mem.writeInt(u64, d[4..12], 1_000_000_000, .little); // reserve
        @memcpy(d[12..44], &staker);
        @memcpy(d[44..76], &withdrawer);
        @memcpy(d[124..156], &voter);
        std.mem.writeInt(u64, d[164..172], 10, .little); // activation_epoch
        std.mem.writeInt(u64, d[172..180], MAXU64, .little); // deact = MAX
    }
    std.mem.writeInt(u64, h.accounts[0].data[156..164], SRC_STAKE, .little);
    std.mem.writeInt(u64, h.accounts[0].data[188..196], 200, .little); // src credits
    std.mem.writeInt(u64, h.accounts[1].data[156..164], DST_STAKE, .little);
    std.mem.writeInt(u64, h.accounts[1].data[188..196], 100, .little); // dst credits
    const hist = try t.allocator.alloc(sysvar_cache.StakeHistoryEntry, 2);
    hist[0] = .{ .epoch = 11, .effective = 1_000_000_000_000, .activating = 0, .deactivating = 0 };
    hist[1] = .{ .epoch = 12, .effective = 1_000_000_000_000, .activating = 0, .deactivating = 0 };
    h.cache.stake_history_entries = hist;
    setClock(&h, 13, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 16, .little);
    std.mem.writeInt(u64, ix[4..12], MOVE, .little);
    try execute(h.ctx, &ix);
    // src stays Stake(2), stake = SRC_STAKE - MOVE = 4 SOL, flags=0
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, h.accounts[0].data[0..4], .little));
    try t.expectEqual(SRC_STAKE - MOVE, std.mem.readInt(u64, h.accounts[0].data[156..164], .little));
    try t.expectEqual(@as(u8, 0), h.accounts[0].data[196]);
    try t.expectEqual(@as(u64, 5_000_000_000), h.accounts[0].lamports);
    // dst stake = DST_STAKE + MOVE = 5 SOL, credits weighted, flags=0
    try t.expectEqual(DST_STAKE + MOVE, std.mem.readInt(u64, h.accounts[1].data[156..164], .little));
    const exp_credits = weightedCreditsObserved(100, DST_STAKE, 200, MOVE).?;
    try t.expectEqual(exp_credits, std.mem.readInt(u64, h.accounts[1].data[188..196], .little));
    try t.expectEqual(@as(u8, 0), h.accounts[1].data[196]);
    try t.expectEqual(@as(u64, 6_000_000_000), h.accounts[1].lamports);
}

// KAT 6 (REJECT, Inactive dest, lamports < min_delegation): InvalidArgument.
// Full move that drains source but dest is Inactive needing >= 1 SOL.
test "M9 stake: MoveStake rejects Inactive dest below min_delegation (InvalidArgument)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;
    const MOVE: u64 = 500_000_000; // 0.5 SOL < 1 SOL min
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 1_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE; // distinct src key (not-same-account check)
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    std.mem.writeInt(u64, sd[4..12], 1_000_000_000, .little);
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &withdrawer);
    @memcpy(sd[124..156], &voter);
    std.mem.writeInt(u64, sd[156..164], MOVE, .little); // src_final = 0 (full move)
    std.mem.writeInt(u64, sd[164..172], 10, .little);
    std.mem.writeInt(u64, sd[172..180], MAXU64, .little);
    const dd = h.accounts[1].data;
    std.mem.writeInt(u32, dd[0..4], 1, .little); // dst Initialized = Inactive
    std.mem.writeInt(u64, dd[4..12], 1_000_000_000, .little);
    @memcpy(dd[12..44], &staker);
    @memcpy(dd[44..76], &withdrawer);
    const hist = try t.allocator.alloc(sysvar_cache.StakeHistoryEntry, 2);
    hist[0] = .{ .epoch = 11, .effective = 1_000_000_000_000, .activating = 0, .deactivating = 0 };
    hist[1] = .{ .epoch = 12, .effective = 1_000_000_000_000, .activating = 0, .deactivating = 0 };
    h.cache.stake_history_entries = hist;
    setClock(&h, 13, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 16, .little);
    std.mem.writeInt(u64, ix[4..12], MOVE, .little);
    try t.expectError(error.M9_Stake_InvalidArgument, execute(h.ctx, &ix));
    // no writes: src lamports unchanged
    try t.expectEqual(@as(u64, 2_000_000_000), h.accounts[0].lamports);
}

// KAT 7 (REJECT, FullyActive dest, voter mismatch): VoteAddressMismatch.
test "M9 stake: MoveStake rejects FullyActive dest with voter mismatch (VoteAddressMismatch)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter_a: [32]u8 = std.mem.zeroes([32]u8);
    voter_a[0] = 0xCC;
    var voter_b: [32]u8 = std.mem.zeroes([32]u8);
    voter_b[0] = 0xDD;
    const MOVE: u64 = 2 * 1_000_000_000;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 7_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 4_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE; // distinct src key (not-same-account check)
    for ([_]usize{ 0, 1 }) |i| {
        const d = h.accounts[i].data;
        std.mem.writeInt(u32, d[0..4], 2, .little);
        std.mem.writeInt(u64, d[4..12], 1_000_000_000, .little);
        @memcpy(d[12..44], &staker);
        @memcpy(d[44..76], &withdrawer);
        std.mem.writeInt(u64, d[164..172], 10, .little);
        std.mem.writeInt(u64, d[172..180], MAXU64, .little);
        std.mem.writeInt(u64, d[156..164], 6 * 1_000_000_000, .little);
    }
    @memcpy(h.accounts[0].data[124..156], &voter_a);
    @memcpy(h.accounts[1].data[124..156], &voter_b); // different voter
    const hist = try t.allocator.alloc(sysvar_cache.StakeHistoryEntry, 2);
    hist[0] = .{ .epoch = 11, .effective = 1_000_000_000_000, .activating = 0, .deactivating = 0 };
    hist[1] = .{ .epoch = 12, .effective = 1_000_000_000_000, .activating = 0, .deactivating = 0 };
    h.cache.stake_history_entries = hist;
    setClock(&h, 13, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 16, .little);
    std.mem.writeInt(u64, ix[4..12], MOVE, .little);
    try t.expectError(error.M9_Stake_VoteAddressMismatch, execute(h.ctx, &ix));
}

// ── MoveLamports (tag 17) KATs — BPF stake v5 (SIMD-0148/0490) ──────────────

// KAT 1 (DISPATCH): tag 17 must reach the handler, NOT the VariantPending stub.
// With an empty frame it falls through EpochRewards (absent ⇒ caught) to the
// account-count guard ⇒ NotEnoughAccounts (proves it is WIRED).
test "M9 MoveLamports (tag 17): dispatches (not VariantPending)" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 17, .little);
    std.mem.writeInt(u64, data[4..12], 1, .little);
    try t.expectError(error.M9_Stake_NotEnoughAccounts, execute(h.ctx, &data));
}

// KAT 2 (SUCCESS, FullyActive source → ActivationEpoch dest): moves exactly the
// free lamports. State bytes on BOTH accounts UNCHANGED (the load-bearing
// assertion — MoveLamports writes ZERO state bytes); lamports conserve by ix arg.
// Proves: (a) FullyActive source allowed; (b) dst ActivationEpoch is VALID (no
// dst_kind body branch); (c) free = src.lamports -| delegation -| reserve.
test "M9 MoveLamports: FullyActive src moves free lamports — state bytes UNCHANGED" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;
    // src: FullyActive, delegation=2 SOL, reserve=1 SOL, lamports=3.5 SOL →
    // free = 3.5e9 -| 2e9 -| 1e6 = 1_499_000_000.
    const FREE: u64 = 3_500_000_000 - 2_000_000_000 - 1_000_000;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 3_500_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] src
        .{ .data_len = 200, .lamports = 2_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [1] dst
        .{ .pubkey = staker, .is_signer = true }, // [2] authority == src staker
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE; // distinct src key (not-same-account check)
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little); // Stake(2)
    std.mem.writeInt(u64, sd[4..12], 1_000_000, .little); // rent_exempt_reserve
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &withdrawer);
    @memcpy(sd[124..156], &voter);
    std.mem.writeInt(u64, sd[156..164], 2_000_000_000, .little); // delegation.stake
    std.mem.writeInt(u64, sd[164..172], 5, .little); // activation_epoch
    std.mem.writeInt(u64, sd[172..180], MAXU64, .little); // deact = MAX
    std.mem.writeInt(u64, sd[188..196], 10, .little); // credits
    // dst: ActivationEpoch (activation_epoch == clock.epoch), same staker/withdrawer.
    const dd = h.accounts[1].data;
    std.mem.writeInt(u32, dd[0..4], 2, .little); // Stake(2)
    std.mem.writeInt(u64, dd[4..12], 1_000_000, .little);
    @memcpy(dd[12..44], &staker);
    @memcpy(dd[44..76], &withdrawer);
    @memcpy(dd[124..156], &voter);
    std.mem.writeInt(u64, dd[156..164], 1_000_000_000, .little);
    std.mem.writeInt(u64, dd[164..172], 6, .little); // activation_epoch == clock.epoch → ActivationEpoch(1)
    std.mem.writeInt(u64, dd[172..180], MAXU64, .little);
    // snapshot both bodies BEFORE (must be byte-identical AFTER).
    var src_before: [200]u8 = undefined;
    var dst_before: [200]u8 = undefined;
    @memcpy(&src_before, sd[0..200]);
    @memcpy(&dst_before, dd[0..200]);
    setClock(&h, 6, 1_000_000); // > src.activation(5) → src FullyActive (empty history)
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 17, .little);
    std.mem.writeInt(u64, ix[4..12], FREE, .little); // move exactly the free lamports
    try execute(h.ctx, &ix);
    // lamport deltas (conservation).
    try t.expectEqual(@as(u64, 3_500_000_000 - FREE), h.accounts[0].lamports); // = 2_001_000_000
    try t.expectEqual(@as(u64, 2_000_000_000 + FREE), h.accounts[1].lamports); // = 3_499_000_000
    // state bytes UNCHANGED on BOTH (MoveLamports writes zero state bytes).
    try t.expectEqualSlices(u8, &src_before, h.accounts[0].data[0..200]);
    try t.expectEqualSlices(u8, &dst_before, h.accounts[1].data[0..200]);
}

// KAT 3 (SUCCESS, Inactive source): free = src.lamports -| reserve (no delegation
// subtraction). Proves the Inactive(0) source path is allowed (NOT requiring
// FullyActive). dst is FullyActive (still valid).
test "M9 MoveLamports: Inactive src — free = lamports -| reserve, state unchanged" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    // src Initialized(1) = Inactive, reserve=1 SOL, lamports=2.5 SOL → free=1.5 SOL.
    const FREE: u64 = 2_500_000_000 - 1_000_000_000;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_500_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 2_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE;
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little); // Initialized → Inactive(0)
    std.mem.writeInt(u64, sd[4..12], 1_000_000_000, .little); // reserve
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &withdrawer);
    const dd = h.accounts[1].data;
    std.mem.writeInt(u32, dd[0..4], 1, .little); // dst also Inactive
    std.mem.writeInt(u64, dd[4..12], 1_000_000_000, .little);
    @memcpy(dd[12..44], &staker);
    @memcpy(dd[44..76], &withdrawer);
    var src_before: [200]u8 = undefined;
    @memcpy(&src_before, sd[0..200]);
    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 17, .little);
    std.mem.writeInt(u64, ix[4..12], FREE, .little);
    try execute(h.ctx, &ix);
    try t.expectEqual(@as(u64, 1_000_000_000), h.accounts[0].lamports); // = reserve only left
    try t.expectEqual(@as(u64, 2_000_000_000 + FREE), h.accounts[1].lamports);
    try t.expectEqualSlices(u8, &src_before, h.accounts[0].data[0..200]); // unchanged
}

// KAT 4 (REJECT, lamports==0): InvalidArgument. UNLIKE Withdraw, MoveLamports
// rejects a zero move.
test "M9 MoveLamports: lamports==0 rejected (InvalidArgument)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 2_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE;
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    std.mem.writeInt(u32, h.accounts[1].data[0..4], 1, .little);
    @memcpy(h.accounts[1].data[12..44], &staker);
    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 17, .little);
    std.mem.writeInt(u64, ix[4..12], 0, .little);
    try t.expectError(error.M9_Stake_InvalidArgument, execute(h.ctx, &ix));
}

// KAT 5 (REJECT, index-2 not signer): MissingRequiredSignature. Proves the
// index-2-specific signer gate (NOT signerSetContains).
test "M9 MoveLamports: authority at idx2 not signing -> MissingRequiredSignature" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 2_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = false }, // NOT a signer
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE;
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 17, .little);
    std.mem.writeInt(u64, ix[4..12], 100, .little);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, &ix));
}

// KAT 6 (REJECT, move > free): InvalidArgument. FullyActive source, ask for 1
// lamport more than free.
test "M9 MoveLamports: move > free rejected (InvalidArgument)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;
    const FREE: u64 = 3_500_000_000 - 2_000_000_000 - 1_000_000;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 3_500_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 2_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE;
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    std.mem.writeInt(u64, sd[4..12], 1_000_000, .little);
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &withdrawer);
    @memcpy(sd[124..156], &voter);
    std.mem.writeInt(u64, sd[156..164], 2_000_000_000, .little);
    std.mem.writeInt(u64, sd[164..172], 5, .little);
    std.mem.writeInt(u64, sd[172..180], MAXU64, .little);
    const dd = h.accounts[1].data;
    std.mem.writeInt(u32, dd[0..4], 2, .little);
    std.mem.writeInt(u64, dd[4..12], 1_000_000, .little);
    @memcpy(dd[12..44], &staker);
    @memcpy(dd[44..76], &withdrawer);
    @memcpy(dd[124..156], &voter);
    std.mem.writeInt(u64, dd[156..164], 1_000_000_000, .little);
    std.mem.writeInt(u64, dd[164..172], 5, .little);
    std.mem.writeInt(u64, dd[172..180], MAXU64, .little);
    setClock(&h, 6, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 17, .little);
    std.mem.writeInt(u64, ix[4..12], FREE + 1, .little); // 1 over free
    try t.expectError(error.M9_Stake_InvalidArgument, execute(h.ctx, &ix));
}

// KAT 7 (REJECT, ActivationEpoch source): InvalidAccountData. The source
// free-lamports switch has no definition for kind 1 (the `else` arm).
test "M9 MoveLamports: ActivationEpoch source rejected (InvalidAccountData)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 3_500_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 2_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE;
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    std.mem.writeInt(u64, sd[4..12], 1_000_000, .little);
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &withdrawer);
    @memcpy(sd[124..156], &voter);
    std.mem.writeInt(u64, sd[156..164], 2_000_000_000, .little);
    std.mem.writeInt(u64, sd[164..172], 6, .little); // activation_epoch == clock.epoch → ActivationEpoch(1)
    std.mem.writeInt(u64, sd[172..180], MAXU64, .little);
    const dd = h.accounts[1].data;
    std.mem.writeInt(u32, dd[0..4], 2, .little);
    std.mem.writeInt(u64, dd[4..12], 1_000_000, .little);
    @memcpy(dd[12..44], &staker);
    @memcpy(dd[44..76], &withdrawer);
    @memcpy(dd[124..156], &voter);
    std.mem.writeInt(u64, dd[156..164], 1_000_000_000, .little);
    std.mem.writeInt(u64, dd[164..172], 6, .little);
    std.mem.writeInt(u64, dd[172..180], MAXU64, .little);
    setClock(&h, 6, 1_000_000); // epoch == activation → ActivationEpoch (no history needed)
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 17, .little);
    std.mem.writeInt(u64, ix[4..12], 100, .little);
    try t.expectError(error.M9_Stake_InvalidAccountData, execute(h.ctx, &ix));
}

// KAT 8 (REJECT, metas mismatch): withdrawer differs → MergeMismatch.
test "M9 MoveLamports: metas mismatch (withdrawer) -> MergeMismatch" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    var w1: [32]u8 = std.mem.zeroes([32]u8);
    w1[0] = 0xB1;
    var w2: [32]u8 = std.mem.zeroes([32]u8);
    w2[0] = 0xB2;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_500_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 200, .lamports = 2_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    h.accounts[0].pubkey[0] = 0xEE;
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little); // Inactive
    std.mem.writeInt(u64, sd[4..12], 1_000_000_000, .little);
    @memcpy(sd[12..44], &staker);
    @memcpy(sd[44..76], &w1);
    const dd = h.accounts[1].data;
    std.mem.writeInt(u32, dd[0..4], 1, .little);
    std.mem.writeInt(u64, dd[4..12], 1_000_000_000, .little);
    @memcpy(dd[12..44], &staker);
    @memcpy(dd[44..76], &w2); // different withdrawer
    setClock(&h, 100, 1_000_000);
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [12]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 17, .little);
    std.mem.writeInt(u64, ix[4..12], 100, .little);
    try t.expectError(error.M9_Stake_MergeMismatch, execute(h.ctx, &ix));
}

// ── DelegateStake (tag 2) KATs — BPF stake v5 (SIMD-0490) ────────────────────

// Build a minimal version-2 (Current) VoteState with ONE epoch_credits entry
// {epoch, credits, prev}. Layout (V2, NO version-3 extra fields):
//   u32 version=2, node[32], withdrawer[32], commission u8, u64 lockouts_len=0,
//   u8 has_root=0, u64 av_len=0, prior_voters[1545]=0, u64 ec_len=1,
//   {epoch,credits,prev}, u64 ts_slot=0, i64 ts=0.
// Returns an allocator-owned buffer (caller frees / harness copies in).
fn buildVoteStateV2OneCredit(alloc: std.mem.Allocator, epoch: u64, credits: u64, prev: u64) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(alloc);
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(u32, tmp[0..4], 2, .little);
    try list.appendSlice(alloc, tmp[0..4]); // version=2
    try list.appendNTimes(alloc, 0, 64); // node[32] + withdrawer[32]
    try list.append(alloc, 0); // commission u8
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // lockouts_len=0
    try list.append(alloc, 0); // has_root=0
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // av_len=0
    try list.appendNTimes(alloc, 0, VOTE_PRIOR_VOTERS_SIZE); // prior_voters
    std.mem.writeInt(u64, &tmp, 1, .little);
    try list.appendSlice(alloc, &tmp); // ec_len=1
    std.mem.writeInt(u64, &tmp, epoch, .little);
    try list.appendSlice(alloc, &tmp);
    std.mem.writeInt(u64, &tmp, credits, .little);
    try list.appendSlice(alloc, &tmp);
    std.mem.writeInt(u64, &tmp, prev, .little);
    try list.appendSlice(alloc, &tmp);
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // ts_slot=0
    try list.appendSlice(alloc, &tmp); // ts i64=0
    return list.toOwnedSlice(alloc);
}

// Build a minimal version-3 (V4/live, SIMD-0185) VoteState with ONE epoch_credits
// entry, has_bls=false. Layout: u32 version=3, node[32], withdrawer[32],
// inflation_collector[32], block_revenue_collector[32], inflation_bps u16,
// block_bps u16, pending_delegator_rewards u64, has_bls u8=0, (NO commission byte),
// u64 lockouts_len=0, u8 has_root=0, u64 av_len=0, (NO prior_voters), u64 ec_len=1,
// {epoch,credits,prev}, u64 ts_slot, i64 ts.
fn buildVoteStateV3OneCredit(alloc: std.mem.Allocator, epoch: u64, credits: u64, prev: u64, has_bls: bool) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(alloc);
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(u32, tmp[0..4], 3, .little);
    try list.appendSlice(alloc, tmp[0..4]); // version=3
    try list.appendNTimes(alloc, 0, 64); // node + withdrawer
    try list.appendNTimes(alloc, 0, 64); // inflation_collector + block_revenue_collector
    try list.appendNTimes(alloc, 0, 4); // inflation_bps u16 + block_bps u16
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // pending_delegator_rewards
    try list.append(alloc, if (has_bls) 1 else 0); // has_bls u8
    if (has_bls) try list.appendNTimes(alloc, 0, 48); // bls_pubkey_compressed[48]
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // lockouts_len=0
    try list.append(alloc, 0); // has_root=0
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // av_len=0
    // NO prior_voters in version-3.
    std.mem.writeInt(u64, &tmp, 1, .little);
    try list.appendSlice(alloc, &tmp); // ec_len=1
    std.mem.writeInt(u64, &tmp, epoch, .little);
    try list.appendSlice(alloc, &tmp);
    std.mem.writeInt(u64, &tmp, credits, .little);
    try list.appendSlice(alloc, &tmp);
    std.mem.writeInt(u64, &tmp, prev, .little);
    try list.appendSlice(alloc, &tmp);
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // ts_slot
    try list.appendSlice(alloc, &tmp); // ts
    return list.toOwnedSlice(alloc);
}

// voteCredits walker unit checks — the only nontrivial new surface. Validated
// INDEPENDENTLY of the production walker (these builders are hand-rolled bincode,
// not the walker reused). V2 + V3(no-bls) + V3(bls) + empty + malformed.
test "M9 stake: voteCredits walker — V2/V3/bls/empty/malformed" {
    const t = std.testing;
    // V2 one credit
    const v2 = try buildVoteStateV2OneCredit(t.allocator, 900, 12345, 0);
    defer t.allocator.free(v2);
    try t.expectEqual(@as(u64, 12345), try voteCredits(v2));
    // V3 no-bls one credit
    const v3 = try buildVoteStateV3OneCredit(t.allocator, 974, 99999, 88, false);
    defer t.allocator.free(v3);
    try t.expectEqual(@as(u64, 99999), try voteCredits(v3));
    // V3 with bls (extra 48 bytes shift) one credit
    const v3b = try buildVoteStateV3OneCredit(t.allocator, 974, 7777, 0, true);
    defer t.allocator.free(v3b);
    try t.expectEqual(@as(u64, 7777), try voteCredits(v3b));
    // (empty epoch_credits → 0 is covered by the dedicated test below.)
    // malformed: truncated buffer → error, NOT 0.
    try t.expectError(error.M9_Stake_MalformedVoteState, voteCredits(v2[0..10]));
    // bad version → error.
    var bad: [80]u8 = std.mem.zeroes([80]u8);
    std.mem.writeInt(u32, bad[0..4], 7, .little);
    try t.expectError(error.M9_Stake_MalformedVoteState, voteCredits(&bad));
}

// voteCredits empty epoch_credits → 0 (clean parse, NOT error). Build a V2 with
// ec_len=0 explicitly.
test "M9 stake: voteCredits empty epoch_credits returns 0 (not error)" {
    const t = std.testing;
    var list = std.ArrayListUnmanaged(u8){};
    defer list.deinit(t.allocator);
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(u32, tmp[0..4], 2, .little);
    try list.appendSlice(t.allocator, tmp[0..4]); // version=2
    try list.appendNTimes(t.allocator, 0, 64); // node+withdrawer
    try list.append(t.allocator, 0); // commission
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(t.allocator, &tmp); // lockouts_len=0
    try list.append(t.allocator, 0); // has_root=0
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(t.allocator, &tmp); // av_len=0
    try list.appendNTimes(t.allocator, 0, VOTE_PRIOR_VOTERS_SIZE);
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(t.allocator, &tmp); // ec_len=0
    try t.expectEqual(@as(u64, 0), try voteCredits(list.items));
}

// KAT 1 — Initialized→Stake success bytes. The full Stake body must be written
// incl. offset 180 = 0.25 bits. Uses a version-3 (LIVE) vote account.
test "M9 stake: DelegateStake Initialized->Stake success bytes (V3 vote) — KAT" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    staker[31] = 0xCD;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var vote_key: [32]u8 = std.mem.zeroes([32]u8);
    vote_key[0] = 0xCC;
    vote_key[31] = 0xC9;

    const vote_data = try buildVoteStateV3OneCredit(t.allocator, 900, 12345, 0, false);
    defer t.allocator.free(vote_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 1_000_000_000 + 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = vote_key, .data_len = vote_data.len, .owner = VOTE_PROGRAM_ID }, // [1] vote (RO)
        .{ .data_len = 0 }, // [2] Clock
        .{ .data_len = 0 }, // [3] StakeHistory
        .{ .data_len = 0 }, // [4] config (unused)
        .{ .pubkey = staker, .is_signer = true }, // [5] staker signs (signer-SET, NOT index-N)
    });
    defer h.deinit();
    const s = h.accounts[0].data;
    std.mem.writeInt(u32, s[0..4], 1, .little); // Initialized
    std.mem.writeInt(u64, s[4..12], 2_282_880, .little); // rent_exempt
    @memcpy(s[12..44], &staker);
    @memcpy(s[44..76], &withdrawer);
    @memcpy(h.accounts[1].data, vote_data);
    setClock(&h, 974, 0);

    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4, 5 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 2, .little);
    try execute(h.ctx, &ix);

    const o = h.accounts[0].data;
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, o[0..4], .little)); // disc=Stake
    try t.expectEqualSlices(u8, &staker, o[12..44]); // meta preserved
    try t.expectEqualSlices(u8, &withdrawer, o[44..76]);
    try t.expectEqualSlices(u8, &vote_key, o[124..156]); // voter
    try t.expectEqual(@as(u64, 1_000_000_000), std.mem.readInt(u64, o[156..164], .little)); // stake = lamports-rent
    try t.expectEqual(@as(u64, 974), std.mem.readInt(u64, o[164..172], .little)); // activation
    try t.expectEqual(@as(u64, MAXU64), std.mem.readInt(u64, o[172..180], .little)); // deact=MAX
    try t.expectEqual(@as(u64, 0x3FD0000000000000), std.mem.readInt(u64, o[180..188], .little)); // warmup 0.25 ← CRITICAL
    try t.expectEqual(@as(u64, 12345), std.mem.readInt(u64, o[188..196], .little)); // credits
    try t.expectEqual(@as(u8, 0), o[196]); // flags=0
    try t.expectEqual(@as(u64, 1_000_000_000 + 2_282_880), h.accounts[0].lamports); // lamports UNCHANGED
}

// KAT 2 — sub-1-SOL rejected (SIMD-0490). stake_amount < 1 SOL → InsufficientDelegation;
// stake bytes UNCHANGED (still disc=1).
test "M9 stake: DelegateStake sub-1-SOL rejected (SIMD-0490)" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var vote_key: [32]u8 = std.mem.zeroes([32]u8);
    vote_key[0] = 0xCC;
    const vote_data = try buildVoteStateV3OneCredit(t.allocator, 900, 1, 0, false);
    defer t.allocator.free(vote_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 999_999_999 + 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = vote_key, .data_len = vote_data.len, .owner = VOTE_PROGRAM_ID },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    std.mem.writeInt(u64, h.accounts[0].data[4..12], 2_282_880, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    @memcpy(h.accounts[1].data, vote_data);
    setClock(&h, 974, 0);
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4, 5 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 2, .little);
    try t.expectError(error.M9_Stake_InsufficientDelegation, execute(h.ctx, &ix));
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // disc unchanged
}

// KAT 3 — staker did not sign → MissingRequiredSignature; bytes unchanged.
test "M9 stake: DelegateStake staker did not sign rejected" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var other: [32]u8 = std.mem.zeroes([32]u8);
    other[0] = 0x99;
    var vote_key: [32]u8 = std.mem.zeroes([32]u8);
    vote_key[0] = 0xCC;
    const vote_data = try buildVoteStateV3OneCredit(t.allocator, 900, 100, 0, false);
    defer t.allocator.free(vote_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = vote_key, .data_len = vote_data.len, .owner = VOTE_PROGRAM_ID },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = other, .is_signer = true }, // a signer, but NOT the staker
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little);
    std.mem.writeInt(u64, h.accounts[0].data[4..12], 2_282_880, .little);
    @memcpy(h.accounts[0].data[12..44], &staker);
    @memcpy(h.accounts[1].data, vote_data);
    setClock(&h, 974, 0);
    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4, 5 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 2, .little);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, &ix));
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // unchanged
}

// KAT 4 — re-delegate reactivate: effective stake != 0, SAME voter, clock.epoch ==
// deactivation_epoch → write ONLY deact=MAX; voter/stake/activation/180/credits/flags PRESERVED.
test "M9 stake: DelegateStake re-delegate reactivate writes ONLY deact=MAX" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xCC; // SAME voter in stake + vote account
    const vote_data = try buildVoteStateV3OneCredit(t.allocator, 900, 555, 0, false);
    defer t.allocator.free(vote_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = voter, .data_len = vote_data.len, .owner = VOTE_PROGRAM_ID }, // vote pubkey == stake.voter
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    const s = h.accounts[0].data;
    std.mem.writeInt(u32, s[0..4], 2, .little); // Stake(2)
    std.mem.writeInt(u64, s[4..12], 2_282_880, .little);
    @memcpy(s[12..44], &staker);
    @memcpy(s[124..156], &voter); // voter == vote pubkey
    std.mem.writeInt(u64, s[156..164], 3_000_000_000, .little); // delegation.stake
    std.mem.writeInt(u64, s[164..172], 10, .little); // activation_epoch (long ago)
    std.mem.writeInt(u64, s[172..180], 974, .little); // deactivation_epoch == clock.epoch
    std.mem.writeInt(u64, s[180..188], 0x3FD0000000000000, .little); // warmup 0.25
    std.mem.writeInt(u64, s[188..196], 999, .little); // credits (must be PRESERVED)
    s[196] = 0x05; // flags (must be PRESERVED)
    @memcpy(h.accounts[1].data, vote_data);

    // history makes the stake FULLY EFFECTIVE at epoch 974 (effective != 0).
    const hist = try t.allocator.alloc(sysvar_cache.StakeHistoryEntry, 1);
    hist[0] = .{ .epoch = 10, .effective = 100_000_000_000, .activating = 0, .deactivating = 0 };
    h.cache.stake_history_entries = hist;
    setClock(&h, 974, 0);

    var before: [200]u8 = undefined;
    @memcpy(&before, s[0..200]);

    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4, 5 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 2, .little);
    try execute(h.ctx, &ix);

    const o = h.accounts[0].data;
    try t.expectEqual(@as(u64, MAXU64), std.mem.readInt(u64, o[172..180], .little)); // deact flipped to MAX
    // everything ELSE preserved: compare all bytes except 172..180.
    try t.expectEqualSlices(u8, before[0..172], o[0..172]);
    try t.expectEqualSlices(u8, before[180..200], o[180..200]);
    try t.expectEqual(@as(u64, 999), std.mem.readInt(u64, o[188..196], .little)); // credits preserved
    try t.expectEqual(@as(u8, 0x05), o[196]); // flags preserved
}

// KAT 5 — full re-delegate (disc=2, effective==0): the HEADLINE-carrier branch.
// It rewrites voter/stake/activation/deact/credits but MUST NOT touch offset 180
// (warmup 0.25) or flags@196 (=args.flags PRESERVED). Source's prior delegation is
// fully deactivated (deact in the past, history present) → effective==0 → full path.
test "M9 stake: DelegateStake full re-delegate (effective==0) preserves 180+flags, rewrites delegation" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAB;
    var old_voter: [32]u8 = std.mem.zeroes([32]u8);
    old_voter[0] = 0xD0;
    var new_voter: [32]u8 = std.mem.zeroes([32]u8);
    new_voter[0] = 0xCC;
    new_voter[31] = 0xC1;
    const vote_data = try buildVoteStateV3OneCredit(t.allocator, 970, 4242, 0, false);
    defer t.allocator.free(vote_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = new_voter, .data_len = vote_data.len, .owner = VOTE_PROGRAM_ID }, // re-delegate to NEW voter
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = true },
    });
    defer h.deinit();
    const s = h.accounts[0].data;
    std.mem.writeInt(u32, s[0..4], 2, .little); // Stake(2)
    std.mem.writeInt(u64, s[4..12], 2_282_880, .little); // rent_exempt
    @memcpy(s[12..44], &staker);
    @memcpy(s[124..156], &old_voter); // old voter (to be overwritten)
    std.mem.writeInt(u64, s[156..164], 1_000_000_000, .little); // old delegation.stake
    std.mem.writeInt(u64, s[164..172], 10, .little); // activation long ago
    std.mem.writeInt(u64, s[172..180], 20, .little); // deactivation_epoch in the past
    std.mem.writeInt(u64, s[180..188], 0x3FD0000000000000, .little); // warmup 0.25 (MUST PRESERVE)
    std.mem.writeInt(u64, s[188..196], 111, .little); // old credits (to be overwritten)
    s[196] = 0x07; // flags (MUST PRESERVE)
    @memcpy(h.accounts[1].data, vote_data);

    // history: the deactivation-epoch(20) entry has deactivating==0 → the cooldown
    // walk sets remaining_eff=0 immediately (curve: `if e.deactivating==0 { eff=0 }`)
    // → getStakeActivationStatus(...).effective == 0 → the FULL re-delegate path.
    const hist = try t.allocator.alloc(sysvar_cache.StakeHistoryEntry, 1);
    hist[0] = .{ .epoch = 20, .effective = 1_000_000_000, .activating = 0, .deactivating = 0 };
    h.cache.stake_history_entries = hist;
    setClock(&h, 974, 0); // 974 > deact(20)+1 → cooled to 0

    try h.pushFrame(0, &.{ 0, 1, 2, 3, 4, 5 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 2, .little);
    try execute(h.ctx, &ix);

    const o = h.accounts[0].data;
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, o[0..4], .little)); // disc stays Stake
    try t.expectEqualSlices(u8, &new_voter, o[124..156]); // voter REWRITTEN to new
    try t.expectEqual(@as(u64, 5_000_000_000 - 2_282_880), std.mem.readInt(u64, o[156..164], .little)); // stake = lamports-rent
    try t.expectEqual(@as(u64, 974), std.mem.readInt(u64, o[164..172], .little)); // activation = clock.epoch
    try t.expectEqual(@as(u64, MAXU64), std.mem.readInt(u64, o[172..180], .little)); // deact = MAX
    try t.expectEqual(@as(u64, 0x3FD0000000000000), std.mem.readInt(u64, o[180..188], .little)); // 180 PRESERVED
    try t.expectEqual(@as(u64, 4242), std.mem.readInt(u64, o[188..196], .little)); // credits = vote getCredits
    try t.expectEqual(@as(u8, 0x07), o[196]); // flags PRESERVED (args.flags)
    try t.expectEqual(@as(u64, 5_000_000_000), h.accounts[0].lamports); // lamports UNCHANGED
}

// ── Initialize (tag 0) KATs ──────────────────────────────────────────────────
// Uninitialized → Initialized, Meta written @[0..124], tail @[124..200] zero,
// disc=1, NO lamport move, NO signer required.
test "M9 stake: Initialize (tag 0) writes Meta, disc=1, success bytes" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0xAA;
    staker[31] = 0xA1;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    withdrawer[31] = 0xB7;
    var custodian: [32]u8 = std.mem.zeroes([32]u8);
    custodian[0] = 0xCC;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true, .lamports = 3_000_000 }, // [0] stake (funded > reserve)
        .{ .data_len = 0 }, // [1] Rent (placeholder; cache.rent_view drives reserve)
    });
    defer h.deinit();
    // stake account starts Uninitialized (all-zero data) — disc already 0.
    setDefaultRent(&h);

    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();

    var ix: [116]u8 = std.mem.zeroes([116]u8);
    std.mem.writeInt(u32, ix[0..4], 0, .little); // Initialize
    @memcpy(ix[4..36], &staker);
    @memcpy(ix[36..68], &withdrawer);
    std.mem.writeInt(i64, ix[68..76], 1234, .little); // lockup.ts
    std.mem.writeInt(u64, ix[76..84], 567, .little); // lockup.epoch
    @memcpy(ix[84..116], &custodian);
    try execute(h.ctx, &ix);

    const d = h.accounts[0].data;
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, d[0..4], .little)); // disc=1
    try t.expectEqual(@as(u64, 2_282_880), std.mem.readInt(u64, d[4..12], .little)); // reserve
    try t.expectEqualSlices(u8, &staker, d[12..44]);
    try t.expectEqualSlices(u8, &withdrawer, d[44..76]);
    try t.expectEqual(@as(i64, 1234), std.mem.readInt(i64, d[76..84], .little));
    try t.expectEqual(@as(u64, 567), std.mem.readInt(u64, d[84..92], .little));
    try t.expectEqualSlices(u8, &custodian, d[92..124]);
    // tail [124..200] must remain zero (Initialized has no Stake region).
    const zero76: [76]u8 = std.mem.zeroes([76]u8);
    try t.expectEqualSlices(u8, &zero76, d[124..200]);
    // NO lamport movement.
    try t.expectEqual(@as(u64, 3_000_000), h.accounts[0].lamports);
}

test "M9 stake: Initialize rejects already-initialized (InvalidAccountData)" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true, .lamports = 3_000_000 },
        .{ .data_len = 0 },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little); // already Initialized(1)
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [116]u8 = std.mem.zeroes([116]u8);
    try t.expectError(error.M9_Stake_InvalidAccountData, execute(h.ctx, &ix));
}

test "M9 stake: Initialize rejects underfunded (InsufficientFunds)" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true, .lamports = 1_000_000 }, // < 2_282_880
        .{ .data_len = 0 },
    });
    defer h.deinit();
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [116]u8 = std.mem.zeroes([116]u8);
    try t.expectError(error.M9_Stake_InsufficientFunds, execute(h.ctx, &ix));
}

test "M9 stake: Initialize rejects wrong data length (InvalidAccountData, != not >=)" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 201, .owner = STAKE_PROGRAM_ID, .is_writable = true, .lamports = 3_000_000 }, // 201 != 200
        .{ .data_len = 0 },
    });
    defer h.deinit();
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [116]u8 = std.mem.zeroes([116]u8);
    try t.expectError(error.M9_Stake_InvalidAccountData, execute(h.ctx, &ix));
}

test "M9 stake: Initialize rejects short ix data (InvalidInstructionData)" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true, .lamports = 3_000_000 },
        .{ .data_len = 0 },
    });
    defer h.deinit();
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [115]u8 = std.mem.zeroes([115]u8); // 115 < 116
    try t.expectError(error.M9_Stake_InvalidInstructionData, execute(h.ctx, &ix));
}

// ── SetLockup (tag 6) KATs ─────────────────────────────────────────────────
// Canonical Meta::set_lockup (v4 == v5). Gate the pass/fail boundary + the exact
// success-byte mutation of meta.lockup (@76 ts / @84 epoch / @92 custodian).

fn buildLockupIx(buf: []u8, ts: ?i64, epoch: ?u64, custodian: ?[32]u8) usize {
    std.mem.writeInt(u32, buf[0..4], 6, .little);
    var o: usize = 4;
    if (ts) |v| {
        buf[o] = 1;
        o += 1;
        std.mem.writeInt(i64, buf[o..][0..8], v, .little);
        o += 8;
    } else {
        buf[o] = 0;
        o += 1;
    }
    if (epoch) |v| {
        buf[o] = 1;
        o += 1;
        std.mem.writeInt(u64, buf[o..][0..8], v, .little);
        o += 8;
    } else {
        buf[o] = 0;
        o += 1;
    }
    if (custodian) |c| {
        buf[o] = 1;
        o += 1;
        @memcpy(buf[o..][0..32], &c);
        o += 32;
    } else {
        buf[o] = 0;
        o += 1;
    }
    return o;
}

// SUCCESS: lockup EXPIRED (ts=0,epoch=0 < clock) → withdrawer signs → sets ts@76 + epoch@84.
test "M9 stake: SetLockup expired, withdrawer signs → writes ts@76 epoch@84" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    withdrawer[31] = 0xB7;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = withdrawer, .is_signer = true }, // [1] authority (withdrawer)
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little); // disc = Stake(2)
    @memcpy(sd[44..76], &withdrawer); // meta.authorized.withdrawer
    // lockup currently zero (ts@76=0, epoch@84=0) → NOT in force at clock epoch 974 / ts 1_000_000
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 1_000_000 };
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildLockupIx(&ix, 2_000_000, 980, null);
    try execute(h.ctx, ix[0..n]);
    try t.expectEqual(@as(i64, 2_000_000), std.mem.readInt(i64, h.accounts[0].data[76..84], .little));
    try t.expectEqual(@as(u64, 980), std.mem.readInt(u64, h.accounts[0].data[84..92], .little));
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // disc unchanged
}

// SUCCESS: lockup IN FORCE → custodian signs → updates custodian@92; epoch unchanged (None).
test "M9 stake: SetLockup in-force, custodian signs → updates custodian@92" {
    const t = std.testing;
    var custodian: [32]u8 = std.mem.zeroes([32]u8);
    custodian[0] = 0xCC;
    var new_cust: [32]u8 = std.mem.zeroes([32]u8);
    new_cust[0] = 0xDD;
    new_cust[31] = 0xD3;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = custodian, .is_signer = true },
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little); // disc = Initialized(1)
    std.mem.writeInt(u64, sd[84..92], 5000, .little); // lockup.epoch = 5000 (future)
    @memcpy(sd[92..124], &custodian); // lockup.custodian
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 1_000_000 }; // 974 < 5000 → in force
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildLockupIx(&ix, null, null, new_cust);
    try execute(h.ctx, ix[0..n]);
    try t.expectEqualSlices(u8, &new_cust, h.accounts[0].data[92..124]);
    try t.expectEqual(@as(u64, 5000), std.mem.readInt(u64, h.accounts[0].data[84..92], .little)); // epoch unchanged (None)
}

// REJECT: lockup in force but only WITHDRAWER signed (not custodian) → MissingRequiredSignature, no write.
test "M9 stake: SetLockup in-force rejects withdrawer-only signer" {
    const t = std.testing;
    var custodian: [32]u8 = std.mem.zeroes([32]u8);
    custodian[0] = 0xCC;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = withdrawer, .is_signer = true }, // withdrawer signs, but lockup IN FORCE needs custodian
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little);
    @memcpy(sd[44..76], &withdrawer);
    std.mem.writeInt(u64, sd[84..92], 5000, .little); // future epoch → in force
    @memcpy(sd[92..124], &custodian);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildLockupIx(&ix, 1, null, null);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, ix[0..n]));
    try t.expectEqual(@as(i64, 0), std.mem.readInt(i64, h.accounts[0].data[76..84], .little)); // ts untouched
}

// REJECT: Uninitialized(0) → InvalidAccountData.
test "M9 stake: SetLockup rejects Uninitialized account" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = withdrawer, .is_signer = true },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 0, .little); // Uninitialized
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 974, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [128]u8 = undefined;
    const n = buildLockupIx(&ix, 1, null, null);
    try t.expectError(error.M9_Stake_InvalidAccountData, execute(h.ctx, ix[0..n]));
}

// ── SetLockupChecked (tag 12) KATs — BPF stake v5 (v4 == v5; pure Meta.lockup) ──
// Canonical: accounts [0] stake W; authorizing signer via signer-SET scan (custodian
// if lockup in force, else withdrawer); [2] new custodian (OPTIONAL, MUST sign). Clock
// from sysvar cache. ix = u32 tag(12) + Option<i64 ts> + Option<u64 epoch> — NO
// custodian Option (the tag-6 delta; new custodian = acct[2].pubkey).

// LockupCheckedArgs (tag 12) ix builder: NO custodian Option.
fn buildLockupCheckedIx(buf: []u8, ts: ?i64, epoch: ?u64) usize {
    std.mem.writeInt(u32, buf[0..4], 12, .little);
    var o: usize = 4;
    if (ts) |v| {
        buf[o] = 1;
        o += 1;
        std.mem.writeInt(i64, buf[o..][0..8], v, .little);
        o += 8;
    } else {
        buf[o] = 0;
        o += 1;
    }
    if (epoch) |v| {
        buf[o] = 1;
        o += 1;
        std.mem.writeInt(u64, buf[o..][0..8], v, .little);
        o += 8;
    } else {
        buf[o] = 0;
        o += 1;
    }
    return o;
}

// SUCCESS: lockup NOT in force → withdrawer signs → sets ts@76 + epoch@84 + custodian@92 (acct[2]).
test "M9 stake: SetLockupChecked (tag 12) — withdrawer signs (no lockup), sets ts+epoch+custodian" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    withdrawer[31] = 0xB7;
    var new_custodian: [32]u8 = std.mem.zeroes([32]u8);
    new_custodian[0] = 0xCC;
    new_custodian[31] = 0xC9;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = withdrawer, .is_signer = true }, // [1] withdrawer authority signs (set-scan)
        .{ .pubkey = new_custodian, .is_signer = true }, // [2] new custodian (must sign)
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little); // disc = Stake(2)
    @memcpy(sd[44..76], &withdrawer);
    // lockup zeroed → not in force at epoch 100 / ts 1_000_000 → withdrawer path.
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 100, .leader_schedule_epoch = 0, .unix_timestamp = 1_000_000 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();

    var ix: [32]u8 = undefined;
    const n = buildLockupCheckedIx(&ix, 5_000_000, 777);
    try execute(h.ctx, ix[0..n]);

    try t.expectEqual(@as(i64, 5_000_000), std.mem.readInt(i64, h.accounts[0].data[76..84], .little)); // lockup_ts @76
    try t.expectEqual(@as(u64, 777), std.mem.readInt(u64, h.accounts[0].data[84..92], .little)); // lockup_epoch @84
    try t.expectEqualSlices(u8, &new_custodian, h.accounts[0].data[92..124]); // custodian @92 from acct[2]
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // disc unchanged
}

// SUCCESS: lockup IN FORCE → current custodian (acct[1]) signs; new custodian (acct[2]) signs;
// ts set (Some), epoch unchanged (None), custodian@92 replaced.
test "M9 stake: SetLockupChecked custodian-in-force path — current custodian must sign" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var lk_custodian: [32]u8 = std.mem.zeroes([32]u8);
    lk_custodian[0] = 0xEE;
    lk_custodian[31] = 0xE3;
    var new_custodian: [32]u8 = std.mem.zeroes([32]u8);
    new_custodian[0] = 0xCC;

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = lk_custodian, .is_signer = true }, // [1] CURRENT custodian signs (lockup in force)
        .{ .pubkey = new_custodian, .is_signer = true }, // [2] new custodian (must sign)
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little); // Initialized(1)
    @memcpy(sd[44..76], &withdrawer);
    std.mem.writeInt(u64, sd[84..92], 200, .little); // lockup.epoch=200 (future) → in force
    @memcpy(sd[92..124], &lk_custodian);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 100, .leader_schedule_epoch = 0, .unix_timestamp = 0 }; // 100<200 → in force

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();

    var ix: [32]u8 = undefined;
    const n = buildLockupCheckedIx(&ix, 9_999, null); // ts Some, epoch None
    try execute(h.ctx, ix[0..n]);
    try t.expectEqual(@as(i64, 9_999), std.mem.readInt(i64, h.accounts[0].data[76..84], .little)); // ts set
    try t.expectEqual(@as(u64, 200), std.mem.readInt(u64, h.accounts[0].data[84..92], .little)); // epoch UNCHANGED (None)
    try t.expectEqualSlices(u8, &new_custodian, h.accounts[0].data[92..124]); // custodian replaced (acct[2])
}

// REJECT: account[2] custodian PRESENT but NOT signer → MissingRequiredSignature (raised at
// get_optional_pubkey, BEFORE the in-force/withdrawer auth). Custodian field unchanged on error.
test "M9 stake: SetLockupChecked rejects when account[2] custodian present but NOT signer" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var new_custodian: [32]u8 = std.mem.zeroes([32]u8);
    new_custodian[0] = 0xCC;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = withdrawer, .is_signer = true }, // [1] withdrawer signs
        .{ .pubkey = new_custodian, .is_signer = false }, // [2] present but DID NOT sign
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    @memcpy(sd[44..76], &withdrawer);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 100, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [32]u8 = undefined;
    const n = buildLockupCheckedIx(&ix, null, null); // ts None, epoch None
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, ix[0..n]));
    var zero32: [32]u8 = std.mem.zeroes([32]u8);
    try t.expectEqualSlices(u8, &zero32, h.accounts[0].data[92..124]); // custodian unchanged on error
}

// REJECT: authorizing signer (withdrawer, lockup not in force) did NOT sign; no acct[2] →
// MissingRequiredSignature.
test "M9 stake: SetLockupChecked rejects when authority did not sign (no custodian acct)" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0xBB;
    var other: [32]u8 = std.mem.zeroes([32]u8);
    other[0] = 0x99;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = other, .is_signer = true }, // wrong signer, not withdrawer
    });
    defer h.deinit();
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 1, .little);
    @memcpy(sd[44..76], &withdrawer);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = 100, .leader_schedule_epoch = 0, .unix_timestamp = 0 };
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();
    var ix: [32]u8 = undefined;
    const n = buildLockupCheckedIx(&ix, null, null); // ts None, epoch None
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, ix[0..n]));
}

// ── InitializeChecked (tag 9) KATs — BPF stake v5 (SIMD-0490; v4 == v5) ─────
// Canonical: accounts [0] stake W (Uninitialized, 200B), [1] Rent, [2] staker,
// [3] withdrawer SIGNER. ix = u32 tag(9) only. Writes disc=1@0, reserve@4,
// staker@12 (acct[2]), withdrawer@44 (acct[3]), lockup zeros@76/84/92.

test "M9 stake: InitializeChecked (tag 9) writes Initialized state — success" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0x51;
    staker[31] = 0x52;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0x77;
    withdrawer[31] = 0x88;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake (Uninit, exactly rent-exempt)
        .{ .data_len = 0 }, // [1] Rent placeholder (cache populated via setDefaultRent)
        .{ .pubkey = staker, .is_signer = false }, // [2] staker — does NOT need to sign
        .{ .pubkey = withdrawer, .is_signer = true }, // [3] withdrawer — MUST sign
    });
    defer h.deinit();
    // stake account is Uninitialized (disc=0, all zero) by default.
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 9, .little);
    try execute(h.ctx, &ix);
    const d = h.accounts[0].data;
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, d[0..4], .little)); // disc=Initialized
    try t.expectEqual(@as(u64, 2_282_880), std.mem.readInt(u64, d[4..12], .little)); // reserve
    try t.expectEqualSlices(u8, &staker, d[12..44]); // staker (from acct[2])
    try t.expectEqualSlices(u8, &withdrawer, d[44..76]); // withdrawer (from acct[3])
    try t.expectEqual(@as(i64, 0), std.mem.readInt(i64, d[76..84], .little)); // lockup ts
    try t.expectEqual(@as(u64, 0), std.mem.readInt(u64, d[84..92], .little)); // lockup epoch
    const zero32: [32]u8 = std.mem.zeroes([32]u8);
    try t.expectEqualSlices(u8, &zero32, d[92..124]); // lockup custodian
}

test "M9 stake: InitializeChecked rejects when withdrawer (acct[3]) did not sign" {
    const t = std.testing;
    var staker: [32]u8 = std.mem.zeroes([32]u8);
    staker[0] = 0x01;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0x02;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = staker, .is_signer = false },
        .{ .pubkey = withdrawer, .is_signer = false }, // NOT signing
    });
    defer h.deinit();
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 9, .little);
    try t.expectError(error.M9_Stake_MissingRequiredSignature, execute(h.ctx, &ix));
    try t.expectEqual(@as(u32, 0), std.mem.readInt(u32, h.accounts[0].data[0..4], .little)); // unchanged
}

test "M9 stake: InitializeChecked rejects under-funded account (InsufficientFunds)" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0x09;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_282_879, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // 1 short
        .{ .data_len = 0 },
        .{ .pubkey = std.mem.zeroes([32]u8), .is_signer = false },
        .{ .pubkey = withdrawer, .is_signer = true },
    });
    defer h.deinit();
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 9, .little);
    try t.expectError(error.M9_Stake_InsufficientFunds, execute(h.ctx, &ix));
}

test "M9 stake: InitializeChecked rejects non-Uninitialized account (InvalidAccountData)" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0x0A;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = std.mem.zeroes([32]u8), .is_signer = false },
        .{ .pubkey = withdrawer, .is_signer = true },
    });
    defer h.deinit();
    std.mem.writeInt(u32, h.accounts[0].data[0..4], 1, .little); // already Initialized(1)
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 9, .little);
    try t.expectError(error.M9_Stake_InvalidAccountData, execute(h.ctx, &ix));
}

// Pins the one subtle consensus decision: canonical serialize_into(Initialized)
// writes ONLY [0..124] and STOPS — it does NOT zero-pad [124..200]. We leave the
// tail UNTOUCHED (matching executeInitialize + canonical set_state), unlike the
// plan sketch which suggested @memset([124..200]). With a garbage tail the byte-
// faithful output preserves it. (Unreachable from a real Uninitialized account,
// which is all-zero, but this nails the exact distinguishing behavior.)
test "M9 stake: InitializeChecked preserves stake tail [124..200] (no zero-pad)" {
    const t = std.testing;
    var withdrawer: [32]u8 = std.mem.zeroes([32]u8);
    withdrawer[0] = 0x0B;
    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 2_282_880, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .data_len = 0 },
        .{ .pubkey = std.mem.zeroes([32]u8), .is_signer = false },
        .{ .pubkey = withdrawer, .is_signer = true },
    });
    defer h.deinit();
    // disc stays Uninitialized(0), but seed garbage into the tail [124..200].
    @memset(h.accounts[0].data[STAKE_OFF_VOTER..STAKE_STATE_SZ], 0xEE);
    setDefaultRent(&h);
    try h.pushFrame(0, &.{ 0, 1, 2, 3 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 9, .little);
    try execute(h.ctx, &ix);
    const d = h.accounts[0].data;
    try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, d[0..4], .little)); // Initialized
    var garbage: [STAKE_STATE_SZ - STAKE_OFF_VOTER]u8 = undefined;
    @memset(&garbage, 0xEE);
    try t.expectEqualSlices(u8, &garbage, d[STAKE_OFF_VOTER..STAKE_STATE_SZ]); // tail preserved, NOT zeroed
}

// ── DeactivateDelinquent (tag 14) KATs ──────────────────────────────────────

// Build a version-2 (Current) vote account whose epoch_credits are the given
// `epochs` (each entry {epoch, credits=100, prev=0}, in order). Layout matches
// buildVoteStateV2OneCredit. Returns an allocator-owned buffer.
fn buildVoteStateV2EpochCredits(alloc: std.mem.Allocator, epochs: []const u64) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(alloc);
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(u32, tmp[0..4], 2, .little);
    try list.appendSlice(alloc, tmp[0..4]); // version=2
    try list.appendNTimes(alloc, 0, 64); // node[32] + withdrawer[32]
    try list.append(alloc, 0); // commission u8
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // lockouts_len=0
    try list.append(alloc, 0); // has_root=0
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // av_len=0
    try list.appendNTimes(alloc, 0, VOTE_PRIOR_VOTERS_SIZE); // prior_voters
    std.mem.writeInt(u64, &tmp, @intCast(epochs.len), .little);
    try list.appendSlice(alloc, &tmp); // ec_len
    for (epochs) |e| {
        std.mem.writeInt(u64, &tmp, e, .little);
        try list.appendSlice(alloc, &tmp); // epoch
        std.mem.writeInt(u64, &tmp, 100, .little);
        try list.appendSlice(alloc, &tmp); // credits
        std.mem.writeInt(u64, &tmp, 0, .little);
        try list.appendSlice(alloc, &tmp); // prev_credits
    }
    std.mem.writeInt(u64, &tmp, 0, .little);
    try list.appendSlice(alloc, &tmp); // last_timestamp.slot=0
    try list.appendSlice(alloc, &tmp); // last_timestamp.timestamp i64=0
    return list.toOwnedSlice(alloc);
}

// KAT 1 — SUCCESS: delinquent (last vote epoch-6) + acceptable reference (epoch-4..epoch)
// → deactivation_epoch set to clock.epoch @172; tail (180..200) + disc preserved.
test "M9 stake: DeactivateDelinquent success — deact_epoch @172, tail preserved (tag 14)" {
    const t = std.testing;
    const epoch: u64 = 974;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xAA;
    voter[31] = 0xA9;

    const delq_data = try buildVoteStateV2EpochCredits(t.allocator, &.{epoch - 6});
    defer t.allocator.free(delq_data);
    const ref_data = try buildVoteStateV2EpochCredits(t.allocator, &.{ epoch - 4, epoch - 3, epoch - 2, epoch - 1, epoch });
    defer t.allocator.free(ref_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true }, // [0] stake
        .{ .pubkey = voter, .data_len = delq_data.len, .owner = VOTE_PROGRAM_ID }, // [1] delinquent vote (pubkey == stake voter)
        .{ .data_len = ref_data.len, .owner = VOTE_PROGRAM_ID }, // [2] reference vote
    });
    defer h.deinit();
    @memcpy(h.accounts[1].data, delq_data);
    @memcpy(h.accounts[2].data, ref_data);
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little); // disc=Stake(2)
    @memcpy(sd[STAKE_OFF_VOTER..][0..32], &voter); // voter == delinquent acct pubkey
    std.mem.writeInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], MAXU64, .little); // deact = MAX (not yet deactivating)
    @memset(sd[180..188], 0x77); // warmup sentinel (tail-preserve check)
    sd[196] = 0x55; // flags sentinel
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = epoch, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 14, .little);
    try execute(h.ctx, &ix);

    try t.expectEqual(epoch, std.mem.readInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little)); // SUCCESS byte
    try t.expectEqual(@as(u32, 2), std.mem.readInt(u32, sd[0..4], .little)); // disc unchanged
    var warm: [8]u8 = undefined;
    @memset(&warm, 0x77);
    try t.expectEqualSlices(u8, &warm, sd[180..188]); // tail preserved
    try t.expectEqual(@as(u8, 0x55), sd[196]); // flags preserved
}

// KAT 2 — REJECT: reference has a GAP in its last 5 (missing epoch-2) →
// InsufficientReferenceVotes; stake bytes UNCHANGED (deact still MAX).
test "M9 stake: DeactivateDelinquent rejects insufficient reference votes (tag 14)" {
    const t = std.testing;
    const epoch: u64 = 974;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xAA;

    const delq_data = try buildVoteStateV2EpochCredits(t.allocator, &.{epoch - 6});
    defer t.allocator.free(delq_data);
    // GAP: epoch-2 missing → reversed last-5 won't equal epoch..epoch-4.
    const ref_data = try buildVoteStateV2EpochCredits(t.allocator, &.{ epoch - 5, epoch - 4, epoch - 3, epoch - 1, epoch });
    defer t.allocator.free(ref_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = voter, .data_len = delq_data.len, .owner = VOTE_PROGRAM_ID },
        .{ .data_len = ref_data.len, .owner = VOTE_PROGRAM_ID },
    });
    defer h.deinit();
    @memcpy(h.accounts[1].data, delq_data);
    @memcpy(h.accounts[2].data, ref_data);
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    @memcpy(sd[STAKE_OFF_VOTER..][0..32], &voter);
    std.mem.writeInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], MAXU64, .little);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = epoch, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 14, .little);
    try t.expectError(error.M9_Stake_InsufficientReferenceVotes, execute(h.ctx, &ix));
    try t.expectEqual(MAXU64, std.mem.readInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little)); // no mutation
}

// KAT 3 — REJECT: delinquent voted recently (epoch-4 > epoch-5) → NOT eligible →
// MinimumDelinquentEpochsNotMet; stake unchanged. (Reference IS acceptable so the
// failure is isolated to the eligibility gate.)
test "M9 stake: DeactivateDelinquent rejects when delinquent voted recently (tag 14)" {
    const t = std.testing;
    const epoch: u64 = 974;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xAA;

    const delq_data = try buildVoteStateV2EpochCredits(t.allocator, &.{epoch - 4}); // > epoch-5 → not eligible
    defer t.allocator.free(delq_data);
    const ref_data = try buildVoteStateV2EpochCredits(t.allocator, &.{ epoch - 4, epoch - 3, epoch - 2, epoch - 1, epoch });
    defer t.allocator.free(ref_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = voter, .data_len = delq_data.len, .owner = VOTE_PROGRAM_ID },
        .{ .data_len = ref_data.len, .owner = VOTE_PROGRAM_ID },
    });
    defer h.deinit();
    @memcpy(h.accounts[1].data, delq_data);
    @memcpy(h.accounts[2].data, ref_data);
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    @memcpy(sd[STAKE_OFF_VOTER..][0..32], &voter);
    std.mem.writeInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], MAXU64, .little);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = epoch, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 14, .little);
    try t.expectError(error.M9_Stake_MinimumDelinquentEpochsNotMet, execute(h.ctx, &ix));
    try t.expectEqual(MAXU64, std.mem.readInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little)); // no mutation
}

// KAT 4 — REJECT: stake.delegation.voter_pubkey != delinquent vote acct pubkey →
// VoteAddressMismatch; stake unchanged. (Reference acceptable, delinquent eligible —
// isolates the voter-match gate.)
test "M9 stake: DeactivateDelinquent rejects voter mismatch (tag 14)" {
    const t = std.testing;
    const epoch: u64 = 974;
    var delq_key: [32]u8 = std.mem.zeroes([32]u8);
    delq_key[0] = 0xAA;
    var other: [32]u8 = std.mem.zeroes([32]u8);
    other[0] = 0xBB; // stake voter != delinquent pubkey

    const delq_data = try buildVoteStateV2EpochCredits(t.allocator, &.{epoch - 6});
    defer t.allocator.free(delq_data);
    const ref_data = try buildVoteStateV2EpochCredits(t.allocator, &.{ epoch - 4, epoch - 3, epoch - 2, epoch - 1, epoch });
    defer t.allocator.free(ref_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = delq_key, .data_len = delq_data.len, .owner = VOTE_PROGRAM_ID },
        .{ .data_len = ref_data.len, .owner = VOTE_PROGRAM_ID },
    });
    defer h.deinit();
    @memcpy(h.accounts[1].data, delq_data);
    @memcpy(h.accounts[2].data, ref_data);
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    @memcpy(sd[STAKE_OFF_VOTER..][0..32], &other); // mismatch
    std.mem.writeInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], MAXU64, .little);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = epoch, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 14, .little);
    try t.expectError(error.M9_Stake_VoteAddressMismatch, execute(h.ctx, &ix));
    try t.expectEqual(MAXU64, std.mem.readInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little));
}

// KAT 5 — REJECT: stake already deactivating (deact != MAX) → AlreadyDeactivated.
test "M9 stake: DeactivateDelinquent rejects already-deactivating (tag 14)" {
    const t = std.testing;
    const epoch: u64 = 974;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xAA;

    const delq_data = try buildVoteStateV2EpochCredits(t.allocator, &.{epoch - 6});
    defer t.allocator.free(delq_data);
    const ref_data = try buildVoteStateV2EpochCredits(t.allocator, &.{ epoch - 4, epoch - 3, epoch - 2, epoch - 1, epoch });
    defer t.allocator.free(ref_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = voter, .data_len = delq_data.len, .owner = VOTE_PROGRAM_ID },
        .{ .data_len = ref_data.len, .owner = VOTE_PROGRAM_ID },
    });
    defer h.deinit();
    @memcpy(h.accounts[1].data, delq_data);
    @memcpy(h.accounts[2].data, ref_data);
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    @memcpy(sd[STAKE_OFF_VOTER..][0..32], &voter);
    std.mem.writeInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], 900, .little); // already deactivating
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = epoch, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 14, .little);
    try t.expectError(error.M9_Stake_AlreadyDeactivated, execute(h.ctx, &ix));
    try t.expectEqual(@as(u64, 900), std.mem.readInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little)); // unchanged
}

// KAT 6 — SUCCESS edge: delinquent vote acct with ZERO epoch_credits (never voted)
// is eligible → success (deact set). Confirms empty≠malformed (clean parse → true).
test "M9 stake: DeactivateDelinquent eligible when delinquent never voted (tag 14)" {
    const t = std.testing;
    const epoch: u64 = 974;
    var voter: [32]u8 = std.mem.zeroes([32]u8);
    voter[0] = 0xAA;

    const delq_data = try buildVoteStateV2EpochCredits(t.allocator, &.{}); // empty epoch_credits
    defer t.allocator.free(delq_data);
    const ref_data = try buildVoteStateV2EpochCredits(t.allocator, &.{ epoch - 4, epoch - 3, epoch - 2, epoch - 1, epoch });
    defer t.allocator.free(ref_data);

    var h = try Harness.init(t.allocator, 100_000, &.{
        .{ .data_len = 200, .lamports = 5_000_000_000, .owner = STAKE_PROGRAM_ID, .is_writable = true },
        .{ .pubkey = voter, .data_len = delq_data.len, .owner = VOTE_PROGRAM_ID },
        .{ .data_len = ref_data.len, .owner = VOTE_PROGRAM_ID },
    });
    defer h.deinit();
    @memcpy(h.accounts[1].data, delq_data);
    @memcpy(h.accounts[2].data, ref_data);
    const sd = h.accounts[0].data;
    std.mem.writeInt(u32, sd[0..4], 2, .little);
    @memcpy(sd[STAKE_OFF_VOTER..][0..32], &voter);
    std.mem.writeInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], MAXU64, .little);
    h.cache.clock_view = .{ .slot = 0, .epoch_start_timestamp = 0, .epoch = epoch, .leader_schedule_epoch = 0, .unix_timestamp = 0 };

    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 14, .little);
    try execute(h.ctx, &ix);
    try t.expectEqual(epoch, std.mem.readInt(u64, sd[STAKE_OFF_DEACTIVATION_EPOCH..][0..8], .little)); // SUCCESS
}

// ── GetMinimumDelegation (tag 13) KATs — canonical Sig lib.zig:373-384 + KAT :3162 ──
// Success: NO accounts, NO signers, NO state mutation; return_data = u64 LE(1 SOL),
// program_id = Stake. Negative KATs prove no EpochRewards gate / no account need.
test "M9 stake: GetMinimumDelegation (tag 13) returns 1 SOL LE, no accounts" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{}); // no instruction accounts (canonical)
    defer h.popFrame();

    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 13, .little);
    try execute(h.ctx, &ix);

    // return_data == 8 bytes LE(1_000_000_000) == 00 CA 9A 3B 00 00 00 00
    const expected = [8]u8{ 0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00 };
    try t.expectEqual(@as(usize, 8), h.ctx.tx.return_data.data.items.len);
    try t.expectEqualSlices(u8, &expected, h.ctx.tx.return_data.data.items[0..8]);
    try t.expectEqual(@as(u64, 1_000_000_000), std.mem.readInt(u64, h.ctx.tx.return_data.data.items[0..8], .little));
    try t.expectEqual(MIN_DELEGATION_LAMPORTS, std.mem.readInt(u64, h.ctx.tx.return_data.data.items[0..8], .little));
    // program_id == Stake program id
    try t.expectEqualSlices(u8, &STAKE_PROGRAM_ID, &h.ctx.tx.return_data.program_id);
}

// EpochRewards-active must NOT block tag 13 (the documented exception, Sig lib.zig:73).
// Every OTHER stake ix would return M9_Stake_EpochRewardsActive here.
test "M9 stake: GetMinimumDelegation NOT gated by EpochRewardsActive" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    h.cache.epoch_rewards_view = .{ .distribution_starting_block_height = 0, .num_partitions = 1, .parent_blockhash = std.mem.zeroes([32]u8), .total_points = 0, .total_rewards = 0, .distributed_rewards = 0, .active = true };
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var ix: [4]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 13, .little);
    try execute(h.ctx, &ix); // must SUCCEED despite active reward window
    try t.expectEqual(@as(u64, 1_000_000_000), std.mem.readInt(u64, h.ctx.tx.return_data.data.items[0..8], .little));
}

// Carrier shape: tag-13 CPI the stub used to FAIL must now succeed; trailing bytes
// ignored, no signer required (mirrors a real CPI invocation packing extra data).
test "M9 stake: GetMinimumDelegation ignores trailing ix bytes + needs no signer — carrier shape" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var ix: [8]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 13, .little);
    std.mem.writeInt(u32, ix[4..8], 0xDEADBEEF, .little); // trailing garbage ignored
    try execute(h.ctx, &ix);
    try t.expectEqual(@as(usize, 8), h.ctx.tx.return_data.data.items.len);
    try t.expectEqual(@as(u64, 1_000_000_000), std.mem.readInt(u64, h.ctx.tx.return_data.data.items[0..8], .little));
}
