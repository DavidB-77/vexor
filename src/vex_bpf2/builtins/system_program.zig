//! Vexor BPF2 — M9: System native builtin program.
//!
//! ── Spec source ───────────────────────────────────────────────────────────
//!   • agave-v4.0.0-beta.7: programs/system/src/system_processor.rs:325-540
//!     (process_instruction match) + system_instruction.rs (enum)
//!   • sig: src/runtime/program/system/{execute.zig,instruction.zig,error.zig}
//!
//! ── Instruction enum (tag = u32 LE) ───────────────────────────────────────
//!     0  CreateAccount { lamports: u64, space: u64, owner: Pubkey }
//!     1  Assign { owner: Pubkey }
//!     2  Transfer { lamports: u64 }
//!     3  CreateAccountWithSeed { base, seed, lamports, space, owner }
//!     4  AdvanceNonceAccount
//!     5  WithdrawNonceAccount(lamports)
//!     6  InitializeNonceAccount(authorized: Pubkey)
//!     7  AuthorizeNonceAccount(authority: Pubkey)
//!     8  Allocate { space: u64 }
//!     9  AllocateWithSeed { base, seed, space, owner }
//!    10  AssignWithSeed { base, seed, owner }
//!    11  TransferWithSeed { lamports, from_seed, from_owner }
//!    12  UpgradeNonceAccount
//!    13  CreateAccountAllowPrefund (SIMD-0083 — gate dormant on testnet)
//!
//! ── Port status (this session) ────────────────────────────────────────────
//!   • Full: 2 Transfer, 1 Assign, 8 Allocate (3 hottest non-create paths).
//!   • Parser: full — every variant decodes its bincode payload.
//!   • VariantPending: 4/5/6 only (Advance/Withdraw/Initialize) — return
//!     module-prefixed `M9_System_VariantPending_<Name>`; they need a NonceEnv
//!     the CPI InvokeContext doesn't carry (Tier-2 follow-up). Nonce
//!     Authorize(7)+Upgrade(12) ARE handled (task#105 Tier-1: env-free ports of
//!     native/nonce.zig, locked by KAT e5/e6). 3/9/10/11/13 are also fully
//!     ported (WithSeed family + SIMD-0312). The parser layer decodes every
//!     variant's bincode payload.
//!
//! ── SIMD inventory ────────────────────────────────────────────────────────
//!   • SIMD-0083 (CreateAccountAllowPrefund) — variant 13. Gate dormant on
//!     testnet AND mainnet; rejecting parse for now is correct.
//!   • SIMD-0082 (Disable account loader special case) — affects loader,
//!     not system program.
//!
//! ── fix_ledger anchors ────────────────────────────────────────────────────
//!   • vex-058 — Rent / EpochSchedule reads in CreateAccount go via
//!     ctx.sysvar_cache.getRent() and propagate SysvarNotPopulated up.

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const InvokeContext = ic.InvokeContext;
const Pubkey32 = ic.Pubkey32;
const AccountView = ic.AccountView;
const trace = @import("mod.zig").trace;

pub const COMPUTE_UNITS: u64 = 150;

pub const Error = error{
    M9_System_OutOfCompute,
    M9_System_NoActiveFrame,
    M9_System_NotEnoughAccounts,
    M9_System_AccountIndexOutOfBounds,
    M9_System_InvalidInstructionData,
    M9_System_UnknownInstructionTag,
    M9_System_AccountAlreadyInUse,
    M9_System_ResultWithNegativeLamports,
    M9_System_InvalidProgramId,
    M9_System_InvalidAccountData,
    M9_System_InvalidAccountDataLength,
    M9_System_MaxSeedLengthExceeded,
    M9_System_AddressWithSeedMismatch,
    M9_System_NonceNoRecentBlockhashes,
    M9_System_NonceBlockhashNotExpired,
    M9_System_NonceUnauthorized,
    M9_System_MissingRequiredSignature,
    M9_System_AccountNotWritable,
    M9_System_InsufficientFunds,
    M9_System_VariantPending_CreateAccount,
    M9_System_VariantPending_CreateAccountWithSeed,
    M9_System_VariantPending_AdvanceNonceAccount,
    M9_System_VariantPending_WithdrawNonceAccount,
    M9_System_VariantPending_InitializeNonceAccount,
    M9_System_VariantPending_AuthorizeNonceAccount,
    M9_System_VariantPending_AllocateWithSeed,
    M9_System_VariantPending_AssignWithSeed,
    M9_System_VariantPending_TransferWithSeed,
    M9_System_VariantPending_UpgradeNonceAccount,
    M9_System_VariantPending_CreateAccountAllowPrefund,
    // task#105 Tier-1: nonce Authorize(7)+Upgrade(12) on the CPI path.
    // Maps to Agave InstructionError::InvalidArgument (writable-fail / Upgrade
    // None branch) and InvalidAccountOwner (Upgrade non-System owner). These
    // do not affect bank_hash (tx-error/CU excluded) — only commit-or-not + the
    // resulting account bytes are consensus-critical — but distinct names keep
    // the failure surfaces auditable.
    M9_System_InvalidArgument,
    M9_System_InvalidAccountOwner,
    // LANE-L-BACKPORT-AUDIT-2026-07-17 #4/#5: maps to Agave
    // InstructionError::ModifiedProgramId, the error BorrowedAccount::
    // set_owner() returns (transaction_context.rs) when any of its 3
    // preconditions fail: the account isn't already owned by the currently
    // executing program, isn't writable, or its data isn't all-zero. This is
    // a generic low-level account-mutation guard (not System-specific in
    // Agave) hit via Assign/AssignWithSeed's owner-reassignment path.
    M9_System_ModifiedProgramId,
};

pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

const SYSTEM_PROGRAM_ID = @import("mod.zig").SYSTEM_PROGRAM_ID;

// ── Instruction parser (bincode tag = u32 LE) ─────────────────────────────

pub const Instruction = union(enum) {
    create_account: struct { lamports: u64, space: u64, owner: Pubkey32 },
    assign: struct { owner: Pubkey32 },
    transfer: struct { lamports: u64 },
    // task#15 FIX 2 (2026-06-11): WithSeed family ported into the CPI path.
    // `seed` borrows from ix_data (valid for the dispatch call). Carrier #12
    // (@414674115) class: address = SHA256(base|seed|owner), NO PDA marker.
    create_account_with_seed: struct { base: Pubkey32, seed: []const u8, lamports: u64, space: u64, owner: Pubkey32 },
    advance_nonce_account: void, // pending (needs NonceEnv/bank state — see execute())
    withdraw_nonce_account: u64, // pending
    initialize_nonce_account: Pubkey32, // pending
    authorize_nonce_account: Pubkey32, // pending
    allocate: struct { space: u64 },
    allocate_with_seed: struct { base: Pubkey32, seed: []const u8, space: u64, owner: Pubkey32 },
    assign_with_seed: struct { base: Pubkey32, seed: []const u8, owner: Pubkey32 },
    transfer_with_seed: struct { lamports: u64, from_seed: []const u8, from_owner: Pubkey32 },
    upgrade_nonce_account: void, // pending
    // PR-5m (2026-05-18): SIMD-0312 activated on testnet at slot 406,604,256
    // (ep 954). Wire-form payload matches CreateAccount (lamports, space, owner).
    create_account_allow_prefund: struct { lamports: u64, space: u64, owner: Pubkey32 },
};

pub fn decode(ix_data: []const u8) Error!Instruction {
    if (ix_data.len < 4) return error.M9_System_InvalidInstructionData;
    const tag = std.mem.readInt(u32, ix_data[0..4], .little);
    const body = ix_data[4..];
    switch (tag) {
        0 => {
            if (body.len < 8 + 8 + 32) return error.M9_System_InvalidInstructionData;
            return .{ .create_account = .{
                .lamports = std.mem.readInt(u64, body[0..8], .little),
                .space = std.mem.readInt(u64, body[8..16], .little),
                .owner = body[16..48].*,
            } };
        },
        1 => {
            if (body.len < 32) return error.M9_System_InvalidInstructionData;
            return .{ .assign = .{ .owner = body[0..32].* } };
        },
        2 => {
            if (body.len < 8) return error.M9_System_InvalidInstructionData;
            return .{ .transfer = .{ .lamports = std.mem.readInt(u64, body[0..8], .little) } };
        },
        3 => {
            // CreateAccountWithSeed { base(32), seed(String: u64 len + bytes),
            //   lamports(u64), space(u64), owner(32) }.
            // Mirrors system_v2.zig execute() .CreateAccountWithSeed parser +
            // Agave system_instruction.rs CreateAccountWithSeed bincode layout.
            if (body.len < 32 + 8) return error.M9_System_InvalidInstructionData;
            const base: Pubkey32 = body[0..32].*;
            const seed_len = std.mem.readInt(u64, body[32..40], .little);
            // FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #1, zbpf 0f0f493): seed_len
            // is attacker-controlled (read straight off the wire, unbounded by
            // body.len). Plain `+` traps as an unrecoverable ReleaseSafe panic
            // (process abort) when seed_len is near u64::MAX, regardless of the
            // real (small) body.len -- a validator-crash DoS on a routine System
            // CPI variant. Agave's bincode deserializer never forms this sum at
            // all (it walks the reader byte-by-byte and EOFs on a length prefix
            // that overruns the remaining buffer), so there is no equivalent
            // overflow surface upstream to match -- the fix is to make the
            // bounds check itself overflow-safe instead of trap-unsafe.
            if (body.len < 40 +| seed_len +| 8 +| 8 +| 32) return error.M9_System_InvalidInstructionData;
            const seed = body[40 .. 40 + seed_len];
            const rest = body[40 + seed_len ..];
            return .{ .create_account_with_seed = .{
                .base = base,
                .seed = seed,
                .lamports = std.mem.readInt(u64, rest[0..8], .little),
                .space = std.mem.readInt(u64, rest[8..16], .little),
                .owner = rest[16..48].*,
            } };
        },
        4 => return .advance_nonce_account,
        5 => {
            if (body.len < 8) return error.M9_System_InvalidInstructionData;
            return .{ .withdraw_nonce_account = std.mem.readInt(u64, body[0..8], .little) };
        },
        6 => {
            if (body.len < 32) return error.M9_System_InvalidInstructionData;
            return .{ .initialize_nonce_account = body[0..32].* };
        },
        7 => {
            if (body.len < 32) return error.M9_System_InvalidInstructionData;
            return .{ .authorize_nonce_account = body[0..32].* };
        },
        8 => {
            if (body.len < 8) return error.M9_System_InvalidInstructionData;
            return .{ .allocate = .{ .space = std.mem.readInt(u64, body[0..8], .little) } };
        },
        9 => {
            // AllocateWithSeed { base(32), seed(String), space(u64), owner(32) }.
            if (body.len < 32 + 8) return error.M9_System_InvalidInstructionData;
            const base: Pubkey32 = body[0..32].*;
            const seed_len = std.mem.readInt(u64, body[32..40], .little);
            // FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #1): same saturating-add
            // fix as CreateAccountWithSeed above -- see that comment.
            if (body.len < 40 +| seed_len +| 8 +| 32) return error.M9_System_InvalidInstructionData;
            const seed = body[40 .. 40 + seed_len];
            const rest = body[40 + seed_len ..];
            return .{ .allocate_with_seed = .{
                .base = base,
                .seed = seed,
                .space = std.mem.readInt(u64, rest[0..8], .little),
                .owner = rest[8..40].*,
            } };
        },
        10 => {
            // AssignWithSeed { base(32), seed(String), owner(32) }.
            if (body.len < 32 + 8) return error.M9_System_InvalidInstructionData;
            const base: Pubkey32 = body[0..32].*;
            const seed_len = std.mem.readInt(u64, body[32..40], .little);
            // FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #1): same saturating-add
            // fix as CreateAccountWithSeed above -- see that comment.
            if (body.len < 40 +| seed_len +| 32) return error.M9_System_InvalidInstructionData;
            const seed = body[40 .. 40 + seed_len];
            const owner = body[40 + seed_len ..][0..32].*;
            return .{ .assign_with_seed = .{ .base = base, .seed = seed, .owner = owner } };
        },
        11 => {
            // TransferWithSeed { lamports(u64), from_seed(String), from_owner(32) }.
            if (body.len < 8 + 8) return error.M9_System_InvalidInstructionData;
            const lamports = std.mem.readInt(u64, body[0..8], .little);
            const seed_len = std.mem.readInt(u64, body[8..16], .little);
            // FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #1): same saturating-add
            // fix as CreateAccountWithSeed above -- see that comment.
            if (body.len < 16 +| seed_len +| 32) return error.M9_System_InvalidInstructionData;
            const seed = body[16 .. 16 + seed_len];
            const from_owner = body[16 + seed_len ..][0..32].*;
            return .{ .transfer_with_seed = .{
                .lamports = lamports,
                .from_seed = seed,
                .from_owner = from_owner,
            } };
        },
        12 => return .upgrade_nonce_account,
        13 => {
            // SIMD-0312 — same wire shape as CreateAccount (variant 0).
            if (body.len < 8 + 8 + 32) return error.M9_System_InvalidInstructionData;
            return .{ .create_account_allow_prefund = .{
                .lamports = std.mem.readInt(u64, body[0..8], .little),
                .space = std.mem.readInt(u64, body[8..16], .little),
                .owner = body[16..48].*,
            } };
        },
        else => return error.M9_System_UnknownInstructionTag,
    }
}

// ── Dispatch ──────────────────────────────────────────────────────────────

pub fn execute(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    ctx.consumeCompute(COMPUTE_UNITS) catch return error.M9_System_OutOfCompute;
    const ix = try decode(ix_data);
    trace("M9.system.execute (variant={s})", .{@tagName(ix)});

    return switch (ix) {
        .transfer => |t| executeTransfer(ctx, t.lamports),
        .assign => |a| executeAssign(ctx, a.owner),
        .allocate => |al| executeAllocate(ctx, al.space),
        .create_account => |c| executeCreateAccount(ctx, c.lamports, c.space, c.owner),
        // task#15 FIX 2 (2026-06-11): WithSeed family — canonical logic ported
        // into the CPI path (no module-cycle bridge to native/system_v2.zig is
        // possible: production vex_bpf2 imports only vex_crypto, and vex_svm
        // imports vex_bpf2 — see build.zig:225-234). These mirror system_v2.zig
        // execCreateAccountWithSeed/execAllocateWithSeed/execAssignWithSeed/
        // execTransferWithSeed byte-for-byte; the differential KAT proves it.
        .create_account_with_seed => |c| executeCreateAccountWithSeed(ctx, &c.base, c.seed, c.lamports, c.space, c.owner),
        .allocate_with_seed => |a| executeAllocateWithSeed(ctx, &a.base, a.seed, a.space, a.owner),
        .assign_with_seed => |a| executeAssignWithSeed(ctx, &a.base, a.seed, a.owner),
        .transfer_with_seed => |t| executeTransferWithSeed(ctx, t.from_seed, &t.from_owner, t.lamports),
        // Nonce ops — env-dependence split (task#105 Tier-1, 2026-06-21):
        //   • Authorize(7) + Upgrade(12) are NOW handled on the CPI path. A
        //     RULE#15 behavior-extractor confirmed they touch NO environment
        //     state — Agave's Versions::authorize takes only signers + the new
        //     authority, and Versions::upgrade reads only the account's own
        //     stored durable_nonce (no recent_blockhash / lamports_per_signature
        //     / rent). They are byte-faithful ports of native/nonce.zig
        //     execAuthorizeNonce/execUpgradeNonce (the differential KAT e5/e6
        //     proves it), with Upgrade's owner==System check mirrored from the
        //     PROCESSOR (native/system_v2.execUpgradeNonce, Agave
        //     system_processor.rs:476-478) since the inner handler omits it.
        //   • Advance(4)/Withdraw(5)/Initialize(6) remain documented-fail: they
        //     require a NonceEnv (recent_blockhash + lamports_per_signature from
        //     the bank's blockhash queue + a rent-minimum fn) that the CPI
        //     InvokeContext does not carry — identical posture to
        //     v2_dispatch.fallbackSystem, which leaves nonce_env null so they
        //     fail loudly rather than commit a garbage blockhash. NonceEnv
        //     plumbing into the CPI path is a separate Tier-2 follow-up. The
        //     TOP-LEVEL path (replay_stage) wires the real env for all five.
        .advance_nonce_account => error.M9_System_VariantPending_AdvanceNonceAccount,
        .withdraw_nonce_account => error.M9_System_VariantPending_WithdrawNonceAccount,
        .initialize_nonce_account => error.M9_System_VariantPending_InitializeNonceAccount,
        .authorize_nonce_account => |new_authority| executeAuthorizeNonce(ctx, new_authority),
        .upgrade_nonce_account => executeUpgradeNonce(ctx),
        // PR-5m (2026-05-18): SIMD-0312 wire into BPF CPI dispatch.
        // (The header comment SIMD-0083/"dormant" is stale; SIMD-0312
        //  activated on testnet at slot 406,604,256, ep 954, per
        //  vex-fd-dev/src/vex_svm/native/system_v2.zig:712.)
        // The native handler at system_v2.zig:415 has been correct since
        // SIMD-0312 landed; this CPI dispatch path returning
        // VariantPending was the gap. Empirically suspected as the
        // Hyperlane carrier (tx[563] @ slot 409321603) where deep BPF
        // CPIs invoke System with variant 13 to fund newly-created PDAs.
        .create_account_allow_prefund => |c| executeCreateAccountAllowPrefund(ctx, c.lamports, c.space, c.owner),
    };
}

// ── Handler: Transfer ─────────────────────────────────────────────────────
// Mirrors agave system_processor.rs transfer() at:325-376.
// Pre:
//   - 2 accounts in borrow set: from(0), to(1).
//   - from is writable + signer.
//   - from.owner == SystemProgram (checked implicitly: only SystemProgram
//     can debit from a System-owned account).
fn executeTransfer(ctx: *InvokeContext, lamports: u64) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 2) return error.M9_System_NotEnoughAccounts;
    const from_idx = frame.account_indices[0];
    const to_idx = frame.account_indices[1];
    if (from_idx >= ctx.tx.accounts.len or to_idx >= ctx.tx.accounts.len)
        return error.M9_System_AccountIndexOutOfBounds;
    const from = &ctx.tx.accounts[from_idx];
    const to = &ctx.tx.accounts[to_idx];

    if (!from.is_writable) return error.M9_System_AccountNotWritable;
    if (!to.is_writable) return error.M9_System_AccountNotWritable;
    if (!from.is_signer) return error.M9_System_MissingRequiredSignature;
    if (!std.mem.eql(u8, &from.owner, &SYSTEM_PROGRAM_ID)) return error.M9_System_InvalidAccountData;
    if (from.data.len != 0) return error.M9_System_InvalidAccountData;

    if (lamports > from.lamports) return error.M9_System_InsufficientFunds;
    // Saturating-safe arithmetic per agave; AccountView.lamports is u64.
    from.lamports = std.math.sub(u64, from.lamports, lamports) catch return error.M9_System_InsufficientFunds;
    const new_to = std.math.add(u64, to.lamports, lamports) catch return error.M9_System_ResultWithNegativeLamports;
    to.lamports = new_to;
}

// ── Handler: Assign ───────────────────────────────────────────────────────
// Mirrors agave system_processor.rs assign() at:194-228.
// Pre: 1 account in borrow set, account is signer and writable.
fn executeAssign(ctx: *InvokeContext, new_owner: Pubkey32) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 1) return error.M9_System_NotEnoughAccounts;
    const idx = frame.account_indices[0];
    if (idx >= ctx.tx.accounts.len) return error.M9_System_AccountIndexOutOfBounds;
    const a = &ctx.tx.accounts[idx];
    // task#15 FIX 3 (2026-06-11): canonical Agave assign() ORDER — the
    // already-owned NO-OP check runs BEFORE the signer check (Agave
    // system_processor.rs assign():194-210; FD fd_system_program.c:227-228;
    // native/system_v2.assign():418). The pre-fix CPI order checked the signer
    // FIRST, so Assign(owner) on an account already owned by `owner` but NOT
    // signed returned MissingRequiredSignature where the cluster returns Ok —
    // a failed-tx-vs-success divergence. The differential KAT ("diff c") caught
    // it.
    //
    // FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #4): the comment above used to
    // claim "Agave's assign() does NOT check writability" and stop there —
    // true only of assign()'s OWN function body (system_processor.rs:194-
    // 228), which indeed has no explicit `if !writable` line. But assign()
    // ends with `account.set_owner(owner.as_ref())?`, and set_owner() itself
    // (transaction_context.rs) enforces 3 preconditions — owned-by-System,
    // writable, AND zero-data — before allowing the mutation, returning
    // ModifiedProgramId on any violation. See checkSetOwnerPreconditions()
    // above for the full citation; this call was missing entirely.
    if (std.mem.eql(u8, &a.owner, &new_owner)) return; // no work to do
    if (!a.is_signer) return error.M9_System_MissingRequiredSignature;
    try checkSetOwnerPreconditions(a);
    a.owner = new_owner;
}

// ── Handler: CreateAccount ────────────────────────────────────────────────
// r75-bug-class-b-create-account (2026-05-06): mirrors agave system_processor.rs
// create_account() — System variant 0, the InitializePriorityFeeDistributionAccount
// CPI carrier. Until now this returned VariantPending → mapped to
// M6_CpiHandlerNotReady at the syscall boundary → tx revert → Vexor missed
// the per-slot PriorityFeeDistribution PDA init → bank_hash diverged from
// slot ~345 onwards (when the cluster's first non-skipped InitPFDA tx fires).
//
// CreateAccount = Transfer (from→to) + Allocate (to.data sized to `space`) +
// Assign (to.owner ← `owner`). Pre-checks: from is writable+signer, to is
// writable+signer (PDA signed via cpi.zig signers_seeds for Anchor `init`),
// to is currently System-owned with zero lamports + zero data length.
// ── Handler: CreateAccountAllowPrefund (SIMD-0312, variant 13) ───────────
// PR-5m (2026-05-18): port of the native handler at system_v2.zig:378-429
// to the BPF CPI dispatch path. Differences from CreateAccount:
//   1. `to` is at frame.account_indices[0] (NOT [1]). The transfer source
//      `from` is at account_indices[1] only when lamports > 0; otherwise
//      no source account is present (caller provides only `to`).
//   2. NO `account_already_in_use` check on `to` — the whole point of
//      prefund is allowing `to` to already hold lamports (paid by an
//      external party before this ix runs).
//   3. The transfer / signer-check on `from` only fires when lamports > 0.
//
// SIMD-0312 active on testnet at slot 406,604,256 (ep 954). Prior to this
// PR, BPF programs CPI'ing into System with variant 13 hard-rejected with
// `M9_System_VariantPending_CreateAccountAllowPrefund`, causing the entire
// outer tx (incl. caller mutations) to revert silently on Vexor while
// succeeding on cluster — a bank_hash divergence carrier.
fn executeCreateAccountAllowPrefund(
    ctx: *InvokeContext,
    lamports: u64,
    space: u64,
    new_owner: Pubkey32,
) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    // At minimum need the `to` account at index 0.
    if (frame.account_indices.len < 1) return error.M9_System_NotEnoughAccounts;
    const to_idx = frame.account_indices[0];
    if (to_idx >= ctx.tx.accounts.len) return error.M9_System_AccountIndexOutOfBounds;
    const to = &ctx.tx.accounts[to_idx];

    if (!to.is_writable) return error.M9_System_AccountNotWritable;
    if (!to.is_signer) return error.M9_System_MissingRequiredSignature;
    // No `account_already_in_use` check — that's the SIMD-0312 relaxation.

    if (space > MAX_PERMITTED_DATA_LENGTH) return error.M9_System_InvalidAccountDataLength;

    // Allocate first (matches native execCreateAccountAllowPrefund order:
    // allocateAndAssign → then transfer). Resize to `space`, zero-fill.
    if (to.data.len != space) {
        const new_data = ctx.allocator.alloc(u8, @intCast(space)) catch
            return error.M9_System_InvalidAccountDataLength;
        @memset(new_data, 0);
        to.data = new_data;
    } else if (space > 0) {
        @memset(to.data, 0);
    }
    // Assign owner.
    to.owner = new_owner;

    // Transfer iff lamports > 0; requires a second `from` account at idx 1.
    if (lamports > 0) {
        if (frame.account_indices.len < 2) return error.M9_System_NotEnoughAccounts;
        const from_idx = frame.account_indices[1];
        if (from_idx >= ctx.tx.accounts.len) return error.M9_System_AccountIndexOutOfBounds;
        const from = &ctx.tx.accounts[from_idx];

        if (!from.is_writable) return error.M9_System_AccountNotWritable;
        if (!from.is_signer) return error.M9_System_MissingRequiredSignature;
        if (!std.mem.eql(u8, &from.owner, &SYSTEM_PROGRAM_ID)) return error.M9_System_InvalidAccountData;
        if (from.data.len != 0) return error.M9_System_InvalidAccountData;
        if (lamports > from.lamports) return error.M9_System_InsufficientFunds;

        from.lamports = std.math.sub(u64, from.lamports, lamports) catch return error.M9_System_InsufficientFunds;
        const new_to_lam = std.math.add(u64, to.lamports, lamports) catch
            return error.M9_System_ResultWithNegativeLamports;
        to.lamports = new_to_lam;
    }
}

fn executeCreateAccount(ctx: *InvokeContext, lamports: u64, space: u64, new_owner: Pubkey32) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 2) return error.M9_System_NotEnoughAccounts;
    const from_idx = frame.account_indices[0];
    const to_idx = frame.account_indices[1];
    if (from_idx >= ctx.tx.accounts.len or to_idx >= ctx.tx.accounts.len)
        return error.M9_System_AccountIndexOutOfBounds;
    const from = &ctx.tx.accounts[from_idx];
    const to = &ctx.tx.accounts[to_idx];

    if (!from.is_writable) return error.M9_System_AccountNotWritable;
    if (!from.is_signer) return error.M9_System_MissingRequiredSignature;
    if (!std.mem.eql(u8, &from.owner, &SYSTEM_PROGRAM_ID)) return error.M9_System_InvalidAccountData;
    if (from.data.len != 0) return error.M9_System_InvalidAccountData;

    if (!to.is_writable) return error.M9_System_AccountNotWritable;
    if (!to.is_signer) return error.M9_System_MissingRequiredSignature;
    // agave checks `account_already_in_use`: to must currently be empty
    // (zero lamports, zero data, System-owned).
    if (to.lamports != 0) return error.M9_System_AccountAlreadyInUse;
    if (space > MAX_PERMITTED_DATA_LENGTH) return error.M9_System_InvalidAccountDataLength;
    // to.owner is initially System (the loader-default for fresh PDAs);
    // we change it to `new_owner` after the transfer + allocate.

    if (lamports > from.lamports) return error.M9_System_InsufficientFunds;

    // Transfer
    from.lamports = std.math.sub(u64, from.lamports, lamports) catch return error.M9_System_InsufficientFunds;
    const new_to = std.math.add(u64, to.lamports, lamports) catch return error.M9_System_ResultWithNegativeLamports;
    to.lamports = new_to;

    // Allocate: grow `to.data` to `space` bytes (zero-filled).
    // r75-bug-class-b-create-account-allocate (2026-05-06): for fresh PDAs
    // being created via Anchor `init`, `to.data.len == 0` pre-call. Agave's
    // System::CreateAccount actively resizes the account's data vec; the
    // M9 handler must do the same. We allocate via `ctx.allocator` (the
    // per-dispatch arena — per replay_stage.zig:4288), which lives until
    // the dispatch frame ends and `extractMutations` has captured the new
    // bytes for commit to db.
    if (to.data.len != space) {
        const new_data = ctx.allocator.alloc(u8, @intCast(space)) catch
            return error.M9_System_InvalidAccountDataLength;
        @memset(new_data, 0);
        to.data = new_data;
    } else if (space > 0) {
        @memset(to.data, 0);
    }
    // Assign owner.
    to.owner = new_owner;
}

// ── Handler: Allocate ─────────────────────────────────────────────────────
// Mirrors agave system_processor.rs allocate() at:230-277.
// Pre: 1 account, signer + writable, currently System-owned, currently
//      data.len == 0. Sets data.len to `space` (zeroes implicit).
fn executeAllocate(ctx: *InvokeContext, space: u64) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 1) return error.M9_System_NotEnoughAccounts;
    const idx = frame.account_indices[0];
    if (idx >= ctx.tx.accounts.len) return error.M9_System_AccountIndexOutOfBounds;
    const a = &ctx.tx.accounts[idx];
    // Agave system_processor.rs allocate():75-101 — exact order:
    //   (1) authority must sign, (2) AccountAlreadyInUse if !data.is_empty()
    //   OR owner != system, (3) space > MAX → InvalidAccountDataLength,
    //   (4) set_data_length(space).
    if (!a.is_signer) return error.M9_System_MissingRequiredSignature;
    if (!a.is_writable) return error.M9_System_AccountNotWritable;

    // task#15 FIX 2 (2026-06-11): the combined already-in-use guard. The
    // carrier-14 fix (2026-06-11) correctly let Allocate GROW a FRESH
    // (data.len==0) system-owned account, but it dropped the canonical
    // `!data.is_empty()` half of Agave's guard — so it would also silently
    // grow/zero an account that ALREADY holds data, where Agave + FD +
    // native/system_v2.allocate() return AccountAlreadyInUse. The differential
    // KAT (kat_system_cpi_native_diff "diff b") caught the divergence. Restore
    // the full guard: reject unless the account is BOTH empty AND system-owned.
    // carrier-14 (data.len==0, system-owned) still passes and grows.
    if (a.data.len != 0 or !std.mem.eql(u8, &a.owner, &SYSTEM_PROGRAM_ID)) {
        return error.M9_System_AccountAlreadyInUse;
    }
    if (space > MAX_PERMITTED_DATA_LENGTH) return error.M9_System_InvalidAccountDataLength;

    // set_data_length(space): grow the fresh (len==0) buffer to `space`,
    // zero-filled. carrier #14 (@414706899): Metaplex
    // create_or_allocate_account_raw on a prefunded PDA does
    // Transfer→Allocate(space)→Assign via invoke_signed; pre-carrier-14 this
    // rejected the 0→679 resize → M7_BuiltinFailed → divergence.
    if (space > 0) {
        const new_data = ctx.allocator.alloc(u8, @intCast(space)) catch
            return error.M9_System_InvalidAccountDataLength;
        @memset(new_data, 0);
        a.data = new_data;
    }
}

// ── WithSeed family (task#15 FIX 2, 2026-06-11) ────────────────────────────
// Canonical logic ported into the CPI path. Byte-for-byte mirror of
// native/system_v2.zig (which mirrors FD fd_system_program.c + Agave
// programs/system/src/system_processor.rs). A module-cycle bridge to
// system_v2.zig is impossible (production vex_bpf2 imports only vex_crypto;
// vex_svm imports vex_bpf2 — build.zig:225-234), so the canonical
// derivation/checks are reproduced here and locked to system_v2 via the
// differential KAT (kat_system_cpi_native_diff.zig).

const PDA_MARKER = "ProgramDerivedAddress"; // 21 bytes

/// Re-derive an account address from (base, seed, owner) and compare with
/// `expected`. Mirrors system_v2.verifySeedAddress + Agave
/// solana_pubkey::Pubkey::create_with_seed + FD fd_pubkey_create_with_seed.
///
/// carrier #12 (2026-06-11 @414674115): the address is SHA256(base|seed|owner)
/// with NO "ProgramDerivedAddress" marker — that 21-byte suffix belongs ONLY
/// to create_program_address / find_program_address (real PDAs), never to
/// create_with_seed. Appending it derives the wrong address → every
/// createAccountWithSeed (stake/nonce/derived accounts) hits
/// AddressWithSeedMismatch → Vexor rolls back a tx the cluster executed.
fn verifySeedAddress(
    expected: *const Pubkey32,
    base: *const Pubkey32,
    seed: []const u8,
    owner: *const Pubkey32,
) Error!void {
    // MAX_SEED_LEN = 32 (Agave). FD: too-long seed → MaxSeedLengthExceeded.
    if (seed.len > 32) return error.M9_System_MaxSeedLengthExceeded;

    // IllegalOwner guard (FD fd_pubkey_utils.c memcmp(owner+11, marker, 21)):
    // owner must NOT end with the PDA marker, else create_with_seed could
    // collide into PDA space. owner[11..32] is the trailing 21 bytes.
    if (std.mem.eql(u8, owner[11..32], PDA_MARKER)) {
        return error.M9_System_InvalidProgramId; // IllegalOwner
    }

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(base);
    hasher.update(seed);
    hasher.update(owner);
    var derived: Pubkey32 = undefined;
    hasher.final(&derived);

    if (!std.mem.eql(u8, &derived, expected)) {
        return error.M9_System_AddressWithSeedMismatch;
    }
}

/// Shared allocate primitive over an AccountView (mirrors system_v2.allocate +
/// the inline executeAllocate self-resize). Account must be empty + system
/// owned; resizes data to `space` zero-filled. The authority signer check is
/// the caller's responsibility (WithSeed authority = `base`, enforced before
/// this is reached via the seed-address derivation + an explicit base signer
/// check in the caller).
fn allocateAccountData(ctx: *InvokeContext, a: *AccountView, space: u64) Error!void {
    // Agave allocate(): account must be unallocated + system-owned.
    if (a.data.len != 0 or !std.mem.eql(u8, &a.owner, &SYSTEM_PROGRAM_ID)) {
        return error.M9_System_AccountAlreadyInUse;
    }
    if (space > MAX_PERMITTED_DATA_LENGTH) return error.M9_System_InvalidAccountDataLength;
    if (space > 0) {
        const new_data = ctx.allocator.alloc(u8, @intCast(space)) catch
            return error.M9_System_InvalidAccountDataLength;
        @memset(new_data, 0);
        a.data = new_data;
    }
}

/// FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #4/#5): mirrors Agave's
/// BorrowedAccount::set_owner() 3-precondition guard (transaction_context.rs)
/// — called internally by system_processor.rs assign()/assign_with_seed()
/// via `account.set_owner(owner.as_ref())?` AFTER the no-op and signer
/// checks pass, but BEFORE the mutation. All 3 preconditions map to the
/// SAME error, ModifiedProgramId:
///   1. the account must already be owned by the CURRENTLY EXECUTING program
///      (System, since Assign/AssignWithSeed are System's own handlers) —
///      i.e. Assign can only ever move ownership AWAY from System, never
///      reassign an account some other program already owns;
///   2. the account must be writable;
///   3. the account's data must be all-zero.
/// Neither executeAssign nor executeAssignWithSeed previously called this at
/// all — a writable, correctly-signed, non-System-owned or non-zero-data
/// account had its owner silently overwritten here where Agave hard-rejects
/// with ModifiedProgramId and writes nothing. Must run AFTER the no-op/
/// signer checks (matches Agave's call order) — do not hoist earlier, that
/// was AssignWithSeed's other bug (see call site).
fn checkSetOwnerPreconditions(a: *const AccountView) Error!void {
    if (!std.mem.eql(u8, &a.owner, &SYSTEM_PROGRAM_ID)) return error.M9_System_ModifiedProgramId;
    if (!a.is_writable) return error.M9_System_ModifiedProgramId;
    if (!std.mem.allEqual(u8, a.data, 0)) return error.M9_System_ModifiedProgramId;
}

/// Shared assign primitive (mirrors system_v2.assign + executeAssign):
/// no-op if already owned by `new_owner`, else set owner.
fn assignAccountOwner(a: *AccountView, new_owner: *const Pubkey32) void {
    if (std.mem.eql(u8, &a.owner, new_owner)) return;
    a.owner = new_owner.*;
}

/// True if `pubkey` appears in the current frame's borrow set as a signer.
/// Mirrors system_v2's authority-scan (fd_system_program.c:168-176): the
/// WithSeed authority signs anywhere in the instruction account list.
fn frameSignerPresent(ctx: *InvokeContext, frame: anytype, authority: *const Pubkey32) bool {
    for (frame.account_indices) |aidx| {
        if (aidx >= ctx.tx.accounts.len) continue;
        const a = &ctx.tx.accounts[aidx];
        if (a.is_signer and std.mem.eql(u8, &a.pubkey, authority)) return true;
    }
    return false;
}

// ── Handler: CreateAccountWithSeed (variant 3) ─────────────────────────────
// Mirrors system_v2.execCreateAccountWithSeed (fd_system_program.c:470-508).
// Accounts: from(0), to(1). The derived `to` address must equal
// SHA256(base|seed|owner). Authority for the allocate/assign on `to` is `base`.
fn executeCreateAccountWithSeed(
    ctx: *InvokeContext,
    base: *const Pubkey32,
    seed: []const u8,
    lamports: u64,
    space: u64,
    new_owner: Pubkey32,
) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 2) return error.M9_System_NotEnoughAccounts;
    const from_idx = frame.account_indices[0];
    const to_idx = frame.account_indices[1];
    if (from_idx >= ctx.tx.accounts.len or to_idx >= ctx.tx.accounts.len)
        return error.M9_System_AccountIndexOutOfBounds;
    const from = &ctx.tx.accounts[from_idx];
    const to = &ctx.tx.accounts[to_idx];

    // verify derived address (carrier #12 — no PDA marker).
    try verifySeedAddress(&to.pubkey, base, seed, &new_owner);

    // `base` must have signed (authority for allocate+assign on the new acct).
    if (!frameSignerPresent(ctx, frame, base)) return error.M9_System_MissingRequiredSignature;

    // createAccount: to must be empty (AccountAlreadyInUse if it holds lamports).
    if (!to.is_writable) return error.M9_System_AccountNotWritable;
    if (to.lamports != 0) return error.M9_System_AccountAlreadyInUse;

    // allocate_and_assign(to, space, owner) then transfer(from→to, lamports).
    try allocateAccountData(ctx, to, space);
    assignAccountOwner(to, &new_owner);

    // transfer requires `from` to be a system-owned, zero-data, signing source.
    if (!from.is_writable) return error.M9_System_AccountNotWritable;
    if (!from.is_signer) return error.M9_System_MissingRequiredSignature;
    if (!std.mem.eql(u8, &from.owner, &SYSTEM_PROGRAM_ID)) return error.M9_System_InvalidAccountData;
    if (from.data.len != 0) return error.M9_System_InvalidAccountData;
    if (lamports > from.lamports) return error.M9_System_InsufficientFunds;
    from.lamports = std.math.sub(u64, from.lamports, lamports) catch return error.M9_System_InsufficientFunds;
    to.lamports = std.math.add(u64, to.lamports, lamports) catch
        return error.M9_System_ResultWithNegativeLamports;
}

// ── Handler: AllocateWithSeed (variant 9) ──────────────────────────────────
// Mirrors system_v2.execAllocateWithSeed (fd_system_program.c:547-587).
// Accounts: account(0). Derived address = SHA256(base|seed|owner). Authority
// = base. allocate_and_assign(account, space, owner).
fn executeAllocateWithSeed(
    ctx: *InvokeContext,
    base: *const Pubkey32,
    seed: []const u8,
    space: u64,
    new_owner: Pubkey32,
) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 1) return error.M9_System_NotEnoughAccounts;
    const idx = frame.account_indices[0];
    if (idx >= ctx.tx.accounts.len) return error.M9_System_AccountIndexOutOfBounds;
    const a = &ctx.tx.accounts[idx];

    try verifySeedAddress(&a.pubkey, base, seed, &new_owner);
    if (!a.is_writable) return error.M9_System_AccountNotWritable;
    if (!frameSignerPresent(ctx, frame, base)) return error.M9_System_MissingRequiredSignature;

    try allocateAccountData(ctx, a, space);
    assignAccountOwner(a, &new_owner);
}

// ── Handler: AssignWithSeed (variant 10) ───────────────────────────────────
// Mirrors system_v2.execAssignWithSeed (fd_system_program.c:594-628).
// Accounts: account(0). Derived address = SHA256(base|seed|owner). Authority
// = base. assign(account, owner).
fn executeAssignWithSeed(
    ctx: *InvokeContext,
    base: *const Pubkey32,
    seed: []const u8,
    new_owner: Pubkey32,
) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 1) return error.M9_System_NotEnoughAccounts;
    const idx = frame.account_indices[0];
    if (idx >= ctx.tx.accounts.len) return error.M9_System_AccountIndexOutOfBounds;
    const a = &ctx.tx.accounts[idx];

    try verifySeedAddress(&a.pubkey, base, seed, &new_owner);
    // FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #5): this used to check
    // `!a.is_writable` here, BEFORE the no-op/signer checks below — wrong
    // order vs. Agave. assign_with_seed() (system_processor.rs) checks the
    // no-op case FIRST (`if account.get_owner() == owner { return Ok(()) }`,
    // no writability involved at all for that branch), THEN the signer
    // check, and only reaches set_owner()'s writable/owned-by-System/
    // zero-data guard (see checkSetOwnerPreconditions) LAST, right before
    // the mutation. The old order meant a non-writable account that was
    // ALREADY owned by new_owner (an idempotent no-op on real Agave) failed
    // here with AccountNotWritable instead of silently succeeding — a
    // success-vs-fail divergence on top of the same silent-mutation gap #4
    // has (owned-by-System + zero-data were never checked at all).
    // assign() is a no-op (no signer needed) if already owned by new_owner.
    if (std.mem.eql(u8, &a.owner, &new_owner)) return;
    if (!frameSignerPresent(ctx, frame, base)) return error.M9_System_MissingRequiredSignature;
    try checkSetOwnerPreconditions(a);
    a.owner = new_owner;
}

// ── Handler: TransferWithSeed (variant 11) ─────────────────────────────────
// Mirrors system_v2.execTransferWithSeed (fd_system_program.c:634-701).
// Accounts: from(0), from_base(1), to(2). from must equal
// SHA256(from_base|from_seed|from_owner) — NO PDA marker.
//
// FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #3, zbpf 7388191): this handler used
// to append PDA_MARKER ("ProgramDerivedAddress") to the hash, on the (wrong)
// belief that TransferWithSeed derives differently from the other 3
// with-seed variants. It does not: Agave's `Pubkey::create_with_seed` is one
// generic function (solana-pubkey, no per-instruction special case) used
// identically by CreateAccountWithSeed / AllocateWithSeed / AssignWithSeed /
// TransferWithSeed alike — SHA256(base||seed||owner), no marker. The PDA
// marker belongs ONLY to create_program_address/find_program_address (CPI
// signer PDAs), an unrelated derivation. This is the exact same defect class
// already root-caused and fixed for CreateAccountWithSeed as carrier #12
// (@414674115, see verifySeedAddress below + native/system_v2.zig:202-244):
// appending the marker means the derived address never matches a real
// cluster-issued `from` pubkey, so every genuine TransferWithSeed
// transaction fails M9_System_AddressWithSeedMismatch here while the
// cluster executes it — a failed-vs-success divergence. Now routed through
// the same shared verifySeedAddress() the other 3 with-seed variants use,
// which also picks up the MAX_SEED_LEN and IllegalOwner guards this handler
// was previously missing entirely. from_base must sign.
fn executeTransferWithSeed(
    ctx: *InvokeContext,
    from_seed: []const u8,
    from_owner: *const Pubkey32,
    lamports: u64,
) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 3) return error.M9_System_NotEnoughAccounts;
    const from_idx = frame.account_indices[0];
    const base_idx = frame.account_indices[1];
    const to_idx = frame.account_indices[2];
    if (from_idx >= ctx.tx.accounts.len or base_idx >= ctx.tx.accounts.len or to_idx >= ctx.tx.accounts.len)
        return error.M9_System_AccountIndexOutOfBounds;
    const from = &ctx.tx.accounts[from_idx];
    const base = &ctx.tx.accounts[base_idx];
    const to = &ctx.tx.accounts[to_idx];

    // base must sign.
    if (!base.is_signer) return error.M9_System_MissingRequiredSignature;

    // derive address from base + seed + owner (NO PDA marker — see fix note above).
    try verifySeedAddress(&from.pubkey, &base.pubkey, from_seed, from_owner);

    // transfer_verified: from must carry no data, sufficient funds.
    if (!from.is_writable) return error.M9_System_AccountNotWritable;
    if (!to.is_writable) return error.M9_System_AccountNotWritable;
    if (from.data.len != 0) return error.M9_System_InvalidAccountData;
    if (lamports > from.lamports) return error.M9_System_InsufficientFunds;
    from.lamports = std.math.sub(u64, from.lamports, lamports) catch return error.M9_System_InsufficientFunds;
    to.lamports = std.math.add(u64, to.lamports, lamports) catch
        return error.M9_System_ResultWithNegativeLamports;
}

// ── Nonce state (de)serialization — mirror of native/nonce.zig ─────────────
// task#105 Tier-1 (2026-06-21). A module-cycle bridge to native/nonce.zig is
// impossible (production vex_bpf2 imports only vex_crypto; vex_svm imports
// vex_bpf2 — build.zig:225-234), so the minimal 80-byte Versions (de)serializer
// is mirrored here exactly as the WithSeed family was. Byte layout is locked by
// the differential KAT (kat_system_cpi_native_diff.zig e5/e6) against the
// canonical native/nonce.zig encode/decode.
//
// Wire format (80 bytes, all little-endian):
//   [0..4]   version_tag : u32   (0 = Legacy, 1 = Current)
//   [4..8]   state_tag   : u32   (0 = Uninitialized, 1 = Initialized)
//   if Initialized:
//     [8..40]   authority             : [32]u8
//     [40..72]  durable_nonce         : [32]u8
//     [72..80]  lamports_per_signature: u64
const NONCE_STATE_SERIALIZED_SIZE: usize = 80;
const NONCE_DURABLE_HASH_PREFIX = "DURABLE_NONCE";

const NonceVersion = enum(u32) { legacy = 0, current = 1, _ };
const NonceStateKind = enum(u32) { uninitialized = 0, initialized = 1, _ };

const NonceData = struct {
    authority: Pubkey32,
    durable_nonce: [32]u8,
    lamports_per_signature: u64,
};

const NonceInner = union(NonceStateKind) {
    uninitialized: void,
    initialized: NonceData,
};

const NonceVersions = struct {
    version: NonceVersion,
    inner: NonceInner,
};

/// Decode 80-byte nonce account data. Mirrors native/nonce.zig decodeNonceState.
fn decodeNonceState(data: []const u8) Error!NonceVersions {
    if (data.len < NONCE_STATE_SERIALIZED_SIZE) return error.M9_System_InvalidAccountData;
    const ver_tag = std.mem.readInt(u32, data[0..4], .little);
    const state_tag = std.mem.readInt(u32, data[4..8], .little);

    const inner: NonceInner = switch (@as(NonceStateKind, @enumFromInt(state_tag))) {
        .uninitialized => .uninitialized,
        .initialized => blk: {
            var nd = NonceData{
                .authority = undefined,
                .durable_nonce = undefined,
                .lamports_per_signature = std.mem.readInt(u64, data[72..80], .little),
            };
            @memcpy(&nd.authority, data[8..40]);
            @memcpy(&nd.durable_nonce, data[40..72]);
            break :blk .{ .initialized = nd };
        },
        _ => return error.M9_System_InvalidAccountData,
    };

    return switch (@as(NonceVersion, @enumFromInt(ver_tag))) {
        .legacy => .{ .version = .legacy, .inner = inner },
        .current => .{ .version = .current, .inner = inner },
        _ => error.M9_System_InvalidAccountData,
    };
}

/// Encode `vsv` into exactly 80 bytes (in place). Mirrors native/nonce.zig
/// encodeNonceState: the buffer is fully zeroed first so trailing/unused bytes
/// are deterministic (Agave bincode writes a fixed 80-byte record).
fn encodeNonceState(vsv: NonceVersions, out: []u8) Error!void {
    if (out.len < NONCE_STATE_SERIALIZED_SIZE) return error.M9_System_InvalidAccountData;
    @memset(out[0..NONCE_STATE_SERIALIZED_SIZE], 0);
    std.mem.writeInt(u32, out[0..4], @intFromEnum(vsv.version), .little);
    std.mem.writeInt(u32, out[4..8], @intFromEnum(std.meta.activeTag(vsv.inner)), .little);
    switch (vsv.inner) {
        .uninitialized => {},
        .initialized => |nd| {
            @memcpy(out[8..40], &nd.authority);
            @memcpy(out[40..72], &nd.durable_nonce);
            std.mem.writeInt(u64, out[72..80], nd.lamports_per_signature, .little);
        },
    }
}

/// SHA256("DURABLE_NONCE" || blockhash). Mirrors native/nonce.zig
/// durableNonceFromHash. Used by Upgrade to re-derive the durable nonce out of
/// the legacy chain-blockhash domain (Agave Versions::upgrade).
fn durableNonceFromHash(blockhash: *const [32]u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(NONCE_DURABLE_HASH_PREFIX);
    hasher.update(blockhash);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

// ── Handler: AuthorizeNonceAccount (variant 7) ─────────────────────────────
// Mirrors native/nonce.execAuthorizeNonce + Agave system_processor.rs:468-472
// (authorize_nonce_account) + solana-nonce Versions::authorize. Touches NO
// environment state — only the account's own 80 bytes + the signer set.
//
// Account layout: [0] nonce account (writable). The CURRENT authority must be
// a signer (anywhere in the instruction's account list); the NEW authority has
// NO signer requirement.
//
// Check order (consensus-critical — determines which inputs flip success→fail):
//   count(1) → writable → decode → uninitialized?fail → current-authority
//   signed? → write (PRESERVING the Legacy/Current version variant).
fn executeAuthorizeNonce(ctx: *InvokeContext, new_authority: Pubkey32) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 1) return error.M9_System_NotEnoughAccounts;
    const idx = frame.account_indices[0];
    if (idx >= ctx.tx.accounts.len) return error.M9_System_AccountIndexOutOfBounds;
    const acct = &ctx.tx.accounts[idx];

    // Agave authorize_nonce_account: !is_writable → InvalidArgument.
    if (!acct.is_writable) return error.M9_System_InvalidArgument;

    const vsv = try decodeNonceState(acct.data);
    switch (vsv.inner) {
        // Versions::authorize on Uninitialized → AuthorizeNonceError::Uninitialized
        // → InvalidAccountData (system_processor.rs:230-237).
        .uninitialized => return error.M9_System_InvalidAccountData,
        .initialized => |nd| {
            // signers.contains(&data.authority) — the current authority must
            // have signed somewhere in this instruction's account list.
            if (!frameSignerPresent(ctx, frame, &nd.authority))
                return error.M9_System_MissingRequiredSignature;

            // Versions::authorize replaces ONLY the authority and PRESERVES the
            // version variant (solana-nonce versions.rs:100-108 — "Preserve
            // Version variant since cannot change durable_nonce field here").
            // durable_nonce + lamports_per_signature are carried unchanged.
            const new_data = NonceData{
                .authority = new_authority,
                .durable_nonce = nd.durable_nonce,
                .lamports_per_signature = nd.lamports_per_signature,
            };
            const new_vsv = NonceVersions{
                .version = vsv.version, // legacy stays legacy, current stays current
                .inner = .{ .initialized = new_data },
            };
            try encodeNonceState(new_vsv, acct.data);
        },
    }
}

// ── Handler: UpgradeNonceAccount (variant 12) ──────────────────────────────
// Mirrors native/nonce.execUpgradeNonce + Agave system_processor.rs:473-493
// (the UpgradeNonceAccount arm) + solana-nonce Versions::upgrade. Touches NO
// environment state — re-derives the durable nonce from the account's OWN
// stored legacy value. NO signer is required.
//
// Account layout: [0] nonce account (writable, System-owned).
//
// Check order (consensus-critical):
//   count(1) → owner==System (PROCESSOR check, BEFORE writable) → writable →
//   decode → Current?fail / Legacy+Uninitialized?fail → Legacy+Initialized:
//   durable_nonce = SHA256("DURABLE_NONCE" || old_durable_nonce), flip to
//   Current → write.
fn executeUpgradeNonce(ctx: *InvokeContext) Error!void {
    const frame = ctx.currentFrame() orelse return error.M9_System_NoActiveFrame;
    if (frame.account_indices.len < 1) return error.M9_System_NotEnoughAccounts;
    const idx = frame.account_indices[0];
    if (idx >= ctx.tx.accounts.len) return error.M9_System_AccountIndexOutOfBounds;
    const acct = &ctx.tx.accounts[idx];

    // Agave system_processor.rs:476-478 — owner must be the System program.
    // This is checked in the PROCESSOR, BEFORE the writable check (and is NOT
    // present in the inner Versions::upgrade), so it must run first here.
    if (!std.mem.eql(u8, &acct.owner, &SYSTEM_PROGRAM_ID))
        return error.M9_System_InvalidAccountOwner;

    // Agave system_processor.rs:479-481 — !is_writable → InvalidArgument.
    if (!acct.is_writable) return error.M9_System_InvalidArgument;

    const vsv = try decodeNonceState(acct.data);
    // Versions::upgrade() returns None for Current (already upgraded) AND for
    // Legacy+Uninitialized; the processor maps None → InvalidArgument.
    switch (vsv.version) {
        .current => return error.M9_System_InvalidArgument,
        .legacy => switch (vsv.inner) {
            .uninitialized => return error.M9_System_InvalidArgument,
            .initialized => |nd| {
                // versions.rs upgrade: data.durable_nonce =
                //   DurableNonce::from_blockhash(&data.blockhash()); flip Legacy→Current.
                var new_nd = nd;
                new_nd.durable_nonce = durableNonceFromHash(&nd.durable_nonce);
                const new_vsv = NonceVersions{
                    .version = .current,
                    .inner = .{ .initialized = new_nd },
                };
                try encodeNonceState(new_vsv, acct.data);
            },
        },
        _ => return error.M9_System_InvalidAccountData,
    }
}

pub fn selfTest() bool {
    return COMPUTE_UNITS == 150;
}

// ── Tests ─────────────────────────────────────────────────────────────────

const Harness = @import("test_harness.zig").Harness;
const mod = @import("mod.zig");

test "M9 system: decode Transfer" {
    const t = std.testing;
    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 2, .little);
    std.mem.writeInt(u64, data[4..12], 1234, .little);
    const ix = try decode(&data);
    try t.expectEqual(@as(u64, 1234), ix.transfer.lamports);
}

test "M9 system: decode Assign" {
    const t = std.testing;
    var data: [4 + 32]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 1, .little);
    @memset(data[4..36], 0xab);
    const ix = try decode(&data);
    try t.expectEqual(@as(u8, 0xab), ix.assign.owner[0]);
}

test "M9 system: decode rejects truncated tag" {
    const t = std.testing;
    try t.expectError(error.M9_System_InvalidInstructionData, decode(&[_]u8{ 1, 2, 3 }));
}

test "M9 system: decode rejects unknown tag" {
    const t = std.testing;
    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 99, .little);
    @memset(data[4..], 0);
    try t.expectError(error.M9_System_UnknownInstructionTag, decode(&data));
}

test "M9 system: Transfer happy path debits + credits" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 100, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = true },
        .{ .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = false },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();

    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 2, .little);
    std.mem.writeInt(u64, data[4..12], 30, .little);
    try execute(h.ctx, &data);
    try t.expectEqual(@as(u64, 70), h.accounts[0].lamports);
    try t.expectEqual(@as(u64, 30), h.accounts[1].lamports);
}

test "M9 system: Transfer rejects unsigned source" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 100, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = false },
        .{ .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = false },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();

    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 2, .little);
    std.mem.writeInt(u64, data[4..12], 30, .little);
    try t.expectError(error.M9_System_MissingRequiredSignature, execute(h.ctx, &data));
}

test "M9 system: Transfer rejects insufficient funds" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 5, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = true },
        .{ .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = false },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();

    var data: [12]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 2, .little);
    std.mem.writeInt(u64, data[4..12], 30, .little);
    try t.expectError(error.M9_System_InsufficientFunds, execute(h.ctx, &data));
}

test "M9 system: Assign happy path" {
    const t = std.testing;
    var new_owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    new_owner[0] = 0xab;
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 1, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = true },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{0});
    defer h.popFrame();

    var data: [4 + 32]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 1, .little);
    @memcpy(data[4..36], &new_owner);
    try execute(h.ctx, &data);
    try t.expectEqual(@as(u8, 0xab), h.accounts[0].owner[0]);
}

test "M9 system: Allocate happy path GROWS a fresh (data_len=0) account" {
    const t = std.testing;
    // Canonical Agave allocate(): a FRESH (data.len==0), system-owned, signed
    // account is grown to `space`, zero-filled. (A non-empty account would
    // canonically reject with AccountAlreadyInUse — see the next test.)
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 1, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = true },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{0});
    defer h.popFrame();

    var data: [4 + 8]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 8, .little);
    std.mem.writeInt(u64, data[4..12], 64, .little);
    try execute(h.ctx, &data);
    try t.expectEqual(@as(usize, 64), h.ctx.tx.accounts[0].data.len);
    for (h.ctx.tx.accounts[0].data) |b| try t.expectEqual(@as(u8, 0), b);
    // Test harness uses gpa; free the arena-style resize buffer.
    h.ctx.allocator.free(h.ctx.tx.accounts[0].data);
}

test "M9 system: Allocate REJECTS a non-empty account (AccountAlreadyInUse)" {
    const t = std.testing;
    // Canonical guard restored by task#15 FIX 2: an account that already holds
    // data must reject (Agave system_processor.rs allocate():93).
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 1, .data_len = 100, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = true },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{0});
    defer h.popFrame();

    var data: [4 + 8]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 8, .little);
    std.mem.writeInt(u64, data[4..12], 200, .little);
    try t.expectError(error.M9_System_AccountAlreadyInUse, execute(h.ctx, &data));
}

test "carrier #14: Allocate GROWS a fresh (data_len=0) prefunded PDA — was rejected (real vector @414706899)" {
    // Real shape: Metaplex CreateMetadataV3 CPIs System Allocate(space=679)
    // on a fresh metadata PDA (DRrD…ASz) that is data_len=0 but PREFUNDED
    // (lamports>0, signed via invoke_signed seeds → is_signer=true).
    // Pre-fix executeAllocate did `if (data.len != space) return error`
    // → 0 != 679 → InvalidAccountDataLength → M7_BuiltinFailed → the
    // Metaplex program M4_RunFailed → Vexor failed a tx the cluster ran.
    // This KAT FAILS on pre-fix code and PASSES after the self-resize.
    const t = std.testing;
    var h = try Harness.init(t.allocator, 1_000, &.{
        // prefunded (lamports=15_616_720), fresh (data_len=0), system-owned, signed PDA
        .{ .lamports = 15_616_720, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = true },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{0});
    defer h.popFrame();

    const space: u64 = 679;
    var data: [4 + 8]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 8, .little); // Allocate discriminant
    std.mem.writeInt(u64, data[4..12], space, .little);
    try execute(h.ctx, &data); // pre-fix: error.M9_System_InvalidAccountDataLength
    // After fix: account grown to `space`, zero-filled.
    try t.expectEqual(@as(usize, space), h.ctx.tx.accounts[0].data.len);
    for (h.ctx.tx.accounts[0].data) |b| try t.expectEqual(@as(u8, 0), b);
    // Production frees this via the per-dispatch arena; the test harness uses
    // gpa, so free the resize buffer here to keep the leak-detector clean.
    h.ctx.allocator.free(h.ctx.tx.accounts[0].data);
}

test "M9 system: CreateAccount (tag=0) transfers, allocates, assigns" {
    // CreateAccount is HANDLED on the CPI path (executeCreateAccount) — the old
    // stale test asserting tag=0 → VariantPending was removed (the variant has
    // been implemented since r75-bug-class-b). from(0) funds + signs, to(1) is
    // a fresh signed PDA; result: transfer N + data grown to space + owner set.
    const t = std.testing;
    var new_owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    new_owner[0] = 0x7e;
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 1_000_000, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = true },
        .{ .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = true },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();

    const lamports: u64 = 500_000;
    const space: u64 = 64;
    var data: [4 + 8 + 8 + 32]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 0, .little);
    std.mem.writeInt(u64, data[4..12], lamports, .little);
    std.mem.writeInt(u64, data[12..20], space, .little);
    @memcpy(data[20..52], &new_owner);
    try execute(h.ctx, &data);
    try t.expectEqual(@as(u64, 500_000), h.ctx.tx.accounts[0].lamports);
    try t.expectEqual(@as(u64, 500_000), h.ctx.tx.accounts[1].lamports);
    try t.expectEqual(@as(usize, space), h.ctx.tx.accounts[1].data.len);
    try t.expectEqual(@as(u8, 0x7e), h.ctx.tx.accounts[1].owner[0]);
    // Free the arena-style resize buffer (test harness uses gpa).
    h.ctx.allocator.free(h.ctx.tx.accounts[1].data);
}

// ── LANE-L-BACKPORT-AUDIT-2026-07-17 regression KATs ───────────────────────

// FIX #1: seed_len is attacker-controlled and unbounded by the real (tiny)
// body.len; plain `+` in the bounds-check guard trapped as an unrecoverable
// ReleaseSafe panic (process abort) instead of a catchable decode error.
// One regression test per with-seed variant (tags 3/9/10/11).
test "M9 system: decode saturates seed_len near u64::MAX instead of trapping (CreateAccountWithSeed)" {
    const t = std.testing;
    var data: [4 + 32 + 8]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 3, .little);
    @memset(data[4..36], 0);
    std.mem.writeInt(u64, data[36..44], std.math.maxInt(u64) - 5, .little); // seed_len
    try t.expectError(error.M9_System_InvalidInstructionData, decode(&data));
}

test "M9 system: decode saturates seed_len near u64::MAX instead of trapping (AllocateWithSeed)" {
    const t = std.testing;
    var data: [4 + 32 + 8]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 9, .little);
    @memset(data[4..36], 0);
    std.mem.writeInt(u64, data[36..44], std.math.maxInt(u64) - 5, .little); // seed_len
    try t.expectError(error.M9_System_InvalidInstructionData, decode(&data));
}

test "M9 system: decode saturates seed_len near u64::MAX instead of trapping (AssignWithSeed)" {
    const t = std.testing;
    var data: [4 + 32 + 8]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 10, .little);
    @memset(data[4..36], 0);
    std.mem.writeInt(u64, data[36..44], std.math.maxInt(u64) - 5, .little); // seed_len
    try t.expectError(error.M9_System_InvalidInstructionData, decode(&data));
}

test "M9 system: decode saturates seed_len near u64::MAX instead of trapping (TransferWithSeed)" {
    const t = std.testing;
    var data: [4 + 8 + 8]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 11, .little);
    std.mem.writeInt(u64, data[4..12], 0, .little); // lamports
    std.mem.writeInt(u64, data[12..20], std.math.maxInt(u64) - 5, .little); // seed_len
    try t.expectError(error.M9_System_InvalidInstructionData, decode(&data));
}

// FIX #3: TransferWithSeed's address derivation must be SHA256(base||seed||
// owner) with NO PDA marker, matching create_with_seed and the other 3
// with-seed variants (verifySeedAddress). A real Agave-issued
// TransferWithSeed's `from` pubkey is derived this way; the pre-fix handler
// appended "ProgramDerivedAddress" and so rejected every genuine one.
test "M9 system: TransferWithSeed derives address WITHOUT PDA marker (matches create_with_seed)" {
    const t = std.testing;
    var base_pk: Pubkey32 = std.mem.zeroes(Pubkey32);
    base_pk[0] = 0x11;
    const seed = "vault";
    var from_owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    from_owner[0] = 0x22;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&base_pk);
    hasher.update(seed);
    hasher.update(&from_owner);
    var derived: Pubkey32 = undefined;
    hasher.final(&derived);

    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .pubkey = derived, .lamports = 100, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = false },
        .{ .pubkey = base_pk, .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = false, .is_signer = true },
        .{ .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = false },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();

    var data: [4 + 8 + 8 + 5 + 32]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 11, .little);
    std.mem.writeInt(u64, data[4..12], 30, .little); // lamports
    std.mem.writeInt(u64, data[12..20], @as(u64, seed.len), .little);
    @memcpy(data[20..25], seed);
    @memcpy(data[25..57], &from_owner);
    try execute(h.ctx, &data);
    try t.expectEqual(@as(u64, 70), h.ctx.tx.accounts[0].lamports);
    try t.expectEqual(@as(u64, 30), h.ctx.tx.accounts[2].lamports);
}

test "M9 system: TransferWithSeed REJECTS the old PDA-marker-included derivation (regression guard)" {
    const t = std.testing;
    var base_pk: Pubkey32 = std.mem.zeroes(Pubkey32);
    base_pk[0] = 0x11;
    const seed = "vault";
    var from_owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    from_owner[0] = 0x22;

    // The WRONG (pre-fix) derivation this handler used to require.
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&base_pk);
    hasher.update(seed);
    hasher.update(&from_owner);
    hasher.update("ProgramDerivedAddress");
    var wrong_derived: Pubkey32 = undefined;
    hasher.final(&wrong_derived);

    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .pubkey = wrong_derived, .lamports = 100, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = false },
        .{ .pubkey = base_pk, .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = false, .is_signer = true },
        .{ .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = true, .is_signer = false },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1, 2 });
    defer h.popFrame();

    var data: [4 + 8 + 8 + 5 + 32]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 11, .little);
    std.mem.writeInt(u64, data[4..12], 30, .little);
    std.mem.writeInt(u64, data[12..20], @as(u64, seed.len), .little);
    @memcpy(data[20..25], seed);
    @memcpy(data[25..57], &from_owner);
    try t.expectError(error.M9_System_AddressWithSeedMismatch, execute(h.ctx, &data));
}

// FIX #4: executeAssign must call the set_owner()-equivalent 3-precondition
// guard (owned-by-System, writable, zero-data). A writable, signed account
// that is NOT owned by System must be rejected (ModifiedProgramId), not
// silently reassigned.
test "M9 system: Assign REJECTS reassigning an account not owned by System (ModifiedProgramId)" {
    const t = std.testing;
    var foreign_owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    foreign_owner[0] = 0x99;
    var new_owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    new_owner[0] = 0xab;
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 1, .data_len = 0, .owner = foreign_owner, .is_writable = true, .is_signer = true },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{0});
    defer h.popFrame();

    var data: [4 + 32]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 1, .little);
    @memcpy(data[4..36], &new_owner);
    try t.expectError(error.M9_System_ModifiedProgramId, execute(h.ctx, &data));
    // Must NOT have mutated the owner.
    try t.expectEqual(foreign_owner, h.ctx.tx.accounts[0].owner);
}

// FIX #5: executeAssignWithSeed's writable check must run AFTER the no-op
// check (Agave order), not before — a non-writable account already owned by
// new_owner is a legitimate no-op success on Agave, not AccountNotWritable.
// Also: a foreign-owned account must reject with ModifiedProgramId (same gap
// as #4), not silently reassign.
test "M9 system: AssignWithSeed no-op succeeds even when account is non-writable (check-order fix)" {
    const t = std.testing;
    var base_pk: Pubkey32 = std.mem.zeroes(Pubkey32);
    base_pk[0] = 0x33;
    const seed = "vault2";
    var owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    owner[0] = 0x44;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&base_pk);
    hasher.update(seed);
    hasher.update(&owner);
    var derived: Pubkey32 = undefined;
    hasher.final(&derived);

    // Account already owned by `owner` (the target) AND non-writable: real
    // Agave's assign_with_seed() hits the no-op branch before ever touching
    // writability, so this must succeed as a no-op.
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .pubkey = derived, .lamports = 1, .data_len = 0, .owner = owner, .is_writable = false, .is_signer = false },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{0});
    defer h.popFrame();

    var data: [4 + 32 + 8 + 6 + 32]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 10, .little);
    @memcpy(data[4..36], &base_pk);
    std.mem.writeInt(u64, data[36..44], @as(u64, seed.len), .little);
    @memcpy(data[44..50], seed);
    @memcpy(data[50..82], &owner);
    try execute(h.ctx, &data); // must NOT error
    try t.expectEqual(owner, h.ctx.tx.accounts[0].owner);
}

test "M9 system: AssignWithSeed REJECTS reassigning an account not owned by System (ModifiedProgramId)" {
    const t = std.testing;
    var base_pk: Pubkey32 = std.mem.zeroes(Pubkey32);
    base_pk[0] = 0x55;
    const seed = "vault3";
    var foreign_owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    foreign_owner[0] = 0x66;
    var new_owner: Pubkey32 = std.mem.zeroes(Pubkey32);
    new_owner[0] = 0x77;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&base_pk);
    hasher.update(seed);
    hasher.update(&new_owner);
    var derived: Pubkey32 = undefined;
    hasher.final(&derived);

    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .pubkey = derived, .lamports = 1, .data_len = 0, .owner = foreign_owner, .is_writable = true, .is_signer = false },
        .{ .pubkey = base_pk, .lamports = 0, .data_len = 0, .owner = SYSTEM_PROGRAM_ID, .is_writable = false, .is_signer = true },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();

    var data: [4 + 32 + 8 + 6 + 32]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 10, .little);
    @memcpy(data[4..36], &base_pk);
    std.mem.writeInt(u64, data[36..44], @as(u64, seed.len), .little);
    @memcpy(data[44..50], seed);
    @memcpy(data[50..82], &new_owner);
    try t.expectError(error.M9_System_ModifiedProgramId, execute(h.ctx, &data));
    try t.expectEqual(foreign_owner, h.ctx.tx.accounts[0].owner);
}
