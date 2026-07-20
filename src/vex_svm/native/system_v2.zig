/// system_v2.zig — Firedancer fd_system_program.c port for Vexor
/// @prov:svm.system-v2-port
///
/// Ported from:
///   firedancer/src/flamenco/runtime/program/fd_system_program.c (841 lines)
///
/// Functions ported:
///   fd_system_program_execute()                → execute()
///   fd_system_program_exec_create_account()    → execCreateAccount()
///   fd_system_program_exec_assign()            → execAssign()
///   fd_system_program_exec_transfer()          → execTransfer()
///   fd_system_program_exec_create_account_with_seed() → execCreateAccountWithSeed()
///   fd_system_program_exec_allocate()          → execAllocate()
///   fd_system_program_exec_allocate_with_seed() → execAllocateWithSeed()
///   fd_system_program_exec_assign_with_seed()  → execAssignWithSeed()
///   fd_system_program_exec_transfer_with_seed() → execTransferWithSeed()
///   fd_system_program_exec_advance_nonce_account() → execAdvanceNonce()     [stub]
///   fd_system_program_exec_withdraw_nonce_account() → execWithdrawNonce()   [stub]
///   fd_system_program_exec_initialize_nonce_account() → execInitializeNonce() [stub]
///   fd_system_program_exec_authorize_nonce_account() → execAuthorizeNonce() [stub]
///   fd_system_program_exec_upgrade_nonce_account() → execUpgradeNonce()     [stub]
///   fd_get_system_account_kind()               → getSystemAccountKind()
///
/// Nonce instructions (advance/withdraw/initialize/authorize/upgrade) are structurally
/// ported with correct account-count and signer checks. Internal nonce-state
/// deserialization depends on a bincode decoder not yet present in this module, so those
/// paths return error.Unimplemented and are marked // TODO stubs.
///
/// Naming: camelCase, no fd_ prefix (Vexor convention).
const std = @import("std");
const types = @import("../types.zig");
const nonce = @import("nonce.zig");

pub const Pubkey = types.Pubkey;
pub const AccountMeta = types.AccountMeta;

// fd_system_program.c:14
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024; // 10 MiB

// ─────────────────────────────────────────────────────────────────────────────
// System Program ID  (11111111111111111111111111111111)
// ─────────────────────────────────────────────────────────────────────────────
pub const PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;

// ─────────────────────────────────────────────────────────────────────────────
// Custom error codes  (fd_system_program.h equivalents)
// ─────────────────────────────────────────────────────────────────────────────

/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE = 0
pub const ERR_ACCT_ALREADY_IN_USE: u32 = 0;
/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_RESULT_WITH_NEGATIVE_LAMPORTS = 1
pub const ERR_RESULT_WITH_NEGATIVE_LAMPORTS: u32 = 1;
/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_INVALID_PROGRAM_ID = 2
pub const ERR_INVALID_PROGRAM_ID: u32 = 2;
/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_INVALID_ACCT_DATA_LEN = 3
pub const ERR_INVALID_ACCT_DATA_LEN: u32 = 3;
/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_MAX_SEED_LEN_EXCEEDED = 4
pub const ERR_MAX_SEED_LEN_EXCEEDED: u32 = 4;
/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH = 5
pub const ERR_ADDR_WITH_SEED_MISMATCH: u32 = 5;
/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES = 6
pub const ERR_NONCE_NO_RECENT_BLOCKHASHES: u32 = 6;
/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED = 7
pub const ERR_NONCE_BLOCKHASH_NOT_EXPIRED: u32 = 7;
/// fd_system_program.h: FD_SYSTEM_PROGRAM_ERR_NONCE_UNEXPECTED_BLOCKHASH_VALUE = 8
pub const ERR_NONCE_UNEXPECTED_BLOCKHASH_VALUE: u32 = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Instruction error codes  (mirrors fd_executor_err.h)
// ─────────────────────────────────────────────────────────────────────────────
pub const InstrError = error{
    MissingAccount,
    InvalidInstructionData,
    InvalidArgument,
    InvalidAccountData,
    InsufficientFunds,
    ArithmeticOverflow,
    MissingRequiredSignature,
    AccountAlreadyInitialized,
    UninitializedAccount,
    AccountNotRentExempt,
    IllegalOwner,
    InvalidRealloc,
    ExternalAccountLamportSpend,
    ExternalAccountDataModified,
    IncorrectProgramId,
    IncorrectAuthority,
    CustomError,
    /// Agave InstructionError::InvalidAccountOwner — UpgradeNonceAccount on a
    /// non-system-owned account (system_processor.rs:476-478).
    InvalidAccountOwner,
    Unimplemented,
};

// ─────────────────────────────────────────────────────────────────────────────
// System Account Kind  (fd_system_program.h)
// ─────────────────────────────────────────────────────────────────────────────
pub const SystemAccountKind = enum(u8) {
    Unknown = 0,
    System = 1,
    Nonce = 2,
};

// ─────────────────────────────────────────────────────────────────────────────
// Instruction discriminants  (fd_system_program_instruction_enum_*)
// fd_system_program.c:721-793
// ─────────────────────────────────────────────────────────────────────────────
pub const Discriminant = enum(u32) {
    CreateAccount = 0,
    Assign = 1,
    Transfer = 2,
    CreateAccountWithSeed = 3,
    AdvanceNonceAccount = 4,
    WithdrawNonceAccount = 5,
    InitializeNonceAccount = 6,
    AuthorizeNonceAccount = 7,
    Allocate = 8,
    AllocateWithSeed = 9,
    AssignWithSeed = 10,
    TransferWithSeed = 11,
    UpgradeNonceAccount = 12,
    CreateAccountAllowPrefund = 13,
    _,
};

// ─────────────────────────────────────────────────────────────────────────────
// Simplified instruction context  (replaces fd_exec_instr_ctx_t)
//
// In a full Vexor integration, InstrCtx will carry the transaction context,
// account table, signer bitmask, and sysvar cache.  Here we carry only what
// the system program needs for account-level mutations.
// ─────────────────────────────────────────────────────────────────────────────

/// Bank-derived environment for the durable-nonce instructions
/// (2026-06-10, carrier @414201776). Mirrors Agave's
/// `invoke_context.environment_config`:
///   - `recent_blockhash` = the executing bank's last_blockhash — i.e. the
///     PARENT bank's final PoH hash as registered in the blockhash queue
///     (environment_config.blockhash). NOT the in-progress poh of the
///     current bank, NOT the transaction's recent_blockhash.
///   - `lamports_per_signature` = environment_config.blockhash_lamports_per_signature
///     (the fee rate paired with that queue entry; 5000 on testnet).
pub const NonceEnv = struct {
    recent_blockhash: [32]u8,
    lamports_per_signature: u64,
    /// True when the RecentBlockhashes sysvar / blockhash queue is empty
    /// (Agave: recent_blockhashes.is_empty() → NonceNoRecentBlockhashes).
    recent_blockhashes_empty: bool,
    /// Rent.minimum_balance(data_len) for the Withdraw/Initialize rent checks.
    rent_minimum_balance_fn: ?*const fn (data_len: u64) u64,
};

/// Minimal stand-in for fd_exec_instr_ctx_t fields consumed by system program.
/// Callers must populate accounts (indexed 0..n) and signers bitset.
pub const InstrCtx = struct {
    /// Slice of accounts referenced by this instruction (in order).
    accounts: []AccountMeta,
    /// Bitmask of which account indices are signers.
    signer_mask: u64,
    /// Scratch allocator for seed-derived address computation.
    allocator: std.mem.Allocator,
    /// Bitmask of which account indices are writable (instruction-level).
    /// Default all-writable preserves the historical behavior for callers
    /// that don't populate it; nonce ops consult this (Agave checks
    /// account.is_writable() FIRST in every nonce handler).
    writable_mask: u64 = std.math.maxInt(u64),
    /// Durable-nonce environment. `null` = caller did not wire bank state;
    /// nonce instructions then fail loudly with Unimplemented (pre-wiring
    /// behavior) instead of advancing with a garbage blockhash.
    nonce_env: ?NonceEnv = null,

    /// True if account at `idx` is a signer.
    pub fn isSigner(self: *const InstrCtx, idx: usize) bool {
        if (idx >= 64) return false;
        return (self.signer_mask >> @intCast(idx)) & 1 != 0;
    }

    /// True if account at `idx` is writable (instruction-level).
    pub fn isWritable(self: *const InstrCtx, idx: usize) bool {
        if (idx >= 64) return false;
        return (self.writable_mask >> @intCast(idx)) & 1 != 0;
    }

    pub fn getAccount(self: *const InstrCtx, idx: usize) InstrError!*AccountMeta {
        if (idx >= self.accounts.len) return InstrError.MissingAccount;
        return &self.accounts[idx];
    }

    /// Check that pubkey at idx signed the transaction.
    /// Mirrors fd_instr_acc_is_signer_idx.
    pub fn requireSigner(self: *const InstrCtx, idx: usize) InstrError!void {
        if (!self.isSigner(idx)) return InstrError.MissingRequiredSignature;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// verify_seed_address
// fd_system_program.c:33-64
// ─────────────────────────────────────────────────────────────────────────────

/// Re-derive a PDA from (base, seed, owner) and compare with expected.
/// Mirrors fd_pubkey_create_with_seed + memcmp check.
/// Full SHA256-based derivation uses:
///   SHA256( base || seed || owner || "ProgramDerivedAddress" )
fn verifySeedAddress(
    expected: *const [32]u8,
    base: *const [32]u8,
    seed: []const u8,
    owner: *const [32]u8,
) InstrError!void {
    // carrier #12 (2026-06-11 @414674115): createAccountWithSeed address is
    //   SHA256(base || seed || owner)
    // with NO "ProgramDerivedAddress" marker. That 21-byte suffix belongs
    // ONLY to create_program_address / find_program_address (PDAs) — NOT to
    // create_with_seed. Canonical refs verified BYTE-EXACT:
    //   Agave  solana_pubkey::Pubkey::create_with_seed = hashv(&[base, seed, owner])
    //   FD     fd_pubkey_create_with_seed (fd_pubkey_utils.c): sha256(base|seed|owner)
    // Pre-fix Vexor appended the marker → wrong derived address → every
    // createAccountWithSeed (stake/nonce/derived accounts) hit
    // ERR_ADDR_WITH_SEED_MISMATCH → Vexor rolled back a tx the cluster
    // executed → accounts_lt_hash divergence (equal sig counts).
    // seed must be at most 32 bytes (MAX_SEED_LEN).
    if (seed.len > 32) return InstrError.InvalidArgument; // MaxSeedLengthExceeded

    // IllegalOwner guard (FD fd_pubkey_utils.c: memcmp(owner+11, marker, 21)):
    // owner must NOT end with the PDA marker, else create_with_seed could
    // collide into PDA space. owner[11..32] is the trailing 21 bytes.
    const PDA_MARKER = "ProgramDerivedAddress"; // 21 bytes
    if (std.mem.eql(u8, owner[11..32], PDA_MARKER)) {
        return InstrError.CustomError; // ERR_ILLEGAL_OWNER
    }

    // Canonical: SHA256(base || seed || owner) — no marker.
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(base);
    hasher.update(seed);
    hasher.update(owner);
    var derived: [32]u8 = undefined;
    hasher.final(&derived);

    if (!std.mem.eql(u8, &derived, expected)) {
        return InstrError.CustomError; // ERR_ADDR_WITH_SEED_MISMATCH
    }
}

test "carrier #12: create_with_seed address = SHA256(base|seed|owner), NO PDA marker (real vector @414674115)" {
    // Golden on-chain vector — testnet slot 414674115, sig 4FTaLpBR…,
    // createAccountWithSeed: base 6fzD95xN…, seed "stake:6",
    // owner Stake11…, newAccount EUzo4zwP… (cluster ACCEPTED this tx).
    // Pre-fix Vexor appended "ProgramDerivedAddress" → derived FNnDF6rn… →
    // ERR_ADDR_WITH_SEED_MISMATCH → rejected a tx the cluster executed.
    const base = [_]u8{
        0x55, 0xc1, 0xf9, 0x1f, 0x4d, 0x47, 0x4b, 0x77, 0xa5, 0xf3, 0x4b, 0x6c, 0x6d, 0x9a, 0x4a, 0xee,
        0xc6, 0x95, 0x32, 0x46, 0x35, 0xc0, 0x5f, 0x8e, 0x91, 0xd9, 0xe4, 0x46, 0x86, 0xb3, 0xae, 0xc1,
    };
    const stake_owner = [_]u8{
        0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a, 0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
        0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b, 0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
    };
    // expected = SHA256(base || "stake:6" || stake_owner)
    var expected: [32]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&base);
    h.update("stake:6");
    h.update(&stake_owner);
    h.final(&expected);

    // Canonical derivation MUST verify against that expected address.
    try verifySeedAddress(&expected, &base, "stake:6", &stake_owner);

    // The OLD (with-marker) derivation must NOT equal expected — proves the
    // pre-fix code rejected this tx (regression guard for the bug).
    var with_marker: [32]u8 = undefined;
    var h2 = std.crypto.hash.sha2.Sha256.init(.{});
    h2.update(&base);
    h2.update("stake:6");
    h2.update(&stake_owner);
    h2.update("ProgramDerivedAddress");
    h2.final(&with_marker);
    try std.testing.expect(!std.mem.eql(u8, &with_marker, &expected));
    try std.testing.expectError(error.CustomError, verifySeedAddress(&with_marker, &base, "stake:6", &stake_owner));

    // IllegalOwner guard: owner ending in the PDA marker is rejected.
    var pda_owner = [_]u8{0} ** 32;
    @memcpy(pda_owner[11..32], "ProgramDerivedAddress");
    try std.testing.expectError(error.CustomError, verifySeedAddress(&expected, &base, "stake:6", &pda_owner));
}

// ─────────────────────────────────────────────────────────────────────────────
// fd_system_program_transfer_verified
// fd_system_program.c:72-120
// ─────────────────────────────────────────────────────────────────────────────

/// Inner transfer that validates the 'from' account has zero data length.
/// Matches system_processor::transfer_verified.
fn transferVerified(
    ctx: *const InstrCtx,
    amount: u64,
    from_idx: usize,
    to_idx: usize,
) InstrError!void {
    const from = try ctx.getAccount(from_idx);
    const to = try ctx.getAccount(to_idx);

    // fd_system_program.c:85-88 — from must carry no data
    if (from.data.len != 0) return InstrError.InvalidArgument;

    // fd_system_program.c:92-97 — sufficient funds
    if (amount > from.lamports) return InstrError.InsufficientFunds; // ERR_RESULT_WITH_NEGATIVE_LAMPORTS

    // r75-bug-class-d-self-transfer (2026-05-06): canonical no-op for self-transfer.
    // Solana's BorrowedAccount pattern shares mutable state when the same pubkey
    // is referenced multiple times in an instruction; the same memory is debited
    // and credited, netting zero. Vexor's executeSystemInstruction caller builds
    // SEPARATE AccountMeta copies per account_indices entry, so a self-transfer
    // (account_indices=[X, X]) produces two independent metas: one debited by N,
    // one credited by N. The caller then commits both via last-write-wins,
    // erroneously gaining N lamports. Detect explicitly and emulate the canonical
    // no-op. Empirically observed on Bp2K vote-fee-payer self-transfers (each
    // priority tx has ix[1] = Transfer Bp2K→Bp2K of N lamports), which gave
    // a net +N drift per tx, accumulating to +422 by slot 300, +802 by slot 500.
    if (std.mem.eql(u8, &from.pubkey.data, &to.pubkey.data)) return;

    // fd_system_program.c:101-103
    from.lamports -= amount;

    // fd_system_program.c:116-117
    to.lamports = std.math.add(u64, to.lamports, amount) catch
        return InstrError.ArithmeticOverflow;
}

// ─────────────────────────────────────────────────────────────────────────────
// fd_system_program_transfer
// fd_system_program.c:127-149
// ─────────────────────────────────────────────────────────────────────────────

/// Transfer that additionally requires 'from' to have signed.
fn transfer(
    ctx: *const InstrCtx,
    amount: u64,
    from_idx: usize,
    to_idx: usize,
) InstrError!void {
    // fd_system_program.c:135-143
    try ctx.requireSigner(from_idx);
    try transferVerified(ctx, amount, from_idx, to_idx);
}

// ─────────────────────────────────────────────────────────────────────────────
// fd_system_program_allocate
// fd_system_program.c:157-210
// ─────────────────────────────────────────────────────────────────────────────

/// Resize account data to `space` bytes.  Account must be unallocated and
/// owned by the system program.  Authority must sign.
fn allocate(
    ctx: *const InstrCtx,
    account: *AccountMeta,
    space: u64,
    authority_key: *const [32]u8,
) InstrError!void {
    // fd_system_program.c:168-176 — authority must sign
    var any_signed = false;
    for (0..ctx.accounts.len) |i| {
        if (std.mem.eql(u8, &ctx.accounts[i].pubkey.data, authority_key) and ctx.isSigner(i)) {
            any_signed = true;
            break;
        }
    }
    if (!any_signed) return InstrError.MissingRequiredSignature;

    // fd_system_program.c:180-190 — account must be empty and system-owned
    if (account.data.len != 0 or !std.mem.eql(u8, &account.owner.data, &PROGRAM_ID)) {
        return InstrError.CustomError; // ERR_ACCT_ALREADY_IN_USE
    }

    // fd_system_program.c:194-200 — space limit
    if (space > MAX_PERMITTED_DATA_LENGTH) {
        return InstrError.CustomError; // ERR_INVALID_ACCT_DATA_LEN
    }

    // fd_system_program.c:204-207 + Agave transaction_accounts.rs:101-107 +
    // fd_borrowed_account_set_data_length. Vexor: AccountMeta.data is a Zig
    // slice cloned from snapshot data via v2_dispatch.zig:306/325/540 (each
    // alloc.alloc(u8, s.data.len)). To grow, allocate new zeroed bytes and
    // free the prior (empty per the guard at line 276 — len==0).
    //
    // PR-5u (2026-05-19): pre-fix this was a no-op `std.log.debug` stub,
    // causing same-tx CreateAccount→Initialize* cascades (Token-2022, ATA,
    // Priority6w, and any program built on System.CreateAccount) to operate
    // on a length=0 buffer where cluster sees `space` bytes. Effect: Anchor
    // deserialize errors / wrong post-state bytes / cascade lthash divergence.
    //
    // space=0 is a legal Allocate (no-op); skip alloc to avoid 0-byte slice
    // owner-confusion. space>0 path mirrors cluster's resize-zero-init pattern.
    if (space > 0) {
        const new_data = ctx.allocator.alloc(u8, @intCast(space)) catch
            return InstrError.InvalidRealloc;
        @memset(new_data, 0);
        if (account.data.len > 0) ctx.allocator.free(account.data);
        account.data = new_data;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// fd_system_program_assign
// fd_system_program.c:218-243
// ─────────────────────────────────────────────────────────────────────────────

/// Assign owner of account.  No-op if already assigned to `owner`.
fn assign(
    ctx: *const InstrCtx,
    account: *AccountMeta,
    owner: *const [32]u8,
    authority_key: *const [32]u8,
) InstrError!void {
    // fd_system_program.c:227-228 — already assigned: no-op
    if (std.mem.eql(u8, &account.owner.data, owner)) return;

    // fd_system_program.c:232-240 — authority must sign
    var any_signed = false;
    for (0..ctx.accounts.len) |i| {
        if (std.mem.eql(u8, &ctx.accounts[i].pubkey.data, authority_key) and ctx.isSigner(i)) {
            any_signed = true;
            break;
        }
    }
    if (!any_signed) return InstrError.MissingRequiredSignature;

    @memcpy(&account.owner.data, owner);
}

// ─────────────────────────────────────────────────────────────────────────────
// fd_system_program_allocate_and_assign
// fd_system_program.c:250-263
// ─────────────────────────────────────────────────────────────────────────────

fn allocateAndAssign(
    ctx: *const InstrCtx,
    account: *AccountMeta,
    space: u64,
    owner: *const [32]u8,
    authority_key: *const [32]u8,
    authority_idx: usize,
) InstrError!void {
    _ = authority_idx;
    try allocate(ctx, account, space, authority_key);
    try assign(ctx, account, owner, authority_key);
}

// ─────────────────────────────────────────────────────────────────────────────
// fd_system_program_create_account
// fd_system_program.c:271-315
// ─────────────────────────────────────────────────────────────────────────────

/// Create a new account funded from `from_idx`.
/// Matches system_processor::create_account.
fn createAccount(
    ctx: *const InstrCtx,
    from_idx: usize,
    to_idx: usize,
    lamports: u64,
    space: u64,
    owner: *const [32]u8,
    authority_key: *const [32]u8,
) InstrError!void {
    const to = try ctx.getAccount(to_idx);

    // fd_system_program.c:292-301 — account must not already have lamports
    if (to.lamports != 0) {
        return InstrError.CustomError; // ERR_ACCT_ALREADY_IN_USE
    }

    // fd_system_program.c:305-308
    try allocateAndAssign(ctx, to, space, owner, authority_key, to_idx);

    // fd_system_program.c:314
    try transfer(ctx, lamports, from_idx, to_idx);
}

// ─────────────────────────────────────────────────────────────────────────────
// SIMD-0312 create_account_allow_prefund (Agave system_processor.rs:188-214)
// ─────────────────────────────────────────────────────────────────────────────
//
// Activated testnet epoch 954, slot 406,604,256.
// Difference from createAccount: the `to` account may already hold lamports
// (rent paid in whole or in part before creation), so the
// "to.lamports == 0 ⇒ AccountAlreadyInUse" check is dropped. When `from_idx`
// is null (the wire form uses lamports==0 for this case), no transfer fires.

fn createAccountAllowPrefund(
    ctx: *const InstrCtx,
    from_idx: ?usize,
    to_idx: usize,
    lamports: u64,
    space: u64,
    owner: *const [32]u8,
    authority_key: *const [32]u8,
) InstrError!void {
    const to = try ctx.getAccount(to_idx);
    try allocateAndAssign(ctx, to, space, owner, authority_key, to_idx);
    if (from_idx) |fi| {
        if (lamports > 0) {
            try transfer(ctx, lamports, fi, to_idx);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public execute entry-points
// ─────────────────────────────────────────────────────────────────────────────

// fd_system_program.c:350-378
pub fn execCreateAccount(
    ctx: *const InstrCtx,
    lamports: u64,
    space: u64,
    owner: *const [32]u8,
) InstrError!void {
    if (ctx.accounts.len < 2) return InstrError.MissingAccount;
    const to_key = &ctx.accounts[1].pubkey.data;
    try createAccount(ctx, 0, 1, lamports, space, owner, to_key);
}

// SIMD-0312 — Agave system_processor.rs:530-560
// Account layout differs from CreateAccount: `to` is ALWAYS at index 0;
// `from` is at index 1 only when lamports > 0.
pub fn execCreateAccountAllowPrefund(
    ctx: *const InstrCtx,
    lamports: u64,
    space: u64,
    owner: *const [32]u8,
) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount;
    const to_key = &ctx.accounts[0].pubkey.data;
    if (lamports > 0) {
        if (ctx.accounts.len < 2) return InstrError.MissingAccount;
        try createAccountAllowPrefund(ctx, 1, 0, lamports, space, owner, to_key);
    } else {
        try createAccountAllowPrefund(ctx, null, 0, 0, space, owner, to_key);
    }
}

// fd_system_program.c:420-445
pub fn execAssign(ctx: *const InstrCtx, owner: *const [32]u8) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount;
    const account = try ctx.getAccount(0);
    const authority_key = &account.pubkey.data;
    try assign(ctx, account, owner, authority_key);
}

// fd_system_program.c:452-463
pub fn execTransfer(ctx: *const InstrCtx, amount: u64) InstrError!void {
    if (ctx.accounts.len < 2) return InstrError.MissingAccount;
    try transfer(ctx, amount, 0, 1);
}

// fd_system_program.c:470-508
pub fn execCreateAccountWithSeed(
    ctx: *const InstrCtx,
    base: *const [32]u8,
    seed: []const u8,
    lamports: u64,
    space: u64,
    owner: *const [32]u8,
) InstrError!void {
    if (ctx.accounts.len < 2) return InstrError.MissingAccount;
    const to_key = &ctx.accounts[1].pubkey.data;
    // fd_system_program.c:484-492 — verify derived address
    try verifySeedAddress(to_key, base, seed, owner);
    try createAccount(ctx, 0, 1, lamports, space, owner, base);
}

// fd_system_program.c:515-540
pub fn execAllocate(ctx: *const InstrCtx, space: u64) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount;
    const account = try ctx.getAccount(0);
    const authority_key = &account.pubkey.data;
    try allocate(ctx, account, space, authority_key);
}

// fd_system_program.c:547-587
pub fn execAllocateWithSeed(
    ctx: *const InstrCtx,
    base: *const [32]u8,
    seed: []const u8,
    space: u64,
    owner: *const [32]u8,
) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount;
    const account = try ctx.getAccount(0);
    const account_key = &account.pubkey.data;
    // fd_system_program.c:563-570
    try verifySeedAddress(account_key, base, seed, owner);
    try allocateAndAssign(ctx, account, space, owner, base, 0);
}

// fd_system_program.c:594-628
pub fn execAssignWithSeed(
    ctx: *const InstrCtx,
    base: *const [32]u8,
    seed: []const u8,
    owner: *const [32]u8,
) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount;
    const account = try ctx.getAccount(0);
    const account_key = &account.pubkey.data;
    // fd_system_program.c:610-617
    try verifySeedAddress(account_key, base, seed, owner);
    try assign(ctx, account, owner, base);
}

// fd_system_program.c:634-701
pub fn execTransferWithSeed(
    ctx: *const InstrCtx,
    from_seed: []const u8,
    from_owner: *const [32]u8,
    lamports: u64,
) InstrError!void {
    // fd_system_program.c:640-641  accounts: from(0), from_base(1), to(2)
    if (ctx.accounts.len < 3) return InstrError.MissingAccount;

    const from_base_idx: usize = 1;
    // fd_system_program.c:651-660  base must sign
    try ctx.requireSigner(from_base_idx);

    const base_key = &ctx.accounts[from_base_idx].pubkey.data;
    const from_key = &ctx.accounts[0].pubkey.data;

    // fd_system_program.c:668-678  derive address from base+seed+owner
    var derived: [32]u8 = undefined;
    {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(base_key);
        hasher.update(from_seed);
        hasher.update(from_owner);
        hasher.update("ProgramDerivedAddress");
        hasher.final(&derived);
    }

    // fd_system_program.c:685-697  derived must match from account
    if (!std.mem.eql(u8, &derived, from_key)) {
        return InstrError.CustomError; // ERR_ADDR_WITH_SEED_MISMATCH
    }

    // fd_system_program.c:700
    try transferVerified(ctx, lamports, 0, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Nonce instructions — wired to the faithful Firedancer port in nonce.zig
// (2026-06-10, fix/wire-nonce-ops: PROVEN bank_hash carrier @414201776 —
// the previous Unimplemented stubs meant AdvanceNonceAccount never advanced
// the nonce; the error was swallowed upstream, the tx was treated as
// success, and STALE nonce bytes were committed → accounts_lt_hash
// divergence vs cluster.)
//
// Cross-checked against Agave 4.1.0-beta.3:
//   programs/system/src/system_processor.rs:410-493 (dispatch + sysvar checks)
//   programs/system/src/system_instruction.rs:25-249 (handlers)
//   solana-nonce-3.2.0 versions.rs (authorize/upgrade variant semantics)
// ─────────────────────────────────────────────────────────────────────────────

/// SysvarRecentB1ockHashes11111111111111111111
const SYSVAR_RECENT_BLOCKHASHES_ID: [32]u8 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
    0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
    0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
    0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
};

/// SysvarRent111111111111111111111111111111111
const SYSVAR_RENT_ID: [32]u8 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x5c, 0x51,
    0x21, 0x8c, 0xc9, 0x4c, 0x3d, 0x4a, 0xf1, 0x7f,
    0x58, 0xda, 0xee, 0x08, 0x9b, 0xa1, 0xfd, 0x44,
    0xe3, 0xdb, 0xd9, 0x8a, 0x00, 0x00, 0x00, 0x00,
};

/// Agave get_sysvar_with_account_check (sysvar id must sit at instruction
/// account `idx`): missing account → NotEnoughAccountKeys, wrong pubkey →
/// InvalidArgument (program-runtime sysvar_cache.rs check_sysvar_account).
fn checkSysvarAccount(ctx: *const InstrCtx, idx: usize, id: *const [32]u8) InstrError!void {
    if (idx >= ctx.accounts.len) return InstrError.MissingAccount;
    if (!std.mem.eql(u8, &ctx.accounts[idx].pubkey.data, id)) return InstrError.InvalidArgument;
}

/// Map nonce.zig's NonceError set onto system_v2's InstrError set.
/// NonceBlockhashNotExpired / NoRecentBlockhashes are SystemError custom
/// errors in Agave (instruction fails either way; failed instructions never
/// commit state, so the exact custom code does not enter bank_hash).
fn mapNonceError(err: nonce.NonceError) InstrError {
    return switch (err) {
        error.MissingAccount => InstrError.MissingAccount,
        error.MissingRequiredSignature => InstrError.MissingRequiredSignature,
        error.InvalidAccountData => InstrError.InvalidAccountData,
        error.InsufficientFunds => InstrError.InsufficientFunds,
        error.InvalidArgument => InstrError.InvalidArgument,
        error.NonceBlockhashNotExpired => InstrError.CustomError, // ERR_NONCE_BLOCKHASH_NOT_EXPIRED
        error.NoRecentBlockhashes => InstrError.CustomError, // ERR_NONCE_NO_RECENT_BLOCKHASHES
        error.AccountAlreadyInitialized => InstrError.AccountAlreadyInitialized,
        error.AccountDataTooSmall => InstrError.InvalidAccountData,
        error.ArithmeticOverflow => InstrError.ArithmeticOverflow,
        error.Unimplemented => InstrError.Unimplemented,
    };
}

/// Bridge state for one nonce-op invocation: nonce.zig BorrowedAccount views
/// over this module's AccountMeta slice. `data` slices ALIAS the AccountMeta
/// buffers (nonce state is always rewritten in place at 80 bytes — never
/// resized), so data mutations land directly; lamports are value-copied and
/// must be committed back on success.
const NonceBridge = struct {
    buf: [8]nonce.BorrowedAccount,
    n: usize,

    fn build(ctx: *const InstrCtx) NonceBridge {
        var self: NonceBridge = .{ .buf = undefined, .n = @min(ctx.accounts.len, 8) };
        for (0..self.n) |i| {
            const m = &ctx.accounts[i];
            self.buf[i] = .{
                .pubkey = m.pubkey.data,
                .lamports = m.lamports,
                .owner = m.owner.data,
                .data = m.data,
                .rent_epoch = m.rent_epoch,
                .executable = m.executable,
                .is_signer = ctx.isSigner(i),
                .is_writable = ctx.isWritable(i),
            };
        }
        return self;
    }

    fn nonceCtx(self: *NonceBridge, ctx: *const InstrCtx, env: NonceEnv) nonce.InstrCtx {
        return .{
            .accounts = self.buf[0..self.n],
            .signer_mask = ctx.signer_mask,
            .recent_blockhash = env.recent_blockhash,
            .lamports_per_signature = env.lamports_per_signature,
            .recent_blockhashes_empty = env.recent_blockhashes_empty,
            .rent_minimum_balance_fn = env.rent_minimum_balance_fn,
        };
    }

    /// Commit lamport changes back to the AccountMeta slice (data already
    /// aliased; owner is never changed by nonce ops).
    fn commit(self: *const NonceBridge, ctx: *const InstrCtx) void {
        for (0..self.n) |i| {
            ctx.accounts[i].lamports = self.buf[i].lamports;
        }
    }
};

/// Fetch the NonceEnv or fail loudly. A null env means the caller did not
/// wire bank state — the exact silent-stale-nonce condition that carried the
/// @414201776 bank_hash divergence. Never advance against a garbage hash.
fn requireNonceEnv(ctx: *const InstrCtx, comptime which: []const u8) InstrError!NonceEnv {
    return ctx.nonce_env orelse {
        std.log.warn("[NONCE] " ++ which ++ " reached with no NonceEnv (caller not wired) — failing instruction instead of committing stale nonce bytes", .{});
        return InstrError.Unimplemented;
    };
}

/// Env placeholder for AuthorizeNonceAccount / UpgradeNonceAccount, which
/// consume NO environment state in Agave (no blockhash, no fee rate, no
/// rent) — they must work even on callers that haven't wired NonceEnv.
const NONCE_ENV_UNUSED = NonceEnv{
    .recent_blockhash = [_]u8{0} ** 32,
    .lamports_per_signature = 0,
    .recent_blockhashes_empty = true,
    .rent_minimum_balance_fn = null,
};

/// AdvanceNonceAccount — Agave system_processor.rs:410-426.
/// Accounts: [0]=nonce(writable), [1]=RecentBlockhashes sysvar, authority
/// signs anywhere in the instruction account list.
pub fn execAdvanceNonce(ctx: *const InstrCtx) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount; // check_number_of_instruction_accounts(1)
    const env = try requireNonceEnv(ctx, "AdvanceNonceAccount");
    // get_sysvar_with_account_check::recent_blockhashes(idx=1)
    try checkSysvarAccount(ctx, 1, &SYSVAR_RECENT_BLOCKHASHES_ID);
    var bridge = NonceBridge.build(ctx);
    var nctx = bridge.nonceCtx(ctx, env);
    nonce.execAdvanceNonce(&nctx) catch |e| return mapNonceError(e);
    bridge.commit(ctx);
}

/// WithdrawNonceAccount(lamports) — Agave system_processor.rs:427-447.
/// Accounts: [0]=nonce(writable), [1]=dest(writable), [2]=RecentBlockhashes,
/// [3]=Rent.
pub fn execWithdrawNonce(ctx: *const InstrCtx, lamports: u64) InstrError!void {
    if (ctx.accounts.len < 2) return InstrError.MissingAccount; // check_number_of_instruction_accounts(2)
    const env = try requireNonceEnv(ctx, "WithdrawNonceAccount");
    try checkSysvarAccount(ctx, 2, &SYSVAR_RECENT_BLOCKHASHES_ID);
    try checkSysvarAccount(ctx, 3, &SYSVAR_RENT_ID);
    var bridge = NonceBridge.build(ctx);
    var nctx = bridge.nonceCtx(ctx, env);
    nonce.execWithdrawNonce(&nctx, lamports) catch |e| return mapNonceError(e);
    bridge.commit(ctx);
}

/// InitializeNonceAccount(authorized) — Agave system_processor.rs:448-467.
/// Accounts: [0]=nonce(writable), [1]=RecentBlockhashes, [2]=Rent.
pub fn execInitializeNonce(ctx: *const InstrCtx, authorized: *const [32]u8) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount; // check_number_of_instruction_accounts(1)
    const env = try requireNonceEnv(ctx, "InitializeNonceAccount");
    try checkSysvarAccount(ctx, 1, &SYSVAR_RECENT_BLOCKHASHES_ID);
    try checkSysvarAccount(ctx, 2, &SYSVAR_RENT_ID);
    var bridge = NonceBridge.build(ctx);
    var nctx = bridge.nonceCtx(ctx, env);
    nonce.execInitializeNonce(&nctx, authorized) catch |e| return mapNonceError(e);
    bridge.commit(ctx);
}

/// AuthorizeNonceAccount(new_authority) — Agave system_processor.rs:468-472.
/// Accounts: [0]=nonce(writable); current authority signs anywhere.
pub fn execAuthorizeNonce(ctx: *const InstrCtx, new_authority: *const [32]u8) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount;
    // Authorize reads/writes only account bytes — no environment needed
    // (Agave Versions::authorize takes signers + new authority only).
    const env = ctx.nonce_env orelse NONCE_ENV_UNUSED;
    var bridge = NonceBridge.build(ctx);
    var nctx = bridge.nonceCtx(ctx, env);
    nonce.execAuthorizeNonce(&nctx, new_authority) catch |e| return mapNonceError(e);
    bridge.commit(ctx);
}

/// UpgradeNonceAccount — Agave system_processor.rs:473-493.
/// Accounts: [0]=nonce(writable, system-owned).
pub fn execUpgradeNonce(ctx: *const InstrCtx) InstrError!void {
    if (ctx.accounts.len < 1) return InstrError.MissingAccount;
    // Upgrade re-derives from the stored legacy hash — no environment needed
    // (Agave Versions::upgrade reads only the account's own state).
    const env = ctx.nonce_env orelse NONCE_ENV_UNUSED;
    // Agave system_processor.rs:476-478 — owner must be the system program
    // (checked in the PROCESSOR, before the writable check).
    if (!std.mem.eql(u8, &ctx.accounts[0].owner.data, &PROGRAM_ID)) {
        return InstrError.InvalidAccountOwner;
    }
    var bridge = NonceBridge.build(ctx);
    var nctx = bridge.nonceCtx(ctx, env);
    nonce.execUpgradeNonce(&nctx) catch |e| return mapNonceError(e);
    bridge.commit(ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// fd_get_system_account_kind
// fd_system_program.c:804-841
// ─────────────────────────────────────────────────────────────────────────────

/// Classify an account as System, Nonce, or Unknown.
/// fd_system_program.c:804-841
pub fn getSystemAccountKind(account: *const AccountMeta) SystemAccountKind {
    // fd_system_program.c:806 — must be system-owned
    if (!std.mem.eql(u8, &account.owner.data, &PROGRAM_ID)) {
        return .Unknown;
    }
    // fd_system_program.c:811-813 — zero-length data = plain system account
    if (account.data.len == 0) {
        return .System;
    }
    // fd_system_program.c:816 — nonce accounts have a specific data length
    // nonce data length = 80 bytes
    const NONCE_DLEN: usize = 80;
    if (account.data.len != NONCE_DLEN) {
        return .Unknown;
    }
    // fd_system_program.c:821-841 — peek discriminant to confirm Initialized nonce
    // NonceStateVersions discriminant layout: u32 version_tag + u32 state_tag
    if (account.data.len < 8) return .Unknown;
    const state_tag = std.mem.readInt(u32, account.data[4..8], .little);
    // state 1 = Initialized, 0 = Uninitialized
    if (state_tag == 1) return .Nonce;
    return .Unknown;
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level dispatch
// fd_system_program.c:704-797
// ─────────────────────────────────────────────────────────────────────────────

/// Decode instruction data and dispatch to the appropriate handler.
/// Instruction data layout: [u32 discriminant][payload...]
/// Mirrors fd_system_program_execute().
pub fn execute(ctx: *const InstrCtx, instr_data: []const u8) InstrError!void {
    if (instr_data.len < 4) return InstrError.InvalidInstructionData;

    const disc_raw = std.mem.readInt(u32, instr_data[0..4], .little);
    const disc: Discriminant = @enumFromInt(disc_raw);
    const payload = instr_data[4..];

    switch (disc) {
        .CreateAccount => {
            // payload: lamports(u64) + space(u64) + owner(32)
            if (payload.len < 8 + 8 + 32) return InstrError.InvalidInstructionData;
            const lamports = std.mem.readInt(u64, payload[0..8], .little);
            const space = std.mem.readInt(u64, payload[8..16], .little);
            const owner = payload[16..48];
            try execCreateAccount(ctx, lamports, space, owner[0..32]);
        },
        .Assign => {
            // payload: owner(32)
            if (payload.len < 32) return InstrError.InvalidInstructionData;
            try execAssign(ctx, payload[0..32]);
        },
        .Transfer => {
            // payload: lamports(u64)
            if (payload.len < 8) return InstrError.InvalidInstructionData;
            const lamports = std.mem.readInt(u64, payload[0..8], .little);
            try execTransfer(ctx, lamports);
        },
        .CreateAccountWithSeed => {
            // payload: base(32) + seed_len(u64) + seed(...) + lamports(u64) + space(u64) + owner(32)
            if (payload.len < 32 + 8) return InstrError.InvalidInstructionData;
            const base: *const [32]u8 = payload[0..32];
            const seed_len = std.mem.readInt(u64, payload[32..40], .little);
            if (payload.len < 40 + seed_len + 8 + 8 + 32) return InstrError.InvalidInstructionData;
            const seed = payload[40 .. 40 + seed_len];
            const rest = payload[40 + seed_len ..];
            const lamports = std.mem.readInt(u64, rest[0..8], .little);
            const space = std.mem.readInt(u64, rest[8..16], .little);
            const owner = rest[16..48];
            try execCreateAccountWithSeed(ctx, base, seed, lamports, space, owner[0..32]);
        },
        .AdvanceNonceAccount => try execAdvanceNonce(ctx),
        .WithdrawNonceAccount => {
            if (payload.len < 8) return InstrError.InvalidInstructionData;
            const lamports = std.mem.readInt(u64, payload[0..8], .little);
            try execWithdrawNonce(ctx, lamports);
        },
        .InitializeNonceAccount => {
            if (payload.len < 32) return InstrError.InvalidInstructionData;
            try execInitializeNonce(ctx, payload[0..32]);
        },
        .AuthorizeNonceAccount => {
            if (payload.len < 32) return InstrError.InvalidInstructionData;
            try execAuthorizeNonce(ctx, payload[0..32]);
        },
        .Allocate => {
            if (payload.len < 8) return InstrError.InvalidInstructionData;
            const space = std.mem.readInt(u64, payload[0..8], .little);
            try execAllocate(ctx, space);
        },
        .AllocateWithSeed => {
            if (payload.len < 32 + 8) return InstrError.InvalidInstructionData;
            const base: *const [32]u8 = payload[0..32];
            const seed_len = std.mem.readInt(u64, payload[32..40], .little);
            if (payload.len < 40 + seed_len + 8 + 32) return InstrError.InvalidInstructionData;
            const seed = payload[40 .. 40 + seed_len];
            const rest = payload[40 + seed_len ..];
            const space = std.mem.readInt(u64, rest[0..8], .little);
            const owner = rest[8..40];
            try execAllocateWithSeed(ctx, base, seed, space, owner[0..32]);
        },
        .AssignWithSeed => {
            if (payload.len < 32 + 8) return InstrError.InvalidInstructionData;
            const base: *const [32]u8 = payload[0..32];
            const seed_len = std.mem.readInt(u64, payload[32..40], .little);
            if (payload.len < 40 + seed_len + 32) return InstrError.InvalidInstructionData;
            const seed = payload[40 .. 40 + seed_len];
            const owner = payload[40 + seed_len ..][0..32];
            try execAssignWithSeed(ctx, base, seed, owner);
        },
        .TransferWithSeed => {
            // payload: lamports(u64) + seed_len(u64) + seed(...) + from_owner(32)
            if (payload.len < 8 + 8) return InstrError.InvalidInstructionData;
            const lamports = std.mem.readInt(u64, payload[0..8], .little);
            const seed_len = std.mem.readInt(u64, payload[8..16], .little);
            if (payload.len < 16 + seed_len + 32) return InstrError.InvalidInstructionData;
            const seed = payload[16 .. 16 + seed_len];
            const from_owner = payload[16 + seed_len ..][0..32];
            try execTransferWithSeed(ctx, seed, from_owner, lamports);
        },
        .UpgradeNonceAccount => try execUpgradeNonce(ctx),
        .CreateAccountAllowPrefund => {
            // SIMD-0312 (active testnet ep 954, slot 406,604,256).
            // payload: lamports(u64) + space(u64) + owner(32) — same wire as CreateAccount
            if (payload.len < 8 + 8 + 32) return InstrError.InvalidInstructionData;
            const lamports = std.mem.readInt(u64, payload[0..8], .little);
            const space = std.mem.readInt(u64, payload[8..16], .little);
            const owner = payload[16..48];
            try execCreateAccountAllowPrefund(ctx, lamports, space, owner[0..32]);
        },
        else => return InstrError.InvalidInstructionData,
    }
}
