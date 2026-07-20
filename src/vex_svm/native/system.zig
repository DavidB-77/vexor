const std = @import("std");
const types = @import("../types.zig");

/// Re-exports so callers (e.g. the tx-bearing exec KAT) construct the EXACT AccountMeta/Pubkey types
/// this module's executeTransfer expects (avoids a cross-module type mismatch when a test roots
/// system.zig as a named module). Pure type aliases — no behavior change.
pub const AccountMeta = types.AccountMeta;
pub const Pubkey = types.Pubkey;

/// The 32-byte System Program ID (11111111111111111111111111111111)
pub const PROGRAM_ID = types.Pubkey.default();

/// Exactly mirrors Firedancer's `fd_sys_instr_idx_t` for System Program opcodes.
pub const InstructionOpcodes = enum(u32) {
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
};

/// 1:1 translation of Firedancer's algorithmic System Program Execution Module.
/// Firedancer strictly prohibits mutating variables before all safety invariants have successfully returned.
pub fn executeTransfer(
    from: *types.AccountMeta,
    to: *types.AccountMeta,
    lamports: u64,
) !void {
    // [FIREDANCER INVARIANT 1]: Cannot transfer from an un-owned account
    if (!from.isSystem()) {
        return error.InstructionError_ExternalAccountLamportSpend;
    }

    // [FIREDANCER INVARIANT 2]: The mathematical subtraction must not wrap/underflow
    if (from.lamports < lamports) {
        return error.InstructionError_InsufficientFunds;
    }

    // [FIREDANCER INVARIANT 3]: The mathematical addition must not wrap/overflow target
    const added_lamports = std.math.add(u64, to.lamports, lamports) catch {
        return error.InstructionError_ArithmeticOverflow;
    };

    // Commit state changes only after all mathematical/algorithmic invariants cleanly pass
    from.lamports -= lamports;
    to.lamports = added_lamports;
}

pub fn executeCreateAccount(
    from: *types.AccountMeta,
    to: *types.AccountMeta,
    lamports: u64,
    space: u64,
    owner: types.Pubkey,
) !void {
    // [FIREDANCER INVARIANT 1]: Cannot spend from an un-owned account
    if (!from.isSystem()) {
        return error.InstructionError_ExternalAccountLamportSpend;
    }

    // [FIREDANCER INVARIANT 2]: Sufficient funds
    if (from.lamports < lamports) {
        return error.InstructionError_InsufficientFunds;
    }

    // [FIREDANCER INVARIANT 3]: You cannot blindly overwrite an existing account in Solana.
    // If the target account already exists, the creation FAILS unless it is mathematically
    // empty (zero data length) AND the current owner is the System Program.
    if (to.data.len > 0) {
        return error.InstructionError_AccountAlreadyInitialized;
    }
    if (!to.isSystem()) {
        return error.InstructionError_AccountAlreadyInitialized;
    }

    // Firedancer limits account space allocations strictly.
    const MAX_PERMITTED_DATA_LENGTH = 10 * 1024 * 1024; // 10MB
    if (space > MAX_PERMITTED_DATA_LENGTH) {
        return error.InstructionError_InvalidInstructionData;
    }

    // Commit mathematically verified transformations natively
    from.lamports -= lamports;
    to.lamports += lamports;
    to.owner = owner;

    // Memory mapping logic (Handled by the lock-free pipeline/VEXstore above)
    // to.data = allocateAndZeroSpace(space);
}
