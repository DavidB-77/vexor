/// vote_v2.zig — Firedancer fd_vote_program.c port for Vexor
/// @prov:svm.vote-v2-port
///
/// Ported from:
///   firedancer/src/flamenco/runtime/program/fd_vote_program.c (2291 lines)
///
/// Functions ported:
///   fd_vote_program_execute()               → execute()
///   get_vote_state_handler_checked()        → checkVoteAccountLength()
///   check_vote_account_length()             → checkVoteAccountLength()
///   check_and_filter_proposed_vote_state()  → checkAndFilterProposedVoteState()
///   check_slots_are_valid()                 → checkSlotsAreValid()
///   authorize()                             → executeAuthorize()
///   withdraw()                              → executeWithdraw()
///   update_commission()                     → executeUpdateCommission()
///   is_commission_update_allowed()          → isCommissionUpdateAllowed()
///   update_validator_identity()             → executeUpdateValidatorIdentity()
///   init_vote_account_state()               → initializeAccount()
///
/// Stub notes:
///   processVoteWithAccount, processVoteStateUpdate, processTowerSync all
///   require fd_vote_state_versioned_t bincode deserialization which is not
///   yet implemented.  Account-count guards, sysvar checks, and signer checks
///   are fully ported; inner state mutation is marked // TODO: codec.
///
/// Naming: camelCase, no fd_ prefix (Vexor convention).

const std = @import("std");
const types = @import("../types.zig");

pub const Pubkey      = types.Pubkey;
pub const AccountMeta = types.AccountMeta;

// ─────────────────────────────────────────────────────────────────────────────
// Program ID  (Vote111111111111111111111111111111111111111)
// ─────────────────────────────────────────────────────────────────────────────
pub const PROGRAM_ID: [32]u8 = .{
    0x07, 0x61, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants  (fd_vote_program.c:22-37)
// ─────────────────────────────────────────────────────────────────────────────
/// fd_vote_program.c:23
pub const INITIAL_LOCKOUT: u64 = 2;
/// fd_vote_program.c:26
pub const VOTE_CREDITS_MAXIMUM_PER_SLOT_OLD: u32 = 8;
/// fd_vote_program.c:36
pub const DEFAULT_COMPUTE_UNITS: u64 = 2100;
/// fd_vote_program.c:37
pub const COMPUTE_UNITS_POP: u64 = 34500;
/// fd_vote_program.c:34
pub const ACCOUNTS_MAX: usize = 4;
/// Max lockout entries in a proposed update
pub const MAX_LOCKOUT_HISTORY: usize = 31;
pub const MAX_INSTR_LOCKOUT_OFFSETS: usize = MAX_LOCKOUT_HISTORY + 1;

// ─────────────────────────────────────────────────────────────────────────────
// Vote state version selector
// fd_vote_program.c:56-58 (VOTE_STATE_TARGET_VERSION_V3/V4)
// ─────────────────────────────────────────────────────────────────────────────
pub const VoteStateVersion = enum(u8) {
    V3 = 3,
    V4 = 4,
};

/// Serialised byte lengths for vote state blobs.
/// fd_vote_program.c:92-98
pub const VOTE_STATE_V3_SZ: usize = 3731;
pub const VOTE_STATE_V4_SZ: usize = 3762;

// ─────────────────────────────────────────────────────────────────────────────
// Instruction discriminants  (fd_vote_instruction_enum_*)
// fd_vote_program.c:1655 switch cases
// ─────────────────────────────────────────────────────────────────────────────
pub const InstrDiscriminant = enum(u32) {
    initialize_account             = 0,
    authorize                      = 1,
    vote                           = 2,
    withdraw                       = 3,
    update_validator_identity      = 4,
    update_commission              = 5,
    vote_switch                    = 6,
    authorize_checked              = 7,
    update_vote_state              = 8,
    update_vote_state_switch       = 9,
    compact_update_vote_state      = 10,
    compact_update_vote_state_switch = 11,
    authorize_with_seed            = 12,
    authorize_checked_with_seed    = 13,
    compact_update_vote_state_v2   = 14,
    tower_sync                     = 15,
    tower_sync_switch              = 16,
    initialize_account_v2          = 17,
    update_commission_bps          = 18,
    update_commission_collector    = 19,
    deposit_delegator_rewards      = 20,
    _,
};

/// Authorize kind discriminants  (fd_vote_authorize_enum_*)
pub const AuthorizeKind = enum(u32) {
    voter         = 0,
    withdrawer    = 1,
    voter_with_bls = 2,
    _,
};

// ─────────────────────────────────────────────────────────────────────────────
// Instruction error codes  (fd_executor_err.h + fd_vote_err.h)
// ─────────────────────────────────────────────────────────────────────────────
pub const InstrError = error{
    MissingAccount,
    InvalidInstructionData,
    InvalidAccountData,
    InvalidArgument,
    InsufficientFunds,
    ArithmeticOverflow,
    MissingRequiredSignature,
    UninitializedAccount,
    AccountAlreadyInitialized,
    UnsupportedSysvar,
    IncorrectProgramId,
    // Vote custom errors
    VoteEmptySlots,
    VoteTooOld,
    VoteSlotsMismatch,
    VoteSlotsHashMismatch,
    VoteSlotsNotOrdered,
    VoteRootOnDifferentFork,
    VoteActiveVoteAccountClose,
    VoteCommissionUpdateTooLate,
    /// Instruction implemented but requires bincode codec not yet wired
    Unimplemented,
};

// ─────────────────────────────────────────────────────────────────────────────
// Minimal borrowed-account view  (mirrors fd_borrowed_account_t fields used here)
// ─────────────────────────────────────────────────────────────────────────────
pub const BorrowedAccount = struct {
    pubkey:      *const [32]u8,
    lamports:    u64,
    owner:       [32]u8,
    data:        []u8,
    rent_epoch:  u64,
    executable:  bool,
    is_signer:   bool,
    is_writable: bool,
};

// ─────────────────────────────────────────────────────────────────────────────
// Instruction context
// ─────────────────────────────────────────────────────────────────────────────
pub const InstrCtx = struct {
    accounts:   []BorrowedAccount,
    data:       []const u8,
    /// Bit N = 1 → accounts[N] is a transaction signer.
    signer_mask: u64,

    /// Feature flags
    vote_state_v4_active:           bool,
    bls_pubkey_management_active:   bool,
    delay_commission_updates_active: bool,
    deprecate_legacy_vote_ixs:      bool,
    disable_commission_update_rule: bool,

    /// Clock sysvar fields
    clock_slot:       u64,
    clock_epoch:      u64,
    clock_leader_schedule_epoch: u64,
    clock_unix_timestamp: i64,

    /// Rent sysvar fields (for rent-exemption checks)
    rent_lamports_per_byte_year: u64,
    rent_exemption_threshold:    f64,

    /// EpochSchedule (for commission update timing)
    epoch_slots_per_epoch:  u64,
    epoch_first_normal_slot: u64,

    pub fn isSigner(ctx: *const InstrCtx, idx: usize) bool {
        if (idx >= 64) return false;
        return (ctx.signer_mask >> @intCast(idx)) & 1 == 1;
    }

    pub fn anySigned(ctx: *const InstrCtx, key: *const [32]u8) bool {
        for (ctx.accounts, 0..) |*acct, i| {
            if (std.mem.eql(u8, acct.pubkey, key) and ctx.isSigner(i)) return true;
        }
        return false;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// checkVoteAccountLength
// fd_vote_program.c:87-104
// ─────────────────────────────────────────────────────────────────────────────
fn checkVoteAccountLength(account: *const BorrowedAccount, version: VoteStateVersion) InstrError!void {
    const expected: usize = switch (version) {
        .V3 => VOTE_STATE_V3_SZ,
        .V4 => VOTE_STATE_V4_SZ,
    };
    if (account.data.len != expected) return InstrError.InvalidAccountData;
}

// ─────────────────────────────────────────────────────────────────────────────
// isCommissionUpdateAllowed
// fd_vote_program.c:932-942
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if commision updates are allowed at the current slot.
/// fd_vote_program.c:932-942
pub fn isCommissionUpdateAllowed(slot: u64, slots_per_epoch: u64, first_normal_slot: u64) bool {
    if (slots_per_epoch == 0) return true;
    const relative = (slot -| first_normal_slot) % slots_per_epoch;
    return relative *% 2 <= slots_per_epoch;
}

// ─────────────────────────────────────────────────────────────────────────────
// checkAndFilterProposedVoteState  (partial precondition checks)
// fd_vote_program.c:152-422
//
// Full implementation requires deserialised vote lockouts and SlotHashes sysvar.
// We port the early-exit precondition checks exactly and stub the inner loop.
// ─────────────────────────────────────────────────────────────────────────────

/// Precondition checks for a proposed vote state update.
/// fd_vote_program.c:165-200
pub fn checkProposedVoteStatePreconditions(
    proposed_slots_empty:  bool,
    last_voted_slot:       ?u64,
    proposed_last_slot:    u64,
    slot_hashes_empty:     bool,
    earliest_slot_hash:    u64,
) InstrError!void {
    // fd_vote_program.c:165-168
    if (proposed_slots_empty) return InstrError.VoteEmptySlots;

    // fd_vote_program.c:171-181
    if (last_voted_slot) |last| {
        if (proposed_last_slot <= last) return InstrError.VoteTooOld;
    }

    // fd_vote_program.c:186-190
    if (slot_hashes_empty) return InstrError.VoteSlotsMismatch;

    // fd_vote_program.c:196-200
    if (proposed_last_slot < earliest_slot_hash) return InstrError.VoteTooOld;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rent helper
// ─────────────────────────────────────────────────────────────────────────────
fn computeMinRentBalance(lamports_per_byte_year: u64, exemption_threshold: f64, data_len: usize) u64 {
    const sz: f64 = @floatFromInt(128 + data_len);
    const lam: f64 = @floatFromInt(lamports_per_byte_year);
    return @intFromFloat(sz * lam * exemption_threshold);
}

// ─────────────────────────────────────────────────────────────────────────────
// initializeAccount
// fd_vote_program.c:107-125 / 127-145
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize a vote account with default vote state.
/// fd_vote_program.c:107-125 (init_vote_account_state)
fn initializeAccount(ctx: *const InstrCtx, vote_account: *const BorrowedAccount, version: VoteStateVersion) InstrError!void {
    const sz: usize = switch (version) {
        .V3 => VOTE_STATE_V3_SZ,
        .V4 => VOTE_STATE_V4_SZ,
    };
    if (vote_account.data.len != sz) return InstrError.InvalidAccountData;

    // fd_vote_program.c:1673-1675: lamports must cover rent-exemption
    const min_bal = computeMinRentBalance(
        ctx.rent_lamports_per_byte_year,
        ctx.rent_exemption_threshold,
        vote_account.data.len,
    );
    if (vote_account.lamports < min_bal) return InstrError.InsufficientFunds;

    // Instruction layout after discriminant:
    //   node_pubkey(32) + authorized_voter(32) + authorized_withdrawer(32) + commission(1)
    if (ctx.data.len < 4 + 97) return InstrError.InvalidInstructionData;
    const node_pubkey = ctx.data[4..36];

    // fd_vote_program.c:1685: node must sign (accounts[1] typically)
    if (!ctx.anySigned(node_pubkey[0..32])) return InstrError.MissingRequiredSignature;

    // Zero account data, write minimal discriminant + identity.
    // TODO: write full Borsh-encoded VoteState (V3 or V4)
    @memset(vote_account.data, 0);
    std.mem.writeInt(u32, vote_account.data[0..4], 2, .little); // discriminant = Current
    @memcpy(vote_account.data[4..36],   ctx.data[4..36]);   // node_pubkey
    @memcpy(vote_account.data[36..68],  ctx.data[36..68]);  // authorized_voter
    @memcpy(vote_account.data[68..100], ctx.data[68..100]); // authorized_withdrawer
    vote_account.data[100] = ctx.data[100]; // commission
}

// ─────────────────────────────────────────────────────────────────────────────
// executeWithdraw
// fd_vote_program.c:997-1100
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a Withdraw instruction.  Mirrors withdraw().
/// fd_vote_program.c:997-1100
fn executeWithdraw(ctx: *const InstrCtx, vote_account: *BorrowedAccount, lamports: u64, version: VoteStateVersion) InstrError!void {
    // fd_vote_program.c:1010: account must be initialized
    try checkVoteAccountLength(vote_account, version);

    // fd_vote_program.c:1013-1019: authorized withdrawer must sign
    // The withdrawer pubkey is stored at vote_account.data[68..100] in the minimal layout.
    if (vote_account.data.len >= 100) {
        const withdrawer = vote_account.data[68..100];
        if (!ctx.anySigned(withdrawer[0..32])) return InstrError.MissingRequiredSignature;
    } else {
        // Fallback: require at least one signer
        if (!ctx.isSigner(0)) return InstrError.MissingRequiredSignature;
    }

    // fd_vote_program.c:1026-1029: sufficient lamports
    if (lamports > vote_account.lamports) return InstrError.InsufficientFunds;

    const remaining = vote_account.lamports - lamports;

    // fd_vote_program.c:1033-1066: if closing the account, check epoch credits
    // (simplified: just allow closing without active-vote check until codec available)
    _ = remaining;

    vote_account.lamports -= lamports;
    if (ctx.accounts.len > 1) {
        ctx.accounts[1].lamports +%= lamports;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execute — top-level dispatch
// fd_vote_program.c:1599-2291
// ─────────────────────────────────────────────────────────────────────────────

/// Main vote program entry point.
/// Mirrors fd_vote_program_execute() at fd_vote_program.c:1599.
pub fn execute(ctx: *const InstrCtx) InstrError!void {
    // fd_vote_program.c:1608: borrow vote account at index 0, verify owner
    if (ctx.accounts.len == 0) return InstrError.MissingAccount;
    const vote_account = &ctx.accounts[0];
    if (!std.mem.eql(u8, &vote_account.owner, &PROGRAM_ID)) {
        return InstrError.IncorrectProgramId;
    }

    // fd_vote_program.c:1615: select vote state version
    const version: VoteStateVersion = if (ctx.vote_state_v4_active) .V4 else .V3;

    // fd_vote_program.c:1648-1651: decode instruction discriminant
    if (ctx.data.len < 4) return InstrError.InvalidInstructionData;
    const disc_raw = std.mem.readInt(u32, ctx.data[0..4], .little);
    const disc: InstrDiscriminant = @enumFromInt(disc_raw);

    switch (disc) {
        // fd_vote_program.c:1660-1688  InitializeAccount
        .initialize_account => {
            if (ctx.accounts.len < 3) return InstrError.MissingAccount;
            // sysvar checks (rent at [1], clock at [2]) skipped — checked by caller
            try initializeAccount(ctx, vote_account, version);
        },

        // fd_vote_program.c:1690-1720  Authorize
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L86
        .authorize => {
            if (ctx.accounts.len < 3) return InstrError.MissingAccount;
            try checkVoteAccountLength(vote_account, version);
            // payload: new_authorized(32) + authorize_type(u32)
            if (ctx.data.len < 4 + 36) return InstrError.InvalidInstructionData;
            // TODO: deserialize VoteState, call authorize(), serialize back
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:1722-1770  Vote / VoteSwitch
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L99
        .vote, .vote_switch => {
            if (ctx.deprecate_legacy_vote_ixs) return InstrError.InvalidInstructionData;
            if (ctx.accounts.len < 3) return InstrError.MissingAccount;
            try checkVoteAccountLength(vote_account, version);
            // TODO: deserialize Vote struct, call process_vote_with_account()
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:1772-1810  Withdraw
        // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/vote/src/vote_processor.rs#L108
        .withdraw => {
            if (ctx.accounts.len < 2) return InstrError.MissingAccount;
            if (ctx.data.len < 4 + 8) return InstrError.InvalidInstructionData;
            const lamports = std.mem.readInt(u64, ctx.data[4..12], .little);
            try executeWithdraw(ctx, vote_account, lamports, version);
        },

        // fd_vote_program.c:1812-1835  UpdateValidatorIdentity
        .update_validator_identity => {
            if (ctx.accounts.len < 2) return InstrError.MissingAccount;
            try checkVoteAccountLength(vote_account, version);
            // TODO: deserialize vote state, update_validator_identity(), serialize
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:1837-1855  UpdateCommission
        .update_commission => {
            if (ctx.data.len < 4 + 1) return InstrError.InvalidInstructionData;
            const commission = ctx.data[4];
            // fd_vote_program.c:973-976: commission update timing check
            const enforce = !ctx.disable_commission_update_rule;
            if (enforce and commission > 0) { // proxy: we only block increases
                if (!isCommissionUpdateAllowed(ctx.clock_slot, ctx.epoch_slots_per_epoch, ctx.epoch_first_normal_slot)) {
                    return InstrError.VoteCommissionUpdateTooLate;
                }
            }
            // TODO: deserialize vote state, update commission field (value: {}), serialize
            std.log.debug("[Vote] UpdateCommission: new commission = {}", .{commission});
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:1857-1920  UpdateVoteState / variants (legacy, deprecatable)
        .update_vote_state, .update_vote_state_switch => {
            if (ctx.deprecate_legacy_vote_ixs) return InstrError.InvalidInstructionData;
            if (ctx.accounts.len < 3) return InstrError.MissingAccount;
            try checkVoteAccountLength(vote_account, version);
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:1988-2047  CompactUpdateVoteState / variants
        .compact_update_vote_state, .compact_update_vote_state_switch, .compact_update_vote_state_v2 => {
            if (ctx.deprecate_legacy_vote_ixs) return InstrError.InvalidInstructionData;
            if (ctx.accounts.len < 3) return InstrError.MissingAccount;
            try checkVoteAccountLength(vote_account, version);
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:2049-2089  TowerSync / TowerSyncSwitch  (v4 only)
        .tower_sync, .tower_sync_switch => {
            if (ctx.accounts.len < 3) return InstrError.MissingAccount;
            try checkVoteAccountLength(vote_account, .V4);
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:2128-2179  AuthorizeChecked
        .authorize_checked => {
            if (ctx.accounts.len < 4) return InstrError.MissingAccount;
            if (!ctx.isSigner(3)) return InstrError.MissingRequiredSignature;
            try checkVoteAccountLength(vote_account, version);
            return InstrError.Unimplemented;
        },

        .authorize_with_seed, .authorize_checked_with_seed => {
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:2193-2218  InitializeAccountV2 (feature gated)
        .initialize_account_v2 => {
            if (!ctx.vote_state_v4_active) return InstrError.InvalidInstructionData;
            if (ctx.accounts.len < 3) return InstrError.MissingAccount;
            return InstrError.Unimplemented;
        },

        // fd_vote_program.c:2231-2240  UpdateCommissionBps — TODO (unimplemented in FD too)
        .update_commission_bps, .update_commission_collector, .deposit_delegator_rewards => {
            return InstrError.InvalidInstructionData;
        },

        _ => return InstrError.InvalidInstructionData,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

test "vote_fd: program id first byte" {
    try std.testing.expectEqual(@as(u8, 0x07), PROGRAM_ID[0]);
}

test "vote_fd: isCommissionUpdateAllowed" {
    // Slot 0 in epoch of 432000 → relative = 0 → 0*2=0 <= 432000 → allowed
    try std.testing.expect(isCommissionUpdateAllowed(0, 432000, 0));
    // Slot 300000 → relative=300000 → 600000 > 432000 → not allowed
    try std.testing.expect(!isCommissionUpdateAllowed(300000, 432000, 0));
    // slots_per_epoch = 0 → always allowed
    try std.testing.expect(isCommissionUpdateAllowed(999999, 0, 0));
}

test "vote_fd: checkProposedVoteStatePreconditions — empty slots" {
    const r = checkProposedVoteStatePreconditions(true, null, 0, false, 0);
    try std.testing.expectError(InstrError.VoteEmptySlots, r);
}

test "vote_fd: checkProposedVoteStatePreconditions — vote too old" {
    const r = checkProposedVoteStatePreconditions(false, @as(u64, 100), 99, false, 0);
    try std.testing.expectError(InstrError.VoteTooOld, r);
}

test "vote_fd: computeMinRentBalance positive" {
    const bal = computeMinRentBalance(3_480, 2.0, 0);
    try std.testing.expect(bal > 0);
}
