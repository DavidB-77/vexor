/// executor.zig — Firedancer fd_executor.c port for Vexor
///
/// Ported from:
///   firedancer-reference/fd_executor.c (1651 lines)
///
/// Functions ported:
///   fd_execute_instr()           → executeInstruction()
///   fd_instr_stack_push()        → instrStackPush()
///   fd_instr_stack_pop()         → instrStackPop()
///   fd_execute_txn()             → executeTransaction()
///   fd_executor_lookup_native_program() → lookupNativeProgram()
///   fd_executor_get_account_rent_state() → getAccountRentState()
///   fd_executor_rent_transition_allowed() → rentTransitionAllowed()
///   fd_executor_txn_check()      → transactionCheck()
///
/// Native program dispatch table (fd_executor.c:48-74):
///   Vote, System, ComputeBudget, ZkElGamal, BpfLoader1/2/Upgradeable, LoaderV4
///
/// Naming: camelCase, no fd_ prefix (Vexor convention).
const std = @import("std");
const vex_crypto = @import("vex_crypto");
const types = @import("types.zig");

pub const Hash = vex_crypto.Hash;
pub const Pubkey = types.Pubkey;

// ─────────────────────────────────────────────────────────────────────────────
// System Program IDs — mirrors fd_system_ids.h
// ─────────────────────────────────────────────────────────────────────────────

/// Vote Program  (Vote111111111111111111111111111111111111111)
const VOTE_PROG_ID: [32]u8 = .{
    0x07, 0x61, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/// System Program (11111111111111111111111111111111)
const SYS_PROG_ID: [32]u8 = [_]u8{0} ** 32;

/// Compute Budget Program (ComputeBudget111111111111111111111111111111)
const COMPUTE_BUDGET_PROG_ID: [32]u8 = .{
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32,
    0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b,
    0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00,
};

/// BPF Loader v1 (BPFLoader1111111111111111111111111111111111)
const BPF_LOADER_1_PROG_ID: [32]u8 = .{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x45,
    0x97, 0x13, 0x78, 0x44, 0x3a, 0x84, 0x61, 0xbd,
    0xa8, 0xb5, 0x18, 0x77, 0xd3, 0xc8, 0x3b, 0x5a,
    0xf1, 0x5d, 0x51, 0x41, 0x00, 0x00, 0x00, 0x00,
};

/// BPF Loader v2 (BPFLoader2111111111111111111111111111111111)
const BPF_LOADER_2_PROG_ID: [32]u8 = .{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x45,
    0x97, 0x13, 0x78, 0x44, 0x3a, 0x84, 0x61, 0xbd,
    0xa8, 0xb5, 0x18, 0x77, 0xd3, 0xc8, 0x3b, 0x5a,
    0xf1, 0x5d, 0x51, 0x42, 0x00, 0x00, 0x00, 0x00,
};

/// BPF Loader Upgradeable (BPFLoaderUpgradeab1e11111111111111111111111)
const BPF_UPGRADEABLE_PROG_ID: [32]u8 = .{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x45,
    0x97, 0x13, 0x78, 0x44, 0x3a, 0x84, 0x61, 0xbd,
    0xa8, 0xb5, 0x18, 0x77, 0xd3, 0xc8, 0x3b, 0x5a,
    0xf1, 0x5d, 0x51, 0x01, 0x00, 0x00, 0x00, 0x00,
};

/// Loader v4 (LoaderV411111111111111111111111111111111111111)
const LOADER_V4_PROG_ID: [32]u8 = .{
    0x03, 0x4f, 0x70, 0x82, 0x6d, 0xab, 0x9c, 0x31,
    0x86, 0xfe, 0x5b, 0x90, 0x76, 0xd2, 0x7c, 0x6e,
    0x46, 0x5a, 0x90, 0xcd, 0x8a, 0xa4, 0x74, 0xcf,
    0x38, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/// ZK ElGamal Proof Program (ZkE1Gama1Proof11111111111111111111111111111)
const ZK_ELGAMAL_PROG_ID: [32]u8 = .{
    0x08, 0x76, 0x54, 0xbc, 0x47, 0xae, 0xf4, 0x01,
    0x25, 0x01, 0x4c, 0x78, 0x60, 0x5b, 0x85, 0x5a,
    0xa0, 0x79, 0x68, 0x1c, 0x8a, 0xd9, 0xd8, 0x02,
    0xae, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/// Native Loader (NativeLoader1111111111111111111111111111111)
const NATIVE_LOADER_ID: [32]u8 = .{
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06,
    0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
    0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81,
    0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d,
};

/// Ed25519SigVerify111111111111111111111111111
/// fd_system_ids_pp.h:56 (ED25519_SV_PROG_ID)
const ED25519_PRECOMPILE_ID: [32]u8 = .{
    0x03, 0x7d, 0x46, 0xd6, 0x7c, 0x93, 0xfb, 0xbe,
    0x12, 0xf9, 0x42, 0x8f, 0x83, 0x8d, 0x40, 0xff,
    0x05, 0x70, 0x74, 0x49, 0x27, 0xf4, 0x8a, 0x64,
    0xfc, 0xca, 0x70, 0x44, 0x80, 0x00, 0x00, 0x00,
};

/// KeccakSecp256k11111111111111111111111111111
/// fd_system_ids_pp.h:58 (KECCAK_SECP_PROG_ID)
const SECP256K1_PRECOMPILE_ID: [32]u8 = .{
    0x04, 0xc6, 0xfc, 0x20, 0xf0, 0x50, 0xcc, 0xf0,
    0x55, 0x84, 0xd7, 0x21, 0x1c, 0x9f, 0x8c, 0xf5,
    0x9e, 0xc1, 0x47, 0x85, 0xbb, 0x16, 0x6a, 0x1e,
    0x28, 0x30, 0xe8, 0x12, 0x20, 0x00, 0x00, 0x00,
};

/// Secp256r1SigVerify1111111111111111111111111
/// fd_system_ids_pp.h:60 (SECP256R1_PROG_ID)
const SECP256R1_PRECOMPILE_ID: [32]u8 = .{
    0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5,
    0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9, 0x03,
    0x1c, 0x83, 0xe7, 0x5f, 0xdb, 0x79, 0x5d, 0x56,
    0x8e, 0x75, 0x47, 0x80, 0x20, 0x00, 0x00, 0x00,
};

// ─────────────────────────────────────────────────────────────────────────────
// Error codes — mirrors fd_executor_err.h / fd_runtime_err.h
// ─────────────────────────────────────────────────────────────────────────────

/// Instruction-level error codes.
/// Mirrors FD_EXECUTOR_INSTR_ERR_* (fd_executor.c:1549-1651).
pub const InstrError = enum(i32) {
    Success = 0,
    Fatal = -1,
    GenericError = 1,
    InvalidArg = 2,
    InvalidInstrData = 3,
    InvalidAccData = 4,
    AccDataTooSmall = 5,
    InsufficientFunds = 6,
    IncorrectProgramId = 7,
    MissingRequiredSignature = 8,
    AccAlreadyInitialized = 9,
    UninitializedAccount = 10,
    UnbalancedInstr = 11,
    ModifiedProgramId = 12,
    ExternalAccountLamportSpend = 13,
    ExternalDataModified = 14,
    ReadonlyLamportChange = 15,
    ReadonlyDataModified = 16,
    DuplicateAccountIdx = 17,
    ExecutableModified = 18,
    RentEpochModified = 19,
    NotEnoughAccKeys = 20,
    AccDataSizeChanged = 21,
    AccNotExecutable = 22,
    AccBorrowFailed = 23,
    AccBorrowOutstanding = 24,
    DuplicateAccountOutOfSync = 25,
    CustomError = 26,
    InvalidError = 27,
    ExecutableDataModified = 28,
    ExecutableLamportChange = 29,
    ExecutableAccountNotRentExempt = 30,
    UnsupportedProgramId = 31,
    CallDepth = 32,
    MissingAcc = 33,
    ReentrancyNotAllowed = 34,
    MaxSeedLengthExceeded = 35,
    InvalidSeeds = 36,
    InvalidRealloc = 37,
    ComputeBudgetExceeded = 38,
    PrivilegeEscalation = 39,
    ProgramEnvironmentSetupFailure = 40,
    ProgramFailedToComplete = 41,
    ProgramFailedToCompile = 42,
    AccImmutable = 43,
    IncorrectAuthority = 44,
    BorshIoError = 45,
    AccNotRentExempt = 46,
    InvalidAccOwner = 47,
    ArithmeticOverflow = 48,
    UnsupportedSysvar = 49,
    IllegalOwner = 50,
    MaxAccsDataAllocsExceeded = 51,
    MaxAccsExceeded = 52,
    MaxInsnTraceLensExceeded = 53,
    BuiltinsMustConsumeCUs = 54,
};

/// Transaction-level error codes.
/// Mirrors FD_RUNTIME_TXN_ERR_* (fd_executor.c / fd_runtime_err.h).
pub const TxnError = error{
    AccountNotFound,
    InvalidAccountForFee,
    InsufficientFundsForFee,
    InsufficientFundsForRent,
    AccountLoadedTwice,
    TooManyAccountLocks,
    ProgramAccountNotFound,
    InvalidProgramForExecution,
    MaxLoadedAccountsDataSizeExceeded,
    SignatureFailure,
    SanitizeFailure,
    AlreadyProcessed,
    BlockhashNotFound,
    InstructionError,
    UnbalancedTransaction,
    AddressLookupTableNotFound,
};

// ─────────────────────────────────────────────────────────────────────────────
// RentState — fd_executor.c:36-46
// ─────────────────────────────────────────────────────────────────────────────

/// Account rent state.
/// Firedancer: struct fd_rent_state / FD_RENT_STATE_* (fd_executor.c:36-46).
pub const RentState = union(enum) {
    /// Account has zero lamports (fd_executor.c:44: FD_RENT_STATE_UNINITIALIZED)
    Uninitialized,
    /// 0 < lamports < rent_exempt_minimum (fd_executor.c:45: FD_RENT_STATE_RENT_PAYING)
    RentPaying: struct { lamports: u64, data_size: usize },
    /// lamports >= rent_exempt_minimum (fd_executor.c:46: FD_RENT_STATE_RENT_EXEMPT)
    RentExempt,
};

/// Compute the rent state for an account.
///
/// Firedancer: fd_executor_get_account_rent_state()
/// fd_executor.c:149-168
pub fn getAccountRentState(
    lamports: u64,
    data_len: usize,
    rent_exempt_min: u64, // caller computes this via RentParams.exemptMinBalance()
) RentState {
    // fd_executor.c:152-154
    if (lamports == 0) return .Uninitialized;

    // fd_executor.c:157-161
    if (lamports >= rent_exempt_min) return .RentExempt;

    // fd_executor.c:163-167
    return .{ .RentPaying = .{ .lamports = lamports, .data_size = data_len } };
}

/// Check whether a rent state transition is allowed.
///
/// Firedancer: fd_executor_rent_transition_allowed()
/// fd_executor.c:109-141
///
/// Rules (fd_executor.c:113-141):
///   Post=Uninitialized or Post=RentExempt → always allowed
///   Post=RentPaying, Pre=Uninitialized    → NOT allowed (fd_executor.c:121)
///   Post=RentPaying, Pre=RentExempt       → NOT allowed (fd_executor.c:122)
///   Post=RentPaying, Pre=RentPaying       → allowed only if data_size unchanged AND lamports decreased
pub fn rentTransitionAllowed(pre: RentState, post: RentState) bool {
    return switch (post) {
        .Uninitialized, .RentExempt => true, // fd_executor.c:115-117

        .RentPaying => |post_rp| switch (pre) {
            .Uninitialized, .RentExempt => false, // fd_executor.c:121-122
            .RentPaying => |pre_rp| {
                // fd_executor.c:123-124: data_size must match, lamports can only decrease
                return post_rp.data_size == pre_rp.data_size and
                    post_rp.lamports <= pre_rp.lamports;
            },
        },
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// NativeProgramKind — dispatch table (fd_executor.c:48-74)
// ─────────────────────────────────────────────────────────────────────────────

/// Native program kinds known to the executor.
/// Mirrors the MAP_PERFECT_* table in fd_executor.c:48-74.
/// fd_executor.c:65-72: VOTE, SYS, COMPUTE_BUDGET, ZK_EL_GAMAL, BPF_LOADER_1/2/UPGRADEABLE, LOADER_V4
pub const NativeProgramKind = enum {
    // ── Precompiles (checked first, fd_executor.c:103-108) ──
    Ed25519Precompile, // fd_precompiles.c:452: ED25519_SV_PROG_ID → fd_precompile_ed25519_verify
    Secp256k1Precompile, // fd_precompiles.c:453: KECCAK_SECP_PROG_ID → fd_precompile_secp256k1_verify
    Secp256r1Precompile, // fd_precompiles.c:454: SECP256R1_PROG_ID → fd_precompile_secp256r1_verify

    // ── Native builtins ──
    Vote, // fd_executor.c:65: VOTE_PROG_ID → fd_vote_program_execute
    System, // fd_executor.c:66: SYS_PROG_ID → fd_system_program_execute
    ComputeBudget, // fd_executor.c:67: COMPUTE_BUDGET_PROG_ID → fd_compute_budget_program_execute
    ZkElGamal, // fd_executor.c:68: ZK_EL_GAMAL_PROG_ID → fd_executor_zk_elgamal_proof_program_execute
    BpfLoader1, // fd_executor.c:69: BPF_LOADER_1_PROG_ID → fd_bpf_loader_program_execute (.is_bpf_loader=1)
    BpfLoader2, // fd_executor.c:70: BPF_LOADER_2_PROG_ID → fd_bpf_loader_program_execute (.is_bpf_loader=1)
    BpfLoaderUpgradeable, // fd_executor.c:71: BPF_UPGRADEABLE_PROG_ID → fd_bpf_loader_program_execute (.is_bpf_loader=1)
    LoaderV4, // fd_executor.c:72: LOADER_V4_PROG_ID → fd_loader_v4_program_execute (.is_bpf_loader=1)
    Bpf, // BPF program: dispatch to sBPF executor (vex_bpf)
    Unknown, // No matching program found

    /// Returns true if this kind is a precompile (not a native builtin).
    /// Used to skip return_data reset (fd_executor.c:1163).
    pub fn isPrecompile(self: NativeProgramKind) bool {
        return switch (self) {
            .Ed25519Precompile, .Secp256k1Precompile, .Secp256r1Precompile => true,
            else => false,
        };
    }
};

/// Identify whether a program ID is a BPF loader.
/// Firedancer: fd_executor_pubkey_is_bpf_loader()
/// fd_executor.c:78-81
pub fn isBpfLoader(program_id: *const [32]u8) bool {
    return std.mem.eql(u8, program_id, &BPF_LOADER_1_PROG_ID) or
        std.mem.eql(u8, program_id, &BPF_LOADER_2_PROG_ID) or
        std.mem.eql(u8, program_id, &BPF_UPGRADEABLE_PROG_ID) or
        std.mem.eql(u8, program_id, &LOADER_V4_PROG_ID);
}

/// Look up the native program for a given program ID and owner.
///
/// Firedancer: fd_executor_lookup_native_program()
/// fd_executor.c:94-147
///
/// Lookup logic (fd_executor.c:96-147):
///   1. Check precompile table first (fd_executor_lookup_native_precompile_program)
///      → TODO: secp256k1, ed25519, secp256r1 precompile check
///   2. Check if owner == NativeLoader → lookup by pubkey in native dispatch table
///   3. Check if owner is a BPF loader → lookup by owner (not pubkey)
///   4. If neither → UnsupportedProgramId error
///
/// Returns the NativeProgramKind or error.
pub fn lookupNativeProgram(
    program_id: *const [32]u8,
    owner: *const [32]u8,
) InstrError!NativeProgramKind {
    // fd_executor.c:103-108: precompile check (ed25519, secp256k1, secp256r1)
    // fd_executor_lookup_native_precompile_program() — checked BEFORE native loader
    if (std.mem.eql(u8, program_id, &ED25519_PRECOMPILE_ID)) return .Ed25519Precompile;
    if (std.mem.eql(u8, program_id, &SECP256K1_PRECOMPILE_ID)) return .Secp256k1Precompile;
    if (std.mem.eql(u8, program_id, &SECP256R1_PRECOMPILE_ID)) return .Secp256r1Precompile;

    // fd_executor.c:110-112: is owner the NativeLoader?
    const is_native = std.mem.eql(u8, owner, &NATIVE_LOADER_ID);

    if (!is_native) {
        // fd_executor.c:117-119: owner must be a BPF loader for non-native programs
        if (!isBpfLoader(owner)) {
            return InstrError.UnsupportedProgramId;
        }
    }

    // fd_executor.c:122: lookup_pubkey = is_native ? pubkey : owner
    const lookup = if (is_native) program_id else owner;

    // fd_executor.c:130-146: perfect hash lookup in dispatch table
    if (std.mem.eql(u8, lookup, &VOTE_PROG_ID)) return .Vote;
    if (std.mem.eql(u8, lookup, &SYS_PROG_ID)) return .System;
    if (std.mem.eql(u8, lookup, &COMPUTE_BUDGET_PROG_ID)) return .ComputeBudget;
    if (std.mem.eql(u8, lookup, &ZK_ELGAMAL_PROG_ID)) return .ZkElGamal;
    if (std.mem.eql(u8, lookup, &BPF_LOADER_1_PROG_ID)) return .BpfLoader1;
    if (std.mem.eql(u8, lookup, &BPF_LOADER_2_PROG_ID)) return .BpfLoader2;
    if (std.mem.eql(u8, lookup, &BPF_UPGRADEABLE_PROG_ID)) return .BpfLoaderUpgradeable;
    if (std.mem.eql(u8, lookup, &LOADER_V4_PROG_ID)) return .LoaderV4;

    // fd_executor.c:139-141: native program not in table → UnsupportedProgramId
    // (also covers migrated programs that now run as BPF)
    return InstrError.UnsupportedProgramId;
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction stack — fd_executor.c:908-1093
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum cross-program invocation call depth.
/// Firedancer: FD_MAX_INSTRUCTION_STACK_DEPTH
/// fd_executor.c:966: "runtime->instr.stack_sz >= FD_MAX_INSTRUCTION_STACK_DEPTH"
pub const MAX_CPI_DEPTH: usize = 4;

/// Maximum instruction trace length per transaction.
/// Firedancer: FD_MAX_INSTRUCTION_TRACE_LENGTH
/// fd_executor.c:960: "runtime->instr.trace_length > FD_MAX_INSTRUCTION_TRACE_LENGTH"
pub const MAX_INSTR_TRACE: usize = 64;

/// Instruction stack entry — mirrors fd_exec_instr_ctx_t (simplified).
/// fd_executor.c:1131-1138: fields populated in fd_execute_instr()
pub const InstrStackEntry = struct {
    program_id_idx: u16, // Index into transaction account keys
    program_id: [32]u8, // Resolved program pubkey
    starting_lamports_hi: u64, // High bits of account sum before instruction (128-bit)
    starting_lamports_lo: u64, // Low bits of account sum before instruction
};

/// Instruction execution stack.
/// Firedancer: runtime->instr.stack / runtime->instr.stack_sz
/// fd_executor.c:908-1093
pub const InstrStack = struct {
    entries: [MAX_CPI_DEPTH]InstrStackEntry = undefined,
    depth: u8 = 0,
    trace_length: usize = 0,

    /// Push a new CPI frame onto the stack.
    /// Firedancer: fd_instr_stack_push() → fd_txn_ctx_push()
    /// fd_executor.c:999-1049, fd_executor.c:908-993
    pub fn push(
        self: *InstrStack,
        program_id_idx: u16,
        program_id: [32]u8,
        starting_lamports_hi: u64,
        starting_lamports_lo: u64,
    ) InstrError!void {
        // fd_executor.c:960-962: trace length check
        if (self.trace_length > MAX_INSTR_TRACE) return InstrError.MaxInsnTraceLensExceeded;

        // fd_executor.c:965-967: stack depth check
        if (self.depth >= MAX_CPI_DEPTH) return InstrError.CallDepth;

        // fd_executor.c:1024-1043: reentrancy check
        // The same program cannot appear twice in the stack unless it's calling itself (last entry)
        for (self.entries[0..self.depth], 0..) |entry, level| {
            if (entry.program_id_idx == program_id_idx) {
                // Only allowed if it's calling itself (the last stack frame)
                if (level < self.depth - 1) {
                    return InstrError.ReentrancyNotAllowed; // fd_executor.c:1042-1043
                }
            }
        }

        // fd_executor.c:968: runtime->instr.stack_sz++
        self.entries[self.depth] = .{
            .program_id_idx = program_id_idx,
            .program_id = program_id,
            .starting_lamports_hi = starting_lamports_hi,
            .starting_lamports_lo = starting_lamports_lo,
        };
        self.depth += 1;
        self.trace_length += 1;
    }

    /// Pop a CPI frame from the stack, checking lamport balance.
    /// Firedancer: fd_instr_stack_pop()
    /// fd_executor.c:1056-1093
    pub fn pop(
        self: *InstrStack,
        ending_lamports_hi: u64,
        ending_lamports_lo: u64,
    ) InstrError!void {
        // fd_executor.c:1061-1063: underflow check
        if (self.depth == 0) return InstrError.CallDepth;

        self.depth -= 1;
        const entry = &self.entries[self.depth];

        // fd_executor.c:1079-1090: lamport balance check
        if (ending_lamports_lo != entry.starting_lamports_lo or
            ending_lamports_hi != entry.starting_lamports_hi)
        {
            return InstrError.UnbalancedInstr;
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// InstrContext — instruction execution context
// ─────────────────────────────────────────────────────────────────────────────

/// Instruction execution context passed to native program handlers.
/// Mirrors fd_exec_instr_ctx_t (fd_executor.c:1131-1138).
pub const InstrContext = struct {
    /// Index of the program account in the transaction's account array
    program_id_idx: u16,
    /// The program ID (pubkey bytes)
    program_id: [32]u8,
    /// Instruction data
    data: []const u8,
    /// Account indices (into transaction account array)
    account_indices: []const u16,
    /// Current stack depth (1 = top-level, 2+ = CPI)
    cpi_depth: u8,
    /// Current instruction index in the transaction (for sysvar instructions)
    instr_idx: u16,
    /// Slot being executed
    slot: u64,
    /// All instruction data slices in the transaction (needed by precompiles).
    /// Precompiles reference data from other instructions via index (fd_precompiles.c:69-118).
    /// For non-precompile instructions this may be an empty slice.
    all_instr_datas: []const []const u8 = &.{},
};

// ─────────────────────────────────────────────────────────────────────────────
// NativeProgramFn — handler function type
// ─────────────────────────────────────────────────────────────────────────────

/// Native program handler function type.
/// Firedancer: fd_exec_instr_fn_t (fd_executor.c line ~100)
/// Returns null on success, or an InstrError on failure.
pub const NativeProgramFn = *const fn (ctx: *const InstrContext) InstrError!void;

// ─────────────────────────────────────────────────────────────────────────────
// executeInstruction — fd_execute_instr() fd_executor.c:1114-1201
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a single instruction via the native program dispatch table.
///
/// Firedancer: fd_execute_instr()
/// fd_executor.c:1114-1201
///
/// Sequence (fd_executor.c:1119-1201):
///   1. instrStackPush() — validate CPI depth, reentrancy, lamport sum
///   2. Look up native program via lookupNativeProgram()
///   3. If precompile → run precompile verifier (TODO)
///   4. If native → call native_prog_fn(ctx) — resets return_data before call
///   5. If BPF → call sBPF executor (vex_bpf)
///   6. instrStackPop() — validate lamport balance after execution
///   7. Log success/failure
///
/// Parameters:
///   stack       — mutable instruction stack (for CPI depth tracking)
///   ctx         — instruction context
///   owner       — owner of the program account (for BPF loader check)
///   handler     — optional pre-resolved native handler (null = look up dynamically)
///
/// Returns InstrError on failure, void on success.
pub fn executeInstruction(
    stack: *InstrStack,
    ctx: *const InstrContext,
    owner: *const [32]u8,
    starting_lamports_hi: u64,
    starting_lamports_lo: u64,
    ending_lamports_hi: u64,
    ending_lamports_lo: u64,
) InstrError!void {
    // fd_executor.c:1121: fd_instr_stack_push
    try stack.push(
        ctx.program_id_idx,
        ctx.program_id,
        starting_lamports_hi,
        starting_lamports_lo,
    );

    // fd_executor.c:1141-1154: lookup native program
    const kind = lookupNativeProgram(&ctx.program_id, owner) catch |err| {
        _ = stack.pop(ending_lamports_hi, ending_lamports_lo) catch {};
        return err;
    };

    // fd_executor.c:1163: precompiles do NOT reset return_data
    // (non-precompile builtins do — handled at caller level if return_data is tracked)

    // fd_executor.c:1157-1174: dispatch to handler
    const exec_result: InstrError!void = switch (kind) {
        // ── Precompile dispatch (fd_precompiles.c:125-421) ──
        // Precompiles verify instruction DATA (signatures), not account state.
        // They receive the current instruction data plus all transaction instruction datas.
        // On failure → CustomError (maps to InstructionError::Custom(0) at tx level).
        .Ed25519Precompile => blk: {
            // fd_precompiles.c:125 (fd_precompile_ed25519_verify)
            // Agave 4.2 runs verify_strict unconditionally (precompiles/src/
            // ed25519.rs:74; SIMD-0152 gate is dead code) — no strict_mode
            // branch to gate here (P0-1, 2026-07-11).
            vex_crypto.ed25519_precompile.verify(ctx.data, ctx.all_instr_datas) catch {
                break :blk InstrError.CustomError;
            };
            break :blk {};
        },
        .Secp256k1Precompile => blk: {
            // fd_precompiles.c:231 (fd_precompile_secp256k1_verify)
            vex_crypto.secp256k1.verify(ctx.data, ctx.all_instr_datas) catch {
                break :blk InstrError.CustomError;
            };
            break :blk {};
        },
        .Secp256r1Precompile => blk: {
            // fd_precompiles.c:341 (fd_precompile_secp256r1_verify)
            vex_crypto.secp256r1.verify(ctx.data, ctx.all_instr_datas) catch {
                break :blk InstrError.CustomError;
            };
            break :blk {};
        },

        .Vote => {
            // TODO: fd_vote_program_execute (fd_executor.c:65)
            // Wire to vex_svm/native/vote.zig
            std.log.debug("[EXEC] Vote program slot={d} instr={d}", .{ ctx.slot, ctx.instr_idx });
        },
        .System => {
            // TODO: fd_system_program_execute (fd_executor.c:66)
            // Wire to vex_svm/native/system.zig
            std.log.debug("[EXEC] System program slot={d} instr={d}", .{ ctx.slot, ctx.instr_idx });
        },
        .ComputeBudget => {
            // TODO: fd_compute_budget_program_execute (fd_executor.c:67)
            // Compute budget is processed at transaction level before instruction execution.
            // In replay, this is a no-op at instruction time.
            std.log.debug("[EXEC] ComputeBudget program (no-op at instr level)", .{});
        },
        .ZkElGamal => {
            // TODO: fd_executor_zk_elgamal_proof_program_execute (fd_executor.c:68)
            std.log.warn("[EXEC] ZkElGamal not implemented, slot={d}", .{ctx.slot});
            return InstrError.UnsupportedProgramId;
        },
        .BpfLoader1, .BpfLoader2, .BpfLoaderUpgradeable => {
            // TODO: fd_bpf_loader_program_execute (fd_executor.c:69-71)
            // Wire to vex_bpf ELF loader path
            std.log.warn("[EXEC] BPF Loader not implemented, slot={d}", .{ctx.slot});
            return InstrError.UnsupportedProgramId;
        },
        .LoaderV4 => {
            // TODO: fd_loader_v4_program_execute (fd_executor.c:72)
            std.log.warn("[EXEC] LoaderV4 not implemented, slot={d}", .{ctx.slot});
            return InstrError.UnsupportedProgramId;
        },
        .Bpf => {
            // TODO: sBPF executor dispatch (vex_bpf)
            // fd_executor.c does this via the program cache lookup at a higher level
            std.log.warn("[EXEC] sBPF execution not implemented, slot={d}", .{ctx.slot});
            return InstrError.UnsupportedProgramId;
        },
        .Unknown => {
            // fd_executor.c:1169-1174: "Unknown program. Do not log program id."
            return InstrError.UnsupportedProgramId;
        },
    };

    // fd_execute_instr_end → fd_instr_stack_pop (fd_executor.c:1099-1112)
    // fd_executor.c:1103: always pop even if exec failed
    const pop_result = stack.pop(ending_lamports_hi, ending_lamports_lo);

    // fd_executor.c:1105-1108: only report pop error if exec succeeded
    if (exec_result) |_| {
        try pop_result;
    } else |exec_err| {
        // Exec failed: pop error is swallowed (fd_executor.c:1103-1104)
        _ = pop_result catch {};
        return exec_err;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// transactionCheck — fd_executor.c:1438-1507
// ─────────────────────────────────────────────────────────────────────────────

/// Per-account writable state for transaction-level rent checks.
/// Matches the data fd_executor_txn_check() iterates over (fd_executor.c:1450-1494).
pub const WritableAccountState = struct {
    pubkey: [32]u8,
    starting_lamports: u64,
    starting_data_len: usize,
    ending_lamports: u64,
    ending_data_len: usize,
    /// True if pubkey == INCINERATOR_ID
    is_incinerator: bool,
    /// Lamports before fees were deducted (for fee payer)
    starting_lamports_h: u64, // high 64 bits of 128-bit running sum
    starting_lamports_l: u64, // low 64 bits
    ending_lamports_h: u64,
    ending_lamports_l: u64,
};

/// Check transaction-level invariants after all instructions have executed.
///
/// ⚠ FOOTGUN: this is a faithful FD port of fd_executor_txn_check but had ZERO
/// production callers until 2026-07-05. If you find it uncalled again, that is
/// a LIVE bank_hash carrier (slot 419957920: cluster failed two System txs
/// with InsufficientFundsForRent and rolled them back; Vexor committed them).
/// It MUST be invoked after a successful ix loop in BOTH executeDagTx AND the
/// serial loop (replay_stage.zig rentCheckSnapshot/rentCheckVerify), with the
/// starting state captured POST-FEE (the fee write sits below tx_mark).
///
/// Firedancer: fd_executor_txn_check()
/// fd_executor.c:1438-1507
///
/// Checks per writable account (fd_executor.c:1450-1494):
///   1. Rent state transition must be valid (unless incinerator)
///   2. Total lamports must be balanced (fd_executor.c:1500-1503)
///
/// Returns null on success, or a TxnError variant on failure.
pub fn transactionCheck(
    writable_accounts: []const WritableAccountState,
    rent_exempt_fn: anytype, // fn(data_len: usize) u64
) TxnError!void {
    var total_starting_hi: u64 = 0;
    var total_starting_lo: u64 = 0;
    var total_ending_hi: u64 = 0;
    var total_ending_lo: u64 = 0;

    for (writable_accounts) |acc| {
        // Accumulate lamport sums (128-bit via hi/lo) — fd_executor.c:1458-1459
        // fd_uwide_inc — wrapping 128-bit addition
        {
            const lo, const carry = @addWithOverflow(total_starting_lo, acc.starting_lamports);
            total_starting_lo = lo;
            total_starting_hi +%= carry;
            total_starting_hi +%= acc.starting_lamports_h;
        }
        {
            const lo, const carry = @addWithOverflow(total_ending_lo, acc.ending_lamports);
            total_ending_lo = lo;
            total_ending_hi +%= carry;
            total_ending_hi +%= acc.ending_lamports_h;
        }

        // fd_executor.c:1466: skip incinerator for rent checks
        if (acc.is_incinerator) continue;

        const rent_min = rent_exempt_fn(acc.ending_data_len);
        const after_uninit = acc.ending_lamports == 0;
        const after_exempt = acc.ending_lamports >= rent_min;

        // fd_executor.c:1472-1490: rent state check
        if (!after_uninit and !after_exempt) {
            // Post-state is RentPaying — check if transition is allowed
            const rent_min_start = rent_exempt_fn(acc.starting_data_len);
            const before_uninit = acc.starting_lamports == 0;
            const before_exempt = acc.starting_lamports >= rent_min_start;

            if (before_uninit or before_exempt) {
                // fd_executor.c:1480-1482: pre-state was not rent-paying → forbidden
                return TxnError.InsufficientFundsForRent;
            }
            // fd_executor.c:1484-1488: pre and post both rent-paying
            // Only allowed if data size unchanged and lamports didn't increase
            if (acc.ending_data_len != acc.starting_data_len or
                acc.ending_lamports > acc.starting_lamports)
            {
                return TxnError.InsufficientFundsForRent;
            }
        }
    }

    // fd_executor.c:1500-1503: total lamport balance check
    if (total_ending_lo != total_starting_lo or total_ending_hi != total_starting_hi) {
        return TxnError.UnbalancedTransaction; // unbalanced transaction error
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// instrErrorString — fd_executor.c:1549-1651
// ─────────────────────────────────────────────────────────────────────────────

/// Return the human-readable error string for an InstrError.
///
/// Firedancer: fd_executor_instr_strerror()
/// fd_executor.c:1549-1651
///
/// Matches Agave's log output format for instruction errors.
pub fn instrErrorString(err: InstrError) []const u8 {
    return switch (err) {
        .Success => "",
        .Fatal => "",
        .GenericError => "generic instruction error",
        .InvalidArg => "invalid program argument",
        .InvalidInstrData => "invalid instruction data",
        .InvalidAccData => "invalid account data for instruction",
        .AccDataTooSmall => "account data too small for instruction",
        .InsufficientFunds => "insufficient funds for instruction",
        .IncorrectProgramId => "incorrect program id for instruction",
        .MissingRequiredSignature => "missing required signature for instruction",
        .AccAlreadyInitialized => "instruction requires an uninitialized account",
        .UninitializedAccount => "instruction requires an initialized account",
        .UnbalancedInstr => "sum of account balances before and after instruction do not match",
        .ModifiedProgramId => "instruction illegally modified the program id of an account",
        .ExternalAccountLamportSpend => "instruction spent from the balance of an account it does not own",
        .ExternalDataModified => "instruction modified data of an account it does not own",
        .ReadonlyLamportChange => "instruction changed the balance of a read-only account",
        .ReadonlyDataModified => "instruction modified data of a read-only account",
        .DuplicateAccountIdx => "instruction contains duplicate accounts",
        .ExecutableModified => "instruction changed executable bit of an account",
        .RentEpochModified => "instruction modified rent epoch of an account",
        .NotEnoughAccKeys => "insufficient account keys for instruction",
        .AccDataSizeChanged => "program other than the account's owner changed the size of the account data",
        .AccNotExecutable => "instruction expected an executable account",
        .AccBorrowFailed => "instruction tries to borrow reference for an account which is already borrowed",
        .AccBorrowOutstanding => "instruction left account with an outstanding borrowed reference",
        .DuplicateAccountOutOfSync => "instruction modifications of multiply-passed account differ",
        .CustomError => "",
        .InvalidError => "program returned invalid error code",
        .ExecutableDataModified => "instruction changed executable accounts data",
        .ExecutableLamportChange => "instruction changed the balance of an executable account",
        .ExecutableAccountNotRentExempt => "executable accounts must be rent exempt",
        .UnsupportedProgramId => "Unsupported program id",
        .CallDepth => "Cross-program invocation call depth too deep",
        .MissingAcc => "An account required by the instruction is missing",
        .ReentrancyNotAllowed => "Cross-program invocation reentrancy not allowed for this instruction",
        .MaxSeedLengthExceeded => "Length of the seed is too long for address generation",
        .InvalidSeeds => "Provided seeds do not result in a valid address",
        .InvalidRealloc => "Failed to reallocate account data",
        .ComputeBudgetExceeded => "Computational budget exceeded",
        .PrivilegeEscalation => "Cross-program invocation with unauthorized signer or writable account",
        .ProgramEnvironmentSetupFailure => "Failed to create program execution environment",
        .ProgramFailedToComplete => "Program failed to complete",
        .ProgramFailedToCompile => "Program failed to compile",
        .AccImmutable => "Account is immutable",
        .IncorrectAuthority => "Incorrect authority provided",
        .BorshIoError => "Failed to serialize or deserialize account data",
        .AccNotRentExempt => "An account does not have enough lamports to be rent-exempt",
        .InvalidAccOwner => "Invalid account owner",
        .ArithmeticOverflow => "Program arithmetic overflowed",
        .UnsupportedSysvar => "Unsupported sysvar",
        .IllegalOwner => "Provided owner is not allowed",
        .MaxAccsDataAllocsExceeded => "Accounts data allocations exceeded the maximum allowed per transaction",
        .MaxAccsExceeded => "Max accounts exceeded",
        .MaxInsnTraceLensExceeded => "Max instruction trace length exceeded",
        .BuiltinsMustConsumeCUs => "Builtin programs must consume compute units",
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// consumeComputeUnits — fd_executor.c:1520-1540
// ─────────────────────────────────────────────────────────────────────────────

/// Consume compute units from the meter.
///
/// Firedancer: fd_executor_consume_cus()
/// fd_executor.c:1520-1540
pub fn consumeComputeUnits(compute_meter: *u64, cus: u64) InstrError!void {
    if (compute_meter.* < cus) {
        compute_meter.* = 0;
        return InstrError.ComputeBudgetExceeded; // fd_executor.c:1530-1531
    }
    compute_meter.* -= cus;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "getAccountRentState: zero lamports → Uninitialized" {
    const state = getAccountRentState(0, 100, 1000);
    try std.testing.expect(state == .Uninitialized);
}

test "getAccountRentState: above minimum → RentExempt" {
    const state = getAccountRentState(10_000, 0, 1000);
    try std.testing.expect(state == .RentExempt);
}

test "getAccountRentState: below minimum → RentPaying" {
    const state = getAccountRentState(100, 0, 1000);
    switch (state) {
        .RentPaying => |rp| {
            try std.testing.expectEqual(@as(u64, 100), rp.lamports);
            try std.testing.expectEqual(@as(usize, 0), rp.data_size);
        },
        else => return error.WrongVariant,
    }
}

test "rentTransitionAllowed: Uninitialized → RentExempt → allowed" {
    try std.testing.expect(rentTransitionAllowed(.Uninitialized, .RentExempt));
    try std.testing.expect(rentTransitionAllowed(.RentExempt, .RentExempt));
    try std.testing.expect(rentTransitionAllowed(.Uninitialized, .Uninitialized));
}

test "rentTransitionAllowed: RentExempt → RentPaying → forbidden" {
    const post = RentState{ .RentPaying = .{ .lamports = 50, .data_size = 10 } };
    try std.testing.expect(!rentTransitionAllowed(.RentExempt, post));
    try std.testing.expect(!rentTransitionAllowed(.Uninitialized, post));
}

test "rentTransitionAllowed: RentPaying → RentPaying: size/lamports constraints" {
    const pre = RentState{ .RentPaying = .{ .lamports = 100, .data_size = 10 } };
    // same size, fewer lamports → allowed
    const ok = RentState{ .RentPaying = .{ .lamports = 90, .data_size = 10 } };
    try std.testing.expect(rentTransitionAllowed(pre, ok));
    // same size, more lamports → NOT allowed
    const bad1 = RentState{ .RentPaying = .{ .lamports = 110, .data_size = 10 } };
    try std.testing.expect(!rentTransitionAllowed(pre, bad1));
    // different size → NOT allowed
    const bad2 = RentState{ .RentPaying = .{ .lamports = 90, .data_size = 11 } };
    try std.testing.expect(!rentTransitionAllowed(pre, bad2));
}

test "transactionCheck: Uninitialized→RentPaying transfer fails — carrier 419957920 KAT" {
    // The live carrier shape: System transfer funds a fresh account to
    // 0 < lamports < rent_exempt_min. Cluster: whole tx fails
    // InsufficientFundsForRent (fees-only); pre-fix Vexor committed it.
    const rentFn = struct {
        fn f(dl: usize) u64 {
            return (@as(u64, dl) + 128) * 3480 * 2; // data_len 0 → 890_880
        }
    }.f;
    const accts = [_]WritableAccountState{
        // fee-payer/source (post-fee starting): stays rent-exempt
        .{ .pubkey = [_]u8{1} ** 32, .starting_lamports = 10_000_000, .starting_data_len = 0, .ending_lamports = 9_500_000, .ending_data_len = 0, .is_incinerator = false, .starting_lamports_h = 0, .starting_lamports_l = 0, .ending_lamports_h = 0, .ending_lamports_l = 0 },
        // dest: 0 (Uninitialized) → 500_000 (< 890_880 = RentPaying) → forbidden
        .{ .pubkey = [_]u8{2} ** 32, .starting_lamports = 0, .starting_data_len = 0, .ending_lamports = 500_000, .ending_data_len = 0, .is_incinerator = false, .starting_lamports_h = 0, .starting_lamports_l = 0, .ending_lamports_h = 0, .ending_lamports_l = 0 },
    };
    try std.testing.expectError(TxnError.InsufficientFundsForRent, transactionCheck(&accts, rentFn));
}

test "transactionCheck: transfer funding dest to rent-exempt is allowed" {
    const rentFn = struct {
        fn f(dl: usize) u64 {
            return (@as(u64, dl) + 128) * 3480 * 2;
        }
    }.f;
    const accts = [_]WritableAccountState{
        .{ .pubkey = [_]u8{1} ** 32, .starting_lamports = 10_000_000, .starting_data_len = 0, .ending_lamports = 9_000_000, .ending_data_len = 0, .is_incinerator = false, .starting_lamports_h = 0, .starting_lamports_l = 0, .ending_lamports_h = 0, .ending_lamports_l = 0 },
        .{ .pubkey = [_]u8{2} ** 32, .starting_lamports = 0, .starting_data_len = 0, .ending_lamports = 1_000_000, .ending_data_len = 0, .is_incinerator = false, .starting_lamports_h = 0, .starting_lamports_l = 0, .ending_lamports_h = 0, .ending_lamports_l = 0 },
    };
    try transactionCheck(&accts, rentFn);
}

test "transactionCheck: unbalanced lamports → UnbalancedTransaction" {
    const rentFn = struct {
        fn f(dl: usize) u64 {
            return (@as(u64, dl) + 128) * 3480 * 2;
        }
    }.f;
    const accts = [_]WritableAccountState{
        .{ .pubkey = [_]u8{1} ** 32, .starting_lamports = 10_000_000, .starting_data_len = 0, .ending_lamports = 9_000_000, .ending_data_len = 0, .is_incinerator = false, .starting_lamports_h = 0, .starting_lamports_l = 0, .ending_lamports_h = 0, .ending_lamports_l = 0 },
        .{ .pubkey = [_]u8{2} ** 32, .starting_lamports = 0, .starting_data_len = 0, .ending_lamports = 999_999, .ending_data_len = 0, .is_incinerator = false, .starting_lamports_h = 0, .starting_lamports_l = 0, .ending_lamports_h = 0, .ending_lamports_l = 0 },
    };
    try std.testing.expectError(TxnError.UnbalancedTransaction, transactionCheck(&accts, rentFn));
}

test "transactionCheck: incinerator dest below min is skipped (allowed)" {
    const rentFn = struct {
        fn f(dl: usize) u64 {
            return (@as(u64, dl) + 128) * 3480 * 2;
        }
    }.f;
    const accts = [_]WritableAccountState{
        .{ .pubkey = [_]u8{1} ** 32, .starting_lamports = 10_000_000, .starting_data_len = 0, .ending_lamports = 9_500_000, .ending_data_len = 0, .is_incinerator = false, .starting_lamports_h = 0, .starting_lamports_l = 0, .ending_lamports_h = 0, .ending_lamports_l = 0 },
        .{ .pubkey = [_]u8{2} ** 32, .starting_lamports = 0, .starting_data_len = 0, .ending_lamports = 500_000, .ending_data_len = 0, .is_incinerator = true, .starting_lamports_h = 0, .starting_lamports_l = 0, .ending_lamports_h = 0, .ending_lamports_l = 0 },
    };
    try transactionCheck(&accts, rentFn);
}

test "lookupNativeProgram: system program" {
    const kind = try lookupNativeProgram(&SYS_PROG_ID, &NATIVE_LOADER_ID);
    try std.testing.expectEqual(NativeProgramKind.System, kind);
}

test "lookupNativeProgram: vote program" {
    const kind = try lookupNativeProgram(&VOTE_PROG_ID, &NATIVE_LOADER_ID);
    try std.testing.expectEqual(NativeProgramKind.Vote, kind);
}

test "lookupNativeProgram: unknown → UnsupportedProgramId" {
    const result = lookupNativeProgram(&([_]u8{0xFF} ** 32), &NATIVE_LOADER_ID);
    try std.testing.expectError(InstrError.UnsupportedProgramId, result);
}

test "instrStack: push/pop roundtrip" {
    var stack = InstrStack{};
    try stack.push(0, SYS_PROG_ID, 0, 1000);
    try std.testing.expectEqual(@as(u8, 1), stack.depth);
    try stack.pop(0, 1000);
    try std.testing.expectEqual(@as(u8, 0), stack.depth);
}

test "instrStack: depth overflow → CallDepth" {
    var stack = InstrStack{};
    for (0..MAX_CPI_DEPTH) |i| {
        try stack.push(@intCast(i), [_]u8{@intCast(i)} ** 32, 0, 0);
    }
    const result = stack.push(255, [_]u8{0xFF} ** 32, 0, 0);
    try std.testing.expectError(InstrError.CallDepth, result);
}

test "instrStack: unbalanced pop → UnbalancedInstr" {
    var stack = InstrStack{};
    try stack.push(0, SYS_PROG_ID, 0, 1000);
    const result = stack.pop(0, 999); // lamports changed
    try std.testing.expectError(InstrError.UnbalancedInstr, result);
}

test "consumeComputeUnits: underflow → ComputeBudgetExceeded" {
    var meter: u64 = 100;
    const result = consumeComputeUnits(&meter, 200);
    try std.testing.expectError(InstrError.ComputeBudgetExceeded, result);
    try std.testing.expectEqual(@as(u64, 0), meter);
}

test "consumeComputeUnits: normal deduction" {
    var meter: u64 = 100;
    try consumeComputeUnits(&meter, 30);
    try std.testing.expectEqual(@as(u64, 70), meter);
}

test "instrErrorString: all codes return non-null" {
    // Just check a few representative cases
    try std.testing.expectEqualStrings("Unsupported program id", instrErrorString(.UnsupportedProgramId));
    try std.testing.expectEqualStrings("Computational budget exceeded", instrErrorString(.ComputeBudgetExceeded));
    try std.testing.expectEqualStrings("Cross-program invocation call depth too deep", instrErrorString(.CallDepth));
}
