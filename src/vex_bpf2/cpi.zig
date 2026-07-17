//! Vexor BPF2 — Cross-Program Invocation handler (M7)
//!
//! Spec-for-spec rebuild against Agave program-runtime/src/cpi.rs (canonical,
//! 2552 LoC, v4.0.0-beta.7) + sig/mollusk/anza-svm as cross-references.
//! @prov:cpi.module-map — full per-function upstream line-map, SIMD inventory,
//! scope (implemented/deferred), and fix_ledger anchors in PROVENANCE.md.
//!
//! API extensions to M-modules: NONE. Every entry point we call on
//! InvokeContext / AlignedMemoryMap / SysvarCache exists today. The
//! program-resolver callback (see ProgramResolver below) is a NEW input
//! parameter to handleSolInvokeSigned itself — it does NOT mutate any locked
//! API. M6 (SyscallRegistry) supplies this when it constructs the
//! sol_invoke_signed_* dispatch closure.

const std = @import("std");
const memory = @import("memory.zig");
const serialize = @import("serialize.zig");
const interpreter = @import("interpreter.zig");
const invoke_ctx_mod = @import("invoke_ctx.zig");
const sysvar_cache = @import("sysvar_cache.zig");
const elf_mod = @import("elf.zig");

const InvokeContext = invoke_ctx_mod.InvokeContext;
const AccountView = invoke_ctx_mod.AccountView;
const TransactionContext = invoke_ctx_mod.TransactionContext;
const Pubkey32 = sysvar_cache.Pubkey32;
const AlignedMemoryMap = memory.AlignedMemoryMap;
const Region = memory.Region;
const MemoryRegionAccess = memory.MemoryRegionAccess;
const AccessError = memory.AccessError;
const MAX_PERMITTED_DATA_INCREASE = serialize.MAX_PERMITTED_DATA_INCREASE;

// ──────────────────────────────────────────────────────────────────────────────
// Trace shim — std.log.err gated on a build-time constant.
// Wave 3.5 will replace this with the trace-module hook.
// ──────────────────────────────────────────────────────────────────────────────

/// Deprecated: kept for backward source-compatibility. Wave 3.5 routes the
/// trace via `trace.zig`'s runtime level filter; this constant is no longer
/// read at the call sites.
const TRACE_CPI = false;

const trace_layer = @import("trace.zig");
const builtins_mod = @import("builtins/mod.zig");
// Phase-1 Core-BPF Stake env gate (VEX_STAKE_BPF, default OFF). Sibling import
// within vex_bpf2 — no cycle (vex_svm imports vex_bpf2, never the reverse).
const vex_bpf2_stake_flag = @import("stake_bpf_flag.zig");

/// M7 trace shim — Wave 3.5 reroutes the body to the global trace layer.
/// Format `[VBPF2-TRACE] M7.<fmt>` is preserved byte-for-byte.
inline fn trace(comptime fmt: []const u8, args: anytype) void {
    trace_layer.emitRaw("[VBPF2-TRACE] M7." ++ fmt, args);
}

// ──────────────────────────────────────────────────────────────────────────────
// Limits (mirror agave program-runtime/src/cpi.rs + transaction_context.rs)
// ──────────────────────────────────────────────────────────────────────────────

/// @prov:cpi.limits
pub const MAX_ACCOUNTS_PER_INSTRUCTION: usize = 256;

/// @prov:cpi.limits
pub const MAX_INSTRUCTION_DATA_LEN: usize = 10 * 1024;

/// @prov:cpi.limits
pub const MAX_SIGNERS: usize = 16;

/// @prov:cpi.limits
pub const MAX_SEEDS: usize = 16;

/// @prov:cpi.limits
pub const MAX_SEED_LEN: usize = 32;

/// @prov:cpi.limits — pre-SIMD-0339 cap
pub const MAX_CPI_ACCOUNT_INFOS: usize = 64;

/// @prov:cpi.limits — post-SIMD-0339 cap (DORMANT)
pub const MAX_CPI_ACCOUNT_INFOS_SIMD_0339: usize = 255;

// ──────────────────────────────────────────────────────────────────────────────
// P0 CU-parity fix (2026-07-12): Agave's cpi_common charges
// TWO CU costs this file never charged, both unconditional (no feature gate):
// @prov:cpi.invoke-units — INVOKE_UNITS flat per-CPI-call fee, charged FIRST,
// before any translation, PLUS the per-CPI instruction-translation byte cost
// charged inside translate_instruction_{c,rust}. Full citation trail (exact
// cpi.rs/execution_budget.rs line ranges, FD cross-check) in PROVENANCE.md.
//
// Root cause: slot 421311644 tx161 (pump.fun 6EF8 `Buy`) — Agave exhausts
// its 150,000-CU tx budget INSIDE this instruction (49839/49839,
// ProgramFailedToComplete) and fails the tx; Vexor completed the SAME
// instruction using only 47,698 of 49,839 (2,141 CU short, instrumented
// replay measurement) and wrongly SUCCEEDED it, keeping the inner-CPI
// buy effects → wrong bank_hash 9577ef43 vs canon 2fc0878d. 6EF8's Buy
// handler makes 5 nested CPIs in this tx (Token + 3×System + a 6EF8 self-
// CPI), each missing INVOKE_UNITS.
pub const INVOKE_UNITS: u64 = 946; // @prov:cpi.invoke-units
pub const CPI_BYTES_PER_UNIT: u64 = 250; // @prov:cpi.invoke-units

/// @prov:cpi.abi-layouts — "Each account meta is 34 bytes (32 pubkey + 1 + 1)".
const ACCOUNT_META_WIRE_SIZE: u64 = 34;

// ──────────────────────────────────────────────────────────────────────────────
// FIX 5 (cpi-invoke-units-cu-parity, 2026-07-12): extends the INVOKE_UNITS +
// instruction-translation fix above with THREE MORE per-account data costs
// Agave charges during CPI account translation that this file still omitted.
// @prov:cpi.per-account-data — (a) account_infos_bytes cost, ONCE per CPI, in
// translate_account_infos: account_infos.len() * ACCOUNT_INFO_BYTE_SIZE(80) /
// cpi_bytes_per_unit(250) (see translateAccountInfos below); (b)
// executable-callee-account data cost PER instruction account (see
// translateInstructionAccountsCommon below); (c) non-executable
// caller-account ref_to_len cost PER instruction account, gated on
// `syscall_parameter_address_restrictions` — Vexor already tracks this
// feature's live activation state as `ctx.syscall_param_addr_restrict_active`
// (invoke_ctx.zig:301, set from the real feature set in v2_dispatch.zig:900 —
// NOT hardcoded permanently-true).
/// @prov:cpi.per-account-data
const ACCOUNT_INFO_BYTE_SIZE: u64 = 80;

/// @prov:cpi.per-account-data — identical formula in both the C and Rust ABI
/// translators. Integer division rounds down, matching `checked_div`.
fn cpiTranslationCost(data_len: u64, accounts_len: u64) u64 {
    const data_cost = data_len / CPI_BYTES_PER_UNIT;
    const meta_cost = (accounts_len *| ACCOUNT_META_WIRE_SIZE) / CPI_BYTES_PER_UNIT;
    return data_cost +| meta_cost;
}

/// PDA marker (agave solana-pubkey::create_program_address).
const PDA_MARKER: []const u8 = "ProgramDerivedAddress";

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

pub const CpiError = error{
    /// Stack at MAX_INSTRUCTION_STACK_DEPTH already.
    M7_DepthExceeded,
    /// num_accounts > MAX_ACCOUNTS_PER_INSTRUCTION.
    M7_TooManyAccounts,
    /// Account in CPI is not present in the caller's transaction.
    M7_AccountNotInTransaction,
    /// data_len > MAX_INSTRUCTION_DATA_LEN.
    M7_InstructionTooLarge,
    /// Memory translation failure (vmap returned AccessViolation).
    M7_TranslateFailed,
    /// PDA seed list invalid (too many seeds, seed > MAX_SEED_LEN, or on curve).
    M7_PdaInvalid,
    /// PDA derived but caller did not list it as a signer.
    M7_PdaNotASigner,
    /// Account info list contains a duplicate pubkey beyond what is permitted.
    M7_DuplicateAccount,
    /// One of the 5 post-execution invariants failed.
    M7_PostCheckFailed,
    /// post_data_len exceeded original_data_len + MAX_PERMITTED_DATA_INCREASE.
    M7_DataIncreaseTooLarge,
    /// Caller is trying to mutate an account whose owner does not permit it.
    M7_OwnershipViolation,
    /// Internal borrow (slice double-mut) violation.
    M7_BorrowError,
    /// Target program is a builtin we have not yet ported. Pre-M9-wireup
    /// blanket. Retained as a CpiError variant only so older paths and tests
    /// referencing the old shape still compile; production no longer emits
    /// it (M9 dispatch always runs).
    M7_BuiltinNotImplemented,
    /// M9 builtin dispatch ran and the builtin handler returned a typed
    /// error. The specific BuiltinError variant is logged via std.log.warn
    /// at the call site so the inner shape (e.g. `M9_System_InsufficientFunds`,
    /// `M9_System_VariantPending_CreateAccount`) is observable in production
    /// logs without us coupling CpiError to the umbrella BuiltinError set.
    M7_BuiltinFailed,
    /// Recursive program load failed (cache miss / bad ELF).
    M7_RecursiveLoadFailed,
    /// Recursive verifier rejected the callee program.
    M7_RecursiveVerifyFailed,
    /// Recursive Vm.run returned an InterpreterError.
    M7_RecursiveExecuteFailed,
    /// ABI flag mismatch (caller asked for a layout we don't support).
    M7_AbiMismatch,
    /// Caller exhausted compute meter while inside the CPI hot path.
    M7_OutOfCompute,
    /// Allocator failure — surfaced for trace continuity.
    M7_OutOfMemory,
    /// Loader-blacklisted program (BPF loader, native loader, precompile).
    M7_ProgramNotSupported,
    /// signers_seeds_len > MAX_SIGNERS.
    M7_TooManySigners,
    /// updateCallerAccount: post-execution destination buffer length differs
    /// from callee's post_len. @prov:cpi.update-caller-account
    M7_AccountDataTooSmall,
};

/// Refinement detail attached as the first arg of the `[VBPF2-TRACE]` line so
/// callers can see which sub-condition triggered without an unstable error
/// payload (Zig 0.15.2 errors carry no payload).
pub const PostCheckKind = enum { lamport_balance, rent, readonly, program_id };

// ──────────────────────────────────────────────────────────────────────────────
// ABI flavour
// ──────────────────────────────────────────────────────────────────────────────

/// The two SolAccountInfo layouts agave registers separate syscalls for.
/// `c`    — `sol_invoke_signed_c`    — POD layout, 80-byte AccountInfo.
/// `rust` — `sol_invoke_signed_rust` — Rc<RefCell<>>-wrapped, 56+ byte layout.
pub const Abi = enum { c, rust };

// ──────────────────────────────────────────────────────────────────────────────
// SolInstruction layouts. @prov:cpi.abi-layouts
// ──────────────────────────────────────────────────────────────────────────────

/// @prov:cpi.abi-layouts
pub const SolInstructionC = extern struct {
    program_id_addr: u64,
    accounts_addr: u64,
    accounts_len: u64,
    data_addr: u64,
    data_len: u64,
};

/// @prov:cpi.abi-layouts
pub const SolAccountMetaC = extern struct {
    pubkey_addr: u64,
    is_writable: u8,
    is_signer: u8,
    // Rust bool is u8 here; the C struct has 6 bytes of trailing pad to align
    // up to 8 — agave reads via repr(C), Zig does the same with extern struct.
    _pad: [6]u8 = .{0} ** 6,
};

/// @prov:cpi.abi-layouts
pub const SolAccountInfoC = extern struct {
    key_addr: u64,
    lamports_addr: u64,
    data_len: u64,
    data_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    is_signer: u8,
    is_writable: u8,
    executable: u8,
    _pad: [5]u8 = .{0} ** 5,
};

/// @prov:cpi.abi-layouts
pub const SolSignerSeedC = extern struct {
    addr: u64,
    len: u64,
};
pub const SolSignerSeedsC = extern struct {
    addr: u64,
    len: u64,
};

/// Rust-flavour StableInstruction layout. @prov:cpi.abi-layouts
/// We don't need the full Rc<RefCell<>> wrapping for AccountInfoRust at the M7
/// boundary, because the only fields we read are key/owner/lamports/data
/// pointers. The Rc<> dance is a host-side concern we sidestep by reading
/// through the same VmValue indirection sig uses (vm_addr → translateType).
pub const StableInstructionRust = extern struct {
    accounts_addr: u64,
    accounts_cap: u64,
    accounts_len: u64,
    data_addr: u64,
    data_cap: u64,
    data_len: u64,
    program_id: [32]u8,
};

/// @prov:cpi.abi-layouts
/// 32 + 1 + 1 = 34 bytes (Rust packs the bools tight; we mirror).
pub const AccountMetaRust = extern struct {
    pubkey: [32]u8,
    is_signer: u8,
    is_writable: u8,
};

/// Rust AccountInfo layout fields we need. @prov:cpi.abi-layouts — the
/// Rc<RefCell<>> wrappers around `lamports` and `data` are 16 bytes each
/// (RcBox: strong+weak). We address the inner value through the Rc pointer —
/// `lamports_box_addr` points at the RcBox, and the inner u64 lives at offset
/// 16 within it. Same for data (RcBox<RefCell<&mut[u8]>>) where the Vec start
/// sits 16 + 8 (RefCell.borrow) + 8 (slice ptr) = 32 bytes in.
pub const AccountInfoRust = extern struct {
    key_addr: u64,
    lamports_box_addr: u64,
    data_box_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    is_signer: u8,
    is_writable: u8,
    executable: u8,
    _pad: [5]u8 = .{0} ** 5,
};

const RC_VALUE_OFFSET: u64 = @sizeOf(usize) * 2; // strong + weak

// ──────────────────────────────────────────────────────────────────────────────
// Builtin pubkey table — M9 stub
// ──────────────────────────────────────────────────────────────────────────────
//
// These pubkeys are used to recognise that the CPI target is a builtin (i.e.
// the runtime resolves it via a Rust handler, not by loading BPF bytecode).
// Until M9 lands we surface `M7_BuiltinNotImplemented` keyed on a match.
//
// @prov:cpi.builtin-pubkeys — sources: solana-sdk-ids (system_program, vote,
// stake, config, compute_budget, address_lookup_table, zk_elgamal_proof_program).
// BPFLoader v1/v2/v3/deprecated — for ProgramNotSupported routing.

const SYSTEM_PROGRAM_ID: Pubkey32 = .{0} ** 32;

// `Vote111111111111111111111111111111111111111` (base58) — first 32 of the program-id.
const VOTE_PROGRAM_ID: Pubkey32 = .{
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
};

// `Stake11111111111111111111111111111111111111`
const STAKE_PROGRAM_ID: Pubkey32 = .{
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a, 0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
    0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b, 0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
};

// `Config1111111111111111111111111111111111111`
const CONFIG_PROGRAM_ID: Pubkey32 = .{
    0x03, 0x06, 0x4a, 0xa3, 0x00, 0x2f, 0x74, 0xdc, 0xc5, 0x6e, 0x59, 0x42, 0xff, 0x71, 0xeb, 0xfb,
    0x65, 0x76, 0xb4, 0x6e, 0x90, 0x4d, 0xc8, 0x5e, 0x8c, 0xf2, 0x90, 0x40, 0x00, 0x00, 0x00, 0x00,
};

// `ComputeBudget111111111111111111111111111111`
const COMPUTE_BUDGET_ID: Pubkey32 = .{
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00,
};

// `AddressLookupTab1e1111111111111111111111111`
const ADDRESS_LOOKUP_TABLE_ID: Pubkey32 = .{
    0x02, 0x6e, 0x69, 0x12, 0x6e, 0x40, 0x88, 0xee, 0x4d, 0x10, 0x53, 0x4e, 0xc7, 0xae, 0xb8, 0x69,
    0x4d, 0x9c, 0xc4, 0xb1, 0xfb, 0x55, 0xfd, 0xc8, 0x9d, 0xfd, 0x12, 0x40, 0x00, 0x00, 0x00, 0x00,
};

// `ZkE1Gama1Proof11111111111111111111111111111`
const ZK_ELGAMAL_PROOF_ID: Pubkey32 = .{
    0x10, 0x18, 0x4e, 0xfa, 0x16, 0x05, 0x73, 0x06, 0x14, 0xfb, 0x69, 0x95, 0xa6, 0x55, 0xa6, 0xb7,
    0x70, 0xff, 0x40, 0x80, 0x6f, 0x4b, 0x69, 0x99, 0x46, 0x69, 0x70, 0xc0, 0x00, 0x00, 0x00, 0x00,
};

// Loader pubkeys (from agave-v4.0.0-beta.7/sdk-ids/src/lib.rs) — used for
// loader-blacklist ProgramNotSupported, NOT routed through builtin handler.
const NATIVE_LOADER_ID: Pubkey32 = .{
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
    0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d,
};
const BPF_LOADER_DEPRECATED: Pubkey32 = .{
    0x02, 0xc4, 0x57, 0x21, 0x9b, 0x6c, 0xa8, 0xab, 0x52, 0x09, 0xb4, 0x80, 0x3b, 0x09, 0xe2, 0x65,
    0x95, 0xa6, 0xfe, 0xc1, 0xa1, 0x5b, 0xa1, 0x80, 0x6f, 0x6e, 0x4f, 0xc0, 0x00, 0x00, 0x00, 0x00,
};
const BPF_LOADER_V2: Pubkey32 = .{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0, 0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2, 0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x01, // v2
};

/// Phase-1 Core-BPF Stake (2026-06-16): the `migrate_stake_program_to_core_bpf`
/// feature pubkey (SIMD-0196, base58 `6M4oQ6eXneVhtLoiAr4yRYQY43eVLjrKbiDZDJc892yk`),
/// decoded via the canonical comptime base58 decoder (never hand-type pubkey
/// bytes). Used in the CPI dispatch gate at handleSolInvokeSigned
/// so a stake CPI falls to the recursive .so path when VEX_STAKE_BPF AND the
/// feature is active. Mirrors `features.zig` MIGRATE_STAKE_PROGRAM_TO_CORE_BPF;
/// cpi.zig cannot import vex_svm/features.zig (cycle), hence the local decode.
const MIGRATE_STAKE_PROGRAM_TO_CORE_BPF: Pubkey32 =
    builtins_mod.decodeBase58Pubkey("6M4oQ6eXneVhtLoiAr4yRYQY43eVLjrKbiDZDJc892yk");

/// All seven builtin program ids (stub-routed to M7_BuiltinNotImplemented).
pub fn isBuiltin(pid: Pubkey32) bool {
    return std.mem.eql(u8, &pid, &SYSTEM_PROGRAM_ID) or
        std.mem.eql(u8, &pid, &VOTE_PROGRAM_ID) or
        std.mem.eql(u8, &pid, &STAKE_PROGRAM_ID) or
        std.mem.eql(u8, &pid, &CONFIG_PROGRAM_ID) or
        std.mem.eql(u8, &pid, &COMPUTE_BUDGET_ID) or
        std.mem.eql(u8, &pid, &ADDRESS_LOOKUP_TABLE_ID) or
        std.mem.eql(u8, &pid, &ZK_ELGAMAL_PROOF_ID);
}

/// Loader-blacklist filter. @prov:cpi.module-map
pub fn isLoaderBlacklisted(pid: Pubkey32) bool {
    return std.mem.eql(u8, &pid, &NATIVE_LOADER_ID) or
        std.mem.eql(u8, &pid, &BPF_LOADER_DEPRECATED) or
        std.mem.eql(u8, &pid, &BPF_LOADER_V2);
}

// ──────────────────────────────────────────────────────────────────────────────
// CallerAccount — host-side translated view. @prov:cpi.caller-account
// ──────────────────────────────────────────────────────────────────────────────

/// Host-side translated view of one account-info from the caller's VM.
/// Caches host slices for lamports/owner/data so we can read+write without
/// re-vmap on every step.
pub const CallerAccount = struct {
    pubkey: Pubkey32,
    /// Host slice covering the lamports u64. Length 8.
    lamports_host: []u8,
    /// Host slice covering the owner pubkey. Length 32.
    owner_host: []u8,
    /// Host slice covering the serialized data area (post-realloc-slack).
    data_host: []u8,
    /// Original data length at translate-time (pre-execution).
    original_data_len: usize,
    /// VM addr of the data buffer's first byte (used by writeback to find
    /// the u64 dlen prefix at vm_data_addr - 8).
    vm_data_addr: u64,
    /// VM addr of the lamports field.
    vm_lamports_addr: u64,
    /// VM addr of the owner pubkey.
    vm_owner_addr: u64,
    /// Rust ABI only: VM addr of the Rc<RefCell<&mut [u8]>>'s slice header
    /// (ptr at +0, len at +8). On data growth/shrink we must rewrite the
    /// len so the program's AccountInfo.data slice reflects post-CPI state.
    /// 0 for C ABI (which uses the dlen-prefix at vm_data_addr-8 instead).
    vm_slice_hdr_addr: u64,
    /// Resolved index into the caller's TransactionContext.accounts.
    index_in_caller: u16,
    is_signer: bool,
    is_writable: bool,
};

/// Result of translateInstruction — the caller-supplied target instruction in
/// host-friendly Zig form.
pub const TranslatedInstruction = struct {
    program_id: Pubkey32,
    /// Caller-allocated; freed by handleSolInvokeSigned on exit.
    accounts: []TranslatedAccountMeta,
    data: []u8,
};

pub const TranslatedAccountMeta = struct {
    pubkey: Pubkey32,
    is_signer: bool,
    is_writable: bool,
};

/// Per-account state carried from translation through post-execute writeback.
/// @prov:cpi.translated-account
///
/// Why this exists (cpi-rebase, 2026-05-13):
/// Pre-rebase, `translateAccountInfos` returned `[]CallerAccount` and the
/// post-execute caller-loop at `handleSolInvokeSigned` ran
/// `updateCallerAccount` for EVERY caller-info unconditionally. That
/// matches a v3.0-era Agave; modern Agave (v4.0.x) gates the update on
/// per-account `update_caller_account_info` derived from whether the
/// caller's CPI metadata marked the account writable. Without the gate,
/// read-only accounts receive a writeback that can corrupt their bytes if
/// the inner CPI's writeback to `ctx.tx.accounts[idx]` happened to land
/// non-canonical bytes there (the d28ff-class regression).
///
/// ⚠ FOOTGUN: `update_caller_account_region` was once "intentionally omitted"
/// here (project_cpi_rebase_fd4ad0b1bbe_2026_05_13.md, on the theory that
/// Vexor's per-frame fresh-region model made it unnecessary). That decision
/// was REFUTED by carrier @412589216 (2026-06-03): under direct mapping an
/// inner CPI that grows a writable account (System::CreateAccount 0→168) moves
/// the data buffer, but the CALLER's input_mem_region kept its stale
/// region_sz/haddr → the outer program (PFD) AccessViolated (pc=3982) → the
/// dispatch M4_RunFailed before §7 → the created account was DROPPED →
/// bank_hash divergence. It is now ported as `updateCallerAccount` step 7
/// (region repoint) — see that function. Do NOT remove it.
///
/// `update_caller_account_info` defaults to the per-account `is_writable`
/// at translate time. Inner-CPI's writeback step can FORCE it to true (e.g.
/// on detected ownership change of a nominally-read-only account) by
/// setting `caller_must_update_info_on_return = true`. @prov:cpi.translated-account
pub const TranslatedAccount = struct {
    /// Index into the caller's TransactionContext.accounts (== caller_account.index_in_caller).
    index_in_caller: u16,
    /// Host-side translated view (lamports/owner/data slices + vm addrs).
    caller_account: CallerAccount,
    /// Whether to call `updateCallerAccount` on this account at CPI exit.
    /// Default = caller-side `is_writable`. May be flipped to true mid-CPI
    /// when inner-frame writeback detects ownership change.
    update_caller_account_info: bool,
};

// ──────────────────────────────────────────────────────────────────────────────
// Program resolver callback
// ──────────────────────────────────────────────────────────────────────────────
//
// M7 needs a way to obtain a verified+ELF-loaded `Executable` for the callee
// program WITHOUT taking a hard dep on a program cache module (none of M1-M5
// or M8 owns such a cache, and the brief is explicit that we don't extend
// locked APIs). The M6 syscall wiring (or test harness) supplies this when
// it constructs `handleSolInvokeSigned`'s closure.
//
// The resolver returns either an Executable to recurse into, or `null` to
// mean "not BPF" — in which case M7 falls through to the builtin dispatch.
//
// Lifetime contract: the returned `*const Executable` MUST outlive the M7
// recursive call (the cache owns it; we just borrow).

pub const ProgramResolver = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        resolve: *const fn (ctx: *anyopaque, pid: Pubkey32) ?*const elf_mod.Executable,
    };
    pub inline fn resolve(self: ProgramResolver, pid: Pubkey32) ?*const elf_mod.Executable {
        return self.vtable.resolve(self.ctx, pid);
    }
};

// ──────────────────────────────────────────────────────────────────────────────
// CPI privilege application — CARRIER #19 FIX (2026-06-12, @414926949/414968444)
// ──────────────────────────────────────────────────────────────────────────────
//
// @prov:cpi.privilege-merge — the callee's instruction accounts are
// DEDUPLICATED per transaction account and their privilege flags OR-MERGED
// across ALL meta occurrences — then the merged flags are back-propagated to
// every duplicate position. Net effect: every position of a duplicated
// account sees the OR of all its metas' flags, so a flattened per-tx-account
// flag view (ours) is exactly representable — PROVIDED duplicates merge.
//
// THE CARRIER: the pre-fix loop OVERWROTE flags per occurrence (last meta
// wins). torX BuyExact's inner self-transfer (from == to == payer; metas
// [signer=1,writable=1], [signer=0,writable=1], both → same tx account)
// ended with is_signer=FALSE → System::Transfer returned
// MissingRequiredSignature → M4_RunFailed → 99M-lamport write dropped →
// accounts_lt_hash divergence (slots 414926949+, cluster-attested DIFFER) →
// delinquency. The cluster (Agave OR-merge: 1|0 = 1) executes it fine.
//
// `saved_flags[mi]` is written ONLY at each account's FIRST occurrence (the
// pre-CPI flags); restore consults the same first-occurrence mask, so the
// caller's flags round-trip exactly even with duplicates.

pub const SavedFlag = packed struct { signer: bool, writable: bool };

/// Apply the inner instruction's account-meta privileges onto the flattened
/// tx-account views, OR-merging duplicate occurrences (Agave-exact).
pub fn applyCpiPrivileges(
    tx_accounts: []AccountView,
    account_indices: []const u16,
    metas: []const TranslatedAccountMeta,
    saved_flags: *[MAX_ACCOUNTS_PER_INSTRUCTION]SavedFlag,
) void {
    for (metas, 0..) |meta, mi| {
        if (mi >= account_indices.len) break;
        const tx_idx = account_indices[mi];
        const a = &tx_accounts[tx_idx];
        if (InvokeContext.isFirstOccurrence(account_indices, mi)) {
            saved_flags[mi] = .{ .signer = a.is_signer, .writable = a.is_writable };
            a.is_signer = meta.is_signer;
            a.is_writable = meta.is_writable;
        } else {
            a.is_signer = a.is_signer or meta.is_signer;
            a.is_writable = a.is_writable or meta.is_writable;
        }
    }
}

/// Restore the caller's pre-CPI privileges; first-occurrence entries only
/// (duplicates' saved_flags slots are undefined by construction).
pub fn restoreCpiPrivileges(
    tx_accounts: []AccountView,
    account_indices: []const u16,
    saved_flags: *const [MAX_ACCOUNTS_PER_INSTRUCTION]SavedFlag,
) void {
    for (account_indices, 0..) |tx_idx, mi| {
        if (!InvokeContext.isFirstOccurrence(account_indices, mi)) continue;
        const a = &tx_accounts[tx_idx];
        a.is_signer = saved_flags[mi].signer;
        a.is_writable = saved_flags[mi].writable;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API entry (called by M6's sol_invoke_signed_c / _rust handlers)
// ──────────────────────────────────────────────────────────────────────────────

/// Top-level CPI entry. @prov:cpi.module-map
/// Returns the inner program's r0 (SUCCESS=0) or a CpiError.
pub fn handleSolInvokeSigned(
    ctx: *InvokeContext,
    abi: Abi,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    mm: *AlignedMemoryMap,
    /// M6/test-harness supplies this. May be null only when the target is a
    /// builtin (System, Vote, Stake, etc.); BPF targets without a resolver
    /// surface M7_RecursiveLoadFailed.
    resolver: ?ProgramResolver,
    /// SyscallRegistry to forward into the recursive Vm. M6 owns construction.
    syscalls: interpreter.SyscallRegistry,
) CpiError!u64 {
    trace("handleSolInvokeSigned(abi={}, ix=0x{x}, ai_len={}, ss_len={})", .{
        abi, instruction_addr, account_infos_len, signers_seeds_len,
    });

    // Step 0 (P0 CU-parity fix, 2026-07-12): flat per-CPI-call charge, FIRST,
    // before any translation. @prov:cpi.invoke-units — charged
    // even if every subsequent step fails (Agave charges unconditionally at
    // entry; matches "consumed N of N" on exhaustion mid-CPI-setup too).
    ctx.consumeCompute(INVOKE_UNITS) catch return CpiError.M7_OutOfCompute;

    // Step 1: translate instruction → host form
    const tix = translateInstruction(ctx, abi, instruction_addr, mm) catch |err| {
        trace("translateInstruction -> err={s}", .{@errorName(err)});
        return err;
    };
    defer ctx.allocator.free(tix.accounts);
    defer ctx.allocator.free(tix.data);
    trace("translateInstruction.ok program_id_first_byte=0x{x} accts={} data={}", .{
        tix.program_id[0], tix.accounts.len, tix.data.len,
    });

    // Step 2: PDA-derived signer pubkeys
    const caller_pid_opt = ctx.currentProgramId();
    const caller_pid = caller_pid_opt orelse {
        if (g_cpi_mm_dumps < 8) {
            g_cpi_mm_dumps += 1;
            std.log.warn("[V2-CPI-MM] caller_pid is null (no current program on instruction stack)", .{});
        }
        return CpiError.M7_AccountNotInTransaction;
    };
    const signers = try translateSigners(ctx, abi, caller_pid, signers_seeds_addr, signers_seeds_len, mm);
    defer ctx.allocator.free(signers);
    trace("translateSigners.ok n={}", .{signers.len});

    // Step 3: loader-blacklist + precompile rejection
    if (isLoaderBlacklisted(tix.program_id)) {
        trace("check_authorized_program -> ProgramNotSupported", .{});
        return CpiError.M7_ProgramNotSupported;
    }

    // Step 4: translate caller account-infos (build CallerAccount[])
    const callers = try translateAccountInfos(ctx, abi, account_infos_addr, account_infos_len, mm);
    defer ctx.allocator.free(callers);
    trace("translateAccountInfos.ok n={}", .{callers.len});

    // Step 5: enforce signer-marks for PDAs.
    // r75-bug-class-b-pda-signer (2026-05-06): the is_signer truth source
    // is the inner instruction's AccountMeta list (`tix.accounts`), NOT the
    // BPF program's AccountInfo (`callers`). The program declares which
    // accounts SIGN the inner ix via the AccountMeta.is_signer flag;
    // AccountInfo.is_signer reflects whether that account signed the OUTER
    // tx (which a PDA being created cannot — it has no keypair).
    //
    // Anchor `init` constraint passes the new PDA as AccountMeta.is_signer=
    // TRUE (the program signs on its behalf via signers_seeds), but the
    // outer AccountInfo.is_signer=FALSE. Without this fix, V2 returned
    // M7_PdaNotASigner on every InitializePriorityFeeDistributionAccount →
    // tx revert → Vexor missed PFDA PDA inits from slot 345 onwards.
    try enforcePdaSigners(tix.accounts, signers);

    // Step 6: build account_indices for the callee frame.
    // We pin every caller-listed pubkey to its index in tx.accounts; the M7 CPI
    // requires that every CPI-passed account already exists in the caller's
    // transaction. (Agave's `instruction_account.index_in_transaction` shape.)
    const account_indices = buildAccountIndices(ctx, tix.accounts) catch |e| {
        if (e == CpiError.M7_AccountNotInTransaction) dumpCpiMismatch(ctx, tix.program_id, tix.accounts);
        return e;
    };
    defer ctx.allocator.free(account_indices);

    // FIX 5b/5c (cpi-invoke-units-cu-parity, 2026-07-12). @prov:cpi.per-account-data
    // PER instruction account (first occurrence only; agave skips
    // `is_instruction_account_duplicate` accounts, mirrored here via
    // `isFirstOccurrence` on `account_indices`, the same de-dup key Agave
    // uses via `instruction_account.index_in_transaction`):
    //   • executable instruction account: charge
    //     `callee_account.get_data().len() / cpi_bytes_per_unit` — using the
    //     CANONICAL on-chain data length (ctx.tx.accounts[tx_idx].data),
    //     not any caller-supplied AccountInfo.
    //   • non-executable instruction account with a matching caller-
    //     supplied AccountInfo, gated on `syscall_parameter_address_restrictions`
    //     (ctx.syscall_param_addr_restrict_active — Vexor's live-tracked
    //     mirror of that feature, set from the real feature set in
    //     v2_dispatch.zig, not hardcoded): charge
    //     `(*caller_account.ref_to_len_in_vm) / cpi_bytes_per_unit`; Vexor's
    //     `CallerAccount.original_data_len` is the same value at this point
    //     (both are the account's data length as observed at CPI-translate
    //     time, before any realloc). This is purely additive: an
    //     instruction account with no matching AccountInfo is left
    //     un-charged here (Agave hard-errors MissingAccount in that case —
    //     out of scope for this CU-parity fix; not introducing new failure
    //     paths).
    for (account_indices, 0..) |tx_idx, mi| {
        if (!InvokeContext.isFirstOccurrence(account_indices, mi)) continue;
        if (tx_idx >= ctx.tx.accounts.len) continue;
        const acct = &ctx.tx.accounts[tx_idx];
        if (acct.executable) {
            const data_len: u64 = @intCast(acct.data.len);
            const amount = if (CPI_BYTES_PER_UNIT == 0) std.math.maxInt(u64) else data_len / CPI_BYTES_PER_UNIT;
            ctx.consumeCompute(amount) catch return CpiError.M7_OutOfCompute;
        } else if (ctx.syscall_param_addr_restrict_active) {
            for (callers) |c| {
                if (c.caller_account.index_in_caller != tx_idx) continue;
                const len_val: u64 = @intCast(c.caller_account.original_data_len);
                const amount = if (CPI_BYTES_PER_UNIT == 0) std.math.maxInt(u64) else len_val / CPI_BYTES_PER_UNIT;
                ctx.consumeCompute(amount) catch return CpiError.M7_OutOfCompute;
                break;
            }
        }
    }

    // Resolve target program_idx in tx.accounts — for builtins we still need a
    // valid program slot in the stack frame, so we look it up; if the caller
    // forgot to pass program_id as an account we surface AccountNotInTransaction.
    const program_idx = findAccountIndex(ctx, tix.program_id) orelse {
        trace("program_id not in tx.accounts -> AccountNotInTransaction", .{});
        dumpCpiMismatch(ctx, tix.program_id, tix.accounts);
        return CpiError.M7_AccountNotInTransaction;
    };

    // Step 7: push frame (M8 enforces MAX_INSTRUCTION_STACK_DEPTH=5 + snapshots)
    ctx.push(program_idx, account_indices) catch |err| switch (err) {
        error.CallDepthExceeded => return CpiError.M7_DepthExceeded,
        error.InvalidIndex => return CpiError.M7_AccountNotInTransaction,
        error.OutOfMemory => return CpiError.M7_OutOfMemory,
        // M8 push() can technically also surface other InvokeError variants
        // (compute/sysvar/etc.) — none of those originate from push() today,
        // but the error set is unioned at the type level. Map them all to a
        // recursive-load failure so we never silently drop an unknown error.
        else => return CpiError.M7_RecursiveLoadFailed,
    };
    trace("ctx.push.ok depth={}", .{ctx.currentDepth()});

    // r75-bug-class-b-inner-meta-flags (2026-05-06): for the duration of the
    // inner frame, override tx.accounts[idx].is_signer/is_writable with the
    // INNER instruction's AccountMeta flags (`tix.accounts[i]`). Otherwise
    // builtin handlers (e.g. System::CreateAccount checking
    // `to.is_signer`) read the OUTER tx flags — which for a fresh PDA
    // being created via Anchor `init` are FALSE (no outer keypair signed
    // for it), even though the inner ix's AccountMeta sets is_signer=TRUE
    // (Anchor's claim of program-signing via signers_seeds).
    //
    // Save the old flags into a stack slot so we can restore on pop. Cap at
    // MAX_ACCOUNTS_PER_INSTRUCTION (Solana's limit) so this is bounded
    // stack memory. We restore via `defer` so any error path also restores.
    var saved_flags: [MAX_ACCOUNTS_PER_INSTRUCTION]SavedFlag = undefined;
    const n_inner = tix.accounts.len;
    applyCpiPrivileges(ctx.tx.accounts, account_indices[0..n_inner], tix.accounts, &saved_flags);
    defer restoreCpiPrivileges(ctx.tx.accounts, account_indices[0..n_inner], &saved_flags);

    // From here on, every error path must `pop` to keep the stack balanced.
    var inner_r0: u64 = 0;
    var dispatch_err: ?CpiError = null;

    // Step 8: dispatch
    //
    // M9 wireup (2026-04-27): builtin programs route to the comptime-decoded
    // pubkey table in `builtins/mod.zig` and dispatch into the per-program
    // execute() handler. This covers the live testnet hole where BPF programs
    // (priority-fee-distribution, ATokenG.Create-via-Allocate-then-Assign-then-
    // Transfer chains, etc.) issue System.Transfer / System.Assign /
    // System.Allocate inner CPIs. The mutations land directly on
    // `ctx.tx.accounts[...]`; the writeback in step 10 propagates them to the
    // caller's BPF AccountInfo memory.
    //
    // Failure path: ANY builtin error (parse failure, VariantPending for
    // unported variants, MissingRequiredSignature, InsufficientFunds, …) is
    // logged via std.log.warn so the inner BuiltinError name is visible in
    // production logs (the legacy `trace()` shim is silent at the default
    // on_error level), then mapped onto a single umbrella `M7_BuiltinFailed`
    // CpiError variant. We deliberately do NOT widen CpiError to include the
    // full BuiltinError set — callers (syscalls.zig solInvokeSigned) already
    // narrow to `M6_CpiHandlerNotReady` and the trace line carries the detail.
    //
    // We keep using `builtins_mod.isBuiltin` (comptime base58 decode) instead
    // of cpi.zig's local hand-typed table — the local table violated the
    // never-hand-type-pubkey-bytes rule; the comptime path is the single
    // source of truth.
    // ── Phase-1 Core-BPF Stake CPI seam (feature-gated, env DEFAULT-OFF) ──
    // When VEX_STAKE_BPF is ON *and* the migrate feature is active, EXCLUDE
    // stake from the builtin branch so it falls to the `resolver`
    // (recursiveExecute) path — i.e. the on-chain stake v5 .so resolved from
    // accounts-db like any SPL program. ENV-FIRST (the flag is the first
    // operand) so when OFF the `ctx.feature_active` hook is never dereferenced
    // and routing is byte-identical to current (native builtin path). FAIL-
    // CLOSED: if the feature_active hook is unwired (null), stay builtin.
    // HARDEN-2 (2026-06-16): read `ctx.stake_bpf_active` — set in
    // v2_dispatch.zig from the SAME live FeatureSet + slot the TOP-LEVEL gate
    // (replay_stage.executeStakeInstruction:10901) reads — instead of the
    // never-wired `feature_active` hook (which was always null → CPI stayed
    // native even when top-level routed to the .so = split-brain). Now a stake
    // ix and a stake CPI in the same tx/slot resolve the migrate gate
    // IDENTICALLY. ENV-FIRST: the flag is the first operand so when OFF
    // (default) `ctx.stake_bpf_active` is never read and routing is
    // byte-identical to current (native builtin path). `stake_bpf_active`
    // itself ALSO folds in `enabled()` (fail-closed) — belt and suspenders.
    const route_stake_bpf = vex_bpf2_stake_flag.enabled() and
        std.mem.eql(u8, &tix.program_id, &builtins_mod.STAKE_PROGRAM_ID) and
        ctx.stake_bpf_active;

    // GATE-COUNTER (2026-06-16): prove the CPI stake ON-path actually fired.
    if (route_stake_bpf) {
        const Seam = struct {
            var n: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
        };
        const c = Seam.n.fetchAdd(1, .monotonic) + 1;
        if (c <= 8 or c % 50 == 0) {
            const disc: u32 = if (tix.data.len >= 4) std.mem.readInt(u32, tix.data[0..4], .little) else 0xFFFF;
            std.log.warn("[STAKE-BPF-SEAM] CPI stake ON-path fired count={d} disc={d}", .{ c, disc });
        }
    }

    // ── F3 Core-BPF ALT CPI seam (feature-gated, 2026-07-01) ──────────────
    // On the cluster (Agave 4.1.0 + FD v0.1004) the Address Lookup Table
    // program is Core-BPF-migrated (SIMD-0128, ACTIVE on testnet, FD
    // cleaned_up=1): a CPI into AddressLookupTab1e111… executes the ON-CHAIN
    // .so and succeeds. Vexor's builtin branch used to short-circuit it into
    // the M9 VariantPending stub → M7_BuiltinFailed → dropped ALT mutation →
    // guaranteed bank_hash divergence (finding F3). Mirror route_stake_bpf:
    // when the migrate feature is active (ctx.alt_bpf_active, threaded in
    // v2_dispatch.zig from the SAME live FeatureSet + slot as every other
    // gate — @prov:cpi.alt-bpf-seam per-slot semantics), EXCLUDE ALT from the builtin branch so the CPI
    // falls through to the `resolver` (recursiveExecute) path — the on-chain
    // ALT .so resolved from the V2 program cache (prewarmCalleeProgram
    // handles the migrated owner=BPFLoaderUpgradeable/state=2 account shape)
    // like any SPL program. UNLIKE stake there is NO env flag: ALT-CPI has no
    // working native fallback (all 13 M9 returns are VariantPending), so the
    // feature gate alone decides. FAIL-CLOSED: alt_bpf_active defaults false
    // (unit fixtures / no real FeatureSet / pre-activation slot) → builtin
    // branch → M9 stub, byte-identical to legacy. Worst-case post-fix failure
    // (resolver miss → M7_RecursiveLoadFailed, fail-LOUD via [V2-CPI-RLF]) is
    // no worse than the M7_BuiltinFailed it replaces. TOP-LEVEL ALT dispatch
    // (replay_stage.executeAltInstruction, native) is untouched.
    const route_alt_bpf =
        std.mem.eql(u8, &tix.program_id, &builtins_mod.ADDRESS_LOOKUP_TABLE_PROGRAM_ID) and
        ctx.alt_bpf_active;

    // GATE-COUNTER: prove the CPI ALT ON-path actually fired live.
    if (route_alt_bpf) {
        const Seam = struct {
            var n: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
        };
        const c = Seam.n.fetchAdd(1, .monotonic) + 1;
        if (c <= 8 or c % 50 == 0) {
            const disc: u32 = if (tix.data.len >= 4) std.mem.readInt(u32, tix.data[0..4], .little) else 0xFFFF;
            std.log.warn("[ALT-BPF-SEAM] CPI ALT ON-path fired count={d} disc={d}", .{ c, disc });
        }
    }

    // ── CPI caller→callee SYNC-IN (canonical `update_callee_account`) ──────
    // Carrier fix (execution divergence slot 419786141, 2026-07-04). BEFORE
    // any inner-instruction execution, copy the caller's CURRENT AccountInfo
    // lamports+owner (the outer BPF program's mid-instruction writes, living in
    // the VM input region = `CallerAccount.lamports_host/owner_host`) INTO the
    // callee transaction-context account (`ctx.tx.accounts[idx]`). This is the
    // read-your-writes guarantee: when an outer program directly credits an
    // account's lamports and then `invoke_signed`→System::Transfer FROM it, the
    // System builtin must see the credited (current) balance — not the stale
    // pre-CPI value loaded from the DB. Vexor had ONLY the inverse
    // (`updateCallerAccount`, callee→caller writeback at Step 10); THIS sync-in
    // was never present, so `system_program.zig:315` (`lamports > from.lamports`)
    // read a stale `ctx.tx.accounts[from].lamports`, returned
    // `M9_System_InsufficientFunds`, and rolled back a tx the cluster COMMITS →
    // bank_hash divergence (79:79 InsufficientFunds↔rollback correlation).
    //
    // CANONICAL (RULE #16 three-way): @prov:cpi.update-callee-account
    //
    // SCOPE = lamports + owner ONLY. The System-transfer carrier needs lamports;
    // owner is the canonical belt-and-suspenders (Assign-then-CPI read-your-
    // writes). The DATA sync-in is DELIBERATELY DEFERRED — the Step-10 writeback's
    // data/realloc path carries the hard-won d28ff regression landmines and its
    // inverse would too; the full-slot offline gate (419786141: OLD reproduces
    // 9838329b, FIXED == cluster canonical AND matches the exact 100-commit/28-
    // fail tx pattern) is the arbiter of whether a data sync-in is ever needed.
    //
    // FILTERS (match Agave): skip non-writable (immutable ⇒ pre==post),
    // executable (never write a program account), and duplicates (first
    // occurrence only — aliased duplicates hold the same current value, so this
    // is idempotent and canonical). NO-OP in the common case (caller==callee),
    // so the ~2767 pre-carrier clean slots are byte-unaffected. Placed BEFORE the
    // dispatch/resolver/recursive branches so it covers every inner-exec path,
    // and before the inner frame's lamport-conservation snapshot is captured
    // (mirrors Agave running it before `process_instruction`).
    for (callers, 0..) |tacc, ci| {
        const ca = &tacc.caller_account;
        if (!ca.is_writable) continue;
        const sidx = ca.index_in_caller;
        if (sidx >= ctx.tx.accounts.len) continue;
        if (ctx.tx.accounts[sidx].executable) continue;
        // first-occurrence dedup (canonical; idempotent for aliased duplicates).
        var is_dup = false;
        for (callers[0..ci]) |prev| {
            if (prev.caller_account.index_in_caller == sidx) {
                is_dup = true;
                break;
            }
        }
        if (is_dup) continue;
        const acc = &ctx.tx.accounts[sidx];
        // (1) lamports — read-your-writes; conditional (agave cpi.rs set_lamports).
        const caller_lamports = std.mem.readInt(u64, ca.lamports_host[0..8], .little);
        if (acc.lamports != caller_lamports) {
            const SyncProbe = struct {
                var n: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
            };
            const sn = SyncProbe.n.fetchAdd(1, .monotonic);
            if (sn < 40) {
                const pk_short = std.fmt.bytesToHex(acc.pubkey[0..8], .lower);
                std.log.warn(
                    "[CPI-CALLEE-SYNC] idx={d} pk={s} stale_lamports={d} caller_lamports={d} inner_pid_first=0x{x} (read-your-writes sync-in)",
                    .{ sidx, &pk_short, acc.lamports, caller_lamports, tix.program_id[0] },
                );
            }
            acc.lamports = caller_lamports;
        }
        // (2) owner — canonical; conditional (agave cpi.rs set_owner).
        if (!std.mem.eql(u8, &acc.owner, ca.owner_host[0..32])) {
            @memcpy(&acc.owner, ca.owner_host[0..32]);
        }
    }

    if (!route_stake_bpf and !route_alt_bpf and builtins_mod.isBuiltin(&tix.program_id)) {
        trace("dispatch.builtin pid_first=0x{x}", .{tix.program_id[0]});
        // PR-5af-probe (2026-05-19): Carrier J diagnosis. Log every successful
        // builtin dispatch. Rate-limited threadlocal counter — first 40 only.
        // Captures inner_pid_first, IX variant (first 4 bytes of data as u32),
        // and outer program context to identify which CPI variant fires for
        // HJT-6009 CopyIsBamConnected → the "63 missing writes" carrier.
        const BuiltinProbe = struct {
            var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
        };
        const bn = BuiltinProbe.count.fetchAdd(1, .monotonic);
        if (bn < 40) {
            const variant_tag: u32 = if (tix.data.len >= 4)
                std.mem.readInt(u32, tix.data[0..4], .little)
            else
                0;
            const outer_pid_first: u8 = if (ctx.currentProgramId()) |pid| pid[0] else 0;
            std.log.warn(
                "[PR5AF-BUILTIN-PROBE n={d}] outer_pid_first=0x{x} inner_pid_first=0x{x} variant=0x{x} data_len={d} accts={d}",
                .{ bn, outer_pid_first, tix.program_id[0], variant_tag, tix.data.len, tix.accounts.len },
            );
        }
        if (builtins_mod.dispatch(ctx, &tix.program_id, tix.data)) {
            // success path: inner_r0 stays 0; writeback fires in step 10.
            // PR-5aj-probe (2026-05-20): Carrier J MM-staleness detector.
            // After successful builtin (e.g. System::CreateAccount/Allocate),
            // compare each writable callee account's data_host.ptr (caller's
            // MM-region buffer ptr at translate time) vs the canonical buffer
            // ptr now in ctx.tx.accounts[idx].data.ptr. Divergence ⇒ the
            // builtin freed+realloc'd the buffer but didn't update the caller
            // MM region → subsequent BPF reads/writes hit a stale buffer and
            // silently no-op the writeback. Matches Carrier J "63 missing
            // accounts" shape per per-pk diff.
            const PtrDiffProbe = struct {
                var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
            };
            for (callers) |t| {
                if (!t.caller_account.is_writable) continue;
                const idx = t.caller_account.index_in_caller;
                if (idx >= ctx.tx.accounts.len) continue;
                const callee_data = ctx.tx.accounts[idx].data;
                const callee_ptr: usize = if (callee_data.len > 0) @intFromPtr(callee_data.ptr) else 0;
                const caller_data = t.caller_account.data_host;
                const caller_ptr: usize = if (caller_data.len > 0) @intFromPtr(caller_data.ptr) else 0;
                if (caller_ptr != callee_ptr or caller_data.len != callee_data.len) {
                    const pn = PtrDiffProbe.count.fetchAdd(1, .monotonic);
                    if (pn < 40) {
                        const outer_pid_first: u8 = if (ctx.currentProgramId()) |pid| pid[0] else 0;
                        const variant_tag: u32 = if (tix.data.len >= 4)
                            std.mem.readInt(u32, tix.data[0..4], .little)
                        else
                            0;
                        const pk_short = std.fmt.bytesToHex(ctx.tx.accounts[idx].pubkey[0..8], .lower);
                        std.log.warn(
                            "[PR5AJ-PTRDIFF n={d}] outer=0x{x} inner=0x{x} variant=0x{x} idx={d} pk={s} caller_ptr=0x{x} callee_ptr=0x{x} caller_len={d} callee_len={d}",
                            .{
                                pn,              outer_pid_first, tix.program_id[0],
                                variant_tag,     idx,             &pk_short,
                                caller_ptr,      callee_ptr,      caller_data.len,
                                callee_data.len,
                            },
                        );
                    }
                }
            }
        } else |err| {
            std.log.warn(
                "[VBPF2-M9] builtins.dispatch failed: pid_first=0x{x} err={s}",
                .{ tix.program_id[0], @errorName(err) },
            );
            // E4 (2026-07-01, latent-carrier batch): a CPI into the VOTE
            // program hits the M9 VariantPending stub (vote_program.zig: every
            // variant returns M9_Vote_VariantPending_*) → M7_BuiltinFailed →
            // Vexor FAILS a tx the cluster COMMITS (vote is a live native
            // builtin on the cluster, CPI-invocable) = known latent
            // divergence. Routing fix deliberately deferred (FallbackContext-
            // into-CPI is structurally unsound — the trampoline re-executes
            // the OUTER ix; real fix = the native M9 vote port). Fail-LOUD,
            // rate-limited like [ALT-BPF-SEAM] above (first 8 + every 50th).
            if (std.mem.eql(u8, &tix.program_id, &builtins_mod.VOTE_PROGRAM_ID)) {
                const VoteStub = struct {
                    var n: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                };
                const vc = VoteStub.n.fetchAdd(1, .monotonic) + 1;
                if (vc <= 8 or vc % 50 == 0) {
                    const slot: u64 = if (ctx.sysvar_cache.clock_view) |ck| ck.slot else 0;
                    const disc: u32 = if (tix.data.len >= 4) std.mem.readInt(u32, tix.data[0..4], .little) else 0xFFFF;
                    std.log.warn(
                        "[CPI-VOTE-STUB-DIVERGENCE] slot={d} count={d} disc={d} err={s} — vote CPI hit M9 stub → M7_BuiltinFailed; cluster commits this tx (latent carrier)",
                        .{ slot, vc, disc, @errorName(err) },
                    );
                }
            }
            dispatch_err = CpiError.M7_BuiltinFailed;
        }
    } else if (resolver) |r| {
        const exe = r.resolve(tix.program_id) orelse {
            trace("resolver.miss -> RecursiveLoadFailed", .{});
            // DIAG (2026-05-31 CPI carrier): name the inner CPI target so we can
            // tell System-mis-read (carrier) from a missing-BPF-ELF (e.g. Token,
            // a fixture-resolver gap). isBuiltin should be TRUE for System.
            const rlf_pidhex = std.fmt.bytesToHex(tix.program_id[0..16], .lower);
            std.log.warn("[V2-CPI-RLF] resolver-miss inner pid={s} accts={d} isBuiltin={}", .{ &rlf_pidhex, tix.accounts.len, builtins_mod.isBuiltin(&tix.program_id) });
            dispatch_err = CpiError.M7_RecursiveLoadFailed;
            ctx.pop();
            return dispatch_err.?;
        };
        // Step 9: recursive Vm.init+run with fresh input region (full BPF→BPF
        // CPI dispatch — see recursiveExecute header for canonical references).
        inner_r0 = recursiveExecute(ctx, exe, &tix.program_id, syscalls, tix.data) catch |err| blk: {
            trace("recursiveExecute -> err={s}", .{@errorName(err)});
            dispatch_err = err;
            break :blk 0;
        };
        trace("recursiveExecute.ok r0={}", .{inner_r0});
    } else {
        trace("no resolver, no builtin -> RecursiveLoadFailed", .{});
        dispatch_err = CpiError.M7_RecursiveLoadFailed;
    }

    // Step 10: writeback (callee → caller).
    //
    // Gated loop (cpi-rebase phase 3+4, 2026-05-13). @prov:cpi.update-caller-account
    //
    // The gate: only run updateCallerAccount when
    // `update_caller_account_info` is true. Default = caller-side
    // is_writable at translate time. Phase 4 OVERRIDE: flip to true if
    // the inner-CPI's writeback changed this account's owner — that's
    // Agave's `out_must_update_caller` semantic.
    // Without the override, an inner-CPI that grants ownership of a
    // nominally read-only account to a new program would leave the
    // caller's vm-mapped owner pointing at stale bytes; later reads
    // would see the OLD owner, and the bank's post-CPI state would
    // diverge from cluster's.
    if (dispatch_err == null) {
        for (callers) |*t| {
            // Ownership-change detection: compare pre-CPI owner (still in
            // the caller's vm-mapped owner_host buffer, because we haven't
            // run updateCallerAccount yet) against post-CPI owner (now in
            // ctx.tx.accounts[idx] courtesy of recursiveExecute step I).
            // If they differ, the inner-CPI changed ownership and we MUST
            // force the writeback even if caller marked the slot read-only.
            const tx_idx = t.caller_account.index_in_caller;
            const post_owner = ctx.tx.accounts[tx_idx].owner;
            const pre_owner_bytes = t.caller_account.owner_host[0..32];
            const owner_changed = !std.mem.eql(u8, &post_owner, pre_owner_bytes);

            if (!t.update_caller_account_info and !owner_changed) continue;

            if (owner_changed and !t.update_caller_account_info) {
                trace("[d28-rebase] forced caller update due to inner-CPI owner change idx={}", .{tx_idx});
            }

            updateCallerAccount(ctx, mm, &t.caller_account) catch |err| {
                trace("updateCallerAccount -> err={s}", .{@errorName(err)});
                dispatch_err = err;
                break;
            };
        }
    }

    // Step 11: 5 invariants (M8 owns the post-checks). Skip when recursion
    // never reached the program (load/builtin failure) — there is nothing to
    // post-validate; the pre-snapshot already rolled back nothing because we
    // never wrote anything.
    if (dispatch_err == null) {
        ctx.checkLamportBalance() catch {
            trace("post.lamport_balance -> PostCheckFailed", .{});
            dispatch_err = CpiError.M7_PostCheckFailed;
        };
    }
    if (dispatch_err == null) {
        ctx.checkRentState() catch {
            trace("post.rent -> PostCheckFailed", .{});
            dispatch_err = CpiError.M7_PostCheckFailed;
        };
    }
    if (dispatch_err == null) {
        ctx.checkReadonlyModified() catch {
            trace("post.readonly -> PostCheckFailed", .{});
            dispatch_err = CpiError.M7_PostCheckFailed;
        };
    }
    if (dispatch_err == null) {
        ctx.checkProgramIdModified() catch {
            trace("post.program_id -> PostCheckFailed", .{});
            dispatch_err = CpiError.M7_PostCheckFailed;
        };
    }

    // Step 12: pop (Agave invokes pop unconditionally on CPI exit; we mirror)
    ctx.pop();
    trace("ctx.pop.ok depth={}", .{ctx.currentDepth()});

    if (dispatch_err) |e| return e;
    return inner_r0;
}

// ──────────────────────────────────────────────────────────────────────────────
// Step impls
// ──────────────────────────────────────────────────────────────────────────────

/// Mirror of agave translate_instruction_{c,rust}. @prov:cpi.module-map
/// Returns a heap-allocated TranslatedInstruction; caller frees `accounts` + `data`.
fn translateInstruction(
    ctx: *InvokeContext,
    abi: Abi,
    instruction_addr: u64,
    mm: *AlignedMemoryMap,
) CpiError!TranslatedInstruction {
    return switch (abi) {
        .c => translateInstructionC(ctx, instruction_addr, mm),
        .rust => translateInstructionRust(ctx, instruction_addr, mm),
    };
}

fn translateInstructionC(
    ctx: *InvokeContext,
    instruction_addr: u64,
    mm: *AlignedMemoryMap,
) CpiError!TranslatedInstruction {
    // 1) Read the SolInstruction struct (40 bytes).
    const ix_bytes = mm.vmap(.load, instruction_addr, @sizeOf(SolInstructionC)) catch
        return CpiError.M7_TranslateFailed;
    if (ix_bytes.len < @sizeOf(SolInstructionC)) return CpiError.M7_TranslateFailed;
    const ix: *align(1) const SolInstructionC = @ptrCast(ix_bytes.ptr);

    // 2) Bounds checks (agave check_instruction_size :147).
    if (ix.accounts_len > MAX_ACCOUNTS_PER_INSTRUCTION) return CpiError.M7_TooManyAccounts;
    if (ix.data_len > MAX_INSTRUCTION_DATA_LEN) return CpiError.M7_InstructionTooLarge;

    // 2b) P0 CU-parity fix: instruction-translation byte cost. @prov:cpi.invoke-units
    // — charged from the header lengths, before any further translation work.
    ctx.consumeCompute(cpiTranslationCost(ix.data_len, ix.accounts_len)) catch
        return CpiError.M7_OutOfCompute;

    // 3) Translate program_id (32 bytes).
    const pid_bytes = mm.vmap(.load, ix.program_id_addr, 32) catch
        return CpiError.M7_TranslateFailed;
    var program_id: Pubkey32 = undefined;
    @memcpy(&program_id, pid_bytes[0..32]);

    // 4) Translate account_metas slice.
    const metas_total = std.math.mul(u64, ix.accounts_len, @sizeOf(SolAccountMetaC)) catch
        return CpiError.M7_TranslateFailed;
    const metas_bytes = if (metas_total > 0)
        mm.vmap(.load, ix.accounts_addr, metas_total) catch return CpiError.M7_TranslateFailed
    else
        @as([]u8, &.{});

    var accounts = ctx.allocator.alloc(TranslatedAccountMeta, @intCast(ix.accounts_len)) catch
        return CpiError.M7_OutOfMemory;
    errdefer ctx.allocator.free(accounts);

    var i: usize = 0;
    while (i < ix.accounts_len) : (i += 1) {
        const off = i * @sizeOf(SolAccountMetaC);
        const meta: *align(1) const SolAccountMetaC = @ptrCast(metas_bytes.ptr + off);
        if (meta.is_signer > 1 or meta.is_writable > 1) return CpiError.M7_AbiMismatch;
        const pk_bytes = mm.vmap(.load, meta.pubkey_addr, 32) catch
            return CpiError.M7_TranslateFailed;
        var pk: Pubkey32 = undefined;
        @memcpy(&pk, pk_bytes[0..32]);
        accounts[i] = .{
            .pubkey = pk,
            .is_signer = meta.is_signer != 0,
            .is_writable = meta.is_writable != 0,
        };
    }

    // 5) Translate data bytes (deep copy so the caller can free safely).
    const data_src = if (ix.data_len > 0)
        mm.vmap(.load, ix.data_addr, ix.data_len) catch return CpiError.M7_TranslateFailed
    else
        @as([]u8, &.{});
    const data = ctx.allocator.dupe(u8, data_src) catch return CpiError.M7_OutOfMemory;

    return .{ .program_id = program_id, .accounts = accounts, .data = data };
}

fn translateInstructionRust(
    ctx: *InvokeContext,
    instruction_addr: u64,
    mm: *AlignedMemoryMap,
) CpiError!TranslatedInstruction {
    // 1) Read StableInstruction (Rust): 6×u64 + 32B program_id = 80 bytes.
    const ix_bytes = mm.vmap(.load, instruction_addr, @sizeOf(StableInstructionRust)) catch
        return CpiError.M7_TranslateFailed;
    if (ix_bytes.len < @sizeOf(StableInstructionRust)) return CpiError.M7_TranslateFailed;
    const ix: *align(1) const StableInstructionRust = @ptrCast(ix_bytes.ptr);

    if (ix.accounts_len > MAX_ACCOUNTS_PER_INSTRUCTION) return CpiError.M7_TooManyAccounts;
    if (ix.data_len > MAX_INSTRUCTION_DATA_LEN) return CpiError.M7_InstructionTooLarge;

    // P0 CU-parity fix: instruction-translation byte cost. @prov:cpi.invoke-units
    // — charged from the header lengths, before any further translation work.
    ctx.consumeCompute(cpiTranslationCost(ix.data_len, ix.accounts_len)) catch
        return CpiError.M7_OutOfCompute;

    const program_id: Pubkey32 = ix.program_id;

    const metas_total = std.math.mul(u64, ix.accounts_len, @sizeOf(AccountMetaRust)) catch
        return CpiError.M7_TranslateFailed;
    const metas_bytes = if (metas_total > 0)
        mm.vmap(.load, ix.accounts_addr, metas_total) catch return CpiError.M7_TranslateFailed
    else
        @as([]u8, &.{});

    var accounts = ctx.allocator.alloc(TranslatedAccountMeta, @intCast(ix.accounts_len)) catch
        return CpiError.M7_OutOfMemory;
    errdefer ctx.allocator.free(accounts);

    var i: usize = 0;
    while (i < ix.accounts_len) : (i += 1) {
        const off = i * @sizeOf(AccountMetaRust);
        const meta: *align(1) const AccountMetaRust = @ptrCast(metas_bytes.ptr + off);
        if (meta.is_signer > 1 or meta.is_writable > 1) return CpiError.M7_AbiMismatch;
        accounts[i] = .{
            .pubkey = meta.pubkey,
            .is_signer = meta.is_signer != 0,
            .is_writable = meta.is_writable != 0,
        };
    }

    const data_src = if (ix.data_len > 0)
        mm.vmap(.load, ix.data_addr, ix.data_len) catch return CpiError.M7_TranslateFailed
    else
        @as([]u8, &.{});
    const data = ctx.allocator.dupe(u8, data_src) catch return CpiError.M7_OutOfMemory;

    return .{ .program_id = program_id, .accounts = accounts, .data = data };
}

/// Mirror of agave translate_account_infos + the C/Rust dispatch.
/// @prov:cpi.caller-account
///
/// Returns `[]TranslatedAccount` (cpi-rebase 2026-05-13): each entry wraps a
/// `CallerAccount` with the per-account `update_caller_account_info` gate
/// derived from the caller-side `is_writable` at translate time. The gate
/// is consulted by step 10 in `handleSolInvokeSigned` to skip the
/// `updateCallerAccount` writeback for accounts the caller did NOT mark
/// writable — preventing pre-rebase behavior where the writeback could
/// silently corrupt a read-only buffer with non-canonical bytes that the
/// inner-CPI writeback (`recursiveExecute:1247-1265`) had left in
/// `ctx.tx.accounts[idx]`.
fn translateAccountInfos(
    ctx: *InvokeContext,
    abi: Abi,
    addr: u64,
    len: u64,
    mm: *AlignedMemoryMap,
) CpiError![]TranslatedAccount {
    if (len > MAX_CPI_ACCOUNT_INFOS) return CpiError.M7_TooManyAccounts;

    // FIX 5a: @prov:cpi.per-account-data — once per CPI, before any per-account
    // translation: (len * ACCOUNT_INFO_BYTE_SIZE(80)) / cpi_bytes_per_unit(250).
    const account_infos_bytes = std.math.mul(u64, len, ACCOUNT_INFO_BYTE_SIZE) catch std.math.maxInt(u64);
    const account_infos_cost = if (CPI_BYTES_PER_UNIT == 0)
        std.math.maxInt(u64)
    else
        account_infos_bytes / CPI_BYTES_PER_UNIT;
    ctx.consumeCompute(account_infos_cost) catch return CpiError.M7_OutOfCompute;

    const elem_sz: u64 = switch (abi) {
        .c => @sizeOf(SolAccountInfoC),
        .rust => @sizeOf(AccountInfoRust),
    };
    const total = std.math.mul(u64, len, elem_sz) catch return CpiError.M7_TranslateFailed;

    const infos = if (total > 0)
        mm.vmap(.load, addr, total) catch return CpiError.M7_TranslateFailed
    else
        @as([]u8, &.{});

    var out = ctx.allocator.alloc(TranslatedAccount, @intCast(len)) catch
        return CpiError.M7_OutOfMemory;
    errdefer ctx.allocator.free(out);

    var i: usize = 0;
    while (i < len) : (i += 1) {
        const off = i * @as(usize, @intCast(elem_sz));
        const ca: CallerAccount = switch (abi) {
            .c => try translateOneInfoC(ctx, mm, @ptrCast(infos.ptr + off)),
            .rust => try translateOneInfoRust(ctx, mm, @ptrCast(infos.ptr + off)),
        };
        out[i] = .{
            .index_in_caller = ca.index_in_caller,
            .caller_account = ca,
            // Agave canonical default: update_caller_account_info matches
            // caller-side is_writable. Inner-CPI's writeback step may
            // flip this true if it detects ownership change of a
            // nominally read-only account (phase 4 wires that path).
            .update_caller_account_info = ca.is_writable,
        };
    }
    return out;
}

fn translateOneInfoC(
    ctx: *InvokeContext,
    mm: *AlignedMemoryMap,
    info: *align(1) const SolAccountInfoC,
) CpiError!CallerAccount {
    if (info.is_signer > 1 or info.is_writable > 1 or info.executable > 1)
        return CpiError.M7_AbiMismatch;

    const pk_bytes = mm.vmap(.load, info.key_addr, 32) catch return CpiError.M7_TranslateFailed;
    var pk: Pubkey32 = undefined;
    @memcpy(&pk, pk_bytes[0..32]);

    const owner_bytes = mm.vmap(.load, info.owner_addr, 32) catch
        return CpiError.M7_TranslateFailed;

    const lamports_bytes = mm.vmap(.load, info.lamports_addr, 8) catch
        return CpiError.M7_TranslateFailed;

    if (info.data_len > MAX_PERMITTED_DATA_INCREASE * 1024) return CpiError.M7_TranslateFailed;
    const data_bytes = if (info.data_len > 0)
        mm.vmap(.load, info.data_addr, info.data_len) catch return CpiError.M7_TranslateFailed
    else
        @as([]u8, &.{});

    const idx = findAccountIndex(ctx, pk) orelse return CpiError.M7_AccountNotInTransaction;

    // PR-5c (SIMD-0459): validate that the BPF program passed AccountInfo
    // pointers matching what the serializer emitted in MODE 2/3 input regions.
    // `acc_region_metas` is indexed by the caller-instruction account position,
    // not the txn-level account index (cpi_common.c:324 → `index_in_caller`).
    // Map our txn-level idx through the current frame's account_indices to get
    // the caller-relative position before indexing acc_region_metas.
    if (ctx.syscall_param_addr_restrict_active) {
        if (ctx.instruction_stack.current()) |frame| {
            for (frame.account_indices, 0..) |aidx, caller_idx| {
                if (aidx != idx) continue;
                if (caller_idx >= mm.acc_region_metas.len) break;
                const acc_meta = mm.acc_region_metas[caller_idx];
                if (info.key_addr != acc_meta.vm_key_addr) return CpiError.M7_AbiMismatch;
                if (info.owner_addr != acc_meta.vm_owner_addr) return CpiError.M7_AbiMismatch;
                if (info.lamports_addr != acc_meta.vm_lamports_addr) return CpiError.M7_AbiMismatch;
                break;
            }
        }
    }

    return .{
        .pubkey = pk,
        .lamports_host = lamports_bytes,
        .owner_host = owner_bytes,
        .data_host = data_bytes,
        .original_data_len = @intCast(info.data_len),
        .vm_data_addr = info.data_addr,
        .vm_lamports_addr = info.lamports_addr,
        .vm_owner_addr = info.owner_addr,
        .vm_slice_hdr_addr = 0, // C ABI: dlen is at vm_data_addr - 8
        .index_in_caller = idx,
        .is_signer = info.is_signer != 0,
        .is_writable = info.is_writable != 0,
    };
}

fn translateOneInfoRust(
    ctx: *InvokeContext,
    mm: *AlignedMemoryMap,
    info: *align(1) const AccountInfoRust,
) CpiError!CallerAccount {
    if (info.is_signer > 1 or info.is_writable > 1 or info.executable > 1)
        return CpiError.M7_AbiMismatch;

    const pk_bytes = mm.vmap(.load, info.key_addr, 32) catch return CpiError.M7_TranslateFailed;
    var pk: Pubkey32 = undefined;
    @memcpy(&pk, pk_bytes[0..32]);

    const owner_bytes = mm.vmap(.load, info.owner_addr, 32) catch
        return CpiError.M7_TranslateFailed;

    // d28cc fix (2026-05-12): Rc<RefCell<&mut u64>> requires a DOUBLE translate.
    //
    // The Rust AccountInfo's lamports field is `Rc<RefCell<&mut u64>>` — note the
    // `&mut u64`, not bare `u64`. The slot at lamports_box_addr + RC_VALUE_OFFSET + 8
    // holds an 8-byte VM POINTER to the actual u64 lamports value (which lives in
    // the input region). Vexor previously read these 8 bytes and treated them as the
    // lamports value; the writeback in updateCallerAccount then overwrote that
    // pointer with the post-CPI lamports u64 → on the next BPF deref of the inner
    // `&mut u64`, the program AccessViolation'd because the "pointer" was the
    // numeric lamports amount (e.g., 0x204900 ≈ rent-exempt minimum for a small
    // PDA initialized via System::CreateAccount).
    //
    // @prov:cpi.caller-account (CallerAccount::from_account_info)
    // We mirror byte-for-byte: load the 8-byte inner pointer, then vmap THAT VM
    // address to get a writable host slice over the actual lamports u64.
    const lamports_ptr_slot_addr = info.lamports_box_addr +% RC_VALUE_OFFSET +% 8;
    const lamports_ptr_bytes = mm.vmap(.load, lamports_ptr_slot_addr, 8) catch
        return CpiError.M7_TranslateFailed;
    const lamports_addr_inner = std.mem.readInt(u64, lamports_ptr_bytes[0..8], .little);
    const lamports_bytes = mm.vmap(.store, lamports_addr_inner, 8) catch
        return CpiError.M7_TranslateFailed;

    // Rc<RefCell<&mut [u8]>>: slice ptr at box+RC_VALUE_OFFSET+borrow(8); slice len at +8 more.
    const slice_hdr_addr = info.data_box_addr +% RC_VALUE_OFFSET +% 8;
    const slice_hdr = mm.vmap(.load, slice_hdr_addr, 16) catch return CpiError.M7_TranslateFailed;
    const data_addr = std.mem.readInt(u64, slice_hdr[0..8], .little);
    const data_len = std.mem.readInt(u64, slice_hdr[8..16], .little);
    if (data_len > MAX_PERMITTED_DATA_INCREASE * 1024) return CpiError.M7_TranslateFailed;
    const data_bytes = if (data_len > 0)
        mm.vmap(.load, data_addr, data_len) catch return CpiError.M7_TranslateFailed
    else
        @as([]u8, &.{});

    const idx = findAccountIndex(ctx, pk) orelse {
        if (g_cpi_mm_dumps < 8) {
            g_cpi_mm_dumps += 1;
            const pkh = std.fmt.bytesToHex(pk[0..16], .lower);
            std.log.warn("[V2-CPI-MM-INFO] account_info key NOT in tx: pk={s} key_addr=0x{x} owner_addr=0x{x} n_tx={}", .{
                &pkh, info.key_addr, info.owner_addr, ctx.tx.accounts.len,
            });
            for (ctx.tx.accounts, 0..) |a, ti| {
                const ah = std.fmt.bytesToHex(a.pubkey[0..16], .lower);
                std.log.warn("[V2-CPI-MM-INFO]   tx[{}] pk={s}", .{ ti, &ah });
            }
        }
        return CpiError.M7_AccountNotInTransaction;
    };

    // PR-5c (SIMD-0459): pointer-equality checks on the AccountInfo fields the
    // Rust ABI carries directly (key + owner). Lamports/data are wrapped in
    // Rc<RefCell> indirections and validated through the box translate-and-deref
    // chain above. Index acc_region_metas by caller-instruction position, not
    // txn-level idx — see translateOneInfoC for the full explanation.
    if (ctx.syscall_param_addr_restrict_active) {
        if (ctx.instruction_stack.current()) |frame| {
            for (frame.account_indices, 0..) |aidx, caller_idx| {
                if (aidx != idx) continue;
                if (caller_idx >= mm.acc_region_metas.len) break;
                const acc_meta = mm.acc_region_metas[caller_idx];
                if (info.key_addr != acc_meta.vm_key_addr) return CpiError.M7_AbiMismatch;
                if (info.owner_addr != acc_meta.vm_owner_addr) return CpiError.M7_AbiMismatch;
                break;
            }
        }
    }

    return .{
        .pubkey = pk,
        .lamports_host = lamports_bytes,
        .owner_host = owner_bytes,
        .data_host = data_bytes,
        .original_data_len = @intCast(data_len),
        .vm_data_addr = data_addr,
        .vm_lamports_addr = lamports_addr_inner,
        .vm_owner_addr = info.owner_addr,
        .vm_slice_hdr_addr = slice_hdr_addr,
        .index_in_caller = idx,
        .is_signer = info.is_signer != 0,
        .is_writable = info.is_writable != 0,
    };
}

/// Mirror of agave translate_signers_{c,rust} + Pubkey::create_program_address.
fn translateSigners(
    ctx: *InvokeContext,
    abi: Abi,
    program_id: Pubkey32,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    mm: *AlignedMemoryMap,
) CpiError![]Pubkey32 {
    if (signers_seeds_len == 0) return ctx.allocator.alloc(Pubkey32, 0) catch
        return CpiError.M7_OutOfMemory;
    if (signers_seeds_len > MAX_SIGNERS) return CpiError.M7_TooManySigners;

    var signers = ctx.allocator.alloc(Pubkey32, @intCast(signers_seeds_len)) catch
        return CpiError.M7_OutOfMemory;
    errdefer ctx.allocator.free(signers);

    // Both ABIs use VmSlice<VmSlice<u8>> at the outer level — same SolSignerSeedsC
    // shape. (sig src/vm/syscalls/cpi.zig confirms identical layout.)
    _ = abi;

    const outer_total = std.math.mul(u64, signers_seeds_len, @sizeOf(SolSignerSeedsC)) catch
        return CpiError.M7_TranslateFailed;
    const outer = mm.vmap(.load, signers_seeds_addr, outer_total) catch
        return CpiError.M7_TranslateFailed;

    var i: usize = 0;
    while (i < signers_seeds_len) : (i += 1) {
        const off = i * @sizeOf(SolSignerSeedsC);
        const ss: *align(1) const SolSignerSeedsC = @ptrCast(outer.ptr + off);
        if (ss.len > MAX_SEEDS) return CpiError.M7_PdaInvalid;

        // Inner array of VmSlice<u8>.
        const inner_total = std.math.mul(u64, ss.len, @sizeOf(SolSignerSeedC)) catch
            return CpiError.M7_TranslateFailed;
        const inner = if (inner_total > 0)
            mm.vmap(.load, ss.addr, inner_total) catch return CpiError.M7_TranslateFailed
        else
            @as([]u8, &.{});

        // Stack-allocated [16]Slice covering each seed bytes.
        var seed_bufs: [MAX_SEEDS][]const u8 = undefined;
        var j: usize = 0;
        while (j < ss.len) : (j += 1) {
            const ioff = j * @sizeOf(SolSignerSeedC);
            const sd: *align(1) const SolSignerSeedC = @ptrCast(inner.ptr + ioff);
            if (sd.len > MAX_SEED_LEN) return CpiError.M7_PdaInvalid;
            const buf = if (sd.len > 0)
                mm.vmap(.load, sd.addr, sd.len) catch return CpiError.M7_TranslateFailed
            else
                @as([]u8, &.{});
            seed_bufs[j] = buf;
        }

        if (g_cpi_mm_dumps < 8) {
            g_cpi_mm_dumps += 1;
            const pidh = std.fmt.bytesToHex(program_id, .lower);
            std.log.warn("[V2-CPI-MM-SEED] signer[{}] n_seeds={} ss.addr=0x{x} program_id(caller_pid)={s}", .{
                i, ss.len, ss.addr, pidh,
            });
            var k: usize = 0;
            while (k < ss.len) : (k += 1) {
                const sb = seed_bufs[k];
                std.log.warn("[V2-CPI-MM-SEED]   seed[{}] len={}", .{ k, sb.len });
                if (sb.len <= 32) {
                    var sbuf: [32]u8 = [_]u8{0} ** 32;
                    @memcpy(sbuf[0..sb.len], sb);
                    const sh = std.fmt.bytesToHex(sbuf, .lower);
                    std.log.warn("[V2-CPI-MM-SEED]     bytes={s}", .{sh[0 .. sb.len * 2]});
                }
            }
        }

        signers[i] = createProgramAddress(seed_bufs[0..ss.len], program_id) catch
            return CpiError.M7_PdaInvalid;
    }

    return signers;
}

/// agave Pubkey::create_program_address — solana-pubkey/src/lib.rs.
/// SHA256 of seeds || program_id || PDA_MARKER. Reject if result is on-curve.
pub fn createProgramAddress(seeds: []const []const u8, program_id: Pubkey32) error{M7_PdaInvalid}!Pubkey32 {
    if (seeds.len > MAX_SEEDS) return error.M7_PdaInvalid;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (seeds) |s| {
        if (s.len > MAX_SEED_LEN) return error.M7_PdaInvalid;
        h.update(s);
    }
    h.update(&program_id);
    h.update(PDA_MARKER);
    var out: Pubkey32 = undefined;
    h.final(&out);
    // On-curve check (off-curve is REQUIRED for PDAs).
    // std.crypto.ecc.Edwards25519.fromBytes returns NotInCurve on off-curve.
    _ = std.crypto.ecc.Edwards25519.fromBytes(out) catch return out;
    return error.M7_PdaInvalid;
}

/// For each PDA-derived signer in `signers`, find the matching CallerAccount
/// and confirm `is_signer == true`. Mirrors agave invoke_context.rs
/// `prepare_next_cpi_instruction` "deduce signer" logic.
fn enforcePdaSigners(metas: []const TranslatedAccountMeta, signers: []const Pubkey32) CpiError!void {
    for (signers) |sig_pk| {
        var matched = false;
        var ok = false;
        for (metas) |m| {
            if (std.mem.eql(u8, &m.pubkey, &sig_pk)) {
                matched = true;
                if (m.is_signer) ok = true;
            }
        }
        if (!matched) {
            if (g_cpi_mm_dumps < 8) {
                g_cpi_mm_dumps += 1;
                const sh = std.fmt.bytesToHex(sig_pk[0..16], .lower);
                std.log.warn("[V2-CPI-MM-PDA] derived signer NOT in inner metas: pda={s} n_metas={}", .{ &sh, metas.len });
                for (metas, 0..) |mm_meta, mi| {
                    const mh = std.fmt.bytesToHex(mm_meta.pubkey[0..16], .lower);
                    std.log.warn("[V2-CPI-MM-PDA]   meta[{}] pk={s} sgn={}", .{ mi, &mh, mm_meta.is_signer });
                }
            }
            return CpiError.M7_AccountNotInTransaction;
        }
        if (!ok) return CpiError.M7_PdaNotASigner;
    }
}

/// Locate `pubkey` in `tx.accounts`, returning the u16 index. Linear scan —
/// the same loop agave's transaction_context uses (accounts.len ≤ 256).
fn findAccountIndex(ctx: *InvokeContext, pubkey: Pubkey32) ?u16 {
    for (ctx.tx.accounts, 0..) |a, i| {
        if (std.mem.eql(u8, &a.pubkey, &pubkey)) return @intCast(i);
    }
    return null;
}

fn buildAccountIndices(ctx: *InvokeContext, metas: []const TranslatedAccountMeta) CpiError![]u16 {
    var out = ctx.allocator.alloc(u16, metas.len) catch return CpiError.M7_OutOfMemory;
    errdefer ctx.allocator.free(out);
    for (metas, 0..) |m, i| {
        out[i] = findAccountIndex(ctx, m.pubkey) orelse return CpiError.M7_AccountNotInTransaction;
    }
    return out;
}

var g_cpi_mm_dumps: usize = 0;
/// RULE #17 diagnostic (2026-05-31, CPI-carrier): on M7_AccountNotInTransaction,
/// dump the inner instruction's program_id + every meta pubkey (with in-tx
/// flag) + the full tx.accounts set, so we can tell a GARBAGE pubkey (rust-ABI
/// translate bug = the carrier) from a VALID-but-absent one (fixture artifact).
/// Rate-limited; error-path only; zero steady-state cost.
fn dumpCpiMismatch(ctx: *InvokeContext, program_id: Pubkey32, metas: []const TranslatedAccountMeta) void {
    if (g_cpi_mm_dumps >= 8) return;
    g_cpi_mm_dumps += 1;
    const ph = std.fmt.bytesToHex(program_id[0..16], .lower);
    std.log.warn("[V2-CPI-MM] inner pid={s} in_tx={} n_metas={} n_tx={}", .{
        &ph, findAccountIndex(ctx, program_id) != null, metas.len, ctx.tx.accounts.len,
    });
    for (metas, 0..) |m, i| {
        const mh = std.fmt.bytesToHex(m.pubkey[0..16], .lower);
        std.log.warn("[V2-CPI-MM]   meta[{}] pk={s} in_tx={} sgn={} wr={}", .{
            i, &mh, findAccountIndex(ctx, m.pubkey) != null, m.is_signer, m.is_writable,
        });
    }
    for (ctx.tx.accounts, 0..) |a, i| {
        const ah = std.fmt.bytesToHex(a.pubkey[0..16], .lower);
        std.log.warn("[V2-CPI-MM]   tx[{}] pk={s}", .{ i, &ah });
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Recursive execution (M4) — BPF→BPF inner CPI
// ──────────────────────────────────────────────────────────────────────────────
//
// Mirrors the canonical inner-BPF dispatch path. @prov:cpi.recursive-execute
// Both reach the inner program via the runtime dispatcher (`process_instruction`
// / `fd_execute_instr`), which redoes serialization + fresh memory map +
// fresh r1/r2 + post-execute writeback. Vexor v2_dispatch.v2DispatchBpfProgram
// already implements this for the top-level program; this function performs
// the same setup for an inner BPF callee invoked via `sol_invoke_signed`.
//
// PRE: caller (`handleSolInvokeSigned`) has already ctx.push()'d the inner
// frame (cpi.zig:569). PRE: account_indices live on `ctx.currentFrame()`.
//
// Inputs come from `ctx.tx.accounts[indices[i]]` — the runtime maintains a
// single TransactionContext for the whole tx, same as Agave + Firedancer, so
// inner mutations land back on the same account view the caller's
// `updateCallerAccount` (cpi.zig step 10) reads.
fn recursiveExecute(
    ctx: *InvokeContext,
    exe: *const elf_mod.Executable,
    program_id: *const [32]u8,
    syscalls: interpreter.SyscallRegistry,
    data: []const u8,
) CpiError!u64 {
    const alloc = ctx.allocator;

    // Step A: collect inner instruction's accounts from outer tx.
    const frame = ctx.currentFrame() orelse return CpiError.M7_AccountNotInTransaction;
    const indices = frame.account_indices;

    const inputs = alloc.alloc(serialize.AccountInput, indices.len) catch
        return CpiError.M7_OutOfMemory;
    defer alloc.free(inputs);
    for (indices, 0..) |idx, i| {
        if (idx >= ctx.tx.accounts.len) return CpiError.M7_AccountNotInTransaction;
        const a = &ctx.tx.accounts[idx];
        inputs[i] = .{
            .pubkey = a.pubkey,
            .owner = a.owner,
            .lamports = a.lamports,
            .data = a.data,
            .executable = a.executable,
            .rent_epoch = a.rent_epoch,
            .is_signer = a.is_signer,
            .is_writable = a.is_writable,
        };
    }

    // Step B: serialize input region (memcpy of pre-state data into fresh buf).
    // SIMD-0459/0460/0257 port (PR-1): SerializeConfig fields are now driven by
    // the per-tx feature-gate booleans on InvokeContext (set in v2_dispatch.zig
    // from the active feature_set, then force-overridden to false by the
    // `SIMD_PORT_FORCE_OFF_*` constants in invoke_ctx.zig). Behavior is
    // byte-identical for PR-1; PR-2/3/5 lift those constants progressively.
    const ser = serialize.serializeParametersAligned(
        alloc,
        program_id.*,
        data,
        inputs,
        .{
            .virtual_address_space_adjustments = ctx.vasa_active,
            .account_data_direct_mapping = ctx.direct_mapping_active,
            .direct_account_pointers = ctx.direct_account_pointers_active, // SIMD-0449 (inactive→false→no trailer)
        },
    ) catch return CpiError.M7_RecursiveLoadFailed;
    defer alloc.free(ser.bytes);
    defer alloc.free(ser.account_layouts);

    // Step C: stack + heap (per-CPI; defaults match v2_dispatch.zig).
    const STACK_FRAME_SIZE: u64 = 4096;
    const MAX_CALL_DEPTH: usize = 64;
    const stack_buf = alloc.alloc(u8, STACK_FRAME_SIZE * MAX_CALL_DEPTH) catch
        return CpiError.M7_OutOfMemory;
    defer alloc.free(stack_buf);
    @memset(stack_buf, 0);

    // Default heap = 32 KiB. RequestHeapFrame for inner CPI is not supported on
    // testnet today (compute_budget instructions only fire at the tx level).
    const HEAP_SIZE: usize = 32 * 1024;
    const heap_buf = alloc.alloc(u8, HEAP_SIZE) catch return CpiError.M7_OutOfMemory;
    defer alloc.free(heap_buf);
    @memset(heap_buf, 0);

    // Step D: 5-region memory map (text/rodata/stack/heap/input).
    // Canonical stack_frame_gaps() = V0 ONLY (anza-xyz/sbpf v0.21.0 program.rs).
    // 2026-06-18 FIX: was `v0 or v1`; v1 must use a FLAT stack (manual bump grows
    // r10 down from top). Mirrors the top-level fix in v2_dispatch.zig:968.
    const v = exe.version();
    const stack_region = if (v == .v0)
        memory.Region.initGapped(memory.MM_STACK_START, stack_buf, STACK_FRAME_SIZE)
    else
        memory.Region.fromSlice(memory.MM_STACK_START, stack_buf);

    // V3 region layout — see the full rationale at v2_dispatch.zig (canonical
    // rc.1 configure_program_regions + sbpf get_ro_region). V3 strict
    // (enable_lower_rodata_vaddr) maps ONE rodata region @ MM_RODATA_START(0);
    // bytecode @ MM_BYTECODE_START(0x1<<32) is UNMAPPED (code runs by PC). We
    // emulate canonical's slot-1 gap with a ZERO-LENGTH region (any access →
    // AccessViolation). vaddrs from elf accessors, NOT memory.zig's name-swapped
    // constants. V0/V1/V2 (else) unchanged: text@0 filler + rodata@rodataVaddr().
    const empty_region: []const u8 = &.{};
    const regions = if (v == .v3) [_]memory.Region{
        memory.Region.fromConst(exe.rodataVaddr(), exe.rodata()), //              slot 0: rodata @ MM_RODATA_START(0)
        memory.Region.fromConst(exe.programRegionVaddr(), empty_region), //       slot 1: bytecode UNMAPPED gap @ MM_BYTECODE_START
        stack_region,
        memory.Region.fromSlice(memory.MM_HEAP_START, heap_buf),
        memory.Region.fromSlice(memory.MM_INPUT_START, ser.bytes),
    } else [_]memory.Region{
        memory.Region.fromConst(0, exe.textBytes()),
        memory.Region.fromConst(exe.rodataVaddr(), exe.rodata()),
        stack_region,
        memory.Region.fromSlice(memory.MM_HEAP_START, heap_buf),
        memory.Region.fromSlice(memory.MM_INPUT_START, ser.bytes),
    };
    // PR-3 (SIMD-0460 vasa): mirror the outer dispatch wiring — propagate
    // the feature-gate bits onto Config, and attach the serializer's per-account
    // region partition so the inner VM's vmap() enforces per-region writability.
    var inner_mm = memory.AlignedMemoryMap.initWithConfig(alloc, regions[0..], .{
        .direct_mapping = ctx.direct_mapping_active,
        .virtual_address_space_adjustments = ctx.vasa_active,
    }) catch return CpiError.M7_RecursiveLoadFailed;
    defer inner_mm.deinit();
    if (ser.input_regions.len > 0) {
        inner_mm.input_mem_regions = alloc.dupe(memory.InputMemRegion, ser.input_regions) catch
            return CpiError.M7_OutOfMemory;
        inner_mm.acc_region_metas = alloc.dupe(memory.AccRegionMeta, ser.acc_region_metas) catch
            return CpiError.M7_OutOfMemory;
        // CARRIER 420364332 PART 1 (2026-07-07): remap each data region's
        // acc_region_meta_idx from the INNER-LOCAL account position the
        // serializer stamped (serialize.zig:627, `i` over THIS CPI's `inputs`
        // subset) to the TX-GLOBAL index into owned.accounts. The realloc
        // callback (v2_dispatch.zig reallocAccountDataCallbackPR5w) and the OOB
        // handler (memory.zig:458-461) consume this index against the tx-global
        // owned.accounts (== ctx.tx.accounts — same slice). At top level the two
        // spaces coincide (the serializer sees the whole tx in order); for an
        // inner CPI whose account subset is reordered they DON'T — so a callee
        // that self-reallocs a writable account it owns (Token-2022 growing the
        // mint in place for a Token-Metadata TLV) grew the WRONG owned.accounts
        // slot, the mint's grown bytes were dropped, and the caller's later read
        // of [pre_len..post_len) AccessViolated → M4_RunFailed → tx rollback
        // (ours 35ea36… vs cluster a93d05…). `indices` (frame.account_indices)
        // maps inner-local → tx-global; metadata regions carry maxInt and are
        // skipped. Bound holds: the stamped idx is a position in `inputs`, whose
        // len == indices.len.
        for (inner_mm.input_mem_regions) |*r| {
            if (r.acc_region_meta_idx != std.math.maxInt(u64)) {
                const local: usize = @intCast(r.acc_region_meta_idx);
                r.acc_region_meta_idx = @intCast(indices[local]);
            }
        }
        // PR-3.5: inner CPI inherits the same per-tx resize budget pointer.
        inner_mm.accounts_resize_delta_ptr = &ctx.tx.accounts_resize_delta;
        // PR-5w (2026-05-19): inner CPI inherits the outer mm's realloc callback
        // so MODE 3 grows during nested execution also propagate to canonical
        // `acct.data` (Agave transaction.rs:541 mirror). ctx.mm holds the outer
        // AlignedMemoryMap pointer (set by v2_dispatch.zig:919). Propagating
        // realloc_fn+realloc_ctx by COPY is safe: both clients (outer + inner
        // ser path) write to the SAME `ctx.tx.accounts` slice.
        if (ctx.mm) |outer_mm_opaque| {
            const outer_mm: *memory.AlignedMemoryMap = @ptrCast(@alignCast(outer_mm_opaque));
            inner_mm.realloc_fn = outer_mm.realloc_fn;
            inner_mm.realloc_ctx = outer_mm.realloc_ctx;
        }
    }
    // And free the serializer's vasa slices when this recursive call exits.
    defer if (ser.input_regions.len > 0) alloc.free(ser.input_regions);
    defer if (ser.acc_region_metas.len > 0) alloc.free(ser.acc_region_metas);

    // fix/cu-parity-batch2 (2026-07-12): heap-entry CU charge, right before
    // THIS CPI-level VM creation. @prov:compute-budget.heap-cost — charges
    // at every VM creation, not just the top-level one. Uses the SAME tx-wide ctx.heap_size the
    // top-level dispatch set (v2_dispatch.zig) — Agave's heap_size comes from
    // invoke_context.get_compute_budget(), one value for the whole tx
    // regardless of call depth. Default heap_size (32768) → cost=0, a no-op
    // for the overwhelming majority of CPIs.
    ctx.chargeHeapCost() catch return CpiError.M7_OutOfCompute;

    // Step E: Vm — F4 (r1=MM_INPUT_START), F5 (r2=ix_data_offset / SIMD-0321).
    const cfg = interpreter.Config{};
    const cu = ctx.computeRemaining();
    var vm = interpreter.Vm.init(alloc, exe, &inner_mm, syscalls, ctx, cfg, cu) catch
        return CpiError.M7_RecursiveLoadFailed;
    defer vm.deinit();
    vm.reg[1] = memory.MM_INPUT_START;
    vm.reg[2] = @intCast(ser.instruction_data_offset);

    // Step F: route ctx.mm at inner mm so the inner program's syscalls translate
    // via the inner memory map (sol_log_, nested sol_invoke_signed, ...).
    // Restore on return so the OUTER program continues with its own mm.
    const outer_mm = ctx.mm;
    ctx.mm = @ptrCast(&inner_mm);
    defer ctx.mm = outer_mm;

    // Step G: run.
    const r0 = vm.run() catch |err| switch (err) {
        error.OutOfCompute, error.ExceededMaxInstructions => return CpiError.M7_OutOfCompute,
        else => return CpiError.M7_RecursiveExecuteFailed,
    };

    // Step H: charge compute.
    const consumed = vm.due_insn_count;
    if (consumed <= cu) {
        ctx.consumeCompute(consumed) catch return CpiError.M7_OutOfCompute;
    } else {
        ctx.consumeCompute(cu) catch return CpiError.M7_OutOfCompute;
    }

    // Step I: post-execute writeback. Read mutations out of the input region
    // and commit to ctx.tx.accounts so the caller-side updateCallerAccount
    // (step 10 in handleSolInvokeSigned) sees them. Mirrors the deserialize
    // pass at the end of v2_dispatch.zig's top-level dispatch.
    const outputs = alloc.alloc(serialize.AccountOutput, indices.len) catch
        return CpiError.M7_OutOfMemory;
    defer alloc.free(outputs);
    serialize.deserializeReturn(ser.bytes, outputs, ser.account_layouts, ctx.direct_mapping_active) catch
        return CpiError.M7_RecursiveExecuteFailed;

    // Inner-CPI writeback (cpi-rebase phase 4, 2026-05-13).
    //
    // @prov:cpi.update-callee-account — byte pattern for the non-VAS path. The pre-rebase
    // shape (always-write lamports + owner; then resize+memcpy data) was
    // identified by audit (project_d28ff_FIX_REGRESSED_REVERTED) as producing
    // post-state bytes that didn't match cluster canonical, contributing to
    // the d28ff regression at slot 1 of boot 408246970.
    //
    // Canonical agave order:
    //   1. Lamports — write ONLY if different.
    //   2. Data — set_data_from_slice; respects can_data_be_resized check
    //      (Vexor has no rent-exempt BorrowedAccount invariant so we follow
    //      Agave's "if Err && data actually changed: surface err" branch by
    //      always allowing — Vexor enforces rent at bank-freeze time, not in
    //      CPI writeback; the agave path resolves to the same final bytes).
    //   3. Owner — write ONLY if different. LAST so the "owner change implies
    //      caller must update" semantic stays correct.
    //
    // is_duplicate filter preserved: agave skips duplicates implicitly through
    // its dedup_map, Vexor uses the explicit layout flag (set by the
    // serializer). Same effect: only write back the first occurrence; later
    // duplicate slots are derived from it at the BorrowedAccount layer.
    for (indices, 0..) |idx, i| {
        const layout = ser.account_layouts[i];
        if (layout.is_duplicate) continue;
        const a = &ctx.tx.accounts[idx];
        const out = outputs[i];

        // (1) Lamports — conditional. @prov:cpi.update-callee-account
        if (a.lamports != out.lamports) {
            a.lamports = out.lamports;
        }

        // (2) Data — agave non-VAS branch. @prov:cpi.update-callee-account — Vexor lacks
        //     BorrowedAccount.can_data_be_resized rent invariants; the agave
        //     branch resolves to set_data_from_slice unconditionally. We
        //     reuse the existing realloc-if-len-changed pattern but it now
        //     runs BEFORE the owner write (canonical order).
        //
        // PR-5s (2026-05-19): MODE 3 (SIMD-0257 ADDM, direct mapping) gate.
        // When direct_mapping_active=true, the BPF callee wrote its data
        // payload DIRECTLY through the shared input region into
        // ctx.tx.accounts[idx].data (a.data) — the buffer at host_data_offset
        // contains only the 8-byte BPF_ALIGN_OF_U128 zero pad from
        // serialize.zig:463-477, so `out.data` is garbage (zero-pad bleed
        // plus next-account header). Replacing a.data with `out.data` here
        // would CORRUPT the canonical post-state with zeros. Symmetric to
        // the top-level dispatch fix at vex_svm/v2_dispatch.zig:1123-1127.
        // @prov:cpi.update-callee-account (`!account_data_direct_
        // mapping` gate before set_data_from_slice). sol_set_data_length is
        // not implemented in Vexor, so the data length cannot change under
        // MODE 3; defensive: clamp `out.data_len` against `a.data.len` is
        // unnecessary here (we'd only consult `out` in non-DM mode).
        if (!ctx.direct_mapping_active) {
            if (out.data_len != a.data.len) {
                const new_data = alloc.alloc(u8, out.data_len) catch
                    return CpiError.M7_OutOfMemory;
                if (out.data_len > 0) @memcpy(new_data, out.data);
                alloc.free(a.data);
                a.data = new_data;
            } else if (out.data_len > 0 and !std.mem.eql(u8, a.data, out.data)) {
                // Only copy when bytes actually differ — saves a memcpy when the
                // inner CPI's callee never touched the data buffer.
                @memcpy(a.data, out.data);
            }
        } else {
            // CARRIER 420364332 PART 2 (2026-07-07): direct-mapping length
            // reconciliation. Under DM the callee wrote its data payload in
            // place through the shared region, so `out.data` is garbage and must
            // NOT be copied (that is the whole point of the `!DM` gate above).
            // BUT a self-realloc GROW routes through handleInputMemRegionOob
            // (memory.zig:432-433), which grows owned.accounts[idx].data to the
            // WHOLE remaining tx budget (up to +10 KiB slack), NOT the program's
            // reported post_len — leaving the account over-grown with trailing
            // slack bytes the program never claimed. The top-level dispatch
            // already reconciles this at commit (v2_dispatch.zig:1517-1524); the
            // inner-CPI Step-I path was gated off entirely under DM (the old
            // guard assumed length can't change under MODE 3 — false for a BPF
            // realloc), so an inner-CPI grow left canon over-committed →
            // bank_hash divergence (carrier 420364332: Token-2022 metadata TLV).
            // Reconcile to the canonical post_len exactly as the top level and
            // Agave set_data_length. @prov:cpi.update-callee-account — trust
            // the region's reported dlen (out.data_len) when it actually changed
            // vs the pre-CPI length; else fall back to the current buffer length
            // (RULE#15 @412589216: an inner-CPI writer such as System::Create-
            // Account grows canon DIRECTLY and leaves the serialized dlen == pre,
            // so we must NOT clamp to pre and drop the created bytes). @min
            // guards a reported dlen larger than the allocated buffer. When the
            // length is unchanged (the overwhelming majority of inner CPIs) this
            // is a pure no-op — no realloc, no perturbation of the earlier slots.
            const pre_len = inputs[i].data.len;
            const post_len_dm: usize = if (out.data_len != @as(u64, @intCast(pre_len)))
                @as(usize, @intCast(out.data_len))
            else
                a.data.len;
            const final_len = @min(a.data.len, post_len_dm);
            if (final_len != a.data.len) {
                a.data = alloc.realloc(a.data, final_len) catch
                    return CpiError.M7_OutOfMemory;
            }
        }

        // (3) Owner — conditional, LAST. @prov:cpi.update-callee-account — The
        //     ownership-change-implies-must-update-caller semantic is
        //     surfaced to the OUTER frame's step 10 by comparing post-state
        //     ctx.tx.accounts[idx].owner against caller_account.owner_host
        //     pre-state in handleSolInvokeSigned.
        if (!std.mem.eql(u8, &a.owner, &out.owner)) {
            a.owner = out.owner;
        }
    }

    return r0;
}

// ──────────────────────────────────────────────────────────────────────────────
// updateCallerAccount. @prov:cpi.update-caller-account (flat-buffer subset)
// ──────────────────────────────────────────────────────────────────────────────
//
// Writes the post-execution callee state back into the caller's VM-mapped
// pointers. Enforces:
//   - MAX_PERMITTED_DATA_INCREASE on data growth (InvalidRealloc → M7_DataIncreaseTooLarge)
//   - lamports + owner copy unconditionally (Agave does this every CPI exit)
//   - data_len u64 prefix at vm_data_addr - 8 (sBPF input region invariant)
//   - data bytes copied into caller_account.data_host range
//
// VAS / direct-mapping branches are deferred (testnet-dormant gates).

fn updateCallerAccount(
    ctx: *InvokeContext,
    mm: *AlignedMemoryMap,
    ca: *CallerAccount,
) CpiError!void {
    const callee = ctx.tx.accountAt(ca.index_in_caller) catch
        return CpiError.M7_AccountNotInTransaction;

    // 1) lamports
    std.mem.writeInt(u64, ca.lamports_host[0..8], callee.lamports, .little);

    // 2) owner
    @memcpy(ca.owner_host[0..32], &callee.owner);

    // 3) realloc bound
    const post_len = callee.data.len;
    const pre = ca.original_data_len;
    if (post_len > pre + MAX_PERMITTED_DATA_INCREASE) {
        // PR-5af-probe (2026-05-19): Carrier J — log realloc bound rejections.
        const ReallocProbe = struct {
            var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
        };
        const rn = ReallocProbe.count.fetchAdd(1, .monotonic);
        if (rn < 10) {
            const pk_short = std.fmt.bytesToHex(callee.pubkey[0..8], .lower);
            std.log.warn(
                "[PR5AF-REALLOC-PROBE n={d}] pre={d} post={d} delta={d} maxincr={d} pk={s}",
                .{ rn, pre, post_len, @as(i64, @intCast(post_len)) - @as(i64, @intCast(pre)), MAX_PERMITTED_DATA_INCREASE, &pk_short },
            );
        }
        return CpiError.M7_DataIncreaseTooLarge;
    }

    // 4) data slice + memcpy — SKIPPED when vasa+DM is active (Firedancer
    // cpi_common.c:574, 624). In DM mode the inner BPF program wrote DIRECTLY
    // to the account's data slot (the region's haddr pointed there), so
    // there's nothing to copy back into a buffer — the data IS the buffer.
    // Zero-fill-on-shrink also unneeded because shrink semantics are handled
    // by setDataLength at the account-meta layer.
    const dm_skip_data = ctx.vasa_active and ctx.direct_mapping_active;
    if (!dm_skip_data) {
        // Re-vmap a writable host slice covering up to post_len. Caller's input
        // region reserves `pre + MAX_PERMITTED_DATA_INCREASE` bytes at
        // vm_data_addr, so post_len ≤ that is always vmap-safe.
        const data_dst = mm.vmap(.store, ca.vm_data_addr, @intCast(post_len)) catch
            return CpiError.M7_TranslateFailed;

        if (post_len < ca.data_host.len) {
            // Shrunk — agave zero-fills the now-unused tail.
            const shrink_zero_addr = ca.vm_data_addr + post_len;
            const shrink_zero_len = ca.data_host.len - post_len;
            const tail = mm.vmap(.store, shrink_zero_addr, @intCast(shrink_zero_len)) catch
                return CpiError.M7_TranslateFailed;
            @memset(tail, 0);
        }

        // @prov:cpi.update-caller-account — length-mismatch check.
        if (data_dst.len != post_len) return CpiError.M7_AccountDataTooSmall;

        @memcpy(data_dst, callee.data[0..post_len]);
    }

    // 5) Update the dlen u64 sitting at vm_data_addr - 8.
    // CARRIER #19 part 3 (2026-06-12). @prov:cpi.update-caller-account — Agave-canonical
    // SATURATING sub. Raw `- 8` PANICKED (integer overflow) when vm_data_addr < 8 — reachable
    // only once the dup-meta privilege fix let torX BuyExact's inner CPIs
    // SUCCEED (dispatch_err==null → writeback runs). An out-of-range result
    // then fails the vmap gracefully (M7_TranslateFailed) instead of crashing
    // the whole validator. Matches Agave: saturating_sub never panics; an
    // invalid address surfaces as a translate error.
    const dlen_bytes = mm.vmap(.store, ca.vm_data_addr -| 8, 8) catch
        return CpiError.M7_TranslateFailed;
    std.mem.writeInt(u64, dlen_bytes[0..8], post_len, .little);

    // 6) Rust ABI only: update the Rc<RefCell<&mut [u8]>>'s slice len so
    //    AccountInfo.data.borrow() reads the post-CPI length. Without this,
    //    a System::CreateAccount that grew data 0→N leaves the program's
    //    data slice at len=0 → out-of-range panics on first read.
    //    Slice layout: [+0..+8]=ptr, [+8..+16]=len.
    if (ca.vm_slice_hdr_addr != 0) {
        const len_bytes = mm.vmap(.store, ca.vm_slice_hdr_addr + 8, 8) catch
            return CpiError.M7_TranslateFailed;
        std.mem.writeInt(u64, len_bytes[0..8], post_len, .little);
    }

    // 7) DIRECT-MAPPING caller-region repoint = the ported update_caller_account_region.
    //    @prov:cpi.caller-account-region — Under direct mapping the
    //    serializer set this account's INPUT data-region haddr = acct.data.ptr with
    //    region_sz = the pre-execution data length (serialize.zig:572/578). An inner
    //    CPI that grew/moved the buffer — e.g. System::CreateAccount 0→168 via
    //    reallocAccountDataCallbackPR5w's realloc (v2_dispatch.zig:706) — leaves the
    //    OUTER caller's region STALE (region_sz too small, haddr at the old/freed
    //    buffer). The caller program's next read of the now-larger account then
    //    translates against that stale region and AccessViolates. Carrier @412589216:
    //    PFD InitializePriorityFeeDistributionAccount, account f1387b4f, faulted at
    //    pc=3982 → v2DispatchBpfProgram M4_RunFailed BEFORE its §7 collection loop →
    //    the create + funder debit were DROPPED → bank_hash diverged. Non-DM needs NO
    //    repoint here: step 4's mm.vmap(.store) already drove handleInputMemRegionOob
    //    to grow the region in place. region_sz = CURRENT post_len, NEVER
    //    address_space_reserved (kat_cpi_region_writeback.zig guard D: a read of
    //    region_sz+1 must still fail, else reserved slack the cluster never exposes
    //    leaks into bank_hash). Located by matching the region whose vaddr_offset ==
    //    ca.vm_data_addr-MM_INPUT_START (both input-relative; mm.vmap normalizes by
    //    -MM_INPUT_START). Duplicate-safe: a duplicated account shares the vaddr → the
    //    same region → an idempotent repoint to the same canonical buffer.
    if (ctx.direct_mapping_active and ca.is_writable) {
        // Agave-canonical saturating sub. @prov:cpi.caller-account-region — never
        // panics on a below-input-region vm_data_addr (carrier #19 part 3).
        const want_offset = ca.vm_data_addr -| memory.MM_INPUT_START;
        for (mm.input_mem_regions) |*region| {
            if (region.vaddr_offset == want_offset) {
                region.haddr = callee.data.ptr;
                region.region_sz = @intCast(post_len);
                break;
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Compile-time invariants
// ──────────────────────────────────────────────────────────────────────────────

comptime {
    // Locked sizes — any of these drifting means agave's wire format changed and
    // we need to revisit the ABI.
    std.debug.assert(@sizeOf(SolInstructionC) == 40);
    std.debug.assert(@sizeOf(SolAccountMetaC) == 16);
    std.debug.assert(@sizeOf(SolAccountInfoC) == 56);
    std.debug.assert(@sizeOf(SolSignerSeedC) == 16);
    std.debug.assert(@sizeOf(SolSignerSeedsC) == 16);
    std.debug.assert(@sizeOf(StableInstructionRust) == 80);
    std.debug.assert(@sizeOf(AccountMetaRust) == 34);
    // MAX_INSTRUCTION_STACK_DEPTH locked to 5 in M8 invoke_ctx.zig:73 per
    // Agave compute_budget. (Brief said 4 — brief was wrong.)
    std.debug.assert(invoke_ctx_mod.MAX_INSTRUCTION_STACK_DEPTH == 5);
    std.debug.assert(MAX_PERMITTED_DATA_INCREASE == 10240);
}
