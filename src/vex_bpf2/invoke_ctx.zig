//! Vexor BPF2 — InvokeContext + TransactionContext + InstructionStack
//!
//! Spec-for-spec rebuild of:
//!   • agave/program-runtime/src/invoke_context.rs (~1894 LoC)
//!   • agave SDK transaction-context (account list + program indices)
//!   • agave SDK instruction-context (per-instruction borrow set + stack frame)
//!
//! ── Why this file exists ───────────────────────────────────────────────────
//! Per R3-loader-runtime.md §1.3, Vexor today has FIVE different per-handler
//! contexts (`bpf_loader.zig:InstrCtx`, `system_v2.zig:InstrCtx`,
//! `executor.zig:InstrContext`, `vm_syscalls.zig:FullSyscallContext`,
//! `vm_interpreter.zig:SyscallContext`) — none compose, none survive CPI,
//! and none carry transaction-level state. CPI cannot recurse correctly
//! without a unified context. This rebuild defines that context.
//!
//! ── Five missing checks per R3 §4 (LOCKED IN HERE) ─────────────────────────
//!   1. instruction-stack push/pop (Agave invoke_context.rs:239,270)
//!   2. compute meter consume_checked (Agave invoke_context.rs:635)
//!   3. lamport-balance invariant (Agave instr-context::process)
//!   4. rent-state transition check (Agave bank::check_rent_state)
//!   5. readonly-modified + program-id-modified check
//!      (Agave program-runtime/src/serialization.rs::deserialize_parameters)
//!
//! ── Agave parity map ───────────────────────────────────────────────────────
//!   InvokeContext::push                  invoke_context.rs:239-269
//!   InvokeContext::pop                   invoke_context.rs:270-275
//!   InvokeContext::consume_checked       invoke_context.rs:635-655
//!   InvokeContext::get_sysvar_cache      invoke_context.rs:679-682
//!   InstructionContext (depth, parent)   sdk/.../instruction_context.rs
//!   TransactionContext                   sdk/.../transaction_context.rs
//!
//! ── SIMD inventory ─────────────────────────────────────────────────────────
//!   SIMD-0096  Reward full priority fee to validators.
//!              Gate: 3opE3EzAKnUftUDURkzMgwpNgimBAypW1mNDYH4x4Zg7
//!              (active on testnet @ 315884256, mainnet @ 320112000).
//!              Affects fee-burn arithmetic elsewhere; this file only exposes
//!              the feature_set hook.
//!   SIMD-0337  Alpenglow handover marker.
//!              Gate: dcomRRWHXP1FVWPqi9Mm4oxJhF4ehC795SvAtUdA9os
//!              (NOT-YET active on testnet OR mainnet). InvokeContext
//!              exposes feature_set so handlers can branch when it flips.
//!   SIMD-0490  Upgrade BPF stake program to v5.
//!              Gate: STk5Xj8hdAx3sTzmtJ3QysKkq6X2A3yj73JtxttiRyk
//!              (NOT-YET active on testnet). Forward only.
//!   SIMD-0118  Partitioned Epoch Rewards. Forward only via SysvarCache.
//!              [Note: SIMD-0459 = sol_*_addr syscall param restrictions
//!              (gate EDGMC5kxFxGk4ixsNkGt8bW7QL5hDMXnbwaZvYMwNfzF, dormant);
//!              SIMD-0460 = virtual address space adjustments (gate
//!              7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz, dormant).
//!              Neither is "EpochRewards partitioned" — that is SIMD-0118.]
//!
//! ── fix_ledger blocks ──────────────────────────────────────────────────────
//!   • vex-058 (LOCKED HERE) — getSysvar must propagate SysvarNotPopulated
//!                             upward; never silent-zero. Test verifies.
//!   • vex-034 (DEFERRED)    — incoming saturating-arith in PanicDbg; this
//!                             file's compute meter uses saturating subtract
//!                             internally so any underflow attempt becomes
//!                             OutOfCompute, not a silent wrap.
//!   • executeBpfProgram-owner-bug (vex-039)  — InvokeContext exposes the
//!                             current program owner via `current_program_id`.
//!                             Wave 4 wiring at replay_stage.zig:3050 must
//!                             read THIS field, not infer owner from data.
//!   • vex-053 (LOCKED) — ALT-resolved txns: TransactionContext.accounts is
//!                             the authoritative resolved list; InvokeContext
//!                             never re-resolves.

const std = @import("std");
const sysvar_cache = @import("sysvar_cache.zig");

pub const SysvarCache = sysvar_cache.SysvarCache;
pub const Pubkey32 = sysvar_cache.Pubkey32;

pub const MAX_INSTRUCTION_STACK_DEPTH: u8 = 5; // Agave compute_budget::max_instruction_stack_depth (INACTIVE / default)
/// SIMD-0268 raise_cpi_nesting_limit_to_8 ACTIVE value. Agave
/// program-runtime/src/execution_budget.rs:10 (get_max_instruction_stack_depth →
/// 9 when active; the SIMD title's "4→8" counts NESTED CPIs, the constant counts
/// the top-level instruction too: 5 = 1+4, 9 = 1+8). Selected per-dispatch into
/// InvokeContext.max_stack_depth; the constant above stays 5 so the cpi.zig `== 5`
/// assert and all inactive-path KATs remain valid.
pub const MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268: u8 = 9;
pub const MAX_INSTRUCTION_TRACE_LENGTH: usize = 64;

// ── SIMD-0459/0460/0257 port — force-off overrides ────────────────────────────
// Single source of truth for whether v2_dispatch should honor the per-tx
// feature_set bits or force them off. PR-1 leaves ALL true so behavior is
// byte-identical. PR-2 lifts vasa (`SIMD_PORT_FORCE_OFF_VASA = false`), PR-5
// lifts ADDM, etc. Read at InvokeContext construction time only — the runtime
// pays no per-tx cost.
/// PR-5d (SIMD-0459) — re-enabled after caller-index fix in cpi.zig. The
/// original PR-5b port indexed `acc_region_metas` by txn-level account index,
/// but the metas are populated in caller-instruction account order at serialize
/// time (matches Firedancer cpi_common.c:324 `index_in_caller`). PR-5c bisect
/// proved this caused immediate cascade. PR-5d remaps idx via
/// `ctx.instruction_stack.current().account_indices` before lookup.
///
/// PR-K-isolation (2026-05-17): re-forced to `true` for the VASA wire-up
/// commit so only SIMD-0460 (VASA) activates at runtime. PR-3.5 lifted
/// `SIMD_PORT_FORCE_OFF_VASA = false` weeks ago BUT the call site at
/// replay_stage.zig was passing `.{}` as feature_set, so VASA never engaged.
/// This commit threads live_feature_set through the call chain. To get clean
/// attribution if anything regresses, we keep 0459 force-off and lift it in
/// a follow-up commit after empirical confirmation that 0460 alone is safe.
pub const SIMD_PORT_FORCE_OFF_SYSCALL_PARAM_ADDR_RESTRICT: bool = true;
/// PR-3 + PR-3.5 (SIMD-0460) — lifted. Vasa active on testnet since
/// slot 407,900,256. Serializer MODE 2, byte-pad fix, OOB-handler bridge to
/// TransactionContext.accounts_resize_delta all live.
pub const SIMD_PORT_FORCE_OFF_VASA: bool = false;
/// PR-5h2-revert (SIMD-0257 ADDM) — RE-REVERTED 2026-05-18 ~05:30 MDT.
///
/// PR-5h2 successfully wired the vmap direct_mapping path (AccessViolations
/// 14169 → 5), but parity stayed at 0.39% because HJT-6009 (program owner
/// `e34d44a45426bd0c`) still diverges under MODE 3 — Vexor's MODE 3
/// implementation produces different output bytes than cluster's despite
/// vmap routing being correct. Smoking gun from this session's diagnostic
/// chain:
///   - slot 409209118 (anchor+0, matched 100%): 0 HJT writes, 572 System, 571 Vote
///   - slot 409209132 (anchor+14, first divergent): +7 HJT writes
/// First diverging slot is the first slot with ANY HJT activity.
/// tx-results-diff confirmed 597/597 txs agree on outcome at the divergent
/// slot — divergence is in POST-STATE BYTES, not tx outcomes.
///
/// All PR-5h / PR-5h2 plumbing fixes STAY in tree (memory.zig + v2_dispatch.zig).
/// They're no-ops when force-off=true (config.direct_mapping=false → vmap
/// resolver path doesn't fire; v2_dispatch loop's MODE 3 branch doesn't fire).
///
/// EXPERIMENTAL 2026-05-19: flipped to false at 01:17 MDT, reverted at 01:25
/// MDT. Empirical result: the validator booted and began receiving shreds
/// but FAILED to advance past `frozen_set_size=0` for 7 minutes. The
/// PR-S5-PROBE counter advanced from 1 to 1201 (so the validator was
/// actively running) yet zero banks were frozen and `pending_chain_count`
/// stayed at 13. No panics, no AccessViolations, no errors in the log.
/// Validator appears to silently stall on first-replay-attempt under MODE 3.
/// Pattern is distinct from the PR-5h2-era 0.39% parity drop (which DID
/// freeze 1732 slots, just with mismatched bank_hashes). This indicates a
/// regression specific to MODE 3 + the current PR stack, NOT the
/// 14169-AV class. Cause unknown; needs investigation BEFORE retry.
/// See [[project_bpf_cpi_carrier_2026_05_19]] addendum for full details.
pub const SIMD_PORT_FORCE_OFF_DIRECT_MAPPING: bool = false;

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

pub const InvokeError = error{
    OutOfCompute,
    SysvarNotPopulated,
    UnbalancedInstruction,
    InvalidRentPaying,
    ReadonlyModified,
    ProgramIdModified,
    CallDepthExceeded,
    StackEmpty,
    InvalidIndex,
    OutOfMemory,
};

// ──────────────────────────────────────────────────────────────────────────────
// AccountView — handles to per-tx accounts the runtime hands to the loader
//
// Pre/post snapshot is what the readonly-modified + program-id-modified +
// lamport-balance invariants are computed against.
// ──────────────────────────────────────────────────────────────────────────────

pub const AccountView = struct {
    pubkey: Pubkey32,
    lamports: u64,
    owner: Pubkey32,
    executable: bool,
    rent_epoch: u64,
    data: []u8,
    /// Set by tx parser. Read-only ⇒ readonly-modified check fires on diff.
    is_writable: bool,
    is_signer: bool,
    /// Pre-execution snapshot captured by `InstructionStack.push`.
    /// Used by post-checks to detect mutations on read-only accounts and
    /// owner mutations on the program account.
    pre_snapshot: ?Snapshot = null,

    pub const Snapshot = struct {
        lamports: u64,
        owner: Pubkey32,
        data_hash: [32]u8,
    };
};

fn hashAccountData(data: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return h;
}

// ──────────────────────────────────────────────────────────────────────────────
// InstructionStack — per-frame state
// ──────────────────────────────────────────────────────────────────────────────

pub const InstructionFrame = struct {
    program_idx: u16,
    /// Indices into `TransactionContext.accounts` for accounts this
    /// instruction borrows. Mirrors Agave InstructionAccount list.
    account_indices: []const u16,
    /// Sum of lamports across all accounts borrowed by this instruction at
    /// frame-push time. Post-execution must equal this exactly. (Agave's
    /// per-instr lamport invariant.)
    lamport_sum_at_push: u128,
    /// Snapshots captured at push for every borrowed account. Indexed
    /// parallel to `account_indices`.
    pre_snapshots: []AccountView.Snapshot,
};

pub const InstructionStack = struct {
    allocator: std.mem.Allocator,
    frames: std.ArrayListUnmanaged(InstructionFrame) = .{},

    pub fn deinit(self: *InstructionStack) void {
        for (self.frames.items) |f| self.allocator.free(f.pre_snapshots);
        self.frames.deinit(self.allocator);
    }

    pub fn depth(self: *const InstructionStack) u8 {
        return @intCast(self.frames.items.len);
    }

    pub fn current(self: *InstructionStack) ?*InstructionFrame {
        if (self.frames.items.len == 0) return null;
        return &self.frames.items[self.frames.items.len - 1];
    }
};

// ──────────────────────────────────────────────────────────────────────────────
// TransactionContext
// ──────────────────────────────────────────────────────────────────────────────

pub const TransactionContext = struct {
    allocator: std.mem.Allocator,
    accounts: []AccountView,
    program_indices: []const u16,
    return_data: ReturnData = .{},
    /// SIMD-0460/0257 port — consensus-affecting per-tx account-data growth
    /// budget (capped at FD_MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION).
    /// `handleInputMemRegionOob` in memory.zig will bump this when the OOB
    /// handler ships in PR-5. Initialized to 0 each tx; signed so a future
    /// shrink path doesn't underflow. Mirrors Agave's
    /// `TransactionContext::accounts_resize_delta` and Firedancer's
    /// `txn_out->details.accounts_resize_delta`.
    accounts_resize_delta: i64 = 0,

    pub const ReturnData = struct {
        program_id: Pubkey32 = std.mem.zeroes(Pubkey32),
        data: std.ArrayListUnmanaged(u8) = .{},

        pub fn set(self: *ReturnData, alloc: std.mem.Allocator, pid: Pubkey32, bytes: []const u8) !void {
            self.program_id = pid;
            self.data.clearRetainingCapacity();
            try self.data.appendSlice(alloc, bytes);
        }
        pub fn deinit(self: *ReturnData, alloc: std.mem.Allocator) void {
            self.data.deinit(alloc);
        }
    };

    pub fn init(
        alloc: std.mem.Allocator,
        accounts: []AccountView,
        program_indices: []const u16,
    ) TransactionContext {
        return .{ .allocator = alloc, .accounts = accounts, .program_indices = program_indices };
    }

    pub fn deinit(self: *TransactionContext) void {
        self.return_data.deinit(self.allocator);
    }

    pub fn accountAt(self: *TransactionContext, idx: u16) InvokeError!*AccountView {
        if (idx >= self.accounts.len) return error.InvalidIndex;
        return &self.accounts[idx];
    }
};

// ──────────────────────────────────────────────────────────────────────────────
// InvokeContext — the unified runtime context Agave gates every BPF call on
// ──────────────────────────────────────────────────────────────────────────────

pub const InvokeContext = struct {
    allocator: std.mem.Allocator,
    tx: *TransactionContext,
    sysvar_cache: *const SysvarCache,
    /// Compute meter — saturating subtract on consume; no silent wrap.
    compute_remaining: u64,
    instruction_stack: InstructionStack,

    /// fix/cu-parity-batch2 (2026-07-12): tx-wide heap_size in bytes, from
    /// ComputeBudgetInstruction::RequestHeapFrame (default MIN_HEAP_FRAME_
    /// BYTES=32768 — Agave program-runtime/src/execution_budget.rs:35-36).
    /// ONE value for the whole tx, set once at top-level dispatch and left
    /// unchanged through every CPI depth (Agave invoke_context.get_compute_
    /// budget().heap_size is tx-wide, not re-derived per call frame — see
    /// create_vm! macro, program-runtime/src/vm.rs:107-138). Consumed by
    /// calculateHeapCost() below at every VM creation (top-level AND each
    /// CPI level in cpi.zig's recursiveExecute).
    heap_size: u32 = 32768,

    /// Bound by the caller; this slice does not own/dispatch nested instrs.
    /// Wave 4 wiring will populate.
    feature_active: ?*const fn (ctx: *InvokeContext, pubkey: Pubkey32) bool = null,

    /// SIMD-0459/0460/0257 port: feature-gate booleans threaded from the
    /// per-tx active feature_set at dispatch time. Default false (Phase A
    /// behavior). PR-1 wires the plumbing but force-overrides all three to
    /// false via `simd_port_force_off_*` so behavior is byte-identical.
    /// PR-2/3/4/5 progressively lift the overrides; the bools below remain
    /// the single read-site for SerializeConfig in cpi.zig.
    syscall_param_addr_restrict_active: bool = false,
    vasa_active: bool = false,
    direct_mapping_active: bool = false,

    /// HARDEN-2 (2026-06-16): Core-BPF Stake routing gate, threaded from the
    /// SAME per-bank live FeatureSet + slot the TOP-LEVEL gate
    /// (replay_stage.executeStakeInstruction:10901) reads, set at the identical
    /// dispatch site as `vasa_active`/`direct_mapping_active` below
    /// (v2_dispatch.zig:~1042). This is the single read-site the CPI seam
    /// (cpi.zig route_stake_bpf) consults INSTEAD of the never-wired
    /// `feature_active` hook — so a stake instruction and a stake CPI inside the
    /// SAME tx/slot resolve the migrate-feature gate IDENTICALLY (no split
    /// brain). It already folds in `vex_bpf2.stake_bpf_flag.enabled()` (env
    /// VEX_STAKE_BPF, default OFF) — so default-OFF leaves it false and CPI
    /// stays on the native builtin path, byte-identical to current.
    stake_bpf_active: bool = false,

    /// F3 fix (2026-07-01): Core-BPF ALT CPI routing gate, threaded in
    /// v2_dispatch.zig from features.MIGRATE_ADDRESS_LOOKUP_TABLE_PROGRAM_TO_
    /// CORE_BPF (SIMD-0128, ACTIVE on testnet) resolved against the SAME live
    /// (feature_set, current_slot) as every other gate above — matching Agave
    /// 4.1.0 bank.rs:5841 (builtin_is_bpf per bank) and FD v0.1004
    /// fd_builtin_programs.c:183 (per-slot migration feature check). Read by
    /// cpi.zig route_alt_bpf: when TRUE, a CPI into AddressLookupTab1e111… is
    /// EXCLUDED from the builtin dispatch branch and falls through to the
    /// resolver → recursiveExecute of the on-chain Core-BPF .so (the cluster's
    /// behavior). When FALSE (default, fail-closed: unit fixtures / no real
    /// FeatureSet / pre-activation slot) routing is byte-identical to legacy
    /// (builtin branch → M9 stub). UNLIKE stake_bpf_active there is NO env-flag
    /// operand: ALT-CPI has no working native fallback (the M9 handler is all
    /// VariantPending), so a default-OFF env would leave the live F3 divergence
    /// open. Top-level ALT dispatch (replay_stage.executeAltInstruction) is
    /// native and unaffected by this field.
    alt_bpf_active: bool = false,

    /// SIMD-0512: enable_sha512_syscall (s512oDwg…, pending epoch 973 testnet).
    /// Resolved per-dispatch in v2_dispatch.zig from the live FeatureSet, same
    /// pattern as the three booleans above. Agave gates by not REGISTERING the
    /// syscall pre-activation; Vexor registers unconditionally and gates at
    /// invoke (before any CU consumption) — same failed-tx outcome either way.
    sha512_syscall_active: bool = false,

    /// Phase 2 (2026-06-19): BN254/Poseidon syscall feature gates, resolved
    /// per-dispatch from the live FeatureSet in v2_dispatch.zig (same pattern as
    /// sha512_syscall_active above). Read in vex_bpf2/syscalls.zig:
    ///   • SIMD-0284 alt_bn128_little_endian — when false, LE group/compress ops
    ///     abort (InvalidAttribute). NOT active on testnet today.
    ///   • SIMD-0302 enable_alt_bn128_g2_syscalls — when false, all G2 group ops
    ///     abort. ACTIVE on testnet.
    ///   • SIMD-0359 poseidon_enforce_padding — selects hashv (enforce) vs
    ///     legacy::hashv. ACTIVE on testnet → enforce path.
    /// Default false (matches a build with no live FeatureSet / pre-activation).
    alt_bn128_little_endian_active: bool = false,
    alt_bn128_g2_active: bool = false,
    poseidon_enforce_padding_active: bool = false,
    /// SIMD-0388 enable_bls12_381_syscall (b1sgUiJ3…, ACTIVE testnet @407127008).
    /// Gates the BLS12-381 arms of sol_curve_validate_point / group_op /
    /// decompress / pairing_map. Default false (pre-activation / no live
    /// FeatureSet) → those curve_ids abort with InvalidAttribute.
    enable_bls12_381_syscall: bool = false,
    /// SIMD-0268 raise_cpi_nesting_limit_to_8. Max instruction stack depth for
    /// THIS dispatch: 5 (inactive, default) or 9 (active). Consumed by push()
    /// instead of the bare MAX_INSTRUCTION_STACK_DEPTH constant. Set per-dispatch
    /// in v2_dispatch.zig from the live FeatureSet; the default = inactive so
    /// every other InvokeContext constructor stays byte-identical to today.
    max_stack_depth: u8 = MAX_INSTRUCTION_STACK_DEPTH,
    /// SIMD-0449 direct_account_pointers_in_program_input. When active, the SVM
    /// input region gets the per-account vm_addr pointer trailer (serialize.zig,
    /// golden-vector-verified). Default false (pre-activation / no live
    /// FeatureSet) → no trailer, byte-identical to baseline. Set per-dispatch in
    /// v2_dispatch.zig; read by cpi.zig when it builds SerializeConfig for a CPI.
    direct_account_pointers_active: bool = false,
    /// disable_zk_elgamal_proof_program / reenable_zk_elgamal_proof_program.
    /// Verified against agave-4.2.0-beta.1-src/programs/zk-elgamal-proof/
    /// src/lib.rs:172-181 (`declare_process_instruction!` entrypoint, the
    /// FIRST thing it does, before even fetching `instruction_data`):
    /// `if invoke_context.get_feature_set().disable_zk_elgamal_proof_program
    /// && !invoke_context.get_feature_set().reenable_zk_elgamal_proof_program
    /// { ic_msg!(...); return Err(InstructionError::InvalidInstructionData); }`
    /// -- zero CU consumed (the macro's default charge is 0 and the gate
    /// returns before any `consume_checked` call). Default false for both,
    /// matching every other SIMD gate on this struct (pre-activation / no
    /// live FeatureSet). Set per-dispatch in v2_dispatch.zig from the live
    /// FeatureSet (same pattern as enable_bls12_381_syscall above).
    disable_zk_elgamal_proof_program_active: bool = false,
    reenable_zk_elgamal_proof_program_active: bool = false,

    /// (M6 RFC `RFC-invoke-ctx-syscall-bindings.md`) Active memory map for
    /// syscall pointer translation. `*anyopaque` to break the otherwise
    /// circular dep `invoke_ctx ⇄ memory`. Bound by the interpreter
    /// immediately before each invoke; null outside the VM.
    mm: ?*anyopaque = null,

    /// (M6 RFC) Transaction signature for `[VBPF2-TRACE]` log lines.
    /// Wave 3.5 wires this from the replay tx context; placeholder
    /// (all zeros) until then. No invariants depend on the bytes.
    tx_signature: [64]u8 = .{0} ** 64,

    /// (Wave 6A) CPI injection — opaque pointers populated by the V2
    /// dispatch entry (`v2_dispatch.v2DispatchBpfProgram`) just before
    /// `vm.run()`, cleared on return. All three are `*anyopaque` to
    /// preserve invoke_ctx's "leaf module, no upward imports" property.
    ///
    ///   • `cpi_syscalls`         — `*M6.SyscallRegistry` (the concrete
    ///                              registry instance whose `.asTrait()`
    ///                              the recursive Vm needs).
    ///   • `cpi_resolver_ctx`     — opaque first half of `cpi.ProgramResolver`.
    ///   • `cpi_resolver_resolve` — function-pointer half: matches
    ///                              `cpi.ProgramResolver.VTable.resolve`'s
    ///                              shape but typed opaque.
    ///
    /// `solInvokeSignedC/Rust` in `syscalls.zig` reads these to construct
    /// the trait + resolver and call `cpi.handleSolInvokeSigned`. When all
    /// three are null (default), CPI returns `error.M6_CpiHandlerNotReady`
    /// — preserving every existing caller's behaviour.
    cpi_syscalls: ?*anyopaque = null,
    cpi_resolver_ctx: ?*anyopaque = null,
    cpi_resolver_resolve: ?*const anyopaque = null,

    pub fn init(
        alloc: std.mem.Allocator,
        tx: *TransactionContext,
        cache: *const SysvarCache,
        compute_units: u64,
    ) InvokeContext {
        return .{
            .allocator = alloc,
            .tx = tx,
            .sysvar_cache = cache,
            .compute_remaining = compute_units,
            .instruction_stack = .{ .allocator = alloc },
        };
    }

    pub fn deinit(self: *InvokeContext) void {
        self.instruction_stack.deinit();
    }

    // ── Stack management ──────────────────────────────────────────────────

    /// True when position `i` holds the FIRST occurrence of its tx-account
    /// index within `indices`. Duplicate instruction-account metas (the same
    /// pubkey listed more than once in one instruction — legal and common,
    /// e.g. LayerZero V2 Send lists the payer 2-3×) all reference the SAME
    /// underlying tx account, so lamport-conservation sums must count each
    /// unique account exactly ONCE.
    ///
    /// CARRIER (2026-06-11, onset slot 414602449): per-occurrence summing
    /// counted a duplicated payer's lamports twice on both sides of the
    /// check; when that account's lamports CHANGED inside the frame the
    /// double-count broke ∑pre==∑post → false UnbalancedInstruction →
    /// M7_PostCheckFailed → Vexor failed (fee-only) a tx the cluster
    /// executed → accounts_lt_hash divergence (equal sig counts).
    /// Canonical refs: Agave tracks a TX-WIDE lamports_delta updated once
    /// per account write (transaction-context/src/transaction_accounts.rs:245,
    /// 411-422; checked at transaction.rs:382,454) — per-unique-account by
    /// construction. Firedancer dedups explicitly (privilege union
    /// fd_vm_syscall_cpi.c:101-124; commit-once-per-unique
    /// fd_vm_syscall_cpi_common.c:260-263). This dedup keeps Vexor's
    /// frame-sum architecture while matching their per-unique semantics.
    pub fn isFirstOccurrence(indices: []const u16, i: usize) bool {
        const aidx = indices[i];
        for (indices[0..i]) |prev| {
            if (prev == aidx) return false;
        }
        return true;
    }

    pub fn push(self: *InvokeContext, program_idx: u16, account_indices: []const u16) InvokeError!void {
        // SIMD-0268: per-dispatch limit (5 inactive / 9 active) instead of the
        // bare constant. self.max_stack_depth defaults to MAX_INSTRUCTION_STACK_DEPTH
        // (5) so the inactive path is byte-identical. Semantics unchanged: 0-based
        // depth, `>=` reject — matches Agave transaction.rs:415.
        if (self.instruction_stack.depth() >= self.max_stack_depth)
            return error.CallDepthExceeded;
        if (program_idx >= self.tx.accounts.len) return error.InvalidIndex;

        // Snapshot every borrowed account (per-occurrence — snapshots back
        // other invariant checks). Lamport sum counts UNIQUE accounts once.
        const snaps = try self.allocator.alloc(AccountView.Snapshot, account_indices.len);
        var sum_lamports: u128 = 0;
        for (account_indices, 0..) |aidx, i| {
            if (aidx >= self.tx.accounts.len) {
                self.allocator.free(snaps);
                return error.InvalidIndex;
            }
            const a = &self.tx.accounts[aidx];
            snaps[i] = .{
                .lamports = a.lamports,
                .owner = a.owner,
                .data_hash = hashAccountData(a.data),
            };
            a.pre_snapshot = snaps[i];
            if (isFirstOccurrence(account_indices, i)) sum_lamports += a.lamports;
        }

        try self.instruction_stack.frames.append(self.allocator, .{
            .program_idx = program_idx,
            .account_indices = account_indices,
            .lamport_sum_at_push = sum_lamports,
            .pre_snapshots = snaps,
        });
    }

    pub fn pop(self: *InvokeContext) void {
        if (self.instruction_stack.frames.items.len == 0) return;
        const frame = self.instruction_stack.frames.pop().?;
        self.allocator.free(frame.pre_snapshots);
    }

    pub fn currentDepth(self: *const InvokeContext) u8 {
        return self.instruction_stack.depth();
    }

    pub fn currentFrame(self: *InvokeContext) ?*InstructionFrame {
        return self.instruction_stack.current();
    }

    pub fn currentProgramId(self: *InvokeContext) ?Pubkey32 {
        const f = self.instruction_stack.current() orelse return null;
        if (f.program_idx >= self.tx.accounts.len) return null;
        return self.tx.accounts[f.program_idx].pubkey;
    }

    // ── Compute meter ─────────────────────────────────────────────────────

    pub fn consumeCompute(self: *InvokeContext, units: u64) error{OutOfCompute}!void {
        if (units > self.compute_remaining) {
            self.compute_remaining = 0;
            return error.OutOfCompute;
        }
        self.compute_remaining -= units;
    }

    pub fn computeRemaining(self: *const InvokeContext) u64 {
        return self.compute_remaining;
    }

    /// Agave program-runtime/src/vm.rs:35-46 calculate_heap_cost(heap_size,
    /// heap_cost=8 [DEFAULT_HEAP_COST, execution_budget.rs:30]):
    ///   rounded = heap_size + (32*1024 - 1)
    ///   cost = (rounded / (32*1024) - 1) * heap_cost
    /// Default heap_size=32768 → cost=0 (the vast majority of txs never set
    /// RequestHeapFrame). Mirrors vex_svm/compute_budget.zig's identical
    /// calculateHeapCost() (kept duplicated, not shared, to avoid a
    /// vex_bpf2 <-> vex_svm module-layering dependency — vex_svm already
    /// depends on vex_bpf2, not the reverse).
    pub fn calculateHeapCost(heap_size: u32) u64 {
        const KIBIBYTE: u64 = 1024;
        const PAGE_SIZE_KB: u64 = 32;
        const page_bytes: u64 = PAGE_SIZE_KB * KIBIBYTE; // 32768
        const rounded: u64 = @as(u64, heap_size) +| (page_bytes -| 1);
        const pages: u64 = rounded / page_bytes;
        return (pages -| 1) *| 8; // DEFAULT_HEAP_COST
    }

    /// Charge this tx's heap-entry cost — call once per VM creation (top-level
    /// ix dispatch AND every CPI level). See calculateHeapCost() doc above.
    pub fn chargeHeapCost(self: *InvokeContext) error{OutOfCompute}!void {
        return self.consumeCompute(calculateHeapCost(self.heap_size));
    }

    // ── Sysvar lookup (generic + typed) ───────────────────────────────────

    /// Generic comptime-typed sysvar accessor. Dispatches to the matching
    /// SysvarCache getter. Locks the vex-058 invariant: no zero-default.
    pub fn getSysvar(self: *InvokeContext, comptime T: type) error{SysvarNotPopulated}!T {
        return switch (T) {
            sysvar_cache.Clock => self.sysvar_cache.getClock(),
            sysvar_cache.Rent => self.sysvar_cache.getRent(),
            sysvar_cache.EpochSchedule => self.sysvar_cache.getEpochSchedule(),
            sysvar_cache.SlotHashes => self.sysvar_cache.getSlotHashes(),
            sysvar_cache.SlotHistory => self.sysvar_cache.getSlotHistory(),
            sysvar_cache.StakeHistory => self.sysvar_cache.getStakeHistory(),
            sysvar_cache.EpochRewards => self.sysvar_cache.getEpochRewards(),
            sysvar_cache.LastRestartSlot => self.sysvar_cache.getLastRestartSlot(),
            else => @compileError("getSysvar: unsupported type " ++ @typeName(T)),
        };
    }

    pub fn getSysvarBytes(self: *InvokeContext, pk: Pubkey32) error{SysvarNotPopulated}![]const u8 {
        return self.sysvar_cache.getBytesByPubkey(pk);
    }

    // ── Five invariant checks (R3 §4) ─────────────────────────────────────

    /// (3) Per-instruction lamport balance must hold (∑pre == ∑post).
    /// Each UNIQUE tx account counted once — see isFirstOccurrence (the
    /// 414602449 duplicate-meta carrier). Must mirror push()'s summing rule
    /// exactly or the check is vacuously broken in the other direction.
    pub fn checkLamportBalance(self: *InvokeContext) error{UnbalancedInstruction}!void {
        const f = self.instruction_stack.current() orelse return; // no frame ⇒ nothing to check.
        var post_sum: u128 = 0;
        for (f.account_indices, 0..) |aidx, i| {
            if (isFirstOccurrence(f.account_indices, i)) post_sum += self.tx.accounts[aidx].lamports;
        }
        if (post_sum != f.lamport_sum_at_push) return error.UnbalancedInstruction;
    }

    /// (4) Rent-state transition: any account that was rent-exempt at push
    /// must still be rent-exempt at pop (no fall into rent-paying state).
    /// Without a Rent sysvar we cannot evaluate; treat as pass.
    pub fn checkRentState(self: *InvokeContext) error{InvalidRentPaying}!void {
        const f = self.instruction_stack.current() orelse return;
        const rent = self.sysvar_cache.getRent() catch return; // no rent populated ⇒ skip
        for (f.account_indices, 0..) |aidx, i| {
            const a = &self.tx.accounts[aidx];
            const pre = f.pre_snapshots[i];
            const min_balance_post = rentExemptMinimum(rent, a.data.len);
            // d28ii fix (2026-05-12): removed unused `min_balance_pre = rentExemptMinimum(
            // rent, pre.lamports)`. It passed `pre.lamports` as `data_len`, which for
            // large lamports values overflowed `total_bytes * lamports_per_byte_year` in
            // rentExemptMinimum, crashing the validator on certain CPIs (notably
            // InitializeTipDistributionAccount where pre.lamports for the
            // tip_distribution_account's funding source could exceed safe bounds).
            // The variable was immediately discarded via `_ = min_balance_pre;` —
            // dead code with a sharp edge. Removing eliminates the panic source.
            //
            // The check below is the only one that matters: an account must NOT
            // transition from rent-exempt (pre.lamports >= min) to rent-paying
            // (a.lamports < min) while still holding data (a.data.len > 0).
            //
            // 2026-06-16 fix: a post-state of ZERO lamports is Agave `RentState::Uninitialized`
            // (the account is being CLOSED/deleted), and `RentState::transition_allowed(_, Uninitialized)`
            // is ALWAYS true — it is NOT RentPaying. Without the `a.lamports > 0` guard this wrongly
            // flagged InvalidRentPaying for any CPI that drains an account to 0 while it still holds
            // data (disc-only zeroed, tail preserved). Surfaced by the Stake Merge (source drain) +
            // full-Withdraw CPI ports; the cluster's stake .so makes the identical 0-lamport-with-data
            // transition and passes. (0-lamport accounts are lt-hash-neutral, so consensus is unaffected
            // either way — this only removes a Vexor-only false rejection.) Ref: Agave RentState::from_account.
            if (pre.lamports >= min_balance_post and a.lamports > 0 and a.lamports < min_balance_post and a.data.len > 0) {
                return error.InvalidRentPaying;
            }
        }
    }

    /// (5a) Readonly accounts must not have data or owner mutated.
    pub fn checkReadonlyModified(self: *InvokeContext) error{ReadonlyModified}!void {
        const f = self.instruction_stack.current() orelse return;
        for (f.account_indices, 0..) |aidx, i| {
            const a = &self.tx.accounts[aidx];
            if (a.is_writable) continue;
            const pre = f.pre_snapshots[i];
            if (!std.mem.eql(u8, &pre.owner, &a.owner)) return error.ReadonlyModified;
            const post_hash = hashAccountData(a.data);
            if (!std.mem.eql(u8, &pre.data_hash, &post_hash)) return error.ReadonlyModified;
            if (pre.lamports != a.lamports) return error.ReadonlyModified;
        }
    }

    /// (5b) The program account's owner may not change during its own execution.
    pub fn checkProgramIdModified(self: *InvokeContext) error{ProgramIdModified}!void {
        const f = self.instruction_stack.current() orelse return;
        const program = &self.tx.accounts[f.program_idx];
        // Find program in account_indices to fetch its snapshot.
        for (f.account_indices, 0..) |aidx, i| {
            if (aidx == f.program_idx) {
                const pre = f.pre_snapshots[i];
                if (!std.mem.eql(u8, &pre.owner, &program.owner)) return error.ProgramIdModified;
                return;
            }
        }
        // Program not in borrow set (program-only-as-id case): nothing to check.
    }
};

fn rentExemptMinimum(rent: sysvar_cache.Rent, data_len: usize) u64 {
    // Agave: (DATA_SIZE + ACCOUNT_STORAGE_OVERHEAD) * lamports_per_byte_year * exemption_threshold
    const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
    // d28ii fix (2026-05-12): defensive overflow protection on the lamports math.
    // Real Solana accounts max out at ~10MB data, with lamports_per_byte_year ~3480,
    // so the product is bounded by ~7e10 — far below u64::MAX. But the formula has
    // historically been called with non-data values as `data_len` (see prior caller
    // in checkRentState passing `pre.lamports`). Saturate on overflow per Agave's
    // u128 intermediate semantics in `account_size_to_rent_exempt_minimum` —
    // Agave widens to u128 internally then narrows at the end, so a corrupted
    // input doesn't crash the validator; it simply yields a too-large result that
    // the caller's < comparison treats as rent-paying.
    const total_bytes: u64 = std.math.add(u64, @as(u64, @intCast(data_len)), ACCOUNT_STORAGE_OVERHEAD) catch
        return std.math.maxInt(u64);
    const annual_tup = @mulWithOverflow(total_bytes, rent.lamports_per_byte_year);
    const annual: u64 = if (annual_tup[1] != 0) std.math.maxInt(u64) else annual_tup[0];
    const min_f: f64 = @as(f64, @floatFromInt(annual)) * rent.exemption_threshold;
    if (min_f > @as(f64, @floatFromInt(std.math.maxInt(u64)))) return std.math.maxInt(u64);
    if (min_f < 0) return 0;
    return @intFromFloat(min_f);
}
