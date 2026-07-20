//! Vexor BPF2 — Wave 5 V2 dispatch + Bank↔TransactionContext adapter.
//!
//! ── Why this file exists ───────────────────────────────────────────────────
//! Wave 4 left `v2DispatchInternal` as a stub that returned
//! `error.M9_V2DispatchNotYetWired` and a `shadowDispatchLog` whose mutation
//! count fields were `?`. Wave 5 closes the gap for the M9 builtin path:
//! given a `program_id` + `ix_data` + a slice of pre-state `AccountSnapshot`s
//! over a real (Bank, AccountsDb) substrate, build an `InvokeContext`,
//! drive `vex_bpf2.builtins.dispatch`, then translate the resulting
//! `[]AccountView` deltas into the canonical `[]AccountMutation` shape that
//! V1's `executeBpfProgramCore` already returns.
//!
//! ── What is NOT in this wave ──────────────────────────────────────────────
//! Real V2 BPF (non-builtin) dispatch — the M1→M3→M2→M6→M8→M4 pipeline over
//! a Bank-backed account store — requires a non-trivial M5↔Bank glue layer
//! (program ELF cache + sysvar-backed feature_set + M6 `cpi_handler` wireup).
//! That is genuinely a separate wave; this file documents the gap by
//! returning a named `DispatchError.M5_BankBackedBpfNotPlumbed` so callers
//! can route to V1 fallback without ambiguity.
//!
//! ── M9 fallback table (skeleton-pending → V1 native) ──────────────────────
//! Each `M9_*_VariantPending_*` error is mapped to its V1 native handler:
//!
//!   • `M9_System_VariantPending_*`  → `vex_svm.native.system_v2.execute`
//!     (clean shape — both take `(InstrCtx, ix_data)` and mutate accounts in
//!     place. Trampoline rebuilds an `InstrCtx` from the same snapshot.)
//!   • `M9_Vote_VariantPending_*`    → V1 `executeVoteInstruction` (made
//!     `pub` in `replay_stage.zig:3213` by Wave 6B; body untouched). Wired
//!     via the `FallbackContext` vtable so this file does not need to
//!     import replay_stage's `ParsedTx` / `Bank` / `AccountsDb`.
//!   • `M9_Stake_VariantPending_*`   → V1 `stake_program.execute` in
//!     `native/stake_program.zig:1749`. Same vtable bridge as Vote.
//!   • `M9_AddressLookupTable_VariantPending_*` → V1
//!     `address_lookup_table.execute(InstrCtx, ix_data)` in
//!     `native/address_lookup_table.zig:643`. Routed via the vtable
//!     because ALT's InstrCtx requires Bank-driven sysvar callbacks
//!     (Clock + SlotHashes + Rent.minimum_balance).
//!   • `M9_Config_VariantPending_FullParityNotYetVerified` — no V1 native;
//!     returns `M9_NoFallback`.
//!   • `M9_ZkElGamalProof_VariantPending_*` — no V1 native; returns
//!     `M9_NoFallback` (off testnet hot path).
//!
//! When the caller does NOT supply a `FallbackContext` and a Vote/Stake/ALT
//! variant fires, this file returns `M9_FallbackContextMissing` — fail-loud,
//! never silent. Production callers (replay_stage.zig) always pass one;
//! unit tests can pass `null` to assert that the fail-loud path fires.
//!
//! Mutation capture for Vote/Stake/ALT: the V1 handlers commit by appending
//! to `bank.pending_writes`. The replay_stage trampoline snapshots
//! `pending_writes.items.len` before the V1 call, slices items appended
//! after, converts each `AccountWrite` to `AccountMutation`, and truncates
//! `pending_writes.items.len` back to the snapshot length so the unified
//! commit path doesn't double-commit. This is safe because `pending_writes`
//! is per-Bank and replay schedules instructions serially per color group.
//!
//! Callers in `replay_stage.dispatchBpfExecution` route `M9_NoFallback`
//! through the V1 BPF path (which is what the legacy program_id route
//! already does today) — i.e. fail-loud-but-recoverable.
//!
//! ── AccountMutation shape unification ─────────────────────────────────────
//! V1's `vex_bpf.AccountMutation` (extended Wave 5 with `new_owner: ?[32]u8`)
//! is the single canonical shape consumed by the bank commit loop and the
//! shadow diff comparator. V2 paths translate post-state `AccountView`s back
//! to this shape; V1 sets `new_owner = null` (owner unchanged at commit).
//!
//! ── fix_ledger anchors ────────────────────────────────────────────────────
//!   • vex-079 — V1 path's BPF align_pad fix lives in
//!     `src/vex_bpf/sbpf_executor.zig:1161` and is NOT touched by this file.
//!   • vex-058 — InvokeContext built here propagates SysvarNotPopulated; the
//!     EpochSchedule.DEFAULT in `src/vex_svm/bank.zig` is the source of truth.
//!   • vex-039 — `currentProgramId()` is read from frame, not inferred.
//!   • vex-053 — ALT-resolved accounts come from caller-supplied snapshots;
//!     this file never re-resolves.

const std = @import("std");

const features = @import("features.zig");
const vex_bpf2 = @import("vex_bpf2");
const builtins = vex_bpf2.builtins;
const ic_mod = vex_bpf2.invoke_ctx;
const bpf_v1 = @import("vex_bpf");
const native_system = @import("native/system_v2.zig");
// Re-use V1 native's AccountMeta alias (= AccountMeta) to keep this
// file's deps narrow — avoids pulling vex_svm/root.zig into the v2_dispatch
// test module's dep graph.
const AccountMeta = native_system.AccountMeta;

pub const InvokeContext = ic_mod.InvokeContext;
pub const TransactionContext = ic_mod.TransactionContext;
pub const AccountView = ic_mod.AccountView;
pub const SysvarCache = ic_mod.SysvarCache;
pub const Pubkey32 = ic_mod.Pubkey32;
pub const AccountMutation = bpf_v1.AccountMutation;

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

/// Top-level dispatch errors from `v2DispatchInternal`. Callers (replay_stage)
/// pattern-match on these to choose between V2 commit, V1 fallback, or
/// fail-loud abort. NO bare `error.NotImplemented` — every gap has a name.
pub const DispatchError = error{
    /// Real V2 BPF (non-builtin) program path is not plumbed in this wave.
    /// Caller must run the V1 BPF path (`executeBpfProgramCore`).
    M5_BankBackedBpfNotPlumbed,
    /// M9 builtin returned a `_VariantPending_` error AND the program has no
    /// V1 native fallback wired (Config + ZkElGamalProof in Wave 6B).
    /// Caller must run the V1 BPF path; the legacy `program_id` route already
    /// handles native programs ahead of this dispatcher.
    M9_NoFallback,
    /// M9 builtin returned an error other than VariantPending. Failed loud.
    /// Caller logs + skips commit.
    M9_BuiltinFailed,
    /// V1 fallback handler itself errored.
    M9_FallbackFailed,
    // ── Wave 6A: V2 BPF program path errors (additive). The variants below
    //    are produced exclusively by `v2DispatchBpfProgram`; the M9-builtin
    //    `v2DispatchInternal` path is unchanged. ─────────────────────────────
    /// Wave 6A: program ELF bytes missing or too short to be a valid ELF.
    M5_ProgramNotLoadable,
    /// Wave 6A: M5 input-region build failed.
    M5_SerializeFailed,
    /// Wave 6A: M5 post-execute write-back failed.
    M5_DeserializeFailed,
    /// Wave 6A: SysvarCache was not populated by the dispatcher caller.
    /// Fail loud — vex-058 invariant prohibits silent zero-fill.
    M5_BankSysvarsNotPopulated,
    /// Wave 6A: M1 ELF parse rejected.
    M1_LoadFailed,
    /// Wave 6A: M3 verifier rejected the bytecode.
    M3_VerifyFailed,
    /// Wave 6A: M2 memory map construction failed (region order, OOM).
    M2_MapInitFailed,
    /// Wave 6A: M6 syscall registry construction failed.
    M6_RegistryInitFailed,
    /// Wave 6A: M4 Vm.run returned an InterpreterError.
    M4_RunFailed,
    /// Wave 6A.1: M8 InvokeContext.push failed before M4 ran. Distinct from
    /// M4_RunFailed so triage can tell push vs run vs init failures apart.
    M8_PushFailed,
    /// Wave 6A.1: M4 Vm.init failed (allocator OOM on call_frames, mostly).
    M4_InitFailed,
    /// Wave 6A: CPI target was a builtin not yet implemented (passthrough
    /// from M7).
    M7_BuiltinNotImplemented,
    /// Wave 6A: catch-all for unforeseen non-recoverable conditions.
    /// Reserved — happy paths above produce named variants.
    M5_UnknownDispatchError,
    /// Wave 6B: caller invoked the dispatcher without a FallbackContext but a
    /// builtin emitted an `M9_*_VariantPending_*` error that requires the
    /// V1 native handler (Vote/Stake/ALT). Fail-loud — the caller must
    /// supply a context or accept that this code path is unreachable.
    M9_FallbackContextMissing,
    /// Wave 6B: V1 Vote native handler failed.
    M9_VoteFallbackFailed,
    /// Wave 6B: V1 Stake native handler failed.
    M9_StakeFallbackFailed,
    /// Wave 6B: V1 Address Lookup Table native handler failed.
    M9_AltFallbackFailed,
    /// Adapter could not allocate mutable account snapshots.
    OutOfMemory,
};

// ──────────────────────────────────────────────────────────────────────────────
// FallbackContext — Wave 6B
// ──────────────────────────────────────────────────────────────────────────────
//
// V1 native handlers for Vote / Stake / ALT require richer state than this
// file's narrow snapshot+sysvar shape carries:
//
//   • Vote   (`executeVoteInstruction` in replay_stage.zig:3213) needs
//     `(ParsedInstruction, ParsedTx, Bank, AccountsDb, Allocator)`.
//   • Stake  (`stake_program.execute` in native/stake_program.zig:1749)
//     takes the same five-tuple via `anytype`.
//   • ALT    (`address_lookup_table.execute` in native/address_lookup_table.zig:643)
//     takes `(InstrCtx, ix_data)` but InstrCtx wants live sysvar callbacks
//     populated from Bank.
//
// We avoid pulling replay_stage's `ParsedTx` / `Bank` / `AccountsDb` into
// this module's import graph (would create a circular edge through
// vex_bpf → vex_store → vex_svm). Instead, this struct carries an opaque
// pointer + a vtable of trampoline fns implemented in replay_stage.zig
// (bodies of V1 handlers untouched — only the visibility of
// `executeVoteInstruction` was widened).
//
// The trampoline contract:
//   • Returns []AccountMutation owned by `alloc` (caller frees per-element
//     `data` and the slice).
//   • Returns `error.M9_<Program>FallbackFailed` on inner failure.
//   • MUST NOT commit to bank.pending_writes — capture-and-rollback is the
//     trampoline's responsibility (snapshot `pending_writes.items.len`
//     before the V1 call, slice the appended items, convert each to
//     AccountMutation, then truncate back to the snapshot length).

pub const FallbackKind = enum { vote, stake, alt };

pub const FallbackTrampoline = *const fn (
    state: *anyopaque,
    kind: FallbackKind,
    alloc: std.mem.Allocator,
    program_id: *const [32]u8,
    ix_data: []const u8,
    snapshots: []const AccountSnapshot,
) DispatchError![]AccountMutation;

pub const FallbackContext = struct {
    state: *anyopaque,
    trampoline: FallbackTrampoline,
    /// Nonce-CPI Tier-2: durable-nonce env (bank.last_blockhash + lamports_per_signature
    /// + rent-min fn), threaded from replay_stage (which has Bank access) so the CPI
    /// `fallbackSystem` path can execute System Advance/Withdraw/Initialize (4/5/6) instead
    /// of failing `M9_System_VariantPending_*`. null on callers without Bank access → nonce
    /// ops still fail loudly via requireNonceEnv (never commit a garbage blockhash).
    nonce_env: ?native_system.NonceEnv = null,
};

// ──────────────────────────────────────────────────────────────────────────────
// AccountSnapshot — caller-supplied per-account input to v2DispatchInternal
// ──────────────────────────────────────────────────────────────────────────────
//
// The replay_stage caller already has (Bank, AccountsDb) and reads
// AccountMeta-shaped state for each instruction's account list. This struct
// is the canonical input to V2 dispatch — the adapter clones each snapshot's
// data into a fresh mutable buffer so M9 handlers can mutate without
// touching the AccountsDb mmap.

pub const AccountSnapshot = struct {
    pubkey: Pubkey32,
    lamports: u64,
    owner: Pubkey32,
    executable: bool,
    rent_epoch: u64,
    /// Pre-state data. Adapter dupes into a fresh writable buffer.
    data: []const u8,
    is_writable: bool,
    is_signer: bool,
};

// ──────────────────────────────────────────────────────────────────────────────
// Adapter: AccountSnapshot[] → TransactionContext
// ──────────────────────────────────────────────────────────────────────────────

/// Owned-state container for a TransactionContext built from snapshots. The
/// caller `deinit`s when done. M9 handlers mutate `tx.accounts[*].data` /
/// `lamports` / `owner` in place; we read the diffs at the end.
pub const TxCtxOwned = struct {
    allocator: std.mem.Allocator,
    accounts: []AccountView,
    program_indices: []u16,
    /// Pre-state copies (parallel to `accounts`); used to detect mutations.
    pre_lamports: []u64,
    pre_owners: []Pubkey32,
    pre_data_lens: []usize,
    pre_data_hashes: [][32]u8,
    /// The TransactionContext itself, allocated inline so InvokeContext can
    /// reference a stable address.
    tx: TransactionContext,

    pub fn init(
        alloc: std.mem.Allocator,
        snapshots: []const AccountSnapshot,
    ) DispatchError!TxCtxOwned {
        return initWithExtras(alloc, snapshots, &[_]AccountSnapshot{});
    }

    /// r75-bug-class-b-tx-cpi-extras (2026-05-06): build tx context with EX
    /// the per-instruction snapshots PLUS extra tx-level accounts that this
    /// instruction doesn't directly reference but a CPI from this program
    /// might (System program, BPF Loader, etc.). The first `snapshots.len`
    /// accounts are the ix-level set used for serialization (BPF input
    /// region); the remainder are CPI-only refs. The serializer sees ONLY
    /// the first slice (caller's responsibility to pass it accordingly);
    /// `findAccountIndex` walks the full set, so CPIs to System::CreateAccount
    /// (and any other tx-level program) resolve correctly.
    ///
    /// Without this, `findAccountIndex` returns null for the System program
    /// because the InitializePriorityFeeDistributionAccount ix doesn't list
    /// System in its account_indices — only its own PDAs + payer. The CPI
    /// to System::CreateAccount then surfaces M7_AccountNotInTransaction →
    /// M6_CpiHandlerNotReady → tx revert → bank_hash divergence (slot 345+
    /// fingerprint, see project_bug_class_b_partial_parity_FIXED memo).
    pub fn initWithExtras(
        alloc: std.mem.Allocator,
        snapshots: []const AccountSnapshot,
        extras: []const AccountSnapshot,
    ) DispatchError!TxCtxOwned {
        const n_ix = snapshots.len;
        const n_extra = extras.len;
        const n = n_ix + n_extra;
        const accounts = alloc.alloc(AccountView, n) catch return error.OutOfMemory;
        errdefer alloc.free(accounts);
        // PR-5f (2026-05-14): size pre-state arrays to full n. The Firedancer
        // #4ad0b1bbe CPI restructure rebase (commit 09f2a56) made the inner-CPI
        // writeback canonical; with that foundation, surfacing extras'
        // mutations via extractMutations no longer propagates divergent bytes.
        // Empirical: at slot 408467681 (anchor+614 cascade), per-pubkey diff
        // showed 1154/1158 cluster accounts byte-exact with Vexor and exactly
        // 4 cluster-only accounts (2 SPL Token + 2 HXGHX, all created via
        // System.createAccount CPI from a HXGHX program ix). The drop site is
        // this extras path. See project_slot_681_cpi_extras_carrier_2026_05_14.
        const pre_lamports = alloc.alloc(u64, n) catch return error.OutOfMemory;
        errdefer alloc.free(pre_lamports);
        const pre_owners = alloc.alloc(Pubkey32, n) catch return error.OutOfMemory;
        errdefer alloc.free(pre_owners);
        const pre_data_lens = alloc.alloc(usize, n) catch return error.OutOfMemory;
        errdefer alloc.free(pre_data_lens);
        const pre_data_hashes = alloc.alloc([32]u8, n) catch return error.OutOfMemory;
        errdefer alloc.free(pre_data_hashes);
        const program_indices = alloc.alloc(u16, 0) catch return error.OutOfMemory;

        for (snapshots, 0..) |s, i| {
            const data_copy = alloc.alloc(u8, s.data.len) catch return error.OutOfMemory;
            if (s.data.len > 0) @memcpy(data_copy, s.data);

            accounts[i] = .{
                .pubkey = s.pubkey,
                .lamports = s.lamports,
                .owner = s.owner,
                .executable = s.executable,
                .rent_epoch = s.rent_epoch,
                .data = data_copy,
                .is_writable = s.is_writable,
                .is_signer = s.is_signer,
            };
            pre_lamports[i] = s.lamports;
            pre_owners[i] = s.owner;
            pre_data_lens[i] = s.data.len;
            std.crypto.hash.sha2.Sha256.hash(s.data, &pre_data_hashes[i], .{});
        }
        for (extras, 0..) |s, i| {
            const data_copy = alloc.alloc(u8, s.data.len) catch return error.OutOfMemory;
            if (s.data.len > 0) @memcpy(data_copy, s.data);
            accounts[n_ix + i] = .{
                .pubkey = s.pubkey,
                .lamports = s.lamports,
                .owner = s.owner,
                .executable = s.executable,
                .rent_epoch = s.rent_epoch,
                .data = data_copy,
                // PR-5f (2026-05-14): propagate caller's W/S. Post-CPI-rebase
                // the inner writeback at cpi.zig is canonical, so surfacing
                // these mutations no longer regresses (d28ff revert rationale
                // no longer applies). At slot 408467681 the cascade carrier
                // was 4 cluster-only accounts created via CPI System.create —
                // dropped here when extras were forced read-only.
                .is_writable = s.is_writable,
                .is_signer = s.is_signer,
            };
            const eidx = n_ix + i;
            pre_lamports[eidx] = s.lamports;
            pre_owners[eidx] = s.owner;
            pre_data_lens[eidx] = s.data.len;
            std.crypto.hash.sha2.Sha256.hash(s.data, &pre_data_hashes[eidx], .{});
        }

        return .{
            .allocator = alloc,
            .accounts = accounts,
            .program_indices = program_indices,
            .pre_lamports = pre_lamports,
            .pre_owners = pre_owners,
            .pre_data_lens = pre_data_lens,
            .pre_data_hashes = pre_data_hashes,
            .tx = TransactionContext.init(alloc, accounts, program_indices),
        };
    }

    pub fn deinit(self: *TxCtxOwned) void {
        for (self.accounts) |*a| self.allocator.free(a.data);
        self.allocator.free(self.accounts);
        self.allocator.free(self.program_indices);
        self.allocator.free(self.pre_lamports);
        self.allocator.free(self.pre_owners);
        self.allocator.free(self.pre_data_lens);
        self.allocator.free(self.pre_data_hashes);
        self.tx.deinit();
    }

    /// Walk `accounts` and emit one `AccountMutation` per writable account
    /// whose lamports / data / owner differ from the pre-state. The returned
    /// slice + every `m.data` are owned by the caller (allocated from
    /// `mut_alloc`, NOT the snapshot allocator — so the mutations outlive
    /// `deinit`).
    pub fn extractMutations(
        self: *const TxCtxOwned,
        mut_alloc: std.mem.Allocator,
    ) DispatchError![]AccountMutation {
        var list = std.ArrayListUnmanaged(AccountMutation){};
        errdefer {
            for (list.items) |*m| mut_alloc.free(m.data);
            list.deinit(mut_alloc);
        }

        // PR-5f (2026-05-14): walk full self.accounts (ix-level + extras).
        // initWithExtras now sizes pre_arrays to n_ix+n_extra and populates
        // pre_data_hashes for extras, so this loop reads valid pre-state for
        // every index. CPI rebase 09f2a56 made writeback canonical, so the
        // d28ff regression rationale no longer applies — at slot 408467681
        // the missing 4 cluster-only accounts are the System.createAccount
        // CPI extras that this widened walk now surfaces.
        for (self.accounts, 0..) |a, i| {
            if (!a.is_writable) continue;
            const lamports_changed = a.lamports != self.pre_lamports[i];
            const data_changed_len = a.data.len != self.pre_data_lens[i];
            var data_changed_bytes: bool = false;
            if (!data_changed_len and a.data.len > 0) {
                var post_hash: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(a.data, &post_hash, .{});
                data_changed_bytes = !std.mem.eql(u8, &post_hash, &self.pre_data_hashes[i]);
            }
            const owner_changed = !std.mem.eql(u8, &a.owner, &self.pre_owners[i]);
            const changed = lamports_changed or data_changed_len or data_changed_bytes or owner_changed;
            if (!changed) continue;

            const data_copy = mut_alloc.alloc(u8, a.data.len) catch return error.OutOfMemory;
            if (a.data.len > 0) @memcpy(data_copy, a.data);

            const new_owner_opt: ?[32]u8 = if (owner_changed) a.owner else null;

            list.append(mut_alloc, .{
                .pubkey = .{ .data = a.pubkey },
                .new_lamports = a.lamports,
                .owner = a.owner, // vex-039 restored: post-mutation owner (V2)
                .data = data_copy,
                .new_owner = new_owner_opt,
            }) catch return error.OutOfMemory;
        }
        return list.toOwnedSlice(mut_alloc) catch error.OutOfMemory;
    }
};

// ──────────────────────────────────────────────────────────────────────────────
// V2 dispatch entry
// ──────────────────────────────────────────────────────────────────────────────

/// Default compute units for builtin invocation when caller hasn't pre-charged.
/// @prov:compute-budget.exec-limit
pub const DEFAULT_COMPUTE_UNITS: u64 = 1_400_000;

/// Top-level V2 dispatch. Routes builtin programs through M9 + the Bank
/// adapter; routes BPF programs to the named `M5_BankBackedBpfNotPlumbed`
/// error so the caller can fall through to V1. Returns mutations the caller
/// commits (mutations alloc'd from `alloc`; caller frees per-element data
/// + the slice itself).
///
/// Wave 6B: `fallback_ctx` is an optional vtable-backed bridge to V1's
/// native handlers for Vote / Stake / ALT. When `null`, M9 emits
/// `M9_FallbackContextMissing` for those programs (fail-loud — production
/// callers always supply a context). Config + ZkElGamalProof remain
/// `M9_NoFallback` (no V1 native handler exists for those).
pub fn v2DispatchInternal(
    alloc: std.mem.Allocator,
    program_id: *const [32]u8,
    ix_data: []const u8,
    snapshots: []const AccountSnapshot,
    sysvars: *const SysvarCache,
    fallback_ctx: ?FallbackContext,
) DispatchError![]AccountMutation {
    if (!builtins.isBuiltin(program_id)) {
        return error.M5_BankBackedBpfNotPlumbed;
    }

    var owned = try TxCtxOwned.init(alloc, snapshots);
    defer owned.deinit();

    var ctx = InvokeContext.init(alloc, &owned.tx, sysvars, DEFAULT_COMPUTE_UNITS);
    defer ctx.deinit();

    // Per M9 dispatch contract, caller must push a frame. We synthesize one
    // covering all snapshots (program_idx = 0 by convention; program account
    // is expected to be present in snapshots if M9 needs it).
    const account_indices = alloc.alloc(u16, snapshots.len) catch return error.OutOfMemory;
    defer alloc.free(account_indices);
    for (account_indices, 0..) |*aidx, i| aidx.* = @intCast(i);

    ctx.push(0, account_indices) catch return error.M9_BuiltinFailed;
    defer ctx.pop();

    builtins.dispatch(&ctx, program_id, ix_data) catch |e| {
        const ename = @errorName(e);
        // System: clean snapshot-shape compat, no Bank needed.
        if (std.mem.startsWith(u8, ename, "M9_System_VariantPending_")) {
            // Nonce-CPI Tier-2: thread the durable-nonce env from the caller's
            // FallbackContext so Advance/Withdraw/Initialize (4/5/6) execute.
            return fallbackSystem(alloc, ix_data, &owned, snapshots, if (fallback_ctx) |fc| fc.nonce_env else null);
        }
        // Vote / Stake / ALT: route through the fallback vtable to V1
        // native handlers. The trampoline lives in replay_stage.zig (where
        // ParsedTx + Bank + AccountsDb are in scope) and captures
        // mutations via bank.pending_writes snapshot-diff-rollback.
        const kind: ?FallbackKind = blk: {
            if (std.mem.startsWith(u8, ename, "M9_Vote_VariantPending_"))
                break :blk .vote;
            if (std.mem.startsWith(u8, ename, "M9_Stake_VariantPending_"))
                break :blk .stake;
            if (std.mem.startsWith(u8, ename, "M9_AddressLookupTable_VariantPending_"))
                break :blk .alt;
            break :blk null;
        };
        if (kind) |k| {
            const fb = fallback_ctx orelse return error.M9_FallbackContextMissing;
            return fb.trampoline(fb.state, k, alloc, program_id, ix_data, snapshots);
        }
        // Config + ZkElGamalProof: no V1 native handler, documented gap.
        if (std.mem.startsWith(u8, ename, "M9_Config_VariantPending_") or
            std.mem.startsWith(u8, ename, "M9_ZkElGamalProof_VariantPending_"))
        {
            return error.M9_NoFallback;
        }
        return error.M9_BuiltinFailed;
    };

    return owned.extractMutations(alloc);
}

// ──────────────────────────────────────────────────────────────────────────────
// V1 native fallbacks
// ──────────────────────────────────────────────────────────────────────────────

/// Build an InstrCtx-shape from snapshots, run V1's system_v2.execute, then
/// translate any mutations back to AccountMutation. Used when M9's system
/// program returns `M9_System_VariantPending_*`.
///
/// V1 signature: `system_v2.execute(ctx: *const InstrCtx, instr_data: []const u8) InstrError!void`
/// (`src/vex_svm/native/system_v2.zig:561`).
fn fallbackSystem(
    alloc: std.mem.Allocator,
    ix_data: []const u8,
    owned: *TxCtxOwned,
    snapshots: []const AccountSnapshot,
    /// Nonce-CPI Tier-2: durable-nonce env from the caller's Bank (null = no Bank
    /// access → nonce 4/5/6 fail loudly via requireNonceEnv, unchanged behavior).
    nonce_env: ?native_system.NonceEnv,
) DispatchError![]AccountMutation {
    // Build [N]AccountMeta + signer mask matching V1's expectations.
    const n = snapshots.len;
    const metas = alloc.alloc(AccountMeta, n) catch return error.OutOfMemory;
    defer {
        // V1 may have replaced .data via realloc; only free if pointer
        // differs from the snapshot's data buffer (which TxCtxOwned
        // already frees in its deinit).
        for (metas, 0..) |m, i| {
            if (m.data.ptr != owned.accounts[i].data.ptr) alloc.free(m.data);
        }
        alloc.free(metas);
    }

    var signer_mask: u64 = 0;
    var writable_mask: u64 = 0;
    for (snapshots, 0..) |s, i| {
        // Re-clone the data buffer so V1 can resize without disturbing the
        // owned TxCtx slot. (TxCtxOwned still owns the original.)
        const data_copy = alloc.alloc(u8, s.data.len) catch return error.OutOfMemory;
        if (s.data.len > 0) @memcpy(data_copy, s.data);
        metas[i] = .{
            .pubkey = .{ .data = s.pubkey },
            .lamports = s.lamports,
            .owner = .{ .data = s.owner },
            .executable = s.executable,
            .rent_epoch = s.rent_epoch,
            .data = data_copy,
        };
        if (s.is_signer and i < 64) signer_mask |= @as(u64, 1) << @intCast(i);
        if (s.is_writable and i < 64) writable_mask |= @as(u64, 1) << @intCast(i);
    }

    // fix/wire-nonce-ops (2026-06-10): writable_mask now populated from the
    // snapshots (nonce ops check instruction-level writability). nonce_env is
    // intentionally LEFT NULL here — this V2 fallback has no Bank access, so
    // Advance/Withdraw/Initialize nonce ops fail loudly (requireNonceEnv
    // [NONCE] warn) instead of advancing against a garbage blockhash. The
    // LIVE path (replay_stage.executeSystemInstruction) wires the real env.
    var ictx = native_system.InstrCtx{
        .accounts = metas,
        .signer_mask = signer_mask,
        .allocator = alloc,
        .writable_mask = writable_mask,
        // Nonce-CPI Tier-2: real env when the caller (replay_stage) supplied one.
        .nonce_env = nonce_env,
    };

    native_system.execute(&ictx, ix_data) catch return error.M9_FallbackFailed;

    // Translate metas back to AccountMutation by diffing against snapshots.
    var list = std.ArrayListUnmanaged(AccountMutation){};
    errdefer {
        for (list.items) |*m| alloc.free(m.data);
        list.deinit(alloc);
    }
    for (metas, snapshots) |m, s| {
        if (!s.is_writable) continue;
        const lamports_changed = m.lamports != s.lamports;
        const owner_changed = !std.mem.eql(u8, &m.owner.data, &s.owner);
        const data_changed = (m.data.len != s.data.len) or
            (m.data.len > 0 and !std.mem.eql(u8, m.data, s.data));
        if (!lamports_changed and !owner_changed and !data_changed) continue;
        const data_out = alloc.alloc(u8, m.data.len) catch return error.OutOfMemory;
        if (m.data.len > 0) @memcpy(data_out, m.data);
        list.append(alloc, .{
            .pubkey = m.pubkey,
            .new_lamports = m.lamports,
            .owner = m.owner.data, // vex-039 restored: post-mutation owner (V2 builtin)
            .data = data_out,
            .new_owner = if (owner_changed) m.owner.data else null,
        }) catch return error.OutOfMemory;
    }
    return list.toOwnedSlice(alloc) catch error.OutOfMemory;
}

// Wave 6B: ALT fallback moved into replay_stage.zig as part of the
// FallbackContext vtable — it needs Bank-driven sysvar callbacks that this
// module deliberately doesn't import. See `replay_stage.zig::wave6b.runAltFallback`.

// ──────────────────────────────────────────────────────────────────────────────
// Wave 6A — V2 BPF program path
// ──────────────────────────────────────────────────────────────────────────────
//
// `v2DispatchBpfProgram` is the end-to-end V2 BPF execution entry. It composes
// the locked v2 modules (M1 elf, M2 memory, M3 verifier, M4 interpreter,
// M5 serialize, M6 syscalls, M7 cpi, M8 invoke_ctx) over a Bank-backed
// account substrate to produce a `[]AccountMutation` the caller commits.
//
// Design constraints (non-negotiable):
//   • DOES NOT modify any locked module (vex-079 / vex-058 / vex-152m/n/n2/o
//     remain in their files, untouched).
//   • Production-mainnet shape: every error path produces a named
//     `DispatchError` variant; no silent stubs.
//   • CPI handler is injected via `InvokeContext.cpi_*` opaque hooks (Wave 6A
//     `invoke_ctx.zig` field additions). The M6 SyscallRegistry itself is
//     unchanged — `solInvokeSignedC/Rust` reads the hooks and calls
//     `cpi.handleSolInvokeSigned`.
//
// CU accounting: caller passes a `compute_budget`; we initialise the Vm with
// it. For Wave 6A the replay_stage caller does NOT thread a per-tx CU pool
// (no such pool exists today); pass `DEFAULT_COMPUTE_UNITS`.
//
// Lifetime contract (CRITICAL):
//   • `program_cache` OWNS every `Executable*` it stores; this function
//     BORROWS on cache hit, INSERTS on cache miss (`cache.put` takes
//     ownership). Callers must NOT free returned executables.

const elf2 = vex_bpf2.elf;
const memory2 = vex_bpf2.memory;
const verifier2 = vex_bpf2.verifier;
const interpreter2 = vex_bpf2.interpreter;
const syscalls2 = vex_bpf2.syscalls;
const serialize2 = vex_bpf2.serialize;
const cpi2 = vex_bpf2.cpi;
pub const V2ProgramCache = vex_bpf2.v2_program_cache.V2ProgramCache;
pub const V2ProgramCacheEntry = vex_bpf2.v2_program_cache.V2ProgramCacheEntry;

/// One entry into the M5 input region — same shape as
/// `serialize.AccountInput`, built from the caller-supplied `AccountSnapshot`.
fn snapshotToAccountInput(s: AccountSnapshot) serialize2.AccountInput {
    return .{
        .pubkey = s.pubkey,
        .owner = s.owner,
        .lamports = s.lamports,
        .data = s.data,
        .executable = s.executable,
        .rent_epoch = s.rent_epoch,
        .is_signer = s.is_signer,
        .is_writable = s.is_writable,
    };
}

/// PR-5e (SIMD-0257 ADDM, BUG-1 fix): MODE-3 direct-mapping writes the BPF
/// VM's mutations directly into the data region's `haddr`. Source the data
/// slice from `owned.tx.accounts[i].data` — the heap-duped writable buffer
/// `TxCtxOwned.initWithExtras` allocated — NOT from `snapshots[i].data` which
/// is the caller's pre-state (often mmap'd, read-only, and not what
/// `extractMutations` diffs against). Other fields are identical to the
/// snapshot they were copied from.
fn accountViewToAccountInput(a: vex_bpf2.invoke_ctx.AccountView) serialize2.AccountInput {
    return .{
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

/// V2 BPF program entry — full pipeline: cache lookup → M1 load → M3 verify
/// → M5 serialize → M2 mm → M6 registry → M8 InvokeContext → M4 Vm.run →
/// M5 deserialize → AccountMutation translation.
///
/// Caller responsibilities:
///   • `sysvars` SHOULD be populated. If a BPF program reads any sysvar
///     against an unpopulated cache, the M6 syscall returns
///     `SysvarNotPopulated`, which folds into M4_RunFailed. Use
///     `vex_svm.bank_sysvar_adapter.BankSysvarAdapter` + `populateFromBank`.
///   • `program_cache` is borrowed; this function may insert a new entry
///     on cache miss. Cache OWNS the executable; we only borrow.
///   • Returned `[]AccountMutation` and each `m.data` are alloc'd from
///     `alloc`; caller frees both per element + the slice.
///
/// ELF bytes + programdata_slot are RESOLVED BY THE CALLER. The caller
/// (replay_stage `executeBpfProgramCore`) already implements the BPF
/// Loader Upgradeable indirection; we accept the result directly so this
/// module does not need to import `vex_store` (matches the existing
/// snapshot-based duck-typed pattern this file uses elsewhere).
///
/// `feature_set` is forwarded to M6 (currently ignored by registry init —
/// `syscalls.SyscallRegistry.init` takes `anytype` and discards it; future
/// waves wire per-feature gating). Pass `.{}` if no feature_set is threaded.
/// PR-5w (2026-05-19) — realloc callback for MODE 3 input-region OOB growth.
/// Mirrors Agave transaction.rs:535-541. When a BPF program writes past
/// current account data length but within `address_space_reserved`, the
/// OOB handler invokes this callback to resize the canonical
/// `owned.accounts[idx].data` slice and update `region.haddr` so subsequent
/// writes land inside the actual buffer instead of heap-adjacent memory.
///
/// Closes the GJHt-class output-byte mismatch carrier. Pre-PR-5w
/// `acct.data` was allocated exactly `s.data.len` bytes (no slack) per
/// v2_dispatch.zig:306,325,540 → writes past dlen corrupted heap-adjacent
/// memory, and the `@min(out.data_len, acct_data.len)` clamp at line 1125
/// discarded them on commit. Now matches cluster's `set_data_length`.
fn reallocAccountDataCallbackPR5w(ctx: *anyopaque, acct_idx: u64, new_len: usize) ?[*]u8 {
    const owned: *TxCtxOwned = @ptrCast(@alignCast(ctx));
    if (acct_idx >= owned.accounts.len) return null;
    const acc = &owned.accounts[acct_idx];
    const old_len = acc.data.len;
    const new_slice = owned.allocator.realloc(acc.data, new_len) catch return null;
    if (new_len > old_len) @memset(new_slice[old_len..new_len], 0);
    acc.data = new_slice;
    return new_slice.ptr;
}

/// FIX #95 (2026-06-01): load + verify + cache one program ELF if not already
/// cached. Used to PRE-WARM CPI-callee programs before dispatch (see
/// replay_stage.zig `prewarmCalleeProgram`). Agave/Firedancer/Sig pre-load
/// every loader-owned executable account in a tx before execution
/// (filter_executable_program_accounts / load_program_accounts /
/// fd_runtime_load_txn_programs); Vexor's resolver
/// (v2_program_cache.zig:resolverThunk) is lookup-only, so a CPI into a
/// program never dispatched top-level THIS run missed → M7_RecursiveLoadFailed
/// → the inner instruction was silently dropped (tx still err=0), corrupting
/// bank_hash. Measured carrier: slot 412458795 BiSoN→SPL-Token CloseAccount
/// (3 closes + a 19,218,520 credit dropped → vote-drop cascade → delinquent).
///
/// Load semantics are byte-identical to the top-level miss path in
/// `v2DispatchBpfProgram` below (same `program_cache.allocator`,
/// `elf2.Executable.load`, `verifier2.verify`, `program_cache.put`) so a
/// pre-warmed program is indistinguishable from a top-level-dispatched one.
/// Idempotent: a `getFresh` hit (upgrade-aware) is a no-op. Strictly additive
/// to cache state — the cache has no LRU/capacity bound (put only replaces an
/// exact-pid upgrade; invalidateBeforeSlot is the only other evictor), so
/// pre-warming a program that is never CPI'd cannot evict anything in use.
pub fn ensureProgramCached(
    program_cache: *V2ProgramCache,
    program_id: [32]u8,
    elf_bytes: []const u8,
    current_slot: u64,
    programdata_slot: u64,
) DispatchError!void {
    if (program_cache.getFresh(program_id, programdata_slot) != null) return;
    if (elf_bytes.len < 16) return DispatchError.M5_ProgramNotLoadable;
    const cache_alloc = program_cache.allocator;
    const exe_heap = cache_alloc.create(elf2.Executable) catch return DispatchError.OutOfMemory;
    exe_heap.* = elf2.Executable.load(cache_alloc, elf_bytes, elf2.Config.DEFAULT) catch {
        cache_alloc.destroy(exe_heap);
        return DispatchError.M1_LoadFailed;
    };
    verifier2.verify(
        exe_heap.textBytes(),
        exe_heap.version(),
        verifier2.VerifyConfig.DEFAULT,
        &exe_heap.function_registry,
    ) catch {
        exe_heap.deinit();
        cache_alloc.destroy(exe_heap);
        return DispatchError.M3_VerifyFailed;
    };
    program_cache.put(program_id, exe_heap, current_slot, programdata_slot) catch {
        exe_heap.deinit();
        cache_alloc.destroy(exe_heap);
        return DispatchError.OutOfMemory;
    };
}

// ── Per-thread reusable BPF-dispatch scratch (perf, 2026-07-09) ─────────────
// Every BPF invocation freshly alloc'd + @memset a 262 KiB stack + a heap
// buffer, then freed — profiled at ~26-29% of BPF-invocation time (a lower
// bound; CPI frames add more), and fresh alloc also faults in cold pages.
// Reuse the allocation across dispatches from a PERSISTENT allocator (so it
// survives per-tx arena resets); we STILL @memset each use, so the result is
// byte-identical. A busy-guard falls back to a fresh allocation if the path is
// ever re-entered on one thread (it is not on today's serial BPF path — CPI
// uses cpi.recursiveExecute, a separate path — but the guard keeps it safe).
const SCRATCH_STACK_BYTES: usize = 4096 * 64; // = STACK_FRAME_SIZE * MAX_CALL_DEPTH
threadlocal var g_scr_stack: ?[]u8 = null;
threadlocal var g_scr_heap: ?[]u8 = null;
threadlocal var g_scr_busy: bool = false;

const DispatchScratch = struct {
    stack: []u8,
    heap: []u8,
    pooled: bool,
    fb: std.mem.Allocator,
};

fn acquireDispatchScratch(fallback: std.mem.Allocator, heap_bytes: usize) !DispatchScratch {
    if (g_scr_busy) {
        // Re-entrant (not expected on the serial BPF path) → fresh buffers.
        const s = try fallback.alloc(u8, SCRATCH_STACK_BYTES);
        errdefer fallback.free(s);
        const h = try fallback.alloc(u8, heap_bytes);
        return .{ .stack = s, .heap = h, .pooled = false, .fb = fallback };
    }
    const pa = std.heap.page_allocator;
    if (g_scr_stack == null) g_scr_stack = try pa.alloc(u8, SCRATCH_STACK_BYTES);
    if (g_scr_heap == null or g_scr_heap.?.len < heap_bytes) {
        if (g_scr_heap) |h| pa.free(h);
        g_scr_heap = try pa.alloc(u8, heap_bytes);
    }
    g_scr_busy = true;
    return .{ .stack = g_scr_stack.?, .heap = g_scr_heap.?[0..heap_bytes], .pooled = true, .fb = fallback };
}

fn releaseDispatchScratch(s: DispatchScratch) void {
    if (s.pooled) {
        g_scr_busy = false;
    } else {
        s.fb.free(s.heap);
        s.fb.free(s.stack);
    }
}

pub fn v2DispatchBpfProgram(
    alloc: std.mem.Allocator,
    program_id: *const [32]u8,
    ix_data: []const u8,
    snapshots: []const AccountSnapshot,
    elf_bytes: []const u8,
    programdata_slot: u64,
    sysvars: *const SysvarCache,
    program_cache: *V2ProgramCache,
    feature_set: anytype,
    compute_budget: u64,
    current_slot: u64,
    heap_size: u32,
    cpi_extras: []const AccountSnapshot,
) DispatchError![]AccountMutation {
    // Back-compat wrapper (tests/fixture harness): unmetered — consumed CUs
    // are not reported back. Production replay MUST use the metered variant
    // (CU-METER fix, carrier 419786142). Cost-side heap_size = the same
    // value as the region-size param (fix/cu-parity-batch2: this wrapper has
    // no ParsedTx to derive the real requested value from, so treat the
    // caller's `heap_size` as authoritative for both purposes — matches
    // this wrapper's existing pre-fix behavior of 0 heap-entry-cost whenever
    // callers pass the default 32768).
    return v2DispatchBpfProgramMetered(alloc, program_id, ix_data, snapshots, elf_bytes, programdata_slot, sysvars, program_cache, feature_set, compute_budget, current_slot, heap_size, heap_size, cpi_extras, null);
}

pub fn v2DispatchBpfProgramMetered(
    alloc: std.mem.Allocator,
    program_id: *const [32]u8,
    ix_data: []const u8,
    snapshots: []const AccountSnapshot,
    elf_bytes: []const u8,
    programdata_slot: u64,
    sysvars: *const SysvarCache,
    program_cache: *V2ProgramCache,
    feature_set: anytype,
    compute_budget: u64,
    current_slot: u64,
    heap_size: u32,
    /// fix/cu-parity-batch2 (2026-07-12): the tx's REAL requested heap_size
    /// (compute_budget.heapSize() — RequestHeapFrame if present+valid, else
    /// MIN_HEAP_FRAME_BYTES=32768), used ONLY for the heap-entry CU charge
    /// (InvokeContext.calculateHeapCost) at every VM creation. Deliberately
    /// separate from `heap_size` above, which still governs the actual VM
    /// heap REGION size (currently hardcoded 256KiB by the caller regardless
    /// of the request — fix-4/architectural, not yet done). Decoupling the
    /// two means this fix is additive-only: it cannot change which programs
    /// run or how much heap memory they see, only the CU charge.
    requested_heap_bytes: u32,
    /// r75-bug-class-b-tx-cpi-extras (2026-05-06): tx-level accounts that the
    /// CURRENT instruction doesn't directly reference but a CPI from this
    /// program might (System program, BPF Loader, etc.). Pass `&.{}` for
    /// backwards-compat (CPI lookup will fall back to AccountNotInTransaction
    /// for those targets).
    cpi_extras: []const AccountSnapshot,
    /// CU-METER fix (2026-07-05, carrier 419786142): actual CUs this dispatch
    /// consumed (VM insns + syscall costs + CPI, all via the unified
    /// InvokeContext meter). The caller draws these down from the ONE shared
    /// per-tx meter (Agave invoke_context.rs:656 out-param). On a genuine
    /// program failure the full remaining budget is reported (the tx dies at
    /// this ix anyway; matches cluster "consumed N of N" on exhaustion).
    consumed_out: ?*u64,
) DispatchError![]AccountMutation {
    if (consumed_out) |co| co.* = 0;
    // SIMD-0459/0460/0257 port (PR-1, extended PR-K 2026-05-17): resolve
    // per-tx feature-gate booleans from `feature_set`. Accepted shapes for
    // `feature_set` (anytype):
    //   - `.{}` empty struct       — gate evaluates false (test / pre-wired path)
    //   - `*const features.FeatureSet` — direct pointer (test scaffolding)
    //   - `?*const features.FeatureSet` — optional pointer (production path
    //                                     from replay_stage where the live
    //                                     FeatureSet may not be wired yet)
    // Resolution: comptime-detect the shape; runtime unwrap optional → false.
    // Each gate is force-overridden by `SIMD_PORT_FORCE_OFF_*` when needed.
    const fs_info = @typeInfo(@TypeOf(feature_set));
    const is_optional_fs = comptime fs_info == .optional and
        @typeInfo(fs_info.optional.child) == .pointer and
        @hasDecl(@typeInfo(fs_info.optional.child).pointer.child, "isActive");
    const is_direct_fs_ptr = comptime fs_info == .pointer and
        @hasDecl(@TypeOf(feature_set.*), "isActive");
    const is_real_feature_set = comptime is_optional_fs or is_direct_fs_ptr;
    const syscall_param_addr_restrict_active: bool = blk: {
        if (ic_mod.SIMD_PORT_FORCE_OFF_SYSCALL_PARAM_ADDR_RESTRICT) break :blk false;
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.SYSCALL_PARAMETER_ADDRESS_RESTRICTIONS, current_slot);
    };
    const vasa_active: bool = blk: {
        if (ic_mod.SIMD_PORT_FORCE_OFF_VASA) break :blk false;
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.VIRTUAL_ADDRESS_SPACE_ADJUSTMENTS, current_slot);
    };
    const direct_mapping_active: bool = blk: {
        if (ic_mod.SIMD_PORT_FORCE_OFF_DIRECT_MAPPING) break :blk false;
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.ACCOUNT_DATA_DIRECT_MAPPING, current_slot);
    };
    // SIMD-0512: sol_sha512 availability (Agave registers the syscall only
    // when enable_sha512_syscall is active; Vexor registers unconditionally
    // and gates at invoke — see vex_bpf2/syscalls.zig solSha512).
    const sha512_syscall_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.ENABLE_SHA512_SYSCALL, current_slot);
    };
    // Phase 2 (2026-06-19): BN254/Poseidon syscall feature gates, resolved from
    // the SAME live (feature_set, current_slot) as sha512 above. Threaded onto
    // the ctx so the syscall bodies (vex_bpf2/syscalls.zig solAltBn128GroupOp /
    // solAltBn128Compress / solPoseidon) gate identically to Agave rc.1:
    //   • SIMD-0284 alt_bn128_little_endian — NOT active on testnet today; LE
    //     ops abort (InvalidAttribute) until it flips. Gate, do not hardcode.
    //   • SIMD-0302 enable_alt_bn128_g2_syscalls — ACTIVE; G2 ops must work.
    //   • SIMD-0359 poseidon_enforce_padding — ACTIVE; use enforce_padding=true.
    const alt_bn128_little_endian_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.ALT_BN128_LITTLE_ENDIAN, current_slot);
    };
    const alt_bn128_g2_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.ENABLE_ALT_BN128_G2_SYSCALLS, current_slot);
    };
    const poseidon_enforce_padding_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.POSEIDON_ENFORCE_PADDING, current_slot);
    };
    // SIMD-0388 enable_bls12_381_syscall — gates the BLS12-381 arms of the
    // sol_curve_* syscalls (validate/group_op/decompress/pairing_map). ACTIVE
    // on testnet @407127008. Derived from the SAME (feature_set, current_slot)
    // as the bn254 gates above.
    const enable_bls12_381_syscall: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.ENABLE_BLS12_381_SYSCALL, current_slot);
    };
    // HARDEN-2 (2026-06-16): Core-BPF Stake CPI routing gate, derived from the
    // SAME (feature_set, current_slot) the TOP-LEVEL gate uses
    // (executeStakeInstruction:10901-10903 reads feature_set.isActive(MIGRATE_
    // STAKE_PROGRAM_TO_CORE_BPF, bank.slot); current_slot here == bank.slot,
    // and feature_set here IS that same threaded live set). ENV-FIRST so OFF
    // short-circuits before isActive → false → CPI stays native, byte-identical.
    const stake_bpf_active: bool = blk: {
        if (!vex_bpf2.stake_bpf_flag.enabled()) break :blk false;
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.MIGRATE_STAKE_PROGRAM_TO_CORE_BPF, current_slot);
    };
    // F3 fix (2026-07-01): Core-BPF ALT CPI routing gate (SIMD-0128, ACTIVE on
    // testnet). Same live (feature_set, current_slot) as every gate above.
    // @prov:dispatch.core-bpf-migration-gates — per-slot migration semantics.
    // NO env-flag operand (unlike stake): ALT-CPI has no
    // working native fallback (M9 handler = all VariantPending), so the gate is
    // the feature alone. Fail-closed: no real FeatureSet → false → legacy
    // builtin routing, byte-identical pre-activation.
    const alt_bpf_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.MIGRATE_ADDRESS_LOOKUP_TABLE_PROGRAM_TO_CORE_BPF, current_slot);
    };
    // SIMD-0268 raise_cpi_nesting_limit_to_8 — gates the instruction-stack-depth
    // limit (5 inactive → 9 active). @prov:dispatch.cpi-nesting-limit — same
    // (feature_set, current_slot) as the gates above. Absent on testnet today →
    // false → ctx.max_stack_depth stays 5 → byte-identical.
    const raise_cpi_nesting_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.RAISE_CPI_NESTING_LIMIT_TO_8, current_slot);
    };
    // SIMD-0449 direct_account_pointers_in_program_input — gates the SVM input
    // pointer trailer (serialize.zig, golden-vector-verified). Same (feature_set,
    // current_slot). Inactive → false → no trailer → byte-identical baseline.
    const direct_account_pointers_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.DIRECT_ACCOUNT_POINTERS_IN_PROGRAM_INPUT, current_slot);
    };
    // disable_zk_elgamal_proof_program / reenable_zk_elgamal_proof_program —
    // gates M9's zk-elgamal-proof builtin (executeReal). Same (feature_set,
    // current_slot) as every gate above. Conformance grind backport
    // (2026-07-18): see zk_elgamal_proof_program.zig's executeReal +
    // invoke_ctx.zig's field doc for the exact Agave check being ported.
    const disable_zk_elgamal_proof_program_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.DISABLE_ZK_ELGAMAL_PROOF_PROGRAM, current_slot);
    };
    const reenable_zk_elgamal_proof_program_active: bool = blk: {
        if (!is_real_feature_set) break :blk false;
        const fs_ptr = if (comptime is_optional_fs) (feature_set orelse break :blk false) else feature_set;
        break :blk fs_ptr.isActive(features.REENABLE_ZK_ELGAMAL_PROOF_PROGRAM, current_slot);
    };

    // PR-5af-probe (2026-05-19): Carrier J — confirm MODE 3 state per BPF
    // dispatch. Rate-limited threadlocal counter — first 40 only. Captures
    // direct_mapping_active + vasa_active + program ID prefix per dispatch
    // to verify whether MODE 3 is actually engaging for HJT-6009 invocations.
    {
        const ModeProbe = struct {
            var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
        };
        const mn = ModeProbe.count.fetchAdd(1, .monotonic);
        if (mn < 40) {
            const pid_short = std.fmt.bytesToHex(program_id[0..4], .lower);
            std.log.warn(
                "[PR5AF-MODE-PROBE n={d}] slot={d} program={s} vasa={} ddm={}",
                .{ mn, current_slot, &pid_short, vasa_active, direct_mapping_active },
            );
        }
    }

    // ── 1. Resolve + cache the executable ──────────────────────────────────
    var executable_ptr: *elf2.Executable = undefined;

    // Wave 6C-1: upgrade-aware lookup. When `programdata_slot != 0` the
    // caller is signalling "I have a fresh programdata last_modified_slot;
    // evict on mismatch". `programdata_slot == 0` keeps the legacy path
    // (non-upgradeable loader v2, or callers that haven't wired the slot
    // lookup yet — both are explicit "no upgrade detection" semantics).
    if (program_cache.getFresh(program_id.*, programdata_slot)) |entry| {
        executable_ptr = entry.executable;
    } else {
        if (elf_bytes.len < 16) return DispatchError.M5_ProgramNotLoadable;

        // The Executable + every slice it owns must outlive this dispatch
        // frame because the cache holds it across slots. The per-dispatch
        // `alloc` is an arena that dies at end of dispatch, so allocating
        // the Executable from it dangles every internal pointer (and
        // `Executable.deinit` later SEGVs). Use the cache's process-lifetime
        // allocator instead. (Death cause of PID 984722 at 2026-04-25 20:22.)
        const cache_alloc = program_cache.allocator;
        const exe_heap = cache_alloc.create(elf2.Executable) catch return DispatchError.OutOfMemory;
        exe_heap.* = elf2.Executable.load(cache_alloc, elf_bytes, elf2.Config.DEFAULT) catch {
            cache_alloc.destroy(exe_heap);
            return DispatchError.M1_LoadFailed;
        };
        // Verify before publishing into the cache.
        verifier2.verify(
            exe_heap.textBytes(),
            exe_heap.version(),
            verifier2.VerifyConfig.DEFAULT,
            &exe_heap.function_registry,
        ) catch {
            exe_heap.deinit();
            cache_alloc.destroy(exe_heap);
            return DispatchError.M3_VerifyFailed;
        };
        program_cache.put(program_id.*, exe_heap, current_slot, programdata_slot) catch {
            exe_heap.deinit();
            cache_alloc.destroy(exe_heap);
            return DispatchError.OutOfMemory;
        };
        executable_ptr = exe_heap;
    }
    // Cache owns the executable post-put; we only borrow.

    // ── 2. Build TxCtx + M5 input region ───────────────────────────────────
    var owned = try TxCtxOwned.initWithExtras(alloc, snapshots, cpi_extras);
    defer owned.deinit();

    const inputs = alloc.alloc(serialize2.AccountInput, snapshots.len) catch
        return DispatchError.OutOfMemory;
    defer alloc.free(inputs);
    // PR-5e (ADDM BUG-1 fix): source from owned.tx.accounts[0..snapshots.len]
    // so MODE-3 direct-mapping writes land in the heap-duped writable buffer
    // (which extractMutations diffs against), not in mmap'd snapshot pre-state.
    // owned.tx.accounts is sized n_ix + n_extras; the first n_ix entries
    // correspond positionally to snapshots[].
    for (owned.tx.accounts[0..snapshots.len], 0..) |a, i| inputs[i] = accountViewToAccountInput(a);

    // PR-3 (SIMD-0460 vasa): serializer reads the per-tx feature-gate bools
    // resolved at the top of this function. Until PR-3 lifts the
    // `SIMD_PORT_FORCE_OFF_VASA` override in invoke_ctx.zig, `vasa_active`
    // resolves to false → MODE 1 byte-identical to PR-1.
    const serialized = serialize2.serializeParametersAligned(
        alloc,
        program_id.*,
        ix_data,
        inputs,
        .{
            .virtual_address_space_adjustments = vasa_active,
            .account_data_direct_mapping = direct_mapping_active,
            .direct_account_pointers = direct_account_pointers_active, // SIMD-0449 (inactive→false→no trailer)
        },
    ) catch return DispatchError.M5_SerializeFailed;
    defer alloc.free(serialized.bytes);
    defer alloc.free(serialized.account_layouts);
    // PR-3: extra slices populated only when vasa_active=true. Defaults to empty.
    defer if (serialized.input_regions.len > 0) alloc.free(serialized.input_regions);
    defer if (serialized.acc_region_metas.len > 0) alloc.free(serialized.acc_region_metas);

    // ── 3. Build the 5-region memory map ───────────────────────────────────
    //
    // V0/V1 use gapped stacks (vex-152m); V2/V3 are flat.
    const STACK_FRAME_SIZE: u64 = 4096;
    // Pooled scratch (byte-neutral — still @memset; reused across dispatches).
    const _scratch = acquireDispatchScratch(alloc, @intCast(heap_size)) catch
        return DispatchError.OutOfMemory;
    defer releaseDispatchScratch(_scratch);
    const stack_buf = _scratch.stack;
    @memset(stack_buf, 0);

    // Heap: per-program, sized via compute_budget.heap_size.
    // ComputeBudgetInstruction::RequestHeapFrame lets a program raise heap
    // from MIN_HEAP_FRAME_BYTES (32 KiB default) up to MAX_HEAP_FRAME_BYTES
    // (256 KiB). Vexor V2 had this hardcoded at 32 KiB which AccessViolation'd
    // HistoryJT — owns 78% (1808/2332) of V2 dispatches in R3 tripwire. r2
    // bucket forensic at pc=16005 showed offset 0x9d6b8 = 644 KiB → drift is
    // HEAP-undersized (vex-V2-HEAPSIZE). sig reference: sig/src/vm/lib.zig:100-111.
    const heap_buf = _scratch.heap; // pooled (sized to heap_size); still @memset below.
    @memset(heap_buf, 0);

    // Canonical stack_frame_gaps() = V0 ONLY (anza-xyz/sbpf v0.21.0
    // program.rs; = Agave rc0 pin). V1 uses a FLAT stack (manual_stack_frame_bump
    // grows r10 down from the top), NOT a gapped one. 2026-06-18 FIX: was
    // `v0 or v1` → v1 wrongly got a gapped region, which (paired with the
    // base-r10 bug) faulted slot-630 PayEntry at pc=18519. Both v1 fixes
    // (flat region here + top-r10 init in interpreter.zig) are required together.
    const v = executable_ptr.version();
    const stack_region = if (v == .v0)
        memory2.Region.initGapped(memory2.MM_STACK_START, stack_buf, STACK_FRAME_SIZE)
    else
        memory2.Region.fromSlice(memory2.MM_STACK_START, stack_buf);

    // Region 1 must hold the executable's rodata section (format strings,
    // constants, etc.) — NOT the text bytes again. Real programs (Router,
    // History, etc.) call sol_log_ with a pointer at vm_addr = MM_RODATA_START
    // + N pointing at a string in .rodata. With textBytes mapped here, that
    // address translates to instruction bytes (or out-of-bounds), yielding
    // M6_AccessViolation on every sol_log_ — which collapses 37 of 40
    // captured shadow fixtures. Reference: solana-sbpf-v0.14.4 elf.rs:357-362
    // (Section::Borrowed(MM_RODATA_START, 0..text_bytes.len()) for v3 with
    // enable_lower_rodata_vaddr; otherwise MM_BYTECODE_START). Vexor's
    // memory.zig has MM_RODATA_START=0x100000000 and MM_BYTECODE_START=0,
    // so region 1 is rodata-at-1<<32. executable_ptr.rodata() returns the
    // parsed RO section (Section.borrowed pointing at the subset of
    // elf_bytes the M1 parser identified).
    // vmap BUG #2 fix: rodata region's vm_addr MUST come from the
    // parsed ro_section's offset (which encodes lowest_sh_addr), NOT the
    // hardcoded MM_RODATA_START constant. For V0/V1/V2 lenient with
    // .text sh_addr=0x120, the canonical ro_vaddr is 0x100000120, NOT
    // 0x100000000. Using the constant shifted every rodata read by
    // lowest_sh_addr bytes — surfaced by HistoryJT's seed-vmaddr-resolves-
    // to-wrong-bytes pattern (vmaddr 0x100074E57 → "idator" via Vexor's
    // off-by-0x120 vmap, vs canonical "config"). Verified reference-side via
    // Python solders.
    //
    // V3 strict (enable_lower_rodata_vaddr, SIMD-0189): rodata lives at vmaddr 0
    // (MM_RODATA_START) and bytecode at MM_BYTECODE_START (0x1<<32), executed by
    // PC — NOT mapped as a readable region. Canonical Agave (rc.1
    // program-runtime/src/vm.rs `configure_program_regions` + sbpf v0.21.0
    // `Executable::get_ro_region`) maps exactly ONE read-only program region
    // (rodata) plus stack/heap/input; the bytecode slot is an UNMAPPED GAP — any
    // read there faults (code runs by PC). anza-sbpf v0.21.0 (= rc.1 pin)
    // AlignedMemoryMapping tolerates that gap via Eytzinger binary search; our
    // O(1) `vm_addr>>32==idx` map cannot represent a gap, so we EMULATE it with a
    // ZERO-LENGTH region at MM_BYTECODE_START (slot 1): any access computes idx=1,
    // hits len 0 in Region.translate → AccessViolation — byte-for-byte identical
    // to canonical's unmapped bytecode. vaddrs come from the elf accessors
    // (rodataVaddr()=0, programRegionVaddr()=0x1<<32 for v3), NOT memory.zig's
    // MM_RODATA/BYTECODE constants (name-swapped vs canonical — see memory.zig
    // footgun note). The PREVIOUS code mapped text@0 + rodata@MM_RODATA_START
    // (=0x1<<32 due to the swap) for v3, so a v3 program reading its rodata
    // pointer (canonical vaddr 0+N) hit the TEXT region → wrong bytes → bank_hash
    // divergence (latent: v3 active cluster-wide since epoch 954). Fixed here.
    //
    // V0/V1/V2 (else branch) is UNCHANGED: text@0 filler in slot 0 + rodata@
    // rodataVaddr()(=MM_REGION_SIZE+offset, slot 1). Canonical leaves slot 0 empty
    // (get_ro_region = merged text+rodata @ MM_BYTECODE_START), but our filler is
    // never legitimately read (v0-v2 rodata pointers are >=0x1<<32, code by PC) —
    // behaviorally identical on every exercised path, bank-exact for months.
    const empty_region: []const u8 = &.{};
    const regions = if (v == .v3) [_]memory2.Region{
        memory2.Region.fromConst(executable_ptr.rodataVaddr(), executable_ptr.rodata()), // slot 0: rodata @ MM_RODATA_START(0)
        memory2.Region.fromConst(executable_ptr.programRegionVaddr(), empty_region), //     slot 1: bytecode UNMAPPED gap @ MM_BYTECODE_START
        stack_region,
        memory2.Region.fromSlice(memory2.MM_HEAP_START, heap_buf),
        memory2.Region.fromSlice(memory2.MM_INPUT_START, serialized.bytes),
    } else [_]memory2.Region{
        memory2.Region.fromConst(0, executable_ptr.textBytes()),
        memory2.Region.fromConst(executable_ptr.rodataVaddr(), executable_ptr.rodata()),
        stack_region,
        memory2.Region.fromSlice(memory2.MM_HEAP_START, heap_buf),
        memory2.Region.fromSlice(memory2.MM_INPUT_START, serialized.bytes),
    };

    var mm = memory2.AlignedMemoryMap.initWithConfig(alloc, regions[0..], .{
        .direct_mapping = direct_mapping_active,
        .virtual_address_space_adjustments = vasa_active,
    }) catch return DispatchError.M2_MapInitFailed;
    defer mm.deinit();
    // PR-3 (SIMD-0460 vasa): attach the per-account-region partition built by
    // the serializer so vmap() can dispatch INPUT_REGION accesses through
    // findInputMemRegion (per-region is_writable enforcement). When vasa is
    // off these slices are empty and vmap() falls through to the existing
    // single-flat-region path.
    if (serialized.input_regions.len > 0) {
        mm.input_mem_regions = alloc.dupe(memory2.InputMemRegion, serialized.input_regions) catch
            return DispatchError.OutOfMemory;
        mm.acc_region_metas = alloc.dupe(memory2.AccRegionMeta, serialized.acc_region_metas) catch
            return DispatchError.OutOfMemory;
        // PR-3.5 OOB-handler wire: route region growth into TransactionContext's
        // per-tx resize budget. handleInputMemRegionOob bumps region.region_sz
        // for in-budget writes and tracks against the cumulative
        // MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION (20 MiB) cap; the per-instruction
        // +10240 cap is enforced separately via address_space_reserved.
        mm.accounts_resize_delta_ptr = &owned.tx.accounts_resize_delta;
        // PR-5w (2026-05-19): wire the realloc callback so the OOB handler
        // can grow `owned.accounts[idx].data` (and update `region.haddr`)
        // when MODE 3 writes extend past dlen but within reserved space.
        // Closes the GJHt-class output-byte mismatch carrier.
        mm.realloc_fn = &reallocAccountDataCallbackPR5w;
        mm.realloc_ctx = @ptrCast(&owned);
    }

    // ── 4. Build the M6 syscall registry ───────────────────────────────────
    var registry = syscalls2.SyscallRegistry.init(alloc, executable_ptr.version(), .{}) catch
        return DispatchError.M6_RegistryInitFailed;
    defer registry.deinit();

    // ── 5. Build the M8 InvokeContext, populate CPI hooks ──────────────────
    var ctx = InvokeContext.init(alloc, &owned.tx, sysvars, compute_budget);
    defer ctx.deinit();
    ctx.mm = @ptrCast(&mm);
    ctx.cpi_syscalls = @ptrCast(&registry);
    // SIMD-0459/0460/0257 port (PR-1): propagate the resolved feature-gate
    // booleans onto the context so cpi.zig can build SerializeConfig from them.
    ctx.syscall_param_addr_restrict_active = syscall_param_addr_restrict_active;
    ctx.vasa_active = vasa_active;
    ctx.direct_mapping_active = direct_mapping_active;
    ctx.sha512_syscall_active = sha512_syscall_active;
    ctx.alt_bn128_little_endian_active = alt_bn128_little_endian_active; // SIMD-0284
    ctx.alt_bn128_g2_active = alt_bn128_g2_active; // SIMD-0302
    ctx.poseidon_enforce_padding_active = poseidon_enforce_padding_active; // SIMD-0359
    ctx.enable_bls12_381_syscall = enable_bls12_381_syscall; // SIMD-0388
    ctx.stake_bpf_active = stake_bpf_active; // HARDEN-2: CPI stake-route gate (see field doc)
    ctx.alt_bpf_active = alt_bpf_active; // F3: CPI ALT Core-BPF route gate (SIMD-0128, see field doc)
    ctx.max_stack_depth = if (raise_cpi_nesting_active) ic_mod.MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268 else ic_mod.MAX_INSTRUCTION_STACK_DEPTH; // SIMD-0268
    ctx.direct_account_pointers_active = direct_account_pointers_active; // SIMD-0449
    ctx.disable_zk_elgamal_proof_program_active = disable_zk_elgamal_proof_program_active; // zk-elgamal gate
    ctx.reenable_zk_elgamal_proof_program_active = reenable_zk_elgamal_proof_program_active; // zk-elgamal gate
    // fix/cu-parity-batch2 (2026-07-12): tx-wide heap_size for the CU-cost
    // charge (NOT the region-size `heap_size` param above — see
    // requested_heap_bytes doc). Propagates unchanged through every CPI
    // depth via ctx (InvokeContext.heap_size doc).
    ctx.heap_size = requested_heap_bytes;
    // Wave 6C-1: wire `V2ProgramCache.asResolver()` so M7's
    // `handleSolInvokeSigned` can recurse into BPF callees. The opaque
    // hook contract (set in Wave 6A `invoke_ctx.zig:252-253`) is two
    // fields: `cpi_resolver_ctx` (cache pointer) + `cpi_resolver_resolve`
    // (vtable resolve fn). `syscalls.zig::dispatchCpi` reconstructs the
    // `ProgramResolver` from these on every CPI call.
    {
        const resolver = program_cache.asResolver();
        ctx.cpi_resolver_ctx = resolver.ctx;
        // The vtable's `resolve` field shape exactly matches what
        // `dispatchCpi` casts to: `fn(ctx, pid) ?*const Executable`.
        ctx.cpi_resolver_resolve = @ptrCast(resolver.vtable.resolve);
    }

    // Push a frame covering all snapshots.
    const account_indices = alloc.alloc(u16, snapshots.len) catch
        return DispatchError.OutOfMemory;
    defer alloc.free(account_indices);
    for (account_indices, 0..) |*aidx, i| aidx.* = @intCast(i);

    // r75-bug-class-b-program-idx (2026-05-06): program_idx must point to
    // the EXECUTING program in tx.accounts, NOT 0. Without this,
    // ctx.currentProgramId() returns tx.accounts[0] (= first DATA account
    // of the ix, e.g. Anchor's `config`), and translateSigners' call to
    // createProgramAddress(seeds, wrong_pid) derives a bogus PDA →
    // enforcePdaSigners fails M7_AccountNotInTransaction → tx revert →
    // missed PriorityFeeDistribution PDA inits from slot 345 onwards →
    // bank_hash divergence.
    //
    // tx.accounts is the FULL caller TX account list (per cpi_extras
    // append in TxCtxOwned.initWithExtras). The executing program's
    // pubkey appears in tx.account_keys (always — Solana enforces it),
    // so a linear scan finds it. If not found (shouldn't happen), fall
    // back to 0 so we surface a recognisable failure, not a silent OOB.
    var program_idx: u16 = 0;
    for (owned.tx.accounts, 0..) |a, i| {
        if (std.mem.eql(u8, &a.pubkey, program_id)) {
            program_idx = @intCast(i);
            break;
        }
    }

    ctx.push(program_idx, account_indices) catch return DispatchError.M8_PushFailed;
    defer ctx.pop();

    // fix/cu-parity-batch2 (2026-07-12): heap-entry CU charge, right before
    // VM creation. @prov:dispatch.heap-entry-cu — charges calculate_heap_cost()
    // BEFORE building the VM, for every VM creation (this top-level one, and
    // every CPI level — see cpi.zig recursiveExecute for the CPI-level twin).
    // Default heap_size (32768, the overwhelming majority of txs) → cost=0,
    // strictly additive/no-op for them. On exhaustion here, Agave never runs
    // the program at all; mirror that with the same M4_RunFailed + full-budget-
    // consumed convention the vm.run() failure path below uses.
    ctx.chargeHeapCost() catch {
        if (consumed_out) |co| co.* = compute_budget;
        return DispatchError.M4_RunFailed;
    };

    // ── 6. Build + run the Vm ──────────────────────────────────────────────
    const vm_cfg: interpreter2.Config = .{ .require_verified = true };
    var vm = interpreter2.Vm.init(
        alloc,
        executable_ptr,
        &mm,
        registry.asTrait(),
        @ptrCast(&ctx),
        vm_cfg,
        compute_budget,
    ) catch return DispatchError.M4_InitFailed;
    defer vm.deinit();

    // R18: V2-INVOKE-ENTRY + dumpInputRegion +
    // dumpInputToFile diagnostic block removed for production build. The
    // diagnostic byte-diffs they enabled (R14-R17) confirmed serialize2
    // correctness + located snapshot-staleness root cause for HistoryJT.
    // heap_trace.zig:enable() now returns 0 without setting g_active, so any
    // residual heap_trace.* call sites in interpreter.zig early-return at
    // their `if (!g_active) return` guard.

    // F4:
    // Solana sBPF entrypoint contract requires r1 = MM_INPUT_START so the BPF
    // program can read the serialized input region. interpreter.zig:537's
    // contract puts this on the caller; v2_dispatch.zig was missing it,
    // causing every BPF main to be entered with r1=0 and read .text@vaddr0
    // instead of accounts/ix_data. Matches Firedancer fd_vm.c:659 +
    // Agave's loader. project_v2_r1_input_addr_root_cause_2026_04_26.md.
    vm.reg[1] = memory2.MM_INPUT_START;

    // F5: SIMD-0321 feature `provide_instruction_data_offset_in_vm_r2`
    // (pubkey 5xXZc66h4UdB6Yq7FzdBxBiRAFMMScMLwHxk2QZDaNZL) is ACTIVE on testnet
    // since slot 388028256. Agave's vm.rs:265-267 passes the RAW offset (not
    // absolute vm_addr) as r2 when active. Feature is permanently active going
    // forward; unconditional set is safe. Mirrors Agave reference exactly.
    // project_v2_r1_input_addr_root_cause_2026_04_26.md (R12 follow-up).
    vm.reg[2] = @intCast(serialized.instruction_data_offset);

    // PR-5ad-probe (2026-05-19): Carrier I = HJT-6009 CopyClusterInfo chronic
    // r0=6009 (Anchor ArithmeticError inside confirmed_blocks_in_epoch).
    // Identified at slot 409578815 in PR-5ac catchup boot. Same root cause as
    // r75-bug-class-d13 (2026-05-16): MODE 3 direct-mapping input-region
    // incompleteness — function_44843 returns u64::MAX, function_9608
    // overflow → 6009 raise. Multi-day MODE 3 port work; capture data this
    // session for next-session diagnosis.
    //
    // Probe fires on EVERY HJT-6009 CCI dispatch (was hardcoded to slot
    // 406448662). Rate-limited via threadlocal counter to avoid log spam in
    // long boots. Dumps sysvar bytes + program counter + due_insns to log.
    if (ix_data.len >= 8 and program_id[0] == 0xf8 and program_id[1] == 0x75 and program_id[2] == 0x59 and program_id[3] == 0x62) {
        const cci_disc = [_]u8{ 0x7c, 0x7e, 0x8b, 0x86, 0x7e, 0xe6, 0x64, 0x25 };
        if (std.mem.eql(u8, ix_data[0..8], &cci_disc)) {
            // Rate-limit: log first 20 dispatches per session
            const CciProbe = struct {
                var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
            };
            const n = CciProbe.count.fetchAdd(1, .monotonic);
            if (n < 20) {
                const clk = sysvars.getClockBytes() catch null;
                const es = sysvars.getEpochScheduleBytes() catch null;
                const sh = sysvars.getSlotHistoryBytes() catch null;
                std.log.warn("[PR5AD-CCI-PROBE n={d}] slot={d} ix_data={x}", .{ n, current_slot, ix_data });
                if (clk) |b| std.log.warn("[PR5AD-CCI-PROBE n={d}] clock len={d} bytes={x}", .{ n, b.len, b[0..@min(40, b.len)] });
                if (es) |b| std.log.warn("[PR5AD-CCI-PROBE n={d}] epoch_schedule len={d} bytes={x}", .{ n, b.len, b[0..@min(33, b.len)] });
                if (sh) |b| {
                    std.log.warn("[PR5AD-CCI-PROBE n={d}] slot_history len={d} first16={x} last16={x}", .{ n, b.len, b[0..@min(16, b.len)], b[b.len -| 16..] });
                }
            }
        }
    }

    const r0_value = vm.run() catch |run_err| {
        // Stage-4 R3 forensic: extend AV/abort log with reg state. The leading hypothesis is r2 (struct base) lands in stack
        // gap → hypothesis (2). Region bucket of r2 discriminates:
        //   0x200000000-0x2FFFFFFFF = stack → (2) confirmed
        //   0x400000000+            = input → (1) confirmed
        //   else                    = garbage / other.
        // Single log line; no vmap hook (which regressed bootstrap in R1+R2).
        const prog_short_for_err = std.fmt.bytesToHex(program_id[0..4], .lower);
        std.log.err(
            "[V2-DISPATCH] vm.run failed: {s} (pc={d}, due_insns={d}) program={s} r0=0x{x} r1=0x{x} r2=0x{x} r3=0x{x} r4=0x{x} r5=0x{x} r6=0x{x} r10=0x{x})",
            .{
                @errorName(run_err),
                vm.reg[11],
                vm.due_insn_count,
                &prog_short_for_err,
                vm.reg[0],
                vm.reg[1],
                vm.reg[2],
                vm.reg[3],
                vm.reg[4],
                vm.reg[5],
                vm.reg[6],
                vm.reg[10],
            },
        );
        // CU-METER: a genuine program failure (incl. ExceededMaxInstructions)
        // reports the FULL budget consumed — cluster logs "consumed N of N" on
        // exhaustion and the tx fails at this ix regardless.
        if (consumed_out) |co| co.* = compute_budget;
        return DispatchError.M4_RunFailed;
    };

    // d28-bbb (2026-05-13): Solana BPF semantics — `r0 == 0` is success,
    // `r0 != 0` indicates program-level error (Anchor returns
    // `custom_program_error: 0xNNN` via `r0 = NNN`). Cluster's runtime treats
    // a non-zero r0 from an outer instruction as a tx-level revert: ALL
    // mutations from that tx (including inner CPI side effects already
    // committed to the BorrowedAccount layer) are discarded.
    //
    // Pre-d28-bbb Vexor IGNORED r0 (`_ = vm.run() catch ...`) and unconditionally
    // committed the post-execute account state — including any inner CPI
    // creations that Anchor's `init` constraint then rejected via
    // `AccountDidNotDeserialize` (error 3003 = 0xbbb). Empirical carrier: at
    // slot 408074796 TX[131] cluster log shows
    //   `Program Priority6w... invoke [1]
    //    Program log: Instruction: InitializePriorityFeeDistributionAccount
    //    Program 11111111111111111111111111111111 invoke [2]
    //    Program 11111111111111111111111111111111 success         <- inner createAccount
    //    Program log: AnchorError ... AccountDidNotDeserialize ... 3003
    //    Program Priority6w... failed: custom program error: 0xbbb`
    // Cluster reverted the inner createAccount; Vexor kept it → an EXTRA
    // pubkey appeared in Vexor's writeset for the slot → bank_hash diverged.
    if (r0_value != 0) {
        const prog_short_r0 = std.fmt.bytesToHex(program_id[0..4], .lower);
        std.log.warn(
            "[V2-DISPATCH] BPF program returned non-zero r0={d} (=0x{x}) → tx revert (program={s} pc={d} due_insns={d})",
            .{ r0_value, r0_value, &prog_short_r0, vm.reg[11], vm.due_insn_count },
        );
        // PR-5ad-probe (2026-05-19): when HJT-6009 returns r0=6009
        // (ArithmeticError), capture richer context for Carrier I diagnosis.
        // Rate-limited threadlocal counter — first 20 only.
        if (r0_value == 6009 and program_id[0] == 0xf8 and program_id[1] == 0x75 and
            program_id[2] == 0x59 and program_id[3] == 0x62)
        {
            const HjtErrProbe = struct {
                var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
            };
            const en = HjtErrProbe.count.fetchAdd(1, .monotonic);
            if (en < 20) {
                std.log.warn(
                    "[PR5AD-HJT-6009 n={d}] slot={d} program={s} pc={d} due_insns={d} prev_meter={d} r1=0x{x} r2=0x{x} r3=0x{x} r4=0x{x} r5=0x{x} r6=0x{x}",
                    .{
                        en,
                        current_slot,
                        &prog_short_r0,
                        vm.reg[11],
                        vm.due_insn_count,
                        vm.previous_instruction_meter,
                        vm.reg[1],
                        vm.reg[2],
                        vm.reg[3],
                        vm.reg[4],
                        vm.reg[5],
                        vm.reg[6],
                    },
                );
                // Dump snapshots: which accounts were loaded for this BPF dispatch
                for (snapshots, 0..) |s, i| {
                    if (i > 8) break;
                    const pk_short = std.fmt.bytesToHex(s.pubkey[0..8], .lower);
                    std.log.warn(
                        "[PR5AD-HJT-6009 n={d}]   acct[{d}] pk={s} lam={d} dlen={d} writable={}",
                        .{ en, i, &pk_short, s.lamports, s.data.len, s.is_writable },
                    );
                }
            }
        }
        // CU-METER: program-level error (r0 != 0) → tx fails at this ix; report
        // full budget (see vm.run catch above).
        if (consumed_out) |co| co.* = compute_budget;
        return DispatchError.M4_RunFailed;
    }

    // CU-METER settle (success path): charge the residual VM insns executed
    // since the last per-syscall reconcile into the InvokeContext meter, then
    // report total consumed = budget − remaining. With the interpreter's
    // per-syscall settle/refresh (interpreter.zig CALL_IMM) every syscall cost
    // and CPI charge already landed in the SAME meter, so this difference is
    // the ix's exact canonical consumption. @prov:dispatch.cu-meter-settle
    ctx.consumeCompute(vm.due_insn_count) catch {};
    if (consumed_out) |co| co.* = compute_budget -| ctx.computeRemaining();

    // ── 7. Deserialize post-state, build AccountMutation list ──────────────
    const outputs = alloc.alloc(serialize2.AccountOutput, snapshots.len) catch
        return DispatchError.OutOfMemory;
    defer alloc.free(outputs);
    @memset(outputs, .{
        .lamports = 0,
        .owner = .{0} ** 32,
        .data_len = 0,
        .data = &[_]u8{},
    });

    serialize2.deserializeReturn(serialized.bytes, outputs, serialized.account_layouts, direct_mapping_active) catch
        return DispatchError.M5_DeserializeFailed;

    var list = std.ArrayListUnmanaged(AccountMutation){};
    errdefer {
        for (list.items) |*m| alloc.free(m.data);
        list.deinit(alloc);
    }

    // ── DIAG: JITO StakeNet in-place write-drop probe (env VEX_JITO_PROBE) ──
    // Settles (b') region-detach vs (c) skipped-store vs omission for the chronic
    // accounts_lt_hash carrier. Gated by env; only fires for VH/Steward owners.
    const jito_probe_on = std.posix.getenv("VEX_JITO_PROBE") != null;
    const JITO_VH8 = [_]u8{ 0xe3, 0x4d, 0x44, 0xa4, 0x54, 0x26, 0xbd, 0x0c };
    const JITO_STW8 = [_]u8{ 0xc1, 0x22, 0x92, 0xce, 0xd5, 0x6f, 0x16, 0x6f };
    if (jito_probe_on) {
        for (owned.tx.accounts, 0..) |a, ai| {
            const is_vh = std.mem.eql(u8, a.owner[0..8], &JITO_VH8);
            const is_stw = std.mem.eql(u8, a.owner[0..8], &JITO_STW8);
            if (is_vh or is_stw) {
                const pk8 = std.fmt.bytesToHex(a.pubkey[0..8], .lower);
                std.log.warn("[JITO-PROBE census] slot={d} ai={d} pk={s} kind={s} wrtbl={} in_snaps={} dlen={d}", .{ current_slot, ai, &pk8, if (is_vh) "VH" else "STW", a.is_writable, ai < snapshots.len, a.data.len });
            }
        }
    }

    // UnbalancedInstruction invariant accumulators (FD/Agave parity — see the
    // post-loop check after this loop). Σ lamports over the instruction's
    // DECLARED accounts (snapshots) must be invariant across execution.
    // 128-bit like FD's fd_uwide sum; realistic per-instruction account counts
    // (<256) make u128 overflow impossible for u64 lamports.
    var pre_lamport_sum: u128 = 0;
    var post_lamport_sum: u128 = 0;

    for (snapshots, 0..) |s, i| {
        if (!s.is_writable) continue;
        if (serialized.account_layouts[i].is_duplicate) continue;
        const out = outputs[i];

        // RULE #15 fix (2026-06-02, carrier @412589216 / Task #123): commit the
        // POST-STATE from the canonical per-tx slot owned.tx.accounts[i], NOT the
        // serialized return region `out`. Under direct mapping the VM region's
        // haddr points AT owned.tx.accounts[i].data, and inner-CPI builtins
        // (System::CreateAccount: system_program.zig:349 funder debit,
        // :362/:377 create+assign) write that slot directly. The serialized
        // region is STALE for inner-CPI effects — an inner create leaves
        // out.data_len=0 and out.lamports=pre — so reading `out` DROPPED the
        // created account + its funder debit (off-by-one modified count →
        // bank_hash divergence). Agave/FD/Sig commit from the canonical slot,
        // never the region (Agave transaction.rs:128 deconstruct +
        // account_saver.rs collect_accounts_for_successful_tx; FD
        // fd_runtime.c:1271). Mirrors the CPI-extras loop below and
        // TxCtxOwned.extractMutations, which already read canonically. GATE:
        // direct_mapping_active only — under non-DM the outer program's direct
        // data writes live in the region, so non-DM keeps the region read.
        const canon = &owned.tx.accounts[i];
        // RULE#15 + JITO @413830104 reconciliation (agave-behavior-extractor 2026-06-08).
        // lamports/owner are NOT direct-mapped: Agave & Firedancer read them back from the
        // serialized region UNCONDITIONALLY of DM (serialization.rs:622-630,673-676;
        // fd_bpf_loader_serialization.c:488-495,563-564). DM gates ONLY data. Vexor's
        // deserializeReturn (serialize.zig:700-704,760-761) already puts the region value
        // in `out`. BUT an inner-CPI effect lands in `canon` (cpi.zig:1586-1631 writes
        // ctx.tx.accounts, NOT the caller's region — Vexor lacks Agave's
        // update_caller_account region-writeback), so `out` is STALE for inner-CPI
        // accounts. So neither source is universally right; pick whichever DIFFERS from
        // pre-state `s` (= the one that was actually written this tx):
        //   • outer-direct lamport/owner write, no CPI (JITO VH crank / SPL CloseAccount):
        //     out≠pre, canon=pre → `out` wins (was DROPPED when DM read canon — THE bug).
        //   • inner-CPI (System::CreateAccount @412589216, RULE#15): out=pre, canon≠pre
        //     → `canon` wins (RULE#15 preserved).
        //   • neither wrote: out==canon==pre → either, no-op.
        // Data stays canon under DM (legitimately direct-mapped). The only residual is the
        // both-touched same-account edge (inner-CPI AND outer-direct on one acct in one
        // instr) → Tier-3 (port the region writeback into cpi.zig). Not present @413830104.
        const post_lamports: u64 = if (out.lamports != s.lamports) out.lamports else canon.lamports;
        const post_owner: Pubkey32 = if (!std.mem.eql(u8, &out.owner, &s.owner)) out.owner else canon.owner;
        // TOP-LEVEL grow/shrink writeback length (carrier: Token-2022 v11 realloc /
        // shrink, agave-behavior-extractor 2026-06-11). Under direct mapping the
        // region haddr aliases canon.data, but canon.data.len is NOT the post_len:
        //   • SHRINK: nothing truncates canon.data (the OOB-grow handler at
        //     memory.zig:435 only fires on GROW), so canon.data keeps its PRE length
        //     and committing it raw ships the stale tail [post_len .. pre_len) that
        //     Agave's `set_data_length(post_len)` drops (serialization.rs:660-661;
        //     FD fd_bpf_loader_serialization.c:543). → lthash leaf + bank_hash diverge.
        //   • GROW via OOB: reallocAccountDataCallbackPR5w grows canon.data to the
        //     WHOLE remaining tx budget (memory.zig:432-433 `region_sz + remaining`),
        //     NOT the program's reported post_len — so canon.data.len can exceed
        //     out.data_len by up to the 10 KiB slack; committing raw would ship slack
        //     bytes the program never claimed.
        // Canonical post_len is the dlen u64 the program wrote, surfaced as
        // out.data_len by deserializeReturn (serialize.zig:710-714,766). BUT for an
        // inner-CPI grow (RULE #15, carrier @412589216: System::CreateAccount writes
        // canon directly, the OUTER serialized region's dlen stays STALE == pre), the
        // region readback is NOT the writer — out.data_len == s.data.len there. So pick
        // the length the SAME way lamports/owner are picked above: trust the top-level
        // region's reported post_len when it actually changed vs pre-state `s`;
        // otherwise fall back to canon.data.len (the inner-CPI writer). @min guards
        // against a reported dlen larger than the allocated canon buffer.
        const post_data: []const u8 = if (direct_mapping_active) blk: {
            const post_len_dm: usize = if (out.data_len != @as(u64, @intCast(s.data.len)))
                @as(usize, @intCast(out.data_len))
            else
                canon.data.len;
            // [epoch-989 carrier @421724293, fix part 2/2] HEADER-ONLY REALLOC GROW.
            // A program that calls AccountInfo::realloc(new_len, zero_init=false)
            // and does NOT store into the extension writes ONLY the serialized dlen
            // field — no access past region_sz ever happens, so the PR-5w OOB grow
            // path (memory.zig handleInputMemRegionOob) never fires and canon.data
            // stays at its pre length. The @min clamp below then silently truncated
            // the committed data back to pre-len while the program (and its later
            // instructions) believed the realloc succeeded — the Jito StakeNet
            // ValidatorHistory create+realloc silent-truncation (bank-hash
            // divergence at slot 421724293; account stuck at 10,240 B).
            // Agave instead commits set_data_length(post_len) at deserialize
            // (serialization.rs:660-661), zero-filling the extension
            // (AccountSharedData::resize semantics). Mirror that here: grow
            // canon.data (zero-filled, via the same PR-5w callback) when the
            // reported post_len is a VALID grow — within the per-instruction
            // +MAX_PERMITTED_DATA_INCREASE bound relative to the instruction-start
            // length `s.data.len` (serialization.rs:389 original_data_len), within
            // the 10 MiB MAX_PERMITTED_DATA_LENGTH, and within the per-tx 20 MiB
            // growth budget (transaction_accounts.rs:314 can_data_be_resized) —
            // updating accounts_resize_delta exactly like the OOB path does.
            // Invalid reported lengths (beyond either cap) keep the pre-existing
            // clamp behavior (Agave fails those with InvalidRealloc /
            // MaxAccountsDataAllocationsExceeded; residual error-semantics edge,
            // see the TODO in memory.zig handleInputMemRegionOob).
            if (post_len_dm > canon.data.len and
                post_len_dm <= s.data.len + memory2.MAX_PERMITTED_DATA_INCREASE and
                post_len_dm <= 10 * 1024 * 1024)
            {
                const growth_i64: i64 = @intCast(post_len_dm - canon.data.len);
                const budget: i64 = @intCast(memory2.MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION);
                if (owned.tx.accounts_resize_delta +| growth_i64 <= budget) {
                    if (reallocAccountDataCallbackPR5w(@ptrCast(&owned), @intCast(i), post_len_dm) != null) {
                        owned.tx.accounts_resize_delta +|= growth_i64;
                    }
                }
            }
            break :blk canon.data[0..@min(canon.data.len, post_len_dm)];
        } else out.data[0..@as(usize, @intCast(out.data_len))];

        // UnbalancedInstruction invariant: accumulate pre (snapshot / instruction
        // start) and post (post_lamports = the CANONICAL committed value — under
        // DM this is out.lamports for an outer-direct write, where owned.tx.accounts
        // is stale; else canon.lamports — i.e. post-dm-writeback state). Restricted
        // to writable non-duplicate accounts (readonly cancel pre==post; duplicates
        // deduped above). Matches FD fd_instr_info_sum_account_lamports over
        // instr->accounts. Checked after the loop.
        pre_lamport_sum += @as(u128, s.lamports);
        post_lamport_sum += @as(u128, post_lamports);

        // [DM-LAMPORT-SPLIT] detector (advisor gate, 2026-06-08): fires only when the
        // serialized-region readback disagrees with canon on lamports/owner under DM —
        // i.e. exactly the outer-direct-write case this fix now captures. On a REAL tx it
        // proves out==new / canon==old (gate #1) and its firing frequency resolves
        // universal-but-net_hash-masked vs JITO-only (gate #2). Self-limiting (only the
        // split case logs) + capped to avoid runaway spam.
        if (direct_mapping_active and
            (out.lamports != canon.lamports or !std.mem.eql(u8, &out.owner, &canon.owner)))
        {
            const SplitProbe = struct {
                var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
            };
            const sn = SplitProbe.count.fetchAdd(1, .monotonic);
            if (sn < 2000) {
                const sp_pk = std.fmt.bytesToHex(s.pubkey[0..8], .lower);
                const sp_own = std.fmt.bytesToHex(canon.owner[0..8], .lower);
                std.log.warn("[DM-LAMPORT-SPLIT n={d}] slot={d} pk={s} owner={s} pre_lam={d} out_lam={d} canon_lam={d} committed_lam={d} owner_split={} lam_chg_vs_pre={}", .{
                    sn,                                         current_slot,               &sp_pk,         &sp_own,
                    s.lamports,                                 out.lamports,               canon.lamports, post_lamports,
                    !std.mem.eql(u8, &out.owner, &canon.owner), out.lamports != s.lamports,
                });
            }
        }

        const lamports_changed = post_lamports != s.lamports;
        const owner_changed = !std.mem.eql(u8, &post_owner, &s.owner);
        const data_changed = (post_data.len != s.data.len) or
            (post_data.len > 0 and !std.mem.eql(u8, post_data, s.data));

        if (jito_probe_on) {
            const is_vh = std.mem.eql(u8, s.owner[0..8], &JITO_VH8);
            const is_stw = std.mem.eql(u8, s.owner[0..8], &JITO_STW8);
            if (is_vh or is_stw) {
                var wrote_flag = false;
                var haddr_eq = false;
                if (mm.input_mem_regions.len > 0 and i < mm.acc_region_metas.len) {
                    const ridx = mm.acc_region_metas[i].region_idx;
                    if (ridx < mm.input_mem_regions.len) {
                        wrote_flag = mm.input_mem_regions[ridx].wrote;
                        haddr_eq = (post_data.len > 0 and @intFromPtr(mm.input_mem_regions[ridx].haddr) == @intFromPtr(post_data.ptr));
                    }
                }
                var c8: [8]u8 = .{0} ** 8;
                var p8: [8]u8 = .{0} ** 8;
                const cn = @min(@as(usize, 8), post_data.len);
                const pn = @min(@as(usize, 8), s.data.len);
                if (cn > 0) @memcpy(c8[0..cn], post_data[0..cn]);
                if (pn > 0) @memcpy(p8[0..pn], s.data[0..pn]);
                const pk8 = std.fmt.bytesToHex(s.pubkey[0..8], .lower);
                const canhex = std.fmt.bytesToHex(&c8, .lower);
                const prehex = std.fmt.bytesToHex(&p8, .lower);
                // Full-data fingerprints (advisor 2026-06-08): the 8-byte
                // preview is useless for the 168-byte Steward (its Anchor
                // discriminator never moves regardless of how stale the body
                // is). pre_sha vs cluster N-1 splits stale-LOAD (read-path
                // root) from input-misread; post_sha confirms whether Vexor's
                // durable buffer ever reaches the cluster's post value.
                var pre_full: [32]u8 = undefined;
                var post_full: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(s.data, &pre_full, .{});
                std.crypto.hash.sha2.Sha256.hash(post_data, &post_full, .{});
                const presha = std.fmt.bytesToHex(&pre_full, .lower);
                const postsha = std.fmt.bytesToHex(&post_full, .lower);
                std.log.warn("[JITO-PROBE snaps] slot={d} i={d} pk={s} kind={s} wrtbl={} wrote={} dm={} data_chg={} canon8={s} pre8={s} clen={d} plen={d} haddr_eq={} pre_sha={s} post_sha={s}", .{ current_slot, i, &pk8, if (is_vh) "VH" else "STW", s.is_writable, wrote_flag, direct_mapping_active, data_changed, &canhex, &prehex, post_data.len, s.data.len, haddr_eq, &presha, &postsha });
            }
        }

        if (!lamports_changed and !owner_changed and !data_changed) continue;

        const data_copy = alloc.alloc(u8, post_data.len) catch
            return DispatchError.OutOfMemory;
        if (post_data.len > 0) @memcpy(data_copy, post_data);

        const new_owner_opt: ?[32]u8 = if (owner_changed) post_owner else null;

        list.append(alloc, .{
            .pubkey = .{ .data = s.pubkey },
            .new_lamports = post_lamports,
            .owner = post_owner,
            .data = data_copy,
            .new_owner = new_owner_opt,
        }) catch return DispatchError.OutOfMemory;
    }

    // ── UnbalancedInstruction invariant (canonical FD/Agave per-instruction
    //    lamport conservation) ────────────────────────────────────────────────
    // Agave transaction-context/src/transaction.rs pop() (get_lamports_delta()!=0
    // ⇒ InstructionError::UnbalancedInstruction) and Firedancer fd_instr_stack_pop
    // / fd_instr_info_sum_account_lamports (Σ start == Σ end over the instruction's
    // non-duplicate accounts, 128-bit) both enforce that the sum of lamports across
    // an instruction's accounts is invariant across execution. Vexor's FD-faithful
    // port lives in executor.zig:451 (InstrStack.pop) but that path is DEAD (0
    // callers); the LIVE v2 BPF path (v2DispatchBpfProgram) bracketed with the
    // no-arg ctx.pop() and never ran the check. So a program that directly
    // manipulates lamports to an unbalanced total returned r0==0 SUCCESS and Vexor
    // COMMITTED the unbalanced writes while the cluster FAILED it + fee-only
    // rollback → bank_hash divergence. Carrier: slot 419369596 tx 8a5wnTn9…
    // (Jito ChangeTipReceiverV1, +150000000/-300000000, net -150M destroyed);
    // cluster returned InstructionError[0, UnbalancedInstruction], we committed.
    //
    // Sum set = the instruction's DECLARED accounts (snapshots) = FD's
    // instr->accounts (snaps is allocated at ix.account_indices.len). CPI extras
    // (owned.tx.accounts[snapshots.len..]) are NOT part of THIS instruction's
    // balance — an inner CPI can only touch accounts the caller passed it (⊆ this
    // instruction's declared set per Solana privilege rules), so every lamport an
    // inner CPI moves stays within snapshots and cancels there. Readonly accounts
    // are immutable (pre==post ⇒ cancel), duplicates are deduped by is_duplicate;
    // both omissions are mathematically identical to FD's full non-duplicate sum.
    // The 946 BENIGN balanced dm-splits (conserved Jito tip moves) have pre==post ⇒
    // pass — only a genuinely unbalanced total fails.
    //
    // On mismatch, fail the tx exactly as any instruction error does by returning
    // M4_RunFailed. Its propagation is PROVEN (carrier #6 @414386920 fix: propagate
    // instead of swallow; the M6 class @419369738 empirically = failed_ix + fee-only
    // rollback + NO V1 retry == cluster). The specific error enum is not part of
    // bank_hash (fee-only post-state is), so reusing M4_RunFailed is byte-identical
    // to the cluster's UnbalancedInstruction outcome; the distinct
    // [V2-UNBALANCED-INSTR] log below preserves triage fidelity. errdefer above
    // frees `list` on this return path.
    if (pre_lamport_sum != post_lamport_sum) {
        const ub_pk = std.fmt.bytesToHex(program_id[0..4], .lower);
        std.log.warn(
            "[V2-UNBALANCED-INSTR] slot={d} program={s} pre_sum={d} post_sum={d} delta={d} → tx FAIL (UnbalancedInstruction, fee-only rollback) == cluster",
            .{
                current_slot,
                &ub_pk,
                pre_lamport_sum,
                post_lamport_sum,
                @as(i128, @intCast(post_lamport_sum)) - @as(i128, @intCast(pre_lamport_sum)),
            },
        );
        return DispatchError.M4_RunFailed;
    }

    // PR-S6 (2026-05-15): walk CPI extras for mutations. Mirrors PR-5f's
    // generalization in TxCtxOwned.extractMutations but applied here in
    // v2DispatchBpfProgram's own mutation-emit path. Empirically: first-divergent
    // slot 408620404 was the first slot to invoke HistoryJT BPF
    // (HistoryJTGbKQD2mRgLZ3XhqHnN811Qpez8X9kCcGHoa); slot 408620400 with GJHt
    // (resolved by PR-5f) MATCHED. The single delta is HistoryJT writes
    // landing on extras that the snapshots-only loop above misses. Compares
    // post-state in owned.tx.accounts[n_ix..] (where CPI writeback lands per
    // PR-5e) against owned.pre_data_hashes for that range.
    const n_ix = snapshots.len;
    const n = owned.tx.accounts.len;
    if (n > n_ix) {
        for (owned.tx.accounts[n_ix..n], n_ix..) |a, i| {
            if (!a.is_writable) continue;
            const lamports_changed = a.lamports != owned.pre_lamports[i];
            const data_changed_len = a.data.len != owned.pre_data_lens[i];
            var data_changed_bytes: bool = false;
            if (!data_changed_len and a.data.len > 0) {
                var post_hash: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(a.data, &post_hash, .{});
                data_changed_bytes = !std.mem.eql(u8, &post_hash, &owned.pre_data_hashes[i]);
            }
            const owner_changed = !std.mem.eql(u8, &a.owner, &owned.pre_owners[i]);
            const changed = lamports_changed or data_changed_len or data_changed_bytes or owner_changed;

            if (jito_probe_on) {
                const is_vh = std.mem.eql(u8, a.owner[0..8], &JITO_VH8);
                const is_stw = std.mem.eql(u8, a.owner[0..8], &JITO_STW8);
                if (is_vh or is_stw) {
                    var c8: [8]u8 = .{0} ** 8;
                    const cn = @min(@as(usize, 8), a.data.len);
                    if (cn > 0) @memcpy(c8[0..cn], a.data[0..cn]);
                    const pk8 = std.fmt.bytesToHex(a.pubkey[0..8], .lower);
                    const canhex = std.fmt.bytesToHex(&c8, .lower);
                    var post_full: [32]u8 = undefined;
                    std.crypto.hash.sha2.Sha256.hash(a.data, &post_full, .{});
                    const postsha = std.fmt.bytesToHex(&post_full, .lower);
                    const presha = std.fmt.bytesToHex(&owned.pre_data_hashes[i], .lower);
                    std.log.warn("[JITO-PROBE extras] slot={d} i={d} pk={s} kind={s} wrtbl={} changed={} canon8={s} clen={d} pre_sha={s} post_sha={s}", .{ current_slot, i, &pk8, if (is_vh) "VH" else "STW", a.is_writable, changed, &canhex, a.data.len, &presha, &postsha });
                }
            }

            if (!changed) continue;

            const data_copy = alloc.alloc(u8, a.data.len) catch return DispatchError.OutOfMemory;
            if (a.data.len > 0) @memcpy(data_copy, a.data);
            const new_owner_opt: ?[32]u8 = if (owner_changed) a.owner else null;
            list.append(alloc, .{
                .pubkey = .{ .data = a.pubkey },
                .new_lamports = a.lamports,
                .owner = a.owner, // vex-039 restored: post-mutation owner (V2 CPI extras)
                .data = data_copy,
                .new_owner = new_owner_opt,
            }) catch return DispatchError.OutOfMemory;
        }
    }

    return list.toOwnedSlice(alloc) catch DispatchError.OutOfMemory;
}

// ──────────────────────────────────────────────────────────────────────────────
// Shadow diff (V1 ≡ V2)
// ──────────────────────────────────────────────────────────────────────────────

/// Result of comparing two AccountMutation lists.
pub const ShadowDiff = struct {
    v1_count: usize,
    v2_count: usize,
    /// Number of mutations that match on (pubkey + lamports + owner + data hash).
    same: usize,
    v2_extra: usize,
    v1_extra: usize,
    owner_diff: usize,
    lamport_diff: usize,
    data_diff: usize,
};

fn matchesMutation(a: AccountMutation, b: AccountMutation) bool {
    if (!std.mem.eql(u8, &a.pubkey.data, &b.pubkey.data)) return false;
    if (a.new_lamports != b.new_lamports) return false;
    // Treat null new_owner as "owner unchanged"; mismatch only when both set
    // and disagree, or one set + one null.
    const a_owner_set = a.new_owner != null;
    const b_owner_set = b.new_owner != null;
    if (a_owner_set != b_owner_set) return false;
    if (a_owner_set and !std.mem.eql(u8, &a.new_owner.?, &b.new_owner.?)) return false;
    var ha: [32]u8 = undefined;
    var hb: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(a.data, &ha, .{});
    std.crypto.hash.sha2.Sha256.hash(b.data, &hb, .{});
    if (!std.mem.eql(u8, &ha, &hb)) return false;
    return true;
}

/// Compare two AccountMutation lists. O(N*M) — fine for the per-tx scale.
pub fn diffMutations(v1: []const AccountMutation, v2: []const AccountMutation) ShadowDiff {
    var d: ShadowDiff = .{
        .v1_count = v1.len,
        .v2_count = v2.len,
        .same = 0,
        .v2_extra = 0,
        .v1_extra = 0,
        .owner_diff = 0,
        .lamport_diff = 0,
        .data_diff = 0,
    };

    var v1_matched = std.bit_set.IntegerBitSet(256).initEmpty();
    var v2_matched = std.bit_set.IntegerBitSet(256).initEmpty();

    // First pass: full matches (same pubkey + values).
    for (v2, 0..) |b, j| {
        if (j >= 256) break;
        for (v1, 0..) |a, i| {
            if (i >= 256) break;
            if (v1_matched.isSet(i)) continue;
            if (matchesMutation(a, b)) {
                v1_matched.set(i);
                v2_matched.set(j);
                d.same += 1;
                break;
            }
        }
    }

    // Second pass: same pubkey, value mismatch.
    for (v2, 0..) |b, j| {
        if (j >= 256 or v2_matched.isSet(j)) continue;
        for (v1, 0..) |a, i| {
            if (i >= 256 or v1_matched.isSet(i)) continue;
            if (!std.mem.eql(u8, &a.pubkey.data, &b.pubkey.data)) continue;
            if (a.new_lamports != b.new_lamports) d.lamport_diff += 1;
            // owner diff
            const ao = a.new_owner != null;
            const bo = b.new_owner != null;
            if (ao != bo) {
                d.owner_diff += 1;
            } else if (ao and !std.mem.eql(u8, &a.new_owner.?, &b.new_owner.?)) {
                d.owner_diff += 1;
            }
            // data diff
            var ha: [32]u8 = undefined;
            var hb: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(a.data, &ha, .{});
            std.crypto.hash.sha2.Sha256.hash(b.data, &hb, .{});
            if (!std.mem.eql(u8, &ha, &hb)) d.data_diff += 1;
            v1_matched.set(i);
            v2_matched.set(j);
            break;
        }
    }

    // Remaining un-matched in v1 / v2.
    for (v1, 0..) |_, i| {
        if (i >= 256) break;
        if (!v1_matched.isSet(i)) d.v1_extra += 1;
    }
    for (v2, 0..) |_, j| {
        if (j >= 256) break;
        if (!v2_matched.isSet(j)) d.v2_extra += 1;
    }
    return d;
}

/// Format a ShadowDiff into a compact human-readable string. Caller supplies
/// a buffer at least 96 bytes.
pub fn formatDelta(buf: []u8, d: ShadowDiff) []const u8 {
    if (d.v1_extra == 0 and d.v2_extra == 0 and
        d.owner_diff == 0 and d.lamport_diff == 0 and d.data_diff == 0 and
        d.v1_count == d.v2_count)
    {
        return std.fmt.bufPrint(buf, "match", .{}) catch buf[0..0];
    }
    return std.fmt.bufPrint(
        buf,
        "+v2_extra:{d},-v1_extra:{d},owner:{d},lamports:{d},data:{d}",
        .{ d.v2_extra, d.v1_extra, d.owner_diff, d.lamport_diff, d.data_diff },
    ) catch buf[0..0];
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests live in `v2_dispatch_test.zig` (sibling) so the test runner's root
// is OUTSIDE the vex_svm directory and the `file-in-two-modules` conflict
// (via vex_bpf → vex_store → vex_svm) doesn't arise. See build.zig step
// `test-vex-bpf2-v2-dispatch` for the wireup.
// ──────────────────────────────────────────────────────────────────────────────

// keep one no-op test so the module isn't empty.
test "v2_dispatch: module loads" {
    try std.testing.expect(@sizeOf(ShadowDiff) > 0);
}
