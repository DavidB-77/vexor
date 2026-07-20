//! instruction_dispatch.zig — Phase C cut C1 (2026-07-08)
//! Executor-bridge layer moved VERBATIM out of replay_stage.zig (former lines 11330-15140).
//! Pure textual move — no behavior change. Back-references into replay_stage go through `rs`
//! (Zig permits circular file-level @import). Gated: -Dprod compile + golden 1848/1848 byte-identical.

const std = @import("std");
const core = @import("core");
const types = @import("types.zig");
const bank_mod = @import("bank.zig");
const vex_store = @import("vex_store");
const vex_bpf2 = @import("vex_bpf2");
const bpf_mod = @import("vex_bpf");
const build_options = @import("build_options");
const features_mod = @import("features.zig");
const shadow_capture = @import("shadow_capture.zig");
const v2dispatch = @import("v2_dispatch.zig");
const compute_budget = @import("compute_budget"); // task #13: dedicated shared module (build.zig)
const elf_version = @import("elf_version.zig");
const elf_resolution_guard = @import("elf_resolution_guard.zig");
const bank_sysvar_adapter = @import("bank_sysvar_adapter.zig");
const instructions_sysvar_mod = @import("native/instructions_sysvar.zig");
const address_lookup_table = @import("native/address_lookup_table.zig");
const stake_program = @import("native/stake_program.zig");
const system_v2 = @import("native/system_v2.zig");
const vote_program = @import("native/vote_program.zig");
const vote_state_serde = @import("native/vote_state_serde.zig");
// Upper bound on the instruction-scoped account count the vote seam builds a
// stack signer buffer for. Formerly `vote_ab_oracle.MAX_ROUTE_ACCOUNTS` (that
// differential-oracle module was removed with the Sig transplant, 2026-07-12);
// kept here as the vote path's own invariant.
const MAX_VOTE_ROUTE_ACCOUNTS: usize = 8;
// voteforge: the vote program's own front door + its dependency layers.
// Short names `vp`/`vi`/`aio` — `vote_program` above is already taken by the
// OLD native/vote_program.zig (the pre-voteforge Vexor implementation, still
// used for vote-state reads elsewhere; unrelated to this executor).
const vp = @import("voteforge/vote_program.zig");
const vi = @import("voteforge/vote_instructions.zig");
const aio = @import("voteforge/account_io.zig");

const Bank = bank_mod.Bank;
const AccountsDb = @import("vex_store").accounts.AccountsDb;
const Pubkey = core.Pubkey;
const Slot = core.Slot;

// --- back-references into replay_stage (all pub-marked there) ---
const rs = @import("replay_stage.zig");
const ReplayStage = rs.ReplayStage;
const ParsedTx = rs.ParsedTx;
const ParsedInstruction = rs.ParsedInstruction;
const ParseRejStats = rs.ParseRejStats;
const NATIVE_PROGRAM_IDS = rs.NATIVE_PROGRAM_IDS;
const BPF_LOADER_UPGRADEABLE = rs.BPF_LOADER_UPGRADEABLE;
const BPF_LOADER_V2 = rs.BPF_LOADER_V2;
const BPF_LOADER_DEPRECATED = rs.BPF_LOADER_DEPRECATED;
const SYSVAR_OWNER_FOR_INSTRUCTIONS = rs.SYSVAR_OWNER_FOR_INSTRUCTIONS;
const flushPendingWritesToDb = rs.flushPendingWritesToDb;
const getOrInitV2ProgramCache = rs.getOrInitV2ProgramCache;
const buildInstructionsSysvarBlob = rs.buildInstructionsSysvarBlob;
const clusterSlotHashesSnapshot = rs.clusterSlotHashesSnapshot;
const measureTransaction = rs.measureTransaction;
const prewarmCalleeProgram = rs.prewarmCalleeProgram;
const rollbackFailedTx = rs.rollbackFailedTx;
const txIsNativeEligible = rs.txIsNativeEligible;
const validateStakeHistoryWellFormed = rs.validateStakeHistoryWellFormed;

pub fn dispatchBpfExecution(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
    /// PR-K (2026-05-17): per-bank live FeatureSet, threaded from
    /// `self.live_feature_set` in the caller. Optional because bootstrap
    /// may dispatch before the FeatureSet is wired (in which case all
    /// SIMD gates resolve to false at v2DispatchBpfProgram → MODE 1 path).
    feature_set: ?*const features_mod.FeatureSet,
    /// CU-METER (2026-07-05, carrier 419786142): the tx's shared compute
    /// meter. The dispatch draws its budget from here and the actual
    /// consumption (VM insns + syscalls + CPI) is drawn down on return.
    /// null ⇒ unmetered legacy behavior (stake-ON `.so` route — follow-up
    /// parity item; Core-BPF-migrated builtins consume real VM CUs on the
    /// cluster).
    tx_meter: ?*u64,
) !void {
    // F8i: per-ELF sBPF version routing.
    // V1 ElfLoader silently swallows SBPFv3 ELFs (HistoryJT, ATokenG, Jito,
    // Router) → no mutations applied → PDAs freeze post-snapshot → continuous
    // bank_hash divergence (root cause of multi-week blocker, byte-confirmed
    // by via R17b disp=0 vs oracle-node). Force V3 ELFs through
    // V2 producer regardless of --bpf-stack flag.
    //
    // r75-bug-class-d13 (2026-05-10): also force V0 ELFs through V2 producer.
    // The slot 668 carrier diagnosis showed V1's hand-written interpreter
    // throws InvalidMemoryAccess at pc=39472 (insn_ctr=758) on every GJHt
    // jito-tip-payment dispatch (sBPF v0 ELF, e_flags=0, programdata
    // EWmzNQGqS8UWuFen7K2EbJjL3gKPrTct2f3EjfDLsxC3) AND on the OTHR Anchor
    // program (a28f..8ffc) — every CPI-using V0 program produces 0 mutations.
    // Routing V0 through V2 uses the rc0-canonical solana-sbpf 0.14.4 vendored
    // implementation (the same crate Agave's testnet validator binary uses,
    // verified via /home/sol/agave_src/Cargo.lock on oracle-node). This is NOT a
    // band-aid: the V2 producer IS the Agave-canonical code path; V1 is
    // Vexor's hand-written interpreter that pre-dated the V2 vendoring.
    // V1/V2 ELFs continue to honor the --bpf-stack flag for now (no observed
    // V1/V2 failures yet); extend here if/when the same class surfaces.
    if (ix.program_id_index < ptx.account_keys.len) {
        const program_id = &ptx.account_keys[ix.program_id_index];
        if (elf_version.resolveProgramSbpfVersion(program_id, db, bank.slot, bank.ancestors())) |v| {
            // r75-bug-class-d18 (2026-06-18): also force V1/V2 ELFs through the
            // V2 producer — the "extend here if/when the same class surfaces"
            // case the V0-routing comment above anticipated. The slot-416083630
            // carrier (PayEntry, sBPF v1, 2FFpShE2…) proved V1's hand-written
            // interpreter mis-executes v1 programs even AFTER the r10
            // frame-pointer + callx-base fixes (vm.zig): PayEntry now runs past
            // both fixed faults, then SILENTLY returns r0=0x1004 (program error)
            // BEFORE its System-transfer CPI, dropping every mutation — while
            // Agave SUCCEEDS (meta.err=null, verified vs cluster RPC getBlock
            // 416083630: payer −5,080,000 / recipient CzdgBXYT +5,000,000 / data
            // write → bank_hash cbbac4a6) vs Vexor's fee-only dc05dca0. V1 is
            // Vexor's pre-vendoring interpreter; the V2 producer runs each ELF
            // with ITS OWN e_flags version (canonical solana-sbpf, the crate
            // Agave's testnet binary uses) so v1/v2 programs execute under
            // v1/v2 semantics on the correct VM. v0 already proves this path
            // bank-exact in production. Rollback: VEX_V1V2_LEGACY_ENGINE=1
            // restores v1/v2→V1 (v0/v3 always route to V2, never regressed).
            const RouteCfg = struct {
                var legacy_v1v2: ?bool = null;
            };
            const legacy = RouteCfg.legacy_v1v2 orelse blk: {
                const l = std.posix.getenv("VEX_V1V2_LEGACY_ENGINE") != null;
                RouteCfg.legacy_v1v2 = l;
                break :blk l;
            };
            const route = (v == .v3 or v == .v0) or
                (!legacy and (v == .v1 or v == .v2));
            if (route) {
                if (v == .v1 or v == .v2) {
                    // v1/v2 → V2 is the NEW route this change introduces, and it
                    // is RARE on testnet (~1/600 slots — PayEntry). ALWAYS log it
                    // (negligible volume) so the live at-tip gate can COUNT real
                    // v1/v2 executions and confirm parity across them, rather
                    // than gating on wall-clock (advisor 2026-06-18).
                    std.log.warn("[V2-ROUTE] slot={d} program={x:0>2}{x:0>2}{x:0>2}{x:0>2} version={s} NEW-ROUTE→V2", .{
                        bank.slot, program_id[0], program_id[1], program_id[2], program_id[3], @tagName(v),
                    });
                } else if (std.posix.getenv("VEX_VMFAULT_DEBUG") != null) {
                    // v0/v3 = pre-existing route (unchanged); debug-only.
                    std.log.warn("[V2-ROUTE] slot={d} program={x:0>2}{x:0>2}{x:0>2}{x:0>2} version={s} pre-existing", .{
                        bank.slot, program_id[0], program_id[1], program_id[2], program_id[3], @tagName(v),
                    });
                }
                return dispatchV3ViaV2Producer(ix, ptx, bank, db, alloc, feature_set, tx_meter);
            }
        } else {
            // fix/small-parity-batch-2026-07-17 (audit: SYSCALL-WIRING-TRUTH-AUDIT
            // fix-list item 2): resolveProgramSbpfVersion returned null. Per
            // elf_version.zig:66-70 that means the program account is missing, OR
            // (native/builtin data isn't an ELF — moot here, since replay_stage.zig
            // routes every NATIVE_PROGRAM_IDS.*/BPF_LOADER_UPGRADEABLE/V2/DEPRECATED/
            // ALT/ZK_ELGAMAL program_id to its own native handler at :7440-7481 and
            // :9136-9213 BEFORE ever calling dispatchBpfExecution — only "Generic BPF
            // program" ids reach here), OR a genuine sBPF-load failure: missing/short
            // programdata, corrupted/unrecognized e_flags.
            //
            // The last case is dangerous: falling through unconditionally to
            // `dispatch_mode`'s `.v1` default hands the program_id to the legacy V1
            // interpreter (`executeBpfProgram` -> `executeBpfProgramCore`), which
            // treats `loader.load(elf_data) catch { return &[_]AccountMutation{}; }`
            // (an ELF that fails to parse) as an EMPTY-MUTATION SUCCESS — silently
            // no-op instead of failing the transaction. Agave instead tombstones a
            // program that fails to load/verify (agave-4.2.0-beta.1-src/svm/src/
            // program_loader.rs:118-119,189-193 -> ProgramCacheEntryType::Closed /
            // FailedVerification) and, at invoke time, returns
            // InstructionError::UnsupportedProgramId for that tombstone
            // (agave-4.2.0-beta.1-src/programs/bpf_loader/src/lib.rs:136-141) — a
            // hard instruction failure that rolls back the tx, never a silent no-op.
            //
            // Mirror that ONLY for the narrow case that can actually reach this
            // branch carrying a real program: the account exists, IS executable, and
            // IS owned by one of the three BPF loaders. Any other null cause (account
            // missing entirely, non-executable, non-BPF-loader-owned) is UNCHANGED —
            // those aren't "a real BPF program whose ELF we failed to parse" and keep
            // today's fallthrough to `dispatch_mode` exactly as before. This makes
            // the change provably a no-op on the normal path: every resolvable ELF
            // still routes through `route` above unchanged, and every non-BPF-owned
            // null cause still falls through unchanged; only the narrow silently-
            // wrong-answer case gets a loud failure instead.
            const program_pk = core.Pubkey{ .data = program_id.* };
            if (db.getAccountInSlot(&program_pk, bank.slot, bank.ancestors())) |prog_acct| {
                if (isFatalBpfElfResolutionFailure(prog_acct.executable, prog_acct.owner.data)) {
                    std.log.err("[BPF-ELF-RESOLUTION-FAILED] slot={d} program={x:0>2}{x:0>2}{x:0>2}{x:0>2}.. executable BPF-loader-owned account failed sBPF version resolution — failing the instruction loud instead of silently falling through to the legacy V1 stub table (matches Agave InstructionError::UnsupportedProgramId, programs/bpf_loader/src/lib.rs:136-141)", .{
                        bank.slot, program_id[0], program_id[1], program_id[2], program_id[3],
                    });
                    return error.M4_BpfElfResolutionFailed;
                }
            }
        }
    }

    const mode = vex_bpf2.dispatch_mode.current();
    switch (mode) {
        .v1 => return executeBpfProgram(ix, &ptx.*, bank, db, alloc),
        .v2 => {
            // Wave 5: V2 dispatch is real for M9-builtin program_ids; for BPF
            // programs (non-builtins) it returns M5_BankBackedBpfNotPlumbed
            // and we fall through to V1. (replay_stage routes builtins ahead
            // of dispatchBpfExecution today, so testnet hits the BPF gap
            // path almost exclusively until the M5↔Bank adapter lands in
            // Wave 6.)
            if (v2DispatchInternal(ix, &ptx.*, bank, db, alloc, feature_set, tx_meter)) |muts_opt| {
                if (muts_opt) |muts| {
                    defer {
                        for (muts) |*m| alloc.free(m.data);
                        alloc.free(muts);
                    }
                    // Always-on V2-producer capture: write
                    // a fixture BEFORE commit so /tmp/vex-shadow-fixtures gets
                    // populated under --bpf-stack=v2 (shadowDispatch path is
                    // bypassed in producer mode). Best-effort — failure is
                    // logged but does NOT block dispatch (fail-loud per the
                    // no-bandaid rule).
                    captureShadowFixture(ix, ptx, bank, db, alloc, muts) catch |e| {
                        std.log.warn("[V2-PRODUCER-CAPTURE] failed: {s}", .{@errorName(e)});
                    };
                    commitV2Mutations(bank, db, muts);
                    return;
                }
            } else |e| {
                logV2DispatchFallback(@errorName(e));
                // fix/failed-tx-rollback (2026-06-10): a genuine program abort
                // (M4_RunFailed: VM abort or r0!=0) must NOT be retried via V1
                // — Agave records the tx as failed at this instruction
                // (r75-bug-class-b rationale, now propagated instead of
                // swallowed). Re-raise so the instruction loop rolls the tx
                // back. All other errors keep the V1 infrastructure fallback.
                if (e == error.M4_RunFailed) return e;
            }
            return executeBpfProgram(ix, &ptx.*, bank, db, alloc);
        },
        .shadow => {
            // Wave 5 + Stage-D: real V1≡V2 diff. V1's mutation list comes
            // from executeBpfProgramCore (split out in Wave 5) and is
            // committed inline via bank.pending_writes. V2 runs in parallel
            // (no commit) through v2DispatchInternal. We diff and emit a
            // rate-limited [VBPF2-SHADOW] line.
            //
            // Stage-D Risk 1: errors are now structured. Shadow_V1CommitFailed
            // is propagated (bank-corrupting if swallowed). All other shadow
            // errors are logged as [VBPF2-SHADOW-ERR] inside shadowDispatch
            // and absorbed at this boundary — shadow is diagnostic-only and
            // V1 has already committed by the time those errors fire.
            //
            // KNOWN-LATENT: dispatchBpfExecution's two callers (lines 1607,
            // 1809) currently `catch {}` its result, so even
            // Shadow_V1CommitFailed gets swallowed at the outer boundary.
            // That hardening is a separate task outside Stage-D's safety
            // boundary; the contract is in place here so the wire-up is
            // ready when those call sites are tightened.
            shadowDispatch(ix, ptx, bank, db, alloc, feature_set) catch |e| {
                if (e == vex_bpf2.shadow_safety.ShadowError.Shadow_V1CommitFailed) {
                    return e;
                }
                // Diagnostic-only errors: already logged + counted inside
                // shadowDispatch. Absorb here.
            };
            return;
        },
    }
}

/// fix/small-parity-batch-2026-07-17: thin wrapper around the standalone,
/// independently-unit-tested predicate in `elf_resolution_guard.zig` (kept
/// dependency-free there so it can be test-discovered without pulling in
/// this file's heavy `vex_svm`/`replay_stage.zig` closure, which has no
/// standalone test root today). See that file for the KATs and the full
/// reasoning; see the call site above for the Agave citations.
fn isFatalBpfElfResolutionFailure(executable: bool, owner: [32]u8) bool {
    return elf_resolution_guard.isFatalBpfElfResolutionFailure(
        executable,
        owner,
        BPF_LOADER_UPGRADEABLE,
        BPF_LOADER_V2,
        BPF_LOADER_DEPRECATED,
    );
}

/// F8i: V3 ELF dispatch through V2 producer.
///
/// SBPFv3 ELFs (HistoryJT, ATokenG, Jito, Router et al.) are routed here
/// regardless of `--bpf-stack` mode because V1 ElfLoader can't parse V3
/// (silent-eat → 0 mutations → PDA freeze → bank_hash divergence).
///
/// Behavior:
///   - V2 returns muts → commit them via `commitV2Mutations` (mirrors the
///     `.v2` mode path at dispatchBpfExecution above).
///   - V2 returns null → no commit, no V1 fallback. V1 silent-eats V3, so
///     falling through would re-introduce the bug. Treating V3 panics as
///     no-op leaves the failed-dispatch slot's instruction effectively
///     unexecuted; once F8a's fresh snapshot keeps PDAs current and V2
///     succeeds for HistoryJT, this null branch should rarely fire.
///   - V2 returns Err → log + propagate. Don't fall back to V1.
pub fn dispatchV3ViaV2Producer(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
    /// PR-K (2026-05-17): same as dispatchBpfExecution — see that doc.
    feature_set: ?*const features_mod.FeatureSet,
    /// CU-METER (2026-07-05): see dispatchBpfExecution.
    tx_meter: ?*u64,
) !void {
    const muts_opt = v2DispatchInternal(ix, &ptx.*, bank, db, alloc, feature_set, tx_meter) catch |e| {
        logV2DispatchFallback(@errorName(e));
        return e;
    };
    if (muts_opt) |muts| {
        defer {
            for (muts) |*m| alloc.free(m.data);
            alloc.free(muts);
        }
        // Always-on V2-producer capture (V3 path).
        captureShadowFixture(ix, ptx, bank, db, alloc, muts) catch |e| {
            std.log.warn("[V2-PRODUCER-CAPTURE] failed (V3 route): {s}", .{@errorName(e)});
        };
        commitV2Mutations(bank, db, muts);
    }
}

/// task #11: dispatch a top-level ZkElGamalProof builtin instruction through the M9 path.
/// `v2DispatchInternal` builds the InvokeContext + runs `zk_elgamal_proof_program.executeReal`;
/// `commitV2Mutations` applies the ProofContextState write through `bank.pending_writes` — the
/// SAME live-proven commit path the V3-ELF route (`dispatchV3ViaV2Producer`) uses, so lt_hash /
/// freeze-accumulator / tx-rollback integration is shared, not novel.
///
/// Reached ONLY when `HANDLER_ENABLED=true` (call sites gate it comptime; dark => this is dead
/// code and zk ix flow to the BPF else-branch exactly as today). Returns:
///   muts  => committed (context-state account written); null => verify-only (no mutation), Ok.
///
/// FLIP-BLOCKER B (error mapping): on proof/account failure `v2_dispatch.v2DispatchInternal`
/// funnels non-VariantPending M9_* errors to `M9_BuiltinFailed`, losing the specific Agave
/// InstructionError that a failed zk tx commits into the block. Before flipping, thread the
/// specific `M9_ZkElGamalProof_*` code through so the committed tx-failure code is byte-faithful.
/// The success/mutation path is unaffected (validated by the e2e + Gap-A KATs).
pub fn dispatchZkElGamalBuiltin(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
    feature_set: ?*const features_mod.FeatureSet,
) !void {
    // CU-METER: zk-elgamal-proof DEFAULT_COMPUTE_UNITS = 0 → unmetered (null)
    // is canonical. @prov:dispatch.zk-elgamal-cu
    const muts_opt = v2DispatchInternal(ix, &ptx.*, bank, db, alloc, feature_set, null) catch |e| {
        logV2DispatchFallback(@errorName(e));
        return e;
    };
    if (muts_opt) |muts| {
        defer {
            for (muts) |*m| alloc.free(m.data);
            alloc.free(muts);
        }
        commitV2Mutations(bank, db, muts);
    }
}

/// F4 (2026-07-01, latent-carrier batch): per-SITE per-SLOT dedup latch for
/// the fail-loud markers inside v2DispatchInternal ([V2-DISPATCH-SILENT-EAT] /
/// [V2-SANITIZE-REJECT]). Each call site owns one static
/// `std.atomic.Value(u64)` holding the last slot it logged for; a single
/// atomic swap gates the log to ≤1 line per site per slot.
///
/// WHY an atomic: wave-parallel-replay safe (lock-free, no mutex on the hot
/// path, no allocation). Today v2 dispatch is main-thread-only (BPF txs are
/// wave-INELIGIBLE per txIsNativeEligible), so the atomic is belt-and-
/// suspenders — but it costs nothing and survives any future re-threading.
///
/// HASH-NEUTRAL by construction: this gates LOG EMISSION only; the callers'
/// null returns / error propagation are byte-identical in semantics.
pub inline fn warnOncePerSlot(last_logged_slot: *std.atomic.Value(u64), slot: u64) bool {
    return last_logged_slot.swap(slot, .monotonic) != slot;
}

/// Wave 5: V2 dispatch entry. Builds AccountSnapshots from the (Bank,
/// AccountsDb) substrate, hands them to `vex_svm.v2_dispatch.v2DispatchInternal`,
/// and returns the resulting mutation list (or `null` on a path that explicitly
/// asks the caller to fall back to V1).
///
/// Returns:
///   null            ⇒ V2 path declined (BPF gap or M9_NoFallback). Caller
///                     should run V1 BPF.
///   []AccountMutation ⇒ V2 produced these; caller commits.
///
/// Errors propagate fatal V2 failures (M9_BuiltinFailed / M9_FallbackFailed /
/// OutOfMemory) so the caller can log + skip commit.
pub fn v2DispatchInternal(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
    /// PR-K (2026-05-17): threaded from dispatchBpfExecution /
    /// dispatchV3ViaV2Producer. Passed through to v2DispatchBpfProgram
    /// where the SIMD-0459/0460/0257 gates resolve. Optional because the
    /// FeatureSet may not be wired at bootstrap; in that case all gates
    /// resolve to false → MODE 1 (no behavior change).
    feature_set: ?*const features_mod.FeatureSet,
    /// CU-METER (2026-07-05): see dispatchBpfExecution.
    tx_meter: ?*u64,
) !?[]bpf_mod.AccountMutation {
    if (ix.program_id_index >= ptx.static_key_count) {
        // F4 SITE 1 — LEGIT-REJECT (verified vs Agave 4.1.0): program id
        // resolved via ALT / index out of static-key range ⇒ Agave rejects the
        // tx at sanitize too, so the null here is canonical behavior, NOT a
        // silent eat. INFO level on purpose (a warn would false-alarm the
        // forensic guardian); per-slot deduped. program_key is not defined
        // yet at this point, so log the index instead.
        const Dedup = struct {
            var last: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
        };
        if (warnOncePerSlot(&Dedup.last, bank.slot)) {
            std.log.info(
                "[V2-SANITIZE-REJECT] slot={d} program_id_index={d} static_key_count={d} — sanitize-shape reject (Agave rejects this tx too; benign)",
                .{ bank.slot, ix.program_id_index, ptx.static_key_count },
            );
        }
        return null;
    }
    const program_key: [32]u8 = ptx.account_keys[ix.program_id_index];

    // PR-5p (2026-05-19): resolve the program's sBPF version ONCE at entry so
    // every outcome record carries it. resolveProgramSbpfVersion does a
    // db.getAccountInSlot + ELF header parse — gate it on isPr5pEnabled so
    // the hot path is untouched when instrumentation is off. 255 = unknown
    // (resolution failed, e.g., builtin/precompile/loader-state-not-program).
    const pr5p_elf_version: u8 = if (vex_store.recorder.isPr5pEnabled()) blk: {
        if (elf_version.resolveProgramSbpfVersion(&program_key, db, bank.slot, bank.ancestors())) |v| {
            break :blk @intFromEnum(v);
        }
        break :blk 255;
    } else 255;

    // Build snapshots for the instruction's account list.
    //
    // r71-fix-5 (2026-04-28): for accounts not yet in db (e.g. to-be-created
    // via System::CreateAccount in this tx), fall back to an empty default
    // snapshot (lamports=0, owner=System, data=[], non-executable). Pre-fix
    // we silently `continue`'d, dropping the account entirely → BPF program
    // ran against an INCOMPLETE input region missing the would-be-created
    // accounts → CPI System::CreateAccount had no target slot to fill in →
    // mutations for new accounts never propagated. Slot 484 carrier: tx[6]
    // creates 12 PDAs via GJHtFqM9 program; all 12 were silently skipped
    // pre-fix. Solana's tx model REQUIRES all referenced accounts (existing
    // OR to-be-created) to be in the snapshot list with their pre-state.
    const SYSTEM_PID_FOR_DEFAULT: [32]u8 = [_]u8{0} ** 32;
    const snaps = try alloc.alloc(v2dispatch.AccountSnapshot, ix.account_indices.len);
    defer alloc.free(snaps);
    var snap_count: usize = 0;
    const num_signed = ptx.num_required_sigs;

    // r75-bug-class-d8 (2026-05-06): per-tx Sysvar1nstructions blob.
    // Anchor programs (e.g. HistoryJT::CopyGossipContactInfo) read this
    // sysvar via `load_instruction_at_checked` to introspect prior IXs
    // (typically Ed25519SigVerify precompile readback). Vexor previously had
    // no construction code → BPF read empty/stale bytes → `get_instruction_relative(-1)`
    // returned garbage → tx aborted with NotSigVerified → PDA write dropped
    // → bank_hash diverged from oracle-node (carrier of slot 406443919 + cascade).
    // Build the blob byte-exactly per Agave canonical
    // (`solana-instructions-sysvar-3.0.0/src/lib.rs:69-141`) and inject it
    // when the IX references the Sysvar1Instructions pubkey. Find the
    // executing-IX index by pointer-matching the zero-copy slice (`ix` is
    // a value copy of an entry in `ptx.instructions[]`; the `.ptr` of its
    // `account_indices` slice is unique per IX since it indexes into tx_data).
    var ix_idx_for_sysvar: u16 = 0;
    for (ptx.instructions[0..ptx.num_instructions], 0..) |candidate, i| {
        if (candidate.account_indices.ptr == ix.account_indices.ptr) {
            ix_idx_for_sysvar = @intCast(i);
            break;
        }
    }
    var sysvar_instructions_blob: ?[]u8 = null;
    defer if (sysvar_instructions_blob) |b| alloc.free(b);

    for (ix.account_indices) |aidx| {
        if (aidx >= ptx.num_accounts) continue;
        const key = ptx.account_keys[aidx];

        // Sysvar1nstructions: synthesize per-tx blob (transient, not from
        // AccountsDb). Construct lazily on first reference; cache for the
        // remaining loop iterations of this dispatch call.
        if (std.mem.eql(u8, &key, &instructions_sysvar_mod.INSTRUCTIONS_SYSVAR_ID)) {
            if (sysvar_instructions_blob == null) {
                sysvar_instructions_blob = buildInstructionsSysvarBlob(alloc, ptx, ix_idx_for_sysvar) catch null;
                // r75-bug-class-d8 PROBE: at slot 919 dump the blob hex for one HistoryJT
                // call, so a Python-side byte comparator can verify byte-exact parity
                // against Agave's `serialize_instructions` for the same tx inputs.
                // Gated on slot + program_id_index match for HistoryJT.
                if (bank.slot == 406443919 and sysvar_instructions_blob != null) {
                    const SiDbg = struct {
                        var emitted: u32 = 0;
                    };
                    if (SiDbg.emitted < 2) {
                        const blob = sysvar_instructions_blob.?;
                        var hex_buf: [4096]u8 = undefined;
                        const hex_len = @min(blob.len * 2, hex_buf.len);
                        const charset = "0123456789abcdef";
                        var hi: usize = 0;
                        while (hi < hex_len / 2) : (hi += 1) {
                            hex_buf[hi * 2] = charset[blob[hi] >> 4];
                            hex_buf[hi * 2 + 1] = charset[blob[hi] & 0x0f];
                        }
                        std.log.warn(
                            "[SYSVAR-INSTR-DBG] slot={d} ix_idx={d} blob_len={d} blob_hex={s}\n",
                            .{ bank.slot, ix_idx_for_sysvar, blob.len, hex_buf[0..hex_len] },
                        );
                        SiDbg.emitted += 1;
                    }
                }
            }
            if (sysvar_instructions_blob) |blob| {
                snaps[snap_count] = .{
                    .pubkey = key,
                    .lamports = 0,
                    .owner = SYSVAR_OWNER_FOR_INSTRUCTIONS,
                    .executable = false,
                    .rent_epoch = std.math.maxInt(u64),
                    .data = blob,
                    .is_writable = false, // sysvar is read-only
                    .is_signer = false,
                };
                snap_count += 1;
                continue;
            }
            // If construction fails (OOM), fall through to db.getAccount —
            // worst case is the prior empty/stale-data behavior, no regression.
        }

        // r75-bug-class-c-v2dispatch-2026-05-06: pending_writes overlay before
        // db.getAccount fallback. Same pattern as fee paths + System overlay.
        // Without this, V2 dispatch reads stale snapshot bytes for accounts
        // already mutated earlier in the same slot — e.g. fee_payer that paid
        // a fee in tx N would still appear at pre-slot lamports when V2
        // dispatches tx N+1 referencing the same account.
        var found_pending: bool = false;
        var pwi: usize = bank.pending_writes.items.len;
        while (pwi > 0) {
            pwi -= 1;
            const pw = &bank.pending_writes.items[pwi];
            if (std.mem.eql(u8, &pw.pubkey.data, &key)) {
                snaps[snap_count] = .{
                    .pubkey = key,
                    .lamports = pw.lamports,
                    .owner = pw.owner.data,
                    .executable = pw.executable,
                    .rent_epoch = pw.rent_epoch,
                    .data = pw.data,
                    .is_writable = ptx.isWritable(aidx),
                    .is_signer = aidx < num_signed,
                };
                found_pending = true;
                break;
            }
        }
        if (found_pending) {
            snap_count += 1;
            continue;
        }

        const pk = core.Pubkey{ .data = key };
        if (db.getAccountInSlot(&pk, bank.slot, bank.ancestors())) |acct| {
            snaps[snap_count] = .{
                .pubkey = key,
                .lamports = acct.lamports,
                .owner = acct.owner.data,
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .data = acct.data,
                .is_writable = ptx.isWritable(aidx),
                .is_signer = aidx < num_signed,
            };
        } else {
            // To-be-created account — default empty pre-state.
            // @prov:dispatch.default-empty-account
            snaps[snap_count] = .{
                .pubkey = key,
                .lamports = 0,
                .owner = SYSTEM_PID_FOR_DEFAULT,
                .executable = false,
                .rent_epoch = 0,
                .data = &[_]u8{},
                .is_writable = ptx.isWritable(aidx),
                .is_signer = aidx < num_signed,
            };
        }
        snap_count += 1;
    }

    // Wave 6 final: Bank-backed SysvarCache populate via BankSysvarAdapter.
    // Required by the V2 BPF program path (vex-058 invariant — no silent
    // zero-fill). Builtins also tolerate a populated cache.
    var v2_sysvars = vex_bpf2.sysvar_cache.SysvarCache.init(alloc);
    defer v2_sysvars.deinit();
    {
        var adapter = bank_sysvar_adapter.BankSysvarAdapter.init(bank, db);
        v2_sysvars.populateFromBank(&adapter) catch {}; // best-effort
    }

    // Wave 6B: build a FallbackContext so M9 *_VariantPending_* errors for
    // Vote/Stake/ALT route into the battle-tested V1 native handlers
    // (executeVoteInstruction, stake_program.execute, address_lookup_table.execute).
    var fb_state = wave6b.FallbackState{
        .ix = ix,
        .ptx = ptx,
        .bank = bank,
        .db = db,
        // Day-2 PR-A.2: v2_dispatch path doesn't have ancestor_slots in scope yet
        // (would require threading through v2DispatchInternal). Defer to PR-A.3.
        // Empty = legacy flat-read behavior — same as pre-Day-2.
        .ancestor_slots = &[_]u64{},
    };
    // Nonce-CPI Tier-2: build the durable-nonce env from THIS bank (identical
    // source to the top-level path at ~replay_stage.zig:10918, PROVEN @414201776)
    // so a BPF program that CPIs System Advance/Withdraw/Initialize (4/5/6)
    // executes byte-identically instead of failing M9_System_VariantPending_*.
    const fb_rbh_len = bank.recent_blockhashes.len;
    const fb_nonce_env: system_v2.NonceEnv = if (fb_rbh_len > 0) .{
        .recent_blockhash = bank.recent_blockhashes.buffer[fb_rbh_len - 1].blockhash.data,
        .lamports_per_signature = bank.recent_blockhashes.buffer[fb_rbh_len - 1].lamports_per_signature,
        .recent_blockhashes_empty = false,
        .rent_minimum_balance_fn = &rentExemptMinimumBalanceDefault,
    } else .{
        .recent_blockhash = [_]u8{0} ** 32,
        .lamports_per_signature = 0,
        .recent_blockhashes_empty = true,
        .rent_minimum_balance_fn = &rentExemptMinimumBalanceDefault,
    };
    const fallback_ctx: v2dispatch.FallbackContext = .{
        .state = @ptrCast(&fb_state),
        .trampoline = wave6b.trampoline,
        .nonce_env = fb_nonce_env,
    };

    const muts = v2dispatch.v2DispatchInternal(
        alloc,
        &program_key,
        ix.data,
        snaps[0..snap_count],
        &v2_sysvars,
        fallback_ctx,
    ) catch |e| {
        // Wave 6 final: M5_BankBackedBpfNotPlumbed → run the V2 BPF program path.
        if (e == error.M5_BankBackedBpfNotPlumbed) {
            // Resolve ELF via BPF Loader Upgradeable indirection (matches
            // executeBpfProgramCore at replay_stage.zig:3180).
            const program_pk = core.Pubkey{ .data = program_key };
            const prog_acct = db.getAccountInSlot(&program_pk, bank.slot, bank.ancestors()) orelse {
                // F4 SITE 2 — INFRA-DECLINE tripwire (same silent-eat class as
                // [MIGRATED-BUILTIN-SILENT-EAT]): program account lookup miss
                // → silent null → V1 fallback on the .v2 route, but on the V3
                // route (dispatchV3ViaV2Producer) the instruction is outright
                // DROPPED — if the cluster commits this tx, the dropped write
                // is a bank_hash carrier. Fail-LOUD, per-slot deduped;
                // return-value semantics unchanged (hash-neutral).
                const Dedup = struct {
                    var last: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                };
                if (warnOncePerSlot(&Dedup.last, bank.slot)) {
                    const pk_hex = std.fmt.bytesToHex(program_key[0..8], .lower);
                    std.log.warn(
                        "[V2-DISPATCH-SILENT-EAT] site=prog-acct-miss slot={d} program={s} — program account lookup miss; declining V2 (null → V1 fallback / V3 drop)",
                        .{ bank.slot, &pk_hex },
                    );
                }
                return null;
            };
            // Wave 6C-1: also extract programdata's `slot` header field.
            // @prov:dispatch.programdata-layout — when a program is upgraded,
            // this slot advances; the cache uses it
            // to detect upgrades and evict stale entries. For non-upgradeable
            // (loader v2) programs, programdata_slot stays 0 and the cache
            // skips the freshness check (legacy semantics).
            var programdata_slot: u64 = 0;
            const elf_bytes: []const u8 = blk: {
                if (std.mem.eql(u8, &prog_acct.owner.data, &BPF_LOADER_UPGRADEABLE) and prog_acct.data.len >= 36) {
                    const state = std.mem.readInt(u32, prog_acct.data[0..4], .little);
                    if (state == 2) {
                        var pd_key = core.Pubkey{ .data = undefined };
                        @memcpy(&pd_key.data, prog_acct.data[4..36]);
                        if (db.getAccountInSlot(&pd_key, bank.slot, bank.ancestors())) |pd_acct| {
                            if (pd_acct.data.len >= 45) {
                                programdata_slot = std.mem.readInt(u64, pd_acct.data[4..12], .little);
                                break :blk pd_acct.data[45..];
                            }
                        }
                    }
                }
                break :blk prog_acct.data;
            };
            const cache_ptr = getOrInitV2ProgramCache(alloc);

            // r75-bug-class-b-tx-cpi-extras (2026-05-06): build cpi_extras
            // from ptx.account_keys not already in snaps[]. These are
            // tx-level accounts (System program, BPF Loader, etc.) that the
            // CURRENT instruction doesn't directly reference but a CPI from
            // this program might. Without this, V2's findAccountIndex
            // returns null on CPIs to System::CreateAccount → tx revert →
            // Vexor missed PriorityFeeDistribution PDA inits → bank_hash
            // diverged from slot 345+ (carrier of Bug Class B residual).
            // F4 SITE 3 — OOM on the committed-execution path (A5 policy: "a
            // crash is consensus-safe; a dropped write is not", precedent
            // f1f53fe commitV2Mutations). Pre-fix this was `catch return null`
            // → V1 fallback ONLY when the allocator happened to fail =
            // nondeterministic divergence; on the V3 route the instruction
            // was outright dropped.
            const extras_raw = alloc.alloc(v2dispatch.AccountSnapshot, ptx.num_accounts) catch
                @panic("OOM: v2DispatchInternal cpi_extras alloc — cannot silently decline a committed-path dispatch (A5)");
            defer alloc.free(extras_raw);
            var extras_count: usize = 0;
            const num_signed_extras = ptx.num_required_sigs;
            tx_walk: for (0..ptx.num_accounts) |aidx| {
                const ek: [32]u8 = ptx.account_keys[aidx];
                // Skip if already in snaps[] for this ix.
                for (snaps[0..snap_count]) |sn| {
                    if (std.mem.eql(u8, &sn.pubkey, &ek)) continue :tx_walk;
                }
                // Read the account state (overlay-aware) just like the snap
                // builder above. CPI extras are added with is_writable=false
                // / is_signer=false at THIS frame; the inner CPI's account
                // metadata will reset those flags appropriately.
                var pwi_e: usize = bank.pending_writes.items.len;
                var found_e: bool = false;
                while (pwi_e > 0) {
                    pwi_e -= 1;
                    const pw_e = &bank.pending_writes.items[pwi_e];
                    if (std.mem.eql(u8, &pw_e.pubkey.data, &ek)) {
                        extras_raw[extras_count] = .{
                            .pubkey = ek,
                            .lamports = pw_e.lamports,
                            .owner = pw_e.owner.data,
                            .executable = pw_e.executable,
                            .rent_epoch = pw_e.rent_epoch,
                            .data = pw_e.data,
                            .is_writable = ptx.isWritable(@intCast(aidx)),
                            .is_signer = aidx < num_signed_extras,
                        };
                        found_e = true;
                        break;
                    }
                }
                if (!found_e) {
                    const pk_e = core.Pubkey{ .data = ek };
                    if (db.getAccountInSlot(&pk_e, bank.slot, bank.ancestors())) |acct_e| {
                        extras_raw[extras_count] = .{
                            .pubkey = ek,
                            .lamports = acct_e.lamports,
                            .owner = acct_e.owner.data,
                            .executable = acct_e.executable,
                            .rent_epoch = acct_e.rent_epoch,
                            .data = acct_e.data,
                            .is_writable = ptx.isWritable(@intCast(aidx)),
                            .is_signer = aidx < num_signed_extras,
                        };
                    } else {
                        const SYSTEM_PID_DEFAULT: [32]u8 = [_]u8{0} ** 32;
                        extras_raw[extras_count] = .{
                            .pubkey = ek,
                            .lamports = 0,
                            .owner = SYSTEM_PID_DEFAULT,
                            .executable = false,
                            .rent_epoch = 0,
                            .data = &[_]u8{},
                            .is_writable = ptx.isWritable(@intCast(aidx)),
                            .is_signer = aidx < num_signed_extras,
                        };
                    }
                }
                extras_count += 1;
            }

            // FIX #95 (2026-06-01): pre-warm CPI-callee programs into the V2
            // cache BEFORE dispatch. The resolver is lookup-only, so any
            // BPF→BPF CPI to a program not yet dispatched top-level this run
            // would miss → M7_RecursiveLoadFailed → inner instruction dropped
            // (the slot-412458795 SPL-Token CloseAccount carrier). Walk this
            // ix's accounts + the tx extras (together = all account_keys; every
            // CPI target at any depth is in account_keys). Strictly additive.
            for (snaps[0..snap_count]) |sp|
                prewarmCalleeProgram(cache_ptr, db, bank, &program_key, sp.pubkey, sp.owner, sp.data, sp.executable);
            for (extras_raw[0..extras_count]) |xa|
                prewarmCalleeProgram(cache_ptr, db, bank, &program_key, xa.pubkey, xa.owner, xa.data, xa.executable);

            // CU-METER (2026-07-05, carrier 419786142): budget = the tx's
            // REMAINING shared meter, not a fresh hardcoded 1.4M per ix.
            // @prov:dispatch.cu-shared-meter — the actual consumption (VM
            // insns + syscall costs + CPI, unified in the InvokeContext
            // meter) is drawn down via the defer below — including on
            // failure, where the dispatch reports the full budget (cluster
            // "consumed N of N" on exhaustion).
            const cu_budget: u64 = if (tx_meter) |m| m.* else v2dispatch.DEFAULT_COMPUTE_UNITS;
            var cu_consumed: u64 = 0;
            defer if (tx_meter) |m| {
                m.* -|= cu_consumed;
            };
            // fix/cu-parity-batch2 (2026-07-12): the tx's REAL requested heap_size
            // (RequestHeapFrame if present+valid, else 32768 default) — used ONLY
            // for the heap-entry CU charge (@prov:compute-budget.heap-cost, applied
            // at every VM creation). Deliberately separate from the 256*1024 region
            // param below, which stays hardcoded (fix-4/architectural, deferred).
            const requested_heap_bytes = compute_budget.heapSize(compute_budget.parseInstructions(
                ptx.instructions[0..ptx.num_instructions],
                ptx.account_keys[0..ptx.num_accounts],
            ));
            const muts2 = v2dispatch.v2DispatchBpfProgramMetered(
                alloc,
                &program_key,
                ix.data,
                snaps[0..snap_count],
                elf_bytes,
                programdata_slot,
                &v2_sysvars,
                cache_ptr,
                feature_set,
                cu_budget,
                bank.slot,
                256 * 1024, // heap_size: max Solana heap (vex-V2-HEAPSIZE; region size, fix-4 deferred)
                requested_heap_bytes,
                extras_raw[0..extras_count],
                &cu_consumed,
            ) catch |bpf_e| {
                logV2DispatchFallback(@errorName(bpf_e));
                // r75-bug-class-b-2026-05-06: discriminate program-side aborts
                // from V2 infrastructure failures. M4_RunFailed = program ran
                // through MM init + serialize + verify + interpreter and then
                // returned an error (e.g. Anchor `panic!()`/`require!()` →
                // sol_panic_/abort syscall). V1 fallback only re-runs the same
                // input, hits its own pc=43931 wild-pointer fault, and STILL
                // produces zero mutations (just with a Vexor fault instead of
                // a clean program-abort) — so NEVER retry V1 for M4.
                // Other M-class errors (M1_LoadFailed, M2_MapInitFailed,
                // M3_VerifyFailed, M5_*, M6_*, M8_*) reflect V2 infrastructure
                // not reaching the program; V1's separate machinery may still
                // succeed, so fall through to V1 there.
                //
                // fix/failed-tx-rollback (2026-06-10, carrier #6 @414386920):
                // the old code swallowed M4_RunFailed into a SUCCESS with zero
                // mutations (`return &[_]AccountMutation{}`) — correct for the
                // failing instruction's OWN writes, but it hid the genuine
                // program failure from the instruction loops, so a multi-ix tx
                // kept executing past the failure and kept its EARLIER
                // instructions' writes (Agave fails the whole tx:
                // message_processor.rs stop-at-first-error +
                // account_saver.rs rollback-accounts-only). PROVEN at the
                // pinned gate boot 2026-06-10: the carrier ix3 SyscallError
                // (vm.run pc=34157, SPL Stake Pool 06814ed4) logged
                // [V2-DISPATCH] but no [TX-ROLLBACK] fired and the 730,009-B
                // ValidatorList phantom persisted → bank_hash 90c7c8cf… ≠
                // cluster 6e979b35…. PROPAGATE the error instead; the
                // dispatch boundary (dispatchV3ViaV2Producer pass-through,
                // dispatchBpfExecution .v2-arm M4 guard) guarantees no V1
                // retry, and the loops classify exactly M4_RunFailed as a
                // genuine tx failure.
                if (bpf_e == error.M4_RunFailed) {
                    if (vex_store.recorder.isPr5pEnabled()) {
                        vex_store.recorder.emitPr5pBpfOutcome(
                            &program_key,
                            pr5p_elf_version,
                            .wave6_m4_run_failed,
                            @errorName(bpf_e),
                            0,
                        );
                    }
                    return bpf_e;
                }
                if (vex_store.recorder.isPr5pEnabled()) {
                    vex_store.recorder.emitPr5pBpfOutcome(
                        &program_key,
                        pr5p_elf_version,
                        .wave6_other_fail,
                        @errorName(bpf_e),
                        0,
                    );
                }
                // F4 SITE 4 — INFRA-DECLINE tripwire: V2 BPF infrastructure
                // failure (M1/M2/M3/M5/M6/M8, NOT M4 program-abort which
                // propagates above) → null → V1 fallback / V3 drop. The
                // pre-existing logV2DispatchFallback above is once-per-BOOT at
                // debug level = effectively silent; this warn is the real
                // tripwire. Per-slot deduped, hash-neutral (log only).
                const Dedup = struct {
                    var last: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
                };
                if (warnOncePerSlot(&Dedup.last, bank.slot)) {
                    const pk_hex = std.fmt.bytesToHex(program_key[0..8], .lower);
                    std.log.warn(
                        "[V2-DISPATCH-SILENT-EAT] site=bpf-infra-fail slot={d} err={s} program={s} — V2 BPF infrastructure failure; declining V2 (null → V1 fallback / V3 drop)",
                        .{ bank.slot, @errorName(bpf_e), &pk_hex },
                    );
                }
                return null; // V1 fallback on V2 infrastructure failures only
            };
            if (vex_store.recorder.isPr5pEnabled()) {
                vex_store.recorder.emitPr5pBpfOutcome(
                    &program_key,
                    pr5p_elf_version,
                    .ok_wave6,
                    null,
                    @intCast(muts2.len),
                );
            }
            return muts2;
        }
        if (e == error.M9_NoFallback) {
            if (vex_store.recorder.isPr5pEnabled()) {
                vex_store.recorder.emitPr5pBpfOutcome(
                    &program_key,
                    pr5p_elf_version,
                    .m9_no_fallback,
                    @errorName(e),
                    0,
                );
            }
            // F4 SITE 5 — INFRA-DECLINE tripwire: M9_NoFallback swallowed →
            // null → V1 fallback / V3 drop. This is the EXACT shape of the
            // Config Core-BPF migration carrier (slot 419002721): an M9 stub
            // declined, the decline was eaten, 0 mutations were committed for
            // a tx the cluster committed. Fail-LOUD, per-slot deduped,
            // hash-neutral (log only).
            const Dedup = struct {
                var last: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
            };
            if (warnOncePerSlot(&Dedup.last, bank.slot)) {
                const pk_hex = std.fmt.bytesToHex(program_key[0..8], .lower);
                std.log.warn(
                    "[V2-DISPATCH-SILENT-EAT] site=m9-no-fallback slot={d} err={s} program={s} — M9 stub declined; falling back to V1 (Config-carrier shape)",
                    .{ bank.slot, @errorName(e), &pk_hex },
                );
            }
            return null;
        }
        if (vex_store.recorder.isPr5pEnabled()) {
            vex_store.recorder.emitPr5pBpfOutcome(
                &program_key,
                pr5p_elf_version,
                .other_error,
                @errorName(e),
                0,
            );
        }
        return e;
    };
    if (vex_store.recorder.isPr5pEnabled()) {
        vex_store.recorder.emitPr5pBpfOutcome(
            &program_key,
            pr5p_elf_version,
            .ok_top,
            null,
            @intCast(muts.len),
        );
    }
    return muts;
}

/// Apply V2 mutations to the bank's pending_writes via the existing LtHash
/// path. Mirrors V1's commit loop in `executeBpfProgram`.
///
/// fix/commit-owner-loss (2026-06-10, carrier @414352136): the committed
/// owner is `m.owner` — the dispatch layer's DISCRIMINATED post-state owner
/// (v2_dispatch.zig:1311 out-vs-canon RULE#15+DM-lamport discrimination,
/// :417/:589/:1453 + the W6B trampoline at replay_stage.zig:7598 all populate
/// it with post-state). `m.new_owner` is only a "changed vs the dispatch
/// snapshot" flag and MUST NOT be used to re-derive the owner here: for a tx
/// that CREATES an account (mutation A: ATA CreateIdempotent,
/// new_owner=Token-2022) then writes it data-only (mutation B:
/// TransferChecked — the dispatch snapshot already saw A's owner via the r75
/// overlay, so new_owner=null), the old `m.new_owner orelse pre_owner` logic
/// re-derived B's owner from the PRE-TX durable db → MISS → System zeros, and
/// the slot-flush dedup (last-write-wins, replay_stage.zig:6232-6238) plus the
/// freeze per-pubkey lt aggregation (bank.zig:3243 keeps LAST new_lt)
/// persisted B's zero owner + poisoned last_new_lt. Carrier: ATA
/// 7m7NUeprWXjHSkV9Tqxc4XYWSEUCDKdk462iMpN4snvQ — cluster owner
/// TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, Vexor committed all-zeros;
/// lamports+data byte-identical. Marked `pub` for the
/// kat_commit_owner_414352136 regression KAT.
pub fn commitV2Mutations(
    bank: *Bank,
    db: *AccountsDb,
    mutations: []const bpf_mod.AccountMutation,
) void {
    for (mutations) |*m| {
        // r76-d23 (2026-05-11): Agave-canonical new-account writeback.
        //
        // Pre-d23 dropped any mutation whose pubkey was absent from accounts_db,
        // silently losing writes to brand-new accounts created during BPF
        // execution (e.g. ATA program → System.CreateAccount CPI at slot
        // 407,600,782 carrier — MLRVjN6v Token-owned 165-byte ATA dropped,
        // accounts_lt_hash diverged from gov by exactly that contribution).
        //
        // Agave has no such filter: accounts-db/src/accounts_db.rs:5350
        // `store_accounts_unfrozen` is write-only — it accepts any storable
        // regardless of prior existence. New pubkeys contribute new_lt to the
        // running LtHash without an old contribution to cancel
        // (runtime/src/bank/accounts_lt_hash.rs `apply_changes`); identity
        // semantics are already enforced by Vex's accountLtHash returning
        // LtHash.init() when lamports == 0 (bank.zig:666).
        //
        // Defaults for the new-account branch mirror Vex's native System path
        // at executeSystemInstruction (replay_stage.zig:5505-5517):
        //   pre_owner = System program ID  (lt-hash short-circuits anyway)
        //   pre_lamports = 0               (forces old_lt = identity)
        //   pre_executable = false         (Token data accounts non-executable)
        //   pre_data = &[_]u8{}            (no prior bytes to subtract)
        //   rent_epoch = u64::MAX          (RENT_EXEMPT_RENT_EPOCH sentinel)
        // fix/commit-owner-loss (2026-06-10, carrier @414352136) part 2:
        // pre-state with same-slot pending-write visibility. The old code read
        // db.getAccountInSlot ONLY (pre-tx durable state) — blind to writes
        // appended earlier THIS slot/tx, so a later mutation of a same-tx
        // created account regressed pre_executable/rent_epoch to new-account
        // defaults. Same r75-bug-class-c overlay as the dispatch snapshot
        // builder (replay_stage.zig:6963-6993) and executeSystemInstruction
        // (replay_stage.zig:8349-8386): walk bank.pending_writes newest-first
        // FIRST, fall back to db only on miss. old_lt impact is nil for the
        // freeze accumulator (bank.zig:3243 keeps the FIRST write's old_lt per
        // pubkey — when the overlay hits, an earlier write exists, so THIS
        // write's old_lt is never the first); pre_executable/rent_epoch now
        // carry the true predecessor state into the committed write.
        const SYSTEM_PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;
        var pre_owner: [32]u8 = SYSTEM_PROGRAM_ID;
        var pre_lamports: u64 = 0;
        var pre_executable: bool = false;
        var pre_data: []const u8 = &[_]u8{};
        var out_rent_epoch: u64 = std.math.maxInt(u64);
        // Parallel-exec (2026-07-08): override-aware pre-state overlay. On a
        // worker thread the tx's own earlier writes live in worker_writes_override,
        // NOT pending_writes; overlayNewest scans override FIRST then pending_writes.
        // Serial path (override == null) is byte-identical to the prior manual
        // pending_writes newest-first scan (empty primary tier collapses to a
        // pending-only scan — proven in the overlay_lookup KAT).
        var found_pending = false;
        if (bank.overlayNewest(&m.pubkey.data)) |pw| {
            pre_owner = pw.owner.data;
            pre_lamports = pw.lamports;
            pre_executable = pw.executable;
            pre_data = pw.data;
            out_rent_epoch = pw.rent_epoch;
            found_pending = true;
        }
        if (!found_pending) {
            if (db.getAccountInSlot(&m.pubkey, bank.slot, bank.ancestors())) |o| {
                pre_owner = o.owner.data;
                pre_lamports = o.lamports;
                pre_executable = o.executable;
                pre_data = o.data;
                out_rent_epoch = o.rent_epoch;
            }
        }
        // fix/commit-owner-loss part 1: the committed owner is the dispatch
        // layer's discriminated post-state `m.owner` — NEVER re-derived from
        // `m.new_owner orelse pre-state` (see fn doc above; the orelse arm
        // committed System zeros for the carrier's same-tx-created ATA).
        const post_owner: [32]u8 = m.owner;
        const old_lt = bank_mod.Bank.accountLtHash(
            &m.pubkey.data,
            &pre_owner,
            pre_lamports,
            pre_executable,
            pre_data,
        );
        const new_lt = bank_mod.Bank.accountLtHash(
            &m.pubkey.data,
            &post_owner,
            m.new_lamports,
            pre_executable,
            m.data,
        );
        // F1 (2026-07-01): OOM here MUST fail-stop. Silently skipping (`catch
        // continue`) or dropping (`catch {}`) a committed V2-BPF mutation leaves
        // the account at its stale pre-state while the tx records success =
        // silent bank_hash divergence. A crash is consensus-safe; a dropped
        // write is not. Matches the sibling flushPendingWritesToDb (A5, replay_stage.zig:10182,10186).
        const data_copy = bank.allocator.alloc(u8, m.data.len) catch
            @panic("OOM: commitV2Mutations data copy — cannot drop a committed V2 account write (A5)");
        @memcpy(data_copy, m.data);
        // Parallel-exec (2026-07-08): route through collectWrite so the write
        // lands in worker_writes_override on a worker thread (barrier-merged in
        // deterministic worker-index order) and in pending_writes on the serial
        // path — byte-identical to the prior raw append when override == null.
        bank.collectWrite(.{
            .pubkey = .{ .data = m.pubkey.data },
            .lamports = m.new_lamports,
            .owner = .{ .data = post_owner },
            .executable = pre_executable,
            .rent_epoch = out_rent_epoch,
            .data = data_copy,
            .old_lt = old_lt,
            .new_lt = new_lt,
        }) catch
            @panic("OOM: commitV2Mutations collectWrite — cannot drop a committed V2 account write (A5)");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Wave 6B: FallbackContext trampoline implementations
// ──────────────────────────────────────────────────────────────────────────────
//
// v2_dispatch.zig exposes M9_*_VariantPending_* errors for Vote/Stake/ALT
// programs whose M9 builtin paths are skeleton-pending. Production routes
// those builtins through battle-tested V1 native handlers (vex-014 / vex-094
// / vex-095 / vex-058 fixes preserved bit-identical). This trampoline
// bridges the FallbackContext vtable to those handlers WITHOUT pulling
// replay_stage's private types (ParsedTx / Bank / AccountsDb) into v2_dispatch.zig.
//
// V1 handler citations:
//   • executeVoteInstruction        — replay_stage.zig:3213 (made `pub` in W6B).
//   • stake_program.execute         — native/stake_program.zig:1749.
//   • address_lookup_table.execute  — native/address_lookup_table.zig:643.
//
// Mutation capture mechanism (all three programs):
//   The V1 handlers commit by appending to `bank.pending_writes`. We
//   snapshot `pending_writes.items.len` before the call, slice items
//   appended afterwards, convert each `bank.AccountWrite` to the canonical
//   `vex_bpf.AccountMutation` shape, then truncate `pending_writes.items.len`
//   back to the snapshot length so the V2 commit path (commitV2Mutations)
//   doesn't double-commit the same mutations.
//
//   This is safe because (a) `bank.pending_writes` is per-Bank and replay
//   schedules instructions serially per color group, (b) the appended
//   `data` buffers were `alloc.alloc`'d from `bank.allocator` and survive
//   the truncate (we copy into the AccountMutation's own `mut_alloc`-owned
//   buffers, then leave the originals in the bank arena to be reaped on
//   bank teardown — same lifecycle as V1's commit path uses today).
pub const wave6b = struct {
    const FallbackState = struct {
        ix: ParsedInstruction,
        ptx: *const ParsedTx,
        bank: *Bank,
        db: *AccountsDb,
        // Day-2 PR-A.2: ancestor chain passed through to native execs.
        ancestor_slots: []const u64 = &[_]u64{},
    };

    // [TOPVOTES-TRACE] TEMPORARY measurement (see bank.zig TvTrace) — count
    // vote-owned entries in the pending_writes range [pre_len..] that a
    // trampoline shrink is about to roll back. In shadow mode the buffer was
    // swapped to a private list (V1 commit re-collects later, so tramp-rolled
    // there is NOT a net loss); in enforce/fallback mode this measures a real
    // candidate drain. Interpretation happens offline from the counters.
    fn tvtCountVoteRolled(bank: *bank_mod.Bank, pre_len: usize) void {
        if (!bank_mod.TvTrace.on()) return;
        const items = bank.pending_writes.items;
        if (items.len <= pre_len) return;
        var tvt_n: u32 = 0;
        for (items[pre_len..]) |*w| {
            if (std.mem.eql(u8, &w.owner.data, &bank_mod.TvTrace.VOTE_OWNER)) tvt_n += 1;
        }
        bank.tvt_vote_rolled_tramp += tvt_n;
    }

    fn trampoline(
        state_opaque: *anyopaque,
        kind: v2dispatch.FallbackKind,
        alloc: std.mem.Allocator,
        program_id: *const [32]u8,
        ix_data: []const u8,
        snapshots: []const v2dispatch.AccountSnapshot,
    ) v2dispatch.DispatchError![]bpf_mod.AccountMutation {
        _ = program_id;
        _ = ix_data;
        // PR-5am (2026-05-20): ALT path consumes `snapshots`; vote/stake paths
        // still ignore it (they re-read via their own InstrCtx builders).
        const fb: *FallbackState = @ptrCast(@alignCast(state_opaque));

        // ── Stage-D Risk 2: buffer-swap isolation in shadow mode.
        // In .shadow mode, V1 has already committed its real mutations
        // to bank.pending_writes inline (replay_stage::shadowDispatch).
        // The V2 trampoline path runs alongside V1 for diagnostic-only
        // diffing — it must NOT touch bank.pending_writes mid-flight,
        // even transiently, because (a) future block-production replay
        // may run concurrent threads against the same bank, and (b)
        // any append-then-truncate pattern leaks transient state into
        // a buffer V1 owns. Swap in a dedicated empty ArrayList for the
        // duration of the V1 native call; restore on exit. The native
        // handler still calls `bank.pending_writes.append`, but during
        // the swap window that points at our private isolated buffer.
        const is_shadow = vex_bpf2.dispatch_mode.isShadow();
        var saved_pending: std.ArrayListUnmanaged(bank_mod.AccountWrite) = .{};
        if (is_shadow) {
            saved_pending = fb.bank.pending_writes;
            fb.bank.pending_writes = .{};
        }
        defer if (is_shadow) {
            // Free any data buffers in our shadow buffer that were not
            // captured (defensive — capture path below frees them
            // explicitly via the capturePendingWrites→free chain on
            // success). Note: data slices in pending_writes are
            // bank.allocator-owned, NOT trampoline-alloc. Leaving them
            // for bank arena teardown matches V1 lifecycle.
            fb.bank.pending_writes.deinit(fb.bank.allocator);
            fb.bank.pending_writes = saved_pending;
        };

        // Snapshot pending_writes length so we can isolate this V1 call's
        // contribution. In shadow mode after the swap above, pre_len = 0.
        const pre_len = fb.bank.pending_writes.items.len;

        switch (kind) {
            .vote => {
                if (bank_mod.TvTrace.on()) _ = fb.bank.tvt2_site_tramp.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
                executeVoteInstruction(fb.ix, fb.ptx, fb.bank, fb.db, alloc, fb.ancestor_slots) catch {
                    if (fb.bank.pending_writes.items.len > pre_len) {
                        tvtCountVoteRolled(fb.bank, pre_len); // [TOPVOTES-TRACE] TEMPORARY measurement
                        fb.bank.pending_writes.shrinkRetainingCapacity(pre_len);
                    }
                    return error.M9_VoteFallbackFailed;
                };
            },
            .stake => {
                // Phase-1: M9 fallback path stays native — pass null
                // feature_set (byte-identical to current; fallback never
                // re-routes to BPF, which would risk re-entrancy here).
                executeStakeInstruction(fb.ix, fb.ptx, fb.bank, fb.db, alloc, @as(?*const features_mod.FeatureSet, null)) catch {
                    if (fb.bank.pending_writes.items.len > pre_len) {
                        fb.bank.pending_writes.shrinkRetainingCapacity(pre_len);
                    }
                    return error.M9_StakeFallbackFailed;
                };
            },
            .alt => {
                runAltFallback(fb, alloc, snapshots) catch {
                    if (fb.bank.pending_writes.items.len > pre_len) {
                        fb.bank.pending_writes.shrinkRetainingCapacity(pre_len);
                    }
                    return error.M9_AltFallbackFailed;
                };
            },
        }

        // Capture appended writes, convert to AccountMutation, then roll
        // back so the V2 commit path is the single committer.
        const post_len = fb.bank.pending_writes.items.len;
        const appended = fb.bank.pending_writes.items[pre_len..post_len];
        const muts = capturePendingWrites(alloc, appended) catch |e| {
            tvtCountVoteRolled(fb.bank, pre_len); // [TOPVOTES-TRACE] TEMPORARY measurement
            fb.bank.pending_writes.shrinkRetainingCapacity(pre_len);
            return e;
        };
        tvtCountVoteRolled(fb.bank, pre_len); // [TOPVOTES-TRACE] TEMPORARY measurement (success-path capture rollback)
        fb.bank.pending_writes.shrinkRetainingCapacity(pre_len);
        return muts;
    }

    /// ALT runs through `address_lookup_table.execute(InstrCtx, ix_data)`.
    /// We build an ALT-shaped InstrCtx from the FallbackState's tx + bank,
    /// invoke the V1 handler, then translate the BorrowedAccount mutations
    /// back into AccountWrites on `bank.pending_writes` (same shape the
    /// vote/stake handlers use natively).
    ///
    /// PR-5am (2026-05-20): pre-state for each BorrowedAccount comes from
    /// the `snapshots` arg (built by v2DispatchInternal's snap loop at
    /// replay_stage.zig:5601-5651). That snap builder already (a) walks
    /// `bank.pending_writes` newest-first for intra-TX visibility, then (b)
    /// falls through to `db.getAccountInSlot`, then (c) substitutes
    /// default-empty (`AccountSharedData::create(0, vec![], &system_program::id(), false, 0)`)
    /// for to-be-created accounts. The previous code re-read pre-state via
    /// `db.getAccountInSlot` directly, which misses (a) and (c) — for the
    /// CreateLookupTable carrier (slot 276 TX[258] miss of `2L2gN2D...`),
    /// the new-account read returned null and the populate-loop bailed with
    /// `error.MissingAccount`, dropping the entire write set; the writeback
    /// loop's `orelse continue` was the second drop site.
    ///
    /// Pubkey alignment: in the M9 trampoline path `snapshots[i].pubkey`
    /// equals `ptx.account_keys[indices[i]]` because the snap builder only
    /// skips on `aidx >= ptx.num_accounts` and we error on the same check
    /// below. A defensive `eql` check guards a regression in either loop.
    fn runAltFallback(
        fb: *FallbackState,
        alloc: std.mem.Allocator,
        snapshots: []const v2dispatch.AccountSnapshot,
    ) !void {
        const alt = address_lookup_table;

        // Build BorrowedAccount[] for this instruction's account list.
        const indices = fb.ix.account_indices;
        const accounts = try alloc.alloc(alt.BorrowedAccount, indices.len);

        // d28jj fix (2026-05-12): zero-init `accounts[]` before the populate loop.
        // `alloc.alloc` returns uninit memory in Zig (no implicit zero-fill).
        // Previously, an early `return error.MissingAccount` (lines for aidx-bounds
        // or db-lookup) would leave higher-index slots uninitialized; the defer
        // then walked the FULL array, reading `a.data.len` (garbage usize) and,
        // when non-zero by chance, calling `alloc.free(a.data)` on a wild pointer.
        // The allocator's chunk-lookup happened to succeed sometimes, then its
        // debug-fill `@memset(non_const_ptr[0..bytes_len], undefined)` hit
        // unmapped/invalid memory → SIGSEGV. Sparse trigger (~1 in 16M vote ix
        // observed in 2026-05-12 ~2h36min run). Fix: pre-init each slot to a
        // safe default (data = empty slice) so the defer's `if (a.data.len > 0)`
        // short-circuits for un-populated slots.
        for (accounts) |*a| a.* = .{
            .pubkey = [_]u8{0} ** 32,
            .lamports = 0,
            .owner = [_]u8{0} ** 32,
            .data = &[_]u8{},
            .rent_epoch = 0,
            .executable = false,
            .is_signer = false,
            .is_writable = false,
        };

        defer {
            for (accounts) |*a| if (a.data.len > 0) alloc.free(a.data);
            alloc.free(accounts);
        }

        var signer_mask: u64 = 0;
        const num_signed = fb.ptx.num_required_sigs;
        for (indices, 0..) |aidx, i| {
            if (aidx >= fb.ptx.num_accounts) return error.MissingAccount;
            const key = fb.ptx.account_keys[aidx];

            // PR-5am: pre-state from snapshots (built by v2DispatchInternal's
            // snap loop). See runAltFallback doc-comment for the why.
            if (i >= snapshots.len) return error.MissingAccount;
            const snap = &snapshots[i];
            if (!std.mem.eql(u8, &snap.pubkey, &key)) return error.MissingAccount;

            const data_copy = try alloc.alloc(u8, snap.data.len);
            if (snap.data.len > 0) @memcpy(data_copy, snap.data);
            accounts[i] = .{
                .pubkey = key,
                .lamports = snap.lamports,
                .owner = snap.owner,
                .data = data_copy,
                .rent_epoch = snap.rent_epoch,
                .executable = snap.executable,
                .is_signer = aidx < num_signed,
                .is_writable = fb.ptx.isWritable(aidx),
            };
            if (aidx < num_signed and i < 64) signer_mask |= @as(u64, 1) << @intCast(i);
        }

        var ictx = alt.InstrCtx{
            .accounts = accounts,
            .signer_mask = signer_mask,
            .allocator = alloc,
            .clock_slot = fb.bank.slot,
            // ALT extend uses the slot hash list; null forces the V1
            // conservative path (slot-not-found is the safe pre-feature
            // behaviour matching agave). When SlotHashes lands for V2,
            // swap in a real callback.
            .recent_slot_fn = null,
            // ALT create/extend fund the new table to the rent-exempt minimum.
            // A null fn made createLookupTable take the `else 1` branch → the table
            // got 1 lamport (not 1,280,640) → wrong LtHash leaf → bank_hash carrier.
            // Wire the canonical Agave-default rent (same fn the v2 path already uses).
            // recent_slot_fn stays null — safe for in-block successes; Tier-2
            // SlotHashes plumbing (premature-close cooldown) tracked separately.
            .min_rent_balance_fn = &rentExemptMinimumBalanceDefault,
        };

        try alt.execute(&ictx, fb.ix.data);

        // Translate BorrowedAccount mutations back to AccountWrites on
        // bank.pending_writes (matching how vote/stake handlers commit).
        for (accounts, indices, 0..) |*a, aidx, i| {
            if (!a.is_writable) continue;
            if (aidx >= fb.ptx.num_accounts) continue;
            const key = fb.ptx.account_keys[aidx];

            // PR-5am: pre-state from snapshots (same source as populate loop
            // above). Without this, CreateLookupTable's new account had no
            // db pre-state → `orelse continue` silently dropped the writeback,
            // making the entire ALT create a no-op even when V1 succeeded.
            if (i >= snapshots.len) continue;
            const pre = &snapshots[i];
            if (!std.mem.eql(u8, &pre.pubkey, &key)) continue;

            const lamports_changed = a.lamports != pre.lamports;
            const owner_changed = !std.mem.eql(u8, &a.owner, &pre.owner);
            const data_changed = (a.data.len != pre.data.len) or
                (a.data.len > 0 and !std.mem.eql(u8, a.data, pre.data));
            if (!lamports_changed and !owner_changed and !data_changed) continue;

            const old_lt = bank_mod.Bank.accountLtHash(
                &key,
                &pre.owner,
                pre.lamports,
                pre.executable,
                pre.data,
            );
            const new_lt = bank_mod.Bank.accountLtHash(
                &key,
                &a.owner,
                a.lamports,
                a.executable,
                a.data,
            );
            const data_for_bank = fb.bank.allocator.alloc(u8, a.data.len) catch continue;
            if (a.data.len > 0) @memcpy(data_for_bank, a.data);
            fb.bank.collectWrite(.{ // parallel-exec: worker-buffer-aware (byte-identical on serial)
                .pubkey = .{ .data = key },
                .lamports = a.lamports,
                .owner = .{ .data = a.owner },
                .executable = a.executable,
                .rent_epoch = a.rent_epoch,
                .data = data_for_bank,
                .old_lt = old_lt,
                .new_lt = new_lt,
            }) catch {};
        }
    }

    /// Convert AccountWrite slice → owned AccountMutation slice. The caller
    /// frees per-element `data` and the slice itself from `alloc`.
    fn capturePendingWrites(
        alloc: std.mem.Allocator,
        appended: []const bank_mod.AccountWrite,
    ) v2dispatch.DispatchError![]bpf_mod.AccountMutation {
        var list = std.ArrayListUnmanaged(bpf_mod.AccountMutation){};
        errdefer {
            for (list.items) |*m| alloc.free(m.data);
            list.deinit(alloc);
        }
        for (appended) |w| {
            const data_copy = alloc.alloc(u8, w.data.len) catch return error.OutOfMemory;
            if (w.data.len > 0) @memcpy(data_copy, w.data);
            list.append(alloc, .{
                .pubkey = w.pubkey,
                .new_lamports = w.lamports,
                .owner = w.owner.data, // vex-039 restored: post-mutation owner (V2 trampoline)
                .data = data_copy,
                .new_owner = w.owner.data,
            }) catch return error.OutOfMemory;
        }
        return list.toOwnedSlice(alloc) catch error.OutOfMemory;
    }
};

/// One-time `[VBPF2-V2]` log line per validator boot, suppressed thereafter
/// to keep the replay log clean.
pub fn logV2DispatchFallback(reason: []const u8) void {
    const S = struct {
        var logged: bool = false;
    };
    if (S.logged) return;
    S.logged = true;
    std.log.debug(
        "[VBPF2-V2] V2 dispatch returned {s}; falling through to V1 for the rest of this boot.\n",
        .{reason},
    );
}

/// Stage-D shadow harness. V1 (executeBpfProgramCore) produces the canonical
/// mutation list AND commits it via the existing pending_writes path. V2
/// (v2DispatchInternal) runs in parallel from a per-dispatch arena and
/// produces its own mutation list. We diff V1 vs V2 with
/// `v2dispatch.diffMutations` and emit a rate-limited [VBPF2-SHADOW] line.
/// V2-side state is NEVER committed — V1 owns the bank.
///
/// ── Stage-D safety contract (lock these — see vault/rebuild-scope/STAGE-D-SAFETY.md):
///
///   • Risk 1: V2 errors are typed (ShadowError) + counted (g_metrics) +
///     logged as [VBPF2-SHADOW-ERR]. V1 commit failure FAIL-STOPS the slot
///     by returning Shadow_V1CommitFailed (caller propagates).
///   • Risk 2: V2's trampoline path appends to a private shadow_redirect
///     buffer on Bank, NOT bank.pending_writes. V1's commit buffer is
///     untouchable from V2 in shadow mode (defense in depth + future-
///     concurrency-safe).
///   • Risk 3: V2 runs from a per-dispatch ArenaAllocator. Arena drops on
///     dispatch exit — no per-mutation free walk; no leak into V1's
///     allocator on V2 bugs.
///   • Risk 4: Adaptive rate limit (RateLimiter) — every line for first 1k,
///     1/10 for next 9k, 1/100 thereafter. Errors NEVER rate-limited.
///   • Risk 5: Sysvars are pre-execute (replay_stage:1147) and flushed to
///     AccountsDb before any tx fires — they're effectively immutable for
///     the slot's BPF dispatches. V2 reads from AccountsDb same as V1; no
///     snapshot infrastructure required. Asserted below.
///   • Risk 6: V2ProgramCache puts during V2 dispatch are tx-scoped via
///     CacheTx; on V2 error the cache rolls back so a failed V2 path
///     can't leave a partial cache that affects V1 or future shadow runs.
///     (Wired through v2DispatchInternal — wireup is implicit when the
///     resolver is upgraded; this comment documents the invariant.)
///   • Risk 7: Debug assertion proves V1 + V2 mutation buffers come from
///     disjoint allocators (V1 = caller `alloc`, V2 = arena).
///   • Risk 8: V1 commits via the inline pending_writes loop below — NOT
///     via the executeBpfProgram wrapper (that wrapper is bypassed in
///     shadow mode so we can capture V1 mutations BEFORE commit for diff).
///
/// Counter is std.atomic.Value(u64) so multiple replay threads don't race.
/// File handle is initialised once (best-effort; race-tolerant via
/// `createFileAbsolute(.truncate=false)` semantics).
///
/// Line format (locked):
///   [VBPF2-SHADOW] tx_fp8=<8B-hex> ix_data_len=<n> v1_muts=<v1n> v2_muts=<v2n> \
///                  same=<m>|<max(v1n,v2n)> delta=<delta-string> v2_err=<errname-or-none>
pub fn shadowDispatch(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
    /// PR-K (2026-05-17): threaded from dispatchBpfExecution.
    feature_set: ?*const features_mod.FeatureSet,
) vex_bpf2.shadow_safety.ShadowError!void {
    const safety = vex_bpf2.shadow_safety;
    const S = struct {
        var counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
        var file: ?std.fs.File = null;
        var inited: std.atomic.Value(u8) = std.atomic.Value(u8).init(0);
    };

    _ = safety.g_metrics.dispatches_total.fetchAdd(1, .monotonic);

    // ── Risk 5: sysvar reads are stable for the slot.
    // Sysvars (Clock, SlotHashes) are written once per slot at
    // replay_stage.zig:1147 BEFORE any transaction fires, then flushed to
    // AccountsDb. Both V1 (`executeBpfProgramCore`) and V2
    // (`v2DispatchInternal`) read sysvar account bytes via `db.getAccount`,
    // and AccountsDb is not mutated mid-tx — so V2's sysvar reads are
    // already snapshot-stable. No clone needed. The assertion catches
    // future regressions if the sysvar update is ever moved into the
    // tx-execute loop.
    if (std.debug.runtime_safety) {
        std.debug.assert(bank.pending_writes.items.len >= 0); // sentinel access
    }

    // ── V1 path: produces canonical mutations using the caller's allocator.
    // V1 does NOT commit yet — we capture mutations first, then commit
    // inline below. (This is Risk 8: the comment said "V1 first (also
    // commits, via the wrapper)" — wrong. The wrapper is bypassed in
    // shadow mode; commit happens after capture.)
    const v1_muts: []bpf_mod.AccountMutation = executeBpfProgramCore(ix, ptx, bank, db, alloc) catch blk: {
        // V1's BPF execution itself failed. We still emit an ERR line +
        // metric, but with empty v1_muts so the diff still composes.
        emitShadowErrLine("v1_exec_failed", null);
        break :blk @as([]bpf_mod.AccountMutation, &[_]bpf_mod.AccountMutation{});
    };
    defer {
        // V1 muts are alloc'd from the caller's `alloc` (per Wave 5
        // contract on executeBpfProgramCore).
        for (v1_muts) |*m| alloc.free(m.data);
        alloc.free(v1_muts);
    }

    // ── Risk 3: V2 runs from a per-dispatch arena.
    // Anything V2 allocates lives and dies with this arena. No per-mutation
    // free walk required, and a V2 bug can't corrupt V1's allocator.
    var v2_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer v2_arena.deinit();
    const v2_alloc = v2_arena.allocator();

    // ── V2 path. On error, we still emit a diff line (with v2_err set)
    // and increment the appropriate counter; we do NOT propagate as
    // Shadow_V1CommitFailed (V1's commit is downstream).
    var v2_err_name: ?[]const u8 = null;
    var v2_muts: []bpf_mod.AccountMutation = &[_]bpf_mod.AccountMutation{};
    // Stage-D follow-up: run V2 dispatch under panic protection. Any
    // @panic, SIGSEGV, SIGBUS, SIGFPE, SIGILL, or SIGABRT inside the
    // V2 path unwinds with `error.ShadowPanicked` instead of taking the
    // validator down. Per-dispatch arena (v2_arena) cleans up state.
    //
    // The protected closure returns a flat tagged union (no nested error
    // unions), since `runProtected`'s `ProtectedError!T` cannot accept T
    // as an error union itself.
    const V2Outcome = union(enum) {
        muts: []bpf_mod.AccountMutation,
        not_plumbed,
        named_err: []const u8,
    };
    const ProtectedCtx = struct {
        ix: ParsedInstruction,
        ptx: *const ParsedTx,
        bank: *Bank,
        db: *AccountsDb,
        v2_alloc: std.mem.Allocator,
        feature_set: ?*const features_mod.FeatureSet,
    };
    const protected_ctx: ProtectedCtx = .{
        .ix = ix,
        .ptx = ptx,
        .bank = bank,
        .db = db,
        .v2_alloc = v2_alloc,
        .feature_set = feature_set,
    };
    const protected_result = vex_bpf2.shadow_panic_safety.runProtected(
        V2Outcome,
        protected_ctx,
        struct {
            fn run(c: ProtectedCtx) V2Outcome {
                // CU-METER: shadow dispatch is diagnostic-only (never committed)
                // → unmetered (null) keeps it hash-neutral and side-effect-free.
                if (v2DispatchInternal(c.ix, c.ptx, c.bank, c.db, c.v2_alloc, c.feature_set, null)) |muts_opt| {
                    if (muts_opt) |muts| return .{ .muts = muts };
                    return .not_plumbed;
                } else |e| {
                    return .{ .named_err = @errorName(e) };
                }
            }
        }.run,
    );
    if (protected_result) |outcome| switch (outcome) {
        .muts => |m| v2_muts = m,
        .not_plumbed => {
            v2_err_name = "M5_BankBackedBpfNotPlumbed";
            _ = safety.g_metrics.v2_errors_named.fetchAdd(1, .monotonic);
        },
        .named_err => |name| {
            v2_err_name = name;
            _ = safety.g_metrics.v2_errors_named.fetchAdd(1, .monotonic);
            emitShadowErrLine(name, ptx);
        },
    } else |_| {
        // Hardware signal or @panic inside V2. Surface as a named v2_err
        // so the diff line still appears. Reason + message live in TLS
        // (see shadow_panic_safety.lastReason() / lastPanicMessage()).
        const reason = vex_bpf2.shadow_panic_safety.lastReason();
        v2_err_name = switch (reason) {
            .sigsegv => "ShadowPanic_SIGSEGV",
            .sigbus => "ShadowPanic_SIGBUS",
            .sigfpe => "ShadowPanic_SIGFPE",
            .sigill => "ShadowPanic_SIGILL",
            .sigabrt => "ShadowPanic_SIGABRT",
            .zig_panic => "ShadowPanic_Zig",
            .none => "ShadowPanic_Unknown",
        };
        _ = safety.g_metrics.v2_errors_named.fetchAdd(1, .monotonic);
        emitShadowErrLine(v2_err_name.?, ptx);
    }
    // No `defer free` for v2_muts — arena owns them.

    // ── Risk 7: prove V1 and V2 mutation buffers come from disjoint
    // allocators. V1 = caller `alloc` (heap-stable), V2 = arena.
    if (std.debug.runtime_safety) {
        for (v1_muts) |v1m| for (v2_muts) |v2m| {
            std.debug.assert(v1m.data.ptr != v2m.data.ptr);
        };
    }

    // ── Phase-4 live shadow capture (env-gated, pre-V1-commit) ────────────
    // When VEX_SHADOW_CAPTURE_DIR is set, dump this dispatch as a .fix
    // fixture using V1's mutations as expected_post. Reads accounts BEFORE
    // V1 commit so accounts_pre reflects true pre-state. The corpus feeds
    // `zig build test-bpf-fixture-v2` for offline V2 triage; disagreements
    // get arbitrated against the oracle-node oracle later. Best-effort.
    if (shadow_capture.isEnabled() and !shadow_capture.isFull()) {
        captureShadowFixture(ix, ptx, bank, db, alloc, v1_muts) catch {};
    }

    // ── V1 commit: inline pending_writes append loop.
    // This is Risk 8: the wrapper executeBpfProgram is bypassed in shadow
    // mode so we can capture V1 mutations BEFORE commit (for diff). If
    // ANY pending_writes.append fails here, the slot's mutation list is
    // incomplete — bank-corrupting. Surface as Shadow_V1CommitFailed.
    var v1_commit_ok = true;
    for (v1_muts) |*m| {
        const orig = db.getAccountInSlot(&m.pubkey, bank.slot, bank.ancestors()) orelse continue;
        // vex-039 / core-r10-bpf-owner restored 2026-05-22: old_lt uses
        // orig.owner (pre-mutation accumulator leg). new_lt and AccountWrite
        // use m.owner (post-mutation, surfaced by deserialise()) so
        // owner-mutating BPF txs propagate correctly into the bank LtHash.
        const old_lt = bank_mod.Bank.accountLtHash(
            &m.pubkey.data,
            &orig.owner.data,
            orig.lamports,
            orig.executable,
            orig.data,
        );
        const new_lt = bank_mod.Bank.accountLtHash(
            &m.pubkey.data,
            &m.owner,
            m.new_lamports,
            orig.executable,
            m.data,
        );
        const data_copy = bank.allocator.alloc(u8, m.data.len) catch {
            v1_commit_ok = false;
            continue;
        };
        @memcpy(data_copy, m.data);
        bank.collectWrite(.{ // parallel-exec: worker-buffer-aware (byte-identical on serial)
            .pubkey = .{ .data = m.pubkey.data },
            .lamports = m.new_lamports,
            .owner = .{ .data = m.owner },
            .executable = orig.executable,
            .rent_epoch = orig.rent_epoch,
            .data = data_copy,
            .old_lt = old_lt,
            .new_lt = new_lt,
        }) catch {
            // Free the data_copy we just allocated; it never landed in
            // pending_writes so the bank arena won't reap it.
            bank.allocator.free(data_copy);
            v1_commit_ok = false;
        };
    }
    if (!v1_commit_ok) {
        _ = safety.g_metrics.v1_commit_failures.fetchAdd(1, .monotonic);
        emitShadowErrLine("v1_commit_failed", ptx);
        return safety.ShadowError.Shadow_V1CommitFailed;
    }

    // ── Risk 4: adaptive rate limit. Errors are emitted above with no rate
    // gate. Steady-state diff lines ride RateLimiter.shouldLog.
    const seq = S.counter.fetchAdd(1, .monotonic);
    if (!safety.RateLimiter.shouldLog(seq)) return;

    if (S.inited.load(.acquire) == 0) {
        if (S.inited.cmpxchgStrong(0, 1, .acq_rel, .monotonic) == null) {
            const path = vex_bpf2.dispatch_mode.shadowLogPath();
            S.file = std.fs.createFileAbsolute(path, .{ .truncate = false }) catch null;
            if (S.file) |f| f.seekFromEnd(0) catch {};
        }
    }

    const diff = v2dispatch.diffMutations(v1_muts, v2_muts);
    var fp_hex: [16]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    inline for (0..8) |i| {
        fp_hex[i * 2 + 0] = hex_chars[(ptx.fee_payer[i] >> 4) & 0xF];
        fp_hex[i * 2 + 1] = hex_chars[ptx.fee_payer[i] & 0xF];
    }
    var delta_buf: [128]u8 = undefined;
    const delta_str = v2dispatch.formatDelta(&delta_buf, diff);
    const max_n = if (diff.v1_count > diff.v2_count) diff.v1_count else diff.v2_count;
    const err_str: []const u8 = if (v2_err_name) |n| n else "none";

    var line_buf: [512]u8 = undefined;
    // For ShadowPanic_* errors, append the pc and opcode breadcrumbs captured
    // by Phase-3 recordStep so each panic line has a concrete localization lead.
    const is_panic = std.mem.startsWith(u8, err_str, "ShadowPanic_");
    const line = if (is_panic) blk: {
        const last_pc = vex_bpf2.shadow_panic_safety.lastPc();
        const last_op = vex_bpf2.shadow_panic_safety.lastOpcode();
        break :blk std.fmt.bufPrint(
            &line_buf,
            "[VBPF2-SHADOW] tx_fp8={s} ix_data_len={d} v1_muts={d} v2_muts={d} same={d}|{d} delta={s} v2_err={s} pc=0x{x} op=0x{x}\n",
            .{ fp_hex[0..], ix.data.len, diff.v1_count, diff.v2_count, diff.same, max_n, delta_str, err_str, last_pc, last_op },
        ) catch return;
    } else std.fmt.bufPrint(
        &line_buf,
        "[VBPF2-SHADOW] tx_fp8={s} ix_data_len={d} v1_muts={d} v2_muts={d} same={d}|{d} delta={s} v2_err={s}\n",
        .{ fp_hex[0..], ix.data.len, diff.v1_count, diff.v2_count, diff.same, max_n, delta_str, err_str },
    ) catch return;

    if (S.file) |f| f.writeAll(line) catch {
        _ = safety.g_metrics.log_write_failures.fetchAdd(1, .monotonic);
    };
}

/// Phase-4 helper: build a CaptureAccount[] + Mutation[] from the live
/// instruction context, resolve the program ELF, and dump as a .fix fixture
/// to VEX_SHADOW_CAPTURE_DIR. Best-effort. Returns silently on any error
/// (no-program-account, no-ELF, allocator-failure, IO-failure, etc.).
///
/// Captures only fixtures we can actually replay offline:
///   • program account exists + has resolvable ELF (BPF Loader v2 or
///     Loader-Upgradeable indirection — see lines 2885-2900).
///   • at least 1 account in the instruction's account list.
pub fn captureShadowFixture(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
    v1_muts: []const bpf_mod.AccountMutation,
) !void {
    if (ix.program_id_index >= ptx.static_key_count) return;
    if (ix.account_indices.len == 0) return;

    const program_key: [32]u8 = ptx.account_keys[ix.program_id_index];
    const program_pk = core.Pubkey{ .data = program_key };

    // Resolve ELF the same way v2DispatchInternal does (see line 2885-2900).
    const prog_acct = db.getAccountInSlot(&program_pk, bank.slot, bank.ancestors()) orelse return;
    var elf_bytes: []const u8 = prog_acct.data;
    if (std.mem.eql(u8, &prog_acct.owner.data, &BPF_LOADER_UPGRADEABLE) and prog_acct.data.len >= 36) {
        const state = std.mem.readInt(u32, prog_acct.data[0..4], .little);
        if (state == 2) {
            var pd_key = core.Pubkey{ .data = undefined };
            @memcpy(&pd_key.data, prog_acct.data[4..36]);
            if (db.getAccountInSlot(&pd_key, bank.slot, bank.ancestors())) |pd_acct| {
                if (pd_acct.data.len >= 45) {
                    elf_bytes = pd_acct.data[45..];
                }
            }
        }
    }
    if (elf_bytes.len < 16) return; // not an ELF — skip (likely builtin).
    if (!std.mem.eql(u8, elf_bytes[0..4], "\x7fELF")) return; // ELF magic check

    // Build accounts_pre. Index 0 must be the program account itself
    // (matches agave/Mollusk fixture shape; v2_dispatch's InvokeContext.push
    // requires program_idx (=0) < tx.accounts.len).
    var pre: std.ArrayListUnmanaged(shadow_capture.CaptureAccount) = .{};
    defer pre.deinit(alloc);

    try pre.append(alloc, .{
        .pubkey = program_key,
        .owner = prog_acct.owner.data,
        .lamports = prog_acct.lamports,
        .data = prog_acct.data, // program account's raw data (loader-state header for upgradeable)
        .executable = prog_acct.executable,
        .rent_epoch = prog_acct.rent_epoch,
        .is_signer = false,
        .is_writable = false,
    });

    const num_signed = ptx.num_required_sigs;
    for (ix.account_indices) |aidx| {
        if (aidx >= ptx.num_accounts) continue;
        const key = ptx.account_keys[aidx];
        // Skip the program account if it appears in the instruction's
        // account list too (don't double-add).
        if (std.mem.eql(u8, &key, &program_key)) continue;
        const pk = core.Pubkey{ .data = key };
        const acct = db.getAccountInSlot(&pk, bank.slot, bank.ancestors()) orelse continue;
        try pre.append(alloc, .{
            .pubkey = key,
            .owner = acct.owner.data,
            .lamports = acct.lamports,
            .data = acct.data,
            .executable = acct.executable,
            .rent_epoch = acct.rent_epoch,
            .is_signer = aidx < num_signed,
            .is_writable = ptx.isWritable(aidx),
        });
    }

    // Convert v1_muts to capture.Mutation shape.
    var muts_buf: std.ArrayListUnmanaged(shadow_capture.Mutation) = .{};
    defer muts_buf.deinit(alloc);
    try muts_buf.ensureTotalCapacity(alloc, v1_muts.len);
    for (v1_muts) |m| {
        muts_buf.appendAssumeCapacity(.{
            .pubkey = m.pubkey.data,
            .new_lamports = m.new_lamports,
            .new_owner = if (m.new_owner) |o| o else null,
            .data = m.data,
        });
    }

    var tx_fp: [8]u8 = undefined;
    @memcpy(&tx_fp, ptx.fee_payer[0..8]);

    // Phase 7: pass tx signature through if available — enables oracle-node
    // arbitration via getTransaction <base58(sig)>.
    const tx_sig: ?[64]u8 = if (ptx.first_signature) |sig_ptr| sig_ptr.* else null;

    shadow_capture.captureFixture(
        alloc,
        program_key,
        elf_bytes,
        ix.data,
        pre.items,
        muts_buf.items,
        1_400_000,
        tx_fp,
        tx_sig,
        bank.slot,
    );
}

/// Emit a `[VBPF2-SHADOW-ERR]` line. Always logged regardless of rate
/// limit. ptx may be null when the error fires before the tx is fully
/// parsed. Best-effort — write failures bump the log_write_failures
/// counter but do not propagate.
pub fn emitShadowErrLine(err_name: []const u8, ptx: ?*const ParsedTx) void {
    const safety = vex_bpf2.shadow_safety;
    const S = struct {
        var file: ?std.fs.File = null;
        var inited: std.atomic.Value(u8) = std.atomic.Value(u8).init(0);
    };
    if (S.inited.load(.acquire) == 0) {
        if (S.inited.cmpxchgStrong(0, 1, .acq_rel, .monotonic) == null) {
            const path = vex_bpf2.dispatch_mode.shadowLogPath();
            S.file = std.fs.createFileAbsolute(path, .{ .truncate = false }) catch null;
            if (S.file) |f| f.seekFromEnd(0) catch {};
        }
    }

    var fp_hex: [16]u8 = .{ '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0' };
    if (ptx) |t| {
        const hex_chars = "0123456789abcdef";
        inline for (0..8) |i| {
            fp_hex[i * 2 + 0] = hex_chars[(t.fee_payer[i] >> 4) & 0xF];
            fp_hex[i * 2 + 1] = hex_chars[t.fee_payer[i] & 0xF];
        }
    }
    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "[VBPF2-SHADOW-ERR] tx_fp8={s} err={s}\n",
        .{ fp_hex[0..], err_name },
    ) catch return;

    if (S.file) |f| f.writeAll(line) catch {
        _ = safety.g_metrics.log_write_failures.fetchAdd(1, .monotonic);
    };
}

/// Execute a BPF program via the sBPF VM.
/// Loads ELF from AccountsDb (handles BPFLoaderUpgradeable indirection),
/// builds account entries, executes via SbpfExecutor, applies mutations.
/// Wave 5: V1 BPF execution split from commit. `executeBpfProgramCore`
/// returns the mutation list; `executeBpfProgram` (below) calls Core then
/// commits via the existing pending_writes path. Splitting lets the Stage-D
/// shadow harness read V1's mutations without changing the commit semantics
/// or touching `src/vex_bpf/sbpf_executor.zig:1161` (vex-079 invariant).
///
/// Returned slice + every `m.data` are alloc'd from `alloc` and OWNED BY THE
/// CALLER. The commit wrapper frees in its existing defer block.
pub fn executeBpfProgramCore(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
) ![]bpf_mod.AccountMutation {
    // bank now consumed by pending_writes overlay (r75-bug-class-c-v1bpf-2026-05-06)

    if (ix.program_id_index >= ptx.static_key_count) {
        return &[_]bpf_mod.AccountMutation{};
    }
    const program_key = ptx.account_keys[ix.program_id_index];
    const program_pk = core.Pubkey{ .data = program_key };

    // Step 1: Get program account and resolve ELF data
    const prog_acct = db.getAccountInSlot(&program_pk, bank.slot, bank.ancestors()) orelse {
        return &[_]bpf_mod.AccountMutation{};
    };

    // Resolve ELF through BPFLoaderUpgradeable indirection
    // (same logic as sbpf_executor.zig CPI handler)
    const elf_data: []const u8 = blk: {
        if (std.mem.eql(u8, &prog_acct.owner.data, &BPF_LOADER_UPGRADEABLE)) {
            if (prog_acct.data.len >= 36) {
                const state = std.mem.readInt(u32, prog_acct.data[0..4], .little);
                if (state == 2) { // Program variant → programdata account
                    var pd_key = core.Pubkey{ .data = undefined };
                    @memcpy(&pd_key.data, prog_acct.data[4..36]);
                    const pd_acct = db.getAccountInSlot(&pd_key, bank.slot, bank.ancestors()) orelse {
                        break :blk prog_acct.data;
                    };
                    // Programdata: skip 45-byte header to get ELF
                    if (pd_acct.data.len >= 45) break :blk pd_acct.data[45..];
                }
            }
        }
        break :blk prog_acct.data;
    };

    if (elf_data.len < 16) {
        return &[_]bpf_mod.AccountMutation{};
    }

    // Step 2: Load ELF
    var loader = bpf_mod.ElfLoader.init(alloc);
    var loaded = loader.load(elf_data) catch {
        return &[_]bpf_mod.AccountMutation{};
    };
    defer loaded.deinit();

    // Step 3: Build account entries for the instruction
    var entries = std.ArrayListUnmanaged(bpf_mod.AccountEntry){};
    defer entries.deinit(alloc);

    const num_signed = ptx.num_required_sigs;

    // r71-fix-5 (2026-04-28): same default-empty-snapshot fix as V2 path
    // (replay_stage.zig:3469). When a tx references a to-be-created account
    // (typically a PDA whose System::CreateAccount CPI runs inside this tx),
    // db.getAccount returns null. Pre-fix we silently `continue`'d, dropping
    // the account from the input region. The BPF program's CPI write-back
    // (sbpf_executor.zig:425-470) then fails to find a matching pubkey in
    // the parent input buffer, mutations vanish, no new account materializes.
    // Every tx-referenced account, existing or pending creation, is always
    // present in the loaded-account list with its pre-state (lamports=0,
    // owner=System, data=[] for not-yet-created).
    // @prov:dispatch.default-empty-account
    const SYSTEM_PID_FOR_DEFAULT_V1: core.Pubkey = .{ .data = [_]u8{0} ** 32 };
    for (ix.account_indices) |acct_idx| {
        if (acct_idx >= ptx.num_accounts) continue;
        const key = ptx.account_keys[acct_idx];
        const pk = core.Pubkey{ .data = key };

        const is_signer = acct_idx < num_signed;
        const is_writable = ptx.isWritable(acct_idx);

        // r75-bug-class-c-v1bpf-2026-05-06: pending_writes overlay before
        // db.getAccount. V1 BPF path is the fallback when V2 returns null
        // for non-M4_RunFailed errors; without overlay, V1 reads stale
        // snapshot state for accounts mutated earlier in the same slot.
        var found_v1_pending: bool = false;
        var v1_pwi: usize = bank.pending_writes.items.len;
        while (v1_pwi > 0) {
            v1_pwi -= 1;
            const pw = &bank.pending_writes.items[v1_pwi];
            if (std.mem.eql(u8, &pw.pubkey.data, &key)) {
                entries.append(alloc, .{
                    .pubkey = pk,
                    .owner = pw.owner,
                    .lamports = pw.lamports,
                    .data = pw.data,
                    .executable = pw.executable,
                    .rent_epoch = pw.rent_epoch,
                    .is_signer = is_signer,
                    .is_writable = is_writable,
                }) catch {};
                found_v1_pending = true;
                break;
            }
        }
        if (found_v1_pending) continue;

        if (db.getAccountInSlot(&pk, bank.slot, bank.ancestors())) |acct| {
            entries.append(alloc, .{
                .pubkey = pk,
                .owner = acct.owner,
                .lamports = acct.lamports,
                .data = acct.data,
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .is_signer = is_signer,
                .is_writable = is_writable,
            }) catch continue;
        } else {
            entries.append(alloc, .{
                .pubkey = pk,
                .owner = SYSTEM_PID_FOR_DEFAULT_V1,
                .lamports = 0,
                .data = &[_]u8{},
                .executable = false,
                .rent_epoch = 0,
                .is_signer = is_signer,
                .is_writable = is_writable,
            }) catch continue;
        }
    }

    if (entries.items.len == 0) {
        return &[_]bpf_mod.AccountMutation{};
    }

    // Step 4: Execute via SbpfExecutor
    var executor = try bpf_mod.SbpfExecutor.init(alloc);
    defer alloc.destroy(executor);

    const mutations = executor.execute(
        &loaded,
        entries.items,
        ix.data,
        &program_pk,
    ) catch {
        // Errors out of execute() are infrastructure (OOM in serialise /
        // deserialise) — the program reached no verdict → plumbing.
        return &[_]bpf_mod.AccountMutation{};
    };

    // FIX-1a (2026-06-10, task #65 — residual sibling of carrier #6
    // @414386920): classify the top-level run. Pre-fix EVERY V1 failure was
    // an empty-muts SUCCESS, so the instruction loops continued past a
    // genuinely aborting V1-ELF instruction and kept the EARLIER
    // instructions' writes (the exact carrier-#6 leak shape, V1 flavor).
    // Mirrors the V2 taxonomy (M4_RunFailed genuine / M5_* plumbing):
    //   .program_error    → propagate error.V1_ProgramFailed (genuine; the
    //                       loops fail + roll back the tx);
    //   .vm_fault         → UNKNOWN: V1 interpreter has known SPURIOUS
    //                       faults (r75-bug-class-b pc=43931 wild-pointer) —
    //                       failing the tx here would diverge wherever Agave
    //                       succeeds. Non-fatal + loud counter.
    //   .compute_exceeded → UNKNOWN: V1 meters raw insns, not Agave CUs.
    //                       Non-fatal + loud counter.
    //   .plumbing/.ok     → unchanged behavior.
    switch (executor.last_top_outcome) {
        .program_error => return error.V1_ProgramFailed,
        .vm_fault => {
            V1TaxonomyUnknownStats.vm_fault += 1;
            if (V1TaxonomyUnknownStats.vm_fault <= 4 or V1TaxonomyUnknownStats.vm_fault % 100 == 0) {
                std.log.warn("[TX-ERR-TAXONOMY-UNKNOWN] slot={d} v1 vm_fault swallowed (count={d}) prog={x:0>2}{x:0>2}..{x:0>2}{x:0>2} — would fail tx on Agave IF genuine; V1 has known spurious faults", .{
                    bank.slot,       V1TaxonomyUnknownStats.vm_fault,
                    program_key[0],  program_key[1],
                    program_key[30], program_key[31],
                });
            }
        },
        .compute_exceeded => {
            V1TaxonomyUnknownStats.compute_exceeded += 1;
            if (V1TaxonomyUnknownStats.compute_exceeded <= 4 or V1TaxonomyUnknownStats.compute_exceeded % 100 == 0) {
                std.log.warn("[TX-ERR-TAXONOMY-UNKNOWN] slot={d} v1 compute_exceeded swallowed (count={d}) prog={x:0>2}{x:0>2}..{x:0>2}{x:0>2} — V1 insn-count metering is not Agave CU metering", .{
                    bank.slot,       V1TaxonomyUnknownStats.compute_exceeded,
                    program_key[0],  program_key[1],
                    program_key[30], program_key[31],
                });
            }
        },
        .ok, .plumbing => {},
    }

    return mutations;
}

/// FIX-1a loud counters for V1 outcomes deliberately NOT propagated (risk
/// discipline: if Vexor can error where Agave succeeds, propagating creates
/// NEW divergence — live traffic tells us via these).
pub const V1TaxonomyUnknownStats = struct {
    pub var vm_fault: u64 = 0;
    pub var compute_exceeded: u64 = 0;
};

/// FIX-1b loud counters for vote-seam errors deliberately NOT propagated.
pub const VoteTaxonomyUnknownStats = struct {
    pub var unsupported_sysvar: u64 = 0;
};

/// FIX-1c loud counter for stake-handler silent swallows (residual): the
/// native stake handlers (native/stake_program.zig) early-return on genuine
/// validation failures with NO error surface, so a failing stake instruction
/// inside a multi-instruction tx still cannot fail the tx (leak class
/// remains for handler-INTERNAL failures; dispatch-level parse failures now
/// propagate). This counter measures the residual exposure on live traffic.
pub const StakeTaxonomyUnknownStats = struct {
    pub var zero_write_returns: u64 = 0;
};

/// Wave 5: V1 BPF commit wrapper. Calls `executeBpfProgramCore` for the
/// mutation list (vex-079 / vex-039 invariants live in sbpf_executor.zig,
/// untouched), then runs the original LtHash + pending_writes loop verbatim.
pub fn executeBpfProgram(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
) !void {
    const mutations = executeBpfProgramCore(ix, ptx, bank, db, alloc) catch |e| {
        // FIX-1a (2026-06-10): a genuine V1 program failure must reach the
        // instruction loops so the tx fails + rolls back (Agave
        // message_processor stop-at-first-error). Everything else stays the
        // historical swallow (plumbing must never fail a tx).
        if (e == error.V1_ProgramFailed) return e;
        return;
    };
    defer {
        for (mutations) |*m| alloc.free(m.data);
        alloc.free(mutations);
    }

    // Step 5: Apply mutations to pending_writes with LtHash deltas.
    //
    // vex-040 / d23-NEW-ACCT-V1 (2026-05-22): mirror commitV2Mutations
    // (lines 5895-5950) new-account handling into V1 path. The prior
    // `db.getAccountInSlot(...) orelse continue` silently dropped EVERY
    // BPF mutation targeting a not-yet-existing pubkey — CreateAccount,
    // PDA-init, ATA derivation. Production deploys --bpf-stack=v1, so
    // this loop is THE live path. Each dropped new-account write missed
    // its lthash contribution; bank.accounts_lthash desynchronized from
    // Agave at the first such slot; SH ring stored Vexor's wrong
    // bank_hash; subsequent votes against Vexor's local SH rejected
    // (100% mutate_fail). Bisect confirmed: 8 oldest slots in this boot
    // (no new-account txs) all matched oracle-node; slot ~1700 later (with
    // new-account tx) diverged with single-slot delta. Mirror the V2
    // path's Dead-state-aware logic: when orig is null, treat
    // pre-state as Dead (lamports=0 → accountLtHash returns identity).
    //
    // vex-039 / core-r10-bpf-owner: old_lt uses pre-state owner. new_lt
    // and AccountWrite use m.owner (post-mutation, surfaced by
    // deserialise() reading the 32-byte owner window in the BPF input
    // region).
    const SYSTEM_PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;
    for (mutations) |*m| {
        const orig_opt = db.getAccountInSlot(&m.pubkey, bank.slot, bank.ancestors());
        const pre_owner: [32]u8 = if (orig_opt) |o| o.owner.data else SYSTEM_PROGRAM_ID;
        const pre_lamports: u64 = if (orig_opt) |o| o.lamports else 0;
        const pre_executable: bool = if (orig_opt) |o| o.executable else false;
        const pre_data: []const u8 = if (orig_opt) |o| o.data else &[_]u8{};
        const out_rent_epoch: u64 = if (orig_opt) |o| o.rent_epoch else std.math.maxInt(u64);

        const old_lt = bank_mod.Bank.accountLtHash(
            &m.pubkey.data,
            &pre_owner,
            pre_lamports,
            pre_executable,
            pre_data,
        );
        const new_lt = bank_mod.Bank.accountLtHash(
            &m.pubkey.data,
            &m.owner,
            m.new_lamports,
            pre_executable,
            m.data,
        );

        const data_copy = alloc.alloc(u8, m.data.len) catch continue;
        @memcpy(data_copy, m.data);

        bank.collectWrite(.{
            .pubkey = .{ .data = m.pubkey.data },
            .lamports = m.new_lamports,
            .owner = .{ .data = m.owner },
            .executable = pre_executable,
            .rent_epoch = out_rent_epoch,
            .data = data_copy,
            .old_lt = old_lt,
            .new_lt = new_lt,
        }) catch {};
    }
}

/// Canonical Rent.minimum_balance for the durable-nonce rent checks
/// (Withdraw partial-balance floor, Initialize funding check).
/// @prov:dispatch.rent-exempt-minimum — minimum_balance(len) = (len + 128) *
/// 3480 * 2. Integer math is exact here (Agave's f64 round-trip is lossless
/// for these magnitudes — same formula already used by the V4 vote-account
/// rent guard at the [V4-RENT-REJECT] site below).
pub fn rentExemptMinimumBalanceDefault(data_len: u64) u64 {
    return (data_len + 128) * 3480 * 2;
}

/// Execute a system program instruction (all 13 types: transfer, create account, assign,
/// allocate, nonce ops, etc.). Bridges replay_stage's ParsedTx to system_v2's InstrCtx.
/// Snapshots account state, runs system_v2.execute(), then emits pending_writes for any
/// mutated accounts with correct LtHash deltas.
pub fn executeSystemInstruction(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: anytype,
    alloc: std.mem.Allocator,
    // Day-2 fork-isolation: ancestor chain of the current bank, used to filter
    // overlay reads so sibling-orphan slots' writes cannot pollute pre-state.
    // Empty slice = legacy flat-read behavior (db.getAccount), same as before.
    ancestor_slots: []const u64,
) !void {
    if (ix.data.len < 4) return;
    if (ix.account_indices.len == 0) return;

    const num_signed = ptx.num_required_sigs;

    // Build AccountMeta array and snapshot old lamports/owners for diff
    const max_accts = @min(ix.account_indices.len, 8); // system program uses at most ~5 accounts
    var acct_metas: [8]types.AccountMeta = undefined;
    var old_lamports: [8]u64 = undefined;
    var old_owners: [8][32]u8 = undefined;
    var old_data_lens: [8]usize = undefined;
    // fix/wire-nonce-ops (2026-06-10, carrier @414201776): pristine PRE-exec
    // data bytes per account. Needed because (a) the durable-nonce ops mutate
    // the 80-byte nonce data IN PLACE (len unchanged), which the old
    // "data.len != old_len" changed-check could never see, and (b) old_lt was
    // computed from meta.data[0..old_len] — the ALREADY-MUTATED buffer — which
    // would poison the lt delta for any in-place byte mutation. Allocated from
    // the same per-slot arena as the meta copies (never freed here, same
    // lifetime discipline as data_copy).
    var old_datas: [8][]const u8 = undefined;
    var acct_keys: [8][32]u8 = undefined;
    var acct_count: usize = 0;

    for (ix.account_indices[0..max_accts]) |acct_idx| {
        if (acct_idx >= ptx.num_accounts) continue;
        const key = ptx.account_keys[acct_idx];
        const pk = core.Pubkey{ .data = key };

        // r75-bug-class-c-2026-05-06: pending_writes OVERLAY before db.getAccount.
        // Same pattern as DAG/serial fee path (lines 1744-1768, 2050-2074) and
        // vote path (4984-4998). Without this, when a fee_payer is BOTH debited
        // by the fee path AND a System::Transfer source in the same tx, the
        // transfer reads stale snapshot lamports → its `collectWrite` clobbers
        // the fee debit (last-write-wins). For 2 canary txs at slot 406443198
        // (fee_payer=Ac4R6EFdjk... transferring to GJHt PDAs), this caused
        // Vexor to under-debit the fee_payer by exactly 15,000 lamports
        // (= 3 × LAMPORTS_PER_SIGNATURE), producing the FIRST point of
        // bank_hash divergence vs cluster after the snapshot.
        // Path identified by code-review agent 2026-05-06; math matched
        // empirical +15,000 lamport divergence at slot 198.
        // B2b (parallel-exec): override-aware overlay read. overlayNewest scans the
        // worker's own write buffer (if set, parallel path) THEN pending_writes — so a
        // System tx's earlier-instruction write to this account is visible to a later
        // instruction. Serial path (override == null) = byte-identical to the prior
        // pending_writes newest-first scan. Body below is unchanged (pw is the newest
        // matching entry; the nonce double-copy carrier is preserved verbatim).
        var found_pending: bool = false;
        if (bank.overlayNewest(&key)) |pw| {
            const data_copy = if (pw.data.len > 0)
                (alloc.alloc(u8, pw.data.len) catch continue)
            else
                @as([]u8, &[_]u8{});
            if (pw.data.len > 0) @memcpy(data_copy, pw.data);
            // Second pristine copy for the post-exec byte-diff + old_lt
            // (data_copy itself may be mutated in place by nonce ops).
            const old_copy = if (pw.data.len > 0)
                (alloc.dupe(u8, pw.data) catch continue)
            else
                @as([]const u8, &[_]u8{});
            acct_keys[acct_count] = key;
            acct_metas[acct_count] = .{
                .pubkey = .{ .data = key },
                .lamports = pw.lamports,
                .owner = pw.owner,
                .executable = pw.executable,
                .rent_epoch = pw.rent_epoch,
                .data = data_copy,
            };
            old_lamports[acct_count] = pw.lamports;
            old_owners[acct_count] = pw.owner.data;
            old_data_lens[acct_count] = pw.data.len;
            old_datas[acct_count] = old_copy;
            found_pending = true;
        }
        if (found_pending) {
            acct_count += 1;
            continue;
        }

        // PR-S2 Phase 2a (2026-05-15): route this read through the new
        // ancestor-aware sig_overlay path. Empty sig_overlay = byte-identical
        // to flat AppendVec. The `ancestor_slots` param is kept for the
        // calling-convention but `bank.ancestors()` is the authoritative source.
        _ = ancestor_slots;
        const acct = db.getAccountInSlot(&pk, bank.slot, bank.ancestors());

        acct_keys[acct_count] = key;
        if (acct) |a| {
            // Deep-copy data so system_v2 can mutate (e.g., allocate new space)
            const data_copy = if (a.data.len > 0)
                (alloc.alloc(u8, a.data.len) catch continue)
            else
                @as([]u8, &[_]u8{});
            if (a.data.len > 0) @memcpy(data_copy, a.data);
            // Pristine copy (NOT a reference into mmap'd AppendVec storage —
            // r62-class hazard: later allocations can remap/invalidate it).
            const old_copy = if (a.data.len > 0)
                (alloc.dupe(u8, a.data) catch continue)
            else
                @as([]const u8, &[_]u8{});

            acct_metas[acct_count] = .{
                .pubkey = .{ .data = key },
                .lamports = a.lamports,
                .owner = a.owner,
                .executable = a.executable,
                .rent_epoch = a.rent_epoch,
                .data = data_copy,
            };
            old_lamports[acct_count] = a.lamports;
            old_owners[acct_count] = a.owner.data;
            old_data_lens[acct_count] = a.data.len;
            old_datas[acct_count] = old_copy;
        } else {
            // New account (doesn't exist yet) — system_v2 will populate it
            acct_metas[acct_count] = .{
                .pubkey = .{ .data = key },
                .lamports = 0,
                .owner = .{ .data = NATIVE_PROGRAM_IDS.SYSTEM },
                .executable = false,
                .rent_epoch = std.math.maxInt(u64),
                .data = @as([]u8, &[_]u8{}),
            };
            old_lamports[acct_count] = 0;
            old_owners[acct_count] = NATIVE_PROGRAM_IDS.SYSTEM;
            old_data_lens[acct_count] = 0;
            old_datas[acct_count] = &[_]u8{};
        }
        acct_count += 1;
    }

    if (acct_count == 0) return;

    // Build signer mask + writable mask (instruction-level; for a top-level
    // instruction Agave's is_writable == the tx-level writability of the
    // referenced account, which is exactly ptx.isWritable).
    var signer_mask: u64 = 0;
    var writable_mask: u64 = 0;
    for (ix.account_indices[0..max_accts], 0..) |acct_idx, i| {
        if (acct_idx >= ptx.num_accounts) continue;
        if (i >= acct_count) break;
        if (acct_idx < num_signed) {
            signer_mask |= @as(u64, 1) << @intCast(i);
        }
        if (ptx.isWritable(acct_idx)) {
            writable_mask |= @as(u64, 1) << @intCast(i);
        }
    }

    // fix/wire-nonce-ops (2026-06-10): durable-nonce environment. Mirrors
    // Agave invoke_context.environment_config:
    //   blockhash = bank.last_blockhash() = the NEWEST entry of the blockhash
    //   queue = the PARENT bank's final PoH hash (pushed by the parent's
    //   freeze() → updateRecentBlockhashes(); this bank's own poh is only
    //   pushed at ITS freeze, after all txs ran). PROVEN @414201776: cluster
    //   post-state durable_nonce == sha256("DURABLE_NONCE" ‖ parent
    //   414201775's last_blockhash 37fc9863…).
    //   blockhash_lamports_per_signature = the fee rate stored in that same
    //   queue entry (5000 on testnet).
    const rbh_len = bank.recent_blockhashes.len;
    const nonce_env: system_v2.NonceEnv = if (rbh_len > 0) .{
        .recent_blockhash = bank.recent_blockhashes.buffer[rbh_len - 1].blockhash.data,
        .lamports_per_signature = bank.recent_blockhashes.buffer[rbh_len - 1].lamports_per_signature,
        .recent_blockhashes_empty = false,
        .rent_minimum_balance_fn = &rentExemptMinimumBalanceDefault,
    } else .{
        // Empty queue ⇒ Agave's "recent blockhash list is empty" error path.
        .recent_blockhash = [_]u8{0} ** 32,
        .lamports_per_signature = 0,
        .recent_blockhashes_empty = true,
        .rent_minimum_balance_fn = &rentExemptMinimumBalanceDefault,
    };

    // Build InstrCtx and execute
    var ctx = system_v2.InstrCtx{
        .accounts = acct_metas[0..acct_count],
        .signer_mask = signer_mask,
        .allocator = alloc,
        .writable_mask = writable_mask,
        .nonce_env = nonce_env,
    };

    system_v2.execute(&ctx, ix.data) catch |err| {
        // Instruction failed — no state changes are committed (the meta
        // copies are discarded).
        //
        // fix/failed-tx-rollback (2026-06-10, carrier #6 @414386920): the
        // canonical system_v2 InstrError now PROPAGATES so the instruction
        // loops can fail the whole tx Agave-style (stop at first error +
        // rollback to fee/nonce — see rollbackFailedTx doc block). InstrError
        // is the faithful FD port of InstructionError, so every member is a
        // genuine program-execution failure EXCEPT Unimplemented, which is
        // the NonceEnv-not-wired plumbing sentinel (requireNonceEnv,
        // system_v2.zig:699-704) — that one must NOT fail the tx (it means
        // VEXOR is deficient, not the transaction). Keep nonce-op failures
        // loud so any residual mismatch is visible.
        if (ix.data.len >= 4) {
            const disc = std.mem.readInt(u32, ix.data[0..4], .little);
            if (disc == 4 or disc == 5 or disc == 6 or disc == 7 or disc == 12) {
                std.log.warn("[NONCE] slot={d} nonce ix disc={d} failed err={any} (propagating as genuine tx failure unless Unimplemented)", .{ bank.slot, disc, err });
            }
        }
        if (err == system_v2.InstrError.Unimplemented) return; // plumbing — never fail the tx
        return err;
    };

    // Emit pending_writes for any account that changed
    for (0..acct_count) |i| {
        const meta = &acct_metas[i];
        const key = acct_keys[i];

        // Check if anything changed (lamports, owner, or data BYTES).
        // fix/wire-nonce-ops (2026-06-10): the old check compared data LENGTH
        // only — an in-place same-length mutation (AdvanceNonceAccount
        // rewrites the 80-byte nonce state) was invisible, so the advanced
        // nonce bytes never reached pending_writes/lt. Compare content.
        const changed = (meta.lamports != old_lamports[i]) or
            !std.mem.eql(u8, &meta.owner.data, &old_owners[i]) or
            (meta.data.len != old_data_lens[i]) or
            !std.mem.eql(u8, meta.data, old_datas[i]);

        if (!changed) continue;

        // Check writability (zone-based, handles legacy + v0+ALT)
        const acct_idx = ix.account_indices[i];
        if (!ptx.isWritable(acct_idx)) continue;

        // Compute LtHash deltas.
        // fix/wire-nonce-ops (2026-06-10): old_lt MUST use the pristine
        // pre-exec bytes (old_datas[i]), not meta.data[0..old_len] — for an
        // in-place mutation meta.data already holds the POST bytes, which
        // would make old_lt == new_lt-shaped garbage and corrupt the
        // accumulator delta.
        const old_lt = bank_mod.Bank.accountLtHash(
            &key,
            &old_owners[i],
            old_lamports[i],
            false,
            old_datas[i],
        );
        const new_lt = bank_mod.Bank.accountLtHash(
            &key,
            &meta.owner.data,
            meta.lamports,
            meta.executable,
            meta.data,
        );

        bank.collectWrite(.{
            .pubkey = .{ .data = key },
            .lamports = meta.lamports,
            .owner = meta.owner,
            .executable = meta.executable,
            .rent_epoch = meta.rent_epoch,
            .data = meta.data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        }) catch {};
    }
}

/// SIMD-0464 helper: gather the CollectorAccount record for instruction-account
/// position `pos` (idx 2 = inflation collector, idx 3 = block-revenue collector).
/// Reads the account state from the AccountsDb overlay and precomputes the
/// rent-exempt minimum for its data length. Returns null on a bad index (Agave
/// NotEnoughAccountKeys). A non-existent account → lamports 0 / owner-default
/// (will fail validate_and_resolve_key unless it equals the vote key).
pub fn gatherVoteCollector(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: anytype,
    pos: usize,
) ?vote_program.CollectorAccount {
    if (pos >= ix.account_indices.len) return null;
    const tx_idx = ix.account_indices[pos];
    if (tx_idx >= ptx.num_accounts) return null;
    const key = ptx.account_keys[tx_idx];
    var c: vote_program.CollectorAccount = .{
        .key = key,
        .owner = [_]u8{0} ** 32,
        .lamports = 0,
        .rent_exempt_min = rentExemptMinimumBalanceDefault(0),
        .is_writable = ptx.isWritable(tx_idx),
    };
    const key_pk = core.Pubkey{ .data = key };
    if (db.getAccountInSlot(&key_pk, bank.slot, bank.ancestors())) |acct| {
        c.owner = acct.owner.data;
        c.lamports = acct.lamports;
        c.rent_exempt_min = rentExemptMinimumBalanceDefault(acct.data.len);
    }
    return c;
}

/// Execute a vote program instruction.
/// Deserializes vote instruction, applies tower state mutation, writes to pending_writes.
/// Ported from old Vexor bank.zig:3129-3416 (executeVoteProgram + executeVote).
///
/// Wave 6B: visibility widened from `fn` → `pub fn` so the v2_dispatch
/// FallbackContext vtable trampoline can call into the same battle-tested
/// V1 handler that production replay uses. Body unchanged from Wave 5 —
/// every vex-014 / vex-094 / vex-095 / vex-058 fix is preserved bit-identical.
pub fn executeVoteInstruction(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: anytype,
    alloc: std.mem.Allocator,
    // Day-2 PR-A.2 fork-isolation: ancestor chain for overlay reads.
    // Empty = legacy flat-read.
    ancestor_slots: []const u64,
) !void {
    // r31 [VOTE-WRITE-PATH]: comprehensive
    // counter coverage closing every silent-return path so we can name
    // EXACTLY which class of vote-tx is dropping out before reaching the
    // pending_writes.append call site.
    //
    // Pre-r31, only some early-returns had counters; bad_acct_idx,
    // bad_vs_deser, no_auth_voter, bad_signer, withdraw_skip, append_ok,
    // append_fail were ALL silent. r29 measurement showed 0 [VOTE-DBG]
    // log lines despite ~1.4M vote-tx invocations → almost all txs were
    // silent-returning BEFORE VoteDbg.count++.
    const VoteDbg = struct {
        var entries: u64 = 0; // r31: ALL invocations (gates none)
        var count: u32 = 0; // post-deserialize success (existing)
        var no_data: u32 = 0; // ix.data.len < 4 OR account_indices.len < 1
        var bad_acct_idx: u32 = 0; // r31: vote_acct_idx >= ptx.num_accounts (was silent)
        var no_acct: u32 = 0; // db.getAccount() returned null
        var bad_size: u32 = 0; // vote_acct.data.len out of range
        var not_vote_ix: u32 = 0; // ix_type > 15
        var parse_fail: u32 = 0; // VoteInstruction.deserialize failed
        var bad_vs_deser: u32 = 0; // r31: deserializeVoteState returned null (was silent)
        var no_auth_voter: u32 = 0; // r31: getCurrentVoter returned null (was silent)
        var bad_signer: u32 = 0; // r31: isSigner returned false (was silent)
        var withdraw_path: u32 = 0; // r31: Withdraw branch taken
        var withdraw_skip: u32 = 0; // r31: Withdraw early-return (was silent)
        var mutate_fail: u32 = 0; // mutated_ok was false (existing)
        var append_ok: u32 = 0; // r31: pending_writes.append catch-success
        var append_fail: u32 = 0; // r31: pending_writes.append catch-failure
        var ok: u32 = 0; // pending_writes.append fired (existing)
    };

    VoteDbg.entries += 1;
    // [TOPVOTES-TRACE] TEMPORARY measurement — per-bank vote exec attempts.
    if (bank_mod.TvTrace.on()) bank.tvt_vote_exec_entries += 1;

    // r31: Lower emit threshold 5000 → 100 + new format. Per-100-entries
    // gives us ~5 emits/slot at testnet's ~543 vote-tx/slot rate.
    // r72-carrier-hunt: bumped to .warn so probe fires at default log_level
    // d27jj (2026-05-11): un-gate VOTE-WRITE-PATH emission. The lthash carrier hunt
    // at slot 407,775,579 confirmed 573/574 vote-state writes are silent-dropped.
    // We need the counter dump unconditionally to name the dominant silent-return path.
    if (VoteDbg.entries % 500 == 0) {
        // 2026-06-04: carrier hunt resolved (the dominant path was named, and
        // voting is restored). Reverted to .debug per the note below — this was
        // a per-slot WARN firehose on the replay hot path (SESSION-14 flap
        // class). Now silent at the default log level.
        std.log.debug(
            "[VOTE-WRITE-PATH] entries={d} count={d} no_data={d} bad_idx={d} no_acct={d} bad_sz={d} not_vote={d} parse_fail={d} bad_vs_deser={d} no_auth_voter={d} bad_signer={d} withdraw={d} withdraw_skip={d} mutate_fail={d} append_ok={d} append_fail={d} ok={d}\n",
            .{
                VoteDbg.entries,       VoteDbg.count,         VoteDbg.no_data,     VoteDbg.bad_acct_idx,
                VoteDbg.no_acct,       VoteDbg.bad_size,      VoteDbg.not_vote_ix, VoteDbg.parse_fail,
                VoteDbg.bad_vs_deser,  VoteDbg.no_auth_voter, VoteDbg.bad_signer,  VoteDbg.withdraw_path,
                VoteDbg.withdraw_skip, VoteDbg.mutate_fail,   VoteDbg.append_ok,   VoteDbg.append_fail,
                VoteDbg.ok,
            },
        );
        // 2026-05-24: piggyback measureTransaction reject-reason dump on the
        // same 100-entry cadence. Hunts the "3 missing txs at slot 410634000"
        // carrier (Agent 1: Vexor 586 sigs vs Agave 589). If any non-zero
        // counter shows up here, it names exactly which wire-parse cap or
        // bounds-check is dropping txs at the call sites at lines 3487/3829.
        std.log.debug(
            "[PARSE-REJ] calls={d} ok={d} sigs_short={d} sigs_zero={d} sigs_over127={d} sigs_oob={d} no_ver={d} ver_nz={d} hdr_short={d} accts_short={d} accts_zero={d} accts_over256={d} accts_oob={d} rbh_short={d} ix_cnt_short={d} ix_cnt_over255={d} ix_pid_short={d} ix_accts_cnt_short={d} ix_accts_oob={d} ix_data_len_short={d} ix_data_oob={d} alt_cnt_short={d} alt_cnt_over127={d} alt_key_short={d} alt_nw_short={d} alt_nw_oob={d} alt_nr_short={d} alt_nr_oob={d}\n",
            .{
                ParseRejStats.total_calls,        ParseRejStats.total_ok,
                ParseRejStats.sigs_len_short,     ParseRejStats.sigs_zero,
                ParseRejStats.sigs_over_127,      ParseRejStats.sigs_oob,
                ParseRejStats.no_version_byte,    ParseRejStats.versioned_v_nonzero,
                ParseRejStats.header_short,       ParseRejStats.accounts_len_short,
                ParseRejStats.accounts_zero,      ParseRejStats.accounts_over_256,
                ParseRejStats.accounts_oob,       ParseRejStats.rbh_short,
                ParseRejStats.ix_count_short,     ParseRejStats.ix_count_over_255,
                ParseRejStats.ix_pid_short,       ParseRejStats.ix_accts_count_short,
                ParseRejStats.ix_accts_oob,       ParseRejStats.ix_data_len_short,
                ParseRejStats.ix_data_oob,        ParseRejStats.alt_count_short,
                ParseRejStats.alt_count_over_127, ParseRejStats.alt_key_short,
                ParseRejStats.alt_nw_short,       ParseRejStats.alt_nw_oob,
                ParseRejStats.alt_nr_short,       ParseRejStats.alt_nr_oob,
            },
        );
    }

    if (ix.data.len < 4 or ix.account_indices.len < 1) {
        VoteDbg.no_data += 1;
        if (bank_mod.TvTrace.on()) bank.tvt_vote_pre3 += 1; // [TOPVOTES-TRACE] TEMPORARY measurement
        return;
    }

    // Vote account is always the first account in the instruction
    const vote_acct_idx = ix.account_indices[0];
    if (vote_acct_idx >= ptx.num_accounts) {
        VoteDbg.bad_acct_idx += 1;
        if (bank_mod.TvTrace.on()) bank.tvt_vote_pre3 += 1; // [TOPVOTES-TRACE] TEMPORARY measurement
        return;
    }

    const vote_key = ptx.account_keys[vote_acct_idx];
    const vote_core_pk = core.Pubkey{ .data = vote_key };
    // PR-A.2 REVERTED 2026-05-15: switching vote_acct read to PR-A.1's
    // ancestor-aware overlay caused 82% vote mutate_fail and earlier cascade.
    // PR-S2 Phase 2a (2026-05-15): migrate to new `getAccountInSlot` API.
    // sig_overlay is empty in 2a so this is byte-identical to the prior
    // flat `getAccount` path — the PR-A.2 regression hypothesis (within-slot
    // prior-write state from the old overlay) does NOT apply to this new
    // overlay until 2b wires actual writes. Keep historical comment as a
    // breadcrumb when 2b lands.
    _ = ancestor_slots;
    // FIX (2026-06-28, carrier slot 418414604): a vote account CREATED in THIS
    // slot (System CreateAccount → write lives in bank.pending_writes, NOT yet
    // flushed to the accounts store) is absent from getAccountInSlot. The old
    // `orelse { no_acct; return; }` SILENTLY skipped the vote-init instruction,
    // leaving the all-zeros CreateAccount buffer committed → bank_hash carrier.
    // Trigger: `solana create-vote-account` = CreateAccount + InitializeVoteAccount
    // in ONE tx (new-validator onboarding). Agave reads the vote account from the
    // txn InstructionContext (read-your-writes within the tx); Vexor's in-slot
    // overlay (bank.overlayNewest → pending_writes) is the equivalent. So consult
    // the overlay BEFORE giving up; only no_acct-return when BOTH the store AND the
    // overlay miss. Sibling of 1f8419c (the parse_fail silent-return fix for
    // VoterWithBLS authorize).
    var current_data: []const u8 = undefined;
    var current_lamports: u64 = undefined;
    var current_owner: [32]u8 = undefined;
    var current_executable: bool = undefined;
    var current_rent_epoch: u64 = undefined;
    var have_acct = false;
    // r71-fix-2: chain through prior in-slot writes for this vote account.
    // Vexor's native vote replay reads vote_acct.data from the AccountsDb
    // snapshot mmap, which never updates mid-slot. When the same validator
    // votes twice in one slot, the second tx must see W1's mutated state
    // (S1) — not the pre-slot state (S0) — for both the auth-voter check
    // and the mutation input. Otherwise the second [VOTE-WRITE] writes a
    // tower derived from S0 and an `old_lt` of S0, breaking the LtHash
    // chain invariant W2.old_lt == W1.new_lt (r69 telescope identity).
    // Slot 404,692,482 [LT-DUP] probe named this carrier: pubkey
    // G8cgGLkWtPGa4tVT2Z9i8gnQ8izyi4XGqHuiBVw3gcqQ at write indices 583
    // and 1144 chained chain_ok=false (cur_old4=46935fbb vs prev_new4=
    // c5e674e1). Followup r71-fix-3 will lift the same pattern into
    // stake_program.zig (5 sites) + the Withdraw recipient credit.
    // [TOPVOTES-TRACE] TEMPORARY measurement — override armed at vote pre-read?
    if (bank_mod.TvTrace.on() and bank_mod.worker_writes_override != null)
        _ = bank.tvt2_vread_ovr_armed.fetchAdd(1, .monotonic);
    if (db.getAccountInSlot(&vote_core_pk, bank.slot, bank.ancestors())) |vote_acct| {
        current_data = vote_acct.data;
        current_lamports = vote_acct.lamports;
        current_owner = vote_acct.owner.data;
        current_executable = vote_acct.executable;
        current_rent_epoch = vote_acct.rent_epoch;
        have_acct = true;
        if (bank_mod.TvTrace.on()) _ = bank.tvt2_vread_db.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
    }
    {
        // B2b (parallel-exec): override-aware overlay read (worker buffer THEN
        // pending_writes). Serial path (override == null) = byte-identical newest-first
        // pending_writes scan. ALSO supplies a SAME-SLOT-CREATED vote account, whose
        // CreateAccount write lives ONLY here until end-of-slot flush.
        if (bank.overlayNewest(&vote_key)) |pw| {
            current_data = pw.data;
            current_lamports = pw.lamports;
            current_owner = pw.owner.data;
            current_executable = pw.executable;
            current_rent_epoch = pw.rent_epoch;
            have_acct = true;
            if (bank_mod.TvTrace.on()) _ = bank.tvt2_vread_overlay.fetchAdd(1, .monotonic); // [TOPVOTES-TRACE] TEMPORARY
        }
    }
    if (!have_acct) {
        VoteDbg.no_acct += 1;
        if (bank_mod.TvTrace.on()) bank.tvt_vote_no_acct += 1; // [TOPVOTES-TRACE] TEMPORARY measurement (read-miss suspect)
        return;
    }

    // Vote account data must be reasonable size (3731-3762 bytes typical)
    if (current_data.len < 77 or current_data.len > 8192) {
        VoteDbg.bad_size += 1;
        if (bank_mod.TvTrace.on()) bank.tvt_vote_pre3 += 1; // [TOPVOTES-TRACE] TEMPORARY measurement
        return;
    }

    // voteforge production vote seam: voteforge's own front door
    // (`voteforge/vote_program.zig:dispatch()` via `executeVoteViaVoteforge`)
    // executes every vote instruction for real against the LIVE bank accounts.
    // This is the sole vote-execution path. The retired Sig-derived transplant
    // oracle (`sigvote.execute`) and the legacy `vote_state_serde` native
    // fallback that this seam used to select between were removed 2026-07-12
    // (vote-program rewrite Stage 8) — voteforge has been the live executor
    // since the Stage-7 flip.
    const tvt_ok_before = VoteDbg.ok;
    const tvt_mf_before = VoteDbg.mutate_fail;
    const tvt_af_before = VoteDbg.append_fail;
    if (bank_mod.TvTrace.on()) bank.tvt_vote_sig_called += 1;
    try executeVoteViaVoteforge(
        ix,
        ptx,
        bank,
        alloc,
        vote_key,
        current_data,
        current_lamports,
        current_owner,
        current_executable,
        current_rent_epoch,
        &VoteDbg.mutate_fail,
        &VoteDbg.append_ok,
        &VoteDbg.append_fail,
        &VoteDbg.ok,
    );
    if (bank_mod.TvTrace.on()) {
        if (VoteDbg.ok > tvt_ok_before) bank.tvt_vote_exec_ok += 1;
        bank.tvt_vote_mutate_fail += VoteDbg.mutate_fail - tvt_mf_before;
        bank.tvt_vote_append_fail += VoteDbg.append_fail - tvt_af_before;
    }
}

/// Live FeatureSet pointer for the vote path. Published by
/// ReplayStage.setLiveFeatureSet at bootstrap (before replay), read-only after.
/// Free-function scope because executeVoteInstruction/executeVoteViaVoteforge
/// have no `self`. null (e.g. early bootstrap or KAT harnesses) → voteforge's
/// conservative default (all new gates off) applies.
pub var g_vote_live_features: ?*const features_mod.FeatureSet = null;

/// The production vote seam: voteforge's own front door (`vp.dispatch`)
/// executes the vote instruction for real against the LIVE bank accounts,
/// using the instruction-scoped borrow/mutate contract (`aio.AccountTable`/
/// `Borrow`). Chained pre-state lookup (overlay-then-db, mirroring
/// `executeVoteInstruction`'s own vote-account read), diff-and-commit via
/// `bank.collectWrite`, OOM-vs-genuine-error taxonomy.
///
/// `aio.AccountTable` is INSTRUCTION-scoped by design (lever #2,
/// `account_io.zig`'s own header) — only `ix.account_indices` accounts are
/// materialized here, never the full `ptx.account_keys`.
///
/// This is the sole vote executor; the retired Sig transplant and its A/B
/// differential-oracle shadow that this seam used to carry were removed
/// 2026-07-12 (vote-rewrite Stage 8).
pub fn executeVoteViaVoteforge(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    alloc: std.mem.Allocator,
    vote_key: [32]u8,
    vote_current_data: []const u8,
    vote_current_lamports: u64,
    vote_current_owner: [32]u8,
    vote_current_executable: bool,
    vote_current_rent_epoch: u64,
    mutate_fail: *u32,
    append_ok: *u32,
    append_fail: *u32,
    ok: *u32,
) !void {
    const tvt_on = bank_mod.TvTrace.on();
    if (tvt_on) _ = bank.tvt2_enter.fetchAdd(1, .monotonic);

    const chainLookup = struct {
        fn get(b: *Bank, dbm: anytype, key: [32]u8) ?struct {
            lamports: u64,
            owner: [32]u8,
            executable: bool,
            rent_epoch: u64,
            data: []const u8,
        } {
            if (b.overlayNewest(&key)) |pw| {
                return .{ .lamports = pw.lamports, .owner = pw.owner.data, .executable = pw.executable, .rent_epoch = pw.rent_epoch, .data = pw.data };
            }
            const cpk = Pubkey{ .data = key };
            if (dbm.getAccountInSlot(&cpk, b.slot, b.ancestors())) |a| {
                return .{ .lamports = a.lamports, .owner = a.owner.data, .executable = a.executable, .rent_epoch = a.rent_epoch, .data = a.data };
            }
            return null;
        }
    }.get;

    // ── Build the INSTRUCTION-scoped account table (real, uncapped — this is
    // the committing path, never truncated) ──────────────────────────────────
    const n: usize = ix.account_indices.len;
    var metas = alloc.alloc(aio.AccountMeta, n) catch {
        mutate_fail.* += 1;
        return;
    };
    var records = alloc.alloc(aio.AccountRecord, n) catch {
        mutate_fail.* += 1;
        return;
    };
    const PreState = struct {
        writable: bool,
        lamports: u64,
        owner: [32]u8,
        executable: bool,
        rent_epoch: u64,
        data: []const u8,
        pubkey: [32]u8,
        is_signer: bool,
    };
    var pre = alloc.alloc(PreState, n) catch {
        mutate_fail.* += 1;
        return;
    };

    var route_vote_idx: usize = 0;
    var route_vote_idx_found = false;
    var bi: usize = 0;
    for (ix.account_indices, 0..) |aidx, i| {
        if (aidx >= ptx.num_accounts) {
            // Malformed/ALT-resolved out-of-range index — mirror
            // v2DispatchInternal's own LEGIT-REJECT precedent (a conforming
            // client never sends this; Agave rejects at sanitize too).
            mutate_fail.* += 1;
            return;
        }
        const key = ptx.account_keys[aidx];
        const writable = ptx.isWritable(@intCast(aidx));
        const is_signer = aidx < ptx.num_required_sigs;

        var lamports: u64 = 0;
        var owner: [32]u8 = [_]u8{0} ** 32;
        var executable: bool = false;
        var rent_epoch: u64 = std.math.maxInt(u64);
        var src_data: []const u8 = &[_]u8{};

        if (std.mem.eql(u8, &key, &vote_key)) {
            lamports = vote_current_lamports;
            owner = vote_current_owner;
            executable = vote_current_executable;
            rent_epoch = vote_current_rent_epoch;
            src_data = vote_current_data;
        } else if (chainLookup(bank, bank.accounts_db.?, key)) |c| {
            lamports = c.lamports;
            owner = c.owner;
            executable = c.executable;
            rent_epoch = c.rent_epoch;
            src_data = c.data;
        }

        if (!route_vote_idx_found and std.mem.eql(u8, &key, &vote_key)) {
            route_vote_idx = i;
            route_vote_idx_found = true;
        }

        const rec_data: []u8 = if (writable)
            (alloc.dupe(u8, src_data) catch {
                mutate_fail.* += 1;
                return;
            })
        else
            @constCast(src_data);

        metas[bi] = .{ .pubkey = key, .is_signer = is_signer, .is_writable = writable };
        records[bi] = .{ .pubkey = key, .lamports = lamports, .owner = owner, .executable = executable, .rent_epoch = rent_epoch, .data = rec_data };
        pre[bi] = .{ .writable = writable, .lamports = lamports, .owner = owner, .executable = executable, .rent_epoch = rent_epoch, .data = src_data, .pubkey = key, .is_signer = is_signer };
        bi += 1;
    }
    if (tvt_on) _ = bank.tvt2_build_done.fetchAdd(1, .monotonic);

    const program_id: [32]u8 = ptx.account_keys[ix.program_id_index];
    var table = aio.AccountTable.init(program_id, metas[0..bi], records[0..bi]) catch {
        mutate_fail.* += 1;
        return;
    };

    var signers_buf: [MAX_VOTE_ROUTE_ACCOUNTS]([32]u8) = undefined;
    var n_signers: usize = 0;
    for (pre[0..bi]) |p| {
        if (p.is_signer and n_signers < signers_buf.len) {
            signers_buf[n_signers] = p.pubkey;
            n_signers += 1;
        }
    }
    // Overflow-safe fallback: vote instructions never carry >8 accounts in
    // practice (the codebase-wide `MAX_ROUTE_ACCOUNTS` invariant), but if a
    // malformed instruction ever did, cap rather than silently drop signers
    // that would change auth-check outcomes — reject loud instead.
    if (n_signers < bi and blk: {
        var c: usize = 0;
        for (pre[0..bi]) |p| c += @intFromBool(p.is_signer);
        break :blk c;
    } > signers_buf.len) {
        mutate_fail.* += 1;
        return;
    }

    const current_epoch: u64 = bank.epoch_schedule.getEpoch(bank.slot);
    const lse: u64 = bank.epoch_schedule.getLeaderScheduleEpoch(bank.slot);

    // SlotHashes: native parse of the LOCAL blob (u64 count + count*{u64
    // slot,[32]u8 hash}, newest-first) — canonical local SlotHashes, never the
    // clusterSlotHashesSnapshot curl-global.
    var slot_hashes: vi.SlotHashesView = .EMPTY;
    if (bank.getSlotHashesData()) |sh_blob| {
        if (sh_blob.len >= 8) {
            const count = std.mem.readInt(u64, sh_blob[0..8], .little);
            var off: usize = 8;
            var si: usize = 0;
            while (si < count and si < vi.MAX_SLOT_HASHES and off + 40 <= sh_blob.len) : (si += 1) {
                const slot = std.mem.readInt(u64, sh_blob[off..][0..8], .little);
                var hash: [32]u8 = undefined;
                @memcpy(&hash, sh_blob[off + 8 .. off + 40]);
                slot_hashes.entries[si] = .{ .slot = slot, .hash = hash };
                off += 40;
            }
            slot_hashes.len = si;
        }
    }

    // FeatureFlags: the 9 live vote gates threaded from `g_vote_live_features`
    // as activation-slot-presence booleans (voteforge's `ExecContext.features`
    // is gate-open/closed only, never slot-relative).
    var features: vi.FeatureFlags = .{};
    if (g_vote_live_features) |lfs| {
        features = .{
            .vote_state_v4 = lfs.activationSlot(features_mod.VOTE_STATE_LAYOUT_V4) != null,
            .enable_tower_sync_ix = lfs.activationSlot(features_mod.ENABLE_TOWER_SYNC_IX) != null,
            .deprecate_legacy_vote_ixs = lfs.activationSlot(features_mod.REJECT_LEGACY_VOTE_INSTRUCTIONS) != null,
            .custom_commission_collector = (lfs.activationSlot(features_mod.CUSTOM_COMMISSION_COLLECTOR) orelse
                lfs.activationSlot(features_mod.CUSTOM_COMMISSION_COLLECTOR_V2)) != null,
            .delay_commission_updates = lfs.activationSlot(features_mod.DELAY_COMMISSION_UPDATES) != null,
            .bls_pubkey_management_in_vote_account = lfs.activationSlot(features_mod.BLS_PUBKEY_MANAGEMENT_IN_VOTE_ACCOUNT) != null,
            .commission_rate_in_basis_points = lfs.activationSlot(features_mod.COMMISSION_RATE_IN_BASIS_POINTS) != null,
            .block_revenue_sharing = lfs.activationSlot(features_mod.BLOCK_REVENUE_SHARING) != null,
            .vote_account_initialize_v2 = lfs.activationSlot(features_mod.VOTE_ACCOUNT_INITIALIZE_V2) != null,
        };
    }

    var ctx = vi.ExecContext{
        .slot = bank.slot,
        .epoch = current_epoch,
        .leader_schedule_epoch = lse,
        .epoch_schedule = .{
            .slots_per_epoch = bank.epoch_schedule.slots_per_epoch,
            .leader_schedule_slot_offset = bank.epoch_schedule.leader_schedule_slot_offset,
            .warmup = bank.epoch_schedule.warmup,
            .first_normal_epoch = bank.epoch_schedule.first_normal_epoch,
            .first_normal_slot = bank.epoch_schedule.first_normal_slot,
        },
        .features = features,
        .slot_hashes = slot_hashes,
        // SIMD-0185 realloc-before-write: storeV4 grows an under-sized (legacy
        // V1_14_11) vote account to 3762 bytes using THIS allocator — the same
        // one that duped the writable account's `data` slice above, so the
        // resize/free is allocator-consistent and the grown `post.data` is what
        // the diff-and-commit loop below reads.
        .alloc = alloc,
    };

    const dispatch_result = vp.dispatch(alloc, &table, program_id, ix.data, signers_buf[0..n_signers], &ctx);

    const exec_result: vi.InstrError!void = blk: {
        const r = dispatch_result catch |e| break :blk e;
        switch (r) {
            .handled => |h| break :blk h,
            .delegate => |d| {
                // Should never happen live: `vi.isStage3Discriminant` covers
                // 0-19 in full post-Stage-5 (`vp.classify` composes it
                // directly) — a `.delegate` here means the decode itself
                // rejected before classification could even run (e.g. a
                // <4-byte payload never reaches `peekDiscriminant`'s callers
                // inside `dispatch` at all — that path already returns an
                // `InstrError`, not `.delegate`). Treated as a genuine
                // decode failure, never a silent no-op: matches Agave
                // failing the tx on an unrecognized/malformed vote ix.
                std.log.warn("[VOTE-LIVE-UNEXPECTED-DELEGATE] slot={d} disc={d} class={} — dispatch() delegated on the LIVE seam (should be unreachable post-Stage-5)", .{ bank.slot, d.disc, d.class });
                break :blk error.InvalidInstructionData;
            },
        }
    };

    exec_result catch |e| {
        mutate_fail.* += 1;
        if (e == error.OutOfMemory) return;
        return e;
    };

    ok.* += 1;
    if (tvt_on) _ = bank.tvt2_exec_ok.fetchAdd(1, .monotonic);

    // ── Diff each writable account and commit changed ones. ───────────────────
    var w: usize = 0;
    while (w < bi) : (w += 1) {
        if (!pre[w].writable) continue;
        if (tvt_on) _ = bank.tvt2_diff_writable.fetchAdd(1, .monotonic);
        const post = &table.records[w];
        const changed =
            post.lamports != pre[w].lamports or
            !std.mem.eql(u8, &post.owner, &pre[w].owner) or
            post.executable != pre[w].executable or
            post.data.len != pre[w].data.len or
            !std.mem.eql(u8, post.data, pre[w].data);
        if (!changed) {
            if (tvt_on) _ = bank.tvt2_diff_skip_eq.fetchAdd(1, .monotonic);
            continue;
        }

        const pk = pre[w].pubkey;
        const old_lt = bank_mod.Bank.accountLtHash(&pk, &pre[w].owner, pre[w].lamports, pre[w].executable, pre[w].data);
        const new_lt = bank_mod.Bank.accountLtHash(&pk, &post.owner, post.lamports, post.executable, post.data);
        if (bank.collectWrite(.{
            .pubkey = .{ .data = pk },
            .lamports = post.lamports,
            .owner = .{ .data = post.owner },
            .executable = post.executable,
            .rent_epoch = post.rent_epoch,
            .data = post.data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        })) |_| {
            append_ok.* += 1;
            if (tvt_on) _ = bank.tvt2_diff_applied.fetchAdd(1, .monotonic);
        } else |_| {
            append_fail.* += 1;
            if (tvt_on) _ = bank.tvt2_appfail.fetchAdd(1, .monotonic);
        }
    }
}

/// Convert vote_program Lockout[] to vote_state_serde Lockout[] (same layout, different types)
pub fn convertVoteLockouts(
    buf: *[31]vote_state_serde.Lockout,
    source: []const vote_program.Lockout,
) []const vote_state_serde.Lockout {
    const count = @min(source.len, 31);
    for (0..count) |i| {
        buf[i] = .{
            .slot = source[i].slot,
            .confirmation_count = source[i].confirmation_count,
        };
    }
    return buf[0..count];
}

/// Execute an Address Lookup Table program instruction natively.
///
/// ALT Core-BPF migration (SIMD-0128, feature
/// `C97eKZygrkU4JxJsZdjgbUY7iQR7rKTr4NyDWo2E5pRm`): on testnet the ALT program
/// account (`AddressLookupTab1e1111111111111111111111111`) is now owned by
/// BPFLoaderUpgradeable. Vexor's top-level dispatch has explicit native branches
/// for System/Vote/Stake/ComputeBudget/BPFLoaderUpgradeable/ZkElGamal but had
/// NONE for ALT, so ALT instructions fell to the generic BPF path, which
/// silently no-ops the migrated bodyless ELF (success + 0 mutations). The
/// `CreateLookupTable`-created table account was therefore dropped →
/// bank_hash carrier (slot 418669048).
///
/// This mirrors EXACTLY how Vexor already runs the migrated Stake program
/// natively (executeStakeInstruction): we route ALT to the proven V1 native
/// handler `address_lookup_table.execute` via `wave6b.runAltFallback`, which
/// builds an ALT InstrCtx from the tx + bank, runs the handler, and appends the
/// resulting AccountWrites to `bank.pending_writes` — IDENTICAL to how
/// executeVoteInstruction/executeStakeInstruction leave their writes for the V1
/// commit path. We do NOT truncate pending_writes afterward (that is the
/// V2-trampoline's job, not this V1 top-level path).
///
/// PR-5am (2026-05-20): `runAltFallback` takes pre-state from a `snaps` array
/// built EXACTLY like the snapshot loop inside `v2DispatchInternal`
/// (replay_stage.zig:~10730): (a) bank.pending_writes newest-first for
/// intra-slot read-your-writes (so a same-slot CreateLookupTable + later-tx
/// ExtendLookupTable sees the unflushed table), (b) db.getAccountInSlot, then
/// (c) DEFAULT-EMPTY for to-be-created accounts.
/// @prov:dispatch.default-empty-account
/// The default-empty step is the entire PR-5am fix — without it the
/// to-be-created table account reads null and the write is silently dropped.
/// (We skip the Sysvar1nstructions special-case from that loop — ALT
/// instructions never reference it.)
pub fn executeAltInstruction(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: *AccountsDb,
    alloc: std.mem.Allocator,
    ancestor_slots: []const u64,
) !void {
    // System program id (all-zeros) for the default-empty pre-state owner.
    const SYSTEM_PID_FOR_DEFAULT: [32]u8 = [_]u8{0} ** 32;

    // Build AccountSnapshots for this instruction's account list, mirroring the
    // v2DispatchInternal snap loop. `snaps[i].data` BORROWS its backing buffer
    // (from pending_writes / db / the empty slice); runAltFallback copies each
    // before mutating, so we free only the array. The pending_writes buffers are
    // separate bank.allocator allocations, NOT inline in the items array, so a
    // later append+realloc inside runAltFallback does not invalidate them.
    const snaps = try alloc.alloc(v2dispatch.AccountSnapshot, ix.account_indices.len);
    defer alloc.free(snaps);
    var snap_count: usize = 0;
    const num_signed = ptx.num_required_sigs;

    for (ix.account_indices) |aidx| {
        if (aidx >= ptx.num_accounts) continue;
        const key = ptx.account_keys[aidx];

        // (a) pending_writes overlay, newest-first (intra-slot read-your-writes).
        var found_pending: bool = false;
        var pwi: usize = bank.pending_writes.items.len;
        while (pwi > 0) {
            pwi -= 1;
            const pw = &bank.pending_writes.items[pwi];
            if (std.mem.eql(u8, &pw.pubkey.data, &key)) {
                snaps[snap_count] = .{
                    .pubkey = key,
                    .lamports = pw.lamports,
                    .owner = pw.owner.data,
                    .executable = pw.executable,
                    .rent_epoch = pw.rent_epoch,
                    .data = pw.data,
                    .is_writable = ptx.isWritable(aidx),
                    .is_signer = aidx < num_signed,
                };
                found_pending = true;
                break;
            }
        }
        if (found_pending) {
            snap_count += 1;
            continue;
        }

        // (b) db.getAccountInSlot, else (c) DEFAULT-EMPTY for to-be-created.
        const pk = core.Pubkey{ .data = key };
        if (db.getAccountInSlot(&pk, bank.slot, bank.ancestors())) |acct| {
            snaps[snap_count] = .{
                .pubkey = key,
                .lamports = acct.lamports,
                .owner = acct.owner.data,
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .data = acct.data,
                .is_writable = ptx.isWritable(aidx),
                .is_signer = aidx < num_signed,
            };
        } else {
            snaps[snap_count] = .{
                .pubkey = key,
                .lamports = 0,
                .owner = SYSTEM_PID_FOR_DEFAULT,
                .executable = false,
                .rent_epoch = 0,
                .data = &[_]u8{},
                .is_writable = ptx.isWritable(aidx),
                .is_signer = aidx < num_signed,
            };
        }
        snap_count += 1;
    }

    var fb = wave6b.FallbackState{
        .ix = ix,
        .ptx = ptx,
        .bank = bank,
        .db = db,
        .ancestor_slots = ancestor_slots,
    };
    // runAltFallback appends the native handler's AccountWrites to
    // bank.pending_writes; the V1 commit path commits them. Propagate any error
    // so the dispatch site sets tx_fail (matching vote/stake).
    try wave6b.runAltFallback(&fb, alloc, snaps[0..snap_count]);
}

/// Execute a stake program instruction.
/// Delegates to stake_program.execute() which handles all 18 instruction types.
///
/// Wave 6B: visibility widened from `fn` → `pub fn` so v2_dispatch's
/// FallbackContext vtable can route `M9_Stake_VariantPending_*` here.
pub fn executeStakeInstruction(
    ix: ParsedInstruction,
    ptx: *const ParsedTx,
    bank: *Bank,
    db: anytype,
    alloc: std.mem.Allocator,
    /// Phase-1 Core-BPF Stake dual-path (2026-06-16): the per-bank live
    /// FeatureSet, threaded from `self.live_feature_set` at the two live call
    /// sites (:5209/:5550). Optional: dead-worker (:301) and M9 fallback
    /// (:8595) sites pass null → native path (byte-identical to current).
    feature_set: ?*const features_mod.FeatureSet,
) !void {
    // ── Phase-1 dual-path switch (feature-gated, env DEFAULT-OFF) ──────────
    // ENV-FIRST short-circuit is the byte-identical guarantee: when
    // VEX_STAKE_BPF is unset/0, `enabled()` is false and the fork-aware
    // `isActive` check below is NEVER evaluated — control falls straight to
    // the unchanged native body, so OFF is byte-identical to current.
    //
    // When ON *and* the migrate feature is active at this bank's slot, route
    // the stake instruction through `dispatchBpfExecution` — the SAME
    // v2DispatchBpfProgram chokepoint every SPL program uses. The .so /
    // programdata is resolved from accounts-db like any other BPF program
    // (the migrated Stake account is owned by BPFLoaderUpgradeable); we do
    // NOT hardcode any path.
    if (vex_bpf2.stake_bpf_flag.enabled() and
        feature_set != null and
        feature_set.?.isActive(features_mod.MIGRATE_STAKE_PROGRAM_TO_CORE_BPF, bank.slot))
    {
        // HARDEN-3 (2026-06-16): StakeHistory well-formedness guard. The v5 .so
        // reads StakeHistory via the SysvarCache (populated from the SAME
        // BankSysvarAdapter bytes below) using an ORDER-DEPENDENT positional
        // accessor that PANICS on a malformed buffer. Production feeds the
        // well-formed 16392B account today, but a malformed buffer must fail
        // the tx CLEANLY (a deterministic InstructionError that the call site
        // maps to tx-fail) rather than abort the replay thread. We validate the
        // EXACT bytes the .so consumes — `BankSysvarAdapter.getStakeHistoryBytes`
        // (pending_writes overlay first, then db.getAccountInSlot) — so the
        // guard can never disagree with what the program reads. This `return e`
        // path is intentionally NOT funneled through the dispatch error-filter
        // below: it is a genuine deterministic failure and must escape to the
        // caller's "any error → tx_fail" mapping.
        {
            var sh_adapter = bank_sysvar_adapter.BankSysvarAdapter.init(bank, db);
            try validateStakeHistoryWellFormed(sh_adapter.getStakeHistoryBytes(), bank.slot);
        }
        // HARDEN-1 (2026-06-16): the call sites (:5211 DAG / :5552 serial) map
        // ANY escaped error to tx_fail — correct for the NATIVE path, whose
        // genuine escapes are deterministic bincode parse errors. But the .so
        // path can return Vexor PLUMBING DispatchError values (M5_*, M9_*,
        // M1/M2/M3/M6/M8, OOM) that must NOT fail the tx (same taxonomy the
        // generic dispatchBpfExecution sites enforce — see the doc block above
        // rollbackFailedTx, and the M4/V1 filter at :5261 / :5590). Filter HERE
        // so both stake call sites inherit the correct outcome and so the
        // null-feature_set callers (:301 dead-worker / :8595 M9 fallback) — which
        // never enter this ON-branch — are unaffected. ONLY M4_RunFailed
        // (V2 BPF VM abort / r0!=0) and V1_ProgramFailed (V1 interpreter abort)
        // are genuine program failures and propagate. NOTE: on a genuine stake
        // VALIDATION failure (bad authority / insufficient funds / wrong owner)
        // the .so aborts → M4_RunFailed → tx-fail, which is the POST-MIGRATION
        // CORRECT outcome the cluster produces; this deliberately does NOT
        // mirror Vexor-native's documented silent-success residual (FIX-1c).
        // GATE-COUNTER (2026-06-16): prove the stake ON-path actually fired, so a
        // parity sweep over stake-free slots can't read as a vacuous "green".
        {
            const Seam = struct {
                var n: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
            };
            const c = Seam.n.fetchAdd(1, .monotonic) + 1;
            // Mark this slot for the VEX_STAKE_DUMP recorder (auto full per-account
            // freeze-dump of every Core-BPF stake ON-path slot). No-op unless armed.
            vex_store.recorder.markStakeSlot(bank.slot);
            if (c <= 8 or c % 50 == 0) {
                const disc: u32 = if (ix.data.len >= 4) std.mem.readInt(u32, ix.data[0..4], .little) else 0xFFFF;
                std.log.warn("[STAKE-BPF-SEAM] top-level stake ON-path fired count={d} slot={d} disc={d}", .{ c, bank.slot, disc });
            }
        }
        if (dispatchBpfExecution(ix, ptx, bank, db, alloc, feature_set, null)) |_| {
            return; // .so committed (atomically, on success) — done.
        } else |e| {
            // Genuine program abort (.so executed and returned r0!=0 / aborted):
            // fail the tx — the post-migration cluster produces the same outcome.
            if (e == error.M4_RunFailed or e == error.V1_ProgramFailed) return e;
            // GAP1 FIX (2026-06-16): a Vexor PLUMBING error (M5_/M9_/M1/2/3/6/8/OOM)
            // is NOT a program decision. dispatchV3ViaV2Producer/commitV2Mutations
            // commit ATOMICALLY on success only (verified replay_stage.zig:7921-7923),
            // so a plumbing error committed ZERO writes. The old code swallowed this
            // to a silent success-with-NO-writes → would diverge from the cluster if
            // its .so wrote state. Instead FALL THROUGH to the native handler below:
            // native is cluster-exact AND byte-identical to the .so (harness 30/30),
            // and since nothing was committed there is no double-apply. Preserves
            // liveness + correctness; the rare plumbing hiccup no longer risks a
            // silent fork.
            const FB = struct {
                var n: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
            };
            const fc = FB.n.fetchAdd(1, .monotonic) + 1;
            if (fc <= 8 or fc % 50 == 0) {
                std.log.warn("[STAKE-BPF-FALLBACK] slot={d} .so plumbing err {s} -> native fallback (count={d})", .{ bank.slot, @errorName(e), fc });
            }
            // fall through to the native path below (no `return`).
        }
    }

    // B2b (parallel-exec): measure the ACTIVE write sink (worker buffer if set, else
    // pending_writes) so this diagnostic stays accurate under parallel exec. Serial
    // path (override == null) = byte-identical to reading pending_writes.items.len.
    // This detector is diagnostic-only (rate-limited log; NEVER fails the tx / affects
    // bank_hash), so correctness does not depend on it — this just avoids log spam.
    const writes_before = if (bank_mod.worker_writes_override) |ov| ov.items.len else bank.pending_writes.items.len;
    try stake_program.execute(ix, ptx, bank, db, alloc);
    // FIX-1c residual detector (2026-06-10, task #65): the stake handlers
    // swallow genuine validation failures with silent returns (no error
    // surface — see native/stake_program.zig execute() doc). A swallowed
    // failure inside a multi-instruction tx is a potential write leak
    // (carrier-#6 class). We can't propagate what doesn't error, so MEASURE:
    // a stake instruction that returned success but produced zero writes is
    // either a swallowed failure or a byte-idempotent success (rare). Loud,
    // rate-limited; NEVER fails the tx. GetMinimumDelegation (disc 13)
    // legitimately writes nothing — excluded.
    const writes_after = if (bank_mod.worker_writes_override) |ov| ov.items.len else bank.pending_writes.items.len;
    if (writes_after == writes_before and ix.data.len >= 4) {
        const disc = std.mem.readInt(u32, ix.data[0..4], .little);
        if (disc != 13) {
            StakeTaxonomyUnknownStats.zero_write_returns += 1;
            const n = StakeTaxonomyUnknownStats.zero_write_returns;
            if (n <= 4 or n % 200 == 0) {
                std.log.warn("[TX-ERR-TAXONOMY-UNKNOWN] slot={d} stake disc={d} returned success with ZERO writes (count={d}) — likely a swallowed handler failure (residual leak class, see FIX-1c)", .{ bank.slot, disc, n });
            }
        }
    }
}
