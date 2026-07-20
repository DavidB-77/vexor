//! Vexor Bank — Slot State Machine
//!
//! @prov:bank.freeze @prov:bank.hash-calc — freeze()/bank-hash reference map below.
//! Represents one slot's execution state: account mutations + hash accumulation.
//!
//! Reference-function map (anchors point at the per-function citation sites):
//!   @prov:bank.freeze          → Bank.freeze()
//!   @prov:bank.settle-fees     → Bank.settleFees()
//!   @prov:bank.incinerator     → Bank.runIncinerator()
//!   @prov:bank.hash-calc       → Bank.computeBankHash()
//!   @prov:bank.lthash-account  → accountLtHash()
//!   @prov:bank.lthash-delta    → Bank.applyLtHashDelta()

const std = @import("std");
const vex_crypto = @import("vex_crypto");
const build_options = @import("build_options");
const recorder = @import("vex_store").recorder;
/// SB-2 getBlock-meta: TxError shape for CapturedTx enrichment (cosmetic RPC meta only).
const block_store_mod = @import("vex_store").block_store;
const types = @import("types.zig");

/// Fork-aware read window (ancestor chain depth fed to AccountsDb reads). The
/// two-tier model widens this from the legacy 64 to RING_CAPACITY (4096) so a
/// read at the tip during a >64-slot root-lag seam can reach an on-fork write
/// many slots back — the stale-read carrier was the 64-cap truncating the
/// window so a 138-slot-back write fell through to the stale rooted store.
/// Bound = the unrooted_ring capacity (root-lag must stay < RING_CAPACITY).
pub const ANCESTORS_CAP: usize = if (build_options.two_tier) 4096 else 64;

const Hash = types.Hash;
const Pubkey = types.Pubkey;
const LtHash = vex_crypto.LtHash;
/// F2/F3 (HARD-FORK-FAMILY-DESIGN-2026-06-17): the snapshot bank's hard-fork
/// entry type, loaded into AccountsDb.hard_forks and consumed by getHashData
/// (bank-hash mixin) + computeLastRestartSlot (LastRestartSlot sysvar).
pub const HardFork = @import("vex_store").snapshot_manifest.HardFork;
const rewards_mod = @import("rewards.zig");
const overlay_lookup = @import("overlay_lookup.zig");

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Incinerator address — lamports sent here are burned.
/// @prov:bank.incinerator — "1nc1nerator11111111111111111111111111111111"
const INCINERATOR: [32]u8 = .{
    0x07, 0x93, 0x6a, 0x08, 0xe1, 0xfa, 0xa7, 0x30,
    0x4a, 0x87, 0x40, 0xcd, 0xb0, 0xda, 0x3d, 0x04,
    0xdb, 0x7c, 0xe0, 0xa3, 0x7b, 0xf4, 0x9f, 0x9a,
    0xd4, 0x0f, 0x14, 0x1a, 0x00, 0x00, 0x00, 0x00,
};

/// SystemProgram owner pubkey (all zeros).
const SYSTEM_PROGRAM: [32]u8 = [_]u8{0} ** 32;

// [TOPVOTES-TRACE] TEMPORARY measurement (2026-07-09, branch
// fix/topvotes-freeze-sourced-refresh-2026-07-09): env-gated tracer
// (VEX_TOPVOTES_TRACE, default OFF, one cached bool) resolving the site1=0
// paradox — where do vote-account writes live at flush time vs freeze time?
// Counters + log lines ONLY; zero behavior change when off (one cached-bool
// branch); strip after the measurement session concludes.
pub const TvTrace = struct {
    /// 0=unchecked, 1=off, 2=on. Replay worker is the dominant caller; the
    /// first-call race is benign (getenv is idempotent).
    var state: u8 = 0;
    pub inline fn on() bool {
        if (state == 0) state = if (std.posix.getenv("VEX_TOPVOTES_TRACE") != null) 2 else 1;
        return state == 2;
    }
    /// Vote program id — copied VERBATIM from native/vote_program.zig:32
    /// VOTE_PROGRAM_ID (bank.zig avoids importing vote_program; the 8-byte
    /// prefix precedent is VOTE_PROG8 in freeze()). Not hand-typed.
    pub const VOTE_OWNER: [32]u8 = .{
        0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
        0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
        0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
        0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
    };
};

// ─────────────────────────────────────────────────────────────────────────────
// Block compute unit limits and cost constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum compute units per block.
///
/// @prov:cost-model.block-limit — d27cc (2026-05-11): bumped 48_000_000 →
/// 60_000_000 (SIMD-0256 activated as Agave's default). Observed at slot
/// 407737320 (carrier in 2026-05-11 d27bb run): Vexor sigs=915 vs
/// cluster sigs=931, exactly 16 txs dropped by the cost-tracker at the
/// 48M cap — this drops ~16-20 sigs in vote-heavy slots near the cap.
/// (Pre-existing latent bug independent of d27 catchup work — would
/// have shown up on any vote-heavy block, just rarely hit.)
///
/// Future: when SIMD-0286 activates (raises cap to 100M, currently
/// queued, no activation date), switch this to MAX_BLOCK_UNITS_SIMD_0286.
/// The clean port is to read from feature_set — left as a follow-up.
pub const MAX_BLOCK_COMPUTE_UNITS: u64 = 60_000_000;

// @prov:bank.no-vote-cu-sublimit — FIX #4 (2026-07-12): there is no separate vote
// compute-unit sub-limit any more; a simple-vote tx is judged by the SAME checks as
// any other tx, no separate ceiling. The former `MAX_VOTE_COMPUTE_UNITS` constant and
// its `block_vote_compute_units`-gated check below were a phantom sub-limit Agave
// doesn't have; both are REMOVED (not just left dormant — see
// `estimateTransactionCost`/`recordTransactionCost`). Mirrors the identical fix in
// cost_tracker.zig (the leader/producer-side CostTracker).

/// TEST-ONLY effective block-CU cap. UNSET (the production/voting default) → exactly
/// MAX_BLOCK_COMPUTE_UNITS, so every voting deploy is byte-identical. The override
/// (VEX_COST_CAP_OVERRIDE) exists ONLY for the #43 offline replay-parity gate: lowering the
/// cap forces estimateTransactionCost to return null (the cost-null "execute-regardless"
/// branch) on a KNOWN-bank-exact slot, proving the DAG/wave fix replays bank-exact even when
/// every tx trips the cap. SOUND to gate this way because block_compute_units is NOT part of
/// bank_hash — the cap drives only the (now pure-stat) cost aggregate, never a consensus value.
/// NEVER set this in a voting/production deploy. Cached once (single-threaded drain caller).
fn effectiveBlockCuCap() u64 {
    const S = struct {
        var cached: ?u64 = null;
    };
    if (S.cached) |c| return c;
    const v: u64 = blk: {
        const s = std.posix.getenv("VEX_COST_CAP_OVERRIDE") orelse break :blk MAX_BLOCK_COMPUTE_UNITS;
        break :blk std.fmt.parseInt(u64, s, 10) catch MAX_BLOCK_COMPUTE_UNITS;
    };
    S.cached = v;
    return v;
}

/// CU cost per transaction signature.
pub const SIGNATURE_COST: u64 = 720;

/// CU cost per writable account lock.
pub const WRITE_LOCK_UNITS: u64 = 300;

/// Instruction data bytes counted as 1 CU per this many bytes.
pub const INSTRUCTION_DATA_BYTES_PER_UNIT: u64 = 4;

// @prov:cost-model.loaded-accts — FIX #2 (2026-07-12): loaded-accounts-data-size cost,
// ABSENT before this fix (ceil-div bytes into pages, pages × DEFAULT_HEAP_COST). Vexor
// does not parse SetLoadedAccountsDataSizeLimit on this (replay-stat) path either, so
// every tx gets the DEFAULT term.
pub const ACCOUNT_DATA_COST_PAGE_SIZE: u64 = 32 * 1024;
pub const DEFAULT_HEAP_COST: u64 = 8;
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES: u64 = 64 * 1024 * 1024;
/// 64MiB / 32KiB = 2048 pages × 8 CU = 16,384 CU — the fixed default term every tx now carries.
pub const DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_COST: u64 = ((MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES + ACCOUNT_DATA_COST_PAGE_SIZE - 1) / ACCOUNT_DATA_COST_PAGE_SIZE) * DEFAULT_HEAP_COST;

/// Sysvar1111111111111111111111111111111111111 — owner of all sysvar accounts
const SYSVAR_OWNER: [32]u8 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0x75, 0xf7, 0x29,
    0xc7, 0x3d, 0x93, 0x40, 0x8f, 0x21, 0x61, 0x20,
    0x06, 0x7e, 0xd8, 0x8c, 0x76, 0xe0, 0x8c, 0x28,
    0x7f, 0xc1, 0x94, 0x60, 0x00, 0x00, 0x00, 0x00,
};

// r37-diag: per-sysvar byte-content probe for lthash carrier
// attribution. After r36-fix-e SECONDARY verdict (cap 60/60 + sig 60/60 +
// lthash 0/60), vex-109's vote_state vindication + vex-110's fee-collector
// vindication left per-slot sysvar DATA bytes as the highest-leverage
// remaining suspect. Coverage perfect, algorithm parity ruled out
// (Audit D), so divergence must be post-state DATA bytes of shared accounts.
//
// Emit format:
//   [PROBE-SYSVAR-BYTES] slot=N name=<NAME> sha256=<hex_64> first16=<hex_32> last16=<hex_32> len=<N>
//
// Compared to oracle-node RPC ground truth via getAccountInfo(<sysvar>, slot=N) →
// base64-decode → sha256 + first16 + last16 + len. First sysvar with
// byte-divergence at the same slot = lthash carrier class.
//
// Env-gated VEX_PROBE_SYSVAR_BYTES=1; bounded 50 emits/process (5 sysvars × ~10
// slots) to bound log size. Logic-additive only — no behavior change. Anti-
// regression: 21+ invariants intact (no edits to sysvar writers, only emits
// after the data buffer is finalized).
fn lookupStake(stakes: anytype, pubkey: [32]u8) u64 {
    for (stakes) |s| {
        if (std.mem.eql(u8, &s.vote_pubkey, &pubkey)) return s.stake;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
/// Epoch schedule parameters — determines epoch boundaries.
/// @prov:bank.epoch-schedule
///
/// FIX-2 (proactive-trio 2026-06-10): the struct now LIVES in
/// native/epoch_schedule.zig — a std-only LEAF module — so the standalone
/// test-module roots (test-vote-state-serde compiles
/// native/vote_state_serde.zig as its own root; test-fork-choice-feed
/// likewise) can import the canonical schedule without dragging bank.zig's
/// vex_crypto/build_options module deps or escaping their module path.
/// Re-exported here so every existing `bank_mod.EpochSchedule` call site
/// keeps working with IDENTICAL type identity. The canonical port (incl.
/// exact warmup math — previously `return 0` TODO stubs) lives there;
/// vex-058 lineage notes preserved in the leaf's doc comments.
pub const epoch_schedule_mod = @import("native/epoch_schedule.zig");
pub const EpochSchedule = epoch_schedule_mod.EpochSchedule;

// AccountWrite: a staged mutation before freeze
// ─────────────────────────────────────────────────────────────────────────────

pub const AccountWrite = struct {
    pubkey: Pubkey,
    lamports: u64,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,

    /// Pre-computed LtHash of the old state (before this write).
    /// null → this is a new account creation (old LtHash is zero).
    old_lt: ?LtHash = null,

    /// Pre-computed LtHash of the new state.
    /// null → compute lazily during freeze().
    new_lt: ?LtHash = null,
};

/// [LT-WRITE-LOCALIZER] (env VEX_VERIFY_LTHASH_WRITES) — per-changed-pubkey
/// capture of the EXACT lthash contribution freeze() applied to the
/// accounts_lthash accumulator, plus the (value-safe) state fields used to
/// compute it. NO account-data slice is captured here — that slice is freed
/// once `last_new_lt` is cached during freeze (rev1 UAF), so it must never be
/// touched post-freeze. The committed data digest is computed later from the
/// fork-aware readback (which is safe). Diagnostic-only; populated only when
/// the VEX_VERIFY_LTHASH_WRITES gate is on, so production pays zero cost.
pub const LtWriteCapture = struct {
    pubkey: [32]u8,
    applied_lt: LtHash,
    applied_lamports: u64,
    applied_owner: [32]u8,
    // [LT-OLD-LOCALIZER] the EXACT `first_old_lt` (the per-pubkey FIRST write's
    // pre-state LtHash) freeze() SUBTRACTED from the accumulator. Compared
    // post-flush in verifyLtHashWrites against the TRUE parent-state contribution
    // to catch the OLD-side stale-pre-state carrier. `had_old=false` means the
    // first write reported a null `old_lt` (newly-created account) — captured as
    // LtHash.init() so the OLD check still validates it against the parent read
    // (which is LtHash.init() for a genuinely-new account, mismatch otherwise).
    first_old_lt: LtHash,
    had_old: bool,
};

/// SB-2 RPC block/transaction-history capture (2026-06-17). One per executed transaction, captured
/// in block transaction order by the replay executor when `-Drpc_store` is built. `wire` is an
/// allocator-owned deep copy of the transaction's raw wire bytes (so it is independent of the
/// executor's per-slot batch arena, which is freed at slot end). Flushed into the RPC stores, then
/// freed, in `replayEntries`.
pub const CapturedTx = struct {
    signature: [64]u8,
    /// Fee-payer (first message account key) — indexed by getSignaturesForAddress.
    fee_payer: [32]u8,
    /// Base transaction fee (5000 × signature count). getBlock meta ONLY — NOT
    /// consensus (bank_hash excludes per-tx fee meta). Priority/precompile fees are
    /// an enrichment follow-up; base covers the vote-dominated steady state.
    fee: u64,
    wire: []u8,
    // ── SB-2 getBlock-meta enrichment (2026-06-21, cosmetic; populated AFTER execute) ──
    // All four are pure OBSERVATION of values the serial executor already computed in
    // block transaction order. They are written by `setLastRpcTxMeta` once per tx at the
    // END of its iteration (after the execute block + rollback), so `err`/`post_balances`
    // reflect the FINAL post-execution state — never read on the consensus path.
    //
    /// Per-tx execution outcome. null ⇒ success (no genuine InstructionError captured).
    /// Maps the serial loop's `tx_fail_serial` to the block_store TxError shape.
    err: ?block_store_mod.TxError = null,
    /// Metered compute units consumed. ALWAYS null today — the dispatch path
    /// (`dispatchBpfExecution`/native handlers) returns `!void` and does not thread
    /// consumed CU back to the replay loop; capturing the cost-model budget here would
    /// be a WRONG number, so we honestly emit null (follow-up: thread the meter out).
    compute_units_consumed: ?u64 = null,
    // ── Q2 content-path expansion (2026-06-25): @prov:bank.rpc-tx-meta full TransactionStatusMeta inputs ──
    // Populated by setRpcTxAccounts() from the serial executor (block-tx order). All owned
    // (allocator.dupe), freed beside `wire`. Empty/0 ⇒ not captured (null-omit on the RPC
    // read path — proto3 default-omit; never a WRONG value). DORMANT on the live deploy:
    // captureRpcTx early-returns unless VEX_RPC_STORE or VEX_LEDGER_CONTENT is set (zero
    // voting-path overhead when content capture is off).
    //
    /// ALL transaction account keys in canonical account-index order (static message
    /// keys first; then ALT-loaded writable; then ALT-loaded readonly). pre/post_balances
    /// are PARALLEL to this. Empty ⇒ not captured. @prov:bank.rpc-tx-meta
    account_keys: [][32]u8 = &[_][32]u8{},
    /// Count of STATIC (message) account keys: account_keys[0..static_account_keys_len] are
    /// the message keys (message.accountKeys); the remainder are ALT-loaded.
    static_account_keys_len: u32 = 0,
    /// Count of ALT-loaded WRITABLE addresses. Splits the loaded portion into two separate
    /// vectors — loaded_writable_addresses vs loaded_readonly_addresses — per
    /// @prov:bank.rpc-tx-meta: writable = account_keys[static_account_keys_len .. static_account_keys_len+
    /// num_loaded_writable]; readonly = account_keys[static_account_keys_len+num_loaded_writable ..].
    num_loaded_writable: u32 = 0,
    /// Message header counts — let the RPC reader reconstruct STATIC-key writable flags
    /// (message.accountKeys) without re-parsing the wire.
    num_required_signatures: u8 = 0,
    num_readonly_signed_accounts: u8 = 0,
    num_readonly_unsigned_accounts: u8 = 0,
    /// FULL per-account lamports BEFORE / AFTER execution, PARALLEL to `account_keys`.
    /// @prov:bank.rpc-tx-meta — OWNED slices, freed beside `wire`. Empty ⇒ not
    /// captured. (Supersedes the old length-1 fee-payer-only semantics — now full-vector
    /// or empty; index i corresponds to account_keys[i].)
    pre_balances: []u64 = &[_]u64{},
    post_balances: []u64 = &[_]u64{},
};

// ─────────────────────────────────────────────────────────────────────────────
// vex-048c — writes-redirect plumbing
// ─────────────────────────────────────────────────────────────────────────────
//
// `worker_writes_override` is a thread-local pointer that, when non-null,
// redirects `Bank.collectWrite()` into a per-worker `AccountWrite` buffer
// instead of `bank.pending_writes`. Enables concurrent parallel-SVM dispatch
// in vex-048d without multiple workers racing on the shared bank list.
//
// Contract:
//   - null → writes go to `self.pending_writes` (current behaviour, byte-identical).
//   - non-null → writes go to `worker_writes_override.*`. Caller owns init/deinit,
//     MUST use `bank.allocator` as the storage allocator (per
//     vault/bugs/pending-writes-lifetime.md — AccountWrite.data slices are
//     allocated with bank.allocator inside executors and must outlive the
//     frame they're merged into).
//
// Set/unset in pairs around a dispatch region:
//     bank_mod.worker_writes_override = &ctx.writes;
//     defer bank_mod.worker_writes_override = null;
//     execute*(...);  // writes flow to ctx.writes
//
// Orchestrator merges ctx.writes → bank.pending_writes after the barrier
// using `appendSlice` on `bank.allocator`. Concurrent dispatch + the merge
// path are vex-048d scope; vex-048c ships plumbing only with flag OFF.
pub threadlocal var worker_writes_override: ?*std.ArrayListUnmanaged(AccountWrite) = null;

// [WRITESET-FULL] bound: emit per-pubkey dumps for the first 500 frozen slots
// after boot. Bumped from 30 because first-divergent slot varies by boot
// (anchor-state-dependent carrier: anchor+14 on one boot, anchor+82 on another).
// 500 covers the typical window where the iter-6 fork-iso fingerprint surfaces.
// Bridge-rip removed the original counter; this is a minimal diagnostic
// re-introduction gated by VEX_WRITESET_FULL=1.
var writeset_full_counter: std.atomic.Value(u32) = std.atomic.Value(u32).init(500);

// ─────────────────────────────────────────────────────────────────────────────
// Bank
// ─────────────────────────────────────────────────────────────────────────────

/// d28ss (2026-05-12): provenance tag for `Bank.block_id`. Drives the
/// trust-regime decision for SIMD-0340 ENFORCE promotion (Item 1).
///   - `manifest`           = cluster-canonical (snapshot tail Hypothesis-B)
///   - `replayed_last_fec`  = derived from this slot's own last-FEC merkle
///                            root at freeze time
///   - `d28oo_first_shred`  = adopted from first child-slot leader's
///                            chained_root claim. UNTRUSTED — could be a
///                            forked leader. ENFORCE on this provenance is
///                            unsafe (would mark cluster-canonical slots
///                            dead vs a forked anchor).
///   - `none`               = unset (genesis / pre-snapshot)
pub const BlockIdSource = enum(u8) {
    none = 0,
    manifest = 1,
    replayed_last_fec = 2,
    d28oo_first_shred = 3,
    /// PR-5av Phase 1 (2026-05-22): block_id set from cluster tower
    /// confirmation BEFORE local shred set has been received.
    /// @prov:bank.block-id-tower-confirmed — when this is the source, the bank may be a
    /// sentinel: local replay has not happened yet, but cluster has
    /// already confirmed the canonical block_id for this slot.
    cluster_tower_confirmed = 4,
    /// 2026-06-19 (leader_mode): block_id fed forward from OUR OWN produced slot's
    /// last-FEC merkle root (computed at produce time, stashed in self_produced_block_id),
    /// so the next slot of our leader window can chain. No received shreds exist for a
    /// self-produced loopback slot, so this is the only block_id source for it. Non-consensus
    /// (block_id is the chained-root source, never a bank_hash input).
    self_produced = 5,
};

pub const Bank = struct {
    allocator: std.mem.Allocator,

    /// Slot number this bank covers.
    slot: u64,

    /// Parent slot (null only for genesis).
    parent_slot: ?u64,

    /// PR-S1.5 (2026-05-15): ancestor chain (parent → grandparent → … → root),
    /// owned by the bank and populated once per slot by `setAncestors` at the
    /// top of `replayBlock`. Every fork-aware read into AccountsDb
    /// (`getAccountInSlot`) takes this slice. Capacity 64 covers >2× typical
    /// tower depth; populated portion is `ancestors_buf[0..ancestors_len]`.
    ancestors_buf: [ANCESTORS_CAP]u64 = .{0} ** ANCESTORS_CAP,
    ancestors_len: u16 = 0,

    /// Previous bank's confirmed hash — fed into SHA256 first step.
    parent_hash: Hash,

    /// PoH hash of the LAST ENTRY in this slot's entry stream.
    /// @prov:bank.hash-calc — this is the `last_blockhash` input to computeBankHash().
    /// CRITICAL: must be set from the entry stream, NOT from transaction.recent_blockhash.
    poh_hash: Hash,

    /// task #28 / verify_ticks canonical (feat/verify-ticks-canonical-zig-2026-06-19):
    /// PoH cadence params. @prov:bank.poh-cadence — populated at bank construction
    /// from the snapshot manifest's EFFECTIVE values (NOT genesis). Used ONLY by the
    /// gated `verify_ticks` block tick-validity check in replay_stage.zig.
    ///
    /// `hashes_per_tick` faithfully mirrors the reference `hashes_per_tick().unwrap_or(0)`:
    /// 0 means hashing disabled / low-power → the verify_ticks hash-count checks are
    /// SKIPPED. The live testnet effective value is 62500. Default 0 here so a default
    /// (verify_ticks .off) build that never populates this field is byte-identical to today.
    hashes_per_tick: u64 = 0,
    /// @prov:bank.poh-cadence — DEFAULT_TICKS_PER_SLOT = 64 (mainnet/testnet).
    ticks_per_slot: u64 = 64,

    /// Number of transaction signatures in this slot's entries. @prov:bank.signature-count
    signature_count: u64,

    /// CONSENSUS-CRITICAL fee-rate governor (epoch-979 "tip carrier" fix). The
    /// `lamports_per_signature` stored into the RecentBlockhashes sysvar each
    /// slot is `fee_rate_governor.lamports_per_signature`, DERIVED per-slot from
    /// the parent's governor + the parent's `signature_count` via
    /// `FeeRateGovernor.newDerived`. @prov:fees.lamports-per-sig — carried across slots the
    /// same way `recent_blockhashes` is — value-copied + re-derived from the
    /// parent at child-bank creation (replay_stage.zig getOrCreateBank, adjacent
    /// to the `recent_blockhashes` inheritance). The ROOT bank's governor is
    /// seeded from the snapshot manifest at bootstrap. Default `.{}` so the
    /// Bank-pool `reset` (`self.* = .{...}`) recycles cleanly (POD, no heap).
    fee_rate_governor: @import("blockhash_queue.zig").FeeRateGovernor = .{},

    /// Computed bank hash (set by freeze(), zero before that).
    bank_hash: Hash,

    /// Running accounts LtHash accumulator.
    /// Inherited from parent; updated per-account write via applyLtHashDelta().
    accounts_lthash: LtHash,

    /// SIMD-0340 (d28ll): 32-byte block_id = this slot's last shred merkle
    /// root. Populated by replay_stage at freeze time from
    /// `SlotAssembly.checkLastFecSet32().ok`. Child slots verify their stored
    /// `chained_merkle_root` against the PARENT bank's `block_id` before
    /// freezing; mismatch = orphaned fork (cluster will mark dead).
    /// `null` for the snapshot anchor (no shred set to derive from) — child
    /// of snapshot anchor falls through SIMD-0340 check via the
    /// `Unavailable→Pass` branch. @prov:bank.block-id-unavailable-pass
    block_id: ?[32]u8 = null,

    /// d28ss (2026-05-12): provenance for `block_id` — see top-level
    /// `BlockIdSource` enum. Required for the safe-ENFORCE decision
    /// at the freeze-time SIMD-0340 gate.
    block_id_source: BlockIdSource = .none,

    /// Pending account writes staged for this slot.
    /// Deduplicated during freeze() — last write per pubkey wins.
    pending_writes: std.ArrayListUnmanaged(AccountWrite),

    /// [LT-WRITE-LOCALIZER] (env VEX_VERIFY_LTHASH_WRITES) per-slot capture of
    /// the exact lthash contributions applied during free() Pass C. Default-
    /// empty; only appended-to when the gate is on, then read post-flush by
    /// AccountsDb.verifyLtHashWrites. Cleared per slot before the Pass-C loop.
    lt_write_capture: std.ArrayListUnmanaged(LtWriteCapture) = .{},

    // [TOPVOTES-TRACE] TEMPORARY measurement counters (see TvTrace at file top).
    // Plain u32: the trace run is serial (VEX_PARALLEL_EXEC=0); bumped only when
    // TvTrace.on(). Never read by replay/consensus logic — log-emit only at freeze.
    tvt_vote_collect: u32 = 0, // collectWrite calls with vote-program owner
    tvt_vote_collect_ovr: u32 = 0, // ...of those, routed to worker_writes_override
    tvt_vote_exec_entries: u32 = 0, // executeVoteInstruction entries for this bank
    tvt_vote_exec_ok: u32 = 0, // ...that reached vote-state commit (VoteDbg.ok)
    tvt_vote_rolled_fail: u32 = 0, // vote-owned writes dropped by rollbackFailedTxWrites
    tvt_vote_rolled_tramp: u32 = 0, // vote-owned writes rolled back by the V2 trampoline capture
    tvt_flush_calls: u32 = 0, // flushPendingWritesToDb calls for this bank
    // [TOPVOTES-TRACE] die-point localization (2nd trace run): WHERE inside
    // executeVoteInstruction do vote txs stop producing writes?
    tvt_vote_no_acct: u32 = 0, // pre-Sig early return: vote account READ MISS (stale-read suspect)
    tvt_vote_pre3: u32 = 0, // pre-Sig early returns: no_data + bad_acct_idx + bad_size
    tvt_vote_sig_called: u32 = 0, // reached the executeVoteViaVoteforge call
    tvt_vote_mutate_fail: u32 = 0, // VoteDbg.mutate_fail delta across the Sig call
    tvt_vote_append_fail: u32 = 0, // VoteDbg.append_fail delta across the Sig call

    // [TOPVOTES-TRACE] ATOMIC die-point counters (3rd trace run, 2026-07-09):
    // the plain-u32 set above proved racy on the vote-exec path (observed
    // sig_called > exec_entries, impossible per-call same-object => lost
    // updates => concurrent execution). These use fetchAdd(.monotonic) so the
    // per-slot attribution is exact. TEMPORARY — strip with the rest of TvTrace.
    tvt2_site_worker: std.atomic.Value(u32) = .init(0), // call site parallelWorkerFn (rs:~308, documented dead)
    tvt2_site_dag: std.atomic.Value(u32) = .init(0), // call site executeDagTx vote branch (rs:~6861)
    tvt2_site_serial: std.atomic.Value(u32) = .init(0), // call site replayEntriesInternal serial loop (rs:~8585)
    tvt2_site_tramp: std.atomic.Value(u32) = .init(0), // call site V2 trampoline .vote fallback (id:~1124)
    tvt2_dag_from_serial_drain: std.atomic.Value(u32) = .init(0), // executeDagTx caller rs:~8103 (DAG serial drain)
    tvt2_dag_from_wave: std.atomic.Value(u32) = .init(0), // executeDagTx caller waveCb rs:~10564 (wave worker)
    tvt2_dag_from_shadow: std.atomic.Value(u32) = .init(0), // executeDagTx callers rs:~7070/7131 (wave shadow-verify)
    tvt2_dag_from_blockdag: std.atomic.Value(u32) = .init(0), // executeDagTx caller rs:~8918
    tvt2_vread_db: std.atomic.Value(u32) = .init(0), // vote-acct pre-read: getAccountInSlot hit
    tvt2_vread_overlay: std.atomic.Value(u32) = .init(0), // vote-acct pre-read: overlayNewest hit (overrides db)
    tvt2_vread_ovr_armed: std.atomic.Value(u32) = .init(0), // worker_writes_override != null at vote pre-read
    tvt2_enter: std.atomic.Value(u32) = .init(0), // executeVoteViaVoteforge entered
    tvt2_build_done: std.atomic.Value(u32) = .init(0), // account-build loop completed
    tvt2_ret_tc: std.atomic.Value(u32) = .init(0), // early return: tc_accounts alloc fail
    tvt2_ret_pre: std.atomic.Value(u32) = .init(0), // early return: pre alloc fail
    tvt2_ret_dupe: std.atomic.Value(u32) = .init(0), // early return: writable data dupe fail
    tvt2_ret_pdupe: std.atomic.Value(u32) = .init(0), // early return: pre-bytes dupe fail
    tvt2_ret_metas: std.atomic.Value(u32) = .init(0), // early return: account_metas append fail
    tvt2_exec_enter: std.atomic.Value(u32) = .init(0), // voteforge dispatch about to be called
    tvt2_exec_ok: std.atomic.Value(u32) = .init(0), // voteforge dispatch returned success
    tvt2_exec_err_oom: std.atomic.Value(u32) = .init(0), // voteforge dispatch OutOfMemory (swallowed)
    tvt2_exec_err_sysvar: std.atomic.Value(u32) = .init(0), // voteforge dispatch UnsupportedSysvar (swallowed)
    tvt2_exec_err_other: std.atomic.Value(u32) = .init(0), // voteforge dispatch genuine InstructionError (propagates)
    tvt2_diff_writable: std.atomic.Value(u32) = .init(0), // diff loop: writable accounts examined
    tvt2_diff_applied: std.atomic.Value(u32) = .init(0), // diff loop: changed -> collectWrite committed
    tvt2_diff_skip_eq: std.atomic.Value(u32) = .init(0), // diff loop: post==pre, skipped
    tvt2_appfail: std.atomic.Value(u32) = .init(0), // diff loop: collectWrite failed
    tvt2_probe_done: std.atomic.Value(u32) = .init(0), // per-slot one-shot voteix probe latch
    tvt2_errprobe_done: std.atomic.Value(u32) = .init(0), // per-slot one-shot voteerr probe latch

    /// SB-2 RPC block/transaction-history capture (2026-06-17). Per-slot, per-transaction
    /// (signature, fee-payer key, raw wire bytes) captured IN-LOOP by the executor (both serial and
    /// DAG dispatch paths), in block transaction order. Flushed to the RPC BlockStore/TxStatusStore in
    /// `replayEntries` after the slot replays. COMPTIME-CONDITIONAL on `-Drpc_store`: when the flag is
    /// OFF the field is `void` (zero size, zero codegen) so the consensus path is byte-identical; when
    /// ON it is a per-slot owned list. Bank-owned ⇒ no cross-slot race even if `replayWorker` runs
    /// slots concurrently. Each entry's `wire`/`signature` are deep-copied at capture (independent of
    /// the executor's batch arena lifetime); freed in `deinit` and after the flush.
    rpc_tx_capture: if (build_options.rpc_store or build_options.vex_ledger) std.ArrayListUnmanaged(CapturedTx) else void =
        if (build_options.rpc_store or build_options.vex_ledger) .{} else {},

    /// Execution fees collected this slot (50% burned, 50% to leader).
    /// @prov:bank.fee-collector-fields
    execution_fees: u64,

    /// Priority fees collected this slot (100% to leader, 0% burned).
    /// @prov:bank.fee-collector-fields
    priority_fees: u64,

    /// Leader identity pubkey for fee distribution. @prov:bank.fee-collector-fields
    /// Must be set before freeze() is called.
    collector_id: Pubkey,

    /// Whether this bank has been frozen (hash committed).
    is_frozen: bool,

    /// PR-5av Phase 1 (2026-05-22): chain-confirmation status.
    /// True once this bank's `block_id` has been verified to chain to a
    /// confirmed ancestor via single-step CMR check. @prov:bank.chain-confirmed
    /// (see `vault/SENTINEL_NODE_DESIGN_RESEARCH.md` §3). Distinct from
    /// `is_frozen`: a bank can be frozen locally but not yet
    /// chain_confirmed against cluster's canonical chain.
    /// Wired in Phase 5; field declared here so the struct shape is
    /// stable across the multi-phase port.
    chain_confirmed: bool = false,

    /// PR-5av Phase 3/4 (2026-05-22): true when this bank is a sentinel —
    /// a placeholder created during shred-defer when parent is unconnected.
    /// Sentinels have parent_slot=null, identity LtHash, zero parent_hash,
    /// and is_frozen=false. They occupy a slot in self.banks + self.subtrees
    /// so Phase 6's relaxed death sentence can consult subtrees, but they
    /// are NEVER returned by getOrCreateBank's fast path — getOrCreateBank
    /// tears them down so a real bank with proper ancestry can take over.
    is_sentinel: bool = false,

    /// CARRIER #7 FIX (2026-06-23): complete INHERITED proper-ancestor set —
    /// Agave bank.rs:1420-1425 parity (`child.ancestors = {parent.slot} ∪
    /// parent.proper_ancestors`, filtered > rooted_slot). Consumed by the tower
    /// lockout ancestry check (replay_stage.zig vote site → tower.isLockedOut)
    /// INSTEAD of the gap-fragile `ancestorChainComplete` parent-walk, which
    /// truncated at a live sentinel bank (parent_slot=null) → `last_vote`
    /// misclassified non-ancestor → false cross-fork lockout → sustained
    /// delinquency (carrier #7, 2026-06-23 @417317107). Built ONCE in
    /// getOrCreateBank from the verified-frozen parent (`ancestor` there is
    /// never a sentinel). A FIXED ARRAY, not a managed list: Bank.reset does
    /// `self.* = .{...}` (recycled on the pool hot path) which would LEAK a heap
    /// list — the fixed array + defaulted len/overflow reset cleanly. On the rare
    /// deep-catch-up overflow (>512 unrooted, where we do not vote), the vote
    /// site falls back to the legacy walk (no regression). PRESERVES carrier-7
    /// safety by construction: only ever ADDS true ancestors, never invents one.
    proper_ancestors: [512]u64 = undefined,
    proper_ancestors_len: u16 = 0,
    proper_ancestors_overflow: bool = false,

    /// Whether this bank received any real entries (not a ghost bank).
    has_entries: bool,

    /// Epoch schedule parameters. @prov:bank.epoch-schedule
    epoch_schedule: EpochSchedule = EpochSchedule.DEFAULT,

    /// Recent blockhashes queue (max 150 entries, newest at end).
    /// Used for RecentBlockhashes sysvar serialization.
    recent_blockhashes: RecentBlockhashQueue,

    /// Optional AccountsDb reference for loading accounts during execution.
    /// Set by replay stage after bootstrap. Cluster-wide state (vote-account
    /// stakes + Clock epoch anchor) rides along on this DB so every child
    /// bank inherits them without explicit per-slot propagation.
    accounts_db: ?*@import("vex_store").accounts.AccountsDb = null,

    // ── Partitioned epoch rewards state ── @prov:bank.epoch-rewards-partition ──
    // Persists across slots during the reward distribution window.

    /// Computed stake reward partitions from RewardsCalculator.
    /// partitions[i] is distributed at block_height = distribution_starting_block_height + i.
    /// Owned by the Bank that processes the epoch boundary; freed when distribution completes.
    stake_reward_partitions: ?[]rewards_mod.StakePartition = null,

    /// Whether this bank OWNS the stake_reward_partitions memory and should free it.
    /// Set to true only in processEpochBoundary() when partitions are created.
    /// Child banks inherit the slice pointer (for distribution) but NOT ownership.
    owns_stake_reward_partitions: bool = false,

    /// Block height at which stake reward distribution begins.
    /// @prov:bank.epoch-rewards-partition
    distribution_starting_block_height: u64 = 0,

    /// Number of partitions (== stake_reward_partitions.len).
    num_reward_partitions: u32 = 0,

    /// Whether epoch rewards are currently being distributed.
    /// @prov:bank.epoch-rewards-partition
    epoch_rewards_active: bool = false,

    /// Total stake rewards to distribute (sum of all staker_rewards across partitions).
    total_stake_rewards: u64 = 0,

    /// Cumulative stake rewards distributed so far.
    distributed_rewards: u64 = 0,

    /// Total vote rewards distributed immediately at epoch boundary.
    vote_rewards_distributed: u64 = 0,

    /// Parent blockhash at epoch boundary (for EpochRewards sysvar).
    /// carrier #16 (@414812256): this is the parent's POH BLOCKHASH
    /// (Agave bank.last_blockhash() at new_from_parent = blockhash_queue head),
    /// NOT the parent's bank_hash. Vexor pre-fix wrote self.parent_hash
    /// (bank_hash da5f94fd… at the 973 boundary) where the cluster's canonical
    /// sysvar carried 49cfff1b… = the parent's poh hash — byte-proven from our
    /// own [BANK-FROZEN] 414812255 poh= line matching details(414812256).
    epoch_reward_parent_blockhash: Hash = Hash.ZERO,

    /// Total reward points (u128) for EpochRewards sysvar.
    epoch_reward_total_points: u128 = 0,

    /// carrier #16: EpochRewards.total_rewards must be point_value.rewards —
    /// the FULL epoch validator-rewards budget from inflation
    /// (calculator.summary.validator_rewards). @prov:bank.epoch-rewards-total —
    /// asserted >= the distributed parts — NOT the reconstructed sum
    /// total_stake_rewards+vote_rewards (diverges by every truncation burn in
    /// redeemRewards).
    epoch_reward_total_rewards: u64 = 0,

    /// Block height for this slot (distinct from slot — skipped slots don't increment).
    block_height: u64 = 0,

    /// Total lamport supply at this slot (capitalization).
    /// Loaded from snapshot manifest at bootstrap.
    /// Used for accurate inflation reward calculations at epoch boundary.
    capitalization: u64 = 0,

    /// Accumulated compute units consumed this slot (block-level CU budget tracking).
    block_compute_units: u64 = 0,
    // @prov:bank.no-vote-cu-sublimit — no `block_vote_compute_units` to accumulate against
    // (see the MAX_BLOCK_COMPUTE_UNITS-block comment near the top of this file).

    /// A blockhash + fee calculator entry for the RecentBlockhashes sysvar.
    pub const BlockhashEntry = struct {
        blockhash: Hash,
        lamports_per_signature: u64,
    };

    /// Bounded queue of recent blockhashes (max 150). @prov:bank.recent-blockhashes-queue
    pub const RecentBlockhashQueue = struct {
        buffer: [150]BlockhashEntry = undefined,
        len: usize = 0,

        pub fn push(self: *RecentBlockhashQueue, entry: BlockhashEntry) void {
            if (self.len >= 150) {
                // Remove oldest (index 0), shift left
                std.mem.copyForwards(BlockhashEntry, self.buffer[0..149], self.buffer[1..150]);
                self.buffer[149] = entry;
            } else {
                self.buffer[self.len] = entry;
                self.len += 1;
            }
        }

        pub fn constSlice(self: *const RecentBlockhashQueue) []const BlockhashEntry {
            return self.buffer[0..self.len];
        }
    };

    const Self = @This();

    // ─────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    /// d27f (2026-05-11): reset an existing Bank to fresh per-slot state.
    /// Used by ReplayStage's Bank pool to recycle banks without going
    /// through the global allocator on the hot path. The previous bank
    /// state must already be cleaned up (pending_writes cleared,
    /// stake_reward_partitions freed) by the caller before calling reset.
    pub fn reset(
        self: *Self,
        slot: u64,
        parent_slot: ?u64,
        parent_hash: Hash,
        parent_lthash: LtHash,
        parent_poh_hash: Hash,
    ) void {
        // Preserve `self.allocator`. Overwrite everything else with init defaults.
        const alloc = self.allocator;
        self.* = .{
            .allocator = alloc,
            .slot = slot,
            .parent_slot = parent_slot,
            .parent_hash = parent_hash,
            .poh_hash = parent_poh_hash,
            // verify_ticks: reset to defaults; re-populated by acquireBank when gated.
            .hashes_per_tick = 0,
            .ticks_per_slot = 64,
            .signature_count = 0,
            // fee_rate_governor: reset to defaults; the cross-slot value is
            // re-derived from the parent in getOrCreateBank (mirrors how
            // recent_blockhashes is inherited there).
            .fee_rate_governor = .{},
            .bank_hash = Hash.default(),
            .accounts_lthash = parent_lthash,
            .pending_writes = .{},
            .execution_fees = 0,
            .priority_fees = 0,
            .collector_id = Pubkey.default(),
            .is_frozen = false,
            .has_entries = false,
            .recent_blockhashes = .{},
        };
    }

    pub fn init(
        allocator: std.mem.Allocator,
        slot: u64,
        parent_slot: ?u64,
        parent_hash: Hash,
        parent_lthash: LtHash,
        parent_poh_hash: Hash,
    ) !*Self {
        const bi_t0 = std.time.milliTimestamp();
        const bank = try allocator.create(Self);
        const bi_t1 = std.time.milliTimestamp();
        bank.* = .{
            .allocator = allocator,
            .slot = slot,
            .parent_slot = parent_slot,
            .parent_hash = parent_hash,
            // r66: inherit parent's poh_hash. Used as the slot's poh_hash for
            // bank_hash composition unless overridden during entry replay
            // (replay_stage.zig:2191 sets it from last entry). When the slot
            // has zero entries (skipped, parse-fail, etc.) this inherited
            // value remains, matching Agave's external PoH service which
            // ticks unbroken across empty slots. Without this inheritance
            // empty slots produced bank.poh_hash=Hash.default()=0, cascading
            // wrong bank_hash through parent_hash chain to all subsequent
            // slots — the carrier of 100% bank_hash divergence we chased
            // for ~6 weeks.
            .poh_hash = parent_poh_hash,
            // verify_ticks: default PoH cadence (0 = disabled-skip, 64 ticks/slot).
            // Populated from the snapshot manifest by ReplayStage.acquireBank /
            // bootstrap when the gate is active; leaving the defaults makes a
            // default (verify_ticks .off) build byte-identical.
            .hashes_per_tick = 0,
            .ticks_per_slot = 64,
            .signature_count = 0,
            // fee_rate_governor: default; cross-slot value re-derived from the
            // parent in getOrCreateBank (mirrors recent_blockhashes inheritance).
            .fee_rate_governor = .{},
            .bank_hash = Hash.default(),
            .accounts_lthash = parent_lthash,
            .pending_writes = .{},
            .execution_fees = 0,
            .priority_fees = 0,
            .collector_id = Pubkey.default(),
            .is_frozen = false,
            .has_entries = false,
            .recent_blockhashes = .{},
        };
        const bi_t2 = std.time.milliTimestamp();
        if (bi_t2 - bi_t0 > 50) {
            std.log.warn(
                "[BANK-INIT-SLOW] slot={d} total={d}ms create={d} structInit={d}",
                .{ slot, bi_t2 - bi_t0, bi_t1 - bi_t0, bi_t2 - bi_t1 },
            );
        }
        return bank;
    }

    pub fn deinit(self: *Self) void {
        self.pending_writes.deinit(self.allocator);
        self.lt_write_capture.deinit(self.allocator); // [LT-WRITE-LOCALIZER]
        if (comptime build_options.rpc_store or build_options.vex_ledger) {
            for (self.rpc_tx_capture.items) |c| {
                self.allocator.free(c.wire);
                if (c.account_keys.len != 0) self.allocator.free(c.account_keys);
                if (c.pre_balances.len != 0) self.allocator.free(c.pre_balances);
                if (c.post_balances.len != 0) self.allocator.free(c.post_balances);
            }
            self.rpc_tx_capture.deinit(self.allocator);
        }
        self.freeStakeRewardPartitions();
        self.allocator.destroy(self);
    }

    /// Cached process-wide RPC-capture gate. Capture is ACTIVE only when VEX_RPC_STORE (SB-2 block
    /// store) or VEX_LEDGER_CONTENT (Q2 VexLedger getBlock/getTransaction content) is set — so a
    /// -Dvex_ledger voting deploy with content OFF pays ZERO per-tx capture overhead (read once, cached).
    var rpc_capture_active_cache: ?bool = null;
    fn rpcCaptureActive() bool {
        return rpc_capture_active_cache orelse blk: {
            const v = (std.posix.getenv("VEX_RPC_STORE") != null) or (std.posix.getenv("VEX_LEDGER_CONTENT") != null);
            rpc_capture_active_cache = v;
            break :blk v;
        };
    }

    /// Q2 (2026-06-25): public, STRICT VEX_LEDGER_CONTENT gate for the VexLedger getBlock/getTransaction
    /// content-population path (separate from rpcCaptureActive(), which ALSO fires for VEX_RPC_STORE). The
    /// serial executor keys its VexLedger writes (putTransactionWire/putSlotSignature/putTransactionStatus/
    /// putAddressSignature) off this so they fire ONLY when content capture is explicitly requested. Read
    /// once, cached. When OFF (neither env set), the whole capture path is dormant → consensus unaffected.
    var content_capture_active_cache: ?bool = null;
    pub fn contentCaptureActive() bool {
        return content_capture_active_cache orelse blk: {
            const v = std.posix.getenv("VEX_LEDGER_CONTENT") != null;
            content_capture_active_cache = v;
            break :blk v;
        };
    }

    /// Q2 population (2026-06-25): attach the full account-key-parallel meta — account_keys (canonical
    /// order, @prov:bank.rpc-tx-meta) + message header counts + FULL pre/post balance vectors — to a captured tx, by the
    /// index from captureRpcTx. Companion to setLastRpcTxMeta (err/CU). COMPTIME no-op when the gate is
    /// off; pure OBSERVATION (never touches accounts_db/pending_writes/lthash/bank_hash). All slices
    /// COPIED into owned storage (freed beside `wire`). Best-effort: dup OOM leaves a field empty
    /// (null-omit on the read path — proto3 default-omit, never a WRONG value). Idempotent (frees prior).
    pub fn setRpcTxAccounts(
        self: *Self,
        idx: usize,
        account_keys: []const [32]u8,
        static_account_keys_len: u32,
        num_loaded_writable: u32,
        num_required_signatures: u8,
        num_readonly_signed: u8,
        num_readonly_unsigned: u8,
        pre: []const u64,
        post: []const u64,
    ) void {
        if (comptime !(build_options.rpc_store or build_options.vex_ledger)) return;
        if (idx >= self.rpc_tx_capture.items.len) return;
        const c = &self.rpc_tx_capture.items[idx];
        if (c.account_keys.len != 0) self.allocator.free(c.account_keys);
        if (c.pre_balances.len != 0) self.allocator.free(c.pre_balances);
        if (c.post_balances.len != 0) self.allocator.free(c.post_balances);
        c.account_keys = self.allocator.dupe([32]u8, account_keys) catch &[_][32]u8{};
        c.static_account_keys_len = static_account_keys_len;
        c.num_loaded_writable = num_loaded_writable;
        c.num_required_signatures = num_required_signatures;
        c.num_readonly_signed_accounts = num_readonly_signed;
        c.num_readonly_unsigned_accounts = num_readonly_unsigned;
        c.pre_balances = if (pre.len != 0) (self.allocator.dupe(u64, pre) catch &[_]u64{}) else &[_]u64{};
        c.post_balances = if (post.len != 0) (self.allocator.dupe(u64, post) catch &[_]u64{}) else &[_]u64{};
    }

    /// SB-2 (2026-06-17): capture one executed transaction for the RPC history stores. COMPTIME no-op
    /// when `-Drpc_store` is OFF (the body is comptime-dead). Deep-copies `wire` so it survives the
    /// executor's batch arena. Called in block transaction order from BOTH executor paths. Capture
    /// failures (OOM) are swallowed — RPC history is best-effort and must NEVER perturb replay.
    ///
    /// Returns the index of the just-captured entry in `rpc_tx_capture` (so the serial executor can
    /// enrich it post-execution via `setLastRpcTxMeta`), or null when the gate is OFF / capture failed.
    pub fn captureRpcTx(self: *Self, signature: [64]u8, fee_payer: [32]u8, fee: u64, wire: []const u8) ?usize {
        if (comptime !(build_options.rpc_store or build_options.vex_ledger)) return null;
        if (!rpcCaptureActive()) return null; // runtime gate: VEX_RPC_STORE or VEX_LEDGER_CONTENT — zero overhead when off
        const copy = self.allocator.dupe(u8, wire) catch return null;
        self.rpc_tx_capture.append(self.allocator, .{
            .signature = signature,
            .fee_payer = fee_payer,
            .fee = fee,
            .wire = copy,
        }) catch {
            self.allocator.free(copy);
            return null;
        };
        return self.rpc_tx_capture.items.len - 1;
    }

    /// SB-2 getBlock-meta enrichment (2026-06-21): attach post-execution meta (err / consumed CU /
    /// fee-payer pre+post balances) to a previously-captured tx, identified by the index returned from
    /// `captureRpcTx`. COMPTIME no-op when `-Drpc_store` is OFF. Pure OBSERVATION — it reads values the
    /// serial executor already computed and writes ONLY into the bank-owned RPC capture list; it NEVER
    /// touches accounts_db / pending_writes / lthash / sigverify / voting, so bank_hash is unaffected.
    ///
    /// `pre`/`post` are COPIED into owned slices (freed beside `wire`). Pass empty slices to leave
    /// balances uncaptured. Best-effort: balance-dup OOM leaves balances empty (meta is cosmetic).
    pub fn setLastRpcTxMeta(
        self: *Self,
        idx: usize,
        err: ?block_store_mod.TxError,
        compute_units_consumed: ?u64,
        pre: []const u64,
        post: []const u64,
    ) void {
        if (comptime !(build_options.rpc_store or build_options.vex_ledger)) return;
        if (idx >= self.rpc_tx_capture.items.len) return;
        const c = &self.rpc_tx_capture.items[idx];
        c.err = err;
        c.compute_units_consumed = compute_units_consumed;
        // Replace any prior balance slices (idempotent if called twice) then deep-copy.
        if (c.pre_balances.len != 0) self.allocator.free(c.pre_balances);
        if (c.post_balances.len != 0) self.allocator.free(c.post_balances);
        c.pre_balances = &[_]u64{};
        c.post_balances = &[_]u64{};
        if (pre.len != 0) {
            c.pre_balances = self.allocator.dupe(u64, pre) catch &[_]u64{};
        }
        if (post.len != 0) {
            c.post_balances = self.allocator.dupe(u64, post) catch &[_]u64{};
        }
    }

    /// PR-S1.5: populate this bank's ancestor chain. Called once by replay_stage
    /// at the top of `replayBlock` after the parent walk completes. The slice
    /// is COPIED into the bank's owned buffer — caller's source can be a
    /// stack buffer with shorter lifetime.
    pub fn setAncestors(self: *Self, ancestor_slots: []const u64) void {
        const n = @min(ancestor_slots.len, self.ancestors_buf.len);
        @memcpy(self.ancestors_buf[0..n], ancestor_slots[0..n]);
        self.ancestors_len = @intCast(n);
    }

    /// PR-S1.5: ancestor chain visible to AccountsDb reads at this bank's slot.
    pub fn ancestors(self: *const Self) []const u64 {
        return self.ancestors_buf[0..self.ancestors_len];
    }

    /// vex-048c: route an `AccountWrite` to the thread's override buffer if set,
    /// otherwise to `self.pending_writes`. Always uses `self.allocator` so the
    /// `AccountWrite.data` slices (which live on bank.allocator) remain in
    /// matching ownership after barrier-merge.
    ///
    /// Serial path (override == null): byte-identical to prior
    /// `self.pending_writes.append(self.allocator, write)`.
    pub inline fn collectWrite(self: *Self, write: AccountWrite) !void {
        // RESIDUAL-HUNT dump fix (2026-07-02): when the freeze-dump gate is
        // armed (VEX_FREEZE_DUMP_SLOT / VEX_ISO_DUMP_SLOT), dump the write's
        // ACTUAL bytes NOW — the data buffer is guaranteed alive at write time.
        // The old freeze-time dump re-read via getAccountInSlot, which cannot
        // see THIS slot's un-flushed pending writes → it dumped NEW lamports +
        // OLD data (proven at 419132257: lt(dumped bytes) == the op=0 contrib,
        // not op=1). Multiple writes to one account emit multiple lines; the
        // LAST line per pubkey is the final state (consumers dedupe last-wins).
        // emitFreezeAccount self-gates on its dump-slot window; isEnabled() is
        // one relaxed atomic load on the hot path. Forensic-only.
        if (recorder.isEnabled()) {
            recorder.emitFreezeAccount(self.slot, &write.pubkey.data, write.lamports, &write.owner.data, write.executable, write.data);
        }
        // [TOPVOTES-TRACE] TEMPORARY measurement — count every vote-owner write
        // at the single collect chokepoint, plus its routing destination.
        if (TvTrace.on() and std.mem.eql(u8, &write.owner.data, &TvTrace.VOTE_OWNER)) {
            self.tvt_vote_collect += 1;
            if (worker_writes_override != null) self.tvt_vote_collect_ovr += 1;
        }
        if (worker_writes_override) |dest| {
            try dest.append(self.allocator, write);
        } else {
            try self.pending_writes.append(self.allocator, write);
        }
    }

    /// Parallel-exec Stage B / B2a — newest-first write-overlay lookup for executor
    /// reads. Scans `worker_writes_override` (the worker's own in-flight write buffer,
    /// if set) FIRST, then `self.pending_writes`, returning a pointer to the newest
    /// write entry matching `key` (or null → caller falls back to accounts_db). The
    /// caller reads fields / copies immediately (before any collectWrite) and keeps its
    /// existing copy/lifetime handling — this returns a pointer, never a flattened copy.
    ///
    /// Serial path (override == null): byte-IDENTICAL to the inline `pending_writes`
    /// newest-first scans executors do today (the empty-primary tier collapses to a
    /// pending-only scan — proven in overlay_lookup KAT). Parallel path: the override
    /// precedence makes a tx's own earlier-instruction writes visible to its later
    /// instructions (intra-tx read-after-write); the DAG (tx_dispatcher addEdges Case-3
    /// W-R + Step-4) guarantees no wave-sibling reads an account another sibling writes,
    /// so a worker only ever needs its OWN buffer + committed pending_writes.
    ///
    /// B2a ships this INERT (no caller yet); B2b converts the inline scan sites to it,
    /// one at a time, each a no-op when override == null.
    pub inline fn overlayNewest(self: *const Self, key: *const [32]u8) ?*const AccountWrite {
        const primary: []const AccountWrite = if (worker_writes_override) |ov| ov.items else &[_]AccountWrite{};
        return overlay_lookup.newestMatchTwo(AccountWrite, primary, self.pending_writes.items, key);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Block compute unit tracking
    // ─────────────────────────────────────────────────────────────────────────

    pub const TransactionCost = struct {
        total: u64,
        /// is_simple_vote_transaction — carried as metadata only. FIX #4: NOT consulted for any
        /// sub-limit check below. @prov:bank.no-vote-cu-sublimit
        is_vote: bool,
    };

    /// Estimate whether a transaction fits in the current block's CU budget.
    /// Returns the cost struct on success, null if block limits would be exceeded.
    ///
    /// Cost formula: sig_cost(720*sigs) + write_lock_cost(300*writable) +
    ///               data_cost(data_len/4) + compute_unit_limit +
    ///               loaded_accounts_data_size_cost(16,384 default — FIX #2)
    pub fn estimateTransactionCost(
        self: *const Self,
        num_signatures: u64,
        num_write_locks: u64,
        instruction_data_len: u64,
        compute_unit_limit: u64,
        is_vote: bool,
    ) ?TransactionCost {
        const sig_cost = num_signatures *| SIGNATURE_COST;
        const write_cost = num_write_locks *| WRITE_LOCK_UNITS;
        const data_cost = instruction_data_len / INSTRUCTION_DATA_BYTES_PER_UNIT;
        // FIX #2: loaded-accounts-data-size default term (see the constants-block comment above).
        const total = sig_cost +| write_cost +| data_cost +| compute_unit_limit +| DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_COST;

        // Block-level CU cap (effectiveBlockCuCap() == MAX_BLOCK_COMPUTE_UNITS unless the
        // test-only VEX_COST_CAP_OVERRIDE is set — production/voting is byte-identical).
        if (self.block_compute_units +| total > effectiveBlockCuCap()) {
            std.log.debug("[COST-MODEL] Block full at slot={d} block_cu={d}/{d} — transaction skipped\n", .{
                self.slot,
                self.block_compute_units,
                effectiveBlockCuCap(),
            });
            return null;
        }

        // @prov:bank.no-vote-cu-sublimit — `is_vote` is carried on the returned struct purely as
        // metadata and intentionally does not gate anything here.
        return .{ .total = total, .is_vote = is_vote };
    }

    /// Record a transaction's cost after it has been accepted for execution.
    pub fn recordTransactionCost(self: *Self, cost: TransactionCost) void {
        self.block_compute_units +|= cost.total;
        if (self.slot % 100 == 0) {
            const CostLog = struct { var last_slot: u64 = std.math.maxInt(u64); };
            if (CostLog.last_slot != self.slot) {
                CostLog.last_slot = self.slot;
                std.log.debug("[COST-MODEL] slot={d} block_cu={d}\n", .{
                    self.slot,
                    self.block_compute_units,
                });
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LtHash helpers — @prov:bank.lthash-account
    // ─────────────────────────────────────────────────────────────────────────

    /// Compute the LtHash contribution of a single account.
    ///
    /// @prov:bank.lthash-account
    ///
    /// Formula:
    ///   if lamports == 0 → return zero (deleted accounts don't contribute)
    ///   BLAKE3-2048( lamports_le || data || (executable & 0x1) || owner || pubkey )
    pub fn accountLtHash(
        pubkey: *const [32]u8,
        owner: *const [32]u8,
        lamports: u64,
        executable: bool,
        data: []const u8,
    ) LtHash {
        // Zero-lamport accounts are excluded. @prov:bank.lthash-account
        if (lamports == 0) return LtHash.init();

        const executable_flag: u8 = if (executable) 1 else 0; // @prov:bank.lthash-account

        // ITEM K: route the load-bearing accountLtHash BLAKE3 through the
        // vex_crypto.blake3 wrapper. With -Dballet_blake3=true this dispatches
        // to an AVX-512 implementation; otherwise (default) it stays
        // on stdlib. Boot-time KAT in vex_crypto/blake3.zig:runBalletSelfTest
        // proves byte-identical 2048-byte XOF output before any vote fires.
        var b3 = vex_crypto.blake3.Blake3.init(.{});
        var lamports_le: [8]u8 = undefined;
        std.mem.writeInt(u64, &lamports_le, lamports, .little);
        b3.update(&lamports_le);
        b3.update(data);
        b3.update(&[_]u8{executable_flag});
        b3.update(owner);
        b3.update(pubkey);

        var out: [2048]u8 = undefined;
        b3.final(&out);

        // Interpret 2048 bytes as 1024 × u16 (wrapping)
        var lt = LtHash.init();
        for (0..1024) |i| {
            lt.elements[i] = std.mem.readInt(u16, out[i * 2 ..][0..2], .little);
        }
        return lt;
    }

    /// Apply a single account write to the running LtHash accumulator.
    ///
    /// @prov:bank.lthash-delta
    ///
    /// lthash = lthash - lthash(old_state) + lthash(new_state)
    pub fn applyLtHashDelta(
        self: *Self,
        pubkey: *const [32]u8,
        owner: *const [32]u8,
        old_lamports: u64,
        new_lamports: u64,
        executable: bool,
        data: []const u8,
        old_data: []const u8,
    ) void {
        const old_lt = accountLtHash(pubkey, owner, old_lamports, executable, old_data);
        const new_lt = accountLtHash(pubkey, owner, new_lamports, executable, data);

        // Recorder-extension 2026-05-17 Tier-2: emit per-account lthash
        // contribution BEFORE the wrapping mix. Pure diagnostic — does not
        // change LtHash math (CLAUDE.md guarantee at lines 2864-2902).
        // For the 4.1% of vote-mismatches that are REAL bank_hash divergence,
        // diff'ing per-account contributions vs oracle-node pinpoints the exact
        // pubkey whose hash drifted.
        if (recorder.isEnabled()) {
            const old_prefix = std.mem.readInt(u64, old_lt.asBytes()[0..8], .big);
            const new_prefix = std.mem.readInt(u64, new_lt.asBytes()[0..8], .big);
            // op=0 → subtract (old), op=1 → add (new). Both emitted so we
            // see the full delta the slot applied to accounts_lthash.
            recorder.emitLtHashContribution(pubkey, old_prefix, 0);
            recorder.emitLtHashContribution(pubkey, new_prefix, 1);
        }

        self.accounts_lthash.wrappingSub(&old_lt);
        self.accounts_lthash.wrappingAdd(&new_lt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bank hash — @prov:bank.hash-calc
    // ─────────────────────────────────────────────────────────────────────────

    /// Compute the two-step SHA256 bank hash.
    ///
    /// @prov:bank.hash-calc
    ///
    /// Step 1: intermediate = SHA256(prev_bank_hash || signature_count_le || poh_hash)
    /// Step 2: bank_hash    = SHA256(intermediate || lthash_2048_bytes)
    /// F2 (HARD-FORK-FAMILY-DESIGN-2026-06-17): data to fold into the bank hash
    /// when a hard fork is scheduled in (parent_slot, slot]. @prov:bank.hard-fork-mixin
    ///   fork_count = Σ count where parent_slot < fork_slot AND slot >= fork_slot
    ///   Some((fork_count as u64).to_le_bytes()) if fork_count > 0 else None
    /// DORMANT on post-restart testnet: every post-fork slot has
    /// parent_slot ≥ fork_slot ⇒ the `parent_slot < fork_slot` term is false ⇒
    /// sum 0 ⇒ None ⇒ no Step-3 mixin ⇒ byte-identical bank hash. Fires only
    /// when replaying the fork slot itself (never on this node — Vexor loads the
    /// fork-slot anchor hash from the snapshot, it does not recompute it).
    /// Unit vectors (crate tests, forks at 10 & 20): (9,0)=null; (10,0)=[1,0..];
    /// (19,0)=[1..]; (20,0)=[2,0..]; (20,10)=[1..]; (21,20)=null.
    pub fn getHashData(hard_forks: []const HardFork, slot: u64, parent_slot: u64) ?[8]u8 {
        var fork_count: u64 = 0;
        for (hard_forks) |hf| {
            if (parent_slot < hf.slot and slot >= hf.slot) fork_count += hf.count;
        }
        if (fork_count == 0) return null;
        return std.mem.toBytes(fork_count); // u64 LE on little-endian targets
    }

    /// F3 (HARD-FORK-FAMILY-DESIGN-2026-06-17): the LastRestartSlot sysvar value
    /// = the highest `fork_slot ≤ slot` (else 0). @prov:bank.last-restart-slot
    /// Pure max-scan (does NOT assume the list is sorted, per advisor). Fires only when a fork
    /// crossed (parent, slot] (getHashData == Some); never on post-restart
    /// testnet. KAT-asserted vs the getHashData firing condition.
    pub fn computeLastRestartSlot(hard_forks: []const HardFork, slot: u64) u64 {
        var highest: u64 = 0;
        for (hard_forks) |hf| {
            if (hf.slot <= slot and hf.slot > highest) highest = hf.slot;
        }
        return highest;
    }

    /// F2: `hard_fork_buf` is the optional 8-byte hard-fork mixin from
    /// `getHashData` (null on every normal/testnet slot). When non-null, an
    /// extra Step-3 SHA-256 folds it after the lt-hash step.
    /// @prov:bank.hard-fork-mixin — Steps 1-2 are UNTOUCHED — the base hash stays byte-exact. All
    /// callers except the freeze site (bank.zig:3695) pass `null`.
    pub fn computeBankHash(
        lthash: *const LtHash,
        prev_bank_hash: *const Hash,
        poh_hash: *const Hash,     // bank->f.poh — LAST ENTRY hash, NOT tx.recent_blockhash
        signature_count: u64,
        hard_fork_buf: ?[8]u8,
    ) Hash {
        // Step 1 — @prov:bank.hash-calc
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        sha.update(&prev_bank_hash.data);
        var sig_le: [8]u8 = undefined;
        std.mem.writeInt(u64, &sig_le, signature_count, .little);
        sha.update(&sig_le);
        sha.update(&poh_hash.data);
        var step1: [32]u8 = undefined;
        sha.final(&step1);

        // Step 2 — @prov:bank.hash-calc
        // lthash is 1024 × u16 LE = 2048 bytes
        var sha2 = std.crypto.hash.sha2.Sha256.init(.{});
        sha2.update(&step1);
        // Write lthash as raw little-endian bytes
        var lthash_bytes: [2048]u8 = undefined;
        for (0..1024) |i| {
            std.mem.writeInt(u16, lthash_bytes[i * 2 ..][0..2], lthash.elements[i], .little);
        }
        sha2.update(&lthash_bytes);
        var result: [32]u8 = undefined;
        sha2.final(&result);

        // Step 3 (F2) — hard-fork mixin. @prov:bank.hard-fork-mixin — hash = hashv(&[hash, &buf]) ==
        // sha256(result[32] ‖ buf[8]) (40 bytes). DORMANT: buf is null on every
        // normal slot ⇒ this branch never runs ⇒ byte-identical to Steps 1-2.
        if (hard_fork_buf) |buf| {
            var sha3 = std.crypto.hash.sha2.Sha256.init(.{});
            sha3.update(&result);
            sha3.update(&buf);
            sha3.final(&result);
        }
        return Hash.init(result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fee settlement — @prov:bank.settle-fees
    // ─────────────────────────────────────────────────────────────────────────

    /// Settle fees accumulated during this slot.
    ///
    /// @prov:bank.settle-fees
    ///
    ///   burn          = execution_fees / 2
    ///   fees_to_leader = priority_fees + (execution_fees - burn)
    ///
    /// Priority fees are NEVER burned. Only 50% of execution/base fees are burned.
    /// The leader account must be:
    ///   - Owned by the System Program
    ///   - Rent-exempt after crediting (otherwise all fees are burned)
    /// Update the Clock sysvar — slot, epoch, timestamps. @prov:bank.clock-sysvar-update
    /// Old Vexor: updateClockSysvar() (bank.zig:316)
    /// Collect per-voter timestamp samples from AccountsDb's top_votes cache
    /// and fold them into `computeStakeWeightedUnixTs` to produce this slot's
    /// cluster-agreed Unix timestamp. Returns `null` if no staked sample
    /// exists (e.g., cold boot before any vote write has landed, or a
    /// snapshot that didn't include a stakes table).
    ///
    /// This is the core of SIMD-0001 on the Vexor side. The algorithm and the
    /// drift anchor now match Agave exactly: the anchor is recomputed EVERY slot
    /// in `updateClockSysvar` as (get_first_slot_in_epoch(parent_epoch),
    /// parent_clock.epoch_start_timestamp), mirroring runtime/src/bank.rs:
    /// 2398-2406 (previously it was cached once per epoch boundary, leaving a
    /// stale full-epoch-wide drift band that failed to correct sub-second
    /// median floor errors near an epoch start — the −1s carrier fixed
    /// 2026-07-09, KAT kat_clock_unixts_420860261.zig).
    fn computeStakeWeightedClockEstimate(self: *Self) !?i64 {
        const ct = @import("clock_timestamp.zig");

        const db = self.accounts_db orelse return null;

        // d16 (2026-05-10): mirror Agave canonical at `runtime/src/bank.rs:2625`
        //   let stakes = self.epoch_vote_accounts(epoch)?;
        // Look up the frozen vote-account stake table for the CURRENT epoch
        // from the snapshot's `epoch_stakes` blob. Pre-fix Vexor used the
        // snapshot's live `Stakes::vote_accounts` (~15k entries — every vote
        // account ever known) which is NOT what Agave's get_timestamp_estimate
        // weights against. First confirmed empirically via [CLOCK-PROBE-SUMMARY]
        // 2026-05-10: stakes_table=15462 vs cluster's ~580 active vote accts.
        const current_epoch = self.epoch_schedule.getEpoch(self.slot);
        var stakes_slice: []const @import("vex_store").snapshot_manifest.VoteAccountStake = &.{};
        for (db.epoch_stakes) |entry| {
            if (entry.epoch == current_epoch) {
                stakes_slice = entry.vote_account_stakes;
                break;
            }
        }
        if (stakes_slice.len == 0) {
            // Mirror Agave canonical at `runtime/src/bank.rs:2625`:
            //   let stakes = self.epoch_vote_accounts(epoch)?;   // None → fn returns None
            // Caller (updateClockSysvar) then inherits parent's Clock.unix_ts.
            // NO fallback to the snapshot's bank.stakes table — that is the
            // pre-d16 broken source whose oversized count (15,462 vs 580)
            // caused the carrier in the first place.
            const NoEpochDbg = struct { var emitted: u32 = 0; };
            if (NoEpochDbg.emitted < 5) {
                NoEpochDbg.emitted += 1;
                std.log.warn("[CLOCK-EPOCH-STAKES-MISS] slot={d} epoch={d} epoch_stakes_loaded={d} — returning null (Agave-faithful)\n", .{
                    self.slot, current_epoch, db.epoch_stakes.len,
                });
            }
            return null;
        }

        // Stakes slice reinterpretation — our VoteAccountStake layout
        // matches clock_timestamp.StakeEntry byte-for-byte by design. Using
        // a direct slice cast avoids a per-slot allocation + copy of a
        // ~1-2k-entry table.
        comptime {
            const src_mod = @import("vex_store").snapshot_manifest;
            if (@sizeOf(src_mod.VoteAccountStake) != @sizeOf(ct.StakeEntry))
                @compileError("VoteAccountStake / StakeEntry layout drifted");
        }
        const stakes_bytes = std.mem.sliceAsBytes(stakes_slice);
        const stakes_entries = std.mem.bytesAsSlice(ct.StakeEntry, stakes_bytes);

        // carrier #15 fix (2026-06-11, @414723807): sample PARENT-BANK VOTE STATE
        // through the fork-aware AccountsDb read path — NOT the global top_votes
        // cache.
        //
        // Agave canonical (runtime/src/bank.rs:2597-2634 get_timestamp_estimate):
        // iterate the bank's vote accounts and read each `vote_state.last_timestamp`
        // from PER-BANK state — update_clock runs at bank creation, before any tx
        // of this slot executes, so the values are exactly the parent's
        // post-execution vote states on THIS fork.
        //
        // Pre-fix Vexor approximated that with the global `top_votes` version
        // cache + selectForFork. PROVEN WRONG at slot 414723807 (carrier #15):
        // the cluster's Clock advanced 1781210359→1781210360 while Vexor held
        // 359; the HC9oBfF9 "UpdateProperty" oracle-crank persisted the cluster's
        // 360 into feed accounts → permanent lt_hash divergence (equal sigs) →
        // divergent fork → root wedge @414731381. The differential KAT
        // (kat_clock_unixts_414723807.zig, canonical vote-account bytes from
        // oracle-node create-snapshot @414723806) proves the estimator yields the
        // cluster's 360 EXACTLY when fed true parent-bank samples — the bug was
        // the top_votes feed serving staler (slot, ts) pairs whose floor-projected
        // estimates sat one second low at the median.
        //
        // Shape: iterate the epoch_stakes voter set (~600, same table Agave
        // weights against) and read each vote account via getAccountInSlot
        // (self.slot, self.ancestors()) — the identical fork-aware parent-state
        // read updateClockSysvar uses for the Clock account itself; setAncestors
        // ran before us (replay_stage.zig PR-5ac ordering). Cost: ~600 index
        // reads + ~600 vote-state parses per slot (lt verifier does ~1100
        // reads/slot without strain). The d16-v3 worry ("580 reads/slot →
        // crash class at ~10 min", 2026-05-10) targeted the PRE-two-tier read
        // path; the store has since been rebuilt (FIX #105 ring + tombstone
        // semantics, carriers #11/#13).
        //
        // Filters mirror Agave runtime/src/bank.rs:2614-2620 EXACTLY:
        //   * future vote (vote_slot > self.slot): checked_sub None → drop ONE.
        //   * slot_delta > slots_per_epoch: drop.
        //   * NO `timestamp == 0` special-case (the pre-fix Vexor-only drop was
        //     proven consensus-neutral by the KAT's vexor-live arm, but Agave
        //     has no such filter — removed for byte-faithfulness).
        const vss = @import("native/vote_state_serde.zig");
        const slots_per_epoch = self.epoch_schedule.slots_per_epoch;
        const fork_anc = self.ancestors();

        var samples_list = std.array_list.Managed(ct.VoteTimestampSample).init(self.allocator);
        defer samples_list.deinit();
        try samples_list.ensureTotalCapacity(stakes_slice.len);

        var read_miss: usize = 0;
        var parse_fail: usize = 0;
        var dropped_future: usize = 0;
        var dropped_old: usize = 0;
        var max_sample_vote_slot: u64 = 0;
        // r55-E class: getAccountInSlot returns slices into mmap'd AppendVec /
        // unflushed-cache storage that parallel flush can remap mid-read. Copy
        // into a fixed buffer before parsing (vote V4 frame = 3762 B; 8 KiB
        // covers every historical vote-state size).
        var data_buf: [8192]u8 = undefined;
        for (stakes_slice) |se| {
            // Zero-stake entries contribute NOTHING to the estimator (their
            // bucket weight and total_stake delta are both 0 — the median is
            // provably unchanged), so skip the account read+parse entirely.
            // Live 2026-06-11: the snapshot's epoch_stakes table carries 15,501
            // entries of which ~14,900 are zero-stake; reading+parsing all of
            // them cost ~+60ms/slot (replay_ms 90.6→156.8, catch-up 2.8→2.1
            // slots/s = tip-divergent). Agave's epoch_vote_accounts iteration
            // only ever sees the staked set (~600).
            if (se.stake == 0) continue;
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&se.vote_pubkey));
            const acct = db.getAccountInSlot(core_pk, self.slot, fork_anc) orelse {
                read_miss += 1;
                continue;
            };
            if (acct.data.len == 0 or acct.data.len > data_buf.len) {
                parse_fail += 1;
                continue;
            }
            @memcpy(data_buf[0..acct.data.len], acct.data);
            const vs = vss.deserializeVoteState(data_buf[0..acct.data.len]) orelse {
                parse_fail += 1;
                continue;
            };
            const lt = vs.last_timestamp;
            const slot_delta = std.math.sub(u64, self.slot, lt.slot) catch {
                dropped_future += 1;
                continue;
            };
            if (slot_delta > slots_per_epoch) {
                dropped_old += 1;
                continue;
            }
            if (lt.slot > max_sample_vote_slot) max_sample_vote_slot = lt.slot;
            try samples_list.append(.{
                .vote_pubkey = se.vote_pubkey,
                .slot = lt.slot,
                .unix_ts = lt.timestamp,
            });
        }

        const SWDbg = struct { var count: u64 = 0; };
        SWDbg.count += 1;
        if (SWDbg.count <= 3 or SWDbg.count % 100 == 0) {
            std.log.warn("[CLOCK-CACHE-SAMPLES] slot={d} src=parent_state stakers={d} kept={d} read_miss={d} parse_fail={d} drop_future={d} drop_old={d} max_vote_slot={d} lag={d}\n", .{
                self.slot, stakes_slice.len, samples_list.items.len,
                read_miss, parse_fail, dropped_future, dropped_old,
                max_sample_vote_slot, std.math.sub(u64, self.slot, max_sample_vote_slot) catch 0,
            });
        }

        // Forensic capture (byte-neutral; no state mutation, no effect unless
        // VEX_CLOCK_KAT_DUMP == this slot). Serializes the exact canonical
        // inputs — samples (vote_pubkey, vote_slot, ts) + per-voter stakes +
        // slot + the anchor the estimator saw — so the differential KAT
        // kat_clock_unixts_420860261.zig can replay null-vs-tight-anchor offline
        // and prove the localization. See that file for the blob format.
        {
            const KatDump = struct {
                var parsed: bool = false;
                var target: u64 = 0;
            };
            if (!KatDump.parsed) {
                KatDump.parsed = true;
                if (std.process.getEnvVarOwned(self.allocator, "VEX_CLOCK_KAT_DUMP")) |v| {
                    defer self.allocator.free(v);
                    KatDump.target = std.fmt.parseInt(u64, std.mem.trim(u8, v, " \t\r\n"), 10) catch 0;
                } else |_| {}
            }
            if (KatDump.target != 0 and self.slot == KatDump.target) {
                self.dumpClockKatInputs(samples_list.items, stakes_entries, db.clock_epoch_anchor) catch |e| {
                    std.log.warn("[CLOCK-KAT-DUMP] slot={d} dump failed: {s}\n", .{ self.slot, @errorName(e) });
                };
            }
        }

        // `warp_timestamp_again` feature was activated on mainnet+testnet
        // long before any slot Vexor can currently boot from, so the fixed
        // (unsigned-clamped) offset math is unconditional.
        const result = try ct.computeStakeWeightedUnixTs(
            self.allocator,
            samples_list.items,
            stakes_entries,
            self.slot,
            400_000_000,
            if (db.clock_epoch_anchor) |a| ct.EpochAnchor{ .slot = a.slot, .unix_ts = a.unix_ts } else null,
            ct.ClockDriftBounds.DEFAULT,
            true,
        );
        return result;
    }

    /// Forensic-only serializer for the Clock stake-weighted-median inputs at a
    /// single target slot (env VEX_CLOCK_KAT_DUMP). Writes the exact canonical
    /// samples + stakes + anchor to a blob the differential KAT replays offline.
    /// Byte-neutral: never mutates bank state, only reads and writes an external
    /// file. Blob format (little-endian) — must match kat_clock_unixts_420860261:
    ///   magic "CKAT" | slot u64 | ns_per_slot u64 |
    ///   anchor_present u8 | anchor_slot u64 | anchor_unix_ts i64 |
    ///   n_samples u32 | { pubkey[32] vote_slot u64 ts i64 } * n_samples |
    ///   n_stakes  u32 | { pubkey[32] stake u64 }             * n_stakes
    fn dumpClockKatInputs(
        self: *Self,
        samples: []const @import("clock_timestamp.zig").VoteTimestampSample,
        stakes: []const @import("clock_timestamp.zig").StakeEntry,
        anchor: anytype,
    ) !void {
        var path_buf: [512]u8 = undefined;
        var owned_path: ?[]u8 = null;
        const path = if (std.process.getEnvVarOwned(self.allocator, "VEX_CLOCK_KAT_DUMP_PATH")) |p| pblk: {
            owned_path = p;
            break :pblk p;
        } else |_|
            try std.fmt.bufPrint(&path_buf, "/tmp/clock_kat_{d}.blob", .{self.slot});
        defer if (owned_path) |p| self.allocator.free(p);

        var out = std.array_list.Managed(u8).init(self.allocator);
        defer out.deinit();
        const w = out.writer();
        try w.writeAll("CKAT");
        try w.writeInt(u64, self.slot, .little);
        try w.writeInt(u64, 400_000_000, .little);
        if (anchor) |a| {
            try w.writeInt(u8, 1, .little);
            try w.writeInt(u64, a.slot, .little);
            try w.writeInt(i64, a.unix_ts, .little);
        } else {
            try w.writeInt(u8, 0, .little);
            try w.writeInt(u64, 0, .little);
            try w.writeInt(i64, 0, .little);
        }
        try w.writeInt(u32, @intCast(samples.len), .little);
        for (samples) |s| {
            try w.writeAll(&s.vote_pubkey);
            try w.writeInt(u64, s.slot, .little);
            try w.writeInt(i64, s.unix_ts, .little);
        }
        try w.writeInt(u32, @intCast(stakes.len), .little);
        for (stakes) |st| {
            try w.writeAll(&st.vote_pubkey);
            try w.writeInt(u64, st.stake, .little);
        }
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = out.items });
        std.log.warn("[CLOCK-KAT-DUMP] slot={d} samples={d} stakes={d} -> {s}\n", .{
            self.slot, samples.len, stakes.len, path,
        });
    }

    pub fn updateClockSysvar(self: *Self) !void {
        // SysvarC1ock11111111111111111111111111111111
        const CLOCK_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9,
            0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
            0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c,
            0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
        } };
        // Sysvar1111111111111111111111111111111111111 (owner for all sysvars)
        const SYSVAR_OWNER_BYTES = SYSVAR_OWNER;

        // Read existing Clock from AccountsDb (parent's Clock state)
        var existing_lamports: u64 = 1_169_280;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var epoch_start_ts: i64 = 0;
        var unix_ts: i64 = 0;
        var parent_epoch: u64 = 0;
        var old_lt_data: ?[]const u8 = null;
        var old_lt_owner: [32]u8 = SYSVAR_OWNER_BYTES;
        var adb_hit_clock: bool = false; // SYSVAR-PROBE 2026-05-26

        if (self.accounts_db) |db| {
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&CLOCK_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                adb_hit_clock = true; // SYSVAR-PROBE 2026-05-26
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                old_lt_owner = existing.owner.data;
                // r55-E: dupe immediately. existing.data is a slice into mmap'd
                // AppendVec storage that can be remapped/evicted by parallel-snapshot
                // (r53) or shadow-cache flush during the ~70 lines below that touch
                // accounts_db (clock_epoch_anchor, computeStakeWeightedClockEstimate).
                // Holding the raw slice across that window caused SIGSEGV in
                // accountLtHash → blake3.update at line 873. Same class as
                // CLAUDE.md Pitfall #5 (mmap is read-only; dupe before use).
                if (existing.data.len > 0) {
                    old_lt_data = self.allocator.dupe(u8, existing.data) catch null;
                }
                if (existing.data.len >= 40) {
                    epoch_start_ts = @bitCast(std.mem.readInt(u64, existing.data[8..16], .little));
                    unix_ts = @bitCast(std.mem.readInt(u64, existing.data[32..40], .little));
                    parent_epoch = std.mem.readInt(u64, existing.data[16..24], .little);
                }
            }
        }

        const epoch = self.epoch_schedule.getEpoch(self.slot);

        // Recompute the stake-weighted-median drift anchor EVERY slot, exactly
        // as Agave does. The drift-bound clamp reads `db.clock_epoch_anchor`.
        //
        // Agave `update_clock` (runtime/src/bank.rs:2398-2406) builds the anchor
        // fresh on every call:
        //     let epoch = parent_epoch.unwrap_or_else(|| self.epoch());
        //     let first_slot_in_epoch = get_first_slot_in_epoch(epoch);
        //     Some((first_slot_in_epoch, self.clock().epoch_start_timestamp))
        // i.e. anchor.slot = first slot of the PARENT bank's epoch, and
        // anchor.unix_ts = the PARENT Clock's `epoch_start_timestamp` field
        // (read here as `epoch_start_ts`, before the boundary overwrite below).
        //
        // The prior Vexor code cached this ONCE at the epoch boundary using the
        // parent epoch's first slot, then FROZE it for the entire epoch. That is
        // correct only for the boundary slot itself: from the 2nd slot of a new
        // epoch onward the parent bank is ALREADY in the new epoch, so Agave's
        // anchor.slot advances to the NEW epoch's first slot (poh_estimate_offset
        // = only (slot - boundary) slots → a sub-second ±25%/150% drift band that
        // tightly pins the estimate to the PoH projection). The frozen Vexor
        // anchor kept pointing a full epoch back (poh_estimate_offset ≈ 432k
        // slots → a ~43200s band that NEVER clamps), so a stake-weighted median
        // that floor-projected one second low sailed through uncorrected.
        // Carrier: Clock.unix_timestamp = canon−1s at epoch-987 boundary+5
        // (slot 420860261) and epoch-986 boundary+109 — both near an epoch start,
        // exactly where the tight current-epoch band is load-bearing. Deep-epoch
        // slots are unaffected (both anchors give a wide band → median passes).
        if (self.accounts_db) |db| {
            if (adb_hit_clock and epoch_start_ts != 0) {
                const anchor_epoch = if (parent_epoch != 0) parent_epoch else epoch;
                db.clock_epoch_anchor = .{
                    .slot = self.epoch_schedule.getFirstSlotInEpoch(anchor_epoch),
                    .unix_ts = epoch_start_ts,
                };
            }
        }

        // Stake-weighted median timestamp (SIMD-0001) is the authoritative
        // source. Only falls back to wall-clock when we have no staked
        // samples yet (cold boot, before any vote write has landed) or no
        // stake table (pre-vex-098 snapshot path or nonsensical snapshot).
        var computed_unix_ts: ?i64 = null;
        if (self.accounts_db) |db| {
            // d16 (2026-05-10): allow the call when EITHER stake source is
            // populated. The estimator now prefers epoch_stakes[E] (Agave
            // mirror) and falls back to bank.stakes if not loaded.
            if (db.epoch_stakes.len > 0 or db.vote_account_stakes.len > 0) {
                computed_unix_ts = self.computeStakeWeightedClockEstimate() catch null;
            }
        }
        if (computed_unix_ts) |est| {
            // Monotonic: Clock.unix_ts never runs backward on the cluster.
            if (est > unix_ts) unix_ts = est;
        }
        // Live trajectory gate (PORT-PLAN §7): one line per frozen slot so the
        // -Dsig_clock=true run can be diffed against cluster getBlockTime(slot).
        // PASS = delta flat ≈0; the pre-fix drift shows as a monotonic ramp.
        std.log.info("[CLOCK-TRAJECTORY] slot={d} computed_unix_ts={?d} clock_unix_ts={d} src={s}\n", .{
            self.slot, computed_unix_ts, unix_ts,
            if (build_options.sig_clock) "sig_live" else "selectForFork",
        });
        // Else: inherit. NO wall-clock fallback: on a catching-up validator
        // wall-clock is the current time, not the time this slot was
        // produced. Using wall-clock for even one slot would push unix_ts
        // forward past any SW-estimate the next slot could produce, and the
        // monotonic rule above would freeze it there forever — that's the
        // exact bug we hit in vex-098 first-pass testing. Inheriting the
        // parent Clock's unix_ts is the same behavior Sig/Agave use when
        // no staked sample is available (e.g., first slot of replay before
        // any vote write has landed). The value then monotonically ratchets
        // upward as soon as the first SW estimate produces something larger.

        // epoch_start_ts: on epoch boundary, set to current unix_ts.
        // Otherwise inherit from parent unchanged.
        //
        // 2026-05-24: was `parent_epoch > 0` which silently skips the
        // genesis epoch-0 → epoch-1 rollover. Firedancer/Agave gate on
        // `parent_epoch != current_epoch` per fd_sysvar_clock.c:400 and
        // bank.rs:2191. Same bug class as the anchor-slot fix above.
        if (epoch != parent_epoch) {
            epoch_start_ts = unix_ts;
        }

        // Serialize Clock sysvar: [slot:u64][epoch_start_ts:i64][epoch:u64][leader_schedule_epoch:u64][unix_ts:i64]
        var buf: [40]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.slot, .little);
        std.mem.writeInt(i64, buf[8..16], epoch_start_ts, .little);
        std.mem.writeInt(u64, buf[16..24], epoch, .little);
        std.mem.writeInt(u64, buf[24..32], epoch + 1, .little);
        std.mem.writeInt(i64, buf[32..40], unix_ts, .little);

        const data_copy = try self.allocator.dupe(u8, &buf);

        // Compute LtHash deltas
        const old_lt = if (old_lt_data) |od|
            accountLtHash(&CLOCK_PUBKEY.data, &old_lt_owner, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&CLOCK_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, data_copy);

        // r55-E: free the duped old slice now that lthash is computed.
        if (old_lt_data) |od| self.allocator.free(od);

        // SYSVAR-PROBE (carrier identification) 2026-05-26
        {
            var _pb = vex_crypto.blake3.Blake3.init(.{});
            _pb.update(data_copy);
            var _po: [32]u8 = undefined;
            _pb.final(&_po);
            std.log.debug("[SYSVAR-PROBE] slot={d} sv=Clock adb_hit={any} lp={d} re={d} dl={d} b3={x}", .{
                self.slot, adb_hit_clock, existing_lamports, existing_rent_epoch, data_copy.len, _po[0..8],
            });
        }

        try self.collectWrite(.{
            .pubkey = CLOCK_PUBKEY,
            .lamports = existing_lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER_BYTES },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = data_copy,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });
    }

    /// Update RecentBlockhashes sysvar — fixed 6,008 bytes. @prov:bank.recent-hashes-update
    /// Old Vexor: updateRecentBlockhashes() (bank.zig:2311)
    fn updateRecentBlockhashes(self: *Self) !void {
        if (self.slot == 0) return;
        if (!self.has_entries) return; // ghost banks don't update RBH

        // SysvarRecentB1ockHashes11111111111111111111
        const RBH_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
            0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
            0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
            0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
        } };
        const SYSVAR_OWNER_BYTES = SYSVAR_OWNER;

        // Skip if account doesn't exist in AccountsDb.
        // 2026-05-27 Task #43 RULE #0: fallback default = canonical rent-exempt
        // for RBH (6008 bytes data → (6008+128)*6960 = 42,706,560). On testnet
        // this fallback never triggers (probe-2026-05-26: adb_hit=true 100%
        // over 86 slots) but mainnet may exercise it. Previously `= 1` was a
        // non-canonical sentinel that would diverge from Agave/oracle-node if the
        // fallback ever fires.
        var existing_lamports: u64 = 42_706_560;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var old_lt_data: ?[]const u8 = null;
        var old_lt_owner: [32]u8 = SYSVAR_OWNER_BYTES;
        var adb_hit_rbh: bool = false; // SYSVAR-PROBE 2026-05-26

        if (self.accounts_db) |db| {
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&RBH_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                adb_hit_rbh = true; // SYSVAR-PROBE 2026-05-26
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                old_lt_owner = existing.owner.data;
                // r62: dupe immediately. Same class of bug as r55-E (Clock).
                // existing.data is a raw slice into mmap'd AppendVec storage.
                // The ~30 lines below allocate sysvar_data + serialize via
                // self.allocator.alloc, which can trigger AppendVec mmap
                // remapping or shadow-cache flush, invalidating this slice.
                // Reading stale/dangling bytes via accountLtHash later produces
                // wrong old_lt → wrong lthash delta at freeze → bank_hash
                // diverges every slot.
                if (existing.data.len > 0) {
                    old_lt_data = self.allocator.dupe(u8, existing.data) catch null;
                }
            } // account not in snapshot — create with default lamports
        }

        // Push current slot's poh_hash into the queue.
        // CONSENSUS-CRITICAL (epoch-979 tip carrier): lps must be the per-slot
        // DERIVED value. @prov:fees.lamports-per-sig — NOT a hardcoded
        // 5000. At slot 849 the parent's 10604-sig spike pushed lps to 5500;
        // the old `= 5000` made the RecentBlockhashes sysvar differ by 8 bytes →
        // accounts-lthash → bank_hash diverged. `fee_rate_governor` is derived
        // from the parent in getOrCreateBank (replay_stage.zig).
        self.recent_blockhashes.push(.{
            .blockhash = self.poh_hash,
            .lamports_per_signature = self.fee_rate_governor.lamports_per_signature,
        });

        // Serialize to FIXED SIZE = 8 + 150*40 = 6008 bytes (zero-padded)
        const FIXED_SIZE: usize = 8 + 150 * 40; // 6008
        const sysvar_data = try self.allocator.alloc(u8, FIXED_SIZE);
        @memset(sysvar_data, 0);

        const count: u64 = self.recent_blockhashes.len;
        std.mem.writeInt(u64, sysvar_data[0..8], count, .little);

        // Newest-first ordering (reverse iteration)
        const entries = self.recent_blockhashes.constSlice();
        var rev_i: usize = 0;
        var j: usize = entries.len;
        while (j > 0) : ({
            j -= 1;
            rev_i += 1;
        }) {
            const bh_entry = entries[j - 1];
            const offset = 8 + rev_i * 40;
            @memcpy(sysvar_data[offset..][0..32], &bh_entry.blockhash.data);
            std.mem.writeInt(u64, sysvar_data[offset + 32..][0..8],
                bh_entry.lamports_per_signature, .little);
        }

        // Compute LtHash deltas
        const old_lt = if (old_lt_data) |od|
            accountLtHash(&RBH_PUBKEY.data, &old_lt_owner, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&RBH_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, sysvar_data);

        // r62: free duped old slice now that lthash is computed.
        if (old_lt_data) |od| self.allocator.free(od);

        // SYSVAR-PROBE (carrier identification) 2026-05-26
        {
            var _pb = vex_crypto.blake3.Blake3.init(.{});
            _pb.update(sysvar_data);
            var _po: [32]u8 = undefined;
            _pb.final(&_po);
            std.log.debug("[SYSVAR-PROBE] slot={d} sv=RBH adb_hit={any} lp={d} re={d} dl={d} b3={x}", .{
                self.slot, adb_hit_rbh, existing_lamports, existing_rent_epoch, sysvar_data.len, _po[0..8],
            });
        }

        try self.collectWrite(.{
            .pubkey = RBH_PUBKEY,
            .lamports = existing_lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER_BYTES },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = sysvar_data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });
    }

    /// Update SlotHistory sysvar — 131,097 byte bitvec marking which slots are present.
    /// @prov:bank.slot-history-update
    /// Old Vexor: updateSlotHistorySysvar() (bank.zig:2397)
    fn updateSlotHistory(self: *Self) !void {
        // SysvarS1otHistory11111111111111111111111111
        const SH_HIST_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf,
            0xc8, 0x75, 0xe2, 0xe1, 0x84, 0x57, 0x7c, 0x50,
            0x69, 0xcf, 0xc8, 0x46, 0x49, 0xe3, 0xeb, 0x92,
            0x78, 0x2f, 0x95, 0x8d, 0x48, 0x00, 0x00, 0x00,
        } };

        const MAX_ENTRIES: u64 = 1_048_576;
        const NUM_WORDS: u64 = MAX_ENTRIES / 64;
        const WORDS_OFFSET: usize = 9; // 1 (Option tag) + 8 (vec len)
        const NBITS_OFFSET: usize = WORDS_OFFSET + @as(usize, NUM_WORDS) * 8;
        const NEXT_SLOT_OFFSET: usize = NBITS_OFFSET + 8;
        const DATA_LEN: usize = NEXT_SLOT_OFFSET + 8; // 131097

        // Read existing from AccountsDb
        var existing_lamports: u64 = 0;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var existing_data_opt: ?[]const u8 = null;
        var old_lt_owner: [32]u8 = SYSVAR_OWNER;
        var adb_hit_shist: bool = false; // SYSVAR-PROBE 2026-05-26

        if (self.accounts_db) |db| {
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&SH_HIST_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                adb_hit_shist = true; // SYSVAR-PROBE 2026-05-26
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                old_lt_owner = existing.owner.data;
                // r62: dupe immediately. Same class of bug as r55-E (Clock) +
                // r62 (RBH). existing.data is a raw slice into mmap'd AppendVec.
                // The slice is dereferenced TWICE below — once at @memcpy (line
                // ~1027) and once at accountLtHash (line ~1080). Both reads
                // happen AFTER self.allocator.alloc(DATA_LEN) which can trigger
                // AppendVec eviction. Without dupe → stale bytes → wrong copy
                // and wrong old_lt → bank_hash diverges every slot.
                if (existing.data.len > 0) {
                    existing_data_opt = self.allocator.dupe(u8, existing.data) catch null;
                }
            }
        }

        const data = try self.allocator.alloc(u8, DATA_LEN);
        @memset(data, 0);

        // Copy existing data if available
        if (existing_data_opt) |ed| {
            const copy_len = @min(ed.len, DATA_LEN);
            if (copy_len > 0) @memcpy(data[0..copy_len], ed[0..copy_len]);
        }

        // Set mandatory fields
        data[0] = 0x01; // Bincode Option::Some tag
        const existing_vec_len = std.mem.readInt(u64, data[1..9], .little);
        if (existing_vec_len == 0 or existing_vec_len > NUM_WORDS) {
            std.mem.writeInt(u64, data[1..9], NUM_WORDS, .little);
        }
        if (std.mem.readInt(u64, data[NBITS_OFFSET..][0..8], .little) == 0) {
            std.mem.writeInt(u64, data[NBITS_OFFSET..][0..8], MAX_ENTRIES, .little);
        }

        // r51-fix: clear bits for skipped slots in [parent_next_slot, self.slot)
        // before setting the current slot's bit. @prov:bank.slot-history-skip-fix —
        // without this, stale bits from earlier wrap-arounds remain set when the bitmap
        // window scrolls past slot N+1M into N+1M's old position, breaking the lthash MATCH.
        const parent_next_slot = std.mem.readInt(u64, data[NEXT_SLOT_OFFSET..][0..8], .little);
        if (self.slot > parent_next_slot and self.slot - parent_next_slot >= MAX_ENTRIES) {
            // Wrapped past entire history — clear all words.
            @memset(data[WORDS_OFFSET..NBITS_OFFSET], 0);
        } else if (parent_next_slot < self.slot) {
            var skip_s = parent_next_slot;
            while (skip_s < self.slot) : (skip_s += 1) {
                const sm = skip_s % MAX_ENTRIES;
                const wi = sm / 64;
                const bi_skip: u6 = @intCast(sm % 64);
                const wo = WORDS_OFFSET + @as(usize, wi) * 8;
                if (wo + 8 <= data.len) {
                    const w = std.mem.readInt(u64, data[wo..][0..8], .little);
                    std.mem.writeInt(u64, data[wo..][0..8], w & ~(@as(u64, 1) << bi_skip), .little);
                }
            }
        }

        // Set bit for this slot
        const slot_mod = self.slot % MAX_ENTRIES;
        const word_idx = slot_mod / 64;
        const bit_idx: u6 = @intCast(slot_mod % 64);
        const word_offset = WORDS_OFFSET + @as(usize, word_idx) * 8;
        if (word_offset + 8 <= data.len) {
            const word = std.mem.readInt(u64, data[word_offset..][0..8], .little);
            std.mem.writeInt(u64, data[word_offset..][0..8], word | (@as(u64, 1) << bit_idx), .little);
        }

        // Update next_slot
        std.mem.writeInt(u64, data[NEXT_SLOT_OFFSET..][0..8], self.slot + 1, .little);

        const lamports = if (existing_lamports > 0) existing_lamports else (@as(u64, DATA_LEN) + 128) * 6960;

        // Compute LtHash deltas
        const old_lt = if (existing_data_opt) |od|
            accountLtHash(&SH_HIST_PUBKEY.data, &old_lt_owner, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&SH_HIST_PUBKEY.data, &SYSVAR_OWNER, lamports, false, data);

        // r62: free duped old slice now that lthash is computed.
        if (existing_data_opt) |od| self.allocator.free(od);

        // SYSVAR-PROBE (carrier identification) 2026-05-26
        {
            var _pb = vex_crypto.blake3.Blake3.init(.{});
            _pb.update(data);
            var _po: [32]u8 = undefined;
            _pb.final(&_po);
            std.log.debug("[SYSVAR-PROBE] slot={d} sv=SlotHistory adb_hit={any} lp={d} re={d} dl={d} b3={x}", .{
                self.slot, adb_hit_shist, lamports, existing_rent_epoch, data.len, _po[0..8],
            });
        }

        try self.collectWrite(.{
            .pubkey = SH_HIST_PUBKEY,
            .lamports = lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });
    }

    /// Update SlotHashes sysvar — prepends (parent_slot, parent_hash) to the list.
    /// Read SlotHashes sysvar bytes (overlay-aware: pending_writes first, then db).
    /// Used by `replay_stage.zig:executeVoteInstruction` to feed
    /// `replaceTowerStateChecked` for the SlotHash mismatch filter (r75-bug-class-d12).
    /// @prov:bank.slot-hashes-overlay-read — the sysvar was written earlier this slot by
    /// `updateSlotHashesSysvar` (replay_stage.zig:1506), so the overlay walk finds
    /// the fresh value with the parent_slot prepended.
    pub fn getSlotHashesData(self: *const Self) ?[]const u8 {
        const SH_PUBKEY: [32]u8 = .{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf,
            0xc6, 0xf2, 0x65, 0xe3, 0xfb, 0x77, 0xcc, 0x7a,
            0xda, 0x82, 0xc5, 0x29, 0xd0, 0xbe, 0x3b, 0x13,
            0x6e, 0x2d, 0x00, 0x55, 0x20, 0x00, 0x00, 0x00,
        };
        var i: usize = self.pending_writes.items.len;
        while (i > 0) {
            i -= 1;
            const w = &self.pending_writes.items[i];
            if (std.mem.eql(u8, &w.pubkey.data, &SH_PUBKEY)) {
                if (w.data.len == 0) return null;
                return w.data;
            }
        }
        if (self.accounts_db) |db| {
            const core_pk_local = @as(*const @import("core").Pubkey, @ptrCast(&Pubkey{ .data = SH_PUBKEY }));
            if (db.getAccountInSlot(core_pk_local, self.slot, self.ancestors())) |acct| {
                if (acct.data.len == 0) return null;
                return acct.data;
            }
        }
        return null;
    }

    /// View of a sysvar account fetched from a parent bank's pending_writes.
    /// Per-bank pending_writes is fork-aware by construction (a sibling fork's
    /// bank has its own pending_writes — never visible across forks). Callers
    /// pass this view to `update*Sysvar` so the new sysvar bytes are derived
    /// from the CANONICAL parent (not from a sibling-fork write that leaked
    /// through `_getRooted → unflushed_cache`).
    pub const SysvarFromParent = struct {
        data: []const u8,
        lamports: u64,
        owner: [32]u8,
        rent_epoch: u64,
    };

    /// Fork-aware sysvar read: walk this bank's pending_writes (NOT
    /// accounts_db) for `pubkey`. Returns null when no pending write exists
    /// (e.g., genesis bank, or bank loaded from snapshot whose slot-start
    /// sysvar updates haven't run yet). Used by child banks at slot start
    /// to fetch the parent's canonical sysvar state without risking the
    /// fork-blind accounts_db fall-through.
    pub fn getSysvarFromPendingWrites(self: *const Self, pubkey: *const [32]u8) ?SysvarFromParent {
        var i: usize = self.pending_writes.items.len;
        while (i > 0) {
            i -= 1;
            const w = &self.pending_writes.items[i];
            if (std.mem.eql(u8, &w.pubkey.data, pubkey)) {
                if (w.data.len == 0) return null;
                return .{
                    .data = w.data,
                    .lamports = w.lamports,
                    .owner = w.owner.data,
                    .rent_epoch = w.rent_epoch,
                };
            }
        }
        return null;
    }

    /// Max 512 entries. @prov:bank.slot-hashes-update
    /// Old Vexor: updateSlotHashesSysvar() (bank.zig:663)
    ///
    /// PR-5{aa} (2026-05-19, fork-isolation): accept optional `parent_sysvar`
    /// from caller. When provided, the existing SlotHashes is read from the
    /// PARENT BANK's pending_writes (fork-aware, per-bank) instead of from
    /// accounts_db (whose `_getRooted` → unflushed_cache fall-through is
    /// fork-blind and returns the most-recent-write-globally regardless of
    /// fork). Empirical carrier closed: testnet slot 409543729 prev-PR-5aa
    /// read slot 730's SH blob (sibling fork, parent=726) via fork-blind
    /// unflushed_cache, prepended (728, hash_728) to it → produced SH
    /// missing slot 727 → 6 vote-tx rejections at 729 → 571 rejections at
    /// 731 → bh+lt divergence cascade for 261 consecutive slots.
    ///
    /// Caller (replay_stage.replayEntriesInternal) walks `self.banks.get(parent_slot)`
    /// and calls `parent_bank.getSysvarFromPendingWrites(&SH_PUBKEY.data)`.
    /// Null falls through to the legacy accounts_db path for genesis and
    /// test compatibility (vulnerable but irrelevant at those points).
    pub fn updateSlotHashesSysvar(self: *Self, parent_sysvar: ?SysvarFromParent) !void {
        // SysvarS1otHashes111111111111111111111111111
        const SH_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf,
            0xc6, 0xf2, 0x65, 0xe3, 0xfb, 0x77, 0xcc, 0x7a,
            0xda, 0x82, 0xc5, 0x29, 0xd0, 0xbe, 0x3b, 0x13,
            0x6e, 0x2d, 0x00, 0x55, 0x20, 0x00, 0x00, 0x00,
        } };
        const SYSVAR_OWNER_BYTES = SYSVAR_OWNER;
        const MAX_SLOT_HASHES: usize = 512;
        const ENTRY_SIZE: usize = 40; // u64 slot + [32]u8 hash

        const parent_slot_num = self.parent_slot orelse return; // skip if no parent
        _ = parent_slot_num;

        // Read existing SlotHashes — fork-aware path first, accounts_db fallback last.
        var existing_count: usize = 0;
        var existing_data_ptr: ?[]const u8 = null;
        // 2026-05-27 Task #43 RULE #0: fallback default = canonical rent-exempt
        // for SlotHashes (20488 bytes data → (20488+128)*6960 = 143,487,360).
        // Was `1_143_600` which would diverge from Agave/oracle-node if fallback
        // fires. On testnet adb_hit=true 100% so this never triggers, but
        // mainnet hygiene per RULE #0.
        var existing_lamports: u64 = 143_487_360;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var old_lt_data: ?[]const u8 = null;
        var old_lt_owner: [32]u8 = SYSVAR_OWNER_BYTES;
        // SYSVAR-PROBE 2026-05-26: psv_hit = parent fork-aware read, adb_hit = legacy accounts_db fallback
        var psv_hit_sh: bool = false;
        var adb_hit_sh: bool = false;

        if (parent_sysvar) |psv| {
            psv_hit_sh = true; // SYSVAR-PROBE 2026-05-26
            // Fork-aware path: parent bank's pending_writes carries the SH
            // blob this slot's start last wrote. Per-bank, never contaminated
            // by sibling forks. We still dupe so the legacy ownership /
            // lifetime semantics below are unchanged.
            existing_lamports = psv.lamports;
            existing_rent_epoch = psv.rent_epoch;
            old_lt_owner = psv.owner;
            if (psv.data.len > 0) {
                if (self.allocator.dupe(u8, psv.data)) |duped| {
                    old_lt_data = duped;
                    if (duped.len >= 8) {
                        const count = std.mem.readInt(u64, duped[0..8], .little);
                        existing_count = @min(@as(usize, @intCast(count)), MAX_SLOT_HASHES - 1);
                        existing_data_ptr = duped;
                    }
                } else |_| {}
            }
        } else if (self.accounts_db) |db| {
            // Legacy fallback: genesis bank, test paths, or any case where
            // the parent bank handle isn't in the registry. VULNERABLE to
            // the sibling-fork leak described above — but at those points
            // there are no sibling forks to contaminate the read.
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&SH_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                adb_hit_sh = true; // SYSVAR-PROBE 2026-05-26
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                old_lt_owner = existing.owner.data;
                // r62: dupe immediately. Same class as r55-E (Clock), r62-RBH,
                // r62-SlotHistory. existing.data is mmap'd; the slice is used
                // THREE times below — count read at line ~1159 (safe, immediate),
                // @memcpy at line ~1181 (after allocator.alloc, unsafe), and
                // accountLtHash at line ~1187 (also after alloc, unsafe).
                if (existing.data.len > 0) {
                    if (self.allocator.dupe(u8, existing.data)) |duped| {
                        old_lt_data = duped;
                        if (duped.len >= 8) {
                            const count = std.mem.readInt(u64, duped[0..8], .little);
                            existing_count = @min(@as(usize, @intCast(count)), MAX_SLOT_HASHES - 1);
                            existing_data_ptr = duped;
                        }
                    } else |_| {}
                }
            }
        }

        // PR-5at v2 (2026-05-22): SH dedup, inline, using same buffer primitives
        // as the original code. @prov:bank.slot-hashes-dedup — binary_search_by →
        // overwrite-in-place OR sorted-insert → truncate. Vexor previously
        // prepended unconditionally, so any fork-rebuild / repair-replay /
        // snapshot-restart that re-presented an already-present slot would push
        // a duplicate into the ring and propagate non-canonical bytes for ~512
        // slots. v2 keeps OLD math primitives (existing_count capped at 511)
        // and adds only the dedup branch.
        const parent_slot_val: u64 = self.parent_slot orelse 0;
        var dedup_index: ?usize = null;
        if (existing_data_ptr) |ed| {
            var i: usize = 0;
            while (i < existing_count) : (i += 1) {
                const off: usize = 8 + i * ENTRY_SIZE;
                if (off + 8 > ed.len) break;
                const probe = std.mem.readInt(u64, ed[off..][0..8], .little);
                if (probe == parent_slot_val) {
                    dedup_index = i;
                    break;
                }
            }
        }

        const out_count: usize = if (dedup_index != null) existing_count else existing_count + 1;
        const data_len = 8 + out_count * ENTRY_SIZE;
        const data = try self.allocator.alloc(u8, data_len);

        std.mem.writeInt(u64, data[0..8], @as(u64, out_count), .little);

        if (dedup_index) |di| {
            // Overwrite-in-place: copy all existing entries unchanged, then
            // patch entry di's hash with parent_hash.
            if (existing_data_ptr) |ed| {
                const copy_bytes = existing_count * ENTRY_SIZE;
                if (ed.len >= 8 + copy_bytes) {
                    @memcpy(data[8..][0..copy_bytes], ed[8..][0..copy_bytes]);
                }
            }
            const hash_off = 8 + di * ENTRY_SIZE + 8;
            @memcpy(data[hash_off..][0..32], &self.parent_hash.data);
        } else {
            // Prepend new entry, then copy existing.
            std.mem.writeInt(u64, data[8..16], parent_slot_val, .little);
            @memcpy(data[16..48], &self.parent_hash.data);
            if (existing_data_ptr) |ed| {
                const copy_bytes = existing_count * ENTRY_SIZE;
                if (ed.len >= 8 + copy_bytes) {
                    @memcpy(data[48..][0..copy_bytes], ed[8..][0..copy_bytes]);
                }
            }
        }

        // Compute LtHash deltas
        const old_lt = if (old_lt_data) |od|
            accountLtHash(&SH_PUBKEY.data, &old_lt_owner, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&SH_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, data);

        // r62: free duped old slice now that lthash is computed.
        if (old_lt_data) |od| self.allocator.free(od);

        // SYSVAR-PROBE (carrier identification) 2026-05-26
        {
            var _pb = vex_crypto.blake3.Blake3.init(.{});
            _pb.update(data);
            var _po: [32]u8 = undefined;
            _pb.final(&_po);
            std.log.debug("[SYSVAR-PROBE] slot={d} sv=SlotHashes psv_hit={any} adb_hit={any} lp={d} re={d} dl={d} ec={d} dd={any} b3={x}", .{
                self.slot, psv_hit_sh, adb_hit_sh, existing_lamports, existing_rent_epoch, data.len, existing_count, dedup_index != null, _po[0..8],
            });
        }

        try self.collectWrite(.{
            .pubkey = SH_PUBKEY,
            .lamports = existing_lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER_BYTES },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });
    }

    /// LastRestartSlot sysvar — per-slot writer.
    ///
    /// r35-fix: r35-A [SYSVAR-WRITES] probe
    /// confirmed Vexor never wrote LastRestartSlot in 10/10 sampled slots.
    /// @prov:bank.last-restart-slot-writer — this wires the missing per-slot
    /// writer at pre-execute, mirroring the Clock+SlotHashes pattern.
    ///
    /// Layout: account.data = [u64 last_restart_slot] (8 bytes total)
    ///
    /// Value: For Vexor on testnet without active hard-forks since boot,
    /// last_restart_slot = 0 always. @prov:bank.last-restart-slot-writer — the
    /// reference impl writes only when the value DIFFERS from existing, but for
    /// byte-parity in the Vexor pending_writes/lthash path we always issue the
    /// write — the lthash delta is 0 when bytes match (BLAKE3-2048 of identical
    /// bytes is identical so old_lt - new_lt = 0). This is an idempotent write
    /// with respect to bank_hash, but ensures the pending_writes flush
    /// path includes the sysvar even when its value hasn't changed.
    ///
    /// Lamports: 946_560 = rent-exempt minimum for 8-byte data.
    /// (data_len + ACCOUNT_STORAGE_OVERHEAD) * lamports_per_byte_year * 2yr
    /// = (8 + 128) * 3480 * 2 = 946_560. @prov:bank.last-restart-slot-writer —
    /// full citation trail (Sig/Firedancer/Agave file:line refs) in PROVENANCE.md.
    ///
    /// TODO (post-r35-fix): expose `bank.last_restart_slot` field computed
    /// from hard_forks list (Vexor's snapshot manifest already skips this
    /// at parse time — `skipHardForks` at snapshot_manifest.zig:305). When
    /// hard-fork tracking lands, replace the hardcoded 0 below with that
    /// field.
    pub fn updateLastRestartSlot(self: *Self) !void {
        // F3 (HARD-FORK-FAMILY-DESIGN-2026-06-17): FAIL-CLOSED hard-fork gate.
        // Key off F2's already-computed hard-fork mixin (getHashData). Invariant
        // (exact, from the design doc): getHashData(slot, parent_slot) == Some
        // ⟺ last_restart_slot changed from parent (a fork in (parent, slot]
        // strictly raises highest-fork-≤-slot; None ⟹ unchanged). So:
        //   * buf == null (EVERY post-restart testnet slot) → the value CANNOT
        //     have changed → fall through to today's preserve + skip-if-unchanged
        //     body VERBATIM (byte-identical, zero dependence on parse correctness).
        //   * buf != null (a fork crossed (parent, slot] — NEVER on testnet) →
        //     compute the highest fork ≤ slot and WRITE the sysvar.
        // This deliberately does NOT compute-then-compare against a parsed list
        // (a wrong parse → divergent LRS write → RULE #13 parity break). Parity
        // risk is moved entirely onto F1's byte-consumption (cursor KAT + soak).
        {
            const hf = if (self.accounts_db) |db| db.hard_forks else &[_]HardFork{};
            if (getHashData(hf, self.slot, self.parent_slot orelse 0)) |_| {
                // FIRING — a hard fork landed in (parent, slot]. Compute the new
                // last_restart_slot = highest fork_slot ≤ slot and write it via
                // the existing collectWrite machinery (same account/owner/lamports
                // as the preserve path). Unreachable on this node.
                const new_lrs = computeLastRestartSlot(hf, self.slot);
                const LRS_PUBKEY_F = Pubkey{ .data = .{
                    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x06, 0xdd, 0xe1,
                    0xcd, 0x3f, 0x94, 0x7d, 0xca, 0xb4, 0xc8, 0xf4,
                    0xf4, 0xf5, 0x1b, 0xad, 0x0f, 0x98, 0x13, 0xb8,
                    0x00, 0xd2, 0x89, 0x47, 0x1f, 0xc0, 0x00, 0x00,
                } };
                const SYSVAR_OWNER_F = SYSVAR_OWNER;
                const RENT_EXEMPT_LAMPORTS_F: u64 = 946_560;

                // Read the existing account (for lamports/rent_epoch/old_lt).
                var ex_lamports: u64 = RENT_EXEMPT_LAMPORTS_F;
                var ex_rent_epoch: u64 = std.math.maxInt(u64);
                var old_data_f: ?[]const u8 = null;
                var old_owner_f: [32]u8 = SYSVAR_OWNER_F;
                if (self.accounts_db) |db| {
                    const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&LRS_PUBKEY_F));
                    if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                        ex_lamports = existing.lamports;
                        ex_rent_epoch = existing.rent_epoch;
                        old_owner_f = existing.owner.data;
                        old_data_f = existing.data;
                    }
                }

                var new_bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &new_bytes, new_lrs, .little);
                const data_f = try self.allocator.dupe(u8, &new_bytes);

                // Skip-if-unchanged. @prov:bank.last-restart-slot-writer
                if (old_data_f) |od| {
                    if (od.len == data_f.len and std.mem.eql(u8, od, data_f)) {
                        self.allocator.free(data_f);
                        return;
                    }
                }

                const old_lt_f = if (old_data_f) |od|
                    accountLtHash(&LRS_PUBKEY_F.data, &old_owner_f, ex_lamports, false, od)
                else
                    null;
                const new_lt_f = accountLtHash(&LRS_PUBKEY_F.data, &SYSVAR_OWNER_F, ex_lamports, false, data_f);

                try self.collectWrite(.{
                    .pubkey = LRS_PUBKEY_F,
                    .lamports = ex_lamports,
                    .owner = Pubkey{ .data = SYSVAR_OWNER_F },
                    .executable = false,
                    .rent_epoch = ex_rent_epoch,
                    .data = data_f,
                    .old_lt = old_lt_f,
                    .new_lt = new_lt_f,
                });
                return;
            }
        }
        // ═══ buf == null: existing preserve + skip-if-unchanged body, VERBATIM ═══
        // SysvarLastRestartS1ot1111111111111111111111 — verified canonical bytes
        // via base58-decode of the pubkey string.
        //
        // r35-fix-c: the original r35-fix
        // (commit 27e0611) hand-typed bytes that base58-encoded to
        // `Sysvar1nstructionrcbw6E4xzw4Qw5oNvY8psLDYhF` — a junk pubkey
        // structurally similar to `Sysvar1nstructions1111...` but with wrong
        // trailing bytes. Vexor's `src/vex_bpf2/sysvar_cache.zig` had a
        // placeholder `SYSVAR_LAST_RESTART_SLOT_ID` constant (and 7 other
        // sysvar IDs) sharing an identical 28-byte prefix — all wrong; only
        // the last byte differed between sysvars (06/04/03/07/0b/08/09/0a).
        // r35-fix copied the broken constant verbatim.
        //
        // CLAUDE.md Common Pitfall #3 (verbatim): "Program ID bytes: NEVER
        // hand-type. Always base58 decode and verify." This bug is the
        // canonical example — cost ~1 hr of investigation cycles.
        //
        // @prov:bank.sysvar-id-cross-check — verified canonical against Sig/Firedancer
        // reference IDs + an independent base58-decode.
        //
        // Latent bug tracked separately: 7 OTHER sysvar pubkey constants in
        // sysvar_cache.zig also have placeholder bytes — all 8 need fixing
        // in a future iteration. r35-fix-c scope is intentionally minimal
        // per ("1-line bytes correction").
        const LRS_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x06, 0xdd, 0xe1,
            0xcd, 0x3f, 0x94, 0x7d, 0xca, 0xb4, 0xc8, 0xf4,
            0xf4, 0xf5, 0x1b, 0xad, 0x0f, 0x98, 0x13, 0xb8,
            0x00, 0xd2, 0x89, 0x47, 0x1f, 0xc0, 0x00, 0x00,
        } };
        const SYSVAR_OWNER_BYTES = SYSVAR_OWNER;
        const RENT_EXEMPT_LAMPORTS: u64 = 946_560;

        var existing_lamports: u64 = RENT_EXEMPT_LAMPORTS;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var old_lt_data: ?[]const u8 = null;
        var old_lt_owner: [32]u8 = SYSVAR_OWNER_BYTES;
        var adb_hit_lrs: bool = false; // SYSVAR-PROBE 2026-05-26

        if (self.accounts_db) |db| {
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&LRS_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                adb_hit_lrs = true; // SYSVAR-PROBE 2026-05-26
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                old_lt_owner = existing.owner.data;
                old_lt_data = existing.data;
            }
        }

        // r36-A diag: per-100-slot emit showing whether snapshot has the
        // LRS account + its bytes. Disambiguates the "snapshot-has-LRS"
        // vs "snapshot-doesn't-have-LRS" branches if r36-A's data-bytes
        // preserve has null effect on lthash. bonus ask.
        if (self.slot % 100 == 0) {
            if (old_lt_data) |od| {
                if (od.len >= 8) {
                    const v = std.mem.readInt(u64, od[0..8], .little);
                    std.log.debug(
                        "[LRS-EXISTING] slot={d} found=YES lamports={d} data_len={d} value={d}\n",
                        .{ self.slot, existing_lamports, od.len, v },
                    );
                } else {
                    std.log.debug(
                        "[LRS-EXISTING] slot={d} found=YES lamports={d} data_len={d} value=<<8B>\n",
                        .{ self.slot, existing_lamports, od.len },
                    );
                }
            } else {
                std.log.debug(
                    "[LRS-EXISTING] slot={d} found=NO default_lamports={d}\n",
                    .{ self.slot, existing_lamports },
                );
            }
        }

        // Build 8-byte data: u64 last_restart_slot (LE).
        //
        // r36-A: preserve existing snapshot
        // bytes when present. r35-fix-c hardcoded data = [0u64 LE] every
        // slot, ignoring what the snapshot actually held. On testnet without
        // active hard-forks since boot, the snapshot value should be 0
        // already — but if Agave's snapshot recorded a non-zero last hard
        // fork slot, r35-fix-c was overwriting it (lthash divergence).
        //
        // Default-0 branch: account doesn't exist in Vexor's accounts_db
        // (snapshot didn't load it OR fresh boot). Same as r35-fix-c default.
        //
        // TODO unchanged: when Bank.last_restart_slot field exists (computed
        // from snapshot manifest hard_forks list — currently skipped at
        // snapshot_manifest.zig:305 skipHardForks), use that field instead
        // of preserving snapshot bytes.
        var data_bytes: [8]u8 = .{0} ** 8;
        if (old_lt_data) |od| {
            if (od.len >= 8) {
                @memcpy(&data_bytes, od[0..8]);
            }
        }
        const data = try self.allocator.dupe(u8, &data_bytes);

        // r50-fix (sub-agent finding 2026-04-27). @prov:bank.last-restart-slot-writer —
        // skip-if-unchanged guard; mid-epoch testnet without recent hard
        // forks means the value never changes. Vexor's pre-r50 unconditional write
        // produced 1 extra unique pubkey in every slot's writeset (1125 vs 1124),
        // driving lthash drift.
        if (old_lt_data) |od| {
            if (od.len == data.len and std.mem.eql(u8, od, data)) {
                self.allocator.free(data);
                return;
            }
        } else {
            // No existing LRS. @prov:bank.last-restart-slot-writer
            // Without an existing record AND no change to record, write nothing.
            self.allocator.free(data);
            return;
        }

        const old_lt = if (old_lt_data) |od|
            accountLtHash(&LRS_PUBKEY.data, &old_lt_owner, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&LRS_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, data);

        // SYSVAR-PROBE (carrier identification) 2026-05-26
        {
            var _pb = vex_crypto.blake3.Blake3.init(.{});
            _pb.update(data);
            var _po: [32]u8 = undefined;
            _pb.final(&_po);
            std.log.debug("[SYSVAR-PROBE] slot={d} sv=LastRestartSlot adb_hit={any} lp={d} re={d} dl={d} b3={x}", .{
                self.slot, adb_hit_lrs, existing_lamports, existing_rent_epoch, data.len, _po[0..8],
            });
        }

        try self.collectWrite(.{
            .pubkey = LRS_PUBKEY,
            .lamports = existing_lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER_BYTES },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });
    }

    fn settleFees(self: *Self, rent_exempt_min_fn: anytype) !void {
        if (self.execution_fees == 0 and self.priority_fees == 0) return;

        const burn: u64 = self.execution_fees / 2;
        const fees_to_leader: u64 = self.priority_fees + (self.execution_fees - burn);

        // r27 cap-burn fix: debit the 50%
        // execution_fee burn from capitalization. Pre-r27 this line was
        // missing — every slot leaked +burn lamports onto Vexor's cap counter
        // (~1.3M / slot on testnet) producing the +185M..+197M cap_delta vs
        // Agave that headtohead-bankdiff.py r26 measurement surfaced over
        // 10 overlap slots. NOTE: capitalization is NOT in the bank_hash
        // chain — fixing this drops cap_delta to ~0 but does NOT close
        // bank_hash divergence (lthash drives that, separate r28 work).
        self.capitalization -= burn;

        if (fees_to_leader == 0) return;

        // Collector must not be the zero address
        const is_zero = std.mem.eql(u8, &self.collector_id.data, &([_]u8{0} ** 32));
        if (is_zero) {
            std.log.warn("[FEE] Slot {d}: collector_id is zero — burning {d} lamports", .{ self.slot, fees_to_leader });
            return;
        }

        // Find existing leader account: pending_writes overlay first, then AccountsDb
        var leader_lamports: u64 = 0;
        var leader_owner: [32]u8 = SYSTEM_PROGRAM;
        var leader_executable = false;
        var leader_rent_epoch: u64 = std.math.maxInt(u64);
        const leader_data: []const u8 = &[_]u8{};
        var found_leader = false;

        // Check pending_writes overlay first (within-slot mutations).
        // Scan REVERSE — last write per pubkey wins (matches freeze's LtHash dedup).
        {
            var i: usize = self.pending_writes.items.len;
            while (i > 0) {
                i -= 1;
                const w = &self.pending_writes.items[i];
                if (std.mem.eql(u8, &w.pubkey.data, &self.collector_id.data)) {
                    leader_lamports = w.lamports;
                    leader_owner = w.owner.data;
                    leader_executable = w.executable;
                    leader_rent_epoch = w.rent_epoch;
                    found_leader = true;
                    break;
                }
            }
        }

        // Fall through to AccountsDb (6M+ accounts from snapshot)
        if (!found_leader) {
            if (self.accounts_db) |db| {
                const core_pubkey = @as(*const @import("core").Pubkey, @ptrCast(&self.collector_id));
                if (db.getAccountInSlot(core_pubkey, self.slot, self.ancestors())) |acct| {
                    leader_lamports = acct.lamports;
                    leader_owner = acct.owner.data;
                    leader_executable = acct.executable;
                    leader_rent_epoch = acct.rent_epoch;
                    found_leader = true;
                }
            }
        }

        const new_lamports = leader_lamports + fees_to_leader;

        // @prov:bank.fee-collector-validate
        // Owner must be SystemProgram AND post-credit balance must be rent-exempt.
        const is_system_owner = std.mem.eql(u8, &leader_owner, &SYSTEM_PROGRAM);
        const rent_min = if (@TypeOf(rent_exempt_min_fn) != void)
            rent_exempt_min_fn(leader_data.len)
        else
            0; // Default: no rent check (genesis/genesis-like)
        const is_rent_exempt = new_lamports >= rent_min;

        if (!is_system_owner or !is_rent_exempt) {
            std.log.warn(
                "[FEE] Slot {d}: leader not rent-exempt or wrong owner — burning {d} lamports",
                .{ self.slot, fees_to_leader },
            );
            return;
        }

        // Compute LtHash delta for the leader credit
        const old_lt = accountLtHash(
            &self.collector_id.data,
            &leader_owner,
            leader_lamports,
            leader_executable,
            leader_data,
        );
        const new_lt = accountLtHash(
            &self.collector_id.data,
            &leader_owner,
            new_lamports,
            leader_executable,
            leader_data,
        );

        try self.collectWrite(.{
            .pubkey = self.collector_id,
            .lamports = new_lamports,
            .owner = Pubkey{ .data = leader_owner },
            .executable = leader_executable,
            .rent_epoch = leader_rent_epoch,
            .data = leader_data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Incinerator — @prov:bank.incinerator
    // ─────────────────────────────────────────────────────────────────────────

    /// Burn any lamports sent to the incinerator address.
    ///
    /// @prov:bank.incinerator
    ///
    /// The incinerator (1nc1nerator11...) is a system account. Any lamports
    /// sent there are burned by zeroing its balance in the LtHash. This reduces
    /// the total supply (capitalization) and must be reflected in the LtHash.
    fn runIncinerator(self: *Self) !void {
        // Find incinerator in pending_writes (someone sent lamports to it this slot)
        for (self.pending_writes.items, 0..) |w, i| {
            if (std.mem.eql(u8, &w.pubkey.data, &INCINERATOR)) {
                if (w.lamports == 0) return; // Already burned

                // Compute LtHash delta: remove old (non-zero) incinerator, add new (zero)
                const old_lt = accountLtHash(
                    &INCINERATOR,
                    &w.owner.data,
                    w.lamports,
                    w.executable,
                    w.data,
                );
                // New state: lamports = 0 → accountLtHash returns zero (excluded)
                const new_lt = LtHash.init();

                // Replace the write with the zeroed version
                self.pending_writes.items[i].lamports = 0;
                self.pending_writes.items[i].old_lt = old_lt;
                self.pending_writes.items[i].new_lt = new_lt;

                std.log.info("[INCINERATOR] Slot {d}: burned {d} lamports", .{ self.slot, w.lamports });
                return;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // freeze() — @prov:bank.freeze
    // ─────────────────────────────────────────────────────────────────────────

    /// Freeze the bank: commit all pending writes to LtHash, then compute bank_hash.
    ///
    /// @prov:bank.freeze
    ///
    /// ORDER MATTERS:
    ///   1. updateRecentBlockhashes()   (slot != 0)  ← caller must do pre-freeze
    ///   2. updateSlotHistory()                       ← caller must do pre-freeze
    ///   3. settleFees()                @prov:bank.settle-fees ← this function
    ///   4. runIncinerator()            @prov:bank.incinerator ← this function
    ///   5. computeBankHash()           @prov:bank.hash-calc   ← this function
    ///
    /// NOTE: Sysvars (RecentBlockhashes, SlotHistory, Clock, SlotHashes,
    ///       LastRestartSlot) must be injected into pending_writes by the
    ///       replay/tvu layer BEFORE calling freeze(). @prov:bank.freeze
    ///
    /// NOTE: poh_hash must be set from the LAST ENTRY of the slot's entry
    ///       stream before calling freeze(). It is NOT the transaction's
    ///       recent_blockhash field.

    // ─────────────────────────────────────────────────────────────────────────
    // Stake activation/deactivation curve functions
    // ─────────────────────────────────────────────────────────────────────────

    pub const StakeActivationStatus = struct {
        effective: u64,
        activating: u64,
        deactivating: u64,
    };

    pub const StakeHistoryEntry = struct {
        epoch: u64,
        effective: u64,
        activating: u64,
        deactivating: u64,
    };

    /// Look up a StakeHistory entry by epoch. Linear scan (history is small, ≤512 entries).
    fn lookupHistory(history: []const StakeHistoryEntry, epoch: u64) ?StakeHistoryEntry {
        for (history) |e| {
            if (e.epoch == epoch) return e;
        }
        return null;
    }

    /// Read StakeHistory sysvar entries from the AccountsDb.
    /// Returns a caller-owned slice of StakeHistoryEntry.
    /// Correct memory management: pre-scan count, allocate exactly that many entries.
    pub fn readStakeHistory(self: *Self, allocator: std.mem.Allocator) ![]StakeHistoryEntry {
        // r36-fix-d: canonical SysvarStakeHistory1111...
        // Hand-typed bytes pre-r36-fix-d encoded to junk pubkey
        // `SysvcSvHxSfdYpkDhuUaqWAwN52LM4aC1xQ6D8o6Y5u`. CLAUDE.md Pitfall #3
        // (third documented violation tonight after r35-fix LRS_PUBKEY +
        // sysvar_cache.zig 8-placeholder constants). @prov:bank.sysvar-id-cross-check
        const SH_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x35, 0x84, 0xd0,
            0xfe, 0xed, 0x9b, 0xb3, 0x43, 0x1d, 0x13, 0x20,
            0x6b, 0xe5, 0x44, 0x28, 0x1b, 0x57, 0xb8, 0x56,
            0x6c, 0xc5, 0x37, 0x5f, 0xf4, 0x00, 0x00, 0x00,
        } };
        const ENTRY_SIZE: usize = 32; // epoch:u64 + effective:u64 + activating:u64 + deactivating:u64

        const db = self.accounts_db orelse return &[_]StakeHistoryEntry{};
        const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&SH_PUBKEY));
        const acct = db.getAccountInSlot(core_pk, self.slot, self.ancestors()) orelse return &[_]StakeHistoryEntry{};

        if (acct.data.len < 8) return &[_]StakeHistoryEntry{};

        // Pre-scan: read count, validate against available data
        const raw_count = std.mem.readInt(u64, acct.data[0..8], .little);
        const max_possible = (acct.data.len - 8) / ENTRY_SIZE;
        const count = @min(raw_count, max_possible);

        if (count == 0) return &[_]StakeHistoryEntry{};

        // Allocate exactly count entries (no subslice UB)
        const entries = try allocator.alloc(StakeHistoryEntry, count);
        var off: usize = 8;
        for (0..count) |i| {
            entries[i] = .{
                .epoch = std.mem.readInt(u64, acct.data[off..][0..8], .little),
                .effective = std.mem.readInt(u64, acct.data[off + 8 ..][0..8], .little),
                .activating = std.mem.readInt(u64, acct.data[off + 16 ..][0..8], .little),
                .deactivating = std.mem.readInt(u64, acct.data[off + 24 ..][0..8], .little),
            };
            off += ENTRY_SIZE;
        }
        return entries;
    }

    /// Compute effective/activating/deactivating stake for a delegation at target_epoch.
    ///
    /// @prov:bank.stake-activation-status — 9 correctness properties verified against
    /// the reference impl (warmup/cooldown base = e.effective ONLY, @max(_,1) floor,
    /// saturating cooldown subtraction, bootstrap = fully effective, mid-warmup/cooldown
    /// null-entry break-not-jump semantics). Full citation trail (exact source line
    /// numbers per property) in PROVENANCE.md.
    /// Per-epoch warmup/cooldown rate (Agave solana-stake-interface
    /// `warmup_cooldown_rate(current_epoch, new_rate_activation_epoch)`):
    /// 25%/epoch before the `reduce_stake_warmup_cooldown` activation epoch,
    /// 9%/epoch from it onward. `new_rate_activation_epoch == 0` → always 9%
    /// (used by tests and the in-tx stake program which previously assumed a
    /// flat 9%). carrier #16 final root cause (@414812256): Vexor used flat
    /// 0.09 for ALL epochs — canonical evaluates the rate PER LOOP EPOCH, so
    /// every warmup/cooldown trajectory crossing epochs < 586 (testnet
    /// reduce_stake_warmup_cooldown @slot 247628260) diverged → total_points
    /// off by −9.84e10 → EpochRewards sysvar + reward distribution divergence.
    /// Offline lab (carrier16_lab.py over all 558,757 delegations): flat 0.09
    /// diff +7.9e17; rate-schedule diff EXACTLY 0 vs canonical.
    fn warmupCooldownRate(current_epoch: u64, new_rate_activation_epoch: u64) f64 {
        return if (new_rate_activation_epoch != 0 and current_epoch < new_rate_activation_epoch) 0.25 else 0.09;
    }

    pub fn getStakeActivationStatus(
        activation_epoch: u64,
        deactivation_epoch: u64,
        stake: u64,
        target_epoch: u64,
        history: []const StakeHistoryEntry,
        new_rate_activation_epoch: u64,
    ) StakeActivationStatus {
        // Phase 1: compute the warmed-up (effective) amount, then fall through to
        // the SHARED deactivation handling below.
        var current_effective: u64 = 0;
        if (activation_epoch == std.math.maxInt(u64)) {
            // Bootstrap (genesis) stake: instantly fully effective, NO warmup.
            // @prov:bank.stake-activation-status — bootstrap returns (stake, 0).
            // CRITICAL (carrier #16 @414812256): this must STILL fall through to the
            // deactivation logic below — a bootstrap stake that later set a
            // deactivation_epoch cools down like any other. The old code early-
            // returned {stake,0,0} and SKIPPED deactivation, so 4 testnet genesis
            // stakes deactivated @epoch 90 (~500k SOL each) were kept fully
            // effective → StakeHistory effective sum +1999999990868480 (~2M SOL) →
            // epoch-973 boundary StakeHistory-sysvar + total_points divergence.
            current_effective = stake;
        } else {
            // Activated and deactivated in same epoch = zero stake. @prov:bank.stake-activation-status
            if (activation_epoch == deactivation_epoch) {
                return .{ .effective = 0, .activating = 0, .deactivating = 0 };
            }
            // Not yet activated
            if (target_epoch < activation_epoch) {
                return .{ .effective = 0, .activating = 0, .deactivating = 0 };
            }
            // At activation epoch: nothing effective yet, all activating. @prov:bank.stake-activation-status
            if (target_epoch == activation_epoch) {
                return .{ .effective = 0, .activating = stake, .deactivating = 0 };
            }

            // Warmup from activation_epoch to min(target_epoch, deactivation_epoch)
            var epoch = activation_epoch;
            const warmup_end = @min(target_epoch, deactivation_epoch);
            while (epoch < warmup_end) : (epoch += 1) {
                const entry = lookupHistory(history, epoch);
                if (entry) |e| {
                    if (e.activating == 0) {
                        // No cluster-wide activating stake = instant activation
                        current_effective = stake;
                        break;
                    }
                    const remaining = stake - current_effective;
                    const weight: f64 = @as(f64, @floatFromInt(remaining)) /
                                        @as(f64, @floatFromInt(e.activating));
                    // CRITICAL: base is e.effective ONLY. Rate evaluated at current_epoch =
                    // epoch+1 (reference loop's prev_epoch+1). @prov:bank.stake-activation-status
                    const newly_effective_cluster: f64 = @as(f64, @floatFromInt(e.effective)) * warmupCooldownRate(epoch + 1, new_rate_activation_epoch);
                    const newly_effective: u64 = @max(@as(u64, @intFromFloat(weight * newly_effective_cluster)), 1);
                    current_effective += newly_effective;
                    if (current_effective >= stake) {
                        current_effective = stake;
                        break;
                    }
                } else {
                    // CRITICAL FIX (NEW-BUG-2): Mid-warmup null = keep partial accumulation.
                    // Only the INITIAL lookup (activation_epoch entry missing) returns fully
                    // activated — that case is when epoch == activation_epoch. @prov:bank.stake-activation-status
                    if (epoch == activation_epoch) {
                        // Initial entry missing = fully activated
                        current_effective = stake;
                    }
                    // Otherwise: mid-warmup, just break with partial
                    break;
                }
            }
        }
        current_effective = @min(current_effective, stake);

        // Not deactivating: return warmup result
        if (target_epoch < deactivation_epoch) {
            return .{
                .effective = current_effective,
                .activating = stake - current_effective,
                .deactivating = 0,
            };
        }

        // At deactivation epoch: all effective stake is now deactivating.
        // @prov:bank.stake-activation-status
        if (target_epoch == deactivation_epoch) {
            return .{
                .effective = current_effective,
                .activating = 0,
                .deactivating = current_effective,
            };
        }

        // Phase 2: Cooldown from deactivation_epoch to target_epoch
        //
        // @prov:bank.stake-activation-status — if entry at deactivation_epoch missing, return .{} (all zeros)
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
                // CRITICAL: base is e.effective ONLY. Rate evaluated at current_epoch =
                // cool_epoch+1 (reference loop's prev_epoch+1). @prov:bank.stake-activation-status
                const newly_not_effective_cluster: f64 = @as(f64, @floatFromInt(e.effective)) * warmupCooldownRate(cool_epoch + 1, new_rate_activation_epoch);
                const newly_not_effective: u64 = @max(1, std.math.lossyCast(u64, weight * newly_not_effective_cluster));
                // Saturating subtraction. @prov:bank.stake-activation-status
                remaining_eff -|= newly_not_effective;
                if (remaining_eff == 0) break;
            } else {
                // CRITICAL FIX (NEW-BUG-3): Mid-cooldown null = keep remaining as-is.
                // @prov:bank.stake-activation-status
                break;
            }
        }

        // CRITICAL: deactivating = remaining_eff (stake still in cooldown)
        // NOT current_effective - remaining_eff (that's amount already cooled)
        // @prov:bank.stake-activation-status
        return .{
            .effective = remaining_eff,
            .activating = 0,
            .deactivating = remaining_eff,
        };
    }

    /// carrier #16 @414812256: per-epoch stake-points (Agave
    /// inflation_rewards/points.rs `calculate_stake_points_and_credits`).
    /// The stake's effective amount is recomputed at EACH epoch in the vote's
    /// epoch_credits window via the activation curve — NOT a single
    /// effective-at-prev-epoch value. For warming/cooling stakes the per-epoch
    /// effective differs; the old single-value path undercounted total_points
    /// (deactivating stakes: effective@971 > effective@972) by ~9.84e10.
    /// `raw_stake` is the delegation's nominal lamports (delegation.stake),
    /// fed through the curve per epoch exactly like Agave's
    /// `stake.delegation.stake(epoch, stake_history, ...)`.
    // VEX_DUMP_STAKEPTS instrumentation (epoch-979 credits-side carrier localization 2026-06-24).
    // Log-only; gated by StakePtDump.on (armed from env in processEpochBoundary). The serial
    // reward calc is single-threaded → plain namespaced globals are safe. Classifies each COUNTED
    // credit-window row by whether its epoch == the rewarded epoch, is OLDER (multi-epoch-gap
    // catch-up / suspect #2 per-epoch curve), or is NEWER (an "extra in-progress next-epoch row"
    // would land here → suspect #1). Zero baseline effect when off.
    const StakePtDump = struct {
        var on: bool = false;
        var rewarded_epoch: u64 = 0;
        var pts_rewarded: u128 = 0;
        var pts_older: u128 = 0;
        var pts_newer: u128 = 0;
        var rows_older: u64 = 0;
        var rows_newer: u64 = 0;
        var multirow_delegs: u64 = 0;
        var earned_total: u128 = 0;
        var counted_rows: u64 = 0;
        var n_delegs: u64 = 0;
        // rewarded-epoch-row sub-classification by credits_observed vs the row's initial credits:
        var pts_rew_normal: u128 = 0; // co == initial (rewarded last epoch → full delta; certainly correct)
        var pts_rew_below: u128 = 0; //  co <  initial (multi-epoch gap; full delta + older rows)
        var pts_rew_partial: u128 = 0; // initial < co < final (touched mid-epoch → canonical = PARTIAL; SUSPECT)
        var n_rew_partial: u64 = 0;
        var per_del_dumped: u64 = 0;
    };

    fn computeStakePointsPerEpoch(
        epoch_credits: []const rewards_mod.EpochCreditsEntry,
        credits_observed: u64,
        activation_epoch: u64,
        deactivation_epoch: u64,
        raw_stake: u64,
        new_rate_activation_epoch: u64,
        history: []const StakeHistoryEntry,
    ) rewards_mod.StakePoints {
        const credits_in_vote: u64 = if (epoch_credits.len > 0)
            epoch_credits[epoch_credits.len - 1].credits
        else
            0;

        // Vote has fewer credits than the stake observed → force credit rewind.
        if (credits_in_vote < credits_observed) {
            return .{ .points = 0, .new_credits_observed = credits_in_vote, .force_credits_update_with_skipped_reward = true };
        }
        // No new credits since last observation (delinquent) → zero points.
        if (credits_in_vote == credits_observed) {
            return .{ .points = 0, .new_credits_observed = credits_in_vote, .force_credits_update_with_skipped_reward = false };
        }

        var total_points: u128 = 0;
        var new_credits_observed: u64 = credits_observed;
        var dump_counted: u64 = 0;
        for (epoch_credits) |ec| {
            const final_credits = ec.credits;
            const initial_credits = ec.prev_credits;
            std.debug.assert(initial_credits <= final_credits);
            if (final_credits <= credits_observed) continue;

            // PER-EPOCH effective stake (Agave stake.delegation.stake(epoch, ...)).
            const stake_amount: u64 = getStakeActivationStatus(
                activation_epoch,
                deactivation_epoch,
                raw_stake,
                ec.epoch,
                history,
                new_rate_activation_epoch,
            ).effective;

            const earned_credits: u64 = if (credits_observed < initial_credits)
                final_credits - initial_credits
            else
                final_credits - new_credits_observed;

            new_credits_observed = @max(new_credits_observed, final_credits);
            const contrib: u128 = @as(u128, stake_amount) * @as(u128, earned_credits);
            total_points += contrib;
            if (StakePtDump.on) {
                dump_counted += 1;
                StakePtDump.counted_rows += 1;
                StakePtDump.earned_total += @as(u128, earned_credits);
                if (ec.epoch == StakePtDump.rewarded_epoch) {
                    StakePtDump.pts_rewarded += contrib;
                    if (credits_observed == initial_credits) {
                        StakePtDump.pts_rew_normal += contrib;
                    } else if (credits_observed < initial_credits) {
                        StakePtDump.pts_rew_below += contrib;
                    } else {
                        StakePtDump.pts_rew_partial += contrib;
                        StakePtDump.n_rew_partial += 1;
                    }
                } else if (ec.epoch < StakePtDump.rewarded_epoch) {
                    StakePtDump.pts_older += contrib;
                    StakePtDump.rows_older += 1;
                } else {
                    StakePtDump.pts_newer += contrib;
                    StakePtDump.rows_newer += 1;
                }
            }
        }
        if (StakePtDump.on) {
            StakePtDump.n_delegs += 1;
            if (dump_counted > 1) StakePtDump.multirow_delegs += 1;
        }

        return .{ .points = total_points, .new_credits_observed = new_credits_observed, .force_credits_update_with_skipped_reward = false };
    }

    /// @prov:bank.warmup-cooldown-rate-epoch
    /// the EPOCH at which `reduce_stake_warmup_cooldown` activated (testnet:
    /// slot 247628260 → epoch 586). Warmup/cooldown trajectories use 25%/epoch
    /// before it and 9%/epoch from it onward. Returns 0 when the feature
    /// account is absent/inactive (sentinel = always-9%; canonical inactive
    /// behavior is always-25%, but testnet/mainnet both activated this long
    /// ago — 0 is only reachable in tests).
    /// Read a feature account (fork-aware at self.slot) and report whether it
    /// is active at the current slot. Feature account layout: bincode
    /// Option<u64> activated_at = [u8 tag][u64 slot LE].
    pub fn featureActiveAtSlot(self: *Self, feature_pubkey: [32]u8) bool {
        const db2 = self.accounts_db orelse return false;
        var pk = feature_pubkey;
        const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&pk));
        const acct = db2.getAccountInSlot(core_pk, self.slot, self.ancestors()) orelse return false;
        if (acct.data.len < 9 or acct.data[0] != 1) return false;
        const aslot = std.mem.readInt(u64, acct.data[1..9], .little);
        return aslot <= self.slot;
    }

    /// pending_writes-overlay variant of `featureActiveAtSlot`, used ONLY by the
    /// epoch-boundary reward commission gate. A feature that activates AT this
    /// boundary slot is rewritten (disc 0→1) into `pending_writes` by
    /// applyNewFeatureActivations (replay_stage.zig), which runs BEFORE
    /// processEpochBoundary's reward calc — but it is NOT yet flushed to
    /// AccountsDb, so the committed-db read in `featureActiveAtSlot` misses it and
    /// returns a STALE false on the activation slot. @prov:bank.feature-activation-overlay —
    /// the reference impl reads the in-memory feature_set (snapshot reflecting
    /// just-applied activations) at the reward calc, so it sees the feature ACTIVE
    /// on the boundary slot. Mirror that here
    /// by consulting pending_writes (newest-first) first, falling back to the
    /// committed read. Scoped to the reward gate so all other `featureActiveAtSlot`
    /// callers stay byte-identical. (Masked at epoch 977: whole-% commissions give
    /// bps == pct*100; bites a future boundary that activates a reward-gating
    /// feature alongside a fractional-bps commission.)
    pub fn featureActiveAtSlotOverlay(self: *Self, feature_pubkey: [32]u8) bool {
        var i: usize = self.pending_writes.items.len;
        while (i > 0) {
            i -= 1;
            const w = &self.pending_writes.items[i];
            if (std.mem.eql(u8, &w.pubkey.data, &feature_pubkey)) {
                if (w.data.len < 9 or w.data[0] != 1) return false;
                const aslot = std.mem.readInt(u64, w.data[1..9], .little);
                return aslot <= self.slot;
            }
        }
        return self.featureActiveAtSlot(feature_pubkey);
    }

    /// Return a feature account's `activated_at` slot as `?u64` (null when the
    /// account is absent or not yet activated). Same fork-aware AccountsDb read
    /// and bincode `Option<u64>` parse as `featureActiveAtSlot`, but it preserves
    /// the activation SLOT instead of collapsing to a bool — required for the
    /// epoch-delayed shred-ingest gates (SIMD-0337), which need the raw slot to
    /// compute `feature_epoch < shred_epoch`.
    pub fn featureActivationSlot(self: *Self, feature_pubkey: [32]u8) ?u64 {
        const db2 = self.accounts_db orelse return null;
        var pk = feature_pubkey;
        const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&pk));
        const acct = db2.getAccountInSlot(core_pk, self.slot, self.ancestors()) orelse return null;
        // Feature account layout: bincode Option<u64> activated_at =
        // [u8 tag][u64 slot LE]; tag 1 = Some, tag 0 = None (pending).
        if (acct.data.len < 9 or acct.data[0] != 1) return null;
        return std.mem.readInt(u64, acct.data[1..9], .little);
    }

    /// SIMD-0337 (discard_unexpected_data_complete_shreds) epoch-delayed gate.
    /// @prov:bank.simd0337-shred-gate — reads `discard_unexpected_data_complete_shreds`'s activation slot from
    /// this (root) bank's fork-aware AccountsDb, then applies the epoch-delayed
    /// rule via EpochSchedule.checkFeatureActivation against `shred_slot`.
    ///
    /// Returns true ONLY when the feature is EFFECTIVE for `shred_slot` (i.e. the
    /// shred's epoch is strictly past the feature's activation epoch). Returns
    /// false — meaning KEEP, never discard — whenever the feature is absent, not
    /// yet activated, or activated in the same/later epoch as the shred. This is
    /// the consensus-critical default: a wrong discard breaks shred ingest, so
    /// the gate is conservative (default-keep) on every uncertain path.
    ///
    /// NOTE: uses the plain committed AccountsDb read (NOT the pending_writes
    /// overlay). The epoch delay makes the boundary-staleness the overlay fixes
    /// irrelevant here: by the time this gate can ever fire (one full epoch after
    /// activation) the activation is long committed and flushed.
    pub fn discardUnexpectedDataCompleteEffective(self: *Self, shred_slot: u64) bool {
        const act = self.featureActivationSlot(@import("features.zig").DATA_COMPLETE_SHRED_PLACEMENT);
        return self.epoch_schedule.checkFeatureActivation(act, shred_slot);
    }

    pub fn getNewRateActivationEpoch(self: *Self) u64 {
        const ftr = @import("features.zig");
        const db2 = self.accounts_db orelse return 0;
        var pk = ftr.REDUCE_STAKE_WARMUP_COOLDOWN;
        const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&pk));
        const acct = db2.getAccountInSlot(core_pk, self.slot, self.ancestors()) orelse return 0;
        if (acct.data.len < 9 or acct.data[0] != 1) return 0;
        const aslot = std.mem.readInt(u64, acct.data[1..9], .little);
        if (aslot > self.slot) return 0;
        return self.epoch_schedule.getEpoch(aslot);
    }

    /// @prov:bank.inflation-start-slot
    ///
    /// Reads the full-inflation feature accounts from the AccountsDb (fork-aware,
    /// at self.slot) and replicates Agave's selection:
    ///   1. full_inflation_features_enabled(): the certusone pair (vote AND enable
    ///      both active → use enable_id's activation slot) UNION devnet_and_testnet
    ///      (if active → its activation slot).
    ///   2. If that set is non-empty, return the MINIMUM activation slot.
    ///   3. Otherwise fall back to pico_inflation's activation slot.
    ///   4. Otherwise 0.
    /// This is cluster-agnostic (correct for mainnet certusone AND testnet pico),
    /// per RULE #0 — no hardcoded testnet constant.
    ///
    /// carrier #16 @414812256: was hardcoded `0` at the call site → year measured
    /// from genesis (5.26y) instead of from pico activation (4.63y) → validator_rate
    /// 0.034 instead of canonical 0.07065 → boundary bank_hash divergence.
    fn getInflationStartSlot(self: *Self) u64 {
        const ftr = @import("features.zig");
        const db = self.accounts_db orelse return 0;
        const slot = self.slot;
        const anc = self.ancestors();

        // Read a feature account's bincode `activated_at: Option<u64>`.
        // Layout: [u8 tag (0=None,1=Some)] [u64 slot LE]. Returns the activation
        // slot only when present AND already active at `slot`.
        const Reader = struct {
            fn activation(d: anytype, pk_bytes: [32]u8, s: u64, a: []const u64) ?u64 {
                var pk = pk_bytes;
                const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&pk));
                const acct = d.getAccountInSlot(core_pk, s, a) orelse return null;
                if (acct.data.len < 9 or acct.data[0] != 1) return null;
                const aslot = std.mem.readInt(u64, acct.data[1..9], .little);
                if (aslot > s) return null;
                return aslot;
            }
        };

        var min_full: ?u64 = null;
        // certusone mainnet pair: BOTH vote and enable must be active → enable slot.
        const vote = Reader.activation(db, ftr.FULL_INFLATION_MAINNET_CERTUSONE_VOTE, slot, anc);
        const enable = Reader.activation(db, ftr.FULL_INFLATION_MAINNET_CERTUSONE_ENABLE, slot, anc);
        if (vote != null and enable != null) min_full = enable.?;
        // devnet_and_testnet single feature.
        if (Reader.activation(db, ftr.FULL_INFLATION_DEVNET_AND_TESTNET, slot, anc)) |dt| {
            min_full = if (min_full) |m| @min(m, dt) else dt;
        }
        if (min_full) |m| return m;
        // Fallback: pico_inflation.
        if (Reader.activation(db, ftr.PICO_INFLATION, slot, anc)) |p| return p;
        return 0;
    }

    /// Process epoch boundary operations.
    /// Called at the first slot of a new epoch, BEFORE transaction execution.
    /// Calculates inflation rewards, distributes vote rewards immediately,
    /// and sets up partitioned stake reward distribution across subsequent slots.
    ///
    /// BUG-1 fix: This is now pub and called from replay_stage.zig pre-execute.
    /// @prov:bank.epoch-boundary-pre-execute — it is no longer called from freeze().
    pub fn processEpochBoundary(self: *Self, new_epoch: u64) !void {
        const prev_epoch = if (new_epoch > 0) new_epoch - 1 else 0;
        // VEX_DUMP_STAKEPTS: arm the credits-side localization dump for this boundary (log-only).
        StakePtDump.on = std.posix.getenv("VEX_DUMP_STAKEPTS") != null;
        StakePtDump.rewarded_epoch = prev_epoch;
        StakePtDump.pts_rewarded = 0;
        StakePtDump.pts_older = 0;
        StakePtDump.pts_newer = 0;
        StakePtDump.rows_older = 0;
        StakePtDump.rows_newer = 0;
        StakePtDump.multirow_delegs = 0;
        StakePtDump.earned_total = 0;
        StakePtDump.counted_rows = 0;
        StakePtDump.n_delegs = 0;
        StakePtDump.pts_rew_normal = 0;
        StakePtDump.pts_rew_below = 0;
        StakePtDump.pts_rew_partial = 0;
        StakePtDump.n_rew_partial = 0;
        StakePtDump.per_del_dumped = 0;
        const vote_serde = @import("native/vote_state_serde.zig");
        const ss = @import("native/stake_state.zig");

        std.log.warn("[EPOCH] Boundary detected: epoch {d} to {d}", .{ prev_epoch, new_epoch });

        // r39 inflation-math fix — three multiplicatively-stacking bugs
        // (byte-diff + smoking-gun forensics,
        //  helm-fresh primary-source verification 2026-04-27T20:50Z).
        //
        // Combined effect (all three): Vexor inflation pool was ~2.23× Agave's per
        // epoch on testnet, distributing as +25%-ish per-slot cap drift through both
        // bank.zig:~1947 (vote_reward_total +=) and bank.zig:~2232 (lamports_distributed
        // +=). Empirically: r38 verdict 60-slot live-tip +346k/slot drift + ~1B
        // catchup-window spike vs Agave oracle-node (bank-frozen capitalization field).
        //
        // Bug 1: Inflation.initial — was 0.15 (rewards.zig:82 struct default), should
        //   be 0.08. Agave testnet runs Inflation::full() (runtime/src/bank.rs:5714).
        //   Source: solana-inflation-3.1.0/src/lib.rs DEFAULT_INITIAL = 0.08 +
        //   Inflation::full() { initial: DEFAULT_INITIAL, ... }. Magnitude: 1.875×
        //   rate over-credit.
        //
        // Bug 2: Inflation.foundation — was 0.05 (rewards.zig:88), should be 0.0.
        //   Agave's Inflation::full() explicitly sets foundation: 0.0 (lib.rs).
        //   `validator(year) = total - foundation`, so Vexor's 0.05 subtracts 5%
        //   that Agave doesn't, partially OFFSETTING Bug 1. Net validator-rate
        //   ratio = 0.15 × 0.95 / (0.08 × 1.0) ≈ 1.78×.
        //
        // Bug 3: slots_per_year — was 63_072_000.0 (= 2 slots/sec × 365 days × 86400),
        //   should be 78_892_314.98 (= 365.242199 × 86400 × 160 / 64). Solana's
        //   actual `years_as_slots(...)` uses SIDEREAL year (365.242199 days) per
        //   solana-time-utils-3.0.0/src/lib.rs:15:
        //     pub const SECONDS_PER_YEAR: f64 = 365.242_199 * 24.0 * 60.0 * 60.0;
        //   With ticks_per_slot=64 and tick_duration=6.25ms (DEFAULT_TICKS_PER_SECOND
        //   =160), seconds_per_slot=0.4, so slots_per_year ≈ 78_892_314.98. Note: a
        //   *different* SECONDS_PER_YEAR=365.25*86400 exists in agave-v4.0.0-beta.7/
        //   runtime/src/bank.rs:236 (Julian-year), but it is NOT the constant fed
        //   into years_as_slots() — that's a localized constant for other tests.
        //   Magnitude: Vexor's epoch_duration_in_years over-counts by 1.2508×.
        //
        // Combined ratio = 1.78 × 1.2508 ≈ 2.23× — matches the byte-diff forensics.
        //
        // Root cause in Vexor: snapshot_manifest.zig:382-385 calls skipInflation()
        // which discards the 6 inflation f64 fields from the snapshot rather than
        // parsing them. Falls back to rewards.zig struct defaults (which also need
        // defensive correction — see rewards.zig:82,88). Proper fix (deferred to
        // r40+): parse the 6 fields from the snapshot.
        //
        // Anti-regression: 22+ invariants from r28→r38 chain preserved including
        // r38 RBH parent-inheritance, r37-diag PROBE-SYSVAR-BYTES envelope,
        // r36-fix-e canonical sysvar pubkeys. Stable rollback eacb9c42 untouched.
        // r38 binary c4a49cea preserved.
        //
        // Lineage: forward-port (per HARD_RULE feedback_forward_port_not_revert).
        //   2026-04-15 council: capitalization INPUT fix (use snapshot value, not
        //                       hardcoded 500M SOL). See vault/research/2026-04-15-
        //                       epoch-capitalization-gap.md
        //   r39 (today):       inflation CONSTANT fixes (multiplier).
        //   r40+ (queued):     StakeHistory + warmup curves + commission BPS.
        // carrier #16 @414812256: the prior "r39" change set initial=0.08 believing
        // testnet runs Inflation::full(). The LIVE testnet inflation governor
        // (verified 2026-06-12 via oracle-node getInflationGovernor) is:
        //   initial=0.15, taper=0.15, terminal=0.015, foundation=0.0, foundationTerm=0.0
        // i.e. Agave Inflation::default() with foundation zeroed in genesis. Matched
        // byte-exact: initial=0.15 + inflation_start=pico(49772256) reproduces the
        // canonical validator_rate 0.07065150777974875 exactly (spy=78892314.984).
        const inflation = rewards_mod.Inflation{
            .initial = 0.15,
            .terminal = 0.015,
            .taper = 0.15,
            .foundation = 0.0,
            .foundation_term = 0.0,
        };
        const slots_per_year: f64 = 78_892_314.984;
        const reward_sched = rewards_mod.EpochSchedule{
            .slots_per_epoch = self.epoch_schedule.slots_per_epoch,
            .first_normal_epoch = self.epoch_schedule.first_normal_epoch,
            .first_normal_slot = self.epoch_schedule.first_normal_slot,
        };

        // Use real capitalization loaded from snapshot manifest at bootstrap.
        const capitalization: u64 = self.capitalization;

        // carrier #16: was hardcoded `0` (year measured from genesis). Canonical
        // Agave reads the inflation-feature activation slot (testnet: pico_inflation
        // @49772256 → epoch-normalized → num_slots 365472000 → year 4.6325).
        const inflation_start_slot = self.getInflationStartSlot();

        const inflation_rewards = rewards_mod.calculatePreviousEpochInflationRewards(
            inflation, reward_sched, slots_per_year, capitalization, self.slot, inflation_start_slot, prev_epoch,
        );

        std.log.warn("[EPOCH-INFLATION] slot={d} prev_epoch={d} cap={d} inflation_start={d} validator_rate={d:.17} validator_rewards={d} (canonical rate=0.07065150777974875 rewards=809764033810611)", .{
            self.slot, prev_epoch, capitalization, inflation_start_slot,
            inflation_rewards.validator_rate,
            inflation_rewards.validator_rewards,
        });

        // BUG-4/6 fix: propagate errors instead of silently returning success.
        const db = self.accounts_db orelse return error.NoAccountsDb;

        // ── Scan vote accounts ──────────────────────────────────────────────
        const vote_owner = Pubkey{ .data = .{
            0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
            0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
            0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
            0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
        } };
        const vote_accounts = try db.scanByOwner(&vote_owner, self.ancestors(), self.slot, self.allocator);
        defer self.allocator.free(vote_accounts);
        std.log.warn("[EPOCH] Found {d} vote accounts", .{vote_accounts.len});

        // ── Scan stake accounts ─────────────────────────────────────────────
        const stake_owner = Pubkey{ .data = .{
            0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
            0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
            0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
            0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
        } };
        const stake_accounts = try db.scanByOwner(&stake_owner, self.ancestors(), self.slot, self.allocator);
        defer self.allocator.free(stake_accounts);
        std.log.warn("[EPOCH] Found {d} stake accounts", .{stake_accounts.len});

        // ── Build vote account index (pubkey → array index) ─────────────────
        var vote_idx = std.AutoHashMap([32]u8, usize).init(self.allocator);
        defer vote_idx.deinit();
        for (vote_accounts, 0..) |va, i| {
            vote_idx.put(va.pubkey.data, i) catch continue;
        }

        // ── Deserialize vote states → VoteRewardAccumulator[] ───────────────
        // We need epoch_credits and commission from each vote account.
        var vote_accums = std.ArrayListUnmanaged(rewards_mod.VoteRewardAccumulator){};
        defer vote_accums.deinit(self.allocator);
        try vote_accums.ensureTotalCapacity(self.allocator, vote_accounts.len);

        // Canonical per-account ownership (mirrors Agave `VoteStateView` /
        // Firedancer `fd_epoch_credits_t`): each accumulator OWNS its
        // `epoch_credits` slice. The prior code sliced into ONE shared,
        // un-reserved `ec_storage` ArrayList — those slices DANGLED when it
        // reallocated mid-loop (use-after-realloc), and were read later in
        // `calculateRewards`. That UAF crashed the epoch boundary 2026-06-04,
        // surfaced as a MIS-ATTRIBUTED "incorrect alignment" panic at the
        // `vs.epoch_credits[ei]` read (the by-value VoteState access is in fact
        // align-8 and faultless — proven by probe). Per-account owned slices
        // remove the whole class of bug. This defer is declared AFTER
        // `vote_accums.deinit` so it runs FIRST (LIFO) — `.items` is still valid
        // when we free — and it covers every return, including the
        // `delegations.items.len == 0` early return below.
        defer for (vote_accums.items) |a| self.allocator.free(a.epoch_credits);

        // Track which vote_accounts[] index maps to which vote_accums[] index
        var va_to_accum = try self.allocator.alloc(?usize, vote_accounts.len);
        defer self.allocator.free(va_to_accum);
        @memset(va_to_accum, null);

        // carrier #16 DELAYED COMMISSION (Agave delay_commission_updates,
        // active on testnet @406604256; calculation.rs:487-502 +
        // bank.rs get_cached_vote_accounts): the commission used for the
        // boundary reward split comes from the vote state FROZEN in
        // epoch_stakes(rewarded_epoch) — i.e. saved a full epoch earlier,
        // "to prevent last minute commission rugs" — falling back to
        // epoch_stakes(current_epoch), then the live state. EGnc8M9Q raised
        // commission 8%→100% mid-epoch; reading the live state paid the voter
        // 12.5× canonical. Maps built from the manifest's versioned
        // epoch_stakes tables (frozen vote-account commission captured at
        // parse). commission_rate_in_basis_points (Eg7tXEwM..) is INACTIVE on
        // testnet → canonical uses the legacy u8 percent ×100 path
        // (VoteStateView::commission(): V4 = min(bps/100,255)) — the raw-bps
        // path only applies once that feature activates.
        // Overlay reads: a feature that activates AT this boundary slot is in
        // pending_writes (disc 0→1) but not yet flushed; the committed read would
        // return a stale false on the activation slot, diverging from Agave's
        // in-memory feature_set. COMMISSION_RATE_IN_BASIS_POINTS first activates
        // exactly here (epoch 977), so it MUST use the overlay. DELAY_COMMISSION_
        // UPDATES activated long ago → overlay falls through to the committed read
        // (not in pending_writes) → unchanged.
        const delay_commission_active = self.featureActiveAtSlotOverlay(@import("features.zig").DELAY_COMMISSION_UPDATES);
        const commission_bps_active = self.featureActiveAtSlotOverlay(@import("features.zig").COMMISSION_RATE_IN_BASIS_POINTS);
        var es_comm_rewarded = std.AutoHashMap([32]u8, u16).init(self.allocator);
        defer es_comm_rewarded.deinit();
        var es_comm_current = std.AutoHashMap([32]u8, u16).init(self.allocator);
        defer es_comm_current.deinit();
        if (delay_commission_active) {
            for (db.epoch_stakes) |entry| {
                const tgt: ?*std.AutoHashMap([32]u8, u16) =
                    if (entry.epoch == prev_epoch) &es_comm_rewarded
                    else if (entry.epoch == new_epoch) &es_comm_current
                    else null;
                if (tgt) |t| {
                    for (entry.vote_account_stakes, 0..) |vas, ci| {
                        const bps: u16 = if (commission_bps_active and ci < entry.commission_bps.len)
                            entry.commission_bps[ci]
                        else if (ci < entry.commission_percent.len)
                            @as(u16, entry.commission_percent[ci]) * 100
                        else
                            continue;
                        t.put(vas.vote_pubkey, bps) catch break;
                    }
                }
            }
            std.log.warn("[EPOCH-DELAY-COMM] active; es({d})={d} votes, es({d})={d} votes", .{
                prev_epoch, es_comm_rewarded.count(), new_epoch, es_comm_current.count(),
            });
        }

        // ── SIMD-0357 Validator Admission Ticket (VAT) — reward vote-set filter ──
        // feature `validator_admission_ticket` ACTIVATES at the epoch-979 boundary
        // (slot 417404256). When active, canonical reward-points restricts the vote
        // accounts to the ADMITTED set BEFORE computing points — Vexor without it
        // over-counts total_points by the excluded votes' points (+11.7% at 979,
        // dominated by validators whose VoteStateV4 BLS pubkey is unset).
        // Canonical: Agave rc.1 bank.rs:6056 maybe_filter_vote_accounts_for_vat →
        // vote/src/vote_account.rs:197 clone_and_filter_for_vat (RULE#16: read 2026-06-24;
        // FD cross-check fd_stakes.c:846 same gate). Criteria, per vote account:
        //   has_bls   = VoteStateV4 bls_pubkey_compressed present
        //   has_stake = delegated stake != 0
        //   has_balance = lamports >= rent.minimum_balance(VoteStateV4::size_of())
        //                 (+VAT_TO_BURN_PER_EPOCH 1.6 SOL ONLY if alpenglow active —
        //                  NOT active at 979)
        // then if more than MAX(2000) remain, drop all whose stake <= the 2000th-ranked
        // stake (STRICT; ties at the boundary dropped → can yield <2000).
        // A non-admitted vote earns 0 points + no credits write — IDENTICAL to Vexor's
        // existing `rej_novote` skip — so we implement it by filtering `delegations[]`
        // AFTER the loop (keeping the [EPOCH-STAKESUM] sums over ALL delegations, since
        // StakeHistory is NOT VAT-filtered). Use the OVERLAY feature read (the feature
        // activates AT this boundary slot; committed read would be a stale false — see
        // carrier #16 overlay note above). Ranking/filter inputs come from the
        // live-scanned vote accounts + live-computed effective stake — the same inputs
        // Vexor's reward path has used bank-exact for many epochs (so live == Agave's
        // epoch_stakes snapshot for reward purposes). GATE: offline replay of 417404256
        // must == cluster bank_hash before deploy.
        const vat_active = self.featureActiveAtSlotOverlay(@import("features.zig").VALIDATOR_ADMISSION_TICKET);
        // task #37 (2026-07-06): Agave 4.2 REKEYED alpenglow (old mustRekey…
        // placeholder can never activate; a1penGLz8… is the real key). Accept
        // EITHER so a 4.2-era activation isn't silently missed.
        const alpenglow_active = self.featureActiveAtSlotOverlay(@import("features.zig").ALPENGLOW) or
            self.featureActiveAtSlotOverlay(@import("features.zig").ALPENGLOW_V2);
        const vat_min_balance: u64 = blk_vmb: {
            // rent.minimum_balance(VoteStateV4::size_of()) =
            //   (data_len + 128) * lamports_per_byte_year * exemption_threshold.
            // Genesis-fixed network constants 3480 / 2.0 (identical testnet/mainnet; the
            // same constants Vexor uses for bank-exact tx-path rent_exempt_min — see
            // replay_stage.zig:11546). ceil() is exact here (×2.0 integral).
            const base: u64 = (@as(u64, @import("native/vote_v2.zig").VOTE_STATE_V4_SZ) + 128) * 3480 * 2;
            break :blk_vmb if (alpenglow_active) base + 1_600_000_000 else base;
        };
        const VatMeta = struct { has_bls: bool, lamports: u64 };
        var vat_meta = std.AutoHashMap([32]u8, VatMeta).init(self.allocator);
        defer vat_meta.deinit();
        if (vat_active) std.log.warn("[EPOCH-VAT] feature ACTIVE at slot {d}; min_balance={d} alpenglow={any}", .{ self.slot, vat_min_balance, alpenglow_active });

        for (vote_accounts, 0..) |va, vi| {
            const vs = vote_serde.deserializeVoteState(va.data) orelse continue;
            // VAT: capture per-vote BLS-present + lamports for the admitted-set filter.
            if (vat_active) {
                vat_meta.put(va.pubkey.data, .{ .has_bls = vs.has_bls_pubkey_compressed, .lamports = va.lamports }) catch {};
            }

            // Owned per-account epoch_credits slice (no shared growing buffer →
            // no realloc can dangle another account's slice). Reuses the proven
            // `deserializeVoteState` walk; only the OWNERSHIP model changed, so
            // the credits bytes (and therefore rewards/bank_hash) are identical.
            const owned_ec = self.allocator.alloc(rewards_mod.EpochCreditsEntry, vs.ec_count) catch continue;
            for (0..vs.ec_count) |ei| {
                const ec = vs.epoch_credits[ei];
                owned_ec[ei] = .{
                    .epoch = ec.epoch,
                    .credits = ec.credits,
                    .prev_credits = ec.prev_credits,
                };
            }

            // carrier #16 commission selection (canonical Agave chain,
            // calculation.rs:487-502):
            //   delay_commission_updates active →
            //     epoch_stakes(rewarded).get → epoch_stakes(current).get → live
            //   commission_rate_in_basis_points INactive (testnet today) →
            //     legacy u8 percent ×100 (V4: min(bps/100,255)×100) — NOT the
            //     raw V4 bps (that path activates with the feature; the old
            //     "r40" unconditional raw-bps read was ahead of the cluster).
            const live_bps: u16 = if (commission_bps_active)
                (if (vs.version != 3) @as(u16, vs.commission) * 100 else vs.inflation_rewards_commission_bps)
            else
                (if (vs.version != 3) @as(u16, vs.commission) * 100 else @as(u16, @intCast(@min(vs.inflation_rewards_commission_bps / 100, 255))) * 100);
            const commission_bps: u16 = blk: {
                if (delay_commission_active) {
                    if (es_comm_rewarded.get(va.pubkey.data)) |b| break :blk b;
                    if (es_comm_current.get(va.pubkey.data)) |b| break :blk b;
                }
                break :blk live_bps;
            };

            va_to_accum[vi] = vote_accums.items.len;
            vote_accums.append(self.allocator, .{
                .vote_account = .{ .data = va.pubkey.data },
                .commission_bps = commission_bps,
                .epoch_credits = owned_ec,
            }) catch {
                self.allocator.free(owned_ec);
                continue;
            };
        }

        std.log.debug("[EPOCH] Deserialized {d} vote states\n", .{vote_accums.items.len});

        // ── Read StakeHistory sysvar for activation curve computation ────────
        // BUG-3 fix: replace flat if/else with warmup/cooldown curves.
        const stake_history = try self.readStakeHistory(self.allocator);
        defer if (stake_history.len > 0) self.allocator.free(stake_history);

        // carrier #16 FINAL root cause (@414812256): the warmup/cooldown rate is
        // NOT a constant 9%. Canonical (Agave solana-stake-interface
        // warmup_cooldown_rate) uses 25%/epoch for epochs BEFORE the
        // `reduce_stake_warmup_cooldown` activation epoch (testnet: slot
        // 247628260 → epoch 586) and 9% from it onward, evaluated PER LOOP
        // EPOCH inside the curve. Offline lab over all 558,757 delegations
        // (epoch973-forensics/carrier16_lab.py): flat 0.09 → total_points off
        // by +7.9e17 with filters / −9.84e10 without; rate schedule → EXACTLY
        // canonical (diff 0).
        const new_rate_activation_epoch = self.getNewRateActivationEpoch();
        std.log.warn("[EPOCH-NRAE] new_rate_activation_epoch={d} (reduce_stake_warmup_cooldown)", .{new_rate_activation_epoch});

        // ── Parse stake delegations → StakeDelegation[] ─────────────────────
        var delegations = std.ArrayListUnmanaged(rewards_mod.StakeDelegation){};
        defer delegations.deinit(self.allocator);
        try delegations.ensureTotalCapacity(self.allocator, stake_accounts.len);

        var effective_stake: u64 = 0;
        var activating_stake: u64 = 0;
        var deactivating_stake: u64 = 0;

        var rej_parse: u64 = 0;
        var rej_type: u64 = 0;
        var rej_zero: u64 = 0;
        var rej_novote: u64 = 0;

        // VEX_DUMP_STAKEPTS per-VOTE accumulator (advisor's decisive localizer, 2026-06-24):
        // sum points+eff per voter_pubkey across this vote's delegations so each top-stake
        // vote's Vexor points can be diffed vs getInflationReward canonical → pinpoints WHICH
        // vote(s) drive the epoch-979 +11.7% total_points over-count. Gated; log-only; freed.
        // `eff` = effective stake summed @prev_epoch (rewarded epoch) — kept for the
        // VEX_DUMP_STAKEPTS localizer only. `eff_new` = effective stake summed
        // @new_epoch (the DISTRIBUTION epoch = prev_epoch+1) — this is the canonical
        // VAT candidacy/ranking key (see RANKING-KEY NOTE below).
        const VoteAcc = struct { points: u128 = 0, eff: u128 = 0, eff_new: u128 = 0, n: u32 = 0 };
        var vote_acc = std.AutoHashMap([32]u8, VoteAcc).init(self.allocator);
        defer vote_acc.deinit();

        for (stake_accounts) |sa| {
            // carrier #16 secondary (@414812256): READ via the byte-offset helpers,
            // NOT viewStakeState's extern *StakeState. That extern struct has a
            // stray `_pad: [4]u8` (to 8-align `meta`) that bincode does NOT have on
            // the wire — so `state.stake.delegation.*` read every field +4 bytes
            // off. stake_state.zig's Offsets/readers exist precisely to dodge this.
            // Canonical: Agave solana-stake-interface state.rs (bincode, no padding).
            const disc = ss.readStakeStateDiscriminant(sa.data) orelse { rej_parse += 1; continue; };
            if (disc != 2) { rej_type += 1; continue; } // Only Stake type
            if (sa.data.len < ss.STAKE_STATE_SZ) { rej_parse += 1; continue; }

            const stake_amt = ss.readU64(sa.data, ss.Offsets.delegation_stake).?;
            if (stake_amt == 0) { rej_zero += 1; continue; }
            const act_epoch = ss.readU64(sa.data, ss.Offsets.activation_epoch).?;
            const deact_epoch = ss.readU64(sa.data, ss.Offsets.deactivation_epoch).?;
            const voter_pubkey = ss.readPubkey(sa.data, ss.Offsets.voter_pubkey).?;
            const credits_observed = ss.readU64(sa.data, ss.Offsets.credits_observed).?;

            // Effective/activating/deactivating @prev_epoch for the StakeHistory
            // sysvar sums (rate-schedule-aware curve).
            const activation = getStakeActivationStatus(
                act_epoch,
                deact_epoch,
                stake_amt,
                prev_epoch,
                stake_history,
                new_rate_activation_epoch,
            );
            effective_stake += activation.effective;
            activating_stake += activation.activating;
            deactivating_stake += activation.deactivating;

            // Only include if the delegation's vote account is known AND its
            // vote state deserialized into a reward accumulator (canonical: a
            // delegation whose vote account is missing from the cached vote set
            // earns 0 points and no reward — equivalent to skipping).
            const vi = vote_idx.get(voter_pubkey) orelse { rej_novote += 1; continue; };
            const accum_idx = va_to_accum[vi] orelse { rej_novote += 1; continue; };

            // carrier #16: PER-EPOCH points over the vote's credit windows
            // (Agave inflation_rewards/points.rs calculate_stake_points_and_
            // credits). CRITICAL — canonical iterates EVERY delegation, with NO
            // activation/dust filter: fully-deactivated stakes still earn points
            // for credit windows that predate their cooldown (their per-epoch
            // effective is nonzero there), and their points DO count in
            // total_points even when the resulting reward rounds to 0 lamports
            // (Agave ZeroReward → no payout/write, but the points stand). The
            // old `effective==0 and activating==0 → skip` filter dropped those
            // points → total_points mismatch.
            const sp = computeStakePointsPerEpoch(
                vote_accums.items[accum_idx].epoch_credits,
                credits_observed,
                act_epoch,
                deact_epoch,
                stake_amt,
                new_rate_activation_epoch,
                stake_history,
            );

            // VEX_DUMP_STAKEPTS sampled per-delegation dump (~1/4096 by stake pk) — log-only.
            // Recomputes the rewarded-epoch (prev_epoch) row so each delegation's exact inputs
            // (credits_observed, initial/final credits, effective stake, earned) can be diffed
            // against canonical RPC to pin which input diverges. Zero baseline effect when off.
            if (StakePtDump.on) {
                const ec_dbg = vote_accums.items[accum_idx].epoch_credits;
                var fin_dbg: u64 = 0;
                var ini_dbg: u64 = 0;
                var found_dbg = false;
                for (ec_dbg) |e| {
                    if (e.epoch == prev_epoch) {
                        fin_dbg = e.credits;
                        ini_dbg = e.prev_credits;
                        found_dbg = true;
                    }
                }
                const eff_dbg = getStakeActivationStatus(act_epoch, deact_epoch, stake_amt, prev_epoch, stake_history, new_rate_activation_epoch).effective;
                const earned_dbg: u64 = if (found_dbg) (if (credits_observed < ini_dbg) fin_dbg - ini_dbg else (if (credits_observed < fin_dbg) fin_dbg - credits_observed else 0)) else 0;
                // dump (a) an UNBIASED sample (pk prefix 0x05, avoids the 0x00 spam batch) and
                // (b) ALL partial-credit contributing delegations (ini<co<fin, eff>0) = the suspect class.
                const is_partial = found_dbg and eff_dbg > 0 and credits_observed > ini_dbg and credits_observed < fin_dbg;
                const unbiased = sa.pubkey.data[0] == 5 and sa.pubkey.data[1] < 16;
                if ((unbiased or is_partial) and StakePtDump.per_del_dumped < 400) {
                    StakePtDump.per_del_dumped += 1;
                    std.log.warn("[STAKEPT-DEL] {s} stake={s} vote={s} co={d} ini={d} fin={d} eff={d} earned={d} pts={d}", .{
                        if (is_partial) @as([]const u8, "PARTIAL") else @as([]const u8, "sample"),
                        &std.fmt.bytesToHex(sa.pubkey.data, .lower),
                        &std.fmt.bytesToHex(voter_pubkey, .lower),
                        credits_observed, ini_dbg, fin_dbg, eff_dbg, earned_dbg, sp.points,
                    });
                }
            }

            // VEX_DUMP_STAKEPTS / VAT: accumulate this delegation's points+eff under its
            // vote. When vat_active this per-vote effective-stake sum is the ranking key
            // for the SIMD-0357 top-2000 cutoff (Agave clone_and_filter_for_vat `stake`).
            if (StakePtDump.on or vat_active) {
                const gop = vote_acc.getOrPut(voter_pubkey) catch null;
                if (gop) |g| {
                    if (!g.found_existing) g.value_ptr.* = .{};
                    g.value_ptr.points += sp.points;
                    g.value_ptr.eff += activation.effective;
                    // Canonical VAT candidacy/ranking key = per-vote effective stake
                    // @new_epoch (the distribution epoch, prev_epoch+1). Agave keys
                    // has_stake/ranking on epoch_stakes(leader_schedule_epoch)
                    // .vote_accounts() stake = Σ delegation.stake(new_epoch) — NOT the
                    // rewarded-epoch (prev_epoch) effective. A vote whose sole delegation
                    // ACTIVATED mid-prev_epoch has effective@prev_epoch == 0 (target ==
                    // activation_epoch, line ~2798) but effective@new_epoch > 0, so it IS
                    // a candidate; keying on @prev_epoch wrongly dropped it → its
                    // delegations' zero-reward credits-only store never happened.
                    const activation_new = getStakeActivationStatus(act_epoch, deact_epoch, stake_amt, new_epoch, stake_history, new_rate_activation_epoch);
                    g.value_ptr.eff_new += activation_new.effective;
                    g.value_ptr.n += 1;
                }
            }

            delegations.append(self.allocator, .{
                .stake_account = .{ .data = sa.pubkey.data },
                .vote_account = .{ .data = voter_pubkey },
                .effective_stake = activation.effective,
                .delegation_stake = stake_amt,
                .activation_epoch = act_epoch,
                .credits_observed = credits_observed,
                .precomputed_points = sp,
            }) catch continue;
        }

        // VEX_DUMP_STAKEPTS: dump top-N votes by accumulated points (advisor localizer).
        // Diff each top vote's Vexor `pts` vs getInflationReward canonical (pts = reward/(pv*comm))
        // to find which vote(s) diverge and whether the error is stake-attribution or earned-side.
        if (StakePtDump.on) {
            const VEntry = struct { vote: [32]u8, points: u128, eff: u128, n: u32 };
            var vlist = std.ArrayListUnmanaged(VEntry){};
            defer vlist.deinit(self.allocator);
            var vit = vote_acc.iterator();
            while (vit.next()) |e| {
                vlist.append(self.allocator, .{ .vote = e.key_ptr.*, .points = e.value_ptr.points, .eff = e.value_ptr.eff, .n = e.value_ptr.n }) catch {};
            }
            std.sort.pdq(VEntry, vlist.items, {}, struct {
                fn lt(_: void, a: VEntry, b: VEntry) bool {
                    return a.points > b.points;
                }
            }.lt);
            std.log.warn("[STAKEPT-VOTE-HDR] n_votes={d}", .{vlist.items.len});
            var vdumped: usize = 0;
            for (vlist.items) |e| {
                if (vdumped >= 80) break;
                vdumped += 1;
                std.log.warn("[STAKEPT-VOTE] vote={s} pts={d} eff={d} ndel={d}", .{
                    &std.fmt.bytesToHex(e.vote, .lower), e.points, e.eff, e.n,
                });
            }
        }

        std.log.debug("[EPOCH] Delegations: {d}, effective={d:.2} SOL, activating={d:.2} SOL, deactivating={d:.2} SOL\n", .{
            delegations.items.len,
            @as(f64, @floatFromInt(effective_stake)) / 1e9,
            @as(f64, @floatFromInt(activating_stake)) / 1e9,
            @as(f64, @floatFromInt(deactivating_stake)) / 1e9,
        });
        // carrier #16 oracle (kept as a cheap permanent tripwire): the prev_epoch
        // effective/activating/deactivating SUMS must match the canonical
        // StakeHistory entry the cluster writes for prev_epoch.
        std.log.warn("[EPOCH-STAKESUM] eff={d} act={d} deact={d} rej: parse={d} type={d} zero={d} novote={d}", .{
            effective_stake, activating_stake, deactivating_stake, rej_parse, rej_type, rej_zero, rej_novote,
        });

        // ── SIMD-0357 VAT: restrict the reward set to ADMITTED votes ────────────
        // (header at the top of the vote loop.) Non-admitted votes' delegations are
        // removed from `delegations[]` so they earn 0 points + no credits write —
        // exactly the existing `rej_novote` skip. STAKESUM above is unaffected (it
        // summed all delegations, matching the non-VAT-filtered StakeHistory).
        if (vat_active) {
            const Cand = struct { vote: [32]u8, stake: u128 };
            var cands = std.ArrayListUnmanaged(Cand){};
            defer cands.deinit(self.allocator);
            // Steps 1+2: candidates = votes with delegations (stake>0) that have_bls
            // AND lamports >= rent-exempt minimum.
            var ait = vote_acc.iterator();
            while (ait.next()) |e| {
                const m = vat_meta.get(e.key_ptr.*) orelse continue; // no vote state → exclude
                if (!m.has_bls) continue; // has_bls
                if (e.value_ptr.eff_new == 0) continue; // has_stake (stake @new_epoch != 0)
                if (m.lamports < vat_min_balance) continue; // has_balance
                cands.append(self.allocator, .{ .vote = e.key_ptr.*, .stake = e.value_ptr.eff_new }) catch continue;
            }
            // Steps 3+4: if more than MAX remain, drop all whose stake <= the MAX-th
            // ranked stake (Agave select_nth_unstable_by(MAX) + retain stake > floor;
            // STRICT). A full descending sort yields the identical floor value and
            // retained set (the element at index MAX has the same stake regardless of
            // tie ordering, and we compare by stake value).
            // RANKING-KEY NOTE (production honesty, RULE#0): the canonical candidacy +
            // ranking stake is epoch_stakes(leader_schedule_epoch).vote_accounts() stake
            // = Σ delegation.stake(new_epoch) = effective stake @new_epoch (the
            // DISTRIBUTION epoch, prev_epoch+1). Agave: clone_and_filter_for_vat
            // (vote_account.rs:197-256) — `has_stake = *stake != 0` and the truncation
            // cutoff both key on THAT stake; 4.2.0-beta.0 is byte-identical
            // (vote_account.rs:216,234). We now key BOTH the has_stake gate AND the rank
            // on vote_acc.eff_new (effective @new_epoch) — this is what fixed the
            // mid-prev_epoch activation drop (a vote effective@prev_epoch==0 but
            // effective@new_epoch>0 is a genuine candidate; Agave admits it, so its
            // zero-reward credits-only store lands).
            //
            // RESIDUAL APPROXIMATION (does NOT affect candidacy, only the rank VALUE):
            // our stake_history at this boundary contains entries through prev_epoch-1
            // (it is still COMPUTING the prev_epoch entry, see STAKESUM tripwire below),
            // so effective@new_epoch for a stake that activated mid-prev_epoch reads as
            // fully-activated (initial-entry-missing → stake) rather than Agave's
            // warmup-partial value. The has_stake!=0 result is identical either way
            // (both nonzero); only the ranking VALUE differs, and ONLY when admitted >
            // MAX_VAT (testnet ~600 staked votes — cutoff never bites). If a future
            // cluster (mainnet ~1.5-1.8k, can exceed 2k) admits > MAX, append the
            // computed prev_epoch StakeHistory entry before recomputing eff_new so the
            // warmup curve matches Agave exactly.
            const MAX_VAT: usize = 2000;
            var floor_stake: u128 = 0;
            var apply_floor = false;
            if (cands.items.len > MAX_VAT) {
                std.sort.pdq(Cand, cands.items, {}, struct {
                    fn lt(_: void, a: Cand, b: Cand) bool {
                        return a.stake > b.stake;
                    }
                }.lt);
                floor_stake = cands.items[MAX_VAT].stake;
                apply_floor = true;
            }
            var admitted = std.AutoHashMap([32]u8, void).init(self.allocator);
            defer admitted.deinit();
            for (cands.items) |c| {
                if (apply_floor and c.stake <= floor_stake) continue;
                admitted.put(c.vote, {}) catch {};
            }
            // Filter delegations[] in place (keep order; admitted votes only).
            var w: usize = 0;
            var dropped_points: u128 = 0;
            for (delegations.items) |d| {
                if (admitted.contains(d.vote_account.data)) {
                    delegations.items[w] = d;
                    w += 1;
                } else {
                    dropped_points += d.precomputed_points.points;
                }
            }
            const removed = delegations.items.len - w;
            delegations.items.len = w;
            std.log.warn("[EPOCH-VAT] cand_votes={d} admitted_votes={d} floor_applied={any} floor_stake={d} delegs_removed={d} dropped_points={d}", .{
                cands.items.len, admitted.count(), apply_floor, floor_stake, removed, dropped_points,
            });
        }

        if (delegations.items.len == 0) {
            std.log.warn("[EPOCH] ZERO delegations from {d} stake accts — rej: parse={d} type={d} zero={d} novote={d}", .{ stake_accounts.len, rej_parse, rej_type, rej_zero, rej_novote });
            return;
        }

        // ── Run RewardsCalculator ───────────────────────────────────────────
        var calculator = rewards_mod.RewardsCalculator.init(self.allocator);
        // Note: don't defer deinit — we transfer partition ownership to Bank

        // BUG-4/6 fix: propagate error, deinit calculator cleanly before returning.
        calculator.calculateRewards(
            delegations.items,
            vote_accums.items,
            inflation_rewards,
            prev_epoch,
            reward_sched,
            self.slot,
            // carrier #16 BUG1: partition assignment is seeded by the parent's
            // POH BLOCKHASH (Agave hasher seed = parent_blockhash from
            // last_blockhash(); fd_epoch_rewards seed likewise), not the parent
            // bank_hash. At boundary-bank creation self.poh_hash still holds
            // the inherited parent poh (replaced only at freeze) — exactly
            // Agave's last_blockhash() at new_from_parent time.
            self.poh_hash.data,
        ) catch |err| {
            std.log.debug("[EPOCH] RewardsCalculator failed: {any}\n", .{err});
            calculator.deinit();
            return err;
        };

        std.log.warn("[EPOCH-CALC] delegations_in={d} partitions={d} vote_rewards={d} points={d} validator_rewards={d}", .{
            delegations.items.len,
            calculator.partitions.items.len,
            calculator.vote_rewards.items.len,
            calculator.summary.validator_points,
            calculator.summary.validator_rewards,
        });
        if (StakePtDump.on) {
            std.log.warn("[STAKEPT-AGG] rewarded_epoch={d} n_delegs={d} counted_rows={d} multirow_delegs={d} earned_total={d} pts_rewarded={d} pts_older={d} rows_older={d} pts_newer={d} rows_newer={d}", .{
                StakePtDump.rewarded_epoch,    StakePtDump.n_delegs,
                StakePtDump.counted_rows,      StakePtDump.multirow_delegs,
                StakePtDump.earned_total,      StakePtDump.pts_rewarded,
                StakePtDump.pts_older,         StakePtDump.rows_older,
                StakePtDump.pts_newer,         StakePtDump.rows_newer,
            });
            std.log.warn("[STAKEPT-SPLIT] pts_rew_normal(co==ini)={d} pts_rew_below(co<ini)={d} pts_rew_partial(ini<co<fin)={d} n_rew_partial={d}", .{
                StakePtDump.pts_rew_normal, StakePtDump.pts_rew_below, StakePtDump.pts_rew_partial, StakePtDump.n_rew_partial,
            });
        }

        // ── Distribute vote rewards immediately ─────────────────────────────
        var vote_reward_total: u64 = 0;
        for (calculator.vote_rewards.items) |vr| {
            if (vr.lamports == 0) continue;

            const vi = vote_idx.get(vr.pubkey.data) orelse continue;
            const va = vote_accounts[vi];

            const old_lt = accountLtHash(&va.pubkey.data, &vote_owner.data, va.lamports, va.executable, va.data);
            const new_lam = va.lamports + vr.lamports;
            const new_lt = accountLtHash(&va.pubkey.data, &vote_owner.data, new_lam, va.executable, va.data);

            self.collectWrite(.{
                .pubkey = .{ .data = va.pubkey.data },
                .lamports = new_lam,
                .owner = .{ .data = vote_owner.data },
                .executable = va.executable,
                .rent_epoch = va.rent_epoch,
                .data = va.data,
                .old_lt = old_lt,
                .new_lt = new_lt,
            }) catch continue;

            vote_reward_total += vr.lamports;
        }

        std.log.debug("[EPOCH] Vote rewards distributed to {d} accounts\n", .{calculator.vote_rewards.items.len});

        // ── Store partitions for per-slot distribution ──────────────────────
        // Transfer ownership of partitions from calculator to Bank.
        // CRITICAL (NEW-BUG-1 fix): shrinkAndFree before storing .items so that
        // capacity == len, ensuring allocator.free() uses the correct allocation size.
        // Without this, if the ArrayList grew, capacity > len and free() passes the
        // wrong byte count to the allocator → heap corruption in release mode.
        calculator.partitions.shrinkAndFree(self.allocator, calculator.partitions.items.len);
        // Also shrink each partition's rewards ArrayList for the same reason.
        for (calculator.partitions.items) |*p| {
            p.rewards.shrinkAndFree(self.allocator, p.rewards.items.len);
        }
        const num_parts: u32 = @intCast(calculator.partitions.items.len);
        self.stake_reward_partitions = calculator.partitions.items;
        self.owns_stake_reward_partitions = true; // This bank owns the partition memory
        self.num_reward_partitions = num_parts;
        self.distribution_starting_block_height = self.block_height + rewards_mod.REWARD_CALCULATION_NUM_BLOCKS;
        self.epoch_rewards_active = true;
        self.vote_rewards_distributed = vote_reward_total;
        // BUG-2 fix: track capitalization increase from vote rewards.
        // Without this, every subsequent epoch's inflation calculation uses stale cap.
        self.capitalization += vote_reward_total;
        // carrier #16 BUG1: poh_hash (parent's POH blockhash at this point in
        // the bank lifecycle), NOT parent_hash (parent's bank_hash).
        self.epoch_reward_parent_blockhash = self.poh_hash;
        self.epoch_reward_total_points = calculator.summary.validator_points;
        // carrier #16 BUG2: canonical total_rewards = point_value.rewards.
        self.epoch_reward_total_rewards = calculator.summary.validator_rewards;

        // Count total stake rewards across all partitions
        var total_staker: u64 = 0;
        for (calculator.partitions.items) |part| {
            for (part.rewards.items) |sr| {
                total_staker += sr.staker_rewards;
            }
        }
        self.total_stake_rewards = total_staker;
        self.distributed_rewards = 0;

        // Free vote_rewards (already distributed) but NOT partitions (transferred)
        calculator.vote_rewards.deinit(self.allocator);
        // Don't call calculator.deinit() — partitions are now owned by Bank

        std.log.debug("[EPOCH] Stake rewards: {d:.2} SOL in {d} partitions, starting at block_height {d}\n", .{
            @as(f64, @floatFromInt(total_staker)) / 1e9,
            num_parts,
            self.distribution_starting_block_height,
        });

        // ── Update StakeHistory sysvar ──────────────────────────────────────
        try self.updateStakeHistory(prev_epoch, effective_stake, activating_stake, deactivating_stake);

        // ── Create EpochRewards sysvar (active) ─────────────────────────────
        try self.createEpochRewardsSysvar();
    }

    /// Update StakeHistory sysvar with previous epoch's stake totals.
    /// Ring buffer of (epoch, effective, activating, deactivating) entries, max 512.
    fn updateStakeHistory(self: *Self, epoch: u64, effective: u64, activating: u64, deactivating: u64) !void {
        // SysvarStakeHistory1111111111111111111111111
        // r36-fix-d: canonical SysvarStakeHistory1111...
        // Hand-typed bytes pre-r36-fix-d encoded to junk pubkey
        // `SysvcSvHxSfdYpkDhuUaqWAwN52LM4aC1xQ6D8o6Y5u`. CLAUDE.md Pitfall #3
        // (third documented violation tonight after r35-fix LRS_PUBKEY +
        // sysvar_cache.zig 8-placeholder constants). @prov:bank.sysvar-id-cross-check
        const SH_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x19, 0x35, 0x84, 0xd0,
            0xfe, 0xed, 0x9b, 0xb3, 0x43, 0x1d, 0x13, 0x20,
            0x6b, 0xe5, 0x44, 0x28, 0x1b, 0x57, 0xb8, 0x56,
            0x6c, 0xc5, 0x37, 0x5f, 0xf4, 0x00, 0x00, 0x00,
        } };
        const SYSVAR_OWNER_BYTES = SYSVAR_OWNER;
        const MAX_ENTRIES: usize = 512;
        // Each entry: u64 epoch + u64 effective + u64 activating + u64 deactivating = 32 bytes
        const ENTRY_SIZE: usize = 32;

        // 2026-05-27 Task #43 RULE #0: fallback default = canonical rent-exempt
        // for StakeHistory (16392 bytes data → (16392+128)*6960 = 114,979,200).
        // Was `1` which would diverge from Agave/oracle-node if fallback fires.
        // Mainnet hygiene per RULE #0.
        var existing_lamports: u64 = 114_979_200;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var old_data: ?[]const u8 = null;

        if (self.accounts_db) |db| {
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&SH_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                // r62: dupe immediately. Same class as r55-E/RBH/SlotHistory/SlotHashes.
                // existing.data is a raw slice; below we read it at @memcpy
                // (line ~2207) and accountLtHash (line ~2212) — both AFTER
                // self.allocator.alloc(data_size) which can trigger AppendVec
                // eviction.
                if (existing.data.len > 0) {
                    old_data = self.allocator.dupe(u8, existing.data) catch null;
                }
            }
        }

        // Parse existing entries count and entries from old data
        var old_count: u64 = 0;
        const old_entries_start: usize = 8;
        if (old_data) |od| {
            if (od.len >= 8) {
                old_count = std.mem.readInt(u64, od[0..8], .little);
            }
        }

        // Build new data: prepend new entry, keep up to MAX_ENTRIES-1 old entries
        const new_count = @min(old_count + 1, MAX_ENTRIES);
        const data_size = 8 + new_count * ENTRY_SIZE;
        const sysvar_data = try self.allocator.alloc(u8, data_size);
        @memset(sysvar_data, 0);

        std.mem.writeInt(u64, sysvar_data[0..8], new_count, .little);

        // Write new entry at position 0
        var off: usize = 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], epoch, .little);
        std.mem.writeInt(u64, sysvar_data[off + 8 ..][0..8], effective, .little);
        std.mem.writeInt(u64, sysvar_data[off + 16 ..][0..8], activating, .little);
        std.mem.writeInt(u64, sysvar_data[off + 24 ..][0..8], deactivating, .little);
        off += ENTRY_SIZE;

        // Copy old entries (up to MAX_ENTRIES-1)
        if (old_data) |od| {
            const copy_count = @min(old_count, MAX_ENTRIES - 1);
            const copy_bytes = copy_count * ENTRY_SIZE;
            if (od.len >= old_entries_start + copy_bytes) {
                @memcpy(sysvar_data[off..][0..copy_bytes], od[old_entries_start..][0..copy_bytes]);
            }
        }

        const old_lt = if (old_data) |od|
            accountLtHash(&SH_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&SH_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, sysvar_data);

        // r62: free duped old slice now that lthash is computed.
        if (old_data) |od| self.allocator.free(od);

        try self.collectWrite(.{
            .pubkey = SH_PUBKEY,
            .lamports = existing_lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER_BYTES },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = sysvar_data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });

        std.log.debug("[EPOCH] StakeHistory: epoch={d} effective={d} activating={d} deactivating={d}\n", .{
            epoch, effective, activating, deactivating,
        });
    }

    /// Create EpochRewards sysvar at epoch boundary (active state).
    /// Contains distribution schedule so programs can detect reward period.
    fn createEpochRewardsSysvar(self: *Self) !void {
        // SysvarEpochRewards1111111111111111111111111
        // r36-fix-d: canonical SysvarEpochRewards1111...
        // Hand-typed bytes pre-r36-fix-d encoded to junk pubkey
        // `SysvczJGFxkE8D4Wy8FRreAM16ZmfBcf8oPAK71QVb5`. CLAUDE.md Pitfall #3
        // — same hand-typed-bytes-wrong pattern as r35-fix and the StakeHistory
        // constant fixed in this commit. @prov:bank.sysvar-id-cross-check
        const ER_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x18, 0xdc, 0x3f, 0xee,
            0x02, 0xa5, 0x58, 0xbf, 0x83, 0xce, 0x66, 0xe1,
            0x44, 0x42, 0x2a, 0x1c, 0x34, 0x95, 0x0b, 0x27,
            0xc1, 0x86, 0x9b, 0x5a, 0x9c, 0x00, 0x00, 0x00,
        } };
        const SYSVAR_OWNER_BYTES = SYSVAR_OWNER;

        var existing_lamports: u64 = 1;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var old_data: ?[]const u8 = null;

        if (self.accounts_db) |db| {
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&ER_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                old_data = existing.data;
            }
        }

        // EpochRewards sysvar layout (bincode):
        //   u64  distribution_starting_block_height
        //   u64  num_partitions
        //   [32] parent_blockhash
        //   u128 total_points (as two u64 LE: low, high)
        //   u64  total_rewards
        //   u64  distributed_rewards
        //   u8   active
        const SYSVAR_SIZE: usize = 8 + 8 + 32 + 16 + 8 + 8 + 1;
        const sysvar_data = try self.allocator.alloc(u8, SYSVAR_SIZE);
        @memset(sysvar_data, 0);

        var off: usize = 0;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.distribution_starting_block_height, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], @as(u64, self.num_reward_partitions), .little);
        off += 8;
        @memcpy(sysvar_data[off..][0..32], &self.epoch_reward_parent_blockhash.data);
        off += 32;
        // u128 total_points as two LE u64
        const points_low: u64 = @truncate(self.epoch_reward_total_points);
        const points_high: u64 = @truncate(self.epoch_reward_total_points >> 64);
        std.mem.writeInt(u64, sysvar_data[off..][0..8], points_low, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], points_high, .little);
        off += 8;
        // @prov:bank.epoch-rewards-total — total_rewards = point_value.rewards (full
        // inflation validator budget), NOT the reconstructed distributed sum
        // (differs by truncation burns).
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.epoch_reward_total_rewards, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.vote_rewards_distributed, .little);
        off += 8;
        sysvar_data[off] = 1; // active = true

        // carrier-16 gate probe (warn-level so the file log captures it):
        // print EXACTLY what we serialize so a replay-proof mismatch is
        // attributable to a specific field without recorder infrastructure.
        std.log.warn("[EPOCH-REWARDS-SYSVAR] slot={d} start_height={d} num_partitions={d} parent_blockhash={x:0>16} total_points={d} total_rewards={d} distributed={d} poh_hash={x:0>16} parent_hash={x:0>16}", .{
            self.slot,
            self.distribution_starting_block_height,
            self.num_reward_partitions,
            std.mem.readInt(u64, self.epoch_reward_parent_blockhash.data[0..8], .big),
            self.epoch_reward_total_points,
            self.epoch_reward_total_rewards,
            self.vote_rewards_distributed,
            std.mem.readInt(u64, self.poh_hash.data[0..8], .big),
            std.mem.readInt(u64, self.parent_hash.data[0..8], .big),
        });

        const old_lt = if (old_data) |od|
            accountLtHash(&ER_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&ER_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, sysvar_data);

        try self.collectWrite(.{
            .pubkey = ER_PUBKEY,
            .lamports = existing_lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER_BYTES },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = sysvar_data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });

        std.log.debug("[EPOCH] EpochRewards sysvar created: active=true, partitions={d}, starting_height={d}\n", .{
            self.num_reward_partitions, self.distribution_starting_block_height,
        });
    }

    /// Distribute one partition of stake rewards for the current block.
    /// Called at the beginning of each slot during the reward distribution window.
    /// Returns the number of lamports distributed in this partition.
    pub fn distributePartitionedRewards(self: *Self) !u64 {
        if (!self.epoch_rewards_active) return 0;

        const partitions = self.stake_reward_partitions orelse return 0;
        if (self.block_height < self.distribution_starting_block_height) return 0;

        const partition_idx = self.block_height - self.distribution_starting_block_height;
        if (partition_idx >= partitions.len) {
            // SAFETY NET only (H3 fix 2026-07-02). @prov:bank.epoch-rewards-partition-distribute —
            // deactivation now happens IN the last-partition block below;
            // our old block-AFTER timing left the sysvar active=1 one block too
            // long = a guaranteed byte diff at the last window slot. This branch is now unreachable in
            // normal flow (epoch_rewards_active flips false in the last block);
            // kept for restart-mid-window states where active was snapshotted
            // true past the window.
            self.epoch_rewards_active = false;
            try self.deactivateEpochRewardsSysvar();
            self.freeStakeRewardPartitions();
            std.log.debug("[EPOCH] All stake rewards distributed: {d:.2} SOL total\n", .{
                @as(f64, @floatFromInt(self.distributed_rewards)) / 1e9,
            });
            return 0;
        }

        const partition = &partitions[partition_idx];
        var lamports_distributed: u64 = 0;

        const stake_owner_bytes = [_]u8{
            0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
            0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
            0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
            0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
        };

        const db = self.accounts_db orelse return 0;

        for (partition.rewards.items) |sr| {
            // E2 fix (2026-07-01): do NOT skip staker_rewards==0 entries.
            // @prov:bank.epoch-rewards-partition-distribute — "even if
            // staker's reward is 0, the stake account still needs to be stored
            // because credits observed has changed." The account flows through
            // below with new_lam = acct.lamports + 0 (unchanged), but its
            // updated credits_observed IS written (Offsets.credits_observed)
            // so the accountLtHash reflects the credit change. Skipping the
            // store (the prior `continue`) left stale credits_observed →
            // divergent lt_hash + compounding total_points drift next epoch.

            // Look up current stake account state
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&sr.stake_account.data));
            const acct = db.getAccountInSlot(core_pk, self.slot, self.ancestors()) orelse continue;

            const old_lt = accountLtHash(&sr.stake_account.data, &stake_owner_bytes, acct.lamports, acct.executable, acct.data);

            // d28gg fix (2026-05-12). @prov:bank.epoch-rewards-partition-distribute —
            // checked_add_lamports → skip-and-continue on overflow (propagated via `?`
            // and skips the account in the surrounding store_stake_rewards_in_partition).
            // Vexor previously used raw `+`, which Zig's ReleaseSafe checks panic on
            // overflow → validator crash.
            const new_lam_tup = @addWithOverflow(acct.lamports, sr.staker_rewards);
            if (new_lam_tup[1] != 0) {
                std.log.warn(
                    "[REWARDS-OVERFLOW] stake_account=... acct.lamports={d} staker_rewards={d} — skipping per Agave canonical (ArithmeticOverflow)",
                    .{ acct.lamports, sr.staker_rewards },
                );
                continue;
            }
            const new_lam = new_lam_tup[0];

            // Defect A+B fix (RCA 2026-07-02, epoch-983 divergence @419132257).
            // @prov:bank.rewards-store-compounded — the reference distribution store
            // writes the CALC-TIME COMPOUNDED StakeStateV2: delegation.stake was
            // compounded `+= staker_rewards` at calc and credits_observed updated —
            // asserting stored.delegation.stake + reward == calc.delegation.stake.
            // The old code here (a) never wrote delegation.stake back
            // (Defect A) and (b) wrote credits_observed at a recomputed
            // offset 192 instead of Offsets.credits_observed=188, clobbering
            // stake_flags@196 (Defect B) → wrong bytes → wrong lt_hash at
            // every distribution slot. Offsets + mutation now live in
            // stake_state.zig applyRewardStoreBytes (KAT-pinned).
            const ss = @import("native/stake_state.zig");
            const cur_stake = ss.readU64(acct.data, ss.Offsets.delegation_stake) orelse {
                std.log.warn(
                    "[REWARDS-STORE-SKIP] stake acct data.len={d} unreadable delegation.stake — skipping store (Agave would fail StakeStateV2 deser)",
                    .{acct.data.len},
                );
                continue;
            };
            if (cur_stake +| sr.staker_rewards != sr.new_delegation_stake) {
                // @prov:bank.rewards-store-compounded — the account's stake
                // changed between boundary calc and this distribution slot
                // (should be impossible: stake program is disabled while
                // EpochRewards.active). Skip-and-warn rather than store bytes
                // we know are wrong.
                std.log.warn(
                    "[REWARDS-STAKE-MISMATCH] cur_stake={d} + reward={d} != calc new_delegation_stake={d} — skipping store",
                    .{ cur_stake, sr.staker_rewards, sr.new_delegation_stake },
                );
                continue;
            }
            var new_data = acct.data;
            {
                const data_copy = try self.allocator.alloc(u8, acct.data.len);
                @memcpy(data_copy, acct.data);
                if (ss.applyRewardStoreBytes(data_copy, sr.new_delegation_stake, sr.new_credits_observed)) {
                    new_data = data_copy;
                } else {
                    // Non-Stake or short account reached distribution — store
                    // nothing (readU64 above should already have caught this).
                    self.allocator.free(data_copy);
                    std.log.warn("[REWARDS-STORE-SKIP] applyRewardStoreBytes refused (disc/len) — skipping store", .{});
                    continue;
                }
            }

            const new_lt = accountLtHash(&sr.stake_account.data, &stake_owner_bytes, new_lam, acct.executable, new_data);

            self.collectWrite(.{
                .pubkey = sr.stake_account,
                .lamports = new_lam,
                .owner = Pubkey{ .data = stake_owner_bytes },
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .data = new_data,
                .old_lt = old_lt,
                .new_lt = new_lt,
            }) catch continue;

            // d28gg: accumulator overflow protection. Cluster total stake rewards
            // per slot are bounded well below u64::MAX, but a corrupted partition
            // table or test scenario could push past. @prov:bank.epoch-rewards-partition-distribute
            const dist_tup = @addWithOverflow(lamports_distributed, sr.staker_rewards);
            if (dist_tup[1] != 0) {
                std.log.warn("[REWARDS-OVERFLOW] lamports_distributed accumulator overflow at slot={d} — capping at u64::MAX", .{self.slot});
                lamports_distributed = std.math.maxInt(u64);
                break;
            }
            lamports_distributed = dist_tup[0];
        }

        const total_dist_tup = @addWithOverflow(self.distributed_rewards, lamports_distributed);
        if (total_dist_tup[1] != 0) {
            std.log.warn("[REWARDS-OVERFLOW] distributed_rewards overflow at slot={d}: prev={d} adding={d}", .{ self.slot, self.distributed_rewards, lamports_distributed });
            self.distributed_rewards = std.math.maxInt(u64);
        } else {
            self.distributed_rewards = total_dist_tup[0];
        }
        // BUG-2 fix: track capitalization increase from stake reward distribution.
        const cap_tup = @addWithOverflow(self.capitalization, lamports_distributed);
        if (cap_tup[1] != 0) {
            std.log.warn("[REWARDS-OVERFLOW] capitalization overflow at slot={d}: prev={d} adding={d}", .{ self.slot, self.capitalization, lamports_distributed });
            self.capitalization = std.math.maxInt(u64);
        } else {
            self.capitalization = cap_tup[0];
        }

        // Update EpochRewards sysvar with new distributed_rewards total
        try self.updateEpochRewardsDistributed();

        if (partition.rewards.items.len > 0) {
            std.log.debug("[EPOCH] Partition {d}/{d}: {d:.4} SOL to {d} stake accounts\n", .{
                partition_idx + 1,
                partitions.len,
                @as(f64, @floatFromInt(lamports_distributed)) / 1e9,
                partition.rewards.items.len,
            });
        }

        // H3 fix (2026-07-02). @prov:bank.epoch-rewards-partition-distribute — the LAST partition
        // block also sets the sysvar INACTIVE — in the SAME block, after the
        // distribution + update writes. Final account state this slot = the
        // deactivated sysvar (freeze lt aggregation takes first-old/last-new per
        // pubkey, so the intermediate update write folds correctly). The old
        // block-AFTER deactivation diverged at the last window slot: cluster
        // sysvar bytes flip active=0 there; ours stayed active=1.
        // NOTE: must run AFTER the last `partition` deref above —
        // freeStakeRewardPartitions frees the slice `partition` points into.
        if (partition_idx + 1 >= partitions.len) {
            self.epoch_rewards_active = false;
            try self.deactivateEpochRewardsSysvar();
            self.freeStakeRewardPartitions();
            std.log.debug("[EPOCH] All stake rewards distributed (last partition {d}): {d:.2} SOL total\n", .{
                partition_idx + 1,
                @as(f64, @floatFromInt(self.distributed_rewards)) / 1e9,
            });
        }

        return lamports_distributed;
    }

    /// Update EpochRewards sysvar distributed_rewards field.
    fn updateEpochRewardsDistributed(self: *Self) !void {
        // r36-fix-d: canonical SysvarEpochRewards1111...
        // Hand-typed bytes pre-r36-fix-d encoded to junk pubkey
        // `SysvczJGFxkE8D4Wy8FRreAM16ZmfBcf8oPAK71QVb5`. CLAUDE.md Pitfall #3
        // — same hand-typed-bytes-wrong pattern as r35-fix and the StakeHistory
        // constant fixed in this commit. @prov:bank.sysvar-id-cross-check
        const ER_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x18, 0xdc, 0x3f, 0xee,
            0x02, 0xa5, 0x58, 0xbf, 0x83, 0xce, 0x66, 0xe1,
            0x44, 0x42, 0x2a, 0x1c, 0x34, 0x95, 0x0b, 0x27,
            0xc1, 0x86, 0x9b, 0x5a, 0x9c, 0x00, 0x00, 0x00,
        } };
        const SYSVAR_OWNER_BYTES = SYSVAR_OWNER;
        const SYSVAR_SIZE: usize = 8 + 8 + 32 + 16 + 8 + 8 + 1;

        var existing_lamports: u64 = 1;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var old_data: ?[]const u8 = null;

        if (self.accounts_db) |db| {
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&ER_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                old_data = existing.data;
            }
        }

        // Re-serialize with updated distributed_rewards
        const sysvar_data = try self.allocator.alloc(u8, SYSVAR_SIZE);
        @memset(sysvar_data, 0);

        var off: usize = 0;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.distribution_starting_block_height, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], @as(u64, self.num_reward_partitions), .little);
        off += 8;
        @memcpy(sysvar_data[off..][0..32], &self.epoch_reward_parent_blockhash.data);
        off += 32;
        const points_low: u64 = @truncate(self.epoch_reward_total_points);
        const points_high: u64 = @truncate(self.epoch_reward_total_points >> 64);
        std.mem.writeInt(u64, sysvar_data[off..][0..8], points_low, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], points_high, .little);
        off += 8;
        // @prov:bank.epoch-rewards-total — total_rewards = point_value.rewards (full
        // inflation validator budget), NOT the reconstructed distributed sum
        // (differs by truncation burns).
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.epoch_reward_total_rewards, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.vote_rewards_distributed +| self.distributed_rewards, .little);
        off += 8;
        sysvar_data[off] = 1; // still active

        const old_lt = if (old_data) |od|
            accountLtHash(&ER_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&ER_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, sysvar_data);

        try self.collectWrite(.{
            .pubkey = ER_PUBKEY,
            .lamports = existing_lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER_BYTES },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = sysvar_data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });
    }

    /// Deactivate EpochRewards sysvar (set active=0).
    fn deactivateEpochRewardsSysvar(self: *Self) !void {
        // r36-fix-d: canonical SysvarEpochRewards1111...
        // Hand-typed bytes pre-r36-fix-d encoded to junk pubkey
        // `SysvczJGFxkE8D4Wy8FRreAM16ZmfBcf8oPAK71QVb5`. CLAUDE.md Pitfall #3
        // — same hand-typed-bytes-wrong pattern as r35-fix and the StakeHistory
        // constant fixed in this commit. @prov:bank.sysvar-id-cross-check
        const ER_PUBKEY = Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x18, 0xdc, 0x3f, 0xee,
            0x02, 0xa5, 0x58, 0xbf, 0x83, 0xce, 0x66, 0xe1,
            0x44, 0x42, 0x2a, 0x1c, 0x34, 0x95, 0x0b, 0x27,
            0xc1, 0x86, 0x9b, 0x5a, 0x9c, 0x00, 0x00, 0x00,
        } };
        const SYSVAR_OWNER_BYTES = SYSVAR_OWNER;
        const SYSVAR_SIZE: usize = 8 + 8 + 32 + 16 + 8 + 8 + 1;

        var existing_lamports: u64 = 1;
        var existing_rent_epoch: u64 = std.math.maxInt(u64);
        var old_data: ?[]const u8 = null;

        if (self.accounts_db) |db| {
            const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&ER_PUBKEY));
            if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |existing| {
                existing_lamports = existing.lamports;
                existing_rent_epoch = existing.rent_epoch;
                old_data = existing.data;
            }
        }

        // Same as current sysvar but active=0
        const sysvar_data = try self.allocator.alloc(u8, SYSVAR_SIZE);
        @memset(sysvar_data, 0);

        var off: usize = 0;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.distribution_starting_block_height, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], @as(u64, self.num_reward_partitions), .little);
        off += 8;
        @memcpy(sysvar_data[off..][0..32], &self.epoch_reward_parent_blockhash.data);
        off += 32;
        const points_low: u64 = @truncate(self.epoch_reward_total_points);
        const points_high: u64 = @truncate(self.epoch_reward_total_points >> 64);
        std.mem.writeInt(u64, sysvar_data[off..][0..8], points_low, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], points_high, .little);
        off += 8;
        // @prov:bank.epoch-rewards-total — total_rewards = point_value.rewards (full
        // inflation validator budget), NOT the reconstructed distributed sum
        // (differs by truncation burns).
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.epoch_reward_total_rewards, .little);
        off += 8;
        std.mem.writeInt(u64, sysvar_data[off..][0..8], self.vote_rewards_distributed +| self.distributed_rewards, .little);
        off += 8;
        sysvar_data[off] = 0; // inactive

        const old_lt = if (old_data) |od|
            accountLtHash(&ER_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, od)
        else
            null;
        const new_lt = accountLtHash(&ER_PUBKEY.data, &SYSVAR_OWNER_BYTES, existing_lamports, false, sysvar_data);

        try self.collectWrite(.{
            .pubkey = ER_PUBKEY,
            .lamports = existing_lamports,
            .owner = Pubkey{ .data = SYSVAR_OWNER_BYTES },
            .executable = false,
            .rent_epoch = existing_rent_epoch,
            .data = sysvar_data,
            .old_lt = old_lt,
            .new_lt = new_lt,
        });

        std.log.debug("[EPOCH] EpochRewards sysvar deactivated: distributed={d:.2} SOL\n", .{
            @as(f64, @floatFromInt(self.distributed_rewards)) / 1e9,
        });
    }

    /// True while this OWNER bank's partitioned-reward distribution window is still
    /// live relative to a given (advancing) tip block_height. Used by the prune path
    /// to defer freeing the owner bank's `stake_reward_partitions` slice until no
    /// child bank in the multi-slot distribution window can still be iterating it.
    ///
    /// Task #14 UAF guard (2026-06-16): the epoch-boundary bank OWNS the slice
    /// (owns_stake_reward_partitions=true, set at the boundary). Child banks across
    /// the ~num_reward_partitions-slot distribution window INHERIT the pointer with
    /// owns=false (replay_stage.zig inheritEpochRewardState) and iterate
    /// `partition.rewards.items` inside distributePartitionedRewards()→freeze(). If
    /// the consensus root advances past the boundary bank DURING that window,
    /// pruneOldBanks→releaseBank→freeStakeRewardPartitions would free the slice while
    /// a tail child still iterates it → SIGSEGV (epoch-975 crash at
    /// distributePartitionedRewards line ~3138).
    ///
    /// The window covers child block_heights
    ///   [distribution_starting_block_height, distribution_starting_block_height + num_reward_partitions).
    /// The child at block_height == window_end-1 is the LAST one to iterate
    /// `partition.rewards.items`; the child at window_end hits the
    /// `partition_idx >= partitions.len` completion branch and never touches the
    /// slice. So the free is safe once tip_block_height >= window_end (>=, not >).
    ///
    /// NOTE: the owner bank's OWN block_height is frozen at the boundary slot
    /// (children advance it, the owner never does) and its epoch_rewards_active stays
    /// true, so the tip signal MUST be supplied by the caller (the advancing root),
    /// not read from `self`.
    pub fn rewardDistributionWindowLive(self: *const Self, tip_block_height: u64) bool {
        if (!self.owns_stake_reward_partitions) return false;
        if (!self.epoch_rewards_active) return false;
        const window_end = self.distribution_starting_block_height + self.num_reward_partitions;
        return tip_block_height < window_end;
    }

    /// Free stake reward partitions memory.
    /// Only frees if this bank owns the allocation (owns_stake_reward_partitions = true).
    /// Child banks that inherit the pointer must NOT free it.
    pub fn freeStakeRewardPartitions(self: *Self) void {
        if (!self.owns_stake_reward_partitions) return;
        if (self.stake_reward_partitions) |parts| {
            for (parts) |*p| {
                var mp = @constCast(p);
                mp.deinit(self.allocator);
            }
            self.allocator.free(parts);
            self.stake_reward_partitions = null;
            self.owns_stake_reward_partitions = false;
        }
    }

    pub fn freeze(self: *Self, rent_exempt_min_fn: anytype) !void {
        if (self.is_frozen) return;

        // ─────────────────────────────────────────────────────────────────────
        // [INJECT-DIVERGE] (env-gated, DORMANT by default) — controlled bank_hash
        // carrier for VALIDATING the blast-radius forensic tooling. When the
        // VEX_INJECT_DIVERGE_* env vars are armed AND this bank's slot == target,
        // perturb the named account's lamports by a delta and commit it via the
        // SAME pending-write + LtHash path a tx executor / settleFees uses, so the
        // perturbation flows through Step-5's accounts_lt_hash accumulation AND the
        // AccountsDb flush — yielding a slot-S bank_hash that diverges from the
        // cluster, attributable to exactly this pubkey, exactly like a real
        // account-state carrier. This lets us check that the forensic tooling names
        // the exact slot + account we corrupted.
        //
        // SAFETY INVARIANT (the reason this is acceptable in the consensus freeze
        // path): if VEX_INJECT_DIVERGE_SLOT is unset/unparseable the hook is OFF —
        // one getenv that returns null, then `break`. ZERO allocation, ZERO log,
        // ZERO behavior change. A production/normal binary is byte-behavior-
        // identical when unarmed. Reads the env ONCE per freeze (top-of-fn), never
        // in a loop. Mirrors the settleFees leader-credit read+lthash+collectWrite
        // pattern (bank.zig:2310-2395).
        // COMPILE-GATED (build.zig -Dinject_diverge, default OFF): when false the entire hook is
        // comptime-eliminated — physically ABSENT from a production binary, not merely env-dormant.
        if (comptime build_options.inject_diverge) inject_diverge: {
            const slot_s = std.posix.getenv("VEX_INJECT_DIVERGE_SLOT") orelse break :inject_diverge;
            const target_slot = std.fmt.parseInt(u64, std.mem.trim(u8, slot_s, " \t\r\n"), 10) catch break :inject_diverge;
            if (self.slot != target_slot) break :inject_diverge;

            const pk_s = std.posix.getenv("VEX_INJECT_DIVERGE_PUBKEY") orelse break :inject_diverge;
            var target_pk: [32]u8 = undefined;
            @import("core").base58.decodeToBuf(std.mem.trim(u8, pk_s, " \t\r\n"), &target_pk) catch break :inject_diverge;

            var delta: i64 = 1; // default +1 lamport
            if (std.posix.getenv("VEX_INJECT_DIVERGE_LAMPORTS")) |d_s|
                delta = std.fmt.parseInt(i64, std.mem.trim(u8, d_s, " \t\r\n"), 10) catch 1;

            // Read the account's CURRENT newest state: pending_writes overlay
            // (REVERSE scan = newest-wins, matches settleFees + freeze dedup) first,
            // then AccountsDb (fork-aware, ancestors-gated).
            var cur_lamports: u64 = 0;
            var cur_owner: [32]u8 = SYSTEM_PROGRAM;
            var cur_executable = false;
            var cur_rent_epoch: u64 = std.math.maxInt(u64);
            var cur_data: []const u8 = &[_]u8{};
            var found = false;
            {
                var i: usize = self.pending_writes.items.len;
                while (i > 0) {
                    i -= 1;
                    const w = &self.pending_writes.items[i];
                    if (std.mem.eql(u8, &w.pubkey.data, &target_pk)) {
                        cur_lamports = w.lamports;
                        cur_owner = w.owner.data;
                        cur_executable = w.executable;
                        cur_rent_epoch = w.rent_epoch;
                        cur_data = w.data;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                if (self.accounts_db) |db| {
                    const core_pk = @as(*const @import("core").Pubkey, @ptrCast(&target_pk));
                    if (db.getAccountInSlot(core_pk, self.slot, self.ancestors())) |acct| {
                        cur_lamports = acct.lamports;
                        cur_owner = acct.owner.data;
                        cur_executable = acct.executable;
                        cur_rent_epoch = acct.rent_epoch;
                        cur_data = acct.data;
                        found = true;
                    }
                }
            }
            if (!found) {
                std.log.warn("[INJECT-DIVERGE] slot={d} pubkey={s} target account NOT FOUND — no carrier injected", .{ self.slot, pk_s });
                break :inject_diverge;
            }

            // Apply delta (saturating — never under/overflow).
            const new_lamports: u64 = if (delta >= 0)
                cur_lamports +| @as(u64, @intCast(delta))
            else
                cur_lamports -| @as(u64, @intCast(-delta));

            // Own the data slice on bank.allocator so it survives until the
            // AccountsDb flush (collectWrite ownership contract; a db-read slice
            // may point into a transient cache). Freed-with-bank (pending_writes
            // element data is not individually freed at deinit), so no double-free;
            // a small one-slot leak only when armed.
            const owned_data = self.allocator.dupe(u8, cur_data) catch break :inject_diverge;

            const old_lt = accountLtHash(&target_pk, &cur_owner, cur_lamports, cur_executable, owned_data);
            const new_lt = accountLtHash(&target_pk, &cur_owner, new_lamports, cur_executable, owned_data);

            // Commit via the SAME write/commit path the executor uses, so Step-5's
            // lthash walk and the AccountsDb flush both pick it up. If this pubkey
            // was already written this slot, this becomes the LAST write → the per-pk
            // freeze aggregation telescopes to (-first.old_lt + this.new_lt), a net
            // +delta vs the real final state. If not, this is the only write →
            // (-old_lt + new_lt) = exactly the +delta change. Either way: +delta.
            try self.collectWrite(.{
                .pubkey = Pubkey{ .data = target_pk },
                .lamports = new_lamports,
                .owner = Pubkey{ .data = cur_owner },
                .executable = cur_executable,
                .rent_epoch = cur_rent_epoch,
                .data = owned_data,
                .old_lt = old_lt,
                .new_lt = new_lt,
            });

            // GROUND TRUTH in the node log — the slot + pubkey + delta we corrupted.
            std.log.warn("[INJECT-DIVERGE] slot={d} pubkey={s} lamports_delta={d} APPLIED (test carrier)", .{ self.slot, pk_s, delta });
        }

        // Distribute one partition of stake rewards (if reward period is active).
        // Must run before epoch boundary — on epoch boundary slot itself,
        // distribution_starting_block_height = block_height + 1, so this is a no-op.
        // BUG-4/9 fix: propagate errors instead of silently swallowing them.
        _ = try self.distributePartitionedRewards();

        // NOTE (BUG-1 fix): processEpochBoundary() has been moved to replay_stage.zig
        // pre-execute path. It is called BEFORE transaction execution begins.
        // @prov:bank.epoch-boundary-pre-execute

        // NOTE: Clock and SlotHashes sysvars are now updated pre-execute in
        // replay_stage.zig replayEntriesInternal(). @prov:bank.freeze — removed from freeze().

        // Step 1: Update RecentBlockhashes sysvar (slot != 0, has entries)
        try self.updateRecentBlockhashes();


        // Step 2: Update SlotHistory sysvar (bitvec marking this slot present)
        try self.updateSlotHistory();

        // Step 3: Settle fees (creates leader credit write)
        // @prov:bank.settle-fees
        //
        // r27 [CAP-DEBUG]: capture cap pre +
        // post settleFees to verify the new `self.capitalization -= burn`
        // line is firing per slot. Useful as long as the experiment runs;
        // remove after r27 verdict is locked.
        const cap_pre_settle = self.capitalization;
        try self.settleFees(rent_exempt_min_fn);
        std.log.debug(
            "[CAP-DEBUG] slot={d} pre_settle={d} post_settle={d} delta={d}",
            .{
                self.slot,
                cap_pre_settle,
                self.capitalization,
                @as(i128, self.capitalization) - @as(i128, cap_pre_settle),
            },
        );

        // Step 4: Burn incinerator lamports
        // @prov:bank.incinerator
        try self.runIncinerator();

        // Step 5: apply all pending writes to the LtHash accumulator
        // r69: walk FORWARD and apply EVERY write's delta. Do NOT deduplicate.
        // LtHash is a homomorphic accumulator — chained deltas telescope correctly:
        // for two writes on the same pubkey (W1: -A+B, W2: -B+C), applying both
        // gives (-B+C) + (-A+B) = -A+C, the true pre-slot→final-state delta.
        // Pre-r69 deduplicated keeping last write only → applied -B+C, dropped -A+B
        // → wrong by (B-A) per duplicated pubkey, EVERY slot. Carrier of bank_hash
        // 0/N MATCH for ~6 weeks. Firedancer (fd_runtime_save_account per write)
        // and Agave (BankHashStats.num_updated_accounts counts every write) both
        // apply per-write without dedup. AccountsDb final-state flush is a
        // SEPARATE concern handled in flushPendingWritesToDb — that path may
        // dedup for storage; this lthash path must not.
        //
        // r71 [LT-DELTA] probe (env-gated, advisor-designed): collapses residual
        // lthash carrier search to one diagnostic pass. The 4 hypotheses (after
        // r71 same-slot diff confirmed all 1160 final bytes match Agave) are:
        //   (1) extra Vexor-only writes
        //   (2) missing writes Agave applies
        //   (3) wrong old_lt for some write
        //   (4) within-slot duplicate where W2.old_lt != W1.new_lt (deltas don't
        //       telescope per r69 invariant)
        // FLUSH log already showed `deduped=1158 from 1160` → 2 dups exist
        // concretely. Probe pass A flags every duplicated pubkey and compares
        // w[i+1].old_lt against w[i].new_lt. Probe pass B logs per-write 8-byte
        // prefixes + null flags so post-run grep names the carrier without a
        // re-deploy. Set VEX_LT_DELTA=1 to enable.
        // r73-carrier4-fix (2026-05-06): per-pubkey lthash dedup.
        //
        // Pre-r73 walked pending_writes forward and applied EVERY write's
        // delta (-w.old_lt + w.new_lt). That telescopes correctly ONLY when
        // chains are intact (W2.old_lt == W1.new_lt for same-pubkey writes).
        // Empirically (LT-DELTA probe 2026-05-06 ~03:25Z), ~5% of dups break
        // chain on live testnet — producing per-slot lthash divergence at the
        // very FIRST live-replay slot. Per advisor's hypothesis #4 confirmation.
        //
        // The fix: aggregate by pubkey, keeping FIRST occurrence's old_lt
        // (= pre-slot ancestor state, since db.getAccount returns pre-slot
        // before flush) and LAST occurrence's new_lt (= final post-slot state).
        // For each unique pubkey, mix (-first.old_lt + last.new_lt). This
        // matches Agave's `update_accounts_lt_hash` semantics:
        //   "For each modified pubkey: mix(-ancestor_lt + final_lt)".
        // (Reference: agave-4.0/runtime/src/bank.rs:1457-1474 + 2685.)
        //
        // Equivalence check vs old behavior:
        //   Single-write case:    -w.old + w.new                  ≡  same delta
        //   Chained dup case:     -W1.old + W1.new - W1.new + W2.new
        //                       = -W1.old + W2.new                ≡  same as new code
        //   Broken-chain dup:     -W1.old + W1.new - X + W2.new  (X != W1.new)
        //                       = WRONG (intermediate state leaks)
        //                       new code: -W1.old + W2.new  ← correct (matches Agave)
        const PerPk = struct {
            first_old_lt: ?LtHash,
            last_new_lt: ?LtHash,
            last_w_idx: usize,
        };
        var per_pk = std.AutoHashMap([32]u8, PerPk).init(self.allocator);
        defer per_pk.deinit();

        // [TOPVOTES-TRACE] TEMPORARY measurement — snapshot of the EXACT buffer
        // Pass A/C consume for the lthash. vote_inline counts vote-owned entries
        // using the INLINE owner field ONLY (never .data — UAF, see the rev1
        // VOTE-PROBE note above). One line per frozen slot carrying the full
        // per-bank counter set (collect/exec/rollback/flush attribution).
        if (TvTrace.on()) {
            var tvt_vote_inline: u32 = 0;
            for (self.pending_writes.items) |*w| {
                if (std.mem.eql(u8, &w.owner.data, &TvTrace.VOTE_OWNER)) tvt_vote_inline += 1;
            }
            std.log.warn(
                "[TOPVOTES-TRACE] freeze slot={d} pw_len={d} vote_inline={d} collect={d} collect_ovr={d} exec_entries={d} exec_ok={d} rolled_fail={d} rolled_tramp={d} flush_calls={d} no_acct={d} pre3={d} sig_called={d} mutate_fail={d} append_fail={d}",
                .{
                    self.slot,                 self.pending_writes.items.len, tvt_vote_inline,
                    self.tvt_vote_collect,     self.tvt_vote_collect_ovr,     self.tvt_vote_exec_entries,
                    self.tvt_vote_exec_ok,     self.tvt_vote_rolled_fail,     self.tvt_vote_rolled_tramp,
                    self.tvt_flush_calls,      self.tvt_vote_no_acct,         self.tvt_vote_pre3,
                    self.tvt_vote_sig_called,  self.tvt_vote_mutate_fail,     self.tvt_vote_append_fail,
                },
            );
            // [TOPVOTES-TRACE] ATOMIC die-point line (exact counts, race-free).
            std.log.warn(
                "[TOPVOTES-TRACE] diepoint slot={d} sw={d} sd={d} ss={d} st={d} dsd={d} dwv={d} dsh={d} dbd={d} vrdb={d} vrov={d} vrarm={d} enter={d} build={d} rtc={d} rpre={d} rdup={d} rpdup={d} rmet={d} xin={d} xok={d} xoom={d} xsys={d} xoth={d} dfw={d} dfap={d} dfeq={d} dfaf={d}",
                .{
                    self.slot,
                    self.tvt2_site_worker.load(.monotonic),         self.tvt2_site_dag.load(.monotonic),
                    self.tvt2_site_serial.load(.monotonic),         self.tvt2_site_tramp.load(.monotonic),
                    self.tvt2_dag_from_serial_drain.load(.monotonic), self.tvt2_dag_from_wave.load(.monotonic),
                    self.tvt2_dag_from_shadow.load(.monotonic),     self.tvt2_dag_from_blockdag.load(.monotonic),
                    self.tvt2_vread_db.load(.monotonic),            self.tvt2_vread_overlay.load(.monotonic),
                    self.tvt2_vread_ovr_armed.load(.monotonic),     self.tvt2_enter.load(.monotonic),
                    self.tvt2_build_done.load(.monotonic),          self.tvt2_ret_tc.load(.monotonic),
                    self.tvt2_ret_pre.load(.monotonic),             self.tvt2_ret_dupe.load(.monotonic),
                    self.tvt2_ret_pdupe.load(.monotonic),           self.tvt2_ret_metas.load(.monotonic),
                    self.tvt2_exec_enter.load(.monotonic),          self.tvt2_exec_ok.load(.monotonic),
                    self.tvt2_exec_err_oom.load(.monotonic),        self.tvt2_exec_err_sysvar.load(.monotonic),
                    self.tvt2_exec_err_other.load(.monotonic),      self.tvt2_diff_writable.load(.monotonic),
                    self.tvt2_diff_applied.load(.monotonic),        self.tvt2_diff_skip_eq.load(.monotonic),
                    self.tvt2_appfail.load(.monotonic),
                },
            );
        }

        // Pass A: aggregate per-pubkey first.old_lt + last.new_lt + last_w_idx.
        for (self.pending_writes.items, 0..) |w, i| {
            const gop = per_pk.getOrPut(w.pubkey.data) catch continue;
            if (!gop.found_existing) {
                gop.value_ptr.* = .{
                    .first_old_lt = w.old_lt,
                    .last_new_lt = w.new_lt,
                    .last_w_idx = i,
                };
            } else {
                gop.value_ptr.last_new_lt = w.new_lt;
                gop.value_ptr.last_w_idx = i;
            }
        }

        // Pass C: apply per-pubkey deltas to accounts_lthash accumulator.
        // Recorder Tier-2 instrumentation lives here, where the ACTUAL lthash
        // mix happens during freeze. (The applyLtHashDelta function is rarely
        // called on the hot path — most writes flow through this per-pk pass.)
        const rec_lt_on = recorder.isEnabled();
        // [VOTE-PROBE] Carrier-K (2026-06-08 rev2 CRASH-SAFE, env VEX_VOTE_PROBE): for
        // Vote-owned accounts log slot+pk+lt-prefix(+lamports) so a diff vs oracle-node
        // agave-ledger-tool per-account ground truth pins the EXACT diverging voter
        // (accounts_lt_hash compute carrier @413928162; vote-state piecewise merge
        // suspect). The lt-prefix already incorporates data+lamports+owner, so an lt
        // diff pins the account regardless of which field drifted.
        //   ⚠ rev1 (reverted) recomputed accountLtHash over lw2.data + sha256(lw2.data)
        //   and CRASHED in blake3: in lean mode the account-data buffer is freed once
        //   e.last_new_lt is cached, so lw2.data dangled (use-after-free). rev2 NEVER
        //   touches lw2.data — it reads the ALREADY-COMPUTED e.last_new_lt and only the
        //   inline struct fields (owner, lamports), which stay valid. Self-limiting cap.
        const vote_probe_on = std.posix.getenv("VEX_VOTE_PROBE") != null;
        const vote_probe_cap: u32 = blk: {
            const s = std.posix.getenv("VEX_VOTE_PROBE_MAX") orelse break :blk 600000;
            break :blk std.fmt.parseInt(u32, s, 10) catch 600000;
        };
        const VOTE_PROG8 = [_]u8{ 0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb };

        // [LT-WRITE-LOCALIZER] (env VEX_VERIFY_LTHASH_WRITES, optional lower-bound
        // VEX_VERIFY_LTHASH_SLOT): capture the EXACT lthash contribution applied to
        // the accumulator for each changed pubkey. Compared post-flush in
        // replay_stage against accountLtHash(committed readback) to name the carrier
        // account+slot whose applied delta != committed state. Capture is value/
        // inline-safe only (applied_lt, lamports, owner) — NEVER lw.data (UAF). The
        // capture buffer is bank-resident (lt_write_capture) so it survives until the
        // post-flush read; cleared per slot to avoid stale cross-slot entries.
        // Computed ONCE before the loop (one getenv); when OFF every per-pk capture
        // branch below is dead, so production pays zero cost.
        const lt_write_on = blk: {
            if (std.posix.getenv("VEX_VERIFY_LTHASH_WRITES") == null) break :blk false;
            const lb = std.posix.getenv("VEX_VERIFY_LTHASH_SLOT") orelse break :blk true;
            const bound = std.fmt.parseInt(u64, std.mem.trim(u8, lb, " \t\r\n"), 10) catch break :blk true;
            break :blk self.slot >= bound;
        };
        if (lt_write_on) self.lt_write_capture.clearRetainingCapacity();

        var iter = per_pk.iterator();
        while (iter.next()) |entry| {
            const pk = entry.key_ptr.*;
            const e = entry.value_ptr.*;

            if (vote_probe_on) {
                if (e.last_new_lt) |new| { // precomputed lt only — never deref lw2.data
                    const lw2 = &self.pending_writes.items[e.last_w_idx];
                    if (std.mem.eql(u8, lw2.owner.data[0..8], &VOTE_PROG8)) {
                        const VP = struct {
                            var n: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
                        };
                        const vn = VP.n.fetchAdd(1, .monotonic);
                        if (vn < vote_probe_cap) {
                            const np = std.mem.readInt(u64, new.asBytes()[0..8], .big);
                            const pkb = std.fmt.bytesToHex(&pk, .lower);
                            std.log.warn("[VOTE-PROBE] slot={d} pk={s} lt={x} lam={d}", .{ self.slot, &pkb, np, lw2.lamports });
                        }
                    }
                }
            }

            // FIX#95 freeze-time dump RETIRED (2026-07-02): the getAccountInSlot
            // re-read here (added for the #81 dangling-slice crash) could not see
            // THIS slot's un-flushed pending writes → it dumped NEW lamports +
            // OLD data (proven at 419132257: lt(dumped bytes) == op=0 contrib).
            // The dump now happens at collectWrite time (bank.zig ~870), where
            // the write's data buffer is guaranteed alive AND is the exact bytes
            // the lt pipeline hashes. Consumers dedupe last-line-per-pubkey.

            // Subtract first.old_lt (pre-slot ancestor state) if non-null.
            if (e.first_old_lt) |old| {
                if (rec_lt_on) {
                    const old_prefix = std.mem.readInt(u64, old.asBytes()[0..8], .big);
                    recorder.emitLtHashContribution(&pk, old_prefix, 0);
                }
                self.accounts_lthash.wrappingSub(&old);
            }

            // Add last.new_lt (final post-slot state) — compute from data
            // fields if not pre-computed.
            //
            // [LT-WRITE-LOCALIZER] `applied_new` holds the EXACT LtHash that hits
            // the accumulator below — captured (only when lt_write_on) for the
            // post-flush carrier check. The assignment is GATED so production pays
            // zero cost (no ~2KB LtHash copy per write); the captured value is
            // byte-identical to what wrappingAdd consumed. Both branches feed it so
            // a pubkey with a non-precomputed new_lt is not silently skipped.
            var applied_new: LtHash = undefined;
            if (e.last_new_lt) |new| {
                if (rec_lt_on) {
                    const new_prefix = std.mem.readInt(u64, new.asBytes()[0..8], .big);
                    recorder.emitLtHashContribution(&pk, new_prefix, 1);
                }
                self.accounts_lthash.wrappingAdd(&new);
                if (lt_write_on) applied_new = new;
            } else {
                const last_w = &self.pending_writes.items[e.last_w_idx];
                const new_lt = accountLtHash(
                    &pk,
                    &last_w.owner.data,
                    last_w.lamports,
                    last_w.executable,
                    last_w.data,
                );
                if (rec_lt_on) {
                    const new_prefix = std.mem.readInt(u64, new_lt.asBytes()[0..8], .big);
                    recorder.emitLtHashContribution(&pk, new_prefix, 1);
                }
                self.accounts_lthash.wrappingAdd(&new_lt);
                if (lt_write_on) applied_new = new_lt;
            }

            // [LT-WRITE-LOCALIZER] record the applied contribution + inline state.
            // last_w fields lamports/owner are inline (struct value), never the
            // freed `.data` slice — safe to read here. Stash the SUBTRACTED
            // first_old_lt (or LtHash.init() if the first write had no pre-state):
            // the EXACT value `accounts_lthash.wrappingSub(&old)` removed above, so
            // the OLD check compares apples-to-apples.
            if (lt_write_on) {
                const last_w = &self.pending_writes.items[e.last_w_idx];
                const cap_old: LtHash = e.first_old_lt orelse LtHash.init();
                self.lt_write_capture.append(self.allocator, .{
                    .pubkey = pk,
                    .applied_lt = applied_new,
                    .applied_lamports = last_w.lamports,
                    .applied_owner = last_w.owner.data,
                    .first_old_lt = cap_old,
                    .had_old = e.first_old_lt != null,
                }) catch {};
            }
        }

        // Step 5: compute bank hash
        // @prov:bank.hash-calc
        //
        // F2 (HARD-FORK-FAMILY-DESIGN-2026-06-17): compute the hard-fork mixin.
        // hard_forks rides on AccountsDb (cluster-wide + immutable for replay);
        // parent_slot is the TRUE parent bank's slot. @prov:bank.hard-fork-mixin —
        // `orelse 0` matching genesis parent_slot()==0. On post-restart
        // testnet this is null on every slot (parent_slot ≥ fork_slot) ⇒ NO
        // Step-3 mixin ⇒ byte-identical bank hash. Fires only when replaying the
        // fork slot itself (never here — the anchor hash is loaded, not recomputed).
        const hard_fork_buf: ?[8]u8 = blk: {
            const hf = if (self.accounts_db) |db| db.hard_forks else &[_]HardFork{};
            break :blk getHashData(hf, self.slot, self.parent_slot orelse 0);
        };
        self.bank_hash = computeBankHash(
            &self.accounts_lthash,
            &self.parent_hash,
            &self.poh_hash,       // ← must be the last entry's PoH hash, NOT tx.recent_blockhash
            self.signature_count,
            hard_fork_buf,
        );

        // [BANK-FROZEN] per-slot bank_hash + 4 inputs. @prov:bank.bank-frozen-log
        // Always-on observability (no env-gate). Required for parity tooling
        // (vex-live-parity-watch, vex-bank-decompose, drift-localizer).
        //
        // d28vv (2026-05-13): restored lthash_chk field that the d28 probe
        // cleanup dropped. Required by vex-bank-decompose.py and
        // lthash-lattice-decomposer.py to localize bank_hash divergence to
        // the actual diverging input (parent / sigs / poh / lthash). Format
        // matches the pre-cleanup convention: SHA-256(2048-byte lthash) →
        // hex first4 + last4 = 8 bytes (16 hex chars), and full 32-byte hash
        // hex for direct comparison. @prov:bank.lthash-checksum-blake3 — pure
        // read of the already-computed self.accounts_lthash field — no math changes.
        {
            const parent_hex = std.fmt.bytesToHex(self.parent_hash.data, .lower);
            const poh_hex = std.fmt.bytesToHex(self.poh_hash.data, .lower);
            const bh_hex = std.fmt.bytesToHex(self.bank_hash.data, .lower);
            // @prov:bank.lthash-checksum-blake3 — SHA256 here was an
            // unintentional 2026-05-13 regression in commit 2fd9ce4 — restored
            // to BLAKE3 per AUDIT_M_bank_hash_lineage.md. Diagnostic-only;
            // computeBankHash itself routes lthash bytes directly so this fix
            // has zero parity impact, but it unblocks drift-localizer tooling.
            var lthash_full: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(self.accounts_lthash.asBytes(), &lthash_full, .{});
            const lthash_full_hex = std.fmt.bytesToHex(lthash_full, .lower);
            const lthash_chk_first4 = std.fmt.bytesToHex(lthash_full[0..4].*, .lower);
            const lthash_chk_last4 = std.fmt.bytesToHex(lthash_full[28..32].*, .lower);
            std.log.warn(
                "[BANK-FROZEN] slot={d} parent={s} sigs={d} poh={s} bank_hash={s} lthash_chk={s}{s} lthash_full={s}\n",
                .{ self.slot, &parent_hex, self.signature_count, &poh_hex, &bh_hex, &lthash_chk_first4, &lthash_chk_last4, &lthash_full_hex },
            );
        }

        // [WRITESET-FULL] env-gated per-pubkey dump for the first ~30 frozen slots
        // after boot, used to diff against oracle-node's agave-ledger-tool cluster-
        // canonical writeset at the first-divergent slot. Bounded by env var
        // VEX_WRITESET_FULL=1 + atomic counter so production deploys pay zero IO.
        // Format: one line per pubkey containing (pubkey, owner, lamports, data_len,
        // sha256(data) first-8-bytes). Sufficient to identify any byte-level diff
        // class (vote-state bytes, sysvar data drift, BPF program PDA diffs,
        // fee-payer lamport deltas). Last-write-wins per pubkey to match Agave's
        // writeset accounting.
        {
            const env_on = std.process.getEnvVarOwned(self.allocator, "VEX_WRITESET_FULL") catch null;
            const ws_enabled = if (env_on) |v| blk: {
                defer self.allocator.free(v);
                break :blk std.mem.eql(u8, v, "1");
            } else false;
            if (ws_enabled) {
                const remaining = writeset_full_counter.load(.monotonic);
                if (remaining > 0) {
                    _ = writeset_full_counter.fetchSub(1, .monotonic);
                    var last_w_map = std.AutoHashMap([32]u8, AccountWrite).init(self.allocator);
                    defer last_w_map.deinit();
                    for (self.pending_writes.items) |w| {
                        last_w_map.put(w.pubkey.data, w) catch continue;
                    }
                    var it = last_w_map.iterator();
                    var emitted: usize = 0;
                    while (it.next()) |e| {
                        const w = e.value_ptr.*;
                        const pk_hex = std.fmt.bytesToHex(w.pubkey.data, .lower);
                        const ow_hex = std.fmt.bytesToHex(w.owner.data, .lower);
                        // Skip SHA over w.data — by freeze time the slice may point to
                        // freed/mmap'd memory (CLAUDE.md Pitfall #5). Emit data_len only;
                        // still identifies lamport diffs, missing/extra pubkeys, and
                        // data_len divergence. Data-byte diffs come from oracle-node's
                        // authoritative bank-file via per-account inspection if needed.
                        std.log.warn(
                            "[WRITESET-FULL] slot={d} pk={s} owner={s} lamports={d} data_len={d}",
                            .{ self.slot, &pk_hex, &ow_hex, w.lamports, w.data.len },
                        );
                        emitted += 1;
                        if (emitted > 2000) break;
                    }
                }
            }
        }

        // HASH-CHECK: periodic diagnostic — first 8 hex bytes of local hash + context
        if (self.slot % 100 == 0) {
            std.log.debug("[HASH-CHECK] slot={d} local_hash={x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2} sigs={d} writes={d}\n", .{
                self.slot,
                self.bank_hash.data[0], self.bank_hash.data[1],
                self.bank_hash.data[2], self.bank_hash.data[3],
                self.bank_hash.data[4], self.bank_hash.data[5],
                self.bank_hash.data[6], self.bank_hash.data[7],
                self.signature_count,
                self.pending_writes.items.len,
            });
        }

        self.is_frozen = true;

        std.log.debug(
            "[BANK] Slot {d}: frozen OK, bank_hash={x:0>8}..{x:0>8} sigs={d} writes={d}",
            .{
                self.slot,
                std.mem.readInt(u32, self.bank_hash.data[0..4], .big),
                std.mem.readInt(u32, self.bank_hash.data[28..32], .big),
                self.signature_count,
                self.pending_writes.items.len,
            },
        );
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "accountLtHash: zero lamports → zero lthash" {
    const lt = Bank.accountLtHash(
        &([_]u8{1} ** 32),
        &([_]u8{0} ** 32),
        0, false, &[_]u8{},
    );
    for (lt.elements) |e| {
        try std.testing.expectEqual(@as(u16, 0), e);
    }
}

test "accountLtHash: non-zero lamports → non-zero lthash" {
    const lt = Bank.accountLtHash(
        &([_]u8{1} ** 32),
        &([_]u8{0} ** 32),
        1_000_000, false, &[_]u8{},
    );
    // At least some elements should be non-zero
    var any_nonzero = false;
    for (lt.elements) |e| {
        if (e != 0) { any_nonzero = true; break; }
    }
    try std.testing.expect(any_nonzero);
}

test "bank freeze: empty slot produces deterministic hash" {
    const alloc = std.testing.allocator;
    const parent_hash = Hash.default();
    const poh = Hash.init([_]u8{0xAB} ** 32);

    var bank = try Bank.init(alloc, 100, 99, parent_hash, LtHash.init(), Hash.default());
    defer bank.deinit();

    bank.poh_hash = poh;
    bank.signature_count = 0;

    try bank.freeze({});

    // Hash must be non-zero for any non-trivial input
    try std.testing.expect(!std.mem.eql(u8, &bank.bank_hash.data, &([_]u8{0} ** 32)));
    try std.testing.expect(bank.is_frozen);
}

test "rewardDistributionWindowLive: defers owner-bank free until tip passes window (task #14 UAF guard)" {
    const alloc = std.testing.allocator;
    var bank = try Bank.init(alloc, 100, 99, Hash.default(), LtHash.init(), Hash.default());
    defer bank.deinit();

    // Simulate the epoch-boundary OWNER bank: owns the slice, distribution active,
    // window = [starting, starting + num_partitions). With REWARD_CALCULATION_NUM_BLOCKS=1
    // and boundary block_height=1000, starting=1001, num_partitions=126 → window_end=1127.
    bank.owns_stake_reward_partitions = true;
    bank.epoch_rewards_active = true;
    bank.block_height = 1000; // boundary block_height (frozen; owner never advances it)
    bank.distribution_starting_block_height = 1001;
    bank.num_reward_partitions = 126;
    const window_end: u64 = 1001 + 126; // 1127

    // Tip inside the window → MUST defer (a tail child may still iterate the slice).
    try std.testing.expect(bank.rewardDistributionWindowLive(1001)); // first child
    try std.testing.expect(bank.rewardDistributionWindowLive(window_end - 1)); // last iterating child
    // Tip AT/PAST window_end → free is safe (window_end child hits the completion
    // branch and never touches partition.rewards.items). Boundary is >=, not >.
    try std.testing.expect(!bank.rewardDistributionWindowLive(window_end));
    try std.testing.expect(!bank.rewardDistributionWindowLive(window_end + 50));

    // After deactivation (completion path sets epoch_rewards_active=false), the
    // window is NOT live even mid-range → the legitimate completion free is not blocked.
    bank.epoch_rewards_active = false;
    try std.testing.expect(!bank.rewardDistributionWindowLive(1001));
    bank.epoch_rewards_active = true;

    // An INHERITOR child (owns=false) is never considered live → it never frees,
    // unaffected by the guard.
    bank.owns_stake_reward_partitions = false;
    try std.testing.expect(!bank.rewardDistributionWindowLive(1001));
}

test "bank freeze: idempotent" {
    const alloc = std.testing.allocator;
    var bank = try Bank.init(alloc, 1, 0, Hash.default(), LtHash.init(), Hash.default());
    defer bank.deinit();
    bank.poh_hash = Hash.init([_]u8{0xFF} ** 32);

    try bank.freeze({});
    const first_hash = bank.bank_hash;
    try bank.freeze({}); // Should be no-op
    try std.testing.expect(std.mem.eql(u8, &bank.bank_hash.data, &first_hash.data));
}

// ─────────────────────────────────────────────────────────────────────────────
// Epoch Boundary Tests
// ─────────────────────────────────────────────────────────────────────────────

// Test fixture: no-warmup schedule for algorithm correctness tests below.
// vex-058 fix made `EpochSchedule.DEFAULT` use canonical Solana
// testnet/mainnet warmup params (warmup=true, first_normal_epoch=14,
// first_normal_slot=524256). The simple-math tests below pre-date that
// fix and were validating the no-warmup branch of the algorithm; they
// continue to do so via an explicit no-warmup fixture, while the
// "DEFAULT carries canonical Solana warmup" test below independently
// asserts DEFAULT's vex-058 lock-in.
const NO_WARMUP_SCHED = EpochSchedule{
    .slots_per_epoch = 432_000,
    .leader_schedule_slot_offset = 432_000,
    .warmup = false,
    .first_normal_epoch = 0,
    .first_normal_slot = 0,
};

test "EpochSchedule: getEpoch calculates correctly (no-warmup fixture)" {
    const sched = NO_WARMUP_SCHED;

    // Epoch 0: slots 0 to 431,999
    try std.testing.expectEqual(@as(u64, 0), sched.getEpoch(0));
    try std.testing.expectEqual(@as(u64, 0), sched.getEpoch(431_999));

    // Epoch 1: slots 432,000 to 863,999
    try std.testing.expectEqual(@as(u64, 1), sched.getEpoch(432_000));
    try std.testing.expectEqual(@as(u64, 1), sched.getEpoch(863_999));

    // Epoch 100: arbitrary epoch
    try std.testing.expectEqual(@as(u64, 100), sched.getEpoch(100 * 432_000));
}

test "EpochSchedule: DEFAULT carries canonical Solana warmup (vex-058 anti-regression)" {
    // Locks in the vex-058 fix: testnet/mainnet DEFAULT must be warmup=true
    // with 14 warmup epochs summing to 524256 slots. ANY revert here will
    // re-introduce the bank_hash divergence vex-058 closed.
    const sched = EpochSchedule.DEFAULT;
    try std.testing.expect(sched.warmup);
    try std.testing.expectEqual(@as(u64, 14), sched.first_normal_epoch);
    try std.testing.expectEqual(@as(u64, 524_256), sched.first_normal_slot);
    try std.testing.expectEqual(@as(u64, 432_000), sched.slots_per_epoch);

    // Smoke: a real testnet slot lands in the post-warmup branch.
    // 524256 + 13 * 432000 = 6,140,256 = first slot of epoch 27 (post-warmup).
    try std.testing.expectEqual(@as(u64, 27), sched.getEpoch(524_256 + 13 * 432_000));
    // 524255 is the last warmup slot; the warmup branch of getEpoch returns 0
    // today (TODO in source: full warmup-epoch calc not yet wired).
    try std.testing.expectEqual(@as(u64, 0), sched.getEpoch(524_255));
}

test "EpochSchedule: getLeaderScheduleEpoch (vote-authorize target_epoch carrier)" {
    // Pins the canonical leader_schedule_epoch used by the vote-program
    // Authorize/AuthorizeChecked handler for target_epoch = lse + 1.
    // Carrier slot 413005757: epoch=968, leader_schedule_epoch=969 -> the
    // AuthorizeChecked on 271KPMd must insert authorized_voters[970].
    const sched = EpochSchedule.DEFAULT;
    try std.testing.expectEqual(@as(u64, 968), sched.getEpoch(413_005_757));
    try std.testing.expectEqual(@as(u64, 969), sched.getLeaderScheduleEpoch(413_005_757));
    // lse is always exactly one ahead of epoch in the post-warmup steady state
    // because leader_schedule_slot_offset == slots_per_epoch (432000).
    try std.testing.expectEqual(
        sched.getEpoch(413_005_757) + 1,
        sched.getLeaderScheduleEpoch(413_005_757),
    );
}

test "EpochSchedule: isEpochBoundary detects boundaries (no-warmup fixture)" {
    const sched = NO_WARMUP_SCHED;

    // Boundaries
    try std.testing.expect(sched.isEpochBoundary(0));       // Genesis
    try std.testing.expect(sched.isEpochBoundary(432_000)); // Epoch 1 start
    try std.testing.expect(sched.isEpochBoundary(864_000)); // Epoch 2 start

    // Non-boundaries
    try std.testing.expect(!sched.isEpochBoundary(1));
    try std.testing.expect(!sched.isEpochBoundary(431_999));
    try std.testing.expect(!sched.isEpochBoundary(432_001));
}

test "EpochSchedule: getFirstSlotInEpoch computes correctly (no-warmup fixture)" {
    const sched = NO_WARMUP_SCHED;

    try std.testing.expectEqual(@as(u64, 0), sched.getFirstSlotInEpoch(0));
    try std.testing.expectEqual(@as(u64, 432_000), sched.getFirstSlotInEpoch(1));
    try std.testing.expectEqual(@as(u64, 864_000), sched.getFirstSlotInEpoch(2));
    try std.testing.expectEqual(@as(u64, 432_000 * 100), sched.getFirstSlotInEpoch(100));
}

test "EpochSchedule: boundary slot equals first slot of next epoch (no-warmup fixture)" {
    const sched = NO_WARMUP_SCHED;

    // Slot 431,999 is NOT a boundary (last slot of epoch 0)
    try std.testing.expect(!sched.isEpochBoundary(431_999));
    try std.testing.expectEqual(@as(u64, 0), sched.getEpoch(431_999));

    // Slot 432,000 IS a boundary (first slot of epoch 1)
    try std.testing.expect(sched.isEpochBoundary(432_000));
    try std.testing.expectEqual(@as(u64, 1), sched.getEpoch(432_000));

    // getFirstSlotInEpoch round-trips correctly
    const epoch1_start = sched.getFirstSlotInEpoch(1);
    try std.testing.expectEqual(@as(u64, 432_000), epoch1_start);
    try std.testing.expect(sched.isEpochBoundary(epoch1_start));
}

test "stake activation: bootstrap validator is immediately fully effective" {
    // Bootstrap validators have activation_epoch == maxInt(u64)
    const history = [_]Bank.StakeHistoryEntry{};
    const status = Bank.getStakeActivationStatus(
        std.math.maxInt(u64), // activation_epoch = bootstrap sentinel
        std.math.maxInt(u64), // deactivation_epoch = never
        1_000_000_000,        // 1 SOL stake
        100,                  // target_epoch
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    try std.testing.expectEqual(@as(u64, 1_000_000_000), status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
    try std.testing.expectEqual(@as(u64, 0), status.deactivating);
}

test "stake activation: not yet activated returns zero" {
    const history = [_]Bank.StakeHistoryEntry{};
    const status = Bank.getStakeActivationStatus(
        10, // activation_epoch
        std.math.maxInt(u64),
        500_000_000,
        5, // target_epoch < activation_epoch
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    try std.testing.expectEqual(@as(u64, 0), status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
    try std.testing.expectEqual(@as(u64, 0), status.deactivating);
}

test "stake activation: at activation epoch all is activating" {
    const history = [_]Bank.StakeHistoryEntry{};
    const stake: u64 = 500_000_000;
    const status = Bank.getStakeActivationStatus(
        10, // activation_epoch
        std.math.maxInt(u64),
        stake,
        10, // target_epoch == activation_epoch
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    try std.testing.expectEqual(@as(u64, 0), status.effective);
    try std.testing.expectEqual(stake, status.activating);
    try std.testing.expectEqual(@as(u64, 0), status.deactivating);
}

test "stake activation: warmup curve applies 9% rate per epoch" {
    // Cluster has 10 SOL effective, 1 SOL activating this epoch.
    // Our delegation: 1 SOL activating at epoch 5.
    // At epoch 6: weight = 1/1 = 1.0, newly_effective = floor(10e9 * 0.09) = 900_000_000
    // But stake is only 1 SOL = 1_000_000_000, so effective = min(900M, 1B) = 900M.
    const stake: u64 = 1_000_000_000; // 1 SOL
    const history = [_]Bank.StakeHistoryEntry{
        .{ .epoch = 5, .effective = 10_000_000_000, .activating = 1_000_000_000, .deactivating = 0 },
    };
    const status = Bank.getStakeActivationStatus(
        5,                    // activation_epoch
        std.math.maxInt(u64),
        stake,
        6,                    // target_epoch = one epoch after activation
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    // weight=1.0, newly_effective = floor(1.0 * 10B * 0.09) = 900_000_000
    try std.testing.expectEqual(@as(u64, 900_000_000), status.effective);
    try std.testing.expectEqual(@as(u64, 100_000_000), status.activating);
    try std.testing.expectEqual(@as(u64, 0), status.deactivating);
}

test "stake activation: warmup floor of 1 lamport for tiny delegations" {
    // Tiny stake: 1 lamport. Even if calculation rounds to 0, floor = 1.
    const history = [_]Bank.StakeHistoryEntry{
        .{ .epoch = 5, .effective = 10_000_000_000_000, .activating = 1_000_000_000_000, .deactivating = 0 },
    };
    const status = Bank.getStakeActivationStatus(
        5,
        std.math.maxInt(u64),
        1, // 1 lamport stake
        6,
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    // weight = 1/1T ≈ 0, newly_effective = max(floor(~0), 1) = 1
    // After one epoch: effective = 1 (the floor), activating = 0
    try std.testing.expectEqual(@as(u64, 1), status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
}

test "stake activation: same epoch activate+deactivate returns zero" {
    const history = [_]Bank.StakeHistoryEntry{};
    const status = Bank.getStakeActivationStatus(
        5, // activation_epoch
        5, // deactivation_epoch == activation_epoch
        1_000_000_000,
        5,
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    try std.testing.expectEqual(@as(u64, 0), status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
    try std.testing.expectEqual(@as(u64, 0), status.deactivating);
}

test "stake deactivation: at deactivation epoch returns effective as deactivating" {
    // Stake was fully activated (1 SOL) by epoch 10.
    // At deactivation epoch 10: effective=1B, deactivating=1B.
    const stake: u64 = 1_000_000_000;
    // Need warmup history so stake reaches full activation by epoch 10.
    // Use activation_epoch=10 so target==activation means immediate deact epoch check.
    const history = [_]Bank.StakeHistoryEntry{
        .{ .epoch = 8, .effective = 10_000_000_000, .activating = 0, .deactivating = 0 },
    };
    // activation=8, target=10, deactivation=10
    // Warmup loop: epoch 8, activating==0 → instant full activation → current_effective=1B
    // target_epoch(10) == deactivation_epoch(10) → return {effective:1B, deactivating:1B}
    const status = Bank.getStakeActivationStatus(
        8,    // activation_epoch
        10,   // deactivation_epoch
        stake,
        10,   // target_epoch == deactivation_epoch
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    try std.testing.expectEqual(stake, status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
    try std.testing.expectEqual(stake, status.deactivating);
}

test "stake deactivation: cooldown decreases remaining each epoch" {
    // Stake: 1 SOL fully effective. Deactivates at epoch 10.
    // Cluster at epoch 10: 10 SOL effective, 1 SOL deactivating.
    // At epoch 11: weight=1/1=1.0, newly_not_effective = max(1, lossyCast(1.0*10B*0.09)) = 900M
    // remaining_eff = 1B -|= 900M = 100M
    const stake: u64 = 1_000_000_000;
    const history = [_]Bank.StakeHistoryEntry{
        .{ .epoch = 8, .effective = 10_000_000_000, .activating = 0, .deactivating = 0 },
        .{ .epoch = 10, .effective = 10_000_000_000, .activating = 0, .deactivating = 1_000_000_000 },
    };
    const status = Bank.getStakeActivationStatus(
        8,
        10,   // deactivation_epoch
        stake,
        11,   // one epoch into cooldown
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    // After cooldown: remaining = 1B - 900M = 100M
    try std.testing.expectEqual(@as(u64, 100_000_000), status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
    try std.testing.expectEqual(@as(u64, 100_000_000), status.deactivating);
}

test "stake deactivation: saturating subtraction prevents underflow" {
    // If cooldown rate is 100% (or weight is large), remaining should not underflow.
    const stake: u64 = 1_000_000_000;
    const history = [_]Bank.StakeHistoryEntry{
        .{ .epoch = 8, .effective = 10_000_000_000, .activating = 0, .deactivating = 0 },
        // Tiny deactivating cluster stake = huge weight → massive cooldown
        .{ .epoch = 10, .effective = 10_000_000_000, .activating = 0, .deactivating = 1 },
    };
    const status = Bank.getStakeActivationStatus(
        8,
        10,
        stake,
        11,
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    // remaining_eff saturates to 0 (not wraps)
    try std.testing.expectEqual(@as(u64, 0), status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
    try std.testing.expectEqual(@as(u64, 0), status.deactivating);
}

test "stake activation: mid-warmup null entry keeps partial accumulation" {
    // Epoch 5: activate. Epoch 6: history entry present → gain 900M.
    // Epoch 7: history entry MISSING → break with partial (900M), don't jump to full.
    const stake: u64 = 2_000_000_000; // 2 SOL so we don't fully activate in one epoch
    const history = [_]Bank.StakeHistoryEntry{
        .{ .epoch = 5, .effective = 10_000_000_000, .activating = 2_000_000_000, .deactivating = 0 },
        // epoch 6 is MISSING from history
    };
    // At epoch 7: warmup loop runs epoch 5 → has entry (gain), epoch 6 → null → break
    // After epoch 5: weight = 2B/2B = 1.0, newly_effective = floor(10B * 0.09) = 900M
    //   current_effective = 900M
    // At epoch 6: null → mid-warmup break, keep 900M
    const status = Bank.getStakeActivationStatus(
        5,
        std.math.maxInt(u64),
        stake,
        7,   // target = epoch 7, warmup_end = min(7, maxInt) = 7
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    try std.testing.expectEqual(@as(u64, 900_000_000), status.effective);
    try std.testing.expectEqual(@as(u64, 1_100_000_000), status.activating); // stake - effective
    try std.testing.expectEqual(@as(u64, 0), status.deactivating);
}

test "stake deactivation: missing deact_entry at deactivation epoch returns zero" {
    // If StakeHistory has no entry at deactivation_epoch, returns all zeros. @prov:bank.stake-activation-status
    const stake: u64 = 1_000_000_000;
    const history = [_]Bank.StakeHistoryEntry{
        .{ .epoch = 8, .effective = 10_000_000_000, .activating = 0, .deactivating = 0 },
        // epoch 10 (deactivation) MISSING → deact_entry == null → return zeros
    };
    const status = Bank.getStakeActivationStatus(
        8,
        10,
        stake,
        11,   // past deactivation_epoch
        &history,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    try std.testing.expectEqual(@as(u64, 0), status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
    try std.testing.expectEqual(@as(u64, 0), status.deactivating);
}

test "stake deactivation: mid-cooldown null entry keeps remaining as-is" {
    // epoch 10: deactivation, entry present. epoch 11: present (cooldown). epoch 12: MISSING → break.
    // After epoch 10 cooldown step: remaining = 1B - 900M = 100M
    // epoch 11: weight = 100M/100M = 1.0, newly_not = max(1, lossyCast(1.0*100M*0.09)) = 9M
    // remaining = 100M - 9M = 91M; then epoch 12 missing → break → 91M remains
    const stake: u64 = 1_000_000_000;
    const history2 = [_]Bank.StakeHistoryEntry{
        .{ .epoch = 8, .effective = 10_000_000_000, .activating = 0, .deactivating = 0 },
        .{ .epoch = 10, .effective = 10_000_000_000, .activating = 0, .deactivating = 1_000_000_000 },
        .{ .epoch = 11, .effective = 100_000_000, .activating = 0, .deactivating = 100_000_000 },
        // epoch 12 missing
    };
    const status = Bank.getStakeActivationStatus(
        8,
        10,
        stake,
        13,   // past the missing epoch
        &history2,
        0, // nrae sentinel: always 9% (flat-rate test expectations)
    );
    // After epoch 10 step: 1B -|= 900M = 100M
    // After epoch 11 step: 100M -|= max(1, lossyCast(100M*0.09)) = 100M-9M = 91M
    // epoch 12: null → break, keep 91M
    try std.testing.expectEqual(@as(u64, 91_000_000), status.effective);
    try std.testing.expectEqual(@as(u64, 0), status.activating);
    try std.testing.expectEqual(@as(u64, 91_000_000), status.deactivating);
}

test "capitalization: tracks field correctly" {
    // Verify capitalization field is accessible and updates as expected.
    const alloc = std.testing.allocator;
    var bank = try Bank.init(alloc, 432_000, 431_999, Hash.default(), LtHash.init(), Hash.default());
    defer bank.deinit();

    // Default is 0
    try std.testing.expectEqual(@as(u64, 0), bank.capitalization);

    // Set a known value (snapshot manifest would normally set this)
    bank.capitalization = 500_000_000_000_000_000; // 500M SOL in lamports
    try std.testing.expectEqual(@as(u64, 500_000_000_000_000_000), bank.capitalization);

    // Simulate reward distribution increasing capitalization
    const reward: u64 = 1_000_000_000; // 1 SOL reward
    bank.capitalization += reward;
    try std.testing.expectEqual(@as(u64, 500_000_001_000_000_000), bank.capitalization);
}

test "EpochSchedule: skipped slot boundary still detected at next slot (no-warmup fixture)" {
    // Simulates: validator missed slot 432,000 but processes 432,001.
    // The boundary epoch is still epoch 1 for both slots. Uses no-warmup
    // fixture so the assertions don't depend on DEFAULT's warmup math —
    // see the "DEFAULT carries canonical Solana warmup" test above for
    // the DEFAULT-shape lock-in.
    const sched = NO_WARMUP_SCHED;

    // Slot 432,000 is the actual boundary
    try std.testing.expect(sched.isEpochBoundary(432_000));
    try std.testing.expectEqual(@as(u64, 1), sched.getEpoch(432_000));

    // Slot 432,001 is NOT a boundary but is in epoch 1
    try std.testing.expect(!sched.isEpochBoundary(432_001));
    try std.testing.expectEqual(@as(u64, 1), sched.getEpoch(432_001));

    // Both are in the same epoch — boundary detection happens at first slot only
    try std.testing.expectEqual(sched.getEpoch(432_000), sched.getEpoch(432_001));
}
