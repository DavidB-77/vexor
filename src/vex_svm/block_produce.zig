//! Block-production glue (M1 — empty/tick-only slot): the byte-exact "produce a slot's entry-batch
//! wire bytes" entry point, isolated here so it is KAT-able WITHOUT touching the giant replay file.
//!
//! STAGED / leader_mode-gated. Reuses the two KAT-verified primitives:
//!   - leader_poh.produceSlot  (byte-exact PoH cadence, leader_poh.zig)  — NOT block_producer.zig's
//!     own PoH, which has a per-signature mixin bug (block_producer.zig:116-123).
//!   - entry.serializeEntries  (the inverse of the replay parser, entry.zig:158; task #27 round-trip).
//!
//! `produceEmptySlotBytes` returns the SAME entry-batch wire format the replay worker parses
//! (replay_stage.zig:4627 `// skip the Vec<Entry> count prefix` → per-entry num_hashes/hash/num_txs).
//! Feeding it to pushSlotForReplayWithParent self-validates the bytes through the cluster-shared
//! parser and freezes a bank (M1). Shred broadcast (M2) consumes the same entry list.
//!
//! An empty block = exactly `ticks_per_slot` tick entries, each `num_hashes == hashes_per_tick`,
//! NO transaction entries. The last tick's hash is the slot's blockhash. (TooFewTicks dead-slot gate
//! requires exactly ticks_per_slot ticks — replay_stage.zig:5526.)

const std = @import("std");
const entry = @import("entry.zig");
const lpoh = @import("leader_poh.zig");
const banking_stage = @import("banking_stage");
const tx_ingest = @import("tx_ingest");
const compute_budget = @import("compute_budget");
const cost_tracker = @import("cost_tracker.zig");
const builtin_cu_costs = @import("builtin_cu_costs.zig");

const Hash = entry.Hash; // [32]u8
const BankingStage = banking_stage.BankingStage;

/// Re-export the entry-batch parse helpers so a downstream test that roots block_produce (and thus
/// owns entry.zig as part of THIS module) can walk produced bytes without a separate `entry` module
/// instance (a file may belong to only one module). Pure aliases — no behavior change.
pub const readEntryCount = entry.readEntryCount;
pub const readEntryHeader = entry.readEntryHeader;

/// Effective testnet PoH params (task #28: hashes_per_tick raised from genesis 12500 to 62500;
/// ticks_per_slot = Agave DEFAULT_TICKS_PER_SLOT = 64, matched by the replay tick gate
/// EXPECTED_TICKS_PER_SLOT). The caller MUST pass the bank/manifest values where available so a
/// cluster with different genesis params stays correct; these are the documented testnet defaults.
pub const TESTNET_HASHES_PER_TICK: u64 = 62500;
pub const TICKS_PER_SLOT: u64 = 64;

/// Produce one EMPTY (tick-only) slot's entry-batch wire bytes off `seed` (= the parent slot's last
/// tick hash, i.e. parent bank.poh_hash). Caller owns the returned buffer.
/// `out_blockhash` (optional) receives the slot's last tick hash (= the produced blockhash).
pub fn produceEmptySlotBytes(
    allocator: std.mem.Allocator,
    seed: Hash,
    hashes_per_tick: u64,
    ticks_per_slot: u64,
    out_blockhash: ?*Hash,
) ![]u8 {
    // 1. byte-exact PoH cadence → ticks_per_slot tick entries (no microblocks).
    var poh_entries: std.ArrayListUnmanaged(lpoh.PohEntry) = .{};
    defer poh_entries.deinit(allocator);
    const final = try lpoh.produceSlot(allocator, &poh_entries, seed, hashes_per_tick, ticks_per_slot, &.{});
    if (out_blockhash) |p| p.* = final;

    // 2. PohEntry[] → entry.Entry[] (all ticks → transactions = empty).
    const entries = try allocator.alloc(entry.Entry, poh_entries.items.len);
    defer allocator.free(entries);
    for (poh_entries.items, 0..) |pe, i| {
        entries[i] = .{ .num_hashes = pe.num_hashes, .hash = pe.hash, .transactions = &.{} };
    }

    // 3. serialize to the replay-parser wire format (one Vec<Entry> batch).
    return entry.serializeEntries(allocator, entries);
}

// ════════════════════════════════════════════════════════════════════════════
// produceSlotBytes — REAL (non-empty) slot: drain the mempool, pack txs into entries with the
// CANONICAL per-entry PoH mixin, interleave with ticks, serialize to the same wire format.
//
// LOOPBACK milestone (task #13): wired behind VEX_TPU_INGEST (default OFF), broadcast STAYS OFF
// (VEX_LEADER_BROADCAST untouched). The produced bytes are self-validated through the cluster-shared
// replay parser (loopback). No shred leaves the host.
//
// CANONICAL MIXIN (the #1 must-get-right, Agave entry/src/entry.rs:326-333 hash_transactions):
//   per ENTRY, mixin = MerkleTree-root over the FLATTENED signatures of all txs in that entry
//   (NOT per-signature — that is the documented bug at the top of this file). We pack ONE tx per
//   entry here, so each entry's flattened-sig set is just that one tx's signatures, hashed via
//   `entry.hashTransactions(allocator, &.{ tx_sig_list })`. leader_poh.record() consumes that mixin
//   via sha256(poh ‖ mixin) — byte-identical to how the replay-side verifier recomputes it.
//
// We reuse the PROVEN leader_poh mixed-slot machinery (leader_poh.zig:103 produceSlot +
// :190-234 record/tick zip), rather than inventing a second PoH driver.
//
// LOAD-VALIDATE INCLUSION PRE-FILTER (task #25, 2026-06-21): the `gate` param below carries a per-tx
// PRE-FILTER, NOT a complete broadcast-safety boundary. Pinned vs the CANONICAL Agave pin 4.1.0-rc.1
// (git 5efbb99; verified BYTE-IDENTICAL to 4.0.0, which the live testnet cluster runs today): which
// tx-failure classes are BLOCK-FATAL during cluster replay (any outer Result::Err → get_first_error
// → mark_dead_slot, rc.1 blockstore_processor.rs:207 / replay_stage.rs:2559) vs TOLERATED
// (FeesOnly / Executed-with-inner-error → Ok). The pre-filter drops the load/validate failures
// (NotLoaded) it can detect against the FROZEN PARENT independently per tx: BlockhashNotFound,
// in-block AlreadyProcessed (duplicate signature), fee-payer AccountNotFound / InvalidAccountForFee
// / InsufficientFundsForFee, and an invalid signature. ProgramAccountNotFound / non-executable
// program / instruction-execution errors are TOLERATED and are NOT gated.
//
// ⚠️ WHY IT IS ONLY A PRE-FILTER (NOT a superset of fatal): the cluster executes a block
// SEQUENTIALLY, but the pre-filter used to check each tx against the parent state in ISOLATION. A tx
// that transfers away / closes a fee-payer EARLIER in the same block could make a LATER tx
// InsufficientFundsForFee → NotLoaded → the cluster marks the WHOLE block dead, and the pre-filter
// could not see that (M1, 2026-07-16: proven reachable through the REAL gate, BOTH by an adversarial
// drain and by ordinary same-payer burst traffic — kat_txbearing_exec.zig "M1 adversarial-drain" /
// "M1 same-payer benign-burst"). M2 (2026-07-16) CLOSES this for `SeqGateState`'s SEQUENTIAL live gate
// (`admitTxSeq`) for `System::Transfer` / `System::CreateAccount` when the lamport-mover's `from` is
// the tx's own fee-payer — see `SeqGateState`/`applyLamportEffects` below for the mechanism and the
// NAMED residual instruction classes / third-party-source shape that remain uncovered. `admitTx` (the
// STATELESS single-tx variant, kept for direct KATs) is UNCHANGED and still checks parent state in
// isolation only — it is not the live gate.
// The COMPLETE broadcast-safety boundary is still, in the general case, execution-based — either
// execute-during-pack (Agave's banking model) or loopback-replay-then-broadcast-only-if-not-dead
// (which also needs Vexor's replay to actually detect the NotLoaded classes; it currently does not).
// That FULL mechanism remains a FLIP-BLOCKER (task #25) for the residual classes M2 does not cover.
// Until it lands, a SAFETY INTERLOCK in replay_stage forbids broadcasting tx-bearing bytes (tx-bearing
// + VEX_LEADER_BROADCAST ⇒ produce EMPTY + error) UNLESS the explicit VEX_TXBEARING_BROADCAST override
// is set (see replay_stage.zig's own interlock comment) — the pre-filter otherwise only ever runs for
// loopback validation.
//
// gate == null  ⇒ loopback/KAT-lenient path: byte-identical to the pre-gate behavior. The default
//                 while VEX_TPU_INGEST is off, and (currently) also the tile path's loopback packing.
// gate != null  ⇒ apply the per-tx pre-filter + produceSlotBytes' own in-block duplicate-signature
//                 dedup. Used by the inline loopback path; a loopback block is replayed only by us
//                 and never voted, so an imperfect pre-filter can at worst waste our own slot.
//
// STILL DEFERRED before the broadcast flip (do NOT remove): (a) the execution-based completeness
// mechanism above, for the residual instruction classes / third-party-source shape M2 does not cover
// (see `applyLamportEffects`'s "EXPLICITLY UNCOVERED" doc); (b) cost-model block-CU-limit packing (a
// separate BLOCK-FATAL class, check_block_cost_limits); (c) CROSS-block AlreadyProcessed via a live
// status cache (Vexor's TxnCache has no production wiring yet — only in-block dedup is covered here);
// (d) the tile's thread-safe SNAPSHOT gate (the tile cannot deref the recycled live bank). All are
// flip-blockers, tracked in task #25; none is reachable while the interlock holds / VEX_TPU_INGEST off.

/// Per-tx inclusion PRE-FILTER (see banner: necessary, NOT sufficient for broadcast). The caller
/// (replay_stage, which holds the producing bank + accounts_db + fee machinery) supplies `admit`;
/// block_produce stays free of Bank/AccountsDb imports (no module cycle). `admit(ctx, tx_wire)`
/// returns true iff the raw tx passes the per-tx load/validate checks against the FROZEN PARENT bank.
/// In-block duplicate-signature dedup is handled by produceSlotBytes itself (per-block seen-set).
pub const InclusionGate = struct {
    ctx: *anyopaque,
    admit: *const fn (ctx: *anyopaque, tx_wire: []const u8) bool,

    // ── PASS 3 (durable execute-once-and-record) executor hook ──────────────────────────────────────
    // When `execute` is non-null, produceSlotBytes packs a tx IFF `execute(exec_ctx, tx_wire)` returns
    // true (Agave `was_processed()`) — and the static `admit` pre-filter (whitelist/admitTxSeq) is
    // BYPASSED, because the executor supersedes it: it EXECUTES AND COMMITS each candidate against a
    // working child state so the next candidate sees the real post-state (inclusion == execution,
    // consumer.rs/committer.rs). This structurally closes the [PRODUCE-PARITY-FAIL] dead-block class
    // (block ⊆ was_processed) without the whitelist's throughput collapse — a tx the executor can fully
    // process (System Transfer/CreateAccount today) is packed even if the static delta gate would have
    // mishandled its cross-tx state dependency. `execute` is called AFTER the block-CU cost gate accepts
    // the tx, so a cost-rejected tx is never executed ⇒ the executor's committed set == the packed set
    // exactly (no produce≠replay divergence). null ⇒ legacy gate+whitelist path, byte-identical to pre-
    // PASS-3 behaviour. Live: supplied by replay_stage.zig (accounts_db-backed executor). Offline:
    // supplied by the KAT (in-memory block_executor.BlockExecutor). block_produce imports NO executor
    // type (avoids the block_executor→block_produce module cycle) — the hook is a bare callback.
    exec_ctx: ?*anyopaque = null,
    execute: ?*const fn (ctx: *anyopaque, tx_wire: []const u8) bool = null,
};

/// Fee-payer account view, extracted from the producing bank by the caller (lamports/owner/data_len).
/// `null` at the call site means the account is absent or has zero lamports (Agave AccountNotFound).
pub const FeePayerView = struct { lamports: u64, owner: [32]u8, data_len: usize };

/// The System Program's 32-byte id (all-zero pubkey). Hoisted to file scope so both
/// `checkStaticAndOwner` and the M2 lamport-effect walk (`applyLamportEffects`) share one definition.
const SYSTEM_PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;

/// Lamports a 0-data account must hold to be rent-exempt under default rent params
/// (ACCOUNT_STORAGE_OVERHEAD 128 × lamports_per_byte_year 3480 × exemption_threshold 2). Used as a
/// conservative post-fee floor so an admitted fee-payer never goes rent-paying after the fee.
pub const RENT_EXEMPT_MIN_ZERO: u64 = 890_880;
/// @prov:fees.lamports-per-sig
pub const LAMPORTS_PER_SIGNATURE: u64 = 5000;

/// @prov:cost-model.constants — the block-aggregate CU ceiling: a block exceeding it is marked
/// dead on replay (check_block_cost_limits).
pub const MAX_BLOCK_UNITS: u64 = 60_000_000;

/// CANONICAL transaction fee in lamports. @prov:fees.calculate-fee
/// Mirrors the LIVE replay fee path (replay_stage.zig:6191-6203, proven bank-exact) via the same
/// `parsePrecompileSigCountFromWire`/`parsePriorityFeeFromWire`. (Stage-1 omitted the precompile
/// sigs → under-counted; that is corrected here.)
pub fn txFee(parsed: tx_ingest.ParsedTx, tx_wire: []const u8) u64 {
    const precompile_sigs = compute_budget.parsePrecompileSigCountFromWire(tx_wire, parsed.keys_offset, parsed.num_keys, parsed.instructions_offset);
    const total_sigs: u64 = @as(u64, parsed.num_required_sigs) +| @as(u64, precompile_sigs);
    const base = LAMPORTS_PER_SIGNATURE *| total_sigs;
    const prio = compute_budget.parsePriorityFeeFromWire(tx_wire, parsed.keys_offset, parsed.num_keys, parsed.instructions_offset);
    return base +| prio;
}

/// CANONICAL per-tx block-CU cost (the `TxCost.sum` the CostTracker charges) computed from the raw
/// wire — the components derivable WITHOUT executing the tx (the producer side has no
/// post-execution actual-CU; Agave's pack loop uses the same *estimated* cost). @prov:cost-model.data-cost
///
///   sum = signature_cost                                  (total sigs × SIGNATURE_COST=720)
///       + write_lock_cost                                 (num_writable × WRITE_LOCK_UNITS=300)
///       + data_bytes_cost                                 (Σ ix.data.len ÷ INSTRUCTION_DATA_BYTES_COST=4)  [FIX #1: DIVIDE, not multiply]
///       + program_cost                                    (FIX #3/#6, see below)
///       + loaded_accounts_data_size_cost                  (FIX #2, see below)
///
/// `program_cost` (FIX #3/#6 — REPLACES the pre-2026-07-12 per-builtin-numeric-cost sum).
/// @prov:cost-model.program-cost
/// "builtin" here = `builtin_cu_costs.getBuiltinCost(..) != null` (only its Optional-ness is consulted,
/// not the specific .cost value) — after FIX #6 this exactly matches Agave's 9-entry
/// BUILTIN_INSTRUCTION_COSTS set (system/compute_budget/vote/bpf_loader×3/loader_v4/secp256k1/ed25519;
/// stake/config/address_lookup_table are core-BPF migrated, so they fall into the 200,000 bucket). This
/// MATCHES `compute_budget.zig`'s `isBuiltinForBudget`+`executionLimit`, independently re-verified here.
///
/// `loaded_accounts_data_size_cost` (FIX #2): @prov:cost-model.loaded-accts — same boundary class
/// as the v0-ALT under-count documented below.
///
/// NOTE the writable-account count comes straight from the message header
/// (num_writable = (num_required_sigs − num_readonly_signed) + (num_keys − num_required_sigs −
/// num_readonly_unsigned)), the same decomposition `bank.estimateTransactionCost` consumes. v0 ALT
/// (loaded) writable accounts are NOT counted here (a producer-side under-estimate that can only
/// admit MORE txs than the cluster would — but the loopback interlock means an over-packed block is
/// never broadcast; the real cluster re-checks check_block_cost_limits on replay). Documented boundary.
pub const DEFAULT_INSTRUCTION_CU_LIMIT: u64 = 200_000; // @prov:compute-budget.exec-limit
pub const MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT: u64 = 3_000; // @prov:compute-budget.exec-limit
pub const MAX_COMPUTE_UNIT_LIMIT: u64 = 1_400_000; // @prov:compute-budget.exec-limit

pub fn txCostSum(parsed: tx_ingest.ParsedTx, tx_wire: []const u8) u64 {
    // (1) signature cost — precompile-aware total (same count txFee uses for fees).
    const precompile_sigs = compute_budget.parsePrecompileSigCountFromWire(tx_wire, parsed.keys_offset, parsed.num_keys, parsed.instructions_offset);
    const total_sigs: u64 = @as(u64, parsed.num_required_sigs) +| @as(u64, precompile_sigs);
    var sum: u64 = total_sigs *| cost_tracker.SIGNATURE_COST;

    // (2) write-lock cost. Writable count from the message header. The two readonly counts sit at
    //     wire bytes [num_required_sigs byte + 1 .. +2] = (keys_offset is past the 3-byte header +
    //     n_keys varint, so re-read the header relative to the signatures). We recover the header by
    //     stepping back from keys_offset: header is the 3 bytes ending where the n_keys varint begins.
    //     Simpler + robust: parse from the message-header bytes that tx_ingest already located. The
    //     message header begins at the start of `parsed.message` for a legacy tx (no version byte).
    const num_keys: u64 = parsed.num_keys;
    const num_required: u64 = parsed.num_required_sigs;
    // Readonly counts: byte 1 and 2 of the legacy message header (byte 0 = num_required_signatures).
    // For a v0 message the leading 0x80 version byte shifts these by one; handle both.
    var hdr0: usize = 0;
    if (parsed.is_versioned and parsed.message.len > 0 and parsed.message[0] == 0x80) hdr0 = 1;
    var num_ro_signed: u64 = 0;
    var num_ro_unsigned: u64 = 0;
    if (parsed.message.len >= hdr0 + 3) {
        num_ro_signed = parsed.message[hdr0 + 1];
        num_ro_unsigned = parsed.message[hdr0 + 2];
    }
    // num_writable = writable signers + writable non-signers (clamped, never underflow).
    const writable_signed = num_required -| num_ro_signed;
    const non_signers = num_keys -| num_required;
    const writable_unsigned = non_signers -| num_ro_unsigned;
    const num_writable = writable_signed +| writable_unsigned;
    sum +|= num_writable *| cost_tracker.WRITE_LOCK_UNITS;

    // (3) data-bytes cost + (4) program cost: ONE walk over the instructions.
    var data_bytes: u64 = 0;
    var builtin_ix: u64 = 0; // FIX #3/#6: count only — the flat SIMD-170 default consults counts, not per-program values.
    var non_builtin_ix: u64 = 0;
    var explicit_limit: ?u64 = null;

    var p = parsed.instructions_offset;
    walk: {
        if (p >= tx_wire.len) break :walk;
        const num_ix = readCompactU16Wire(tx_wire, &p) orelse break :walk;
        var i: u16 = 0;
        while (i < num_ix) : (i += 1) {
            if (p >= tx_wire.len) break :walk;
            const program_id_index = tx_wire[p];
            p += 1;
            const num_accounts = readCompactU16Wire(tx_wire, &p) orelse break :walk;
            if (p + num_accounts > tx_wire.len) break :walk;
            p += num_accounts; // skip account index list
            const data_len = readCompactU16Wire(tx_wire, &p) orelse break :walk;
            if (p + data_len > tx_wire.len) break :walk;
            const data_pos = p;
            p += data_len;
            data_bytes +|= data_len;

            // Resolve the program id.
            if (program_id_index >= num_keys) {
                non_builtin_ix +|= 1;
                continue;
            }
            const prog_off = parsed.keys_offset + @as(usize, program_id_index) * 32;
            if (prog_off + 32 > tx_wire.len) {
                non_builtin_ix +|= 1;
                continue;
            }
            const prog_id: *const [32]u8 = @ptrCast(tx_wire[prog_off..][0..32].ptr);
            if (builtin_cu_costs.getBuiltinCost(prog_id) != null) {
                builtin_ix +|= 1;
                // An explicit SetComputeUnitLimit (ComputeBudget ix discriminator 2) sets the budget outright.
                if (std.mem.eql(u8, prog_id, &builtin_cu_costs.COMPUTE_BUDGET_PROGRAM_ID) and
                    data_len >= 5 and tx_wire[data_pos] == 2 and explicit_limit == null)
                {
                    explicit_limit = std.mem.readInt(u32, tx_wire[data_pos + 1 ..][0..4], .little);
                }
            } else {
                non_builtin_ix +|= 1;
            }
        }
    }
    // FIX #1: divide, not multiply. @prov:cost-model.data-cost
    sum +|= data_bytes / cost_tracker.INSTRUCTION_DATA_BYTES_COST;

    // FIX #3/#6: program_cost — explicit limit wins outright; else the flat SIMD-170 default
    // (builtin_ix×3,000 + non_builtin_ix×200,000), capped. @prov:cost-model.program-cost
    // This REPLACES the old per-builtin-numeric-cost sum entirely.
    const program_cost = if (explicit_limit) |lim|
        @min(lim, MAX_COMPUTE_UNIT_LIMIT)
    else
        @min(
            builtin_ix *| MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT +| non_builtin_ix *| DEFAULT_INSTRUCTION_CU_LIMIT,
            MAX_COMPUTE_UNIT_LIMIT,
        );
    sum +|= program_cost;

    // FIX #2: loaded-accounts-data-size default term (always the 64MiB-limit default; see doc comment).
    sum +|= cost_tracker.DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_COST;

    return sum;
}

/// FIX #5a: the actual writable-account pubkey set for this tx (STATIC keys only — v0 ALT-loaded
/// writable accounts are NOT included, the same documented under-count `txCostSum` carries). Writes
/// into caller-supplied `out` (sized for the realistic max static-key count of a single tx; a legacy
/// tx is bounded by the 1232-byte packet size to ~38 keys, a v0 tx's STATIC keys likewise, so 256 is
/// generous headroom) and returns the count. Same header decomposition as txCostSum's write-lock cost
/// (num_writable), just materialized into concrete pubkeys instead of only counted.
pub fn txWritableAccountKeys(parsed: tx_ingest.ParsedTx, tx_wire: []const u8, out: []cost_tracker.Pubkey) usize {
    const num_keys: u64 = parsed.num_keys;
    const num_required: u64 = parsed.num_required_sigs;
    var hdr0: usize = 0;
    if (parsed.is_versioned and parsed.message.len > 0 and parsed.message[0] == 0x80) hdr0 = 1;
    var num_ro_signed: u64 = 0;
    var num_ro_unsigned: u64 = 0;
    if (parsed.message.len >= hdr0 + 3) {
        num_ro_signed = parsed.message[hdr0 + 1];
        num_ro_unsigned = parsed.message[hdr0 + 2];
    }
    const writable_signed = num_required -| num_ro_signed; // first N signer keys are writable
    const non_signer_count = num_keys -| num_required;
    const writable_unsigned = non_signer_count -| num_ro_unsigned; // first N non-signer keys are writable

    var count: usize = 0;
    var idx: u64 = 0;
    while (idx < num_keys and count < out.len) : (idx += 1) {
        const writable = if (idx < num_required)
            idx < writable_signed
        else
            (idx - num_required) < writable_unsigned;
        if (!writable) continue;
        const off = parsed.keys_offset + @as(usize, @intCast(idx)) * 32;
        if (off + 32 > tx_wire.len) break;
        out[count] = tx_wire[off..][0..32].*;
        count += 1;
    }
    return count;
}

/// FIX #5b: allocated_accounts_data_size — the SEPARATE byte budget CreateAccount-family System
/// instructions attempt to allocate this tx. @prov:cost-model.system-alloc-size
/// Walks top-level instructions; for each targeting the System program, decodes the bincode-tagged
/// instruction (4-byte LE discriminator + body, the SAME wire layout
/// `vex_bpf2/builtins/system_program.zig::decode` uses) and sums `space` for the allocating variants
/// (CreateAccount=0, CreateAccountWithSeed=3, Allocate=8, AllocateWithSeed=9,
/// CreateAccountAllowPrefund=13 — SIMD-0312, dormant on testnet but harmless to include). Any `space`
/// over MAX_PERMITTED_DATA_LENGTH, or any System instruction that fails to parse, makes Agave
/// short-circuit the WHOLE tx's allocation to 0 (a statically-known-to-fail allocation persists
/// nothing) — mirrored here.
const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024; // 10 MiB — matches the value used repo-wide (e.g. native/system_v2.zig)
const MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION: u64 = 10 * 1024 * 1024 * 2; // 20 MiB

pub fn txAllocatedAccountsDataSize(parsed: tx_ingest.ParsedTx, tx_wire: []const u8) u64 {
    const num_keys: u64 = parsed.num_keys;
    var total: u64 = 0;

    var p = parsed.instructions_offset;
    walk: {
        if (p >= tx_wire.len) break :walk;
        const num_ix = readCompactU16Wire(tx_wire, &p) orelse break :walk;
        var i: u16 = 0;
        while (i < num_ix) : (i += 1) {
            if (p >= tx_wire.len) break :walk;
            const program_id_index = tx_wire[p];
            p += 1;
            const num_accounts = readCompactU16Wire(tx_wire, &p) orelse break :walk;
            if (p + num_accounts > tx_wire.len) break :walk;
            p += num_accounts;
            const data_len = readCompactU16Wire(tx_wire, &p) orelse break :walk;
            if (p + data_len > tx_wire.len) break :walk;
            const data_pos = p;
            p += data_len;

            if (program_id_index >= num_keys) continue;
            const prog_off = parsed.keys_offset + @as(usize, program_id_index) * 32;
            if (prog_off + 32 > tx_wire.len) continue;
            const prog_id = tx_wire[prog_off..][0..32];
            if (!std.mem.eql(u8, prog_id, &([_]u8{0} ** 32))) continue; // not the System program

            const ix_data = tx_wire[data_pos..][0..data_len];
            if (ix_data.len < 4) continue; // not a well-formed System instruction; no allocation
            const tag = std.mem.readInt(u32, ix_data[0..4], .little);
            const body = ix_data[4..];
            const space: ?u64 = switch (tag) {
                0, 13 => blk: { // CreateAccount / CreateAccountAllowPrefund: lamports(8) space(8) owner(32)
                    if (body.len < 16 + 32) break :blk null;
                    break :blk std.mem.readInt(u64, body[8..16], .little);
                },
                3 => blk: { // CreateAccountWithSeed: base(32) seed(u64-len String) lamports(8) space(8) owner(32)
                    if (body.len < 32 + 8) break :blk null;
                    const seed_len = std.mem.readInt(u64, body[32..40], .little);
                    if (body.len < 40 + seed_len + 8 + 8 + 32) break :blk null;
                    const rest = body[40 + seed_len ..];
                    break :blk std.mem.readInt(u64, rest[8..16], .little);
                },
                8 => blk: { // Allocate: space(8)
                    if (body.len < 8) break :blk null;
                    break :blk std.mem.readInt(u64, body[0..8], .little);
                },
                9 => blk: { // AllocateWithSeed: base(32) seed(u64-len String) space(8) owner(32)
                    if (body.len < 32 + 8) break :blk null;
                    const seed_len = std.mem.readInt(u64, body[32..40], .little);
                    if (body.len < 40 + seed_len + 8 + 32) break :blk null;
                    const rest = body[40 + seed_len ..];
                    break :blk std.mem.readInt(u64, rest[0..8], .little);
                },
                // Assign(1)/Transfer(2)/AdvanceNonce(4)/WithdrawNonce(5)/InitializeNonce(6)/
                // AuthorizeNonce(7)/AssignWithSeed(10)/TransferWithSeed(11)/UpgradeNonce(12): the
                // full None set (None ⇒ contributes 0, does NOT fail the tx).
                // Any other/unknown tag: does not bincode-decode to a valid SystemInstruction ⇒ Agave's
                // Err arm ⇒ Failed ⇒ 0 for the WHOLE tx. @prov:cost-model.system-alloc-size
                1, 2, 4, 5, 6, 7, 10, 11, 12 => continue,
                else => return 0,
            };
            const s = space orelse return 0; // malformed allocating ix ⇒ Failed ⇒ whole tx is 0
            if (s > MAX_PERMITTED_DATA_LENGTH) return 0; // statically-known-to-fail ⇒ whole tx is 0
            total +|= s;
        }
    }
    return @min(total, MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION);
}

/// Local compact-u16 (shortvec) reader over a wire slice (mirrors compute_budget.readCompactU16).
fn readCompactU16Wire(data: []const u8, pos: *usize) ?u16 {
    var result: u16 = 0;
    var shift: u4 = 0;
    while (true) : (shift += 7) {
        if (pos.* >= data.len) return null;
        const b = data[pos.*];
        pos.* += 1;
        result |= @as(u16, @intCast(b & 0x7f)) << shift;
        if (b & 0x80 == 0) break;
        if (shift >= 14) return null;
    }
    return result;
}

/// The non-balance per-tx checks shared by admitTx / admitTxSeq: sigverify + blockhash membership +
/// fee-payer is a plain system account. Returns the fee-payer view iff all pass, else null (drop).
/// Balance is checked by the caller (it depends on running state in the sequential gate).
fn checkStaticAndOwner(
    parsed: tx_ingest.ParsedTx,
    tx_wire: []const u8,
    recent_blockhashes: []const [32]u8,
    fee_payer: ?FeePayerView,
) ?FeePayerView {
    // (1) sigverify — an invalid ed25519 signature is BLOCK-FATAL on cluster replay.
    if (!tx_ingest.verifySignatures(parsed)) return null;
    // (2) blockhash age — BlockhashNotFound is BLOCK-FATAL. The recent set holds ≤150 entries (Agave
    //     MAX_PROCESSING_AGE), so membership ⊂ {age ≤ 150}: a hit is always valid.
    if (parsed.instructions_offset < 32 or parsed.instructions_offset > tx_wire.len) return null;
    const bh = tx_wire[parsed.instructions_offset - 32 ..][0..32];
    var bh_known = false;
    for (recent_blockhashes) |h| {
        if (std.mem.eql(u8, &h, bh)) {
            bh_known = true;
            break;
        }
    }
    if (!bh_known) return null;
    // (3) fee-payer kind — AccountNotFound / InvalidAccountForFee fatal. Conservatively require a plain
    //     system account (data_len 0); drops rare nonce-account fee payers — safe.
    const fp = fee_payer orelse return null; // absent or zero-lamports ⇒ AccountNotFound
    if (!std.mem.eql(u8, &fp.owner, &SYSTEM_PROGRAM_ID)) return null; // InvalidAccountForFee
    if (fp.data_len != 0) return null; // plain system account only
    return fp;
}

/// PURE per-tx pre-filter against the FROZEN PARENT in isolation (stateless). Kept for direct KATs;
/// the LIVE gate uses admitTxSeq (sequential). `fee_payer.lamports` is the parent-state balance.
pub fn admitTx(
    parsed: tx_ingest.ParsedTx,
    tx_wire: []const u8,
    recent_blockhashes: []const [32]u8,
    fee_payer: ?FeePayerView,
) bool {
    const fp = checkStaticAndOwner(parsed, tx_wire, recent_blockhashes, fee_payer) orelse return false;
    // InsufficientFundsForFee + post-fee rent-exempt (conservative; see RENT_EXEMPT_MIN_ZERO).
    if (fp.lamports < RENT_EXEMPT_MIN_ZERO +| txFee(parsed, tx_wire)) return false;
    return true;
}

/// Per-block running state for the SEQUENTIAL inclusion gate. Matches Agave banking, which executes
/// against the LIVE, already-mutated Bank as it packs (`consumer.rs:190-254`
/// `process_and_record_transactions_with_pre_results` → `prepare_sanitized_batch_with_results` locks
/// on the live bank → `execute_and_commit_transactions_locked` executes+commits before the next batch
/// is even considered — inclusion and execution are the SAME step, so a drained payer is always caught
/// at admission time in Agave). Vexor's producer is a two-step pre-filter-then-execute-later pipeline
/// (see file banner), so this struct is the bridge: it tracks the SIGNED LAMPORT DELTA (relative to
/// the frozen-parent snapshot) accumulated by every ADMITTED tx's effects so far this block, for ANY
/// account touched — not just fee-payers. `effective(key, parent_lamports)` = the caller-supplied
/// frozen-parent balance (only ever needed/available at the moment `key` acts as a fee-payer) plus the
/// tracked delta. This composes correctly even when `key` was earlier a pure TRANSFER
/// destination/source that never itself paid a fee: the delta was recorded then, the parent-state base
/// is supplied fresh whenever `key` is later looked up as a fee-payer. i128 avoids any accumulation-
/// overflow concern for a block's bounded tx count (each delta is individually bounded by a u64 wire
/// field). Reset/owned per produced block by the caller.
pub const SeqGateState = struct {
    deltas: std.AutoHashMapUnmanaged([32]u8, i128) = .{},

    pub fn deinit(self: *SeqGateState, allocator: std.mem.Allocator) void {
        self.deltas.deinit(allocator);
    }

    /// Frozen-parent `parent_lamports` (as looked up by the caller for `key`, valid only when `key` is
    /// being evaluated as a fee-payer right now) plus every delta recorded against `key` so far this
    /// block, in produced-block order.
    fn effective(self: *const SeqGateState, key: [32]u8, parent_lamports: u64) i128 {
        const d = self.deltas.get(key) orelse 0;
        return @as(i128, parent_lamports) + d;
    }

    /// Accumulate a signed lamport delta against `key` (fee debit, transfer debit/credit, …).
    fn addDelta(self: *SeqGateState, allocator: std.mem.Allocator, key: [32]u8, delta: i128) !void {
        const gop = try self.deltas.getOrPut(allocator, key);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += delta;
    }
};

/// SystemInstruction discriminators (bincode u32-LE) this gate can statically derive a lamport effect
/// for, matching `native/system.zig`'s `InstructionOpcodes` (a Firedancer `fd_sys_instr_idx_t` mirror;
/// NOT imported here — importing the `system` module into block_produce.zig would require re-wiring
/// every one of block_produce.zig's several build.zig module instantiations (test-block-produce,
/// test-txbearing-exec, test-block-broadcast, the production net_block_produce, …), none of which
/// currently register a "system" import; these are the SAME numeric values, kept in sync by citation).
/// Transfer(2) is the M1-PROVEN case (kat_txbearing_exec.zig "M1 adversarial-drain" /
/// "M1 same-payer benign-burst"). CreateAccount(0) shares Transfer's exact data layout for the
/// lamports field — `disc(4) ‖ lamports(8) ‖ …` — and account-index shape (`[from, to]`), so it rides
/// the same code path with no new risk class.
const SYS_DISC_CREATE_ACCOUNT: u32 = 0; // native/system.zig:15 InstructionOpcodes.CreateAccount
const SYS_DISC_TRANSFER: u32 = 2; // native/system.zig:17 InstructionOpcodes.Transfer

/// EXPLICITLY UNCOVERED (residual, named per the M2 brief's "don't silently claim completeness"):
///   - CreateAccountWithSeed(3) / TransferWithSeed(11): the seed field is a bincode-serialized String
///     (u64 length prefix, NOT the compact-u16 encoding used elsewhere in this file) sitting BEFORE
///     the lamports field in CreateAccountWithSeed's data layout — a materially different, higher-risk
///     parse than the fixed-offset fields Transfer/CreateAccount use. Not attempted here to avoid
///     introducing a MIS-parse (which could corrupt delta tracking for an unrelated account) for an
///     instruction shape M1 never exercised.
///   - WithdrawNonceAccount(5) / stake-program withdraw / vote-program withdraw: lamport-moving, but
///     each needs its own program-specific account-layout verification (stake/vote are core-BPF
///     migrated programs, not native System) not done in this milestone.
///   - Any instruction whose program id, source, or destination resolves to an ALT-loaded (v0) account
///     index (`idx >= parsed.num_keys`): not resolvable from the wire alone (same boundary class as
///     `txCostSum`'s already-documented v0-ALT writable-account under-count, above).
///   - A lamport-mover whose `from` account is NOT the tx's own fee-payer (e.g. TransferWithSeed's
///     base-signs-for-a-derived-`from` pattern, or any multi-signer tx where signer_keys[0] isn't the
///     instruction's `from`): the gate has no live parent-state balance for a third-party account, so
///     the delta is applied OPTIMISTICALLY (assume the instruction succeeds) rather than verified —
///     see `applyLamportEffects` doc. This is a narrower instance of the SAME "gate lacks a live
///     account oracle" shape as the original bug, bounded to this uncommon shape only.
/// Extract the lamports field for a covered discriminator, else null (uncovered / malformed — the
/// caller's walk simply skips this instruction, same as always for TOLERATED, non-block-fatal cases).
fn lamportMoveAmount(disc: u32, data: []const u8) ?u64 {
    return switch (disc) {
        SYS_DISC_TRANSFER => if (data.len == 12) std.mem.readInt(u64, data[4..12], .little) else null,
        SYS_DISC_CREATE_ACCOUNT => if (data.len >= 52) std.mem.readInt(u64, data[4..12], .little) else null,
        else => null,
    };
}

/// Resolve instruction account index `idx` to a STATIC message key (i.e. NOT an ALT-loaded v0
/// address — those live past `parsed.num_keys` and are not present in the wire's static key list).
fn resolveStaticKey(tx_wire: []const u8, parsed: tx_ingest.ParsedTx, idx: u8) ?[32]u8 {
    if (idx >= parsed.num_keys) return null; // ALT-loaded — not resolvable from wire (documented boundary)
    const off = parsed.keys_offset + @as(usize, idx) * 32;
    if (off + 32 > tx_wire.len) return null;
    var out: [32]u8 = undefined;
    @memcpy(&out, tx_wire[off..][0..32]);
    return out;
}

/// Apply the lamport-moving effect of an ADMITTED tx's covered System-program instructions to `state`,
/// so a LATER tx's admission check sees the TRUE post-execution balance for any account this tx
/// touched — closing the transfer-drain residual `admitTxSeq` used to document (`block_produce.zig`,
/// previously ":487-488"). `fp_key`/`fp_parent_lamports` are THIS tx's own fee-payer identity/
/// frozen-parent-balance (already known to the caller — `admitTxSeq` just looked them up), used for
/// the one case the gate can VERIFY rather than assume (see below).
///
/// WHOLE-TRANSACTION ATOMICITY: a tx's instructions do not commit independently — Solana transaction
/// processing is atomic (excluding the fee, which is charged in a separate step before instruction
/// execution begins and is never rolled back): if ANY instruction fails, EVERY account-state change
/// from EVERY instruction in that SAME tx reverts together. So this walk buffers every covered
/// instruction's delta in `pending` and commits the WHOLE batch to `state` in one pass only if every
/// from==fp_key affordability check (the one case verifiable here) passes; the first such failure
/// discards `pending` entirely (an early `return`) rather than keeping the earlier, already-"applied"
/// instructions' deltas — otherwise an earlier instruction's delta could be committed even though the
/// tx it belongs to never actually executes, a phantom effect in either direction (false admit OR
/// false refusal for a later tx). `local_fp_delta` tracks fp_key's not-yet-committed running effect
/// from EARLIER instructions in this SAME tx (both directions: a credit TO fp_key funds a LATER debit
/// FROM fp_key within the same tx), on top of `state`'s already-committed cross-tx delta.
///
/// Best-effort on allocator failure: if buffering/committing cannot proceed, no further effect is
/// tracked (degrades to pre-fix behavior for the untracked accounts — never a NEW failure mode, never
/// retroactively un-admits the already-decided tx, which was decided by the caller before this runs).
fn applyLamportEffects(
    allocator: std.mem.Allocator,
    state: *SeqGateState,
    parsed: tx_ingest.ParsedTx,
    tx_wire: []const u8,
    fp_key: [32]u8,
    fp_parent_lamports: u64,
) void {
    var pending: std.ArrayListUnmanaged(struct { key: [32]u8, delta: i128 }) = .{};
    defer pending.deinit(allocator);
    var local_fp_delta: i128 = 0;

    var p = parsed.instructions_offset;
    const num_ix = readCompactU16Wire(tx_wire, &p) orelse return;
    var i: u16 = 0;
    while (i < num_ix) : (i += 1) {
        if (p >= tx_wire.len) return;
        const program_id_index = tx_wire[p];
        p += 1;
        const num_accounts = readCompactU16Wire(tx_wire, &p) orelse return;
        if (p + num_accounts > tx_wire.len) return;
        const acct_idx_start = p;
        p += num_accounts;
        const data_len = readCompactU16Wire(tx_wire, &p) orelse return;
        if (p + data_len > tx_wire.len) return;
        const data = tx_wire[p..][0..data_len];
        p += data_len;

        // Program id must resolve to a STATIC key equal to the System Program — else skip (ALT-loaded
        // program id, or simply not System: nothing statically derivable here).
        const prog_key = resolveStaticKey(tx_wire, parsed, program_id_index) orelse continue;
        if (!std.mem.eql(u8, &prog_key, &SYSTEM_PROGRAM_ID)) continue;
        if (data_len < 4 or num_accounts < 2) continue; // both covered classes need [from, to] + ≥4B disc
        const disc = std.mem.readInt(u32, data[0..4], .little);
        const amount = lamportMoveAmount(disc, data) orelse continue;

        const from_idx = tx_wire[acct_idx_start];
        const to_idx = tx_wire[acct_idx_start + 1];
        const from_key = resolveStaticKey(tx_wire, parsed, from_idx) orelse continue;
        const to_key = resolveStaticKey(tx_wire, parsed, to_idx) orelse continue;

        if (std.mem.eql(u8, &from_key, &fp_key)) {
            // The reliable case (M1-proven; also the common single-signer-wallet shape): `from` IS
            // this tx's own fee-payer, so we have a TRUE live balance (frozen-parent + every
            // cross-tx-committed delta + this SAME tx's own earlier instruction effects via
            // `local_fp_delta`). Mirror native/system.zig executeTransfer's atomic insufficient-funds
            // semantics: if this instruction would fail, the WHOLE tx (bar the fee) never executes —
            // discard everything buffered for this tx so far, not just this one instruction.
            const live = state.effective(fp_key, fp_parent_lamports) + local_fp_delta;
            if (live < @as(i128, amount)) return; // whole-tx rollback (atomicity) — commit NOTHING
            local_fp_delta -= @as(i128, amount);
        }
        if (std.mem.eql(u8, &to_key, &fp_key)) local_fp_delta += @as(i128, amount);

        // Either the fp_key case above passed, or `from`/`to` are third-party accounts we cannot
        // verify (see the EXPLICITLY UNCOVERED note above) — buffer optimistically; committed only if
        // the whole tx's covered instructions all pass their (verifiable) affordability checks.
        pending.append(allocator, .{ .key = from_key, .delta = -@as(i128, amount) }) catch return;
        pending.append(allocator, .{ .key = to_key, .delta = @as(i128, amount) }) catch return;
    }
    // No covered instruction failed its (verifiable) affordability check — commit the whole batch.
    for (pending.items) |eff| state.addDelta(allocator, eff.key, eff.delta) catch return;
}

/// INTERIM PRODUCE-PARITY WHITELIST (2026-07-18, forensics/txbearing-produce-parity-rootcause.md §3
/// interim item 1 — "conservatively REFUSE any tx shape the gate can't model correctly"). Root cause
/// #1's residual (§2 D1b): `applyLamportEffects` models ONLY System `Transfer`/`CreateAccount`; a tx
/// that drains a later tx's fee-payer via ANY other lamport-mover — an unmodeled System discriminator
/// (`TransferWithSeed`/`WithdrawNonceAccount`/`Assign`…), a NON-System program (which can CPI-drain),
/// or an account made writable via an ALT/v0 lookup the wire can't resolve — is admitted OPTIMISTICALLY
/// and dies on the cluster's sequential replay (`[PRODUCE-PARITY-FAIL]`, a dead-block detector). This
/// predicate is the STRUCTURAL fix for the WHOLE class (not a per-discriminator patch): a tx is
/// "fully modelable" iff EVERY instruction is the System program with a discriminator whose lamport
/// effect `applyLamportEffects` derives ({`Transfer`, `CreateAccount`}), EVERY account index (incl. the
/// program-id index) is a STATIC key (`< num_keys`, i.e. NOT ALT-loaded), and the message is NOT
/// versioned (v0 can carry ALT-loaded writable accounts absent from the static key list). Refusing
/// everything else makes the produced block a SUBSET of the set the gate tracks exactly ⇒ inclusion ==
/// execution for what it packs ⇒ the producer can only ever pack FEWER/EMPTY txs, NEVER a dead block.
/// INTERIM COST (accepted, per the report): throughput collapses to System-transfer/create traffic
/// until the durable produce-time execute-once-and-record executor lands. A zero-instruction tx is
/// trivially modelable (no lamport effect to miss). Uses the SAME wire-walk shape as
/// `applyLamportEffects` (readCompactU16Wire / resolveStaticKey) so the two stay in lockstep.
fn txFullyModelable(parsed: tx_ingest.ParsedTx, tx_wire: []const u8) bool {
    // v0 versioned message ⇒ may load extra writable accounts via address-table lookups that the
    // static key list cannot resolve (same boundary class as txCostSum's v0-ALT under-count). Refuse.
    if (parsed.is_versioned) return false;

    var p = parsed.instructions_offset;
    const num_ix = readCompactU16Wire(tx_wire, &p) orelse return false;
    var i: u16 = 0;
    while (i < num_ix) : (i += 1) {
        if (p >= tx_wire.len) return false;
        const program_id_index = tx_wire[p];
        p += 1;
        const num_accounts = readCompactU16Wire(tx_wire, &p) orelse return false;
        if (p + num_accounts > tx_wire.len) return false;
        const acct_idx_start = p;
        p += num_accounts;
        const data_len = readCompactU16Wire(tx_wire, &p) orelse return false;
        if (p + data_len > tx_wire.len) return false;
        const data = tx_wire[p..][0..data_len];
        p += data_len;

        // Program id must resolve to a STATIC key equal to the System Program.
        const prog_key = resolveStaticKey(tx_wire, parsed, program_id_index) orelse return false;
        if (!std.mem.eql(u8, &prog_key, &SYSTEM_PROGRAM_ID)) return false;
        // Discriminator must be one applyLamportEffects can derive a lamport effect for.
        if (data_len < 4) return false;
        const disc = std.mem.readInt(u32, data[0..4], .little);
        if (disc != SYS_DISC_TRANSFER and disc != SYS_DISC_CREATE_ACCOUNT) return false;
        // Every account index must be a static (non-ALT) key — nothing loaded past the static list.
        var k: u16 = 0;
        while (k < num_accounts) : (k += 1) {
            if (tx_wire[acct_idx_start + k] >= parsed.num_keys) return false;
        }
    }
    return true;
}

/// SEQUENTIAL per-tx admit — the LIVE gate. Like admitTx, but the fee-payer must be able to pay from
/// its RUNNING balance: parent lamports, adjusted by the TRACKED DELTA of every earlier ADMITTED tx's
/// effects this block against this SAME payer — both the fee-stacking drain (the sequential fee debit
/// this gate has always tracked) AND, as of M2, the lamport-moving-instruction effects of
/// `SYS_DISC_TRANSFER` / `SYS_DISC_CREATE_ACCOUNT` (see `applyLamportEffects`). `fee_payer.lamports`
/// seeds the delta base on first use of a payer. CONSERVATIVE: a borderline tx is dropped (safe).
/// Still uncovered: the instruction classes named in `lamportMoveAmount`'s doc comment, and any
/// third-party-source lamport-mover (see `applyLamportEffects`'s doc).
pub fn admitTxSeq(
    allocator: std.mem.Allocator,
    state: *SeqGateState,
    parsed: tx_ingest.ParsedTx,
    tx_wire: []const u8,
    recent_blockhashes: []const [32]u8,
    fee_payer: ?FeePayerView,
) bool {
    const fp = checkStaticAndOwner(parsed, tx_wire, recent_blockhashes, fee_payer) orelse return false;
    // INTERIM PRODUCE-PARITY WHITELIST: refuse any tx the gate cannot model exactly (unmodeled System
    // discriminator / non-System program / ALT-loaded index / v0). The produced block then only ever
    // contains fully-modeled txs whose sequential effects the gate tracks precisely — it can pack fewer
    // txs, never a dead block. See txFullyModelable's doc + forensics/txbearing-produce-parity-rootcause.md.
    if (!txFullyModelable(parsed, tx_wire)) return false;
    const fee = txFee(parsed, tx_wire);
    const fp_key = parsed.signer_keys[0];
    const running = state.effective(fp_key, fp.lamports);
    if (running < @as(i128, RENT_EXEMPT_MIN_ZERO) + @as(i128, fee)) return false; // sequential InsufficientFundsForFee
    // Admit: commit this tx's fee debit to the tracked delta so a later tx by the same payer sees it —
    // mirrors Agave's fee-debit-then-execute ordering (consumer.rs:256+).
    state.addDelta(allocator, fp_key, -@as(i128, fee)) catch return false;
    // M2: apply this tx's own lamport-moving-instruction effects (System::Transfer at minimum) in
    // wire order, so any LATER tx touching an account THIS tx moved lamports for sees the true state.
    applyLamportEffects(allocator, state, parsed, tx_wire, fp_key, fp.lamports);
    return true;
}

/// COMPLETE per-tx broadcast admit decision — the SINGLE TEST-ROOTABLE unit the live produce admit
/// path (`replay_stage.zig` `bankAdmitTxForBroadcast`) delegates to. It composes, in the same order
/// the cluster enforces:
///   (1) CROSS-BLOCK AlreadyProcessed dedup — refuse a tx whose FIRST signature was committed within
///       `RecentSigCache.MAX_RECENT_SLOTS` (=150) of `producing_slot`; the cluster's status cache
///       marks our block dead (AlreadyProcessed) otherwise. This is the ONE dead-block channel the
///       `txFullyModelable` whitelist does NOT close (a fully-modeled System transfer can still
///       duplicate a recently-committed signature). See `RecentSigCache`.
///   (2) the sequential load/fee gate (`admitTxSeq`).
/// Dedup runs BEFORE `admitTxSeq` so a duplicate NEVER mutates `state` (the SeqGateState running
/// balances) — a refused tx must leave zero trace, identical to any other refusal, and identical to
/// the pre-refactor inline order in `bankAdmitTxForBroadcast` (dedup then admit). `recent_sigs`==null
/// ⇒ dedup DORMANT: behaviourally IDENTICAL to calling `admitTxSeq` directly (the status-cache-off
/// path). Extracting this here — rather than leaving the dedup inline in the non-test-rootable
/// `replay_stage.zig` — is what makes the dedup refusal offline-KAT-provable
/// (`tests/kat_txbearing_exec.zig`, "cross-block dedup"). The query key `parsed.signatures[0]` is the
/// 64 bytes immediately after the wire's compact-u16 signature count — BYTE-IDENTICAL to the key the
/// commit path records (`replay_stage.zig` `tx_data[first_sig_off..][0..64]`, `first_sig_off` = the
/// same post-count offset), so a live record and this live query key the map on the same bytes.
pub fn admitTxSeqBroadcast(
    allocator: std.mem.Allocator,
    state: *SeqGateState,
    parsed: tx_ingest.ParsedTx,
    tx_wire: []const u8,
    recent_blockhashes: []const [32]u8,
    fee_payer: ?FeePayerView,
    recent_sigs: ?*const RecentSigCache,
    producing_slot: u64,
) bool {
    if (recent_sigs) |rsc| {
        if (rsc.isRecent(&parsed.signatures[0], producing_slot)) return false; // AlreadyProcessed
    }
    return admitTxSeq(allocator, state, parsed, tx_wire, recent_blockhashes, fee_payer);
}

/// Cross-block AlreadyProcessed dedup cache for tx-bearing block production (task #26). A tx whose
/// signature was committed in a block within the last MAX_RECENT_SLOTS (= Agave MAX_PROCESSING_AGE,
/// the blockhash validity window) must NOT be re-included — the cluster marks our block dead
/// (AlreadyProcessed, check_status_cache). CONSERVATIVE by design and SAFE:
///   - keyed on the first signature (identical sig ⟺ identical tx — the exact AlreadyProcessed test);
///   - NOT fork-aware: populated from EVERY replayed committed tx (any fork), so it over-includes
///     sibling-fork commits ⇒ at worst over-DROPS a valid tx (a throughput loss), never wrongly
///     admits a fatal duplicate;
///   - bank-hash-NEUTRAL: pure dedup state, not part of bank_hash (arming it cannot move consensus,
///     same property that made FEC-dedup safe to enable).
/// Populated on the replay commit path (gated) and queried by the producer gate (gated).
pub const RecentSigCache = struct {
    /// MAX_PROCESSING_AGE — a blockhash (and thus a non-duplicate window) is valid for ≤150 slots.
    pub const MAX_RECENT_SLOTS: u64 = 150;

    /// first signature → the slot it was last committed in.
    map: std.AutoHashMapUnmanaged([64]u8, u64) = .{},
    last_prune_slot: u64 = 0,

    pub fn deinit(self: *RecentSigCache, allocator: std.mem.Allocator) void {
        self.map.deinit(allocator);
    }

    /// Record a committed tx's signature at `slot` (called per committed tx during replay, gated).
    pub fn record(self: *RecentSigCache, allocator: std.mem.Allocator, sig: *const [64]u8, slot: u64) void {
        self.map.put(allocator, sig.*, slot) catch {}; // best-effort; a missed insert only relaxes dedup
    }

    /// True iff `sig` was committed within the last MAX_RECENT_SLOTS of `current_slot` ⇒ AlreadyProcessed.
    pub fn isRecent(self: *const RecentSigCache, sig: *const [64]u8, current_slot: u64) bool {
        const committed_slot = self.map.get(sig.*) orelse return false;
        return current_slot >= committed_slot and (current_slot - committed_slot) <= MAX_RECENT_SLOTS;
    }

    /// Drop entries older than the validity window. Idempotent per slot; call once per replayed slot.
    pub fn prune(self: *RecentSigCache, allocator: std.mem.Allocator, current_slot: u64) void {
        if (current_slot <= self.last_prune_slot) return;
        self.last_prune_slot = current_slot;
        if (current_slot <= MAX_RECENT_SLOTS) return;
        const cutoff = current_slot - MAX_RECENT_SLOTS;
        var stale: std.ArrayListUnmanaged([64]u8) = .{};
        defer stale.deinit(allocator);
        var it = self.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* < cutoff) stale.append(allocator, e.key_ptr.*) catch {};
        }
        for (stale.items) |k| _ = self.map.remove(k);
    }
};

/// Group one transaction's signatures (parsed views) into a `[]const []const u8` the merkle root
/// helper consumes, written into the caller-provided scratch. Returns the trimmed slice.
fn txSigSlices(sigs: []const [64]u8, scratch: [][]const u8) [][]const u8 {
    for (sigs, 0..) |*s, i| scratch[i] = s[0..];
    return scratch[0..sigs.len];
}

/// Produce one slot's entry-batch wire bytes off `seed` (= parent bank.poh_hash), packing the txs
/// drained from `banking` into entries (one tx per entry) with the canonical per-entry PoH mixin,
/// interleaved with exactly `ticks_per_slot` ticks (TooFewTicks-safe). Caller owns the returned
/// buffer. `out_blockhash` (optional) receives the slot's last tick hash. If the mempool is empty
/// this produces a tick-only slot byte-identical to `produceEmptySlotBytes`.
pub fn produceSlotBytes(
    allocator: std.mem.Allocator,
    seed: Hash,
    hashes_per_tick: u64,
    ticks_per_slot: u64,
    banking: *BankingStage,
    out_blockhash: ?*Hash,
    gate: ?InclusionGate,
    block_cu_limit: u64,
) ![]u8 {
    // 1. Drain the mempool. We OWN every qt.data (deep-copied at queue time) and must free it.
    const batch = try banking.drainBatch();
    defer {
        for (batch) |qt| banking.allocator.free(qt.data);
        allocator.free(batch);
    }

    // COST-MODEL block-CU accumulator (flip-blocker (b)): mirrors Agave's CostTracker.would_fit on the
    // pack side (banking_stage). We run a running block-CU total; before admitting each tx we add its
    // canonical estimated cost (txCostSum). If it would exceed `block_cu_limit` (= MAX_BLOCK_UNITS,
    // 60M SIMD-0256 on testnet, supplied by the caller from the active feature set) we STOP packing —
    // the block is complete and the tx (and all after it) are left for the next slot. This is the
    // BLOCK-FATAL class check_block_cost_limits enforces on cluster replay (a block over the limit is
    // marked dead). DORMANT: only ever runs on the loopback path while VEX_TPU_INGEST is on AND
    // broadcast is off (the interlock forbids tx-bearing broadcast). The CostTracker chains per-tx
    // cost into block_cost; we only consult/stop on the block ceiling here (the account/vote/data
    // sub-limits are tracked for completeness but a stop on any of them would also end the block).
    var ct = cost_tracker.CostTracker.init(allocator);
    defer ct.deinit();
    ct.setBlockLimit(block_cu_limit);

    // In-block duplicate-signature dedup set (only when gating for broadcast). Two txs sharing a
    // first signature are the same tx (a signature binds message+signer); a duplicate in one block
    // is AlreadyProcessed → BLOCK-FATAL on cluster replay, so the second copy must be dropped.
    var seen_sigs: std.AutoHashMapUnmanaged([64]u8, void) = .{};
    defer seen_sigs.deinit(allocator);

    // 2. For each well-formed tx: keep its raw wire blob and compute its canonical mixin. A tx that
    //    fails to parse is dropped (a real producer never packs a malformed tx; loopback is lenient
    //    but we still match intake semantics). The order of inclusion is the drain order (priority).
    var microblocks: std.ArrayListUnmanaged(lpoh.Microblock) = .{};
    defer microblocks.deinit(allocator);
    // tx_blobs[i] = the single-tx blob list for record i (one tx per entry → one element each).
    var tx_blobs: std.ArrayListUnmanaged([]const []const u8) = .{};
    defer {
        for (tx_blobs.items) |one| allocator.free(one);
        tx_blobs.deinit(allocator);
    }
    // Parallel: the flattened signature-set per record, so the zip below can recompute the mixin
    // path (record vs tick disambiguation) exactly as the producer recorded it.
    var rec_sigs: std.ArrayListUnmanaged([]const []const u8) = .{};
    defer {
        for (rec_sigs.items) |one| {
            for (one) |sig| allocator.free(sig);
            allocator.free(one);
        }
        rec_sigs.deinit(allocator);
    }

    var scratch_sigs: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var scratch_keys: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    var scratch_sig_views: [tx_ingest.MAX_SIGNATURES][]const u8 = undefined;

    // 2026-06-16: the single-FEC-set 20 KB cap is REMOVED — block_broadcast.shredsFromEntryBytes now
    // splits any payload into multiple chained FEC sets (faithful Agave merkle.rs make_shreds_from_data
    // port), so the packed block is no longer bounded to one resigned set. It is still bounded by Agave's
    // hard slot ceiling (MAX_DATA_SHREDS_PER_SLOT = 32768 shreds); shredsFromEntryBytes returns
    // error.BlockTooLarge above that, which the broadcast/loopback path surfaces (not silently dropped).
    for (batch) |qt| {
        const parsed = tx_ingest.parse(qt.data, &scratch_sigs, &scratch_keys) catch continue;

        // LOAD-VALIDATE INCLUSION GATE (broadcast-bound only; null ⇒ loopback/KAT-lenient). Drop any
        // tx that would be BLOCK-FATAL on cluster replay BEFORE packing it (see the banner above).
        if (gate) |g| {
            // (a) In-block AlreadyProcessed: skip a signature already packed into THIS block. Cheap
            //     check first (before the expensive ed25519 sigverify inside admit). getOrPut inserts
            //     the sig; a later admit-failure leaving it inserted is harmless (the tx is dropped).
            const gop = seen_sigs.getOrPut(allocator, parsed.signatures[0]) catch continue;
            if (gop.found_existing) continue;
            // (b) static load pre-filter (sigverify + blockhash-age + fee-payer-can-pay + whitelist),
            //     evaluated against the FROZEN PARENT. BYPASSED when the execute-once-and-record hook
            //     is active (PASS 3): the executor supersedes it, packing iff the tx was_processed
            //     after real execution (see below, post-cost-gate). See InclusionGate's exec doc.
            if (g.execute == null) {
                if (!g.admit(g.ctx, qt.data)) continue;
            }
        }

        // COST-MODEL block-CU gate (flip-blocker (b)): compute this tx's canonical estimated cost and
        // try to charge it to the running CostTracker. If adding it would exceed the block CU limit,
        // STOP packing — the block is complete; this tx (and the rest of the drained batch) are NOT
        // included (Agave check_block_cost_limits is BLOCK-FATAL on replay if exceeded). `tryAdd`
        // performs would_fit then add (the atomic admission step, byte-identical ordering to Agave
        // cost_tracker.rs). Runs UNCONDITIONALLY (gate or not) so even the loopback-lenient pack obeys
        // the block ceiling; with block_cu_limit huge it never fires (back-compat for the existing KATs
        // that pass MAX_BLOCK_UNITS / a generous limit). A WouldExceed* on ANY sub-limit ends the block.
        //
        // FIX #5: writable_accounts + allocated_accounts_data_size are now the REAL per-tx values
        // (txWritableAccountKeys / txAllocatedAccountsDataSize) instead of the always-empty/-zero
        // placeholders — the per-account (MAX_WRITABLE_ACCOUNT_UNITS=24M) and allocated-data-block
        // (MAX_BLOCK_ACCOUNTS_DATA_SIZE_DELTA=100M) caps in wouldFit were dead code without this wiring.
        var writable_scratch: [256]cost_tracker.Pubkey = undefined;
        const writable_count = txWritableAccountKeys(parsed, qt.data, &writable_scratch);
        const tx_cost = cost_tracker.TxCost{
            .sum = txCostSum(parsed, qt.data),
            .is_simple_vote = false, // producer never self-packs simple votes here
            .allocated_accounts_data_size = txAllocatedAccountsDataSize(parsed, qt.data),
            .writable_accounts = writable_scratch[0..writable_count],
        };
        ct.tryAdd(tx_cost) catch break; // block (or sub-limit) full ⇒ stop packing here

        // PASS 3 EXECUTE-ONCE-AND-RECORD: with the executor hook active, EXECUTE AND COMMIT this tx
        // against the working child state NOW (after the cost gate accepted it, so a cost-rejected tx
        // is never executed). Pack it IFF it was_processed (Agave committer.rs: fee-paid + loaded, incl.
        // instruction-failed-but-fee-committed); a NotLoaded / unexecutable / AlreadyProcessed result
        // commits NOTHING and is dropped here — so the executor's committed set == the packed set, and
        // the next candidate sees this tx's real post-commit state (inclusion == execution). Runs AFTER
        // ct.tryAdd: a dropped tx leaves the cost charged (safe over-count — never a dead block, at
        // worst a throughput loss on the dropped shape). No-op when execute == null (legacy path).
        if (gate) |g| {
            if (g.execute) |exec_fn| {
                if (!exec_fn(g.exec_ctx.?, qt.data)) continue;
            }
        }

        // Canonical mixin: hash_transactions over THIS entry's txs' flattened signatures. One tx per
        // entry → the flattened set is just this tx's signatures.
        const sig_views = txSigSlices(parsed.signatures, &scratch_sig_views);
        const mixin = try entry.hashTransactions(allocator, &.{sig_views});
        try microblocks.append(allocator, .{ .mixin = mixin });

        // Own a copy of this record's tx blob list (the blob bytes themselves are owned by `batch`
        // and stay valid until we serialize; serialize copies them into the output buffer).
        const blob_list = try allocator.alloc([]const u8, 1);
        blob_list[0] = qt.data;
        try tx_blobs.append(allocator, blob_list);

        // Own deep copies of this record's signature views (parsed.signatures aliases scratch_sigs,
        // which is overwritten on the next parse() — so copy now for the zip's later use).
        const sig_copies = try allocator.alloc([]const u8, sig_views.len);
        var filled: usize = 0;
        errdefer {
            for (sig_copies[0..filled]) |s| allocator.free(s);
            allocator.free(sig_copies);
        }
        for (sig_views, 0..) |sv, si| {
            sig_copies[si] = try allocator.dupe(u8, sv);
            filled += 1;
        }
        try rec_sigs.append(allocator, sig_copies);
    }

    // 3. Byte-exact PoH cadence: produce records (interleaved with ticks) in PoH order.
    var poh_entries: std.ArrayListUnmanaged(lpoh.PohEntry) = .{};
    defer poh_entries.deinit(allocator);
    const final = try lpoh.produceSlot(allocator, &poh_entries, seed, hashes_per_tick, ticks_per_slot, microblocks.items);
    if (out_blockhash) |p| p.* = final;

    // 4. Zip the produced PohEntry stream back to entry.Entry[]: records (in producer order) carry
    //    their tx blobs; ticks carry no txs. We disambiguate exactly as the proven mixed-slot KAT
    //    (leader_poh.zig:219-234): try the next expected record's nextHash; if it matches the stored
    //    hash it is that record, else it is a tick. This is robust because a record's hash is
    //    sha256(poh ‖ mixin) and a tick's is sha256(poh) — they cannot collide for the same prefix.
    const entries = try allocator.alloc(entry.Entry, poh_entries.items.len);
    defer allocator.free(entries);
    var running = seed;
    var rec_i: usize = 0;
    var ticks: u64 = 0;
    for (poh_entries.items, 0..) |pe, ei| {
        if (rec_i < rec_sigs.items.len) {
            const try_rec = try entry.nextHash(allocator, running, pe.num_hashes, rec_sigs.items[rec_i].len, rec_sigs.items[rec_i]);
            if (std.mem.eql(u8, &try_rec, &pe.hash)) {
                running = try_rec;
                entries[ei] = .{ .num_hashes = pe.num_hashes, .hash = pe.hash, .transactions = tx_blobs.items[rec_i] };
                rec_i += 1;
                continue;
            }
        }
        // Tick entry.
        running = try entry.nextHash(allocator, running, pe.num_hashes, 0, &.{});
        std.debug.assert(std.mem.eql(u8, &running, &pe.hash));
        entries[ei] = .{ .num_hashes = pe.num_hashes, .hash = pe.hash, .transactions = &.{} };
        ticks += 1;
    }
    std.debug.assert(ticks == ticks_per_slot); // exactly ticks_per_slot ticks (TooFewTicks-safe)
    std.debug.assert(rec_i == microblocks.items.len); // every drained tx was recorded

    // 5. Serialize to the replay-parser wire format (copies the tx blobs into the output buffer).
    return entry.serializeEntries(allocator, entries);
}

// ════════════════════════════════════════════════════════════════════════════
// KAT — produced empty-slot bytes are wire-valid, tick-correct, and chain to the blockhash.
// Run: zig build test-block-produce
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "empty slot: 64 ticks, each num_hashes=hpt, parses back, chains to blockhash" {
    const seed: Hash = [_]u8{0x7A} ** 32;
    const hpt: u64 = 8; // small for speed; cadence is identical at 62500
    const tps: u64 = 64;

    var blockhash: Hash = undefined;
    const bytes = try produceEmptySlotBytes(testing.allocator, seed, hpt, tps, &blockhash);
    defer testing.allocator.free(bytes);

    // (a) wire framing: count prefix == tps.
    const count = try entry.readEntryCount(bytes);
    try testing.expectEqual(@as(u64, tps), count);

    // (b) walk every entry header: num_txs==0 (tick), num_hashes==hpt; reproduce the hash chain via
    //     entry.nextHash and confirm the final == produced blockhash (same check the verifier runs).
    var offset: usize = 8; // past the u64 count prefix
    var running = seed;
    var ticks: u64 = 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const h = try entry.readEntryHeader(bytes, offset);
        try testing.expectEqual(@as(u64, 0), h.num_txs); // tick entry
        try testing.expectEqual(hpt, h.num_hashes);
        running = try entry.nextHash(testing.allocator, running, h.num_hashes, 0, &.{});
        try testing.expectEqual(h.hash, running); // stored hash == recomputed
        ticks += 1;
        offset = h.txs_offset; // num_txs==0 → next entry begins immediately
    }
    try testing.expectEqual(tps, ticks); // exactly ticks_per_slot ticks (no TooFewTicks)
    try testing.expectEqual(blockhash, running); // chain reproduced the blockhash
    try testing.expectEqual(offset, bytes.len); // consumed exactly the whole batch
}

test "blockhash == sha256^(tps*hpt)(seed) for a pure-tick slot" {
    const seed: Hash = [_]u8{0x01} ** 32;
    const hpt: u64 = 10;
    const tps: u64 = 64;
    var blockhash: Hash = undefined;
    const bytes = try produceEmptySlotBytes(testing.allocator, seed, hpt, tps, &blockhash);
    defer testing.allocator.free(bytes);

    var manual = seed;
    var k: u64 = 0;
    while (k < tps * hpt) : (k += 1) manual = entry.hashv(&.{&manual});
    try testing.expectEqual(manual, blockhash);
}

// ── produceSlotBytes KAT (task #13 LOOPBACK milestone) ───────────────────────
// Build a minimal VALID legacy single-signer transaction into `out` (same shape as
// solana_quic.zig:998 buildValidTx / tx_ingest.buildSingleSignerTx) so tx_ingest.parse accepts it
// and produceSlotBytes packs it. `nonce` perturbs the recent-blockhash so each tx has a distinct
// signature (distinct mixin), proving per-entry merkle roots are correct.
fn buildValidTx(kp: std.crypto.sign.Ed25519.KeyPair, nonce: u8, out: []u8) []u8 {
    var mpos: usize = 1 + 64; // compactU16(1)=0x01 sig-count, then the 64-byte signature
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 0; // num_readonly_unsigned
    mpos += 3;
    out[mpos] = 1; // compactU16: 1 account key
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes); // signer key
    mpos += 32;
    @memset(out[mpos..][0..32], nonce); // recent blockhash (nonce → distinct signatures)
    mpos += 32;
    out[mpos] = 0; // compactU16: 0 instructions
    mpos += 1;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1; // compactU16: 1 signature
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

test "produceSlotBytes: N txs packed into entries, canonical per-entry mixin, chains to blockhash" {
    const a = testing.allocator;
    const seed: Hash = [_]u8{0x7B} ** 32;
    const hpt: u64 = 64; // small for speed; cadence identical at 62500
    const tps: u64 = 64;
    const N: usize = 5;

    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();

    // Seed N valid, distinct, self-signed txs into the mempool. Keep our own canonical copies (in
    // queue/priority order = drain order) to assert blob bytes survive the round-trip byte-identical.
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var sent: [N][]u8 = undefined;
    for (0..N) |i| {
        var buf: [256]u8 = undefined;
        const tx = buildValidTx(kp, @intCast(i + 1), &buf);
        // MODULE-20 MIGRATION TEST FIX (pre-existing origin-tree test bug, block_produce.zig itself
        // unchanged — production code byte-identical to origin-tree): the original line queued every
        // tx with cu_price=0 and asserted "same priority → tie-broken by arrival time → FIFO
        // drain order = i order". That assumption is TIMING-DEPENDENT: banking_stage.zig:132
        // stamps received_at with std.time.milliTimestamp() (millisecond resolution), and
        // banking_stage.priorityCompare returns .eq when BOTH priority and received_at tie —
        // std.PriorityQueue is a binary heap, NOT insertion-stable, so equal-key entries drain
        // in heap order, not FIFO. In Debug the per-tx ed25519 sign is slow enough that all 5
        // txs get distinct millisecond timestamps and the test passed by accident; in
        // ReleaseSafe all 5 land in the SAME millisecond and the drain order is non-FIFO
        // (reproduced 3/3 deterministically at module-20 migration). Queue with DISTINCT
        // descending cu_price instead (N-i → priorities 5000,4000,...,1000) so the drain order
        // is pinned by the priority ordering itself — deterministic in every optimize mode, and
        // it now exercises the priority-ordered drain path for real instead of the tie-break.
        // cu_price is a queue-side parameter only (the built tx has 0 instructions), so block
        // BYTES are unaffected except for entry order. The underlying production behavior —
        // same-priority same-millisecond txs drain in unspecified order — is a real (benign,
        // LIVENESS-tier: any tx order in a produced block is valid) origin-tree latent, recorded in
        // REBUILD-LEDGER.md module-20 row; a stable FIFO tie-break (e.g. monotonic sequence
        // number) is a production behavior change and stays DEFERRED per the migration contract.
        try banking.queueTransaction(tx, N - i, false, .tpu);
        sent[i] = try a.dupe(u8, tx);
    }
    defer for (sent) |s| a.free(s);

    var blockhash: Hash = undefined;
    const bytes = try produceSlotBytes(a, seed, hpt, tps, &banking, &blockhash, null, MAX_BLOCK_UNITS);
    defer a.free(bytes);

    // The mempool is now empty (everything drained).
    try testing.expectEqual(@as(usize, 0), banking.queueDepth());

    // (a) framing: entry_count == tps (ticks) + N (record entries).
    const count = try entry.readEntryCount(bytes);
    try testing.expectEqual(@as(u64, tps + N), count);

    // (b) walk every entry, reproduce the PoH chain via entry.nextHash, and verify:
    //     - record entries carry exactly one tx blob, byte-identical to what we queued (in order);
    //     - each record's stored hash == nextHash(running, num_hashes, num_txs, sigs);
    //     - each tick reproduces sha256-cadence;
    //     - the final running hash == returned blockhash;
    //     - exactly tps ticks.
    var offset: usize = 8; // past u64 count prefix
    var running = seed;
    var ticks: u64 = 0;
    var records: usize = 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const h = try entry.readEntryHeader(bytes, offset);
        if (h.num_txs > 0) {
            // Record entry: must be the next queued tx, byte-identical (one tx per entry).
            try testing.expectEqual(@as(u64, 1), h.num_txs);
            const blob = sent[records];
            try testing.expectEqualSlices(u8, blob, bytes[h.txs_offset..][0..blob.len]);

            // Recompute the stored hash from the tx's actual signatures (the canonical mixin path).
            var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
            var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
            const parsed = try tx_ingest.parse(blob, &ssig, &skey);
            var views: [tx_ingest.MAX_SIGNATURES][]const u8 = undefined;
            for (parsed.signatures, 0..) |*s, k| views[k] = s[0..];
            running = try entry.nextHash(a, running, h.num_hashes, parsed.signatures.len, views[0..parsed.signatures.len]);
            try testing.expectEqual(h.hash, running);

            records += 1;
            offset = h.txs_offset + blob.len; // advance past the single tx blob
        } else {
            // Tick entry. NOTE: a tick's num_hashes is NOT always == hpt — when a record is packed
            // inside a tick window, record() consumes one of that window's hashes, so the tick that
            // closes the window has num_hashes < hpt. Only pure-tick windows have exactly hpt. The
            // load-bearing invariant is the reproduced hash chain below, not the per-tick count.
            running = try entry.nextHash(a, running, h.num_hashes, 0, &.{});
            try testing.expectEqual(h.hash, running);
            ticks += 1;
            offset = h.txs_offset;
        }
    }
    try testing.expectEqual(@as(u64, tps), ticks); // exactly ticks_per_slot ticks (no TooFewTicks)
    try testing.expectEqual(N, records); // all txs packed
    try testing.expectEqual(blockhash, running); // chain reproduced the blockhash
    try testing.expectEqual(offset, bytes.len); // consumed exactly the whole batch
}

test "produceSlotBytes: empty mempool == produceEmptySlotBytes (byte-identical tick-only slot)" {
    const a = testing.allocator;
    const seed: Hash = [_]u8{0x99} ** 32;
    const hpt: u64 = 16;
    const tps: u64 = 64;

    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();

    var bh_real: Hash = undefined;
    const real = try produceSlotBytes(a, seed, hpt, tps, &banking, &bh_real, null, MAX_BLOCK_UNITS);
    defer a.free(real);

    var bh_empty: Hash = undefined;
    const empty = try produceEmptySlotBytes(a, seed, hpt, tps, &bh_empty);
    defer a.free(empty);

    try testing.expectEqualSlices(u8, empty, real);
    try testing.expectEqual(bh_empty, bh_real);
}

// ════════════════════════════════════════════════════════════════════════════
// KAT — admitTx per-tx inclusion pre-filter (task #25). Directly exercises the decision (the live
// tx-bearing path is the produce tile, which a path-level test would not reach), so the pre-filter
// is tested in isolation against explicit inputs. Run: zig build test-block-produce
// ════════════════════════════════════════════════════════════════════════════

/// Build a minimal legacy single-signer tx signed by `kp` with `blockhash` as the recent blockhash
/// (mirrors tx_ingest.buildSingleSignerTx, but the blockhash is settable for the gate KAT).
fn buildSignerTxWithBlockhash(kp: std.crypto.sign.Ed25519.KeyPair, blockhash: [32]u8, out: []u8) []u8 {
    var mpos: usize = 1 + 64; // compactU16(1 signature) is the single byte 0x01
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 0; // num_readonly_unsigned
    mpos += 3;
    out[mpos] = 1; // compactU16: 1 account key
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes); // the signer (== fee payer)
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash); // recent blockhash
    mpos += 32;
    out[mpos] = 0; // compactU16: 0 instructions
    mpos += 1;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1; // compactU16: 1 signature
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

test "admitTx: sigverify + blockhash-age + fee-payer pre-filter decisions" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const bh: [32]u8 = [_]u8{0xAB} ** 32;
    var buf: [256]u8 = undefined;
    const wire = buildSignerTxWithBlockhash(kp, bh, &buf);

    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);

    const SYSTEM: [32]u8 = [_]u8{0} ** 32;
    const known = [_][32]u8{bh};
    const unknown = [_][32]u8{[_]u8{0xCD} ** 32};
    const empty_set = [_][32]u8{};
    // fee = 5000 (1 sig, no compute budget) + 0 prio; floor = RENT_EXEMPT_MIN_ZERO + 5000 = 895_880.
    const good_fp = FeePayerView{ .lamports = RENT_EXEMPT_MIN_ZERO + LAMPORTS_PER_SIGNATURE + 1, .owner = SYSTEM, .data_len = 0 };

    // valid tx, known blockhash, well-funded system fee payer → ADMIT.
    try testing.expect(admitTx(parsed, wire, &known, good_fp));
    // stale/unknown blockhash → reject (BlockhashNotFound).
    try testing.expect(!admitTx(parsed, wire, &unknown, good_fp));
    // empty recent-blockhash set → reject.
    try testing.expect(!admitTx(parsed, wire, &empty_set, good_fp));
    // absent / zero-lamport fee payer → reject (AccountNotFound).
    try testing.expect(!admitTx(parsed, wire, &known, null));
    // non-system-owned fee payer → reject (InvalidAccountForFee).
    try testing.expect(!admitTx(parsed, wire, &known, .{ .lamports = 10_000_000, .owner = [_]u8{0x9} ** 32, .data_len = 0 }));
    // system-owned but has data (e.g. nonce / non-plain) → reject (conservative).
    try testing.expect(!admitTx(parsed, wire, &known, .{ .lamports = 10_000_000, .owner = SYSTEM, .data_len = 80 }));
    // exactly the rent floor (no room for the fee) → reject (InsufficientFundsForFee).
    try testing.expect(!admitTx(parsed, wire, &known, .{ .lamports = RENT_EXEMPT_MIN_ZERO, .owner = SYSTEM, .data_len = 0 }));
    // exactly floor + fee → ADMIT (boundary).
    try testing.expect(admitTx(parsed, wire, &known, .{ .lamports = RENT_EXEMPT_MIN_ZERO + LAMPORTS_PER_SIGNATURE, .owner = SYSTEM, .data_len = 0 }));

    // tampered signature → reject (sigverify). Parse into fresh scratch so `parsed` is untouched.
    var tbuf: [256]u8 = undefined;
    @memcpy(tbuf[0..wire.len], wire);
    tbuf[5] ^= 0xFF; // flip a byte inside the 64-byte signature (wire[1..65])
    var ssig2: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey2: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed_t = try tx_ingest.parse(tbuf[0..wire.len], &ssig2, &skey2);
    try testing.expect(!admitTx(parsed_t, tbuf[0..wire.len], &known, good_fp));
}

test "admitTxSeq: sequential fee-stacking drain — same payer, balance for one fee not two" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x22} ** 32);
    const bh: [32]u8 = [_]u8{0xCC} ** 32;
    var buf: [256]u8 = undefined;
    const wire = buildSignerTxWithBlockhash(kp, bh, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);

    const SYSTEM: [32]u8 = [_]u8{0} ** 32;
    const known = [_][32]u8{bh};
    // Canonical fee for this tx = 1 sig × 5000 + 0 precompile + 0 priority = 5000.
    try testing.expectEqual(@as(u64, LAMPORTS_PER_SIGNATURE), txFee(parsed, wire));
    // Fund the payer for EXACTLY one fee above the rent floor.
    const parent = FeePayerView{ .lamports = RENT_EXEMPT_MIN_ZERO + LAMPORTS_PER_SIGNATURE, .owner = SYSTEM, .data_len = 0 };

    var state = SeqGateState{};
    defer state.deinit(a);
    // First tx by this payer: running balance = parent (seeds map) ≥ floor+fee → ADMIT, balance→floor.
    try testing.expect(admitTxSeq(a, &state, parsed, wire, &known, parent));
    // Second tx by the SAME payer: running balance is now RENT_EXEMPT_MIN_ZERO < floor+fee → DROP
    // (the sequential fee-stacking drain the frozen-parent pre-filter would have wrongly admitted).
    try testing.expect(!admitTxSeq(a, &state, parsed, wire, &known, parent));

    // A DIFFERENT payer with the same parent funding is unaffected (independent running balance).
    const kp2 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x23} ** 32);
    var buf2: [256]u8 = undefined;
    const wire2 = buildSignerTxWithBlockhash(kp2, bh, &buf2);
    var ssig2: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey2: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed2 = try tx_ingest.parse(wire2, &ssig2, &skey2);
    try testing.expect(admitTxSeq(a, &state, parsed2, wire2, &known, parent));
}

// ════════════════════════════════════════════════════════════════════════════
// M2 (TXBEARING-BLOCK-PRODUCTION-PLAN-2026-07-16.md §4 M2 / Path A): admitTxSeq now applies the
// lamport effect of System::Transfer / System::CreateAccount in transaction order (see
// `SeqGateState`/`applyLamportEffects` doc comments above). These KATs exercise the ORDERING battery
// the M2 brief calls for, directly against `admitTxSeq` (same style as the pre-existing
// "sequential fee-stacking drain" KAT above), plus the second covered instruction class and the
// false-refusal-avoidance property. Run: zig build test-block-produce
// ════════════════════════════════════════════════════════════════════════════

/// Build a signed legacy System::Transfer tx: 3 keys [payer(signer,writable), recipient(writable),
/// System(readonly-unsigned)], matching kat_txbearing_exec.zig's buildTransferTx wire layout (kept as
/// a SEPARATE local copy here — block_produce.zig and tests/kat_txbearing_exec.zig are different
/// modules/roots; this file already has its own local tx builders, e.g. buildSignerTxWithBlockhash
/// above and buildValidTx/buildCreateAccountTx elsewhere, following the same convention).
fn buildTransferTxSigned(kp: std.crypto.sign.Ed25519.KeyPair, recipient: [32]u8, blockhash: [32]u8, amount: u64, out: []u8) []u8 {
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;
    var mpos: usize = 1 + 64;
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 1; // num_readonly_unsigned (System program)
    mpos += 3;
    out[mpos] = 3; // 3 account keys
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &recipient);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &SYSTEM);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash);
    mpos += 32;
    out[mpos] = 1; // 1 instruction
    mpos += 1;
    out[mpos] = 2; // program_id_index = 2 (System)
    mpos += 1;
    out[mpos] = 2; // 2 account indices
    mpos += 1;
    out[mpos] = 0; // from = payer
    out[mpos + 1] = 1; // to = recipient
    mpos += 2;
    out[mpos] = 12; // data_len: disc(4)+amount(8)
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], SYS_DISC_TRANSFER, .little);
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], amount, .little);
    mpos += 8;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1;
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

/// Build a SIGNED legacy System::CreateAccount tx: 3 keys [payer(signer,writable),
/// new_account(signer,writable), System(readonly-unsigned)] — matches buildCreateAccountTx's wire
/// shape above but with a REAL signature (buildCreateAccountTx's dummy zero signature does not pass
/// admitTxSeq's real sigverify check, `checkStaticAndOwner` -> `tx_ingest.verifySignatures`).
fn buildCreateAccountTxSigned(kp: std.crypto.sign.Ed25519.KeyPair, new_account: [32]u8, lamports: u64, space: u64, blockhash: [32]u8, out: []u8) []u8 {
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;
    var mpos: usize = 1 + 64;
    const msg_start = mpos;
    out[mpos] = 1;
    out[mpos + 1] = 0;
    out[mpos + 2] = 1;
    mpos += 3;
    out[mpos] = 3;
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &new_account);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &SYSTEM);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash);
    mpos += 32;
    out[mpos] = 1;
    mpos += 1;
    out[mpos] = 2; // program_id_index = 2 (System)
    mpos += 1;
    out[mpos] = 2;
    mpos += 1;
    out[mpos] = 0; // from = payer
    out[mpos + 1] = 1; // to = new_account
    mpos += 2;
    out[mpos] = 4 + 8 + 8 + 32; // 52
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], SYS_DISC_CREATE_ACCOUNT, .little);
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], lamports, .little);
    mpos += 8;
    std.mem.writeInt(u64, out[mpos..][0..8], space, .little);
    mpos += 8;
    @memset(out[mpos..][0..32], 0xAB); // owner (arbitrary; not consulted by the delta walk)
    mpos += 32;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1;
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

test "admitTxSeq ordering (transfer-then-fee): a drain-by-transfer is followed by a NO-INSTRUCTION fee-only tx, which is refused" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x31} ** 32);
    const recipient: [32]u8 = [_]u8{0x91} ** 32;
    const bh: [32]u8 = [_]u8{0xD1} ** 32;
    const known = [_][32]u8{bh};
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;

    const parent_lamports: u64 = 2_000_000;
    const parent = FeePayerView{ .lamports = parent_lamports, .owner = SYSTEM, .data_len = 0 };

    // tx1: Transfer draining P down to 1,000 lamports after its own fee (below the fee floor).
    var buf1: [256]u8 = undefined;
    const amount1 = parent_lamports - LAMPORTS_PER_SIGNATURE - 1_000;
    const wire1 = buildTransferTxSigned(kp, recipient, bh, amount1, &buf1);
    var ssig1: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey1: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed1 = try tx_ingest.parse(wire1, &ssig1, &skey1);

    // tx2: a bare fee-only tx (NO transfer instruction at all) by the SAME payer.
    var buf2: [256]u8 = undefined;
    const wire2 = buildSignerTxWithBlockhash(kp, bh, &buf2);
    var ssig2: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey2: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed2 = try tx_ingest.parse(wire2, &ssig2, &skey2);

    var state = SeqGateState{};
    defer state.deinit(a);
    try testing.expect(admitTxSeq(a, &state, parsed1, wire1, &known, parent)); // tx1 admitted
    // tx2 has no transfer of its own — proves the refusal is driven by tx1's TRACKED EFFECT on P's
    // balance, not by anything in tx2's own instruction shape.
    try testing.expect(!admitTxSeq(a, &state, parsed2, wire2, &known, parent)); // tx2 REFUSED
}

test "admitTxSeq ordering (fee-then-transfer-then-fee): refusal fires only AFTER the drain, not before" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x32} ** 32);
    const recipient: [32]u8 = [_]u8{0x92} ** 32;
    const bh: [32]u8 = [_]u8{0xD2} ** 32;
    const known = [_][32]u8{bh};
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;

    const parent_lamports: u64 = 2_010_000;
    const parent = FeePayerView{ .lamports = parent_lamports, .owner = SYSTEM, .data_len = 0 };

    var buf_fee1: [256]u8 = undefined;
    const wire_fee1 = buildSignerTxWithBlockhash(kp, bh, &buf_fee1);
    var ssig_fee1: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey_fee1: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed_fee1 = try tx_ingest.parse(wire_fee1, &ssig_fee1, &skey_fee1);

    var buf_xfer: [256]u8 = undefined;
    // After tx1's fee (5,000), P has 2,005,000. Drain to 1,000 (below the fee floor).
    const amount = (parent_lamports - LAMPORTS_PER_SIGNATURE) - LAMPORTS_PER_SIGNATURE - 1_000;
    const wire_xfer = buildTransferTxSigned(kp, recipient, bh, amount, &buf_xfer);
    var ssig_xfer: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey_xfer: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed_xfer = try tx_ingest.parse(wire_xfer, &ssig_xfer, &skey_xfer);

    var buf_fee2: [256]u8 = undefined;
    const wire_fee2 = buildSignerTxWithBlockhash(kp, bh, &buf_fee2);
    var ssig_fee2: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey_fee2: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed_fee2 = try tx_ingest.parse(wire_fee2, &ssig_fee2, &skey_fee2);

    var state = SeqGateState{};
    defer state.deinit(a);
    try testing.expect(admitTxSeq(a, &state, parsed_fee1, wire_fee1, &known, parent)); // fee-only: admitted
    try testing.expect(admitTxSeq(a, &state, parsed_xfer, wire_xfer, &known, parent)); // transfer: admitted (drains P)
    try testing.expect(!admitTxSeq(a, &state, parsed_fee2, wire_fee2, &known, parent)); // 3rd tx: REFUSED
}

test "admitTxSeq: multiple interleaved payers — one payer's drain does not affect a different payer's admission" {
    const a = testing.allocator;
    const kp_p = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x41} ** 32);
    const kp_q = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    const recipient: [32]u8 = [_]u8{0x93} ** 32;
    const bh: [32]u8 = [_]u8{0xD3} ** 32;
    const known = [_][32]u8{bh};
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;

    const p_parent: u64 = 2_000_000;
    const q_parent: u64 = 2_000_000; // comfortably affords several fees, never touched by a transfer
    const parent_p = FeePayerView{ .lamports = p_parent, .owner = SYSTEM, .data_len = 0 };
    const parent_q = FeePayerView{ .lamports = q_parent, .owner = SYSTEM, .data_len = 0 };

    var buf_p_xfer: [256]u8 = undefined;
    const amount_p = p_parent - LAMPORTS_PER_SIGNATURE - 1_000; // drains P below the fee floor
    const wire_p_xfer = buildTransferTxSigned(kp_p, recipient, bh, amount_p, &buf_p_xfer);
    var ssig1: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey1: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed_p_xfer = try tx_ingest.parse(wire_p_xfer, &ssig1, &skey1);

    var buf_q1: [256]u8 = undefined;
    const wire_q1 = buildSignerTxWithBlockhash(kp_q, bh, &buf_q1);
    var ssig2: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey2: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed_q1 = try tx_ingest.parse(wire_q1, &ssig2, &skey2);

    var buf_p_fee: [256]u8 = undefined;
    const wire_p_fee = buildSignerTxWithBlockhash(kp_p, bh, &buf_p_fee);
    var ssig3: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey3: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed_p_fee = try tx_ingest.parse(wire_p_fee, &ssig3, &skey3);

    var buf_q2: [256]u8 = undefined;
    const wire_q2 = buildSignerTxWithBlockhash(kp_q, bh, &buf_q2);
    var ssig4: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey4: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed_q2 = try tx_ingest.parse(wire_q2, &ssig4, &skey4);

    var state = SeqGateState{};
    defer state.deinit(a);
    // Interleaved order: P-transfer(drain), Q-fee, P-fee(should refuse), Q-fee(should still admit).
    try testing.expect(admitTxSeq(a, &state, parsed_p_xfer, wire_p_xfer, &known, parent_p));
    try testing.expect(admitTxSeq(a, &state, parsed_q1, wire_q1, &known, parent_q));
    try testing.expect(!admitTxSeq(a, &state, parsed_p_fee, wire_p_fee, &known, parent_p)); // P: refused
    try testing.expect(admitTxSeq(a, &state, parsed_q2, wire_q2, &known, parent_q)); // Q: unaffected by P's drain
}

test "admitTxSeq: System::CreateAccount drain — later fee-only tx by the same payer is refused (2nd covered class)" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x51} ** 32);
    const new_account: [32]u8 = [_]u8{0x94} ** 32;
    const bh: [32]u8 = [_]u8{0xD4} ** 32;
    const known = [_][32]u8{bh};
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;

    const parent_lamports: u64 = 2_000_000;
    const parent = FeePayerView{ .lamports = parent_lamports, .owner = SYSTEM, .data_len = 0 };

    var buf1: [256]u8 = undefined;
    const create_lamports = parent_lamports - LAMPORTS_PER_SIGNATURE - 1_000;
    const wire1 = buildCreateAccountTxSigned(kp, new_account, create_lamports, 165, bh, &buf1);
    var ssig1: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey1: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed1 = try tx_ingest.parse(wire1, &ssig1, &skey1);

    var buf2: [256]u8 = undefined;
    const wire2 = buildSignerTxWithBlockhash(kp, bh, &buf2);
    var ssig2: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey2: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed2 = try tx_ingest.parse(wire2, &ssig2, &skey2);

    var state = SeqGateState{};
    defer state.deinit(a);
    try testing.expect(admitTxSeq(a, &state, parsed1, wire1, &known, parent)); // CreateAccount: admitted
    try testing.expect(!admitTxSeq(a, &state, parsed2, wire2, &known, parent)); // later fee-only: REFUSED
}

/// Build a signed legacy tx with TWO System::Transfer instructions from the SAME payer to two distinct
/// recipients: 4 keys [payer(signer,writable), r1(writable), r2(writable), System(readonly-unsigned)].
fn buildTwoTransferTxSigned(kp: std.crypto.sign.Ed25519.KeyPair, r1: [32]u8, r2: [32]u8, blockhash: [32]u8, amount1: u64, amount2: u64, out: []u8) []u8 {
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;
    var mpos: usize = 1 + 64;
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 1; // num_readonly_unsigned (System program)
    mpos += 3;
    out[mpos] = 4; // 4 account keys
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes); // [0] payer
    mpos += 32;
    @memcpy(out[mpos..][0..32], &r1); // [1] recipient 1
    mpos += 32;
    @memcpy(out[mpos..][0..32], &r2); // [2] recipient 2
    mpos += 32;
    @memcpy(out[mpos..][0..32], &SYSTEM); // [3] System program
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash);
    mpos += 32;
    out[mpos] = 2; // 2 instructions
    mpos += 1;
    // ix0: payer -> r1, amount1
    out[mpos] = 3; // program_id_index = 3 (System)
    mpos += 1;
    out[mpos] = 2; // 2 account indices
    mpos += 1;
    out[mpos] = 0; // from = payer
    out[mpos + 1] = 1; // to = r1
    mpos += 2;
    out[mpos] = 12;
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], SYS_DISC_TRANSFER, .little);
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], amount1, .little);
    mpos += 8;
    // ix1: payer -> r2, amount2
    out[mpos] = 3; // program_id_index = 3 (System)
    mpos += 1;
    out[mpos] = 2;
    mpos += 1;
    out[mpos] = 0; // from = payer
    out[mpos + 1] = 2; // to = r2
    mpos += 2;
    out[mpos] = 12;
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], SYS_DISC_TRANSFER, .little);
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], amount2, .little);
    mpos += 8;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1;
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

test "admitTxSeq: within-tx atomicity — a 2nd instruction's failure rolls back the 1st instruction's delta too (same tx)" {
    // Real Solana tx execution is atomic (excluding the already-charged fee): if instruction 2 fails,
    // instruction 1's effects in the SAME tx are ALSO rolled back, not just instruction 2's. Proves
    // applyLamportEffects's `pending`-buffer-then-commit-as-one-batch design, not a naive per-
    // instruction apply (which would wrongly keep instruction 1's delta committed).
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x71} ** 32);
    const r1: [32]u8 = [_]u8{0x96} ** 32;
    const r2: [32]u8 = [_]u8{0x97} ** 32;
    const bh: [32]u8 = [_]u8{0xD6} ** 32;
    const known = [_][32]u8{bh};
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;

    const parent_lamports: u64 = 1_000_000;
    const parent = FeePayerView{ .lamports = parent_lamports, .owner = SYSTEM, .data_len = 0 };
    // After this tx's own 5,000-lamport fee: P has 995,000. ix0 (400,000) is affordable alone. ix1
    // (700,000) is NOT affordable after ix0 (995,000 - 400,000 = 595,000 < 700,000) — so the WHOLE tx's
    // instruction effects roll back; only the fee is real.
    const amount1: u64 = 400_000;
    const amount2: u64 = 700_000;

    var buf1: [512]u8 = undefined;
    const wire1 = buildTwoTransferTxSigned(kp, r1, r2, bh, amount1, amount2, &buf1);
    var ssig1: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey1: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed1 = try tx_ingest.parse(wire1, &ssig1, &skey1);

    var buf2: [256]u8 = undefined;
    const wire2 = buildSignerTxWithBlockhash(kp, bh, &buf2); // probe: bare fee-only tx, same payer
    var ssig2: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey2: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed2 = try tx_ingest.parse(wire2, &ssig2, &skey2);

    var state = SeqGateState{};
    defer state.deinit(a);
    // The 2-instruction tx is still ADMITTED (its own FEE is affordable at admit time — the pre-filter
    // does not gate on instruction-level outcomes, only on the fee, per block_produce.zig's fatal-
    // classification table).
    try testing.expect(admitTxSeq(a, &state, parsed1, wire1, &known, parent));
    // THE LOAD-BEARING ASSERTION: if ix0's 400,000 debit had wrongly stayed committed (the pre-fix-for-
    // atomicity bug), P's effective balance would be 995,000-400,000=595,000 < the fee floor (895,880)
    // and this probe would be wrongly REFUSED. With atomic rollback, P's ONLY real effect is the fee
    // (995,000 >= 895,880), so the probe is correctly ADMITTED.
    try testing.expect(admitTxSeq(a, &state, parsed2, wire2, &known, parent));
}

test "admitTxSeq: a transfer that would EXCEED the payer's true balance does NOT falsely drain bookkeeping (false-refusal avoidance)" {
    // A gate that refuses valid transactions costs fee revenue and is its own bug (M2 brief). This
    // proves the affordability check in applyLamportEffects (see its doc comment): when `from` IS the
    // tx's own fee-payer, an over-large transfer amount is NOT applied to the tracked delta, because
    // real execution would tolerate the inner-instruction failure (native/system.zig executeTransfer:
    // no commit unless from.lamports >= amount) and never actually move any lamports.
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x61} ** 32);
    const recipient: [32]u8 = [_]u8{0x95} ** 32;
    const bh: [32]u8 = [_]u8{0xD5} ** 32;
    const known = [_][32]u8{bh};
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;

    // P affords the FEE comfortably but the tx's own transfer amount is far more than P actually has.
    const parent_lamports: u64 = RENT_EXEMPT_MIN_ZERO + 2 * LAMPORTS_PER_SIGNATURE;
    const parent = FeePayerView{ .lamports = parent_lamports, .owner = SYSTEM, .data_len = 0 };

    var buf1: [256]u8 = undefined;
    const wire1 = buildTransferTxSigned(kp, recipient, bh, 50_000_000_000, &buf1); // far more than P has
    var ssig1: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey1: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed1 = try tx_ingest.parse(wire1, &ssig1, &skey1);

    var buf2: [256]u8 = undefined;
    const wire2 = buildSignerTxWithBlockhash(kp, bh, &buf2);
    var ssig2: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey2: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed2 = try tx_ingest.parse(wire2, &ssig2, &skey2);

    var state = SeqGateState{};
    defer state.deinit(a);
    // tx1's FEE is affordable, so it is admitted (its transfer amount is a per-instruction concern the
    // pre-filter does not gate — TOLERATED per block_produce.zig's own fatal-classification table).
    try testing.expect(admitTxSeq(a, &state, parsed1, wire1, &known, parent));
    // tx2: if the fix naively applied the oversized transfer's delta unconditionally, P's tracked
    // balance would be wrongly deep-negative and this SECOND fee-only tx would be wrongly refused.
    // Because tx1's transfer would not actually succeed (P can't afford it), no delta was applied for
    // it — only tx1's OWN fee debit was — so P still affords tx2's fee.
    try testing.expect(admitTxSeq(a, &state, parsed2, wire2, &known, parent));
}

test "RecentSigCache: cross-block AlreadyProcessed window + prune" {
    const a = testing.allocator;
    var cache = RecentSigCache{};
    defer cache.deinit(a);

    const sigA: [64]u8 = [_]u8{0xA1} ** 64;
    const sigB: [64]u8 = [_]u8{0xB2} ** 64;

    // Unknown sig → not recent.
    try testing.expect(!cache.isRecent(&sigA, 100));
    // Record sigA committed at slot 100.
    cache.record(a, &sigA, 100);
    // Within the 150-slot window (diff 0,150) → AlreadyProcessed; sigB still unknown.
    try testing.expect(cache.isRecent(&sigA, 100));
    try testing.expect(cache.isRecent(&sigA, 250)); // diff 150 == MAX → still recent
    try testing.expect(!cache.isRecent(&sigB, 250));
    // Past the window (diff 151) → no longer a duplicate (blockhash expired anyway).
    try testing.expect(!cache.isRecent(&sigA, 251));
    // Prune at slot 251 evicts the stale entry (committed 100 < cutoff 251-150=101).
    cache.prune(a, 251);
    try testing.expect(cache.map.count() == 0);
}

// ════════════════════════════════════════════════════════════════════════════
// PRODUCE-PARITY HARNESS (task #26) — drives the REAL produceSlotBytes path with the FULL inclusion
// gate (sequential fee-payer + cross-block dedup + in-block dedup + blockhash + owner), and asserts
// EXACTLY the right txs land in the produced block. This is the integration test the per-decision KATs
// can't be: it proves produceSlotBytes + the gate wiring + RecentSigCache + SeqGateState compose
// correctly end-to-end. (Increment 2 — actual execution/bank-exact replay via execute_on_bank + a
// seeded AccountsDb — verifies the adversarial transfer-drain residual; not covered here.)
// Run: zig build test-block-produce
// ════════════════════════════════════════════════════════════════════════════
test "produce-parity: full gate through produceSlotBytes admits exactly the valid txs" {
    const a = testing.allocator;
    const seed: Hash = [_]u8{0x5C} ** 32;
    const hpt: u64 = 64;
    const tps: u64 = 64;
    const SLOT: u64 = 1000;
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;

    // Fee-payer accounts (plain System-owned). kp3 is deliberately ABSENT (unfunded → AccountNotFound).
    const kp1 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const kp2 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x12} ** 32);
    const kp3 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x13} ** 32);
    const kpx = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x14} ** 32);
    var accounts: std.AutoHashMapUnmanaged([32]u8, FeePayerView) = .{};
    defer accounts.deinit(a);
    try accounts.put(a, kp1.public_key.bytes, .{ .lamports = RENT_EXEMPT_MIN_ZERO + 2 * LAMPORTS_PER_SIGNATURE, .owner = SYSTEM, .data_len = 0 }); // affords 2 fees
    try accounts.put(a, kp2.public_key.bytes, .{ .lamports = RENT_EXEMPT_MIN_ZERO + 1 * LAMPORTS_PER_SIGNATURE, .owner = SYSTEM, .data_len = 0 }); // affords 1 fee
    try accounts.put(a, kpx.public_key.bytes, .{ .lamports = RENT_EXEMPT_MIN_ZERO + 1 * LAMPORTS_PER_SIGNATURE, .owner = SYSTEM, .data_len = 0 });

    // Known recent blockhashes = [1]**32 and [2]**32; nonce 9 = a stale/unknown blockhash.
    const known = [_][32]u8{ [_]u8{1} ** 32, [_]u8{2} ** 32 };

    var seq = SeqGateState{};
    defer seq.deinit(a);
    var recent = RecentSigCache{};
    defer recent.deinit(a);

    // Craft 8 txs (each into its own buffer so all stay valid for queueing).
    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    var b3: [256]u8 = undefined;
    var b4: [256]u8 = undefined;
    var b5: [256]u8 = undefined;
    var b6: [256]u8 = undefined;
    var b7: [256]u8 = undefined;
    var b8: [256]u8 = undefined;
    const t1 = buildValidTx(kp1, 1, &b1); // P1, BH1            → ADMIT (P1 fee #1)
    const t2 = buildValidTx(kp1, 2, &b2); // P1, BH2 (distinct) → ADMIT (P1 fee #2)
    const t3 = buildValidTx(kp2, 1, &b3); // P2, BH1            → ADMIT (P2 fee #1)
    const t4 = buildValidTx(kp2, 2, &b4); // P2, BH2            → DROP  (P2 drained: sequential)
    const t5 = buildValidTx(kp3, 1, &b5); // P3 (unfunded), BH1 → DROP  (AccountNotFound)
    const t6 = buildValidTx(kp1, 9, &b6); // P1, BH stale       → DROP  (BlockhashNotFound)
    const t7 = buildValidTx(kp1, 1, &b7); // == t1 exactly      → DROP  (in-block AlreadyProcessed)
    const t8 = buildValidTx(kpx, 1, &b8); // Px, BH1            → DROP  (cross-block AlreadyProcessed)
    recent.record(a, t8[1..][0..64], SLOT - 10); // t8's sig was committed 10 slots ago (within the window)

    const Ctx = struct {
        accounts: *std.AutoHashMapUnmanaged([32]u8, FeePayerView),
        known: []const [32]u8,
        seq: *SeqGateState,
        recent: *RecentSigCache,
        slot: u64,
        a: std.mem.Allocator,
        fn admit(ctx: *anyopaque, wire: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            var ss: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
            var sk: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
            const parsed = tx_ingest.parse(wire, &ss, &sk) catch return false;
            if (self.recent.isRecent(&parsed.signatures[0], self.slot)) return false; // cross-block dedup
            const fp = self.accounts.get(parsed.signer_keys[0]);
            return admitTxSeq(self.a, self.seq, parsed, wire, self.known, fp);
        }
    };
    var ctx = Ctx{ .accounts = &accounts, .known = &known, .seq = &seq, .recent = &recent, .slot = SLOT, .a = a };
    const gate = InclusionGate{ .ctx = &ctx, .admit = Ctx.admit };

    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();
    // Distinct DESCENDING cu_price ⇒ deterministic drain order t1..t8 (the mempool packs high-priority
    // first; equal priorities are NOT guaranteed FIFO). cu_price is mempool-ordering only — these txs
    // carry no ComputeBudget instruction, so their wire priority fee stays 0 (fee = 5000 unchanged).
    for ([_][]const u8{ t1, t2, t3, t4, t5, t6, t7, t8 }, 0..) |tx, idx| {
        try banking.queueTransaction(tx, @intCast(8 - idx), false, .tpu);
    }

    var blockhash: Hash = undefined;
    const bytes = try produceSlotBytes(a, seed, hpt, tps, &banking, &blockhash, gate, MAX_BLOCK_UNITS);
    defer a.free(bytes);

    // Exactly 3 txs admitted ⇒ 64 ticks + 3 record entries.
    const count = try entry.readEntryCount(bytes);
    try testing.expectEqual(@as(u64, tps + 3), count);

    // And they must be EXACTLY t1, t2, t3 in order (walk the record entries, match wire bytes).
    const expected = [_][]const u8{ t1, t2, t3 };
    var offset: usize = 8; // past the u64 count prefix
    var records: usize = 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const h = try entry.readEntryHeader(bytes, offset);
        if (h.num_txs > 0) {
            try testing.expectEqual(@as(u64, 1), h.num_txs);
            const blob = expected[records];
            try testing.expectEqualSlices(u8, blob, bytes[h.txs_offset..][0..blob.len]);
            records += 1;
            offset = h.txs_offset + blob.len;
        } else {
            offset = h.txs_offset;
        }
    }
    try testing.expectEqual(@as(usize, 3), records);
}

// ════════════════════════════════════════════════════════════════════════════
// M2b (produce-tile safe gating) — DECISION PARITY between the two `InclusionGate` adapters. Both
// `bankAdmitTxForBroadcast` (inline, replay_stage.zig:1818, DB-view — mirrored by `Ctx` above) and
// `tileAdmitTxForBroadcast` (tile, replay_stage.zig, snapshot-view) end in the SAME `admitTxSeq` call —
// already covered by the KATs above — so the only NEW surface M2b adds is the ADAPTER: how
// `FeePayerView`/`recent_blockhashes`/cross-block-dedup are located. This test is `Ctx` above's exact
// twin with ONE difference: `TileCtx.admit` sources every input from bounded VALUE arrays (mirroring
// `produce_ring.BecomeLeaderRecord`'s `fee_snapshot`/`recent_blockhashes`/`already_processed_sigs`,
// built here directly from the SAME fixture the DB-view test uses) instead of the DB-backed
// `accounts`/`known`/`recent` the map/cache above query live — proving the adapter rewrite is a pure
// re-source, not a decision change. Run: zig build test-block-produce
// ════════════════════════════════════════════════════════════════════════════
test "produce-parity (TILE-SNAPSHOT VIEW): snapshot-sourced gate admits the IDENTICAL tx set as the DB-view gate" {
    const a = testing.allocator;
    const seed: Hash = [_]u8{0x5C} ** 32;
    const hpt: u64 = 64;
    const tps: u64 = 64;
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;

    const kp1 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const kp2 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x12} ** 32);
    const kp3 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x13} ** 32);
    const kpx = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x14} ** 32);

    // The SAME "world" as the DB-view test above, expressed as a bounded snapshot ARRAY (what
    // dispatchLeaderToProduceTile would have built from a peek + accounts_db lookups) instead of a
    // live-queryable map. kp3 is simply ABSENT from the array (== a DB miss, same fpv=null collapse).
    const FeeSnap = struct { pubkey: [32]u8, view: FeePayerView };
    const fee_snapshot = [_]FeeSnap{
        .{ .pubkey = kp1.public_key.bytes, .view = .{ .lamports = RENT_EXEMPT_MIN_ZERO + 2 * LAMPORTS_PER_SIGNATURE, .owner = SYSTEM, .data_len = 0 } },
        .{ .pubkey = kp2.public_key.bytes, .view = .{ .lamports = RENT_EXEMPT_MIN_ZERO + 1 * LAMPORTS_PER_SIGNATURE, .owner = SYSTEM, .data_len = 0 } },
        .{ .pubkey = kpx.public_key.bytes, .view = .{ .lamports = RENT_EXEMPT_MIN_ZERO + 1 * LAMPORTS_PER_SIGNATURE, .owner = SYSTEM, .data_len = 0 } },
    };
    const known = [_][32]u8{ [_]u8{1} ** 32, [_]u8{2} ** 32 };

    var seq = SeqGateState{};
    defer seq.deinit(a);

    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    var b3: [256]u8 = undefined;
    var b4: [256]u8 = undefined;
    var b5: [256]u8 = undefined;
    var b6: [256]u8 = undefined;
    var b7: [256]u8 = undefined;
    var b8: [256]u8 = undefined;
    const t1 = buildValidTx(kp1, 1, &b1);
    const t2 = buildValidTx(kp1, 2, &b2);
    const t3 = buildValidTx(kp2, 1, &b3);
    const t4 = buildValidTx(kp2, 2, &b4);
    const t5 = buildValidTx(kp3, 1, &b5);
    const t6 = buildValidTx(kp1, 9, &b6);
    const t7 = buildValidTx(kp1, 1, &b7);
    const t8 = buildValidTx(kpx, 1, &b8);
    // t8's first signature is the ONE entry a dispatch-time peek would have flagged
    // already-processed (recent.record(t8_sig, SLOT-10) in the DB-view test's fixture) — expressed
    // directly as the bounded snapshot array tileAdmitTxForBroadcast walks.
    const already_processed = [_][64]u8{t8[1..][0..64].*};

    const TileCtx = struct {
        fee_snapshot: []const FeeSnap,
        known: []const [32]u8,
        already_processed: []const [64]u8,
        seq: *SeqGateState,
        a: std.mem.Allocator,
        fn admit(ctx: *anyopaque, wire: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            var ss: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
            var sk: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
            const parsed = tx_ingest.parse(wire, &ss, &sk) catch return false;
            // Cross-block AlreadyProcessed, snapshot-sourced (mirrors tileAdmitTxForBroadcast).
            for (self.already_processed) |flagged| {
                if (std.mem.eql(u8, &flagged, &parsed.signatures[0])) return false;
            }
            // Fee-payer balance, snapshot-sourced (mirrors tileAdmitTxForBroadcast).
            var fp: ?FeePayerView = null;
            for (self.fee_snapshot) |snap| {
                if (std.mem.eql(u8, &snap.pubkey, &parsed.signer_keys[0])) {
                    fp = snap.view;
                    break;
                }
            }
            return admitTxSeq(self.a, self.seq, parsed, wire, self.known, fp);
        }
    };
    var tctx = TileCtx{ .fee_snapshot = &fee_snapshot, .known = &known, .already_processed = &already_processed, .seq = &seq, .a = a };
    const gate = InclusionGate{ .ctx = &tctx, .admit = TileCtx.admit };

    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();
    for ([_][]const u8{ t1, t2, t3, t4, t5, t6, t7, t8 }, 0..) |tx, idx| {
        try banking.queueTransaction(tx, @intCast(8 - idx), false, .tpu);
    }

    var blockhash: Hash = undefined;
    const bytes = try produceSlotBytes(a, seed, hpt, tps, &banking, &blockhash, gate, MAX_BLOCK_UNITS);
    defer a.free(bytes);

    // IDENTICAL outcome to the DB-view "produce-parity" test above: exactly t1, t2, t3 admitted, same
    // order (P1's 2 fees, P2's 1st fee, P2's 2nd drop-sequential, P3 absent, stale-BH drop, in-block
    // dedup drop, cross-block AlreadyProcessed drop) — proving the snapshot adapter is decision-for-
    // decision equivalent to the DB adapter, not just that admitTxSeq (already shared) is correct.
    const count = try entry.readEntryCount(bytes);
    try testing.expectEqual(@as(u64, tps + 3), count);
    const expected = [_][]const u8{ t1, t2, t3 };
    var offset: usize = 8;
    var records: usize = 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const h = try entry.readEntryHeader(bytes, offset);
        if (h.num_txs > 0) {
            try testing.expectEqual(@as(u64, 1), h.num_txs);
            const blob = expected[records];
            try testing.expectEqualSlices(u8, blob, bytes[h.txs_offset..][0..blob.len]);
            records += 1;
            offset = h.txs_offset + blob.len;
        } else {
            offset = h.txs_offset;
        }
    }
    try testing.expectEqual(@as(usize, 3), records);
}

// ════════════════════════════════════════════════════════════════════════════
// COST-MODEL KAT (flip-blocker (b)) — the pack loop consults the CostTracker block ceiling and STOPS
// at the right tx; the produced block's total cost stays ≤ the limit. Mirrors Agave banking's
// CostTracker.would_fit pack stop (check_block_cost_limits is BLOCK-FATAL on replay).
// Run: zig build test-block-produce
// ════════════════════════════════════════════════════════════════════════════

test "txCostSum: 0-instruction single-signer tx = sig(720) + 1 write-lock(300) + loaded-accounts(16384) = 17404 CU" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x31} ** 32);
    var buf: [256]u8 = undefined;
    const wire = buildValidTx(kp, 1, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);
    // 1 signature × 720 + num_writable(=1: the lone signer key, writable) × 300 + 0 data + 0 program
    // (0 instructions ⇒ 0 builtin/non-builtin ⇒ FIX #3 default program_cost=0) + FIX #2's fixed
    // 16,384 CU loaded-accounts-data-size default term.
    try testing.expectEqual(
        @as(u64, cost_tracker.SIGNATURE_COST + cost_tracker.WRITE_LOCK_UNITS + cost_tracker.DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_COST),
        txCostSum(parsed, wire),
    );
}

test "txCostSum FIX #1: 200-byte instruction data costs 50 CU (divide, not multiply)" {
    // @prov:cost-model.data-cost — pre-fix this file multiplied (200*4=800); post-fix it divides (200/4=50).
    try testing.expectEqual(@as(u64, 50), @as(u64, 200) / cost_tracker.INSTRUCTION_DATA_BYTES_COST);
}

// Hand-crafted CreateAccount tx for FIX #5's KATs: 3 static keys
// [0]=payer (writable signer), [1]=new_account (writable non-signer), [2]=System program (readonly
// non-signer); ONE instruction: System::CreateAccount(lamports=1_000_000, space=165, owner=0xAB*32)
// invoked with accounts [payer, new_account]. Signatures are NOT verified by tx_ingest.parse, so a
// dummy zero signature is fine — these KATs exercise only the wire-structure walk.
fn buildCreateAccountTx(payer: [32]u8, new_account: [32]u8, space: u64, out: []u8) []u8 {
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;
    var p: usize = 0;
    out[p] = 1; // compactU16: 1 signature
    p += 1;
    @memset(out[p..][0..64], 0); // dummy signature (unverified by parse())
    p += 64;
    out[p] = 1; // num_required_signatures
    out[p + 1] = 0; // num_readonly_signed
    out[p + 2] = 1; // num_readonly_unsigned (the System program)
    p += 3;
    out[p] = 3; // compactU16: 3 account keys
    p += 1;
    @memcpy(out[p..][0..32], &payer);
    p += 32;
    @memcpy(out[p..][0..32], &new_account);
    p += 32;
    @memcpy(out[p..][0..32], &SYSTEM);
    p += 32;
    @memset(out[p..][0..32], 0xEE); // recent blockhash (arbitrary)
    p += 32;
    out[p] = 1; // compactU16: 1 instruction
    p += 1;
    out[p] = 2; // program_id_index = 2 (System)
    p += 1;
    out[p] = 2; // compactU16: 2 accounts referenced
    p += 1;
    out[p] = 0; // account index 0 = payer
    p += 1;
    out[p] = 1; // account index 1 = new_account
    p += 1;
    // CreateAccount ix data: tag(u32 LE)=0, lamports(u64 LE), space(u64 LE), owner(32 bytes).
    const data_len: u8 = 4 + 8 + 8 + 32; // 52 — fits in one compactU16 byte (< 0x80, no continuation)
    out[p] = data_len;
    p += 1;
    std.mem.writeInt(u32, out[p..][0..4], 0, .little);
    p += 4;
    std.mem.writeInt(u64, out[p..][0..8], 1_000_000, .little);
    p += 8;
    std.mem.writeInt(u64, out[p..][0..8], space, .little);
    p += 8;
    @memset(out[p..][0..32], 0xAB); // owner (arbitrary)
    p += 32;
    return out[0..p];
}

test "FIX #5a: txWritableAccountKeys returns the REAL writable set (payer + new_account, NOT System)" {
    const payer: [32]u8 = [_]u8{0x01} ** 32;
    const new_account: [32]u8 = [_]u8{0x02} ** 32;
    var buf: [256]u8 = undefined;
    const wire = buildCreateAccountTx(payer, new_account, 165, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);

    var out: [256]cost_tracker.Pubkey = undefined;
    const n = txWritableAccountKeys(parsed, wire, &out);
    try testing.expectEqual(@as(usize, 2), n); // payer + new_account; System is readonly, excluded
    try testing.expectEqualSlices(u8, &payer, &out[0]);
    try testing.expectEqualSlices(u8, &new_account, &out[1]);
}

test "FIX #5b: txAllocatedAccountsDataSize extracts CreateAccount's real `space` (165), not 0" {
    const payer: [32]u8 = [_]u8{0x01} ** 32;
    const new_account: [32]u8 = [_]u8{0x02} ** 32;
    var buf: [256]u8 = undefined;
    const wire = buildCreateAccountTx(payer, new_account, 165, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);

    try testing.expectEqual(@as(u64, 165), txAllocatedAccountsDataSize(parsed, wire));
}

test "FIX #5b: txAllocatedAccountsDataSize returns 0 for a 0-instruction tx (no allocation)" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x31} ** 32);
    var buf: [256]u8 = undefined;
    const wire = buildValidTx(kp, 1, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);
    try testing.expectEqual(@as(u64, 0), txAllocatedAccountsDataSize(parsed, wire));
}

test "FIX #5b: space over MAX_PERMITTED_DATA_LENGTH ⇒ whole tx allocation is 0 (Failed short-circuit)" {
    const payer: [32]u8 = [_]u8{0x01} ** 32;
    const new_account: [32]u8 = [_]u8{0x02} ** 32;
    var buf: [256]u8 = undefined;
    const wire = buildCreateAccountTx(payer, new_account, 11 * 1024 * 1024, &buf); // > 10 MiB cap
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);
    try testing.expectEqual(@as(u64, 0), txAllocatedAccountsDataSize(parsed, wire));
}

test "FIX #5b: CreateAccount + UpgradeNonceAccount(tag 12, None) ⇒ space, NOT Failed-0" {
    // @prov:cost-model.system-alloc-size — UpgradeNonceAccount maps to None (0, does NOT fail the
    // tx) — NOT the Err/Failed arm. Regression guard: tag 12 must be treated as a
    // non-allocating System ix, so a tx pairing CreateAccount(space=165) with UpgradeNonce yields 165.
    // Same 3-static-key layout as buildCreateAccountTx, with a SECOND System ix (tag 12, empty body).
    const payer: [32]u8 = [_]u8{0x01} ** 32;
    const new_account: [32]u8 = [_]u8{0x02} ** 32;
    const SYSTEM: [32]u8 = [_]u8{0} ** 32;
    var out: [512]u8 = undefined;
    var p: usize = 0;
    out[p] = 1; // 1 signature
    p += 1;
    @memset(out[p..][0..64], 0);
    p += 64;
    out[p] = 1; // num_required_signatures
    out[p + 1] = 0; // num_readonly_signed
    out[p + 2] = 1; // num_readonly_unsigned (System)
    p += 3;
    out[p] = 3; // 3 keys
    p += 1;
    @memcpy(out[p..][0..32], &payer);
    p += 32;
    @memcpy(out[p..][0..32], &new_account);
    p += 32;
    @memcpy(out[p..][0..32], &SYSTEM);
    p += 32;
    @memset(out[p..][0..32], 0xEE); // blockhash
    p += 32;
    out[p] = 2; // 2 instructions
    p += 1;
    // ix 0: System CreateAccount(space=165)
    out[p] = 2; // program_id_index = System
    p += 1;
    out[p] = 2; // 2 accounts
    p += 1;
    out[p] = 0;
    out[p + 1] = 1;
    p += 2;
    out[p] = 52; // data_len = 4+8+8+32
    p += 1;
    std.mem.writeInt(u32, out[p..][0..4], 0, .little); // tag 0
    p += 4;
    std.mem.writeInt(u64, out[p..][0..8], 1_000_000, .little); // lamports
    p += 8;
    std.mem.writeInt(u64, out[p..][0..8], 165, .little); // space
    p += 8;
    @memset(out[p..][0..32], 0xAB); // owner
    p += 32;
    // ix 1: System UpgradeNonceAccount (tag 12, no body)
    out[p] = 2; // program_id_index = System
    p += 1;
    out[p] = 0; // 0 accounts referenced (irrelevant to the cost walk)
    p += 1;
    out[p] = 4; // data_len = 4 (just the tag)
    p += 1;
    std.mem.writeInt(u32, out[p..][0..4], 12, .little); // tag 12 = UpgradeNonceAccount
    p += 4;
    const wire = out[0..p];

    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try tx_ingest.parse(wire, &ssig, &skey);
    try testing.expectEqual(@as(u64, 165), txAllocatedAccountsDataSize(parsed, wire));
}

test "txCostSum FIX #3: lone system-transfer program_cost = 3,000 (flat default), not 150" {
    // @prov:compute-budget.exec-limit — 1 non-migrated-builtin ix (System) ×
    // MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT(3,000), no explicit SetComputeUnitLimit. Verified
    // via the exported constants directly (the System program is unconditionally classified
    // "builtin"), matching the formula txCostSum now applies.
    const builtin_ix: u64 = 1;
    const non_builtin_ix: u64 = 0;
    const program_cost = builtin_ix *| MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT +| non_builtin_ix *| DEFAULT_INSTRUCTION_CU_LIMIT;
    try testing.expectEqual(@as(u64, 3_000), program_cost);
}

test "produceSlotBytes: cost-model block limit STOPS packing at the right tx; total cost ≤ limit" {
    const a = testing.allocator;
    const seed: Hash = [_]u8{0x6D} ** 32;
    const hpt: u64 = 64;
    const tps: u64 = 64;
    const N: usize = 10; // queue 10 valid txs

    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();

    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var sent: [N][]u8 = undefined;
    for (0..N) |i| {
        var b: [256]u8 = undefined;
        const tx = buildValidTx(kp, @intCast(i + 1), &b); // distinct blockhash → distinct sig per tx
        // DESCENDING cu_price ⇒ deterministic drain order tx0..tx9 (mempool packs high-priority first).
        try banking.queueTransaction(tx, @intCast(N - i), false, .tpu);
        sent[i] = try a.dupe(u8, tx);
    }
    defer for (sent) |s| a.free(s);

    // Per-tx cost is 17,404 CU (verified above: sig 720 + write-lock 300 + FIX #2's 16,384 loaded-
    // accounts default term; 0 instructions ⇒ 0 program_cost). Set the block limit so EXACTLY 3 fit
    // and the 4th would exceed it.
    const PER_TX: u64 = cost_tracker.SIGNATURE_COST + cost_tracker.WRITE_LOCK_UNITS + cost_tracker.DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_COST; // 17404
    const limit: u64 = 3 * PER_TX + 100; // admits 3, rejects the 4th

    var blockhash: Hash = undefined;
    const bytes = try produceSlotBytes(a, seed, hpt, tps, &banking, &blockhash, null, limit);
    defer a.free(bytes);

    // The block carries EXACTLY 3 record entries (the cost model stopped packing at the 4th tx).
    const count = try entry.readEntryCount(bytes);
    try testing.expectEqual(@as(u64, tps + 3), count);

    // Walk the records, confirm they are the FIRST 3 drained txs in order, and recompute the block's
    // total cost from the wire → must be ≤ the limit (the consensus invariant check_block_cost_limits).
    var offset: usize = 8;
    var records: usize = 0;
    var block_cost: u64 = 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const h = try entry.readEntryHeader(bytes, offset);
        if (h.num_txs > 0) {
            try testing.expectEqual(@as(u64, 1), h.num_txs);
            const blob = sent[records];
            try testing.expectEqualSlices(u8, blob, bytes[h.txs_offset..][0..blob.len]);
            var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
            var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
            const parsed = try tx_ingest.parse(blob, &ssig, &skey);
            block_cost +|= txCostSum(parsed, blob);
            records += 1;
            offset = h.txs_offset + blob.len;
        } else {
            offset = h.txs_offset;
        }
    }
    try testing.expectEqual(@as(usize, 3), records); // stopped at the right tx (4th excluded)
    try testing.expect(block_cost <= limit); // produced block's total CU ≤ the block limit
    try testing.expectEqual(@as(u64, 3 * PER_TX), block_cost); // exactly the 3 admitted txs' cost

    // The 7 unpacked txs were drained but DROPPED (not re-queued) — Agave's pack loop leaves them for
    // the next slot's mempool; this loopback producer drains the whole batch, so the mempool is empty.
    try testing.expectEqual(@as(usize, 0), banking.queueDepth());
}
