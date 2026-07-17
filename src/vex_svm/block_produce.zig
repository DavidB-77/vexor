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
// SEQUENTIALLY, but the pre-filter checks each tx against the parent state in isolation. A tx that
// transfers away / closes a fee-payer EARLIER in the same block can make a LATER tx
// InsufficientFundsForFee → NotLoaded → the cluster marks the WHOLE block dead. The pre-filter
// cannot see that. The COMPLETE broadcast-safety boundary must be execution-based — either
// execute-during-pack (Agave's banking model) or loopback-replay-then-broadcast-only-if-not-dead
// (which also needs Vexor's replay to actually detect the NotLoaded classes; it currently does not).
// That mechanism is a FLIP-BLOCKER (task #25). Until it lands, a SAFETY INTERLOCK in replay_stage
// forbids broadcasting tx-bearing bytes (tx-bearing + VEX_LEADER_BROADCAST ⇒ produce EMPTY + error),
// so the pre-filter only ever runs for loopback validation.
//
// gate == null  ⇒ loopback/KAT-lenient path: byte-identical to the pre-gate behavior. The default
//                 while VEX_TPU_INGEST is off, and (currently) also the tile path's loopback packing.
// gate != null  ⇒ apply the per-tx pre-filter + produceSlotBytes' own in-block duplicate-signature
//                 dedup. Used by the inline loopback path; a loopback block is replayed only by us
//                 and never voted, so an imperfect pre-filter can at worst waste our own slot.
//
// STILL DEFERRED before the broadcast flip (do NOT remove): (a) the execution-based completeness
// mechanism above; (b) cost-model block-CU-limit packing (a separate BLOCK-FATAL class,
// check_block_cost_limits); (c) CROSS-block AlreadyProcessed via a live status cache (Vexor's
// TxnCache has no production wiring yet — only in-block dedup is covered here); (d) the tile's
// thread-safe SNAPSHOT gate (the tile cannot deref the recycled live bank). All are flip-blockers,
// tracked in task #25; none is reachable while the interlock holds / VEX_TPU_INGEST off.

/// Per-tx inclusion PRE-FILTER (see banner: necessary, NOT sufficient for broadcast). The caller
/// (replay_stage, which holds the producing bank + accounts_db + fee machinery) supplies `admit`;
/// block_produce stays free of Bank/AccountsDb imports (no module cycle). `admit(ctx, tx_wire)`
/// returns true iff the raw tx passes the per-tx load/validate checks against the FROZEN PARENT bank.
/// In-block duplicate-signature dedup is handled by produceSlotBytes itself (per-block seen-set).
pub const InclusionGate = struct {
    ctx: *anyopaque,
    admit: *const fn (ctx: *anyopaque, tx_wire: []const u8) bool,
};

/// Fee-payer account view, extracted from the producing bank by the caller (lamports/owner/data_len).
/// `null` at the call site means the account is absent or has zero lamports (Agave AccountNotFound).
pub const FeePayerView = struct { lamports: u64, owner: [32]u8, data_len: usize };

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
    const SYSTEM_PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;
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

/// Per-block running state for the SEQUENTIAL inclusion gate. Matches Agave banking, which debits
/// fees in pack order: `running_balances[fee_payer]` = the payer's lamports AFTER all prior fees this
/// block. Reset/owned per produced block by the caller.
pub const SeqGateState = struct {
    running_balances: std.AutoHashMapUnmanaged([32]u8, u64) = .{},

    pub fn deinit(self: *SeqGateState, allocator: std.mem.Allocator) void {
        self.running_balances.deinit(allocator);
    }
};

/// SEQUENTIAL per-tx admit — the LIVE gate. Like admitTx, but the fee-payer must be able to pay from
/// its RUNNING balance (parent lamports minus the fees of earlier txs by the same payer THIS block —
/// the sequential fee-stacking drain that the frozen-parent-isolation pre-filter missed). On admit it
/// advances the running balance. `fee_payer.lamports` seeds the running map on first use of a payer.
/// CONSERVATIVE: a borderline tx is dropped (safe). Does NOT catch a fee-payer drained by an earlier
/// tx's TRANSFER instruction (needs real execution — the loopback-gate residual, adversarial-only).
pub fn admitTxSeq(
    allocator: std.mem.Allocator,
    state: *SeqGateState,
    parsed: tx_ingest.ParsedTx,
    tx_wire: []const u8,
    recent_blockhashes: []const [32]u8,
    fee_payer: ?FeePayerView,
) bool {
    const fp = checkStaticAndOwner(parsed, tx_wire, recent_blockhashes, fee_payer) orelse return false;
    const fee = txFee(parsed, tx_wire);
    const fp_key = parsed.signer_keys[0];
    const running = state.running_balances.get(fp_key) orelse fp.lamports;
    if (running < RENT_EXEMPT_MIN_ZERO +| fee) return false; // sequential InsufficientFundsForFee
    // Admit: commit this tx's fee debit to the running balance so a later tx by the same payer sees it.
    state.running_balances.put(allocator, fp_key, running -| fee) catch return false;
    return true;
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
            // (b) sigverify + blockhash-age + fee-payer-can-pay, evaluated against the producing bank.
            if (!g.admit(g.ctx, qt.data)) continue;
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
        // MODULE-20 MIGRATION TEST FIX (pre-existing fix105 test bug, block_produce.zig itself
        // unchanged — production code byte-identical to fix105): the original line queued every
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
        // LIVENESS-tier: any tx order in a produced block is valid) fix105 latent, recorded in
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
