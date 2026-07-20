//! Canonical block CostTracker — admission control for block production (and replay cost checks).
//!
//! STAGED / MODULAR: not wired to the live path. Gated behind -Dleader_mode at the call site
//! (block_producer). std-only so the KAT (`zig build test-cost-tracker`) is self-contained.
//!
//! @prov:cost-tracker.would-fit — admission ordering (4 checks, no vote sub-limit),
//! re-verified 2026-07-12 against Agave 4.2.0-beta.0. Full citation trail + grep-verification
//! notes in PROVENANCE.md.
//!
//! This module is the TRACKER (decides when a block / account budget is full given a
//! per-tx cost). Computing a transaction's cost from its instructions is a separate concern
//! (cost_model — a later staging step); the tracker takes a precomputed TxCost.
//!
//! Testnet feature state (re-verified 2026-06-13 via RPC): block limit = 60,000,000
//! (raise_block_limits_to_60m ACTIVE 6oMCUgfY…@345260256; 100M variant INACTIVE).

const std = @import("std");

pub const Pubkey = [32]u8;

// @prov:cost-model.constants — block_cost_limits.rs constants (Agave 4.1.0-beta.3)
pub const COMPUTE_UNIT_TO_US_RATIO: u64 = 30;
pub const SIGNATURE_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 24; // 720
pub const SECP256K1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 223; // 6690
pub const ED25519_VERIFY_STRICT_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 80; // 2400
pub const SECP256R1_VERIFY_COST: u64 = COMPUTE_UNIT_TO_US_RATIO * 160; // 4800
pub const WRITE_LOCK_UNITS: u64 = COMPUTE_UNIT_TO_US_RATIO * 10; // 300
pub const INSTRUCTION_DATA_BYTES_COST: u64 = 140 / COMPUTE_UNIT_TO_US_RATIO; // 4

pub const MAX_BLOCK_UNITS_SIMD_0256: u64 = 60_000_000; // testnet ACTIVE
pub const MAX_BLOCK_UNITS_SIMD_0286: u64 = 100_000_000; // INACTIVE on testnet
pub const MAX_BLOCK_UNITS: u64 = MAX_BLOCK_UNITS_SIMD_0256;
pub const MAX_WRITABLE_ACCOUNT_UNITS: u64 = 24_000_000;
pub const MAX_BLOCK_ACCOUNTS_DATA_SIZE_DELTA: u64 = 100_000_000;
// NOTE: no MAX_VOTE_UNITS here — see FIX #4 below (phantom vote pool removed).

/// Resolve the block limit from the active feature set (caller supplies whether SIMD-0286/100M is
/// active). @prov:cost-model.block-limit
pub fn blockLimitFor(simd_0286_active: bool) u64 {
    return if (simd_0286_active) MAX_BLOCK_UNITS_SIMD_0286 else MAX_BLOCK_UNITS_SIMD_0256;
}

// ── FIX #2: loaded-accounts-data-size cost ──────────────────────────────────
// @prov:cost-model.loaded-accts — DEFAULT term only: Vexor does not parse
// SetLoadedAccountsDataSizeLimit anywhere on the producer/estimate path, so every
// tx gets the DEFAULT term, matching the overwhelmingly common case; a safe
// over-estimate for the rare tx that requests a smaller explicit limit, same
// boundary class as the documented v0-ALT writable-account under-count below).
pub const ACCOUNT_DATA_COST_PAGE_SIZE: u64 = 32 * 1024; // @prov:cost-model.loaded-accts
pub const DEFAULT_HEAP_COST: u64 = 8; // @prov:cost-model.loaded-accts
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES: u64 = 64 * 1024 * 1024; // @prov:cost-model.loaded-accts

/// @prov:cost-model.loaded-accts — calculate_pages_cost(calculate_pages_for_bytes(bytes)).
pub fn loadedAccountsDataSizeCost(bytes: u64) u64 {
    const pages = (bytes +| (ACCOUNT_DATA_COST_PAGE_SIZE - 1)) / ACCOUNT_DATA_COST_PAGE_SIZE;
    return pages *| DEFAULT_HEAP_COST;
}

/// The DEFAULT loaded-accounts-data-size term (64MiB limit ⇒ 2048 pages ⇒ 16,384 CU) — what
/// every tx gets absent an explicit SetLoadedAccountsDataSizeLimit instruction.
pub const DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_COST: u64 = loadedAccountsDataSizeCost(MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES);

pub const CostTrackerError = error{
    WouldExceedBlockMaxLimit,
    WouldExceedAccountMaxLimit,
    WouldExceedAccountDataBlockLimit,
};

/// A precomputed per-transaction cost (the input to the tracker).
/// @prov:cost-tracker.tx-cost-shape
pub const TxCost = struct {
    /// tx_cost.sum() — total CU charged to the block + every writable account.
    sum: u64,
    /// is_simple_vote_transaction() — carried as metadata (Agave's TransactionMeta still exposes
    /// it), but FIX #4: would_fit/add/remove do NOT special-case it — Agave 4.2 cost_tracker.rs
    /// has no vote sub-limit; a vote is charged exactly like any other tx (would_fit's 4 regular
    /// checks). Kept on the struct only so callers don't need two TxCost shapes.
    is_simple_vote: bool,
    /// allocated_accounts_data_size() — the SEPARATE byte budget this tx consumes.
    allocated_accounts_data_size: u64,
    /// writable_accounts() — keys charged the full `sum` each.
    writable_accounts: []const Pubkey,
};

pub const CostTracker = struct {
    account_cost_limit: u64 = MAX_WRITABLE_ACCOUNT_UNITS,
    block_cost_limit: u64 = MAX_BLOCK_UNITS,
    allocated_data_size_limit: u64 = MAX_BLOCK_ACCOUNTS_DATA_SIZE_DELTA,

    cost_by_writable_accounts: std.AutoHashMapUnmanaged(Pubkey, u64) = .{},
    block_cost: u64 = 0,
    allocated_accounts_data_size: u64 = 0,
    transaction_count: u64 = 0,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) CostTracker {
        return .{ .allocator = allocator };
    }

    /// Override limits from the active feature set (e.g. 100M when SIMD-0286 activates).
    pub fn setBlockLimit(self: *CostTracker, limit: u64) void {
        self.block_cost_limit = limit;
    }

    pub fn deinit(self: *CostTracker) void {
        self.cost_by_writable_accounts.deinit(self.allocator);
    }

    pub fn blockCost(self: *const CostTracker) u64 {
        return self.block_cost;
    }

    /// @prov:cost-tracker.would-fit — EXACT ordering (consensus-critical on the replay side,
    /// any CostTrackerError dead-marks the block). `tx.is_simple_vote` is intentionally NOT
    /// consulted here (see TxCost doc comment).
    pub fn wouldFit(self: *const CostTracker, tx: TxCost) CostTrackerError!void {
        const cost = tx.sum;

        // (1) total block cost.
        if (self.block_cost +| cost > self.block_cost_limit) return error.WouldExceedBlockMaxLimit;
        // (2) the tx itself vs the per-account limit.
        if (cost > self.account_cost_limit) return error.WouldExceedAccountMaxLimit;
        // (3) allocated account-data byte budget.
        if (self.allocated_accounts_data_size +| tx.allocated_accounts_data_size > self.allocated_data_size_limit)
            return error.WouldExceedAccountDataBlockLimit;
        // (4) each writable account's chained cost.
        for (tx.writable_accounts) |acct| {
            if (self.cost_by_writable_accounts.get(acct)) |chained| {
                if (chained +| cost > self.account_cost_limit) return error.WouldExceedAccountMaxLimit;
            }
        }
    }

    /// add — charge the full `sum` to block + each writable account and the allocated-data budget.
    /// @prov:cost-tracker.add
    pub fn add(self: *CostTracker, tx: TxCost) !void {
        self.block_cost +|= tx.sum;
        self.allocated_accounts_data_size +|= tx.allocated_accounts_data_size;
        self.transaction_count += 1;
        for (tx.writable_accounts) |acct| {
            const gop = try self.cost_by_writable_accounts.getOrPut(self.allocator, acct);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* +|= tx.sum;
        }
    }

    /// try_add — would_fit then add (the atomic admission step).
    pub fn tryAdd(self: *CostTracker, tx: TxCost) CostTrackerError!void {
        try self.wouldFit(tx);
        self.add(tx) catch return error.WouldExceedBlockMaxLimit; // OOM mapped conservatively
    }

    /// remove — roll back the full `sum`. @prov:cost-tracker.remove
    pub fn remove(self: *CostTracker, tx: TxCost) void {
        self.block_cost -|= tx.sum;
        self.allocated_accounts_data_size -|= tx.allocated_accounts_data_size;
        if (self.transaction_count > 0) self.transaction_count -= 1;
        for (tx.writable_accounts) |acct| {
            if (self.cost_by_writable_accounts.getPtr(acct)) |p| p.* -|= tx.sum;
        }
    }
};

// ════════════════════════════════════════════════════════════════════════════
// KAT — admission ordering. @prov:cost-tracker.would-fit — Run: zig build test-cost-tracker
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

fn pk(b: u8) Pubkey {
    return [_]u8{b} ** 32;
}

test "constants match block_cost_limits.rs (Agave 4.2.0-beta.0)" {
    try testing.expectEqual(@as(u64, 720), SIGNATURE_COST);
    try testing.expectEqual(@as(u64, 300), WRITE_LOCK_UNITS);
    try testing.expectEqual(@as(u64, 4), INSTRUCTION_DATA_BYTES_COST);
    try testing.expectEqual(@as(u64, 60_000_000), MAX_BLOCK_UNITS);
    try testing.expectEqual(@as(u64, 24_000_000), MAX_WRITABLE_ACCOUNT_UNITS);
    try testing.expectEqual(@as(u64, 100_000_000), blockLimitFor(true));
    try testing.expectEqual(@as(u64, 60_000_000), blockLimitFor(false));
    // FIX #2: loaded-accounts-data-size default term — 64MiB / 32KiB = 2048 pages × 8 CU = 16,384.
    try testing.expectEqual(@as(u64, 8), DEFAULT_HEAP_COST);
    try testing.expectEqual(@as(u64, 32 * 1024), ACCOUNT_DATA_COST_PAGE_SIZE);
    try testing.expectEqual(@as(u64, 64 * 1024 * 1024), MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES);
    try testing.expectEqual(@as(u64, 2048), (MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES + ACCOUNT_DATA_COST_PAGE_SIZE - 1) / ACCOUNT_DATA_COST_PAGE_SIZE);
    try testing.expectEqual(@as(u64, 16_384), DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_COST);
    try testing.expectEqual(@as(u64, 0), loadedAccountsDataSizeCost(0));
    try testing.expectEqual(@as(u64, 8), loadedAccountsDataSizeCost(1)); // 1 byte still costs 1 page
}

test "empty tracker fits a normal tx; add accumulates block + per-account" {
    var ct = CostTracker.init(testing.allocator);
    defer ct.deinit();
    const a = [_]Pubkey{ pk(1), pk(2) };
    const tx = TxCost{ .sum = 5000, .is_simple_vote = false, .allocated_accounts_data_size = 0, .writable_accounts = &a };
    try ct.wouldFit(tx);
    try ct.add(tx);
    try testing.expectEqual(@as(u64, 5000), ct.blockCost());
    try testing.expectEqual(@as(u64, 5000), ct.cost_by_writable_accounts.get(pk(1)).?);
    try testing.expectEqual(@as(u64, 1), ct.transaction_count);
}

test "ordering: block-limit fires before account-limit (61M tx)" {
    var ct = CostTracker.init(testing.allocator);
    defer ct.deinit();
    const a = [_]Pubkey{pk(1)};
    const tx = TxCost{ .sum = 61_000_000, .is_simple_vote = false, .allocated_accounts_data_size = 0, .writable_accounts = &a };
    try testing.expectError(error.WouldExceedBlockMaxLimit, ct.wouldFit(tx));
}

test "ordering: 25M tx passes block(60M) but trips account-limit(24M) via check #3" {
    var ct = CostTracker.init(testing.allocator);
    defer ct.deinit();
    const a = [_]Pubkey{pk(1)};
    const tx = TxCost{ .sum = 25_000_000, .is_simple_vote = false, .allocated_accounts_data_size = 0, .writable_accounts = &a };
    try testing.expectError(error.WouldExceedAccountMaxLimit, ct.wouldFit(tx));
}

test "FIX #4: simple-vote transactions use REGULAR limits (no phantom vote pool)" {
    // @prov:cost-tracker.would-fit — a 37M-CU simple-vote tx is judged ONLY against the
    // regular per-account limit (24M) via check #2 (cost > account_cost_limit) — there is no
    // separate 36M vote ceiling to trip first.
    var ct = CostTracker.init(testing.allocator);
    defer ct.deinit();
    const a = [_]Pubkey{pk(9)};
    const tx = TxCost{ .sum = 37_000_000, .is_simple_vote = true, .allocated_accounts_data_size = 0, .writable_accounts = &a };
    try testing.expectError(error.WouldExceedAccountMaxLimit, ct.wouldFit(tx));

    // A vote tx that fits the regular limits is admitted and charged block_cost like any tx —
    // is_simple_vote has NO side effect on accounting.
    var ct2 = CostTracker.init(testing.allocator);
    defer ct2.deinit();
    const b = [_]Pubkey{pk(10)};
    const vote_tx = TxCost{ .sum = 5000, .is_simple_vote = true, .allocated_accounts_data_size = 0, .writable_accounts = &b };
    try ct2.tryAdd(vote_tx);
    try testing.expectEqual(@as(u64, 5000), ct2.blockCost());

    // Two vote txs against DIFFERENT accounts, each individually well under 24M but together
    // well under the block limit too — both admit fine (regular per-account chaining only,
    // no aggregate vote-pool ceiling anywhere near 36M could ever fire for these).
    var ct3 = CostTracker.init(testing.allocator);
    defer ct3.deinit();
    const c1 = [_]Pubkey{pk(11)};
    const c2 = [_]Pubkey{pk(12)};
    try ct3.tryAdd(.{ .sum = 20_000_000, .is_simple_vote = true, .allocated_accounts_data_size = 0, .writable_accounts = &c1 });
    try ct3.tryAdd(.{ .sum = 20_000_000, .is_simple_vote = true, .allocated_accounts_data_size = 0, .writable_accounts = &c2 });
    try testing.expectEqual(@as(u64, 40_000_000), ct3.blockCost());
}

test "per-account chaining: A=20M then +10M on A trips account-limit via check #4" {
    var ct = CostTracker.init(testing.allocator);
    defer ct.deinit();
    const a = [_]Pubkey{pk(7)};
    const t1 = TxCost{ .sum = 20_000_000, .is_simple_vote = false, .allocated_accounts_data_size = 0, .writable_accounts = &a };
    try ct.tryAdd(t1);
    // second tx: cost 10M ≤ account_limit (#2 ok), block 30M ≤ 60M (#1 ok), but A chained 20M+10M>24M (#4).
    const t2 = TxCost{ .sum = 10_000_000, .is_simple_vote = false, .allocated_accounts_data_size = 0, .writable_accounts = &a };
    try testing.expectError(error.WouldExceedAccountMaxLimit, ct.wouldFit(t2));
}

test "allocated-data block limit (#3) fires" {
    var ct = CostTracker.init(testing.allocator);
    defer ct.deinit();
    const a = [_]Pubkey{pk(3)};
    const tx = TxCost{ .sum = 1000, .is_simple_vote = false, .allocated_accounts_data_size = 100_000_001, .writable_accounts = &a };
    try testing.expectError(error.WouldExceedAccountDataBlockLimit, ct.wouldFit(tx));
}

test "remove rolls back block + per-account + count" {
    var ct = CostTracker.init(testing.allocator);
    defer ct.deinit();
    const a = [_]Pubkey{ pk(1), pk(2) };
    const tx = TxCost{ .sum = 5000, .is_simple_vote = false, .allocated_accounts_data_size = 7, .writable_accounts = &a };
    try ct.tryAdd(tx);
    ct.remove(tx);
    try testing.expectEqual(@as(u64, 0), ct.blockCost());
    try testing.expectEqual(@as(u64, 0), ct.cost_by_writable_accounts.get(pk(1)).?);
    try testing.expectEqual(@as(u64, 0), ct.allocated_accounts_data_size);
    try testing.expectEqual(@as(u64, 0), ct.transaction_count);
}
