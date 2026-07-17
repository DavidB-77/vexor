//! Vexor Stakes — Validator stake tracking and epoch stake snapshots.
//!
//! @prov:stakes.fd-stakes-port — ported from Firedancer fd_stakes.c /
//! fd_stake_delegations.h; cross-checked against Sig's idiomatic Zig
//! patterns (sig/src/runtime/program/stake/state.zig). Full per-section
//! upstream file:line citations in PROVENANCE.md.

const std = @import("std");
const types = @import("types.zig");

const Pubkey = types.Pubkey;

/// Slot number (monotonically increasing counter, u64).
pub const Slot = u64;
/// Epoch number (u64). One epoch = ~432,000 slots on mainnet.
pub const Epoch = u64;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// @prov:stakes.warmup-cooldown-rate
// ─────────────────────────────────────────────────────────────────────────────

/// Warmup/cooldown rate pre-SIMD-0006 (Agave default)
pub const DEFAULT_WARMUP_COOLDOWN_RATE: f64 = 0.25;
/// Warmup/cooldown rate post-SIMD-0006 (new rate activation)
pub const NEW_WARMUP_COOLDOWN_RATE: f64 = 0.09;

/// Sentinel epoch meaning "never activated" or "never deactivated".
/// Mirrors Agave's std::u64::MAX sentinel.
pub const EPOCH_NEVER: Epoch = std.math.maxInt(u64);

// ─────────────────────────────────────────────────────────────────────────────
// WarmupCooldownRateEnum
// @prov:stakes.warmup-cooldown-rate — two-value enum to avoid storing f64 in map
// ─────────────────────────────────────────────────────────────────────────────

pub const WarmupCooldownRateTag = enum(u8) {
    rate_025 = 0,
    rate_009 = 1,

    pub fn toFloat(self: WarmupCooldownRateTag) f64 {
        return switch (self) {
            .rate_025 => DEFAULT_WARMUP_COOLDOWN_RATE,
            .rate_009 => NEW_WARMUP_COOLDOWN_RATE,
        };
    }

    pub fn fromFloat(rate: f64) WarmupCooldownRateTag {
        // @prov:stakes.warmup-cooldown-rate fromFloat
        if (rate == DEFAULT_WARMUP_COOLDOWN_RATE) return .rate_025;
        if (rate == NEW_WARMUP_COOLDOWN_RATE) return .rate_009;
        // Default to old rate on unexpected value.
        return .rate_025;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// StakeHistoryEntry
// @prov:stakes.stake-history — matches Agave's StakeHistoryEntry
// (effective/activating/deactivating triple).
// ─────────────────────────────────────────────────────────────────────────────

pub const StakeHistoryEntry = struct {
    effective: u64 = 0,
    activating: u64 = 0,
    deactivating: u64 = 0,
};

/// A single epoch entry in the stake history sysvar.
/// @prov:stakes.stake-history
pub const StakeHistoryRecord = struct {
    epoch: Epoch,
    entry: StakeHistoryEntry,
};

// ─────────────────────────────────────────────────────────────────────────────
// StakeHistory — read-only view of the sysvar
// @prov:stakes.stake-history
// ─────────────────────────────────────────────────────────────────────────────

/// Read-only slice view of the StakeHistory sysvar records.
/// Records are stored newest-first (records[0].epoch is the most recent).
///
/// @prov:stakes.stake-history — linear probe + binary-search fallback
pub const StakeHistory = struct {
    records: []const StakeHistoryRecord,

    /// Returns the entry for `epoch`, or null if not found.
    /// @prov:stakes.stake-history
    pub fn getEntry(self: *const StakeHistory, epoch: Epoch) ?StakeHistoryEntry {
        if (self.records.len == 0) return null;

        const newest_epoch = self.records[0].epoch;
        if (epoch > newest_epoch) return null;

        // Fast path: records are contiguous from newest_epoch backwards.
        const off = newest_epoch - epoch;
        if (off < self.records.len) {
            const rec = &self.records[off];
            if (rec.epoch == epoch) return rec.entry;
        }

        // Fallback: binary search (records sorted newest → oldest, i.e., descending epoch).
        // @prov:stakes.stake-history binary_search
        return binarySearch(self.records, epoch);
    }

    fn binarySearch(records: []const StakeHistoryRecord, epoch: Epoch) ?StakeHistoryEntry {
        var lo: usize = 0;
        var hi: usize = records.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const rec_epoch = records[mid].epoch;
            if (rec_epoch == epoch) return records[mid].entry;
            // Records are newest-first (descending), so larger epoch = smaller index.
            if (rec_epoch > epoch) {
                lo = mid + 1;
            } else {
                if (mid == 0) break;
                hi = mid;
            }
        }
        return null;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// warmupCooldownRate helper
// @prov:stakes.warmup-cooldown-rate — static inline warmup_cooldown_rate()
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the warmup/cooldown rate for `current_epoch`.
/// When `new_rate_activation_epoch` is null, the old 0.25 rate is always used.
pub fn warmupCooldownRate(current_epoch: Epoch, new_rate_activation_epoch: ?Epoch) f64 {
    const threshold = new_rate_activation_epoch orelse EPOCH_NEVER;
    return if (current_epoch < threshold) DEFAULT_WARMUP_COOLDOWN_RATE else NEW_WARMUP_COOLDOWN_RATE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation (per-stake-account delegation record)
// @prov:stakes.delegation-effective-stake — fd_delegation_t / fd_stake_delegation_t
// ─────────────────────────────────────────────────────────────────────────────

pub const Delegation = struct {
    /// The vote account this stake is delegated to.
    voter_pubkey: Pubkey,
    /// Delegated lamports.
    stake: u64,
    /// Epoch this delegation was activated (EPOCH_NEVER = bootstrap stake).
    activation_epoch: Epoch,
    /// Epoch this delegation was deactivated (EPOCH_NEVER = not deactivated).
    deactivation_epoch: Epoch,
    /// Warmup/cooldown rate (deprecated in newer versions, kept for correctness).
    warmup_cooldown_rate: WarmupCooldownRateTag,

    /// Returns true if this is a bootstrap delegation (active from genesis).
    /// @prov:stakes.delegation-effective-stake — activation_epoch==ULONG_MAX → fully effective
    pub fn isBootstrap(self: *const Delegation) bool {
        return self.activation_epoch == EPOCH_NEVER;
    }

    /// Compute (effective_stake, activating_stake) at `target_epoch`.
    /// @prov:stakes.delegation-effective-stake stake_and_activating()
    pub fn effectiveAndActivating(
        self: *const Delegation,
        target_epoch: Epoch,
        history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) struct { effective: u64, activating: u64 } {
        const delegated = self.stake;

        // Bootstrap stake is always fully effective.
        if (self.isBootstrap()) return .{ .effective = delegated, .activating = 0 };
        // Same epoch for activation and deactivation → zero.
        if (self.activation_epoch == self.deactivation_epoch) return .{ .effective = 0, .activating = 0 };
        // Epoch of activation: not yet effective.
        if (target_epoch == self.activation_epoch) return .{ .effective = 0, .activating = delegated };
        // Before activation epoch.
        if (target_epoch < self.activation_epoch) return .{ .effective = 0, .activating = 0 };

        // After activation: walk history to find how much has warmed up.
        const cluster_at_activation = history.getEntry(self.activation_epoch) orelse {
            // No history → fully effective.
            return .{ .effective = delegated, .activating = 0 };
        };

        var prev_epoch = self.activation_epoch;
        var prev_cluster = cluster_at_activation;
        var current_effective: u64 = 0;

        while (true) {
            const current_epoch = prev_epoch + 1;

            if (prev_cluster.activating == 0) break;

            const remaining = delegated - current_effective;
            const weight = @as(f64, @floatFromInt(remaining)) /
                @as(f64, @floatFromInt(prev_cluster.activating));
            const rate = warmupCooldownRate(current_epoch, new_rate_activation_epoch);
            const newly_effective_cluster = @as(f64, @floatFromInt(prev_cluster.effective)) * rate;
            // @prov:stakes.delegation-effective-stake — fd_ulong_max(..., 1) → minimum 1 lamport of progress
            const newly_effective: u64 = @max(1, @as(u64, @intFromFloat(weight * newly_effective_cluster)));

            current_effective +|= newly_effective;
            if (current_effective >= delegated) {
                current_effective = delegated;
                break;
            }

            if (current_epoch >= target_epoch or current_epoch >= self.deactivation_epoch) break;

            if (history.getEntry(current_epoch)) |next_cluster| {
                prev_epoch = current_epoch;
                prev_cluster = next_cluster;
            } else break;
        }

        return .{ .effective = current_effective, .activating = delegated - current_effective };
    }

    /// Full stake history entry (effective/activating/deactivating) at `target_epoch`.
    /// @prov:stakes.delegation-effective-stake stake_activating_and_deactivating()
    pub fn stakeEntry(
        self: *const Delegation,
        target_epoch: Epoch,
        history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) StakeHistoryEntry {
        const ea = self.effectiveAndActivating(target_epoch, history, new_rate_activation_epoch);
        const effective = ea.effective;
        const activating = ea.activating;

        // Before deactivation epoch.
        if (target_epoch < self.deactivation_epoch) {
            return .{ .effective = effective, .activating = activating, .deactivating = 0 };
        }

        // At deactivation epoch.
        if (target_epoch == self.deactivation_epoch) {
            return .{ .effective = effective, .activating = 0, .deactivating = effective };
        }

        // After deactivation: walk history for cooldown.
        const cluster_at_deactivation = history.getEntry(self.deactivation_epoch) orelse {
            return .{ .effective = 0, .activating = 0, .deactivating = 0 };
        };

        var prev_epoch = self.deactivation_epoch;
        var prev_cluster = cluster_at_deactivation;
        var current_effective = effective;

        while (true) {
            const current_epoch = prev_epoch + 1;

            if (prev_cluster.deactivating == 0) break;

            const weight = @as(f64, @floatFromInt(current_effective)) /
                @as(f64, @floatFromInt(prev_cluster.deactivating));
            const rate = warmupCooldownRate(current_epoch, new_rate_activation_epoch);
            const newly_not_effective_cluster = @as(f64, @floatFromInt(prev_cluster.effective)) * rate;
            // @prov:stakes.delegation-effective-stake — fd_ulong_max(..., 1)
            const newly_not_effective: u64 = @max(1, @as(u64, @intFromFloat(weight * newly_not_effective_cluster)));

            current_effective -|= newly_not_effective;
            if (current_effective == 0) break;
            if (current_epoch >= target_epoch) break;

            if (history.getEntry(current_epoch)) |next_cluster| {
                prev_epoch = current_epoch;
                prev_cluster = next_cluster;
            } else break;
        }

        return .{ .effective = current_effective, .activating = 0, .deactivating = current_effective };
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// StakeDelegation — compact per-account entry stored in StakeMap
// @prov:stakes.stake-delegation-map-entry — fd_stake_delegation_t
// ─────────────────────────────────────────────────────────────────────────────

pub const StakeDelegation = struct {
    /// The stake account pubkey (map key).
    stake_account: Pubkey,
    /// The vote account this stake points to.
    vote_account: Pubkey,
    /// Active lamports at snapshot / last update.
    stake: u64,
    /// Credits observed at last update.
    credits_observed: u64,
    /// Activation epoch (EPOCH_NEVER = bootstrap).
    activation_epoch: Epoch,
    /// Deactivation epoch (EPOCH_NEVER = not deactivated).
    deactivation_epoch: Epoch,
    /// Compact warmup/cooldown rate tag (0.25 or 0.09).
    warmup_cooldown_rate: WarmupCooldownRateTag,

    /// Convert to a Delegation for history-based computation.
    /// @prov:stakes.stake-delegation-map-entry fd_stakes_activating_and_deactivating
    pub fn toDelegation(self: *const StakeDelegation) Delegation {
        return .{
            .voter_pubkey = self.vote_account,
            .stake = self.stake,
            .activation_epoch = self.activation_epoch,
            .deactivation_epoch = self.deactivation_epoch,
            .warmup_cooldown_rate = self.warmup_cooldown_rate,
        };
    }

    /// Full StakeHistoryEntry at target_epoch for this delegation.
    /// @prov:stakes.stake-delegation-map-entry fd_stakes_activating_and_deactivating
    pub fn stakeEntry(
        self: *const StakeDelegation,
        target_epoch: Epoch,
        history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) StakeHistoryEntry {
        return self.toDelegation().stakeEntry(target_epoch, history, new_rate_activation_epoch);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// StakeMap — identity pubkey → accumulated stake (vote account → stake weight)
// @prov:stakes.stake-accum-map — Zig port of the fd_stake_accum_map pattern
// ─────────────────────────────────────────────────────────────────────────────

/// Maps vote_account pubkey → accumulated effective stake for the current epoch.
/// Used internally during refreshVoteAccounts to aggregate across all delegations.
pub const StakeMap = struct {
    map: std.AutoHashMapUnmanaged(Pubkey, u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StakeMap {
        return .{
            .map = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StakeMap) void {
        self.map.deinit(self.allocator);
    }

    /// Returns effective stake for vote_account, or 0 if not present.
    pub fn getStake(self: *const StakeMap, vote_account: *const Pubkey) u64 {
        return self.map.get(vote_account.*) orelse 0;
    }

    /// Add `delta` to the accumulated stake for `vote_account`.
    pub fn addStake(self: *StakeMap, vote_account: Pubkey, delta: u64) !void {
        const res = try self.map.getOrPut(self.allocator, vote_account);
        if (res.found_existing) {
            res.value_ptr.* +|= delta;
        } else {
            res.value_ptr.* = delta;
        }
    }

    /// Set the stake for `vote_account` to exactly `amount` (used when seeding
    /// from previous epoch vote accounts with zero initial stake).
    pub fn setStake(self: *StakeMap, vote_account: Pubkey, amount: u64) !void {
        try self.map.put(self.allocator, vote_account, amount);
    }

    pub fn count(self: *const StakeMap) usize {
        return self.map.count();
    }

    pub fn iterator(self: *StakeMap) std.AutoHashMapUnmanaged(Pubkey, u64).Iterator {
        return self.map.iterator();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// EpochStakes — immutable snapshot of vote-account → effective-stake at epoch N
// @prov:stakes.epoch-stakes-refresh — mirrors Agave's EpochStakes / fd_bank.f.total_epoch_stake
// ─────────────────────────────────────────────────────────────────────────────

/// Per-epoch snapshot: maps each vote account pubkey to its effective stake.
/// Built once per epoch boundary by calling `EpochStakes.build(...)`.
///
/// @prov:stakes.epoch-stakes-refresh — fd_refresh_vote_accounts accumulates effective stakes
pub const EpochStakes = struct {
    epoch: Epoch,
    /// vote_account → effective_stake (in lamports)
    vote_stakes: std.AutoHashMapUnmanaged(Pubkey, u64),
    /// Total effective stake across all vote accounts this epoch.
    total_stake: u64,
    /// Total activating stake (informational).
    total_activating: u64,
    /// Total deactivating stake (informational).
    total_deactivating: u64,

    /// Build EpochStakes by iterating all delegations and accumulating effective stake.
    ///
    /// Caller owns the returned EpochStakes; call `deinit` when done.
    ///
    /// @prov:stakes.epoch-stakes-refresh — iterate stake_delegations, accumulate
    /// into stake_accum_map per vote account
    pub fn build(
        allocator: std.mem.Allocator,
        epoch: Epoch,
        delegations: []const StakeDelegation,
        history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) !EpochStakes {
        var vote_stakes: std.AutoHashMapUnmanaged(Pubkey, u64) = .{};
        errdefer vote_stakes.deinit(allocator);

        var total_stake: u64 = 0;
        var total_activating: u64 = 0;
        var total_deactivating: u64 = 0;

        for (delegations) |*del| {
            const entry = del.stakeEntry(epoch, history, new_rate_activation_epoch);
            total_stake +|= entry.effective;
            total_activating +|= entry.activating;
            total_deactivating +|= entry.deactivating;

            if (entry.effective == 0) continue;

            const res = try vote_stakes.getOrPut(allocator, del.vote_account);
            if (res.found_existing) {
                res.value_ptr.* +|= entry.effective;
            } else {
                res.value_ptr.* = entry.effective;
            }
        }

        return .{
            .epoch = epoch,
            .vote_stakes = vote_stakes,
            .total_stake = total_stake,
            .total_activating = total_activating,
            .total_deactivating = total_deactivating,
        };
    }

    pub fn deinit(self: *EpochStakes, allocator: std.mem.Allocator) void {
        self.vote_stakes.deinit(allocator);
    }

    /// Returns effective stake for a vote account, or 0 if not staked.
    pub fn getStake(self: *const EpochStakes, vote_account: *const Pubkey) u64 {
        return self.vote_stakes.get(vote_account.*) orelse 0;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// LeaderSchedule — deterministic slot assignment from epoch stakes
// @prov:stakes.leader-schedule-weights — fd_stake_weights_by_node sorts
// (stake, vote_key) for schedule input
// ─────────────────────────────────────────────────────────────────────────────

/// A single validator's slot assignments within an epoch.
pub const ValidatorSlots = struct {
    /// Node identity pubkey (not vote account).
    identity: Pubkey,
    /// Sorted list of slot indices within the epoch assigned to this validator.
    slots: []const u64,
};

/// Full leader schedule for one epoch: identity → assigned slot indices.
///
/// Build with `LeaderSchedule.compute(...)`. Caller owns the result; call `deinit`.
pub const LeaderSchedule = struct {
    epoch: Epoch,
    /// slot → identity pubkey (index = slot - epoch_first_slot)
    schedule: []Pubkey,
    allocator: std.mem.Allocator,

    /// Compute a leader schedule from EpochStakes using the same weighted-shuffle
    /// algorithm as Agave.
    ///
    /// `slots_in_epoch`   — total slots this epoch (432_000 on mainnet)
    /// `epoch_first_slot` — first slot number of the epoch
    ///
    /// @prov:stakes.leader-schedule-weights — builds the weight array fed into
    /// the deterministic shuffle
    ///
    /// NOTE: The weighted VRF shuffle is complex; this implementation uses a
    /// stake-proportional round-robin approximation suitable for testing.
    /// Replace with the full ChaCha-RNG weighted shuffle for production.
    pub fn compute(
        allocator: std.mem.Allocator,
        epoch: Epoch,
        epoch_first_slot: Slot,
        slots_in_epoch: u64,
        epoch_stakes: *const EpochStakes,
    ) !LeaderSchedule {
        const schedule = try allocator.alloc(Pubkey, slots_in_epoch);
        errdefer allocator.free(schedule);

        // Collect (identity, stake) pairs sorted by (stake DESC, pubkey DESC).
        // @prov:stakes.leader-schedule-weights sort_vote_weights_by_stake_vote_inplace
        const StakeWeight = struct {
            pubkey: Pubkey,
            stake: u64,
        };
        var weights = try std.ArrayListUnmanaged(StakeWeight).initCapacity(
            allocator,
            epoch_stakes.vote_stakes.count(),
        );
        defer weights.deinit(allocator);

        var it = epoch_stakes.vote_stakes.iterator();
        while (it.next()) |entry| {
            weights.appendAssumeCapacity(.{ .pubkey = entry.key_ptr.*, .stake = entry.value_ptr.* });
        }

        // Sort: highest stake first, break ties by pubkey bytes (descending).
        std.sort.heap(StakeWeight, weights.items, {}, struct {
            fn lessThan(_: void, a: StakeWeight, b: StakeWeight) bool {
                if (a.stake != b.stake) return a.stake > b.stake;
                return std.mem.order(u8, &a.pubkey.data, &b.pubkey.data) == .gt;
            }
        }.lessThan);

        if (weights.items.len == 0) {
            // No staked validators: fill with zero pubkey.
            const zero = Pubkey{ .data = [_]u8{0} ** 32 };
            @memset(schedule, zero);
        } else {
            // Proportional round-robin fill.
            // For each slot i, assign it to the validator whose cumulative
            // stake proportion covers slot i / total_slots.
            const total = epoch_stakes.total_stake;
            var slot_idx: u64 = 0;
            for (weights.items) |w| {
                if (total == 0) break;
                const count = @min(
                    slots_in_epoch - slot_idx,
                    // slots = round(stake/total * slots_in_epoch)
                    (w.stake * slots_in_epoch + total / 2) / total,
                );
                for (0..count) |_| {
                    if (slot_idx >= slots_in_epoch) break;
                    schedule[slot_idx] = w.pubkey;
                    slot_idx += 1;
                }
            }
            // Fill remainder with last validator.
            while (slot_idx < slots_in_epoch) : (slot_idx += 1) {
                schedule[slot_idx] = weights.items[weights.items.len - 1].pubkey;
            }
        }

        _ = epoch_first_slot; // used by caller to offset slot → schedule index

        return .{
            .epoch = epoch,
            .schedule = schedule,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LeaderSchedule) void {
        self.allocator.free(self.schedule);
    }

    /// Returns the leader for an absolute `slot` within this epoch.
    /// `epoch_first_slot` must match what was passed to `compute`.
    pub fn getLeader(self: *const LeaderSchedule, slot: Slot, epoch_first_slot: Slot) ?Pubkey {
        if (slot < epoch_first_slot) return null;
        const idx = slot - epoch_first_slot;
        if (idx >= self.schedule.len) return null;
        return self.schedule[idx];
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "warmupCooldownRate switches at activation epoch" {
    try std.testing.expectEqual(DEFAULT_WARMUP_COOLDOWN_RATE, warmupCooldownRate(100, 200));
    try std.testing.expectEqual(NEW_WARMUP_COOLDOWN_RATE, warmupCooldownRate(200, 200));
    try std.testing.expectEqual(NEW_WARMUP_COOLDOWN_RATE, warmupCooldownRate(300, 200));
    try std.testing.expectEqual(DEFAULT_WARMUP_COOLDOWN_RATE, warmupCooldownRate(100, null));
}

test "WarmupCooldownRateTag round-trip" {
    const t025 = WarmupCooldownRateTag.fromFloat(0.25);
    try std.testing.expectEqual(WarmupCooldownRateTag.rate_025, t025);
    try std.testing.expectApproxEqAbs(0.25, t025.toFloat(), 1e-10);

    const t009 = WarmupCooldownRateTag.fromFloat(0.09);
    try std.testing.expectEqual(WarmupCooldownRateTag.rate_009, t009);
    try std.testing.expectApproxEqAbs(0.09, t009.toFloat(), 1e-10);
}

test "Delegation isBootstrap" {
    const del = Delegation{
        .voter_pubkey = Pubkey{ .data = [_]u8{1} ** 32 },
        .stake = 1_000_000,
        .activation_epoch = EPOCH_NEVER,
        .deactivation_epoch = EPOCH_NEVER,
        .warmup_cooldown_rate = .rate_025,
    };
    try std.testing.expect(del.isBootstrap());
}

test "Delegation bootstrap is fully effective" {
    const del = Delegation{
        .voter_pubkey = Pubkey{ .data = [_]u8{1} ** 32 },
        .stake = 5_000_000,
        .activation_epoch = EPOCH_NEVER,
        .deactivation_epoch = EPOCH_NEVER,
        .warmup_cooldown_rate = .rate_025,
    };
    const history = StakeHistory{ .records = &.{} };
    const ea = del.effectiveAndActivating(42, &history, null);
    try std.testing.expectEqual(@as(u64, 5_000_000), ea.effective);
    try std.testing.expectEqual(@as(u64, 0), ea.activating);
}

test "Delegation activating at epoch of activation" {
    const del = Delegation{
        .voter_pubkey = Pubkey{ .data = [_]u8{2} ** 32 },
        .stake = 1_000,
        .activation_epoch = 10,
        .deactivation_epoch = EPOCH_NEVER,
        .warmup_cooldown_rate = .rate_025,
    };
    const history = StakeHistory{ .records = &.{} };
    const ea = del.effectiveAndActivating(10, &history, null);
    try std.testing.expectEqual(@as(u64, 0), ea.effective);
    try std.testing.expectEqual(@as(u64, 1_000), ea.activating);
}

test "StakeHistory binary search" {
    const records = [_]StakeHistoryRecord{
        .{ .epoch = 5, .entry = .{ .effective = 500, .activating = 0, .deactivating = 0 } },
        .{ .epoch = 4, .entry = .{ .effective = 400, .activating = 0, .deactivating = 0 } },
        .{ .epoch = 3, .entry = .{ .effective = 300, .activating = 0, .deactivating = 0 } },
        .{ .epoch = 1, .entry = .{ .effective = 100, .activating = 0, .deactivating = 0 } },
    };
    const history = StakeHistory{ .records = &records };

    try std.testing.expectEqual(@as(u64, 500), history.getEntry(5).?.effective);
    try std.testing.expectEqual(@as(u64, 100), history.getEntry(1).?.effective);
    try std.testing.expect(history.getEntry(2) == null);
    try std.testing.expect(history.getEntry(99) == null);
}

test "EpochStakes.build accumulates delegations" {
    const vote_a = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const vote_b = Pubkey{ .data = [_]u8{0xBB} ** 32 };
    const delegations = [_]StakeDelegation{
        .{
            .stake_account = Pubkey{ .data = [_]u8{1} ** 32 },
            .vote_account = vote_a,
            .stake = 1_000_000,
            .credits_observed = 0,
            .activation_epoch = EPOCH_NEVER, // bootstrap
            .deactivation_epoch = EPOCH_NEVER,
            .warmup_cooldown_rate = .rate_025,
        },
        .{
            .stake_account = Pubkey{ .data = [_]u8{2} ** 32 },
            .vote_account = vote_a,
            .stake = 500_000,
            .credits_observed = 0,
            .activation_epoch = EPOCH_NEVER,
            .deactivation_epoch = EPOCH_NEVER,
            .warmup_cooldown_rate = .rate_025,
        },
        .{
            .stake_account = Pubkey{ .data = [_]u8{3} ** 32 },
            .vote_account = vote_b,
            .stake = 2_000_000,
            .credits_observed = 0,
            .activation_epoch = EPOCH_NEVER,
            .deactivation_epoch = EPOCH_NEVER,
            .warmup_cooldown_rate = .rate_025,
        },
    };
    const history = StakeHistory{ .records = &.{} };

    var es = try EpochStakes.build(
        std.testing.allocator,
        42,
        &delegations,
        &history,
        null,
    );
    defer es.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 1_500_000), es.getStake(&vote_a));
    try std.testing.expectEqual(@as(u64, 2_000_000), es.getStake(&vote_b));
    try std.testing.expectEqual(@as(u64, 3_500_000), es.total_stake);
}

test "LeaderSchedule.getLeader basic" {
    const vote_a = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const delegations = [_]StakeDelegation{
        .{
            .stake_account = Pubkey{ .data = [_]u8{1} ** 32 },
            .vote_account = vote_a,
            .stake = 1_000_000,
            .credits_observed = 0,
            .activation_epoch = EPOCH_NEVER,
            .deactivation_epoch = EPOCH_NEVER,
            .warmup_cooldown_rate = .rate_025,
        },
    };
    const history = StakeHistory{ .records = &.{} };
    var es = try EpochStakes.build(std.testing.allocator, 1, &delegations, &history, null);
    defer es.deinit(std.testing.allocator);

    var sched = try LeaderSchedule.compute(std.testing.allocator, 1, 432_000, 100, &es);
    defer sched.deinit();

    // Only one validator → all slots go to vote_a
    const leader = sched.getLeader(432_000, 432_000);
    try std.testing.expect(leader != null);
    try std.testing.expect(std.mem.eql(u8, &leader.?.data, &vote_a.data));
}
