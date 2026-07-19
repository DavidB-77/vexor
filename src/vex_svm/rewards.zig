//! Vexor Rewards — Epoch reward calculation and partitioned distribution.
//!
//! Ported from Firedancer's fd_rewards.c / fd_rewards.h / fd_rewards_base.h.
//! Agave counterpart: solana_runtime::bank::partitioned_epoch_rewards.
//!
//! Firedancer source references:
//!   fd_rewards_base.h:1-29      — constants (LAMPORTS_PER_SOL, REWARD_CALCULATION_NUM_BLOCKS,
//!                                  STAKE_ACCOUNT_STORES_PER_BLOCK, MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH)
//!   fd_rewards.h:1-114          — public API (begin_partitioned_rewards, distribute_partitioned_epoch_rewards,
//!                                  get_reward_distribution_num_blocks, vote_commission_split)
//!   fd_rewards.c:1-599+         — full implementation
//!     :17-25   inflation::total()
//!     :27-29   inflation::foundation()
//!     :33-38   inflation::validator()
//!     :47-64   getInflationStartSlot()
//!     :66-80   getInflationNumSlots()
//!     :82-88   slotInYearForInflation()
//!     :94-173  calculateStakePointsAndCredits()
//!     :179-214 voteCommissionSplit()
//!     :217-276 redeemRewards()
//!     :279-330 getRewardDistributionNumBlocks()
//!     :340-389 calculateRewardPointsPartitioned()
//!     :407-498 calculateStakeVoteRewards()
//!     :577-599 calculateValidatorRewards()
//!
//! cf. sig/src/runtime/program/stake/ for Zig-idiomatic stake delegation patterns.
//!
//! Call hierarchy for a new epoch boundary:
//!   beginPartitionedRewards()
//!     └─ calculateRewardsAndDistributeVoteRewards()
//!          ├─ calculatePreviousEpochInflationRewards()
//!          ├─ calculateRewardPointsPartitioned()   (total points from all delegations)
//!          ├─ calculateStakeVoteRewards()           (per-delegation reward amounts)
//!          └─ distributeVoteAccountRewards()        (credit vote accounts immediately)
//!
//!   distributePartitionedEpochRewards()            (called REWARD_CALCULATION_NUM_BLOCKS later,
//!                                                    then once per partition)
//!     └─ distributeEpochRewardToStakeAccount()

const std = @import("std");
const types = @import("types.zig");
const stakes = @import("stakes.zig");
const siphash13 = @import("siphash13.zig");
const zpow = @import("zpow.zig");

const Pubkey = types.Pubkey;
const Epoch = stakes.Epoch;
const Slot = stakes.Slot;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// fd_rewards_base.h:6-27
// ─────────────────────────────────────────────────────────────────────────────

/// Lamports in one SOL.
/// fd_rewards_base.h:7 — LAMPORTS_PER_SOL
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// Number of blocks reserved for reward *calculation* before distribution begins.
/// fd_rewards_base.h:13 — REWARD_CALCULATION_NUM_BLOCKS
pub const REWARD_CALCULATION_NUM_BLOCKS: u64 = 1;

/// Target number of stake accounts to distribute per block during the payout window.
/// fd_rewards_base.h:21 — STAKE_ACCOUNT_STORES_PER_BLOCK
pub const STAKE_ACCOUNT_STORES_PER_BLOCK: u64 = 4096;

/// Maximum ratio of reward-distribution blocks to epoch length.
/// fd_rewards_base.h:25 — MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH
pub const MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH: u64 = 10;

/// Hard cap on the number of reward partitions per epoch.
/// fd_rewards_base.h:27 — MAX_PARTITIONS_PER_EPOCH
pub const MAX_PARTITIONS_PER_EPOCH: u64 = 43200;

// ─────────────────────────────────────────────────────────────────────────────
// Inflation parameters
// fd_types.h: fd_inflation_t — mirrors Agave's sdk::inflation::Inflation
// ─────────────────────────────────────────────────────────────────────────────

/// Inflation schedule parameters.
/// Agave: solana_sdk::inflation::Inflation
pub const Inflation = struct {
    /// Starting inflation rate (year 0).
    /// r39 inflation-math fix: was 0.15 (Firedancer default tracking pre-
    /// `full_inflation` testnet); Agave 4.0-beta.7 testnet runs Inflation::full()
    /// where initial = DEFAULT_INITIAL = 0.08 (solana-inflation-3.1.0/src/lib.rs).
    initial: f64 = 0.08,
    /// Terminal (minimum) inflation rate.
    terminal: f64 = 0.015,
    /// Annual rate at which inflation tapers toward terminal.
    taper: f64 = 0.15,
    /// Foundation allocation fraction.
    /// r39 inflation-math fix: was 0.05 (Default::default()); Agave testnet uses
    /// Inflation::full() which explicitly sets foundation = 0.0 (no foundation
    /// share on testnet — `validator(year) = total - foundation`).
    foundation: f64 = 0.0,
    /// Duration (years) for which foundation allocation applies.
    foundation_term: f64 = 7.0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Inflation helpers
// fd_rewards.c:17-88
// ─────────────────────────────────────────────────────────────────────────────

/// Pure-Zig pow, byte-verified vs glibc (see src/vex_svm/zpow.zig for the
/// full provenance/derivation). This is the SAME correctly-rounded result
/// Agave's Rust `f64::powf` and Firedancer's C `pow` resolve to on this
/// hardware (all three ultimately bottom out at glibc 2.29's ARM
/// optimized-routines pow on znver4). Zig's `std.math.pow` is a DIFFERENT
/// pure-Zig reimplementation that is NOT bit-identical to libm (off by up to
/// ~1 ULP on some inputs), which at epoch 990 put our inflation rate 1 ULP
/// low and the reward pool 1 lamport short → EpochRewards sysvar bytes
/// diverged → bank_hash diverged (incident 2026-07-15, slot 422156256). The
/// epoch-990 fix first swapped in libm's `extern fn pow` (dynamically linked,
/// zero new dep) as an immediate mitigation; zpow.pow replaces that with a
/// pure-Zig port so consensus math no longer depends on libc at all, closing
/// out the "no libc in consensus math" northstar. Byte-identity was verified
/// by an exhaustive differential fuzz (158,001,954 checks across two
/// independently-seeded runs — random/boundary/edge-case/subnormal
/// (base,exp) pairs, including this exact epoch-990 KAT — 0 mismatches
/// against the box's linked `extern fn pow`) before this swap was made.
/// The old libm extern is kept below, commented out, as a documented
/// fallback if a future glibc/table mismatch is ever suspected:
///   extern fn pow(x: f64, y: f64) f64;
/// Total inflation rate at a given year in the schedule.
/// fd_rewards.c:17 — agave: sdk/src/inflation.rs#L85 Inflation::total()
pub fn inflationTotal(inf: Inflation, year: f64) f64 {
    std.debug.assert(year != 0.0);
    // MUST be byte-identical to libm pow — byte-parity with Agave/FD (see above).
    const tapered = inf.initial * zpow.pow(1.0 - inf.taper, year);
    return @max(tapered, inf.terminal);
}

/// Foundation allocation rate at a given year.
/// fd_rewards.c:27 — Inflation::foundation()
pub fn inflationFoundation(inf: Inflation, year: f64) f64 {
    return if (year < inf.foundation_term) inf.foundation * inflationTotal(inf, year) else 0.0;
}

/// Validator allocation rate at a given year (total minus foundation).
/// fd_rewards.c:33 — Inflation::validator()
pub fn inflationValidator(inf: Inflation, year: f64) f64 {
    return inflationTotal(inf, year) - inflationFoundation(inf, year);
}

// ─────────────────────────────────────────────────────────────────────────────
// EpochSchedule — minimal projection (mirrors fd_epoch_schedule_t)
// ─────────────────────────────────────────────────────────────────────────────

/// Epoch schedule parameters.
/// Mirrors fd_epoch_schedule_t used throughout fd_rewards.c.
pub const EpochSchedule = struct {
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64 = 0,
    warmup: bool = true,
    first_normal_epoch: u64,
    first_normal_slot: u64,
};

/// Return the first slot of an epoch.
/// Agave: EpochSchedule::get_first_slot_in_epoch
pub fn epochFirstSlot(sched: EpochSchedule, epoch: Epoch) Slot {
    if (epoch < sched.first_normal_epoch) {
        // warmup phase: slot 0 of epoch N is 2^(N + TRAILING_ZEROS) - 1
        // Firedancer: fd_epoch_slot0 (which handles warmup)
        // Simplified: first_normal_slot - (first_normal_epoch - epoch) * slots_per_epoch
        // We use the closed-form for warmup epochs (fd_epoch_slot0 logic):
        const trailing_zeros: u6 = 3; // FD_EPOCH_LEN_MIN_TRAILING_ZERO
        var slots: u64 = @as(u64, 1) << @intCast(epoch + trailing_zeros);
        if (slots > sched.slots_per_epoch) slots = sched.slots_per_epoch;
        // Sum up all prior epochs in warmup.
        var first: u64 = 0;
        var e: u64 = 0;
        while (e < epoch) : (e += 1) {
            const ep_slots: u64 = @as(u64, 1) << @intCast(e + trailing_zeros);
            first += @min(ep_slots, sched.slots_per_epoch);
        }
        return first;
    }
    return sched.first_normal_slot +
        (epoch - sched.first_normal_epoch) * sched.slots_per_epoch;
}

/// Return the number of slots in a given epoch.
/// fd_rewards.c:283 — get_slots_in_epoch
pub fn slotsInEpoch(epoch: Epoch, sched: EpochSchedule) u64 {
    if (epoch < sched.first_normal_epoch) {
        const trailing_zeros: u6 = 3; // FD_EPOCH_LEN_MIN_TRAILING_ZERO
        return @as(u64, 1) << @intCast(epoch + trailing_zeros);
    }
    return sched.slots_per_epoch;
}

/// Return which epoch a slot belongs to.
/// Agave: EpochSchedule::get_epoch_and_slot_index
pub fn slotToEpoch(sched: EpochSchedule, slot: Slot) Epoch {
    if (slot < sched.first_normal_slot) {
        // warmup binary search
        const trailing_zeros: u6 = 3;
        var cumulative: u64 = 0;
        var e: u64 = 0;
        while (e < sched.first_normal_epoch) : (e += 1) {
            const ep_slots: u64 = @as(u64, 1) << @intCast(e + trailing_zeros);
            if (cumulative + ep_slots > slot) return e;
            cumulative += ep_slots;
        }
        return sched.first_normal_epoch;
    }
    return sched.first_normal_epoch +
        (slot - sched.first_normal_slot) / sched.slots_per_epoch;
}

// ─────────────────────────────────────────────────────────────────────────────
// PrevEpochInflationRewards — output of calculatePreviousEpochInflationRewards
// fd_rewards.h:8-13 — fd_prev_epoch_inflation_rewards_t
// ─────────────────────────────────────────────────────────────────────────────

/// Inflation reward summary for the previous epoch.
/// fd_rewards.h:8 — fd_prev_epoch_inflation_rewards_t
pub const PrevEpochInflationRewards = struct {
    /// Total lamports minted as validator rewards.
    validator_rewards: u64,
    /// Epoch duration expressed as a fraction of a year.
    prev_epoch_duration_in_years: f64,
    /// Validator inflation rate (fraction).
    validator_rate: f64,
    /// Foundation inflation rate (fraction).
    foundation_rate: f64,
};

// ─────────────────────────────────────────────────────────────────────────────
// calculatePreviousEpochInflationRewards
// fd_rewards.c:297-310
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the inflation rewards for the previous epoch given bank parameters.
///
/// fd_rewards.c:297 — calculate_previous_epoch_inflation_rewards
pub fn calculatePreviousEpochInflationRewards(
    inflation: Inflation,
    epoch_sched: EpochSchedule,
    slots_per_year: f64,
    prev_epoch_capitalization: u64,
    /// Current slot (used to derive year-in-schedule).
    current_slot: Slot,
    inflation_start_slot: Slot,
    prev_epoch: Epoch,
) PrevEpochInflationRewards {
    // slot_in_year_for_inflation: fd_rewards.c:82-88
    const num_slots = slotInYearNumSlots(epoch_sched, current_slot, inflation_start_slot);
    const slot_in_year = @as(f64, @floatFromInt(num_slots)) / slots_per_year;

    const validator_rate = inflationValidator(inflation, slot_in_year);
    const foundation_rate = inflationFoundation(inflation, slot_in_year);
    const duration = epochDurationInYears(epoch_sched, prev_epoch, slots_per_year);
    const validator_rewards: u64 = @intFromFloat(
        validator_rate * @as(f64, @floatFromInt(prev_epoch_capitalization)) * duration,
    );

    return .{
        .validator_rewards = validator_rewards,
        .prev_epoch_duration_in_years = duration,
        .validator_rate = validator_rate,
        .foundation_rate = foundation_rate,
    };
}

/// Helper: number of slots since inflation started (for year calculation).
/// fd_rewards.c:66-79 — get_inflation_num_slots
fn slotInYearNumSlots(sched: EpochSchedule, slot: Slot, inflation_start_slot: Slot) u64 {
    const inflation_epoch = slotToEpoch(sched, inflation_start_slot);
    const inflation_start = epochFirstSlot(sched, if (inflation_epoch > 0) inflation_epoch - 1 else 0);
    const current_epoch = slotToEpoch(sched, slot);
    return epochFirstSlot(sched, current_epoch) -| inflation_start;
}

/// Duration of an epoch in fractional years.
/// fd_rewards.c:289-295 — epoch_duration_in_years
fn epochDurationInYears(sched: EpochSchedule, epoch: Epoch, slots_per_year: f64) f64 {
    return @as(f64, @floatFromInt(slotsInEpoch(epoch, sched))) / slots_per_year;
}

// ─────────────────────────────────────────────────────────────────────────────
// CommissionSplit
// fd_rewards.h:99-110 — fd_commission_split_t
// ─────────────────────────────────────────────────────────────────────────────

/// Result of splitting a reward between voter and staker given a commission %.
/// fd_rewards.h:99 — fd_commission_split_t
pub const CommissionSplit = struct {
    /// Lamports to the vote account.
    voter_portion: u64,
    /// Lamports to the stake account.
    staker_portion: u64,
    /// True whenever the commission is a genuine split (0 < bps < 10000), REGARDLESS of
    /// whether either portion floored to zero — Agave inflation_rewards/mod.rs:240-267 returns
    /// (mine, theirs, true) unconditionally on this branch; FD fd_rewards.c:206 sets is_split=1.
    /// The redeem-path guard (is_split && one side == 0 → skip the reward entirely) depends on
    /// this: deriving it from the outputs made that guard unsatisfiable and paid dust rewards
    /// the cluster skips (epoch-983 carrier, slot 419132285, +13 lamports).
    is_split: bool,
};

/// Split `on` lamports between voter and staker using the given commission in basis points.
///
/// Uses integer-only arithmetic to avoid floating-point inconsistencies.
/// fd_rewards.c:179-214 — fd_vote_commission_split (now bps-aware to match Agave 4.0-beta.7)
/// Agave: runtime/src/inflation_rewards/mod.rs:243 — commission_split(commission_bps: u16, on: u64)
///
/// r40 Bug 4 fix: was `(commission: u8, on: u64)` with /100 — lossy for v4 vote accounts that
/// store commission in u16 bps (0-10000). Caller used to pre-divide bps/100 → u8, dropping
/// sub-percentage precision (e.g. bps=2050 → 20%, losing 0.5% commission per validator per epoch).
/// Now matches Agave byte-exact: divide by MAX_BPS (10000) directly.
pub fn voteCommissionSplit(commission_bps: u16, on: u64) CommissionSplit {
    const MAX_BPS: u64 = 10_000;
    const bps: u64 = @min(@as(u64, commission_bps), MAX_BPS);
    if (bps == 0) return .{ .voter_portion = 0, .staker_portion = on, .is_split = false };
    if (bps == MAX_BPS) return .{ .voter_portion = on, .staker_portion = 0, .is_split = false };

    // Agave inflation_rewards/mod.rs:256-267 — symmetric integer multiply-then-divide.
    const voter_portion = mulDiv128(on, bps, MAX_BPS);
    const staker_portion = mulDiv128(on, MAX_BPS - bps, MAX_BPS);
    return .{
        .voter_portion = voter_portion,
        .staker_portion = staker_portion,
        .is_split = true,
    };
}

/// 128-bit multiply-then-divide: (a * b) / c, truncating.
inline fn mulDiv128(a: u64, b: u64, c: u64) u64 {
    const product: u128 = @as(u128, a) * @as(u128, b);
    return @intCast(product / @as(u128, c));
}

// ─────────────────────────────────────────────────────────────────────────────
// StakePoints — intermediate per-delegation point tally
// ─────────────────────────────────────────────────────────────────────────────

/// Per-delegation point calculation result.
/// Mirrors fd_calculated_stake_points_t used throughout fd_rewards.c.
pub const StakePoints = struct {
    /// 128-bit weighted credit×stake product.
    points: u128,
    /// Updated credits_observed after reward application.
    new_credits_observed: u64,
    /// If true, advance credits_observed but skip lamport payout.
    force_credits_update_with_skipped_reward: bool,
};

// ─────────────────────────────────────────────────────────────────────────────
// EpochCreditsEntry — one entry from a vote account's epoch_credits list
// ─────────────────────────────────────────────────────────────────────────────

/// A single epoch's credit window stored in a vote account.
/// fd_rewards.c:94-103 — epoch_credits / base_credits / credits_delta / prev_credits_delta
pub const EpochCreditsEntry = struct {
    epoch: Epoch,
    /// Absolute credits at end of window.
    credits: u64,
    /// Absolute credits at start of window.
    prev_credits: u64,
};

// ─────────────────────────────────────────────────────────────────────────────
// calculateStakePointsAndCredits
// fd_rewards.c:94-173
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate points earned by a stake delegation given a vote account's epoch credits.
///
/// Points = Σ (earned_credits_in_epoch × effective_stake_in_epoch)
///
/// fd_rewards.c:94 — calculate_stake_points_and_credits
/// Agave: programs/stake/src/points.rs#L109
pub fn calculateStakePointsAndCredits(
    /// Epoch credits history from the vote account (newest-first or oldest-first slice).
    epoch_credits: []const EpochCreditsEntry,
    /// Credits already observed by this stake delegation.
    credits_observed: u64,
    /// Effective stake (lamports) for the delegation.  Simplified: constant here.
    /// A full implementation would call stakeActivatingAndDeactivating per epoch.
    effective_stake: u64,
) StakePoints {
    // Derive total credits at end of the most recent epoch.
    const credits_in_vote: u64 = if (epoch_credits.len > 0)
        epoch_credits[epoch_credits.len - 1].credits
    else
        0;

    // fd_rewards.c:111-116 — vote has fewer credits than stake → force update
    if (credits_in_vote < credits_observed) {
        return .{
            .points = 0,
            .new_credits_observed = credits_in_vote,
            .force_credits_update_with_skipped_reward = true,
        };
    }

    // fd_rewards.c:121-127 — no new credits
    if (credits_in_vote == credits_observed) {
        return .{
            .points = 0,
            .new_credits_observed = credits_in_vote,
            .force_credits_update_with_skipped_reward = false,
        };
    }

    // fd_rewards.c:130-172 — iterate over credit windows
    var total_points: u128 = 0;
    var new_credits_observed: u64 = credits_observed;

    for (epoch_credits) |ec| {
        const final_credits = ec.credits;
        const initial_credits = ec.prev_credits;

        std.debug.assert(initial_credits <= final_credits);

        if (final_credits <= credits_observed) continue;

        const earned_credits: u64 = if (credits_observed < initial_credits)
            final_credits - initial_credits
        else
            final_credits - new_credits_observed;

        new_credits_observed = @max(new_credits_observed, final_credits);
        total_points += @as(u128, effective_stake) * @as(u128, earned_credits);
    }

    return .{
        .points = total_points,
        .new_credits_observed = new_credits_observed,
        .force_credits_update_with_skipped_reward = false,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// StakeReward — per-account reward computed during partition setup
// ─────────────────────────────────────────────────────────────────────────────

/// Computed reward for a single stake account.
/// Mirrors fd_calculated_stake_rewards_t (fd_rewards.c).
pub const StakeReward = struct {
    /// Public key of the stake account.
    stake_account: Pubkey,
    /// Lamports to add to the stake account.
    staker_rewards: u64,
    /// Updated credits_observed to write back to the stake account.
    new_credits_observed: u64,
    /// Compounded delegation.stake to write back at distribution (Defect-A fix,
    /// RCA 2026-07-02): calc-time `pre-redeem delegation.stake + staker_rewards`,
    /// mirroring Agave `stake.delegation.stake += staker_rewards`
    /// (inflation_rewards/mod.rs:114) whose result distribution.rs:212-225 stores
    /// (and asserts == stored stake + reward); FD fd_rewards.c:778 sat-add.
    new_delegation_stake: u64,
};

// ─────────────────────────────────────────────────────────────────────────────
// redeemRewards
// fd_rewards.c:217-276
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the voter and staker reward for one delegation.
/// Returns null if the delegation earns no reward (skip, no points, zero split).
///
/// fd_rewards.c:217 — redeem_rewards
/// Agave: programs/stake/src/rewards.rs#L33
pub fn redeemRewards(
    stake_points: StakePoints,
    activation_epoch: Epoch,
    rewarded_epoch: Epoch,
    total_rewards: u64,
    total_points: u128,
    commission_bps: u16,
) ?struct { staker: u64, voter: u64, new_credits_observed: u64 } {
    var sp = stake_points;

    // Force credit update if rewards disabled or activation epoch matches rewarded epoch.
    // fd_rewards.c:233-237
    if (total_rewards == 0 or activation_epoch == rewarded_epoch) {
        sp.force_credits_update_with_skipped_reward = true;
    }

    if (sp.force_credits_update_with_skipped_reward) {
        return .{ .staker = 0, .voter = 0, .new_credits_observed = sp.new_credits_observed };
    }

    if (sp.points == 0 or total_points == 0) return null;

    // fd_rewards.c:249-260 — proportional reward: (points * total_rewards) / total_points
    const rewards_u128: u128 = sp.points *% @as(u128, total_rewards) / total_points;
    if (rewards_u128 > std.math.maxInt(u64)) {
        // Should never happen in practice; Firedancer FD_LOG_ERR here.
        return null;
    }
    const rewards: u64 = @intCast(rewards_u128);
    if (rewards == 0) return null;

    // fd_rewards.c:266-270 — split between voter and staker (bps-aware per Agave 4.0-beta.7)
    const split = voteCommissionSplit(commission_bps, rewards);
    if (split.is_split and (split.voter_portion == 0 or split.staker_portion == 0)) {
        return null;
    }

    return .{
        .staker = split.staker_portion,
        .voter = split.voter_portion,
        .new_credits_observed = sp.new_credits_observed,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// getRewardDistributionNumBlocks
// fd_rewards.c:312-338 — get_reward_distribution_num_blocks
// fd_rewards.h:95-97   — fd_rewards_get_reward_distribution_num_blocks
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate the number of slots required to distribute all stake rewards.
///
/// fd_rewards.c:312 — get_reward_distribution_num_blocks
/// Agave: runtime/src/bank/partitioned_epoch_rewards/mod.rs#L214
pub fn getRewardDistributionNumBlocks(
    epoch_sched: EpochSchedule,
    slot: Slot,
    total_stake_accounts: u64,
) u32 {
    // Warmup epochs use a single block for all rewards.
    // fd_rewards.c:321-323
    if (epoch_sched.warmup and slotToEpoch(epoch_sched, slot) < epoch_sched.first_normal_epoch) {
        return 1;
    }

    // fd_rewards.c:326-330 — chunk count clamped to epoch/10
    var num_chunks = total_stake_accounts / STAKE_ACCOUNT_STORES_PER_BLOCK +
        @intFromBool(total_stake_accounts % STAKE_ACCOUNT_STORES_PER_BLOCK != 0);
    num_chunks = @max(num_chunks, 1);
    const epoch_cap = @max(epoch_sched.slots_per_epoch / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH, 1);
    num_chunks = @min(num_chunks, epoch_cap);

    return @intCast(num_chunks);
}

// ─────────────────────────────────────────────────────────────────────────────
// PartitionedRewardsCalculation — summary returned to caller
// fd_rewards.h:16-26 — fd_partitioned_rewards_calculation_t
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of a partitioned rewards calculation pass.
/// fd_rewards.h:16 — fd_partitioned_rewards_calculation_t
pub const PartitionedRewardsCalculation = struct {
    /// Total validator (staker+voter) reward points (u128).
    validator_points: u128,
    /// Sum of vote balances + delegated stake before rewards.
    old_vote_balance_and_staked: u64,
    /// Total lamports distributed as validator rewards.
    validator_rewards: u64,
    /// Validator inflation rate.
    validator_rate: f64,
    /// Foundation inflation rate.
    foundation_rate: f64,
    /// Duration of previous epoch in years.
    prev_epoch_duration_in_years: f64,
    /// Total supply (capitalization) at epoch boundary.
    capitalization: u64,
};

// ─────────────────────────────────────────────────────────────────────────────
// StakePartition — one slice of stakes to distribute in one block
// fd_rewards_base.h / fd_stake_rewards.h design
// ─────────────────────────────────────────────────────────────────────────────

/// A single partition of stake rewards to be distributed in one block.
/// fd_stake_rewards.h:15-53 — design notes on linked-list partitions.
pub const StakePartition = struct {
    rewards: std.ArrayListUnmanaged(StakeReward) = .{},

    pub fn deinit(self: *StakePartition, alloc: std.mem.Allocator) void {
        self.rewards.deinit(alloc);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// RewardsCalculator — orchestrates a full epoch rewards run
// ─────────────────────────────────────────────────────────────────────────────

/// Delegation input for rewards calculation.
pub const StakeDelegation = struct {
    stake_account: Pubkey,
    vote_account: Pubkey,
    /// Lamports effectively delegated.
    effective_stake: u64,
    /// RAW delegation.stake from the account bytes (Offsets.delegation_stake,
    /// 156..164) — NOT warmup/cooldown-adjusted. This is the value Agave
    /// compounds at calc time (`stake.delegation.stake += staker_rewards`) and
    /// stores back at distribution (Defect-A fix, RCA 2026-07-02).
    delegation_stake: u64,
    /// Epoch in which this delegation became active.
    activation_epoch: Epoch,
    /// Credits observed at last reward payout.
    credits_observed: u64,
    /// carrier #16: stake-points precomputed by the caller using PER-EPOCH
    /// effective stake (the curve lives in bank.zig). When present, the
    /// calculator uses this instead of the single-effective approximation.
    precomputed_points: StakePoints = .{ .points = 0, .new_credits_observed = 0, .force_credits_update_with_skipped_reward = false },
};

/// Vote account rewards accumulator.
pub const VoteRewardAccumulator = struct {
    vote_account: Pubkey,
    /// Commission in basis points (0-10000). v4 vote accounts store this directly;
    /// older v1/v2 commission_u8 (0-100) gets converted via `commission * 100` at construction.
    commission_bps: u16,
    /// Accumulated voter lamports from all delegations.
    vote_rewards: u64 = 0,
    /// Epoch credits history for this vote account.
    epoch_credits: []const EpochCreditsEntry,
};

/// Full rewards calculation run for one epoch boundary.
///
/// Usage:
///   1. init()
///   2. calculateRewards() → fills partitions[] and vote_rewards[]
///   3. Distribute vote_rewards immediately.
///   4. Distribute partitions[i] once per slot during payout window.
///   5. deinit()
pub const RewardsCalculator = struct {
    allocator: std.mem.Allocator,

    /// Computed stake reward partitions.
    partitions: std.ArrayListUnmanaged(StakePartition) = .{},

    /// Per-vote-account reward totals to distribute immediately.
    vote_rewards: std.ArrayListUnmanaged(struct { pubkey: Pubkey, lamports: u64 }) = .{},

    /// Summary of the calculation pass.
    summary: PartitionedRewardsCalculation = std.mem.zeroes(PartitionedRewardsCalculation),

    pub fn init(allocator: std.mem.Allocator) RewardsCalculator {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RewardsCalculator) void {
        for (self.partitions.items) |*p| p.deinit(self.allocator);
        self.partitions.deinit(self.allocator);
        self.vote_rewards.deinit(self.allocator);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // calculateRewards — main entry point for epoch boundary
    // fd_rewards.c:340-498 (calculateRewardPointsPartitioned + calculateStakeVoteRewards
    //                       + setup_stake_partitions)
    // ─────────────────────────────────────────────────────────────────────────

    /// Calculate all rewards for an epoch boundary.
    ///
    /// Parameters:
    ///   delegations   — all stake delegations active at epoch boundary
    ///   vote_accounts — vote account metadata (indexed same as used in delegations)
    ///   inflation_rewards — output of calculatePreviousEpochInflationRewards
    ///   rewarded_epoch — the epoch being rewarded (previous epoch)
    ///   epoch_sched    — epoch schedule
    ///   current_slot   — first slot of the new epoch
    ///
    /// fd_rewards.c:575-598 — calculate_validator_rewards (orchestrator)
    pub fn calculateRewards(
        self: *RewardsCalculator,
        delegations: []const StakeDelegation,
        vote_accounts: []VoteRewardAccumulator,
        inflation_rewards: PrevEpochInflationRewards,
        rewarded_epoch: Epoch,
        epoch_sched: EpochSchedule,
        current_slot: Slot,
        /// Parent blockhash used to seed partition assignment.
        parent_blockhash: [32]u8,
    ) !void {
        // ── Phase 1: calculate total points ──────────────────────────────────
        // fd_rewards.c:340-389 — calculate_reward_points_partitioned
        var total_points: u128 = 0;

        // stake_points[i] cached for phase 2 reuse.
        const stake_points = try self.allocator.alloc(StakePoints, delegations.len);
        defer self.allocator.free(stake_points);

        for (delegations, 0..) |del, i| {
            // carrier #16 @414812256: use the caller's PER-EPOCH precomputed
            // points (bank.zig computeStakePointsPerEpoch, which recomputes the
            // effective stake at each epoch in the credits window via the
            // activation curve). The old single-effective calculateStakePoints
            // AndCredits undercounted total_points for warming/cooling stakes.
            stake_points[i] = del.precomputed_points;
            total_points += del.precomputed_points.points;
        }

        self.summary.validator_points = total_points;
        self.summary.validator_rewards = inflation_rewards.validator_rewards;
        self.summary.validator_rate = inflation_rewards.validator_rate;
        self.summary.foundation_rate = inflation_rewards.foundation_rate;
        self.summary.prev_epoch_duration_in_years = inflation_rewards.prev_epoch_duration_in_years;

        // ── Phase 2: compute per-delegation rewards ───────────────────────────
        // fd_rewards.c:407-498 — calculate_stake_vote_rewards
        //
        // carrier #16 BUG4 (@414812256): num_partitions must derive from the
        // number of stake accounts that actually EARNED a reward (Agave
        // partitioned_epoch_rewards: get_reward_distribution_num_blocks takes
        // stake_rewards.len() = rewarded entries), NOT total delegations.
        // Canonical at the 973 boundary: 126 partitions ⇒ rewarded count in
        // [512001, 516096], while delegations.len() over-counted. Two-pass:
        // PASS A redeems every delegation (also accumulating vote rewards
        // exactly once), PASS B sizes the partitions from the rewarded count
        // and assigns each rewarded entry by pubkey hash.
        const PendingReward = struct {
            stake_account: Pubkey,
            staker_rewards: u64,
            new_credits_observed: u64,
            new_delegation_stake: u64,
        };
        var rewarded = std.array_list.Managed(PendingReward).init(self.allocator);
        defer rewarded.deinit();
        try rewarded.ensureTotalCapacity(delegations.len);

        for (delegations, 0..) |del, i| {
            const vote_idx = findVoteAccount(vote_accounts, del.vote_account) orelse continue;
            const va = &vote_accounts[vote_idx];

            const result = redeemRewards(
                stake_points[i],
                del.activation_epoch,
                rewarded_epoch,
                inflation_rewards.validator_rewards,
                total_points,
                va.commission_bps,
            ) orelse continue;

            va.vote_rewards += result.voter;

            // carrier #16 @414812256: Agave counts a stake in `stake_rewards`
            // whenever calculate_stake_rewards returns Some — INCLUDING the
            // force-credits-update path where staker_rewards == 0 (inflation_
            // rewards/mod.rs:171-176). The prior `if (result.staker > 0)` filter
            // under-counted → num_partitions collapsed (got 2, canonical 126).
            // Append on every non-null redeem; staker may legitimately be 0
            // (the credit-only update is still written during distribution).
            try rewarded.append(.{
                .stake_account = del.stake_account,
                .staker_rewards = result.staker,
                .new_credits_observed = result.new_credits_observed,
                // Defect-A fix: compound at calc time exactly like Agave
                // (inflation_rewards/mod.rs:114); saturating add per FD
                // fd_ulong_sat_add (fd_rewards.c:778).
                .new_delegation_stake = del.delegation_stake +| result.staker,
            });
        }

        const num_partitions = getRewardDistributionNumBlocks(
            epoch_sched,
            current_slot,
            @intCast(rewarded.items.len),
        );

        // Allocate partitions, then assign every rewarded stake account by
        // pubkey hash (fd_stake_rewards.c partition assignment; seed =
        // parent POH blockhash — see carrier #16 BUG1 at the caller).
        try self.partitions.resize(self.allocator, num_partitions);
        for (self.partitions.items) |*p| p.* = .{};

        for (rewarded.items) |pr| {
            const part_idx = assignPartition(pr.stake_account, num_partitions, parent_blockhash);
            try self.partitions.items[part_idx].rewards.append(self.allocator, .{
                .stake_account = pr.stake_account,
                .staker_rewards = pr.staker_rewards,
                .new_credits_observed = pr.new_credits_observed,
                .new_delegation_stake = pr.new_delegation_stake,
            });
        }

        // ── Phase 3: collect vote rewards ─────────────────────────────────────
        for (vote_accounts) |va| {
            if (va.vote_rewards > 0) {
                try self.vote_rewards.append(self.allocator, .{
                    .pubkey = va.vote_account,
                    .lamports = va.vote_rewards,
                });
            }
        }
    }
};

/// Find the index of a vote account in the slice, or null.
fn findVoteAccount(accounts: []const VoteRewardAccumulator, pubkey: Pubkey) ?usize {
    for (accounts, 0..) |va, i| {
        if (std.mem.eql(u8, &va.vote_account.data, &pubkey.data)) return i;
    }
    return null;
}

/// Deterministically assign a stake account to a partition index.
/// CANONICAL (Agave `EpochRewardsHasher` == FD `fd_stake_rewards.c:271-277`):
///   SipHash1-3 keyed (0,0) over parent_blockhash (32B, FIRST) ‖ stake_pubkey
///   (32B, SECOND) → hash64; partition = (u128)num_partitions * hash64 >> 64
///   (multiply-shift, NOT modulo).
/// (Prior impl used SHA256(pubkey‖blockhash)%N — wrong hash, wrong input order,
///  and wrong bucketing; the old comment falsely attributed SHA256%N to FD.)
fn assignPartition(pubkey: Pubkey, num_partitions: u32, parent_blockhash: [32]u8) u32 {
    return siphash13.assignPartitionIndex(parent_blockhash, pubkey.data, num_partitions);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "inflationTotal decreases with time and floors at terminal" {
    const testing = std.testing;
    const inf = Inflation{};
    const t1 = inflationTotal(inf, 1.0);
    const t5 = inflationTotal(inf, 5.0);
    const t100 = inflationTotal(inf, 100.0);
    try testing.expect(t1 > t5);
    try testing.expect(t100 >= inf.terminal - 1e-9);
    try testing.expect(t100 <= inf.terminal + 1e-9);
}

test "epoch-990 inflation pool = canonical (libm pow byte-parity regression, incident 422156256)" {
    const testing = std.testing;
    // Exact live inputs at slot 422156256 (first slot epoch 990), from the live
    // log + oracle-node canonical bank. Zig std.math.pow gave rate …535 → pool
    // …237 (1 lamph short); glibc pow gives rate …537 → pool …238 (canonical).
    const inf = Inflation{ .initial = 0.15, .terminal = 0.015, .taper = 0.15, .foundation = 0.0, .foundation_term = 0.0 };
    const slots_per_year: f64 = 78_892_314.984;
    const num_slots: u64 = 372_816_000;
    const year: f64 = @as(f64, @floatFromInt(num_slots)) / slots_per_year;
    const rate = inflationValidator(inf, year); // = inflationTotal here (foundation 0)
    // Canonical validator rate bits (glibc pow): 0.06959068621499537.
    try testing.expectEqual(@as(u64, 4589678958079265892), @as(u64, @bitCast(rate)));
    const cap: f64 = @floatFromInt(@as(u64, 2_106_790_928_481_151_500));
    const duration: f64 = 432_000.0 / slots_per_year;
    const pool: u64 = @intFromFloat(rate * cap * duration);
    // Canonical total reward pool (oracle-node bank commission log: "out of 802826326344238").
    try testing.expectEqual(@as(u64, 802_826_326_344_238), pool);
}

test "voteCommissionSplit edge cases (bps)" {
    const testing = std.testing;

    // 0 bps → all to staker
    const s0 = voteCommissionSplit(0, 1000);
    try testing.expect(s0.voter_portion == 0);
    try testing.expect(s0.staker_portion == 1000);
    try testing.expect(!s0.is_split);

    // 10_000 bps (100%) → all to voter
    const s100 = voteCommissionSplit(10_000, 1000);
    try testing.expect(s100.voter_portion == 1000);
    try testing.expect(s100.staker_portion == 0);

    // 1000 bps (10%) → 100 voter / 900 staker
    const s10 = voteCommissionSplit(1000, 1000);
    try testing.expect(s10.voter_portion == 100);
    try testing.expect(s10.staker_portion == 900);
    try testing.expect(s10.is_split);

    // voter + staker should not exceed original (may be 1 less due to truncation).
    try testing.expect(s10.voter_portion + s10.staker_portion <= 1000);

    // r40 precision check: 250 bps (2.5%) — old u8 path would have lost the 0.5%
    // (250/100=2 → 2% effective). With bps math we get 25 voter / 975 staker on 1000.
    const s250bps = voteCommissionSplit(250, 1000);
    try testing.expect(s250bps.voter_portion == 25);
    try testing.expect(s250bps.staker_portion == 975);
    try testing.expect(s250bps.is_split);

    // u16::MAX clamps to 100% (matches Agave's MAX_BPS clamp)
    const sMax = voteCommissionSplit(std.math.maxInt(u16), 1000);
    try testing.expect(sMax.voter_portion == 1000);
    try testing.expect(sMax.staker_portion == 0);
}

test "voteCommissionSplit one-sided truncation still reports is_split (epoch-983 carrier class)" {
    const testing = std.testing;

    // Live carrier EZU3eyAbuvnk8bAZVCVuhAa6i3RwCSpFMCvKPvZD47KZ @ slot 419132285:
    // R=14, 500 bps → voter floors to 0, staker 13. Agave mod.rs:240-267 returns
    // (0, 13, true); the redeem guard must then SKIP the reward entirely.
    const carrier = voteCommissionSplit(500, 14);
    try testing.expect(carrier.voter_portion == 0);
    try testing.expect(carrier.staker_portion == 13);
    try testing.expect(carrier.is_split); // was false pre-fix → guard unsatisfiable → paid dust

    // Mirror class: staker side floors to 0 near 100% commission.
    const mirror = voteCommissionSplit(9_900, 50);
    try testing.expect(mirror.voter_portion == 49);
    try testing.expect(mirror.staker_portion == 0);
    try testing.expect(mirror.is_split);

    // Both sides floor to 0.
    const both = voteCommissionSplit(5_000, 1);
    try testing.expect(both.voter_portion == 0);
    try testing.expect(both.staker_portion == 0);
    try testing.expect(both.is_split);
}

test "redeemRewards skips one-sided-truncation split entirely (TooEarlyUnfairSplit)" {
    const testing = std.testing;

    // Drive the real redeem path with the carrier's arithmetic shape: points=14,
    // total_rewards=1, total_points=1 → rewards=14, commission 500 bps → (0, 13, split).
    // Canonical outcome (Agave mod.rs:217-225): None — no store, no CO advance.
    // activation_epoch (0) != rewarded_epoch (1) so the force-skip path stays off.
    const sp = StakePoints{
        .points = 14,
        .new_credits_observed = 2_029_012_698,
        .force_credits_update_with_skipped_reward = false,
    };
    const out = redeemRewards(sp, 0, 1, 1, 1, 500);
    try testing.expect(out == null);

    // Control: a healthy split at the same commission still pays exactly.
    const sp2 = StakePoints{
        .points = 10_000,
        .new_credits_observed = 2_029_012_698,
        .force_credits_update_with_skipped_reward = false,
    };
    const out2 = redeemRewards(sp2, 0, 1, 1, 1, 500) orelse return error.TestUnexpectedResult;
    try testing.expect(out2.voter == 500);
    try testing.expect(out2.staker == 9_500);
    try testing.expect(out2.new_credits_observed == 2_029_012_698);
}

test "calculateStakePointsAndCredits basic" {
    const testing = std.testing;

    const ec = [_]EpochCreditsEntry{
        .{ .epoch = 0, .credits = 100, .prev_credits = 0 },
        .{ .epoch = 1, .credits = 200, .prev_credits = 100 },
    };

    // credits_observed = 0: should earn all 200 credits × stake
    const sp = calculateStakePointsAndCredits(&ec, 0, 1000);
    try testing.expect(sp.points == 200 * 1000);
    try testing.expect(sp.new_credits_observed == 200);
    try testing.expect(!sp.force_credits_update_with_skipped_reward);

    // Already observed 200 → no new points
    const sp2 = calculateStakePointsAndCredits(&ec, 200, 1000);
    try testing.expect(sp2.points == 0);
    try testing.expect(!sp2.force_credits_update_with_skipped_reward);
}

test "getRewardDistributionNumBlocks normal epoch" {
    const testing = std.testing;

    const sched = EpochSchedule{
        .slots_per_epoch = 432_000,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    // 10,000 accounts → ceil(10000/4096) = 3 blocks
    const n = getRewardDistributionNumBlocks(sched, 0, 10_000);
    try testing.expect(n == 3);

    // 0 accounts → 1 block minimum
    const n0 = getRewardDistributionNumBlocks(sched, 0, 0);
    try testing.expect(n0 == 1);
}

test "redeemRewards zero total_points returns null" {
    const testing = std.testing;
    const sp = StakePoints{ .points = 1000, .new_credits_observed = 100, .force_credits_update_with_skipped_reward = false };
    // commission_bps=1000 (10%); zero total_points still short-circuits to null.
    const r = redeemRewards(sp, 0, 1, 1_000_000, 0, 1000);
    try testing.expect(r == null);
}

test "calculateRewards wiring: new_delegation_stake compounds + assignPartition seeded from parent_blockhash (real callsite)" {
    // RCA 2026-07-02 Gate-3 wiring KAT (follow-up owed by commit 1b28512/566f95a):
    // drives PASS A → PASS B through the REAL calculateRewards entry so the
    // Defect-A compounding (new_delegation_stake = raw delegation_stake +
    // staker_rewards) and the E1 partition assignment (SipHash13 seeded with
    // the parent_blockhash ARGUMENT) are pinned at the callsite, not just in
    // their leaf primitives. Fixture: 8303 delegations (3 zero-reward via
    // force_credits_update — the E2/carrier-16 membership class) on one vote
    // account at 10% commission → per-delegation reward exactly 1000
    // (voter 100 / staker 900), rewarded count 8303 → num_partitions 3.
    const alloc = std.testing.allocator;

    const N: usize = 8303;
    const N_FORCED: usize = 3; // first 3 = zero-reward credit-only updates
    const POINTS_PER: u128 = 1000;
    const STAKER_PER: u64 = 900; // 1000 reward − 10% commission
    const BASE_STAKE: u64 = 1_000_000;

    const vote_pk = Pubkey{ .data = [_]u8{0xEE} ** 32 };
    var vote_accounts = [_]VoteRewardAccumulator{.{
        .vote_account = vote_pk,
        .commission_bps = 1000, // 10%
        .epoch_credits = &.{},
    }};

    const delegations = try alloc.alloc(StakeDelegation, N);
    defer alloc.free(delegations);
    for (delegations, 0..) |*d, i| {
        var pk = [_]u8{0} ** 32;
        std.mem.writeInt(u32, pk[0..4], @intCast(i), .little);
        pk[31] = 0x5A; // keep away from all-zero
        d.* = .{
            .stake_account = .{ .data = pk },
            .vote_account = vote_pk,
            .effective_stake = 7_777, // deliberately different from raw stake:
            // the compound MUST use delegation_stake, never effective_stake
            .delegation_stake = BASE_STAKE + @as(u64, @intCast(i)),
            .activation_epoch = 1,
            .credits_observed = 50,
            .precomputed_points = .{
                .points = POINTS_PER,
                .new_credits_observed = 60 + @as(u64, @intCast(i % 7)),
                .force_credits_update_with_skipped_reward = i < N_FORCED,
            },
        };
    }

    const parent_blockhash = [_]u8{0xC7} ++ [_]u8{0x4D} ** 31;
    const sched = EpochSchedule{
        .slots_per_epoch = 432_000,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    var calc = RewardsCalculator.init(alloc);
    defer calc.deinit();
    try calc.calculateRewards(
        delegations,
        &vote_accounts,
        .{
            // total = points_sum × 1000 / points_sum = 1000 per delegation
            .validator_rewards = @intCast(POINTS_PER * N),
            .validator_rate = 0.0,
            .foundation_rate = 0.0,
            .prev_epoch_duration_in_years = 0.0,
        },
        5, // rewarded_epoch ≠ activation_epoch (else forced-zero path)
        sched,
        432_000 * 100, // any normal-epoch slot
        parent_blockhash,
    );

    // Partition count: ceil(8303/4096) = 3, from the REAL rewarded count.
    const expect_parts = getRewardDistributionNumBlocks(sched, 432_000 * 100, N);
    try std.testing.expectEqual(@as(usize, expect_parts), calc.partitions.items.len);
    try std.testing.expect(calc.partitions.items.len == 3);

    // Every entry: correct partition (SipHash13 over the parent_blockhash we
    // passed), correct compounded stake, zero-reward membership preserved.
    var seen: usize = 0;
    var seen_forced: usize = 0;
    for (calc.partitions.items, 0..) |part, pidx| {
        for (part.rewards.items) |sr| {
            seen += 1;
            const i: u64 = std.mem.readInt(u32, sr.stake_account.data[0..4], .little);
            const expect_idx = siphash13.assignPartitionIndex(
                parent_blockhash,
                sr.stake_account.data,
                @intCast(calc.partitions.items.len),
            );
            try std.testing.expectEqual(@as(usize, expect_idx), pidx);
            if (i < N_FORCED) {
                seen_forced += 1;
                try std.testing.expectEqual(@as(u64, 0), sr.staker_rewards);
                // zero reward ⇒ stake value unchanged
                try std.testing.expectEqual(BASE_STAKE + i, sr.new_delegation_stake);
            } else {
                try std.testing.expectEqual(STAKER_PER, sr.staker_rewards);
                // Defect-A wiring: raw delegation_stake + staker — NOT effective_stake
                try std.testing.expectEqual(BASE_STAKE + i + STAKER_PER, sr.new_delegation_stake);
            }
            try std.testing.expectEqual(60 + i % 7, sr.new_credits_observed);
        }
    }
    try std.testing.expectEqual(N, seen); // all delegations stored, incl. zero-reward
    try std.testing.expectEqual(N_FORCED, seen_forced);

    // Voter side: 100 lamports × 8300 rewarded (forced entries pay no voter cut).
    try std.testing.expectEqual(@as(u64, 100 * (N - N_FORCED)), vote_accounts[0].vote_rewards);
    try std.testing.expectEqual(@as(usize, 1), calc.vote_rewards.items.len);
    try std.testing.expectEqual(@as(u64, 100 * (N - N_FORCED)), calc.vote_rewards.items[0].lamports);
}
