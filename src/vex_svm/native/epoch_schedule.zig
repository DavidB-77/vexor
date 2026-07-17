//! Canonical EpochSchedule — FIX-2 (proactive-trio 2026-06-10).
//!
//! Exact port of Agave's EpochSchedule (solana-epoch-schedule-3.1.0, dep of
//! agave-4.1.0-beta.3): get_epoch / get_epoch_and_slot_index (incl. the
//! warmup doubling-epoch math) / get_first_slot_in_epoch /
//! get_leader_schedule_epoch. Firedancer: fd_epoch_schedule_t.
//!
//! LEAF MODULE ON PURPOSE: depends on std only, so it can be imported from
//! standalone test-module roots (test-vote-state-serde / test-fork-choice-
//! feed compile vote_state_serde.zig / fork_choice_feed.zig as their OWN
//! root modules — importing bank.zig from there either escapes the module
//! path or drags vex_crypto/build_options, which those targets don't wire).
//! bank.zig re-exports this struct (`bank_mod.EpochSchedule` is the SAME
//! type), so all existing call sites keep working unchanged.
//!
//! Historical context: vote_state_serde carried a local hardcoded
//! slotToEpoch whose first_normal_slot was once 524288 (canonical testnet =
//! 524256 = (2^14−1)×32). The off-by-32 mapped the first 32 slots of every
//! epoch to epoch N−1 → incrementCredits(wrong_epoch) → poisoned vote
//! epoch_credits at boundaries (epoch-972 crossing @414380256 prime
//! suspect). This struct is the single canonical source now.

const std = @import("std");

/// Agave MINIMUM_SLOTS_PER_EPOCH (solana-epoch-schedule/src/lib.rs:47).
pub const MINIMUM_SLOTS_PER_EPOCH: u64 = 32;

pub const EpochSchedule = struct {
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64,
    warmup: bool,
    first_normal_epoch: u64,
    first_normal_slot: u64,

    /// Testnet/mainnet default: warmup=true, 14 warmup epochs (32..262144
    /// slots doubling) summing to 524,256 warmup slots, then 432,000
    /// slots/epoch from epoch 14 onward. (vex-058 lineage; see bank.zig.)
    pub const DEFAULT = EpochSchedule{
        .slots_per_epoch = 432000,
        .leader_schedule_slot_offset = 432000,
        .warmup = true,
        .first_normal_epoch = 14,
        .first_normal_slot = 524256,
    };

    /// Get the epoch for a given slot.
    /// FIX-2: canonical Agave get_epoch; the warmup branch was previously a
    /// `return 0` TODO stub in bank.zig.
    pub fn getEpoch(self: *const EpochSchedule, slot: u64) u64 {
        return self.getEpochAndSlotIndex(slot).epoch;
    }

    /// Canonical port of Agave `EpochSchedule::get_epoch_and_slot_index`
    /// (solana-epoch-schedule-3.1.0/src/lib.rs:161-190). Warmup math, exact:
    ///   epoch     = tz(next_pow2(slot + MIN + 1)) − tz(MIN) − 1
    ///   epoch_len = 2^(epoch + tz(MIN))
    ///   slot_idx  = slot − (epoch_len − MIN)
    /// Agave gates the warmup branch on `slot < first_normal_slot` alone
    /// (without_warmup ⇒ fns=0 makes it unreachable); we ALSO require
    /// `self.warmup` so a hand-built {warmup=false, fns≠0} schedule can't
    /// take the warmup path — value-identical for every Agave-constructible
    /// schedule.
    pub fn getEpochAndSlotIndex(
        self: *const EpochSchedule,
        slot: u64,
    ) struct { epoch: u64, slot_index: u64 } {
        if (self.warmup and slot < self.first_normal_slot) {
            const min_tz: u6 = @intCast(@ctz(MINIMUM_SLOTS_PER_EPOCH)); // 5
            // Rust u64::next_power_of_two(n) = smallest pow2 >= n.
            const n = slot +| MINIMUM_SLOTS_PER_EPOCH +| 1;
            const np2: u64 = std.math.ceilPowerOfTwo(u64, n) catch std.math.maxInt(u64);
            const np2_tz: u64 = @ctz(np2);
            const epoch: u64 = (np2_tz -| min_tz) -| 1;
            const epoch_len: u64 = std.math.shl(u64, 1, epoch +| min_tz);
            return .{
                .epoch = epoch,
                .slot_index = slot -| (epoch_len -| MINIMUM_SLOTS_PER_EPOCH),
            };
        }
        const normal_slot_index = slot -| self.first_normal_slot;
        const normal_epoch_index = if (self.slots_per_epoch > 0)
            normal_slot_index / self.slots_per_epoch
        else
            0;
        return .{
            .epoch = self.first_normal_epoch +| normal_epoch_index,
            .slot_index = if (self.slots_per_epoch > 0)
                normal_slot_index % self.slots_per_epoch
            else
                0,
        };
    }

    /// Get the leader-schedule epoch for a given slot.
    /// (Moved verbatim from bank.zig — see its doc there for the vote-program
    /// target_epoch rationale; verified getLeaderScheduleEpoch(413005757)==969
    /// with testnet offsets.)
    pub fn getLeaderScheduleEpoch(self: *const EpochSchedule, slot: u64) u64 {
        if (self.warmup and slot < self.first_normal_slot) return 1;
        const offset = slot - self.first_normal_slot + self.leader_schedule_slot_offset;
        return self.first_normal_epoch + offset / self.slots_per_epoch;
    }

    /// Get the first slot in a given epoch.
    /// FIX-2: warmup branch ported from Agave get_first_slot_in_epoch
    /// (lib.rs:192-203): (2^e − 1) × MIN. Sanity anchor: (2^14−1)×32 =
    /// 524,256 == DEFAULT.first_normal_slot (the canonical value DERIVED).
    pub fn getFirstSlotInEpoch(self: *const EpochSchedule, epoch: u64) u64 {
        if (!self.warmup or epoch >= self.first_normal_epoch) {
            return self.first_normal_slot + (epoch - self.first_normal_epoch) * self.slots_per_epoch;
        }
        const pow: u64 = std.math.shl(u64, 1, epoch);
        return (pow -| 1) *| MINIMUM_SLOTS_PER_EPOCH;
    }

    /// Check if slot is the first slot of a new epoch (epoch boundary)
    pub fn isEpochBoundary(self: *const EpochSchedule, slot: u64) bool {
        if (slot == 0) return true;
        const epoch = self.getEpoch(slot);
        const first_slot = self.getFirstSlotInEpoch(epoch);
        return slot == first_slot;
    }

    /// Byte-faithful port of Agave `check_feature_activation`
    /// (ledger/src/shred/filter.rs:390-402). Returns true iff the feature is
    /// EFFECTIVE for `shred_slot`.
    ///
    /// CRITICAL: unlike ordinary feature flags (active at-and-after their
    /// activation slot), shred-ingest feature flags take effect ONE FULL EPOCH
    /// AFTER activation — the gate is `feature_epoch < shred_epoch`, NOT
    /// `activation_slot <= shred_slot`. This epoch delay is what prevents a
    /// fork during the activation epoch (a node that hasn't yet seen the
    /// activation and a node that has must agree on admission for the whole
    /// activation epoch; they only diverge once everyone is past it). Using a
    /// per-slot `isActive` here would over-discard during the activation epoch
    /// and CAUSE the very fork it must avoid.
    ///
    /// `activation_slot == null` (feature absent / not activated) → false (keep).
    pub fn checkFeatureActivation(
        self: *const EpochSchedule,
        activation_slot: ?u64,
        shred_slot: u64,
    ) bool {
        const act = activation_slot orelse return false;
        const feature_epoch = self.getEpoch(act);
        const shred_epoch = self.getEpoch(shred_slot);
        return feature_epoch < shred_epoch;
    }
};
