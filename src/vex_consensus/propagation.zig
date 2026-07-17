//! Agave propagation-confirmation — the canonical signal behind `can_vote_on_candidate_bank`'s
//! `propagation_confirmed` gate (core/src/consensus/fork_choice.rs:370). Port of the consensus-essential
//! pieces of Agave `PropagatedStats` (core/src/consensus/progress_map.rs:221) +
//! `update_slot_propagated_threshold_from_votes` (core/src/replay_stage.rs:4301).
//!
//! WHY (task #93): the #92 prop-gate PROXY checked the candidate's OWN subtree stake, per-slot,
//! NON-latching — so at an epoch boundary (slot 418268256, epoch-981/SIMD-0449, 2026-06-27) the new
//! epoch's slots read 0 stake until votes re-accumulated → it WITHHELD every vote → vote-wedge.
//! Agave is boundary-robust for two reasons this module ports EXACTLY:
//!   1. LEADER-WINDOW indirection — propagation is tracked at the leader-window START slot
//!      (4 consecutive slots per leader, NUM_CONSECUTIVE_LEADER_SLOTS), not per-tip.
//!   2. LATCH — once a window's accumulated voter-stake exceeds 1/3 (SUPERMINORITY_THRESHOLD, strict),
//!      `is_propagated` is set TRUE and NEVER cleared (Agave replay_stage.rs:4317-4318/4357-4361).
//! Fed by Vexor's existing fork_choice subtree stake (ForkInfo.stake_voted_subtree, the same
//! per-validator vote ingestion that already drives heaviest-fork choice) — NOT a foreign VoteTracker
//! graft. A byte-faithful gossip SlotVoteTracker (sig-verified) is a later refinement tied to #41.

const std = @import("std");
const core = @import("core");
const Slot = core.Slot;

/// Agave `SUPERMINORITY_THRESHOLD: f64 = 1/3` (core/src/replay_stage.rs:112). We avoid float:
/// `stake/total > 1/3`  ⇔  `stake*3 > total` (strict, matches Agave's `>`).
pub const SUPERMINORITY_DEN: u64 = 3;

/// Agave `NUM_CONSECUTIVE_LEADER_SLOTS` (leader-schedule/src/lib.rs:20) — 4 consecutive slots/leader.
pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;

/// Leader-window START slot for `slot`, given the slot's epoch first slot. Leader windows are aligned
/// to NUM_CONSECUTIVE_LEADER_SLOTS within the epoch (slot_index = slot - epoch_first; window =
/// floor(slot_index/4)*4). At an epoch boundary the first window starts exactly at epoch_first_slot,
/// so the boundary slot is its own window's leader slot.
pub fn leaderWindowStart(slot: Slot, epoch_first_slot: Slot) Slot {
    if (slot < epoch_first_slot) return slot; // defensive (shouldn't happen)
    const idx = slot - epoch_first_slot;
    return slot - (idx % NUM_CONSECUTIVE_LEADER_SLOTS);
}

/// `stake/total > 1/3` without floats (strict, Agave parity). total==0 ⇒ false (no epoch-stake view).
pub fn exceedsSuperminority(stake: u64, total: u64) bool {
    if (total == 0) return false;
    // stake*3 > total — guard overflow: stakes are lamports (< 2^63 for testnet total ~2.9e17), *3 fits u128.
    return @as(u128, stake) * SUPERMINORITY_DEN > @as(u128, total);
}

/// Latching propagation map keyed by leader-window-START slot. Presence ⇒ propagated (latched true).
pub const PropagationMap = struct {
    propagated: std.AutoHashMapUnmanaged(Slot, void) = .{},
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PropagationMap {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PropagationMap) void {
        self.propagated.deinit(self.allocator);
    }

    /// Observe a leader window's accumulated fork voter-stake. LATCHES is_propagated once it exceeds
    /// 1/3 of total epoch stake; idempotent and monotonic (never un-latches). Agave
    /// update_slot_propagated_threshold_from_votes:4317/4357.
    pub fn observe(self: *PropagationMap, window_start: Slot, subtree_stake: u64, total_stake: u64) !void {
        if (self.propagated.contains(window_start)) return; // already latched
        if (exceedsSuperminority(subtree_stake, total_stake))
            try self.propagated.put(self.allocator, window_start, {});
    }

    /// Latched is_propagated for a leader-window-start slot.
    pub fn isPropagated(self: *const PropagationMap, window_start: Slot) bool {
        return self.propagated.contains(window_start);
    }

    /// Drop windows strictly below `root` (call on root advance to bound memory). The root and all
    /// ancestors are implicitly propagated (rooted ⇒ supermajority-confirmed), so dropping is safe.
    pub fn pruneBelow(self: *PropagationMap, root: Slot) void {
        var it = self.propagated.iterator();
        var to_drop: [256]Slot = undefined;
        var n: usize = 0;
        while (it.next()) |e| {
            if (e.key_ptr.* < root and n < to_drop.len) {
                to_drop[n] = e.key_ptr.*;
                n += 1;
            }
        }
        for (to_drop[0..n]) |s| _ = self.propagated.remove(s);
    }

    pub fn count(self: *const PropagationMap) usize {
        return self.propagated.count();
    }
};

// ───────────────────────────── KAT (RULE #15 boot-time gate) ─────────────────────────────
test "leaderWindowStart aligns to 4-slot windows from epoch first slot (incl boundary)" {
    const ef: Slot = 418268256; // epoch-981 first slot
    try std.testing.expectEqual(@as(Slot, 418268256), leaderWindowStart(418268256, ef)); // window [256..259]
    try std.testing.expectEqual(@as(Slot, 418268256), leaderWindowStart(418268257, ef));
    try std.testing.expectEqual(@as(Slot, 418268256), leaderWindowStart(418268259, ef));
    try std.testing.expectEqual(@as(Slot, 418268260), leaderWindowStart(418268260, ef)); // next window
    try std.testing.expectEqual(@as(Slot, 418268260), leaderWindowStart(418268263, ef));
}

test "exceedsSuperminority is strict 1/3 (Agave parity)" {
    try std.testing.expect(!exceedsSuperminority(100, 0)); // no stake view
    try std.testing.expect(!exceedsSuperminority(100, 300)); // exactly 1/3 is NOT > 1/3
    try std.testing.expect(exceedsSuperminority(101, 300)); // just over
    try std.testing.expect(exceedsSuperminority(2, 3)); // 2/3
    // no overflow at testnet scale
    try std.testing.expect(exceedsSuperminority(100_000_000_000_000_000, 290_000_000_000_000_000));
}

test "PropagationMap latches and never un-latches (boundary-robustness invariant)" {
    var pm = PropagationMap.init(std.testing.allocator);
    defer pm.deinit();
    const ws: Slot = 418268256;
    try std.testing.expect(!pm.isPropagated(ws));
    // below threshold → not yet propagated (the brief boundary withhold)
    try pm.observe(ws, 90, 300);
    try std.testing.expect(!pm.isPropagated(ws));
    // crosses 1/3 → latches
    try pm.observe(ws, 105, 300);
    try std.testing.expect(pm.isPropagated(ws));
    // LATCH: a later under-threshold observation must NOT clear it (this is the fix vs the per-slot proxy)
    try pm.observe(ws, 0, 300);
    try std.testing.expect(pm.isPropagated(ws));
}

test "pruneBelow root bounds memory, keeps >= root" {
    var pm = PropagationMap.init(std.testing.allocator);
    defer pm.deinit();
    try pm.observe(100, 2, 3);
    try pm.observe(200, 2, 3);
    try pm.observe(300, 2, 3);
    pm.pruneBelow(200);
    try std.testing.expect(!pm.isPropagated(100));
    try std.testing.expect(pm.isPropagated(200));
    try std.testing.expect(pm.isPropagated(300));
}
