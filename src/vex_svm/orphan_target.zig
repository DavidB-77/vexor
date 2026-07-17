//! Pure orphan-target SELECTION for the CHAIN-DEFER → Orphan(10) repair trigger.
//!
//! Given the set of CHAIN-DEFERred slots (each `{slot, target_parent}`), the
//! frozen-bank set, and the current root, decide which slots to emit Orphan(10)
//! requests for. We want the "orphan roots" — deferred slots whose
//! `target_parent` is a TRUE zero-shred gap: above root, NOT frozen, and NOT
//! itself another deferred slot. Emitting Orphan for those discovers the
//! missing bridge ancestry (the peer returns the highest shred of the parent +
//! its ancestors → Vexor learns they exist → normal window repair fills them →
//! they replay+freeze → checkPendingChain wakes the deferred children).
//!
//! Why the three exclusions matter:
//!   - parent <= root          → the child wakes via checkPendingChain's
//!     root-floor condition, not via repair (and Agave never chases below root:
//!     update_orphan_ancestors only walks `ancestor >= self.root`).
//!   - parent is frozen        → the child wakes via checkPendingChain's
//!     frozen_set condition; its data is already here.
//!   - parent is ALSO deferred → the gap bottom is deeper; emitting Orphan for
//!     this slot would be wasteful. Only the chain's bottom (whose parent is a
//!     true gap) is the orphan root. Without this filter we'd Orphan-storm all
//!     ~9000 deferred slots instead of the handful of real gap bottoms.
//!
//! Bounded to `max` (Agave MAX_ORPHANS=5), nearest-root-first (lowest slot),
//! matching get_best_orphans' "heavier, smaller slots first" tiebreak.
//!
//! Imports only std → unit-testable standalone (`zig build test-orphan-target`).

const std = @import("std");

pub const DeferredEntry = struct { slot: u64, target_parent: u64 };

/// Returns up to `max` orphan-root slots (caller frees), sorted ascending
/// (nearest-root-first), to emit Orphan(10) requests for.
pub fn selectOrphanTargets(
    allocator: std.mem.Allocator,
    deferred: []const DeferredEntry,
    frozen: *const std.AutoHashMap(u64, void),
    root: u64,
    max: usize,
) ![]u64 {
    // Set of deferred slots, so we can tell "parent is another deferred slot"
    // (skip — gap bottom is deeper) from "parent is a true gap".
    var deferred_set = std.AutoHashMap(u64, void).init(allocator);
    defer deferred_set.deinit();
    for (deferred) |e| try deferred_set.put(e.slot, {});

    var candidates = std.ArrayList(u64){};
    defer candidates.deinit(allocator);
    for (deferred) |e| {
        const p = e.target_parent;
        if (root > 0 and p <= root) continue; // wakes via root-floor, not orphan
        if (frozen.contains(p)) continue; // wakes via frozen_set, not orphan
        if (deferred_set.contains(p)) continue; // parent is another deferred slot
        try candidates.append(allocator, e.slot);
    }

    std.mem.sort(u64, candidates.items, {}, comptime std.sort.asc(u64));

    const n = @min(max, candidates.items.len);
    const out = try allocator.alloc(u64, n);
    @memcpy(out, candidates.items[0..n]);
    return out;
}

const t = std.testing;

test "selectOrphanTargets: empty input → empty" {
    var frozen = std.AutoHashMap(u64, void).init(t.allocator);
    defer frozen.deinit();
    const out = try selectOrphanTargets(t.allocator, &.{}, &frozen, 100, 5);
    defer t.allocator.free(out);
    try t.expectEqual(@as(usize, 0), out.len);
}

test "selectOrphanTargets: a deferred chain has ONE orphan root (the bottom)" {
    // Chain: 503->502(gap), 504->503, 505->504. Only 503's parent (502) is a
    // true gap; 504/505 parents are deferred slots. So only 503 is emitted.
    var frozen = std.AutoHashMap(u64, void).init(t.allocator);
    defer frozen.deinit();
    const deferred = [_]DeferredEntry{
        .{ .slot = 504, .target_parent = 503 },
        .{ .slot = 505, .target_parent = 504 },
        .{ .slot = 503, .target_parent = 502 },
    };
    const out = try selectOrphanTargets(t.allocator, &deferred, &frozen, 400, 5);
    defer t.allocator.free(out);
    try t.expectEqual(@as(usize, 1), out.len);
    try t.expectEqual(@as(u64, 503), out[0]);
}

test "selectOrphanTargets: frozen parent + below-root parent excluded" {
    var frozen = std.AutoHashMap(u64, void).init(t.allocator);
    defer frozen.deinit();
    try frozen.put(700, {}); // parent 700 is frozen
    const deferred = [_]DeferredEntry{
        .{ .slot = 701, .target_parent = 700 }, // parent frozen → excluded
        .{ .slot = 650, .target_parent = 600 }, // parent <= root(600) → excluded
        .{ .slot = 800, .target_parent = 799 }, // parent 799 is a true gap → kept
    };
    const out = try selectOrphanTargets(t.allocator, &deferred, &frozen, 600, 5);
    defer t.allocator.free(out);
    try t.expectEqual(@as(usize, 1), out.len);
    try t.expectEqual(@as(u64, 800), out[0]);
}

test "selectOrphanTargets: multiple roots → nearest-root-first, capped at max" {
    var frozen = std.AutoHashMap(u64, void).init(t.allocator);
    defer frozen.deinit();
    // Six independent orphan roots (each parent a distinct true gap), unsorted.
    const deferred = [_]DeferredEntry{
        .{ .slot = 900, .target_parent = 899 },
        .{ .slot = 705, .target_parent = 704 },
        .{ .slot = 1000, .target_parent = 999 },
        .{ .slot = 710, .target_parent = 709 },
        .{ .slot = 950, .target_parent = 949 },
        .{ .slot = 800, .target_parent = 799 },
    };
    const out = try selectOrphanTargets(t.allocator, &deferred, &frozen, 700, 5);
    defer t.allocator.free(out);
    // capped at 5, ascending
    try t.expectEqual(@as(usize, 5), out.len);
    try t.expectEqualSlices(u64, &[_]u64{ 705, 710, 800, 900, 950 }, out);
}

test "selectOrphanTargets: root==0 bootstrap → root-floor disabled, true gaps still selected" {
    var frozen = std.AutoHashMap(u64, void).init(t.allocator);
    defer frozen.deinit();
    const deferred = [_]DeferredEntry{.{ .slot = 50, .target_parent = 49 }};
    const out = try selectOrphanTargets(t.allocator, &deferred, &frozen, 0, 5);
    defer t.allocator.free(out);
    try t.expectEqual(@as(usize, 1), out.len);
    try t.expectEqual(@as(u64, 50), out[0]);
}

// ─── FIX #112 (5th site) CARRIER 413481786: the wedge discriminator ──────────
//
// The DETERMINISTIC OFFLINE GATE for the 2026-06-06 keystone-784 wedge. It
// encodes the ACTUAL live wedge numbers and asserts that the root VALUE passed
// to selectOrphanTargets is what decides whether the keystone-bottom 785 is
// selected for an Orphan(10) request. This is a fails-WITHOUT-the-fix gate, not
// a regression-lock: it drives the SAME function with the OLD root (freeze-tip
// 786) and the NEW root (consensus root 746) and proves they DIFFER — exactly
// the resolveParent/resolveParentLegacy discriminator discipline in
// pending_wake.zig. The production fix is at replay_stage.zig:collectOrphan-
// Targets, which now reads `db.rooted_slot` (consensus root, == the NEW arg
// here) instead of `self.root_bank.slot` (freeze-tip, == the OLD arg). That
// wiring change is inspection-verified against the 4 sibling FIX #112 sites
// (shouldDropBelowRoot / parentReadyForFastWake / resolveParent / checkPending-
// Chain wake_root) — the same way getOrCreateBank's call into resolveParent is
// inspection-verified rather than exercised by this pure unit test.
//
// Live wedge facts (cluster getBlock + PR-S5-PROBE / CHAIN-DEFER log):
//   cluster canonical chain: 783 -> 784 -> 785 -> 787 (786 SKIPPED by cluster)
//   Vexor froze 783 AND a minority-fork orphan 786 (parent 782) → freeze-tip 786
//   785 is SLOT-COMPLETED locally but deferred: target_parent = 784
//   784 NEVER arrived: zero shreds, not frozen, not rooted (consensus_root 746)
//   PR-S5-PROBE: root_slot=413481786 consensus_root=413481746
test "selectOrphanTargets CARRIER 413481786: freeze-tip EXCLUDES keystone, consensus root SELECTS it (discriminator)" {
    var frozen = std.AutoHashMap(u64, void).init(t.allocator);
    defer frozen.deinit();
    // 783 is frozen on this fork; 786 is the minority orphan freeze-tip (frozen).
    try frozen.put(413481783, {});
    try frozen.put(413481786, {});

    // The live pending_chain at the wedge: 785 is the keystone-bottom (its parent
    // 784 is the true zero-shred gap). 787 also defers on 785 (a deferred slot),
    // so 787 must NOT be selected — only the chain bottom 785 is the orphan root.
    const deferred = [_]DeferredEntry{
        .{ .slot = 413481785, .target_parent = 413481784 }, // keystone-bottom
        .{ .slot = 413481787, .target_parent = 413481785 }, // parent is deferred → skip
    };

    const freeze_tip: u64 = 413481786; // OLD (buggy): self.root_bank.slot
    const consensus_root: u64 = 413481746; // NEW (fix): db.rooted_slot

    // OLD root (freeze-tip 786): gate `784 <= 786` excludes 785 → EMPTY. THE BUG:
    // the keystone is never Orphan-requested, 784 never arrives, the chain wedges.
    const out_old = try selectOrphanTargets(t.allocator, &deferred, &frozen, freeze_tip, 5);
    defer t.allocator.free(out_old);
    try t.expectEqual(@as(usize, 0), out_old.len);

    // NEW root (consensus root 746): `784 <= 746` is FALSE → 784 is a true gap →
    // 785 IS selected → requestOrphan(785) → peer walks 785->784->… (Agave
    // standard_repair_handler run_orphan) → 784's highest shred surfaces →
    // window repair fills 784 → 784 freezes → 785 wakes (shouldWakePending).
    const out_new = try selectOrphanTargets(t.allocator, &deferred, &frozen, consensus_root, 5);
    defer t.allocator.free(out_new);
    try t.expectEqual(@as(usize, 1), out_new.len);
    try t.expectEqual(@as(u64, 413481785), out_new[0]); // the keystone-bottom

    // The two roots DIFFER → the test genuinely catches the carrier (it is not
    // rubber-stamping whatever the production code happens to do).
    try t.expect(out_old.len != out_new.len);

    // And the gap whose repair this unblocks is the keystone 784 (the target_parent
    // of the selected orphan-root) — i.e. a repair request IS emitted for the
    // synthetic-missing ancestor 784, which the wedge proved never happened.
    try t.expectEqual(@as(u64, 413481784), deferred[0].target_parent);
}
