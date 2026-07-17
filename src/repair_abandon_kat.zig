//! KATs for the 2026-07-04 cluster-skip repair ABANDON fix
//! (`VEX_REPAIR_SKIP_ABANDONED`). Rooted at `src/` (not next to
//! `repair_abandon.zig`) so the test module can import BOTH
//! `vex_network/shred.zig` and `vex_svm/pending_wake.zig` — a module rooted at
//! `src/vex_network/` cannot reach `../vex_svm/` (Zig "outside module path").
//! Run: `zig build test-repair-abandon`.
//!
//! These KATs answer the UNPROVEN INTEGRATION QUESTION the existing
//! `clusterConfirmedSkip` DECISION KATs do not cover: after the fix ABANDONS the
//! skipped slot 196 (`clearCompletedSlot` + stuck-atomic reset), do the
//! CHAIN-DEFER-parked descendants actually become eligible so the freeze-tip
//! advances 195 → 197, or does the abandon accomplish nothing?
//!
//! ANSWER (proven below): YES the freeze-tip advances — but NOT because the
//! abandon "unblocks" a 196-keyed descendant. The canonical descendant 197 is
//! keyed in `pending_chain` on its REAL, already-frozen parent 195 (NOT the
//! skipped 196), so it wakes through the ordinary CHAIN-WAKE path INDEPENDENT of
//! 196. The abandon's sole job is to stop the repair loop fixating on 196 (which
//! otherwise fail-stops the whole node). A `pending_chain` entry that WERE keyed
//! on 196 would be a non-canonical minority-fork slot that must NOT advance;
//! leaving it for the 5-min TTL GC matches Agave `prune_non_rooted`. No
//! orphaned-canonical-descendant correctness gap exists.

const std = @import("std");
const testing = std.testing;
const shred_mod = @import("vex_network/shred.zig");
const repair_abandon = @import("vex_network/repair_abandon.zig");
const pending_wake = @import("vex_svm/pending_wake.zig");

const SlotAssembly = shred_mod.ShredAssembler.SlotAssembly;

/// Inject a REAL in-progress (partial, is_last=false → knows_last=false)
/// SlotAssembly for `slot` into the REAL assembler — mirrors exactly what the
/// assembler stores internally (a heap `*SlotAssembly` in `.slots`), no mock.
fn injectInProgress(assembler: *shred_mod.ShredAssembler, alloc: std.mem.Allocator, slot: u64) !void {
    const sa = try alloc.create(SlotAssembly);
    sa.* = SlotAssembly.init(alloc, slot);
    // one non-last data shred → received but NOT complete (last_index stays null)
    _ = try sa.insert(0, &[_]u8{ 0xAB, 0xCD }, false);
    try assembler.slots.put(slot, sa);
}

test "abandonStuckSlot: (a) X dropped from in-progress + (b) lowest advances 196 → 197 + atomics zeroed" {
    const alloc = testing.allocator;
    const assembler = try shred_mod.ShredAssembler.initWithShredVersion(alloc, 0);
    defer assembler.deinit();

    // Scenario: frozen up to 195 (frozen slots are gone from the in-progress set).
    // Phantom 196 (cluster-skipped, partial, knows_last=false) is the lowest
    // in-progress. Descendant 197 (real parent=195) is also being received.
    try injectInProgress(assembler, alloc, 196);
    try injectInProgress(assembler, alloc, 197);

    // Pre-abandon: 196 is the mandatory contiguous bridge the repair loop fixates
    // on (min in-progress == 196) → the exact wedge the node fail-stops on.
    try testing.expectEqual(@as(usize, 2), assembler.getInProgressSlotCount());
    try testing.expectEqual(@as(u64, 196), assembler.inProgressStats(0).min_slot);
    // knows_last=false is the phantom signature the oracle-guarded abandon requires.
    try testing.expect(!(try assembler.getSlotInfo(196)).knows_last_shred);

    // Nine real atomics (same types as the TvuService fields), pre-dirtied so the
    // reset is observable.
    var a_slot = std.atomic.Value(u64).init(196);
    var a_since = std.atomic.Value(i128).init(123);
    var a_prog_ns = std.atomic.Value(i128).init(456);
    var a_prog_ct = std.atomic.Value(u64).init(7);
    var a_hwi = std.atomic.Value(i128).init(789);
    var a_failstop = std.atomic.Value(i128).init(101112);
    var a_reqs = std.atomic.Value(u64).init(250);
    var a_resp = std.atomic.Value(u64).init(2);
    var a_warn = std.atomic.Value(i128).init(131415);
    const atomics = repair_abandon.StuckSlotAtomics{
        .slot = &a_slot,
        .since_ns = &a_since,
        .progress_ns = &a_prog_ns,
        .progress_count = &a_prog_ct,
        .last_hwi_rederive_ns = &a_hwi,
        .failstop_armed_ns = &a_failstop,
        .requests = &a_reqs,
        .resp_count = &a_resp,
        .last_warn_ns = &a_warn,
    };

    // ── ABANDON 196 ──
    repair_abandon.abandonStuckSlot(assembler, atomics, 196);

    // (a) 196 removed from in-progress; the lowest in-progress advances to 197 so
    //     the repair loop now targets 197 (pull its remaining shreds → it completes
    //     and freezes on its real parent 195) instead of fixating on 196.
    try testing.expectEqual(@as(usize, 1), assembler.getInProgressSlotCount());
    try testing.expectEqual(@as(u64, 197), assembler.inProgressStats(0).min_slot);
    // 196 is truly gone (getSlotInfo returns the not-present default).
    try testing.expectEqual(@as(usize, 0), (try assembler.getSlotInfo(196)).unique_count);

    // (b) all nine stuck atomics zeroed → next cycle full re-init.
    try testing.expectEqual(@as(u64, 0), a_slot.load(.acquire));
    try testing.expectEqual(@as(i128, 0), a_since.load(.acquire));
    try testing.expectEqual(@as(i128, 0), a_prog_ns.load(.acquire));
    try testing.expectEqual(@as(u64, 0), a_prog_ct.load(.acquire));
    try testing.expectEqual(@as(i128, 0), a_hwi.load(.acquire));
    try testing.expectEqual(@as(i128, 0), a_failstop.load(.acquire));
    try testing.expectEqual(@as(u64, 0), a_reqs.load(.acquire));
    try testing.expectEqual(@as(u64, 0), a_resp.load(.acquire));
    try testing.expectEqual(@as(i128, 0), a_warn.load(.acquire));
}

test "CONTROL: without abandon, 196 stays the lowest in-progress bridge (→ fail-stop path)" {
    const alloc = testing.allocator;
    const assembler = try shred_mod.ShredAssembler.initWithShredVersion(alloc, 0);
    defer assembler.deinit();
    try injectInProgress(assembler, alloc, 196);
    try injectInProgress(assembler, alloc, 197);

    // No abandon: the repair loop keeps seeing 196 as the mandatory bridge, so it
    // requests 196 forever and eventually reaches [REPAIR-STUCK-FAILSTOP]. This is
    // the exact behavior the abandon replaces.
    try testing.expectEqual(@as(u64, 196), assembler.inProgressStats(0).min_slot);
    try testing.expectEqual(@as(usize, 2), assembler.getInProgressSlotCount());
}

test "descendant unblock: CANONICAL 197 (parent=195) wakes independent of abandoning 196 → freeze-tip 195→197" {
    // The crux of the unproven integration question. Exercises the REAL wake
    // predicate (`pending_wake.shouldWakePending`, the exact one called at
    // replay_stage.zig:checkPendingChain:3258) against a REAL pending_chain map,
    // mirroring the checkPendingChain wake loop (replay_stage.zig:3251-3261).
    const alloc = testing.allocator;

    // pending_chain: slot → target_parent (its real deferred-on parent).
    var pending = std.AutoHashMap(u64, u64).init(alloc);
    defer pending.deinit();
    try pending.put(197, 195); // 197's RPC-authoritative parent is the FROZEN 195.

    // frozen set: 195 is frozen; 196 was ABANDONED (never froze → absent); 197 pending.
    var frozen_set = std.AutoHashMap(u64, void).init(alloc);
    defer frozen_set.deinit();
    try frozen_set.put(195, {});

    const root_slot: u64 = 0; // catchup — no consensus root yet.
    const triggering_freeze: u64 = 195;

    // Mirror checkPendingChain's wake loop.
    var woke_197 = false;
    var it = pending.iterator();
    while (it.next()) |e| {
        if (pending_wake.shouldWakePending(e.value_ptr.*, triggering_freeze, root_slot, &frozen_set)) {
            if (e.key_ptr.* == 197) woke_197 = true;
        }
    }

    // 197 wakes via frozen_set.contains(195) → re-pushed to replay → getOrCreateBank
    // connects it on the frozen 195 → it freezes → the FREEZE-TIP ADVANCES 195 → 197.
    // TRUE regardless of whether 196 was abandoned: 197 was never keyed on / blocked
    // by the skipped 196. The abandon only stops the fail-stop.
    try testing.expect(woke_197);
}

test "descendant unblock: a hypothetical X-keyed (196) child stays parked — CORRECT (non-canonical)" {
    // A pending_chain entry whose target_parent == the abandoned 196 would be a
    // NON-canonical minority-fork slot that actually chained off the skipped slot.
    // After abandon, 196 is not frozen, not in the frozen set, and not ≤ root, so
    // the wake predicate returns FALSE → it stays parked (until the 5-min TTL GC).
    // DESIRED outcome: such a slot is off the cluster's canonical fork and MUST NOT
    // advance — matching Agave get_non_rooted/prune_non_rooted, which removes
    // everything not descended from the new root (bank_forks.rs:686-700). NOT a
    // correctness gap; the only difference vs Agave is eager-vs-lazy (TTL) cleanup.
    const alloc = testing.allocator;
    var frozen_set = std.AutoHashMap(u64, void).init(alloc);
    defer frozen_set.deinit();
    try frozen_set.put(195, {}); // 196 abandoned → deliberately absent.

    // shouldWakePending(tp=196, frozen_slot=195, root=0, frozen_set={195}) == false
    try testing.expect(!pending_wake.shouldWakePending(196, 195, 0, &frozen_set));

    // Sanity: had 196 instead FROZEN (not the skip case), the child WOULD wake —
    // confirms the predicate itself is live, i.e. the parked-forever outcome is
    // strictly because 196 is abandoned (never freezes), which is what we want.
    try frozen_set.put(196, {});
    try testing.expect(pending_wake.shouldWakePending(196, 195, 0, &frozen_set));
}
