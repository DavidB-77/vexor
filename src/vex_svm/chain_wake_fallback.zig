//! chain_wake_fallback.zig — pure CHAIN-WAKE fallback decision for the
//! CHAIN-DEFER continuation self-heal (fix/chain-defer-tip-guard, liveness wedge
//! @422050470, 2026-07-15). RCA: forensics/incident-wedge-422050470/RCA-DATA.md.
//!
//! ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
//! When the CHAIN-DEFER GC backstop evicts a deferred slot whose parent has NOT
//! yet frozen, replay loses the "resume here" pointer for that child. In the
//! @422050470 wedge the direct child of the freeze tip (422052441) was evicted
//! 2,374 log lines before its parent (422052440) froze; when the parent froze
//! there was no live defer entry to fire CHAIN-WAKE, replay had nothing to
//! schedule, and the node self-decapitated (watchdog exit, 5h47m dead).
//!
//! The tip-aware backstop (pending_chain_gc.backstopEligible) PREVENTS the
//! near-tip eviction. This fallback is the independent SELF-HEAL: on every bank
//! freeze, for each slot we PREVIOUSLY EVICTED whose parent is the just-frozen
//! slot, decide what to do. Keying on the recorded eviction set (not on "did a
//! child wake?") makes the check precise and cost-free in healthy operation
//! (the set is empty) — a healthy fast-waked continuation is never in it, so no
//! block is ever needlessly re-derived.
//!
//! Pure over its boolean inputs ⟹ KAT-able without a live ReplayStage (which,
//! like bank.zig, cannot be a `zig build test` root). The replay_stage.zig
//! caller supplies the two facts and executes the returned action.

const std = @import("std");

pub const Action = enum {
    /// The evicted child already recovered on its own (it is now frozen, or it
    /// came back into the defer map / replay queue). Nothing to do beyond
    /// dropping the stale eviction record.
    recovered,
    /// The child's block is STILL fully held in the shred assembler — re-derive
    /// its bytes and re-enqueue for replay (its parent just froze). Self-heal.
    reenqueue,
    /// The child's block is no longer re-derivable in-process — request it via
    /// the normal repair path so it can be re-fetched and replayed.
    repair,
};

/// Decide the CHAIN-WAKE fallback action for an evicted child whose parent just
/// froze.
///   - `frozen_or_deferred`: the child is already frozen, OR already back in the
///     defer map / replay queue (it recovered without our help).
///   - `completed_in_assembler`: the child's shreds are still fully held
///     (is_complete) so its bytes can be re-derived and re-enqueued.
/// Precedence: recovery wins (never re-touch a slot that healed); else re-enqueue
/// if the bytes survive; else repair.
pub fn decide(frozen_or_deferred: bool, completed_in_assembler: bool) Action {
    if (frozen_or_deferred) return .recovered;
    if (completed_in_assembler) return .reenqueue;
    return .repair;
}

// ════════════════════════════════════════════════════════════════════════════
// KATs — `zig build test-chain-wake-fallback`
// ════════════════════════════════════════════════════════════════════════════

test "KAT (c): freeze-with-missing-child, bytes still in assembler → re-enqueue (the @422052441 self-heal)" {
    // The exact incident: child 422052441 was GC-evicted, is NOT frozen and NOT
    // back in the defer map, but its completed SlotAssembly still holds the block.
    try std.testing.expectEqual(Action.reenqueue, decide(false, true));
}

test "KAT (d): freeze-with-child-truly-absent (assembly gone) → repair request" {
    // Evicted AND the assembler no longer holds the block → cannot self-heal in
    // process; the normal repair path must re-fetch it.
    try std.testing.expectEqual(Action.repair, decide(false, false));
}

test "KAT (e): child recovered on its own → recovered (no re-derivation, no repair)" {
    // Already frozen or already re-deferred/queued: recovery ALWAYS wins, even if
    // the assembler still happens to hold the (now redundant) bytes. This is what
    // makes a healthy fast-waked continuation cost-free — it is never re-derived.
    try std.testing.expectEqual(Action.recovered, decide(true, true));
    try std.testing.expectEqual(Action.recovered, decide(true, false));
}

test "decision is a total function over the 2x2 boolean grid" {
    try std.testing.expectEqual(Action.recovered, decide(true, true));
    try std.testing.expectEqual(Action.recovered, decide(true, false));
    try std.testing.expectEqual(Action.reenqueue, decide(false, true));
    try std.testing.expectEqual(Action.repair, decide(false, false));
}
