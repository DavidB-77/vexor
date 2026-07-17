//! In-process ABANDON mutation for a cluster-confirmed cluster-SKIPPED stuck
//! repair slot — extracted from `tvu.zig:checkAndRequestRepairs` so the mutation
//! is unit-PROVEN (`zig build test-repair-abandon`), not reasoned-correct in
//! place. Same discipline as `pending_wake.zig` / `repair_escalate.zig`.
//!
//! ── The fix under test (VEX_REPAIR_SKIP_ABANDONED, default OFF) ──────────────
//! 2026-07-04 carrier: catching up, Vexor repair-wedged trying to COMPLETE a
//! cluster-SKIPPED minority-fork slot X (e.g. 196: 32 partial shreds, is_full=
//! false; the canonical chain routes …195 → …197 with 197.parent == 195, skipping
//! 196). Vexor treats the lowest incomplete in-progress slot as a MANDATORY
//! contiguous bridge → the repair loop fixates on X forever → after >5min it hits
//! the `[REPAIR-STUCK-FAILSTOP]` posix.exit(70) → the whole node goes down (the
//! 12h outage). Once the cluster oracle (`repair_escalate.clusterConfirmedSkip`)
//! CONFIRMS X is genuinely cluster-skipped, the fix ABANDONS X in-process instead
//! of fail-stopping: `abandonStuckSlot` (1) drops X from the shred assembler's
//! in-progress + repair set so it is no longer the mandatory bridge, and (2)
//! zeroes the stuck-slot escalation atomics so the NEXT repair cycle re-evaluates
//! the new lowest in-progress slot from scratch (stuck_slot := 0 guarantees
//! prev_stuck != next_slot → full re-init). Agave `RepairWeight::set_root`
//! (core/src/repair/repair_weight.rs:385) / `BankForks::prune_non_rooted`
//! (runtime/src/bank_forks.rs:659) analog.
//!
//! ── SCOPE OF THE MUTATION (proven by the KATs below — answers the unproven
//!    integration question: does abandoning X UNBLOCK descendants so the freeze-
//!    tip advances 195 → 197?) ──────────────────────────────────────────────
//! `abandonStuckSlot` mutates ONLY (a) the assembler in-progress set and (b) the
//! stuck atomics. It deliberately does NOT touch replay's `pending_chain`, and it
//! does NOT need to:
//!   • A CANONICAL descendant of the skip (197, whose RPC-AUTHORITATIVE parent is
//!     the already-FROZEN 195, NOT the skipped 196) is keyed in `pending_chain`
//!     on `target_parent == 195`. It wakes through the ordinary CHAIN-WAKE path
//!     (`pending_wake.shouldWakePending` → `frozen_set.contains(195)`) the moment
//!     any freeze fires — INDEPENDENT of X. So the freeze-tip advances 195 → 197
//!     whether or not X was abandoned. The abandon's job is purely to stop the
//!     fail-stop; it never had to unblock 195's descendants because they were
//!     NEVER keyed on / blocked by the skipped 196. (KAT: "canonical descendant".)
//!   • A `pending_chain` entry keyed on `target_parent == X` would be a
//!     NON-canonical minority-fork slot that actually chained off the skipped X.
//!     It MUST NOT advance (it is off the cluster's canonical fork). Leaving it
//!     for the `pending_chain` 5-min TTL GC reaches the SAME end state Agave's
//!     `get_non_rooted`/`prune_non_rooted` reaches eagerly (bank_forks.rs:686-700
//!     keeps only root + descendants-of-root; everything chained off a skipped
//!     slot is removed at remove(slot), bank_forks.rs:673-676). So NOT waking it
//!     is CORRECT, not a gap. (KAT: "X-keyed descendant stays parked".)
//! Net: NO orphaned-canonical-descendant correctness gap. The only residual is
//! COSMETIC — a non-canonical X-keyed entry lingers up to 5 min in `pending_chain`
//! memory (Agave prunes eagerly). If a future gate wants eager parity, add a
//! thread-safe `ReplayStage.dropPendingChainForTargetParent(X)` and call it from
//! the abandon site (see the TODO at tvu.zig's [REPAIR-SKIP-ABANDONED] block);
//! do NOT reach into `pending_chain` from the TVU repair thread.

const std = @import("std");
const shred_mod = @import("shred.zig");

/// Typed pointers to the nine stuck-slot escalation atomics on `TvuService`
/// that the abandon path zeroes. Passed by pointer so the helper mutates the
/// REAL fields in place (no copy) — byte-identical to the prior inline sequence.
pub const StuckSlotAtomics = struct {
    slot: *std.atomic.Value(u64),
    since_ns: *std.atomic.Value(i128),
    progress_ns: *std.atomic.Value(i128),
    progress_count: *std.atomic.Value(u64),
    last_hwi_rederive_ns: *std.atomic.Value(i128),
    failstop_armed_ns: *std.atomic.Value(i128),
    requests: *std.atomic.Value(u64),
    resp_count: *std.atomic.Value(u64),
    last_warn_ns: *std.atomic.Value(i128),

    /// Zero all nine atomics (.release), forcing the next repair cycle to
    /// re-init tracking for whatever the new lowest in-progress slot is
    /// (stuck_slot := 0 ⇒ prev_stuck != next_slot ⇒ full re-init).
    pub fn reset(self: StuckSlotAtomics) void {
        self.slot.store(0, .release);
        self.since_ns.store(0, .release);
        self.progress_ns.store(0, .release);
        self.progress_count.store(0, .release);
        self.last_hwi_rederive_ns.store(0, .release);
        self.failstop_armed_ns.store(0, .release);
        self.requests.store(0, .release);
        self.resp_count.store(0, .release);
        self.last_warn_ns.store(0, .release);
    }
};

/// The exact in-process ABANDON mutation for a cluster-confirmed skipped stuck
/// slot X: drop X from the shred assembler's in-progress + repair set, then zero
/// the stuck-slot escalation atomics. Byte-identical to the prior inline sequence
/// in `checkAndRequestRepairs`; the caller still logs `[REPAIR-SKIP-ABANDONED]`
/// and `continue`s past the HWI-rederive / fail-stop.
pub fn abandonStuckSlot(
    assembler: *shred_mod.ShredAssembler,
    atomics: StuckSlotAtomics,
    slot: u64,
) void {
    // (1) drop X from in-progress + repair set (also frees its held frames /
    //     copied payloads via clearCompletedSlot → deinit + fec_resolver.removeSlot).
    assembler.clearCompletedSlot(slot);
    // (2) reset stuck-slot tracking so next cycle re-evaluates the new lowest
    //     in-progress slot from scratch.
    atomics.reset();
}

// KATs live in `src/repair_abandon_kat.zig` (rooted at `src/` so the test module
// can import both `vex_network/shred.zig` and `vex_svm/pending_wake.zig`, which a
// module rooted at this file's own directory cannot). Run: `zig build
// test-repair-abandon`.
