//! Switch-proof Part 2, M2 — Shape-A dead-slot REVIVE decision core (pure).
//! Design: vexor-research/design-docs/SWITCHPROOF-PART2-IMPLEMENTATION-PLAN-2026-07-16.md
//! §1.2 (dump anatomy), §2 M2 (scope), §5 (Shape-B deferred); Agave analog
//! `core/src/repair/cluster_slot_state_verifier.rs`
//! `check_duplicate_confirmed_hash_against_bank_status` (ResultingStateChange:
//! Dead→RepairDuplicateConfirmedVersion, Frozen==→DuplicateConfirmedSlotMatchesCluster,
//! Frozen!=→MarkSlotDuplicate+Repair).
//!
//! WHY A PURE LEAF (identical rationale to root_guards.zig / revive_detect.zig):
//! replay_stage.zig is an unmigrated god-file whose own inline `test` blocks
//! never run under any build target (see build.zig test-root-guards comment). So
//! the REVIVE decision — the load-bearing state machine (refuse-on-frozen / Shape-B
//! rejection, bounded-retry give-up, cluster-match escape hatch, flag-off
//! dormancy) — is factored here as a PURE function over explicit primitive inputs,
//! unit-testable standalone (`zig build test-revive-repair`), and replay_stage.zig's
//! sweep-path caller does ALL mutation (self.banks.remove under banks_lock,
//! dead_slots.remove, assembler.clearCompletedSlot, the requestHighestWindowIndex
//! kick) itself. This module never takes the live maps, never mutates, never
//! allocates, never logs — exactly like root_guards.evalRootGuards.
//!
//! THREADING NOTE (for the god-file caller, not this module): per plan §1.2, the
//! `self.banks.remove(slot)` half of the dump MUST run on the replay/sweep thread
//! under an exclusive banks_lock — NEVER the TVU repair thread. This pure core
//! carries no thread affinity; it only tells the caller WHAT to do, not from where.

const std = @import("std");

/// Local replay state of the dead slot's bank, reduced to the three cases the
/// decision needs. Mirrors Agave `BankStatus` (Unprocessed/Dead/Frozen) but
/// Shape-A-scoped: "dead" is carried separately (`ReviveInputs.is_dead`) because
/// a Vexor tick-gate/contiguity kill leaves its ABORTED bank in `self.banks`
/// unfrozen (bank_hash still all-zeros) — it is present-but-not-frozen, which is
/// exactly the Shape-A distinction from Agave's frozen-bad-bank Shape B.
pub const LocalBank = union(enum) {
    /// Not in `self.banks` at all — never created, or already dumped by a prior
    /// revive attempt. A repaired slot re-enters replay fresh from this state.
    absent,
    /// Present in `self.banks`, `is_frozen == false` — the Shape-A aborted bank
    /// left behind by a pre-freeze tick-gate/contiguity kill. The dump removes it.
    unfrozen,
    /// Present in `self.banks`, `is_frozen == true`, with this bank_hash. A dead
    /// AND frozen slot is NOT Shape A (Shape A never froze) — it is Shape B
    /// (equivocation / wrong-version), OUT of M2 scope.
    frozen: [32]u8,
};

/// All inputs the revive decision reads, gathered by the god-file caller from
/// (is_dead) `dead_slots`, (cluster_hash) the read-only SlotHashes cache via
/// `scanCachedSlotHash`, (local) `self.banks.get(slot)`+`is_frozen`, and
/// (attempt_count/max_attempts) the caller's per-slot bounded-retry map.
pub const ReviveInputs = struct {
    /// VEX_REVIVE_DEAD_SLOTS armed. Default OFF → every decision is `.no_action`
    /// (byte-identical dormant binary, the M2 deploy-safety invariant).
    flag_enabled: bool,
    /// slot ∈ dead_slots (terminal today; revive is the only path that removes it).
    is_dead: bool,
    /// The cluster's canonical bank_hash for this slot (scanCachedSlotHash result).
    /// null = the cluster has not confirmed a hash yet (cache stale at-tip, exactly
    /// why the sweep re-checks every refresh) → `.no_action` until it resolves.
    cluster_hash: ?[32]u8,
    /// State of `self.banks.get(slot)` (§ LocalBank).
    local: LocalBank,
    /// Revive attempts already spent for this slot (0 on first fire).
    attempt_count: u8,
    /// Bounded-retry ceiling. At attempt_count >= max_attempts the decision is
    /// `.give_up_exhausted` — never an unbounded dump/repair/re-fail loop.
    max_attempts: u8,
};

/// The single decision this core emits — the Vexor Shape-A analog of Agave's
/// `ResultingStateChange` set, narrowed to what M2 acts on. The caller maps each
/// to a concrete action; only `.proceed_dump_repair` and `.give_up_exhausted`
/// mutate state in M2. `.matches_cluster_no_repair` and `.refuse_not_shape_a`
/// are log-only in M2 (frozen slots are OUT of Shape-A scope) — the core still
/// distinguishes them for observability and the deferred Part 2b.
pub const ReviveDecision = enum {
    /// Nothing to do this sweep pass: flag off, slot not dead, or the cluster has
    /// not yet confirmed a hash. The overwhelmingly common case.
    no_action,
    /// Shape A: dead, unfrozen-or-absent local bank, cluster hash known, attempts
    /// remain. Caller: dump (banks.remove + clearCompletedSlot + dead_slots.remove),
    /// kick repair (requestHighestWindowIndex), bump attempt_count, let re-replay
    /// re-adjudicate through the UNMODIFIED Part-1 tick-gate/contiguity gates.
    proceed_dump_repair,
    /// Shape A but bounded-retry exhausted (repair kept returning a still-bad slot).
    /// Caller: re-insert into dead_slots PERMANENTLY (latch so no further retry) +
    /// emit [REVIVE-GAVE-UP] guardian escalation. Guarantees termination.
    give_up_exhausted,
    /// Escape hatch (plan §2 #5 / Agave DuplicateConfirmedSlotMatchesCluster): a
    /// frozen local bank whose hash already EQUALS the cluster's — our mark-dead was
    /// wrongly conservative. Caller (M2): log only; un-dead is a fork-choice touch
    /// deferred with Shape B. Present here for faithfulness + Part 2b.
    matches_cluster_no_repair,
    /// A frozen local bank whose hash does NOT match the cluster's — genuine
    /// wrong-version / equivocation = Shape B, OUT of M2 scope. Caller (M2): log
    /// [REVIVE-REFUSE-NOT-SHAPE-A] and do nothing (no dump of a frozen bank, no
    /// fork-choice mutation). Shape B recovery is the deferred Part 2b line.
    refuse_not_shape_a,
};

/// PURE decision. No allocation, no logging, no mutation. See `ReviveDecision`.
///
/// Order is load-bearing:
///  1. flag off              → no_action  (dormancy / byte-identity when disarmed)
///  2. not dead              → no_action  (only dead slots are revive candidates)
///  3. cluster hash unknown  → no_action  (can't repair toward an unknown target)
///  4. frozen local == hash  → matches_cluster_no_repair  (escape hatch)
///  5. frozen local != hash  → refuse_not_shape_a          (Shape B, deferred)
///  6. unfrozen|absent, exhausted → give_up_exhausted
///  7. unfrozen|absent, attempts remain → proceed_dump_repair
pub fn decideRevive(in: ReviveInputs) ReviveDecision {
    if (!in.flag_enabled) return .no_action;
    if (!in.is_dead) return .no_action;
    const ch = in.cluster_hash orelse return .no_action;
    switch (in.local) {
        .frozen => |h| {
            if (std.mem.eql(u8, &h, &ch)) return .matches_cluster_no_repair;
            return .refuse_not_shape_a;
        },
        .absent, .unfrozen => {
            if (in.attempt_count >= in.max_attempts) return .give_up_exhausted;
            return .proceed_dump_repair;
        },
    }
}

/// The attempt counter the caller persists AFTER a `.proceed_dump_repair` fires
/// (a dump+repair was just issued for this slot). Saturating at 255 so it can
/// never wrap back below `max_attempts` and defeat the give-up bound.
pub fn recordAttempt(prev: u8) u8 {
    return if (prev == 255) 255 else prev + 1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS — these DO run (zig build test-revive-repair): this file is its own module
// root, unlike replay_stage.zig's inline tests.
// ═══════════════════════════════════════════════════════════════════════════════

const H_A = [_]u8{0xAA} ** 32;
const H_B = [_]u8{0xBB} ** 32;

fn baseProceed() ReviveInputs {
    return .{
        .flag_enabled = true,
        .is_dead = true,
        .cluster_hash = H_A,
        .local = .unfrozen,
        .attempt_count = 0,
        .max_attempts = 3,
    };
}

test "flag OFF is total dormancy — no_action even when every other input says proceed" {
    var in = baseProceed();
    in.flag_enabled = false;
    try std.testing.expectEqual(ReviveDecision.no_action, decideRevive(in));
}

test "not-dead slot never revives (only dead_slots members are candidates)" {
    var in = baseProceed();
    in.is_dead = false;
    try std.testing.expectEqual(ReviveDecision.no_action, decideRevive(in));
}

test "dead slot with cluster hash NOT yet known → no_action (cannot repair toward unknown target)" {
    // This is the terminal-dead-guard-UNCHANGED case: a dead slot the cluster has
    // not confirmed stays dead, exactly as today. Plan §2 M2 KAT #2.
    var in = baseProceed();
    in.cluster_hash = null;
    try std.testing.expectEqual(ReviveDecision.no_action, decideRevive(in));
}

test "Shape A: dead + unfrozen + cluster hash + attempts remain → proceed_dump_repair" {
    try std.testing.expectEqual(ReviveDecision.proceed_dump_repair, decideRevive(baseProceed()));
}

test "Shape A: dead + ABSENT bank (already dumped) + cluster hash → proceed_dump_repair" {
    var in = baseProceed();
    in.local = .absent;
    try std.testing.expectEqual(ReviveDecision.proceed_dump_repair, decideRevive(in));
}

test "bounded retry: at attempt_count == max_attempts → give_up_exhausted (never loops forever)" {
    var in = baseProceed();
    in.attempt_count = 3;
    in.max_attempts = 3;
    try std.testing.expectEqual(ReviveDecision.give_up_exhausted, decideRevive(in));
}

test "bounded retry boundary: attempt_count == max_attempts - 1 still proceeds" {
    var in = baseProceed();
    in.attempt_count = 2;
    in.max_attempts = 3;
    try std.testing.expectEqual(ReviveDecision.proceed_dump_repair, decideRevive(in));
}

test "escape hatch: dead + FROZEN local whose hash == cluster → matches_cluster_no_repair" {
    var in = baseProceed();
    in.local = .{ .frozen = H_A };
    in.cluster_hash = H_A;
    try std.testing.expectEqual(ReviveDecision.matches_cluster_no_repair, decideRevive(in));
}

test "Shape-B refusal: dead + FROZEN local whose hash != cluster → refuse_not_shape_a" {
    var in = baseProceed();
    in.local = .{ .frozen = H_B };
    in.cluster_hash = H_A;
    try std.testing.expectEqual(ReviveDecision.refuse_not_shape_a, decideRevive(in));
}

test "refuse-on-frozen takes precedence over retry accounting (a frozen slot is never dumped by M2)" {
    // Even with attempts exhausted, a frozen mismatched bank is Shape B (refuse),
    // not give_up — M2 must never dump a frozen bank regardless of retry state.
    var in = baseProceed();
    in.local = .{ .frozen = H_B };
    in.attempt_count = 99;
    in.max_attempts = 3;
    try std.testing.expectEqual(ReviveDecision.refuse_not_shape_a, decideRevive(in));
}

test "recordAttempt increments and saturates at 255 (cannot wrap below the give-up bound)" {
    try std.testing.expectEqual(@as(u8, 1), recordAttempt(0));
    try std.testing.expectEqual(@as(u8, 3), recordAttempt(2));
    try std.testing.expectEqual(@as(u8, 255), recordAttempt(254));
    try std.testing.expectEqual(@as(u8, 255), recordAttempt(255));
}

test "termination proof: repeated proceed→recordAttempt reaches give_up in exactly max_attempts steps" {
    var in = baseProceed();
    in.max_attempts = 3;
    in.attempt_count = 0;
    var steps: u8 = 0;
    while (decideRevive(in) == .proceed_dump_repair) {
        in.attempt_count = recordAttempt(in.attempt_count);
        steps += 1;
        try std.testing.expect(steps <= 3); // must not exceed the bound
    }
    try std.testing.expectEqual(@as(u8, 3), steps);
    try std.testing.expectEqual(ReviveDecision.give_up_exhausted, decideRevive(in));
}
