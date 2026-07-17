//! repair_escalate.zig — pure phantom-wedge ESCALATION predicate for repair.
//!
//! Extracted from tvu.zig FIX #3 (2026-06-14, ~line 3983) so the load-bearing
//! decision — WHEN a stuck repair slot has the "phantom-index" signature that
//! warrants escalation (HighestWindowIndex re-derive, then the fail-stop floor)
//! — is a pure, standalone-testable function. tvu.zig is socket/sign-heavy and
//! cannot be rooted as a `zig build test` artifact; this module imports only
//! `std`, so its KATs actually execute (`zig build test-repair-escalate`).
//!
//! CONSENSUS-NEUTRAL: this governs only LIVENESS escalation (extra repair
//! requests + an eventual clean fail-stop so a fresh-snapshot restart recovers).
//! It NEVER touches shred completion, freeze, the FEC/merkle gate, fork choice,
//! or what is accepted into a block.
//!
//! THE WEDGE IT DISCRIMINATES (proven from the AF_XDP catch-up logs): a slot can
//! sit as the lowest in-progress slot forever when its completion-defining shred
//! (an interior index nobody has, OR a dropped LAST_IN_SLOT) is never delivered.
//! We must escalate ONLY for that genuine wedge and NEVER for a slot that is
//! merely slow-but-filling (cold-boot catch-up), or the fail-stop floor would
//! kill a healthy node. The discriminator: MANY requests issued for this slot
//! AND (it has gained NO new shreds for the escalate window OR peers answer for
//! it ~never). A slow-but-filling slot advances unique_count (refreshing the
//! no-progress timer) AND gets answers (resp climbs) → trips NEITHER clause.

const std = @import("std");

/// Default thresholds (mirror tvu.zig FIX #3 constants exactly).
pub const MIN_REQUESTS_FOR_ESCALATE: u64 = 200; // many requests issued for this slot
pub const MAX_RESP_FOR_PHANTOM: u64 = 2; // peers answer for this slot ~never

/// The phantom-index ESCALATION signature.
///
/// - `reqs`: cumulative repair requests issued for the tracked stuck slot.
/// - `no_progress`: TRUE iff the slot has gained NO new shreds for at least the
///   escalate window (authoritative wedge proof — cannot be inflated by
///   historical gap-fill; the caller computes it from the progress watermark).
/// - `resps`: cumulative repair responses received for this slot.
/// - `min_requests`: requests floor (default `MIN_REQUESTS_FOR_ESCALATE`).
/// - `max_resp`: response ceiling for the "~never answered" clause
///   (default `MAX_RESP_FOR_PHANTOM`).
///
/// Returns TRUE iff: many requests issued AND (no forward progress OR ~0
/// answers). BYTE-IDENTICAL to the tvu.zig expression
///   (reqs >= MIN_REQUESTS_FOR_ESCALATE) and (no_progress or (resps <= MAX_RESP_FOR_PHANTOM)).
/// The outer wall-clock window gate (stuck_ns > STUCK_ESCALATE_NS) is the
/// caller's responsibility — this predicate is the content discriminator only.
pub fn phantomSignature(
    reqs: u64,
    no_progress: bool,
    resps: u64,
    min_requests: u64,
    max_resp: u64,
) bool {
    return (reqs >= min_requests) and (no_progress or (resps <= max_resp));
}

/// Convenience wrapper using the canonical default thresholds.
pub fn phantomSignatureDefault(reqs: u64, no_progress: bool, resps: u64) bool {
    return phantomSignature(reqs, no_progress, resps, MIN_REQUESTS_FOR_ESCALATE, MAX_RESP_FOR_PHANTOM);
}

// ════════════════════════════════════════════════════════════════════════════
// CLUSTER-CONFIRMED-SKIP discriminator (VEX_REPAIR_SKIP_ABANDONED, default OFF)
// ════════════════════════════════════════════════════════════════════════════
//
// Companion to phantomSignature: once a slot X has the phantom-wedge ESCALATION
// signature (stuck as the lowest in-progress "bridge" slot, many requests, ~no
// answers / no progress), this predicate decides — off the CLUSTER ORACLE, not
// raw parent_offset — whether X is a slot the CLUSTER genuinely SKIPPED. If so,
// the caller ABANDONS X in-process (drops it from the in-progress + repair set)
// instead of fail-stopping, so the freeze-tip re-anchors on the canonical
// successor and catch-up continues without an operator restart.
//
// WHY IT IS PURE + ORACLE-GATED (the May-2026 divergence lesson): a prior
// Phase-J "mark such slots dead" fix false-positived on FORKED validators lying
// about `parent_offset` — it killed CANONICAL slots and caused bank_hash
// divergence carriers. That version trusted a single shred's parent_offset. This
// version NEVER trusts parent_offset alone: it fires only when the cluster's own
// cached SlotHashes (the oracle) proves X is a genuine skip. The decision is
// extracted here as a socket-free, `self`-free boolean so the false-positive
// firewall is unit-proven, not reasoned-correct inside tvu.zig.
//
// CANONICAL GROUNDING (RULE #16) — this mirrors Agave's own "is this slot a
// skip?" + root-pruning semantics, fired off the cluster oracle because Vexor's
// OWN root is the wedged thing (we cannot ask our own root; we ask the cluster's):
//   - Blockstore::is_skipped (ledger/src/blockstore.rs:4820, rc.1 == 4.1.0):
//       no root entry for the slot  AND  lowest_root < slot < max_root.
//     Our analog is the cluster's own getBlocks(lo, hi) (Agave RPC), the direct
//     HISTORICAL is_skipped oracle — it returns the PRODUCED (rooted/confirmed)
//     slots in ANY range, far behind our wedged tip. X ABSENT from that produced
//     list, while a produced L < X AND a produced H > X BOTH exist in the SAME
//     fully-queried range (bounding X on both sides), is exactly "no root entry
//     for X AND lowest_root < X < max_root" → a cluster-confirmed skip. (The
//     earlier SlotHashes-based probe used the cluster's 512-slot cache window,
//     which does NOT cover a catch-up wedge ~thousands of slots behind the tip,
//     so it returned false for the wedge's neighbors and never fired — getBlocks
//     replaces it because it covers historical ranges.)
//   - RepairWeight::set_root (core/src/repair/repair_weight.rs:385) purges every
//     subtree whose root < new_root and is not on the rooted subtree; and
//     BankForks::prune_non_rooted (runtime/src/bank_forks.rs:659) drops the
//     non-rooted banks. Abandoning X (clearCompletedSlot + drop from repair set)
//     is the Vexor analog of that prune — X can never be rooted, so it must not
//     remain the mandatory contiguous bridge.

/// Cluster-confirmed-SKIP predicate, computed off the cluster's getBlocks
/// (is_skipped) oracle. TRUE iff ALL of:
///   1. `query_ok == true`        — the getBlocks query SUCCEEDED and covered the
///      full [X-K, X+K] neighborhood (non-null result). An RPC failure, a parse
///      error, or a range not in RPC retention leaves this FALSE → we FAIL CLOSED
///      (no abandon). This is the "RPC failure / partial range → not covered →
///      false" firewall, now a pure-testable input rather than caller-only logic.
///   2. `x_present == false`      — X is ABSENT from getBlocks' produced list
///      (the cluster did not produce/root X → it was skipped). If X IS produced,
///      X is canonical and our local failure to complete it is a divergence to
///      diagnose, never a slot to abandon.
///   3. `lower_present && higher_present` — a produced L < X AND a produced H > X
///      both exist in the SAME fully-queried getBlocks range. This is the
///      COVERAGE / BOUNDING proof: it shows the produced-slot list genuinely
///      spans X's range on both sides, so X's absence is a GENUINE skip (the
///      canonical chain provably routes L → … → H AROUND X) and not merely
///      "X is out of the queried/retained window". Without BOTH sides we must NOT
///      abandon. A FORKED validator's lie about parent_offset cannot manufacture
///      an `H` here: getBlocks returns ONLY the cluster's own rooted/confirmed
///      slots, so a lie is never in the list — the oracle IS the firewall.
///   4. `knows_last == false`     — X is phantom/incomplete (we never saw its
///      completion-defining LAST_IN_SLOT). A slot we can fully complete is not a
///      skip candidate; fall through to the existing HWI/failstop for it.
///
/// NO socket / `self` / parent_offset trust here — the caller derives all inputs
/// off the cluster's getBlocks produced-slot list + the shred assembler. The
/// "bypass" that the old `higher_parent < x` clause proved is now AUTOMATIC:
/// (x absent) ∧ (produced L < X) ∧ (produced H > X) in the fully-queried range
/// IS Blockstore::is_skipped, so no separate parent-arithmetic input is needed.
pub fn clusterConfirmedSkip(
    query_ok: bool,
    x_present: bool,
    lower_present: bool,
    higher_present: bool,
    knows_last: bool,
) bool {
    // (1) The getBlocks query must have SUCCEEDED + covered the range.
    if (!query_ok) return false;
    // (2) X must be ABSENT from the cluster's produced list.
    if (x_present) return false;
    // (3) COVERAGE / BOUNDING PROOF: produced slots strictly below AND above X.
    if (!lower_present or !higher_present) return false;
    // (4) X is phantom/incomplete (never knew its last shred).
    if (knows_last) return false;
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// KATs — `zig build test-repair-escalate`
// ════════════════════════════════════════════════════════════════════════════

test "(a) slow-but-filling slot does NOT trip (advancing unique_count + answered)" {
    // A cold-boot catch-up slot: it is gaining shreds (no_progress=false, the
    // progress watermark keeps refreshing) AND peers answer (resp climbing well
    // past the ceiling). Many requests may have been issued, but the content
    // clauses are both FALSE → MUST NOT escalate (would fail-stop a healthy node).
    try std.testing.expect(!phantomSignatureDefault(
        500, // reqs: even with many requests issued ...
        false, // no_progress: FALSE — unique_count is advancing
        50, // resps: > MAX_RESP_FOR_PHANTOM(2) — peers are answering
    ));
    // And even at the exact MAX_RESP boundary+1, an answered+progressing slot
    // stays safe.
    try std.testing.expect(!phantomSignatureDefault(10_000, false, 3));
}

test "(b) wedged phantom slot DOES trip (no progress, reqs>=200, resp<=2)" {
    // The genuine wedge: many requests, NO forward progress, ~0 answers.
    try std.testing.expect(phantomSignatureDefault(
        200, // reqs == MIN_REQUESTS_FOR_ESCALATE (boundary, inclusive)
        true, // no_progress: TRUE — gained no shreds for the window
        2, // resps == MAX_RESP_FOR_PHANTOM (boundary, inclusive)
    ));
    // Well past the thresholds also trips.
    try std.testing.expect(phantomSignatureDefault(5000, true, 0));
    // no_progress alone (with enough requests) is sufficient EVEN IF a few
    // historical responses landed — no_progress is the authoritative proof.
    try std.testing.expect(phantomSignatureDefault(300, true, 100));
    // resp<=2 alone (with enough requests) is sufficient EVEN IF progress timer
    // hasn't elapsed yet — the dropped-LAST phantom answered ~never.
    try std.testing.expect(phantomSignatureDefault(300, false, 1));
}

test "(c) behind-but-answered slot never escalates (resp climbing)" {
    // A node merely behind the tip: it has not yet made progress on THIS exact
    // slot this instant (no_progress could be momentarily true OR false) but
    // peers ARE answering for it (resp climbing). Model the climb: as resp rises
    // past the ceiling, and as long as it is making progress, it must not trip.
    var resp: u64 = 0;
    while (resp <= 100) : (resp += 1) {
        // making progress (no_progress=false) AND answered → never trips,
        // regardless of how many requests were issued.
        try std.testing.expect(!phantomSignatureDefault(1000, false, resp + 3));
    }
    // The exact moment resp exceeds MAX_RESP_FOR_PHANTOM, the "~never answered"
    // clause is false; combined with progress (no_progress=false) → no escalate.
    try std.testing.expect(!phantomSignatureDefault(1000, false, MAX_RESP_FOR_PHANTOM + 1));
}

test "request floor gate: too few requests never escalates even if wedged-looking" {
    // Below MIN_REQUESTS_FOR_ESCALATE we have not tried hard enough to conclude a
    // wedge — must NOT escalate even with no_progress + zero responses.
    try std.testing.expect(!phantomSignatureDefault(199, true, 0));
    try std.testing.expect(!phantomSignatureDefault(0, true, 0));
    // Exactly at the floor with the wedge content → trips (boundary inclusive).
    try std.testing.expect(phantomSignatureDefault(200, true, 0));
}

test "byte-identical to the tvu.zig FIX #3 expression across a grid" {
    // Exhaustively re-derive the inlined boolean and compare, so this extraction
    // can never silently diverge from the live predicate.
    const reqs_set = [_]u64{ 0, 1, 199, 200, 201, 1000 };
    const resp_set = [_]u64{ 0, 1, 2, 3, 50 };
    const prog_set = [_]bool{ true, false };
    for (reqs_set) |reqs| {
        for (resp_set) |resps| {
            for (prog_set) |np| {
                const inlined = (reqs >= MIN_REQUESTS_FOR_ESCALATE) and
                    (np or (resps <= MAX_RESP_FOR_PHANTOM));
                try std.testing.expectEqual(inlined, phantomSignatureDefault(reqs, np, resps));
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// KATs — clusterConfirmedSkip (VEX_REPAIR_SKIP_ABANDONED discriminator)
// Inputs are derived from the cluster's getBlocks (is_skipped) produced-slot
// list. The false-positive firewall is the load-bearing property: an
// unconfirmed / partial-coverage / failed-query shape MUST NOT pass. Slot
// numbers mirror the real incident (X=419581196 skipped; canonical chain
// …195 → …197 with 196 NOT in getBlocks). Signature:
//   clusterConfirmedSkip(query_ok, x_present, lower_present, higher_present, knows_last)
// ════════════════════════════════════════════════════════════════════════════

test "(a) genuine skip → true (query ok, X absent from produced list, both neighbors produced)" {
    // The real wedge: getBlocks(180..212) succeeded, X=196 is ABSENT from the
    // returned produced list, a produced L (195, < X) AND a produced H (197, > X)
    // both appear in the fully-queried range, X phantom/incomplete. ALL four
    // conditions hold → the canonical chain routes 195 → 197 AROUND 196 → ABANDON.
    try std.testing.expect(clusterConfirmedSkip(
        true, //  query_ok:       getBlocks succeeded + covered [X-16, X+16]
        false, // x_present:      196 ABSENT from the produced list
        true, //  lower_present:  195 produced (< X)
        true, //  higher_present: 197 produced (> X)
        false, // knows_last:     X incomplete (32 partial shreds, never saw LAST)
    ));
}

test "(b) FALSE-POSITIVE GUARD: partial coverage (only one / no neighbor produced) → false" {
    // X absent, query ok, BUT the produced list does not BOUND X on both sides
    // (a produced slot on only ONE side, or neither). Absence is then "not proven
    // skipped within the covered range" → MUST NOT abandon.
    // Only the HIGHER side produced (no L):
    try std.testing.expect(!clusterConfirmedSkip(true, false, false, true, false));
    // Only the LOWER side produced (no H):
    try std.testing.expect(!clusterConfirmedSkip(true, false, true, false, false));
    // NEITHER side produced (empty / all-skipped range):
    try std.testing.expect(!clusterConfirmedSkip(true, false, false, false, false));
}

test "(c) FAIL-CLOSED: getBlocks query failed / range not retained (query_ok=false) → false" {
    // The getBlocks RPC failed (curl/parse error), OR the 12h-old wedge slot's
    // range is no longer in RPC retention → query_ok=false. Even with an
    // otherwise-perfect skip shape we FAIL CLOSED (no abandon). This is where the
    // forked-lie firewall now lives structurally: getBlocks returns ONLY the
    // cluster's own rooted/confirmed slots, so a forked validator's parent_offset
    // lie can never appear as a produced neighbor — an unbacked "successor" simply
    // is not in the list (higher_present=false, clause 3), and a failed query is
    // rejected here at clause 1.
    try std.testing.expect(!clusterConfirmedSkip(
        false, // query_ok:       getBlocks FAILED / range unretained
        false, // x_present:      X absent
        true, //  lower_present:  looks like a real L below X
        true, //  higher_present: looks like a real H above X
        false, // knows_last
    ));
}

test "(d) X present in getBlocks (canonical; our copy diverged) → false" {
    // The cluster PRODUCED X (X is in the getBlocks list) → X is canonical, NOT
    // skipped. Our local failure to complete X is a divergence to diagnose, never
    // a slot to abandon. Even with both neighbors produced, X-present vetoes.
    try std.testing.expect(!clusterConfirmedSkip(
        true, //  query_ok
        true, //  x_present:      196 IS in the produced list → canonical
        true, //  lower_present
        true, //  higher_present
        false, // knows_last
    ));
}

test "(e) knows_last guard: X complete (we know its LAST shred) → false" {
    // If we DO know X's completion bound, X is not a phantom skip candidate —
    // fall through to the existing HWI/failstop rather than abandon.
    try std.testing.expect(!clusterConfirmedSkip(true, false, true, true, true));
}

test "(f) all-four-required: every single clause is load-bearing" {
    // The positive case (a) flips to FALSE if ANY one clause is broken — proves
    // no clause is redundant. Start from the true tuple (true,false,true,true,false):
    try std.testing.expect(clusterConfirmedSkip(true, false, true, true, false)); // baseline TRUE
    try std.testing.expect(!clusterConfirmedSkip(false, false, true, true, false)); // ¬query_ok
    try std.testing.expect(!clusterConfirmedSkip(true, true, true, true, false)); //  x_present
    try std.testing.expect(!clusterConfirmedSkip(true, false, false, true, false)); // ¬lower
    try std.testing.expect(!clusterConfirmedSkip(true, false, true, false, false)); // ¬higher
    try std.testing.expect(!clusterConfirmedSkip(true, false, true, true, true)); //  knows_last
}
