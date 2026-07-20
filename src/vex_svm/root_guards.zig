//! Part 4b — ROOT-GUARDS pure predicate (switch-proof / self-recovery root-fix).
//! Design: vexor-research/design-docs/SWITCHPROOF-SELFRECOVERY-ROOTFIX-DESIGN-2026-07-15 §4b.
//!
//! Two REFUSE-ONLY guards evaluated in replay_stage.doRootAdvance before a local
//! root advance. They prevent the single worst outcome of the 421935259 incident
//! class: rooting a divergent / cluster-unconfirmed fork PAST consensus (in the
//! incident root advanced 248→266→289→326 while the cluster lagged ~289), which
//! made recovery impossible without a fresh snapshot. Both guards ONLY ever REFUSE
//! the advance (keep the previous root) — strictly safe, cannot corrupt state; a
//! fire degrades any future recurrence from "unrecoverable" to a "recoverable
//! stall" that VOTE-REJECT-ALARM catches in ~30s.
//!
//! Factored here as a PURE function over explicit inputs so the decision is
//! unit-testable without a live fork-choice tree or cluster oracle. The impl-side
//! collector `ReplayStage.rootGuardInputs` gathers these inputs from fork-choice
//! (candidate-root fork_info) and the read-only SlotHashes cache.
//!
//!   G1 — never root a fork whose ancestry (or the root itself) includes an
//!        INVALID slot (fork_info.latest_invalid_ancestor != null).
//!   G2 — never root a slot the CLUSTER has diverged from: refuse when the
//!        cluster's SlotHashes holds a KNOWN-DIFFERENT canonical bank_hash for the
//!        candidate root slot (positive-divergence). ALLOW when the candidate is
//!        duplicate-confirmed (future-proof: today only the genesis root is, until
//!        Part 2 wires the cluster dup-confirm feed) or when the cluster oracle is
//!        silent / agrees (fail-open — a no-op at bootstrap / offline).
//!
//! NOTE on G2 vs the design's literal wording. The design's literal G2 ("refuse
//! UNLESS the candidate is duplicate-confirmed") is inert-armed in this tree:
//! is_duplicate_confirmed is set only for the genesis root
//! (fork_choice.zig:754 parent_key==null) and never propagates to a non-root slot
//! without Part 2's cluster duplicate-confirm feed — so an "unless-confirmed"
//! refuse would reject EVERY advance (total self-stall). The positive-divergence
//! form implemented here is the safe, faithful realization of the same protective
//! intent given the signals that exist today; it auto-strengthens once Part 2 sets
//! is_duplicate_confirmed for real (the ALLOW short-circuit is already wired).

const std = @import("std");
const core = @import("core");

pub const Slot = core.Slot;

/// Inputs for the root-guards, all read for the CANDIDATE ROOT slot.
pub const RootGuardInputs = struct {
    /// fork_info.latest_invalid_ancestor for the candidate root key; null when the
    /// fork has no invalid ancestor OR the key is absent (offline / bootstrap).
    latest_invalid_ancestor: ?Slot,
    /// fork_info.is_duplicate_confirmed for the candidate root key (false when
    /// absent). Today only the genesis root is true, until Part 2's cluster
    /// duplicate-confirm feed lands — the ALLOW short-circuit is future-proofing.
    is_duplicate_confirmed: bool,
    /// The bank_hash of the version we are about to root (the candidate root key's
    /// hash); null when the candidate root is absent from the fork-choice tree.
    our_root_hash: ?[32]u8,
    /// The cluster's canonical bank_hash for the candidate root slot, from the
    /// read-only SlotHashes cache; null when the oracle is silent (offline / boot).
    cluster_canonical_hash: ?[32]u8,

    // ── G0 FIRST-ROOT POSITIVE-ATTESTATION LATCH (incident 423083743, 2026-07-19) ──
    // Boot 18:45 rooted cluster-SKIPPED slot 423083742 during catch-up: a skipped
    // slot never appears in cluster SlotHashes → cluster_canonical_hash == null →
    // the G2 fail-open branch allowed the advance → irreversible dead-fork root.
    // Pre-latch (first_root_pending=true) a HASH-SILENT candidate now additionally
    // requires positive cluster-PRODUCED confirmation. Both fields default to the
    // values that make the predicate BYTE-IDENTICAL to the pre-latch code, so
    // offline replay / golden gate (which never sets first_root_pending) and all
    // pre-existing callers/tests are unaffected.

    /// True ONLY while the per-process first-root latch is armed and not yet
    /// satisfied (live boot, VEX_FIRST_ROOT_LATCH not disabled, no positively
    /// attested root yet). Offline replay (VEX_LEDGER_REPLAY/VEX_SNAPSHOT_OFFLINE)
    /// always passes false — no cluster exists to attest there.
    first_root_pending: bool = false,
    /// Historical-oracle verdict for the candidate slot (fetchProducedSlots — the
    /// Agave Blockstore::is_skipped analog): true = the cluster PRODUCED the slot
    /// (present in getBlocks), false = cluster-skipped (absent — the 742 shape),
    /// null = oracle unreachable. Consulted ONLY pre-latch on a hash-silent
    /// candidate; callers may leave it null otherwise.
    cluster_produced: ?bool = null,
};

/// Why G0 refused a pre-latch hash-silent candidate (for the log line).
pub const G0Why = enum { not_produced, oracle_unreachable };

pub const RootGuardDecision = union(enum) {
    /// Advance permitted (no attestation information — e.g. oracle silent
    /// post-latch, or produced-confirmed-only pre-latch: does NOT set the latch).
    allow,
    /// Advance permitted AND the candidate is POSITIVELY cluster-attested
    /// (cluster SlotHashes hash matches ours, or duplicate-confirmed). The
    /// caller sets the first-root latch on this decision.
    allow_attested,
    /// G0 fired — pre-latch candidate is HASH-SILENT and not positively
    /// confirmed cluster-produced (payload says which). Cannot fire post-latch
    /// or when first_root_pending is false.
    refuse_g0: G0Why,
    /// G1 fired — candidate root's ancestry includes an invalid slot (payload =
    /// the latest invalid ancestor slot, for the log).
    refuse_g1: Slot,
    /// G2 fired — cluster holds a known-different canonical hash for this slot.
    refuse_g2,
};

/// The root-guards as a pure decision. REFUSE-ONLY: any refuse_* result means
/// "keep the previous root, do not advance." Never allocates, never logs.
/// With first_root_pending=false (the default, and always the case offline)
/// the allow/refuse partition is BYTE-IDENTICAL to the pre-G0 predicate —
/// allow_attested is an `allow` that additionally carries attestation info.
pub fn evalRootGuards(in: RootGuardInputs) RootGuardDecision {
    // G1 — never root a fork whose ancestry (or the root itself) is marked
    // invalid. A canonical root is never marked invalid, so this cannot fire on
    // healthy replay; it fires only once a slot in the rooted ancestry has been
    // duplicate/dead-marked in fork-choice.
    if (in.latest_invalid_ancestor) |lia| return .{ .refuse_g1 = lia };

    // G2 — never root a slot the cluster has DIVERGED from. Duplicate-confirmed
    // candidates always pass (future-proof; today only genesis) — and count as
    // positive cluster attestation. Otherwise, if the cluster's SlotHashes has a
    // canonical bank_hash for this slot that DIFFERS from the version we hold,
    // we are about to root a fork the cluster did not confirm → refuse. A MATCH
    // is positive attestation (allow + latch).
    if (in.is_duplicate_confirmed) return .allow_attested;
    if (in.cluster_canonical_hash) |ch| {
        if (in.our_root_hash) |oh| {
            if (!std.mem.eql(u8, &ch, &oh)) return .refuse_g2;
            return .allow_attested;
        }
        // Cluster has a hash but ours is unresolvable (candidate absent from the
        // fork-choice tree) — cannot compare, fail-open exactly as before. A
        // SlotHashes entry does prove the slot was cluster-PRODUCED, so even
        // pre-latch this is produced-confirmed → allow; but with no hash match
        // it is NOT positive attestation → no latch.
        return .allow;
    }

    // HASH-SILENT (the incident hole: a cluster-SKIPPED slot can never appear in
    // cluster SlotHashes, so G2 alone can never refuse it).
    // Post-latch / latch disabled / offline: today's fail-open behavior, verbatim.
    if (!in.first_root_pending) return .allow;

    // G0 — pre-latch, a hash-silent candidate needs positive cluster-PRODUCED
    // confirmation from the historical oracle. Produced (deep catch-up, outside
    // the 512-slot SlotHashes window) → allow WITHOUT latching — presence in the
    // canonical getBlocks chain is chain-level attestation; any hash divergence
    // is caught at the next in-window candidate by G2. Not produced (the exact
    // 423083742 shape) or oracle unreachable → REFUSE (fail-closed ONLY
    // pre-latch; worst case = deferred rooting, strictly better than an
    // unrecoverable dead-fork root).
    const produced = in.cluster_produced orelse return .{ .refuse_g0 = .oracle_unreachable };
    if (produced) return .allow;
    return .{ .refuse_g0 = .not_produced };
}

test "4b root-guard: healthy monotonic canonical root — no fire (all signals absent)" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = null,
        .cluster_canonical_hash = null,
    });
    try std.testing.expect(d == .allow);
}

test "4b root-guard: healthy — cluster oracle AGREES with our hash — no fire (positive attestation)" {
    const h = [_]u8{0xab} ** 32;
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = h,
        .cluster_canonical_hash = h,
    });
    // A hash match is now reported as allow_attested (still an allow; the G0
    // latch caller uses the attestation signal).
    try std.testing.expect(d == .allow_attested);
}

test "4b root-guard G1: invalid ancestor in rooted fork — REFUSE" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = 259,
        .is_duplicate_confirmed = false,
        .our_root_hash = [_]u8{0x11} ** 32,
        .cluster_canonical_hash = null,
    });
    switch (d) {
        .refuse_g1 => |lia| try std.testing.expectEqual(@as(Slot, 259), lia),
        else => return error.TestExpectedG1Refuse,
    }
}

test "4b root-guard G1 dominates G2: invalid ancestor refuses even if cluster agrees" {
    const h = [_]u8{0x22} ** 32;
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = 100,
        .is_duplicate_confirmed = false,
        .our_root_hash = h,
        .cluster_canonical_hash = h,
    });
    try std.testing.expect(d == .refuse_g1);
}

test "4b root-guard G2: cluster canonical hash DIFFERS from ours — REFUSE (unconfirmed divergent fork)" {
    const ours = [_]u8{0x01} ** 32;
    const cluster = [_]u8{0x02} ** 32;
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = ours,
        .cluster_canonical_hash = cluster,
    });
    try std.testing.expect(d == .refuse_g2);
}

test "4b root-guard G2: refusal CLEARS once cluster confirms our version (re-evaluated, not latched)" {
    const ours = [_]u8{0x07} ** 32;
    // Before confirmation: cluster shows a different hash → refuse.
    try std.testing.expect(evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = ours,
        .cluster_canonical_hash = [_]u8{0x08} ** 32,
    }) == .refuse_g2);
    // After confirmation: cluster's canonical hash now equals ours → allow
    // (with positive attestation).
    try std.testing.expect(evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = ours,
        .cluster_canonical_hash = ours,
    }) == .allow_attested);
}

test "4b root-guard G2: duplicate-confirmed candidate ALLOWS even against a cluster mismatch (future-proof; counts as attestation)" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = true,
        .our_root_hash = [_]u8{0x01} ** 32,
        .cluster_canonical_hash = [_]u8{0x02} ** 32,
    });
    try std.testing.expect(d == .allow_attested);
}

test "4b root-guard G2: cluster known but our hash unavailable — allow (cannot compare, fail-open)" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = null,
        .cluster_canonical_hash = [_]u8{0x09} ** 32,
    });
    try std.testing.expect(d == .allow);
}

// ═══ G0 first-root positive-attestation latch (incident 423083743) ═══

test "G0: pre-latch hash-silent + cluster-NOT-produced — REFUSE (the skipped-742 shape)" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = [_]u8{0x42} ** 32,
        .cluster_canonical_hash = null, // skipped slot: never in cluster SlotHashes
        .first_root_pending = true,
        .cluster_produced = false, // absent from getBlocks — cluster-confirmed skip
    });
    switch (d) {
        .refuse_g0 => |why| try std.testing.expectEqual(G0Why.not_produced, why),
        else => return error.TestExpectedG0Refuse,
    }
}

test "G0: pre-latch hash-silent + oracle UNREACHABLE — REFUSE (fail-closed only pre-latch)" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = [_]u8{0x42} ** 32,
        .cluster_canonical_hash = null,
        .first_root_pending = true,
        .cluster_produced = null, // probe failed
    });
    switch (d) {
        .refuse_g0 => |why| try std.testing.expectEqual(G0Why.oracle_unreachable, why),
        else => return error.TestExpectedG0Refuse,
    }
}

test "G0: pre-latch hash-silent + produced-CONFIRMED — allow WITHOUT attestation (deep catch-up, no latch)" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = [_]u8{0x42} ** 32,
        .cluster_canonical_hash = null, // outside the 512-slot SlotHashes window
        .first_root_pending = true,
        .cluster_produced = true, // present in the canonical getBlocks chain
    });
    try std.testing.expect(d == .allow);
}

test "G0: pre-latch positive hash MATCH — allow_attested (latch source)" {
    const h = [_]u8{0x55} ** 32;
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = h,
        .cluster_canonical_hash = h,
        .first_root_pending = true,
    });
    try std.testing.expect(d == .allow_attested);
}

test "G0: pre-latch positive MISMATCH still refuses via G2 (unchanged)" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = [_]u8{0x01} ** 32,
        .cluster_canonical_hash = [_]u8{0x02} ** 32,
        .first_root_pending = true,
    });
    try std.testing.expect(d == .refuse_g2);
}

test "G0: POST-latch (first_root_pending=false) hash-silent — allow, cluster_produced ignored (today's behavior verbatim)" {
    // Even a definitive "not produced" verdict must not refuse once latched /
    // when the latch is disabled or offline — G0 is a boot-window-only gate.
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = [_]u8{0x42} ** 32,
        .cluster_canonical_hash = null,
        .first_root_pending = false,
        .cluster_produced = false,
    });
    try std.testing.expect(d == .allow);
}
