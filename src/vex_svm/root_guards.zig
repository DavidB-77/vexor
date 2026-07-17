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

/// Inputs for the two root-guards, all read for the CANDIDATE ROOT slot.
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
};

pub const RootGuardDecision = union(enum) {
    /// Advance permitted.
    allow,
    /// G1 fired — candidate root's ancestry includes an invalid slot (payload =
    /// the latest invalid ancestor slot, for the log).
    refuse_g1: Slot,
    /// G2 fired — cluster holds a known-different canonical hash for this slot.
    refuse_g2,
};

/// The two root-guards as a pure decision. REFUSE-ONLY: any non-`allow` result
/// means "keep the previous root, do not advance." Never allocates, never logs.
pub fn evalRootGuards(in: RootGuardInputs) RootGuardDecision {
    // G1 — never root a fork whose ancestry (or the root itself) is marked
    // invalid. A canonical root is never marked invalid, so this cannot fire on
    // healthy replay; it fires only once a slot in the rooted ancestry has been
    // duplicate/dead-marked in fork-choice.
    if (in.latest_invalid_ancestor) |lia| return .{ .refuse_g1 = lia };

    // G2 — never root a slot the cluster has DIVERGED from. Duplicate-confirmed
    // candidates always pass (future-proof; today only genesis). Otherwise, if the
    // cluster's SlotHashes has a canonical bank_hash for this slot that DIFFERS
    // from the version we hold, we are about to root a fork the cluster did not
    // confirm → refuse. Cluster silent (null) or agreeing → allow (fail-open: a
    // no-op at bootstrap / offline).
    if (in.is_duplicate_confirmed) return .allow;
    if (in.cluster_canonical_hash) |ch| {
        if (in.our_root_hash) |oh| {
            if (!std.mem.eql(u8, &ch, &oh)) return .refuse_g2;
        }
    }
    return .allow;
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

test "4b root-guard: healthy — cluster oracle AGREES with our hash — no fire" {
    const h = [_]u8{0xab} ** 32;
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = h,
        .cluster_canonical_hash = h,
    });
    try std.testing.expect(d == .allow);
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
    // After confirmation: cluster's canonical hash now equals ours → allow.
    try std.testing.expect(evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = false,
        .our_root_hash = ours,
        .cluster_canonical_hash = ours,
    }) == .allow);
}

test "4b root-guard G2: duplicate-confirmed candidate ALLOWS even against a cluster mismatch (future-proof)" {
    const d = evalRootGuards(.{
        .latest_invalid_ancestor = null,
        .is_duplicate_confirmed = true,
        .our_root_hash = [_]u8{0x01} ** 32,
        .cluster_canonical_hash = [_]u8{0x02} ** 32,
    });
    try std.testing.expect(d == .allow);
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
