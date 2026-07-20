//! VOTE-THRESHOLD depth-8 stake wiring — regression gate (incident 423083743
//! companion fix, 2026-07-19).
//!
//! The depth-8 threshold check in tower.zig `shouldVote` was structurally DEAD:
//! both live call sites passed (cluster_voted_stake=0, total_stake=0) and the
//! check is skipped entirely under `total_stake > 0`. That hollow gate is how
//! the 2026-07-19 boot voted 32× onto cluster-SKIPPED 423083742 and rooted it —
//! Agave (consensus.rs check_vote_stake_threshold) and Firedancer
//! (fd_tower.c threshold_check) run this check with REAL observed stake, which
//! is what structurally prevents their towers from ever filling 31-deep on a
//! fork the cluster abandoned.
//!
//! This file proves, at every layer of the new wiring:
//!   1. `VoteState.thresholdDepthSlot` — the Agave-faithful simulated-tower
//!      nth_recent_lockout(8) slot selection (pure).
//!   2. `TowerBft.thresholdStakesForMode` — the SINGLE seam deciding what
//!      reaches shouldVote: shadow/off forward (0,0), so SHADOW MODE CAN NEVER
//!      ALTER THE VOTE DECISION by construction; only armed forwards real stakes.
//!   3. `shouldVote` verdicts — cluster stake present at depth-8 ⇒ PASS;
//!      absent ⇒ WOULD-REFUSE; (0,0) ⇒ legacy skip (today's behavior).
//!   4. The REAL fork-choice glue `ReplayStage.clusterVotedStakeAtDepthSlot`
//!      (real ReplayStage + real HeaviestSubtreeForkChoice + real addVotes):
//!      stake voted on a descendant aggregates to the depth-8 ancestor
//!      (stake_voted_subtree — the Agave voted_stakes[slot] analog); a fork the
//!      cluster is not voting reads 0.
//!
//! Build/run: zig build test-vote-threshold-shadow

const std = @import("std");
const vex_svm = @import("vex_svm");
const vex_consensus = @import("vex_consensus");
const core = @import("core");

const ReplayStage = vex_svm.replay_stage.ReplayStage;
const tower_mod = vex_consensus.tower;
const TowerBft = tower_mod.TowerBft;
const fc_mod = vex_consensus.fork_choice;
const Pubkey = core.Pubkey;
const Hash = core.Hash;

fn mkHash(b: u8) Hash {
    return .{ .data = [_]u8{b} ** 32 };
}

/// Same rationale as kat_revive_would_fire.zig / kat_first_root_latch.zig.
fn stopAndJoinWorkers(stage: *ReplayStage) void {
    stage.is_running.store(false, .release);
    if (stage.worker_thread) |t| {
        t.join();
        stage.worker_thread = null;
    }
    if (stage.sysvar_refresh_thread) |t| {
        t.join();
        stage.sysvar_refresh_thread = null;
    }
}

/// A tower of `n` consecutive-slot votes starting at `first` (consecutive slots
/// never expire prior lockouts, so len == n afterwards).
fn towerOf(first: u64, n: usize) TowerBft.VoteState {
    var vs = TowerBft.VoteState.init();
    var i: u64 = 0;
    while (i < n) : (i += 1) vs.recordVote(first + i);
    return vs;
}

test "thresholdDepthSlot: simulated-tower nth_recent_lockout(8) — Agave check_vote_stake_threshold slot selection" {
    // Too shallow: simulated tower of 1..8 entries ⇒ null (Agave trivial-pass).
    {
        const vs = TowerBft.VoteState.init();
        try std.testing.expectEqual(@as(?u64, null), vs.thresholdDepthSlot(100));
    }
    {
        const vs = towerOf(100, 7); // sim len 8 == THRESHOLD_DEPTH ⇒ still null
        try std.testing.expectEqual(@as(?u64, null), vs.thresholdDepthSlot(107));
    }
    // 8 existing votes 100..107, candidate 108 ⇒ simulated len 9 ⇒ the slot at
    // index len-1-8 = 0 ⇒ 100 (the 9th-most-recent — Agave nth_recent_lockout(8)).
    {
        const vs = towerOf(100, 8);
        try std.testing.expectEqual(@as(?u64, 100), vs.thresholdDepthSlot(108));
    }
    // 9 existing votes 100..108, candidate 109 ⇒ simulated len 10 ⇒ buf[1] = 101.
    {
        const vs = towerOf(100, 9);
        try std.testing.expectEqual(@as(?u64, 101), vs.thresholdDepthSlot(109));
    }
}

test "thresholdStakesForMode: only ARMED forwards real stakes — shadow can never alter the decision by construction" {
    const armed = TowerBft.thresholdStakesForMode(.armed, 123, 456);
    try std.testing.expectEqual(@as(u64, 123), armed.voted);
    try std.testing.expectEqual(@as(u64, 456), armed.total);

    inline for (.{ TowerBft.ThresholdMode.shadow, TowerBft.ThresholdMode.off }) |m| {
        const s = TowerBft.thresholdStakesForMode(m, 123, 456);
        try std.testing.expectEqual(@as(u64, 0), s.voted);
        try std.testing.expectEqual(@as(u64, 0), s.total);
    }
}

test "shouldVote verdicts: cluster stake present at depth-8 => PASS; absent => WOULD-REFUSE; (0,0) => legacy skip; shadow decision identical to legacy" {
    var t = try TowerBft.init(std.testing.allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    defer t.deinit();
    t.vote_state = towerOf(100, 8); // len 8 ≥ THRESHOLD_DEPTH: threshold clause live when total>0

    // Every slot is an ancestor (rooted prefix covers all) — isolates the
    // threshold clause from the lockout/fork gates.
    const anc = TowerBft.SliceAncestors{ .rooted_slot = std.math.maxInt(u64), .chain = &.{} };
    const cand: u64 = 108;

    // Cluster stake PRESENT at/beyond our depth-8 slot: 670/1000 = 67% ≥ 67 ⇒ PASS.
    try std.testing.expect(t.shouldVote(cand, true, anc, 670, 1000));
    // Cluster stake ABSENT (the dead-fork boot shape): 0/1000 ⇒ WOULD-REFUSE.
    try std.testing.expect(!t.shouldVote(cand, true, anc, 0, 1000));
    // Just under threshold: 66% ⇒ WOULD-REFUSE.
    try std.testing.expect(!t.shouldVote(cand, true, anc, 660, 1000));
    // Legacy (0,0): check skipped entirely ⇒ PASS — today's live behavior.
    try std.testing.expect(t.shouldVote(cand, true, anc, 0, 0));

    // SHADOW NEVER ALTERS THE DECISION: what shouldVote receives in shadow mode
    // is thresholdStakesForMode(.shadow, real...) = (0,0) — identical verdict to
    // the legacy call even when the REAL stakes would refuse.
    const sh = TowerBft.thresholdStakesForMode(.shadow, 0, 1000); // real stakes would refuse
    try std.testing.expectEqual(
        t.shouldVote(cand, true, anc, 0, 0),
        t.shouldVote(cand, true, anc, sh.voted, sh.total),
    );
    // ...while ARMED with the same real stakes flips it — the enforcement delta
    // arming is expected to introduce, and the only one.
    const ar = TowerBft.thresholdStakesForMode(.armed, 0, 1000);
    try std.testing.expect(!t.shouldVote(cand, true, anc, ar.voted, ar.total));
}

test "real fork-choice glue: descendant vote stake aggregates to the depth-8 ancestor; unvoted fork reads 0" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    // Chain 100 → 101 → … → 112, plus an unvoted sibling fork 100 → 150.
    const fc = if (stage.fork_choice) |*p| p else return error.TestNoForkChoice;
    {
        var s: u64 = 101;
        while (s <= 112) : (s += 1) {
            try fc_mod.addForkCompat(fc, s, s - 1, mkHash(@intCast(s - 100)), if (s == 101) mkHash(0x00) else mkHash(@intCast(s - 101)));
        }
        try fc_mod.addForkCompat(fc, 150, 100, mkHash(0x99), mkHash(0x00));
    }

    // One cluster voter (stake 500) whose LATEST landed vote is the tip (112) —
    // the shape buildVoteAccountBatchFresh feeds addVotes every replayed bank.
    const PkVote = fc_mod.HeaviestSubtreeForkChoice.PubkeyVote;
    const StakeLookup = struct {
        pub fn lookup(_: @This(), _: Pubkey, _: u64) u64 {
            return 500;
        }
    };
    _ = try fc.addVotes(&[_]PkVote{.{
        .pubkey = Pubkey{ .data = [_]u8{7} ** 32 },
        .slot_hash = .{ .slot = 112, .hash = mkHash(12) },
    }}, StakeLookup{});

    // Depth-8 ancestor of the tip on OUR fork: subtree stake includes the
    // descendant vote ⇒ the armed/shadow numerator is REAL (⇒ PASS verdicts).
    try std.testing.expectEqual(@as(u64, 500), stage.clusterVotedStakeAtDepthSlot(104, 112, mkHash(12)));
    // Same walk through an intermediate ancestor key resolution.
    try std.testing.expectEqual(@as(u64, 500), stage.clusterVotedStakeAtDepthSlot(101, 112, mkHash(12)));
    // A fork the cluster is NOT voting (the dead-fork boot shape) reads 0 ⇒
    // with total>0 the armed verdict is WOULD-REFUSE — exactly the gate that
    // would have stopped the 423083742 tower fill.
    try std.testing.expectEqual(@as(u64, 0), stage.clusterVotedStakeAtDepthSlot(150, 150, mkHash(0x99)));
}

test "REGRESSION (DIFF987 catch 2026-07-20): mainnet-magnitude lamport stakes must not overflow the pct math" {
    // The gate replay panicked at tower.zig shouldVote: (voted * 100) in u64
    // overflows for voted >= ~1.845e17 lamports (u64max/100). Real testnet
    // voted stake is ~2-3e17. Pin the fix with magnitudes above the overflow
    // line on both sides of the 67% threshold.
    const identity = @import("core").Pubkey{ .data = [_]u8{9} ** 32 };
    var t = try TowerBft.init(std.testing.allocator, identity);
    defer t.deinit();
    var s: u64 = 100;
    while (s < 109) : (s += 1) t.vote_state.recordVote(s);
    const anc = TowerBft.SliceAncestors{ .rooted_slot = 108, .chain = &.{} };
    const total: u64 = 400_000_000_000_000_000; // 4e17 lamports total epoch stake
    // 75% of total (3e17): ×100 = 3e19 — would overflow u64; must PASS at 75%.
    try std.testing.expect(t.shouldVote(109, true, anc, 300_000_000_000_000_000, total));
    // 50% of total: must REFUSE (below the 67% threshold), still no overflow.
    try std.testing.expect(!t.shouldVote(109, true, anc, 200_000_000_000_000_000, total));
}
