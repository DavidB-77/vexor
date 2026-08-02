//! VOTE-THRESHOLD depth-8 stake wiring — regression gate (incident 423083743
//! companion fix, 2026-07-19; ARMED BY DEFAULT 2026-07-29 — F348/F723,
//! operator no-shadow-modes hard cutover).
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
//! There is no shadow/observe-only leg any more — this file pins the ARMED
//! (default) behavior directly, at every layer of the wiring:
//!   1. `VoteState.thresholdDepthSlot` — the Agave-faithful simulated-tower
//!      nth_recent_lockout(8) slot selection (pure).
//!   2. `TowerBft.thresholdStakesForMode` — the SINGLE seam deciding what
//!      reaches shouldVote: ONLY `.armed` and `.off` exist (no third mode);
//!      armed forwards the real pair unconditionally, off zeroes it (kill-
//!      switch only).
//!   3. `TowerBft.thresholdPasses` — the pure pct predicate shared by
//!      shouldVote's enforcement AND replay_stage's [VOTE-THRESHOLD-ARMED]
//!      proof-of-arming counters. Pins the (0,0) edge explicitly: `total==0`
//!      trivially passes (not-deep-enough-tower / no-epoch-stake-data, the
//!      ONLY legitimate way (0,0) still reaches shouldVote while armed);
//!      `voted==0, total>0` (the dead-fork boot shape) always refuses.
//!   4. `shouldVote` verdicts — cluster stake present at depth-8 ⇒ PASS;
//!      absent (real total>0) ⇒ REFUSE; this is now the live, enforced
//!      behavior, not an observed-only diff.
//!   5. The REAL fork-choice glue `ReplayStage.clusterVotedStakeAtDepthSlot`
//!      (real ReplayStage + real HeaviestSubtreeForkChoice + real addVotes):
//!      stake voted on a descendant aggregates to the depth-8 ancestor
//!      (stake_voted_subtree — the Agave voted_stakes[slot] analog); a fork the
//!      cluster is not voting reads 0.
//!
//! Build/run: zig build test-vote-threshold-armed

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

test "ThresholdMode: exactly {off, armed} — no third (shadow) variant, no-shadow-modes cutover is structural not just default" {
    const fields = @typeInfo(TowerBft.ThresholdMode).@"enum".fields;
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    inline for (fields) |f| {
        try std.testing.expect(std.mem.eql(u8, f.name, "off") or std.mem.eql(u8, f.name, "armed"));
    }
}

test "thresholdStakesForMode: armed forwards the real pair unconditionally; off zeroes it (kill-switch only)" {
    const armed = TowerBft.thresholdStakesForMode(.armed, 123, 456);
    try std.testing.expectEqual(@as(u64, 123), armed.voted);
    try std.testing.expectEqual(@as(u64, 456), armed.total);

    const off = TowerBft.thresholdStakesForMode(.off, 123, 456);
    try std.testing.expectEqual(@as(u64, 0), off.voted);
    try std.testing.expectEqual(@as(u64, 0), off.total);
}

test "thresholdPasses: (0,0)-on-the-live-path arithmetic edge — total==0 trivial-passes; voted==0,total>0 always refuses" {
    // The ONLY legitimate way the live path still sees (0,0) once armed: tower
    // not yet 8-deep, or no epoch-stake data cached yet. Must trivial-pass —
    // this is Agave's own not-deep-enough-data behavior, not a bypass.
    try std.testing.expect(TowerBft.thresholdPasses(0, 0));
    try std.testing.expect(TowerBft.thresholdPasses(999, 0)); // total==0 dominates regardless of voted

    // The dead-fork boot shape (423083742): real epoch stake present, cluster
    // voted stake at depth-8 is zero ⇒ must ALWAYS refuse once armed, never
    // silently trivial-pass. This is exactly the gate that was dead pre-fix.
    try std.testing.expect(!TowerBft.thresholdPasses(0, 1_000));

    // Boundary: exactly 67% passes, 1 lamport under refuses.
    try std.testing.expect(TowerBft.thresholdPasses(67, 100));
    try std.testing.expect(!TowerBft.thresholdPasses(66, 100));
}

test "shouldVote verdicts (ARMED, the live default): cluster stake present at depth-8 => PASS; absent => REFUSE; not-deep-enough (0,0) => trivial pass" {
    var t = try TowerBft.init(std.testing.allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    defer t.deinit();
    t.vote_state = towerOf(100, 8); // len 8 ≥ THRESHOLD_DEPTH: threshold clause live when total>0

    // Every slot is an ancestor (rooted prefix covers all) — isolates the
    // threshold clause from the lockout/fork gates.
    const anc = TowerBft.SliceAncestors{ .rooted_slot = std.math.maxInt(u64), .chain = &.{} };
    const cand: u64 = 108;

    // Cluster stake PRESENT at/beyond our depth-8 slot: 670/1000 = 67% ≥ 67 ⇒ PASS.
    try std.testing.expect(t.shouldVote(cand, true, anc, 670, 1000));
    // Cluster stake ABSENT (the dead-fork boot shape): 0/1000 ⇒ REFUSE — this is
    // now the ENFORCED live behavior (armed by default), not an observed diff.
    try std.testing.expect(!t.shouldVote(cand, true, anc, 0, 1000));
    // Just under threshold: 66% ⇒ REFUSE.
    try std.testing.expect(!t.shouldVote(cand, true, anc, 660, 1000));
    // total==0 (tower not deep enough yet, or no epoch-stake data): trivial pass
    // — the ONLY legitimate way (0,0) still passes on the armed live path.
    try std.testing.expect(t.shouldVote(cand, true, anc, 0, 0));

    // thresholdStakesForMode(.armed, ...) round-trips through shouldVote
    // identically to calling shouldVote directly with the real pair — the seam
    // adds no behavior of its own when armed.
    const ar = TowerBft.thresholdStakesForMode(.armed, 0, 1000);
    try std.testing.expectEqual(
        t.shouldVote(cand, true, anc, 0, 1000),
        t.shouldVote(cand, true, anc, ar.voted, ar.total),
    );
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
    // descendant vote ⇒ the armed numerator is REAL (⇒ PASS verdicts).
    try std.testing.expectEqual(@as(u64, 500), stage.clusterVotedStakeAtDepthSlot(104, 112, mkHash(12)));
    // Same walk through an intermediate ancestor key resolution.
    try std.testing.expectEqual(@as(u64, 500), stage.clusterVotedStakeAtDepthSlot(101, 112, mkHash(12)));
    // A fork the cluster is NOT voting (the dead-fork boot shape) reads 0 ⇒
    // with total>0 the armed verdict is REFUSE — exactly the gate that would
    // have stopped the 423083742 tower fill.
    try std.testing.expectEqual(@as(u64, 0), stage.clusterVotedStakeAtDepthSlot(150, 150, mkHash(0x99)));
}

test "REGRESSION (DIFF987 catch 2026-07-20): mainnet-magnitude lamport stakes must not overflow the pct math" {
    // The gate replay panicked at tower.zig shouldVote: (voted * 100) in u64
    // overflows for voted >= ~1.845e17 lamports (u64max/100). Real testnet
    // voted stake is ~2-3e17. Pin the fix with magnitudes above the overflow
    // line on both sides of the 67% threshold. Now runs through the shared
    // thresholdPasses() helper (also exercised directly by the counters test
    // above), armed by default.
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

// ═══════════════════════════════════════════════════════════════════════════════
// F348b REWORK (2026-07-29, adversarial audit): depthSlotAlreadyRooted —
// the 2026-07-29 boot-restore wedge, WITHOUT fork-blind bank-vote-account counting
// ═══════════════════════════════════════════════════════════════════════════════
//
// A first version of this fix sourced stake from the bank's vote accounts
// directly (read each staked voter's CURRENT on-chain vote-state, count it
// if last_voted/root >= depth_slot). Adversarial audit caught it fork-blind:
// `db.getAccountInSlot` resolves each voter's account at (bank.slot,
// bank.ancestors()) regardless of which fork that voter's landed vote was
// actually ON — an equivocating/partitioned voter voting ahead on a
// DIFFERENT fork would get credited to OUR depth_slot, and the `@max`
// composition with the fork-aware subtree source propagated that overcount
// straight into the armed gate (fund-safety direction). Deleted entirely,
// along with `getRootSlot` (orphaned) and the bank-side KATs.
//
// Replacement (`ReplayStage.depthSlotAlreadyRooted`, replay_stage.zig):
// depth_slot <= our own rooted_slot ⇒ trivial-pass (0,0), citing Agave
// `consensus.rs` `Tower::adjust_lockouts_after_replay` — see that function's
// doc comment for the full citation and the adversarial reasoning on why our
// own root-advance guards (carrier #7 ancestry guard + G0/G1/G2) make this
// sound rather than a bypass. depth_slot > root keeps the EXISTING fork-
// aware `clusterVotedStakeAtDepthSlot` alone — no bank source, no `@max`,
// no fork-blind counting anywhere.

test "depthSlotAlreadyRooted: pure boundary — at/below root trivially rooted, one above is not" {
    try std.testing.expect(ReplayStage.depthSlotAlreadyRooted(100, 100)); // equal: rooted
    try std.testing.expect(ReplayStage.depthSlotAlreadyRooted(99, 100)); // below root: rooted
    try std.testing.expect(!ReplayStage.depthSlotAlreadyRooted(101, 100)); // one above root: NOT rooted
    try std.testing.expect(!ReplayStage.depthSlotAlreadyRooted(1, 0)); // root==0 (no root yet): nothing is rooted
}

test "KAT boot-restore specimen (F348b): depth8_slot below the boot root trivial-passes via the rooted rule" {
    // The exact live wedge shape: depth8_slot=424854743 was ~83k slots BELOW
    // the boot root (the restored tower's depth-8 lockout predates this
    // boot's fork-choice tree entirely — clusterVotedStakeAtDepthSlot alone
    // would read 0 here forever, which is the 308-refusals-0-votes wedge).
    const depth8_slot: u64 = 424_854_743;
    const boot_root: u64 = 424_938_112; // cluster-attested root at boot, well past depth8_slot
    const total: u64 = 338_616_020_681_980_752; // the live epoch total from the incident log

    // Rule (a): rooted ⇒ trivial-pass. This is the SPECIFIC path that fixes
    // tonight's wedge — assert it directly, not just the downstream arithmetic.
    try std.testing.expect(ReplayStage.depthSlotAlreadyRooted(depth8_slot, boot_root));

    // Downstream: the call site leaves (thr_voted, thr_total) at (0,0) on this
    // path (never touches clusterVotedStakeAtDepthSlot or any bank source),
    // and thresholdPasses(0,0) trivially passes — the SAME sentinel used for
    // "tower isn't that deep yet", never a fork-blind stake count.
    try std.testing.expect(TowerBft.thresholdPasses(0, 0));
    _ = total; // documents the real magnitude; not fed into the (0,0) trivial-pass path
}

test "KAT (F348b): depth8_slot ABOVE root — armed REFUSE preserved, unattested slot still gates on real (fork-aware) stake" {
    // Once depth_slot is above our root, rule (b) applies unchanged: the sole
    // source is clusterVotedStakeAtDepthSlot (fork-aware, walks OUR ancestry).
    // A slot the cluster has not attested reads 0 stake there ⇒ REFUSE, exactly
    // preserving the armed behavior this whole gate exists for.
    const depth8_slot: u64 = 424_954_800;
    const boot_root: u64 = 424_938_112; // depth8_slot is ABOVE root here
    try std.testing.expect(!ReplayStage.depthSlotAlreadyRooted(depth8_slot, boot_root));

    const total: u64 = 338_616_020_681_980_752;
    // clusterVotedStakeAtDepthSlot would return 0 for an unattested/unvoted
    // slot (see the "real fork-choice glue" test above, unvoted-fork case) —
    // compose that with the armed predicate directly: REFUSE.
    try std.testing.expect(!TowerBft.thresholdPasses(0, total));
}
