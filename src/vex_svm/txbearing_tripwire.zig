//! M3 — auto-safe-off tripwire pure predicate + tracked-state bundle for
//! tx-bearing block production, extracted so the trip DECISION is unit-KAT'd
//! (`zig build test-txbearing-tripwire`) rather than reasoned-correct inline in
//! replay_stage.zig — same discipline as `repair_escalate.zig`'s
//! `phantomSignature`/`clusterConfirmedSkip` and `revive_detect.zig`'s
//! `checkReviveWouldFire` (replay_stage.zig is an unmigrated god-file whose own
//! inline `test` blocks never run under any build target).
//!
//! Design: tx-bearing block production plan, §4 M3. Wiring (the caller side)
//! lives in replay_stage.zig.
//!
//! ── WHAT THIS GUARDS ─────────────────────────────────────────────────────────
//! The 07-10 incident (memory: incident-txbearing-broadcast-leader-skip-
//! regression-2026-07-10.md): arming VEX_TXBEARING_BROADCAST=1 VEX_TPU_INGEST=1
//! VEX_FORCE_INLINE_PRODUCE=1 live caused leader window 421073912-15 (4
//! consecutive slots) to produce parity-diverging blocks — local self-check
//! `[PRODUCE-PARITY-FAIL] total=4` matched the cluster's observed 4 skips 1:1
//! (getBlockProduction [156,152], validators.app 0%→2.56% skip). No automatic
//! response; a human noticed ~20 minutes later and manually stripped the flags.
//! M2 (block_produce.zig admitTxSeq) fixed the PROVEN transfer-drain/
//! CreateAccount-drain mechanism; M2b gave the produce tile a safe (non-inline)
//! way to run that same fixed gate. Both close the mechanism M1 CONFIRMED fired
//! on 07-10. Named residuals remain uncovered by the gate itself (M2's own
//! progress log): CreateAccountWithSeed/TransferWithSeed (variable-length
//! bincode String — mis-parse risk), WithdrawNonceAccount + stake/vote
//! withdraws (program-specific layouts unverified), ALT-loaded (v0) account
//! indices (not wire-resolvable), and any lamport-mover whose `from` is NOT the
//! tx's own fee-payer (applied optimistically — no live oracle for a third-party
//! account). This tripwire is defense-in-depth against ANY of those residuals
//! (or an unknown future mechanism) recurring live: it cannot PREVENT the first
//! bad block (that is the gate's job, and the gate is already the best offline-
//! provable defense — see M2/M2b), but it bounds the BLAST RADIUS of a
//! recurrence to a small, fixed number of dead slots instead of an entire
//! leader window, with zero operator latency and zero process restart.
//!
//! ── SIGNAL CHOSEN: [PRODUCE-PARITY-FAIL] on a self-produced TX-BEARING slot ──
//! `[PRODUCE-PARITY-FAIL]` (replay_stage.zig ~9202, enriched by M1's f3fc4d2
//! with sig_prefix/fee_payer/same_block_earlier_writer) fires when OUR OWN
//! loopback replay hits a NotLoaded fee-payer tx in a block we self-produced.
//! Because block_produce.zig's banner documents that BOTH the broadcast path
//! and the loopback path reuse the IDENTICAL `leader_poh`/`produceSlotBytes`
//! machinery on the IDENTICAL entry bytes, our own loopback replay executing a
//! NotLoaded tx is the SAME deterministic outcome the cluster's own independent
//! replay of those same bytes would hit — and per Agave's block-fatal
//! classification (blockstore_processor.rs:149 get_first_error → mark_dead_slot,
//! cited at block_produce.zig:91-93), any Err during replay marks the WHOLE
//! slot dead. This is why the 07-10 incident's 4 local parity-fails and 4
//! cluster-observed skips matched exactly 1:1 (plan §1) — a transport failure
//! would not produce that correlation; a receive-and-reject failure does.
//! PROPERTIES that make this the PRIMARY (hard-trip) signal:
//!   - FAST: in-process, zero network round-trip. Fires the instant our own
//!     replay commits the bad tx — no cluster-oracle latency to wait out.
//!   - ~ZERO FALSE-POSITIVE RATE FROM ORDINARY CONDITIONS: it is a
//!     deterministic, content-driven execution outcome of OUR OWN bytes (did
//!     THIS tx's fee-payer actually have enough lamports when THIS tx replayed
//!     sequentially), not a timing/liveness observation. Network jitter, a
//!     momentarily-slow peer, or an ordinary SlotHashes refresh lag cannot make
//!     this fire when it otherwise wouldn't.
//!   - REUSES existing, already-live infrastructure (the M1 diagnostic
//!     enrichment), rather than inventing a parallel detector.
//!
//! ── SIGNAL CONSIDERED AND NOT WIRED AS A SECOND HARD TRIGGER: cluster-oracle
//!    absence-after-timeout (scanCachedSlotHash never showing our self-produced
//!    slot canonical) ──────────────────────────────────────────────────────────
//! Structurally available (mirrors the EXISTING sweepPendingTickGateSlots /
//! sweepPendingFecGateSlots 30s-timeout pattern in replay_stage.zig, which
//! already reuses this exact cluster-oracle seam for an analogous
//! "did the cluster confirm this the way we expected" question) — but its
//! polarity for THIS question is inverted (those sweeps treat "no positive
//! confirmation within 30s" as "assume canonical", the opposite of what a skip-
//! detector needs) and, more importantly, it is NETWORK-TIMING-dependent: an
//! ordinary SlotHashes refresh lag, RPC hiccup, or a benign momentary partition
//! can produce the SAME "absent after N seconds" shape as a genuine cluster
//! skip. Wiring it as a second independent HARD trip trigger risks exactly the
//! failure mode this milestone's own brief warns against ("trip too early = we
//! lose fee revenue on a network blip"), for a failure class (H4: shred/FEC-
//! only breakage, scored LOW-UNVERIFIED in the RCA — no evidence it has ever
//! fired) that the PP signal cannot see. NOT built in this milestone; named as
//! a residual gap in TXBEARING-M3-PROGRESS.log for a future line if the
//! cluster-oracle signal is ever needed as a hard trigger (it would need its
//! own hysteresis tuned independently, on live-traffic evidence, the same way
//! this milestone's PP-consecutive threshold was reasoned from the ONE real
//! incident's own shape — not guessed in advance).
//!
//! ── THRESHOLD: 2 self-produced tx-bearing slots showing [PRODUCE-PARITY-FAIL]
//!    with no intervening SUCCESSFUL tx-bearing slot trips. Not 1, not 4. See
//!    the "HONEST NAMING" note below for the precise (weaker-than-it-sounds)
//!    property this actually is. ─────────────────────────────────────────────
//!   - NOT 1: a single occurrence could be one genuinely rare, non-repeating
//!     residual-instruction edge case (the named residuals above are narrow,
//!     uncommon shapes on testnet's current traffic). Tripping on the very
//!     first occurrence forfeits all tx-bearing revenue for the rest of the
//!     process's life over what could be a one-off; block_produce.zig's own
//!     (pre-incident) comment called this shape "self-healing" for exactly
//!     this reason — wrongly, as it turned out for 07-10's SPECIFIC mempool
//!     shape, but not wrongly in general for a rare residual.
//!   - NOT 4 (07-10's own damage window): the incident's own root-cause chapter
//!     names WHY waiting to the full window doesn't help — multi-slot leader-
//!     window BLOCK-ID CHAINING (replay_stage.zig ~1946-49) means each produced
//!     slot chains off the PREVIOUS SELF-produced block_id, not the cluster's;
//!     once slot 1 fails, slots 2-4 chain off a block the cluster never
//!     accepted and cascade regardless. There is no "wait and see" value in
//!     slots 3-4 — the structural cause of slot 2 failing (the SAME mempool
//!     content driving the SAME gate gap) is already fully evidenced by slot 1
//!     failing alone.
//!   - 2: catches a REAL recurrence within the SAME leader window (bounding the
//!     07-10 cascade shape to at most 2 dead slots instead of 4 — a 50%
//!     reduction of the actual historical damage), while still tolerating
//!     exactly one isolated failure before disarming. This is the minimum
//!     window that distinguishes "isolated residual, does not repeat" from
//!     "systemic, will keep failing" without burning the whole window to find
//!     out.
//! NOT "M of K" (unlike repair_escalate.zig's phantomSignature, which
//! deliberately tolerates historical noise via a response ceiling) — CONSECUTIVE
//! only, with a single interceding CLEAN self-produced TX-BEARING slot
//! resetting the counter to 0. A clean tx-bearing slot between two failures is
//! itself strong evidence the failure is data-dependent/intermittent (the
//! mempool shape that broke admission is no longer present), not a stuck
//! systemic gate bug.
//!
//! HONEST NAMING OF WHAT "CONSECUTIVE" ACTUALLY MEANS (caught in review — the
//! property is WEAKER than "2 fails in the very next 2 leader slots", and this
//! is deliberate, not an oversight): `recordSlotOutcome` is called ONLY for
//! self-produced TX-BEARING slots (the caller gates on `self_produced_tx_bearing.
//! contains(slot)`, see replay_stage.zig); an EMPTY self-produced slot (no txs
//! packed at all — common on low-volume testnet, this milestone's explicit
//! target env) is skipped entirely — neither a failure NOR a reset. So the real
//! trip condition is "2 tx-bearing fails with NO intervening SUCCESSFUL
//! tx-bearing block between them", which can span an arbitrary number of empty
//! leader slots (and arbitrary wall-clock time) in between — NOT literally "the
//! next 2 consecutive leader slots". Concretely: a fail at slot N, many empty
//! slots, a second UNRELATED isolated fail at slot N+400 with no successful
//! tx-bearing block in between, WILL trip — even though the two fails may be
//! unrelated one-offs, exactly the "isolated, self-heals" shape the threshold
//! doc above argues should be tolerated once. This is a KNOWN, ACCEPTED
//! deviation from that argument, kept deliberately because it errs in the SAFE
//! direction: the failure mode is over-tripping (tx-bearing stops slightly
//! more eagerly than the "genuinely 2-in-a-row" ideal would), not under-
//! tripping — no liveness harm (empty-block production continues
//! uninterrupted) and no bounded-blast-radius violation (still at most 2 dead
//! tx-bearing slots before disarming). Resetting the counter on an EMPTY slot
//! instead would make the tripwire nearly inert on low-volume testnet (any
//! isolated fail would almost always have an empty slot before the next
//! tx-bearing attempt, permanently resetting the counter) — worse than the
//! deviation this accepts. An empty self-produced slot is therefore, precisely:
//! not evidence of anything, not a partial reset, not a partial fail — simply
//! absent from the sequence `recordSlotOutcome` ever sees.
//!
//! ── LATCH: never auto-clears, never auto-re-arms ─────────────────────────────
//! Once tripped, `TripwireState` stays tripped for the life of the process — no
//! automatic clearing, no automatic re-arm. Per the standing "no automated
//! restarts — self-heal in-process" rule: the self-heal here IS falling back to
//! the known-good empty-block mode in-process; it is explicitly NOT a self-heal
//! that re-attempts tx-bearing on its own ("a flapping producer is worse than a
//! stopped one"). Re-arming after a trip requires an OPERATOR restart with the
//! flags re-set (a fresh process gets a fresh `TripwireState`) — no in-process
//! re-arm path exists, deliberately: building one would be a second new risky
//! control surface this milestone does not need, and the existing flag-strip-
//! and-restart rollback is already proven (~3min, the 07-10 recovery itself).

const std = @import("std");

/// Consecutive self-produced tx-bearing [PRODUCE-PARITY-FAIL] slots required to
/// trip. See the threshold-reasoning doc above — deliberately 2, not 1 or 4.
pub const TRIP_THRESHOLD: u32 = 2;

/// Small tracked-state bundle, owned by ReplayStage. `consecutive_fails` and
/// `tripped_at_slot` are mutated ONLY on the replay thread (same single-writer
/// discipline as `self_produced`/`self_produced_block_id` — no lock needed).
/// `tripped` is the ONE field read cross-thread (the produce TILE's
/// `produceTileLoop`, core 20, must consult it every tile-produced slot to
/// decide whether to broadcast tx-bearing bytes) — it is therefore the only
/// atomic field, mirroring the EXISTING `produce_tile_active` atomic-bool
/// cross-thread-gate pattern already in ReplayStage.
pub const TripwireState = struct {
    consecutive_fails: u32 = 0,
    tripped: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Diagnostic only (replay-thread-owned; never read from the tile thread —
    /// the tile's own trip log omits it rather than risk a torn cross-thread
    /// read of a non-atomic field).
    tripped_at_slot: u64 = 0,

    /// Record the outcome of one self-produced TX-BEARING slot's loopback
    /// replay. Caller contract: call this EXACTLY ONCE per self-produced
    /// tx-bearing slot, at the point that slot's replay/freeze completes, with
    /// `had_parity_fail` = did >=1 [PRODUCE-PARITY-FAIL] fire for that slot.
    /// Do NOT call this for an empty (non-tx-bearing) self-produced slot — it
    /// has nothing to fail on and is neither a failure nor a clean reset (see
    /// the threshold-reasoning doc's LATCH/threshold section).
    ///
    /// Latch-first (mirrors revive_detect.checkReviveWouldFire's "check the
    /// latch BEFORE the [there: expensive scan; here: any further work]"
    /// discipline): once tripped, every subsequent call is a cheap no-op — the
    /// counter is frozen, never incremented or reset again.
    ///
    /// Returns true iff THIS call is the exact call that transitions
    /// not-tripped -> tripped (so the caller logs the trip exactly once, at
    /// the transition — the same single-fire contract checkReviveWouldFire's
    /// dedup latch gives its caller).
    pub fn recordSlotOutcome(self: *TripwireState, slot: u64, had_parity_fail: bool) bool {
        if (self.tripped.load(.acquire)) return false;
        if (had_parity_fail) {
            self.consecutive_fails += 1;
            if (self.consecutive_fails >= TRIP_THRESHOLD) {
                self.tripped.store(true, .release);
                self.tripped_at_slot = slot;
                return true;
            }
        } else {
            self.consecutive_fails = 0;
        }
        return false;
    }

    /// Effective tx-bearing-broadcast gate: the operator's env-derived flag AND
    /// NOT tripped. Pure w.r.t. env (caller supplies the getenv result) so this
    /// stays testable without env mutation. Safe to call from EITHER thread
    /// (inline path: replay thread; tile path: produce tile thread) — the only
    /// field read is the atomic `tripped`.
    pub fn effectiveArmed(self: *const TripwireState, env_armed: bool) bool {
        return env_armed and !self.tripped.load(.acquire);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// KATs — these DO run (`zig build test-txbearing-tripwire`): this file is its
// own module root, unlike replay_stage.zig's inline tests.
// ═══════════════════════════════════════════════════════════════════════════════

test "recordSlotOutcome: a single isolated fail does NOT trip (below threshold)" {
    var s = TripwireState{};
    try std.testing.expect(!s.recordSlotOutcome(100, true));
    try std.testing.expectEqual(@as(u32, 1), s.consecutive_fails);
    try std.testing.expect(!s.tripped.load(.acquire));
}

test "recordSlotOutcome: 2 CONSECUTIVE fails trips on the 2nd call" {
    var s = TripwireState{};
    try std.testing.expect(!s.recordSlotOutcome(100, true));
    try std.testing.expect(s.recordSlotOutcome(101, true)); // trips HERE
    try std.testing.expect(s.tripped.load(.acquire));
    try std.testing.expectEqual(@as(u64, 101), s.tripped_at_slot);
}

test "recordSlotOutcome: a clean slot in between resets the counter — no cascade to 3 non-consecutive fails" {
    var s = TripwireState{};
    try std.testing.expect(!s.recordSlotOutcome(100, true)); // fail #1
    try std.testing.expect(!s.recordSlotOutcome(101, false)); // clean -> reset
    try std.testing.expectEqual(@as(u32, 0), s.consecutive_fails);
    try std.testing.expect(!s.recordSlotOutcome(102, true)); // fail #1 again (not #2)
    try std.testing.expect(!s.tripped.load(.acquire));
    // NOW two genuinely consecutive fails trips.
    try std.testing.expect(s.recordSlotOutcome(103, true));
    try std.testing.expect(s.tripped.load(.acquire));
}

test "recordSlotOutcome: mirrors the 07-10 4-slot cascade shape — trips at slot 2 of 4, bounding the blast radius" {
    var s = TripwireState{};
    var trips: u32 = 0;
    var trip_slot: u64 = 0;
    const slots = [_]u64{ 421073912, 421073913, 421073914, 421073915 };
    for (slots) |slot| {
        if (s.recordSlotOutcome(slot, true)) {
            trips += 1;
            trip_slot = slot;
        }
    }
    try std.testing.expectEqual(@as(u32, 1), trips); // fires exactly once
    try std.testing.expectEqual(@as(u64, 421073913), trip_slot); // the 2nd slot, not the 4th
}

test "recordSlotOutcome: latch — once tripped, further calls are frozen no-ops (no log spam, no un-trip)" {
    var s = TripwireState{};
    _ = s.recordSlotOutcome(100, true);
    _ = s.recordSlotOutcome(101, true); // trips
    try std.testing.expect(s.tripped.load(.acquire));
    const before = s.consecutive_fails;
    try std.testing.expect(!s.recordSlotOutcome(102, true)); // no 2nd fire
    try std.testing.expect(!s.recordSlotOutcome(103, false)); // no un-trip either
    try std.testing.expectEqual(before, s.consecutive_fails); // frozen, not incremented further
    try std.testing.expectEqual(@as(u64, 101), s.tripped_at_slot); // unchanged
}

test "effectiveArmed: env unset -> always false regardless of tripped state (dark-mode inertness)" {
    var s = TripwireState{};
    try std.testing.expect(!s.effectiveArmed(false));
    _ = s.recordSlotOutcome(1, true);
    _ = s.recordSlotOutcome(2, true); // trips
    // Even tripped, env=false still yields false -- and critically, env=false
    // ALSO yielded false before the trip. Zero observable behavior change from
    // the tripwire's internal state when the operator flag is off: this is the
    // formal inertness property the dark-mode design depends on.
    try std.testing.expect(!s.effectiveArmed(false));
}

test "effectiveArmed: env set + not tripped -> true; env set + tripped -> false" {
    var s = TripwireState{};
    try std.testing.expect(s.effectiveArmed(true));
    _ = s.recordSlotOutcome(1, true);
    _ = s.recordSlotOutcome(2, true); // trips
    try std.testing.expect(!s.effectiveArmed(true));
}

test "recordSlotOutcome: ordinary intermittent single-skip-then-recover traffic never trips, across a long run" {
    // Simulates the "trip too early = lose fee revenue on a network blip" concern
    // this milestone explicitly weighs against: isolated fails, never 2 in a row,
    // over a long run of slots. Must never trip.
    var s = TripwireState{};
    var slot: u64 = 0;
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        slot += 1;
        try std.testing.expect(!s.recordSlotOutcome(slot, true)); // isolated fail
        slot += 1;
        try std.testing.expect(!s.recordSlotOutcome(slot, false)); // recovers
    }
    try std.testing.expect(!s.tripped.load(.acquire));
}
