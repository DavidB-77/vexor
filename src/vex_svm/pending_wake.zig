//! Pure WAKE-decision predicate for CHAIN-DEFER `pending_chain` entries.
//!
//! Extracted from `replay_stage.zig:checkPendingChain` so the wake gate — the
//! decision that re-drives a deferred child slot once its parent situation
//! changes — is PROVEN by unit test, not reasoned-correct in place. This is the
//! advisor-mandated discriminator before the orphan-repair FETCH fix
//! (2026-05-30): the live stalled validator shows frozen_set=116 stable, root
//! pinned, 9009 pending, 0 CHAIN-WAKE — consistent with FETCH-blocked (parents
//! never fetched, so never frozen, so the wake never fires). This test confirms
//! the wake logic itself is correct, i.e. the moment a parent IS fetched and
//! frozen, its deferred child DOES wake — so FETCH alone is the missing piece.
//!
//! A child slot S is deferred keyed on its `target_parent` P (the parent it is
//! waiting to become replayable). `checkPendingChain` wakes S when ANY of three
//! Agave-canonical conditions holds:
//!   (a) P just froze this tick           `tp == frozen_slot`
//!   (b) P is at or below root            `root_slot > 0 and tp <= root_slot`
//!        (d27z: d21 falls back to root_bank as the parent in that case)
//!   (c) P is anywhere in the frozen set  `frozen_set.contains(tp)`
//!        (PR-S5: Agave generate_new_bank_forks semantics — independent of the
//!         ordering between the defer event and the parent's freeze event)
//!
//! Imports only std → unit-testable standalone (`zig build test-pending-wake`).

const std = @import("std");

/// Returns true iff a `pending_chain` entry whose `target_parent == tp` should
/// be woken (removed from pending_chain and re-pushed for replay) given the
/// `frozen_slot` whose freeze triggered this pass, the current `root_slot`, and
/// the set of all currently-frozen slots `frozen_set`.
///
/// This is the EXACT predicate at `replay_stage.zig:checkPendingChain`. The
/// caller MUST call this function rather than duplicating the boolean, so the
/// two never drift.
pub fn shouldWakePending(
    tp: u64,
    frozen_slot: u64,
    root_slot: u64,
    frozen_set: *const std.AutoHashMap(u64, void),
) bool {
    return tp == frozen_slot or
        (root_slot > 0 and tp <= root_slot) or
        frozen_set.contains(tp);
}

/// FIX #112 (2026-05-30): drop decision for an UNCONNECTED `pending_chain` entry.
///
/// Canonical invariant (Agave `bank_forks.get_non_rooted` fires ONLY from
/// `set_root`; Firedancer removes from the forest ONLY in `fd_forest_publish`):
/// a not-yet-replayed slot may be dropped as "below root" ONLY when the monotonic
/// CONSENSUS root (`db.rooted_slot`) has advanced strictly past it — NEVER as a
/// side effect of some other slot merely freezing.
///
/// The wedge this fixes: the prior code keyed the drop on `self.root_bank.slot`,
/// which is the LAST-FROZEN bank (replay_stage.zig:2662 stores it on every
/// freeze), not the consensus root. It is non-monotonic — observed live going
/// 869→870→874→876→872. When an out-of-order minority freeze (slot 876, FIX #55)
/// transiently set root_bank=876, the canonical bridge slots 873/875 (received,
/// above the TRUE root 872) were dropped before 872 even froze, permanently
/// orphaning the canonical chain. `db.rooted_slot` is the tower/consensus root
/// (set only via `advanceRoot`, monotonic-guarded) and cannot be a minority slot.
///
/// `rooted_slot == 0` (pre-first-root, e.g. catchup before voting resumes)
/// disables the drop → full retention, matching Agave's "blockstore holds all
/// shreds; replay retains until root advances" behavior. Strict `<` keeps the
/// root slot itself (Agave `get_non_rooted` retains `slot == root`).
pub fn shouldDropBelowRoot(slot: u64, rooted_slot: u64) bool {
    return rooted_slot > 0 and slot < rooted_slot;
}

/// FIX #112 (2026-05-30): FAST-WAKE readiness for a deferred child (the PR-5ak
/// fast-path that pushes a child straight to replay instead of waiting for a
/// freeze-triggered `checkPendingChain` sweep).
///
/// A child's `target_parent` is "ready" iff the parent is ACTUALLY frozen, OR the
/// parent is at/below the CONSENSUS root (`rooted_slot`) — a rooted parent is a
/// legitimate boundary parent that `getOrCreateBank` resolves against the root
/// bank.
///
/// Keying the root-fallback on `db.rooted_slot` (NOT the non-monotonic
/// `root_bank.slot`) is what breaks the FAST-WAKE ⇄ getOrCreateBank-reject
/// livelock (the historical "104M+ log mentions" wedge): when root_bank
/// transiently exceeds the true root, a canonical child whose `target_parent` is
/// just above the real root is no longer mis-judged "ready", fast-wake-pushed,
/// and then rejected by getOrCreateBank (`root_bank >= slot`) in a tight loop —
/// it instead rests in `pending_chain` until its real parent freezes (woken via
/// `shouldWakePending`'s `tp == frozen_slot` / `frozen_set` paths). Normal
/// in-order catchup throughput is preserved because the common case wakes via
/// `parent_frozen == true`, independent of how far `rooted_slot` lags.
///
/// FIX #18a-B (2026-06-12, CARRIER #18 wedge @414926973): the rooted-boundary
/// arm must MIRROR resolveParent's d28mm guard. resolveParent refuses the
/// root-fallback build when `root_bank_slot >= slot` (building on the freeze-tip
/// bank would give the child a parent ABOVE itself / a wrong-fork state). The
/// old predicate here did not know (root_bank_slot, slot), so for the live
/// wedge state — parent bank evicted, target_parent == consensus_root
/// (414926972), freeze-tip (414930423) >= slot (414926973) — fast-wake said
/// READY while resolve said DEFER: a tight defer→push→defer livelock with a
/// 2.5MB payload memcpy per lap (RSS 37→115GB over ~3.4h, replay starved,
/// total stall). The two predicates MUST agree: ready-via-rooted-boundary only
/// when the build would actually be accepted (`root_bank_slot < slot`). The
/// parent_frozen arm is unchanged — a genuinely frozen parent connects
/// directly in resolveParent regardless of the freeze-tip.
pub fn parentReadyForFastWake(
    parent_frozen: bool,
    target_parent: u64,
    rooted_slot: u64,
    root_bank_slot: u64,
    slot: u64,
) bool {
    return parent_frozen or
        (rooted_slot > 0 and target_parent <= rooted_slot and root_bank_slot < slot);
}

/// FAR_AHEAD_THRESHOLD gate for `pushSlotForReplay[WithBoundaries]`, mirrored
/// against `parentReadyForFastWake`'s parent-frozen arm the same way that
/// function mirrors `resolveParent`'s guard.
///
/// The disease this closes: the FAR_AHEAD check used to key off the LAST-FROZEN
/// bank (`root_bank.slot`), which is non-monotonic — out-of-order catchup churn
/// can make it dip backward. When it dipped more than `threshold` slots behind a
/// child whose parent `parentReadyForFastWake` had ALREADY certified genuinely
/// frozen (its unconditional `parent_frozen == true` arm), FAR_AHEAD disagreed
/// and bounced the fast-woken push straight back into the deferral path, which
/// re-derived the SAME frozen-parent fact and re-fired fast-wake — an unbounded
/// push↔defer recursion (observed live on testnet: slot=423543960,
/// target_parent=423543859 frozen, last-frozen dipped to 423543751 from a
/// high-water mark of 423543887, gap=209 > threshold=200).
///
/// FIX: never key FAR_AHEAD off the volatile freeze-tip. Key it off a
/// monotonically non-decreasing high-water mark of the highest slot ever
/// frozen (only ever advanced forward, at the single canonical freeze-record
/// point) so an out-of-order backward freeze can never re-widen a gap the
/// forward-progress high-water mark had already closed. This is the same
/// discipline `parentReadyForFastWake`'s root-fallback arm above already
/// applies: a non-monotonic quantity must never be allowed to contradict a
/// fact another gate already certified.
pub fn isFarAheadOfReplay(slot: u64, highest_frozen_slot: u64, threshold: u64) bool {
    return slot > highest_frozen_slot + threshold;
}

/// The three outcomes of `getOrCreateBank`'s parent-ancestor selection.
pub const ParentResolve = enum {
    /// A frozen ancestor exists exactly at `target_parent` (or `target_parent`
    /// is the always-frozen freeze-tip boundary) → build the child on it.
    connected,
    /// `target_parent` is at/below the CONSENSUS root → a genuinely-rooted,
    /// squashed boundary parent → build the child on the root bank.
    use_root_fallback,
    /// Parent is not yet replayable → DEFER into pending_chain (caller returns
    /// error.UnconnectedSlot); CHAIN-WAKE re-drives it when the parent freezes.
    defer_unconnected,
};

/// Pure replica of `replay_stage.zig:getOrCreateBank`'s parent-ancestor
/// decision. Extracted (2026-06-05) so the decision is unit-PROVEN, not
/// reasoned-correct in place — same discipline as `shouldWakePending`. The
/// caller MUST call this rather than duplicating the branch, so the two cannot
/// drift.
///
/// CARRIER 413389395 FIX: the root-fallback is keyed on the monotonic CONSENSUS
/// root (`consensus_root` = db.rooted_slot), NOT the freeze-tip
/// (`root_bank_slot` = self.root_bank.slot). The freeze-tip advances on EVERY
/// freeze and is non-monotonic, so an orphan sibling that froze first can
/// masquerade as "root" and capture a child whose true parent is BELOW the
/// freeze-tip but ABOVE the consensus root. That is exactly the 413389395 bug:
/// cluster canonical chain 392→393→395 (394 SKIPPED); Vexor built orphan 394
/// (froze first → freeze-tip=394); slot 395's true parent 393 satisfied the old
/// `target_parent <= root_bank_slot` (393 ≤ 394) → 395 was built on the orphan
/// 394 instead of deferring for 393 → wrong SlotHashes → all votes rejected →
/// accounts_lt_hash divergence → delinquency. This is the same principle FIX
/// #112 applied to the drop + fast-wake paths (`shouldDropBelowRoot`,
/// `parentReadyForFastWake`); it had not been applied to getOrCreateBank's
/// resolve. `consensus_root == 0` (pre-first-root / catchup) disables the
/// fallback → pure defer-until-parent-frozen, matching `parentReadyForFastWake`.
pub fn resolveParent(
    target_parent: u64,
    parent_frozen: bool, // banks[target_parent] exists AND is_frozen
    root_bank_slot: u64, // self.root_bank.slot (freeze-tip; always frozen)
    root_bank_frozen: bool, // self.root_bank.is_frozen
    consensus_root: u64, // db.rooted_slot (0 if no accounts_db / pre-first-root)
    slot: u64, // the child slot being created
) ParentResolve {
    // self.root_bank is the LAST-FROZEN bank by construction (set on every
    // freeze), so the freeze-tip boundary does NOT need an is_frozen re-check.
    // Gating on a freshly-read root_bank_frozen flag LIVELOCKS during catchup:
    // when consensus_root==0 (pre-first-root) and the flag read races the freeze,
    // a child whose target_parent IS the freeze-tip would defer → wake → defer
    // forever (observed live 2026-06-05 slot 413406746). Param retained for
    // signature/test stability but intentionally not consulted.
    _ = root_bank_frozen;
    // A frozen ancestor exactly at target_parent → connected (ancestor.slot == tp).
    if (parent_frozen) return .connected;
    // Root fallback in TWO cases, both of which build the child on root_bank:
    //   (a) CONTIGUOUS forward: target_parent IS the freeze-tip (the common
    //       in-order case; matches the pre-fix unconditional `tp == root.slot`).
    //   (b) ROOTED boundary: target_parent at/below the monotonic CONSENSUS root
    //       (a genuinely-rooted/squashed parent). FIX#112 principle.
    // The carrier case — target_parent STRICTLY BELOW the freeze-tip AND ABOVE
    // the consensus root and unfrozen (413389395: tp=393, freeze-tip=394,
    // consensus_root<393) — matches NEITHER → DEFER, instead of attaching to the
    // orphan freeze-tip. That is the whole fix.
    const is_freeze_tip = (target_parent == root_bank_slot);
    const is_rooted = (consensus_root > 0 and target_parent <= consensus_root);
    if (is_freeze_tip or is_rooted) {
        // d28mm guard: root advanced past this slot → defer (avoid parent > slot).
        if (root_bank_slot >= slot) return .defer_unconnected;
        return .use_root_fallback;
    }
    return .defer_unconnected;
}

/// The PRE-FIX (buggy) resolve logic — root-fallback keyed on the freeze-tip.
/// Kept ONLY so the unit tests can DISCRIMINATE: a test that asserts
/// `resolveParentLegacy(...) == .use_root_fallback` AND `resolveParent(...) ==
/// .defer_unconnected` on the real 413389395 numbers proves the test actually
/// catches the carrier (it is not rubber-stamping whatever the new code does).
/// NOT called by production code.
pub fn resolveParentLegacy(
    target_parent: u64,
    parent_frozen: bool,
    root_bank_slot: u64,
    root_bank_frozen: bool,
    slot: u64,
) ParentResolve {
    if (parent_frozen) return .connected;
    if (target_parent == root_bank_slot and root_bank_frozen) return .connected;
    if (target_parent <= root_bank_slot) { // BUG: freeze-tip, not consensus root
        if (root_bank_slot >= slot) return .defer_unconnected;
        return .use_root_fallback;
    }
    return .defer_unconnected;
}

test "shouldWakePending (a): target_parent just froze → wake" {
    var frozen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer frozen.deinit();
    // tp == frozen_slot wakes even with root unset and tp not in the set.
    try std.testing.expect(shouldWakePending(500, 500, 0, &frozen));
}

test "shouldWakePending (b): target_parent at/below root → wake; above root → no wake" {
    var frozen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer frozen.deinit();
    try std.testing.expect(shouldWakePending(400, 999, 450, &frozen)); // 400 < 450
    try std.testing.expect(shouldWakePending(450, 999, 450, &frozen)); // tp == root boundary
    // 451 > root, not frozen, != frozen_slot → must NOT wake.
    try std.testing.expect(!shouldWakePending(451, 999, 450, &frozen));
}

test "shouldWakePending (c) PR-S5: target_parent in frozen_set → wake even if != frozen_slot and > root" {
    var frozen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer frozen.deinit();
    try frozen.put(700, {}); // parent 700 has frozen (e.g. orphan-repair fetched it)
    // tp=700 is in the set, but != frozen_slot(999) and > root(600) → STILL wakes.
    try std.testing.expect(shouldWakePending(700, 999, 600, &frozen));
}

test "shouldWakePending: FETCH-blocked then FETCH→WAKE transition (the live 9009-pending case)" {
    var frozen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer frozen.deinit();
    try frozen.put(116, {}); // an unrelated frozen slot (mirrors the live frozen_set region)
    // Child waiting on bridge-ancestor 800: not frozen, > root(600), != frozen_slot(116).
    // This is EXACTLY the live stall — the wake correctly does NOT fire.
    try std.testing.expect(!shouldWakePending(800, 116, 600, &frozen));
    // Once orphan-repair fetches 800 and it freezes, the SAME child now wakes.
    // Proves the stall is FETCH (no parent), not a broken WAKE.
    try frozen.put(800, {});
    try std.testing.expect(shouldWakePending(800, 116, 600, &frozen));
}

test "shouldWakePending: root==0 guard — condition (b) disabled at bootstrap" {
    var frozen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer frozen.deinit();
    // root_slot==0 must NOT wake everything with tp<=0; tp=0 not frozen, != frozen_slot(5).
    try std.testing.expect(!shouldWakePending(0, 5, 0, &frozen));
}

test "FIX #112 shouldDropBelowRoot: retain above-root canonical slots, drop only below CONSENSUS root" {
    // The exact live wedge (slots 412002872..877): consensus root = 872
    // (canonical, monotonic tower root). Minority 874/876 froze out of order and
    // the OLD code used root_bank=876 (last-frozen) as the drop threshold, so it
    // dropped the canonical bridge slots 873/875. Keyed on the CONSENSUS root:
    try std.testing.expect(!shouldDropBelowRoot(873, 872)); // RETAINED (873 > 872)
    try std.testing.expect(!shouldDropBelowRoot(875, 872)); // RETAINED (875 > 872)
    try std.testing.expect(!shouldDropBelowRoot(877, 872)); // RETAINED (the wedge slot)
    // Genuinely-below-root slots still drop (canonical GC continues to work):
    try std.testing.expect(shouldDropBelowRoot(870, 872));
    try std.testing.expect(shouldDropBelowRoot(871, 872));
    // slot == root is NOT dropped (Agave get_non_rooted retains the root itself):
    try std.testing.expect(!shouldDropBelowRoot(872, 872));
    // root == 0 (pre-first-root / catchup before voting) → drop disabled, full
    // retention. This is the key immunity: even if rooted_slot lags at the
    // snapshot during catchup, the canonical bridge is never dropped.
    try std.testing.expect(!shouldDropBelowRoot(875, 0));
    try std.testing.expect(!shouldDropBelowRoot(1, 0));
    // Contrast — the OLD buggy threshold (root_bank=876) WOULD have dropped them,
    // which is precisely the bug:
    try std.testing.expect(shouldDropBelowRoot(873, 876));
    try std.testing.expect(shouldDropBelowRoot(875, 876));
}

test "FIX #112 parentReadyForFastWake: loop-freedom for the out-of-order minority freeze" {
    // 875's target_parent = 873; consensus root = 872; 873 not yet frozen.
    // OLD bug: keyed on root_bank=876 → 873<=876 → "ready" → fast-wake-push 875 →
    //   getOrCreateBank rejects (876>=875) → defer → (drop no longer catches it
    //   once #112 retention lands) → fast-wake again → LIVELOCK.
    // FIX: keyed on consensus root=872 → 873<=872 is false AND parent not frozen
    //   → NOT ready → 875 rests in pending_chain (no re-push loop).
    // (#18a-B: freeze-tip 876 / child 875 passed through; irrelevant to these
    //  arms but keeps the live numbers.)
    try std.testing.expect(!parentReadyForFastWake(false, 873, 872, 876, 875));
    // Once 873 actually freezes, the SAME child becomes ready via parent_frozen:
    try std.testing.expect(parentReadyForFastWake(true, 873, 872, 876, 875));
    // Throughput preserved: normal in-order catchup fast-wakes via parent_frozen
    // regardless of how far the consensus root lags (rooted_slot may sit at the
    // snapshot during catchup → 0 here):
    try std.testing.expect(parentReadyForFastWake(true, 999, 0, 999, 1000));
    // A genuinely-rooted parent (tp <= consensus root) is a valid boundary parent
    // when the freeze-tip is BELOW the child (normal boundary case):
    try std.testing.expect(parentReadyForFastWake(false, 872, 872, 873, 875));
    // root == 0 with parent not frozen → never spuriously "ready":
    try std.testing.expect(!parentReadyForFastWake(false, 5, 0, 0, 6));
}

test "FIX #18a-B parentReadyForFastWake: CARRIER #18 live wedge numbers (DISCRIMINATING)" {
    // The EXACT live wedge state (2026-06-12 18:42 UTC, 3.4h stall, RSS 115GB):
    //   re-delivered slot 414926973, target_parent 414926972 (== consensus root,
    //   bank evicted ⇒ parent_frozen=false), freeze-tip root_bank=414930423.
    // resolveParent: is_rooted(972<=972) → d28mm guard (30423 >= 973) → DEFER.
    // OLD fast-wake (no d28mm mirror): 972<=972 → READY → push → defer → READY…
    // NEW: root_bank_slot(30423) >= slot(973) → NOT ready → rests in pending_chain.
    try std.testing.expect(!parentReadyForFastWake(false, 414926972, 414926972, 414930423, 414926973));
    // resolveParent agrees (defer) — the two predicates are now CONSISTENT:
    try std.testing.expectEqual(
        ParentResolve.defer_unconnected,
        resolveParent(414926972, false, 414930423, true, 414926972, 414926973),
    );
    // If the parent bank were still present+frozen, both accept (connected/ready):
    try std.testing.expect(parentReadyForFastWake(true, 414926972, 414926972, 414930423, 414926973));
    try std.testing.expectEqual(
        ParentResolve.connected,
        resolveParent(414926972, true, 414930423, true, 414926972, 414926973),
    );
    // Normal rooted-boundary build (freeze-tip below child) still fast-wakes:
    try std.testing.expect(parentReadyForFastWake(false, 414926972, 414926972, 414926972, 414926973));
}

test "FIX #18a-B INVARIANTS: loop-freedom + forward-progress (fails on EITHER #18a regression)" {
    // Task #24 demands a re-implementation that fixes the carrier-18 livelock WITHOUT the
    // forward-progress regression #18a was suspected of (the real post-soak tower stall was
    // carrier-20, fixed independently in ancestorChainComplete). This pins the predicate from
    // BOTH sides over a small state grid so it can be neither too LOOSE (re-opens the wedge)
    // nor too STRICT (strands a buildable rooted-boundary child). Either failure mode breaks a
    // concrete assertion below — that is what makes it a regression test, not a rubber stamp.
    //
    //   (LF) loop-freedom:    fast-wake READY ⇒ resolveParent does NOT defer. Else a fast-wake
    //        push is re-deferred by getOrCreateBank in a tight spin = the 3.4h / 115GB wedge.
    //   (FP) forward-progress: resolveParent would BUILD a not-yet-frozen child on the ROOTED
    //        boundary (use_root_fallback, target_parent ≤ consensus_root) ⇒ fast-wake MUST be
    //        READY. Else the child rests in pending_chain forever — its rooted/squashed parent
    //        will not re-freeze to wake it. THIS is the forward-progress regression the task names.
    //
    // The parent_frozen arm is excluded (it trivially wakes via the unchanged arm and CONNECTS in
    // resolveParent). The freeze-tip-only arm (tp==ftip, NOT ≤ root) reaches use_root_fallback only
    // with an EVICTED freeze-tip parent — a distinct corner owned by #18a-A dedup / the sentinel
    // path, not this rooted arm — so (FP) is asserted where both predicates share the rooted boundary.
    var rooted: u64 = 1;
    while (rooted <= 6) : (rooted += 1) {
        var tp: u64 = 0;
        while (tp <= 8) : (tp += 1) {
            var ftip: u64 = 1;
            while (ftip <= 8) : (ftip += 1) {
                var slot: u64 = tp + 1; // a child is always above its parent
                while (slot <= 10) : (slot += 1) {
                    const ready = parentReadyForFastWake(false, tp, rooted, ftip, slot);
                    const res = resolveParent(tp, false, ftip, true, rooted, slot);
                    if (ready) try std.testing.expect(res != .defer_unconnected); // (LF)
                    if (res == .use_root_fallback and tp <= rooted) try std.testing.expect(ready); // (FP)
                }
            }
        }
    }
}

// ─── resolveParent: the 413389395 wrong-parent carrier (DISCRIMINATING) ──────
//
// These tests encode the ACTUAL live slot numbers and assert that the NEW
// (consensus-root-keyed) logic DEFERS slot 395 while the OLD (freeze-tip-keyed)
// logic would have built it on the orphan 394. The legacy-vs-new contrast is the
// proof the test catches the carrier rather than rubber-stamping the new code.

test "resolveParent CARRIER 413389395: new DEFERS, legacy USE_ROOT (discriminator)" {
    // Live seam state at the moment 395 was created (recorder meta + cluster RPC):
    //   target_parent = 413389393 (395's true parent, from the shred wire-format;
    //                   cluster getBlock(413389395).parentSlot == 413389393)
    //   393 NOT yet frozen (it was deferred waiting on its own parent 392)
    //   freeze-tip root_bank = 413389394 (the orphan that froze first), frozen
    //   consensus root db.rooted_slot = 413389353 (recorder meta "rooted")
    //   child slot = 413389395
    const tp: u64 = 413389393;
    const tip: u64 = 413389394;
    const consensus_root: u64 = 413389353;
    const slot: u64 = 413389395;

    // NEW logic: 393 is above consensus_root (353) and below the freeze-tip (394)
    // and not frozen → DEFER (wait for 393 to freeze on its real parent 392).
    try std.testing.expectEqual(
        ParentResolve.defer_unconnected,
        resolveParent(tp, false, tip, true, consensus_root, slot),
    );
    // OLD logic: 393 <= 394 (freeze-tip) → builds 395 on the orphan 394. THE BUG.
    try std.testing.expectEqual(
        ParentResolve.use_root_fallback,
        resolveParentLegacy(tp, false, tip, true, slot),
    );
    // Both differ → the test genuinely discriminates the fix from the carrier.
    try std.testing.expect(resolveParent(tp, false, tip, true, consensus_root, slot) !=
        resolveParentLegacy(tp, false, tip, true, slot));
}

test "resolveParent CARRIER 413389395: once 393 freezes, 395 CONNECTS to it" {
    // After 393 freezes on its real parent 392 and CHAIN-WAKE re-drives 395:
    const tp: u64 = 413389393;
    try std.testing.expectEqual(
        ParentResolve.connected,
        resolveParent(tp, true, 413389394, true, 413389353, 413389395),
    );
}

test "resolveParent: rooted-parent boundary still uses root (NOT broken by the fix)" {
    // A genuinely-rooted parent (tp <= consensus root) is a legitimate squashed
    // boundary parent — must STILL resolve to the root bank, not defer.
    // freeze-tip (873) must be < child slot (875), else the d28mm guard
    // (root raced past slot) correctly defers instead — see the test below.
    const tp: u64 = 412000870;
    const consensus_root: u64 = 412000872;
    try std.testing.expectEqual(
        ParentResolve.use_root_fallback,
        resolveParent(tp, false, 412000873, true, consensus_root, 412000875),
    );
}

test "resolveParent: freeze-tip boundary uses root even at root==0 (NO catchup livelock)" {
    // CONTIGUOUS catchup / snapshot-anchor: target_parent == the freeze-tip,
    // consensus_root==0 (pre-first-root). MUST build on root, NOT defer — else
    // wake↔defer livelock. This is the exact regression the live deploy hit at
    // slot 413406746 (tp==freeze-tip==413406745, consensus_root=0). is_frozen of
    // the root bank is NOT consulted (param=false here on purpose).
    try std.testing.expectEqual(
        ParentResolve.use_root_fallback,
        resolveParent(500, false, 500, false, 0, 501),
    );
    // The live livelock numbers, exactly:
    try std.testing.expectEqual(
        ParentResolve.use_root_fallback,
        resolveParent(413406745, false, 413406745, false, 0, 413406746),
    );
    // And the 413389395 carrier STILL defers (the fix is preserved): tp strictly
    // below the freeze-tip, above consensus root, unfrozen → defer, NOT root.
    try std.testing.expectEqual(
        ParentResolve.defer_unconnected,
        resolveParent(413389393, false, 413389394, false, 413389353, 413389395),
    );
}

test "resolveParent: d28mm guard — root advanced past slot → defer" {
    // tp <= consensus_root would route to use_root, but the freeze-tip is already
    // >= the child slot (root raced past) → must defer, never parent>slot.
    try std.testing.expectEqual(
        ParentResolve.defer_unconnected,
        resolveParent(900, false, 905, true, 905, 902),
    );
}

test "resolveParent: catchup (consensus_root==0) defers a gap instead of guessing root" {
    // During catchup before the first root, an unfrozen non-tip parent must defer
    // (wait for it to freeze), NOT fall back to root. Legacy would have used root.
    try std.testing.expectEqual(
        ParentResolve.defer_unconnected,
        resolveParent(700, false, 750, true, 0, 760),
    );
    try std.testing.expectEqual(
        ParentResolve.use_root_fallback, // legacy: 700 <= 750 freeze-tip → guess root
        resolveParentLegacy(700, false, 750, true, 760),
    );
}

// ─── shouldWakePending: the 413389395 livelock band (DISCRIMINATING) ─────────
//
// The freeze-sweep wake must be keyed on the CONSENSUS root too, or it would
// spuriously wake 395 (393 <= freeze-tip 394) → getOrCreateBank re-defers it →
// wake↔defer churn on every freeze. Passing the consensus root removes the
// spurious wake while still waking the moment 393 actually freezes.
test "shouldWakePending CARRIER 413389395: freeze-tip would livelock, consensus root does not" {
    var frozen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer frozen.deinit();
    const tp: u64 = 413389393; // 395's target_parent, not yet frozen
    const some_unrelated_freeze: u64 = 413389396; // a later sibling freeze fires the sweep
    const freeze_tip: u64 = 413389394;
    const consensus_root: u64 = 413389353;

    // BUG (freeze-tip): 393 <= 394 → spurious wake → re-defer → livelock.
    try std.testing.expect(shouldWakePending(tp, some_unrelated_freeze, freeze_tip, &frozen));
    // FIX (consensus root): 393 > 353, not frozen, != frozen_slot → NO wake.
    try std.testing.expect(!shouldWakePending(tp, some_unrelated_freeze, consensus_root, &frozen));
    // But the instant 393 ACTUALLY freezes, it wakes via (a) tp == frozen_slot:
    try std.testing.expect(shouldWakePending(tp, tp, consensus_root, &frozen));
    // …and via (c) once 393 is in the frozen set, independent of event ordering:
    try frozen.put(tp, {});
    try std.testing.expect(shouldWakePending(tp, some_unrelated_freeze, consensus_root, &frozen));
}

// ─── isFarAheadOfReplay: fast-wake/far-ahead push↔defer recursion (DISCRIMINATING) ──
//
// slot 423543960's parent (423543859) genuinely froze — parentReadyForFastWake's
// parent_frozen arm correctly says READY. The OLD FAR_AHEAD gate, keyed on the
// volatile last-frozen slot (which had just dipped 423543887→423543751, a
// 136-slot backward jump from out-of-order catchup churn), then disagreed and
// bounced the fast-woken push back into a synchronous re-defer — closing an
// unbounded recursive cycle. The FIX keys FAR_AHEAD on a monotonic high-water
// mark that cannot dip below 423543887 regardless of out-of-order freeze
// ordering, so the two gates can no longer disagree on this slot.

test "isFarAheadOfReplay 423543960: OLD (last-frozen slot) recurses, NEW (monotonic high-water) does not" {
    const slot: u64 = 423543960;
    const target_parent: u64 = 423543859; // frozen — parentReadyForFastWake says READY
    const last_frozen_slot_dipped: u64 = 423543751; // last-frozen, AFTER the 136-slot backward jump
    const highest_frozen_slot: u64 = 423543887; // monotonic high-water mark (never dips)
    const threshold: u64 = 200;

    // Sanity: parentReadyForFastWake genuinely certifies this parent ready
    // (parent_frozen=true arm — unconditional; the parent really is frozen).
    try std.testing.expect(parentReadyForFastWake(true, target_parent, 0, last_frozen_slot_dipped, slot));

    // OLD behavior (the raw arithmetic the pre-fix code performed inline —
    // `slot > last_frozen_slot + threshold`): 423543960 > 423543751 + 200
    // (423543951) → TRUE → FAR_AHEAD fires → bounces the fast-woken push back
    // to defer → recursion. This line proves the exact live gap (209 > 200,
    // margin of 9) that tripped the wedge.
    try std.testing.expect(slot > last_frozen_slot_dipped + threshold);

    // NEW: gate on the monotonic high-water mark instead. 423543960 -
    // 423543887 = 73, well under the 200 threshold → FAR_AHEAD does NOT fire
    // → the fast-woken, parent-certified-frozen push proceeds to slot_queue,
    // never re-enters the deferral path. No recursion.
    try std.testing.expect(!isFarAheadOfReplay(slot, highest_frozen_slot, threshold));

    // The two gates are now CONSISTENT for this slot: fast-wake says READY
    // and FAR_AHEAD does not reject it.
}

test "isFarAheadOfReplay: genuinely far-ahead slot (no frozen parent anywhere near) still gates" {
    // A slot 300 ahead of the highest-ever-frozen ancestor, with no parent
    // freeze anywhere in range, is a REAL far-ahead push (needs repair to
    // bridge the intermediate gap) — must still defer, not be exempted by
    // the fix. This proves the fix narrows the false-positive, not the gate
    // itself.
    try std.testing.expect(isFarAheadOfReplay(424000300, 424000000, 200));
    // Slot exactly at the boundary (gap == threshold) does not fire (matches
    // the original strict `>` semantics — unchanged by this fix).
    try std.testing.expect(!isFarAheadOfReplay(424000200, 424000000, 200));
    try std.testing.expect(isFarAheadOfReplay(424000201, 424000000, 200));
}

test "isFarAheadOfReplay MONOTONICITY: a backward last-frozen-slot jump cannot re-trigger" {
    // The exact backward jump observed live: highest-ever-frozen stays pinned
    // at its high-water mark even though the volatile last-frozen slot (not
    // passed to this predicate at all anymore) churns backward underneath it.
    const slot: u64 = 423543960;
    const threshold: u64 = 200;
    const highest_frozen_slot: u64 = 423543887; // set once, at the high-water event

    // Before the backward churn: gap = 73, no fire.
    try std.testing.expect(!isFarAheadOfReplay(slot, highest_frozen_slot, threshold));
    // Simulate the SAME backward churn the live log showed
    // (423543887→423543751, a 136-slot dip) landing on a variable that is NO
    // LONGER consulted by this predicate at all — highest_frozen_slot is
    // untouched by construction (it is only ever advanced forward, never
    // assigned the dipped value). Re-checking with the SAME highest_frozen_slot
    // after the simulated churn proves the predicate is immune:
    const last_frozen_slot_after_backward_jump: u64 = 423543751;
    try std.testing.expect(!isFarAheadOfReplay(slot, highest_frozen_slot, threshold));

    // A monotonic value, by definition, only ever moves forward. Model that
    // explicitly: taking max() against a smaller "new" reading never regresses
    // the tracked high-water mark, which is exactly the update rule the
    // freeze-record point applies (`if (frozen_slot > prev_high) store`).
    const simulated_next_highest = @max(highest_frozen_slot, last_frozen_slot_after_backward_jump);
    try std.testing.expectEqual(highest_frozen_slot, simulated_next_highest); // unchanged — no regression
    try std.testing.expect(!isFarAheadOfReplay(slot, simulated_next_highest, threshold));

    // Forward progress still works normally: once a NEW higher freeze lands,
    // the high-water mark advances and a previously-far-ahead slot's gap
    // shrinks accordingly (no regression in legitimate forward catch-up).
    const advanced = @max(highest_frozen_slot, @as(u64, 423543900));
    try std.testing.expectEqual(@as(u64, 423543900), advanced);
    try std.testing.expect(!isFarAheadOfReplay(slot, advanced, threshold));
}
