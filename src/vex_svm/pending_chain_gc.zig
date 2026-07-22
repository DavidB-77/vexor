//! pending_chain_gc.zig — pure GC-drop predicate for the CHAIN-DEFER pending_chain.
//!
//! Extracted from replay_stage.zig `deferUnconnectedSlotWithBoundaries` GC block
//! (2026-06-14) so the RSS-bound DROP decision is a pure, standalone-testable
//! function. replay_stage.zig is bank/lock/SVM-heavy and cannot be rooted as a
//! `zig build test` artifact; this module imports only `std`, so its KATs
//! actually execute (`zig build test-pending-chain-gc`).
//!
//! ── WHY THIS EXISTS (the reverted FIX #2 silent-consensus-hole) ──────────────
//! A slot enters pending_chain ONLY after it is is_complete in the shred
//! assembler. The wake path (checkPendingChain) and orphan repair
//! (selectOrphanTargets) BOTH key exclusively on LIVE pending_chain entries. So
//! dropping a pending entry that is NOT obsolete makes it UNRECOVERABLE — a
//! silent consensus hole. The earlier FIX #2 dropped the HIGHEST-keyed entries
//! down to a 2048 cap unconditionally; those slots were re-requestable nowhere
//! reliable (seedCatchupRepairs is root-anchored + SEED_CAP=2048, so the upper
//! half of an evicted set is beyond its ceiling, and any in-range slot
//! re-completes → re-defers → re-evicts = livelock). FIX #2 is REVERTED.
//!
//! Two drop clauses with DIFFERENT recoverability guarantees (re-review w8w5sld4p):
//!   (1) ROOT-ADVANCE (recoverability-preserving): slot < consensus root
//!       (db.rooted_slot). Already rooted on some fork; cannot help forward
//!       progress; children wake via checkPendingChain's root-floor — Agave
//!       `bank_forks.get_non_rooted` drops exactly here. (rooted_slot==0 disables
//!       the drop → full retention pre-first-root.) SAFE.
//!   (2) BACKSTOP (LOSSY last-resort — NOT recoverability-preserving): over the
//!       HARD_CAP (4096) AND older than the 60-min TTL. ⚠️ An ABOVE-root,
//!       is_complete, never-replayed CANONICAL slot dropped here is UNRECOVERABLE
//!       in-process (repair skips is_complete via getInProgressSlots; checkPendingChain
//!       can't wake a slot absent from the map; root can't advance past it). Recovery
//!       = OPERATOR FRESH-SNAPSHOT RESTART only. Fires only if the consensus root
//!       genuinely stalls > 1h AND the map is over the hard cap — a wedge the
//!       targeting-fanout fix is meant to PREVENT upstream. Effective RSS bound before
//!       it fires ≈ slot-rate(~2.5/s) × 60min ≈ ~9k entries ≈ ~22GB (4096 is NOT a
//!       ceiling — nothing drops while younger than the TTL). FOLLOW-UP (separate
//!       change, not built): a genuinely-recoverable backstop (re-key dedup so a
//!       re-fetch re-surfaces, OR extend the restart floor to track complete-but-
//!       unreplayed slots at frozen_tip+1).
//!
//! A slot ABOVE the consensus root AND younger than the backstop TTL is NEVER dropped,
//! no matter how far over any soft cap the map is. That is the recoverability invariant
//! the KATs assert (the backstop is the sole, documented, restart-only exception).

const std = @import("std");
const pending_wake = @import("pending_wake.zig"); // single source of truth for the root-advance drop

pub const PENDING_CHAIN_HARD_CAP: usize = 4096;
pub const PENDING_CHAIN_BACKSTOP_TTL_MS: i64 = 60 * 60 * 1000; // 60 min

/// Should this pending_chain entry be GC-dropped?
///
/// - `slot`: the deferred slot key.
/// - `rooted_slot`: monotonic CONSENSUS root (db.rooted_slot); 0 disables the
///   root-advance drop (pre-first-root → full retention).
/// - `cur_count`: current pending_chain entry count (for the cap test).
/// - `age_ms`: now_ms - entry.added_ms (entry age).
/// - `hard_cap`: the over-cap threshold for the backstop (default HARD_CAP).
/// - `ttl_ms`: backstop age threshold (default BACKSTOP_TTL_MS).
///
/// Reference recoverability-invariant predicate (root-advance + scalar backstop,
/// NO tip-awareness). As of fix/chain-defer-tip-guard (wedge @422050470) the
/// WIRED GC composes `pending_wake.shouldDropBelowRoot` (clause 1) with
/// `backstopEligible` (clause 2, tip-aware furthest-from-tip eviction) in
/// replay_stage.zig — see that call site. This function is retained as the KAT'd
/// statement of the recoverability invariant the tip-aware path also upholds.
/// Two RECOVERABILITY-PRESERVING clauses:
///   (1) root-advance: DELEGATED to pending_wake.shouldDropBelowRoot — the same
///       shared, wired predicate the wake/fast-wake paths use (single source of
///       truth; no duplicated boolean).
///   (2) backstop: over_cap (cur_count > hard_cap) AND (age > ttl).
pub fn shouldDrop(
    slot: u64,
    rooted_slot: u64,
    cur_count: usize,
    age_ms: i64,
    hard_cap: usize,
    ttl_ms: i64,
) bool {
    // (1) root-advance: obsolete, recoverable via root-floor. Shared predicate.
    if (pending_wake.shouldDropBelowRoot(slot, rooted_slot)) return true;
    // (2) backstop: only when over the HARD cap AND very old.
    const over_cap = cur_count > hard_cap;
    if (over_cap and age_ms > ttl_ms) return true;
    return false;
}

/// Convenience wrapper with the canonical default thresholds.
pub fn shouldDropDefault(slot: u64, rooted_slot: u64, cur_count: usize, age_ms: i64) bool {
    return shouldDrop(slot, rooted_slot, cur_count, age_ms, PENDING_CHAIN_HARD_CAP, PENDING_CHAIN_BACKSTOP_TTL_MS);
}

// ════════════════════════════════════════════════════════════════════════════
// TIP-AWARE backstop (fix/chain-defer-tip-guard, liveness wedge @422050470,
// 2026-07-15; live testnet root-cause analysis).
//
// The scalar `shouldDrop` backstop above drops EVERY over-cap entry older than
// the TTL — with no regard to WHERE the entry sits relative to the replay tip.
// Under an 11k-slot turbine-vs-replay catch-up gap that GC'd the deferred-
// continuation entry for slot 422052441 — the DIRECT CHILD of the slot replay
// was about to freeze (422052440) — 2,374 log lines before its parent froze.
// When the parent froze there was no live defer entry left to fire CHAIN-WAKE,
// replay had nothing to schedule, and the node self-decapitated (watchdog
// exit(1), 5h47m dead). The backstop raced replay's slow catch-up and severed
// the chain at the one point that mattered.
//
// Correctness fix: a PROTECTED BAND around the freeze tip is NEVER evicted, and
// when over cap the caller evicts FURTHEST-from-tip first (highest slot; every
// deferred slot is above the tip). The near-tip continuation — the entry that is
// imminently resolvable because its parent is at/near the tip — is thus the LAST
// thing dropped, never the first. The furthest-ahead entries (turbine frontier,
// thousands of slots up) are the genuinely-backed-up ones that can wait, and are
// re-discoverable via repair / the CHAIN-WAKE assembler fallback as replay
// reaches them.
// ════════════════════════════════════════════════════════════════════════════

/// Protected band (in slots) above the freeze tip that the backstop must never
/// evict. Sized well above a single catch-up child so the direct continuation
/// (tip+1) — and a healthy margin of near-tip descendants — always survive. The
/// band is a CORRECTNESS bound, not a memory bound; memory is still bounded by
/// the hard cap applied to the region ABOVE the band.
pub const PENDING_CHAIN_PROTECT_BAND: u64 = 512;

/// Is this entry ELIGIBLE for tip-aware backstop eviction? Necessary, NOT
/// sufficient — the caller additionally (a) evicts only when over the hard cap
/// and (b) evicts FURTHEST-from-tip first, only down to the cap. Eligibility:
///   • older than the backstop TTL (`age_ms > ttl_ms`), AND
///   • OUTSIDE the protected band above the freeze tip (`slot > frozen_tip + band`).
/// `frozen_tip == 0` (no bank frozen yet) disables the band — during cold-boot
/// catch-up the map is small and there is no tip to protect around.
/// An entry AT or BELOW the freeze tip, or within `band` slots above it, is
/// ALWAYS protected — it is imminently resolvable (parent at/near the tip).
pub fn backstopEligible(
    slot: u64,
    frozen_tip: u64,
    age_ms: i64,
    protect_band: u64,
    ttl_ms: i64,
) bool {
    if (age_ms <= ttl_ms) return false; // not old enough for the last-resort bound
    if (frozen_tip > 0 and slot <= frozen_tip +| protect_band) return false; // protected band
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// KATs — `zig build test-pending-chain-gc`
// ════════════════════════════════════════════════════════════════════════════

const FRESH_MS: i64 = 5_000; // 5 s old — younger than any TTL
const OLD_MS: i64 = PENDING_CHAIN_BACKSTOP_TTL_MS + 1; // older than backstop

test "recoverability invariant: above-root + fresh entries are NEVER dropped, even far over any soft cap" {
    // Simulate the EXACT scenario the reverted FIX #2 mis-handled: a contiguous
    // run of is_complete slots ABOVE a stuck consensus root, accreting far past
    // the old 2048 soft cap and even past the 4096 hard cap, but YOUNG. None may
    // be dropped — each must stay wakeable / re-requestable.
    const rooted: u64 = 1000;
    // 6000 entries (well over both the old 2048 evict cap AND the 4096 hard cap).
    const cur_count: usize = 6000;
    var slot: u64 = rooted + 1; // all strictly ABOVE the consensus root
    while (slot <= rooted + 6000) : (slot += 1) {
        // Fresh (age below TTL): NEVER dropped regardless of count.
        try std.testing.expect(!shouldDropDefault(slot, rooted, cur_count, FRESH_MS));
    }
    // In particular the HIGHEST-keyed entry — the one FIX #2 evicted FIRST — is
    // retained. That is the bug fix: no silent furthest-from-root drop.
    try std.testing.expect(!shouldDropDefault(rooted + 6000, rooted, cur_count, FRESH_MS));
}

test "root-advance drop: a slot below the consensus root IS dropped (obsolete, recoverable via root-floor)" {
    const rooted: u64 = 1000;
    // Below root → dropped (its children wake via checkPendingChain root-floor).
    try std.testing.expect(shouldDropDefault(999, rooted, 10, FRESH_MS));
    try std.testing.expect(shouldDropDefault(0, rooted, 10, FRESH_MS));
    // Strict `<`: the root slot itself is RETAINED (Agave get_non_rooted keeps
    // slot == root).
    try std.testing.expect(!shouldDropDefault(1000, rooted, 10, FRESH_MS));
}

test "pre-first-root: rooted_slot==0 disables the root drop → FULL retention" {
    // Before the first consensus root (cold-boot catch-up), nothing is dropped by
    // the root clause — matches Agave 'blockstore holds all shreds'.
    var slot: u64 = 0;
    while (slot < 5000) : (slot += 1) {
        try std.testing.expect(!shouldDropDefault(slot, 0, 5000, FRESH_MS));
    }
}

test "backstop: drops ONLY when over the HARD cap AND older than the 60-min TTL" {
    const rooted: u64 = 1000;
    const above: u64 = rooted + 500; // above root, so only the backstop can fire
    // Over hard cap but FRESH → NOT dropped (recoverability preserved; the bound
    // is a >1h last resort, not an immediate eviction).
    try std.testing.expect(!shouldDropDefault(above, rooted, PENDING_CHAIN_HARD_CAP + 1, FRESH_MS));
    // OLD but UNDER hard cap → NOT dropped (normal catch-up is never affected).
    try std.testing.expect(!shouldDropDefault(above, rooted, PENDING_CHAIN_HARD_CAP, OLD_MS));
    // Over hard cap AND old → dropped (the genuine >1h root-stall last resort).
    try std.testing.expect(shouldDropDefault(above, rooted, PENDING_CHAIN_HARD_CAP + 1, OLD_MS));
    // Boundary: cur_count == hard_cap is NOT "over" (strict >).
    try std.testing.expect(!shouldDropDefault(above, rooted, PENDING_CHAIN_HARD_CAP, OLD_MS + 100));
    // Boundary: age == TTL exactly is NOT "older than" (strict >).
    try std.testing.expect(!shouldDropDefault(above, rooted, PENDING_CHAIN_HARD_CAP + 1, PENDING_CHAIN_BACKSTOP_TTL_MS));
    try std.testing.expect(shouldDropDefault(above, rooted, PENDING_CHAIN_HARD_CAP + 1, PENDING_CHAIN_BACKSTOP_TTL_MS + 1));
}

test "no silent highest-keyed eviction: a near-tip orphan run stays bounded ONLY by the recoverable predicates" {
    // The reverted FIX #2 would have dropped the top (cur_count - 2048) entries
    // here purely by key. Prove the surviving set under the CORRECT predicate is
    // exactly {slots >= rooted that are fresh OR (<=cap)} — i.e. every above-root
    // fresh entry survives; the count is NOT clamped to a soft cap.
    const rooted: u64 = 414_000_000;
    const cur_count: usize = 3000; // over the old 2048 cap, under the 4096 hard cap
    var survivors: usize = 0;
    var slot: u64 = rooted + 1;
    while (slot <= rooted + 3000) : (slot += 1) {
        if (!shouldDropDefault(slot, rooted, cur_count, FRESH_MS)) survivors += 1;
    }
    // ALL 3000 above-root fresh entries survive — NONE silently evicted.
    try std.testing.expectEqual(@as(usize, 3000), survivors);
}

test "clause-1 delegates to the SHARED wired pending_wake.shouldDropBelowRoot (no duplicate boolean)" {
    // The root-advance clause must be the SAME predicate the wake/fast-wake paths
    // use, so a future change to the canonical drop boundary updates both at once.
    const slots = [_]u64{ 0, 999, 1000, 1001, 5000 };
    const roots = [_]u64{ 0, 1000 };
    for (slots) |s| {
        for (roots) |r| {
            // With count under cap (no backstop), shouldDrop == shouldDropBelowRoot.
            try std.testing.expectEqual(
                pending_wake.shouldDropBelowRoot(s, r),
                shouldDropDefault(s, r, PENDING_CHAIN_HARD_CAP, OLD_MS),
            );
        }
    }
}

test "full grid: shouldDrop == (shared root-advance) OR (over-cap AND old)" {
    const slots = [_]u64{ 0, 999, 1000, 1001, 5000 };
    const roots = [_]u64{ 0, 1000 };
    const counts = [_]usize{ 0, PENDING_CHAIN_HARD_CAP, PENDING_CHAIN_HARD_CAP + 1 };
    const ages = [_]i64{ 0, FRESH_MS, PENDING_CHAIN_BACKSTOP_TTL_MS, OLD_MS };
    for (slots) |s| {
        for (roots) |r| {
            for (counts) |c| {
                for (ages) |a| {
                    // Clause-1 via the shared predicate (NOT a re-derivation).
                    const drop_below_root = pending_wake.shouldDropBelowRoot(s, r);
                    const over_cap = c > PENDING_CHAIN_HARD_CAP;
                    const backstop = over_cap and a > PENDING_CHAIN_BACKSTOP_TTL_MS;
                    const expected = drop_below_root or backstop;
                    try std.testing.expectEqual(expected, shouldDropDefault(s, r, c, a));
                }
            }
        }
    }
}

// ── TIP-AWARE backstop KATs (fix/chain-defer-tip-guard) ──────────────────────

const BAND = PENDING_CHAIN_PROTECT_BAND;

test "protected band: the DIRECT child of the freeze tip is NEVER backstop-eligible (the @422052441 wedge)" {
    // Exact incident geometry: freeze tip = 422052440, its direct child 422052441
    // is deferred, OLD (>60min), and the map is over cap. The scalar backstop
    // dropped it → self-decapitation. Tip-aware: it is INSIDE the band → protected.
    const tip: u64 = 422052440;
    try std.testing.expect(!backstopEligible(tip + 1, tip, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
    // Every entry from the tip up through the full band is protected, however old.
    var s: u64 = tip;
    while (s <= tip + BAND) : (s += 1) {
        try std.testing.expect(!backstopEligible(s, tip, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
    }
    // The FIRST slot beyond the band IS eligible (furthest-from-tip is evicted first).
    try std.testing.expect(backstopEligible(tip + BAND + 1, tip, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
}

test "age respects the band: a within-band entry older than the TTL is still protected" {
    const tip: u64 = 1_000_000;
    // OLD but inside band → NOT eligible (band wins over age).
    try std.testing.expect(!backstopEligible(tip + 10, tip, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
    // Outside band but FRESH → NOT eligible (age gate).
    try std.testing.expect(!backstopEligible(tip + BAND + 100, tip, FRESH_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
    // Outside band AND old → eligible.
    try std.testing.expect(backstopEligible(tip + BAND + 100, tip, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
    // Boundary: age == TTL exactly is NOT "older than" (strict >).
    try std.testing.expect(!backstopEligible(tip + BAND + 100, tip, PENDING_CHAIN_BACKSTOP_TTL_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
}

test "furthest-from-tip ordering: eligibility boundary is exactly frozen_tip + band" {
    const tip: u64 = 500_000;
    // slot == tip+band → protected (<=); slot == tip+band+1 → eligible (>).
    try std.testing.expect(!backstopEligible(tip + BAND, tip, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
    try std.testing.expect(backstopEligible(tip + BAND + 1, tip, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
    // Higher slot = further from tip = evicted earlier by the caller's descending sort.
    try std.testing.expect(backstopEligible(tip + 100_000, tip, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS));
}

test "frozen_tip==0 disables the band (cold-boot catch-up): only the age gate applies" {
    // No bank frozen yet → nothing to protect around; matches the pre-first-freeze
    // regime where the map is small.
    try std.testing.expect(!backstopEligible(5, 0, FRESH_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS)); // fresh
    try std.testing.expect(backstopEligible(5, 0, OLD_MS, BAND, PENDING_CHAIN_BACKSTOP_TTL_MS)); // old
}
