//! Bank-pruning policy (C8d).
//!
//! Pulled out of `replay_stage.zig` so the clamp logic can be unit-tested in
//! isolation without the full replay-stage module graph (core/vex_crypto/
//! vex_store/etc).
//!
//! The single exposed function, `computePruneCutoff`, decides how aggressively
//! `pruneOldBanks` may evict banks from `self.banks`.  Any bank whose slot is
//! strictly less than the returned cutoff is a candidate for `bank.deinit()`
//! and `allocator.destroy(bank)` — freeing its memory region.
//!
//! CORRECTNESS REQUIREMENT: the caller may still be holding a `*Bank` pointer
//! into two slots — the one currently being processed, and whatever
//! `self.root_bank` (atomic) points to.  Both MUST survive the prune; reading
//! a freed bank observes ReleaseSafe-poisoned memory (0xAA pattern) and
//! subsequent accesses may panic or produce nonsense.
//!
//! Background: testnet 2026-04-17 PID 1424464 at slot 402515584 panicked the
//! replay thread with `writes=0xAAAAAAAAAAAAAAAA` in the `[REPLAY]` summary
//! line.  Root cause: during catchup, `tower_storage.zig` had loaded
//! `vote_state.root_slot` AHEAD of the replay cursor.  The un-clamped cutoff
//! then exceeded the current slot; `pruneOldBanks` freed the bank the caller
//! was still reading from.

const std = @import("std");

/// Compute the safe prune cutoff.  Banks with slot `< cutoff` may be freed.
///
/// Inputs:
///   - `tower_root_slot`: the tower's persisted `vote_state.root_slot` (or
///     null if tower is uninitialised).  Ideal cutoff "aspiration" upper bound.
///   - `slot`: the slot currently being processed by the caller.
///   - `root_bank_slot`: the slot of whatever `self.root_bank` currently
///     points at (or null if no root bank is stored yet).
///
/// The returned cutoff is clamped by `min(slot - 1, root_bank_slot)` so the
/// two live banks are never freed out from under the caller.  A cutoff of 0
/// means the caller should skip the prune entirely (no bank qualifies).
pub fn computePruneCutoff(
    tower_root_slot: ?u64,
    slot: u64,
    root_bank_slot: ?u64,
) u64 {
    const tower_cutoff: u64 = tower_root_slot orelse 0;
    const slot_cutoff: u64 = slot -| 512;
    const raw: u64 = @max(tower_cutoff, slot_cutoff);
    const rb: u64 = root_bank_slot orelse slot;
    const guard: u64 = @min(slot -| 1, rb);
    return @min(raw, guard);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

test "computePruneCutoff: ahead-of-cursor tower never frees the current bank (C8d regression)" {
    // Incident-exact: slot 402515584, tower already voted at 402515600 (16
    // slots ahead of the replay cursor — the catchup-mode failure mode that
    // triggered writes=0xAAAAAAAAAAAAAAAA on 2026-04-17 PID 1424464).  The
    // bank for slot 402515584 MUST survive the prune.
    const c = computePruneCutoff(402515600, 402515584, 402515584);
    try std.testing.expect(c <= 402515583);

    // Far-ahead tower (cluster committed long before local replay caught up).
    const c2 = computePruneCutoff(402520000, 402515584, 402515584);
    try std.testing.expect(c2 <= 402515583);
}

test "computePruneCutoff: steady-state — slot_cutoff dominates, clamp is a no-op" {
    // When tower_root_slot trails the cursor, the unclamped max(...) should
    // match `slot - 512`.  Clamp must not alter this.
    const c = computePruneCutoff(402515070, 402515584, 402515584);
    try std.testing.expectEqual(@as(u64, 402515584 - 512), c);
}

test "computePruneCutoff: no tower + no root_bank (fresh boot)" {
    // Only `slot - 512` applies; current bank is preserved by construction
    // because `1000 - 512 = 488 < 1000`.
    const c = computePruneCutoff(null, 1000, null);
    try std.testing.expectEqual(@as(u64, 488), c);
}

test "computePruneCutoff: small slot where slot_cutoff saturates to 0" {
    // `5 -| 512` is 0 under saturating subtraction, so the cutoff collapses
    // and the caller's `if (cutoff > 0)` gate skips the prune.
    const c = computePruneCutoff(null, 5, null);
    try std.testing.expectEqual(@as(u64, 0), c);
}

test "computePruneCutoff: ghost-bank run — root_bank.slot trails current slot" {
    // Multiple consecutive slots with zero poh_hash leave `root_bank`
    // pointing at an older bank.  Clamp MUST also preserve root_bank.slot,
    // not just current slot - 1.
    const c = computePruneCutoff(500, 1000, 994);
    try std.testing.expect(c <= 994);
}

test "computePruneCutoff: slot = 0 never underflows (defensive)" {
    // The caller's `if (slot % 64 == 0 and slot > 0)` already gates slot=0,
    // but the helper must return a sane value in case a future caller omits
    // that gate.  No integer underflow under ReleaseSafe.
    const c = computePruneCutoff(123, 0, 0);
    try std.testing.expectEqual(@as(u64, 0), c);
}

test "computePruneCutoff: tower == current slot (slot was voted instantly)" {
    // Edge case — tower claims the current slot as the new root.  Clamp must
    // still preserve the current bank because the caller hasn't finished
    // freezing it yet.
    const c = computePruneCutoff(1000, 1000, 1000);
    try std.testing.expect(c <= 999);
}

test "computePruneCutoff: monotonicity — larger tower_root never decreases cutoff" {
    // Sanity: bumping the aspirational tower cutoff only ever raises the
    // returned cutoff, up to the clamp ceiling.
    const lo = computePruneCutoff(100, 1000, 999);
    const hi = computePruneCutoff(800, 1000, 999);
    try std.testing.expect(hi >= lo);
}
