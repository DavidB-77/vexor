//! repair_targeting.zig — pure peer-selection mapping for WindowIndex repair.
//!
//! Extracted from tvu.zig `requestRepairs` (PRIMARY ROOT FIX 2026-06-14) so the
//! load-bearing targeting decision — WHICH peers a given missing shred index is
//! requested from — is a pure, standalone-testable function. tvu.zig is
//! socket/sign-heavy and cannot be rooted as a `zig build test` artifact; this
//! module imports only `std`, so its KATs actually execute (`zig build
//! test-repair-targeting`).
//!
//! The ONLY behavior this governs is peer SELECTION + COUNT for a repair
//! request. It NEVER touches shred completion, freeze, the FEC/merkle gate, or
//! what is accepted into a block — a repaired shred still lands only via the
//! verified ingest path. So this is consensus-NEUTRAL (liveness/convergence
//! only).
//!
//! ROOT CAUSE it addresses (proven from vex-fd-dev_testnet.log):
//! the AF_XDP catch-up DELINQUENCY was SLOW REPAIR CONVERGENCE, not a phantom
//! completion index. A slot's only hole was a single interior data shred
//! ([REPAIR-STUCK] slot=415398209 missing={260}) that provably exists
//! cluster-wide; the pre-fix "1 shred → exactly 1 peer" round-robin
//! (`peer_idx = i % peers_to_use`) requested a SINGLETON hole (i==0) from
//! `repair_peers[0]` ONLY, every cycle — and with slot-aware getRepairPeers
//! returning advertisers in fixed order, that was the SAME non-holder forever
//! (WindowIndex sends no negative ack when a peer lacks the shred). ~13s per
//! hole × thousands of holes = never reach tip = delinquent.

const std = @import("std");

/// Inclusive-exclusive peer-index range [lo, hi) to request `missing_indices[i]`
/// from, given the current targeting parameters. The caller iterates `lo..hi`
/// and sends one WindowIndex packet per peer in that range.
pub const PeerRange = struct {
    lo: usize,
    hi: usize,
};

/// Compute the peer range for the `i`-th missing index of a repair batch.
///
/// - `i`: position of this index within `missing_indices` (0-based).
/// - `peers_to_use`: number of distinct repair peers available this cycle
///   (already `@min(REPAIR_FANOUT, repair_peers.len)`); MUST be >= 1.
/// - `rot`: per-call rotation offset in `[0, peers_to_use)` so the 1:1 mapping
///   (and the fanout start) is not pinned to peer 0 every cycle.
/// - `fanout_all`: TRUE only for the single tracked STUCK slot with a SMALL
///   missing set. When TRUE, request this index from ALL `peers_to_use` peers
///   (so a holder is reached in one cycle). When FALSE (every healthy slot),
///   request from EXACTLY ONE peer (1:1 round-robin, rotated) — no duplication,
///   no O(slots) amplification.
///
/// CONSERVATIVE / anti-amplification: when `fanout_all == false` the range is
/// always width-1, so the per-cycle packet count for a non-stuck slot is
/// exactly `missing_indices.len` — byte-identical to the pre-fix 1:1 behavior.
pub fn peerRange(i: usize, peers_to_use: usize, rot: usize, fanout_all: bool) PeerRange {
    std.debug.assert(peers_to_use >= 1);
    std.debug.assert(rot < peers_to_use);
    if (fanout_all) {
        return .{ .lo = 0, .hi = peers_to_use };
    }
    const lo = (i + rot) % peers_to_use;
    return .{ .lo = lo, .hi = lo + 1 };
}

/// Total WindowIndex packets a repair batch will emit (sum of range widths).
/// Used to charge the true wire cost against the repair budget and to assert
/// the no-amplification invariant in tests.
pub fn packetsForBatch(missing_len: usize, peers_to_use: usize, fanout_all: bool) usize {
    if (fanout_all) return missing_len * peers_to_use;
    return missing_len; // 1:1 — exactly one packet per missing index
}

// ════════════════════════════════════════════════════════════════════════════
// KATs — `zig build test-repair-targeting`
// ════════════════════════════════════════════════════════════════════════════

test "1:1 round-robin: each missing index maps to exactly ONE peer (no amplification)" {
    const peers_to_use: usize = 6;
    const rot: usize = 0;
    // Large/healthy missing set, fanout OFF.
    const missing_len: usize = 100;
    var total_packets: usize = 0;
    var i: usize = 0;
    while (i < missing_len) : (i += 1) {
        const r = peerRange(i, peers_to_use, rot, false);
        try std.testing.expectEqual(@as(usize, 1), r.hi - r.lo); // width-1
        try std.testing.expect(r.lo < peers_to_use); // in range
        total_packets += (r.hi - r.lo);
    }
    // ANTI-AMPLIFICATION INVARIANT: packets sent == indices charged to budget.
    try std.testing.expectEqual(missing_len, total_packets);
    try std.testing.expectEqual(missing_len, packetsForBatch(missing_len, peers_to_use, false));
}

test "singleton STUCK slot fans out to ALL peers (breaks the single-non-holder loop)" {
    const peers_to_use: usize = 6;
    const rot: usize = 0;
    // Singleton missing set on the stuck slot, fanout ON.
    const r = peerRange(0, peers_to_use, rot, true);
    try std.testing.expectEqual(@as(usize, 0), r.lo);
    try std.testing.expectEqual(peers_to_use, r.hi); // ALL peers asked
    // Every peer index 0..peers_to_use is covered → a holder is reached this cycle.
    var covered = [_]bool{false} ** 6;
    var p = r.lo;
    while (p < r.hi) : (p += 1) covered[p] = true;
    for (covered) |c| try std.testing.expect(c);
    try std.testing.expectEqual(peers_to_use, packetsForBatch(1, peers_to_use, true));
}

test "anti-amplification: only the stuck slot fans out; healthy small sets stay 1:1" {
    // Simulate a catch-up cycle: MANY slots each with a SMALL missing set
    // (the BRIDGE-DIAG-observed common case), exactly ONE of which is the
    // tracked stuck slot. Total packets must be bounded — NOT N_slots * peers.
    const peers_to_use: usize = 6;
    const n_healthy_slots: usize = 200;
    const per_slot_missing: usize = 3; // typical small set
    // Healthy slots: fanout_all=false → 1:1.
    var total: usize = 0;
    var s: usize = 0;
    while (s < n_healthy_slots) : (s += 1) {
        total += packetsForBatch(per_slot_missing, peers_to_use, false);
    }
    // The single stuck slot: fanout_all=true → per_slot_missing * peers.
    const stuck_packets = packetsForBatch(per_slot_missing, peers_to_use, true);
    total += stuck_packets;

    // Pre-fix-equivalent baseline (no fanout anywhere).
    const baseline = (n_healthy_slots + 1) * per_slot_missing;
    // Amplification is bounded to the ONE stuck slot's extra (peers-1)*missing.
    const extra = stuck_packets - per_slot_missing;
    try std.testing.expectEqual(baseline + extra, total);
    // The extra is O(1) in slots: <= SMALL_MISSING_FANOUT(4) * peers_to_use(6) = 24.
    try std.testing.expect(extra <= 4 * peers_to_use);
    // And the total stays far under the AGAVE_MAX_REPAIR_LENGTH=512 budget
    // headroom for this synthetic small workload's stuck-slot contribution.
    try std.testing.expect(stuck_packets <= 4 * peers_to_use);
}

test "rotation: a singleton 1:1 request is NOT pinned to peer 0 across cycles" {
    // Pre-fix BUG: missing=[260] (i==0) always hit peer 0. With per-call
    // rotation, successive cycles target DIFFERENT peers, so a non-holder at
    // index 0 cannot stall the hole forever. Prove every peer is eventually hit.
    const peers_to_use: usize = 6;
    var hit = [_]bool{false} ** 6;
    var cycle: usize = 0;
    while (cycle < peers_to_use) : (cycle += 1) {
        const rot: usize = cycle % peers_to_use;
        const r = peerRange(0, peers_to_use, rot, false); // singleton, 1:1, rotated
        try std.testing.expectEqual(@as(usize, 1), r.hi - r.lo);
        hit[r.lo] = true;
    }
    for (hit) |h| try std.testing.expect(h); // all peers covered over the cycles
}

test "no-regression: large-set 1:1 covers peers round-robin starting at rot" {
    const peers_to_use: usize = 4;
    const rot: usize = 2;
    // Indices 0..7 with rot=2 → peers 2,3,0,1,2,3,0,1
    const expect = [_]usize{ 2, 3, 0, 1, 2, 3, 0, 1 };
    for (expect, 0..) |e, i| {
        const r = peerRange(i, peers_to_use, rot, false);
        try std.testing.expectEqual(e, r.lo);
        try std.testing.expectEqual(@as(usize, 1), r.hi - r.lo);
    }
}
