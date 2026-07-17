//! Layer-A snapshot trust — known-validator gossip agreement (FULL-base).
//!
//! Canonical mechanism (Agave 4.1.0-rc.1, validator/src/bootstrap.rs:924
//! `build_known_snapshot_hashes`): with `--known-validator` set, a snapshot's
//! full (slot,hash) is trusted iff the known (trusted) validators VOUCH for it via
//! their gossip `SnapshotHashes` CRDS advertisements, using a **keep-first /
//! conflict-drop** rule — the FIRST known validator to advertise a given slot's
//! hash wins; a later known validator advertising a DIFFERENT hash for that SAME
//! slot is ignored for that slot (Agave drops the conflicting contribution). It is
//! NOT a majority vote.
//!
//! This module is the PURE canonical core: it takes the already-resolved
//! per-known-validator full advertisements (the caller pulls them from gossip via
//! `CrdsTable.getSnapshotHashes`) and produces the vouched set + an `isVouched`
//! predicate. Keeping it free of any gossip/cluster dependency makes it directly
//! unit-testable offline (kat_snapshot_trust.zig) — no node, no full build.
//!
//! SCOPE: full-base only. The incremental (slot,hash) is NOT validated here — that
//! is the deferred A4 residual (Vexor's CRDS deserialize drops the incremental list;
//! retaining it needs gossip-core allocation lifecycle). A poisoned incremental on a
//! vouched full is liveness-only and divergence-caught. See
//! VEXOR-SNAPSHOT-TRUST-DECISION-2026-06-22.md.

const std = @import("std");

/// A full-snapshot (slot, hash) pair as advertised in gossip `SnapshotHashes.full`.
pub const SlotHash = struct {
    slot: u64,
    hash: [32]u8,
};

/// The conflict-free set of full-snapshot (slot → hash) pairs vouched-for by the
/// known validators. Built with Agave's keep-first/conflict-drop rule.
pub const KnownSnapshotHashes = struct {
    /// slot → vouched hash (keep-first; conflicts ignored, see `conflicts`).
    map: std.AutoHashMap(u64, [32]u8),
    /// Count of (slot, different-hash) conflicts observed among known validators —
    /// a security-relevant signal (trusted validators disagreeing on a slot).
    conflicts: u32 = 0,

    pub fn deinit(self: *KnownSnapshotHashes) void {
        self.map.deinit();
    }

    /// Whether a candidate full (slot,hash) is vouched-for by the known set.
    /// A slot absent from the map (no known validator advertised it) is NOT vouched.
    pub fn isVouched(self: *const KnownSnapshotHashes, slot: u64, hash: [32]u8) bool {
        const vouched = self.map.get(slot) orelse return false;
        return std.mem.eql(u8, &vouched, &hash);
    }

    pub fn count(self: *const KnownSnapshotHashes) usize {
        return self.map.count();
    }
};

/// Build the vouched set from per-known-validator full advertisements, applying
/// Agave's keep-first/conflict-drop rule. `fulls[i]` is known_validators[i]'s
/// advertised full (slot,hash), or null if that validator has no `SnapshotHashes`
/// entry in gossip yet. Iteration order == the order `fulls` is given (== the order
/// `--known-validator` flags were supplied), which defines "first" deterministically.
///
/// Conflict (same slot, different hash from a later known validator): the existing
/// (first) hash is KEPT, the conflicting one is ignored, and `conflicts` is bumped
/// (caller should log it — a trusted-validator disagreement is security-relevant).
pub fn build(allocator: std.mem.Allocator, fulls: []const ?SlotHash) !KnownSnapshotHashes {
    var result = KnownSnapshotHashes{ .map = std.AutoHashMap(u64, [32]u8).init(allocator) };
    errdefer result.map.deinit();

    for (fulls) |maybe_full| {
        const full = maybe_full orelse continue;
        const gop = try result.map.getOrPut(full.slot);
        if (gop.found_existing) {
            // Keep-first: a different hash for the same slot is a conflict (ignored).
            if (!std.mem.eql(u8, gop.value_ptr, &full.hash)) {
                result.conflicts += 1;
            }
            // same hash → agreement, no-op; different hash → keep the first.
        } else {
            gop.value_ptr.* = full.hash;
        }
    }

    return result;
}
