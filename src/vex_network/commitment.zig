//! SB-4 (parity backlog, shared blocker — part 2/2): commitment level + bank/slot selection.
//!
//! Every RPC read takes a `commitment` (processed | confirmed | finalized, default `finalized` for
//! most methods) and an optional `minContextSlot`. This module is the pure selector that maps a
//! commitment to the slot RPC should read, and enforces minContextSlot. It is also the machinery the
//! block producer registers its in-flight "processed but not rooted" bank into (the leader serving RPC
//! about its own block = the `processed` tip). Today Vexor's RPC ignores commitment entirely.
//!
//! ADDITIVE + KAT-gated; NOT wired into the live RPC path yet.

const std = @import("std");

pub const Commitment = enum {
    processed,
    confirmed,
    finalized,

    /// Parse the RPC string. Agave also accepts the deprecated aliases `recent`→processed,
    /// `single`/`singleGossip`→confirmed, `root`/`max`→finalized.
    pub fn fromString(s: []const u8) ?Commitment {
        if (std.mem.eql(u8, s, "processed") or std.mem.eql(u8, s, "recent")) return .processed;
        if (std.mem.eql(u8, s, "confirmed") or std.mem.eql(u8, s, "single") or std.mem.eql(u8, s, "singleGossip")) return .confirmed;
        if (std.mem.eql(u8, s, "finalized") or std.mem.eql(u8, s, "root") or std.mem.eql(u8, s, "max")) return .finalized;
        return null;
    }

    pub fn toString(self: Commitment) []const u8 {
        return switch (self) {
            .processed => "processed",
            .confirmed => "confirmed",
            .finalized => "finalized",
        };
    }
};

/// The three live slot tips the validator tracks. `processed` ≥ `confirmed` ≥ `finalized` always
/// (a slot is processed before it is cluster-confirmed before it is rooted). Updated by replay/tower;
/// the producer bumps `processed` to its in-flight slot.
pub const SlotTips = struct {
    processed: u64,
    confirmed: u64,
    finalized: u64,

    pub fn forCommitment(self: SlotTips, c: Commitment) u64 {
        return switch (c) {
            .processed => self.processed,
            .confirmed => self.confirmed,
            .finalized => self.finalized,
        };
    }
};

pub const SelectError = error{MinContextSlotNotReached};

/// Select the slot RPC should read for `commitment`, enforcing `min_context_slot`. Agave returns the
/// JSON error -32016 ("Minimum context slot has not been reached") when the chosen slot is below the
/// requested minimum; the RPC layer maps this error to that code.
pub fn selectSlot(tips: SlotTips, commitment: Commitment, min_context_slot: ?u64) SelectError!u64 {
    const slot = tips.forCommitment(commitment);
    if (min_context_slot) |m| {
        if (slot < m) return error.MinContextSlotNotReached;
    }
    return slot;
}

// ─────────────────────────────── KATs ───────────────────────────────

const testing = std.testing;

test "Commitment.fromString incl. deprecated aliases" {
    try testing.expectEqual(Commitment.processed, Commitment.fromString("processed").?);
    try testing.expectEqual(Commitment.processed, Commitment.fromString("recent").?);
    try testing.expectEqual(Commitment.confirmed, Commitment.fromString("confirmed").?);
    try testing.expectEqual(Commitment.confirmed, Commitment.fromString("singleGossip").?);
    try testing.expectEqual(Commitment.finalized, Commitment.fromString("finalized").?);
    try testing.expectEqual(Commitment.finalized, Commitment.fromString("max").?);
    try testing.expect(Commitment.fromString("nonsense") == null);
}

test "selectSlot: picks the right tip per commitment" {
    const tips = SlotTips{ .processed = 1000, .confirmed = 990, .finalized = 950 };
    try testing.expectEqual(@as(u64, 1000), try selectSlot(tips, .processed, null));
    try testing.expectEqual(@as(u64, 990), try selectSlot(tips, .confirmed, null));
    try testing.expectEqual(@as(u64, 950), try selectSlot(tips, .finalized, null));
}

test "selectSlot: minContextSlot enforcement" {
    const tips = SlotTips{ .processed = 1000, .confirmed = 990, .finalized = 950 };
    // confirmed tip 990 >= 980 → ok
    try testing.expectEqual(@as(u64, 990), try selectSlot(tips, .confirmed, 980));
    // finalized tip 950 < 980 → not reached
    try testing.expectError(error.MinContextSlotNotReached, selectSlot(tips, .finalized, 980));
    // exactly equal → ok (>= boundary)
    try testing.expectEqual(@as(u64, 950), try selectSlot(tips, .finalized, 950));
}
