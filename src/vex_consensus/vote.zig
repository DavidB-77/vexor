//! Vexor Vote Types
//!
//! Vote structures and lockout calculations for consensus.

const std = @import("std");
const core = @import("core");

/// A vote for a slot
pub const Vote = struct {
    slot: core.Slot,
    hash: core.Hash,
    timestamp: i64,
    signature: core.Signature,
};

/// Vote lockout state
pub const Lockout = struct {
    slot: core.Slot,
    confirmation_count: u32,

    const Self = @This();

    /// Calculate lockout duration (exponential: 2^confirmation_count)
    pub fn lockoutDuration(self: *const Self) u64 {
        if (self.confirmation_count >= 64) return std.math.maxInt(u64);
        return @as(u64, 1) << @intCast(self.confirmation_count);
    }

    /// Check if lockout has expired for a given slot
    pub fn isExpired(self: *const Self, current_slot: core.Slot) bool {
        const duration = self.lockoutDuration();
        // Use saturating add to prevent overflow
        const expiration = self.slot +| duration;
        return current_slot > expiration;
    }

    /// Slot at which this lockout expires
    pub fn expirationSlot(self: *const Self) u64 {
        const duration = self.lockoutDuration();
        if (duration == std.math.maxInt(u64)) return std.math.maxInt(u64);
        return self.slot +| duration;
    }
};

/// Vote transaction
pub const VoteTransaction = struct {
    /// Vote account being updated
    vote_account: core.Pubkey,
    /// Slots being voted on (can batch)
    slots: []const core.Slot,
    /// Bank hash for the latest slot
    hash: core.Hash,
    /// Timestamp
    timestamp: ?i64,
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "lockout duration" {
    const lockout = Lockout{
        .slot = 100,
        .confirmation_count = 5,
    };

    try std.testing.expectEqual(@as(u64, 32), lockout.lockoutDuration()); // 2^5
    try std.testing.expectEqual(@as(u64, 132), lockout.expirationSlot()); // 100 + 32
}

test "lockout expiration" {
    const lockout = Lockout{
        .slot = 100,
        .confirmation_count = 3, // Duration = 8
    };

    // CARRIER #7 (2026-06-10): this test was LATENT (vote.zig's tests were
    // never in any test step's root module until test-tower pulled the file
    // in) and its original expectation `isExpired(108) == true` contradicted
    // canonical Agave: `is_locked_out_at_slot(s) = last_locked_out_slot() >= s`
    // with last_locked_out_slot = slot + lockout = 108 — i.e. STILL locked out
    // AT 108, expired strictly after (solana-vote-interface state/mod.rs:84-90).
    // The implementation (`current_slot > expiration`) was always correct;
    // the test now locks the canonical boundary.
    try std.testing.expect(!lockout.isExpired(100));
    try std.testing.expect(!lockout.isExpired(107));
    try std.testing.expect(!lockout.isExpired(108)); // boundary: locked out AT slot+lockout
    try std.testing.expect(lockout.isExpired(109)); // expired strictly after
    try std.testing.expect(lockout.isExpired(200));
}

