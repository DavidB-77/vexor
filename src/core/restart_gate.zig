//! Halt-restart gate helpers for `--expected-bank-hash` and
//! `--wait-for-supermajority` (wired 2026-06-15, branch
//! restart-flags-wiring-2026-06-15).
//!
//! These two flags were ALREADY parsed + logged (config.zig:77/83) but did
//! NOTHING. This module holds the PURE, unit-testable predicates that the
//! enforcement sites in main.zig call. Keeping the logic here (a `std`+base58
//! leaf module) lets the KATs root this file standalone (`zig build
//! test-restart-flags`) without dragging in the whole validator graph.
//!
//! Mirrors Agave's two restart-safety behaviors:
//!   * `--expected-bank-hash`  → halt-on-mismatch of the loaded snapshot bank
//!     (Agave: `ledger-tool`/validator boot bank-hash cross-check).
//!   * `--wait-for-supermajority` → block voting/production until ≥80% of the
//!     epoch's activated stake is observed in gossip
//!     (Agave WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT = 80).
//!
//! CONSENSUS SAFETY: every public fn here is only ever reached when the
//! corresponding flag is SET. When the flags are unset, main.zig never calls
//! into this module, so boot behavior is byte-for-byte unchanged.

const std = @import("std");
const base58 = @import("base58.zig");

/// Agave's `WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT`. A coordinated restart
/// resumes once this fraction of activated stake is back online.
pub const SUPERMAJORITY_THRESHOLD_PERCENT: u64 = 80;

/// Result of comparing the loaded snapshot bank hash to `--expected-bank-hash`.
pub const BankHashCheck = union(enum) {
    /// The flag's base58 decoded to a 32-byte hash equal to the loaded bank's.
    match,
    /// The decoded expected hash differs from the loaded bank's hash.
    mismatch,
    /// The flag value was not a valid 32-byte base58 hash.
    invalid_expected,
};

/// Compare a base58 `--expected-bank-hash` string against the loaded snapshot
/// bank's 32-byte hash. PURE: no logging, no exit — the caller decides the
/// fatal action. `allocator` is used only for the transient base58 decode.
pub fn checkExpectedBankHash(
    allocator: std.mem.Allocator,
    expected_b58: []const u8,
    loaded_hash: [32]u8,
) BankHashCheck {
    const decoded = base58.decode(allocator, expected_b58) catch return .invalid_expected;
    defer allocator.free(decoded);
    if (decoded.len != 32) return .invalid_expected;
    return if (std.mem.eql(u8, decoded, &loaded_hash)) .match else .mismatch;
}

/// Whether `observed_stake` meets the supermajority threshold of `total_stake`.
/// PURE integer math (no floating point) so it is deterministic and matches
/// Agave's `observed * 100 >= total * THRESHOLD` comparison exactly.
/// `total_stake == 0` → returns false (cannot have observed a supermajority of
/// nothing; the caller treats an empty epoch_stakes as "gate cannot be
/// satisfied" and logs the limitation rather than silently passing).
pub fn supermajorityMet(observed_stake: u128, total_stake: u128) bool {
    if (total_stake == 0) return false;
    return observed_stake * 100 >= total_stake * @as(u128, SUPERMAJORITY_THRESHOLD_PERCENT);
}

/// Percent (0..=100, integer-floored) of `total_stake` that `observed_stake`
/// represents, for human-readable progress logging. `total_stake == 0` → 0.
pub fn observedPercent(observed_stake: u128, total_stake: u128) u64 {
    if (total_stake == 0) return 0;
    return @intCast((observed_stake * 100) / total_stake);
}

// ─────────────────────────────────────────────────────────────────────────────
// KATs — `zig build test-restart-flags -Dcpu=znver4`
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "expected-bank-hash: matching base58 passes" {
    // All-ones hash, base58-encoded via the same library, must compare equal.
    var h: [32]u8 = undefined;
    for (&h, 0..) |*b, i| b.* = @intCast(i + 1); // 1,2,3,... distinct nonzero
    const enc = try base58.encode(testing.allocator, &h);
    defer testing.allocator.free(enc);
    try testing.expectEqual(BankHashCheck.match, checkExpectedBankHash(testing.allocator, enc, h));
}

test "expected-bank-hash: mismatched hash is detected" {
    var h: [32]u8 = undefined;
    for (&h, 0..) |*b, i| b.* = @intCast(i + 1);
    const enc = try base58.encode(testing.allocator, &h);
    defer testing.allocator.free(enc);
    var other = h;
    other[0] +%= 1; // perturb one byte
    try testing.expectEqual(BankHashCheck.mismatch, checkExpectedBankHash(testing.allocator, enc, other));
}

test "expected-bank-hash: known real 32-byte base58 decodes and matches" {
    // A genuine 32-byte base58 string (Solana pubkey-shaped). Decoded length
    // must be 32 and compare equal to its own decoding — guards against a
    // base58 length regression that would let a non-32B value false-match.
    // SYNTHETIC vector (base58 of bytes 0x01..0x20) — replaced the embedded
    // sibling-validator identity pubkey at rebuild migration (key isolation).
    const real = "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw";
    const decoded = try base58.decode(testing.allocator, real);
    defer testing.allocator.free(decoded);
    try testing.expectEqual(@as(usize, 32), decoded.len);
    var arr: [32]u8 = undefined;
    @memcpy(&arr, decoded);
    try testing.expectEqual(BankHashCheck.match, checkExpectedBankHash(testing.allocator, real, arr));
}

test "expected-bank-hash: too-short base58 is invalid_expected" {
    // "11" decodes to two zero bytes — not 32 → invalid, never a false match.
    try testing.expectEqual(BankHashCheck.invalid_expected, checkExpectedBankHash(testing.allocator, "11", [_]u8{0} ** 32));
}

test "supermajority: 79.9% NOT met" {
    // 799 / 1000 = 79.9% < 80%
    try testing.expect(!supermajorityMet(799, 1000));
}

test "supermajority: exactly 80% IS met" {
    try testing.expect(supermajorityMet(800, 1000));
}

test "supermajority: 100% IS met" {
    try testing.expect(supermajorityMet(1000, 1000));
}

test "supermajority: zero total stake is NOT met (conservative)" {
    try testing.expect(!supermajorityMet(0, 0));
    try testing.expect(!supermajorityMet(123, 0));
}

test "supermajority: large stake values do not overflow (u128 math)" {
    // ~13.3M SOL-scale lamports: 800e15 / 1000e15 = 80% met.
    const observed: u128 = 800_000_000_000_000_000;
    const total: u128 = 1_000_000_000_000_000_000;
    try testing.expect(supermajorityMet(observed, total));
    try testing.expect(!supermajorityMet(observed - 1, total));
}

test "observedPercent: floors correctly" {
    try testing.expectEqual(@as(u64, 79), observedPercent(799, 1000));
    try testing.expectEqual(@as(u64, 80), observedPercent(800, 1000));
    try testing.expectEqual(@as(u64, 100), observedPercent(1000, 1000));
    try testing.expectEqual(@as(u64, 0), observedPercent(5, 0));
}
