//! KAT for SIMD-0437 — incremental rent reduction (5 staged feature gates).
//!
//! SCOPE: this KAT locks the two parts of SIMD-0437 that are PROVABLE NOW (pure
//! functions of the spec), per the agave-behavior-extractor finding against Agave
//! 4.1.0-rc.1 (git 5efbb99). The genuinely-new live mechanism that 0437 requires —
//! re-serializing the SysvarRent111 account back to AccountsDb at the activation
//! epoch boundary (+ migrating Vexor's hardcoded 3480/2.0 rent-exemption math to
//! mutable per-bank rent, + the SIMD-0194 threshold-deprecation prerequisite) — is
//! HELD as a documented watch-item: it touches the LIVE epoch-boundary replay path
//! and only proves out at a real activation boundary (none of the 5 gates is active
//! on testnet today). Wiring it dormant is NOT cheaply-airtight (advisor 2026-06-21),
//! so we land the verifiable pieces and gate the rest.
//!
//! Spec/refs: Agave bank.rs:5623-5650 (trigger), :2494 (update_rent),
//! feature-set/lib.rs:1465-1494 (the 5 gates), solana-rent-4.2.0 lib.rs:26-38
//! (struct), bank/tests.rs:6358-6395 (selection-rule unit tests). Vexor feature
//! pubkeys already present: features.zig SET_LAMPORTS_PER_BYTE_TO_{6333,5080,2575,
//! 1322,696}. Integration point (held): replay_stage.zig:6962 applyNewFeatureActivations.

const std = @import("std");

// The 5 staged values, in Agave's fixed array order (highest→lowest). The
// reduction starts from DEFAULT_LAMPORTS_PER_BYTE = 6960 (rc.1, post-SIMD-0194).
const RENT_STEPS = [_]u64{ 6333, 5080, 2575, 1322, 696 };

/// Serialize a Rent record to its 17 on-chain bincode bytes (matches the Vexor
/// layout at sysvar_cache.zig:310-316 and Agave solana-rent-4.2.0): u64 LE
/// lamports_per_byte_year, f64 LE exemption_threshold, u8 burn_percent.
fn serializeRent(lamports_per_byte_year: u64, exemption_threshold: f64, burn_percent: u8) [17]u8 {
    var out: [17]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], lamports_per_byte_year, .little);
    std.mem.writeInt(u64, out[8..16], @bitCast(exemption_threshold), .little);
    out[16] = burn_percent;
    return out;
}

test "SIMD-0437: per-step Rent sysvar 17-byte serialization — golden vectors" {
    // exemption_threshold = 1.0 (post-SIMD-0194), burn_percent = 50. Only
    // lamports_per_byte (bytes 0..8) varies. Golden hex from the rc.1 extractor §13
    // (empirically bincode-confirmed against solana-rent-4.2.0).
    const cases = [_]struct { v: u64, hex: []const u8 }{
        .{ .v = 6333, .hex = "bd18000000000000000000000000f03f32" },
        .{ .v = 5080, .hex = "d813000000000000000000000000f03f32" },
        .{ .v = 2575, .hex = "0f0a000000000000000000000000f03f32" },
        .{ .v = 1322, .hex = "2a05000000000000000000000000f03f32" },
        .{ .v = 696, .hex = "b802000000000000000000000000f03f32" },
    };
    for (cases) |c| {
        const got = serializeRent(c.v, 1.0, 50);
        var expected: [17]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, c.hex);
        try std.testing.expectEqualSlices(u8, &expected, &got);
    }
    // 1.0 IEEE-754 LE sanity (bytes 8..16): 00 00 00 00 00 00 f0 3f.
    const r = serializeRent(696, 1.0, 50);
    try std.testing.expectEqual(@as(u64, 0x3FF0000000000000), std.mem.readInt(u64, r[8..16], .little));
    try std.testing.expectEqual(@as(u8, 50), r[16]);
}

// Mirror of Agave's selection rule (bank.rs:5645-5649): iterate the fixed array,
// overwrite lamports_per_byte for each gate that activated THIS boundary. Within a
// boundary the lowest-valued active gate wins (array is high→low, last write sticks);
// across boundaries whatever activated most recently wins.
fn selectRent(start: u64, newly_active: [5]bool) u64 {
    var lpb = start;
    for (RENT_STEPS, newly_active) |v, active| {
        if (active) lpb = v;
    }
    return lpb;
}

test "SIMD-0437: selection rule — lowest-value wins within one boundary" {
    // agave bank/tests.rs:6358-6382: activate 6333 + 2575 together → 2575.
    try std.testing.expectEqual(@as(u64, 2575), selectRent(6960, .{ true, false, true, false, false }));
    // single gate (1322) activates later → 1322 (across-boundary most-recent).
    try std.testing.expectEqual(@as(u64, 1322), selectRent(2575, .{ false, false, false, true, false }));
    // all five in one boundary → lowest (696).
    try std.testing.expectEqual(@as(u64, 696), selectRent(6960, .{ true, true, true, true, true }));
    // none active this boundary → unchanged (the dormant-today case: strict no-op).
    try std.testing.expectEqual(@as(u64, 6960), selectRent(6960, .{ false, false, false, false, false }));
}
