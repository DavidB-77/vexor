//! KAT: Layer-A known-validator snapshot-hash agreement (keep-first/conflict-drop).
//! Pure offline test of snapshot_trust.build + KnownSnapshotHashes.isVouched —
//! mirrors Agave build_known_snapshot_hashes (validator/src/bootstrap.rs:924).
//! Run: zig build test-snapshot-trust

const std = @import("std");
const st = @import("snapshot_trust.zig");

fn h(byte: u8) [32]u8 {
    return [_]u8{byte} ** 32;
}

test "empty known set vouches for nothing" {
    var k = try st.build(std.testing.allocator, &.{});
    defer k.deinit();
    try std.testing.expectEqual(@as(usize, 0), k.count());
    try std.testing.expect(!k.isVouched(100, h(0xAA)));
}

test "single validator: exact (slot,hash) vouched, others rejected" {
    const fulls = [_]?st.SlotHash{.{ .slot = 100, .hash = h(0xAA) }};
    var k = try st.build(std.testing.allocator, &fulls);
    defer k.deinit();
    try std.testing.expect(k.isVouched(100, h(0xAA))); // exact match
    try std.testing.expect(!k.isVouched(100, h(0xBB))); // right slot, wrong hash
    try std.testing.expect(!k.isVouched(101, h(0xAA))); // wrong slot
    try std.testing.expectEqual(@as(u32, 0), k.conflicts);
}

test "two validators agreeing on a slot: vouched, no conflict" {
    const fulls = [_]?st.SlotHash{
        .{ .slot = 200, .hash = h(0xCC) },
        .{ .slot = 200, .hash = h(0xCC) },
    };
    var k = try st.build(std.testing.allocator, &fulls);
    defer k.deinit();
    try std.testing.expect(k.isVouched(200, h(0xCC)));
    try std.testing.expectEqual(@as(u32, 0), k.conflicts);
    try std.testing.expectEqual(@as(usize, 1), k.count());
}

test "conflict: keep-first hash wins, conflict counted, loser rejected" {
    const fulls = [_]?st.SlotHash{
        .{ .slot = 300, .hash = h(0x11) }, // first wins
        .{ .slot = 300, .hash = h(0x22) }, // conflicting → ignored
    };
    var k = try st.build(std.testing.allocator, &fulls);
    defer k.deinit();
    try std.testing.expect(k.isVouched(300, h(0x11))); // first kept
    try std.testing.expect(!k.isVouched(300, h(0x22))); // conflicting loser NOT vouched
    try std.testing.expectEqual(@as(u32, 1), k.conflicts);
}

test "null advertisements (validator not yet in gossip) are skipped" {
    const fulls = [_]?st.SlotHash{
        null,
        .{ .slot = 400, .hash = h(0x33) },
        null,
    };
    var k = try st.build(std.testing.allocator, &fulls);
    defer k.deinit();
    try std.testing.expect(k.isVouched(400, h(0x33)));
    try std.testing.expectEqual(@as(usize, 1), k.count());
}

test "multiple distinct slots across validators all vouched" {
    const fulls = [_]?st.SlotHash{
        .{ .slot = 500, .hash = h(0x44) },
        .{ .slot = 600, .hash = h(0x55) },
        .{ .slot = 700, .hash = h(0x66) },
    };
    var k = try st.build(std.testing.allocator, &fulls);
    defer k.deinit();
    try std.testing.expect(k.isVouched(500, h(0x44)));
    try std.testing.expect(k.isVouched(600, h(0x55)));
    try std.testing.expect(k.isVouched(700, h(0x66)));
    try std.testing.expect(!k.isVouched(500, h(0x55))); // cross-slot hash must not match
    try std.testing.expectEqual(@as(usize, 3), k.count());
}

test "A3b gate decision: map.get distinguishes absent / present-match / present-mismatch" {
    // Mirrors main.zig's post-load/pre-vote gate, which branches on
    // agreement.map.get(loaded_slot): null⇒absent⇒PROCEED, present+eql⇒VOUCHED,
    // present+!eql⇒MISMATCH (log in log-mode, ABORT in reject-mode). isVouched()
    // alone conflates absent and mismatch as false, so the gate uses map.get to
    // separate "no known-validator advertised our slot" (safe) from "a
    // known-validator advertised our slot with a DIFFERENT hash" (poisoned).
    const fulls = [_]?st.SlotHash{
        .{ .slot = 900, .hash = h(0x77) }, // a known-validator advertised slot 900
    };
    var k = try st.build(std.testing.allocator, &fulls);
    defer k.deinit();

    // ABSENT: we loaded a slot no known-validator advertised → null → PROCEED.
    try std.testing.expect(k.map.get(901) == null);

    // PRESENT-AND-MATCH: loaded slot 900 with the vouched hash → VOUCHED.
    const got_match = k.map.get(900);
    try std.testing.expect(got_match != null);
    try std.testing.expect(std.mem.eql(u8, &got_match.?, &h(0x77)));

    // PRESENT-AND-MISMATCH: loaded slot 900 with a DIFFERENT hash → the reject path.
    const got_mismatch = k.map.get(900);
    try std.testing.expect(got_mismatch != null);
    try std.testing.expect(!std.mem.eql(u8, &got_mismatch.?, &h(0x88)));
}
