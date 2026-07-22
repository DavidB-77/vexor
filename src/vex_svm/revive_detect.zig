//! Switch-proof Part 2, M1 — [REVIVE-WOULD-FIRE] detection pure predicate + the
//! offline SlotHashes-injection parser, factored out of replay_stage.zig exactly
//! like root_guards.zig (Part 4b): replay_stage.zig is an unmigrated god-file
//! whose OWN inline `test` blocks never run under any build target (see
//! root_guards.zig's own header note + build.zig's test-root-guards step comment:
//! "replay_stage.zig itself is an unmigrated god-file inside the vex_svm named
//! module, so its own test blocks do not run under any target") — so the testable
//! logic here is factored into this small leaf (imports only `core`, exactly like
//! root_guards.zig) and replay_stage.zig's `sweepPendingTickGateSlots` /
//! `fetchSlotHashesRemote` become thin callers with no test blocks of their own.
//!
//! Design: switch-proof self-recovery Part 2, §1.1 (feed) / §2 M1 (scope:
//! read-only detection, zero mutation of dead_slots / self.banks / the
//! assembler / fork_choice).

const std = @import("std");
const core = @import("core");

/// Pure decision for ONE `dead_slots` member on a single sweep pass.
/// `cluster_hash` is the caller's `scanCachedSlotHash(slot)` result (null = the
/// cluster hasn't confirmed a hash for this dead slot yet — the cache may be
/// stale at-tip, exactly why the sweep re-checks on every refresh rather than
/// once at mark-dead time). `already_logged` is whether this slot is already in
/// the caller's dedup latch (without it, a dead slot would re-fire every sweep
/// pass for as long as it stays in `dead_slots`, since M1 never removes it).
/// Returns the hash to log iff [REVIVE-WOULD-FIRE] should fire now; null
/// otherwise. Never allocates, never logs, never mutates — the caller owns the
/// latch update and the actual log call.
pub fn checkReviveWouldFire(cluster_hash: ?[32]u8, already_logged: bool) ?[32]u8 {
    if (already_logged) return null;
    return cluster_hash;
}

/// One parsed (slot, hash) pair from an injected SlotHashes text file.
pub const InjectedEntry = struct { slot: u64, hash: [32]u8 };

/// Parses "slot=<u64> hash=<base58>" tokens out of `contents`, one slot per
/// line; any other whitespace-delimited tokens on the line (e.g. the real
/// forensics CANONICAL-HASHES.txt capture format's `signature_count=`/
/// `total_data_len=` fields) are ignored, so that exact forensics file is
/// consumable directly with no conversion step. Malformed/non-matching lines
/// are skipped. Pure text→data parsing, no I/O — the caller
/// (`parseSlotHashInjectFile` in replay_stage.zig) does the file read; this is
/// the `VEX_SLOT_HASH_INJECT_FILE` offline/gate-injection mechanism (switch-proof
/// Part 2, M1) that lets an offline replay gate supply the cluster's bank_hash
/// for a dead slot deterministically, since both M1 gate incidents are days-old
/// slots outside the live ~512-slot SlotHashes sysvar window. Caller owns/frees
/// the returned slice.
pub fn parseSlotHashInjectContent(allocator: std.mem.Allocator, contents: []const u8) ![]InjectedEntry {
    var entries = std.ArrayListUnmanaged(InjectedEntry){};
    errdefer entries.deinit(allocator);

    var lines = std.mem.tokenizeAny(u8, contents, "\r\n");
    while (lines.next()) |line| {
        var slot_val: ?u64 = null;
        var hash_val: ?[32]u8 = null;
        var toks = std.mem.tokenizeAny(u8, line, " \t");
        while (toks.next()) |tok| {
            if (std.mem.startsWith(u8, tok, "slot=")) {
                slot_val = std.fmt.parseInt(u64, tok[5..], 10) catch null;
            } else if (std.mem.startsWith(u8, tok, "hash=")) {
                var buf: [32]u8 = undefined;
                core.base58.decodeToBuf(tok[5..], &buf) catch continue;
                hash_val = buf;
            }
        }
        if (slot_val) |s| {
            if (hash_val) |h| {
                try entries.append(allocator, .{ .slot = s, .hash = h });
            }
        }
    }
    return entries.toOwnedSlice(allocator);
}

/// Serializes parsed entries into the SAME wire shape `installSlotHashes`
/// expects from the live RPC path (`fetchSlotHashesRemote`'s normal curl+decode
/// result): 8-byte LE entry count + count*(8-byte LE slot, 32-byte hash) —
/// the on-chain SlotHashes sysvar's own account layout. Returns null for an
/// empty input; the caller should treat that exactly like a failed curl
/// (degrade to "no injection, keep last cached value").
pub fn encodeSlotHashBlob(allocator: std.mem.Allocator, entries: []const InjectedEntry) !?[]u8 {
    if (entries.len == 0) return null;
    const out = try allocator.alloc(u8, 8 + entries.len * 40);
    std.mem.writeInt(u64, out[0..8], entries.len, .little);
    for (entries, 0..) |e, i| {
        const off = 8 + i * 40;
        std.mem.writeInt(u64, out[off..][0..8], e.slot, .little);
        @memcpy(out[off + 8 ..][0..32], &e.hash);
    }
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS — these DO run (zig build test-revive-detect): this file is its own
// module root, unlike replay_stage.zig's inline tests.
// ═══════════════════════════════════════════════════════════════════════════════

test "checkReviveWouldFire: fires when cluster hash is present and not already logged" {
    const h = [_]u8{0xAB} ** 32;
    const got = checkReviveWouldFire(h, false);
    try std.testing.expect(got != null);
    try std.testing.expectEqualSlices(u8, &h, &got.?);
}

test "checkReviveWouldFire: no cluster hash yet -> does not fire" {
    try std.testing.expect(checkReviveWouldFire(null, false) == null);
}

test "checkReviveWouldFire: dedup latch suppresses a second fire even though the hash is still present" {
    const h = [_]u8{0xCD} ** 32;
    // First pass: fires.
    try std.testing.expect(checkReviveWouldFire(h, false) != null);
    // Subsequent pass, same hash still in cache, but caller's latch says already
    // logged -> must NOT fire again.
    try std.testing.expect(checkReviveWouldFire(h, true) == null);
}

test "checkReviveWouldFire: already_logged with no cluster hash still does not fire (order-independent)" {
    try std.testing.expect(checkReviveWouldFire(null, true) == null);
}

test "parseSlotHashInjectContent: parses CANONICAL-HASHES.txt-shaped lines, ignores extra tokens and non-matching lines" {
    const allocator = std.testing.allocator;
    // hash_a: 32 zero bytes == base58 "1" * 32 (System Program ID's well-known form).
    // hash_b: an arbitrary real testnet hash (406's canonical, from CANONICAL-HASHES.txt).
    const contents =
        "slot=422359400 hash=11111111111111111111111111111111 signature_count=485 total_data_len=1970917\n" ++
        "slot=422359406 hash=86AprRYZ4bLLDmr86WNtxZvp5r77PTdAkq9QLbz1GEwk signature_count=485 total_data_len=1973469  ** CANONICAL **\n" ++
        "this line matches nothing\n" ++
        "\n";

    const entries = try parseSlotHashInjectContent(allocator, contents);
    defer allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqual(@as(u64, 422359400), entries[0].slot);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &entries[0].hash);
    try std.testing.expectEqual(@as(u64, 422359406), entries[1].slot);
    // Not all-zero (sanity: the base58 decode actually produced distinct bytes).
    try std.testing.expect(!std.mem.eql(u8, &([_]u8{0} ** 32), &entries[1].hash));
}

test "parseSlotHashInjectContent: empty/garbage input yields zero entries, not an error" {
    const allocator = std.testing.allocator;
    const entries = try parseSlotHashInjectContent(allocator, "nothing here\nslot=missing-hash\nhash=missing-slot\n");
    defer allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "encodeSlotHashBlob: empty entries -> null (degrade like a failed curl)" {
    const allocator = std.testing.allocator;
    const blob = try encodeSlotHashBlob(allocator, &.{});
    try std.testing.expect(blob == null);
}

test "encodeSlotHashBlob: wire shape is 8-byte LE count + (8-byte LE slot, 32-byte hash) per entry" {
    const allocator = std.testing.allocator;
    const h0 = [_]u8{0x11} ** 32;
    const h1 = [_]u8{0x22} ** 32;
    const entries = [_]InjectedEntry{
        .{ .slot = 100, .hash = h0 },
        .{ .slot = 200, .hash = h1 },
    };
    const blob = try encodeSlotHashBlob(allocator, &entries);
    defer allocator.free(blob.?);
    const data = blob.?;

    try std.testing.expectEqual(@as(usize, 8 + 2 * 40), data.len);
    try std.testing.expectEqual(@as(u64, 2), std.mem.readInt(u64, data[0..8], .little));
    try std.testing.expectEqual(@as(u64, 100), std.mem.readInt(u64, data[8..][0..8], .little));
    try std.testing.expectEqualSlices(u8, &h0, data[16..][0..32]);
    try std.testing.expectEqual(@as(u64, 200), std.mem.readInt(u64, data[48..][0..8], .little));
    try std.testing.expectEqualSlices(u8, &h1, data[56..][0..32]);
}

test "end-to-end: parse -> encode round-trips slot+hash pairs (mirrors the offline gate's real usage)" {
    const allocator = std.testing.allocator;
    const contents = "slot=421935259 hash=3JG7REXRN7QAYJhj7j9nFPeVq3okjBFMHhSnXBzpuFxZ\n";
    const entries = try parseSlotHashInjectContent(allocator, contents);
    defer allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(u64, 421935259), entries[0].slot);

    const blob = try encodeSlotHashBlob(allocator, entries);
    defer allocator.free(blob.?);
    // Independently re-decode the blob the same way scanCachedSlotHash does, to
    // prove the round trip without depending on replay_stage.zig.
    const data = blob.?;
    const count = std.mem.readInt(u64, data[0..8], .little);
    try std.testing.expectEqual(@as(u64, 1), count);
    const got_slot = std.mem.readInt(u64, data[8..][0..8], .little);
    try std.testing.expectEqual(@as(u64, 421935259), got_slot);
    try std.testing.expectEqualSlices(u8, &entries[0].hash, data[16..][0..32]);
}
