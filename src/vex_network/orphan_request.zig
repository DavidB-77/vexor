//! Pure byte-builder for the Orphan repair request (`RepairProtocol::Orphan`,
//! discriminant 10) — the FETCH half of the orphan-repair catchup fix.
//!
//! The catchup stall is FETCH-blocked: Vexor's live repair requester emits only
//! WindowIndex(8) + HighestWindowIndex(9), never Orphan(10), so the 0-shred
//! bridge-ancestors between root and tip are never discovered/fetched. This is
//! the request that asks a peer "who are the ancestors of this orphan slot?".
//!
//! Confirmed against LOCAL agave-4.1.0-beta.1 (2026-05-30):
//!   - serve_repair.rs:429 enum order: …Pong=7, WindowIndex=8,
//!     HighestWindowIndex=9, **Orphan=10**, AncestorHashes=11.
//!   - RepairRequestHeader { signature[64], sender[32], recipient[32],
//!     timestamp:u64, nonce:u32 }.
//! The on-wire Orphan request is the 152-byte prefix of Vexor's PROVEN
//! WindowIndex/HighestWindowIndex builder (tvu.zig:requestHighestWindowIndex)
//! with the discriminant set to 10 and the trailing 8-byte shred_index OMITTED.
//! Because that builder already pulls shreds off the wire, the byte layout is
//! empirically correct — we clone it rather than re-derive it.
//!
//! Layout (little-endian; bincode 4-byte enum discriminant):
//!   [0..4]     u32  discriminant = 10
//!   [4..68]    [64] Ed25519 signature (filled by caller after signing)
//!   [68..100]  [32] sender    (requester identity pubkey)
//!   [100..132] [32] recipient (destination peer pubkey — binds the request)
//!   [132..140] u64  timestamp_ms
//!   [140..144] u32  nonce
//!   [144..152] u64  slot (the orphan whose ancestry we want)
//! Signature domain = [0..4] ++ [68..152] (everything except the sig field) —
//! identical composition to the proven WindowIndex sign domain.
//!
//! Imports only std → `zig build test-orphan-request`.

const std = @import("std");

pub const DISCRIMINANT_ORPHAN: u32 = 10;
pub const REQUEST_LEN: usize = 152;
pub const SIGN_DOMAIN_LEN: usize = 88; // 4 (disc) + 84 ([68..152])

/// Fill `out` with the Orphan request EXCEPT the signature ([4..68] left as-is).
/// Caller composes `signDomain(out)`, Ed25519-signs it, and writes the 64-byte
/// signature into out[4..68].
pub fn buildUnsigned(
    out: *[REQUEST_LEN]u8,
    sender: [32]u8,
    recipient: [32]u8,
    timestamp_ms: u64,
    nonce: u32,
    slot: u64,
) void {
    std.mem.writeInt(u32, out[0..4], DISCRIMINANT_ORPHAN, .little);
    @memcpy(out[68..100], &sender);
    @memcpy(out[100..132], &recipient);
    std.mem.writeInt(u64, out[132..140], timestamp_ms, .little);
    std.mem.writeInt(u32, out[140..144], nonce, .little);
    std.mem.writeInt(u64, out[144..152], slot, .little);
}

/// Compose the Ed25519 signing domain: discriminant ++ header-after-sig ++ slot
/// = req[0..4] ++ req[68..152]. Excludes the 64-byte signature field at [4..68].
pub fn signDomain(req: *const [REQUEST_LEN]u8, out: *[SIGN_DOMAIN_LEN]u8) void {
    @memcpy(out[0..4], req[0..4]);
    @memcpy(out[4..88], req[68..152]);
}

test "orphan request: protocol constants" {
    try std.testing.expectEqual(@as(u32, 10), DISCRIMINANT_ORPHAN);
    try std.testing.expectEqual(@as(usize, 152), REQUEST_LEN);
    try std.testing.expectEqual(@as(usize, 88), SIGN_DOMAIN_LEN);
}

test "orphan request: byte layout is exact + deterministic" {
    var sender: [32]u8 = undefined;
    var recipient: [32]u8 = undefined;
    for (&sender, 0..) |*b, i| b.* = @intCast(i); // 0x00..0x1f
    for (&recipient, 0..) |*b, i| b.* = @intCast(0x80 + i); // 0x80..0x9f
    var req: [REQUEST_LEN]u8 = [_]u8{0} ** REQUEST_LEN;
    buildUnsigned(&req, sender, recipient, 0x1122334455667788, 0xDEADBEEF, 0x0102030405060708);

    // discriminant = 10 (LE)
    try std.testing.expectEqual(@as(u32, 10), std.mem.readInt(u32, req[0..4], .little));
    // signature region must be left untouched (caller fills it)
    for (req[4..68]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    // sender / recipient at the canonical offsets
    try std.testing.expectEqualSlices(u8, &sender, req[68..100]);
    try std.testing.expectEqualSlices(u8, &recipient, req[100..132]);
    // timestamp / nonce / slot (LE)
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), std.mem.readInt(u64, req[132..140], .little));
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), std.mem.readInt(u32, req[140..144], .little));
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), std.mem.readInt(u64, req[144..152], .little));
}

test "orphan request: sign domain = disc ++ [68..152], excludes the signature field" {
    var req: [REQUEST_LEN]u8 = [_]u8{0} ** REQUEST_LEN;
    // Put recognizable bytes in the sig region; they must NOT leak into the domain.
    for (req[4..68]) |*b| b.* = 0xFF;
    buildUnsigned(&req, [_]u8{0xAA} ** 32, [_]u8{0xBB} ** 32, 7, 9, 42);
    var dom: [SIGN_DOMAIN_LEN]u8 = undefined;
    signDomain(&req, &dom);
    // domain starts with the discriminant
    try std.testing.expectEqual(@as(u32, 10), std.mem.readInt(u32, dom[0..4], .little));
    // domain tail equals the header-after-sig + slot, byte for byte
    try std.testing.expectEqualSlices(u8, req[68..152], dom[4..88]);
    // none of the 0xFF signature bytes were included
    try std.testing.expect(std.mem.indexOfScalar(u8, &dom, 0xFF) == null);
}
