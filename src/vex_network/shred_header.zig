//! Canonical Solana merkle-shred HEADER (de)serialization — the foundation of the shred encoder.
//!
//! STAGED / MODULAR: not wired to the live path; gated behind -Dleader_mode at the call site. This
//! is the first piece of the shredder rewrite (BP campaign step 4). It owns ONLY the byte-exact
//! header layout; FEC-set chunking, the merkle tree over a set (reuses vex_network/bmtree.zig),
//! Reed-Solomon parity, chained root (SIMD-0340), and signing are subsequent sub-pieces.
//!
//! Ground truth: Firedancer pin v0.1002.40103 src/ballet/shred/fd_shred.h (the version testnet runs;
//! operator-pinned). Verified offsets:
//!   common: 0x00 signature[64]; 0x40 variant u8; 0x41 slot u64; 0x49 idx u32; 0x4d version u16;
//!           0x4f fec_set_idx u32.
//!   data  : 0x53 parent_off u16; 0x55 flags u8; 0x56 size u16  -> header end 0x58 (88).
//!   code  : 0x53 data_cnt u16; 0x55 code_cnt u16; 0x57 idx u16 -> header end 0x59 (89).
//! Type (high nibble of variant @0x40): MERKLE_DATA 0x80 / _CODE 0x40; CHAINED data 0x90 / code 0x60;
//!   CHAINED_RESIGNED data 0xB0 / code 0x70. Flags: SLOT_COMPLETE 0x80, DATA_COMPLETE 0x40,
//!   REF_TICK_MASK 0x3f. MERKLE_ROOT_SZ 32, NODE_SZ 20, LAYER_CNT 7, SIGNATURE_SZ 64.

const std = @import("std");

pub const SIGNATURE_SZ: usize = 64;
pub const MERKLE_ROOT_SZ: usize = 32;
pub const MERKLE_NODE_SZ: usize = 20;
pub const DATA_HEADER_SZ: usize = 0x58; // 88
pub const CODE_HEADER_SZ: usize = 0x59; // 89
pub const SHRED_MIN_SZ: usize = 1203;
pub const SHRED_MAX_SZ: usize = 1228;

pub const VARIANT_OFF: usize = 0x40;

// fd_shred.h shred type byte values (high nibble of variant).
pub const TYPE_MERKLE_DATA: u8 = 0x80;
pub const TYPE_MERKLE_CODE: u8 = 0x40;
pub const TYPE_MERKLE_DATA_CHAINED: u8 = 0x90;
pub const TYPE_MERKLE_CODE_CHAINED: u8 = 0x60;
pub const TYPE_MERKLE_DATA_CHAINED_RESIGNED: u8 = 0xB0;
pub const TYPE_MERKLE_CODE_CHAINED_RESIGNED: u8 = 0x70;
pub const TYPEMASK_DATA: u8 = TYPE_MERKLE_DATA; // 0x80 — data types have bit 0x80
pub const TYPEMASK_CODE: u8 = TYPE_MERKLE_CODE; // 0x40

// Data flags (byte 0x55).
pub const DATA_FLAG_SLOT_COMPLETE: u8 = 0x80;
pub const DATA_FLAG_DATA_COMPLETE: u8 = 0x40;
pub const DATA_REF_TICK_MASK: u8 = 0x3f;

pub const ShredType = enum { merkle_data, merkle_code };

/// Returns whether a variant byte is a data (vs code) shred. fd_shred.h: data types carry the 0x80
/// bit and NOT 0x40; code types carry 0x40 and not 0x80. (Proof depth lives in the low nibble.)
pub fn isData(variant: u8) bool {
    return (variant & 0xF0 & TYPEMASK_DATA) != 0 and (variant & 0xF0 & 0x40) == 0;
}
pub fn shredType(variant: u8) ShredType {
    return if (isData(variant)) .merkle_data else .merkle_code;
}
/// Low nibble of a merkle variant = the merkle proof depth (number of inclusion-proof nodes).
pub fn proofDepth(variant: u8) u4 {
    return @intCast(variant & 0x0F);
}
pub fn isChained(variant: u8) bool {
    const t = variant & 0xF0;
    return t == TYPE_MERKLE_DATA_CHAINED or t == TYPE_MERKLE_CODE_CHAINED or
        t == TYPE_MERKLE_DATA_CHAINED_RESIGNED or t == TYPE_MERKLE_CODE_CHAINED_RESIGNED;
}
pub fn isResigned(variant: u8) bool {
    const t = variant & 0xF0;
    return t == TYPE_MERKLE_DATA_CHAINED_RESIGNED or t == TYPE_MERKLE_CODE_CHAINED_RESIGNED;
}

/// Build a merkle-data variant byte from a proof depth + chaining/resigned flags.
pub fn dataVariant(depth: u4, chained: bool, resigned: bool) u8 {
    const hi: u8 = if (resigned) TYPE_MERKLE_DATA_CHAINED_RESIGNED else if (chained) TYPE_MERKLE_DATA_CHAINED else TYPE_MERKLE_DATA;
    return hi | @as(u8, depth);
}
pub fn codeVariant(depth: u4, chained: bool, resigned: bool) u8 {
    const hi: u8 = if (resigned) TYPE_MERKLE_CODE_CHAINED_RESIGNED else if (chained) TYPE_MERKLE_CODE_CHAINED else TYPE_MERKLE_CODE;
    return hi | @as(u8, depth);
}

/// The common header fields (0x00..0x53) shared by data + code shreds.
pub const CommonHeader = struct {
    signature: [SIGNATURE_SZ]u8 = [_]u8{0} ** SIGNATURE_SZ,
    variant: u8,
    slot: u64,
    idx: u32,
    version: u16,
    fec_set_idx: u32,
};

pub const DataHeader = struct {
    common: CommonHeader,
    parent_off: u16,
    flags: u8,
    size: u16, // total shred size incl headers (the `size` field at 0x56)

    /// Serialize the 88-byte data shred header into `out` (out.len >= DATA_HEADER_SZ).
    pub fn serialize(self: DataHeader, out: []u8) void {
        std.debug.assert(out.len >= DATA_HEADER_SZ);
        @memcpy(out[0..SIGNATURE_SZ], &self.common.signature);
        out[0x40] = self.common.variant;
        std.mem.writeInt(u64, out[0x41..][0..8], self.common.slot, .little);
        std.mem.writeInt(u32, out[0x49..][0..4], self.common.idx, .little);
        std.mem.writeInt(u16, out[0x4d..][0..2], self.common.version, .little);
        std.mem.writeInt(u32, out[0x4f..][0..4], self.common.fec_set_idx, .little);
        std.mem.writeInt(u16, out[0x53..][0..2], self.parent_off, .little);
        out[0x55] = self.flags;
        std.mem.writeInt(u16, out[0x56..][0..2], self.size, .little);
    }

    pub fn parse(buf: []const u8) error{Truncated}!DataHeader {
        if (buf.len < DATA_HEADER_SZ) return error.Truncated;
        var sig: [SIGNATURE_SZ]u8 = undefined;
        @memcpy(&sig, buf[0..SIGNATURE_SZ]);
        return .{
            .common = .{
                .signature = sig,
                .variant = buf[0x40],
                .slot = std.mem.readInt(u64, buf[0x41..][0..8], .little),
                .idx = std.mem.readInt(u32, buf[0x49..][0..4], .little),
                .version = std.mem.readInt(u16, buf[0x4d..][0..2], .little),
                .fec_set_idx = std.mem.readInt(u32, buf[0x4f..][0..4], .little),
            },
            .parent_off = std.mem.readInt(u16, buf[0x53..][0..2], .little),
            .flags = buf[0x55],
            .size = std.mem.readInt(u16, buf[0x56..][0..2], .little),
        };
    }

    pub fn referenceTick(self: DataHeader) u8 {
        return self.flags & DATA_REF_TICK_MASK;
    }
    pub fn isDataComplete(self: DataHeader) bool {
        return (self.flags & DATA_FLAG_DATA_COMPLETE) != 0;
    }
    pub fn isSlotComplete(self: DataHeader) bool {
        return (self.flags & DATA_FLAG_SLOT_COMPLETE) != 0;
    }
};

pub const CodeHeader = struct {
    common: CommonHeader,
    data_cnt: u16,
    code_cnt: u16,
    idx: u16, // position of this coding shred within the FEC set's coding shreds

    pub fn serialize(self: CodeHeader, out: []u8) void {
        std.debug.assert(out.len >= CODE_HEADER_SZ);
        @memcpy(out[0..SIGNATURE_SZ], &self.common.signature);
        out[0x40] = self.common.variant;
        std.mem.writeInt(u64, out[0x41..][0..8], self.common.slot, .little);
        std.mem.writeInt(u32, out[0x49..][0..4], self.common.idx, .little);
        std.mem.writeInt(u16, out[0x4d..][0..2], self.common.version, .little);
        std.mem.writeInt(u32, out[0x4f..][0..4], self.common.fec_set_idx, .little);
        std.mem.writeInt(u16, out[0x53..][0..2], self.data_cnt, .little);
        std.mem.writeInt(u16, out[0x55..][0..2], self.code_cnt, .little);
        std.mem.writeInt(u16, out[0x57..][0..2], self.idx, .little);
    }

    pub fn parse(buf: []const u8) error{Truncated}!CodeHeader {
        if (buf.len < CODE_HEADER_SZ) return error.Truncated;
        var sig: [SIGNATURE_SZ]u8 = undefined;
        @memcpy(&sig, buf[0..SIGNATURE_SZ]);
        return .{
            .common = .{
                .signature = sig,
                .variant = buf[0x40],
                .slot = std.mem.readInt(u64, buf[0x41..][0..8], .little),
                .idx = std.mem.readInt(u32, buf[0x49..][0..4], .little),
                .version = std.mem.readInt(u16, buf[0x4d..][0..2], .little),
                .fec_set_idx = std.mem.readInt(u32, buf[0x4f..][0..4], .little),
            },
            .data_cnt = std.mem.readInt(u16, buf[0x53..][0..2], .little),
            .code_cnt = std.mem.readInt(u16, buf[0x55..][0..2], .little),
            .idx = std.mem.readInt(u16, buf[0x57..][0..2], .little),
        };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// KAT — byte-exact layout vs fd_shred.h (pin v0.1002.40103). Run: zig build test-shred-header
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "constants match fd_shred.h v0.1002.40103" {
    try testing.expectEqual(@as(usize, 0x58), DATA_HEADER_SZ);
    try testing.expectEqual(@as(usize, 0x59), CODE_HEADER_SZ);
    try testing.expectEqual(@as(usize, 20), MERKLE_NODE_SZ);
    try testing.expectEqual(@as(u8, 0x80), TYPE_MERKLE_DATA);
    try testing.expectEqual(@as(u8, 0x90), TYPE_MERKLE_DATA_CHAINED);
    try testing.expectEqual(@as(u8, 0x60), TYPE_MERKLE_CODE_CHAINED);
}

test "variant helpers: type / chained / resigned / depth" {
    try testing.expect(isData(0x90)); // chained data
    try testing.expect(!isData(0x60)); // chained code
    try testing.expectEqual(ShredType.merkle_data, shredType(0x96));
    try testing.expectEqual(ShredType.merkle_code, shredType(0x66));
    try testing.expectEqual(@as(u4, 6), proofDepth(0x96));
    try testing.expect(isChained(0x90) and !isResigned(0x90));
    try testing.expect(isChained(0xB0) and isResigned(0xB0));
    try testing.expectEqual(@as(u8, 0x96), dataVariant(6, true, false));
    try testing.expectEqual(@as(u8, 0xB6), dataVariant(6, true, true));
    try testing.expectEqual(@as(u8, 0x66), codeVariant(6, true, false));
}

test "data header serialize → parse round-trip + exact byte offsets" {
    var sig: [SIGNATURE_SZ]u8 = undefined;
    for (&sig, 0..) |*b, i| b.* = @intCast(i & 0xFF);
    const h = DataHeader{
        .common = .{ .signature = sig, .variant = dataVariant(6, true, false), .slot = 415064690, .idx = 7, .version = 57087, .fec_set_idx = 5 },
        .parent_off = 1,
        .flags = DATA_FLAG_DATA_COMPLETE | 0x05, // reference_tick=5, data-complete
        .size = 1203,
    };
    var buf: [DATA_HEADER_SZ]u8 = undefined;
    h.serialize(&buf);

    // exact offsets
    try testing.expectEqual(@as(u8, 0x96), buf[0x40]); // variant
    try testing.expectEqual(@as(u64, 415064690), std.mem.readInt(u64, buf[0x41..][0..8], .little));
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, buf[0x49..][0..4], .little));
    try testing.expectEqual(@as(u16, 57087), std.mem.readInt(u16, buf[0x4d..][0..2], .little));
    try testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, buf[0x4f..][0..4], .little));
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, buf[0x53..][0..2], .little));
    try testing.expectEqual(@as(u16, 1203), std.mem.readInt(u16, buf[0x56..][0..2], .little));

    const p = try DataHeader.parse(&buf);
    try testing.expectEqualSlices(u8, &h.common.signature, &p.common.signature);
    try testing.expectEqual(h.common.slot, p.common.slot);
    try testing.expectEqual(h.size, p.size);
    try testing.expect(p.isDataComplete());
    try testing.expect(!p.isSlotComplete());
    try testing.expectEqual(@as(u8, 5), p.referenceTick());
}

test "code header serialize → parse round-trip + 0x59 length" {
    const h = CodeHeader{
        .common = .{ .variant = codeVariant(6, true, false), .slot = 100, .idx = 32, .version = 57087, .fec_set_idx = 5 },
        .data_cnt = 32,
        .code_cnt = 32,
        .idx = 3,
    };
    var buf: [CODE_HEADER_SZ]u8 = undefined;
    h.serialize(&buf);
    try testing.expectEqual(@as(u16, 32), std.mem.readInt(u16, buf[0x53..][0..2], .little)); // data_cnt
    try testing.expectEqual(@as(u16, 32), std.mem.readInt(u16, buf[0x55..][0..2], .little)); // code_cnt
    try testing.expectEqual(@as(u16, 3), std.mem.readInt(u16, buf[0x57..][0..2], .little)); // idx
    const p = try CodeHeader.parse(&buf);
    try testing.expectEqual(h.data_cnt, p.data_cnt);
    try testing.expectEqual(h.code_cnt, p.code_cnt);
    try testing.expectEqual(h.idx, p.idx);
    try testing.expectEqual(ShredType.merkle_code, shredType(p.common.variant));
}
