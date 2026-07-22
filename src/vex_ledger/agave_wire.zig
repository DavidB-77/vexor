//! Byte-exact Agave 4.1.0-rc.1 blockstore metadata wire encoders/decoders.
//!
//! Per the operator byte-fidelity directive (2026-06-24): every metadata record
//! VexLedger exposes must byte-match Agave rc.1 — VALUES are **wincode 0.5.3**
//! (== bincode wire: LE fixed ints, BincodeLen length prefixes), CF KEYS are
//! BIG-ENDIAN. Every claim below is cited to an exact rc.1 file:line.
//! This module is pure + std-only so it is KAT-able in isolation
//! against the validation oracles (Index value = 8232 B, empty-next_slots meta =
//! 4197 B, merkle_root_meta = 6 B None / 38 B Some).
//!
//! Wincode primitives used here (DefaultConfig):
//!   u8..u64/i64  fixed width LITTLE-ENDIAN
//!   usize        u64 LE (8 B)
//!   bool         1 byte
//!   Option<T>    1-byte tag (0=None,1=Some) then T
//!   Vec<T>       u64 LE count then elements
//!   [u8;N]/Hash  N raw bytes, NO length prefix
//! Wrapper types that change the wire form:
//!   OptionCompat<u64>  bare u64 LE, None = u64::MAX, NO tag byte
//!   U32AsU64           a u32 serialized as u64 LE (8 B, zero-extended)
//!   BitVec<32768>      u64 LE count = 4096, then 4096 raw bytes (NEVER trimmed),
//!                      LSB-first: index i -> byte i/8, bit i&7
//!   DefaultOnEmptyRead writer ALWAYS emits the full value; reader defaults on EOF

const std = @import("std");

/// Agave MAX_DATA_SHREDS_PER_SLOT (shred.rs:125) → BitVec word count.
pub const MAX_DATA_SHREDS_PER_SLOT: usize = 32768;
pub const BITVEC_WORDS: usize = MAX_DATA_SHREDS_PER_SLOT / 8; // 4096 bytes, Word=u8.

/// ShredType wincode tag (shred.rs:238, #[wincode(tag_encoding="u8")]).
pub const SHRED_TYPE_DATA: u8 = 0xA5; // 165
pub const SHRED_TYPE_CODE: u8 = 0x5A; // 90

/// OptionCompat None sentinel (blockstore_meta.rs:195) — bare u64::MAX.
pub const OPTION_COMPAT_NONE: u64 = std.math.maxInt(u64);

pub const WireError = error{ Truncated, BadShredType, IndexTooLarge };

const Writer = std.ArrayListUnmanaged(u8);

// ── primitive appenders ─────────────────────────────────────────────────────

fn putU8(a: std.mem.Allocator, w: *Writer, v: u8) !void {
    try w.append(a, v);
}
fn putU32LE(a: std.mem.Allocator, w: *Writer, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try w.appendSlice(a, &b);
}
fn putU64LE(a: std.mem.Allocator, w: *Writer, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try w.appendSlice(a, &b);
}
fn putI64LE(a: std.mem.Allocator, w: *Writer, v: i64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(i64, &b, v, .little);
    try w.appendSlice(a, &b);
}

/// OptionCompat<u64>: bare u64 LE, None encoded as u64::MAX (NO tag byte).
fn putOptionCompat(a: std.mem.Allocator, w: *Writer, v: ?u64) !void {
    try putU64LE(a, w, v orelse OPTION_COMPAT_NONE);
}

/// BitVec<32768>: u64 LE count=4096 then 4096 raw bytes (never trimmed), bits
/// set LSB-first for each index. Indices must be < 32768.
fn putBitVec(a: std.mem.Allocator, w: *Writer, indices: []const u32) !void {
    var words = [_]u8{0} ** BITVEC_WORDS;
    for (indices) |idx| {
        if (idx >= MAX_DATA_SHREDS_PER_SLOT) return WireError.IndexTooLarge;
        words[idx / 8] |= (@as(u8, 1) << @intCast(idx & 7));
    }
    try putU64LE(a, w, BITVEC_WORDS); // 4096
    try w.appendSlice(a, &words);
}

// ── primitive readers (cursor-based) ────────────────────────────────────────

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, n: usize) ![]const u8 {
        if (self.pos + n > self.buf.len) return WireError.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
    /// Bytes left to read. Used for preallocation-safety: NEVER allocate a
    /// length-prefixed collection sized by an untrusted count without first
    /// proving the buffer actually holds that many element bytes (wincode's
    /// stricter deserialize rejects oversized dynamic structures — a corrupt or
    /// hostile count must error, not trigger a huge speculative allocation).
    fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }
    fn u32LE(self: *Reader) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn u64LE(self: *Reader) !u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
    fn i64LE(self: *Reader) !i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .little);
    }
    fn optionCompat(self: *Reader) !?u64 {
        const v = try self.u64LE();
        return if (v == OPTION_COMPAT_NONE) null else v;
    }
    /// Read a BitVec → owned ascending list of set indices. Tolerates any stored
    /// length (Agave resizes to 4096), scanning min(stored, 4096) bytes.
    fn bitVec(self: *Reader, a: std.mem.Allocator) ![]u32 {
        const count: usize = @intCast(try self.u64LE());
        const bytes = try self.take(count);
        var out = std.ArrayListUnmanaged(u32){};
        errdefer out.deinit(a);
        const scan = @min(count, BITVEC_WORDS);
        var byte_i: usize = 0;
        while (byte_i < scan) : (byte_i += 1) {
            var bit: u3 = 0;
            while (true) : (bit += 1) {
                if ((bytes[byte_i] & (@as(u8, 1) << bit)) != 0) {
                    try out.append(a, @intCast(byte_i * 8 + bit));
                }
                if (bit == 7) break;
            }
        }
        return out.toOwnedSlice(a);
    }
};

// ── ErasureMeta (CF erasure_meta, value = 40 B) ─────────────────────────────

pub const ErasureMeta = struct {
    fec_set_index: u32, // serialized U32AsU64 → u64 LE
    first_coding_index: u64,
    first_received_coding_index: u64,
    num_data: u64, // usize → u64 LE
    num_coding: u64, // usize → u64 LE

    pub fn encode(self: ErasureMeta, a: std.mem.Allocator) ![]u8 {
        var w = Writer{};
        errdefer w.deinit(a);
        try putU64LE(a, &w, self.fec_set_index); // U32AsU64
        try putU64LE(a, &w, self.first_coding_index);
        try putU64LE(a, &w, self.first_received_coding_index);
        try putU64LE(a, &w, self.num_data);
        try putU64LE(a, &w, self.num_coding);
        return w.toOwnedSlice(a);
    }
    pub fn decode(buf: []const u8) !ErasureMeta {
        var r = Reader{ .buf = buf };
        const fec = try r.u64LE();
        return .{
            .fec_set_index = @intCast(fec),
            .first_coding_index = try r.u64LE(),
            .first_received_coding_index = try r.u64LE(),
            .num_data = try r.u64LE(),
            .num_coding = try r.u64LE(),
        };
    }
};

// ── MerkleRootMeta (CF merkle_root_meta, value = 6 B None / 38 B Some) ───────

pub const MerkleRootMeta = struct {
    merkle_root: ?[32]u8,
    first_received_shred_index: u32,
    first_received_shred_type: u8, // 0xA5 data / 0x5A code

    pub fn encode(self: MerkleRootMeta, a: std.mem.Allocator) ![]u8 {
        var w = Writer{};
        errdefer w.deinit(a);
        if (self.merkle_root) |h| {
            try putU8(a, &w, 1); // Option Some tag
            try w.appendSlice(a, &h); // 32 raw
        } else {
            try putU8(a, &w, 0); // Option None tag
        }
        try putU32LE(a, &w, self.first_received_shred_index);
        try putU8(a, &w, self.first_received_shred_type);
        return w.toOwnedSlice(a);
    }
    pub fn decode(buf: []const u8) !MerkleRootMeta {
        var r = Reader{ .buf = buf };
        const tag = (try r.take(1))[0];
        var root: ?[32]u8 = null;
        if (tag == 1) {
            var h: [32]u8 = undefined;
            @memcpy(&h, try r.take(32));
            root = h;
        }
        const idx = try r.u32LE();
        const st = (try r.take(1))[0];
        if (st != SHRED_TYPE_DATA and st != SHRED_TYPE_CODE) return WireError.BadShredType;
        return .{ .merkle_root = root, .first_received_shred_index = idx, .first_received_shred_type = st };
    }
};

// ── ShredIndex (4112 B) + Index (CF index, value = 8232 B) ──────────────────

/// Encode one ShredIndex = BitVec(4104) + num_shreds usize→u64 (8) = 4112 B.
fn putShredIndex(a: std.mem.Allocator, w: *Writer, indices: []const u32) !void {
    try putBitVec(a, w, indices);
    try putU64LE(a, w, @intCast(indices.len)); // num_shreds (stored count)
}

/// Encode the full Index CF value: slot u64 LE + data ShredIndex + coding
/// ShredIndex = 8 + 4112 + 4112 = 8232 B. (VexLedger derives this on demand from
/// its per-slot lists; it is not persisted.)
pub fn encodeIndex(a: std.mem.Allocator, slot: u64, data_indices: []const u32, coding_indices: []const u32) ![]u8 {
    var w = Writer{};
    errdefer w.deinit(a);
    try putU64LE(a, &w, slot);
    try putShredIndex(a, &w, data_indices);
    try putShredIndex(a, &w, coding_indices);
    return w.toOwnedSlice(a);
}

// ── SlotMetaV3 (CF meta, value = 4197 B with empty next_slots) ──────────────

pub const SlotMetaV3 = struct {
    slot: u64,
    consumed: u64,
    received: u64,
    first_shred_timestamp: u64,
    last_index: ?u64, // OptionCompat
    parent_slot: ?u64, // OptionCompat
    next_slots: []const u64 = &.{},
    connected_flags: u8 = 0,
    completed_data_indexes: []const u32 = &.{}, // BitVec
    parent_block_id: [32]u8 = [_]u8{0} ** 32, // DefaultOnEmptyRead, always emitted
    replay_fec_set_index: u32 = 0, // DefaultOnEmptyRead, always emitted

    pub fn encode(self: SlotMetaV3, a: std.mem.Allocator) ![]u8 {
        var w = Writer{};
        errdefer w.deinit(a);
        try putU64LE(a, &w, self.slot);
        try putU64LE(a, &w, self.consumed);
        try putU64LE(a, &w, self.received);
        try putU64LE(a, &w, self.first_shred_timestamp);
        try putOptionCompat(a, &w, self.last_index);
        try putOptionCompat(a, &w, self.parent_slot);
        try putU64LE(a, &w, @intCast(self.next_slots.len)); // Vec<u64> count
        for (self.next_slots) |s| try putU64LE(a, &w, s);
        try putU8(a, &w, self.connected_flags);
        try putBitVec(a, &w, self.completed_data_indexes);
        try w.appendSlice(a, &self.parent_block_id); // always (writer side)
        try putU32LE(a, &w, self.replay_fec_set_index); // always
        return w.toOwnedSlice(a);
    }

    /// Decode. `next_slots` + `completed_data_indexes` are owned slices the caller
    /// frees (via `freeDecoded`). The trailing parent_block_id+replay_fec_set_index
    /// default to zero if absent (DefaultOnEmptyRead reader tolerance).
    pub fn decode(a: std.mem.Allocator, buf: []const u8) !SlotMetaV3 {
        var r = Reader{ .buf = buf };
        const slot = try r.u64LE();
        const consumed = try r.u64LE();
        const received = try r.u64LE();
        const fst = try r.u64LE();
        const last_index = try r.optionCompat();
        const parent_slot = try r.optionCompat();
        const n_next: usize = @intCast(try r.u64LE());
        // Preallocation safety: reject a count that can't fit in the remaining
        // bytes (8 per u64) BEFORE allocating — a corrupt/oversized len-prefix must
        // error, never trigger a huge speculative alloc (wincode read-strictness).
        if (n_next > r.remaining() / 8) return WireError.Truncated;
        const next = try a.alloc(u64, n_next);
        errdefer a.free(next);
        for (next) |*s| s.* = try r.u64LE();
        const flags = (try r.take(1))[0];
        const cdi = try r.bitVec(a);
        errdefer a.free(cdi);
        // DefaultOnEmptyRead: parent_block_id (32) + replay_fec_set_index (4).
        var pbid = [_]u8{0} ** 32;
        var rfsi: u32 = 0;
        if (r.pos + 36 <= buf.len) {
            @memcpy(&pbid, try r.take(32));
            rfsi = try r.u32LE();
        }
        return .{
            .slot = slot,
            .consumed = consumed,
            .received = received,
            .first_shred_timestamp = fst,
            .last_index = last_index,
            .parent_slot = parent_slot,
            .next_slots = next,
            .connected_flags = flags,
            .completed_data_indexes = cdi,
            .parent_block_id = pbid,
            .replay_fec_set_index = rfsi,
        };
    }

    pub fn freeDecoded(self: SlotMetaV3, a: std.mem.Allocator) void {
        if (self.next_slots.len != 0) a.free(self.next_slots);
        if (self.completed_data_indexes.len != 0) a.free(self.completed_data_indexes);
    }
};

// ── bank_hashes CF value: FrozenHashVersioned (wincode, EXACTLY 37 bytes) ────
//
// Agave rc.1 `bank_hashes` CF (column.rs:675 NAME="bank_hashes", SlotColumn → BE
// u64 key) stores `FrozenHashVersioned::Current(FrozenHashStatus{ frozen_hash:
// Hash[32], is_duplicate_confirmed: bool })` via **wincode** DefaultConfig
// (LittleEndian / FixInt / u32 tag). Layout — 37 bytes, NO trailing padding (the
// CF read path is `deserialize_reject_trailing`, so a longer buffer FAILS Agave):
//   [0..4)  enum tag u32 LE = 0 (the only variant, `Current`)
//   [4..36) frozen_hash — 32 raw bytes (fixed array, no length prefix)
//   [36]    is_duplicate_confirmed — 1 byte (0=false, 1=true)
pub const FROZEN_HASH_LEN: usize = 37;
pub const FROZEN_HASH_CURRENT_TAG: u32 = 0;

pub const FrozenHash = struct {
    frozen_hash: [32]u8,
    is_duplicate_confirmed: bool,
};

/// Encode the `bank_hashes` CF value into `out` (exactly FROZEN_HASH_LEN bytes).
pub fn encodeFrozenHash(out: *[FROZEN_HASH_LEN]u8, frozen_hash: [32]u8, is_duplicate_confirmed: bool) void {
    std.mem.writeInt(u32, out[0..4], FROZEN_HASH_CURRENT_TAG, .little);
    @memcpy(out[4..36], &frozen_hash);
    out[36] = if (is_duplicate_confirmed) 1 else 0;
}

/// Decode the `bank_hashes` CF value. Strict: rejects any length != 37 (matches
/// Agave's reject-trailing read), an unknown enum tag, or a non-0/1 bool byte.
pub fn decodeFrozenHash(buf: []const u8) WireError!FrozenHash {
    if (buf.len != FROZEN_HASH_LEN) return WireError.Truncated;
    if (std.mem.readInt(u32, buf[0..4], .little) != FROZEN_HASH_CURRENT_TAG) return WireError.BadShredType;
    if (buf[36] > 1) return WireError.BadShredType; // wincode bool read rejects >1
    var fh: [32]u8 = undefined;
    @memcpy(&fh, buf[4..36]);
    return .{ .frozen_hash = fh, .is_duplicate_confirmed = buf[36] == 1 };
}

// ── KATs: validate FRAMING (oracle lengths) AND bit-packing (content) ────────

test "ErasureMeta = 40 B + round-trip" {
    const a = std.testing.allocator;
    const em: ErasureMeta = .{ .fec_set_index = 96, .first_coding_index = 100, .first_received_coding_index = 103, .num_data = 32, .num_coding = 32 };
    const b = try em.encode(a);
    defer a.free(b);
    try std.testing.expectEqual(@as(usize, 40), b.len); // oracle
    // fec_set_index is U32AsU64 → first 8 bytes = 96 LE.
    try std.testing.expectEqual(@as(u64, 96), std.mem.readInt(u64, b[0..8], .little));
    const got = try ErasureMeta.decode(b);
    try std.testing.expectEqual(em, got);
}

test "MerkleRootMeta = 6 B (None) / 38 B (Some) + ShredType byte" {
    const a = std.testing.allocator;
    const none: MerkleRootMeta = .{ .merkle_root = null, .first_received_shred_index = 7, .first_received_shred_type = SHRED_TYPE_DATA };
    const bn = try none.encode(a);
    defer a.free(bn);
    try std.testing.expectEqual(@as(usize, 6), bn.len); // oracle None
    try std.testing.expectEqual(@as(u8, 0), bn[0]); // Option None tag
    try std.testing.expectEqual(@as(u8, SHRED_TYPE_DATA), bn[bn.len - 1]); // 0xA5

    var h: [32]u8 = undefined;
    for (&h, 0..) |*x, i| x.* = @intCast(i);
    const some: MerkleRootMeta = .{ .merkle_root = h, .first_received_shred_index = 9, .first_received_shred_type = SHRED_TYPE_CODE };
    const bs = try some.encode(a);
    defer a.free(bs);
    try std.testing.expectEqual(@as(usize, 38), bs.len); // oracle Some
    try std.testing.expectEqual(@as(u8, 1), bs[0]); // Option Some tag
    try std.testing.expectEqual(@as(u8, SHRED_TYPE_CODE), bs[bs.len - 1]); // 0x5A
    const got = try MerkleRootMeta.decode(bs);
    try std.testing.expectEqualSlices(u8, &h, &got.merkle_root.?);
    try std.testing.expectEqual(@as(u32, 9), got.first_received_shred_index);
}

test "Index = 8232 B + LSB-first BitVec content + independent num_shreds" {
    const a = std.testing.allocator;
    // data {0,7,8} (LSB-first: words[0]=0x81, words[1]=0x01), coding {1}.
    const b = try encodeIndex(a, 424242, &[_]u32{ 0, 7, 8 }, &[_]u32{1});
    defer a.free(b);
    try std.testing.expectEqual(@as(usize, 8232), b.len); // oracle (8 + 4112 + 4112)
    try std.testing.expectEqual(@as(u64, 424242), std.mem.readInt(u64, b[0..8], .little));
    // data ShredIndex starts at 8: u64 count=4096, then words. word0@16, word1@17.
    try std.testing.expectEqual(@as(u64, BITVEC_WORDS), std.mem.readInt(u64, b[8..16], .little));
    try std.testing.expectEqual(@as(u8, 0x81), b[16]); // bit0 | bit7  ← proves LSB-first
    try std.testing.expectEqual(@as(u8, 0x01), b[17]); // bit8 = byte1 bit0
    // data num_shreds (offset 8 + 4104) = 3 (independent popcount of data type).
    try std.testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, b[8 + 4104 ..][0..8], .little));
    // coding ShredIndex starts at 8+4112=4120; its word0 (offset 4120+8=4128) = 0x02 (bit1).
    try std.testing.expectEqual(@as(u8, 0x02), b[4128]);
    // coding num_shreds (offset 8 + 4112 + 4104) = 1 (separate counter).
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, b[8 + 4112 + 4104 ..][0..8], .little));
}

test "SlotMetaV3 = 4197 B (empty next_slots) + OptionCompat + content round-trip" {
    const a = std.testing.allocator;
    const m: SlotMetaV3 = .{
        .slot = 500,
        .consumed = 64,
        .received = 64,
        .first_shred_timestamp = 123,
        .last_index = 63, // OptionCompat Some
        .parent_slot = 499,
        .next_slots = &.{},
        .connected_flags = 3,
        .completed_data_indexes = &[_]u32{ 0, 7, 8 },
        .parent_block_id = [_]u8{0} ** 32,
        .replay_fec_set_index = 0,
    };
    const b = try m.encode(a);
    defer a.free(b);
    try std.testing.expectEqual(@as(usize, 4197), b.len); // oracle (empty next_slots)
    // last_index OptionCompat Some=63 at offset 32 (after slot/consumed/received/fst).
    try std.testing.expectEqual(@as(u64, 63), std.mem.readInt(u64, b[32..40], .little));
    // parent_slot at offset 40.
    try std.testing.expectEqual(@as(u64, 499), std.mem.readInt(u64, b[40..48], .little));
    // completed_data_indexes BitVec LSB-first: count(8) at 49 (after next_slots u64=0 @48 + flags @56?).
    // layout: 48=next_slots count(8)→56, 56=connected_flags(1)→57, 57=BitVec count(8)→65, 65=word0.
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, b[48..56], .little)); // next_slots empty
    try std.testing.expectEqual(@as(u8, 3), b[56]); // connected_flags
    try std.testing.expectEqual(@as(u64, BITVEC_WORDS), std.mem.readInt(u64, b[57..65], .little));
    try std.testing.expectEqual(@as(u8, 0x81), b[65]); // completed {0,7} word0 LSB-first
    try std.testing.expectEqual(@as(u8, 0x01), b[66]); // {8} word1

    const got = try SlotMetaV3.decode(a, b);
    defer got.freeDecoded(a);
    try std.testing.expectEqual(@as(?u64, 63), got.last_index);
    try std.testing.expectEqual(@as(?u64, 499), got.parent_slot);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0, 7, 8 }, got.completed_data_indexes);
    try std.testing.expectEqual(@as(u8, 3), got.connected_flags);
}

test "SlotMetaV3 OptionCompat None = u64::MAX + next_slots Vec" {
    const a = std.testing.allocator;
    const m: SlotMetaV3 = .{
        .slot = 1,
        .consumed = 0,
        .received = 0,
        .first_shred_timestamp = 0,
        .last_index = null, // None → u64::MAX, NO tag
        .parent_slot = null,
        .next_slots = &[_]u64{ 2, 3 },
    };
    const b = try m.encode(a);
    defer a.free(b);
    try std.testing.expectEqual(@as(usize, 4197 + 16), b.len); // +2 next_slots × 8
    try std.testing.expectEqual(OPTION_COMPAT_NONE, std.mem.readInt(u64, b[32..40], .little)); // last_index None
    try std.testing.expectEqual(OPTION_COMPAT_NONE, std.mem.readInt(u64, b[40..48], .little)); // parent None
    try std.testing.expectEqual(@as(u64, 2), std.mem.readInt(u64, b[48..56], .little)); // next_slots count
    const got = try SlotMetaV3.decode(a, b);
    defer got.freeDecoded(a);
    try std.testing.expect(got.last_index == null);
    try std.testing.expect(got.parent_slot == null);
    try std.testing.expectEqualSlices(u64, &[_]u64{ 2, 3 }, got.next_slots);
}

test "read-strictness: oversized next_slots count is REJECTED, not over-allocated" {
    const a = std.testing.allocator;
    // Build a minimal SlotMetaV3 prefix then a BOGUS huge next_slots count.
    var w = std.ArrayListUnmanaged(u8){};
    defer w.deinit(a);
    try putU64LE(a, &w, 1); // slot
    try putU64LE(a, &w, 0); // consumed
    try putU64LE(a, &w, 0); // received
    try putU64LE(a, &w, 0); // first_shred_timestamp
    try putU64LE(a, &w, OPTION_COMPAT_NONE); // last_index
    try putU64LE(a, &w, OPTION_COMPAT_NONE); // parent_slot
    try putU64LE(a, &w, 0xFFFF_FFFF_FFFF_FFFF); // next_slots count = u64::MAX (hostile)
    // (no element bytes follow — a correct reader must reject on the count, not
    //  attempt to allocate 2^64 u64s.)
    const r = SlotMetaV3.decode(a, w.items);
    try std.testing.expectError(WireError.Truncated, r);
}

test "FrozenHashVersioned bank_hashes value = 37 B wincode + round-trip + strictness" {
    // Minted golden (rc.1 ships no byte vector): tag(0 LE) + 32 hash + bool.
    var hash: [32]u8 = undefined;
    for (&hash, 0..) |*b, i| b.* = @intCast((i * 9 + 5) & 0xff);
    var out: [FROZEN_HASH_LEN]u8 = undefined;
    encodeFrozenHash(&out, hash, true);
    try std.testing.expectEqual(@as(usize, 37), out.len); // oracle: NO trailing bytes
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, out[0..4], .little)); // Current tag
    try std.testing.expectEqualSlices(u8, &hash, out[4..36]);
    try std.testing.expectEqual(@as(u8, 1), out[36]);

    const back = try decodeFrozenHash(&out);
    try std.testing.expectEqualSlices(u8, &hash, &back.frozen_hash);
    try std.testing.expectEqual(true, back.is_duplicate_confirmed);

    // is_duplicate_confirmed=false → byte 36 == 0.
    encodeFrozenHash(&out, hash, false);
    try std.testing.expectEqual(@as(u8, 0), out[36]);
    try std.testing.expectEqual(false, (try decodeFrozenHash(&out)).is_duplicate_confirmed);

    // Strictness: wrong length, unknown tag, and a non-0/1 bool all rejected.
    try std.testing.expectError(WireError.Truncated, decodeFrozenHash(out[0..36]));
    var bad = out;
    std.mem.writeInt(u32, bad[0..4], 1, .little); // unknown variant
    try std.testing.expectError(WireError.BadShredType, decodeFrozenHash(&bad));
    bad = out;
    bad[36] = 2; // illegal bool
    try std.testing.expectError(WireError.BadShredType, decodeFrozenHash(&bad));
}
