//! Vexor DuplicateShred (CRDS type 9) — Tier-1 equivocation detection + proof build.
//!
//! CANONICAL: Agave 4.1.0-rc.1 (git 5efbb99), gossip/src/duplicate_shred.rs +
//! gossip/src/crds_gossip.rs (push_duplicate_shred) + ledger/src/shred.rs
//! (is_shred_duplicate). This is BANK_HASH-NEUTRAL: it reports leader
//! equivocation over gossip; it never touches block execution or bank state.
//!
//! Tier-1 = the simplest conflict variant: two shreds with the SAME
//! (slot, index, shred_type) — guaranteed by colliding at the same position in
//! the same FEC set — whose raw payloads DIFFER after the trailing retransmitter
//! signature is stripped (resigned variants only). Both shreds are already
//! leader-signature-verified at the FEC-resolver hook, so a payload conflict at
//! one position means the leader signed two different shreds for one slot/index
//! = equivocation.
//!
//! Wire format (see crds.zig DuplicateShred + this module's buildProof):
//!   CrdsData::DuplicateShred(DuplicateShredIndex /*u16*/, DuplicateShred)
//!   tag:u32(=9) | index:u16 | from:[32] | wallclock:u64 | slot:u64
//!   | _unused:u32(=0) | _unused_shred_type:u8(=90) | num_chunks:u8
//!   | chunk_index:u8 | chunk_len:u64 | chunk bytes
//!
//! DuplicateSlotProof inner payload (wincode == bincode legacy LE/fixint):
//!   [u64 LE len(shred1)][shred1 raw bytes][u64 LE len(shred2)][shred2 raw bytes]

const std = @import("std");
const crypto = @import("vex_crypto");
const crds = @import("crds.zig");

/// Re-export the crds module so a test rooting at this file (via a named module)
/// shares the SAME crds instance — avoids a duplicate-module type mismatch
/// between `dupshred`'s internal CrdsValue and a separately-imported one.
pub const crds_mod = crds;

/// Agave: PACKET_DATA_SIZE (1232) - 115. Max serialized size of each
/// DuplicateShred chunk-carrying value (protocol.rs:32).
pub const DUPLICATE_SHRED_MAX_PAYLOAD_SIZE: usize = 1232 - 115; // = 1117

/// Agave: DUPLICATE_SHRED_HEADER_SIZE (duplicate_shred.rs:21). Fixed overhead of
/// the per-chunk header that is subtracted from max_size to get chunk_size.
pub const DUPLICATE_SHRED_HEADER_SIZE: usize = 63;

/// chunk_size = max_size - header = 1117 - 63 = 1054 (duplicate_shred.rs:260-261).
pub const DUPLICATE_SHRED_CHUNK_SIZE: usize = DUPLICATE_SHRED_MAX_PAYLOAD_SIZE - DUPLICATE_SHRED_HEADER_SIZE; // = 1054

/// Agave: MAX_DUPLICATE_SHREDS (duplicate_shred.rs:24). The DuplicateShredIndex
/// (tuple u16) is taken mod this when assigning CRDS labels.
pub const MAX_DUPLICATE_SHREDS: u16 = 512;

pub const Error = error{
    /// The two payloads are identical (not a conflict).
    IdenticalPayloads,
    /// Serialized proof needs more than 255 chunks.
    TooManyChunks,
    OutOfMemory,
};

/// Strip the trailing retransmitter signature from a raw shred payload, mirroring
/// Agave `is_shred_duplicate`/`retransmitter_signature_offset`
/// (ledger/src/shred.rs:571 + shred/merkle.rs:454). Only RESIGNED merkle
/// variants carry a 64-byte retransmitter signature at the very end of the
/// payload; for every other variant the full payload is compared.
///
/// `resigned` must be read from the shred variant byte (shred.zig
/// parseVariantByte → variant.resigned). The retransmitter sig is the last 64
/// bytes for resigned shreds (matches shred.zig merkleRoot
/// `suffix_after_proof = if (v.resigned) 64 else 0`).
pub fn payloadForCompare(raw: []const u8, resigned: bool) []const u8 {
    if (resigned and raw.len >= 64) {
        return raw[0 .. raw.len - 64];
    }
    return raw;
}

/// Tier-1 conflict predicate. Both payloads are assumed to be the SAME
/// (slot, index, shred_type) (guaranteed by colliding at one FEC-set position).
/// Returns true iff the leader-signed bodies differ once the retransmitter
/// signature is stripped — i.e. a genuine equivocation, not a re-signed
/// retransmit of the same shred.
pub fn isConflict(raw1: []const u8, resigned1: bool, raw2: []const u8, resigned2: bool) bool {
    const a = payloadForCompare(raw1, resigned1);
    const b = payloadForCompare(raw2, resigned2);
    return !std.mem.eql(u8, a, b);
}

/// Serialize the DuplicateSlotProof inner payload (wincode/bincode-legacy):
///   [u64 LE len(shred1)][shred1][u64 LE len(shred2)][shred2]
/// Caller owns the returned slice.
pub fn serializeDuplicateSlotProof(allocator: std.mem.Allocator, shred1: []const u8, shred2: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    var len_buf: [8]u8 = undefined;

    std.mem.writeInt(u64, &len_buf, @as(u64, shred1.len), .little);
    try out.appendSlice(allocator, &len_buf);
    try out.appendSlice(allocator, shred1);

    std.mem.writeInt(u64, &len_buf, @as(u64, shred2.len), .little);
    try out.appendSlice(allocator, &len_buf);
    try out.appendSlice(allocator, shred2);

    return out.toOwnedSlice(allocator);
}

/// Round-trip helper for the KAT: parse [len1][raw1][len2][raw2] back to slices
/// into the supplied proof bytes. Returns the two sub-slices (no copy).
pub fn parseDuplicateSlotProof(proof: []const u8) !struct { shred1: []const u8, shred2: []const u8 } {
    if (proof.len < 8) return error.InvalidProof;
    const len1 = std.mem.readInt(u64, proof[0..8], .little);
    const off1: usize = 8;
    const end1 = off1 + @as(usize, @intCast(len1));
    if (end1 + 8 > proof.len) return error.InvalidProof;
    const shred1 = proof[off1..end1];
    const len2 = std.mem.readInt(u64, proof[end1..][0..8], .little);
    const off2 = end1 + 8;
    const end2 = off2 + @as(usize, @intCast(len2));
    if (end2 > proof.len) return error.InvalidProof;
    const shred2 = proof[off2..end2];
    return .{ .shred1 = shred1, .shred2 = shred2 };
}

/// A built, signed CRDS DuplicateShred value ready for the local crds table /
/// push batch. Owns its chunk bytes; caller frees via `deinit`.
pub const SignedChunk = struct {
    value: crds.CrdsValue,
    chunk: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SignedChunk) void {
        self.allocator.free(self.chunk);
    }
};

/// Build + sign all DuplicateShred CRDS chunks for one equivocation proof.
///
/// Mirrors Agave from_shred (duplicate_shred.rs:236) + crds_gossip
/// push_duplicate_shred chunk-label assignment (crds_gossip.rs:88). The caller
/// supplies:
///   - shred1_raw / shred2_raw: the two conflicting raw shred payloads,
///   - secret_key: Solana-format [seed(32)][pubkey(32)] for signing,
///   - self_pubkey: our node identity (the `from` field),
///   - wallclock / slot: gossip wallclock + the conflicting slot,
///   - index_offset: the starting DuplicateShredIndex (caller computes per
///     crds_gossip.rs:137 as the count of existing dup-shred records for this
///     node, or the oldest index when at MAX_DUPLICATE_SHREDS). KAT passes 0.
///
/// Each chunk k gets CrdsData.DuplicateShred(index, ds) with
///   index = (index_offset + k) % MAX_DUPLICATE_SHREDS,
/// is signed over bincode(CrdsData) (tag + tuple index + body), and returned in
/// chunk_index order. Caller owns + frees each SignedChunk.
pub fn buildSignedProofChunks(
    allocator: std.mem.Allocator,
    shred1_raw: []const u8,
    shred2_raw: []const u8,
    secret_key: [64]u8,
    self_pubkey: [32]u8,
    wallclock: u64,
    slot: u64,
    index_offset: u16,
) ![]SignedChunk {
    if (std.mem.eql(u8, shred1_raw, shred2_raw)) return error.IdenticalPayloads;

    const proof = try serializeDuplicateSlotProof(allocator, shred1_raw, shred2_raw);
    defer allocator.free(proof);

    // ceil(len / chunk_size), capped at u8::MAX (Agave u8::try_from).
    const chunk_size = DUPLICATE_SHRED_CHUNK_SIZE;
    const num_chunks_usize = (proof.len + chunk_size - 1) / chunk_size;
    if (num_chunks_usize == 0 or num_chunks_usize > 255) return error.TooManyChunks;
    const num_chunks: u8 = @intCast(num_chunks_usize);

    var chunks = try allocator.alloc(SignedChunk, num_chunks_usize);
    var built: usize = 0;
    errdefer {
        var j: usize = 0;
        while (j < built) : (j += 1) chunks[j].deinit();
        allocator.free(chunks);
    }

    var i: usize = 0;
    while (i < num_chunks_usize) : (i += 1) {
        const start = i * chunk_size;
        const end = @min(start + chunk_size, proof.len);
        const chunk_copy = try allocator.alloc(u8, end - start);
        @memcpy(chunk_copy, proof[start..end]);

        const index: u16 = @intCast((@as(u32, index_offset) + @as(u32, @intCast(i))) % @as(u32, MAX_DUPLICATE_SHREDS));

        const ds = crds.DuplicateShred{
            .index = index,
            .from = self_pubkey,
            .wallclock = wallclock,
            .slot = slot,
            ._unused = 0,
            ._unused_shred_type = crds.DuplicateShred.UNUSED_SHRED_TYPE_CODE,
            .num_chunks = num_chunks,
            .chunk_index = @intCast(i),
            .chunk = chunk_copy,
        };
        const data = crds.CrdsData{ .DuplicateShred = ds };

        // Sign over bincode(CrdsData) — tag(4) + index(2) + body. Buffer sized
        // for the fixed 57B header + a full max-size chunk plus slack.
        var sig_buf: [1500]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&sig_buf);
        data.serialize(fbs.writer()) catch {
            allocator.free(chunk_copy);
            return error.OutOfMemory;
        };
        const signed_bytes = fbs.getWritten();
        const sig = crypto.ed25519.sign(secret_key, signed_bytes);

        chunks[i] = SignedChunk{
            .value = crds.CrdsValue{ .signature = sig, .data = data },
            .chunk = chunk_copy,
            .allocator = allocator,
        };
        built += 1;
    }

    return chunks;
}

// ════════════════════════════════════════════════════════════════════════════
// CONFLICT QUEUE — bridge from the FEC resolver (detection) to gossip (push).
// ════════════════════════════════════════════════════════════════════════════

/// One detected equivocation, captured under fec_mutex during detection. Holds
/// OWNED copies of both raw payloads so the FecSet can free/recycle its buffers.
pub const Conflict = struct {
    slot: u64,
    index: u32,
    shred1: []u8,
    shred2: []u8,

    pub fn deinit(self: *Conflict, allocator: std.mem.Allocator) void {
        allocator.free(self.shred1);
        allocator.free(self.shred2);
    }
};

/// A tiny bounded FIFO of detected conflicts. Detection (always compiled) pushes
/// here under the resolver's existing fec_mutex; the gossip side (flag+env gated)
/// drains and turns them into signed CRDS pushes. Bounded so a pathological
/// stream of conflicts can never grow unbounded; overflow drops the newest
/// (the once-per-slot guard on the push side dedups anyway).
pub const ConflictQueue = struct {
    pub const CAPACITY: usize = 16;

    items: [CAPACITY]?Conflict = [_]?Conflict{null} ** CAPACITY,
    head: usize = 0,
    len: usize = 0,
    allocator: std.mem.Allocator,
    dropped: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) ConflictQueue {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ConflictQueue) void {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const idx = (self.head + i) % CAPACITY;
            if (self.items[idx]) |*c| c.deinit(self.allocator);
            self.items[idx] = null;
        }
        self.len = 0;
    }

    /// Push a conflict, taking OWNED copies of both payloads. Returns false (and
    /// frees nothing) if the queue is full.
    pub fn push(self: *ConflictQueue, slot: u64, index: u32, raw1: []const u8, raw2: []const u8) bool {
        if (self.len >= CAPACITY) {
            self.dropped += 1;
            return false;
        }
        const s1 = self.allocator.alloc(u8, raw1.len) catch {
            self.dropped += 1;
            return false;
        };
        const s2 = self.allocator.alloc(u8, raw2.len) catch {
            self.allocator.free(s1);
            self.dropped += 1;
            return false;
        };
        @memcpy(s1, raw1);
        @memcpy(s2, raw2);
        const slot_idx = (self.head + self.len) % CAPACITY;
        self.items[slot_idx] = Conflict{ .slot = slot, .index = index, .shred1 = s1, .shred2 = s2 };
        self.len += 1;
        return true;
    }

    /// Pop the oldest conflict (caller takes ownership of its payload slices and
    /// must call Conflict.deinit). Returns null when empty.
    pub fn pop(self: *ConflictQueue) ?Conflict {
        if (self.len == 0) return null;
        const c = self.items[self.head].?;
        self.items[self.head] = null;
        self.head = (self.head + 1) % CAPACITY;
        self.len -= 1;
        return c;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// TESTS — see tests/kat_duplicate_shred.zig for the full KAT suite. The detail
// asserts (byte layout, chunking, sign/verify) live there so the build target
// can root a single file with the crds module wired.
// ════════════════════════════════════════════════════════════════════════════

test "duplicate slot proof round-trips" {
    const a = std.testing.allocator;
    const s1 = [_]u8{ 1, 2, 3, 4, 5 };
    const s2 = [_]u8{ 9, 8, 7 };
    const proof = try serializeDuplicateSlotProof(a, &s1, &s2);
    defer a.free(proof);
    const parsed = try parseDuplicateSlotProof(proof);
    try std.testing.expectEqualSlices(u8, &s1, parsed.shred1);
    try std.testing.expectEqualSlices(u8, &s2, parsed.shred2);
}

test "isConflict strips retransmitter sig for resigned" {
    // Same body, differing only in the trailing 64-byte retransmitter sig: NOT a
    // conflict for resigned variants (stripped before compare).
    var a = [_]u8{0} ** 200;
    var b = [_]u8{0} ** 200;
    for (a[0..136], 0..) |*x, i| x.* = @intCast(i & 0xff);
    @memcpy(b[0..136], a[0..136]);
    // differ ONLY in the last 64 bytes (retransmitter sig region)
    for (a[136..200], 0..) |*x, i| x.* = @intCast(i & 0xff);
    for (b[136..200], 0..) |*x, i| x.* = @intCast((i + 1) & 0xff);
    try std.testing.expect(!isConflict(&a, true, &b, true)); // resigned: stripped → equal
    try std.testing.expect(isConflict(&a, false, &b, false)); // not resigned: full compare → differ
}
