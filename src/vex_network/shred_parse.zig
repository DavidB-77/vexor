//! Vexor shred wire-format layer (SPLIT module 57, from `shred.zig`).
//!
//! Wire-format parsing/typing for a single shred: variant-byte decoding,
//! common-header layout, Merkle root reconstruction (20-byte and 32-byte
//! canonical forms), chained_merkle_root extraction, and signature
//! verification. This is the "TWO independent top-level structs" half of
//! the original monolith identified by the module-56 §J scout — `ShredType`/
//! `ShredVariant`/`ShredCommonHeader`/`Shred` (plus the free functions
//! `isUnexpectedDataComplete`/`parseShred`) never reference `ShredAssembler`,
//! which is why this is a clean move-only carve (contrast with the
//! `tvu.zig`/`bank.zig`-class monolith wall) — see `shred_assembler.zig` for
//! the other half. See REBUILD-LEDGER.md module 57 for the full split
//! rationale, fidelity proof, and per-file md5s.
const std = @import("std");
const core = @import("core");
const crypto = @import("vex_crypto");
const fec_resolver = @import("fec_resolver.zig");
const bmtree = @import("bmtree.zig");

pub const SHRED_PAYLOAD_SIZE: usize = 1228;
pub const SHRED_HEADER_SIZE: usize = 88;

pub const ShredType = enum(u8) {
    data = 0b1010_0101,
    code = 0b0101_1010,
    pub fn isData(self: ShredType) bool {
        return self == .data;
    }
};

/// Parsed variant byte with Merkle V2 metadata.
/// Unifies with fec_resolver.parseVariantByte for consistent interpretation.
pub const ShredVariant = struct {
    is_data: bool,
    is_merkle: bool,
    proof_size: u8,
    chained: bool,
    resigned: bool,

    pub fn fromByte(variant: u8) ShredVariant {
        const parsed = fec_resolver.parseVariantByte(variant);
        const high_nibble = variant & 0xF0;

        // Determine chained/resigned from high nibble
        const chained = switch (high_nibble) {
            0x60, 0x70, 0x90, 0xB0 => true, // chained code/data variants
            else => false,
        };
        const resigned = switch (high_nibble) {
            0x70, 0xB0 => true, // resigned variants
            else => false,
        };

        return .{
            .is_data = parsed.is_data,
            .is_merkle = parsed.is_merkle,
            .proof_size = parsed.proof_size,
            .chained = chained,
            .resigned = resigned,
        };
    }
};

pub const ShredCommonHeader = struct {
    signature: core.Signature,
    variant_byte: u8,
    variant: ShredVariant,
    shred_type: ShredType,
    slot: core.Slot,
    index: u32,
    version: u16,
    fec_set_index: u32,
    parent_offset: u16,

    pub fn fromBytes(data: []const u8) !ShredCommonHeader {
        if (data.len < 83) return error.ShredTooShort;
        var sig: core.Signature = .{ .data = [_]u8{0} ** 64 };
        @memcpy(&sig.data, data[0..64]);

        const variant_byte = data[64];
        const variant = ShredVariant.fromByte(variant_byte);

        // Data shreds carry two more bytes (parent_offset, [83..85)) than code
        // shreds. The `data.len < 83` floor above is only sufficient for a code
        // shred (fields end at byte 83); a data-shred buffer of exactly 83 or 84
        // bytes passed that check but then read `data[83..85]` out of bounds —
        // found by fuzz/fuzz_shred_parse.zig (index out of bounds, not caught as
        // a parse error). Widen the floor to 85 whenever the variant is data.
        if (variant.is_data and data.len < 85) return error.ShredTooShort;

        return ShredCommonHeader{
            .signature = sig,
            .variant_byte = variant_byte,
            .variant = variant,
            .shred_type = if (variant.is_data) .data else .code,
            .slot = std.mem.readInt(u64, data[65..73], .little),
            .index = std.mem.readInt(u32, data[73..77], .little),
            .version = std.mem.readInt(u16, data[77..79], .little),
            .fec_set_index = std.mem.readInt(u32, data[79..83], .little),
            .parent_offset = if (variant.is_data) std.mem.readInt(u16, data[83..85], .little) else 0,
        };
    }
};

pub const Shred = struct {
    common: ShredCommonHeader,
    payload: []const u8,

    pub fn slot(self: *const Shred) core.Slot {
        return self.common.slot;
    }

    pub fn index(self: *const Shred) u32 {
        return self.common.index;
    }

    pub fn isData(self: *const Shred) bool {
        return self.common.shred_type == .data;
    }

    pub fn parentOffset(self: *const Shred) u16 {
        return self.common.parent_offset;
    }

    pub fn rawData(self: *const Shred) []const u8 {
        return self.payload;
    }

    pub fn dataSize(self: *const Shred) u16 {
        if (!self.isData()) return 0;
        if (self.payload.len < 88) return 0;
        return std.mem.readInt(u16, self.payload[86..88], .little);
    }

    pub fn numData(self: *const Shred) u16 {
        if (self.isData()) return 0;
        if (self.payload.len < 85) return 0;
        return std.mem.readInt(u16, self.payload[83..85], .little);
    }

    pub fn numCoding(self: *const Shred) u16 {
        if (self.isData()) return 0;
        if (self.payload.len < 87) return 0;
        return std.mem.readInt(u16, self.payload[85..87], .little);
    }

    pub fn codingPosition(self: *const Shred) u16 {
        if (self.isData()) return 0;
        if (self.payload.len < 89) return 0;
        return std.mem.readInt(u16, self.payload[87..89], .little);
    }

    pub fn fecSetIndex(self: *const Shred) u32 {
        return self.common.fec_set_index;
    }

    pub fn version(self: *const Shred) u16 {
        return self.common.version;
    }

    pub fn fromPayload(payload: []const u8) !Shred {
        const common = try ShredCommonHeader.fromBytes(payload);
        return Shred{
            .common = common,
            .payload = payload,
        };
    }

    pub fn isLastInSlot(self: *const Shred) bool {
        if (!self.isData()) return false;
        if (self.payload.len <= 85) return false;
        // Data Shred flags are at offset 85.
        // Solana's LAST_SHRED_IN_SLOT is 0b1100_0000 (0xC0).
        // It requires both the DATA_COMPLETE (0x40) and LAST_IN_SLOT (0x80) bits.
        return (self.payload[85] & 0xC0) == 0xC0;
    }

    /// SIMD-0337 (discard_unexpected_data_complete_shreds): the DATA_COMPLETE
    /// flag is bit 0x40 of the data-shred flags byte (offset 85). Agave
    /// `ShredFlags::DATA_COMPLETE_SHRED`. This is BROADER than isLastInSlot:
    /// it is true for both the last-in-slot shred (flags 0xC0 = 0x40|0x80) AND
    /// for a mid-slot FEC-batch-complete shred (flags 0x40 alone). Coding
    /// shreds are never DATA_COMPLETE (guarded by isData → returns false).
    pub fn isDataComplete(self: *const Shred) bool {
        if (!self.isData()) return false;
        if (self.payload.len <= 85) return false;
        return (self.payload[85] & 0x40) != 0;
    }

    /// Returns the proof_size from the Merkle V2 variant.
    pub fn proofSize(self: *const Shred) u8 {
        return self.common.variant.proof_size;
    }

    /// Returns whether this is a Merkle shred (as opposed to legacy).
    pub fn isMerkle(self: *const Shred) bool {
        return self.common.variant.is_merkle;
    }

    pub fn deinit(self: *const Shred, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }

    /// Compute the Merkle root from the proof nodes embedded in the shred.
    /// Returns null if the shred is not a Merkle shred or the payload is too short.
    ///
    /// d27mm-FIX (2026-05-12): Layout corrected per Agave 4.0.0-beta.7 canonical
    /// (agave-4.0/ledger/src/shred/merkle.rs:181-201, get_proof_offset at :336):
    ///   [signature 64B]
    ///   [common_header 24B + data_or_coding_header (5B or 6B)]   = SIZE_OF_HEADERS
    ///   [entry data — `capacity(proof_size, resigned)` bytes]
    ///   [chained_merkle_root 32B] ← ONLY for chained variants — INSIDE leaf scope
    ///   [merkle proof — proof_size × 20B]
    ///   [retransmitter_sig 64B] ← ONLY for resigned variants — AFTER proof
    ///
    /// The PRIOR Vexor code mistakenly placed chained_merkle_root AFTER the proof
    /// (between proof and retransmitter_sig), causing proof_start to be off by
    /// 32 bytes for every chained shred. Each shred's "proof" then read a mix of
    /// (chained_root_tail + actual_proof_head), producing 32 different "roots"
    /// for shreds that share one canonical root. Empirically: slot 407,803,808
    /// fec_set 352, 32 shreds with identical variant byte 0xb6 (proof=6,
    /// chained+resigned+data), payload 1203B each — all returned distinct roots
    /// under the buggy logic; verified live in cluster.
    ///
    /// Cross-validation: Agave's `get_merkle_node(shred, 64..proof_offset)`
    /// hashes the prefix INCLUDING chained_merkle_root as the leaf — same scope
    /// we use here once proof_start is corrected.
    pub fn merkleRoot(self: *const Shred) ?[bmtree.MERKLE_NODE_SIZE]u8 {
        const v = self.common.variant;
        if (!v.is_merkle) return null;
        if (v.proof_size == 0) return null;

        const payload = self.payload;
        const proof_bytes: usize = @as(usize, v.proof_size) * bmtree.MERKLE_NODE_SIZE;

        // d27mm-FIX: only `retransmitter_sig` lives AFTER the proof. The
        // chained_merkle_root sits BEFORE the proof (inside the leaf scope).
        // Per Agave merkle.rs:capacity / get_proof_offset.
        const suffix_after_proof: usize = if (v.resigned) @as(usize, 64) else @as(usize, 0);

        if (payload.len < suffix_after_proof + proof_bytes) return null;
        const proof_end = payload.len - suffix_after_proof;
        const proof_start = proof_end - proof_bytes;

        // The leaf data is everything from the variant byte (offset 64) up to
        // the proof start. For chained variants this includes the 32-byte
        // chained_merkle_root sitting immediately before the proof — that is
        // intentional and matches Agave's `get_merkle_node(shred, 64..proof_offset)`.
        const header_size: usize = if (v.is_data) SHRED_HEADER_SIZE else 89; // data: 88, code: 89
        if (proof_start < header_size) return null;

        // Hash the leaf scope as the merkle leaf (truncated to 20 bytes per
        // SIZE_OF_MERKLE_PROOF_ENTRY).
        const erasure_shard = payload[64..proof_start];
        const leaf_hash = bmtree.MerkleTree.hashMerkleLeaf(erasure_shard);

        // The shred's index within the FEC set (0..N for data shreds, then
        // continuing for coding shreds — matches Agave's index calc).
        const fec_set_idx = self.common.fec_set_index;
        // CODING-LEAF FIX (2026-06-15): a coding shred's erasure-batch leaf index is
        // numData()+codingPosition() (a SEPARATE coding index space), NOT
        // index-fec_set_index (the DATA formula). Verified canonical vs Agave
        // merkle.rs:248-259 / shred_code.rs:30 and Firedancer fd_fec_resolver.c:638-639.
        // The old single formula gave coding shreds a wrong leaf -> wrong root -> they
        // failed sig-verify and were dropped (degraded FEC recovery).
        const shred_idx_in_fec: usize = if (self.isData())
            (if (self.common.index >= fec_set_idx) @as(usize, self.common.index - fec_set_idx) else 0)
        else
            @as(usize, self.numData()) + @as(usize, self.codingPosition());

        // Walk the proof upward to reconstruct the root. Algorithm matches
        // agave-4.0/ledger/src/shred/merkle_tree.rs:108 get_merkle_root.
        const proof_nodes = payload[proof_start..proof_end];
        return bmtree.MerkleTree.reconstructRoot(leaf_hash, proof_nodes, shred_idx_in_fec);
    }

    /// SIMD-0340 (d28ll): full 32-byte merkle root — Agave canonical
    /// `Hash` width used by `check_chained_block_id`. Same algorithm as
    /// `merkleRoot()` but feeds a 32-byte leaf into `reconstructRootFull`
    /// and returns the LAST `current_hash` (32 bytes, untruncated) instead
    /// of the 20-byte proof-node form. Required because Agave stores +
    /// compares 32-byte hashes; comparing Vexor's 20-byte form would fail
    /// any byte-exact match.
    pub fn merkleRoot32(self: *const Shred) ?[32]u8 {
        const v = self.common.variant;
        if (!v.is_merkle) return null;
        if (v.proof_size == 0) return null;

        const payload = self.payload;
        const proof_bytes: usize = @as(usize, v.proof_size) * bmtree.MERKLE_NODE_SIZE;
        const suffix_after_proof: usize = if (v.resigned) @as(usize, 64) else @as(usize, 0);
        if (payload.len < suffix_after_proof + proof_bytes) return null;
        const proof_end = payload.len - suffix_after_proof;
        const proof_start = proof_end - proof_bytes;

        const header_size: usize = if (v.is_data) SHRED_HEADER_SIZE else 89;
        if (proof_start < header_size) return null;

        const erasure_shard = payload[64..proof_start];
        const leaf_hash_32 = bmtree.MerkleTree.hashMerkleLeaf32(erasure_shard);

        const fec_set_idx = self.common.fec_set_index;
        // CODING-LEAF FIX (2026-06-15): a coding shred's erasure-batch leaf index is
        // numData()+codingPosition() (a SEPARATE coding index space), NOT
        // index-fec_set_index (the DATA formula). Verified canonical vs Agave
        // merkle.rs:248-259 / shred_code.rs:30 and Firedancer fd_fec_resolver.c:638-639.
        // The old single formula gave coding shreds a wrong leaf -> wrong root -> they
        // failed sig-verify and were dropped (degraded FEC recovery).
        const shred_idx_in_fec: usize = if (self.isData())
            (if (self.common.index >= fec_set_idx) @as(usize, self.common.index - fec_set_idx) else 0)
        else
            @as(usize, self.numData()) + @as(usize, self.codingPosition());

        const proof_nodes = payload[proof_start..proof_end];
        return bmtree.MerkleTree.reconstructRootFull(leaf_hash_32, proof_nodes, shred_idx_in_fec);
    }

    /// SIMD-0340 (d28ll): extract the 32-byte `chained_merkle_root` stored in
    /// the shred payload. Per d27mm-FIX layout (shred.zig:185), the
    /// chained_merkle_root sits at `payload[proof_start - 32 .. proof_start]`
    /// for chained variants — INSIDE the leaf scope, immediately before the
    /// proof. Returns null if the variant is not chained, not merkle, or the
    /// payload is too short.
    ///
    /// Used by check_chained_block_id (replay_stage.zig) to verify that THIS
    /// slot's leader claims a parent consistent with what Vexor froze for the
    /// parent slot (= parent bank's `block_id` = last shred's merkleRoot32).
    /// Mismatch ⇒ this slot is on an orphaned fork; the cluster will mark it
    /// dead. Agave reference: ledger/src/shred/wire.rs:229-245
    /// (`get_chained_merkle_root` reads 32 raw bytes from the payload and
    /// wraps as Hash — no hashing).
    pub fn chainedMerkleRoot(self: *const Shred) ?[32]u8 {
        const v = self.common.variant;
        if (!v.is_merkle) return null;
        if (!v.chained) return null;
        if (v.proof_size == 0) return null;

        const payload = self.payload;
        const proof_bytes: usize = @as(usize, v.proof_size) * bmtree.MERKLE_NODE_SIZE;
        const suffix_after_proof: usize = if (v.resigned) @as(usize, 64) else @as(usize, 0);
        if (payload.len < suffix_after_proof + proof_bytes + 32) return null;
        const proof_end = payload.len - suffix_after_proof;
        const proof_start = proof_end - proof_bytes;

        const header_size: usize = if (v.is_data) SHRED_HEADER_SIZE else 89;
        if (proof_start < header_size + 32) return null;

        var out: [32]u8 = undefined;
        @memcpy(&out, payload[proof_start - 32 .. proof_start]);
        return out;
    }

    /// Verify that this shred was signed by the given leader.
    /// For Merkle shreds: computes the Merkle root and verifies the Ed25519
    /// signature (in the shred header) against it.
    /// For legacy shreds: verifies the signature against the payload directly.
    pub fn verifySignature(self: *const Shred, leader_pubkey: *const core.Pubkey) bool {
        if (!self.isMerkle()) {
            // Legacy shreds: signature covers payload bytes [64..]
            if (self.payload.len <= 64) return false;
            // perf#1 (scoped): shred sigverify uses the AVX-512 FFI (verifyShred). Drop-safe — a
            // rejected shred triggers FEC/repair, never a bank_hash divergence. Consensus tx/gossip
            // verify stays on crypto.verify (stdlib/Agave-equivalent) — see ed25519.zig verify().
            return crypto.verifyShred(&self.common.signature.data, &leader_pubkey.data, self.payload[64..]);
        }

        // Merkle shreds: signature covers the 20-byte Merkle root
        const root = self.merkleRoot() orelse {
            // Can't compute root — reject the shred
            std.log.warn("[Shred] Cannot compute Merkle root for slot {d} index {d}", .{ self.common.slot, self.common.index });
            return false;
        };

        return crypto.verifyShred(&self.common.signature.data, &leader_pubkey.data, &root);
    }
};

/// SIMD-0337 receive-side admission predicate. Byte-faithful port of Agave
/// `should_discard_shred`'s DATA_COMPLETE block (ledger/src/shred/filter.rs:327-342):
///
///   expected_data_complete_index = fec_set_index.checked_add(32).and_then(|i| i.checked_sub(1))
///   unexpected = shred_flags.contains(DATA_COMPLETE_SHRED)
///                && (expected_data_complete_index != Some(index))
///
/// In the merkle shred format EVERY FEC set (including the final, padded one) holds
/// exactly DATA_SHREDS_PER_FEC_BLOCK (=32) data shreds, so the DATA_COMPLETE flag is
/// canonical ONLY on the 32nd data shred of its set, i.e. at index == fec_set_index + 31.
/// Any other index carrying DATA_COMPLETE is "unexpected" (spurious / equivocated /
/// corrupt). This predicate is PURELY structural; whether an unexpected shred is
/// actually DISCARDED is gated separately by the epoch-delayed feature check (see
/// EpochSchedule.checkFeatureActivation / Bank.discardUnexpectedDataCompleteEffective).
///
/// Coding shreds are exempt (isDataComplete → false via its isData guard), matching
/// Agave which only runs this block under `ShredType::Data`.
pub fn isUnexpectedDataComplete(shred: *const Shred) bool {
    if (!shred.isData() or !shred.isDataComplete()) return false;
    const fec_set = shred.fecSetIndex();
    // Mirror Agave's checked_add(32).and_then(checked_sub(1)): on overflow the
    // expected index is None, so ANY DATA_COMPLETE is unexpected (faithful;
    // practically unreachable since fec_set_index is far below u32 max).
    const expected: ?u32 = if (fec_set <= std.math.maxInt(u32) - 32)
        fec_set + 32 - 1
    else
        null;
    return expected != shred.index();
}

pub fn parseShred(data: []const u8) !Shred {
    const common = try ShredCommonHeader.fromBytes(data);
    return Shred{ .common = common, .payload = data };
}

const testing = std.testing;

// Regression KAT for the out-of-bounds `parent_offset` read fuzz/fuzz_shred_parse.zig
// found: a data-shred-variant buffer of exactly 83 or 84 bytes passed the old
// `data.len < 83` floor and then panicked reading data[83..85]. Must return a clean
// parse error instead.
test "fromBytes: 83/84-byte data-shred buffer errors cleanly (does not panic)" {
    inline for (.{ 83, 84 }) |len| {
        var buf = [_]u8{0} ** len;
        buf[64] = 0x80; // Merkle DATA variant, proof_size=0 (is_data=true)
        try testing.expectError(error.ShredTooShort, ShredCommonHeader.fromBytes(&buf));
    }
}

test "fromBytes: 85-byte data-shred buffer parses (parent_offset now in range)" {
    var buf = [_]u8{0} ** 85;
    buf[64] = 0x80;
    const hdr = try ShredCommonHeader.fromBytes(&buf);
    try testing.expect(hdr.variant.is_data);
    try testing.expectEqual(@as(u16, 0), hdr.parent_offset);
}

test "fromBytes: 83-byte code-shred buffer still parses (code shreds have no parent_offset field)" {
    var buf = [_]u8{0} ** 83;
    buf[64] = 0x40; // Merkle CODE variant, proof_size=0 (is_data=false)
    const hdr = try ShredCommonHeader.fromBytes(&buf);
    try testing.expect(!hdr.variant.is_data);
    try testing.expectEqual(@as(u16, 0), hdr.parent_offset);
}
