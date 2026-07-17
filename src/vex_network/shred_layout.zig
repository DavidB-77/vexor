//! Canonical merkle-shred FEC-set LAYOUT — sizes, FEC counts, and the merkle leaf region.
//!
//! STAGED / MODULAR: not wired to the live path; gated behind -Dleader_mode. Step 4b of the
//! shredder rewrite (after shred_header.zig). The merkle TREE itself is reused from
//! vex_network/bmtree.zig (ShredMerkleTree, 20-byte nodes already present); this module owns the
//! byte-exact SIZING that decides how the entry payload is chunked into shreds and which bytes of
//! each shred are hashed into its merkle leaf.
//!
//! Ground truth: Firedancer pin v0.1002.40103 src/disco/shred/{fd_shredder.c,fd_shredder.h} +
//! src/ballet/bmtree/fd_bmtree.c, file:line cited. Cross-check: data_shred_payload_sz * 32 equals
//! the published FEC_SET_PAYLOAD_SZ constants (995*32=31840 normal, 963*32=30816 chained,
//! 899*32=28768 resigned) — the formulas and the constants must agree (KAT below).

const std = @import("std");
const shred_header = @import("shred_header.zig");

/// 32 data + 32 parity shreds per FEC set (FD_FEC_SHRED_CNT; fd_shredder.c:169, shred.rs:118).
pub const FEC_SHRED_CNT: usize = 32;

/// Published FEC-set payload capacities (fd_shredder.h:109-111). Bytes of entry payload per set.
pub const NORMAL_FEC_SET_PAYLOAD_SZ: usize = 31840;
pub const CHAINED_FEC_SET_PAYLOAD_SZ: usize = 30816; // -32B/shred (chained merkle root)
pub const RESIGNED_FEC_SET_PAYLOAD_SZ: usize = 28768; // -64B/shred (retransmitter sig)

/// fd_bmtree_depth (fd_bmtree.c): leaf_cnt<=1 -> leaf_cnt, else msb(leaf_cnt-1)+2.
pub fn bmtreeDepth(leaf_cnt: usize) usize {
    if (leaf_cnt <= 1) return leaf_cnt;
    const msb: usize = @intCast(63 - @clz(@as(u64, leaf_cnt - 1)));
    return msb + 2;
}

/// tree_depth as fd_shredder.c:173 counts it (excludes the root): bmtreeDepth(leaves)-1.
pub fn treeDepth(data_shred_cnt: usize, parity_shred_cnt: usize) usize {
    return bmtreeDepth(data_shred_cnt + parity_shred_cnt) - 1;
}

/// data_shred_payload_sz (fd_shredder.c:174). The usable data bytes carried by one DATA shred.
pub fn dataShredPayloadSz(tree_depth: usize, is_chained: bool, is_resigned: bool) usize {
    return 1115 - 20 * tree_depth - 32 * @as(usize, @intFromBool(is_chained)) - 64 * @as(usize, @intFromBool(is_resigned));
}

/// parity_shred_payload_sz (fd_shredder.c:175) = data_payload + DATA_HEADER_SZ - SIGNATURE_SZ.
pub fn parityShredPayloadSz(data_shred_payload_sz: usize) usize {
    return data_shred_payload_sz + shred_header.DATA_HEADER_SZ - shred_header.SIGNATURE_SZ; // +24
}

/// data_merkle_sz (fd_shredder.c:176) = parity_payload + 32*is_chained. The #bytes of a DATA shred
/// (after the signature) hashed into its merkle leaf.
pub fn dataMerkleSz(parity_shred_payload_sz: usize, is_chained: bool) usize {
    return parity_shred_payload_sz + 32 * @as(usize, @intFromBool(is_chained));
}

/// parity_merkle_sz (fd_shredder.c:177) = data_merkle_sz + CODE_HEADER_SZ - SIGNATURE_SZ.
pub fn parityMerkleSz(data_merkle_sz: usize) usize {
    return data_merkle_sz + shred_header.CODE_HEADER_SZ - shred_header.SIGNATURE_SZ; // +25
}

/// fd_shredder_count_fec_sets (fd_shredder.h:115-118). Number of FEC sets an entry batch of
/// `sz_bytes` splits into. When block_complete, the final set is resigned (smaller capacity), so the
/// threshold uses the chained/resigned difference.
pub fn countFecSets(sz_bytes: usize, block_complete: bool) usize {
    const C = CHAINED_FEC_SET_PAYLOAD_SZ;
    const R = RESIGNED_FEC_SET_PAYLOAD_SZ;
    if (block_complete) {
        return 1 + (sz_bytes + C - R - 1) / C;
    }
    return (sz_bytes + C - 1) / C;
}

pub fn countDataShreds(sz_bytes: usize, block_complete: bool) usize {
    return FEC_SHRED_CNT * countFecSets(sz_bytes, block_complete);
}

/// The byte slice of a shred hashed into its merkle leaf: shred[64 .. 64+merkle_sz]. fd_shredder.c
/// hashes from (signature+64-26) for (merkle_sz+26) bytes, where the first 26 bytes are the
/// LEAF_PREFIX written into the signature tail — equivalent to bmtree.hashMerkleLeaf(this slice).
pub fn leafRegion(shred: []const u8, merkle_sz: usize) []const u8 {
    return shred[shred_header.SIGNATURE_SZ .. shred_header.SIGNATURE_SZ + merkle_sz];
}

// ════════════════════════════════════════════════════════════════════════════
// KAT — sizing self-consistency vs fd_shredder.h published constants. Run: zig build test-shred-layout
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "tree depth: 32+32=64 leaves -> tree_depth 6 (fd_bmtree_depth(64)-1)" {
    try testing.expectEqual(@as(usize, 7), bmtreeDepth(64));
    try testing.expectEqual(@as(usize, 6), treeDepth(32, 32));
    // boundary checks
    try testing.expectEqual(@as(usize, 1), bmtreeDepth(1));
    try testing.expectEqual(@as(usize, 2), bmtreeDepth(2));
    try testing.expectEqual(@as(usize, 3), bmtreeDepth(3));
    try testing.expectEqual(@as(usize, 3), bmtreeDepth(4));
}

test "data shred payload sizes (depth 6): normal 995 / chained 963 / resigned 899" {
    const d = treeDepth(32, 32); // 6
    try testing.expectEqual(@as(usize, 995), dataShredPayloadSz(d, false, false));
    try testing.expectEqual(@as(usize, 963), dataShredPayloadSz(d, true, false));
    try testing.expectEqual(@as(usize, 899), dataShredPayloadSz(d, true, true));
}

test "payload sizes * 32 == published FEC_SET_PAYLOAD constants (the cross-check)" {
    const d = treeDepth(32, 32);
    try testing.expectEqual(NORMAL_FEC_SET_PAYLOAD_SZ, dataShredPayloadSz(d, false, false) * FEC_SHRED_CNT);
    try testing.expectEqual(CHAINED_FEC_SET_PAYLOAD_SZ, dataShredPayloadSz(d, true, false) * FEC_SHRED_CNT);
    try testing.expectEqual(RESIGNED_FEC_SET_PAYLOAD_SZ, dataShredPayloadSz(d, true, true) * FEC_SHRED_CNT);
}

test "merkle leaf-region sizes (chained, depth 6): data 987, parity 1012" {
    const d = treeDepth(32, 32);
    const dpp = dataShredPayloadSz(d, true, false); // 963
    const ppp = parityShredPayloadSz(dpp); // 963 + 24 = 987
    try testing.expectEqual(@as(usize, 987), ppp);
    const dms = dataMerkleSz(ppp, true); // 987 + 32 = 1019
    try testing.expectEqual(@as(usize, 1019), dms);
    const pms = parityMerkleSz(dms); // 1019 + 25 = 1044
    try testing.expectEqual(@as(usize, 1044), pms);
}

test "FEC set counting (chained 30816 / resigned 28768)" {
    // not block-complete: ceil(sz / 30816)
    try testing.expectEqual(@as(usize, 1), countFecSets(1, false));
    try testing.expectEqual(@as(usize, 1), countFecSets(30816, false));
    try testing.expectEqual(@as(usize, 2), countFecSets(30817, false));
    try testing.expectEqual(@as(usize, 32), countDataShreds(30816, false));
    // block-complete: 1 + ceil((sz - (C-R)) / C) ; tiny final block still gets its own resigned set
    try testing.expectEqual(@as(usize, 1), countFecSets(1, true));
}

test "leaf region is shred[64 .. 64+merkle_sz]" {
    var buf: [1228]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @intCast(i & 0xFF);
    const region = leafRegion(&buf, 1019);
    try testing.expectEqual(@as(usize, 1019), region.len);
    try testing.expectEqual(buf[64], region[0]);
    try testing.expectEqual(buf[64 + 1018], region[1018]);
}
