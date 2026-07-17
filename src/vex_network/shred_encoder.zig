//! FEC-set shred ENCODER — assembles one Reed-Solomon FEC set into 32 data + 32 code merkle shreds.
//!
//! STAGED / MODULAR: not wired to the live path; gated behind -Dleader_mode at the call site. This is
//! the capstone of the shredder rewrite — it composes shred_layout (sizes) + shred_header (headers) +
//! shred_reedsol (RS parity) + the 20-byte Solana merkle tree (built here on bmtree primitives) +
//! ed25519 signing into "entry-payload chunk → signed merkle shreds".
//!
//! Ground truth: Firedancer pin v0.1002.40103 src/disco/shred/fd_shredder.c (the AUTHORITATIVE encode
//! order — the receive-side recovery's erasure_sz is NOT the RS shard size and must not be used for
//! encode) + src/ballet/shred/fd_shred.h (offsets). Verified for the chained, non-resigned, depth-6
//! case (32 data : 32 parity), data shred 1203 B, code shred 1228 B:
//!   RS shard = parity_shred_payload_sz = 987 B (fd_shredder.c:175,179). data shard = data_shred[64..
//!     64+987]=[64..1051] (header-tail+payload; EXCLUDES chained_root). parity → code[89..89+987]=
//!     [89..1076] (fd_shredder.c:212,234). chained_root written AFTER RS at chain_off (fd_shredder.c:
//!     215-216,237-238): data [1051..1083], code [1076..1108].
//!   merkle LEAF = shred[64..proof_start] (data [64..1083]=1019 B, code [64..1108]=1044 B) — INCLUDES
//!     the chained_root. leaf = sha256(LEAF_PREFIX ‖ region) truncated to 20 B (bmtree.hashMerkleLeaf).
//!   tree over 64 leaves (data 0..31 then code 0..31), 20-byte nodes, duplicate-last on odd levels
//!     (Agave merkle_tree.rs). sign the 20-byte? NO — Agave signs the leaf-form root; the shred sig is
//!     ed25519 over the merkle root, copied into every shred's sig[0..64]. proof (6×20 B) embedded at
//!     merkle_off (data 1083, code 1108).
//!
//! Gate: every produced shred's leaf+embedded-proof reconstructs (bmtree.reconstructRoot, the SAME
//! function that validates REAL cluster shreds on the receive path) to the signed root; ed25519 sig
//! verifies; data payloads extract back to the original chunk. (Full byte-match vs FD demo-shreds.pcap
//! is the remaining 100% gate — this round-trip proves format-correctness via consensus-validated code.)

const std = @import("std");
const bmtree = @import("bmtree.zig");
const hdr = @import("shred_header.zig");
const layout = @import("shred_layout.zig");
const rs = @import("shred_reedsol.zig");

const Ed25519 = std.crypto.sign.Ed25519;
pub const NODE = bmtree.MERKLE_NODE_SIZE; // 20 — proof-entry / intermediate-input width
pub const ROOT_SZ = 32; // FD_SHRED_MERKLE_ROOT_SZ — the SIGNED + chained root is full 32 B

pub const FecSetShreds = struct {
    /// 32 data shred buffers (1203 B each) + 32 code shred buffers (1228 B each), allocator-owned.
    data: [][]u8,
    code: [][]u8,
    /// the 32-byte merkle root that was signed (= the chained_root the NEXT FEC set carries, and the
    /// block_id on the block's last FEC set). SIMD-0340.
    root: [ROOT_SZ]u8,

    pub fn deinit(self: *FecSetShreds, allocator: std.mem.Allocator) void {
        for (self.data) |d| allocator.free(d);
        for (self.code) |c| allocator.free(c);
        allocator.free(self.data);
        allocator.free(self.code);
    }
};

pub const FecSetParams = struct {
    slot: u64,
    version: u16,
    fec_set_idx: u32,
    /// index of the first DATA shred in this FEC set (within the block).
    data_start_idx: u32,
    /// index of the first CODE shred in this FEC set (within the block's coding shreds).
    code_start_idx: u32,
    parent_off: u16,
    reference_tick: u8,
    /// last DATA shred gets DATA_COMPLETE (end of entry batch). + SLOT_COMPLETE if the block ends here.
    data_complete: bool = true,
    slot_complete: bool = false,
    /// resigned variant — used for the BLOCK'S LAST FEC set (fd_shredder.c:150). Smaller payload
    /// (899 vs 963), a zeroed 64-byte retransmitter signature at the end of every shred, and all
    /// offsets shifted by -64. The leader writes the retransmitter sig = 0 (fd_shredder.c:273).
    is_resigned: bool = false,
};

/// Build one chained, non-resigned FEC set (32 data + 32 code, depth 6). `payload` is this set's data
/// (<= 32*963 = 30816 B; zero-padded to fill the last data shred). `chained_root` is the previous FEC
/// set's root (or the parent block's last-FEC root for the block's first set). `secret_key` is the
/// leader's ed25519 secret (64 B: seed‖pubkey, std KeyPair.SecretKey form).
pub fn assembleFecSet(
    allocator: std.mem.Allocator,
    params: FecSetParams,
    payload: []const u8,
    chained_root: [ROOT_SZ]u8,
    secret_key: [64]u8,
) !FecSetShreds {
    const rsg = params.is_resigned;
    const suffix: usize = if (rsg) 64 else 0; // retransmitter sig at the shred tail (resigned only)
    const N: usize = layout.FEC_SHRED_CNT; // 32 data
    const M: usize = layout.FEC_SHRED_CNT; // 32 parity
    const depth = layout.treeDepth(N, M); // 6
    const dpp = layout.dataShredPayloadSz(depth, true, rsg); // 963 (chained) / 899 (resigned)
    const rs_sz = layout.parityShredPayloadSz(dpp); // 987 / 923 — RS shard size
    const dms = layout.dataMerkleSz(rs_sz, true); // 1019 / 955 — data merkle leaf region
    const pms = layout.parityMerkleSz(dms); // 1044 / 980 — code merkle leaf region
    const proof_bytes = depth * NODE; // 120
    const data_sz = hdr.SHRED_MIN_SZ; // 1203
    const code_sz = hdr.SHRED_MAX_SZ; // 1228

    std.debug.assert(payload.len <= N * dpp);

    const data_variant = hdr.dataVariant(@intCast(depth), true, rsg); // 0x96 / 0xB6
    const code_variant = hdr.codeVariant(@intCast(depth), true, rsg); // 0x66 / 0x76

    // ── 1. Build the 32 DATA shreds (header + payload + chained_root; proof later). ──
    var data_shreds = try allocator.alloc([]u8, N);
    for (0..N) |i| {
        const buf = try allocator.alloc(u8, data_sz);
        @memset(buf, 0);
        const is_last = (i == N - 1);
        var flags: u8 = params.reference_tick & hdr.DATA_REF_TICK_MASK;
        if (is_last and params.data_complete) flags |= hdr.DATA_FLAG_DATA_COMPLETE;
        if (is_last and params.slot_complete) flags |= hdr.DATA_FLAG_SLOT_COMPLETE; // 0x80 (with 0x40 = 0xC0)
        // Per-shred payload size = the actual (un-padded) bytes of this set's payload landing in
        // THIS data shred. FD writes shred->data.size = DATA_HEADER_SZ + shred_payload_sz
        // (fd_shredder.c:197) where shred_payload_sz = min(remaining_in_set, dpp). The padded /
        // empty trailing shreds therefore carry size = 88 (header only), NOT the full 1203. This
        // field is inside the merkle leaf region [64..1083] so it is consensus-bound.
        const off = i * dpp;
        const n_copy = @min(dpp, if (off < payload.len) payload.len - off else 0);
        const dh = hdr.DataHeader{
            .common = .{ .variant = data_variant, .slot = params.slot, .idx = params.data_start_idx + @as(u32, @intCast(i)), .version = params.version, .fec_set_idx = params.fec_set_idx },
            .parent_off = params.parent_off,
            .flags = flags,
            .size = @intCast(hdr.DATA_HEADER_SZ + n_copy),
        };
        dh.serialize(buf);
        // payload [88 .. 88+n_copy]
        if (n_copy > 0) @memcpy(buf[hdr.DATA_HEADER_SZ..][0..n_copy], payload[off..][0..n_copy]);
        // chained_root: data_sz - suffix - 32 - proof_bytes (1051 chained / 987 resigned)
        const chain_off_data = data_sz - suffix - 32 - proof_bytes;
        @memcpy(buf[chain_off_data..][0..32], &chained_root);
        data_shreds[i] = buf;
    }

    // ── 2. RS-encode: 32 data shards [64..64+987] → 32 parity shards (987 B). ──
    var data_shards = try allocator.alloc([]const u8, N);
    defer allocator.free(data_shards);
    for (0..N) |i| data_shards[i] = data_shreds[i][hdr.SIGNATURE_SZ..][0..rs_sz];
    const gf = rs.GaloisField.init();
    const parity = try rs.encodeParity(&gf, allocator, data_shards, M, rs_sz);
    defer allocator.free(parity);

    // ── 3. Build the 32 CODE shreds (header + parity + chained_root; proof later). ──
    var code_shreds = try allocator.alloc([]u8, M);
    for (0..M) |j| {
        const buf = try allocator.alloc(u8, code_sz);
        @memset(buf, 0);
        const ch = hdr.CodeHeader{
            .common = .{ .variant = code_variant, .slot = params.slot, .idx = params.code_start_idx + @as(u32, @intCast(j)), .version = params.version, .fec_set_idx = params.fec_set_idx },
            .data_cnt = @intCast(N),
            .code_cnt = @intCast(M),
            .idx = @intCast(j),
        };
        ch.serialize(buf);
        // parity [89 .. 89+987=1076]
        @memcpy(buf[hdr.CODE_HEADER_SZ..][0..rs_sz], parity[j * rs_sz ..][0..rs_sz]);
        // chained_root: code_sz - suffix - 32 - proof_bytes (1076 chained / 1012 resigned)
        const chain_off_code = code_sz - suffix - 32 - proof_bytes;
        @memcpy(buf[chain_off_code..][0..32], &chained_root);
        code_shreds[j] = buf;
    }

    // ── 4. Merkle leaves over all 64 shreds (data 0..31 then code 0..31). 32-byte leaves. ──
    const total = N + M;
    var leaves = try allocator.alloc([ROOT_SZ]u8, total);
    defer allocator.free(leaves);
    for (0..N) |i| leaves[i] = bmtree.MerkleTree.hashMerkleLeaf32(data_shreds[i][hdr.SIGNATURE_SZ..][0..dms]); // [64..1083]
    for (0..M) |j| leaves[N + j] = bmtree.MerkleTree.hashMerkleLeaf32(code_shreds[j][hdr.SIGNATURE_SZ..][0..pms]); // [64..1108]

    // ── 5. Build the tree (32-byte root, 20-byte intermediate inputs) → root + per-leaf proofs. ──
    const tree = try buildTree32(allocator, leaves);
    defer tree.deinit(allocator);
    const root = tree.root;

    // ── 6. Sign the 32-byte root (ed25519) and write the 64-byte sig into EVERY shred. ──
    const kp = try Ed25519.KeyPair.fromSecretKey(try Ed25519.SecretKey.fromBytes(secret_key));
    const sig = (try kp.sign(&root, null)).toBytes();
    for (0..N) |i| @memcpy(data_shreds[i][0..64], &sig);
    for (0..M) |j| @memcpy(code_shreds[j][0..64], &sig);

    // ── 7. Embed each shred's proof at merkle_off = shred_sz - suffix - proof_bytes. ──
    const merkle_off_data = data_sz - suffix - proof_bytes; // 1083 chained / 1019 resigned
    const merkle_off_code = code_sz - suffix - proof_bytes; // 1108 chained / 1044 resigned
    for (0..N) |i| {
        const p = try tree.proof(allocator, i);
        defer allocator.free(p);
        @memcpy(data_shreds[i][merkle_off_data..][0..proof_bytes], p);
        // resigned: retransmitter signature at the tail = ZERO (leader writes 0; fd_shredder.c:273).
        if (rsg) @memset(data_shreds[i][data_sz - 64 ..][0..64], 0);
    }
    for (0..M) |j| {
        const p = try tree.proof(allocator, N + j);
        defer allocator.free(p);
        @memcpy(code_shreds[j][merkle_off_code..][0..proof_bytes], p);
        if (rsg) @memset(code_shreds[j][code_sz - 64 ..][0..64], 0);
    }

    return .{ .data = data_shreds, .code = code_shreds, .root = root };
}

// ── Solana shred merkle tree (32-byte nodes, 20-byte hash inputs) — build + inclusion proof ──
// Mirrors Agave ledger/src/shred/merkle.rs + bmtree.reconstructRootFull: leaf = sha256(LEAF_PREFIX‖
// data) (32 B); node(l,r) = sha256(NODE_PREFIX ‖ l[0..20] ‖ r[0..20]) (32 B); odd level → duplicate
// last node. Proof ENTRIES are the 20-byte truncations of sibling nodes (what the shred carries).

/// node(left32, right32) = sha256(NODE_PREFIX ‖ left[0..20] ‖ right[0..20]) → 32 B. Matches
/// bmtree.reconstructRootFull's per-step hash exactly.
fn hashNode32(left: [ROOT_SZ]u8, right: [ROOT_SZ]u8) [ROOT_SZ]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(bmtree.NODE_PREFIX);
    h.update(left[0..NODE]);
    h.update(right[0..NODE]);
    return h.finalResult();
}

const Tree32 = struct {
    levels: [][][ROOT_SZ]u8, // levels[0] = leaves (32 B), levels[last] = [root]
    root: [ROOT_SZ]u8,

    fn deinit(self: Tree32, allocator: std.mem.Allocator) void {
        for (self.levels) |lvl| allocator.free(lvl);
        allocator.free(self.levels);
    }

    /// Inclusion proof for leaf `index`: the 20-byte truncation of the sibling node at each level,
    /// bottom-up. Reconstructs to `root` via bmtree.reconstructRootFull(leaf32, proof, index).
    fn proof(self: Tree32, allocator: std.mem.Allocator, index: usize) ![]u8 {
        const depth = self.levels.len - 1;
        var out = try allocator.alloc(u8, depth * NODE);
        var idx = index;
        for (0..depth) |d| {
            const lvl = self.levels[d];
            const sib = if (idx % 2 == 0)
                (if (idx + 1 < lvl.len) idx + 1 else idx) // even: right sibling, or self if last (odd)
            else
                idx - 1; // odd: left sibling
            @memcpy(out[d * NODE ..][0..NODE], lvl[sib][0..NODE]); // 20-byte truncation
            idx /= 2;
        }
        return out;
    }
};

fn buildTree32(allocator: std.mem.Allocator, leaves: []const [ROOT_SZ]u8) !Tree32 {
    var levels: std.ArrayListUnmanaged([][ROOT_SZ]u8) = .{};
    errdefer {
        for (levels.items) |lvl| allocator.free(lvl);
        levels.deinit(allocator);
    }
    const l0 = try allocator.alloc([ROOT_SZ]u8, leaves.len);
    @memcpy(l0, leaves);
    try levels.append(allocator, l0);

    var cur = l0;
    while (cur.len > 1) {
        const next_len = (cur.len + 1) / 2;
        const next = try allocator.alloc([ROOT_SZ]u8, next_len);
        for (0..next_len) |j| {
            const l = cur[2 * j];
            const r = if (2 * j + 1 < cur.len) cur[2 * j + 1] else cur[2 * j]; // duplicate last on odd
            next[j] = hashNode32(l, r);
        }
        try levels.append(allocator, next);
        cur = next;
    }
    const lv = try levels.toOwnedSlice(allocator);
    return .{ .levels = lv, .root = lv[lv.len - 1][0] };
}

// ════════════════════════════════════════════════════════════════════════════
// KAT — produce → verify via consensus-validated receive code. Run: zig build test-shred-encoder
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "assemble FEC set → every shred's leaf+proof reconstructs to the signed root + sig verifies + data extracts" {
    const allocator = testing.allocator;

    // deterministic leader keypair from a fixed seed.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xFF);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const sk = kp.secret_key.toBytes();

    // a full FEC set's worth of data (32 * 963 = 30816 B), distinct bytes.
    const dpp = layout.dataShredPayloadSz(6, true, false);
    const total_payload = layout.FEC_SHRED_CNT * dpp;
    const payload = try allocator.alloc(u8, total_payload);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 131 + 17) & 0xFF);

    var chained: [ROOT_SZ]u8 = undefined;
    for (&chained, 0..) |*b, i| b.* = @intCast((i * 9 + 1) & 0xFF);

    var set = try assembleFecSet(allocator, .{
        .slot = 415064690,
        .version = 57087,
        .fec_set_idx = 0,
        .data_start_idx = 0,
        .code_start_idx = 0,
        .parent_off = 1,
        .reference_tick = 5,
        .data_complete = true,
        .slot_complete = false,
    }, payload, chained, sk);
    defer set.deinit(allocator);

    try testing.expectEqual(@as(usize, 32), set.data.len);
    try testing.expectEqual(@as(usize, 32), set.code.len);

    // ed25519 sig (same in every shred) verifies over the root with the leader pubkey.
    const sig_bytes = set.data[0][0..64].*;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    try sig.verify(&set.root, kp.public_key);

    const proof_bytes = 6 * NODE;
    // DATA: leaf32 = hashMerkleLeaf32(shred[64..1083]); reconstructRootFull(leaf, proof, i) == root32.
    for (set.data, 0..) |d, i| {
        try testing.expectEqual(@as(usize, 1203), d.len);
        const proof_start = d.len - proof_bytes; // 1083
        const leaf = bmtree.MerkleTree.hashMerkleLeaf32(d[64..proof_start]);
        const proof = d[proof_start..];
        const r = bmtree.MerkleTree.reconstructRootFull(leaf, proof, i);
        try testing.expectEqualSlices(u8, &set.root, &r);
        try testing.expectEqualSlices(u8, &sig_bytes, d[0..64]); // sig identical across shreds
    }
    // CODE: leaf32 = hashMerkleLeaf32(shred[64..1108]); index = 32+j.
    for (set.code, 0..) |c, j| {
        try testing.expectEqual(@as(usize, 1228), c.len);
        const proof_start = c.len - proof_bytes; // 1108
        const leaf = bmtree.MerkleTree.hashMerkleLeaf32(c[64..proof_start]);
        const proof = c[proof_start..];
        const r = bmtree.MerkleTree.reconstructRootFull(leaf, proof, 32 + j);
        try testing.expectEqualSlices(u8, &set.root, &r);
    }

    // data payloads extract back to the original chunk.
    for (set.data, 0..) |d, i| {
        const off = i * dpp;
        const n = @min(dpp, total_payload - off);
        try testing.expectEqualSlices(u8, payload[off..][0..n], d[88..][0..n]);
    }

    // last data shred carries DATA_COMPLETE, others don't.
    const last = try hdr.DataHeader.parse(set.data[31]);
    try testing.expect(last.isDataComplete());
    const first = try hdr.DataHeader.parse(set.data[0]);
    try testing.expect(!first.isDataComplete());
}

test "resigned variant (block's last FEC set): reconstruct + sig + zeroed retransmitter sig" {
    const allocator = testing.allocator;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast((i * 5 + 11) & 0xFF);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const sk = kp.secret_key.toBytes();

    const dpp = layout.dataShredPayloadSz(6, true, true); // 899
    const total_payload = layout.FEC_SHRED_CNT * dpp; // 28768
    const payload = try allocator.alloc(u8, total_payload);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 97 + 5) & 0xFF);

    var chained: [ROOT_SZ]u8 = undefined;
    for (&chained, 0..) |*b, i| b.* = @intCast((i * 3 + 2) & 0xFF);

    var set = try assembleFecSet(allocator, .{
        .slot = 100,
        .version = 6051,
        .fec_set_idx = 224, // last of 8 sets (7*32)
        .data_start_idx = 224,
        .code_start_idx = 224,
        .parent_off = 1,
        .reference_tick = 0,
        .data_complete = true,
        .slot_complete = true, // block ends here
        .is_resigned = true,
    }, payload, chained, sk);
    defer set.deinit(allocator);

    const sig = Ed25519.Signature.fromBytes(set.data[0][0..64].*);
    try sig.verify(&set.root, kp.public_key);

    const proof_bytes = 6 * NODE;
    for (set.data, 0..) |d, i| {
        const proof_start = d.len - 64 - proof_bytes; // 1019
        const leaf = bmtree.MerkleTree.hashMerkleLeaf32(d[64..proof_start]);
        const r = bmtree.MerkleTree.reconstructRootFull(leaf, d[proof_start..][0..proof_bytes], i);
        try testing.expectEqualSlices(u8, &set.root, &r);
        // retransmitter sig (last 64 B) = zero
        try testing.expect(std.mem.allEqual(u8, d[d.len - 64 ..], 0));
        // variant is resigned-data 0xB6
        try testing.expectEqual(@as(u8, 0xB6), d[64]);
    }
    for (set.code, 0..) |c, j| {
        const proof_start = c.len - 64 - proof_bytes; // 1044
        const leaf = bmtree.MerkleTree.hashMerkleLeaf32(c[64..proof_start]);
        const r = bmtree.MerkleTree.reconstructRootFull(leaf, c[proof_start..][0..proof_bytes], 32 + j);
        try testing.expectEqualSlices(u8, &set.root, &r);
        try testing.expect(std.mem.allEqual(u8, c[c.len - 64 ..], 0));
        try testing.expectEqual(@as(u8, 0x76), c[64]); // resigned-code variant
    }
    // last data shred carries SLOT_COMPLETE (block ends)
    const last = try hdr.DataHeader.parse(set.data[31]);
    try testing.expect(last.isSlotComplete());
}
