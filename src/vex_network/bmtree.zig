//! Vexor Binary Merkle Tree
//!
//! SHA256-based Merkle tree for shred verification.
//! Based on Firedancer: src/ballet/bmtree/fd_bmtree.h
//!
//! Used to verify the authenticity and integrity of shreds.
//! The root of the Merkle tree is signed by the block producer.

const std = @import("std");
const core = @import("core");

/// Merkle node size (SHA256 hash)
pub const NODE_SIZE: usize = 32;

/// Merkle node size for Merkle shreds (truncated SHA256)
pub const MERKLE_NODE_SIZE: usize = 20;

/// Solana Merkle shred prefixes
pub const LEAF_PREFIX = "\x00SOLANA_MERKLE_SHREDS_LEAF";
pub const NODE_PREFIX = "\x01SOLANA_MERKLE_SHREDS_NODE";

/// Maximum tree depth (log2 of max leaves)
pub const MAX_DEPTH: usize = 20;

/// Maximum leaves in a tree (2^20 = ~1M)
pub const MAX_LEAVES: usize = 1 << MAX_DEPTH;

/// Merkle tree node (32-byte hash)
pub const Node = [NODE_SIZE]u8;

/// Merkle inclusion proof
/// Reference: Firedancer fd_bmtree_inc_proof
pub const InclusionProof = struct {
    /// Nodes on the path from leaf to root
    nodes: []Node,

    /// Positions (left=0, right=1) for each node in the path
    positions: []u1,

    /// Index of the leaf this proof is for
    leaf_index: usize,

    pub fn deinit(self: *InclusionProof, allocator: std.mem.Allocator) void {
        allocator.free(self.nodes);
        allocator.free(self.positions);
    }
};

/// Binary Merkle Tree
/// Reference: Firedancer fd_bmtree_commit
pub const MerkleTree = struct {
    allocator: std.mem.Allocator,

    /// All nodes in the tree (leaf and branch)
    /// Layout: leaves at bottom, branches above
    nodes: std.ArrayList(Node),

    /// Number of leaf nodes
    leaf_count: usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            // Zig 0.15.2: ArrayList is unmanaged — allocator is passed per-op
            // (held in self.allocator), not stored in the list.
            .nodes = .{},
            .leaf_count = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.nodes.deinit(self.allocator);
    }

    /// Hash a leaf blob to create a leaf node
    /// Reference: Firedancer fd_bmtree_hash_leaf
    pub fn hashLeaf(data: []const u8) Node {
        // Prefix with 0x00 to distinguish from branch nodes
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&[_]u8{0x00});
        hasher.update(data);
        return hasher.finalResult();
    }

    /// Hash two child nodes to create a branch node
    /// Reference: Firedancer fd_bmtree_hash_branch
    pub fn hashBranch(left: *const Node, right: *const Node) Node {
        // Prefix with 0x01 to distinguish from branch nodes
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&[_]u8{0x01});
        hasher.update(left);
        hasher.update(right);
        return hasher.finalResult();
    }

    /// Hash a leaf for Solana Merkle shreds (20-byte truncated)
    pub fn hashMerkleLeaf(data: []const u8) [MERKLE_NODE_SIZE]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(LEAF_PREFIX);
        hasher.update(data);
        const res = hasher.finalResult();
        var out: [MERKLE_NODE_SIZE]u8 = undefined;
        @memcpy(&out, res[0..MERKLE_NODE_SIZE]);
        return out;
    }

    /// Hash two nodes for Solana Merkle shreds (20-byte truncated)
    pub fn hashMerkleNode(left: []const u8, right: []const u8) [MERKLE_NODE_SIZE]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(NODE_PREFIX);
        hasher.update(left[0..MERKLE_NODE_SIZE]);
        hasher.update(right[0..MERKLE_NODE_SIZE]);
        const res = hasher.finalResult();
        var out: [MERKLE_NODE_SIZE]u8 = undefined;
        @memcpy(&out, res[0..MERKLE_NODE_SIZE]);
        return out;
    }

    /// Full 32-byte SHA-256 of LEAF_PREFIX || data — the leaf node Agave uses
    /// in get_merkle_node (ledger/src/shred/merkle.rs:661). Required for the
    /// SIMD-0340 chained_block_id path: Agave's `get_merkle_root` returns a
    /// 32-byte `Hash`; the legacy 20-byte path (hashMerkleLeaf above) is only
    /// for the truncated proof-entry form. Empty-proof FEC sets must compare
    /// against this 32-byte leaf directly.
    pub fn hashMerkleLeaf32(data: []const u8) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(LEAF_PREFIX);
        hasher.update(data);
        return hasher.finalResult();
    }

    /// Reconstruct the FULL 32-byte merkle root (Agave canonical) from a
    /// 32-byte leaf, 20-byte proof entries, and the leaf's index in the FEC
    /// set. Mirrors Agave's `ledger/src/shred/merkle_tree.rs:108` get_merkle_root
    /// exactly: each iteration truncates BOTH the running node and the sibling
    /// to 20 bytes before hashing (via join_nodes), but the SHA-256 output is
    /// kept at full 32-byte width and propagated as the next iteration's input.
    /// Final return is the last 32-byte hash (or the leaf untouched if proof
    /// is empty, matching Agave's `fold((index, node), …)` initial-value path).
    pub fn reconstructRootFull(leaf_hash_32: [32]u8, proof_hashes: []const u8, index: usize) [32]u8 {
        var current_hash: [32]u8 = leaf_hash_32;
        var idx = index;
        var i: usize = 0;
        while (i < proof_hashes.len) : (i += MERKLE_NODE_SIZE) {
            const sibling = proof_hashes[i..][0..MERKLE_NODE_SIZE];
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(NODE_PREFIX);
            if (idx % 2 == 0) {
                hasher.update(current_hash[0..MERKLE_NODE_SIZE]);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(current_hash[0..MERKLE_NODE_SIZE]);
            }
            current_hash = hasher.finalResult();
            idx /= 2;
        }
        return current_hash;
    }

    /// Reconstruct Merkle root from leaf and proof hashes
    /// proof_hashes: slice of 20-byte siblings
    /// index: leaf index in the tree
    /// Returns the 20-byte truncated SHA256 of the root node.
    pub fn reconstructRoot(leaf_hash_20: [MERKLE_NODE_SIZE]u8, proof_hashes: []const u8, index: usize) [MERKLE_NODE_SIZE]u8 {
        var current_hash: [32]u8 = undefined;
        var temp_hash: [MERKLE_NODE_SIZE]u8 = leaf_hash_20;

        var idx = index;
        var i: usize = 0;
        while (i < proof_hashes.len) : (i += MERKLE_NODE_SIZE) {
            const sibling = proof_hashes[i..][0..MERKLE_NODE_SIZE];

            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(NODE_PREFIX);

            if (idx % 2 == 0) {
                hasher.update(&temp_hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&temp_hash);
            }

            current_hash = hasher.finalResult();
            // Intermediate nodes are always truncated to 20 bytes for the NEXT level
            @memcpy(&temp_hash, current_hash[0..MERKLE_NODE_SIZE]);

            idx /= 2;
        }

        return temp_hash;
    }

    /// Number of nodes in a Solana merkle tree with `num_leaves` leaves.
    /// Canonical mirror of Agave ledger/src/shred/merkle_tree.rs:155
    /// get_merkle_tree_size = sum of successors(n, |k| (k>1)?(k+1)>>1).
    pub fn merkleTreeSize(num_leaves: usize) usize {
        var sum: usize = 0;
        var k = num_leaves;
        while (true) {
            sum += k;
            if (k <= 1) break;
            k = (k + 1) >> 1;
        }
        return sum;
    }

    /// Number of 20-byte proof entries for a tree with `num_leaves` leaves
    /// (= number of levels above the leaves). Canonical: equals Agave
    /// merkle_tree.rs:160 get_proof_size(num_shreds) and the on-wire variant
    /// byte's low-nibble proof_size for that FEC set.
    pub fn merkleProofLen(num_leaves: usize) usize {
        var sz = num_leaves;
        var n: usize = 0;
        while (sz > 1) : (sz = (sz + 1) >> 1) n += 1;
        return n;
    }

    /// FORWARD merkle build + proof emission — the canonical inverse of
    /// `reconstructRoot`. Builds the Solana merkle tree over `leaves` (20-byte leaf
    /// NODES, already hashed via `hashMerkleLeaf`, in erasure-shard order: data
    /// [0..num_data) then coding [num_data..total)), writes the inclusion proof for
    /// `leaf_index` into `out_proof`, and returns the 20-byte root.
    ///
    /// Byte-for-byte mirror of Agave ledger/src/shred/merkle_tree.rs:
    ///   try_new_with_len (:47): flat `nodes` array; per level of `size` nodes at
    ///     `offset`, parent[i] = join_nodes(nodes[i], nodes[(i+1).min(offset+size-1)])
    ///     — the ODD node pairs with ITSELF (duplicate-LAST rule, :61).
    ///   make_merkle_proof (:76): sibling = nodes[offset + (index^1).min(size-1)];
    ///     then offset+=size, size=(size+1)>>1, index>>=1; emit node[..20] (:88-94).
    /// `join_nodes` (:107, hashv(NODE_PREFIX, node[..20], other[..20])) == this
    /// module's `hashMerkleNode` — verified byte-identical (prefixes match
    /// merkle_tree.rs:17-18). `out_proof.len` must be >= proof_size for `total`.
    pub fn makeMerkleProof(
        allocator: std.mem.Allocator,
        leaves: []const [MERKLE_NODE_SIZE]u8,
        leaf_index: usize,
        out_proof: [][MERKLE_NODE_SIZE]u8,
    ) ![MERKLE_NODE_SIZE]u8 {
        const total = leaves.len;
        if (total == 0) return error.EmptyLeaves;
        if (leaf_index >= total) return error.IndexOutOfRange;

        const tree_size = merkleTreeSize(total);
        const nodes = try allocator.alloc([MERKLE_NODE_SIZE]u8, tree_size);
        defer allocator.free(nodes);

        // Leaves first (Agave: nodes.push(shred) for each leaf).
        for (leaves, 0..) |lf, i| nodes[i] = lf;
        var nlen: usize = total;

        // Build parents bottom-up (try_new_with_len successors loop).
        var size = total;
        while (size > 1) {
            const offset = nlen - size;
            var i = offset;
            while (i < offset + size) : (i += 2) {
                const node = nodes[i];
                const other = nodes[@min(i + 1, offset + size - 1)];
                nodes[nlen] = hashMerkleNode(&node, &other);
                nlen += 1;
            }
            size = (size + 1) >> 1;
        }
        std.debug.assert(nlen == tree_size);

        // Emit the inclusion proof for `leaf_index` (make_merkle_proof).
        // The proof length for a `total`-leaf tree is ceil(log2(total)) entries.
        // `out_proof` is sized by the CALLER from the shred's *declared* proof
        // byte-count (fec_resolver.zig:1512), which a malformed/adversarial repair
        // shred can understate vs the actual leaf count → `p` would overrun
        // out_proof. Guard it: a mismatch means the shred's merkle variant is
        // inconsistent with the FEC set, so refuse to recover from it (the caller
        // catches this and falls back to repair — no bank_hash impact). This also
        // covers the resigned-merkle (variant 0xb6) proof-count class. Previously
        // this OOB-wrote and SIGABRT'd the node (2026-06-26 repair-path crash).
        var idx = leaf_index;
        var sz = total;
        var offset: usize = 0;
        var p: usize = 0;
        while (sz > 1) {
            if (p >= out_proof.len) return error.ProofBufferTooSmall;
            out_proof[p] = nodes[offset + @min(idx ^ 1, sz - 1)];
            p += 1;
            offset += sz;
            sz = (sz + 1) >> 1;
            idx >>= 1;
        }
        return nodes[tree_size - 1];
    }

    /// Add a leaf to the tree (must call finalize after all leaves added)
    pub fn addLeaf(self: *Self, data: []const u8) !void {
        const leaf_node = hashLeaf(data);
        try self.nodes.append(self.allocator, leaf_node);
        self.leaf_count += 1;
    }

    /// Add a pre-hashed leaf node directly
    pub fn addLeafNode(self: *Self, node: Node) !void {
        try self.nodes.append(self.allocator, node);
        self.leaf_count += 1;
    }

    /// Finalize the tree by computing all branch nodes up to root
    /// Reference: Firedancer fd_bmtree_commit_fini
    pub fn finalize(self: *Self) !void {
        if (self.leaf_count == 0) return;
        if (self.leaf_count == 1) {
            // Single leaf is also the root
            return;
        }

        // Build tree bottom-up
        var level_start: usize = 0;
        var level_count: usize = self.leaf_count;

        while (level_count > 1) {
            const next_level_count = (level_count + 1) / 2;

            var i: usize = 0;
            while (i < level_count) : (i += 2) {
                const left = &self.nodes.items[level_start + i];
                const right = if (i + 1 < level_count)
                    &self.nodes.items[level_start + i + 1]
                else
                    left; // Duplicate last node if odd count

                const branch = hashBranch(left, right);
                try self.nodes.append(self.allocator, branch);
            }

            level_start += level_count;
            level_count = next_level_count;
        }
    }

    /// Get the root hash of the tree
    pub fn root(self: *const Self) ?Node {
        if (self.nodes.items.len == 0) return null;
        return self.nodes.items[self.nodes.items.len - 1];
    }

    /// Create an inclusion proof for a leaf
    /// Reference: Firedancer fd_bmtree_inc_proof_from_tree
    pub fn createProof(self: *const Self, leaf_index: usize) !InclusionProof {
        if (leaf_index >= self.leaf_count) return error.InvalidLeafIndex;

        // Calculate tree depth
        var depth: usize = 0;
        var temp = self.leaf_count;
        while (temp > 1) : (temp = (temp + 1) / 2) {
            depth += 1;
        }

        var nodes = try self.allocator.alloc(Node, depth);
        errdefer self.allocator.free(nodes);
        var positions = try self.allocator.alloc(u1, depth);
        errdefer self.allocator.free(positions);

        var current_index = leaf_index;
        var level_start: usize = 0;
        var level_count = self.leaf_count;
        var proof_idx: usize = 0;

        while (level_count > 1 and proof_idx < depth) {
            // Find sibling
            const sibling_index = if (current_index % 2 == 0)
                current_index + 1
            else
                current_index - 1;

            // Position: 0 if we're on left, 1 if we're on right
            positions[proof_idx] = @intCast(current_index % 2);

            // Get sibling node (or self if at edge)
            if (sibling_index < level_count) {
                nodes[proof_idx] = self.nodes.items[level_start + sibling_index];
            } else {
                nodes[proof_idx] = self.nodes.items[level_start + current_index];
            }

            // Move to parent
            level_start += level_count;
            level_count = (level_count + 1) / 2;
            current_index = current_index / 2;
            proof_idx += 1;
        }

        return InclusionProof{
            .nodes = nodes[0..proof_idx],
            .positions = positions[0..proof_idx],
            .leaf_index = leaf_index,
        };
    }

    /// Verify an inclusion proof against a root
    /// Reference: Firedancer fd_bmtree_inc_proof_verify
    pub fn verifyProof(leaf: *const Node, proof: *const InclusionProof, expected_root: *const Node) bool {
        var current = leaf.*;

        for (proof.nodes, 0..) |sibling, i| {
            if (proof.positions[i] == 0) {
                // We're on left, sibling on right
                current = hashBranch(&current, &sibling);
            } else {
                // We're on right, sibling on left
                current = hashBranch(&sibling, &current);
            }
        }

        return std.mem.eql(u8, &current, expected_root);
    }
};

/// Shred Merkle tree for verifying shreds in an FEC set
/// Reference: Firedancer fd_bmtree_commit for shred verification
pub const ShredMerkleTree = struct {
    tree: MerkleTree,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .tree = MerkleTree.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.tree.deinit();
    }

    /// Add a shred to the tree (payload only, not signature)
    pub fn addShred(self: *Self, shred_data: []const u8) !void {
        // Hash the shred payload (skip the signature at offset 0..64)
        const payload = if (shred_data.len > 64) shred_data[64..] else shred_data;
        try self.tree.addLeaf(payload);
    }

    /// Finalize and get the root for signing
    pub fn finalize(self: *Self) !void {
        try self.tree.finalize();
    }

    /// Get the Merkle root that should be signed
    pub fn root(self: *const Self) ?Node {
        return self.tree.root();
    }

    /// Verify that a shred is part of the signed tree
    pub fn verifyShred(
        self: *const Self,
        shred_data: []const u8,
        shred_index: usize,
        signed_root: *const Node,
    ) !bool {
        // Hash the shred
        const payload = if (shred_data.len > 64) shred_data[64..] else shred_data;
        const leaf = MerkleTree.hashLeaf(payload);

        // Create and verify proof
        const proof = try self.tree.createProof(shred_index);
        defer @constCast(&proof).deinit(self.tree.allocator);

        return MerkleTree.verifyProof(&leaf, &proof, signed_root);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "merkle tree basic" {
    const allocator = std.testing.allocator;

    var tree = MerkleTree.init(allocator);
    defer tree.deinit();

    // Add some leaves
    try tree.addLeaf("leaf1");
    try tree.addLeaf("leaf2");
    try tree.addLeaf("leaf3");
    try tree.addLeaf("leaf4");

    try tree.finalize();

    const r = tree.root();
    try std.testing.expect(r != null);
}

test "merkle inclusion proof" {
    const allocator = std.testing.allocator;

    var tree = MerkleTree.init(allocator);
    defer tree.deinit();

    // Add 4 leaves
    try tree.addLeaf("leaf0");
    try tree.addLeaf("leaf1");
    try tree.addLeaf("leaf2");
    try tree.addLeaf("leaf3");

    try tree.finalize();

    const r = tree.root().?;

    // Create and verify proof for leaf 2
    var proof = try tree.createProof(2);
    defer proof.deinit(allocator);

    const leaf = MerkleTree.hashLeaf("leaf2");
    try std.testing.expect(MerkleTree.verifyProof(&leaf, &proof, &r));

    // Wrong leaf should fail
    const wrong_leaf = MerkleTree.hashLeaf("wrong");
    try std.testing.expect(!MerkleTree.verifyProof(&wrong_leaf, &proof, &r));
}

test "shred merkle tree" {
    const allocator = std.testing.allocator;

    var tree = ShredMerkleTree.init(allocator);
    defer tree.deinit();

    // Add some fake shreds (with 64-byte signature prefix)
    var shred1: [128]u8 = undefined;
    @memset(&shred1, 0xAA);
    try tree.addShred(&shred1);

    var shred2: [128]u8 = undefined;
    @memset(&shred2, 0xBB);
    try tree.addShred(&shred2);

    try tree.finalize();

    const r = tree.root().?;
    try std.testing.expect(try tree.verifyShred(&shred1, 0, &r));
    try std.testing.expect(try tree.verifyShred(&shred2, 1, &r));
}

test "solana merkle hashing" {
    const data = "test shred data";
    const leaf = MerkleTree.hashMerkleLeaf(data);
    try std.testing.expectEqual(@as(usize, 20), leaf.len);

    const leaf2 = MerkleTree.hashMerkleLeaf(data);
    try std.testing.expectEqualSlices(u8, &leaf, &leaf2);

    const node = MerkleTree.hashMerkleNode(&leaf, &leaf2);
    try std.testing.expectEqual(@as(usize, 20), node.len);
}

test "merkle root reconstruction" {
    // Height 2 tree (4 leaves)
    const l0 = MerkleTree.hashMerkleLeaf("leaf0");
    const l1 = MerkleTree.hashMerkleLeaf("leaf1");
    const l2 = MerkleTree.hashMerkleLeaf("leaf2");
    const l3 = MerkleTree.hashMerkleLeaf("leaf3");

    const n01 = MerkleTree.hashMerkleNode(&l0, &l1);
    const n23 = MerkleTree.hashMerkleNode(&l2, &l3);

    const root = MerkleTree.hashMerkleNode(&n01, &n23);

    // Proof for l2 (index 2)
    // Siblings are l3 (position 3) and n01 (position 0/1)
    var proof: [40]u8 = undefined;
    @memcpy(proof[0..20], l3[0..20]);
    @memcpy(proof[20..40], n01[0..20]);

    const reconstructed = MerkleTree.reconstructRoot(l2, &proof, 2);
    try std.testing.expectEqualSlices(u8, &root, &reconstructed);
}

test "makeMerkleProof: undersized out_proof returns error, never OOB-writes (2026-06-26 repair-path SIGABRT guard)" {
    // Regression for the SIGABRT at bmtree.zig:277, hit via FEC recovery
    // (drainRepairPackets → fec_resolver.recoverWithSigMethod) of a
    // malformed/adversarial REPAIR shred whose DECLARED proof byte-count (which
    // sizes the caller's out_proof, fec_resolver.zig:1512) is smaller than the
    // real proof depth = merkleProofLen(leaves.len). Must return a graceful
    // error (caller skips recovery → falls back to repair), never OOB-write.
    const allocator = std.testing.allocator;
    const size: usize = 64; // real FEC tree → merkleProofLen(64) = 6 entries
    const leaves = try allocator.alloc([MERKLE_NODE_SIZE]u8, size);
    defer allocator.free(leaves);
    for (0..size) |i| {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, @as(u64, i) *% 0x9E3779B97F4A7C15 +% 1, .little);
        leaves[i] = MerkleTree.hashMerkleLeaf(&buf);
    }
    // Correctly-sized buffer still succeeds (no false positive).
    const ok = try allocator.alloc([MERKLE_NODE_SIZE]u8, MerkleTree.merkleProofLen(size));
    defer allocator.free(ok);
    _ = try MerkleTree.makeMerkleProof(allocator, leaves, 1, ok);
    // Undersized (len 1 < 6) — the malformed-shred case that crashed: graceful error.
    var tiny: [1][MERKLE_NODE_SIZE]u8 = undefined;
    try std.testing.expectError(error.ProofBufferTooSmall, MerkleTree.makeMerkleProof(allocator, leaves, 1, tiny[0..]));
    // Zero-length buffer also guarded.
    try std.testing.expectError(error.ProofBufferTooSmall, MerkleTree.makeMerkleProof(allocator, leaves, 1, &[_][MERKLE_NODE_SIZE]u8{}));
}

test "makeMerkleProof round-trip — every leaf's proof reconstructs the root (Agave merkle_tree.rs round-trip parity)" {
    // Canonical mirror of Agave merkle_tree.rs run_merkle_tree_round_trip: for each
    // FEC-set size, build the tree, and for every leaf assert its emitted proof
    // reconstructs the SAME root (and a wrong leaf does NOT). This proves the
    // forward builder (makeMerkleProof) is the exact inverse of reconstructRoot and
    // matches Agave's odd-node (duplicate-last) + proof-sibling rules byte-for-byte.
    const allocator = std.testing.allocator;
    // Cover powers of two, odd counts, and the real 32/32→64 and 32/33→65 FEC shapes.
    const sizes = [_]usize{ 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 67, 110, 134 };
    for (sizes) |size| {
        // Deterministic distinct leaves: hashMerkleLeaf over the index bytes.
        const leaves = try allocator.alloc([MERKLE_NODE_SIZE]u8, size);
        defer allocator.free(leaves);
        for (0..size) |i| {
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, @as(u64, i) *% 0x9E3779B97F4A7C15 +% 1, .little);
            leaves[i] = MerkleTree.hashMerkleLeaf(&buf);
        }
        const plen = MerkleTree.merkleProofLen(size);
        const proof = try allocator.alloc([MERKLE_NODE_SIZE]u8, @max(plen, 1));
        defer allocator.free(proof);

        var reference_root: ?[MERKLE_NODE_SIZE]u8 = null;
        for (0..size) |k| {
            const root = try MerkleTree.makeMerkleProof(allocator, leaves, k, proof);
            // The flattened proof bytes for reconstructRoot:
            const proof_bytes = std.mem.sliceAsBytes(proof[0..plen]);
            const recon = MerkleTree.reconstructRoot(leaves[k], proof_bytes, k);
            try std.testing.expectEqualSlices(u8, &root, &recon);
            // Root must be identical across all leaves of the same tree.
            if (reference_root) |rr| {
                try std.testing.expectEqualSlices(u8, &rr, &root);
            } else reference_root = root;
            // A DIFFERENT leaf must NOT reconstruct the root with k's proof
            // (guards against a degenerate all-collapse-to-same builder), size>1.
            if (size > 1) {
                const wrong_leaf = leaves[(k + 1) % size];
                const wrong = MerkleTree.reconstructRoot(wrong_leaf, proof_bytes, k);
                try std.testing.expect(!std.mem.eql(u8, &root, &wrong));
            }
        }
    }
}
