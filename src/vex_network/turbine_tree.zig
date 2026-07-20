//! Vexor Turbine Tree
//!
//! Implements the Solana Turbine protocol for shred propagation.
//! Based on Sig (Zig) and Firedancer (C) implementations.
//!
//! The Turbine tree is a stake-weighted broadcast tree that determines
//! which validators should receive shreds and in what order.
//!
//! Key concepts:
//! - Nodes are sorted by (stake, pubkey) in descending order
//! - A deterministic weighted shuffle is computed for each shred
//! - The seed is SHA256(slot || shred_type || index || leader_pubkey)
//! - Children are computed based on position in the shuffled tree
//!
//! @prov:turbine.tree

const std = @import("std");
const core = @import("core");
const crypto = @import("vex_crypto");
const gossip = @import("gossip.zig");
const packet = @import("packet.zig");
const ws_mod = @import("weighted_shuffle.zig");

/// Maximum fanout (number of children per node)
pub const DATA_PLANE_FANOUT: usize = 200;

/// Maximum depth of the turbine tree
pub const MAX_TURBINE_TREE_DEPTH: usize = 4;

/// Maximum nodes per IP address (for Sybil protection)
pub const MAX_NODES_PER_IP_ADDRESS: usize = 10;

/// A node in the Turbine tree
pub const TurbineNode = struct {
    pubkey: core.Pubkey,
    stake: u64,
    tvu_addr: ?packet.SocketAddr,

    /// Compare nodes for sorting (descending by stake, then by pubkey)
    pub fn lessThan(_: void, a: TurbineNode, b: TurbineNode) bool {
        if (a.stake != b.stake) {
            return a.stake > b.stake; // Higher stake first
        }
        // Tie-break by pubkey (descending lexicographic)
        return std.mem.order(u8, &a.pubkey.data, &b.pubkey.data) == .gt;
    }
};

/// Shred identifier for seeding the shuffle
pub const ShredId = struct {
    slot: u64,
    index: u32,
    shred_type: ShredType,

    pub const ShredType = enum(u8) {
        data = 0xA5,
        code = 0x5A,
    };
};

/// Result of tree search/placement
pub const TurbineSearchResult = struct {
    my_index: usize,
    root_distance: usize,
};

/// Turbine Tree for computing shred destinations
pub const TurbineTree = struct {
    allocator: std.mem.Allocator,
    my_pubkey: core.Pubkey,

    /// All nodes sorted by (stake, pubkey) descending
    nodes: std.ArrayListUnmanaged(TurbineNode),

    /// Pubkey -> index in nodes
    index_map: std.AutoHashMap([32]u8, usize),

    /// Stakes for weighted shuffle
    stakes: std.ArrayListUnmanaged(u64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, my_pubkey: core.Pubkey) Self {
        return .{
            .allocator = allocator,
            .my_pubkey = my_pubkey,
            .nodes = .empty,
            .index_map = std.AutoHashMap([32]u8, usize).init(allocator),
            .stakes = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.nodes.deinit(self.allocator);
        self.index_map.deinit();
        self.stakes.deinit(self.allocator);
    }

    /// Build the tree from gossip peers and stake information
    pub fn build(
        self: *Self,
        gossip_peers: []const gossip.ContactInfo,
        staked_nodes: *const std.AutoHashMap([32]u8, u64),
    ) !void {
        self.nodes.clearRetainingCapacity();
        self.index_map.clearRetainingCapacity();
        self.stakes.clearRetainingCapacity();

        // Track seen pubkeys to avoid duplicates
        var seen = std.AutoHashMap([32]u8, void).init(self.allocator);
        defer seen.deinit();

        // Add ourselves first
        const my_stake = staked_nodes.get(self.my_pubkey.data) orelse 0;
        try self.nodes.append(self.allocator, .{
            .pubkey = self.my_pubkey,
            .stake = my_stake,
            .tvu_addr = null, // We don't send to ourselves
        });
        try seen.put(self.my_pubkey.data, {});

        // Add gossip peers with TVU addresses
        for (gossip_peers) |peer| {
            if (seen.contains(peer.pubkey.data)) continue;

            const stake = staked_nodes.get(peer.pubkey.data) orelse 0;
            try self.nodes.append(self.allocator, .{
                .pubkey = peer.pubkey,
                .stake = stake,
                .tvu_addr = peer.tvu_addr,
            });
            try seen.put(peer.pubkey.data, {});
        }

        // Add staked nodes without contact info (for deterministic shuffle)
        var stake_iter = staked_nodes.iterator();
        while (stake_iter.next()) |entry| {
            if (seen.contains(entry.key_ptr.*)) continue;
            if (entry.value_ptr.* == 0) continue; // Skip zero-stake

            try self.nodes.append(self.allocator, .{
                .pubkey = .{ .data = entry.key_ptr.* },
                .stake = entry.value_ptr.*,
                .tvu_addr = null,
            });
        }

        // Sort by (stake desc, pubkey desc)
        std.mem.sort(TurbineNode, self.nodes.items, {}, TurbineNode.lessThan);

        // Build index map and stakes array
        for (self.nodes.items, 0..) |node, i| {
            try self.index_map.put(node.pubkey.data, i);
            try self.stakes.append(self.allocator, node.stake);
        }
    }

    /// Compute the seed for the weighted shuffle
    /// seed = SHA256(slot || shred_type || index || leader_pubkey)
    fn computeSeed(slot: u64, shred_id: ShredId, leader: core.Pubkey) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Slot (little-endian)
        var slot_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &slot_bytes, slot, .little);
        hasher.update(&slot_bytes);

        // Shred type
        hasher.update(&[_]u8{@intFromEnum(shred_id.shred_type)});

        // Index (little-endian)
        var index_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &index_bytes, shred_id.index, .little);
        hasher.update(&index_bytes);

        // Leader pubkey
        hasher.update(&leader.data);

        return hasher.finalResult();
    }

    /// LEADER broadcast target: the FIRST node of the stake-weighted shuffle.
    /// @prov:turbine.broadcast-peer
    ///   `weighted_shuffle.first(&mut TurbineRng::new_seeded(&pubkey, shred, use_cha_cha_8))`
    /// The leader sends each shred to exactly ONE root node; that node roots the retransmit tree.
    /// Pipeline (all byte-exact, KAT'd in weighted_shuffle.zig against upstream vectors):
    ///   seed = sha256(slot_LE ‖ type_byte ‖ index_LE ‖ leader)        (== ShredId::seed)
    ///   rng  = ChaCha8 if use_cha_cha_8 else ChaCha20                  (rand_chacha 0.3 layout)
    ///   ws   = WeightedShuffle(stakes); ws.removeIndex(leader)          (excludes the leader)
    ///   root = ws.first(rng)                                           (Fenwick FANOUT=16 search)
    ///
    /// `use_cha_cha_8` MUST reflect the cluster's switch_to_chacha8_turbine (SIMD-0332) activation
    /// (ACTIVE on testnet since epoch 909 / slot 387164256) — a wrong variant picks a different seed
    /// stream → a different root than the cluster expects.
    ///
    /// LIVENESS-only: a correctly-signed shred sent to the "wrong" root is still accepted and
    /// re-propagated, so this never affects block validity — only first-hop fan-out efficiency.
    pub fn getBroadcastPeer(self: *Self, leader: core.Pubkey, shred_id: ShredId, use_cha_cha_8: bool) !?TurbineNode {
        if (self.nodes.items.len == 0) return null;
        const seed = computeSeed(shred_id.slot, shred_id, leader);

        var ws = try ws_mod.WeightedShuffle.init(self.allocator, self.stakes.items);
        defer ws.deinit();
        if (self.index_map.get(leader.data)) |leader_idx| ws.removeIndex(leader_idx);

        const idx = if (use_cha_cha_8) blk: {
            var rng = ws_mod.ChaCha8Rng.fromSeed(seed);
            break :blk ws.first(&rng);
        } else blk: {
            var rng = ws_mod.ChaCha20Rng.fromSeed(seed);
            break :blk ws.first(&rng);
        };
        if (idx) |i| return self.nodes.items[i];
        return null;
    }

    /// Get my position and children in the shuffled tree for a specific shred
    /// Returns: (my_index, root_distance, children)
    ///
    /// @prov:turbine.retransmit-children — uses the SAME canonical ws_mod ChaCha +
    /// WeightedShuffle primitives as getBroadcastPeer (KAT'd in test-turbine-shuffle),
    /// so the retransmit tree matches the cluster's. The
    /// caller must thread `use_cha_cha_8` from the cluster's switch_to_chacha8_turbine
    /// (SIMD-0332) state — the SAME flag getBroadcastPeer takes — else the shuffle
    /// stream diverges from the network's. LIVENESS-only: a wrong-stream child set
    /// only degrades fan-out efficiency, never block validity (no bank_hash effect).
    ///
    /// 2026-06-21 REVIVAL NOTE: this body previously referenced the non-existent
    /// `crypto.ChaChaRng`/`crypto.WeightedShuffle(u64)` and used the managed
    /// (pre-0.15.2) ArrayList API, so it was dead (un-analyzed — its only caller
    /// `getRetransmitChildrenForShred` was itself dead since `broadcastShred` was
    /// removed, tvu.zig:2361). Rewritten to use `ws_mod` (the real primitives) +
    /// the Zig-0.15.2 unmanaged ArrayList API so the gated turbine-retransmit path
    /// (-Dturbine_retransmit) can instantiate it. Children-selection math
    /// (computeRetransmitChildrenFromShuffled) is unchanged + KAT'd.
    pub fn getRetransmitChildren(
        self: *Self,
        children: *std.ArrayList(TurbineNode),
        leader: core.Pubkey,
        shred_id: ShredId,
        fanout: usize,
        use_cha_cha_8: bool,
    ) !TurbineSearchResult {
        children.clearRetainingCapacity();

        if (self.nodes.items.len == 0) {
            return TurbineSearchResult{ .my_index = 0, .root_distance = 0 };
        }

        // @prov:turbine.retransmit-children — shuffle seed, byte-exact, KAT'd computeSeed
        const seed = computeSeed(shred_id.slot, shred_id, leader);

        // Create weighted shuffle from stakes (ws_mod = the canonical primitive)
        var weighted_shuffle = try ws_mod.WeightedShuffle.init(self.allocator, self.stakes.items);
        defer weighted_shuffle.deinit();

        // Remove leader from shuffle if present (leader doesn't participate in retransmit)
        if (self.index_map.get(leader.data)) |leader_idx| {
            weighted_shuffle.removeIndex(leader_idx);
        }

        // Perform the weighted shuffle and collect indices. shuffle() is DESTRUCTIVE
        // (consumes weighted_shuffle), which is fine here — we discard it after.
        // ChaCha8 vs ChaCha20 must match the cluster's SIMD-0332 activation.
        var shuffled = try std.ArrayList(usize).initCapacity(self.allocator, self.nodes.items.len);
        defer shuffled.deinit(self.allocator);

        if (use_cha_cha_8) {
            var rng = ws_mod.ChaCha8Rng.fromSeed(seed);
            var shuffle_iter = weighted_shuffle.shuffle(&rng);
            while (shuffle_iter.next()) |idx| {
                try shuffled.append(self.allocator, idx);
            }
        } else {
            var rng = ws_mod.ChaCha20Rng.fromSeed(seed);
            var shuffle_iter = weighted_shuffle.shuffle(&rng);
            while (shuffle_iter.next()) |idx| {
                try shuffled.append(self.allocator, idx);
            }
        }

        // Find my position in the shuffled list
        // Logical indices: Leader = 0, Retransmitters = 1..N
        var my_index: usize = 0;
        var found_self = false;

        if (std.mem.eql(u8, &leader.data, &self.my_pubkey.data)) {
            my_index = 0;
            found_self = true;
        } else {
            for (shuffled.items, 0..) |idx, pos| {
                if (std.mem.eql(u8, &self.nodes.items[idx].pubkey.data, &self.my_pubkey.data)) {
                    my_index = pos + 1;
                    found_self = true;
                    break;
                }
            }
        }

        if (!found_self) {
            // We're not in the shuffle and not the leader (shouldn't happen)
            return TurbineSearchResult{ .my_index = 0, .root_distance = 0 };
        }

        // Compute root distance
        // root (0) -> layer 1 [1, fanout] -> layer 2 [fanout+1, fanout*(fanout+1)] -> layer 3+
        const root_distance: usize = if (my_index == 0)
            0
        else if (my_index <= fanout)
            1
        else if (my_index <= (fanout +| 1) *| fanout)
            2
        else
            3;

        // Compute retransmit children based on position in tree
        // Tree structure:
        // root (0) -> children [1, 2, ..., fanout]
        // node k in layer 1 -> children [fanout + k, 2*fanout + k, ..., fanout*fanout + k]
        try children.ensureTotalCapacity(self.allocator, fanout);

        computeRetransmitChildrenFromShuffled(children, fanout, my_index, shuffled.items, self.nodes.items);

        return TurbineSearchResult{ .my_index = my_index, .root_distance = root_distance };
    }

    /// Compute retransmit children from shuffled node list
    /// This matches Sig's computeRetransmitChildren function
    fn computeRetransmitChildrenFromShuffled(
        children: *std.ArrayList(TurbineNode),
        fanout: usize,
        index: usize,
        shuffled: []const usize,
        nodes: []const TurbineNode,
    ) void {
        const offset = if (index == 0) 0 else (index -| 1) % fanout;
        const anchor = index - offset;
        const step: usize = if (index == 0) 1 else fanout;
        var curr = anchor * fanout + offset + 1;
        var steps: usize = 0;

        while (curr <= shuffled.len and steps < fanout) {
            const node_idx = shuffled[curr - 1];
            const node = nodes[node_idx];
            // Only add nodes with valid TVU addresses
            if (node.tvu_addr != null) {
                children.appendAssumeCapacity(node);
            }
            curr += step;
            steps += 1;
        }
    }

    /// Get the number of nodes in the tree
    pub fn nodeCount(self: *const Self) usize {
        return self.nodes.items.len;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "turbine tree init" {
    const allocator = std.testing.allocator;
    const my_pubkey: core.Pubkey = .{ .data = [_]u8{0x11} ** 32 };

    var tree = TurbineTree.init(allocator, my_pubkey);
    defer tree.deinit();

    try std.testing.expectEqual(@as(usize, 0), tree.nodeCount());
}

test "turbine node sorting" {
    const nodes = [_]TurbineNode{
        .{ .pubkey = .{ .data = [_]u8{0x01} ** 32 }, .stake = 100, .tvu_addr = null },
        .{ .pubkey = .{ .data = [_]u8{0x02} ** 32 }, .stake = 200, .tvu_addr = null },
        .{ .pubkey = .{ .data = [_]u8{0x03} ** 32 }, .stake = 100, .tvu_addr = null },
    };

    var sorted = nodes;
    std.mem.sort(TurbineNode, &sorted, {}, TurbineNode.lessThan);

    // Highest stake first
    try std.testing.expectEqual(@as(u64, 200), sorted[0].stake);
    // Then by pubkey descending for equal stakes
    try std.testing.expectEqual(@as(u8, 0x03), sorted[1].pubkey.data[0]);
    try std.testing.expectEqual(@as(u8, 0x01), sorted[2].pubkey.data[0]);
}

test "compute seed deterministic" {
    const leader = core.Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const shred_id = ShredId{
        .slot = 12345,
        .index = 42,
        .shred_type = .data,
    };

    const seed1 = TurbineTree.computeSeed(12345, shred_id, leader);
    const seed2 = TurbineTree.computeSeed(12345, shred_id, leader);

    try std.testing.expectEqualSlices(u8, &seed1, &seed2);
}

// @prov:turbine.compute-seed-kat — computeSeed GOLDEN VECTORS, proves computeSeed
// is byte-faithful: SHA256(slot.to_le_bytes ‖ u8(shred_type)
// ‖ index.to_le_bytes ‖ leader), with ShredType Data=0b1010_0101=0xA5,
// Code=0b0101_1010=0x5A. The test-turbine-shuffle KATs start from FIXED seeds, so
// they NEVER exercise this function — without these vectors a type-byte / index-width
// / endianness / field-order slip would be silently masked (and the canonical-root-by-
// composition claim would be unsound). Expected bytes computed independently (python
// SHA256 over the exact Agave byte layout). See blockprod-turbine-uniform-stake-
// rootcause-2026-06-20.
test "computeSeed golden vector A (Data type, slot 12345, index 42, leader 0xAA)" {
    const leader = core.Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const sid = ShredId{ .slot = 12345, .index = 42, .shred_type = .data };
    const got = TurbineTree.computeSeed(12345, sid, leader);
    const want = [_]u8{ 0xaf, 0x61, 0xda, 0x4d, 0xfe, 0xac, 0x47, 0x34, 0x7a, 0x95, 0x2c, 0x1e, 0xb8, 0x88, 0xea, 0xd2, 0x78, 0xa7, 0xcd, 0x9e, 0xec, 0xde, 0xe6, 0x49, 0x58, 0x81, 0x14, 0xad, 0x28, 0xcc, 0xf5, 0x14 };
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "computeSeed golden vector B (Code type, slot 416687408, index 0, leader 0x11)" {
    // Distinct shred_type (Code=0x5A) + a real-scale slot exercise the type byte and
    // u64 LE width that vector A's small values don't fully stress.
    const leader = core.Pubkey{ .data = [_]u8{0x11} ** 32 };
    const sid = ShredId{ .slot = 416687408, .index = 0, .shred_type = .code };
    const got = TurbineTree.computeSeed(416687408, sid, leader);
    const want = [_]u8{ 0x6a, 0x42, 0x23, 0x7a, 0xb5, 0xbc, 0x80, 0xb4, 0xf1, 0x30, 0xe3, 0x5e, 0x90, 0x6a, 0xb2, 0x1e, 0xa4, 0xcc, 0x04, 0x89, 0x94, 0xf2, 0xd2, 0xd3, 0x60, 0xb2, 0xdd, 0xbe, 0xa0, 0x04, 0xa1, 0x5a };
    try std.testing.expectEqualSlices(u8, &want, &got);
}

// Guards the ShredType enum values themselves (the byte hashed into the seed).
test "ShredType byte values match Agave u8(ShredType)" {
    try std.testing.expectEqual(@as(u8, 0xA5), @intFromEnum(ShredId.ShredType.data));
    try std.testing.expectEqual(@as(u8, 0x5A), @intFromEnum(ShredId.ShredType.code));
}

// @prov:turbine.get-nodes-kat — get_nodes membership + ordering KAT (2026-06-20)
// Proves TurbineTree.build() produces the byte-faithful `get_nodes`
// ordered node list for a fixed input: [self] ++ gossip
// tvu_peers ++ ALL staked-with-stake>0 (contactless), deduped by pubkey, sorted
// DESC(stake, pubkey). This is the load-bearing INPUT side of the broadcast-root
// fix (the uniform-1000 stub fed garbage); composed with the already-KAT'd
// weighted_shuffle.first primitive (test-turbine-shuffle, Agave vectors) it proves
// getBroadcastPeer returns the canonical root by composition. Pure membership/
// ordering — no rng. Expected orderings hand-derived from TurbineNode.lessThan
// (DESC stake, then DESC pubkey). See memory blockprod-turbine-uniform-stake-
// rootcause-2026-06-20.

fn katPk(b: u8) core.Pubkey {
    return .{ .data = [_]u8{b} ** 32 };
}

/// A ContactInfo with everything UNSPECIFIED except identity + TVU addr — the only
/// two fields build() reads. Distinct TVU per node so a later dedup_tvu_addrs test
/// (Tier 2) can tell them apart; here it just makes tvu_addr non-default.
fn katPeer(b: u8) gossip.ContactInfo {
    const a = packet.SocketAddr.UNSPECIFIED;
    return .{
        .pubkey = katPk(b),
        .gossip_addr = a,
        .tpu_addr = a,
        .tpu_fwd_addr = a,
        .tpu_vote_addr = a,
        .tvu_addr = packet.SocketAddr.ipv4(.{ 127, 0, 0, b }, 8003),
        .tvu_fwd_addr = a,
        .repair_addr = a,
        .rpc_addr = a,
        .serve_repair_addr = a,
        .tpu_quic_addr = a,
        .tpu_vote_quic_addr = a,
        .tvu_quic_addr = a,
        .wallclock = 0,
        .shred_version = 1516,
        .version = .{ .major = 0, .minor = 0, .patch = 0, .commit = null },
    };
}

const KatExpect = struct { pk: u8, stake: u64, has_tvu: bool };

fn katBuildAndCheck(
    self_b: u8,
    peers: []const gossip.ContactInfo,
    staked_kv: []const struct { k: u8, v: u64 },
    expect: []const KatExpect,
) !void {
    const a = std.testing.allocator;
    var staked = std.AutoHashMap([32]u8, u64).init(a);
    defer staked.deinit();
    for (staked_kv) |e| try staked.put(katPk(e.k).data, e.v);

    var tree = TurbineTree.init(a, katPk(self_b));
    defer tree.deinit();
    try tree.build(peers, &staked);

    try std.testing.expectEqual(expect.len, tree.nodes.items.len);
    for (tree.nodes.items, expect) |node, want| {
        try std.testing.expectEqual(want.pk, node.pubkey.data[0]);
        try std.testing.expectEqual(want.stake, node.stake);
        try std.testing.expectEqual(want.has_tvu, node.tvu_addr != null);
    }
    // Stakes array must parallel nodes (the WeightedShuffle input order).
    try std.testing.expectEqual(expect.len, tree.stakes.items.len);
    for (tree.stakes.items, expect) |s, want| try std.testing.expectEqual(want.stake, s);
}

test "get_nodes KAT: equal-stake pubkey tiebreak (DESC pubkey)" {
    // self=0x11, peers 0x22/0x33, all stake 50. DESC stake then DESC pubkey: 33,22,11.
    const peers = [_]gossip.ContactInfo{ katPeer(0x22), katPeer(0x33) };
    try katBuildAndCheck(0x11, &peers, &.{ .{ .k = 0x11, .v = 50 }, .{ .k = 0x22, .v = 50 }, .{ .k = 0x33, .v = 50 } }, &.{
        .{ .pk = 0x33, .stake = 50, .has_tvu = true },
        .{ .pk = 0x22, .stake = 50, .has_tvu = true },
        .{ .pk = 0x11, .stake = 50, .has_tvu = false }, // self: tvu=null
    });
}

test "get_nodes KAT: contactless staked node is a member (DESC stake)" {
    // self=0x11 stake 10; peer 0x22 stake 100; 0x44 stake 1000 NOT in gossip (contactless).
    // @prov:turbine.get-nodes-kat — contactless staked node included. DESC stake: 44(1000),22(100),11(10).
    // 0x44 has_tvu=false → if first() lands on it getBroadcastPeer→null→shred dropped (== Agave).
    const peers = [_]gossip.ContactInfo{katPeer(0x22)};
    try katBuildAndCheck(0x11, &peers, &.{ .{ .k = 0x11, .v = 10 }, .{ .k = 0x22, .v = 100 }, .{ .k = 0x44, .v = 1000 } }, &.{
        .{ .pk = 0x44, .stake = 1000, .has_tvu = false },
        .{ .pk = 0x22, .stake = 100, .has_tvu = true },
        .{ .pk = 0x11, .stake = 10, .has_tvu = false },
    });
}

test "get_nodes KAT: zero-stake gossip peer kept, ordered after staked (zeros lemma)" {
    // self=0x11 stake 100; peer 0x55 NOT in staked map → stake 0. Agave keeps it (has TVU)
    // but weight 0 → zeros tail, invisible to first(). Order: 11(100) then 55(0).
    const peers = [_]gossip.ContactInfo{katPeer(0x55)};
    try katBuildAndCheck(0x11, &peers, &.{.{ .k = 0x11, .v = 100 }}, &.{
        .{ .pk = 0x11, .stake = 100, .has_tvu = false },
        .{ .pk = 0x55, .stake = 0, .has_tvu = true },
    });
}

test "get_nodes KAT: peer+staked dedup keeps one node with contact-info" {
    // 0x22 is BOTH a gossip peer AND in the staked map → must appear once, WITH tvu
    // (the peer-loop adds it first with tvu + real stake; contactless loop skips seen).
    const peers = [_]gossip.ContactInfo{katPeer(0x22)};
    try katBuildAndCheck(0x11, &peers, &.{ .{ .k = 0x11, .v = 5 }, .{ .k = 0x22, .v = 77 } }, &.{
        .{ .pk = 0x22, .stake = 77, .has_tvu = true },
        .{ .pk = 0x11, .stake = 5, .has_tvu = false },
    });
}

// ── getRetransmitChildren REVIVAL KATs (2026-06-21, -Dturbine_retransmit) ─────
// These INSTANTIATE getRetransmitChildren (which was dead/un-analyzed before the
// ws_mod rewrite) and prove the gated turbine-retransmit path computes a sane,
// deterministic, leader-excluded, fanout-bounded child set whose targets are
// exactly the TVU addresses relayShred will send to. Proven here:
//   1. determinism — same (slot,index,type,variant) → byte-identical children.
//   2. leader exclusion — the leader is never a retransmit target.
//   3. self exclusion — we never retransmit to ourselves.
//   4. TVU validity — every child has a tvu_addr (computeRetransmitChildren-
//      FromShuffled drops tvu==null), so the captured send-target list == children.
//   5. fanout bound — children.len <= DATA_PLANE_FANOUT (tree-bounded ~200).
//   6. variant sensitivity — ChaCha8 vs ChaCha20 can select different children
//      (use_cha_cha_8 is load-bearing; must match the cluster's SIMD-0332 state).
// NOT proven here (honest boundary): byte-exact agreement with Agave's *specific*
// child set for a real cluster (no Agave golden vector for getRetransmitChildren —
// only the seed + weighted_shuffle.first primitives are KAT'd against Agave). This
// proves the wiring/selection is internally canonical + safe, not network-identical.

/// Build a tree where `self` is a non-leader retransmitter among N staked TVU peers.
fn katRetransmitTree(a: std.mem.Allocator, self_b: u8, peer_bytes: []const u8) !TurbineTree {
    var staked = std.AutoHashMap([32]u8, u64).init(a);
    defer staked.deinit();
    // Give every node a distinct non-zero stake so the shuffle is fully ordered
    // (no zeros-tail ambiguity) and self is a visible retransmitter.
    try staked.put(katPk(self_b).data, 1000);
    var peers = std.ArrayList(gossip.ContactInfo){};
    defer peers.deinit(a);
    for (peer_bytes, 0..) |pb, i| {
        try staked.put(katPk(pb).data, 100 + @as(u64, @intCast(i)) * 10);
        try peers.append(a, katPeer(pb));
    }
    var tree = TurbineTree.init(a, katPk(self_b));
    try tree.build(peers.items, &staked);
    return tree;
}

test "getRetransmitChildren KAT: deterministic, leader+self excluded, tvu-valid, fanout-bounded" {
    const a = std.testing.allocator;
    // self=0x11; 8 peers; leader=0x99 is NOT self and NOT a peer (external leader).
    const peer_bytes = [_]u8{ 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xAA };
    var tree = try katRetransmitTree(a, 0x11, &peer_bytes);
    defer tree.deinit();
    // leader must be a tree member for index_map.removeIndex to fire; use a peer
    // as leader (0xAA) so leader-exclusion is actually exercised.
    const leader = katPk(0xAA);
    const sid = ShredId{ .slot = 416687408, .index = 7, .shred_type = .data };

    var c1 = std.ArrayList(TurbineNode){};
    defer c1.deinit(a);
    var c2 = std.ArrayList(TurbineNode){};
    defer c2.deinit(a);

    _ = try tree.getRetransmitChildren(&c1, leader, sid, DATA_PLANE_FANOUT, true);
    _ = try tree.getRetransmitChildren(&c2, leader, sid, DATA_PLANE_FANOUT, true);

    // (1) determinism: identical children across two calls (same pubkeys, same order)
    try std.testing.expectEqual(c1.items.len, c2.items.len);
    for (c1.items, c2.items) |x, y| try std.testing.expectEqualSlices(u8, &x.pubkey.data, &y.pubkey.data);

    // (5) fanout bound
    try std.testing.expect(c1.items.len <= DATA_PLANE_FANOUT);

    for (c1.items) |child| {
        // (3) self exclusion
        try std.testing.expect(!std.mem.eql(u8, &child.pubkey.data, &katPk(0x11).data));
        // (2) leader exclusion
        try std.testing.expect(!std.mem.eql(u8, &child.pubkey.data, &leader.data));
        // (4) TVU validity — these ARE the addresses relayShred sends to
        try std.testing.expect(child.tvu_addr != null);
    }
}

test "getRetransmitChildren KAT: use_cha_cha_8 variant is load-bearing" {
    // The per-node *children* slice can coincide between variants for a small tree
    // (a child set is only one slice of the permutation), so we assert the variant
    // matters where it is deterministic: the FULL weighted-shuffle ORDER that
    // getRetransmitChildren consumes. ChaCha8 vs ChaCha20 over the same seed/stakes
    // MUST yield a different permutation — proving use_cha_cha_8 is not ignored.
    const a = std.testing.allocator;
    const peer_bytes = [_]u8{ 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xAA, 0xBB, 0xCC };
    var tree = try katRetransmitTree(a, 0x11, &peer_bytes);
    defer tree.deinit();
    const leader = katPk(0xCC);
    const sid = ShredId{ .slot = 12345, .index = 3, .shred_type = .code };
    const seed = TurbineTree.computeSeed(sid.slot, sid, leader);

    const Helper = struct {
        fn order(alloc: std.mem.Allocator, stakes: []const u64, ldr_idx: ?usize, s: [32]u8, use8: bool, out: *std.ArrayList(usize)) !void {
            var ws = try ws_mod.WeightedShuffle.init(alloc, stakes);
            defer ws.deinit();
            if (ldr_idx) |li| ws.removeIndex(li);
            if (use8) {
                var rng = ws_mod.ChaCha8Rng.fromSeed(s);
                var it = ws.shuffle(&rng);
                while (it.next()) |i| try out.append(alloc, i);
            } else {
                var rng = ws_mod.ChaCha20Rng.fromSeed(s);
                var it = ws.shuffle(&rng);
                while (it.next()) |i| try out.append(alloc, i);
            }
        }
    };
    const leader_idx = tree.index_map.get(leader.data);

    var o8 = std.ArrayList(usize){};
    defer o8.deinit(a);
    var o20 = std.ArrayList(usize){};
    defer o20.deinit(a);
    try Helper.order(a, tree.stakes.items, leader_idx, seed, true, &o8);
    try Helper.order(a, tree.stakes.items, leader_idx, seed, false, &o20);

    try std.testing.expectEqual(o8.items.len, o20.items.len);
    var differ = false;
    for (o8.items, o20.items) |x, y| {
        if (x != y) {
            differ = true;
            break;
        }
    }
    try std.testing.expect(differ);

    // And both variants still produce valid, bounded, tvu-only child sets.
    var c8 = std.ArrayList(TurbineNode){};
    defer c8.deinit(a);
    var c20 = std.ArrayList(TurbineNode){};
    defer c20.deinit(a);
    _ = try tree.getRetransmitChildren(&c8, leader, sid, DATA_PLANE_FANOUT, true);
    _ = try tree.getRetransmitChildren(&c20, leader, sid, DATA_PLANE_FANOUT, false);
    try std.testing.expect(c8.items.len <= DATA_PLANE_FANOUT);
    try std.testing.expect(c20.items.len <= DATA_PLANE_FANOUT);
    for (c8.items) |ch| try std.testing.expect(ch.tvu_addr != null);
    for (c20.items) |ch| try std.testing.expect(ch.tvu_addr != null);
}

test "getRetransmitChildren KAT: empty tree no-ops safely" {
    const a = std.testing.allocator;
    var tree = TurbineTree.init(a, katPk(0x11));
    defer tree.deinit();
    var children = std.ArrayList(TurbineNode){};
    defer children.deinit(a);
    const sid = ShredId{ .slot = 1, .index = 0, .shred_type = .data };
    const res = try tree.getRetransmitChildren(&children, katPk(0xAA), sid, DATA_PLANE_FANOUT, true);
    try std.testing.expectEqual(@as(usize, 0), children.items.len);
    try std.testing.expectEqual(@as(usize, 0), res.my_index);
}
