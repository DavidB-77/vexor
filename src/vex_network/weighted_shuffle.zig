//! Vexor WeightedShuffle — byte-exact port of Agave's turbine weighted shuffle.
//!
//! Canonical references (verified against agave 4.1.0-beta.3 source == rc.0 algorithm, unchanged):
//!   - WeightedShuffle (Fenwick FANOUT=16 tree): agave gossip/src/weighted_shuffle.rs:32-215
//!     (new/remove/search/remove_index/first/shuffle/get_num_nodes_and_tree_size).
//!   - UniformU64Sampler::new_like_trait_sample / sample: agave random/src/range.rs:47-67
//!     (agave-random crate; first()/shuffle() use new_like_trait_sample, NOT instance_sample).
//!   - ChaCha8/20 RNG: gossip pins `rand_chacha = "0.9.0"` (workspace Cargo.toml). 0.9.0 wraps
//!     a rand_core BlockRng over a 64-u32 (4-block) buffer (refill4); the broadcast path draws
//!     ONLY via next_u64 (sampler.sample → rng.random::<u64>()), and since the block width (16)
//!     and buffer width (64) are both even, u64 word-pairs never straddle a block boundary —
//!     so this single-16-u32-block model is byte-stream-IDENTICAL to 0.9.0 for the next_u64 path.
//!     PROVEN: a Rust harness showed rand_chacha 0.9.0 == 0.3.1 ChaCha8 output for these vectors,
//!     and the KATs below reproduce Agave's hard-coded vectors (which were generated under 0.9.0).
//!     ChaCha8 = 4 double-rounds (8 rounds); ChaCha20 = 10. Counter at state[12..14], LE.
//!     ⚠️ GUARDRAIL: this equivalence holds ONLY for the next_u64-exclusive path. If anything ever
//!     adds a next_u32 or fill_bytes call on the broadcast RNG, re-verify against 0.9.0's BlockRng
//!     (shared 64-word index) before trusting the stream.
//!   - get_broadcast_peer: agave turbine/src/cluster_nodes.rs:259-263
//!     `weighted_shuffle.first(&mut TurbineRng::new_seeded(pubkey, shred, use_cha_cha_8))`.
//!
//! WHY this module exists (2026-06-17, C1): the pre-existing `turbine_tree.zig:getBroadcastPeer`
//! referenced `crypto.WeightedShuffle` / `crypto.ChaChaRng` which DO NOT EXIST in vex_crypto — it
//! was dead code (0 callers) that Zig never semantically analyzed, so it never compiled its shuffle.
//! This module supplies the real, compiling, byte-exact primitives.
//!
//! CONSENSUS NOTE: the broadcast root must be the SAME node the cluster's retransmit stage expects,
//! else the shred is still accepted+re-propagated (liveness-only) but first-hop fan-out diverges.
//! switch_to_chacha8_turbine (SIMD-0332) is ACTIVE on testnet since epoch 909 (slot 387164256), so
//! the live path MUST use ChaCha8. ChaCha20 is retained for the pre-activation/KAT path.

const std = @import("std");

// Fenwick-tree fanout (Agave weighted_shuffle.rs:21-23).
const BIT_SHIFT: usize = 4;
const FANOUT: usize = 1 << BIT_SHIFT; // 16
const BIT_MASK: usize = FANOUT - 1; // 15

// ─────────────────────────────────────────────────────────────────────────
// ChaCha RNG (8- and 20-round), rand_chacha-0.3.1 layout.
// ─────────────────────────────────────────────────────────────────────────

/// ChaCha block RNG parameterised by the number of DOUBLE-rounds.
/// `double_rounds = 4` → ChaCha8 (rand_chacha ChaCha8Rng); `= 10` → ChaCha20.
///
/// State layout (rand_chacha 0.9.0; stream-identical to 0.3.x for the next_u64-only path):
///   [0..4]   constants "expand 32-byte k"
///   [4..12]  key (seed, 32 bytes LE)
///   [12..14] 64-bit block counter (starts 0)
///   [14..16] 64-bit stream id (starts 0)
/// Each refill emits one 64-byte (16-u32) keystream block consumed in index order;
/// `nextU64` packs two consecutive u32 words little-endian (== rand_chacha next_u64).
pub fn ChaChaRngGeneric(comptime double_rounds: usize) type {
    return struct {
        state: [16]u32,
        block: [16]u32,
        block_word_idx: u8, // 0..16

        const Self = @This();

        pub fn fromSeed(seed: [32]u8) Self {
            var st: [16]u32 = undefined;
            st[0] = 0x61707865;
            st[1] = 0x3320646e;
            st[2] = 0x79622d32;
            st[3] = 0x6b206574;
            var i: usize = 0;
            while (i < 8) : (i += 1) {
                st[4 + i] = std.mem.readInt(u32, seed[i * 4 ..][0..4], .little);
            }
            st[12] = 0;
            st[13] = 0;
            st[14] = 0;
            st[15] = 0;
            return .{ .state = st, .block = undefined, .block_word_idx = 16 };
        }

        fn refill(self: *Self) void {
            var s = self.state;
            var r: usize = 0;
            while (r < double_rounds) : (r += 1) {
                qr(&s, 0, 4, 8, 12);
                qr(&s, 1, 5, 9, 13);
                qr(&s, 2, 6, 10, 14);
                qr(&s, 3, 7, 11, 15);
                qr(&s, 0, 5, 10, 15);
                qr(&s, 1, 6, 11, 12);
                qr(&s, 2, 7, 8, 13);
                qr(&s, 3, 4, 9, 14);
            }
            var i: usize = 0;
            while (i < 16) : (i += 1) self.block[i] = s[i] +% self.state[i];
            // 64-bit block counter at state[12..14].
            self.state[12] +%= 1;
            if (self.state[12] == 0) self.state[13] +%= 1;
            self.block_word_idx = 0;
        }

        pub fn nextU32(self: *Self) u32 {
            if (self.block_word_idx >= 16) self.refill();
            const v = self.block[self.block_word_idx];
            self.block_word_idx += 1;
            return v;
        }

        pub fn nextU64(self: *Self) u64 {
            const lo: u64 = self.nextU32();
            const hi: u64 = self.nextU32();
            return lo | (hi << 32);
        }
    };
}

pub const ChaCha8Rng = ChaChaRngGeneric(4);
pub const ChaCha20Rng = ChaChaRngGeneric(10);

fn qr(s: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
    s[a] +%= s[b];
    s[d] = std.math.rotl(u32, s[d] ^ s[a], @as(u5, 16));
    s[c] +%= s[d];
    s[b] = std.math.rotl(u32, s[b] ^ s[c], @as(u5, 12));
    s[a] +%= s[b];
    s[d] = std.math.rotl(u32, s[d] ^ s[a], @as(u5, 8));
    s[c] +%= s[d];
    s[b] = std.math.rotl(u32, s[b] ^ s[c], @as(u5, 7));
}

// ─────────────────────────────────────────────────────────────────────────
// UniformU64Sampler — Agave random/src/range.rs.
// ─────────────────────────────────────────────────────────────────────────

/// Lemire wmul rejection sampler over [0, range_end).
///
/// WeightedShuffle::first/shuffle use `new_like_trait_sample` (NOT instance_sample):
///   zone = (range_end << leading_zeros(range_end)) - 1   (Agave range.rs:48)
/// This differs from `new_like_instance_sample` (zone via modulo), so the two are
/// NOT interchangeable — picking the wrong one changes the rejection zone → wrong sample.
pub const UniformU64Sampler = struct {
    range_end: u64, // must be non-zero
    zone: u64,

    /// Agave UniformU64Sampler::new_like_trait_sample (range.rs:46-49).
    pub fn newLikeTraitSample(range_end: u64) UniformU64Sampler {
        std.debug.assert(range_end != 0);
        const lz: u6 = @intCast(@clz(range_end));
        // (range_end << lz).wrapping_sub(1)
        const zone: u64 = (range_end << lz) -% 1;
        return .{ .range_end = range_end, .zone = zone };
    }

    /// Agave UniformU64Sampler::sample (range.rs:51-59): loop drawing u64, accept
    /// when the low 64 bits of (x * range_end) ≤ zone, return the high 64 bits.
    pub fn sample(self: *const UniformU64Sampler, rng: anytype) u64 {
        while (true) {
            const x: u64 = rng.nextU64();
            const tmp: u128 = @as(u128, x) * @as(u128, self.range_end);
            const hi: u64 = @intCast(tmp >> 64);
            const lo: u64 = @truncate(tmp);
            if (lo <= self.zone) return hi;
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────
// WeightedShuffle — Agave gossip/src/weighted_shuffle.rs.
// ─────────────────────────────────────────────────────────────────────────

/// Agave `get_num_nodes_and_tree_size` (weighted_shuffle.rs:207-215).
fn getNumNodesAndTreeSize(count: usize) struct { num_nodes: usize, tree_size: usize } {
    var size: usize = 0;
    var nodes: usize = 1;
    while (nodes * FANOUT < count) {
        size += nodes;
        nodes *= FANOUT;
    }
    const div_ceil = (count + FANOUT - 1) / FANOUT;
    return .{ .num_nodes = size + nodes, .tree_size = size + div_ceil };
}

/// Stake-weighted shuffle over indices [0, weights.len). Byte-exact with Agave's
/// turbine WeightedShuffle. `first` / `shuffle` reproduce the cluster's node order.
pub const WeightedShuffle = struct {
    allocator: std.mem.Allocator,
    num_nodes: usize,
    /// Fenwick tree: tree[i][j] = sum of weights in the j'th sub-tree of node i.
    tree: [][FANOUT]u64,
    /// Current sum of all weights, excluding already-sampled ones.
    weight: u64,
    /// Indices of zero-weighted entries (shuffled to the end).
    zeros: std.ArrayListUnmanaged(usize),

    pub const Error = error{OutOfMemory};

    /// Agave WeightedShuffle::new (weighted_shuffle.rs:48-101). Weights that overflow
    /// the running sum are treated as zero (pushed to `zeros`), exactly like Agave.
    pub fn init(allocator: std.mem.Allocator, weights: []const u64) Error!WeightedShuffle {
        const dims = getNumNodesAndTreeSize(weights.len);
        const tree = try allocator.alloc([FANOUT]u64, dims.tree_size);
        @memset(tree, [_]u64{0} ** FANOUT);

        var zeros: std.ArrayListUnmanaged(usize) = .{};
        errdefer zeros.deinit(allocator);

        var sum: u64 = 0;
        for (weights, 0..) |w, k| {
            if (w == 0) {
                try zeros.append(allocator, k);
                continue;
            }
            const new_sum = std.math.add(u64, sum, w) catch {
                // Overflow → treat as zero (Agave datapoint "weighted-shuffle-overflow").
                try zeros.append(allocator, k);
                continue;
            };
            sum = new_sum;
            // Traverse leaf→root, accumulating the sub-tree sums.
            var index: usize = dims.num_nodes + k; // leaf node
            while (index != 0) {
                const offset = (index - 1) & BIT_MASK;
                index = (index - 1) >> BIT_SHIFT; // parent node
                tree[index][offset] += w;
            }
        }

        return .{
            .allocator = allocator,
            .num_nodes = dims.num_nodes,
            .tree = tree,
            .weight = sum,
            .zeros = zeros,
        };
    }

    pub fn deinit(self: *WeightedShuffle) void {
        self.allocator.free(self.tree);
        self.zeros.deinit(self.allocator);
    }

    /// Agave WeightedShuffle::remove (weighted_shuffle.rs:104-121): subtract `weight`
    /// at leaf k along the leaf→root path.
    fn remove(self: *WeightedShuffle, k: usize, weight: u64) void {
        self.weight -= weight;
        var index: usize = self.num_nodes + k; // leaf node
        while (index != 0) {
            const offset = (index - 1) & BIT_MASK;
            index = (index - 1) >> BIT_SHIFT; // parent node
            self.tree[index][offset] -= weight;
        }
    }

    /// Agave WeightedShuffle::search (weighted_shuffle.rs:124-150). Returns the
    /// smallest index k such that sum(weights[..=k]) > val, with its weight.
    fn search(self: *const WeightedShuffle, val_in: u64) struct { index: usize, weight: u64 } {
        var val = val_in;
        var index: usize = 0; // root
        while (true) {
            var offset: usize = 0;
            var node: u64 = 0;
            // .find(|node| if val < node {true} else {val -= node; false}).unwrap()
            while (offset < FANOUT) : (offset += 1) {
                const nv = self.tree[index][offset];
                if (val < nv) {
                    node = nv;
                    break;
                }
                val -= nv;
            }
            index = (index << BIT_SHIFT) + offset + 1;
            if (self.tree.len <= index) {
                return .{ .index = index - self.num_nodes, .weight = node };
            }
        }
    }

    /// Agave WeightedShuffle::remove_index (weighted_shuffle.rs:151-164). Removes the
    /// entry at original index k (used to drop the leader before broadcast/retransmit).
    pub fn removeIndex(self: *WeightedShuffle, k: usize) void {
        const leaf: usize = self.num_nodes + k;
        const offset = (leaf - 1) & BIT_MASK;
        const parent = (leaf - 1) >> BIT_SHIFT;
        if (parent >= self.tree.len) return; // Invalid index (Agave logs + returns).
        const weight = self.tree[parent][offset];
        if (weight == 0) {
            self.removeZero(k);
        } else {
            self.remove(k, weight);
        }
    }

    fn removeZero(self: *WeightedShuffle, k: usize) void {
        for (self.zeros.items, 0..) |ix, i| {
            if (ix == k) {
                _ = self.zeros.orderedRemove(i);
                return;
            }
        }
    }

    /// Agave WeightedShuffle::first (weighted_shuffle.rs:175-186) ==
    /// `shuffle(&mut rng).next()`. Returns the first index of the weighted shuffle,
    /// or null if no entries remain. Non-destructive on the tree (zeros path uses get).
    pub fn first(self: *const WeightedShuffle, rng: anytype) ?usize {
        if (self.weight != 0) {
            const sampler = UniformU64Sampler.newLikeTraitSample(self.weight);
            const sample = sampler.sample(rng);
            return self.search(sample).index;
        }
        if (self.zeros.items.len == 0) return null;
        const sampler = UniformU64Sampler.newLikeTraitSample(@as(u64, self.zeros.items.len));
        const idx = sampler.sample(rng);
        if (idx >= self.zeros.items.len) return null;
        return self.zeros.items[@intCast(idx)];
    }

    /// Agave WeightedShuffle::shuffle (weighted_shuffle.rs:189-201) as an iterator.
    /// DESTRUCTIVE: consumes the shuffle (removes sampled entries). Call on a clone
    /// if the shuffle must be reused. Used to KAT the full order against Agave vectors.
    pub const Iterator = struct {
        ws: *WeightedShuffle,
        rng_ptr: *anyopaque,
        next_fn: *const fn (*anyopaque) u64,

        pub fn next(self: *Iterator) ?usize {
            const ws = self.ws;
            if (ws.weight != 0) {
                const sampler = UniformU64Sampler.newLikeTraitSample(ws.weight);
                // sample(rng): inline the wmul loop over the type-erased rng.
                var hi: u64 = undefined;
                while (true) {
                    const x = self.next_fn(self.rng_ptr);
                    const tmp: u128 = @as(u128, x) * @as(u128, sampler.range_end);
                    hi = @intCast(tmp >> 64);
                    const lo: u64 = @truncate(tmp);
                    if (lo <= sampler.zone) break;
                }
                const res = ws.search(hi);
                ws.remove(res.index, res.weight);
                return res.index;
            }
            if (ws.zeros.items.len == 0) return null;
            const sampler = UniformU64Sampler.newLikeTraitSample(@as(u64, ws.zeros.items.len));
            var hi: u64 = undefined;
            while (true) {
                const x = self.next_fn(self.rng_ptr);
                const tmp: u128 = @as(u128, x) * @as(u128, sampler.range_end);
                hi = @intCast(tmp >> 64);
                const lo: u64 = @truncate(tmp);
                if (lo <= sampler.zone) break;
            }
            // swap_remove(hi)
            const i: usize = @intCast(hi);
            const last = ws.zeros.items.len - 1;
            const v = ws.zeros.items[i];
            ws.zeros.items[i] = ws.zeros.items[last];
            ws.zeros.items.len = last;
            return v;
        }
    };

    /// Build a destructive shuffle iterator bound to `rng` (must outlive the iterator).
    pub fn shuffle(self: *WeightedShuffle, rng: anytype) Iterator {
        const RngT = @TypeOf(rng);
        const Wrap = struct {
            fn nextU64(p: *anyopaque) u64 {
                const r: RngT = @ptrCast(@alignCast(p));
                return r.nextU64();
            }
        };
        return .{ .ws = self, .rng_ptr = @ptrCast(rng), .next_fn = &Wrap.nextU64 };
    }

    /// Deep clone (Agave clone) so a `shuffle` can be run without destroying the original.
    pub fn clone(self: *const WeightedShuffle) Error!WeightedShuffle {
        const tree = try self.allocator.alloc([FANOUT]u64, self.tree.len);
        @memcpy(tree, self.tree);
        var zeros: std.ArrayListUnmanaged(usize) = .{};
        errdefer zeros.deinit(self.allocator);
        try zeros.appendSlice(self.allocator, self.zeros.items);
        return .{
            .allocator = self.allocator,
            .num_nodes = self.num_nodes,
            .tree = tree,
            .weight = self.weight,
            .zeros = zeros,
        };
    }
};

// ═════════════════════════════════════════════════════════════════════════
// KATs — proven byte-exact against Agave's own hard-coded test vectors
// (agave gossip/src/weighted_shuffle.rs tests). If these pass, the seed→RNG→
// sampler→tree pipeline matches the cluster's turbine root selection exactly.
// ═════════════════════════════════════════════════════════════════════════

const testing = std.testing;

// Agave weights from `test_weighted_shuffle_hard_coded`.
const HC_WEIGHTS = [_]u64{ 78, 70, 38, 27, 21, 0, 82, 42, 21, 77, 77, 0, 17, 4, 50, 96, 0, 83, 33, 16, 72 };

test "getNumNodesAndTreeSize matches Agave" {
    // Agave test_get_num_nodes_and_tree_size sanity values.
    try testing.expectEqual(@as(usize, 1), getNumNodesAndTreeSize(0).num_nodes);
    try testing.expectEqual(@as(usize, 0), getNumNodesAndTreeSize(0).tree_size);
    // counts 1..=16 → (1, 1)
    var c: usize = 1;
    while (c <= FANOUT) : (c += 1) {
        try testing.expectEqual(@as(usize, 1), getNumNodesAndTreeSize(c).num_nodes);
        try testing.expectEqual(@as(usize, 1), getNumNodesAndTreeSize(c).tree_size);
    }
    // count 17 → num_nodes = 1+16 = 17, tree_size = 1 + ceil(17/16) = 3
    try testing.expectEqual(@as(usize, 17), getNumNodesAndTreeSize(17).num_nodes);
    try testing.expectEqual(@as(usize, 3), getNumNodesAndTreeSize(17).tree_size);
}

test "WeightedShuffle.first matches Agave ChaCha20 hard-coded vectors" {
    // seed=[48;32], ChaCha20 → first == 10
    {
        var rng = ChaCha20Rng.fromSeed([_]u8{48} ** 32);
        var ws = try WeightedShuffle.init(testing.allocator, &HC_WEIGHTS);
        defer ws.deinit();
        try testing.expectEqual(@as(?usize, 10), ws.first(&rng));
    }
    // seed=[37;32], ChaCha20 → first == 3
    {
        var rng = ChaCha20Rng.fromSeed([_]u8{37} ** 32);
        var ws = try WeightedShuffle.init(testing.allocator, &HC_WEIGHTS);
        defer ws.deinit();
        try testing.expectEqual(@as(?usize, 3), ws.first(&rng));
    }
}

fn collectShuffle(seed_byte: u8, out: *[HC_WEIGHTS.len]usize) !usize {
    var rng = ChaCha20Rng.fromSeed([_]u8{seed_byte} ** 32);
    var ws = try WeightedShuffle.init(testing.allocator, &HC_WEIGHTS);
    defer ws.deinit();
    var it = ws.shuffle(&rng);
    var n: usize = 0;
    while (it.next()) |idx| : (n += 1) out[n] = idx;
    return n;
}

test "WeightedShuffle.shuffle full order matches Agave ChaCha20 vectors" {
    const expect_48 = [_]usize{ 10, 3, 14, 18, 0, 9, 19, 6, 2, 1, 17, 7, 13, 15, 20, 12, 4, 8, 5, 16, 11 };
    const expect_37 = [_]usize{ 3, 15, 10, 6, 19, 17, 2, 0, 9, 20, 1, 14, 7, 8, 12, 18, 4, 13, 5, 11, 16 };

    var got: [HC_WEIGHTS.len]usize = undefined;
    var n = try collectShuffle(48, &got);
    try testing.expectEqual(@as(usize, HC_WEIGHTS.len), n);
    try testing.expectEqualSlices(usize, &expect_48, got[0..n]);

    n = try collectShuffle(37, &got);
    try testing.expectEqual(@as(usize, HC_WEIGHTS.len), n);
    try testing.expectEqualSlices(usize, &expect_37, got[0..n]);
}

test "WeightedShuffle.removeIndex then first matches Agave (seed 48 → still 10)" {
    var ws = try WeightedShuffle.init(testing.allocator, &HC_WEIGHTS);
    defer ws.deinit();
    ws.removeIndex(11);
    ws.removeIndex(3);
    ws.removeIndex(15);
    ws.removeIndex(0);
    var rng = ChaCha20Rng.fromSeed([_]u8{48} ** 32);
    try testing.expectEqual(@as(?usize, 10), ws.first(&rng));
    // Full shuffle after the removals (Agave vector).
    var rng2 = ChaCha20Rng.fromSeed([_]u8{48} ** 32);
    const expect = [_]usize{ 10, 6, 9, 17, 20, 8, 4, 1, 2, 14, 7, 12, 18, 19, 13, 16, 5 };
    var it = ws.shuffle(&rng2);
    var got: [HC_WEIGHTS.len]usize = undefined;
    var n: usize = 0;
    while (it.next()) |idx| : (n += 1) got[n] = idx;
    try testing.expectEqualSlices(usize, &expect, got[0..n]);
}

// ChaCha8 NON-zero-weight golden vectors (the LIVE testnet variant: SIMD-0332 active).
// Generated 2026-06-17 by a from-scratch Rust harness porting Agave's
// gossip/src/weighted_shuffle.rs + random/src/range.rs UniformU64Sampler::new_like_trait_sample,
// driven by rand_chacha::ChaCha8Rng over the SAME HC_WEIGHTS used by Agave's hard-coded
// ChaCha20 vectors above. The harness ALSO reproduced Agave's own hard-coded ChaCha8
// zero-weight vector (first=Some(4), shuffle=[4,3,1,2,0]) as a self-check, and proved
// rand_chacha 0.9.0 == 0.3.1 produce byte-identical ChaCha8 streams for the next_u64 path
// (closing the 0.3.1-vs-0.9.0 documentation discrepancy: gossip actually pins 0.9.0).
// Harness: /tmp/c1-chacha8-kat (cargo, rand_chacha 0.9 + 0.3).
fn collectShuffle8(seed_byte: u8, out: *[HC_WEIGHTS.len]usize) !usize {
    var rng = ChaCha8Rng.fromSeed([_]u8{seed_byte} ** 32);
    var ws = try WeightedShuffle.init(testing.allocator, &HC_WEIGHTS);
    defer ws.deinit();
    var it = ws.shuffle(&rng);
    var n: usize = 0;
    while (it.next()) |idx| : (n += 1) out[n] = idx;
    return n;
}

test "WeightedShuffle.first matches Agave ChaCha8 NON-zero vectors (seed 48→15, seed 37→17)" {
    {
        var rng = ChaCha8Rng.fromSeed([_]u8{48} ** 32);
        var ws = try WeightedShuffle.init(testing.allocator, &HC_WEIGHTS);
        defer ws.deinit();
        try testing.expectEqual(@as(?usize, 15), ws.first(&rng));
    }
    {
        var rng = ChaCha8Rng.fromSeed([_]u8{37} ** 32);
        var ws = try WeightedShuffle.init(testing.allocator, &HC_WEIGHTS);
        defer ws.deinit();
        try testing.expectEqual(@as(?usize, 17), ws.first(&rng));
    }
}

test "WeightedShuffle.shuffle full order matches Agave ChaCha8 NON-zero vectors" {
    // ChaCha8, HC_WEIGHTS, seeds [48;32] and [37;32].
    const expect_48 = [_]usize{ 15, 9, 7, 17, 0, 20, 1, 14, 3, 19, 6, 18, 10, 2, 4, 8, 12, 13, 16, 5, 11 };
    const expect_37 = [_]usize{ 17, 10, 6, 15, 7, 18, 8, 2, 9, 0, 20, 1, 4, 14, 3, 19, 12, 13, 11, 16, 5 };

    var got: [HC_WEIGHTS.len]usize = undefined;
    var n = try collectShuffle8(48, &got);
    try testing.expectEqual(@as(usize, HC_WEIGHTS.len), n);
    try testing.expectEqualSlices(usize, &expect_48, got[0..n]);

    n = try collectShuffle8(37, &got);
    try testing.expectEqual(@as(usize, HC_WEIGHTS.len), n);
    try testing.expectEqualSlices(usize, &expect_37, got[0..n]);
}

test "WeightedShuffle all-zero weights → ChaCha8 first == 4, ChaCha20 first == 1 (Agave)" {
    const zeros = [_]u64{0} ** 5;
    // ChaCha8 (the LIVE testnet variant, SIMD-0332 active) → Some(4).
    {
        var rng = ChaCha8Rng.fromSeed([_]u8{37} ** 32);
        var ws = try WeightedShuffle.init(testing.allocator, &zeros);
        defer ws.deinit();
        try testing.expectEqual(@as(?usize, 4), ws.first(&rng));
    }
    // ChaCha20 (legacy) → Some(1).
    {
        var rng = ChaCha20Rng.fromSeed([_]u8{37} ** 32);
        var ws = try WeightedShuffle.init(testing.allocator, &zeros);
        defer ws.deinit();
        try testing.expectEqual(@as(?usize, 1), ws.first(&rng));
    }
}

test "WeightedShuffle empty weights → first is null" {
    var rng = ChaCha8Rng.fromSeed([_]u8{1} ** 32);
    var ws = try WeightedShuffle.init(testing.allocator, &[_]u64{});
    defer ws.deinit();
    try testing.expectEqual(@as(?usize, null), ws.first(&rng));
}

test "first() is deterministic for a fixed seed+weights" {
    var ws = try WeightedShuffle.init(testing.allocator, &HC_WEIGHTS);
    defer ws.deinit();
    var prev: ?usize = null;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        var rng = ChaCha8Rng.fromSeed([_]u8{99} ** 32);
        const f = ws.first(&rng);
        if (prev) |p| try testing.expectEqual(p, f.?);
        prev = f;
    }
}
