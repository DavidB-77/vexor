//! Compatibility-faithful port of Agave's `agave-random/src/range.rs`
//! (`UniformU64Sampler`) and `agave-random/src/weighted.rs`
//! (`WeightedU64Index`). Required to reproduce
//! `agave-leader-schedule::stake_weighted_slot_leaders` byte-for-byte.
//!
//! These utilities reproduce sample sequences from `rand::distributions`
//! at versions <=0.8.5 (which Agave 4.0.0-beta.7 uses through
//! `rand_chacha::ChaChaRng::from_seed`).
//!
//! Algorithms ported:
//!   - `UniformU64Sampler::new_like_instance_sample(range_end)`:
//!     `ints_to_reject = (u64::MAX - range_end + 1) % range_end`
//!     `zone = u64::MAX - ints_to_reject`
//!   - `UniformU64Sampler::sample(rng)`: loop, draw u64, do
//!     `wmul(x, range_end)` (128-bit multiply), accept when low half
//!     fits inside `zone`, return high half.
//!   - `WeightedU64Index::new(weights)`: in-place prefix sum, drop the
//!     last element (kept implicitly as total_weight), build a uniform
//!     sampler over [0, total_weight).
//!   - `WeightedU64Index::sample(rng)`: draw chosen_weight, then
//!     `partition_point(|w| *w <= chosen_weight)`.
//!
//! No allocations after `init`. The `weights` slice is owned by the caller
//! and must outlive the index (we keep a pointer to it).
//!
//! References:
//!   - agave-4.0/random/src/range.rs (lines 30-67)
//!   - agave-4.0/random/src/weighted.rs (lines 19-51)

const std = @import("std");

/// Compatibility u64 random sampler over `[0, range_end)`.
/// Equivalent to `UniformU64Sampler::new_like_instance_sample` from Agave.
pub const UniformU64Sampler = struct {
    range_end: u64, // must be non-zero
    zone: u64,

    pub fn newLikeInstanceSample(range_end: u64) UniformU64Sampler {
        std.debug.assert(range_end != 0);
        // ints_to_reject = (u64::MAX - range_end + 1) % range_end
        // In Rust this uses wrapping arithmetic; in Zig std.math.maxInt(u64)
        // is fine because u64::MAX - range_end + 1 cannot underflow.
        // Note: if range_end == 1, ints_to_reject = (max - 1 + 1) % 1 = 0,
        // so zone = u64::MAX (every value accepted), which is correct.
        const max_u64: u64 = std.math.maxInt(u64);
        const ints_to_reject: u64 = (max_u64 - range_end +% 1) % range_end;
        const zone: u64 = max_u64 - ints_to_reject;
        return .{ .range_end = range_end, .zone = zone };
    }

    /// Sample a u64 in `[0, range_end)` using `rng` as keystream of u64s.
    /// `rng_next_u64` is a closure that returns the next u64 from the rng.
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

/// Compatibility weighted u64 sampler.
/// Equivalent to `WeightedU64Index` from Agave.
///
/// IMPORTANT: this struct holds an internal owned slice of cumulative
/// prefix-sum weights (length = original_weights.len - 1). Caller must
/// `deinit` to free.
pub const WeightedU64Index = struct {
    /// Prefix sums except the last (which is `total_weight`).
    weights: []u64,
    total_weight_sampler: UniformU64Sampler,
    allocator: std.mem.Allocator,

    pub const Error = error{
        InvalidInput, // empty input
        InsufficientNonZero, // total weight == 0
        Overflow, // sum exceeds u64
        OutOfMemory,
    };

    /// Build a weighted sampler. Takes ownership of nothing — caller's
    /// `weights` slice is read-only and not retained. We allocate our own
    /// prefix sums.
    pub fn init(allocator: std.mem.Allocator, weights_in: []const u64) Error!WeightedU64Index {
        if (weights_in.len == 0) return Error.InvalidInput;

        var weights = try allocator.alloc(u64, weights_in.len);
        errdefer allocator.free(weights);

        var total_weight: u64 = 0;
        for (weights_in, 0..) |w, i| {
            total_weight = std.math.add(u64, total_weight, w) catch return Error.Overflow;
            weights[i] = total_weight;
        }

        if (total_weight == 0) return Error.InsufficientNonZero;

        // Pop the last element — Agave: `weights.pop()`. The popped value
        // equals total_weight; binary search ignores it.
        const truncated = try allocator.realloc(weights, weights.len - 1);

        return .{
            .weights = truncated,
            .total_weight_sampler = UniformU64Sampler.newLikeInstanceSample(total_weight),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *WeightedU64Index) void {
        self.allocator.free(self.weights);
    }

    /// Sample an index into the original weights slice.
    /// Returns `0..weights_in.len`.
    pub fn sample(self: *const WeightedU64Index, rng: anytype) usize {
        const chosen_weight = self.total_weight_sampler.sample(rng);
        // partition_point(|w| *w <= chosen_weight) — find first index `i`
        // where `weights[i] > chosen_weight`. Returns `weights.len` if no
        // such index (caller should make sure that resolves correctly —
        // in the leader-schedule context, that maps to the LAST weight,
        // which was popped from the prefix-sum array).
        var lo: usize = 0;
        var hi: usize = self.weights.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.weights[mid] <= chosen_weight) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }
};

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Test ChaCha20 RNG matching `rand_chacha::ChaChaRng::from_seed`.
/// Used in tests to validate sampler output against Agave's known vectors.
/// State layout: 16 u32 = 64 bytes per block. Counter at state[12]+state[13]
/// (64-bit). Stream at state[14]+state[15] (64-bit). From-seed: all zero.
const TestChaCha = struct {
    state: [16]u32,
    block: [16]u32, // generated keystream block
    block_word_idx: u8, // next u32 to consume from `block`, in 0..16

    pub fn fromSeed(seed: [32]u8) TestChaCha {
        var st: [16]u32 = undefined;
        st[0] = 0x61707865;
        st[1] = 0x3320646e;
        st[2] = 0x79622d32;
        st[3] = 0x6b206574;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            st[4 + i] = std.mem.readInt(u32, seed[i * 4 ..][0..4], .little);
        }
        st[12] = 0; // block counter low
        st[13] = 0; // block counter high
        st[14] = 0; // stream id low
        st[15] = 0; // stream id high
        var rng = TestChaCha{ .state = st, .block = undefined, .block_word_idx = 16 };
        _ = &rng;
        return rng;
    }

    fn refill(self: *TestChaCha) void {
        var s = self.state;
        var r: usize = 0;
        while (r < 10) : (r += 1) {
            quarterRound(&s, 0, 4, 8, 12);
            quarterRound(&s, 1, 5, 9, 13);
            quarterRound(&s, 2, 6, 10, 14);
            quarterRound(&s, 3, 7, 11, 15);
            quarterRound(&s, 0, 5, 10, 15);
            quarterRound(&s, 1, 6, 11, 12);
            quarterRound(&s, 2, 7, 8, 13);
            quarterRound(&s, 3, 4, 9, 14);
        }
        var i: usize = 0;
        while (i < 16) : (i += 1) self.block[i] = s[i] +% self.state[i];
        // Advance block counter (64-bit at state[12..14])
        self.state[12] +%= 1;
        if (self.state[12] == 0) self.state[13] +%= 1;
        self.block_word_idx = 0;
    }

    pub fn nextU32(self: *TestChaCha) u32 {
        if (self.block_word_idx >= 16) self.refill();
        const v = self.block[self.block_word_idx];
        self.block_word_idx += 1;
        return v;
    }

    pub fn nextU64(self: *TestChaCha) u64 {
        // rand_chacha::ChaChaRng::next_u64 reads two consecutive u32s
        // (low, high) and packs them little-endian.
        const lo: u64 = self.nextU32();
        const hi: u64 = self.nextU32();
        return lo | (hi << 32);
    }
};

fn quarterRound(s: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
    s[a] +%= s[b];
    s[d] = std.math.rotl(u32, s[d] ^ s[a], @as(u5, 16));
    s[c] +%= s[d];
    s[b] = std.math.rotl(u32, s[b] ^ s[c], @as(u5, 12));
    s[a] +%= s[b];
    s[d] = std.math.rotl(u32, s[d] ^ s[a], @as(u5, 8));
    s[c] +%= s[d];
    s[b] = std.math.rotl(u32, s[b] ^ s[c], @as(u5, 7));
}

test "uniform sampler new_like_instance_sample matches Agave example" {
    // From agave-4.0/random/src/range.rs test_uniform_sample_like_instance_sample_example:
    //   seed=[16; 32], range_end=294_533
    //   first 10 samples = [280405, 7507, 84194, 272634, 52124, 190984, 8676, 230277, 223574, 126007]
    const seed: [32]u8 = [_]u8{16} ** 32;
    var rng = TestChaCha.fromSeed(seed);
    const sampler = UniformU64Sampler.newLikeInstanceSample(294_533);
    const expected = [_]u64{ 280405, 7507, 84194, 272634, 52124, 190984, 8676, 230277, 223574, 126007 };
    for (expected, 0..) |want, i| {
        const got = sampler.sample(&rng);
        if (got != want) {
            std.debug.print("[FAIL] i={d} want={d} got={d}\n", .{ i, want, got });
        }
        try testing.expectEqual(want, got);
    }
}

test "weighted u64 index matches Agave example" {
    // From agave-4.0/random/src/weighted.rs test_weighted_u64_index_example:
    //   weights = (0..100).map(|i| i.pow(0)) = [1; 100]
    //   expected = [95, 2, 28, 92, 17, 64, 2, 78, 75, 42]
    const seed: [32]u8 = [_]u8{16} ** 32;
    var rng = TestChaCha.fromSeed(seed);

    var weights: [100]u64 = undefined;
    for (&weights) |*w| w.* = 1;

    var idx = try WeightedU64Index.init(testing.allocator, &weights);
    defer idx.deinit();

    const expected = [_]usize{ 95, 2, 28, 92, 17, 64, 2, 78, 75, 42 };
    for (expected, 0..) |want, i| {
        const got = idx.sample(&rng);
        if (got != want) {
            std.debug.print("[FAIL] i={d} want={d} got={d}\n", .{ i, want, got });
        }
        try testing.expectEqual(want, got);
    }
}
