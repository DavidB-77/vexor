//! Byte-faithful port of Agave 4.0.0-beta.7's
//! `agave-leader-schedule::vote_keyed::LeaderSchedule` and
//! `stake_weighted_slot_leaders`.
//!
//! References:
//!   - agave-4.0/leader-schedule/src/lib.rs (lines 40-84)
//!   - agave-4.0/leader-schedule/src/vote_keyed.rs (lines 17-56)
//!   - agave-4.0/runtime/src/leader_schedule_utils.rs (lines 9-19)
//!
//! Algorithm:
//!   1. Build (SlotLeader, stake) vec where stake > 0.
//!   2. Sort descending by stake; tiebreak descending by `vote_address`.
//!   3. Dedup identical (vote_address, stake) pairs.
//!   4. Build `WeightedU64Index` from stakes.
//!   5. Seed `ChaChaRng` with `epoch.to_le_bytes()` padded to 32 bytes.
//!   6. Iterate `len` slots; resample every `repeat` slots
//!      (NUM_CONSECUTIVE_LEADER_SLOTS = 4 in production).
//!
//! `SlotLeader.id` = validator identity (node_pubkey from VoteState).
//! `SlotLeader.vote_address` = vote account pubkey.
//!
//! The caller is responsible for providing `slot_leader_stakes` already
//! resolved to (node_pubkey, vote_address, stake) tuples. In production,
//! this comes from the snapshot manifest's per-epoch vote_account_stakes
//! plus a one-time AccountsDb lookup that extracts each VoteState's
//! node_pubkey.

const std = @import("std");
const WeightedU64Index = @import("weighted_u64_index.zig").WeightedU64Index;

/// Matches Agave `solana_clock::NUM_CONSECUTIVE_LEADER_SLOTS`.
pub const NUM_CONSECUTIVE_LEADER_SLOTS: u64 = 4;

/// Mirrors Agave `SlotLeader`. Both fields are 32-byte pubkeys.
pub const SlotLeader = struct {
    id: [32]u8, // node_pubkey (validator identity) — what bank.collector_id wants
    vote_address: [32]u8, // vote account pubkey

    pub fn eql(a: SlotLeader, b: SlotLeader) bool {
        return std.mem.eql(u8, &a.id, &b.id) and std.mem.eql(u8, &a.vote_address, &b.vote_address);
    }
};

/// Input pair for leader-schedule computation.
pub const SlotLeaderStake = struct {
    leader: SlotLeader,
    stake: u64,
};

/// Mirrors Agave `LeaderSchedule`.
///
/// `slot_leaders` is a borrowed slice owned by the schedule. Index it with
/// `slot_leaders[slot_index % slot_leaders.len]`.
pub const LeaderSchedule = struct {
    slot_leaders: []SlotLeader,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *LeaderSchedule) void {
        self.allocator.free(self.slot_leaders);
    }

    /// Construct from a vector of (SlotLeader, stake) — equivalent to
    /// Agave's `LeaderSchedule::new(vote_accounts_map, epoch, len, repeat)`
    /// once you've turned the map into the pair vector.
    pub fn init(
        allocator: std.mem.Allocator,
        stakes_in: []const SlotLeaderStake,
        epoch: u64,
        len: u64,
        repeat: u64,
    ) !LeaderSchedule {
        // Filter stake > 0 + dup so we can sort in place.
        var pruned = try allocator.alloc(SlotLeaderStake, stakes_in.len);
        defer allocator.free(pruned);
        var pruned_len: usize = 0;
        for (stakes_in) |ss| {
            if (ss.stake == 0) continue;
            pruned[pruned_len] = ss;
            pruned_len += 1;
        }
        if (pruned_len == 0) return error.NoStake;
        var working = pruned[0..pruned_len];

        sortStakes(working);

        // Dedup identical (vote_address, stake) pairs — Agave's
        // `stakes.dedup_by(|l, r| r_stake == l_stake && r_va == l_va)`.
        // The sorted order means duplicates are adjacent.
        var write: usize = 1;
        var read: usize = 1;
        while (read < working.len) : (read += 1) {
            const prev = working[write - 1];
            const cur = working[read];
            if (cur.stake == prev.stake and std.mem.eql(u8, &cur.leader.vote_address, &prev.leader.vote_address)) {
                continue;
            }
            working[write] = cur;
            write += 1;
        }
        working = working[0..write];

        // Compute slot leaders.
        const slot_leaders = try stakeWeightedSlotLeaders(allocator, working, epoch, len, repeat);
        errdefer allocator.free(slot_leaders);

        return .{ .slot_leaders = slot_leaders, .allocator = allocator };
    }

    /// Return leader at the given slot_index (mod schedule length).
    pub fn getLeader(self: *const LeaderSchedule, slot_index: u64) SlotLeader {
        return self.slot_leaders[@intCast(slot_index % self.slot_leaders.len)];
    }
};

/// Equivalent to Agave's `sort_stakes`:
///   sort by stake DESC; on tie, by vote_address DESC (bytewise reverse).
fn sortStakes(stakes: []SlotLeaderStake) void {
    std.mem.sort(SlotLeaderStake, stakes, {}, struct {
        fn lessThan(_: void, l: SlotLeaderStake, r: SlotLeaderStake) bool {
            // Want descending stake first.
            if (r.stake != l.stake) return r.stake < l.stake;
            // Tiebreak: descending vote_address (i.e., l.vote_address > r.vote_address)
            return std.mem.order(u8, &l.leader.vote_address, &r.leader.vote_address) == .gt;
        }
    }.lessThan);
}

/// Port of Agave's ChaCha20 RNG (`rand_chacha::ChaChaRng::from_seed`).
///
/// Equivalent state layout:
///   constants  [0..4]  = "expand 32-byte k"
///   key        [4..12] = seed (32 bytes LE)
///   counter    [12..14] (64-bit block counter, starts at 0)
///   stream id  [14..16] (64-bit stream, starts at 0)
///
/// Each refill emits a 64-byte block of keystream that gets dispensed as
/// 16 u32 words in order.
///
/// `nextU64` reads two consecutive u32s and packs them little-endian, matching
/// `rand_chacha::ChaChaRng::next_u64` (which sources from the same fill_bytes
/// path that fills a [u8; 8] buffer LE).
pub const ChaChaRng = struct {
    state: [16]u32,
    block: [16]u32,
    block_word_idx: u8, // 0..16

    pub fn fromSeed(seed: [32]u8) ChaChaRng {
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

    fn refill(self: *ChaChaRng) void {
        var s = self.state;
        var r: usize = 0;
        while (r < 10) : (r += 1) {
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
        // 64-bit block counter at state[12..14]
        self.state[12] +%= 1;
        if (self.state[12] == 0) self.state[13] +%= 1;
        self.block_word_idx = 0;
    }

    pub fn nextU32(self: *ChaChaRng) u32 {
        if (self.block_word_idx >= 16) self.refill();
        const v = self.block[self.block_word_idx];
        self.block_word_idx += 1;
        return v;
    }

    pub fn nextU64(self: *ChaChaRng) u64 {
        const lo: u64 = self.nextU32();
        const hi: u64 = self.nextU32();
        return lo | (hi << 32);
    }
};

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

/// Equivalent to Agave's `stake_weighted_slot_leaders`.
/// Caller MUST have already passed the stakes through `sortStakes` + dedup.
fn stakeWeightedSlotLeaders(
    allocator: std.mem.Allocator,
    sorted: []const SlotLeaderStake,
    epoch: u64,
    len: u64,
    repeat: u64,
) ![]SlotLeader {
    std.debug.assert(len % repeat == 0);

    // Split sorted into parallel arrays.
    var leaders = try allocator.alloc(SlotLeader, sorted.len);
    defer allocator.free(leaders);
    var weights = try allocator.alloc(u64, sorted.len);
    defer allocator.free(weights);
    for (sorted, 0..) |ss, i| {
        leaders[i] = ss.leader;
        weights[i] = ss.stake;
    }

    var index = try WeightedU64Index.init(allocator, weights);
    defer index.deinit();

    var seed: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, seed[0..8], epoch, .little);
    var rng = ChaChaRng.fromSeed(seed);

    const out = try allocator.alloc(SlotLeader, @intCast(len));
    errdefer allocator.free(out);

    var current_leader: SlotLeader = .{ .id = [_]u8{0} ** 32, .vote_address = [_]u8{0} ** 32 };
    var i: u64 = 0;
    while (i < len) : (i += 1) {
        if (i % repeat == 0) {
            const idx = index.sample(&rng);
            current_leader = leaders[idx];
        }
        out[@intCast(i)] = current_leader;
    }

    return out;
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn pubkeyFromU16(n: u16) [32]u8 {
    var p: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u16, p[0..2], n, .little);
    return p;
}

fn buildTestStakes(stakes: []const u64) ![]SlotLeaderStake {
    const arr = try testing.allocator.alloc(SlotLeaderStake, stakes.len);
    for (stakes, 0..) |s, i| {
        // Match Agave test: id = pubkey_from_u16(seed), vote_address = Pubkey::new_unique() — non-deterministic.
        // For testing, we'd want vote_address to be unique-and-stable so sort is deterministic.
        // Since stakes are unique in our test cases, vote_address tiebreak doesn't fire.
        arr[i] = .{
            .leader = .{
                .id = pubkeyFromU16(@intCast(i)),
                .vote_address = pubkeyFromU16(@intCast(i + 1000)), // distinct, irrelevant for unique stakes
            },
            .stake = s,
        };
    }
    return arr;
}

test "stake_weighted_slot_leaders matches Agave test_case (1, [10,20,30], 12, 1)" {
    // From agave-4.0/leader-schedule/src/lib.rs:154:
    //   epoch=1, stakes=[10,20,30], len=12, repeat=1
    //   expected_order = [1, 1, 2, 1, 1, 0, 0, 1, 2, 1, 0, 1]
    //
    // expected_order[i] indexes into the ORIGINAL stakes vec (pre-sort).
    // Our test passes (id=pubkey_from_u16(i), stake=stakes[i]).
    // After sort by stake desc: [(p2,30), (p1,20), (p0,10)] — indices 2,1,0 of original.
    const stakes_arr = try buildTestStakes(&[_]u64{ 10, 20, 30 });
    defer testing.allocator.free(stakes_arr);

    var schedule = try LeaderSchedule.init(testing.allocator, stakes_arr, 1, 12, 1);
    defer schedule.deinit();

    // Map output back to original indices (find p0/p1/p2 by id).
    const expected = [_]usize{ 1, 1, 2, 1, 1, 0, 0, 1, 2, 1, 0, 1 };
    for (expected, 0..) |want, slot_i| {
        const got_leader = schedule.slot_leaders[slot_i];
        const got_idx = std.mem.readInt(u16, got_leader.id[0..2], .little);
        if (got_idx != want) {
            std.debug.print("[FAIL] slot {d}: want={d} got={d}\n", .{ slot_i, want, got_idx });
        }
        try testing.expectEqual(@as(u16, @intCast(want)), got_idx);
    }
}

test "stake_weighted_slot_leaders matches Agave test_case (1, [10,20,30], 12, 2)" {
    // repeat=2: every 2 slots same leader
    //   expected_order = [1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 0, 0]
    const stakes_arr = try buildTestStakes(&[_]u64{ 10, 20, 30 });
    defer testing.allocator.free(stakes_arr);

    var schedule = try LeaderSchedule.init(testing.allocator, stakes_arr, 1, 12, 2);
    defer schedule.deinit();

    const expected = [_]usize{ 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 0, 0 };
    for (expected, 0..) |want, slot_i| {
        const got_leader = schedule.slot_leaders[slot_i];
        const got_idx = std.mem.readInt(u16, got_leader.id[0..2], .little);
        try testing.expectEqual(@as(u16, @intCast(want)), got_idx);
    }
}

test "stake_weighted_slot_leaders matches Agave test_case (1, [30,10,20], 12, 1)" {
    // Same stakes set, different input order. Output must be identical.
    //   expected_order = [2, 2, 0, 2, 2, 1, 1, 2, 0, 2, 1, 2]
    // expected_order indexes into [30,10,20] (input order at indices 0,1,2).
    // After sort: [(p0,30), (p2,20), (p1,10)] (id matches input index 0,2,1).
    const stakes_arr = try buildTestStakes(&[_]u64{ 30, 10, 20 });
    defer testing.allocator.free(stakes_arr);

    var schedule = try LeaderSchedule.init(testing.allocator, stakes_arr, 1, 12, 1);
    defer schedule.deinit();

    const expected = [_]usize{ 2, 2, 0, 2, 2, 1, 1, 2, 0, 2, 1, 2 };
    for (expected, 0..) |want, slot_i| {
        const got_leader = schedule.slot_leaders[slot_i];
        const got_idx = std.mem.readInt(u16, got_leader.id[0..2], .little);
        try testing.expectEqual(@as(u16, @intCast(want)), got_idx);
    }
}

test "stake_weighted_slot_leaders epoch=457468 [10,20,30] repeat=1" {
    // From the same test_case set, with non-trivial epoch:
    //   epoch=457468, stakes=[10,20,30], len=12, repeat=1
    //   expected_order = [2, 2, 0, 1, 0, 2, 1, 2, 1, 2, 2, 2]
    const stakes_arr = try buildTestStakes(&[_]u64{ 10, 20, 30 });
    defer testing.allocator.free(stakes_arr);

    var schedule = try LeaderSchedule.init(testing.allocator, stakes_arr, 457468, 12, 1);
    defer schedule.deinit();

    const expected = [_]usize{ 2, 2, 0, 1, 0, 2, 1, 2, 1, 2, 2, 2 };
    for (expected, 0..) |want, slot_i| {
        const got_leader = schedule.slot_leaders[slot_i];
        const got_idx = std.mem.readInt(u16, got_leader.id[0..2], .little);
        try testing.expectEqual(@as(u16, @intCast(want)), got_idx);
    }
}
