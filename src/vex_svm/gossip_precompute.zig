//! Single-pass ancestry-gossip precompute — the O(voters×depth) replacement for the
//! per-node O(voters×depth) gossip-stake sum that made the gossip-fed prop_retarget
//! shadow (VEX_GOSSIP_PROP) too slow to ARM.
//!
//! WHY THIS EXISTS
//! ---------------
//! `gossip_retarget.walk` asks `sctx.combined(node)` for every node on our tip's
//! ancestry (~2×depth calls per submitVote). The old prod `SCtx.combined` answered
//! each with `LatestGossipVotes.stakeForSlotAncestryKey(node)`, which iterates ALL
//! ~527 voters and for EACH calls `fc.isStrictAncestor` (an O(depth) tree walk) →
//! O(voters×depth) PER node → O(voters×depth²) per vote. It lagged voting (had to
//! be throttled to a 5 s shadow), which blocks arming (armed must run per-vote).
//!
//! THE OPTIMIZATION (single pass, result BYTE-IDENTICAL to the reference)
//! --------------------------------------------------------------------
//! Precompute the gossip stake for EVERY ancestry node in ONE pass:
//!   1. Collect our tip's ancestry keys tip→root (SAME start_key-first +
//!      ancestorIterator + CAP=256 bound `gossip_retarget.walk` uses), and an
//!      index map key→i (0 = tip, nchain-1 = deepest/root-ward).
//!   2. bucket[0..n] = 0. For each voter, walk UP from its voted key `vk`
//!      (INCLUSIVE of vk) via ancestorIterator; the FIRST key that is an ancestry
//!      node is the voter's "entry" node[e]; add the voter's epoch stake (via the
//!      SAME gctx.epochStake, bound to the voter's voted-slot epoch) to bucket[e].
//!      If no ancestry node is hit (vk not in tree, or its fork joins BELOW the
//!      collected window), the voter contributes 0. This is O(depth) per voter.
//!   3. Prefix-sum tip→root: gossip_stake[node[i]] = Σ bucket[j] for j ≤ i. A voter
//!      entering at index e is an ancestor-or-equal of node[i] for ALL i ≥ e
//!      (node[e] and every root-ward node above it), so it lands in node[e]'s bucket
//!      and flows to every deeper index. node[i] therefore collects all entries with
//!      e ≤ i — the running sum as i increases from the tip.
//!
//! CORRECTNESS = EXACT MATCH TO THE REFERENCE. For any ancestry node `C = node[i]`,
//! `stakeForSlotAncestryKey(C)` sums voters where C is ancestor-or-equal of vk.
//! Because our ancestry is a LINEAR chain, the ancestry nodes that are
//! ancestor-or-equal of vk are exactly {node[e], node[e+1], …} (node[e] = the join
//! point, everything above it toward root). So `Σ_{e≤i} bucket` == the reference at
//! every ancestry node. The `test-gossip-precompute` KAT asserts this against the
//! TRUSTED `LatestGossipVotes.stakeForSlotAncestryKey` for every ancestry node
//! (never against our own math).
//!
//! CAP=256 TRUNCATION (audit point — reasoned, exercised by the deep-tree KAT):
//! If the tree is deeper than 256, root is NOT collected. A voter whose fork joins
//! our ancestry BELOW the collected window hits no ancestry-map node on its upward
//! walk → 0 contribution, which is correct: the deepest collected node node[255] is
//! a DESCENDANT of that join, hence NOT an ancestor of vk, so the reference also
//! credits 0. The voter's upward walk is bounded by tree depth (ancestorIterator
//! stops at root), NOT by CAP — do not cap the per-voter walk.

const std = @import("std");
const fork_choice = @import("vex_consensus").fork_choice;
const gossip_votes = @import("gossip_votes.zig");

pub const SlotHashKey = fork_choice.SlotHashKey;
pub const ForkChoice = fork_choice.ForkChoice;
const Ctx = fork_choice.SlotHashKeyContext{};

/// Same bound `gossip_retarget.walk` uses (races are near-tip; deeper is assumed
/// clean). The precompute MUST collect the identical ancestry set so its keys are
/// exactly the nodes `walk` will query with `combined`.
pub const CAP: usize = 256;

const KeyStakeMap = std.HashMapUnmanaged(
    SlotHashKey,
    u64,
    fork_choice.SlotHashKeyContext,
    std.hash_map.default_max_load_percentage,
);
const KeyIndexMap = std.HashMapUnmanaged(
    SlotHashKey,
    usize,
    fork_choice.SlotHashKeyContext,
    std.hash_map.default_max_load_percentage,
);

/// Precomputed gossip stake per ancestry node. `get(key)` returns null for any node
/// NOT on the collected ancestry (a sibling / off-ancestry node) — the caller then
/// falls back to the on-demand reference for that key (safe: absent → exact
/// reference; present → the precomputed value, which the KAT gates to be exact).
pub const AncestryGossip = struct {
    map: KeyStakeMap = .{},
    allocator: std.mem.Allocator,

    pub fn deinit(self: *AncestryGossip) void {
        self.map.deinit(self.allocator);
    }

    /// Gossip stake for an ancestry node, or null if `key` is not an ancestry node.
    pub fn get(self: *const AncestryGossip, key: SlotHashKey) ?u64 {
        return self.map.getContext(key, Ctx);
    }
};

/// Build the ancestry-gossip precompute for `start_key`'s ancestry. `gctx` must
/// expose `epochStake(pubkey: [32]u8) u64` (the voter's voted-slot-epoch stake) —
/// the SAME context the reference `stakeForSlotAncestryKey` uses, so epoch binding
/// cancels out and the result is byte-identical.
///
/// Caller owns the returned map (call `deinit`). The caller MUST hold whatever lock
/// guards `lv` (and `gctx`'s reads of `lv`) for the duration of this call — it reads
/// `lv.map` AND calls `gctx.epochStake` (which reads `lv`).
pub fn precompute(
    allocator: std.mem.Allocator,
    fc: *const ForkChoice,
    start_key: SlotHashKey,
    lv: *const gossip_votes.LatestGossipVotes,
    gctx: anytype,
) !AncestryGossip {
    return precomputeCap(CAP, allocator, fc, start_key, lv, gctx);
}

/// CAP is a comptime parameter so the KAT can exercise the deeper-than-CAP
/// truncation path with a small bound. Prod calls `precompute` (CAP=256).
pub fn precomputeCap(
    comptime cap: usize,
    allocator: std.mem.Allocator,
    fc: *const ForkChoice,
    start_key: SlotHashKey,
    lv: *const gossip_votes.LatestGossipVotes,
    gctx: anytype,
) !AncestryGossip {
    // 1. Collect ancestry tip→root — SAME start_key-first + ancestorIterator + cap
    //    bound as gossip_retarget.walk (so our keys == the nodes walk queries).
    var chain: [cap]SlotHashKey = undefined;
    var nchain: usize = 0;
    {
        var first = true;
        var it = fc.ancestorIterator(start_key);
        while (nchain < cap) {
            const nkey = if (first) start_key else (it.next() orelse break);
            first = false;
            chain[nchain] = nkey;
            nchain += 1;
        }
    }

    // Ancestry membership: key → index (0 = tip … nchain-1 = deepest/root-ward).
    // O(1) lookup keeps the per-voter upward walk O(depth), not O(depth²).
    var index_map: KeyIndexMap = .{};
    defer index_map.deinit(allocator);
    try index_map.ensureTotalCapacityContext(allocator, @intCast(nchain), Ctx);
    for (chain[0..nchain], 0..) |ckey, idx| {
        index_map.putAssumeCapacityContext(ckey, idx, Ctx);
    }

    // 2. bucket[e] = Σ epoch-stake of voters whose entry index (first ancestry node
    //    on the voter's INCLUSIVE upward walk) == e.
    var bucket: [cap]u64 = [_]u64{0} ** cap;
    var vit = lv.map.iterator();
    while (vit.next()) |entry| {
        const vk = SlotHashKey{ .slot = entry.value_ptr.slot, .hash = .{ .data = entry.value_ptr.hash } };
        // Inclusive: vk itself may be an ancestry node (a voter voting exactly for
        // one of our ancestry nodes). Matches the reference's `eql` inclusive branch.
        var e: ?usize = index_map.getContext(vk, Ctx);
        if (e == null) {
            // Walk UP vk's FULL path (bounded by tree depth, NOT cap): the first
            // ancestry-map hit is the join point. If none, vk contributes 0.
            var wit = fc.ancestorIterator(vk);
            while (wit.next()) |anc| {
                if (index_map.getContext(anc, Ctx)) |idx| {
                    e = idx;
                    break;
                }
            }
        }
        if (e) |ei| bucket[ei] +|= gctx.epochStake(entry.key_ptr.*);
    }

    // 3. Prefix-sum tip→root: gossip_stake[node[i]] = Σ bucket[j] for j ≤ i.
    var ag = AncestryGossip{ .allocator = allocator };
    errdefer ag.deinit();
    try ag.map.ensureTotalCapacityContext(allocator, @intCast(nchain), Ctx);
    var running: u64 = 0;
    for (chain[0..nchain], 0..) |ckey, idx| {
        running +|= bucket[idx];
        ag.map.putAssumeCapacityContext(ckey, running, Ctx);
    }
    return ag;
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS — precompute vs the TRUSTED reference over a real ForkChoice tree.
//   zig build test-gossip-precompute
// ═══════════════════════════════════════════════════════════════════════════
const testing = std.testing;

fn hk(slot: u64, b: u8) SlotHashKey {
    return .{ .slot = slot, .hash = .{ .data = [_]u8{b} ** 32 } };
}

/// Production-shaped context: epochStake by per-voter stake table; isAncestorKey
/// hash-aware + INCLUSIVE via the REAL fork tree (mirrors replay_stage GCtx). The
/// KAT feeds this SAME ctx to both the precompute (epochStake only) and the trusted
/// reference (epochStake + isAncestorKey), so any epoch binding cancels.
const KatCtx = struct {
    fc: *const ForkChoice,
    stakes: []const StakeRow,
    const StakeRow = struct { pk: [32]u8, stake: u64 };
    pub fn epochStake(self: *const @This(), pk: [32]u8) u64 {
        for (self.stakes) |s| if (std.mem.eql(u8, &s.pk, &pk)) return s.stake;
        return 0;
    }
    pub fn isAncestorKey(self: *const @This(), cs: u64, ch: [32]u8, vs: u64, vh: [32]u8) bool {
        const ck = SlotHashKey{ .slot = cs, .hash = .{ .data = ch } };
        const vk = SlotHashKey{ .slot = vs, .hash = .{ .data = vh } };
        if (SlotHashKey.eql(ck, vk)) return true; // inclusive
        return self.fc.isStrictAncestor(ck, vk);
    }
};

/// Assert precompute[node] == reference(node) for EVERY ancestry node, collecting
/// ancestry the SAME way (start_key first + ancestorIterator, given cap) that walk
/// and precompute do. Returns (tip_value, root_value) for direction assertions.
fn assertMatchesReference(
    comptime cap: usize,
    fc: *const ForkChoice,
    start_key: SlotHashKey,
    lv: *const gossip_votes.LatestGossipVotes,
    ctx: *const KatCtx,
) !struct { tip: u64, root: u64 } {
    var ag = try precomputeCap(cap, testing.allocator, fc, start_key, lv, ctx);
    defer ag.deinit();

    var tip_val: u64 = 0;
    var root_val: u64 = 0;
    var first = true;
    var count: usize = 0;
    var cur = start_key;
    var it = fc.ancestorIterator(start_key);
    while (count < cap) {
        const node = if (first) start_key else (it.next() orelse break);
        first = false;
        cur = node;
        count += 1;

        const got = ag.get(node) orelse return error.AncestryNodeMissingFromPrecompute;
        const want = lv.stakeForSlotAncestryKey(node.slot, node.hash.data, ctx);
        testing.expectEqual(want, got) catch |err| {
            std.debug.print("MISMATCH at slot={d}: precompute={d} reference={d}\n", .{ node.slot, got, want });
            return err;
        };
        if (node.slot == start_key.slot) tip_val = got;
    }
    root_val = ag.get(cur).?; // last collected = deepest/root-ward
    return .{ .tip = tip_val, .root = root_val };
}

test "gossip-precompute: matches stakeForSlotAncestryKey for every ancestry node (sibling + exact-ancestry voters)" {
    // Tree (main chain = our tip's ancestry):
    //   root(10,1) → n1(11,2) → n2(12,3) → tip(13,4)          [ancestry: tip,n2,n1,root]
    //   n2 also parents sib(13,5) → sibchild(14,6)            [sibling fork, joins at n2]
    //   tip also parents tipc(14,7)                           [descendant of tip]
    var fc = ForkChoice.init(testing.allocator);
    defer fc.deinit();
    const root = hk(10, 1);
    const n1 = hk(11, 2);
    const n2 = hk(12, 3);
    const tip = hk(13, 4);
    const sib = hk(13, 5);
    const sibchild = hk(14, 6);
    const tipc = hk(14, 7);
    try fc.addNewLeafSlot(root, null);
    try fc.addNewLeafSlot(n1, root);
    try fc.addNewLeafSlot(n2, n1);
    try fc.addNewLeafSlot(tip, n2);
    try fc.addNewLeafSlot(sib, n2);
    try fc.addNewLeafSlot(sibchild, sib);
    try fc.addNewLeafSlot(tipc, tip);

    var lv = gossip_votes.LatestGossipVotes.init(testing.allocator);
    defer lv.deinit();
    const V1 = [_]u8{0xA1} ** 32; // votes tip EXACTLY (exact-ancestry voter) → enters at tip
    const V2 = [_]u8{0xA2} ** 32; // votes n2 EXACTLY (exact-ancestry voter) → enters at n2, NOT tip
    const V3 = [_]u8{0xA3} ** 32; // votes tipc (descendant of tip) → walk up → enters at tip
    const V4 = [_]u8{0xA4} ** 32; // votes sibchild (SIBLING fork) → joins at n2 → n2 + deeper, NOT tip
    const V5 = [_]u8{0xA5} ** 32; // votes a key NOT in the tree → contributes 0 everywhere
    _ = try lv.checkAddVote(V1, tip.slot, tip.hash.data);
    _ = try lv.checkAddVote(V2, n2.slot, n2.hash.data);
    _ = try lv.checkAddVote(V3, tipc.slot, tipc.hash.data);
    _ = try lv.checkAddVote(V4, sibchild.slot, sibchild.hash.data);
    _ = try lv.checkAddVote(V5, 999, [_]u8{0xEE} ** 32);

    const rows = [_]KatCtx.StakeRow{
        .{ .pk = V1, .stake = 7 },
        .{ .pk = V2, .stake = 11 },
        .{ .pk = V3, .stake = 13 },
        .{ .pk = V4, .stake = 17 },
        .{ .pk = V5, .stake = 19 },
    };
    const ctx = KatCtx{ .fc = &fc, .stakes = &rows };

    const vals = try assertMatchesReference(CAP, &fc, tip, &lv, &ctx);

    // Direction gate: tip sees only voters entering at the tip (V1+V3 = 20); root sees
    // ALL on-tree voters (V1+V2+V3+V4 = 48; V5 off-tree excluded). A FLIPPED prefix-sum
    // direction would make these equal (or swap them) → this line fails loudly.
    try testing.expectEqual(@as(u64, 7 + 13), vals.tip); // V1 + V3
    try testing.expectEqual(@as(u64, 7 + 11 + 13 + 17), vals.root); // V1+V2+V3+V4, NOT V5
    try testing.expect(vals.tip < vals.root);

    // Spot-check the reference directly at the middle node so the equality loop above
    // is anchored to a hand-computed value too: n2 = V1+V2+V3+V4 (everything but V5).
    try testing.expectEqual(@as(u64, 48), lv.stakeForSlotAncestryKey(n2.slot, n2.hash.data, &ctx));
    // tip via reference excludes V2 (n2-exact) and V4 (sibling): only V1+V3 = 20.
    try testing.expectEqual(@as(u64, 20), lv.stakeForSlotAncestryKey(tip.slot, tip.hash.data, &ctx));
}

test "gossip-precompute: CAP truncation — voter joining below the collected window contributes 0 (matches reference)" {
    // Build a chain DEEPER than a tiny cap so the collected ancestry is truncated and
    // root is NOT collected. A voter whose fork joins BELOW the window must contribute
    // 0 to every collected node — and the precompute must still equal the reference
    // (which is queried only at the collected, near-tip nodes).
    var fc = ForkChoice.init(testing.allocator);
    defer fc.deinit();

    // Linear chain slots 0..9 (10 nodes), hash byte = slot+1 to keep keys distinct.
    var keys: [10]SlotHashKey = undefined;
    for (0..10) |i| keys[i] = hk(@intCast(i), @intCast(i + 1));
    try fc.addNewLeafSlot(keys[0], null);
    for (1..10) |i| try fc.addNewLeafSlot(keys[i], keys[i - 1]);
    // A sibling fork off slot 2 (BELOW the top-3 window when tip=slot 9): joinlow(3,50)
    // child of keys[2], then its descendant (4,51).
    const joinlow = hk(3, 50);
    const joinlow_c = hk(4, 51);
    try fc.addNewLeafSlot(joinlow, keys[2]);
    try fc.addNewLeafSlot(joinlow_c, joinlow);

    var lv = gossip_votes.LatestGossipVotes.init(testing.allocator);
    defer lv.deinit();
    const Vtip = [_]u8{0xB1} ** 32; // votes the tip (slot 9) → inside the window
    const Vlow = [_]u8{0xB2} ** 32; // votes joinlow_c → joins main chain at slot 2 (BELOW a top-3 window)
    _ = try lv.checkAddVote(Vtip, keys[9].slot, keys[9].hash.data);
    _ = try lv.checkAddVote(Vlow, joinlow_c.slot, joinlow_c.hash.data);
    const rows = [_]KatCtx.StakeRow{
        .{ .pk = Vtip, .stake = 100 },
        .{ .pk = Vlow, .stake = 200 },
    };
    const ctx = KatCtx{ .fc = &fc, .stakes = &rows };

    // cap=3 → collected ancestry is only {slot9, slot8, slot7}; root (slot0) truncated,
    // and Vlow's join (slot2) is below the window. Reference == precompute at all 3.
    const vals = try assertMatchesReference(3, &fc, keys[9], &lv, &ctx);
    // Every collected node is at/above slot 7; Vlow (joins at slot 2) is an ancestor of
    // NONE of them → only Vtip's 100 shows, uniformly across the truncated window.
    try testing.expectEqual(@as(u64, 100), vals.tip);
    try testing.expectEqual(@as(u64, 100), vals.root);
    // Sanity: the FULL-cap precompute DOES credit Vlow to slot 2 and below (reference-exact).
    const full = try assertMatchesReference(CAP, &fc, keys[9], &lv, &ctx);
    try testing.expectEqual(@as(u64, 100), full.tip); // tip still only Vtip
    try testing.expectEqual(@as(u64, 300), full.root); // root (slot 0) sees both Vtip + Vlow
}
