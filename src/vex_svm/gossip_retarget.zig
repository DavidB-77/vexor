//! Gossip-fed prop_retarget target selection — the root→tip heaviest-sibling walk,
//! extracted so prod (replay_stage.submitVote) and the KATs share ONE implementation.
//!
//! Orphan-safety is COMPARATIVE (heaviest-sibling), not an absolute >=1/3 floor: an
//! absolute floor still confirms a ~40% near-even-loser orphan (advisor 2026-07-01).
//! The walk accumulates `chain_clean` ROOT->TIP: chain_clean(node)=chain_clean(parent)
//! AND our child strictly beats every sibling by combined stake. gv_safe = the highest
//! (nearest-tip) node still chain_clean AND combined>1/3. In a freeze-race the losing
//! fork's fork-point is contested (canonical sibling >= us) -> chain_clean goes false
//! there -> gv_safe backs off to the shared fork-point P (<= last_vote -> withhold).
//!
//! WALK DIRECTION IS LOad-BEARING: tip->root accumulation is INVERTED and votes the
//! near-even orphan (its failing fork point is below it, unvisited -> reads clean). The
//! `near-even orphan 2 slots above divergence` KAT below is the discriminating gate.

const std = @import("std");
const fork_choice = @import("vex_consensus").fork_choice;

pub const SlotHashKey = fork_choice.SlotHashKey;
pub const ForkChoice = fork_choice.ForkChoice;

pub const Result = struct {
    gv_safe: ?SlotHashKey = null, // highest chain_clean AND combined>1/3 (THE armed target)
    gv_floor: ?SlotHashKey = null, // highest combined>1/3, NO sibling guard (unsafe probe)
    gv_majority: ?SlotHashKey = null, // highest chain_clean AND combined>1/2 (plurality probe)
    landed_tgt: ?SlotHashKey = null, // highest landed-only>1/3 (today's lagging baseline)
    contested_at: ?u64 = null, // first (root-ward) contested fork point
};

/// Root->tip heaviest-sibling walk. `sctx` (duck-typed) must expose:
///   fn combined(sctx, k: SlotHashKey) u64  — landed +| hash-aware gossip stake
///   fn landed(sctx, k: SlotHashKey) u64    — landed-only (baseline probe)
/// Reads the fork tree only through fc.ancestorIterator + fc.childrenOf.
pub fn walk(fc: *const ForkChoice, start_key: SlotHashKey, threshold: u64, majority: u64, sctx: anytype) Result {
    // Collect ancestry tip->root (bounded — races are near-tip; deeper is assumed clean).
    const CAP = 256;
    var chain: [CAP]SlotHashKey = undefined;
    var nchain: usize = 0;
    {
        var first = true;
        var it = fc.ancestorIterator(start_key);
        while (nchain < CAP) {
            const nkey = if (first) start_key else (it.next() orelse break);
            first = false;
            chain[nchain] = nkey;
            nchain += 1;
        }
    }
    // Process ROOT->TIP: chain[nchain-1] is deepest (root-ward), chain[0] is the tip.
    var res = Result{};
    var chain_clean = true; // clean below the deepest collected node (races are near-tip)
    var i: usize = nchain;
    while (i > 0) {
        i -= 1;
        const node = chain[i];
        if (i + 1 < nchain) { // fork point between parent chain[i+1] and node chain[i]
            const parent = chain[i + 1];
            const ours = sctx.combined(node);
            var win = true;
            for (fc.childrenOf(parent)) |sib| {
                if (sib.slot == node.slot and std.mem.eql(u8, &sib.hash.data, &node.hash.data)) continue;
                if (sctx.combined(sib) >= ours) { // sibling ties/beats us -> contested
                    win = false;
                    break;
                }
            }
            if (!win) {
                if (chain_clean) res.contested_at = parent.slot; // highest (first) contested point
                chain_clean = false; // stays false for all more-tip-ward nodes
            }
        }
        const comb = sctx.combined(node);
        if (comb > threshold) res.gv_floor = node; // nearest-tip wins (root->tip, last assignment)
        if (chain_clean and comb > threshold) res.gv_safe = node;
        if (chain_clean and comb > majority) res.gv_majority = node;
        if (sctx.landed(node) > threshold) res.landed_tgt = node;
    }
    return res;
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS — a mock sctx (per-key combined/landed) + a real ForkChoice tree.
// ═══════════════════════════════════════════════════════════════════════════
const testing = std.testing;

fn k(slot: u64, b: u8) SlotHashKey {
    return .{ .slot = slot, .hash = .{ .data = [_]u8{b} ** 32 } };
}

const MockSCtx = struct {
    keys: []const SlotHashKey,
    combined_v: []const u64,
    landed_v: []const u64,
    fn idxOf(self: *const @This(), key: SlotHashKey) ?usize {
        for (self.keys, 0..) |kk, idx| if (SlotHashKey.eql(kk, key)) return idx;
        return null;
    }
    pub fn combined(self: *const @This(), key: SlotHashKey) u64 {
        return if (self.idxOf(key)) |idx| self.combined_v[idx] else 0;
    }
    pub fn landed(self: *const @This(), key: SlotHashKey) u64 {
        return if (self.idxOf(key)) |idx| self.landed_v[idx] else 0;
    }
};

test "gossip-retarget: near-even orphan 2 slots above divergence -> gv_safe backs off to P, NOT the orphan" {
    // THE DISCRIMINATING KAT (advisor 2026-07-01). Tree: root(100) -> P(101) -> {Q(102), C(102')} ,
    // Q -> O(103). O is the orphan TIP, 2 slots above the divergence point P. Q is O's parent (the
    // losing sibling); C is the canonical sibling of Q under P. Near-even: O-fork 40 vs C-fork 55.
    var fc = ForkChoice.init(testing.allocator);
    defer fc.deinit();
    const root = k(100, 1);
    const P = k(101, 2);
    const Q = k(102, 3); // orphan-side child of P
    const C = k(102, 4); // canonical sibling (same slot, different bank hash — a freeze-race)
    const O = k(103, 5); // orphan tip
    try fc.addNewLeafSlot(root, null);
    try fc.addNewLeafSlot(P, root);
    try fc.addNewLeafSlot(Q, P);
    try fc.addNewLeafSlot(C, P);
    try fc.addNewLeafSlot(O, Q);

    const keys = [_]SlotHashKey{ root, P, Q, C, O };
    const comb = [_]u64{ 95, 95, 40, 55, 40 }; // O/Q fork 40, C fork 55 (near-even loser is O)
    const land = [_]u64{ 95, 95, 40, 55, 40 };
    const sctx = MockSCtx{ .keys = &keys, .combined_v = &comb, .landed_v = &land };

    const res = walk(&fc, O, 30, 50, &sctx); // threshold=30, majority=50

    // gv_safe MUST be P (101) — the shared fork-point — NEVER the orphan O (103) or Q (102).
    // (An inverted tip->root walk would return O here — that is the bug this KAT guards.)
    try testing.expect(res.gv_safe != null);
    try testing.expectEqual(@as(u64, 101), res.gv_safe.?.slot);
    try testing.expectEqual(@as(u64, 101), res.contested_at.?); // Q loses to C at fork point P
    // The UNSAFE floor DID reach the orphan O — proof the heaviest-sibling guard (not the floor) saves us.
    try testing.expectEqual(@as(u64, 103), res.gv_floor.?.slot);
}

test "gossip-retarget: clean skip (orphan ~0 stake) -> gv_safe backs off to P, orphan never clears floor" {
    var fc = ForkChoice.init(testing.allocator);
    defer fc.deinit();
    const root = k(200, 1);
    const P = k(201, 2);
    const Q = k(202, 3);
    const C = k(202, 4);
    const O = k(203, 5);
    try fc.addNewLeafSlot(root, null);
    try fc.addNewLeafSlot(P, root);
    try fc.addNewLeafSlot(Q, P);
    try fc.addNewLeafSlot(C, P);
    try fc.addNewLeafSlot(O, Q);

    const keys = [_]SlotHashKey{ root, P, Q, C, O };
    const comb = [_]u64{ 91, 91, 1, 90, 1 }; // orphan fork ~0, canonical 90
    const land = [_]u64{ 91, 91, 1, 90, 1 };
    const sctx = MockSCtx{ .keys = &keys, .combined_v = &comb, .landed_v = &land };

    const res = walk(&fc, O, 30, 50, &sctx);
    try testing.expectEqual(@as(u64, 201), res.gv_safe.?.slot); // backs off to P
    // clean skip: orphan never clears the floor either, so gv_floor also stops at P.
    try testing.expectEqual(@as(u64, 201), res.gv_floor.?.slot);
}

test "gossip-retarget: 3-way plurality -> heaviest-sibling tracks, majority stalls (why >1/2 is not primary)" {
    // root(300) -> P(301) -> {A(302,45), B(302',30), D(302'',25)}. Our tip is A. A is the 45% plurality
    // winner but never reaches >1/2. gv_safe (heaviest-sibling) tracks A; gv_majority (>1/2) does NOT.
    var fc = ForkChoice.init(testing.allocator);
    defer fc.deinit();
    const root = k(300, 1);
    const P = k(301, 2);
    const A = k(302, 3);
    const B = k(302, 4);
    const D = k(302, 6);
    try fc.addNewLeafSlot(root, null);
    try fc.addNewLeafSlot(P, root);
    try fc.addNewLeafSlot(A, P);
    try fc.addNewLeafSlot(B, P);
    try fc.addNewLeafSlot(D, P);

    const keys = [_]SlotHashKey{ root, P, A, B, D };
    const comb = [_]u64{ 100, 100, 45, 30, 25 };
    const land = [_]u64{ 100, 100, 45, 30, 25 };
    const sctx = MockSCtx{ .keys = &keys, .combined_v = &comb, .landed_v = &land };

    const res = walk(&fc, A, 30, 50, &sctx); // threshold=30, majority=50
    // Heaviest-sibling: A (302) strictly beats B(30) and D(25) -> gv_safe tracks A.
    try testing.expectEqual(@as(u64, 302), res.gv_safe.?.slot);
    // Majority: A=45 < 50 at the leaf, so gv_majority stalls back at P (301) — proving >1/2 would
    // withhold where heaviest-sibling correctly tracks the plurality winner.
    try testing.expectEqual(@as(u64, 301), res.gv_majority.?.slot);
}
