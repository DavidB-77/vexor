//! FIX #105 (Option A): PURE root-advance partition logic, extracted from
//! replay_stage.zig's advanceRoot call site so the parent-walk + abandoned-
//! sibling enumeration can be unit-tested independent of the live bank tree.
//!
//! Given a root advance prev_root → root and a snapshot of all live frozen
//! banks (slot + parent_slot), compute:
//!   - chain:    the ASCENDING rooted-ancestor slots in (prev_root, root]
//!               (highest-ancestor-wins on promote, mirrors Agave latest_slot)
//!   - siblings: PROVEN abandoned sibling slots in (prev_root, root) — frozen
//!               banks NOT on root's ancestor chain
//!   - chain_complete: true iff the parent-walk reached at-or-below prev_root
//!               without breaking on a missing/malformed bank.
//!
//! SAFETY: siblings are emitted ONLY when chain_complete. If the walk breaks
//! (a pruned bank severs the chain) the ancestor set is partial, so a real
//! ancestor could be misclassified as a sibling — the caller must purge
//! NOTHING in that case (accept residual pollution, never destroy rooted data).
const std = @import("std");

pub const SlotParent = struct { slot: u64, parent: ?u64 };

pub const RootPartition = struct {
    chain: std.ArrayListUnmanaged(u64) = .{},
    siblings: std.ArrayListUnmanaged(u64) = .{},
    chain_complete: bool = false,

    pub fn deinit(self: *RootPartition, alloc: std.mem.Allocator) void {
        self.chain.deinit(alloc);
        self.siblings.deinit(alloc);
    }
};

/// Cap matches sig_overlay MAX_SLOTS — a longer unrooted run is a consensus
/// stall, not normal operation.
const WALK_GUARD: usize = 4096;

pub fn partitionRootAdvance(
    alloc: std.mem.Allocator,
    prev_root: u64,
    root: u64,
    banks: []const SlotParent,
) !RootPartition {
    var result: RootPartition = .{};
    errdefer result.deinit(alloc);

    // Nothing to advance.
    if (root <= prev_root) {
        result.chain_complete = true;
        return result;
    }

    var parent_of = std.AutoHashMap(u64, ?u64).init(alloc);
    defer parent_of.deinit();
    for (banks) |b| try parent_of.put(b.slot, b.parent);

    var anc = std.AutoHashMap(u64, void).init(alloc);
    defer anc.deinit();

    // Walk root → parent → ... collecting ancestors in (prev_root, root]
    // (descending). Append BEFORE the parent lookup so a slot reached via a
    // child's parent pointer is treated as a proven ancestor even if its own
    // parent link can't be resolved (we just can't continue past it).
    var cur: u64 = root;
    var guard: usize = 0;
    while (guard < WALK_GUARD) : (guard += 1) {
        if (cur <= prev_root) {
            result.chain_complete = true;
            break;
        }
        try result.chain.append(alloc, cur);
        try anc.put(cur, {});
        const entry = parent_of.get(cur) orelse break; // cur not a known bank → incomplete
        const p = entry orelse break; // no parent recorded → incomplete
        if (p >= cur) break; // malformed parent link → incomplete
        cur = p;
    }

    // Ascending order: highest ancestor slot wins per-pubkey on promote.
    std.mem.reverse(u64, result.chain.items);

    // Proven siblings: frozen banks strictly inside (prev_root, root) that are
    // NOT on root's ancestor chain. ONLY when the chain is provably complete.
    if (result.chain_complete) {
        for (banks) |b| {
            if (b.slot > prev_root and b.slot < root and !anc.contains(b.slot)) {
                try result.siblings.append(alloc, b.slot);
            }
        }
    }

    return result;
}

/// CARRIER #7 LAYER 2 (2026-06-10): pure ancestry predicate for the root-
/// advance guard. TRUE iff `candidate_root` lies on the parent-chain ancestry
/// of `voted_slot` (inclusive: candidate_root == voted_slot is on it).
///
/// `ctx` is any type exposing `getParent(slot: u64) ?u64` (production: the
/// durable AccountsDb.slot_parents map under shared lock — the SAME source
/// partitionRootAdvance trusts; tests: a plain hashmap).
///
/// Conservative by construction: a broken chain (missing parent link) or a
/// walk longer than WALK_GUARD (consensus-stall shape, same cap as the
/// partition walk) returns FALSE — the caller must then REFUSE the root
/// advance (keep the previous root; a deferred advance is retried on the next
/// vote, while advancing to an off-ancestry root would promote an abandoned
/// fork's writes into the rooted store and purge the canonical siblings —
/// the carrier #7 poison @414406146).
///
/// Mirrors Agave's structural property that BankForks::set_root roots a bank
/// ON THE WORKING FORK'S ANCESTRY, never a bare slot number.
pub fn rootOnVotedAncestry(ctx: anytype, candidate_root: u64, voted_slot: u64) bool {
    if (candidate_root == voted_slot) return true;
    if (candidate_root > voted_slot) return false; // a root above the voted bank is never its ancestor
    var p: u64 = voted_slot;
    var guard: usize = 0;
    while (guard < WALK_GUARD) : (guard += 1) {
        const parent = ctx.getParent(p) orelse return false; // chain broken → cannot prove → refuse
        if (parent >= p) return false; // malformed/cycle guard (same as partition walk)
        p = parent;
        if (p == candidate_root) return true;
        if (p < candidate_root) return false; // walked PAST the candidate — it is on a different fork (the 146 shape)
    }
    return false; // guard exhausted → refuse (consensus stall, never a silent promote)
}

// ───────────────────────────────────────────────────────────────────────────
// Tests — the 4 cases the advisor required (call-site logic was untested).
// Run with: zig build test-root-partition
// ───────────────────────────────────────────────────────────────────────────

test "partition: +1 advance (512→513) → chain [513], no siblings" {
    const a = std.testing.allocator;
    const banks = [_]SlotParent{.{ .slot = 513, .parent = 512 }};
    var p = try partitionRootAdvance(a, 512, 513, &banks);
    defer p.deinit(a);
    try std.testing.expect(p.chain_complete);
    try std.testing.expectEqualSlices(u64, &[_]u64{513}, p.chain.items);
    try std.testing.expectEqual(@as(usize, 0), p.siblings.items.len);
}

test "partition: skip advance with sibling (512→515, 514 off 510) → chain [513,515], siblings [514]" {
    // The actual slot-733 carrier shape: main chain 512→513→515; slot 514 is a
    // sibling branched off 510, abandoned. Root advances 512→515.
    const a = std.testing.allocator;
    const banks = [_]SlotParent{
        .{ .slot = 513, .parent = 512 },
        .{ .slot = 514, .parent = 510 }, // abandoned sibling
        .{ .slot = 515, .parent = 513 },
    };
    var p = try partitionRootAdvance(a, 512, 515, &banks);
    defer p.deinit(a);
    try std.testing.expect(p.chain_complete);
    try std.testing.expectEqualSlices(u64, &[_]u64{ 513, 515 }, p.chain.items);
    try std.testing.expectEqualSlices(u64, &[_]u64{514}, p.siblings.items);
}

test "partition: multi-slot jump (510→515) → ascending chain, 514 sibling" {
    const a = std.testing.allocator;
    const banks = [_]SlotParent{
        .{ .slot = 511, .parent = 510 },
        .{ .slot = 512, .parent = 511 },
        .{ .slot = 513, .parent = 512 },
        .{ .slot = 514, .parent = 510 }, // abandoned sibling
        .{ .slot = 515, .parent = 513 },
    };
    var p = try partitionRootAdvance(a, 510, 515, &banks);
    defer p.deinit(a);
    try std.testing.expect(p.chain_complete);
    try std.testing.expectEqualSlices(u64, &[_]u64{ 511, 512, 513, 515 }, p.chain.items);
    try std.testing.expectEqualSlices(u64, &[_]u64{514}, p.siblings.items);
}

test "partition: incomplete chain (pruned bank) → chain_complete=false, NO siblings purged" {
    // 513 is missing from the bank snapshot (pruned), severing the walk below
    // it. We still promote what we proved (513 reached via 515's parent ptr),
    // but purge NOTHING — the conservative guard.
    const a = std.testing.allocator;
    const banks = [_]SlotParent{
        .{ .slot = 514, .parent = 510 }, // would-be sibling, but...
        .{ .slot = 515, .parent = 513 }, // 513 not in snapshot → walk breaks
    };
    var p = try partitionRootAdvance(a, 512, 515, &banks);
    defer p.deinit(a);
    try std.testing.expect(!p.chain_complete);
    try std.testing.expectEqualSlices(u64, &[_]u64{ 513, 515 }, p.chain.items);
    try std.testing.expectEqual(@as(usize, 0), p.siblings.items.len); // never purge on uncertainty
}

test "partition: no-op when root <= prev_root" {
    const a = std.testing.allocator;
    const banks = [_]SlotParent{.{ .slot = 500, .parent = 499 }};
    var p = try partitionRootAdvance(a, 513, 513, &banks);
    defer p.deinit(a);
    try std.testing.expect(p.chain_complete);
    try std.testing.expectEqual(@as(usize, 0), p.chain.items.len);
    try std.testing.expectEqual(@as(usize, 0), p.siblings.items.len);
}

// ───────────────────────────────────────────────────────────────────────────
// CARRIER #7 LAYER 2 KATs — rootOnVotedAncestry (414406146 carrier topology)
// ───────────────────────────────────────────────────────────────────────────

const MapParentCtx = struct {
    m: *const std.AutoHashMap(u64, u64),
    pub fn getParent(self: @This(), slot: u64) ?u64 {
        return self.m.get(slot);
    }
};

fn carrierMap(a: std.mem.Allocator) !std.AutoHashMap(u64, u64) {
    // The live carrier topology (slots mod 414406000):
    //   canonical: 140 → 141 → 142 → 143 → 144 → 145 → 147
    //   fork:                    142 → 146   (cluster SKIPPED 146)
    var m = std.AutoHashMap(u64, u64).init(a);
    try m.put(141, 140);
    try m.put(142, 141);
    try m.put(143, 142);
    try m.put(144, 143);
    try m.put(145, 144);
    try m.put(146, 142); // the abandoned fork block
    try m.put(147, 145);
    return m;
}

test "carrier #7: rootOnVotedAncestry REFUSES the abandoned-fork root (146 vs voted 147)" {
    const a = std.testing.allocator;
    var m = try carrierMap(a);
    defer m.deinit();
    const ctx = MapParentCtx{ .m = &m };

    // THE carrier: tower root = fork-146, voted bank = canonical 147. The walk
    // 147→145→144→143→142 passes BELOW 146 without hitting it → refuse.
    // (Live, this advance promoted fork-146's writes and PURGED canonical
    // 143/144/145 — the rooted-store poison behind the −34 epoch credits.)
    try std.testing.expect(!rootOnVotedAncestry(ctx, 146, 147));

    // Canonical ancestors of 147 are accepted.
    try std.testing.expect(rootOnVotedAncestry(ctx, 145, 147));
    try std.testing.expect(rootOnVotedAncestry(ctx, 143, 147));
    try std.testing.expect(rootOnVotedAncestry(ctx, 140, 147));

    // Inclusive: the voted slot itself.
    try std.testing.expect(rootOnVotedAncestry(ctx, 147, 147));

    // A root ABOVE the voted bank is never its ancestor.
    try std.testing.expect(!rootOnVotedAncestry(ctx, 148, 147));

    // Symmetric view: had we voted the FORK bank 146, canonical 143/144/145
    // are NOT on its ancestry (142 and below are).
    try std.testing.expect(!rootOnVotedAncestry(ctx, 145, 146));
    try std.testing.expect(rootOnVotedAncestry(ctx, 142, 146));
}

test "carrier #7: rootOnVotedAncestry refuses on broken chain (conservative)" {
    const a = std.testing.allocator;
    var m = try carrierMap(a);
    defer m.deinit();
    _ = m.remove(144); // sever the chain: 147→145→144→(missing)
    const ctx = MapParentCtx{ .m = &m };

    // 145 still provable (reached before the break)...
    try std.testing.expect(rootOnVotedAncestry(ctx, 145, 147));
    // ...but anything below the break cannot be PROVEN → refuse (never
    // advance the root on uncertainty; retried next vote).
    try std.testing.expect(!rootOnVotedAncestry(ctx, 142, 147));
    try std.testing.expect(!rootOnVotedAncestry(ctx, 140, 147));
}

test "carrier #7: rootOnVotedAncestry malformed parent link (cycle) refuses" {
    const a = std.testing.allocator;
    var m = std.AutoHashMap(u64, u64).init(a);
    defer m.deinit();
    try m.put(200, 199);
    try m.put(199, 199); // self-cycle
    const ctx = MapParentCtx{ .m = &m };
    try std.testing.expect(rootOnVotedAncestry(ctx, 199, 200));
    try std.testing.expect(!rootOnVotedAncestry(ctx, 198, 200)); // cycle below → refuse, no hang
}
