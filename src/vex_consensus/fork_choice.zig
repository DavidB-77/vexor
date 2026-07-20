//! Vexor Fork Choice — byte-for-byte port of Agave's HeaviestSubtreeForkChoice.
//!
//! Canonical source:
//!   agave-4.0.0-rc.1/core/src/consensus/heaviest_subtree_fork_choice.rs
//!   (Apache-2.0, Anza Inc. 2025)
//!
//! Phase 1 (this file): stake aggregation + (Slot, Hash) keying + vote migration.
//!   * SlotHashKey-keyed fork_infos    (Agave line 27, 186)
//!   * latest_votes HashMap            (Agave line 187)
//!   * add_new_leaf_slot               (Agave 457-500)
//!   * propagate_new_leaf              (Agave 742-784)
//!   * aggregate_slot                  (Agave 856-948)
//!   * add_votes / generate_update_operations / process_update_operations
//!                                     (Agave 343-357, 972-1104)
//!   * set_tree_root                   (Agave 363-378)
//!   * is_best_child / is_deepest_child (Agave 504-563)
//!   * Vote migration with per-epoch stake lookup — fixes team-b stake=0 bug.
//!
//! Future phases (NOT in this file):
//!   - Phase 2: switch threshold, tower lockouts, heaviest_slot_on_same_voted_fork
//!   - Phase 3: dump-then-repair (split_off, merge, mark_fork_invalid_candidate)
//!   - Phase 4: progress map / tower-sync integration
//!
//! Design constraints:
//!   - Pure Zig stdlib (no FFI, no bindings).
//!   - Production-grade error handling; allocations propagate, no `catch unreachable`
//!     for paths that can fail with corrupt input.
//!   - Saturating math for stake subtraction (defensive — Agave panics on underflow).
//!   - Every algorithmic choice cites Agave file:line in comments.

const std = @import("std");
const core = @import("core");
const vote_mod = @import("vote.zig");

const Vote = vote_mod.Vote;

// ═══════════════════════════════════════════════════════════════════════════════
// SlotHashKey — Agave `pub type SlotHashKey = (Slot, Hash)` (line 27)
//
// The KEY structural prerequisite: two equivocating blocks at the same slot but
// with different bank hashes are DISTINCT nodes in the fork tree. Without this,
// fork choice cannot represent — and therefore cannot choose between — sibling
// versions of the same slot.
// ═══════════════════════════════════════════════════════════════════════════════

pub const SlotHashKey = extern struct {
    // IMPORTANT: never use std.AutoHashMap with SlotHashKey — always go through
    // SlotHashKeyContext (defined below). `extern struct` can introduce
    // padding bytes that AutoHashMap's autoHash would feed into Wyhash,
    // hashing uninitialized memory.
    slot: core.Slot,
    hash: core.Hash,

    pub const ZERO: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };

    pub fn eql(a: SlotHashKey, b: SlotHashKey) bool {
        return a.slot == b.slot and std.mem.eql(u8, &a.hash.data, &b.hash.data);
    }

    /// Lexicographic order on (slot ASC, hash ASC bytes) — mirrors Rust derive(Ord)
    /// on `(Slot, Hash)` where Hash is a 32-byte array compared byte-by-byte.
    pub fn order(a: SlotHashKey, b: SlotHashKey) std.math.Order {
        if (a.slot != b.slot) return std.math.order(a.slot, b.slot);
        return std.mem.order(u8, &a.hash.data, &b.hash.data);
    }

    pub fn lessThan(a: SlotHashKey, b: SlotHashKey) bool {
        return order(a, b) == .lt;
    }
};

/// HashMap context for SlotHashKey. Uses Wyhash over (slot bytes ++ hash bytes).
pub const SlotHashKeyContext = struct {
    pub fn hash(_: SlotHashKeyContext, k: SlotHashKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&k.slot));
        h.update(&k.hash.data);
        return h.final();
    }
    pub fn eql(_: SlotHashKeyContext, a: SlotHashKey, b: SlotHashKey) bool {
        return SlotHashKey.eql(a, b);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// ForkInfo — Agave `struct ForkInfo` (lines 89-113)
//
// Per-node state in the fork tree. Each (Slot, Hash) pair has exactly one ForkInfo.
// ═══════════════════════════════════════════════════════════════════════════════

pub const ForkWeight = u64;

pub const ForkInfo = struct {
    /// Stake that voted for exactly this slot (not descendants).
    stake_voted_at: ForkWeight,
    /// stake_voted_at + sum of children's stake_voted_subtree.
    stake_voted_subtree: ForkWeight,
    /// Tree height of the subtree rooted here. Leaf = 1.
    height: usize,
    /// Heaviest descendant (excludes invalid forks via is_candidate).
    best_slot: SlotHashKey,
    /// Deepest descendant (no validity filter — for fallback voting).
    deepest_slot: SlotHashKey,
    parent: ?SlotHashKey,
    /// Children, kept sorted by SlotHashKey.order — mirrors Rust BTreeSet.
    children: std.ArrayListUnmanaged(SlotHashKey),
    /// Latest ancestor (or self) marked invalid; null if all ancestors valid.
    /// If this slot itself is marked, latest_invalid_ancestor == self_slot.
    latest_invalid_ancestor: ?core.Slot,
    /// True if this slot or any descendant reached duplicate-confirmed threshold.
    is_duplicate_confirmed: bool,

    pub fn deinit(self: *ForkInfo, allocator: std.mem.Allocator) void {
        self.children.deinit(allocator);
    }

    /// Whether the fork rooted here is included in fork choice.
    /// Agave line 125.
    pub fn isCandidate(self: *const ForkInfo) bool {
        return self.latest_invalid_ancestor == null;
    }

    /// Agave line 133.
    pub fn setDuplicateConfirmed(self: *ForkInfo) void {
        self.is_duplicate_confirmed = true;
        self.latest_invalid_ancestor = null;
    }

    /// 2026-05-28 FIX #87 Phase 3 port — Agave heaviest_subtree_fork_choice.rs:140-158.
    /// When an ancestor is marked invalid, every descendant's latest_invalid_ancestor
    /// must be updated to remember the LATEST (highest slot) invalid ancestor.
    /// Updates only if newly_invalid_ancestor is strictly greater than current —
    /// preserves the "highest invalid ancestor wins" invariant.
    pub fn updateWithNewlyInvalidAncestor(
        self: *ForkInfo,
        my_key: SlotHashKey,
        newly_invalid_ancestor: core.Slot,
    ) void {
        // Agave: assert(!self.is_duplicate_confirmed). We soft-fail with a log
        // since we'd rather not panic in production on an invariant gap.
        if (self.is_duplicate_confirmed) {
            std.log.warn(
                "[FORK-INFO-INVALID-ANCESTOR] refusing update — slot={d} hash={x} is duplicate_confirmed " ++
                    "(would-be invalid_ancestor={d})",
                .{ my_key.slot, my_key.hash.data[0..8].*, newly_invalid_ancestor },
            );
            return;
        }
        const should_update = if (self.latest_invalid_ancestor) |lia|
            newly_invalid_ancestor > lia
        else
            true;
        if (should_update) {
            std.log.warn(
                "[FORK-INFO-INVALID-ANCESTOR] slot={d} hash={x} latest_invalid_ancestor: {?d} -> {d}",
                .{ my_key.slot, my_key.hash.data[0..8].*, self.latest_invalid_ancestor, newly_invalid_ancestor },
            );
            self.latest_invalid_ancestor = newly_invalid_ancestor;
        }
    }

    /// 2026-05-28 FIX #87 Phase 3 port — Agave heaviest_subtree_fork_choice.rs:121-139.
    /// When an ancestor is marked VALID (duplicate-confirmed), clear our
    /// latest_invalid_ancestor IF it was at-or-below the newly-valid slot.
    pub fn updateWithNewlyValidAncestor(
        self: *ForkInfo,
        my_key: SlotHashKey,
        newly_valid_ancestor: core.Slot,
    ) void {
        if (self.latest_invalid_ancestor) |lia| {
            if (lia <= newly_valid_ancestor) {
                std.log.info(
                    "[FORK-INFO-VALID-ANCESTOR] slot={d} hash={x} clearing latest_invalid_ancestor {d} " ++
                        "because {d} was duplicate-confirmed",
                    .{ my_key.slot, my_key.hash.data[0..8].*, lia, newly_valid_ancestor },
                );
                self.latest_invalid_ancestor = null;
            }
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// HeaviestSubtreeForkChoice — Agave struct (line 185)
// ═══════════════════════════════════════════════════════════════════════════════

const ForkInfoMap = std.HashMapUnmanaged(
    SlotHashKey,
    ForkInfo,
    SlotHashKeyContext,
    std.hash_map.default_max_load_percentage,
);

const SlotHashKeySet = std.HashMapUnmanaged(
    SlotHashKey,
    void,
    SlotHashKeyContext,
    std.hash_map.default_max_load_percentage,
);

const SlotHashKeyIndex = std.HashMapUnmanaged(
    SlotHashKey,
    usize,
    SlotHashKeyContext,
    std.hash_map.default_max_load_percentage,
);

pub const HeaviestSubtreeForkChoice = struct {
    allocator: std.mem.Allocator,
    fork_infos: ForkInfoMap,
    /// pubkey -> last (slot, hash) this validator voted for.
    /// Used for vote migration: when pubkey moves vote from old → new, we
    /// subtract their stake at old and add at new. Missing in pre-port Vexor —
    /// without this, votes double-count and stake aggregation is unreliable.
    latest_votes: std.AutoHashMapUnmanaged(core.Pubkey, SlotHashKey),
    /// Current finalized root of the tree.
    tree_root: SlotHashKey,
    /// Whether the tree has been initialized with a root.
    initialized: bool,

    const Self = @This();
    const Ctx = SlotHashKeyContext{};

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .fork_infos = .{},
            .latest_votes = .{},
            .tree_root = SlotHashKey.ZERO,
            .initialized = false,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.fork_infos.valueIterator();
        while (it.next()) |info| info.deinit(self.allocator);
        self.fork_infos.deinit(self.allocator);
        self.latest_votes.deinit(self.allocator);
    }

    /// Seed the tree with a root. Must be called before any addNewLeafSlot
    /// whose parent is the root. Idempotent on re-seed with same root.
    /// Mirrors Agave `new(tree_root: SlotHashKey)` (line 218).
    pub fn seedRoot(self: *Self, root: SlotHashKey) !void {
        if (self.initialized) {
            if (SlotHashKey.eql(self.tree_root, root)) return;
            // Different root — caller wants a re-seed (e.g. snapshot restart).
            const alloc = self.allocator;
            self.deinit();
            self.* = Self.init(alloc);
        }
        self.tree_root = root;
        try self.fork_infos.putContext(self.allocator, root, .{
            .stake_voted_at = 0,
            .stake_voted_subtree = 0,
            .height = 1,
            .best_slot = root,
            .deepest_slot = root,
            .parent = null,
            .children = .{},
            .latest_invalid_ancestor = null,
            .is_duplicate_confirmed = true, // root is implicitly duplicate-confirmed
        }, Ctx);
        self.initialized = true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Read accessors — Agave public read methods
    // ─────────────────────────────────────────────────────────────────────────

    pub fn containsBlock(self: *const Self, key: SlotHashKey) bool {
        return self.fork_infos.containsContext(key, Ctx);
    }

    /// Best descendant of `key` (excludes invalid forks). Agave line 298.
    pub fn bestSlotOf(self: *const Self, key: SlotHashKey) ?SlotHashKey {
        return if (self.fork_infos.getContext(key, Ctx)) |info| info.best_slot else null;
    }

    /// Deepest descendant of `key`. Agave line 304.
    pub fn deepestSlotOf(self: *const Self, key: SlotHashKey) ?SlotHashKey {
        return if (self.fork_infos.getContext(key, Ctx)) |info| info.deepest_slot else null;
    }

    /// Heaviest slot anywhere in the tree. Agave line 310.
    pub fn bestOverallSlot(self: *const Self) SlotHashKey {
        return self.bestSlotOf(self.tree_root) orelse self.tree_root;
    }

    /// Agave `heaviest_slot_on_same_voted_fork` (heaviest_subtree_fork_choice.rs:1138-1207)
    /// — the FailedSwitch fallback target: stay on our OWN last-voted fork.
    ///   * `is_candidate(last) == Some(true)`  → its heaviest descendant `best_slot`.
    ///   * `is_candidate(last) == Some(false)` → its `deepest_slot` — our last fork was
    ///     marked invalid (duplicate); Agave keeps building on it (Scenario 1/2) because a
    ///     duplicate fork can still become duplicate-confirmed.
    ///   * key absent (`None`) → null. Agave panics here unless the vote is stray; we
    ///     soft-fail to null (the caller then keeps its current target), which is safe.
    /// The prior call site used `deepest_slot` UNCONDITIONALLY (the Some(false) branch
    /// only) — non-canonical when our last vote is still a valid candidate.
    pub fn heaviestSlotOnSameVotedFork(self: *const Self, last_key: SlotHashKey) ?SlotHashKey {
        return switch (self.isCandidate(last_key) orelse return null) {
            true => self.bestSlotOf(last_key),
            false => self.deepestSlotOf(last_key),
        };
    }

    pub fn stakeVotedSubtree(self: *const Self, key: SlotHashKey) ?u64 {
        return if (self.fork_infos.getContext(key, Ctx)) |info| info.stake_voted_subtree else null;
    }

    pub fn stakeVotedAt(self: *const Self, key: SlotHashKey) ?u64 {
        return if (self.fork_infos.getContext(key, Ctx)) |info| info.stake_voted_at else null;
    }

    pub fn heightOf(self: *const Self, key: SlotHashKey) ?usize {
        return if (self.fork_infos.getContext(key, Ctx)) |info| info.height else null;
    }

    pub fn treeRoot(self: *const Self) SlotHashKey {
        return self.tree_root;
    }

    pub fn parentOf(self: *const Self, key: SlotHashKey) ?SlotHashKey {
        return if (self.fork_infos.getContext(key, Ctx)) |info| info.parent else null;
    }

    /// Read-only slice of a node's child keys, for sibling comparison (the
    /// heaviest-sibling safety guard in prop_retarget). Empty slice if the node is
    /// absent or has no children. The returned slice aliases the node's `children`
    /// backing store, so the caller must hold whatever lock guards concurrent
    /// mutation of the fork tree for as long as it reads the slice (same discipline
    /// as `stakeVotedSubtree`/`ancestorIterator`).
    pub fn childrenOf(self: *const Self, key: SlotHashKey) []const SlotHashKey {
        if (self.fork_infos.getContext(key, Ctx)) |info| return info.children.items;
        return &.{};
    }

    pub fn isCandidate(self: *const Self, key: SlotHashKey) ?bool {
        return if (self.fork_infos.getContext(key, Ctx)) |info| info.isCandidate() else null;
    }

    pub fn latestInvalidAncestor(self: *const Self, key: SlotHashKey) ?core.Slot {
        if (self.fork_infos.getContext(key, Ctx)) |info| return info.latest_invalid_ancestor;
        return null;
    }

    /// True iff this node (or a descendant) reached the duplicate-confirmed
    /// threshold. null when the key is absent from the tree. Used by the
    /// replay_stage doRootAdvance root-guard G2 (4b) as a future-proof ALLOW
    /// short-circuit — today only the genesis root is duplicate-confirmed, until
    /// Part 2 wires the cluster duplicate-confirm feed that sets it for others.
    pub fn isDuplicateConfirmed(self: *const Self, key: SlotHashKey) ?bool {
        if (self.fork_infos.getContext(key, Ctx)) |info| return info.is_duplicate_confirmed;
        return null;
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.fork_infos.size == 0;
    }

    /// Live node count of the fork tree. Used by the Phase-1 setTreeRoot wiring
    /// soak gate to observe the bounded-tree plateau (nodeCount stops growing
    /// monotonically once re-rooting prunes non-descendants on each root
    /// advance). Pure read — does not touch the tree.
    pub fn nodeCount(self: *const Self) usize {
        return self.fork_infos.size;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ancestor walk — Agave AncestorIterator (line 1382)
    // ─────────────────────────────────────────────────────────────────────────

    pub const AncestorIterator = struct {
        current: SlotHashKey,
        fork_infos: *const ForkInfoMap,

        pub fn next(self: *AncestorIterator) ?SlotHashKey {
            const info = self.fork_infos.getContext(self.current, Ctx) orelse return null;
            const p = info.parent orelse return null;
            self.current = p;
            return p;
        }
    };

    pub fn ancestorIterator(self: *const Self, start: SlotHashKey) AncestorIterator {
        return .{ .current = start, .fork_infos = &self.fork_infos };
    }

    /// Whether `candidate` is a strict ancestor of `node_key`. Excludes self.
    /// Agave line 719.
    pub fn isStrictAncestor(self: *const Self, candidate: SlotHashKey, node_key: SlotHashKey) bool {
        if (SlotHashKey.eql(candidate, node_key)) return false;
        if (candidate.slot > node_key.slot) return false;
        var it = self.ancestorIterator(node_key);
        while (it.next()) |a| if (SlotHashKey.eql(a, candidate)) return true;
        return false;
    }

    /// Slot-only ancestor query — convenience for replay_stage's is_same_fork
    /// check, which only has slot numbers (not bank hashes) at the callsite.
    /// Walks from any node at `node_slot` toward root. Returns true iff some
    /// node at `node_slot` has an ancestor at `candidate_slot`.
    pub fn isAncestorBySlot(self: *const Self, node_slot: core.Slot, candidate_slot: core.Slot) bool {
        if (candidate_slot == node_slot) return true;
        if (candidate_slot > node_slot) return false;
        var it = self.fork_infos.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.slot != node_slot) continue;
            var anc = self.ancestorIterator(entry.key_ptr.*);
            while (anc.next()) |a| {
                if (a.slot == candidate_slot) return true;
                if (a.slot < candidate_slot) break;
            }
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Switch-threshold proof — Agave Tower::make_check_switch_threshold_decision
    // (core/src/consensus.rs:959-1273), Tier-1 (second/latest_votes loop only).
    // ─────────────────────────────────────────────────────────────────────────

    /// SWITCH_FORK_THRESHOLD — Agave consensus.rs:158, Firedancer fd_tower.c:85.
    /// A cross-fork switch requires STRICTLY MORE than this fraction of total
    /// EPOCH stake to be locked out on forks the candidate descends from.
    pub const SWITCH_FORK_THRESHOLD: f64 = 0.38;

    pub const SwitchDecision = struct {
        /// Candidate descends from OUR last vote — Agave SameFork (no proof
        /// needed). When true, `would_switch` is also true (a same-fork vote
        /// is always permitted once lockout-clear).
        same_fork: bool,
        /// True iff `same_fork`, OR ≥38% of total epoch stake is locked out on
        /// forks from which `switch_slot` descends (a valid switch proof).
        would_switch: bool,
        locked_out_stake: u64,
        total_stake: u64,
        /// DIAG (2026-07-10 wedge 421109451): gossip-loop observability so the
        /// next incident log shows at a glance whether the real-time feed was
        /// present and contributing. 0/0 when the gossip loop never ran (early
        /// same-fork return, zero denominator, or landed loop already proved).
        gossip_considered: u32 = 0,
        gossip_counted: u32 = 0,
    };

    /// Greatest-common-ancestor of two slots, by walking the (Slot,Hash) tree's
    /// parent pointers (Agave greatest_common_ancestor, consensus.rs:947-956).
    /// Allocation-free two-pointer converge: advance the higher node toward the
    /// root until both pointers land on the IDENTICAL node (handles equivocating
    /// same-slot siblings). Returns null if either slot is absent from the tree
    /// or the chains never converge — caller treats null as "don't count" (the
    /// conservative, undercount direction).
    fn gcaBySlot(self: *const Self, a_slot: core.Slot, b_slot: core.Slot) ?core.Slot {
        var ka = self.firstKeyAtSlot(a_slot) orelse return null;
        var kb = self.firstKeyAtSlot(b_slot) orelse return null;
        var guard: usize = 0;
        while (!SlotHashKey.eql(ka, kb)) {
            guard += 1;
            if (guard > 2_000_000) return null; // safety backstop, never hit in practice
            // Advance the strictly-higher node; on equal slots advance `ka` so
            // an equivocating pair (same slot, different hash) still converges.
            if (ka.slot >= kb.slot) {
                ka = self.parentOf(ka) orelse return null;
            } else {
                kb = self.parentOf(kb) orelse return null;
            }
        }
        return ka.slot;
    }

    /// First (Slot,Hash) node found at `slot` (tree may hold duplicate-version
    /// siblings at one slot; slot-based ancestry collapses them, biasing
    /// conservative). O(tree size); only called on the rare cross-fork path.
    /// pub: also used by replay_stage doRootAdvance root-guards (4b) as the
    /// fallback candidate-root key resolver when the anchor-ancestry walk misses.
    pub fn firstKeyAtSlot(self: *const Self, slot: core.Slot) ?SlotHashKey {
        var it = self.fork_infos.iterator();
        while (it.next()) |e| if (e.key_ptr.slot == slot) return e.key_ptr.*;
        return null;
    }

    /// Tier-1 canonical port of `Tower::make_check_switch_threshold_decision`
    /// (Agave consensus.rs:959-1273) — the SECOND (latest_votes / gossip-frozen)
    /// loop ONLY. The first (lockout_intervals/descendants) loop and the
    /// duplicate-rollback / stray / major-unsynced corners are DELIBERATELY
    /// omitted; every omission UNDERCOUNTS `locked_out_stake` or defaults a
    /// corner to no-switch → the result can only FAIL-TO-SWITCH (a harmless
    /// liveness pause), never produce a false SwitchProof. CONSERVATIVE and
    /// ONE-DIRECTIONAL by construction.
    ///
    /// CORRECTION (2026-07-17, live wedge 422521275): `self.latest_votes`
    /// (fed by the caller's per-bank vote-account scan, see
    /// vex_svm/fork_choice_feed.zig) plays the role of Agave's PRIMARY,
    /// bank-derived loop (consensus.rs:1119-1218) collapsed to one vote per
    /// voter — NOT the secondary gossip loop, despite the "latest_votes"
    /// name. The admission rule for this loop was, until this fix, a
    /// strictly-newer-than-`last_voted_slot` filter — WRONG: confirmed
    /// against Agave's real primary loop (`interval.end >= last_voted_slot`
    /// then `!last_vote_ancestors.contains(start) && start > root`,
    /// consensus.rs:1190-1206 — no comparison to `last_voted_slot` by
    /// number) and Firedancer `fd_tower.c:550-555` (`!is_slot_descendant(...)
    /// && interval_slot > root_slot`, same shape). The strictly-newer rule is
    /// canonical ONLY for Agave's SECONDARY gossip loop (consensus.rs:1228,
    /// which Firedancer's switch_check does not even have). Applying it to
    /// this (primary-equivalent) loop silently excluded every voter whose
    /// current, genuinely-different-fork vote happened to number below
    /// `last_voted_slot` — exactly the case where our own dead fork raced
    /// ahead of the canonical one before dying. Fixed to `cand_slot >
    /// self.tree_root.slot` (newer than ROOT, matching Agave/FD) — fork
    /// ancestry + GCA/switch_slot descent (`switchProofVoteCounts` below,
    /// the ported `is_valid_switching_proof_vote`) does the real admission
    /// work, exactly as it does in both canonical implementations.
    ///
    /// ⚠ SAFETY: this is an ADDITIONAL liveness gate, NEVER a lockout override.
    /// Agave composes it as a pure AND — `!is_locked_out && switch.can_vote()`
    /// (fork_choice.rs:382-385); Firedancer states it in words (fd_tower.c:803
    /// "If we pass the switch check we can reset; if we ADDITIONALLY pass the
    /// lockout check we can also vote"). The switch proof NEVER releases tower
    /// lockout. The caller MUST already be lockout-clear; given that, even a
    /// wrong result here cannot cast a slashable vote — it only decides whether
    /// to bother switching forks.
    ///
    /// `stake_lookup_ctx` must expose `.lookup(core.Pubkey, core.Slot) u64`
    /// (the SAME adapter `addVotes` uses, keyed identically to `latest_votes` by
    /// construction). `total_stake` MUST be TOTAL epoch stake, NOT voted stake
    /// (Agave consensus.rs:965 heaviest_bank.total_epoch_stake()); a voted-stake
    /// denominator would shrink the denominator and inflate the ratio →
    /// switch-when-you-shouldn't.
    pub fn checkSwitchThreshold(
        self: *const Self,
        last_voted_slot: core.Slot,
        switch_slot: core.Slot,
        total_stake: u64,
        stake_lookup_ctx: anytype,
    ) SwitchDecision {
        // Landed-feed-only compatibility wrapper (pre-2026-07-10 signature).
        // Production callers should pass the real-time gossip observations —
        // see checkSwitchThresholdGossip below (wedge 421109451 root fix).
        return self.checkSwitchThresholdGossip(last_voted_slot, switch_slot, total_stake, stake_lookup_ctx, &.{});
    }

    /// Switch-threshold decision over BOTH canonical observation sources:
    ///
    ///   1. `latest_votes` — the LANDED feed (vote-account state from banks we
    ///      replayed, via buildVoteAccountBatch/addVotes). This is the only
    ///      source the pre-2026-07-10 code consulted.
    ///   2. `gossip_votes` — REAL-TIME gossip vote observations (CRDS tag-1),
    ///      the Agave `max_gossip_frozen_votes` second loop (consensus.rs:1222
    ///      "Check the latest votes for potentially gossip votes that haven't
    ///      landed yet").
    ///
    /// WHY BOTH ARE REQUIRED (P0 wedge 2026-07-10, slot 421109451): when our
    /// tower is on a losing fork, the landed feed structurally CANNOT prove the
    /// switch — every cluster voter's landed vote-state in OUR banks lags the
    /// tip by several slots (and freezes/prunes entirely across the fork), so
    /// the canonical strictly-newer filter (`cand_slot > last_voted_slot`,
    /// Agave consensus.rs:1228) rejects ALL of it while our own last vote rides
    /// our fork's tip → locked_out = 0/325M observed live → tower could never
    /// escape → on-chain lastVote froze → delinquency. Agave never wedges here
    /// precisely because its second loop reads gossip votes observed in real
    /// time, which lead the landed view by the same margin ours lagged.
    ///
    /// Gossip-entry predicate (all four canonical, in order):
    ///   a. strictly newer than our last vote (consensus.rs:1228);
    ///   b. NOT already counted via the landed loop (Agave
    ///      `locked_out_vote_accounts` dedup, consensus.rs:1224-1226);
    ///   c. the voted (slot, hash) is a bank WE FROZE — `fork_infos` contains
    ///      the exact key. This is Agave's `max_gossip_frozen_votes` admission
    ///      invariant (LatestValidatorVotesForFrozenBanks.check_add_vote only
    ///      inserts when `frozen_hash.is_some()`, i.e. after
    ///      UnfrozenGossipVerifiedVoteHashes matched the vote's hash against
    ///      our frozen bank's hash at freeze time). A hash mismatch (vote for a
    ///      duplicate version we did not freeze) or an unfrozen/unknown slot →
    ///      not counted (conservative, undercount-only);
    ///   d. the same memoized is_valid_switching_proof_vote tree-walk the
    ///      landed loop uses (consensus.rs:1249).
    ///
    /// Every deviation direction remains UNDERCOUNT-only → can only
    /// FAIL-TO-SWITCH, never manufacture a false SwitchProof. The ⚠ SAFETY
    /// contract above checkSwitchThreshold is unchanged: this is an ADDITIONAL
    /// liveness gate consulted ONLY when the caller is already lockout-clear;
    /// even a wrong result cannot cast a slashable vote.
    pub fn checkSwitchThresholdGossip(
        self: *const Self,
        last_voted_slot: core.Slot,
        switch_slot: core.Slot,
        total_stake: u64,
        stake_lookup_ctx: anytype,
        gossip_votes: []const PubkeyVote,
    ) SwitchDecision {
        // SameFork (Agave consensus.rs:1094): candidate == last vote, or the
        // candidate descends from our last vote. isAncestorBySlot(node, cand)
        // is true iff `cand` is an ancestor of `node`; so
        // isAncestorBySlot(switch_slot, last_voted_slot) == "switch descends
        // from last vote".
        if (switch_slot == last_voted_slot or self.isAncestorBySlot(switch_slot, last_voted_slot)) {
            return .{ .same_fork = true, .would_switch = true, .locked_out_stake = 0, .total_stake = total_stake };
        }
        // Different fork → require a switch proof. Guard the denominator
        // (total==0 → NaN ratio would compare false anyway; be explicit).
        if (total_stake == 0) {
            return .{ .same_fork = false, .would_switch = false, .locked_out_stake = 0, .total_stake = 0 };
        }
        var locked_out: u64 = 0;
        // latest_votes is one entry per pubkey by construction, so Agave's
        // per-voter `locked_out_vote_accounts` dedup set is unnecessary here.
        //
        // PERF MEMOIZATION (2026-07-06, task #32 starvation root fix): the per-voter
        // verdict depends ONLY on the candidate's SLOT — Agave rc.1 consensus.rs:1249
        // `is_valid_switching_proof_vote(*candidate_latest_frozen_vote /*a Slot*/,
        // last_voted_slot, switch_slot, ancestors, last_vote_ancestors)`; only the
        // STAKE (consensus.rs:1258) is per-pubkey. Thousands of voters cluster on a
        // handful of recent slots, so caching the verdict per unique slot collapses
        // O(voters × tree-walk) → O(unique_slots × tree-walk) + O(voters) lookups.
        // The un-memoized walk (isAncestor + gcaBySlot with its O(tree) firstKeyAtSlot
        // scans, per voter) starved the vote-submit path during fork churn — the
        // 2026-07-06 04:36Z/12:22Z vote-landing delinquencies (VEX_HEAVIEST_SHADOW).
        // Bounded stack cache, allocation-free; overflow falls back to computing (exact).
        const Memo = struct { slot: core.Slot, count: bool };
        var memo: [64]Memo = undefined;
        var memo_len: usize = 0;
        var it = self.latest_votes.iterator();
        while (it.next()) |e| {
            const pk = e.key_ptr.*;
            const cand_slot = e.value_ptr.slot;
            // FIX (switch-proof gossip-arming wedge, 2026-07-17): NOT a
            // strictly-newer-than-last-vote filter. Confirmed against Agave's
            // REAL primary bank-derived loop (consensus.rs:1182-1204,
            // `lockout_intervals.iter().filter(|interval| interval.end >=
            // last_voted_slot)` then `!last_vote_ancestors.contains(start) &&
            // start > root` — no comparison to `last_voted_slot` by number)
            // and Firedancer's `switch_check` (fd_tower.c:550-555, identical
            // shape: `!is_slot_descendant(interval_slot, vote_slot) &&
            // interval_slot > root_slot`). The strictly-newer-than-last-vote
            // rule is canonical ONLY for Agave's SECONDARY gossip loop
            // (consensus.rs:1228) — see the gossip loop below, unchanged.
            // Applying it here as well (the pre-fix rule) silently excludes
            // every voter whose CURRENT, genuinely-different-fork vote
            // happens to number below our last vote — exactly the case an
            // escaping validator needs when its own dead fork raced ahead of
            // the canonical one before dying. `switchProofVoteCounts` below
            // (the ported `is_valid_switching_proof_vote`) already proves
            // fork-ancestry + GCA/switch_slot descent; this newer-than-ROOT
            // check is the one Agave/FD actually gate on (a candidate below
            // our root is stale/pruned history, never a live escape route).
            if (cand_slot <= self.tree_root.slot) continue;
            var verdict: ?bool = null;
            for (memo[0..memo_len]) |m| {
                if (m.slot == cand_slot) {
                    verdict = m.count;
                    break;
                }
            }
            const counts = verdict orelse blk: {
                const c = self.switchProofVoteCounts(cand_slot, last_voted_slot, switch_slot);
                if (memo_len < memo.len) {
                    memo[memo_len] = .{ .slot = cand_slot, .count = c };
                    memo_len += 1;
                }
                break :blk c;
            };
            if (!counts) continue;
            // Stake for this voter (missing → 0, Agave consensus.rs:1258).
            locked_out += stake_lookup_ctx.lookup(pk, cand_slot);
            // STRICT f64 ratio > 0.38 (Agave consensus.rs:1263). NEVER an
            // integer percent — truncation flips the boundary and can
            // manufacture a false SwitchProof.
            if (@as(f64, @floatFromInt(locked_out)) / @as(f64, @floatFromInt(total_stake)) > SWITCH_FORK_THRESHOLD) {
                return .{ .same_fork = false, .would_switch = true, .locked_out_stake = locked_out, .total_stake = total_stake };
            }
        }

        // ── Gossip loop (Agave consensus.rs:1222-1268, max_gossip_frozen_votes) ──
        // The real-time observation source. See checkSwitchThresholdGossip doc
        // above for the four predicates (a)-(d) and the wedge-421109451 rationale.
        var gossip_considered: u32 = 0;
        var gossip_counted: u32 = 0;
        for (gossip_votes) |gv| {
            const cand_slot = gv.slot_hash.slot;
            // (a) Only votes strictly newer than ours (Agave consensus.rs:1228,
            //     same predicate as the landed loop).
            if (cand_slot <= last_voted_slot) continue;
            gossip_considered += 1;
            // (b) Cross-source dedup (Agave `locked_out_vote_accounts`,
            //     consensus.rs:1224-1226): skip a voter whose stake the landed
            //     loop above ALREADY added. Recomputed via the shared memo
            //     instead of a heap set — exact, because the landed loop counts
            //     pk iff (lv.slot > root) AND counts(lv.slot) — the landed
            //     loop's admission rule as of the 2026-07-17 fix (was `lv.slot
            //     > last_voted_slot`, matching the landed loop's OLD, now-
            //     removed, over-restrictive filter; see the landed loop above),
            //     and reaching this loop means the landed loop ran to
            //     completion (no early threshold return).
            if (self.latest_votes.get(gv.pubkey)) |lv| {
                if (lv.slot > self.tree_root.slot) {
                    var lv_verdict: ?bool = null;
                    for (memo[0..memo_len]) |m| {
                        if (m.slot == lv.slot) {
                            lv_verdict = m.count;
                            break;
                        }
                    }
                    const landed_counted = lv_verdict orelse blk: {
                        const c = self.switchProofVoteCounts(lv.slot, last_voted_slot, switch_slot);
                        if (memo_len < memo.len) {
                            memo[memo_len] = .{ .slot = lv.slot, .count = c };
                            memo_len += 1;
                        }
                        break :blk c;
                    };
                    if (landed_counted) continue;
                }
            }
            // (c) Frozen-bank admission (Agave max_gossip_frozen_votes
            //     invariant): the voted (slot, hash) must be a bank WE froze —
            //     the exact key must exist in the tree. A vote for a hash we
            //     did not freeze (duplicate version) or an unknown/unfrozen
            //     slot is NOT counted (conservative).
            if (!self.fork_infos.containsContext(gv.slot_hash, Ctx)) continue;
            // (d) The same memoized switching-proof tree-walk as the landed
            //     loop (Agave consensus.rs:1249 is_valid_switching_proof_vote).
            var verdict: ?bool = null;
            for (memo[0..memo_len]) |m| {
                if (m.slot == cand_slot) {
                    verdict = m.count;
                    break;
                }
            }
            const counts = verdict orelse blk: {
                const c = self.switchProofVoteCounts(cand_slot, last_voted_slot, switch_slot);
                if (memo_len < memo.len) {
                    memo[memo_len] = .{ .slot = cand_slot, .count = c };
                    memo_len += 1;
                }
                break :blk c;
            };
            if (!counts) continue;
            gossip_counted += 1;
            // Stake for this voter (missing → 0, Agave consensus.rs:1258-1262).
            locked_out += stake_lookup_ctx.lookup(gv.pubkey, cand_slot);
            // STRICT f64 ratio > 0.38 (Agave consensus.rs:1263-1265).
            if (@as(f64, @floatFromInt(locked_out)) / @as(f64, @floatFromInt(total_stake)) > SWITCH_FORK_THRESHOLD) {
                return .{
                    .same_fork = false,
                    .would_switch = true,
                    .locked_out_stake = locked_out,
                    .total_stake = total_stake,
                    .gossip_considered = gossip_considered,
                    .gossip_counted = gossip_counted,
                };
            }
        }
        return .{
            .same_fork = false,
            .would_switch = false,
            .locked_out_stake = locked_out,
            .total_stake = total_stake,
            .gossip_considered = gossip_considered,
            .gossip_counted = gossip_counted,
        };
    }

    /// Per-candidate-SLOT switching-proof verdict — the tree-walk half of Agave
    /// `is_valid_switching_proof_vote` (consensus.rs:863-925), extracted so
    /// checkSwitchThreshold can memoize it by unique slot (task #32). Pubkey
    /// plays no role here (Agave passes only slots + ancestry maps); stake is
    /// looked up per-pubkey by the caller.
    fn switchProofVoteCounts(
        self: *const Self,
        cand_slot: core.Slot,
        last_voted_slot: core.Slot,
        switch_slot: core.Slot,
    ) bool {
        // (a) if the candidate vote descends from our last vote, it is on
        //     OUR fork → not locked out from us → don't count.
        if (self.isAncestorBySlot(cand_slot, last_voted_slot)) return false;
        // (b) count iff switch_slot descends from GCA(cand, last_vote);
        //     unknown ancestry (null GCA) → don't count (unwrap_or false).
        const gca = self.gcaBySlot(cand_slot, last_voted_slot) orelse return false;
        return self.isAncestorBySlot(switch_slot, gca);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PER-VOTER SWITCH-PROOF INSTRUMENTATION (2026-07-17, wedge 422521275 /
    // live sibling-race 422600922 follow-up)
    //
    // checkSwitchThresholdGossip (above) only returns an aggregate
    // locked_out_stake — after the 2026-07-17 event, the log showed
    // "locked_out=124281058237859446/325478908024556077 (38.18%)" with
    // gossip_cnt=0/0 (the ENTIRE figure came from the landed loop) and no way
    // to attribute it to specific voters/slots. This is a DIAGNOSTIC-ONLY,
    // opt-in (VEX_SWITCH_PROOF_VOTER_DIAG) parallel walk — never called from
    // the production checkSwitchThresholdGossip path, never affects the vote
    // decision. It duplicates checkSwitchThresholdGossip's admission logic
    // (kept in sync deliberately — same predicates, same order) but never
    // early-returns on threshold-cross, so it can report the FULL breakdown:
    // top contributing (pubkey-prefix, cand_slot, stake) entries plus a count
    // of how many candidates were excluded at each predicate. This is what
    // turns "38.18%, source unknown" into an attributable, next-event-ready
    // trace — see fork_choice_feed.zig / replay_stage.zig switch_proof block
    // for the call site (gated behind VEX_SWITCH_PROOF_VOTER_DIAG, off by
    // default; only reached when VEX_SWITCH_PROOF is already shadow/armed AND
    // a cross-fork evaluation is actually happening, i.e. already a rare
    // path).
    // ─────────────────────────────────────────────────────────────────────────

    /// One admitted (or top-tracked) voter contribution.
    pub const VoterContribution = struct {
        pubkey: core.Pubkey,
        cand_slot: core.Slot,
        stake: u64,
        source: enum { landed, gossip },
    };

    /// Fixed-size, allocation-free top-N tracker + exclusion counters.
    /// `top` is kept sorted DESCENDING by stake (insertion-sort into a small
    /// array — N is tiny (8), so this is O(N) per insert, negligible even
    /// walked over every voter in the diagnostic path).
    pub const SwitchThresholdBreakdown = struct {
        pub const TOP_N = 8;
        top: [TOP_N]VoterContribution = undefined,
        top_len: usize = 0,

        // Landed-loop (self.latest_votes) predicate funnel — matches the
        // admission order in checkSwitchThresholdGossip's first loop:
        landed_seen: u32 = 0, // total entries in self.latest_votes iterated
        landed_excluded_root: u32 = 0, // cand_slot <= tree_root.slot
        landed_excluded_no_gca: u32 = 0, // switchProofVoteCounts() == false (own-fork or unresolvable GCA)
        landed_counted: u32 = 0,
        landed_stake: u64 = 0,

        // Gossip-loop (max_gossip_frozen_votes-equivalent) predicate funnel —
        // matches checkSwitchThresholdGossip's second loop, predicates (a)-(d):
        gossip_seen: u32 = 0, // total entries in the caller-supplied gossip_votes slice
        gossip_excluded_not_newer: u32 = 0, // (a) cand_slot <= last_voted_slot
        gossip_excluded_dup: u32 = 0, // (b) already counted via the landed loop
        gossip_excluded_not_frozen: u32 = 0, // (c) (slot,hash) not in fork_infos
        gossip_excluded_no_gca: u32 = 0, // (d) switchProofVoteCounts() == false
        gossip_counted: u32 = 0,
        gossip_stake: u64 = 0,

        fn record(self: *SwitchThresholdBreakdown, contrib: VoterContribution) void {
            // Find insertion point (descending by stake); drop if smaller
            // than everything already held and the buffer is full.
            if (self.top_len < TOP_N) {
                var i = self.top_len;
                while (i > 0 and self.top[i - 1].stake < contrib.stake) : (i -= 1) {
                    self.top[i] = self.top[i - 1];
                }
                self.top[i] = contrib;
                self.top_len += 1;
            } else if (contrib.stake > self.top[TOP_N - 1].stake) {
                var i: usize = TOP_N - 1;
                while (i > 0 and self.top[i - 1].stake < contrib.stake) : (i -= 1) {
                    self.top[i] = self.top[i - 1];
                }
                self.top[i] = contrib;
            }
        }
    };

    /// DIAGNOSTIC-ONLY per-voter breakdown for a switch-threshold evaluation.
    /// Mirrors checkSwitchThresholdGossip's two admission loops exactly
    /// (same predicates, same order — kept in sync deliberately) but never
    /// early-returns on threshold-cross, so `out` always reflects the FULL
    /// candidate set. Never called from the production vote-decision path;
    /// callers gate this behind an explicit env/diag flag. Same complexity
    /// class as checkSwitchThresholdGossip (O(voters) with the same memoized
    /// per-slot verdict), so it is safe to call at the same cadence — just
    /// intentionally not on by default given it's forensic-only output.
    pub fn switchThresholdVoterBreakdown(
        self: *const Self,
        last_voted_slot: core.Slot,
        switch_slot: core.Slot,
        stake_lookup_ctx: anytype,
        gossip_votes: []const PubkeyVote,
        out: *SwitchThresholdBreakdown,
    ) void {
        out.* = .{};
        // SameFork short-circuit — nothing to attribute (checkSwitchThresholdGossip:596).
        if (switch_slot == last_voted_slot or self.isAncestorBySlot(switch_slot, last_voted_slot)) return;

        const Memo = struct { slot: core.Slot, count: bool };
        var memo: [64]Memo = undefined;
        var memo_len: usize = 0;

        // ── Landed loop (mirrors checkSwitchThresholdGossip's first loop) ──
        var it = self.latest_votes.iterator();
        while (it.next()) |e| {
            out.landed_seen += 1;
            const pk = e.key_ptr.*;
            const cand_slot = e.value_ptr.slot;
            if (cand_slot <= self.tree_root.slot) {
                out.landed_excluded_root += 1;
                continue;
            }
            var verdict: ?bool = null;
            for (memo[0..memo_len]) |m| {
                if (m.slot == cand_slot) {
                    verdict = m.count;
                    break;
                }
            }
            const counts = verdict orelse blk: {
                const c = self.switchProofVoteCounts(cand_slot, last_voted_slot, switch_slot);
                if (memo_len < memo.len) {
                    memo[memo_len] = .{ .slot = cand_slot, .count = c };
                    memo_len += 1;
                }
                break :blk c;
            };
            if (!counts) {
                out.landed_excluded_no_gca += 1;
                continue;
            }
            const stake = stake_lookup_ctx.lookup(pk, cand_slot);
            out.landed_counted += 1;
            out.landed_stake +%= stake;
            out.record(.{ .pubkey = pk, .cand_slot = cand_slot, .stake = stake, .source = .landed });
        }

        // ── Gossip loop (mirrors checkSwitchThresholdGossip's second loop) ──
        for (gossip_votes) |gv| {
            out.gossip_seen += 1;
            const cand_slot = gv.slot_hash.slot;
            if (cand_slot <= last_voted_slot) {
                out.gossip_excluded_not_newer += 1;
                continue;
            }
            if (self.latest_votes.get(gv.pubkey)) |lv| {
                if (lv.slot > self.tree_root.slot) {
                    var lv_verdict: ?bool = null;
                    for (memo[0..memo_len]) |m| {
                        if (m.slot == lv.slot) {
                            lv_verdict = m.count;
                            break;
                        }
                    }
                    const landed_counted = lv_verdict orelse blk: {
                        const c = self.switchProofVoteCounts(lv.slot, last_voted_slot, switch_slot);
                        if (memo_len < memo.len) {
                            memo[memo_len] = .{ .slot = lv.slot, .count = c };
                            memo_len += 1;
                        }
                        break :blk c;
                    };
                    if (landed_counted) {
                        out.gossip_excluded_dup += 1;
                        continue;
                    }
                }
            }
            if (!self.fork_infos.containsContext(gv.slot_hash, Ctx)) {
                out.gossip_excluded_not_frozen += 1;
                continue;
            }
            var verdict: ?bool = null;
            for (memo[0..memo_len]) |m| {
                if (m.slot == cand_slot) {
                    verdict = m.count;
                    break;
                }
            }
            const counts = verdict orelse blk: {
                const c = self.switchProofVoteCounts(cand_slot, last_voted_slot, switch_slot);
                if (memo_len < memo.len) {
                    memo[memo_len] = .{ .slot = cand_slot, .count = c };
                    memo_len += 1;
                }
                break :blk c;
            };
            if (!counts) {
                out.gossip_excluded_no_gca += 1;
                continue;
            }
            const stake = stake_lookup_ctx.lookup(gv.pubkey, cand_slot);
            out.gossip_counted += 1;
            out.gossip_stake +%= stake;
            out.record(.{ .pubkey = gv.pubkey, .cand_slot = cand_slot, .stake = stake, .source = .gossip });
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // add_new_leaf_slot — Agave lines 457-500
    // ─────────────────────────────────────────────────────────────────────────

    /// Insert a new node into the tree. Idempotent on re-insert. If `parent_key`
    /// is non-null, the parent must already exist in the tree.
    pub fn addNewLeafSlot(self: *Self, key: SlotHashKey, parent_key: ?SlotHashKey) !void {
        if (self.fork_infos.containsContext(key, Ctx)) {
            // Can happen on repair of duplicate version after dump — Agave 458-462.
            return;
        }

        const parent_latest_invalid = if (parent_key) |pk|
            self.latestInvalidAncestor(pk)
        else
            null;

        try self.fork_infos.putContext(self.allocator, key, .{
            .stake_voted_at = 0,
            .stake_voted_subtree = 0,
            .height = 1,
            .best_slot = key,
            .deepest_slot = key,
            .parent = parent_key,
            .children = .{},
            .latest_invalid_ancestor = parent_latest_invalid,
            // Agave 481: parent.is_none() implies this is the root, which is
            // implicitly duplicate-confirmed. For non-root nodes, default false.
            .is_duplicate_confirmed = parent_key == null,
        }, Ctx);

        const pk = parent_key orelse return;

        // Insert into parent.children at sorted position (mirrors BTreeSet semantics).
        const parent_info = self.fork_infos.getPtrContext(pk, Ctx) orelse {
            // Agave asserts parent exists. We surface as error rather than crash.
            return error.ForkChoiceParentMissing;
        };
        const ix = sortedInsertIndex(parent_info.children.items, key);
        try parent_info.children.insert(self.allocator, ix, key);

        // Propagate best/deepest up the tree — Agave 499.
        try self.propagateNewLeaf(key, pk);
    }

    /// Find the index where `key` should be inserted into a sorted slice
    /// of SlotHashKey to keep it sorted.
    fn sortedInsertIndex(slice: []const SlotHashKey, key: SlotHashKey) usize {
        // Linear search — children lists are typically very small (a few siblings
        // at most).
        var i: usize = 0;
        while (i < slice.len) : (i += 1) {
            if (SlotHashKey.lessThan(key, slice[i])) return i;
        }
        return slice.len;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // propagate_new_leaf — Agave lines 742-784
    //
    // Called once when a new leaf is inserted. Walks ancestors and updates:
    //   - best_slot: if leaf is the new best child of parent, push up while
    //     each ancestor's best_slot equals parent's old best_slot.
    //   - deepest_slot + height: walk up while leaf is still the deepest child
    //     at each level.
    // ─────────────────────────────────────────────────────────────────────────

    fn propagateNewLeaf(self: *Self, leaf_key: SlotHashKey, parent_key: SlotHashKey) !void {
        const parent_best_slot = self.bestSlotOf(parent_key) orelse return;

        // Best-slot propagation (Agave 751-765)
        if (self.isBestChild(leaf_key)) {
            var ancestor: ?SlotHashKey = parent_key;
            while (ancestor) |a| {
                const info = self.fork_infos.getPtrContext(a, Ctx) orelse break;
                if (!SlotHashKey.eql(info.best_slot, parent_best_slot)) break;
                info.best_slot = leaf_key;
                ancestor = info.parent;
            }
        }

        // Deepest-slot propagation (Agave 767-783)
        var ancestor: ?SlotHashKey = parent_key;
        var current_child = leaf_key;
        var current_height: usize = 1;
        while (ancestor) |a| {
            if (!self.isDeepestChild(current_child)) break;
            const info = self.fork_infos.getPtrContext(a, Ctx) orelse break;
            info.deepest_slot = leaf_key;
            info.height = current_height + 1;
            current_child = a;
            current_height = info.height;
            ancestor = info.parent;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // is_best_child / is_deepest_child — Agave lines 504-563
    // ─────────────────────────────────────────────────────────────────────────

    /// Is `candidate` the heaviest among its siblings? Tie-break by lower
    /// SlotHashKey ordering. Skips siblings marked invalid (Agave 517).
    fn isBestChild(self: *const Self, candidate: SlotHashKey) bool {
        const cand_weight = self.stakeVotedSubtree(candidate) orelse return false;
        const parent_key = self.parentOf(candidate) orelse return true; // root
        const parent_info = self.fork_infos.getContext(parent_key, Ctx) orelse return true;

        for (parent_info.children.items) |child_key| {
            // Don't count children currently marked invalid (Agave 517)
            const is_cand_child = self.isCandidate(child_key) orelse continue;
            if (!is_cand_child) continue;

            const child_weight = self.stakeVotedSubtree(child_key) orelse continue;

            if (child_weight > cand_weight) return false;
            if (child_weight == cand_weight and SlotHashKey.lessThan(child_key, candidate)) return false;
        }
        return true;
    }

    /// Is `candidate` the deepest among its siblings? Tie-break by stake, then
    /// lower SlotHashKey ordering. Considers ALL siblings (no validity filter).
    fn isDeepestChild(self: *const Self, candidate: SlotHashKey) bool {
        const cand_weight = self.stakeVotedSubtree(candidate) orelse return false;
        const cand_height = self.heightOf(candidate) orelse return false;
        const parent_key = self.parentOf(candidate) orelse return true; // root
        const parent_info = self.fork_infos.getContext(parent_key, Ctx) orelse return true;

        for (parent_info.children.items) |child_key| {
            const child_height = self.heightOf(child_key) orelse continue;
            const child_weight = self.stakeVotedSubtree(child_key) orelse continue;

            const h_cmp = std.math.order(child_height, cand_height);
            const s_cmp = std.math.order(child_weight, cand_weight);
            const k_cmp = SlotHashKey.order(child_key, candidate);

            // Greater height beats us
            if (h_cmp == .gt) return false;
            // Equal height + greater stake beats us
            if (h_cmp == .eq and s_cmp == .gt) return false;
            // Equal height + equal stake + lower key beats us
            if (h_cmp == .eq and s_cmp == .eq and k_cmp == .lt) return false;
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // aggregate_slot — Agave lines 856-948
    //
    // Recompute stake_voted_subtree, height, best_slot, deepest_slot from this
    // slot's stake_voted_at + children's aggregated state. Called bottom-up
    // (children before parents) — process_update_operations enforces this.
    //
    // IMPORTANT: child subtree stakes contribute REGARDLESS of validity (Agave
    // 877-893 comment); only best_slot selection filters by is_candidate.
    // ─────────────────────────────────────────────────────────────────────────

    fn aggregateSlot(self: *Self, key: SlotHashKey) void {
        var stake_voted_subtree: u64 = 0;
        var deepest_child_height: usize = 0;
        var best_slot_key = key;
        var deepest_slot_key = key;
        var is_duplicate_confirmed = false;

        // First pass: read all children, decide best/deepest.
        {
            const info = self.fork_infos.getContext(key, Ctx) orelse return;
            stake_voted_subtree = info.stake_voted_at;

            var best_child_stake: u64 = 0;
            var best_child_key = key;
            var deepest_child_stake: u64 = 0;
            var deepest_child_key = key;

            for (info.children.items) |child_key| {
                const child = self.fork_infos.getContext(child_key, Ctx) orelse {
                    // Agave: panic "Child must exist". We surface as continue
                    // rather than crash — but log loudly so the broken-invariant
                    // bug is visible. Under correct usage this branch is unreachable.
                    std.log.err(
                        "[FORK-CHOICE-CORRUPT] aggregateSlot: child slot={d} of parent " ++
                            "slot={d} listed in children but missing from fork_infos. " ++
                            "Subtree stats will be under-counted.",
                        .{ child_key.slot, key.slot },
                    );
                    continue;
                };

                const child_subtree = child.stake_voted_subtree;
                const child_height = child.height;
                is_duplicate_confirmed = is_duplicate_confirmed or child.is_duplicate_confirmed;

                // All children (incl invalid) contribute — Agave 896
                stake_voted_subtree +%= child_subtree;

                // Best-slot selection (Agave 898-909): candidate filter applied here.
                if (child.isCandidate()) {
                    const first_child = SlotHashKey.eql(best_child_key, key);
                    const heavier = child_subtree > best_child_stake;
                    const tied_lower = child_subtree == best_child_stake and
                        SlotHashKey.lessThan(child_key, best_child_key);

                    if (first_child or heavier or tied_lower) {
                        best_child_stake = child_subtree;
                        best_child_key = child_key;
                        best_slot_key = child.best_slot;
                    }
                }

                // Deepest-slot selection (Agave 911-931): no validity filter.
                const first_deepest = SlotHashKey.eql(deepest_child_key, key);
                const h_cmp = std.math.order(child_height, deepest_child_height);
                const s_cmp = std.math.order(child_subtree, deepest_child_stake);
                const k_cmp = SlotHashKey.order(child_key, deepest_child_key);

                const update_deepest = first_deepest or
                    h_cmp == .gt or
                    (h_cmp == .eq and s_cmp == .gt) or
                    (h_cmp == .eq and s_cmp == .eq and k_cmp == .lt);

                if (update_deepest) {
                    deepest_child_height = child_height;
                    deepest_child_stake = child_subtree;
                    deepest_child_key = child_key;
                    deepest_slot_key = child.deepest_slot;
                }
            }
        }

        // Second pass: write the new aggregated state.
        const info_mut = self.fork_infos.getPtrContext(key, Ctx) orelse return;
        if (is_duplicate_confirmed and !info_mut.is_duplicate_confirmed) {
            info_mut.setDuplicateConfirmed();
        }
        info_mut.stake_voted_subtree = stake_voted_subtree;
        info_mut.height = deepest_child_height + 1;
        info_mut.best_slot = best_slot_key;
        info_mut.deepest_slot = deepest_slot_key;
    }

    fn addSlotStake(self: *Self, key: SlotHashKey, stake: u64) void {
        const info = self.fork_infos.getPtrContext(key, Ctx) orelse return;
        info.stake_voted_at +%= stake;
        info.stake_voted_subtree +%= stake;
    }

    fn subtractSlotStake(self: *Self, key: SlotHashKey, stake: u64) void {
        const info = self.fork_infos.getPtrContext(key, Ctx) orelse return;
        // Saturating subtraction — defensive; Agave panics on underflow but we
        // prefer a soft-fail since stake bookkeeping bugs shouldn't crash the
        // validator. Log loudly when an underflow occurs so it stays visible.
        if (stake > info.stake_voted_at) {
            std.log.warn(
                "[FORK-CHOICE-UNDERFLOW] subtractSlotStake: slot={d} stake={d} have={d} " ++
                    "(stake bookkeeping inconsistency — vote migration likely off-by-one)",
                .{ key.slot, stake, info.stake_voted_at },
            );
        }
        info.stake_voted_at = info.stake_voted_at -| stake;
        info.stake_voted_subtree = info.stake_voted_subtree -| stake;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // add_votes / process_update_operations — Agave 343-357, 972-1104
    //
    // Vote migration is THE critical correctness piece this port adds vs.
    // pre-port Vexor:
    //
    //   When pubkey P moves their vote from old (slot, hash) to new:
    //     1. Subtract P's stake (at OLD vote's epoch) from old slot_hash.
    //     2. Add P's stake (at NEW vote's epoch) to new slot_hash.
    //     3. Aggregate up ancestors of BOTH old and new keys.
    //
    // Without this, every vote double-counts on the new slot without removing
    // its contribution from the old slot — wrong fork accumulates fake weight.
    //
    // Stake is looked up via the caller-supplied context, parametrized by the
    // slot the vote is for. This lets the caller route to the correct epoch's
    // stake map — fixes team-b's stake=0 bug where stakes were captured once
    // at init and never refreshed across epoch boundaries.
    // ─────────────────────────────────────────────────────────────────────────

    pub const PubkeyVote = struct {
        pubkey: core.Pubkey,
        slot_hash: SlotHashKey,
    };

    const UpdateLabel = enum(u8) {
        // Order matches Agave's UpdateLabel enum declaration order at line 33.
        // Used in sort key — lower ordinal = earlier in ASC sort.
        aggregate = 0,
        add = 1,
        // Reserved: mark_valid = 2, mark_invalid = 3 (Phase 3)
        subtract = 4,
    };

    const UpdateOperation = union(enum) {
        add: u64,
        subtract: u64,
        aggregate: void,
    };

    const UpdateEntry = struct {
        key: SlotHashKey,
        label: UpdateLabel,
        op: UpdateOperation,

        fn compositeOrder(a: UpdateEntry, b: UpdateEntry) std.math.Order {
            const k_cmp = SlotHashKey.order(a.key, b.key);
            if (k_cmp != .eq) return k_cmp;
            const al: u8 = @intFromEnum(a.label);
            const bl: u8 = @intFromEnum(b.label);
            return std.math.order(al, bl);
        }

        fn lessThan(_: void, a: UpdateEntry, b: UpdateEntry) bool {
            return compositeOrder(a, b) == .lt;
        }
    };

    /// Process a batch of votes; returns the new best overall slot.
    /// `stake_lookup_ctx` must have `.lookup(pubkey, slot) u64`.
    ///
    /// Agave: `add_votes` (line 343).
    pub fn addVotes(
        self: *Self,
        votes: []const PubkeyVote,
        stake_lookup_ctx: anytype,
    ) !SlotHashKey {
        var operations = std.ArrayListUnmanaged(UpdateEntry){};
        defer operations.deinit(self.allocator);

        // Maps from SlotHashKey -> index in `operations` for accumulating
        // add/subtract stakes (one entry per (key, label) combo).
        var add_idx: SlotHashKeyIndex = .{};
        defer add_idx.deinit(self.allocator);
        var sub_idx: SlotHashKeyIndex = .{};
        defer sub_idx.deinit(self.allocator);
        // Tracks which (key, aggregate) entries are already in operations.
        var seen_agg: SlotHashKeySet = .{};
        defer seen_agg.deinit(self.allocator);
        // Each pubkey at most once per batch — Agave panics on duplicate.
        var observed_pubkeys: std.AutoHashMapUnmanaged(core.Pubkey, void) = .{};
        defer observed_pubkeys.deinit(self.allocator);

        for (votes) |pv| {
            const pubkey = pv.pubkey;
            const new_key = pv.slot_hash;

            // Skip votes below tree_root — Agave 985-996.
            if (new_key.slot < self.tree_root.slot) continue;

            // Each pubkey processed at most once per batch. Agave panics on
            // duplicate; we log+skip so a caller dedup bug stays visible.
            const obs_gop = try observed_pubkeys.getOrPut(self.allocator, pubkey);
            if (obs_gop.found_existing) {
                std.log.warn(
                    "[FORK-CHOICE-DUPLICATE-VOTE] pubkey in batch twice (caller " ++
                        "dedup bug?) — first wins, second skipped",
                    .{},
                );
                continue;
            }

            const prev_latest = self.latest_votes.get(pubkey);

            // Filter: skip if not strictly newer than prev (Agave 1017-1023).
            // Specifically: drop if new_slot < prev_slot, OR new_slot == prev_slot
            // and new_hash >= prev_hash. (Equal slot + smaller hash IS allowed —
            // signals a duplicate version of the same slot, Agave 1015.)
            if (prev_latest) |prev| {
                if (new_key.slot < prev.slot) continue;
                if (new_key.slot == prev.slot) {
                    const hash_cmp = std.mem.order(u8, &new_key.hash.data, &prev.hash.data);
                    if (hash_cmp != .lt) continue;
                }
            }

            // Subtract pubkey's stake from old vote's slot.
            if (prev_latest) |old| {
                const old_stake = stake_lookup_ctx.lookup(pubkey, old.slot);
                if (old_stake > 0) {
                    try recordSubtract(&operations, &sub_idx, self.allocator, old, old_stake);
                    try recordAggregateAcrossAncestors(self, &operations, &seen_agg, old);
                }
            }

            // Add pubkey's stake to new vote's slot.
            const new_stake = stake_lookup_ctx.lookup(pubkey, new_key.slot);
            try recordAdd(&operations, &add_idx, self.allocator, new_key, new_stake);
            try recordAggregateAcrossAncestors(self, &operations, &seen_agg, new_key);

            // Update latest_votes.
            try self.latest_votes.put(self.allocator, pubkey, new_key);
        }

        // Sort ASC by (SlotHashKey, UpdateLabel).
        std.mem.sort(UpdateEntry, operations.items, {}, UpdateEntry.lessThan);

        // Process in REVERSE order (greatest key first) — Agave 1091.
        // Within a slot, this yields: subtract, then add, then aggregate.
        // Across slots: children process before parents (children always have
        // higher slot numbers than their ancestors). This is the invariant
        // aggregate_slot depends on.
        var i = operations.items.len;
        while (i > 0) {
            i -= 1;
            const e = operations.items[i];
            switch (e.op) {
                .add => |s| self.addSlotStake(e.key, s),
                .subtract => |s| self.subtractSlotStake(e.key, s),
                .aggregate => self.aggregateSlot(e.key),
            }
        }

        return self.bestOverallSlot();
    }

    fn recordAdd(
        ops: *std.ArrayListUnmanaged(UpdateEntry),
        index: *SlotHashKeyIndex,
        allocator: std.mem.Allocator,
        key: SlotHashKey,
        stake: u64,
    ) !void {
        const gop = try index.getOrPutContext(allocator, key, Ctx);
        if (gop.found_existing) {
            const slot_idx = gop.value_ptr.*;
            switch (ops.items[slot_idx].op) {
                .add => |s| ops.items[slot_idx].op = .{ .add = s +% stake },
                else => unreachable, // index integrity invariant
            }
        } else {
            gop.value_ptr.* = ops.items.len;
            try ops.append(allocator, .{
                .key = key,
                .label = .add,
                .op = .{ .add = stake },
            });
        }
    }

    fn recordSubtract(
        ops: *std.ArrayListUnmanaged(UpdateEntry),
        index: *SlotHashKeyIndex,
        allocator: std.mem.Allocator,
        key: SlotHashKey,
        stake: u64,
    ) !void {
        const gop = try index.getOrPutContext(allocator, key, Ctx);
        if (gop.found_existing) {
            const slot_idx = gop.value_ptr.*;
            switch (ops.items[slot_idx].op) {
                .subtract => |s| ops.items[slot_idx].op = .{ .subtract = s +% stake },
                else => unreachable,
            }
        } else {
            gop.value_ptr.* = ops.items.len;
            try ops.append(allocator, .{
                .key = key,
                .label = .subtract,
                .op = .{ .subtract = stake },
            });
        }
    }

    /// Insert aggregate operations for `start` and walk up its ancestors,
    /// stopping at the first ancestor already in `seen`. Matches
    /// `insert_aggregate_operations` / `do_insert_aggregate_operations_across_ancestors`
    /// (Agave 786-817).
    fn recordAggregateAcrossAncestors(
        self: *Self,
        ops: *std.ArrayListUnmanaged(UpdateEntry),
        seen: *SlotHashKeySet,
        start: SlotHashKey,
    ) !void {
        var cursor: ?SlotHashKey = start;
        while (cursor) |key| {
            const gop = try seen.getOrPutContext(self.allocator, key, Ctx);
            if (gop.found_existing) return; // matches Agave 813-815 short-circuit
            try ops.append(self.allocator, .{
                .key = key,
                .label = .aggregate,
                .op = .{ .aggregate = {} },
            });
            const info = self.fork_infos.getContext(key, Ctx) orelse return;
            cursor = info.parent;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // set_tree_root — Agave lines 363-378
    //
    // Removes everything reachable from old root but NOT from new root.
    // Severs new root's parent link.
    // ─────────────────────────────────────────────────────────────────────────

    pub fn setTreeRoot(self: *Self, new_root: SlotHashKey) !void {
        if (!self.fork_infos.containsContext(new_root, Ctx)) return error.NewRootNotInTree;

        // Collect everything reachable from new_root.
        var keep: SlotHashKeySet = .{};
        defer keep.deinit(self.allocator);
        var queue: std.ArrayListUnmanaged(SlotHashKey) = .{};
        defer queue.deinit(self.allocator);
        try queue.append(self.allocator, new_root);
        while (queue.items.len > 0) {
            const k = queue.pop().?;
            const gop = try keep.getOrPutContext(self.allocator, k, Ctx);
            if (gop.found_existing) continue;
            if (self.fork_infos.getContext(k, Ctx)) |info| {
                for (info.children.items) |c| try queue.append(self.allocator, c);
            }
        }

        // Remove everything not in keep.
        var to_remove: std.ArrayListUnmanaged(SlotHashKey) = .{};
        defer to_remove.deinit(self.allocator);
        var it = self.fork_infos.keyIterator();
        while (it.next()) |kptr| {
            if (!keep.containsContext(kptr.*, Ctx)) try to_remove.append(self.allocator, kptr.*);
        }
        for (to_remove.items) |k| {
            if (self.fork_infos.fetchRemoveContext(k, Ctx)) |kv| {
                var info = kv.value;
                info.deinit(self.allocator);
            }
        }

        // Sever new root's parent link.
        if (self.fork_infos.getPtrContext(new_root, Ctx)) |info| info.parent = null;

        // Prune latest_votes whose target key no longer exists.
        var votes_to_remove: std.ArrayListUnmanaged(core.Pubkey) = .{};
        defer votes_to_remove.deinit(self.allocator);
        var vit = self.latest_votes.iterator();
        while (vit.next()) |e| {
            if (!self.fork_infos.containsContext(e.value_ptr.*, Ctx)) {
                try votes_to_remove.append(self.allocator, e.key_ptr.*);
            }
        }
        for (votes_to_remove.items) |pk| _ = self.latest_votes.remove(pk);

        self.tree_root = new_root;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Mark fork invalid / valid — Phase 3 port.
    // 2026-05-28 FIX #87: replaced Phase 3 TODO stubs with full Agave-canonical
    // port of mark_fork_invalid_candidate (heaviest_subtree_fork_choice.rs:1328-1351)
    // and mark_fork_valid_candidate (Agave:1353-1379).
    //
    // Why this matters: without these, markSlotDead (replay_stage.zig:1566)
    // updates dead_slots but fork-choice retains the dead subtree at full weight.
    // bestOverallSlot then keeps picking the dead subtree as canonical, and
    // the validator wedges on the dead branch. Wedge observed 2026-05-28 ~05:00
    // UTC: slot 411405258 phantom-frozen, fork-choice couldn't pivot to alternate.
    //
    // The Agave canonical flow:
    //   1. Notify all descendants in the subtree that an ancestor is now invalid
    //      → each descendant's latest_invalid_ancestor is updated to the deepest
    //        (highest-slot) invalid ancestor.
    //   2. Re-aggregate the invalid_key node and all its ancestors so best_slot
    //      and stake_voted_subtree are recomputed with the new invalid subtree
    //      filtered out via isCandidate() in aggregateSlot's best-slot selection
    //      (which already filters by child.isCandidate()).
    // ─────────────────────────────────────────────────────────────────────────

    /// Recursively collect all keys in the subtree rooted at `start` (inclusive).
    /// Mirrors Agave's subtree_diff helper used in mark_fork_invalid_candidate.
    /// Returns silently if start is not in fork_infos.
    fn collectSubtree(
        self: *const Self,
        start: SlotHashKey,
        out: *std.ArrayListUnmanaged(SlotHashKey),
    ) void {
        // FIX #87: was self-recursive → unbounded native stack on a deep fork tree
        // (a long unrooted chain ⇒ stack-overflow CRASH). Iterative DFS with an explicit
        // heap worklist. subtree_diff is order-INSENSITIVE (it collects ALL keys in the
        // subtree to mark them), so any traversal order is faithful to the recursive version:
        // every key reached is appended to `out`; a key absent from fork_infos is still
        // appended (matching the original's append-before-getContext) but its children are
        // not traversed (matching the original's `orelse return`).
        var stack: std.ArrayListUnmanaged(SlotHashKey) = .{};
        defer stack.deinit(self.allocator);
        stack.append(self.allocator, start) catch return;
        while (stack.pop()) |key| {
            out.append(self.allocator, key) catch return;
            const info = self.fork_infos.getContext(key, Ctx) orelse continue;
            for (info.children.items) |child_key| {
                stack.append(self.allocator, child_key) catch return;
            }
        }
    }

    /// Agave: heaviest_subtree_fork_choice.rs:1328-1351.
    ///
    /// Mark the fork starting at `invalid_slot_hash_key` invalid. This:
    ///   - Updates latest_invalid_ancestor on the invalid node and all descendants
    ///   - Re-aggregates the invalid node and all ancestors (so best_slot updates
    ///     skip the dead subtree via aggregateSlot's child.isCandidate() filter)
    ///
    /// Safety: refuses to mark a duplicate-confirmed slot invalid (matches Agave's
    /// debug_assert). Silently returns if key is not in fork_infos.
    pub fn markForkInvalidCandidate(self: *Self, invalid_slot_hash_key: SlotHashKey) void {
        const info_ptr = self.fork_infos.getPtrContext(invalid_slot_hash_key, Ctx) orelse {
            std.log.warn(
                "[markForkInvalidCandidate] no fork_info for slot={d} hash={x} — skipping",
                .{ invalid_slot_hash_key.slot, invalid_slot_hash_key.hash.data[0..8].* },
            );
            return;
        };

        if (info_ptr.is_duplicate_confirmed) {
            std.log.warn(
                "[markForkInvalidCandidate] refusing to mark duplicate_confirmed slot={d} hash={x} invalid",
                .{ invalid_slot_hash_key.slot, invalid_slot_hash_key.hash.data[0..8].* },
            );
            return;
        }

        // NOTE: this fires on every dead-slot event in production; keep at info level
        // to avoid log spam during normal mark-dead activity. Reviewer flagged warn would
        // saturate logs on testnet/mainnet steady-state.
        //
        // CONCURRENCY (FIX #87 review #2) — RESOLVED 2026-06-20: no mutex needed; fork_choice is
        // SINGLE-THREADED in production. Verified by tracing every fork_choice touch to the replay
        // thread (replayWorker, replay_stage.zig:6488):
        //   • addVotes      ← onSlotCompleted (replay_stage.zig:2934) ← replayWorker:6578
        //   • setTreeRoot    ← submitVote (:4128) ← onSlotCompleted ← replayWorker
        //   • markForkInvalidCandidate ← markSlotDeadOne ← markSlotDead (de-recursed to an explicit
        //     worklist, :2143) ← sweepPending{TickGate,FecGate}Slots ← installSlotHashes (:1650) ←
        //     replayWorker:6559  (also via getNetworkBankHash, same thread)
        // The other spawned threads do NOT touch fork_choice: sysvarRefreshWorker only fetches remote
        // blockhash/slot-hashes; parallelFetchWorker + the produce tile have ZERO fork_choice calls
        // (grep-verified). The original TODO assumed multi-thread access (TVU sweep / FEC-GATE on
        // their own threads); the architecture was since refactored to funnel all of it onto the
        // replay thread. Matches fork_choice_feed.zig's "single-threaded ... no lock is needed today"
        // invariant. ⚠️ If a FUTURE caller adds a parallel fork_choice access, it MUST add a
        // caller-side lock wrapping each individual fork_choice method call (NOT an internal
        // per-method mutex — the mutating methods call the read methods internally, so that would
        // self-deadlock; and NOT a coarse lock around markSlotDead — keep it narrow).
        std.log.info(
            "[FORK-INVALID-CANDIDATE] marking fork starting at slot={d} hash={x} invalid candidate (Phase 3 port)",
            .{ invalid_slot_hash_key.slot, invalid_slot_hash_key.hash.data[0..8].* },
        );

        // Step 1: collect ALL nodes in the subtree (invalid_key + all descendants)
        // and mark each one's latest_invalid_ancestor to point at invalid_slot.
        var subtree: std.ArrayListUnmanaged(SlotHashKey) = .{};
        defer subtree.deinit(self.allocator);
        self.collectSubtree(invalid_slot_hash_key, &subtree);

        for (subtree.items) |desc_key| {
            if (self.fork_infos.getPtrContext(desc_key, Ctx)) |desc_info| {
                desc_info.updateWithNewlyInvalidAncestor(desc_key, invalid_slot_hash_key.slot);
            }
        }

        // Step 2: re-aggregate the invalid node and all its ancestors.
        // aggregateSlot's best-slot loop already filters by child.isCandidate(),
        // so after step 1 the dead subtree is automatically excluded from
        // best_slot computation. Order: invalid_key first (deepest), then walk
        // up to root (children-before-parents — aggregateSlot requirement).
        self.aggregateSlot(invalid_slot_hash_key);
        var anc_it = self.ancestorIterator(invalid_slot_hash_key);
        while (anc_it.next()) |anc_key| {
            self.aggregateSlot(anc_key);
        }
    }

    /// Agave: heaviest_subtree_fork_choice.rs:1353-1379.
    ///
    /// Mark the fork starting at `valid_slot_hash_key` valid (duplicate-confirmed).
    /// This:
    ///   - Sets is_duplicate_confirmed = true on this node (and clears its
    ///     latest_invalid_ancestor via setDuplicateConfirmed)
    ///   - Walks all descendants: clears latest_invalid_ancestor where it was
    ///     <= valid_slot (the newly-valid ancestor invalidates any equal-or-shallower
    ///     invalid ancestor)
    ///   - Re-aggregates from valid node up through ancestors
    pub fn markForkValidCandidate(self: *Self, valid_slot_hash_key: SlotHashKey) void {
        const info_ptr = self.fork_infos.getPtrContext(valid_slot_hash_key, Ctx) orelse {
            std.log.warn(
                "[markForkValidCandidate] no fork_info for slot={d} hash={x} — skipping",
                .{ valid_slot_hash_key.slot, valid_slot_hash_key.hash.data[0..8].* },
            );
            return;
        };
        if (info_ptr.is_duplicate_confirmed) return; // idempotent

        std.log.info(
            "[FORK-VALID-CANDIDATE] marking fork starting at slot={d} hash={x} valid (duplicate-confirmed)",
            .{ valid_slot_hash_key.slot, valid_slot_hash_key.hash.data[0..8].* },
        );

        info_ptr.setDuplicateConfirmed();

        // Walk descendants: clear latest_invalid_ancestor where it was <= valid_slot.
        var subtree: std.ArrayListUnmanaged(SlotHashKey) = .{};
        defer subtree.deinit(self.allocator);
        self.collectSubtree(valid_slot_hash_key, &subtree);
        for (subtree.items) |desc_key| {
            if (SlotHashKey.eql(desc_key, valid_slot_hash_key)) continue; // already handled above
            if (self.fork_infos.getPtrContext(desc_key, Ctx)) |desc_info| {
                desc_info.updateWithNewlyValidAncestor(desc_key, valid_slot_hash_key.slot);
            }
        }

        // Re-aggregate the valid node and its ancestors.
        self.aggregateSlot(valid_slot_hash_key);
        var anc_it = self.ancestorIterator(valid_slot_hash_key);
        while (anc_it.next()) |anc_key| {
            self.aggregateSlot(anc_key);
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Backward-compatibility shim — keeps replay_stage compiling during migration.
//
// The OLD type `ForkChoice` is aliased to `HeaviestSubtreeForkChoice`. Old method
// names that replay_stage calls today are wrapped here. As we migrate replay_stage
// callsites to use the new (Slot, Hash) keyed API directly, these shims shrink.
// ═══════════════════════════════════════════════════════════════════════════════

pub const ForkChoice = HeaviestSubtreeForkChoice;

/// Legacy entrypoint used by replay_stage today. New code should call
/// `addNewLeafSlot` directly with explicit (Slot, Hash) keys.
pub fn addForkCompat(
    fc: *ForkChoice,
    slot: core.Slot,
    parent_slot: ?core.Slot,
    bank_hash: core.Hash,
    parent_hash: core.Hash,
) !void {
    // Seed root from the first call's parent if not yet initialized.
    if (!fc.initialized) {
        if (parent_slot) |ps| {
            try fc.seedRoot(.{ .slot = ps, .hash = parent_hash });
        } else {
            try fc.seedRoot(.{ .slot = slot, .hash = bank_hash });
            return;
        }
    }

    const key = SlotHashKey{ .slot = slot, .hash = bank_hash };
    const parent_key: ?SlotHashKey = if (parent_slot) |ps|
        .{ .slot = ps, .hash = parent_hash }
    else
        null;
    try fc.addNewLeafSlot(key, parent_key);
}

/// Legacy: best slot as just a Slot (drops hash). New code should use
/// `bestOverallSlot()` which returns SlotHashKey.
pub fn bestSlotCompat(fc: *const ForkChoice) ?core.Slot {
    if (!fc.initialized) return null;
    const best = fc.bestOverallSlot();
    return best.slot;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

const StubStakeLookup = struct {
    stake: u64,
    pub fn lookup(self: StubStakeLookup, _: core.Pubkey, _: core.Slot) u64 {
        return self.stake;
    }
};

test "init/deinit clean" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    try std.testing.expect(fc.isEmpty());
}

test "seed root + best is root" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const root: SlotHashKey = .{ .slot = 100, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);
    try std.testing.expect(SlotHashKey.eql(fc.bestOverallSlot(), root));
    try std.testing.expectEqual(@as(?usize, 1), fc.heightOf(root));
}

test "linear chain: best slot tracks tip" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const r: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(r);
    var h1 = core.Hash.ZERO;
    h1.data[0] = 1;
    const k1: SlotHashKey = .{ .slot = 1, .hash = h1 };
    var h2 = core.Hash.ZERO;
    h2.data[0] = 2;
    const k2: SlotHashKey = .{ .slot = 2, .hash = h2 };
    try fc.addNewLeafSlot(k1, r);
    try fc.addNewLeafSlot(k2, k1);
    try std.testing.expect(SlotHashKey.eql(fc.bestOverallSlot(), k2));
    try std.testing.expectEqual(@as(?usize, 3), fc.heightOf(r));
}

test "two siblings: heaviest wins" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const r: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(r);
    var hA = core.Hash.ZERO;
    hA.data[0] = 1;
    const kA: SlotHashKey = .{ .slot = 1, .hash = hA };
    var hB = core.Hash.ZERO;
    hB.data[0] = 2;
    const kB: SlotHashKey = .{ .slot = 1, .hash = hB };
    try fc.addNewLeafSlot(kA, r);
    try fc.addNewLeafSlot(kB, r);

    var pk_b: core.Pubkey = .{ .data = [_]u8{0} ** 32 };
    pk_b.data[0] = 0xBB;
    const votes = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = pk_b, .slot_hash = kB },
    };
    const best = try fc.addVotes(&votes, StubStakeLookup{ .stake = 100 });
    try std.testing.expect(SlotHashKey.eql(best, kB));
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedSubtree(kB));
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedSubtree(r));
}

test "vote migration: old slot loses stake_voted_at, subtree preserved via child" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const r: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(r);
    var hA = core.Hash.ZERO;
    hA.data[0] = 1;
    const kA: SlotHashKey = .{ .slot = 1, .hash = hA };
    var hB = core.Hash.ZERO;
    hB.data[0] = 2;
    const kB: SlotHashKey = .{ .slot = 2, .hash = hB };
    try fc.addNewLeafSlot(kA, r);
    try fc.addNewLeafSlot(kB, kA);

    var pk: core.Pubkey = .{ .data = [_]u8{0} ** 32 };
    pk.data[0] = 0xAB;

    _ = try fc.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = kA }},
        StubStakeLookup{ .stake = 100 },
    );
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedAt(kA));
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedSubtree(kA));

    _ = try fc.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = kB }},
        StubStakeLookup{ .stake = 100 },
    );
    try std.testing.expectEqual(@as(?u64, 0), fc.stakeVotedAt(kA));
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedSubtree(kA));
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedAt(kB));
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedSubtree(kB));
}

test "addForkCompat seeds root then adds leaf" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    var h1 = core.Hash.ZERO;
    h1.data[0] = 1;
    var h2 = core.Hash.ZERO;
    h2.data[0] = 2;
    try addForkCompat(&fc, 1, 0, h1, core.Hash.ZERO);
    try std.testing.expect(fc.initialized);
    try std.testing.expectEqual(@as(?core.Slot, 1), bestSlotCompat(&fc));

    try addForkCompat(&fc, 2, 1, h2, h1);
    try std.testing.expectEqual(@as(?core.Slot, 2), bestSlotCompat(&fc));
}

test "isAncestorBySlot walks via any matching node" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const r: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(r);
    var h1 = core.Hash.ZERO;
    h1.data[0] = 1;
    var h2 = core.Hash.ZERO;
    h2.data[0] = 2;
    const k1: SlotHashKey = .{ .slot = 1, .hash = h1 };
    const k2: SlotHashKey = .{ .slot = 2, .hash = h2 };
    try fc.addNewLeafSlot(k1, r);
    try fc.addNewLeafSlot(k2, k1);
    try std.testing.expect(fc.isAncestorBySlot(2, 1));
    try std.testing.expect(fc.isAncestorBySlot(2, 0));
    try std.testing.expect(!fc.isAncestorBySlot(1, 2));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Boot-time KATs — invariant cases identified by agave-behavior-extractor agents
// (2026-05-26). These cover the corners most likely to drift on future refactor.
// ═══════════════════════════════════════════════════════════════════════════════

const PubkeyStakeEntry = struct { pubkey: core.Pubkey, stake: u64 };

/// Per-pubkey stake map, used by tests that need different stakes per voter.
const PerPubkeyStakeLookup = struct {
    entries: []const PubkeyStakeEntry,

    pub fn lookup(self: PerPubkeyStakeLookup, pubkey: core.Pubkey, _: core.Slot) u64 {
        for (self.entries) |e| {
            if (std.mem.eql(u8, &e.pubkey.data, &pubkey.data)) return e.stake;
        }
        return 0;
    }
};

test "Fork divergence — heavy stake wins, vote migration flips winner (full chain)" {
    // Tests_forks.zig scenario, inlined: linear chain 0..10, fork at 10 into
    // (11,A) and (12,B). A=60% votes 11, B=40% votes 12 → best=11. A migrates
    // to 12 → best=12, AND A's stake_voted_at on 11 returns to 0 (proving
    // migration actually subtracted; pre-port Vexor would have left 6000 stuck).
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const valA_pk = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const valB_pk = core.Pubkey.fromBytes([_]u8{2} ** 32);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = valA_pk, .stake = 6000 },
        .{ .pubkey = valB_pk, .stake = 4000 },
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);

    var prev = root;
    for (1..11) |i| {
        const slot = @as(u64, i);
        var hash_data = [_]u8{0} ** 32;
        std.mem.writeInt(u64, hash_data[0..8], slot, .little);
        const k: SlotHashKey = .{ .slot = slot, .hash = .{ .data = hash_data } };
        try fc.addNewLeafSlot(k, prev);
        prev = k;
    }
    const k10 = prev;
    const k11A: SlotHashKey = .{ .slot = 11, .hash = .{ .data = [_]u8{0xAA} ** 32 } };
    const k12B: SlotHashKey = .{ .slot = 12, .hash = .{ .data = [_]u8{0xBB} ** 32 } };
    try fc.addNewLeafSlot(k11A, k10);
    try fc.addNewLeafSlot(k12B, k10);

    const initial = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = valA_pk, .slot_hash = k11A },
        .{ .pubkey = valB_pk, .slot_hash = k12B },
    };
    const best1 = try fc.addVotes(&initial, stakes);
    try std.testing.expectEqual(@as(u64, 11), best1.slot);
    try std.testing.expectEqual(@as(?u64, 6000), fc.stakeVotedAt(k11A));
    try std.testing.expectEqual(@as(?u64, 4000), fc.stakeVotedAt(k12B));

    const switch_vote = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = valA_pk, .slot_hash = k12B },
    };
    const best2 = try fc.addVotes(&switch_vote, stakes);
    try std.testing.expectEqual(@as(u64, 12), best2.slot);
    try std.testing.expectEqual(@as(?u64, 0), fc.stakeVotedAt(k11A));
    try std.testing.expectEqual(@as(?u64, 0), fc.stakeVotedSubtree(k11A));
    try std.testing.expectEqual(@as(?u64, 10000), fc.stakeVotedAt(k12B));
    // Parent subtree weight conserved (10 had only 11+12 as children).
    try std.testing.expectEqual(@as(?u64, 10000), fc.stakeVotedSubtree(k10));
}

test "Equivocating siblings at the same slot — both representable, heavier wins" {
    // (Slot, Hash) keying invariant: two blocks at same slot with different
    // bank_hashes are distinct nodes. The pre-port slot-only HashMap could
    // represent at most one of them — exactly the bug this Phase 1 fixes.
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);

    const v1: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{0x11} ** 32 } };
    const v2: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{0x22} ** 32 } };
    try fc.addNewLeafSlot(v1, root);
    try fc.addNewLeafSlot(v2, root);

    try std.testing.expect(fc.containsBlock(v1));
    try std.testing.expect(fc.containsBlock(v2));

    const a_pk = core.Pubkey.fromBytes([_]u8{0xAA} ** 32);
    const b_pk = core.Pubkey.fromBytes([_]u8{0xBB} ** 32);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = a_pk, .stake = 100 },
        .{ .pubkey = b_pk, .stake = 200 }, // B heavier
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };

    const votes = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = a_pk, .slot_hash = v1 },
        .{ .pubkey = b_pk, .slot_hash = v2 },
    };
    const best = try fc.addVotes(&votes, stakes);
    try std.testing.expect(SlotHashKey.eql(best, v2));
}

test "KAT 1 — aggregate_slot: invalid children still contribute weight" {
    // White-box test: directly mutates ForkInfo fields (stake_voted_at,
    // latest_invalid_ancestor) to construct the test state. The mark-invalid
    // public API is Phase 3 work — once shipped, replace these pokes with
    // calls to markForkInvalidCandidate / setStakeForTesting helpers.
    //
    // Agave 877-893 comment block: child forks marked invalid (latest_invalid_ancestor
    // set) still propagate their stake_voted_subtree to the parent's
    // stake_voted_subtree. Only `best_slot` selection filters by is_candidate.
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);
    const k1: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{1} ** 32 } };
    const k_invalid: SlotHashKey = .{ .slot = 2, .hash = .{ .data = [_]u8{2} ** 32 } };
    const k_valid: SlotHashKey = .{ .slot = 3, .hash = .{ .data = [_]u8{3} ** 32 } };
    try fc.addNewLeafSlot(k1, root);
    try fc.addNewLeafSlot(k_invalid, k1);
    try fc.addNewLeafSlot(k_valid, k1);

    // Mark k_invalid as invalid (Phase 1 doesn't have the public marker yet,
    // so we hand-set the field — Phase 3 will replace this with the proper API).
    if (fc.fork_infos.getPtrContext(k_invalid, .{})) |info| {
        info.latest_invalid_ancestor = k_invalid.slot;
    }

    // Set stakes_voted_at directly to bypass needing a real stake lookup, then
    // call aggregateSlot on the parent to recompute its subtree.
    if (fc.fork_infos.getPtrContext(k_invalid, .{})) |info| info.stake_voted_at = 66;
    if (fc.fork_infos.getPtrContext(k_valid, .{})) |info| info.stake_voted_at = 34;
    if (fc.fork_infos.getPtrContext(k_invalid, .{})) |info| info.stake_voted_subtree = 66;
    if (fc.fork_infos.getPtrContext(k_valid, .{})) |info| info.stake_voted_subtree = 34;

    fc.aggregateSlot(k1);

    // Invariant: invalid child STILL counts toward parent's subtree weight.
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedSubtree(k1));
    // But best_slot prefers k_valid (only candidate).
    const best_under_k1 = fc.bestSlotOf(k1) orelse return error.MissingBestSlot;
    try std.testing.expect(SlotHashKey.eql(best_under_k1, k_valid));
}

test "KAT 2 — aggregate_slot: best-slot tiebreak by lower hash on equal stake" {
    // Two candidate children with equal stake_voted_subtree — Agave 904
    // tiebreaks by lower SlotHashKey (slot ASC, then hash bytes lex ASC).
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);

    // Two equivocating slot-11 siblings. h_a < h_b byte-lex.
    const h_a: core.Hash = .{ .data = [_]u8{0x10} ** 32 };
    const h_b: core.Hash = .{ .data = [_]u8{0x20} ** 32 };
    const k_a: SlotHashKey = .{ .slot = 11, .hash = h_a };
    const k_b: SlotHashKey = .{ .slot = 11, .hash = h_b };
    try fc.addNewLeafSlot(k_a, root);
    try fc.addNewLeafSlot(k_b, root);

    if (fc.fork_infos.getPtrContext(k_a, .{})) |info| {
        info.stake_voted_at = 50;
        info.stake_voted_subtree = 50;
    }
    if (fc.fork_infos.getPtrContext(k_b, .{})) |info| {
        info.stake_voted_at = 50;
        info.stake_voted_subtree = 50;
    }
    fc.aggregateSlot(root);

    // Lower hash wins.
    const best_under_root = fc.bestSlotOf(root) orelse return error.MissingBestSlot;
    try std.testing.expect(SlotHashKey.eql(best_under_root, k_a));
}

test "KAT 3 — aggregate_slot: deepest ignores is_candidate filter" {
    // White-box test: directly mutates ForkInfo fields. Same reason as KAT 1
    // (Phase 3 will provide proper mark-invalid + height-setter APIs).
    //
    // Agave 911-931: deepest_slot selection considers ALL siblings regardless
    // of validity. An invalid child with greater height beats a valid child
    // with shorter height (for the deepest slot — not for best_slot).
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);
    const parent: SlotHashKey = .{ .slot = 10, .hash = .{ .data = [_]u8{10} ** 32 } };
    const k_invalid: SlotHashKey = .{ .slot = 11, .hash = .{ .data = [_]u8{0xA} ** 32 } };
    const k_valid: SlotHashKey = .{ .slot = 11, .hash = .{ .data = [_]u8{0xB} ** 32 } };
    try fc.addNewLeafSlot(parent, root);
    try fc.addNewLeafSlot(k_invalid, parent);
    try fc.addNewLeafSlot(k_valid, parent);

    // Set up: k_invalid has height 5 (deep) but is marked invalid.
    //         k_valid has height 3 (shallow) but is candidate.
    const deep_leaf: SlotHashKey = .{ .slot = 99, .hash = .{ .data = [_]u8{0x99} ** 32 } };
    if (fc.fork_infos.getPtrContext(k_invalid, .{})) |info| {
        info.height = 5;
        info.stake_voted_subtree = 50;
        info.latest_invalid_ancestor = k_invalid.slot;
        info.deepest_slot = deep_leaf;
    }
    if (fc.fork_infos.getPtrContext(k_valid, .{})) |info| {
        info.height = 3;
        info.stake_voted_subtree = 999;
    }

    fc.aggregateSlot(parent);

    // Best (candidate-filtered) = k_valid.
    const best_under_parent = fc.bestSlotOf(parent) orelse return error.MissingBestSlot;
    try std.testing.expect(SlotHashKey.eql(best_under_parent, k_valid));

    // Deepest (no validity filter) = k_invalid.deepest_slot = deep_leaf.
    const deepest_under_parent = fc.deepestSlotOf(parent) orelse return error.MissingDeepestSlot;
    try std.testing.expect(SlotHashKey.eql(deepest_under_parent, deep_leaf));
}

test "KAT 4 — propagate_new_leaf: best-loop early-break invariant" {
    // When a new leaf inserts but is NOT the heaviest child of its parent
    // (because a sibling has more stake), propagate_new_leaf must NOT push
    // best_slot up past the parent — the ancestor's best_slot was already
    // pointing at the previous-heaviest path. Specifically: a fresh leaf has
    // stake_voted_subtree=0, so it generally loses to any sibling with stake.
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);

    const k1: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{1} ** 32 } };
    try fc.addNewLeafSlot(k1, root);
    if (fc.fork_infos.getPtrContext(k1, .{})) |info| {
        info.stake_voted_at = 100;
        info.stake_voted_subtree = 100;
    }
    // Recompute root so its best_slot points at k1.
    fc.aggregateSlot(root);
    const root_best_before = fc.bestSlotOf(root) orelse return error.MissingBestSlot;
    try std.testing.expect(SlotHashKey.eql(root_best_before, k1));

    // Now add a heavier-key sibling under root — k2 has slot=2, hash all-0x22.
    // Fresh leaf has stake=0, k1 sibling has stake=100. k2 loses isBestChild
    // (less stake), so propagate_new_leaf's best-loop must NOT push up.
    const k2: SlotHashKey = .{ .slot = 2, .hash = .{ .data = [_]u8{0x22} ** 32 } };
    try fc.addNewLeafSlot(k2, root);

    // Root.best_slot must STILL be k1 (the propagation broke at the first
    // ancestor because the new leaf wasn't the best child).
    const root_best_after = fc.bestSlotOf(root) orelse return error.MissingBestSlot;
    try std.testing.expect(SlotHashKey.eql(root_best_after, k1));
}

test "KAT — Task #3 shadow basis: bestOverallSlot = fresh tip; orphan w/ stake-sibling NOT picked" {
    // Validates the two claims the observe-only [HEAVIEST-SHADOW] log (replay_stage.submitVote) relies on:
    //  (1) HEALTHY CHAIN — a freshly-frozen tip with ZERO votes is the heaviest leaf (propagate_new_leaf
    //      makes a single-child fork's leaf the best_slot of every ancestor), so bestOverallSlot() == the
    //      fresh tip. That is exactly the latency-1 target Agave/FD vote, and the ~1 credit the shadow
    //      measures us forgoing by retargeting one slot behind.
    //  (2) ORPHAN SAFETY — once a canonical sibling carries cluster vote-stake, a 0-stake orphan sibling
    //      is NEVER bestOverallSlot (even when the orphan has the HIGHER slot number). This is the safety
    //      basis for an eventual armed path: the 2026-06-27 delinquency orphan was a cluster-skipped fork
    //      with 0 subtree stake, so heaviest-subtree selection structurally avoids it.
    const allocator = std.testing.allocator;
    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    const a: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{1} ** 32 } };
    const b: SlotHashKey = .{ .slot = 2, .hash = .{ .data = [_]u8{2} ** 32 } }; // canonical

    // (1) root(0) -> A(1) -> B(2), B unvoted: fresh tip B is the heaviest leaf.
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();
    try fc.seedRoot(root);
    try fc.addNewLeafSlot(a, root);
    try fc.addNewLeafSlot(b, a);
    try std.testing.expect(SlotHashKey.eql(fc.bestOverallSlot(), b)); // shadow would log best_is_tip=true

    // (2) root(0) -> A(1) -> { B(2)=canonical (voted), C(3)=orphan, higher slot, 0 stake }.
    var fc2 = HeaviestSubtreeForkChoice.init(allocator);
    defer fc2.deinit();
    try fc2.seedRoot(root);
    try fc2.addNewLeafSlot(a, root);
    try fc2.addNewLeafSlot(b, a);
    const c: SlotHashKey = .{ .slot = 3, .hash = .{ .data = [_]u8{3} ** 32 } }; // orphan sibling
    try fc2.addNewLeafSlot(c, a);
    const voter = core.Pubkey.fromBytes([_]u8{0xCD} ** 32);
    const entries = [_]PubkeyStakeEntry{.{ .pubkey = voter, .stake = 1000 }};
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    _ = try fc2.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = voter, .slot_hash = b }},
        stakes,
    );
    // Orphan C has the HIGHER slot (3 > 2) yet is never chosen: the stake-carrying canonical B wins.
    try std.testing.expect(SlotHashKey.eql(fc2.bestOverallSlot(), b));
}

test "KAT — checkSwitchThreshold slot-memoization is exact incl. cache overflow (task #32)" {
    // The 2026-07-06 starvation root fix memoizes the per-voter switching-proof
    // verdict by unique candidate SLOT (canonical: Agave consensus.rs:1249 passes
    // only the slot to is_valid_switching_proof_vote). This KAT builds 70 unique
    // candidate slots — OVERFLOWING the 64-entry memo so both the cached and the
    // fallback-compute paths run — with 2 voters per slot, and checks the summed
    // locked_out_stake equals the exact per-voter expectation, plus the threshold
    // flip behaves identically under a small denominator.
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();
    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);

    // Our fork: root -> 1 (last_voted = 1).
    const our_leaf: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{0xAA} ** 32 } };
    try fc.addNewLeafSlot(our_leaf, root);
    // Switch-target fork: root -> 5000.
    const switch_leaf: SlotHashKey = .{ .slot = 5000, .hash = .{ .data = [_]u8{0xBB} ** 32 } };
    try fc.addNewLeafSlot(switch_leaf, root);
    // Candidate fork: root -> 10 -> 11 -> ... -> 79 (70 unique slots > 64 memo entries).
    var parent = root;
    var s: u64 = 10;
    while (s < 80) : (s += 1) {
        var h: [32]u8 = [_]u8{0} ** 32;
        h[0] = @intCast(s & 0xFF);
        h[1] = 0xC0;
        const k: SlotHashKey = .{ .slot = s, .hash = .{ .data = h } };
        try fc.addNewLeafSlot(k, parent);
        parent = k;
    }

    // 140 voters: 2 per candidate slot, stake 7 each. Every candidate slot is
    // cross-fork from last_voted=1 with GCA=0, and switch_slot=5000 descends
    // from 0 → every voter counts. Exact expected locked_out = 140 * 7 = 980.
    var entries: [140]PubkeyStakeEntry = undefined;
    var votes: [140]HeaviestSubtreeForkChoice.PubkeyVote = undefined;
    var i: usize = 0;
    while (i < 140) : (i += 1) {
        var pkb: [32]u8 = [_]u8{0} ** 32;
        pkb[0] = @intCast(i & 0xFF);
        pkb[1] = 0xEE;
        const pk = core.Pubkey.fromBytes(pkb);
        entries[i] = .{ .pubkey = pk, .stake = 7 };
        const vslot: u64 = 10 + (i / 2); // 2 voters per slot, slots 10..79
        var vh: [32]u8 = [_]u8{0} ** 32;
        vh[0] = @intCast(vslot & 0xFF);
        vh[1] = 0xC0;
        votes[i] = .{ .pubkey = pk, .slot_hash = .{ .slot = vslot, .hash = .{ .data = vh } } };
    }
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    _ = try fc.addVotes(&votes, stakes);

    // Huge denominator → threshold never crossed → full loop runs → exact sum.
    const dec_full = fc.checkSwitchThreshold(1, 5000, 1_000_000_000_000, stakes);
    try std.testing.expect(!dec_full.same_fork);
    try std.testing.expect(!dec_full.would_switch);
    try std.testing.expectEqual(@as(u64, 980), dec_full.locked_out_stake);

    // Small denominator → 980/1000 > 0.38 → SwitchProof fires (identical to naive).
    const dec_small = fc.checkSwitchThreshold(1, 5000, 1000, stakes);
    try std.testing.expect(!dec_small.same_fork);
    try std.testing.expect(dec_small.would_switch);

    // Same-fork fast path unchanged: switching to a descendant of last vote.
    const child_of_our: SlotHashKey = .{ .slot = 2, .hash = .{ .data = [_]u8{0xAD} ** 32 } };
    try fc.addNewLeafSlot(child_of_our, our_leaf);
    const dec_same = fc.checkSwitchThreshold(1, 2, 1000, stakes);
    try std.testing.expect(dec_same.same_fork);
    try std.testing.expect(dec_same.would_switch);
}

test "KAT 5 — addVotes: same slot, smaller hash, re-vote processes (equivocation)" {
    // Agave 1015: when new_slot == prev_slot but new_hash < prev_hash, the
    // vote IS processed (it's a duplicate version of the same slot).
    // This is essential for handling equivocating blocks — Firedancer's
    // fd_ghost_count_vote rejects this entirely; Vexor follows Agave.
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);

    const h_high: core.Hash = .{ .data = [_]u8{0xFF} ** 32 };
    const h_low: core.Hash = .{ .data = [_]u8{0x01} ** 32 };
    const k_high: SlotHashKey = .{ .slot = 10, .hash = h_high };
    const k_low: SlotHashKey = .{ .slot = 10, .hash = h_low };
    try fc.addNewLeafSlot(k_high, root);
    try fc.addNewLeafSlot(k_low, root);

    const pk = core.Pubkey.fromBytes([_]u8{0xAB} ** 32);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk, .stake = 100 },
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };

    // Step 1: vote for k_high.
    _ = try fc.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = k_high }},
        stakes,
    );
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedAt(k_high));

    // Step 2: same pubkey, same slot, SMALLER hash — must process.
    _ = try fc.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = k_low }},
        stakes,
    );
    try std.testing.expectEqual(@as(?u64, 0), fc.stakeVotedAt(k_high));
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedAt(k_low));

    // Step 3: same again — must skip (equal hash, not strictly smaller).
    _ = try fc.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = k_low }},
        stakes,
    );
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedAt(k_low));

    // Step 4: slot < tree_root → skip.
    const below_root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    _ = try fc.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = below_root }},
        stakes,
    );
    try std.testing.expectEqual(@as(?u64, 100), fc.stakeVotedAt(k_low));
}

test "FIX #87 — markForkInvalidCandidate downweights subtree, bestOverallSlot pivots" {
    // 2026-05-28 Phase 3 port test. Models the actual wedge scenario:
    //   - root has 2 children k1 and k2
    //   - k1 has descendant k1_child (vote target with stake)
    //   - mark k1 invalid → fork-choice should pivot bestOverallSlot to k2
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);

    const k1: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{0x11} ** 32 } };
    const k1_child: SlotHashKey = .{ .slot = 2, .hash = .{ .data = [_]u8{0x12} ** 32 } };
    const k2: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{0x22} ** 32 } };

    try fc.addNewLeafSlot(k1, root);
    try fc.addNewLeafSlot(k1_child, k1);
    try fc.addNewLeafSlot(k2, root);

    // Vote k1_child heavily so it would be best_slot without intervention.
    const pk = core.Pubkey.fromBytes([_]u8{0xAB} ** 32);
    _ = try fc.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = k1_child }},
        StubStakeLookup{ .stake = 100 },
    );

    // Pre-condition: bestOverallSlot should be k1_child (heaviest).
    const best_before = fc.bestOverallSlot();
    try std.testing.expect(SlotHashKey.eql(best_before, k1_child));

    // Verify k1 and k1_child are candidates pre-mark.
    try std.testing.expect(fc.isCandidate(k1).?);
    try std.testing.expect(fc.isCandidate(k1_child).?);

    // Action: mark k1 invalid. This should:
    //   - Set k1.latest_invalid_ancestor = 1 (self)
    //   - Set k1_child.latest_invalid_ancestor = 1 (descendant)
    //   - Re-aggregate root → best_slot pivots to k2 (only remaining candidate)
    fc.markForkInvalidCandidate(k1);

    // k1 and k1_child should now be non-candidates.
    try std.testing.expect(!fc.isCandidate(k1).?);
    try std.testing.expect(!fc.isCandidate(k1_child).?);
    // k2 should still be a candidate.
    try std.testing.expect(fc.isCandidate(k2).?);

    // Best slot should pivot to k2 (the only remaining valid child of root).
    const best_after = fc.bestOverallSlot();
    try std.testing.expect(SlotHashKey.eql(best_after, k2));

    // latest_invalid_ancestor checks.
    try std.testing.expectEqual(@as(?core.Slot, 1), fc.latestInvalidAncestor(k1));
    try std.testing.expectEqual(@as(?core.Slot, 1), fc.latestInvalidAncestor(k1_child));
    try std.testing.expectEqual(@as(?core.Slot, null), fc.latestInvalidAncestor(k2));
}

test "FIX #87 — markForkInvalidCandidate on duplicate-confirmed slot refuses" {
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);
    // Root is implicitly duplicate-confirmed (line 215 init).
    fc.markForkInvalidCandidate(root);
    // Should refuse — root stays candidate.
    try std.testing.expect(fc.isCandidate(root).?);
}

test "FIX #87 — markForkValidCandidate reverses mark-invalid" {
    const allocator = std.testing.allocator;
    var fc = HeaviestSubtreeForkChoice.init(allocator);
    defer fc.deinit();

    const root: SlotHashKey = .{ .slot = 0, .hash = core.Hash.ZERO };
    try fc.seedRoot(root);

    const k1: SlotHashKey = .{ .slot = 1, .hash = .{ .data = [_]u8{0x11} ** 32 } };
    const k1_child: SlotHashKey = .{ .slot = 2, .hash = .{ .data = [_]u8{0x12} ** 32 } };
    try fc.addNewLeafSlot(k1, root);
    try fc.addNewLeafSlot(k1_child, k1);

    fc.markForkInvalidCandidate(k1);
    try std.testing.expect(!fc.isCandidate(k1).?);
    try std.testing.expect(!fc.isCandidate(k1_child).?);

    // Mark k1 valid (duplicate-confirmed).
    fc.markForkValidCandidate(k1);
    try std.testing.expect(fc.isCandidate(k1).?);
    // k1_child's latest_invalid_ancestor was 1, which <= 1 (newly-valid),
    // so it gets cleared too.
    try std.testing.expect(fc.isCandidate(k1_child).?);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 1 — setTreeRoot wiring (the dead setTreeRoot is now called on root
// advance in replay_stage.zig:submitVote, gated by VEX_FC_REROOT). These tests
// cover the PURE setTreeRoot behavior the wiring relies on. The wiring itself is
// gated by the live soak (flag ON → re-root counter nonzero, nodeCount plateaus,
// voting continues) — an offline replay_stage test is out of Phase-1 scope.
//
// Tree shape used below (distinct slots so post-prune isAncestorBySlot over a
// pruned slot is unambiguous — no surviving node at that slot):
//   R(slot 0) ── A(slot 1) ── A1(slot 3) ── A2(slot 4)
//             └─ B(slot 2)              (sibling of A under R)
// ═══════════════════════════════════════════════════════════════════════════════

const ReRootTree = struct {
    r: SlotHashKey,
    a: SlotHashKey,
    b: SlotHashKey,
    a1: SlotHashKey,
    a2: SlotHashKey,

    fn build(fc: *HeaviestSubtreeForkChoice) !ReRootTree {
        const t = ReRootTree{
            .r = .{ .slot = 0, .hash = core.Hash.ZERO },
            .a = .{ .slot = 1, .hash = .{ .data = [_]u8{0xAA} ** 32 } },
            .b = .{ .slot = 2, .hash = .{ .data = [_]u8{0xBB} ** 32 } },
            .a1 = .{ .slot = 3, .hash = .{ .data = [_]u8{0xA1} ** 32 } },
            .a2 = .{ .slot = 4, .hash = .{ .data = [_]u8{0xA2} ** 32 } },
        };
        try fc.seedRoot(t.r);
        try fc.addNewLeafSlot(t.a, t.r);
        try fc.addNewLeafSlot(t.b, t.r);
        try fc.addNewLeafSlot(t.a1, t.a);
        try fc.addNewLeafSlot(t.a2, t.a1);
        return t;
    }
};

test "Phase 1 — setTreeRoot prunes non-descendants, keeps the A-subtree" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try ReRootTree.build(&fc);

    try fc.setTreeRoot(t.a);

    // Kept: A and its descendants.
    try std.testing.expect(fc.containsBlock(t.a));
    try std.testing.expect(fc.containsBlock(t.a1));
    try std.testing.expect(fc.containsBlock(t.a2));
    // Pruned: old root R and the sibling subtree B.
    try std.testing.expect(!fc.containsBlock(t.r));
    try std.testing.expect(!fc.containsBlock(t.b));
    // Exactly the A-subtree remains: {A, A1, A2}.
    try std.testing.expectEqual(@as(usize, 3), fc.nodeCount());
    // A's parent link is severed; A is the new tree root.
    try std.testing.expectEqual(@as(?SlotHashKey, null), fc.parentOf(t.a));
    try std.testing.expect(SlotHashKey.eql(fc.treeRoot(), t.a));
}

test "Phase 1 — setTreeRoot bounds the tree (nodeCount strictly drops)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try ReRootTree.build(&fc);

    const before = fc.nodeCount();
    try std.testing.expectEqual(@as(usize, 5), before);
    try fc.setTreeRoot(t.a);
    try std.testing.expect(fc.nodeCount() < before);
}

test "Phase 1 — re-root to on-fork ancestor keeps the heaviest in the live subtree" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try ReRootTree.build(&fc);

    // Vote A2 heaviest so the heaviest slot lives inside the A-subtree we keep.
    var pk: core.Pubkey = .{ .data = [_]u8{0} ** 32 };
    pk.data[0] = 0xA2;
    _ = try fc.addVotes(
        &[_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = t.a2 }},
        StubStakeLookup{ .stake = 100 },
    );

    try fc.setTreeRoot(t.a);

    // bestOverallSlot must stay within the kept fork {A, A1, A2} — the guard
    // against re-rooting having pruned the live (heaviest) fork.
    const best = fc.bestOverallSlot();
    try std.testing.expect(SlotHashKey.eql(best, t.a) or
        SlotHashKey.eql(best, t.a1) or
        SlotHashKey.eql(best, t.a2));
    try std.testing.expect(SlotHashKey.eql(best, t.a2)); // A2 is heaviest+deepest
}

test "Phase 1 — setTreeRoot fail-safe: key not in tree leaves tree unchanged" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try ReRootTree.build(&fc);

    const nodes_before = fc.nodeCount();
    const root_before = fc.treeRoot();
    // A key for a slot that is NOT in the tree.
    const not_in_tree: SlotHashKey = .{ .slot = 99, .hash = .{ .data = [_]u8{0xFF} ** 32 } };

    try std.testing.expectError(error.NewRootNotInTree, fc.setTreeRoot(not_in_tree));
    // The error is checked BEFORE any mutation — tree must be untouched.
    try std.testing.expectEqual(nodes_before, fc.nodeCount());
    try std.testing.expect(SlotHashKey.eql(fc.treeRoot(), root_before));
    try std.testing.expect(fc.containsBlock(t.r)); // R still present (no prune happened)
}

test "Phase 1 — is_same_fork primitive still behaves after re-root" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try ReRootTree.build(&fc);

    try fc.setTreeRoot(t.a);

    // Kept descendant: A2(slot 4) has ancestor A(slot 1) → true.
    try std.testing.expect(fc.isAncestorBySlot(t.a2.slot, t.a.slot));
    // Pruned slot B(slot 2): no node at slot 2 survives → ancestor query false.
    try std.testing.expect(!fc.isAncestorBySlot(t.a2.slot, t.b.slot));
    try std.testing.expect(!fc.isAncestorBySlot(t.b.slot, t.a.slot));
}

// ─────────────────────────────────────────────────────────────────────────
// Switch-threshold KATs (Agave make_check_switch_threshold_decision, Tier-1).
// Fork graph:
//          root(100)
//           /     \
//     A:200(L)     B:300   ← switch target
//                     \
//                    B:305 ── B:308 ── B:310
// last vote L = 200 on fork A; we evaluate switching to 300 on fork B.
// GCA(any B-voter, 200) = 100; switch(300) descends from 100 → B-voters count.
// ─────────────────────────────────────────────────────────────────────────
const SwitchTree = struct {
    root: SlotHashKey,
    a200: SlotHashKey,
    b300: SlotHashKey,
    b305: SlotHashKey,
    b308: SlotHashKey,
    a250: SlotHashKey, // same-fork-as-A descendant (for the "don't count" case)
    fn k(slot: u64, tag: u8) SlotHashKey {
        return .{ .slot = slot, .hash = .{ .data = [_]u8{tag} ** 32 } };
    }
    fn build(fc: *HeaviestSubtreeForkChoice) !SwitchTree {
        const root = k(100, 0x10);
        try fc.seedRoot(root);
        const a200 = k(200, 0xAA);
        const a250 = k(250, 0xAB);
        const b300 = k(300, 0xB0);
        const b305 = k(305, 0xB5);
        const b308 = k(308, 0xB8);
        const b310 = k(310, 0xBA);
        try fc.addNewLeafSlot(a200, root);
        try fc.addNewLeafSlot(a250, a200);
        try fc.addNewLeafSlot(b300, root);
        try fc.addNewLeafSlot(b305, b300);
        try fc.addNewLeafSlot(b308, b305);
        try fc.addNewLeafSlot(b310, b308);
        return .{ .root = root, .a200 = a200, .b300 = b300, .b305 = b305, .b308 = b308, .a250 = a250 };
    }
};

test "switch threshold: just-UNDER 38% fails (no switch)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{2} ** 32);
    try fc.latest_votes.put(fc.allocator, pk1, t.b305);
    try fc.latest_votes.put(fc.allocator, pk2, t.b308);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 200 }, // 20%
        .{ .pubkey = pk2, .stake = 170 }, // +17% = 37%
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const d = fc.checkSwitchThreshold(200, t.b300.slot, 1000, stakes);
    try std.testing.expect(!d.same_fork);
    try std.testing.expect(!d.would_switch); // 0.37 !> 0.38
    try std.testing.expectEqual(@as(u64, 370), d.locked_out_stake);
}

test "switch threshold: just-OVER 38% proves switch" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{2} ** 32);
    try fc.latest_votes.put(fc.allocator, pk1, t.b305);
    try fc.latest_votes.put(fc.allocator, pk2, t.b308);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 200 },
        .{ .pubkey = pk2, .stake = 181 }, // 38.1%
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const d = fc.checkSwitchThreshold(200, t.b300.slot, 1000, stakes);
    try std.testing.expect(d.would_switch); // 0.381 > 0.38
}

test "switch threshold: EXACTLY 0.38 fails (strict >)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    try fc.latest_votes.put(fc.allocator, pk1, t.b305);
    const entries = [_]PubkeyStakeEntry{.{ .pubkey = pk1, .stake = 380 }}; // exactly 38.0%
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const d = fc.checkSwitchThreshold(200, t.b300.slot, 1000, stakes);
    try std.testing.expect(!d.would_switch); // boundary: NOT > 0.38
}

test "switch threshold: conservative default — same-fork + unknown-fork voters NOT counted" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{2} ** 32);
    // pk1: votes on fork A (slot 250 descends from our last vote 200) → excluded.
    try fc.latest_votes.put(fc.allocator, pk1, t.a250);
    // pk2: votes at slot 999 which is NOT in the tree → null GCA → excluded.
    try fc.latest_votes.put(fc.allocator, pk2, SwitchTree.k(999, 0xCC));
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 600 }, // huge, but same fork
        .{ .pubkey = pk2, .stake = 600 }, // huge, but unknown fork
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const d = fc.checkSwitchThreshold(200, t.b300.slot, 1000, stakes);
    try std.testing.expect(!d.would_switch); // 0% counted → no switch
    try std.testing.expectEqual(@as(u64, 0), d.locked_out_stake);
}

test "switch threshold: SameFork (candidate descends from last vote) — always permitted" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const entries = [_]PubkeyStakeEntry{};
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    // last vote 200, candidate 250 descends from 200 → SameFork, no proof needed.
    const d = fc.checkSwitchThreshold(200, t.a250.slot, 1000, stakes);
    try std.testing.expect(d.same_fork);
    try std.testing.expect(d.would_switch);
}

test "switch threshold: cross-fork with <38% must NOT switch (no-proof-vote regression, §3a)" {
    // Regression for the GHOST is_same_fork gap: a cross-fork candidate
    // (300 does NOT descend from our last vote 200) with only 10% locked out
    // must be refused — the decision must never silently permit a no-proof vote.
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    try fc.latest_votes.put(fc.allocator, pk1, t.b305);
    const entries = [_]PubkeyStakeEntry{.{ .pubkey = pk1, .stake = 100 }}; // 10%
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const d = fc.checkSwitchThreshold(200, t.b300.slot, 1000, stakes);
    try std.testing.expect(!d.same_fork); // confirms it IS treated as cross-fork
    try std.testing.expect(!d.would_switch); // and refused at 10% < 38%
}

// ─────────────────────────────────────────────────────────────────────────
// KAT — switch-proof GOSSIP feed (P0 wedge 421109451, 2026-07-10).
//
// Live failure shape: fork at ~421109451; our tower voted own-fork tips
// (votecov fallback), the cluster rooted the sibling fork. The switch proof
// observed 0/325M SOL (0.00%) because its ONLY feed — latest_votes, i.e.
// LANDED vote-account state — lags the tip: every cluster voter's landed
// cand_slot <= our last_voted_slot → all filtered by the canonical
// strictly-newer predicate → locked_out=0 → [TOWER-LOCKOUT] refused all
// votes → on-chain lastVote froze → DELINQUENT.
//
// Model on SwitchTree: our last vote = 200 (fork A tip). Cluster's LANDED
// votes are stale (≤ 200: the root, 100). Cluster's fresh GOSSIP votes are
// on fork B (305/308 — banks we froze; the cluster rooted B).
// ─────────────────────────────────────────────────────────────────────────

test "KAT wedge-421109451: stale landed feed alone observes 0% (pre-fix repro)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{2} ** 32);
    // Cluster voters' LANDED view is stale: last landed votes at the fork
    // point (root 100) — at/below our last vote 200, exactly the wedge state.
    try fc.latest_votes.put(fc.allocator, pk1, t.root);
    try fc.latest_votes.put(fc.allocator, pk2, t.root);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 500 }, // 50%
        .{ .pubkey = pk2, .stake = 470 }, // +47% = 97% — "the ENTIRE cluster"
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    // Pre-fix call shape (landed only): 97% of stake is on fork B but the
    // landed feed can't see it → 0.00% observed, no switch. This reproduces
    // the live line: locked_out=0/325483776387703672 (0.00%).
    const d = fc.checkSwitchThreshold(200, t.b300.slot, 1000, stakes);
    try std.testing.expect(!d.same_fork);
    try std.testing.expect(!d.would_switch);
    try std.testing.expectEqual(@as(u64, 0), d.locked_out_stake);
}

test "KAT wedge-421109451: gossip feed rescues — authorize with correct stake % (post-fix)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{2} ** 32);
    // Same stale landed view as the pre-fix repro…
    try fc.latest_votes.put(fc.allocator, pk1, t.root);
    try fc.latest_votes.put(fc.allocator, pk2, t.root);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 500 },
        .{ .pubkey = pk2, .stake = 470 },
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    // …plus the REAL-TIME gossip observations: both voters' fresh votes are on
    // fork B, for (slot, hash) keys we froze.
    const gossip = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = pk1, .slot_hash = t.b305 },
        .{ .pubkey = pk2, .slot_hash = t.b308 },
    };
    const d = fc.checkSwitchThresholdGossip(200, t.b300.slot, 1000, stakes, &gossip);
    try std.testing.expect(!d.same_fork);
    try std.testing.expect(d.would_switch); // THE fix: cross-fork escape authorized
    // Early return fires at pk1 already (500/1000 = 50% > 38%).
    try std.testing.expectEqual(@as(u64, 500), d.locked_out_stake);
    try std.testing.expect(d.gossip_counted >= 1);
}

test "KAT gossip switch-proof: cross-source dedup — landed-counted voter's gossip vote adds NO stake" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    // pk1's LANDED vote is fresh AND on fork B → the landed loop counts its
    // 300 stake (30%, under threshold, no early return).
    try fc.latest_votes.put(fc.allocator, pk1, t.b305);
    const entries = [_]PubkeyStakeEntry{.{ .pubkey = pk1, .stake = 300 }};
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    // pk1 ALSO has a (newer) gossip vote on fork B. Counting it again would
    // double 300 → 600 = 60% → false SwitchProof. Agave dedups via
    // locked_out_vote_accounts; we must too.
    const gossip = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = pk1, .slot_hash = t.b308 },
    };
    const d = fc.checkSwitchThresholdGossip(200, t.b300.slot, 1000, stakes, &gossip);
    try std.testing.expect(!d.would_switch); // 30% !> 38% — NOT double-counted
    try std.testing.expectEqual(@as(u64, 300), d.locked_out_stake);
    try std.testing.expectEqual(@as(u32, 0), d.gossip_counted);
}

test "KAT gossip switch-proof: frozen-bank admission — unknown (slot,hash) NOT counted" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{2} ** 32);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 600 },
        .{ .pubkey = pk2, .stake = 600 },
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const gossip = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        // pk1: vote for slot 305 but a DIFFERENT hash than the bank we froze
        // (duplicate version) → Agave would never have admitted it to
        // max_gossip_frozen_votes → must not count.
        .{ .pubkey = pk1, .slot_hash = SwitchTree.k(305, 0xEE) },
        // pk2: vote for a slot we never froze at all → must not count.
        .{ .pubkey = pk2, .slot_hash = SwitchTree.k(999, 0xEF) },
    };
    const d = fc.checkSwitchThresholdGossip(200, t.b300.slot, 1000, stakes, &gossip);
    try std.testing.expect(!d.would_switch);
    try std.testing.expectEqual(@as(u64, 0), d.locked_out_stake);
    try std.testing.expectEqual(@as(u32, 0), d.gossip_counted);
}

test "KAT gossip switch-proof: same-fork + stale gossip votes NOT counted (predicates a+d)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try SwitchTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{2} ** 32);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 600 },
        .{ .pubkey = pk2, .stake = 600 },
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const gossip = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        // pk1: gossip vote on OUR OWN fork (250 descends from last vote 200) —
        // same-fork votes never count toward a switch proof (predicate d).
        .{ .pubkey = pk1, .slot_hash = t.a250 },
        // pk2: gossip vote at/below our last vote — strictly-newer filter
        // (predicate a; the wedge's landed-feed failure mode must apply to
        // stale gossip too).
        .{ .pubkey = pk2, .slot_hash = t.root },
    };
    const d = fc.checkSwitchThresholdGossip(200, t.b300.slot, 1000, stakes, &gossip);
    try std.testing.expect(!d.would_switch);
    try std.testing.expectEqual(@as(u64, 0), d.locked_out_stake);
    try std.testing.expectEqual(@as(u32, 0), d.gossip_counted);
}

// ═══════════════════════════════════════════════════════════════════════════════
// KAT — landed-loop filter fix (2026-07-17, fix/switchproof-gossip-arming).
// Small tree modeling "our dead fork raced numerically AHEAD of the canonical
// one before dying" — the exact scenario the pre-fix strictly-newer-than-
// last-vote filter could never escape:
//
//   root(100) --dead(300) [OUR last vote, doomed fork, numerically high]
//             \-canon_mid(250)--canon_tip(260) [REAL cluster fork, lower slot
//                                                numbers than our dead tip]
// ═══════════════════════════════════════════════════════════════════════════════

const AheadTree = struct {
    root: SlotHashKey,
    dead: SlotHashKey,
    canon_mid: SlotHashKey,
    canon_tip: SlotHashKey,
    fn k(slot: u64, tag: u8) SlotHashKey {
        return .{ .slot = slot, .hash = .{ .data = [_]u8{tag} ** 32 } };
    }
    fn build(fc: *HeaviestSubtreeForkChoice) !AheadTree {
        const root = k(100, 0x10);
        try fc.seedRoot(root);
        const dead = k(300, 0xDE);
        const canon_mid = k(250, 0xC1);
        const canon_tip = k(260, 0xC2);
        try fc.addNewLeafSlot(dead, root);
        try fc.addNewLeafSlot(canon_mid, root);
        try fc.addNewLeafSlot(canon_tip, canon_mid);
        return .{ .root = root, .dead = dead, .canon_mid = canon_mid, .canon_tip = canon_tip };
    }
};

test "KAT landed-filter fix: dead fork numerically AHEAD of canonical — lower-slot landed vote NOW counts" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try AheadTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    // Our last vote is 300 (the dead fork). This voter's landed vote is 260 —
    // numerically LOWER than our last vote — but on the genuinely different,
    // LIVE canonical fork. Pre-fix (`cand_slot <= last_voted_slot` filter):
    // 260 <= 300 → silently excluded forever, no matter how much real stake
    // sits here — this is the re-wedge scenario a "25k slots elapsed" argument
    // does NOT cover. Post-fix: 260 > root(100) passes the new filter, and
    // switchProofVoteCounts's ancestry+GCA walk correctly proves 260 is on a
    // different fork from 300 whose GCA (100) is an ancestor of switch_slot.
    try fc.latest_votes.put(fc.allocator, pk1, t.canon_tip);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 500 }, // 50% > 38%
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const d = fc.checkSwitchThreshold(300, t.canon_tip.slot, 1000, stakes);
    try std.testing.expect(!d.same_fork);
    try std.testing.expect(d.would_switch); // THE fix: arms even though 260 < 300
    try std.testing.expectEqual(@as(u64, 500), d.locked_out_stake);
}

test "KAT landed-filter fix both-directions safety: a vote that's an ancestor of OUR OWN last vote still does NOT count" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const t = try AheadTree.build(&fc);
    const pk1 = core.Pubkey.fromBytes([_]u8{1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{2} ** 32);
    // pk1's landed vote is the ROOT itself (100) — an ancestor of BOTH forks,
    // not evidence of the canonical side. Excluded by the new root filter
    // (100 is not > root(100)).
    try fc.latest_votes.put(fc.allocator, pk1, t.root);
    // pk2's landed vote is 300 == our OWN last vote (dead fork) — on OUR
    // fork, not a different one. switchProofVoteCounts's ancestry check
    // (isAncestorBySlot(cand_slot, last_voted_slot)) must still exclude it:
    // 300 descends from (equals) 300, so it never counts toward escaping 300.
    try fc.latest_votes.put(fc.allocator, pk2, t.dead);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 500 },
        .{ .pubkey = pk2, .stake = 500 },
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const d = fc.checkSwitchThreshold(300, t.canon_tip.slot, 1000, stakes);
    try std.testing.expect(!d.would_switch); // neither vote is valid switch evidence
    try std.testing.expectEqual(@as(u64, 0), d.locked_out_stake);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TASK #3 — canonical vote-selection self-heal (advisor 2026-07-01, load-bearing).
// The freeze-race orphan is voted BY DESIGN at the freeze instant (canonical —
// Agave votes it too); orphan-safety is SELF-HEAL via the ARMED switch proof, NOT
// prevention. These KATs drive the REAL checkSwitchThreshold + addVotes so the
// armed cross-fork switch path actually FIRES (the earlier sketched KAT modeled
// only the safe case = false confidence — advisor). Tree (freeze-race, unique
// slots so *BySlot ancestry is unambiguous):
//   root(100) → s631 → { o636 [ORPHAN, our vote, skips 632-635] ,
//                        c637 → c638 → c640 [canonical, revealed later] }
// ═══════════════════════════════════════════════════════════════════════════════
fn hkey(slot: u64, tag: u8) SlotHashKey {
    return .{ .slot = slot, .hash = .{ .data = [_]u8{tag} ** 32 } };
}

test "TASK#3 self-heal: freeze-race orphan is SameFork at freeze, switch-proof authorizes OFF it once canonical >=38%" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const root = hkey(100, 0x10);
    const s631 = hkey(631, 0x63); // fork point = our last landed vote
    const o636 = hkey(636, 0x60); // ORPHAN tip (our freeze-race vote; skips 632-635)
    const c637 = hkey(637, 0xC7);
    const c638 = hkey(638, 0xC8);
    const c640 = hkey(640, 0xCA); // canonical tip (revealed after cluster votes)
    try fc.seedRoot(root);
    try fc.addNewLeafSlot(s631, root);
    try fc.addNewLeafSlot(o636, s631);
    try fc.addNewLeafSlot(c637, s631);
    try fc.addNewLeafSlot(c638, c637);
    try fc.addNewLeafSlot(c640, c638);

    // ── Phase 1 (freeze instant): last landed vote = fork point 631; we are about
    // to vote the orphan tip 636 (the only leaf). 636 descends from 631 → SameFork
    // → B1 votes it. This is SAFE / canonical (Agave votes it too) — assert it so
    // sections A and E of the design can't silently contradict.
    const p1 = fc.checkSwitchThreshold(631, 636, 1000, PerPubkeyStakeLookup{ .entries = &[_]PubkeyStakeEntry{} });
    try std.testing.expect(p1.same_fork);
    try std.testing.expect(p1.would_switch);

    // ── Phase 2 (cluster reveals canonical): our last vote is now the orphan 636.
    // >=38% of cluster stake lands on the canonical fork (votes at 640).
    const pk1 = core.Pubkey.fromBytes([_]u8{0xA1} ** 32);
    const pk2 = core.Pubkey.fromBytes([_]u8{0xA2} ** 32);
    const entries = [_]PubkeyStakeEntry{
        .{ .pubkey = pk1, .stake = 200 }, // 20%
        .{ .pubkey = pk2, .stake = 190 }, // +19% = 39% > 38%
    };
    const stakes = PerPubkeyStakeLookup{ .entries = &entries };
    const votes = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = pk1, .slot_hash = c640 },
        .{ .pubkey = pk2, .slot_hash = c640 },
    };
    const best = try fc.addVotes(&votes, stakes);
    // bestOverallSlot flips to the canonical tip (orphan has ~0 subtree stake).
    try std.testing.expectEqual(@as(u64, 640), best.slot);
    try std.testing.expectEqual(@as(u64, 640), fc.bestOverallSlot().slot);

    // The armed switch decision: from orphan 636 to canonical 640 is CROSS-FORK
    // (640 does not descend from 636) and >=38% is locked out → would_switch=true.
    // THIS is what an armed VEX_SWITCH_PROOF authorizes → node switches OFF the
    // orphan → self-heal. With the switch shadow/off this cross-fork vote is
    // refused forever = the observed permanent wedge.
    const p2 = fc.checkSwitchThreshold(636, 640, 1000, stakes);
    try std.testing.expect(!p2.same_fork);
    try std.testing.expect(p2.would_switch);
    try std.testing.expect(p2.locked_out_stake > 380); // > 38% of 1000
}

test "TASK#3 heaviestSlotOnSameVotedFork: candidate->best_slot, invalid->deepest_slot, absent->null (Agave rs:1138)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const root = hkey(100, 0x10);
    const last = hkey(200, 0x20); // our last vote
    const shallow = hkey(210, 0x21); // valid leaf on our fork
    const deep1 = hkey(220, 0x22); // will be marked invalid
    const deep2 = hkey(230, 0x23); // deepest descendant (under the invalid deep1)
    try fc.seedRoot(root);
    try fc.addNewLeafSlot(last, root);
    try fc.addNewLeafSlot(shallow, last);
    try fc.addNewLeafSlot(deep1, last);
    try fc.addNewLeafSlot(deep2, deep1);
    // Mark the deep branch invalid so best_slot(last) EXCLUDES it (→ shallow 210)
    // while deepest_slot(last) still returns it (→ 230): best_slot != deepest_slot,
    // making the branch discrimination non-vacuous.
    fc.markForkInvalidCandidate(deep1);
    try std.testing.expectEqual(@as(u64, 210), fc.bestSlotOf(last).?.slot);
    try std.testing.expectEqual(@as(u64, 230), fc.deepestSlotOf(last).?.slot);

    // last itself still a candidate → best_slot branch (210).
    try std.testing.expect(fc.isCandidate(last).?);
    try std.testing.expectEqual(@as(u64, 210), fc.heaviestSlotOnSameVotedFork(last).?.slot);

    // Mark our last-voted fork invalid (duplicate) → deepest_slot branch (230),
    // per Agave Scenario 1/2 (keep building on the invalid fork).
    fc.markForkInvalidCandidate(last);
    try std.testing.expect(!fc.isCandidate(last).?);
    try std.testing.expectEqual(@as(u64, 230), fc.heaviestSlotOnSameVotedFork(last).?.slot);

    // Absent key → null (Agave's stray-vote None; we soft-fail, no panic).
    try std.testing.expect(fc.heaviestSlotOnSameVotedFork(hkey(999, 0xFF)) == null);
}

// ─────────────────────────────────────────────────────────────────────────
// LIVE EVENT 422600922 (2026-07-17) — "own-fork tip" fallback fed an
// unvalidated cross-fork SIBLING into the switch-proof block.
//
// Sequence (vex-fd-dev_testnet.log lines 43970-44044): last_vote=422600919
// was ALREADY CANONICAL (fork-choice's own heaviest pick, `best`, was still
// 919 — nothing new had been voted heavier yet). A sibling 422600922 (SAME
// PARENT 422600918, NOT a descendant of 919) froze moments later via a
// normal freeze race. replay_stage.zig's VOTE-COVERAGE ".tip" fallback
// (submitVote, ~line 6311) — designed to avoid silently withholding when a
// propagation-confirmed retarget lands exactly on last_voted_slot — blindly
// substituted the raw just-frozen bank_in (922) as the vote candidate
// WITHOUT checking it was actually a descendant of last_voted_slot. That
// unvalidated slot then got fed into the switch-proof block as `switch_slot`
// — a category error: Agave only ever evaluates check_switch_threshold
// against fork-choice's own heaviest_bank.slot(), never an arbitrary
// just-replayed sibling (core/src/consensus/fork_choice.rs:434-445; see
// AGAVE-SWITCHPROOF-CANONICAL-SPEC-2026-07-17.md §1.4). The switch-proof
// stake math found 38.18% > 38% and authorized a vote onto 922, which then
// got orphaned.
//
// The fix (replay_stage.zig .tip case) requires
// `fc.isAncestorBySlot(bank_in.slot, last_voted_slot)` before accepting the
// tip fallback — i.e. bank_in must genuinely be "our own fork's tip" (a
// descendant of, or equal to, last_voted_slot), not merely "whatever froze
// most recently". These two tests pin that exact predicate against the
// exact incident topology: the sibling case (must reject) and the
// legitimate same-fork-extension case the fallback exists for (must accept).

test "LIVE EVENT 422600922 fix: sibling of last_voted_slot (same parent, freeze race) is NOT an own-fork tip" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const root = hkey(422_600_800, 0x10);
    const parent918 = hkey(422_600_918, 0x18);
    const voted919 = hkey(422_600_919, 0x19); // our last vote — ALREADY canonical
    const sibling922 = hkey(422_600_922, 0x22); // freeze-race sibling, SAME parent 918

    try fc.seedRoot(root);
    try fc.addNewLeafSlot(parent918, root);
    try fc.addNewLeafSlot(voted919, parent918);
    try fc.addNewLeafSlot(sibling922, parent918);

    // This is EXACTLY the predicate replay_stage.zig's fixed .tip branch
    // evaluates: `fc.isAncestorBySlot(bank_in.slot, last_voted)`. 922 is a
    // sibling of 919 (both children of 918) — 919 is NOT an ancestor of 922.
    try std.testing.expect(!fc.isAncestorBySlot(sibling922.slot, voted919.slot));

    // Confirm the OTHER direction the incident depended on: fork-choice's
    // own heaviest pick genuinely preferred 919 over the brand-new,
    // zero-weight 922 (i.e. there was no legitimate reason to even consider
    // switching at this tick — bestOverallSlot never nominated 922).
    const pk = core.Pubkey.fromBytes([_]u8{0xB1} ** 32);
    const stakes = PerPubkeyStakeLookup{ .entries = &[_]PubkeyStakeEntry{.{ .pubkey = pk, .stake = 100 }} };
    const votes = [_]HeaviestSubtreeForkChoice.PubkeyVote{.{ .pubkey = pk, .slot_hash = voted919 }};
    const best = try fc.addVotes(&votes, stakes);
    try std.testing.expectEqual(voted919.slot, best.slot);
    try std.testing.expectEqual(voted919.slot, fc.bestOverallSlot().slot);
}

test "LIVE EVENT 422600922 fix, contrast: a genuine descendant IS an own-fork tip (the fallback's actual intended case)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const root = hkey(422_600_800, 0x10);
    const parent918 = hkey(422_600_918, 0x18);
    const voted919 = hkey(422_600_919, 0x19); // our last vote
    const tip920 = hkey(422_600_920, 0x20); // genuine extension of OUR OWN fork

    try fc.seedRoot(root);
    try fc.addNewLeafSlot(parent918, root);
    try fc.addNewLeafSlot(voted919, parent918);
    try fc.addNewLeafSlot(tip920, voted919);

    // 920 descends from 919 → the fallback's own-fork-tip guard must ACCEPT
    // it (this is the ~29%-coverage case the mechanism was built for: a
    // propagated-ancestor retarget conservatively lands on 919 while the
    // raw, already-frozen tip 920 is a perfectly safe same-fork extension).
    try std.testing.expect(fc.isAncestorBySlot(tip920.slot, voted919.slot));
}

// ─────────────────────────────────────────────────────────────────────────
// switchThresholdVoterBreakdown — per-voter instrumentation KATs
// (2026-07-17, wedge-422521275/422600922 follow-up). Proves the diagnostic
// walk stays byte-for-byte IN SYNC with checkSwitchThresholdGossip's
// aggregate (same admission predicates, same order) and correctly
// attributes/excludes voters on the 422600918/919/922 topology.
// ─────────────────────────────────────────────────────────────────────────

test "switchThresholdVoterBreakdown: stays in sync with checkSwitchThresholdGossip's aggregate (landed + gossip, mixed exclusions)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const root = hkey(422_600_800, 0x10);
    const parent918 = hkey(422_600_918, 0x18);
    const voted919 = hkey(422_600_919, 0x19); // our last vote
    const sibling922 = hkey(422_600_922, 0x22); // switch candidate (the incident's target)

    try fc.seedRoot(root);
    try fc.addNewLeafSlot(parent918, root);
    try fc.addNewLeafSlot(voted919, parent918);
    try fc.addNewLeafSlot(sibling922, parent918);

    const pk_own_fork = core.Pubkey.fromBytes([_]u8{0xA1} ** 32); // latest vote = 919 (our fork) -> excluded
    const pk_switch1 = core.Pubkey.fromBytes([_]u8{0xA2} ** 32); // latest vote = 922 (the switch fork) -> counted
    const pk_switch2 = core.Pubkey.fromBytes([_]u8{0xA3} ** 32); // gossip vote = 922, no landed entry -> counted via gossip
    const pk_dup = core.Pubkey.fromBytes([_]u8{0xA4} ** 32); // landed AND gossip both on 922 -> gossip must be deduped

    const stakes = PerPubkeyStakeLookup{ .entries = &[_]PubkeyStakeEntry{
        .{ .pubkey = pk_own_fork, .stake = 100 },
        .{ .pubkey = pk_switch1, .stake = 150 },
        .{ .pubkey = pk_switch2, .stake = 130 },
        .{ .pubkey = pk_dup, .stake = 120 },
    } };
    const landed_votes = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = pk_own_fork, .slot_hash = voted919 },
        .{ .pubkey = pk_switch1, .slot_hash = sibling922 },
        .{ .pubkey = pk_dup, .slot_hash = sibling922 },
    };
    _ = try fc.addVotes(&landed_votes, stakes);

    const gossip_votes = [_]HeaviestSubtreeForkChoice.PubkeyVote{
        .{ .pubkey = pk_switch2, .slot_hash = sibling922 }, // newer than last_voted, not yet landed -> counts
        .{ .pubkey = pk_dup, .slot_hash = sibling922 }, // ALREADY counted via landed loop -> must dedup out
    };

    const dec = fc.checkSwitchThresholdGossip(voted919.slot, sibling922.slot, 1000, stakes, &gossip_votes);
    var bd = HeaviestSubtreeForkChoice.SwitchThresholdBreakdown{};
    fc.switchThresholdVoterBreakdown(voted919.slot, sibling922.slot, stakes, &gossip_votes, &bd);

    // Landed loop: pk_own_fork's vote (919) is on OUR OWN fork -> excluded.
    // pk_switch1 (150) AND pk_dup (120) both voted 922 (the switch fork,
    // GCA=918 is an ancestor of switch_slot=922) -> BOTH count in the landed
    // loop (dedup against gossip happens in the GOSSIP loop, not here).
    try std.testing.expectEqual(@as(u32, 3), bd.landed_seen); // pk_own_fork, pk_switch1, pk_dup
    try std.testing.expectEqual(@as(u32, 1), bd.landed_excluded_no_gca); // pk_own_fork
    try std.testing.expectEqual(@as(u32, 2), bd.landed_counted); // pk_switch1, pk_dup
    try std.testing.expectEqual(@as(u64, 270), bd.landed_stake); // 150 + 120

    // Gossip loop: pk_switch2 has NO landed entry -> counts fresh. pk_dup DOES
    // have a landed entry that already counted (922, not own-fork) -> the
    // cross-source dedup (predicate b) excludes it from gossip, even though
    // its raw gossip vote is otherwise well-formed.
    try std.testing.expectEqual(@as(u32, 2), bd.gossip_seen); // pk_switch2, pk_dup
    try std.testing.expectEqual(@as(u32, 1), bd.gossip_excluded_dup); // pk_dup
    try std.testing.expectEqual(@as(u32, 1), bd.gossip_counted); // pk_switch2
    try std.testing.expectEqual(@as(u64, 130), bd.gossip_stake); // pk_switch2 only

    // The production aggregate's locked_out_stake (at whichever point it
    // early-returns past the 38% threshold) equals the diagnostic walk's full
    // landed+gossip sum here BECAUSE the only entry the full walk sees beyond
    // the early-return point (pk_dup, in gossip) contributes ZERO additional
    // stake (it's deduped) — i.e. this is not a general identity, but it DOES
    // hold whenever (as here) nothing past the crossing point would have
    // counted, which is exactly the property worth pinning: the diagnostic
    // walk cannot UNDER-attribute stake the production path actually counted.
    try std.testing.expectEqual(dec.locked_out_stake, bd.landed_stake + bd.gossip_stake);
    try std.testing.expectEqual(@as(u64, 400), dec.locked_out_stake);

    // Top-N contains exactly the two counted contributors, sorted descending.
    try std.testing.expectEqual(@as(usize, 3), bd.top_len); // pk_switch1 (landed) + pk_dup (landed) + pk_switch2 (gossip)
    try std.testing.expectEqual(@as(u64, 150), bd.top[0].stake);
}

test "switchThresholdVoterBreakdown: SameFork short-circuit reports zero attribution (nothing to attribute)" {
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const root = hkey(100, 0x10);
    const last = hkey(200, 0x20);
    const child = hkey(210, 0x21); // descends from last -> SameFork
    try fc.seedRoot(root);
    try fc.addNewLeafSlot(last, root);
    try fc.addNewLeafSlot(child, last);

    const stakes = PerPubkeyStakeLookup{ .entries = &[_]PubkeyStakeEntry{} };
    var bd = HeaviestSubtreeForkChoice.SwitchThresholdBreakdown{};
    fc.switchThresholdVoterBreakdown(last.slot, child.slot, stakes, &[_]HeaviestSubtreeForkChoice.PubkeyVote{}, &bd);
    try std.testing.expectEqual(@as(u32, 0), bd.landed_seen);
    try std.testing.expectEqual(@as(u32, 0), bd.gossip_seen);
    try std.testing.expectEqual(@as(usize, 0), bd.top_len);
}

test "KAT @423281048 — cross-fork non-advancing target must fail the fallback ancestry gate" {
    // Live wedge 2026-07-20: node voted skip-fork 048→054→055→056 (canonical
    // 049–053 arrived late via repair). Fork-choice retargeted to canonical 051,
    // non-advancing vs last_vote 056 → the .tip fallback voted own tips 057–063,
    // deepening lockout ~2^10 slots → delinquency. The replay_stage gate pair must
    // decide: tip extends our tower (old gate TRUE) but target is NOT an ancestor
    // of the tip (new gate FALSE) → withhold. Slots use the incident's low bytes.
    var fc = HeaviestSubtreeForkChoice.init(std.testing.allocator);
    defer fc.deinit();
    const mk = struct {
        fn h(b: u8) core.Hash {
            var x = core.Hash.ZERO;
            x.data[0] = b;
            return x;
        }
    };
    const r: SlotHashKey = .{ .slot = 1048, .hash = mk.h(48) }; // 423281048 = last landed vote
    try fc.seedRoot(r);
    // Canonical fork: 048 → 049 → 050 → 051 (late-arriving; fork-choice's pick).
    const k49: SlotHashKey = .{ .slot = 1049, .hash = mk.h(49) };
    const k50: SlotHashKey = .{ .slot = 1050, .hash = mk.h(50) };
    const k51: SlotHashKey = .{ .slot = 1051, .hash = mk.h(51) };
    try fc.addNewLeafSlot(k49, r);
    try fc.addNewLeafSlot(k50, k49);
    try fc.addNewLeafSlot(k51, k50);
    // Own (skip) fork: 048 → 054 → 055 → 056 → 057 (last_vote=056, frozen tip=057).
    const k54: SlotHashKey = .{ .slot = 1054, .hash = mk.h(54) };
    const k55: SlotHashKey = .{ .slot = 1055, .hash = mk.h(55) };
    const k56: SlotHashKey = .{ .slot = 1056, .hash = mk.h(56) };
    const k57: SlotHashKey = .{ .slot = 1057, .hash = mk.h(57) };
    try fc.addNewLeafSlot(k54, r);
    try fc.addNewLeafSlot(k55, k54);
    try fc.addNewLeafSlot(k56, k55);
    try fc.addNewLeafSlot(k57, k56);

    // Old gate (ed7c750): tip 057 DOES extend last_vote 056 — passes, as live.
    try std.testing.expect(fc.isAncestorBySlot(1057, 1056));
    // New gate: canonical target 051 is NOT an ancestor of tip 057 → REFUSE the
    // fallback (this exact predicate returned true-equivalent live and dug the hole).
    try std.testing.expect(!fc.isAncestorBySlot(1057, 1051));
    // Preserved liveness case (vote-coverage fix, 2026-07-10): a same-fork target
    // that merely trails the advancing own-fork tip still passes both gates.
    try std.testing.expect(fc.isAncestorBySlot(1057, 1054));
    // Root/self edges stay ancestors (sanity for the conservative-direction claim).
    try std.testing.expect(fc.isAncestorBySlot(1057, 1048));
    try std.testing.expect(fc.isAncestorBySlot(1057, 1057));
}
