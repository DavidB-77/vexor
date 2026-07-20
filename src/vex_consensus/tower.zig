//! Vexor Tower BFT Implementation
//!
//! Tower BFT is Solana's optimized PBFT-like consensus with:
//! - Exponential lockouts for vote stability
//! - Optimistic confirmation
//! - Fork choice based on stake-weighted votes

const std = @import("std");
const core = @import("core");
const vote_mod = @import("vote.zig");

const Vote = vote_mod.Vote;
const Lockout = vote_mod.Lockout;

/// Maximum vote history depth
pub const MAX_LOCKOUT_HISTORY: usize = 31;

/// Tower BFT state machine
pub const TowerBft = struct {
    allocator: std.mem.Allocator,
    identity: core.Pubkey,
    identity_keypair: ?core.Keypair, // For signing votes
    vote_state: VoteState,
    last_vote: ?Vote,
    last_vote_slot: core.Slot,
    fork_choice: ?*@import("fork_choice.zig").ForkChoice,

    const Self = @This();

    pub const VoteState = struct {
        buf: [MAX_LOCKOUT_HISTORY]Lockout = undefined,
        len: usize = 0,
        root_slot: ?core.Slot = null,
        epoch: core.Epoch = 0,
        credits: u64 = 0,

        pub fn init() VoteState {
            return .{};
        }

        /// Get a const slice of the current lockout stack.
        pub fn constSlice(self: *const VoteState) []const Lockout {
            return self.buf[0..self.len];
        }

        /// Get a mutable slice of the current lockout stack.
        pub fn slice(self: *VoteState) []Lockout {
            return self.buf[0..self.len];
        }

        /// Get the last voted slot.
        pub fn lastVotedSlot(self: *const VoteState) ?core.Slot {
            if (self.len == 0) return null;
            return self.buf[self.len - 1].slot;
        }

        /// Check if we can vote for a slot.
        ///
        /// ⚠️ CARRIER #7 (2026-06-10): this check is SLOT-NUMBER-ONLY — it is
        /// fork-BLIND and is NOT a sufficient vote-admission check on its own.
        /// It permitted the cross-fork lockout violation @414406146→147 that
        /// rooted an abandoned fork block at tower depth 31 and poisoned the
        /// rooted store (epoch_credits −34 @414406188). Vote admission MUST
        /// also pass `isLockedOut` (the Agave/Sig fork-ancestry invariant);
        /// `shouldVote` enforces both.
        pub fn canVote(self: *const VoteState, slot: core.Slot) bool {
            const last = self.lastVotedSlot() orelse return true;
            if (slot <= last) return false;

            for (self.buf[0..self.len]) |lockout| {
                if (!lockout.isExpired(slot)) {
                    if (slot <= lockout.slot) return false;
                }
            }
            return true;
        }

        /// VOTE-COVERAGE target resolution (2026-07-10, vote-credit-gap-coverage mechanism).
        /// The caller (submitVote) has a PROP-RETARGET-selected `target` (the highest
        /// ≥1/3-propagated ancestor of the frozen tip) and the frozen `tip` itself. When the
        /// retarget is NON-ADVANCING (`canVote(target)` is false because target ≤ last_vote —
        /// propagation for the intervening slot hasn't crossed 1/3 yet), the historical code
        /// SILENTLY withheld — casting ZERO votes on ~29% of slots. This decides the final
        /// slot-gate target:
        ///   • canVote(target)                                   → .target  (advancing; normal)
        ///   • !canVote(target) ∧ target≠tip ∧ tip_frozen ∧ canVote(tip) → .tip (fallback = own-fork tip)
        ///   • otherwise                                         → .withhold (unchanged refresh path)
        /// SLOT-gate ONLY: the caller still applies isLockedOut / shouldVote to the returned
        /// slot. Slashing-safe — returns only `target` or `tip` (both frozen own-fork banks the
        /// caller supplied), never a synthesized slot; canVote gates whichever is returned.
        pub const VoteTargetChoice = enum { target, tip, withhold };
        pub fn resolveVoteTarget(
            self: *const VoteState,
            target: core.Slot,
            tip: core.Slot,
            tip_frozen: bool,
        ) VoteTargetChoice {
            if (self.canVote(target)) return .target;
            if (target != tip and tip_frozen and self.canVote(tip)) return .tip;
            return .withhold;
        }

        /// CARRIER #7 FIX (2026-06-10) — fork-aware lockout check.
        /// @prov:tower.is-locked-out semantics:
        ///
        ///   1. isRecent: a candidate at or below our last vote (or, with an
        ///      empty stack, at or below our root) is always locked out.
        ///   2. Simulate adding a vote for `slot` on a COPY of the tower
        ///      (pops expired lockouts, roots the oldest if the stack fills).
        ///   3. If ANY remaining voted slot is not the candidate itself and
        ///      not in the candidate bank's ancestry → LOCKED OUT (the
        ///      candidate extends a different fork while a prior vote's
        ///      lockout is still active — the slashable-class violation).
        ///   4. Root sanity: the (possibly just-popped) tower root must be on
        ///      the candidate's ancestry. Agave asserts here ("should never
        ///      happen because bank forks purges all non-descendants of the
        ///      root"); Sig returns error.InvalidRootSlot. Production
        ///      rendering: treat as locked out + loud err log — never panic
        ///      the replay loop on a consensus-state inconsistency.
        ///
        /// `ancestors` is any type exposing `containsSlot(core.Slot) bool`
        /// describing the CANDIDATE bank's ancestor set (see `SliceAncestors`
        /// for the production view: unrooted parent chain + rooted prefix).
        ///
        /// This is the invariant whose absence let an abandoned fork slot
        /// march to tower depth 31 and become the AccountsDb root: with it,
        /// a switched-away vote must EXPIRE (and be popped) before the next
        /// cross-fork vote, so a dead fork slot can never root.
        pub fn isLockedOut(self: *const VoteState, slot: core.Slot, ancestors: anytype) bool {
            // @prov:tower.is-locked-out — isRecent check
            if (self.lastVotedSlot()) |last| {
                if (slot <= last) return true;
            } else if (self.root_slot) |root| {
                if (slot <= root) return true;
            }

            // Simulate the vote on a copy (VoteState is a flat value type —
            // fixed inline buffer, no heap pointers — so this copy is safe).
            // @prov:tower.record-vote — pop expired, root the oldest if full,
            // double confirmations, push (slot, conf=1).
            var copy = self.*;
            copy.recordVote(slot);

            for (copy.buf[0..copy.len]) |lockout| {
                if (lockout.slot != slot and !ancestors.containsSlot(lockout.slot)) {
                    // Voting `slot` would violate the still-active lockout of
                    // a prior vote on a different fork.
                    return true;
                }
            }

            if (copy.root_slot) |root| {
                if (slot != root and !ancestors.containsSlot(root)) {
                    std.log.err(
                        "[TOWER-LOCKOUT] InvalidRootSlot shape: tower root {d} not an ancestor of candidate {d} — vote refused (Agave asserts here; we refuse loudly)",
                        .{ root, slot },
                    );
                    return true;
                }
            }

            return false;
        }

        /// Record a vote — expires old lockouts, doubles consecutive confirmations, pushes new entry.
        /// @prov:tower.record-vote
        /// 1. Pop expired lockouts from tail
        /// 2. If stack full, pop head as new root
        /// 3. Double consecutive confirmations going upward from tail
        /// 4. Push new vote with conf=1
        pub fn recordVote(self: *VoteState, slot: core.Slot) void {
            // Step 1: Pop expired lockouts from the top (tail) of the stack
            while (self.len > 0) {
                if (self.buf[self.len - 1].isExpired(slot)) {
                    self.len -= 1;
                } else {
                    break;
                }
            }

            // Step 2: If stack is full after expiry, pop head as root
            if (self.len >= MAX_LOCKOUT_HISTORY) {
                self.root_slot = self.buf[0].slot;
                std.mem.copyForwards(Lockout, self.buf[0 .. self.len - 1], self.buf[1..self.len]);
                self.len -= 1;
            }

            // Step 3: Double consecutive confirmations going upward from tail.
            // Only increment confirmation if it forms an unbroken chain:
            // conf[tail] must equal 1, conf[tail-1] must equal 2, etc.
            // This is the exponential lockout doubling rule.
            if (self.len > 0) {
                var expected_conf: u32 = 1;
                var i: usize = self.len;
                while (i > 0) : (expected_conf += 1) {
                    i -= 1;
                    if (self.buf[i].confirmation_count != expected_conf) break;
                    self.buf[i].confirmation_count = expected_conf + 1;
                }
            }

            // Step 4: Push new vote with confirmation_count = 1
            self.buf[self.len] = .{ .slot = slot, .confirmation_count = 1 };
            self.len += 1;
        }

        /// VOTE-THRESHOLD wiring (incident 423083743 companion fix, 2026-07-19):
        /// the slot whose cluster-voted stake the depth-8 threshold check must
        /// examine, for a candidate vote on `candidate`. Mirrors Agave
        /// `check_vote_stake_threshold` (consensus.rs:1332-1369): simulate the
        /// candidate vote on a COPY of the tower (pop expired / pop root / push —
        /// the same simulation isLockedOut already does), then take
        /// `nth_recent_lockout(VOTE_THRESHOLD_DEPTH)` = the lockout at index
        /// `len - 1 - THRESHOLD_DEPTH` of the SIMULATED stack. Returns null when
        /// the simulated tower is not deep enough (Agave: threshold trivially
        /// PASSES — "a shallow first vote is permitted"); callers translate null
        /// into the (0,0) stake pair that skips the check in `shouldVote`.
        /// Pure + allocation-free (VoteState is a flat value type).
        pub fn thresholdDepthSlot(self: *const VoteState, candidate: core.Slot) ?core.Slot {
            var copy = self.*;
            copy.recordVote(candidate);
            if (copy.len <= THRESHOLD_DEPTH) return null;
            return copy.buf[copy.len - 1 - THRESHOLD_DEPTH].slot;
        }
    };

    /// VOTE-THRESHOLD gate mode (VEX_VOTE_THRESHOLD, parsed at the replay_stage
    /// call site): .off → check fully dormant (hot path computes nothing);
    /// .shadow (DEFAULT) → real stakes are computed and the would-be verdict is
    /// logged, but the values actually PASSED to shouldVote stay (0,0) — byte-
    /// identical vote decisions to the pre-fix binary; .armed → the real stakes
    /// are passed and the depth-8 threshold check enforces.
    pub const ThresholdMode = enum { off, shadow, armed };

    pub const ThresholdStakes = struct { voted: u64, total: u64 };

    /// The SINGLE point deciding which stake pair reaches shouldVote. Shadow
    /// mode can never alter the vote decision BY CONSTRUCTION: only .armed ever
    /// forwards non-zero stakes, and (0,0) skips the threshold check entirely
    /// (shouldVote's `total_stake > 0` guard) — KAT'd in
    /// src/kat_vote_threshold_shadow.zig.
    pub fn thresholdStakesForMode(mode: ThresholdMode, voted: u64, total: u64) ThresholdStakes {
        return switch (mode) {
            .armed => .{ .voted = voted, .total = total },
            .off, .shadow => .{ .voted = 0, .total = 0 },
        };
    }

    /// CARRIER #7 (2026-06-10): production ancestry view for `isLockedOut`.
    /// The candidate bank's ancestor set =
    ///   - the UNROOTED parent chain (from AccountsDb.unrootedAncestorChain —
    ///     the durable slot_parents walk, newest-first, down to rooted_slot), plus
    ///   - the rooted prefix: every slot ≤ rooted_slot IS an ancestor, because
    ///     the rooted chain is linear (Agave: "bank forks purges all
    ///     non-descendants of the root every time root is set"; same property
    ///     our root-advance promote/purge maintains).
    /// Mirrors Sig's Ancestors semantics for tower checks.
    pub const SliceAncestors = struct {
        rooted_slot: core.Slot,
        chain: []const core.Slot,

        pub fn containsSlot(self: SliceAncestors, slot: core.Slot) bool {
            if (slot <= self.rooted_slot) return true;
            for (self.chain) |c| {
                if (c == slot) return true;
            }
            return false;
        }
    };

    /// Threshold check: at least 2/3 of stake must have voted at or beyond
    /// our depth-8 slot. Prevents voting too far ahead of the cluster.
    pub const THRESHOLD_DEPTH: usize = 8;
    pub const THRESHOLD_PCT: u64 = 67;
    // ⚠ FOOTGUN (removed integer SWITCH_PCT=38): the switch threshold is a STRICT
    // f64 ratio `locked_out_stake / total_stake > 0.38` (Agave consensus.rs:1263,
    // Firedancer fd_tower.c:563), NOT an integer percent. Do NOT reintroduce
    // `(stake*100)/total > 38` — truncation flips the 38% boundary and can
    // manufacture a false SwitchProof (switch-when-you-shouldn't = slashing class
    // if the lockout gate were ever weakened). The canonical proof lives in
    // fork_choice.zig `checkSwitchThreshold` (SWITCH_FORK_THRESHOLD: f64 = 0.38),
    // consulted (gated) at the replay_stage vote site. See agave-behavior-extractor
    // 2026-06-26 overcount risk #7.

    /// Full vote decision: combines lockout + threshold + switch checks.
    /// Returns the slot to vote for, or null if we should not vote.
    ///
    /// CARRIER #7 (2026-06-10): `ancestors` (anytype with
    /// `containsSlot(core.Slot) bool`, e.g. `SliceAncestors`) describes the
    /// CANDIDATE bank's ancestry; the fork-aware `isLockedOut` check is now
    /// the first admission gate. The pre-existing `is_same_fork` flag is a
    /// GHOST best-slot heuristic, NOT a lockout check (it compares against
    /// fork-choice best, not against our last vote's fork) — it did not and
    /// cannot enforce the lockout invariant.
    pub fn shouldVote(
        self: *Self,
        slot: core.Slot,
        is_same_fork: bool,
        ancestors: anytype,
        cluster_voted_stake: u64,
        total_stake: u64,
    ) bool {
        // Basic lockout check
        if (!self.vote_state.canVote(slot)) return false;

        // CARRIER #7: fork-aware lockout (Agave is_locked_out / Sig isLockedOut).
        // A prior vote on a slot NOT in the candidate's ancestry locks us out
        // until that vote's lockout expires (and is popped by the simulation).
        if (self.vote_state.isLockedOut(slot, ancestors)) return false;

        // Threshold check: cluster must have enough stake at our depth-8 slot.
        // u128 widen (DIFF987 gate catch, 2026-07-20): real lamport-scale stakes
        // overflow u64 at ×100 — testnet voted stake ≈2-3e17 lamports, ×100 ≈
        // 2-3e19 > u64 max 1.84e19. Panicked the offline golden replay at the
        // first deep-tower vote (shadow mode calls this with real stakes for
        // its would-be verdict, so the overflow reaches production even
        // before arming). Toy-stake KATs missed it; the mainnet-magnitude
        // regression KAT in kat_vote_threshold_shadow.zig now pins it.
        if (total_stake > 0 and self.vote_state.len >= THRESHOLD_DEPTH) {
            const pct = (@as(u128, cluster_voted_stake) * 100) / total_stake;
            if (pct < THRESHOLD_PCT) return false;
        }

        // Switch check: a cross-fork vote requires a 38% switch proof.
        // ⚠ This conservative stub (refuse ALL cross-fork votes) is the DORMANT
        // default. The canonical switch proof now lives in fork_choice.zig
        // `checkSwitchThreshold` and is consulted at the replay_stage vote site
        // ONLY when gated (VEX_SWITCH_PROOF=shadow|armed). The proof is an
        // ADDITIONAL gate layered on the isLockedOut check above — it NEVER
        // overrides lockout (Agave fork_choice.rs:382 pure AND). Do NOT "fix"
        // this to `return true` for cross-fork: that would admit a no-proof
        // cross-fork vote (Agave SameFork ≠ GHOST is_same_fork; see #87 §3a).
        if (!is_same_fork) {
            return false;
        }

        return true;
    }

    pub fn init(allocator: std.mem.Allocator, identity: core.Pubkey) !TowerBft {
        return .{
            .allocator = allocator,
            .identity = identity,
            .identity_keypair = null,
            .vote_state = VoteState.init(),
            .last_vote = null,
            .last_vote_slot = 0,
            .fork_choice = null,
        };
    }

    /// Set keypair for vote signing
    pub fn setKeypair(self: *Self, keypair: core.Keypair) void {
        self.identity_keypair = keypair;
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Generate a vote for a slot
    /// Note: timestamp is computed once per vote; if called frequently,
    /// consider passing in a cached timestamp for better performance
    pub fn vote(self: *Self, slot: core.Slot, bank_hash: core.Hash) !Vote {
        return self.voteWithTimestamp(slot, bank_hash, @as(i64, @intCast(std.time.timestamp())));
    }

    /// Generate a vote for a slot with a provided timestamp (avoids syscall)
    ///
    /// ⚠️ CARRIER #7 (2026-06-10): NOT on the production vote path (replay_stage
    /// admits via canVote + isLockedOut + shouldVote, then calls recordVote
    /// directly and builds a TowerSync). This helper only has the fork-BLIND
    /// canVote check — callers with fork context MUST gate on
    /// `vote_state.isLockedOut(slot, ancestors)` first.
    pub fn voteWithTimestamp(self: *Self, slot: core.Slot, bank_hash: core.Hash, timestamp: i64) !Vote {
        if (!self.vote_state.canVote(slot)) {
            return error.LockedOut;
        }

        self.vote_state.recordVote(slot);
        self.last_vote_slot = slot;

        // Build message to sign: [slot (8 bytes)][hash (32 bytes)][timestamp (8 bytes)]
        var msg_buf: [48]u8 = undefined;
        std.mem.writeInt(u64, msg_buf[0..8], slot, .little);
        @memcpy(msg_buf[8..40], &bank_hash.data);
        std.mem.writeInt(i64, msg_buf[40..48], timestamp, .little);

        // Sign the vote
        const signature = if (self.identity_keypair) |kp|
            kp.sign(&msg_buf)
        else
            core.Signature{ .data = [_]u8{0} ** 64 }; // Unsigned if no keypair

        const new_vote = Vote{
            .slot = slot,
            .hash = bank_hash,
            .timestamp = timestamp,
            .signature = signature,
        };

        self.last_vote = new_vote;
        return new_vote;
    }

    /// Get current root slot
    pub fn rootSlot(self: *const Self) ?core.Slot {
        return self.vote_state.root_slot;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TOWER PERSISTENCE
    // ═══════════════════════════════════════════════════════════════════════════

    /// Save tower state to disk. Called after every vote.
    /// Format: [magic:4][version:4][last_vote_slot:8][root_slot:8][num_lockouts:4]
    ///         [lockout_slot:8 + lockout_conf:4] * num_lockouts
    pub fn saveToDisk(self: *const Self, path: []const u8) !void {
        // Serialize tower state into a fixed buffer
        // Format: [VXR1:4][version:4][last_vote:8][root:8][has_root:1][num_lockouts:4]
        //         [slot:8+conf:4]*N [credits:8][epoch:8]
        // Max size: 4+4+8+8+1+4 + 31*(8+4) + 8+8 = 417 bytes
        var buf: [512]u8 = undefined;
        var off: usize = 0;

        @memcpy(buf[off..][0..4], "VXR1");
        off += 4;
        std.mem.writeInt(u32, buf[off..][0..4], 1, .little);
        off += 4;
        std.mem.writeInt(u64, buf[off..][0..8], self.last_vote_slot, .little);
        off += 8;
        std.mem.writeInt(u64, buf[off..][0..8], self.vote_state.root_slot orelse 0, .little);
        off += 8;
        buf[off] = if (self.vote_state.root_slot != null) 1 else 0;
        off += 1;

        const num: u32 = @intCast(self.vote_state.len);
        std.mem.writeInt(u32, buf[off..][0..4], num, .little);
        off += 4;
        for (self.vote_state.constSlice()) |lockout| {
            std.mem.writeInt(u64, buf[off..][0..8], lockout.slot, .little);
            off += 8;
            std.mem.writeInt(u32, buf[off..][0..4], lockout.confirmation_count, .little);
            off += 4;
        }

        std.mem.writeInt(u64, buf[off..][0..8], self.vote_state.credits, .little);
        off += 8;
        std.mem.writeInt(u64, buf[off..][0..8], self.vote_state.epoch, .little);
        off += 8;

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(buf[0..off]);

        // Only log periodically (every 100 votes)
        const TowerSaveDbg = struct {
            var count: u64 = 0;
        };
        TowerSaveDbg.count += 1;
        if (TowerSaveDbg.count <= 3 or TowerSaveDbg.count % 100 == 0) std.log.debug("[Tower] Saved: last_vote={d} root={?d} lockouts={d} [#{d}]\n", .{
            self.last_vote_slot, self.vote_state.root_slot, num, TowerSaveDbg.count,
        });
    }

    /// Load tower state from disk. Called on startup.
    pub fn loadFromDisk(self: *Self, path: []const u8) !void {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                std.log.debug("[Tower] No saved state at {s}, starting fresh\n", .{path});
                return;
            }
            return err;
        };
        defer file.close();

        var buf: [512]u8 = undefined;
        const n = try file.readAll(&buf);
        if (n < 29) return; // minimum valid: 4+4+8+8+1+4 = 29

        if (!std.mem.eql(u8, buf[0..4], "VXR1")) {
            std.log.debug("[Tower] Invalid magic, starting fresh\n", .{});
            return;
        }
        const version = std.mem.readInt(u32, buf[4..8], .little);
        if (version != 1) {
            std.log.debug("[Tower] Unknown version {d}, starting fresh\n", .{version});
            return;
        }

        var off: usize = 8;
        self.last_vote_slot = std.mem.readInt(u64, buf[off..][0..8], .little);
        off += 8;
        const root_val = std.mem.readInt(u64, buf[off..][0..8], .little);
        off += 8;
        const has_root = buf[off];
        off += 1;
        self.vote_state.root_slot = if (has_root != 0) root_val else null;

        const num_lockouts = std.mem.readInt(u32, buf[off..][0..4], .little);
        off += 4;
        self.vote_state.len = 0;
        var i: u32 = 0;
        while (i < num_lockouts and i < MAX_LOCKOUT_HISTORY) : (i += 1) {
            if (off + 12 > n) break;
            self.vote_state.buf[self.vote_state.len] = .{
                .slot = std.mem.readInt(u64, buf[off..][0..8], .little),
                .confirmation_count = std.mem.readInt(u32, buf[off + 8 ..][0..4], .little),
            };
            self.vote_state.len += 1;
            off += 12;
        }

        if (off + 16 <= n) {
            self.vote_state.credits = std.mem.readInt(u64, buf[off..][0..8], .little);
            self.vote_state.epoch = std.mem.readInt(u64, buf[off + 8 ..][0..8], .little);
        }

        std.log.debug("[Tower] Loaded: last_vote={d} root={?d} lockouts={d}\n", .{
            self.last_vote_slot, self.vote_state.root_slot, self.vote_state.len,
        });
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "vote state init" {
    var state = TowerBft.VoteState.init();
    try std.testing.expect(state.lastVotedSlot() == null);
    try std.testing.expect(state.canVote(100));
}

test "vote lockout" {
    var state = TowerBft.VoteState.init();

    state.recordVote(100);
    try std.testing.expectEqual(@as(?core.Slot, 100), state.lastVotedSlot());

    // Can vote for higher slot
    try std.testing.expect(state.canVote(101));

    // Cannot vote for same or lower slot
    try std.testing.expect(!state.canVote(100));
    try std.testing.expect(!state.canVote(99));
}

test "tower bft" {
    const identity = core.Pubkey{ .data = [_]u8{1} ** 32 };
    var tower = try TowerBft.init(std.testing.allocator, identity);
    defer tower.deinit();

    const hash = core.Hash{ .data = [_]u8{2} ** 32 };
    const first_vote = try tower.vote(100, hash);
    try std.testing.expectEqual(@as(core.Slot, 100), first_vote.slot);

    // Should fail for same slot
    const result = tower.vote(100, hash);
    try std.testing.expectError(error.LockedOut, result);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CARRIER #7 KATs — fork-aware lockout (414406146 carrier shape)
// Run with: zig build test-tower
// ═══════════════════════════════════════════════════════════════════════════════

/// Test ancestry view: the CANONICAL chain excludes the fork slot(s) listed in
/// `forks`; everything else strictly below `candidate` is an ancestor. Models
/// the carrier topology where the candidate extends the canonical chain and the
/// fork block (e.g. 146, parent 142) is NOT on it.
const TestCanonAncestors = struct {
    candidate: core.Slot,
    forks: []const core.Slot,

    pub fn containsSlot(self: @This(), slot: core.Slot) bool {
        if (slot >= self.candidate) return false;
        for (self.forks) |f| {
            if (f == slot) return false;
        }
        return true;
    }
};

test "carrier #7: cross-fork vote locked out until fork vote expires (414406146 shape)" {
    // The live carrier, scaled down: votes 140, 141, 142 on the canonical
    // chain, then 146 on a FORK (parent 142; the cluster later skips it).
    // Candidate 147 extends the CANONICAL chain (…142→143→144→145→147), whose
    // ancestry excludes 146.
    var state = TowerBft.VoteState.init();
    state.recordVote(140);
    state.recordVote(141);
    state.recordVote(142);
    state.recordVote(146); // the fork vote

    const fork_slots = [_]core.Slot{146};

    // BUG SHAPE (regression-lock documentation): the OLD fork-blind canVote
    // admits 147 immediately — the exact lockout violation that voted 147 one
    // slot after fork-146 live and let 146 march to root at depth 31.
    try std.testing.expect(state.canVote(147));

    // NEW: fork-aware lockout REFUSES 147 and 148 (146's lockout, conf=1,
    // covers slots ≤ 148)...
    try std.testing.expect(state.isLockedOut(147, TestCanonAncestors{ .candidate = 147, .forks = &fork_slots }));
    try std.testing.expect(state.isLockedOut(148, TestCanonAncestors{ .candidate = 148, .forks = &fork_slots }));

    // ...but ALLOWS 149: the simulation pops the expired 146 (146+2=148 < 149).
    try std.testing.expect(!state.isLockedOut(149, TestCanonAncestors{ .candidate = 149, .forks = &fork_slots }));

    // Extending the FORK itself (147' with 146 in its ancestry) is NOT locked
    // out — lockout only forbids abandoning 146 while its lockout is active.
    const SameForkAnc = struct {
        pub fn containsSlot(_: @This(), slot: core.Slot) bool {
            return slot <= 146; // fork ancestry: …140,141,142,146
        }
    };
    try std.testing.expect(!state.isLockedOut(147, SameForkAnc{}));

    // Take the first allowed canonical vote (149): the expired fork vote MUST
    // be popped from the real tower.
    state.recordVote(149);
    for (state.constSlice()) |lk| {
        try std.testing.expect(lk.slot != 146);
    }

    // March canonical votes 150..185 (the live carrier's continuation window):
    // every vote admitted, and the tower root NEVER becomes the fork slot 146.
    var s: core.Slot = 150;
    while (s <= 185) : (s += 1) {
        try std.testing.expect(!state.isLockedOut(s, TestCanonAncestors{ .candidate = s, .forks = &fork_slots }));
        state.recordVote(s);
        if (state.root_slot) |r| {
            try std.testing.expect(r != 146);
        }
    }
}

test "carrier #7: isLockedOut isRecent — at/below last vote (or root) always locked out" {
    var state = TowerBft.VoteState.init();
    const AllAnc = struct {
        pub fn containsSlot(_: @This(), _: core.Slot) bool {
            return true;
        }
    };

    // Empty tower, no root: nothing is locked out.
    try std.testing.expect(!state.isLockedOut(100, AllAnc{}));

    state.recordVote(100);
    try std.testing.expect(state.isLockedOut(100, AllAnc{})); // == last vote
    try std.testing.expect(state.isLockedOut(99, AllAnc{})); // below last vote
    try std.testing.expect(!state.isLockedOut(101, AllAnc{})); // same fork, above

    // Empty stack but root set (restart shape): candidates ≤ root locked out.
    var rooted = TowerBft.VoteState.init();
    rooted.root_slot = 500;
    try std.testing.expect(rooted.isLockedOut(500, AllAnc{}));
    try std.testing.expect(rooted.isLockedOut(499, AllAnc{}));
    try std.testing.expect(!rooted.isLockedOut(501, AllAnc{}));
}

test "carrier #7: SliceAncestors — rooted prefix + unrooted chain membership" {
    const chain = [_]core.Slot{ 145, 144, 143, 142, 141 }; // newest-first, as unrootedAncestorChain yields
    const anc = TowerBft.SliceAncestors{ .rooted_slot = 140, .chain = &chain };

    try std.testing.expect(anc.containsSlot(140)); // rooted prefix
    try std.testing.expect(anc.containsSlot(100)); // deep rooted prefix
    try std.testing.expect(anc.containsSlot(145)); // on unrooted chain
    try std.testing.expect(anc.containsSlot(141));
    try std.testing.expect(!anc.containsSlot(146)); // the fork slot — NOT on chain
    try std.testing.expect(!anc.containsSlot(147)); // above the chain
}

test "carrier #7: deep cross-fork lockout — high-confirmation vote blocks until expiry" {
    // A vote with confirmation_count > 1 must lock out a cross-fork candidate
    // for its FULL exponential window, not just 2 slots.
    var state = TowerBft.VoteState.init();
    state.recordVote(100);
    state.recordVote(101);
    state.recordVote(102); // stack: 100(c3) 101(c2) 102(c1)

    // Fork F excludes 101 and 102 (forked off after 100).
    const fork_slots = [_]core.Slot{ 101, 102 };
    // 102 (c1) expires after 104; 101 (c2) expires after 105.
    try std.testing.expect(state.isLockedOut(104, TestCanonAncestors{ .candidate = 104, .forks = &fork_slots }));
    try std.testing.expect(state.isLockedOut(105, TestCanonAncestors{ .candidate = 105, .forks = &fork_slots }));
    try std.testing.expect(!state.isLockedOut(106, TestCanonAncestors{ .candidate = 106, .forks = &fork_slots }));
}

test "carrier #7 (2026-06-23): inherited proper-ancestor set fixes the false cross-fork lockout from walk truncation" {
    // Models the live carrier (delinquency @417317107): canonical chain
    // 140(root) → 141..145(=last_vote) → 146 → 147 → 148 → 149 → 150(candidate),
    // with a LIVE SENTINEL bank at slot 147 (parent_slot=null) on the ancestry path.
    // The OLD `ancestorChainComplete` WALK reads the sentinel's null parent and
    // TRUNCATES there → every true ancestor at/below 147 (incl last_vote 145) is
    // lost → `isLockedOut` sees a tower vote missing from `ancestors` → returns
    // true → ALL votes refused → sustained delinquency. The FIX gives each bank a
    // COMPLETE INHERITED proper-ancestor set (Agave bank.rs:1420-1425 parity:
    // child = {parent.slot} ∪ parent.proper_ancestors, filtered > root; consumed
    // by Tower::is_locked_out at agave consensus.rs:827; FD fd_ghost.h:250 +
    // fd_tower.c:396 agree) which can never truncate. Carrier-7 cross-fork safety
    // is preserved because the set is built only from VERIFIED true ancestors, so
    // it can never contain a non-ancestor (abandoned-fork) slot.
    const Slot = core.Slot;
    const root: Slot = 140;
    const candidate: Slot = 150;

    var state = TowerBft.VoteState.init();
    state.recordVote(141);
    state.recordVote(142);
    state.recordVote(143);
    state.recordVote(144);
    state.recordVote(145); // last_vote = 145 — a TRUE ancestor of candidate 150

    // (A) THE BUG (regression-lock): the walk truncated at the live sentinel (147),
    // so only the slots ABOVE it survive. A deep true ancestor (141) is missing →
    // FALSE cross-fork lockout (the exact delinquency we are fixing).
    const truncated = [_]Slot{ 149, 148 }; // walk stopped at sentinel 147 → 147..141 dropped
    const trunc_anc = TowerBft.SliceAncestors{ .rooted_slot = root, .chain = &truncated };
    try std.testing.expect(state.isLockedOut(candidate, trunc_anc));

    // (B) THE FIX: the COMPLETE inherited set holds every true ancestor > root
    // (incl last_vote) → the same-fork vote is ALLOWED (delinquency fixed).
    const complete = [_]Slot{ 149, 148, 147, 146, 145, 144, 143, 142, 141 };
    const full_anc = TowerBft.SliceAncestors{ .rooted_slot = root, .chain = &complete };
    try std.testing.expect(!state.isLockedOut(candidate, full_anc));

    // (B2) The INHERITANCE BUILD itself (the getOrCreateBank logic, Agave bank.rs:1420):
    // child.set = {ancestor.slot} ∪ ancestor.proper_ancestors, filtered > root. Assert
    // it reproduces the COMPLETE set exactly — it never truncates at a sentinel because
    // it is inherited from the verified-frozen parent, not walked.
    const parent_slot: Slot = 149;
    const parent_set = [_]Slot{ 148, 147, 146, 145, 144, 143, 142, 141 };
    var built: [16]Slot = undefined;
    var n: usize = 0;
    if (parent_slot > root) {
        built[n] = parent_slot;
        n += 1;
    }
    for (parent_set) |a| {
        if (a > root) {
            built[n] = a;
            n += 1;
        }
    }
    try std.testing.expectEqualSlices(Slot, &complete, built[0..n]);

    // (C) CARRIER-7 SAFETY preserved: a genuine ABANDONED-FORK vote is still refused.
    // forked tower votes 141,142,146f where 146f is on a different fork (parent 142,
    // cluster abandons it). The canonical candidate's COMPLETE inherited set does NOT
    // contain 146f (never a true ancestor) → isLockedOut correctly REFUSES (147 is
    // inside 146f's still-active lockout) — no lockout violation, exactly as before.
    var forked = TowerBft.VoteState.init();
    forked.recordVote(141);
    forked.recordVote(142);
    forked.recordVote(146); // fork vote — lockout active through 148
    const canon_excl_fork = [_]Slot{ 145, 144, 143, 142, 141 }; // canonical ancestry EXCLUDES fork 146
    const safe_anc = TowerBft.SliceAncestors{ .rooted_slot = root, .chain = &canon_excl_fork };
    try std.testing.expect(forked.isLockedOut(147, safe_anc));
}

// ═══════════════════════════════════════════════════════════════════════════════
// VOTE-COVERAGE KATs — resolveVoteTarget non-advancing-retarget fall-through
// (2026-07-10, vote-credit-gap-coverage mechanism). Run with: zig build test-tower
// ═══════════════════════════════════════════════════════════════════════════════

test "vote-coverage: retarget non-advancing + tip votable -> tip chosen" {
    // Live shape: last vote 100. PROP-RETARGET picks ancestor A=100 (highest ≥1/3
    // propagated), which is NON-ADVANCING (canVote(100)=false, ≤ last_vote). The frozen
    // tip T=101 strictly advances (canVote(101)=true). The un-fixed code SILENTLY
    // withheld here; the fix falls through and votes the tip.
    var state = TowerBft.VoteState.init();
    state.recordVote(100);
    try std.testing.expect(!state.canVote(100)); // A non-advancing
    try std.testing.expect(state.canVote(101)); // tip advances
    try std.testing.expectEqual(
        TowerBft.VoteState.VoteTargetChoice.tip,
        state.resolveVoteTarget(100, 101, true),
    );
    // And a deeper non-advancing ancestor (A=99) with tip 101 also falls back to the tip.
    try std.testing.expectEqual(
        TowerBft.VoteState.VoteTargetChoice.tip,
        state.resolveVoteTarget(99, 101, true),
    );
}

test "vote-coverage: retarget non-advancing + tip NOT votable -> withhold (unchanged)" {
    // last vote 101. Both the retarget A=100 AND the tip T=101 are ≤ last_vote (a
    // duplicate/stale freeze) → neither is votable → .withhold, exactly the pre-fix
    // refresh path (SAFETY INVARIANT 4: behavior when nothing is votable is unchanged).
    var state = TowerBft.VoteState.init();
    state.recordVote(101);
    try std.testing.expect(!state.canVote(100));
    try std.testing.expect(!state.canVote(101));
    try std.testing.expectEqual(
        TowerBft.VoteState.VoteTargetChoice.withhold,
        state.resolveVoteTarget(100, 101, true),
    );
    // Tip not frozen also withholds even if the slot number would advance.
    var s2 = TowerBft.VoteState.init();
    s2.recordVote(100);
    try std.testing.expectEqual(
        TowerBft.VoteState.VoteTargetChoice.withhold,
        s2.resolveVoteTarget(100, 101, false), // tip_frozen=false
    );
}

test "vote-coverage: retarget advancing -> retarget used (unchanged)" {
    // last vote 100. The retarget A=102 strictly advances (canVote true) → .target;
    // the fallback is NOT engaged and the retargeted ancestor is voted as before.
    var state = TowerBft.VoteState.init();
    state.recordVote(100);
    try std.testing.expect(state.canVote(102));
    try std.testing.expectEqual(
        TowerBft.VoteState.VoteTargetChoice.target,
        state.resolveVoteTarget(102, 105, true),
    );
    // Fresh tower (no prior vote) — every target is votable → .target (never withholds a first vote).
    var fresh = TowerBft.VoteState.init();
    try std.testing.expectEqual(
        TowerBft.VoteState.VoteTargetChoice.target,
        fresh.resolveVoteTarget(50, 51, true),
    );
}

test "vote-coverage: target == tip non-advancing -> withhold (no self-fallback)" {
    // Degenerate: retarget did NOT move the target off the tip (A == T) and the tip is
    // non-advancing. The fallback must NOT engage (target==tip guard) → .withhold. Guards
    // against a spurious fallback when the tip itself is the stale slot.
    var state = TowerBft.VoteState.init();
    state.recordVote(101);
    try std.testing.expectEqual(
        TowerBft.VoteState.VoteTargetChoice.withhold,
        state.resolveVoteTarget(101, 101, true),
    );
}
