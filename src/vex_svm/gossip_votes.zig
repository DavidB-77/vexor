//! Gossip-vote EXTRACTION + real-time vote tracker (the plumbing half of the
//! canonical propagation/confirmation fix).
//!
//! WHY THIS EXISTS
//! ---------------
//! ⚠️ CANONICITY CORRECTION (2026-07-01 audit, RULE #16): an earlier version of
//! this comment claimed "Agave feeds gossip votes into fork choice." That is
//! FALSE. Verified against Agave 4.1.0 AND Firedancer 0.1004 source:
//!   * Agave's HeaviestSubtreeForkChoice stake is fed ONLY by LANDED (replayed)
//!     votes. Gossip votes (`LatestValidatorVotesForFrozenBanks`) are consumed
//!     SOLELY by the 0.38 switch-proof and duplicate-confirmation — they NEVER
//!     enter the heaviest-subtree stake weight
//!     (heaviest_subtree_fork_choice.rs:1257-1259; consensus.rs:1222).
//!   * Firedancer (fd_ghost) is the same: landed-fed ghost; gossip = validity +
//!     switch only (fd_tower_tile.c:697-729). Two-source agreement = canonical.
//! The CANONICAL cure for the orphan-vote / vote-landing stall is therefore NOT a
//! gossip-stake gate — it is: vote `bestOverallSlot` (heaviest LANDED leaf, near
//! the tip → no stall), gated by lockout + the 0.38 switch, made orphan-safe by
//! gossip DUPLICATE-CONFIRMATION excluding the orphan from candidacy
//! (`latest_invalid_ancestor`). That machinery already exists in fork_choice.zig.
//!
//! This module's gossip-VOTE extraction is still useful (it can feed the
//! switch-proof / dup-confirmation), but the `gossip_retarget` ≥1/3-stake target
//! selection built on top of it is a NON-CANONICAL dead end — kept SHADOW-only,
//! never armed. See VEXOR-ROLLING-WORKLOG-2026-06-29.md (2026-07-01 pivot).
//!
//! THIS MODULE is the extraction + tracker only:
//!   * `parseGossipVote(tx_bytes)` — decode a gossip Vote transaction → the REAL
//!     vote ACCOUNT pubkey (NOT the gossip node identity) + voted_slot + voted_hash.
//!   * `LatestGossipVotes` — the `max_gossip_frozen_votes` analog: newest gossip
//!     vote per voter, prune-below-root, and a stake-sum helper the gate calls.
//! The integration into prop_retarget is done SEPARATELY by the main session;
//! see INTEGRATION-NOTES.md at repo root.
//!
//! PLACEMENT NOTE (deviation from the task's `vex_consensus` suggestion): this
//! module lives in **vex_svm**, NOT vex_consensus, on purpose. `parseGossipVote`
//! must reuse `native/vote_program.zig` (the canonical, battle-tested vote-tx
//! deserializers), which transitively pulls `bls_pop` + `vex_store` — both already
//! wired for vex_svm. vex_consensus is imported BY vex_svm (replay_stage uses
//! fork_choice), so importing vote_program from vex_consensus would invert that
//! edge into a dependency CYCLE. vex_svm is the cycle-free home and also where the
//! primary consumer (prop_retarget in replay_stage) lives.
//!
//! VOTE-ACCOUNT vs NODE-IDENTITY (the load-bearing distinction)
//! ------------------------------------------------------------
//! A gossip Vote's `from` field is the NODE identity that gossiped it. The value
//! the propagation gate needs is the VOTE ACCOUNT pubkey, which is
//! `account_keys[ix.account_indices[0]]` of the vote-program instruction (Agave:
//! the first instruction account is the vote account). These are different keys;
//! using `from` would credit stake to the wrong account. parseGossipVote returns
//! the vote-account key and the unit tests assert it != the fee-payer/identity.

const std = @import("std");
const vote_program = @import("native/vote_program.zig");

/// Plain 32-byte key/hash. Kept as raw arrays (not core.Pubkey/Hash) so this
/// module has no core/vex_crypto dependency; core.Pubkey.data / core.Hash.data
/// are `[32]u8`, so conversion at the integration seam is a field access.
pub const Pubkey = [32]u8;
pub const Hash = [32]u8;
pub const Slot = u64;

/// Vote program ID (Vote111111111111111111111111111111111111111).
pub const VOTE_PROGRAM_ID: [32]u8 = vote_program.VOTE_PROGRAM_ID;

/// The extracted gossip vote: the REAL vote account + what it voted for.
pub const GossipVote = struct {
    /// account_keys[ix.account_indices[0]] of the vote-program instruction — the
    /// vote ACCOUNT, never the gossip node identity / fee payer.
    vote_pubkey: Pubkey,
    /// Max lockout/voted slot in the vote instruction (the slot being voted on).
    voted_slot: Slot,
    /// The `.hash` field of the vote instruction (the voted bank hash).
    voted_hash: Hash,
    /// Number of transaction bytes consumed by the embedded bincode Transaction.
    /// The CRDS Vote wire is `index(1) | from(32) | Transaction | wallclock(8)`
    /// with NO length prefix on the Transaction (Agave crds_data.rs:330 +
    /// `slot: Option<Slot>` is `#[serde(skip_serializing)]`), so the live gossip
    /// walker can only delimit a Vote value by PARSING the tx. The caller uses
    /// this to compute the exact value size and to locate the trailing wallclock.
    /// See INTEGRATION-NOTES.md.
    tx_bytes_consumed: usize,
};

// ─────────────────────────────────────────────────────────────────────────────
// Compact-u16 (short_vec) reader — bounds-checked, never panics.
// ─────────────────────────────────────────────────────────────────────────────

/// Read a Solana compact-u16. Advances `pos`. Returns null on truncation or a
/// malformed (non-terminating) encoding. NEVER panics on a short buffer.
fn readCompactU16(buf: []const u8, pos: *usize) ?u16 {
    var value: u32 = 0;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (pos.* + i >= buf.len) return null;
        const byte = buf[pos.* + i];
        value |= @as(u32, byte & 0x7F) << @as(u5, @intCast(i * 7));
        if (byte & 0x80 == 0) {
            pos.* += i + 1;
            if (value > std.math.maxInt(u16)) return null;
            return @intCast(value);
        }
    }
    return null; // 3rd byte must terminate
}

// ─────────────────────────────────────────────────────────────────────────────
// parseGossipVote — decode a gossip Vote transaction.
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a serialized Vote `Transaction` (the bincode body embedded in a CRDS
/// Vote value, starting at the `compact_u16(num_signatures)` prefix) and extract
/// the vote ACCOUNT pubkey + voted slot + voted hash.
///
/// Returns null on ANY malformed input — truncation, a non-vote tx, an
/// out-of-range account index, an unparseable vote instruction, or an empty
/// lockout/slot set. This is a hostile-input path (arbitrary gossip bytes); it
/// must never panic. Run the tests under `--release=safe`/Debug so a missed
/// bounds check trips a panic rather than silently passing.
///
/// `tx_bytes` may extend PAST the transaction (e.g. an open-ended slice into a
/// CRDS value that still holds the trailing wallclock) — parsing stops at the end
/// of the message and reports `tx_bytes_consumed` so the caller can find the
/// trailing fields. The transaction itself carries no length prefix on the wire.
///
/// V0/ALT CAVEAT: `tx_bytes_consumed` stops after the instruction vector and does
/// NOT account for a v0 transaction's trailing address-lookup-table section. For
/// a legacy vote tx (the real case — accounts are exactly [identity, vote_account,
/// vote_program], no ALT) `consumed` lands exactly at the trailing wallclock. For
/// a v0+ALT vote tx it would point mid-ALT; such txs are not delimited here. The
/// extracted vote_pubkey/slot/hash are still correct (they come from static keys +
/// instruction data); only the byte-delimit value is ALT-unaware.
pub fn parseGossipVote(tx_bytes: []const u8) ?GossipVote {
    var pos: usize = 0;

    // 1. Signatures: compact_u16(num_sigs) then num_sigs * 64 bytes.
    const num_sigs = readCompactU16(tx_bytes, &pos) orelse return null;
    if (num_sigs == 0 or num_sigs > 127) return null; // FD_TXN_SIG_MAX = 127
    const sigs_bytes = @as(usize, num_sigs) * 64;
    if (pos + sigs_bytes > tx_bytes.len) return null;
    pos += sigs_bytes;

    // 2. Version byte (v0 high-bit), then the 3-byte message header.
    if (pos >= tx_bytes.len) return null;
    if ((tx_bytes[pos] & 0x80) != 0) pos += 1; // versioned (v0+) → skip prefix
    if (pos + 3 > tx_bytes.len) return null;
    const num_required_sigs = tx_bytes[pos];
    pos += 3; // num_required_sigs, num_readonly_signed, num_readonly_unsigned

    // 3. Static account keys (zero-copy view).
    const num_accounts = readCompactU16(tx_bytes, &pos) orelse return null;
    if (num_accounts == 0 or num_accounts > 256) return null;
    const keys_start = pos;
    const keys_end = keys_start + @as(usize, num_accounts) * 32;
    if (keys_end > tx_bytes.len) return null;
    const account_keys: [*]const [32]u8 = @ptrCast(tx_bytes.ptr + keys_start);
    const keys = account_keys[0..num_accounts];
    pos = keys_end;
    // num_required_sigs is the count of leading signer keys; the fee payer is
    // account 0. Used only to sanity-bound; not consensus-critical here.
    if (num_required_sigs > num_accounts) return null;

    // 4. Recent blockhash.
    if (pos + 32 > tx_bytes.len) return null;
    pos += 32;

    // 5. Instructions. Walk each, looking for the vote-program instruction.
    const num_instructions = readCompactU16(tx_bytes, &pos) orelse return null;
    if (num_instructions > 255) return null;

    var found: ?GossipVote = null;
    var ix_idx: usize = 0;
    while (ix_idx < num_instructions) : (ix_idx += 1) {
        if (pos >= tx_bytes.len) return null;
        const program_id_index = tx_bytes[pos];
        pos += 1;

        const num_ix_accounts = readCompactU16(tx_bytes, &pos) orelse return null;
        if (pos + num_ix_accounts > tx_bytes.len) return null;
        const ix_accounts = tx_bytes[pos..][0..num_ix_accounts];
        pos += num_ix_accounts;

        const ix_data_len = readCompactU16(tx_bytes, &pos) orelse return null;
        if (pos + ix_data_len > tx_bytes.len) return null;
        const ix_data = tx_bytes[pos..][0..ix_data_len];
        pos += ix_data_len;

        // Is this the vote program? (still finish walking later instructions so
        // `tx_bytes_consumed` is the full message length, but capture the first.)
        if (found == null and
            program_id_index < num_accounts and
            std.mem.eql(u8, &keys[program_id_index], &VOTE_PROGRAM_ID))
        {
            // Vote account = first instruction account (Agave convention).
            if (num_ix_accounts == 0) return null;
            const vote_acct_idx = ix_accounts[0];
            if (vote_acct_idx >= num_accounts) return null; // out-of-range → reject
            const slot_hash = voteInstructionSlotHash(ix_data) orelse return null;
            found = GossipVote{
                .vote_pubkey = keys[vote_acct_idx],
                .voted_slot = slot_hash.slot,
                .voted_hash = slot_hash.hash,
                .tx_bytes_consumed = 0, // filled after the walk completes
            };
        }
    }

    var result = found orelse return null;
    result.tx_bytes_consumed = pos;
    return result;
}

/// Extract (voted_slot, voted_hash) from a vote-program instruction's data by
/// reusing the canonical deserializers in native/vote_program.zig. Handles every
/// vote-CASTING discriminant (TowerSync/Switch, UpdateVoteState/Switch,
/// Compact*/Switch, legacy Vote/VoteSwitch). Non-vote-casting discriminants
/// (Authorize, Withdraw, Initialize, …) and any parse failure → null.
const SlotHash = struct { slot: Slot, hash: Hash };

fn voteInstructionSlotHash(ix_data: []const u8) ?SlotHash {
    const vi = vote_program.VoteInstruction.deserialize(ix_data) catch return null;
    return switch (vi) {
        .TowerSync => |t| sh(maxLockoutSlot(t.lockouts) orelse return null, t.hash),
        .TowerSyncSwitch => |t| sh(maxLockoutSlot(t.sync.lockouts) orelse return null, t.sync.hash),
        .UpdateVoteState => |u| sh(maxLockoutSlot(u.lockouts) orelse return null, u.hash),
        .UpdateVoteStateSwitch => |u| sh(maxLockoutSlot(u.update.lockouts) orelse return null, u.update.hash),
        .CompactUpdateVoteState => |c| sh(maxLockoutSlot(c.lockouts) orelse return null, c.hash),
        .CompactUpdateVoteStateSwitch => |c| sh(maxLockoutSlot(c.update.lockouts) orelse return null, c.update.hash),
        .Vote => |v| sh(maxSlot(v.slots) orelse return null, v.hash),
        .VoteSwitch => |v| sh(maxSlot(v.vote.slots) orelse return null, v.vote.hash),
        else => null, // not a vote-casting instruction
    };
}

inline fn sh(slot: Slot, hash: Hash) SlotHash {
    return .{ .slot = slot, .hash = hash };
}

fn maxLockoutSlot(lockouts: []const vote_program.Lockout) ?Slot {
    if (lockouts.len == 0) return null;
    var m: Slot = 0;
    for (lockouts) |l| {
        if (l.slot > m) m = l.slot;
    }
    return m;
}

fn maxSlot(slots: []const u64) ?Slot {
    if (slots.len == 0) return null;
    var m: Slot = 0;
    for (slots) |s| {
        if (s > m) m = s;
    }
    return m;
}

// ─────────────────────────────────────────────────────────────────────────────
// LatestGossipVotes — newest gossip vote per voter (max_gossip_frozen_votes analog)
// ─────────────────────────────────────────────────────────────────────────────

pub const VoteRecord = struct {
    slot: Slot,
    hash: Hash,
};

/// Tracks the latest gossip-observed vote per voter (vote account).
///
/// Mirrors Agave `LatestValidatorVotesForFrozenBanks.max_gossip_frozen_votes`
/// (HashMap<Pubkey, (Slot, Vec<Hash>)>). Simplified to a SINGLE hash per voter
/// (the task's `struct{slot,hash}` shape) rather than Agave's `Vec<Hash>`: the
/// propagation/confirmation stake gate only needs the latest voted slot per voter
/// to attribute stake to a fork, and `checkAddVote` keeps strictly-newer slots —
/// so the multi-hash same-slot case (rare; duplicate-bank tie-break) collapses to
/// the most-recently-seen hash. Documented here so it reads as a deliberate scope
/// choice, not an omission.
///
/// Allocation-bounded: at most one entry per distinct voter (≈ cluster validator
/// count); `pruneBelow(root)` drops voters whose latest vote is below the rooted
/// slot so the map cannot grow without bound.
pub const LatestGossipVotes = struct {
    map: std.AutoHashMapUnmanaged(Pubkey, VoteRecord) = .{},
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{ .map = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        self.map.deinit(self.allocator);
    }

    /// Record a gossip vote. Keeps only the NEWEST per voter: replaces an existing
    /// entry iff `slot` is strictly greater than the stored slot; inserts if the
    /// voter is unseen. Returns true iff the map was updated (a genuinely newer
    /// vote), false if this vote was stale/equal (ignored — Agave: "we have newer
    /// votes for this validator, we don't care about this vote").
    pub fn checkAddVote(self: *Self, pubkey: Pubkey, slot: Slot, hash: Hash) !bool {
        const gop = try self.map.getOrPut(self.allocator, pubkey);
        if (gop.found_existing) {
            if (slot <= gop.value_ptr.slot) return false; // stale/equal → ignore
        }
        gop.value_ptr.* = .{ .slot = slot, .hash = hash };
        return true;
    }

    /// Latest recorded vote for a voter, or null if unseen.
    pub fn get(self: *const Self, pubkey: Pubkey) ?VoteRecord {
        return self.map.get(pubkey);
    }

    pub fn count(self: *const Self) usize {
        return self.map.count();
    }

    /// Drop every voter whose latest vote is strictly below `root` (those votes
    /// are rooted/irrelevant to the live ≥1/3 gate). Keeps the map bounded.
    ///
    /// Collect-then-remove (NOT remove-during-iteration): mutating the map mid
    /// `iterator()` walk relies on open-addressed-removal internals that this
    /// code does not want to assume (RULE #8/#15 — no memory-safety claim on an
    /// uncited stdlib detail). The map is tiny (≈ validator count) and prune is
    /// rare, so the small scratch list is free. Allocation failure → skip prune
    /// this round (the map stays bounded by the next successful prune; never
    /// unsafe).
    pub fn pruneBelow(self: *Self, root: Slot) void {
        var doomed: std.ArrayListUnmanaged(Pubkey) = .{};
        defer doomed.deinit(self.allocator);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.slot < root)
                doomed.append(self.allocator, entry.key_ptr.*) catch return;
        }
        for (doomed.items) |k| _ = self.map.remove(k);
    }

    /// Sum the epoch stake of every voter whose latest gossip vote lands on a fork
    /// that CONTAINS `candidate` — i.e. `candidate` is an ancestor of (or equal to)
    /// the voter's voted slot. This is the gossip-side contribution to the
    /// propagation/confirmation ≥1/3 gate (analogous to fork_choice
    /// `stake_voted_subtree(candidate)`, but sourced from real-time gossip votes).
    ///
    /// `ctx` is an injected context supplied by the integration (replay_stage),
    /// duck-typed with two methods so this module needs NO import of fork_choice /
    /// epoch_stakes (keeps it testable in isolation):
    ///
    ///   fn epochStake(ctx, vote_pubkey: Pubkey) u64
    ///       → the voter's activated stake in the relevant epoch (0 if unknown).
    ///   fn isAncestor(ctx, candidate: Slot, voted_slot: Slot) bool
    ///       → true iff `candidate` is an ancestor of `voted_slot` on the fork tree,
    ///         INCLUSIVE of candidate == voted_slot. NOTE the argument ORDER:
    ///         (candidate, voted). Getting this backwards sums the wrong fork set.
    ///
    /// Returns the summed stake (saturating). Each voter is counted at most once.
    pub fn stakeForSlotAncestry(self: *const Self, candidate: Slot, ctx: anytype) u64 {
        var total: u64 = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const voted_slot = entry.value_ptr.slot;
            if (ctx.isAncestor(candidate, voted_slot)) {
                total +|= ctx.epochStake(entry.key_ptr.*);
            }
        }
        return total;
    }

    /// Hash-aware variant of `stakeForSlotAncestry`. The candidate fork is
    /// identified by its full `(slot, hash)` key, and a voter is credited iff its
    /// voted `(slot, hash)` IS the candidate or a hash-aware DESCENDANT of it.
    ///
    /// This closes the EQUIVOCATION hole the slot-only variant has: in a
    /// duplicate-bank race (same slot `S`, two hashes `oH`/`cH`), the slot-only
    /// sum credits an `(S, cH)` voter to an `(S, oH)` candidate. Keying on hash
    /// means a voter of the canonical `(S, cH)` is NOT summed into the orphan
    /// `(S, oH)` candidate — the two forks are distinguished, not conflated.
    ///
    /// `ctx` (duck-typed, no fork_choice import) must expose:
    ///   fn epochStake(ctx, vote_pubkey: Pubkey) u64
    ///   fn isAncestorKey(ctx, cand_slot: Slot, cand_hash: Hash,
    ///                    voted_slot: Slot, voted_hash: Hash) bool
    ///       → true iff `(cand_slot,cand_hash)` is an ancestor of (or equal to)
    ///         `(voted_slot,voted_hash)` on the fork tree. Argument ORDER is
    ///         (candidate, voted); reversing it sums the wrong fork set.
    /// Returns the summed stake (saturating); each voter counted at most once.
    pub fn stakeForSlotAncestryKey(self: *const Self, cand_slot: Slot, cand_hash: Hash, ctx: anytype) u64 {
        var total: u64 = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (ctx.isAncestorKey(cand_slot, cand_hash, entry.value_ptr.slot, entry.value_ptr.hash)) {
                total +|= ctx.epochStake(entry.key_ptr.*);
            }
        }
        return total;
    }
};

/// Thin wrapper for the gossip.zig CRDS length-parser injection (P2 fix): parse a
/// gossip vote transaction and report only how many bytes it consumed, or null if
/// the tx is malformed. Lets vex_network delimit a CRDS Vote value's embedded
/// (length-prefix-free) Transaction without importing the vote-program types.
pub fn parseTxConsumed(tx_bytes: []const u8) ?usize {
    const gv = parseGossipVote(tx_bytes) orelse return null;
    return gv.tx_bytes_consumed;
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;

/// Append a compact-u16 to a byte list (test helper).
fn tCompactU16(list: *std.ArrayListUnmanaged(u8), a: std.mem.Allocator, v: u16) !void {
    if (v < 0x80) {
        try list.append(a, @intCast(v));
    } else if (v < 0x4000) {
        try list.append(a, @intCast((v & 0x7F) | 0x80));
        try list.append(a, @intCast(v >> 7));
    } else {
        try list.append(a, @intCast((v & 0x7F) | 0x80));
        try list.append(a, @intCast(((v >> 7) & 0x7F) | 0x80));
        try list.append(a, @intCast(v >> 14));
    }
}

/// Build a real TowerSync (disc 14) instruction-data blob:
///   disc:u32 | root:u64(MAX=None) | lockout_count:compact-u16
///   | lockouts{ varint offset, u8 conf } | hash[32] | ts:u8(0=None) | block_id[32]
fn buildTowerSyncIxData(a: std.mem.Allocator, voted_slot: u64, vote_hash: [32]u8) ![]u8 {
    var d = std.ArrayListUnmanaged(u8){};
    errdefer d.deinit(a);
    try d.appendSlice(a, &std.mem.toBytes(@as(u32, 14))); // disc 14 = TowerSync
    try d.appendSlice(a, &std.mem.toBytes(@as(u64, std.math.maxInt(u64)))); // root None
    try tCompactU16(&d, a, 1); // one lockout
    // varint offset from root(0) == voted_slot. voted_slot 100 fits one byte.
    try testing.expect(voted_slot < 0x80);
    try d.append(a, @intCast(voted_slot)); // offset
    try d.append(a, 1); // confirmation_count
    try d.appendSlice(a, &vote_hash); // hash[32]
    try d.append(a, 0); // timestamp None
    try d.appendSlice(a, &([_]u8{0xCD} ** 32)); // block_id[32]
    return d.toOwnedSlice(a);
}

/// Assemble a full TowerSync vote transaction with account layout
/// [identity, vote_account, vote_program] and ix.account_indices = [1, 0].
fn buildTowerSyncTx(
    a: std.mem.Allocator,
    identity: [32]u8,
    vote_account: [32]u8,
    voted_slot: u64,
    vote_hash: [32]u8,
) ![]u8 {
    const ix_data = try buildTowerSyncIxData(a, voted_slot, vote_hash);
    defer a.free(ix_data);

    var t = std.ArrayListUnmanaged(u8){};
    errdefer t.deinit(a);
    // signatures
    try tCompactU16(&t, a, 1); // 1 signature
    try t.appendNTimes(a, 0, 64); // signature bytes (parse does not verify)
    // message header
    try t.append(a, 1); // num_required_signatures
    try t.append(a, 0); // num_readonly_signed
    try t.append(a, 1); // num_readonly_unsigned
    // account keys
    try tCompactU16(&t, a, 3);
    try t.appendSlice(a, &identity); // 0: identity / fee payer
    try t.appendSlice(a, &vote_account); // 1: vote account
    try t.appendSlice(a, &VOTE_PROGRAM_ID); // 2: vote program
    // blockhash
    try t.appendSlice(a, &([_]u8{0x03} ** 32));
    // instructions
    try tCompactU16(&t, a, 1);
    try t.append(a, 2); // program_id_index = vote program
    try tCompactU16(&t, a, 2); // 2 instruction accounts
    try t.append(a, 1); // account index 1 = vote account (FIRST → the vote pubkey)
    try t.append(a, 0); // account index 0 = authority/identity
    try tCompactU16(&t, a, @intCast(ix_data.len));
    try t.appendSlice(a, ix_data);
    return t.toOwnedSlice(a);
}

test "parseGossipVote: real TowerSync → vote ACCOUNT (not identity), slot, hash" {
    const a = testing.allocator;
    const identity = [_]u8{0x11} ** 32; // node identity / fee payer (account 0)
    const vote_account = [_]u8{0x22} ** 32; // the REAL vote account (account 1)
    const vote_hash = [_]u8{0xAB} ** 32;

    const tx = try buildTowerSyncTx(a, identity, vote_account, 100, vote_hash);
    defer a.free(tx);

    const gv = parseGossipVote(tx) orelse return error.ParseReturnedNull;

    // THE load-bearing assertion: vote_pubkey is the vote ACCOUNT, NOT the node
    // identity / fee payer (account 0). This is the entire point of the task.
    try testing.expectEqualSlices(u8, &vote_account, &gv.vote_pubkey);
    try testing.expect(!std.mem.eql(u8, &identity, &gv.vote_pubkey));

    try testing.expectEqual(@as(Slot, 100), gv.voted_slot);
    try testing.expectEqualSlices(u8, &vote_hash, &gv.voted_hash);
    // Consumed the whole transaction (no trailing wallclock present here).
    try testing.expectEqual(tx.len, gv.tx_bytes_consumed);
}

test "parseGossipVote: trailing bytes past the tx are ignored, consumed is exact" {
    const a = testing.allocator;
    const identity = [_]u8{0x11} ** 32;
    const vote_account = [_]u8{0x22} ** 32;
    const vote_hash = [_]u8{0xAB} ** 32;
    const tx = try buildTowerSyncTx(a, identity, vote_account, 100, vote_hash);
    defer a.free(tx);

    // Emulate a CRDS Vote value tail: append a wallclock (8 bytes) after the tx.
    var withtail = std.ArrayListUnmanaged(u8){};
    defer withtail.deinit(a);
    try withtail.appendSlice(a, tx);
    try withtail.appendSlice(a, &std.mem.toBytes(@as(u64, 1234567)));

    const gv = parseGossipVote(withtail.items) orelse return error.ParseReturnedNull;
    try testing.expectEqualSlices(u8, &vote_account, &gv.vote_pubkey);
    try testing.expectEqual(@as(Slot, 100), gv.voted_slot);
    // consumed must point exactly at the start of the trailing wallclock.
    try testing.expectEqual(tx.len, gv.tx_bytes_consumed);
}

test "parseGossipVote: malformed inputs return null (never panic)" {
    const a = testing.allocator;

    // empty
    try testing.expect(parseGossipVote(&[_]u8{}) == null);
    // single garbage byte
    try testing.expect(parseGossipVote(&[_]u8{0xFF}) == null);
    // claims many sigs but no bytes
    try testing.expect(parseGossipVote(&[_]u8{0x7F}) == null);

    const identity = [_]u8{0x11} ** 32;
    const vote_account = [_]u8{0x22} ** 32;
    const vote_hash = [_]u8{0xAB} ** 32;
    const tx = try buildTowerSyncTx(a, identity, vote_account, 100, vote_hash);
    defer a.free(tx);

    // Truncate at every length up to the full tx — none may panic, all must be null
    // (a complete parse only happens at the full length).
    var cut: usize = 0;
    while (cut < tx.len) : (cut += 1) {
        try testing.expect(parseGossipVote(tx[0..cut]) == null);
    }
}

test "parseGossipVote: non-vote tx (no vote-program instruction) → null" {
    const a = testing.allocator;
    // Same shape as a vote tx but the program account is the System program (zeros),
    // so no instruction targets the vote program.
    var t = std.ArrayListUnmanaged(u8){};
    defer t.deinit(a);
    try tCompactU16(&t, a, 1);
    try t.appendNTimes(a, 0, 64);
    try t.append(a, 1);
    try t.append(a, 0);
    try t.append(a, 1);
    try tCompactU16(&t, a, 3);
    try t.appendSlice(a, &([_]u8{0x11} ** 32)); // identity
    try t.appendSlice(a, &([_]u8{0x22} ** 32)); // some account
    try t.appendSlice(a, &([_]u8{0x00} ** 32)); // System program (NOT vote)
    try t.appendSlice(a, &([_]u8{0x03} ** 32)); // blockhash
    try tCompactU16(&t, a, 1);
    try t.append(a, 2); // program = System
    try tCompactU16(&t, a, 1);
    try t.append(a, 1);
    try tCompactU16(&t, a, 4);
    try t.appendSlice(a, &[_]u8{ 2, 0, 0, 0 }); // arbitrary system ix data
    try testing.expect(parseGossipVote(t.items) == null);
}

test "parseGossipVote: vote-program instruction with out-of-range account index → null" {
    const a = testing.allocator;
    const ix_data = try buildTowerSyncIxData(a, 100, [_]u8{0xAB} ** 32);
    defer a.free(ix_data);

    var t = std.ArrayListUnmanaged(u8){};
    defer t.deinit(a);
    try tCompactU16(&t, a, 1);
    try t.appendNTimes(a, 0, 64);
    try t.append(a, 1);
    try t.append(a, 0);
    try t.append(a, 1);
    try tCompactU16(&t, a, 3);
    try t.appendSlice(a, &([_]u8{0x11} ** 32));
    try t.appendSlice(a, &([_]u8{0x22} ** 32));
    try t.appendSlice(a, &VOTE_PROGRAM_ID); // 2: vote program
    try t.appendSlice(a, &([_]u8{0x03} ** 32));
    try tCompactU16(&t, a, 1);
    try t.append(a, 2); // program = vote
    try tCompactU16(&t, a, 1);
    try t.append(a, 9); // account index 9 — OUT OF RANGE (only 3 accounts)
    try tCompactU16(&t, a, @intCast(ix_data.len));
    try t.appendSlice(a, ix_data);
    try testing.expect(parseGossipVote(t.items) == null);
}

test "LatestGossipVotes: newer replaces older, stale ignored" {
    var lv = LatestGossipVotes.init(testing.allocator);
    defer lv.deinit();

    const voter = [_]u8{0x01} ** 32;
    const h1 = [_]u8{0xA1} ** 32;
    const h2 = [_]u8{0xA2} ** 32;

    try testing.expect(try lv.checkAddVote(voter, 100, h1)); // first → inserted
    try testing.expectEqual(@as(?VoteRecord, VoteRecord{ .slot = 100, .hash = h1 }), lv.get(voter));

    // older slot → ignored
    try testing.expect(!try lv.checkAddVote(voter, 90, h2));
    try testing.expectEqual(@as(Slot, 100), lv.get(voter).?.slot);

    // equal slot → ignored (strictly-greater only)
    try testing.expect(!try lv.checkAddVote(voter, 100, h2));
    try testing.expectEqualSlices(u8, &h1, &lv.get(voter).?.hash);

    // newer slot → replaces
    try testing.expect(try lv.checkAddVote(voter, 101, h2));
    try testing.expectEqual(@as(Slot, 101), lv.get(voter).?.slot);
    try testing.expectEqualSlices(u8, &h2, &lv.get(voter).?.hash);

    try testing.expectEqual(@as(usize, 1), lv.count());
}

test "LatestGossipVotes: pruneBelow drops rooted voters, keeps live" {
    var lv = LatestGossipVotes.init(testing.allocator);
    defer lv.deinit();

    const a = [_]u8{0x0A} ** 32;
    const b = [_]u8{0x0B} ** 32;
    const c = [_]u8{0x0C} ** 32;
    _ = try lv.checkAddVote(a, 50, [_]u8{1} ** 32);
    _ = try lv.checkAddVote(b, 100, [_]u8{2} ** 32);
    _ = try lv.checkAddVote(c, 150, [_]u8{3} ** 32);
    try testing.expectEqual(@as(usize, 3), lv.count());

    lv.pruneBelow(100); // drop slot < 100 → removes `a` (50); keeps b(100), c(150)
    try testing.expectEqual(@as(usize, 2), lv.count());
    try testing.expect(lv.get(a) == null);
    try testing.expect(lv.get(b) != null);
    try testing.expect(lv.get(c) != null);
}

test "LatestGossipVotes: stakeForSlotAncestry sums only on-fork voters" {
    var lv = LatestGossipVotes.init(testing.allocator);
    defer lv.deinit();

    const v_on1 = [_]u8{0x01} ** 32; // voted 200, on the candidate fork
    const v_on2 = [_]u8{0x02} ** 32; // voted 210, on the candidate fork
    const v_off = [_]u8{0x03} ** 32; // voted 205, on a DIFFERENT fork

    _ = try lv.checkAddVote(v_on1, 200, [_]u8{0} ** 32);
    _ = try lv.checkAddVote(v_on2, 210, [_]u8{0} ** 32);
    _ = try lv.checkAddVote(v_off, 205, [_]u8{0} ** 32);

    // Context: candidate=150 is an ancestor of 200 and 210 but NOT 205.
    const Ctx = struct {
        on1: Pubkey,
        on2: Pubkey,
        off: Pubkey,
        fn epochStake(self: *const @This(), pk: Pubkey) u64 {
            if (std.mem.eql(u8, &pk, &self.on1)) return 30;
            if (std.mem.eql(u8, &pk, &self.on2)) return 40;
            if (std.mem.eql(u8, &pk, &self.off)) return 1000;
            return 0;
        }
        fn isAncestor(self: *const @This(), candidate: Slot, voted: Slot) bool {
            _ = self;
            _ = candidate;
            // model: 205 is on a sibling fork; 200/210 descend from candidate 150.
            return voted != 205;
        }
    };
    const ctx = Ctx{ .on1 = v_on1, .on2 = v_on2, .off = v_off };
    const stake = lv.stakeForSlotAncestry(150, &ctx);
    try testing.expectEqual(@as(u64, 70), stake); // 30 + 40, NOT the 1000 off-fork
}

test "LatestGossipVotes: stakeForSlotAncestryKey is hash-aware — (S,cH) voter NOT credited to (S,oH) orphan" {
    var lv = LatestGossipVotes.init(testing.allocator);
    defer lv.deinit();

    const S: Slot = 300;
    const oH = [_]u8{0xAA} ** 32; // orphan bank hash at slot S
    const cH = [_]u8{0xBB} ** 32; // canonical bank hash at slot S
    const v_orphan = [_]u8{0x01} ** 32; // voted (S, oH)
    const v_canon = [_]u8{0x02} ** 32; // voted (S, cH)

    _ = try lv.checkAddVote(v_orphan, S, oH);
    _ = try lv.checkAddVote(v_canon, S, cH);

    // Both voters sit AT slot S, so only an EXACT (slot,hash) match is credited — the
    // property that keeps a canonical-sibling voter out of the orphan candidate's sum.
    const Ctx = struct {
        orphan_pk: Pubkey,
        canon_pk: Pubkey,
        fn epochStake(self: *const @This(), pk: Pubkey) u64 {
            if (std.mem.eql(u8, &pk, &self.orphan_pk)) return 40;
            if (std.mem.eql(u8, &pk, &self.canon_pk)) return 55;
            return 0;
        }
        fn isAncestorKey(self: *const @This(), cs: Slot, ch: Hash, vs: Slot, vh: Hash) bool {
            _ = self;
            return cs == vs and std.mem.eql(u8, &ch, &vh); // inclusive exact-key match
        }
    };
    const ctx = Ctx{ .orphan_pk = v_orphan, .canon_pk = v_canon };

    // Orphan candidate (S,oH): only its own 40 — the canonical 55 is NOT conflated in.
    try testing.expectEqual(@as(u64, 40), lv.stakeForSlotAncestryKey(S, oH, &ctx));
    // Canonical candidate (S,cH): only its own 55 — the orphan 40 is NOT conflated in.
    try testing.expectEqual(@as(u64, 55), lv.stakeForSlotAncestryKey(S, cH, &ctx));
}
