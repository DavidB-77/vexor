//! Vexor Vote State Full Round-Trip Serialization/Deserialization
//!
//! Matches Agave's exact behavior: deserialize → mutate struct → re-serialize.
//! This replaces the previous "surgical mutation" approach which was broken for
//! TowerSync instructions because post-root fields (authorized_voters, prior_voters,
//! epoch_credits, BlockTimestamp) sit at dynamic offsets that shift when the lockout
//! count changes.
//!
//! Binary layout for VoteState (Bincode format, all little-endian):
//!   Version discriminant (u32) — 1 = VoteState1_14_11, 2 = Current (with latency), 3 = V4 (extra fields)
//!   [32]u8 node_pubkey
//!   [32]u8 authorized_withdrawer
//!   u8 commission
//!   u64 votes.len + Lockout/LandedVote[len]
//!     v1 Lockout: {u64 slot, u32 confirmation_count} = 12 bytes
//!     v2 LandedVote: {u8 latency, u64 slot, u32 confirmation_count} = 13 bytes
//!   Option<u64> root_slot: u8 discriminant + u64 value (if present)
//!   u64 authorized_voters.len + entries of {u64 epoch, [32]u8 pubkey}
//!   PriorVoters CircBuf: 32 × {[32]u8 pubkey, u64 epoch_start, u64 epoch_end} + u64 idx + u8 is_empty = 1545 bytes
//!   u64 epoch_credits.len + entries of {u64 epoch, u64 credits, u64 prev_credits}
//!   BlockTimestamp: {u64 slot, i64 timestamp} = 16 bytes

const std = @import("std");
const recorder = @import("vex_store").recorder;
// FIX-2 (2026-06-10, proactive-trio): canonical EpochSchedule (leaf module
// native/epoch_schedule.zig, re-exported by bank.zig — SAME type identity;
// Agave solana-epoch-schedule port). Replaces the deleted local slotToEpoch
// helper — epoch values are now THREADED from the caller's
// bank.epoch_schedule (clock.epoch semantics); EpochSchedule.DEFAULT is the
// fallback ONLY for legacy null-epoch test wrappers. Same-dir import keeps
// the standalone test-vote-state-serde module root compiling (bank.zig
// would escape its module path AND drag vex_crypto/build_options).
const epoch_schedule_mod = @import("epoch_schedule.zig");

/// Maximum lockout history (tower depth)
pub const MAX_LOCKOUT_HISTORY: usize = 31;

/// Maximum epoch credits entries
pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;

/// Timely Vote Credits (SIMD-033, active on testnet)
/// Values: maximum_per_slot=16, grace_slots=2 (Solana protocol constants)
pub const VOTE_CREDITS_MAXIMUM_PER_SLOT: u64 = 16;
pub const VOTE_CREDITS_GRACE_SLOTS: u64 = 2;

/// Compute credits for a single rooted lockout based on its latency.
/// latency == 0 means legacy (no latency stored) → 1 credit.
/// latency <= GRACE → maximum credits.
/// latency > GRACE → credits decay linearly, minimum 1.
fn creditsForVote(latency: u8) u64 {
    if (latency == 0) return 1; // legacy lockout — no latency stored
    const lat: u64 = latency;
    if (lat <= VOTE_CREDITS_GRACE_SLOTS) return VOTE_CREDITS_MAXIMUM_PER_SLOT;
    const diff = lat - VOTE_CREDITS_GRACE_SLOTS;
    return if (diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT) 1 else VOTE_CREDITS_MAXIMUM_PER_SLOT - diff;
}

/// Maximum authorized voters entries
pub const MAX_AUTHORIZED_VOTERS: usize = 8;

/// Prior voters CircBuf size: 32 entries × 48 bytes + 8 (idx) + 1 (is_empty) = 1545
pub const PRIOR_VOTERS_SIZE: usize = 1545;

/// Default slots per epoch (for epoch calculation)
pub const DEFAULT_SLOTS_PER_EPOCH: u64 = 432_000;

/// Vote state size constants (Solana protocol fixed sizes)
pub const VOTE_STATE_V2_SZ: usize = 3731;
pub const VOTE_STATE_V3_SZ: usize = 3762;

// FIX-2 (2026-06-10, proactive-trio): the local hardcoded `slotToEpoch`
// helper was DELETED (it carried its own first_normal_slot constant — the
// 524288-vs-524256 off-by-32 carrier class, where the first 32 slots of
// EVERY epoch got epoch N−1 → incrementCredits(wrong_epoch) → poisoned
// epoch_credits → accounts_lt_hash divergence exactly at boundaries, e.g.
// the epoch-972 crossing @414380256). Epoch values are now threaded from
// the caller's bank.epoch_schedule (canonical Agave EpochSchedule port in
// bank.zig, incl. exact warmup math). Per the serde TODO: "Accept actual
// EpochSchedule when available" — done.

/// A single tower lockout entry
pub const Lockout = struct {
    slot: u64,
    confirmation_count: u32,
};

/// A landed vote (v3 format) = lockout + latency
pub const LandedVote = struct {
    latency: u8,
    slot: u64,
    confirmation_count: u32,
};

/// Epoch credits entry
pub const EpochCredits = struct {
    epoch: u64,
    credits: u64,
    prev_credits: u64,
};

/// Block timestamp (always last 16 bytes)
pub const BlockTimestamp = struct {
    slot: u64,
    timestamp: i64,
};

/// Authorized voter entry
pub const AuthorizedVoter = struct {
    epoch: u64,
    pubkey: [32]u8,
};

// ═══════════════════════════════════════════════════════════════════════════
// FULL VOTE STATE STRUCT — for complete deserialization round-trip
// ═══════════════════════════════════════════════════════════════════════════

/// Complete vote state representation.
/// Used for TowerSync/UpdateVoteState which require full deserialization → mutation → re-serialization.
pub const VoteState = struct {
    version: u32, // 1 = v1_14_11 (12-byte), 2 = current (13-byte w/ latency), 3 = v4 (extra fields)
    node_pubkey: [32]u8,
    authorized_withdrawer: [32]u8,
    commission: u8,

    // V4 extra fields (disc=3 only)
    inflation_rewards_collector: [32]u8,
    block_revenue_collector: [32]u8,
    inflation_rewards_commission_bps: u16,
    block_revenue_commission_bps: u16,
    pending_delegator_rewards: u64,
    has_bls_pubkey_compressed: bool,
    bls_pubkey_compressed: [48]u8,

    // Lockouts (tower)
    lockout_count: u32,
    lockouts: [MAX_LOCKOUT_HISTORY]Lockout,
    latencies: [MAX_LOCKOUT_HISTORY]u8, // v2 (Current) only

    // Root
    root_slot: ?u64,

    // Authorized voters
    av_count: u32,
    authorized_voters: [MAX_AUTHORIZED_VOTERS]AuthorizedVoter,

    // Prior voters (opaque CircBuf — copy raw bytes unchanged)
    prior_voters_raw: [PRIOR_VOTERS_SIZE]u8,

    // Epoch credits
    ec_count: u32,
    epoch_credits: [MAX_EPOCH_CREDITS_HISTORY]EpochCredits,

    // Block timestamp
    last_timestamp: BlockTimestamp,

    pub fn init() VoteState {
        var vs: VoteState = undefined;
        vs.version = 0;
        @memset(&vs.node_pubkey, 0);
        @memset(&vs.authorized_withdrawer, 0);
        vs.commission = 0;
        // V4 fields
        @memset(&vs.inflation_rewards_collector, 0);
        @memset(&vs.block_revenue_collector, 0);
        vs.inflation_rewards_commission_bps = 0;
        vs.block_revenue_commission_bps = 0;
        vs.pending_delegator_rewards = 0;
        vs.has_bls_pubkey_compressed = false;
        @memset(&vs.bls_pubkey_compressed, 0);
        // Tower
        vs.lockout_count = 0;
        // SIMD-0185 byte-blocker A: V1_14_11 has NO per-lockout latency byte, so
        // deserialize never writes vs.latencies for a V1 source. convertToV4 later
        // sets latency=0 for the live range, but memset here defensively so an
        // unwritten slot can never serialize a garbage (non-deterministic) byte.
        @memset(&vs.latencies, 0);
        vs.root_slot = null;
        vs.av_count = 0;
        vs.ec_count = 0;
        @memset(&vs.prior_voters_raw, 0);
        vs.last_timestamp = .{ .slot = 0, .timestamp = 0 };
        return vs;
    }

    /// Get the last voted slot (highest lockout slot)
    pub fn lastVotedSlot(self: *const VoteState) ?u64 {
        if (self.lockout_count == 0) return null;
        return self.lockouts[self.lockout_count - 1].slot;
    }

    /// Increment epoch credits by `credits_earned` for the given epoch.
    /// In Agave, credits are incremented each time lockouts are promoted to root.
    /// The epoch_credits array tracks (epoch, cumulative_credits, prev_credits_at_epoch_start).
    ///
    /// r46-B fix (2026-04-27): exact byte-equivalent port of Agave 4.0-beta.7
    /// `programs/vote/src/vote_state/handler.rs:140` `increment_credits`. Pre-r46-B,
    /// Vexor unconditionally pushed a new entry when epoch != last.epoch, even when
    /// `credits == prev_credits` (silent-epoch — validator earned 0 credits in the
    /// previous epoch). Agave instead MUTATES the last entry's epoch IN PLACE in that
    /// case, keeping epoch_credits.len bounded.
    ///
    /// Effect of the bug: every silent-epoch transition grew Vexor's epoch_credits.len
    /// by 1 spuriously. The 8-byte length-prefix on epoch_credits shifts every byte
    /// after it → vote-account post-state byte-divergence vs Agave → lthash drift
    /// across all ~60 active vote accounts × per-slot. Magnitude (~1.49 SOL/slot at
    /// slot 404550578) is consistent with this carrier per /tmp/helius_research.md
    /// finding F1.
    ///
    /// Source: agave-v4.0.0-beta.7/programs/vote/src/vote_state/handler.rs:140-167.
    pub fn incrementCredits(self: *VoteState, epoch: u64, credits_earned: u64) void {
        // PR-5ap (2026-05-20): the prior early-return on credits_earned==0
        // was WRONG. Per agave-v4.0.0-beta.7/programs/vote/src/vote_state/handler.rs:140-167,
        // Agave executes the ec_count==0 push, the epoch-rollover push,
        // AND the epoch-mutation branch regardless of whether credits_earned
        // is zero. Only the final saturating_add becomes a no-op for
        // credits_earned=0. Skipping the whole function meant that when a
        // validator's first vote of a new epoch had earned_credits == 0
        // (e.g. all newly-rooted lockouts already counted in a prior epoch),
        // Vexor never advanced `epoch_credits[last].epoch` while Agave did.
        // Subsequent votes diverged forever — chronic byte mismatch in
        // serialized vote state across all ~570 active vote accounts,
        // producing the post-PR-5an `0,1,1,0` lthash divergence shape that
        // chronically fired starting at slot 409802185 (cluster epoch 961
        // transition window).
        if (self.ec_count == 0) {
            // never seen a credit — push (epoch, 0, 0); credits get added at the bottom
            self.epoch_credits[0] = .{ .epoch = epoch, .credits = 0, .prev_credits = 0 };
            self.ec_count = 1;
        } else if (self.epoch_credits[self.ec_count - 1].epoch != epoch) {
            const last_idx = self.ec_count - 1;
            const last = self.epoch_credits[last_idx];

            if (last.credits != last.prev_credits) {
                // Credits were earned in the previous epoch — push a new entry.
                // r46-B-fix-1: Agave's `Vec.push` then `remove(0)` allows transient
                // len = MAX+1; Vexor's fixed-size [MAX]EpochCreditEntry array cannot.
                // Equivalent net behavior: drop oldest BEFORE push when at capacity.
                // The dropped element was at index 0; surviving elements (1..MAX-1)
                // shift left to (0..MAX-2), so old `last` content now lives at
                // (MAX-2). After ec_count -= 1, ec_count = MAX-1; push at [MAX-1]
                // is valid; ec_count++ brings us back to MAX.
                // last.credits captured before shift == new last position's credits
                // (shift preserved the most-recent entry's content), so push value
                // unchanged.
                if (self.ec_count >= MAX_EPOCH_CREDITS_HISTORY) {
                    var j: u32 = 0;
                    while (j < MAX_EPOCH_CREDITS_HISTORY - 1) : (j += 1) {
                        self.epoch_credits[j] = self.epoch_credits[j + 1];
                    }
                    self.ec_count = MAX_EPOCH_CREDITS_HISTORY - 1;
                }
                self.epoch_credits[self.ec_count] = .{
                    .epoch = epoch,
                    .credits = last.credits,
                    .prev_credits = last.credits,
                };
                self.ec_count += 1;
            } else {
                // No credits earned in the previous epoch — mutate the last entry's
                // epoch in place. No len change → no drop-oldest needed.
                self.epoch_credits[last_idx].epoch = epoch;
            }
        }
        // last.1 += credits — saturating to avoid overflow on extreme epochs
        const li = self.ec_count - 1;
        self.epoch_credits[li].credits = self.epoch_credits[li].credits +| credits_earned;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// @prov:vote.authorized-voters-map — canonical BTreeMap<Epoch,Pubkey>-EQUIVALENT
// operations over the fixed array `authorized_voters[0..av_count]`. The
// serializer writes the array in index order (serializeVoteState lines
// ~466-473), so the array MUST be kept ASCENDING by epoch for byte-match.
// All inserts overwrite-on-exact-key and NEVER evict; Vexor keeps a fixed cap
// (MAX_AUTHORIZED_VOTERS) and fail-loud (return false) on overflow rather
// than silently evicting (RULE#0).
// ═══════════════════════════════════════════════════════════════════════════

/// Ascending sorted insert with overwrite-on-exact-key into the AV array.
/// Returns false ONLY on capacity overflow (no canonical eviction).
/// @prov:vote.authorized-voters-map
pub fn avSortedInsert(vs: *VoteState, target_epoch: u64, new_pubkey: [32]u8) bool {
    // Find first index with epoch >= target_epoch.
    var i: u32 = 0;
    while (i < vs.av_count and vs.authorized_voters[i].epoch < target_epoch) : (i += 1) {}
    if (i < vs.av_count and vs.authorized_voters[i].epoch == target_epoch) {
        // Exact key — overwrite pubkey (BTreeMap::insert replaces the value).
        vs.authorized_voters[i].pubkey = new_pubkey;
        return true;
    }
    if (vs.av_count >= MAX_AUTHORIZED_VOTERS) return false; // fail-loud, no evict
    // Shift [i..av_count) up by one to make room at i.
    var j: u32 = vs.av_count;
    while (j > i) : (j -= 1) {
        vs.authorized_voters[j] = vs.authorized_voters[j - 1];
    }
    vs.authorized_voters[i] = .{ .epoch = target_epoch, .pubkey = new_pubkey };
    vs.av_count += 1;
    return true;
}

/// Canonical `get_and_update_authorized_voter(current_epoch)`.
/// @prov:vote.authorized-voter-update — runs on EVERY vote AND at the top of
/// the authorize handler. Two steps:
///   1. get_and_cache (carry-forward): if no entry at exactly current_epoch,
///      find the predecessor (highest entry with epoch < current_epoch) and
///      insert {current_epoch, predecessor.pubkey}. If there is no predecessor
///      AND no exact entry, return false (INVALID_ACC_DATA reject).
///   2. purge: remove every entry with epoch < bound, where the bound differs
///      by wire version (V3 vs V4 — see PROVENANCE.md for exact refs).
/// In Vexor's version encoding, version==3 is the V4 wire; version 1/2 are V3-
/// family. Returns false on the no-voter reject OR a capacity overflow.
/// NOTE: this is a NO-OP at slot 757 (exact-hit on epoch 968; V4 purge<967
/// removes nothing) — gated by the carry-forward KAT + epoch-boundary soak.
pub fn getAndUpdateAuthorizedVoter(vs: *VoteState, current_epoch: u64) bool {
    if (vs.av_count == 0) return false;

    // Step 1: get_and_cache (carry-forward).
    var exact = false;
    var pred_idx: ?u32 = null;
    for (0..vs.av_count) |k| {
        const e = vs.authorized_voters[k].epoch;
        if (e == current_epoch) {
            exact = true;
            break;
        }
        if (e < current_epoch) {
            if (pred_idx == null or e > vs.authorized_voters[pred_idx.?].epoch) {
                pred_idx = @intCast(k);
            }
        }
    }
    if (!exact) {
        const pi = pred_idx orelse return false; // no entry <= current_epoch
        const carried = vs.authorized_voters[pi].pubkey;
        if (!avSortedInsert(vs, current_epoch, carried)) return false;
    }

    // Step 2: purge entries with epoch < bound (V4 = ce-1, else ce).
    const bound: u64 = if (vs.version == 3) current_epoch -| 1 else current_epoch;
    var w: u32 = 0;
    for (0..vs.av_count) |r| {
        if (vs.authorized_voters[r].epoch < bound) continue; // drop
        if (w != r) vs.authorized_voters[w] = vs.authorized_voters[r];
        w += 1;
    }
    vs.av_count = w;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// DESERIALIZATION: raw bytes → VoteState struct
// ═══════════════════════════════════════════════════════════════════════════

/// Deserialize vote account data into a VoteState struct.
/// Handles both v2 (VoteState1_14_11) and v3 (current) formats.
pub fn deserializeVoteState(data: []const u8) ?VoteState {
    if (data.len < 77) return null;
    var vs = VoteState.init();
    var pos: usize = 0;

    // Version
    vs.version = readU32(data, &pos) orelse return null;
    if (vs.version != 1 and vs.version != 2 and vs.version != 3) return null;

    // Pubkeys + commission
    if (data.len < pos + 65) return null;
    @memcpy(&vs.node_pubkey, data[pos..][0..32]);
    pos += 32;
    @memcpy(&vs.authorized_withdrawer, data[pos..][0..32]);
    pos += 32;

    // V4 extra fields (between authorized_withdrawer and commission)
    if (vs.version == 3) {
        // inflation_rewards_collector [32]u8
        if (data.len < pos + 32) return null;
        @memcpy(&vs.inflation_rewards_collector, data[pos..][0..32]);
        pos += 32;
        // block_revenue_collector [32]u8
        if (data.len < pos + 32) return null;
        @memcpy(&vs.block_revenue_collector, data[pos..][0..32]);
        pos += 32;
        // inflation_rewards_commission_bps u16
        if (data.len < pos + 2) return null;
        vs.inflation_rewards_commission_bps = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;
        // block_revenue_commission_bps u16
        if (data.len < pos + 2) return null;
        vs.block_revenue_commission_bps = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;
        // pending_delegator_rewards u64
        vs.pending_delegator_rewards = readU64(data, &pos) orelse return null;
        // has_bls_pubkey_compressed u8
        if (pos >= data.len) return null;
        vs.has_bls_pubkey_compressed = data[pos] != 0;
        pos += 1;
        // bls_pubkey_compressed [48]u8 (only if has_bls)
        if (vs.has_bls_pubkey_compressed) {
            if (data.len < pos + 48) return null;
            @memcpy(&vs.bls_pubkey_compressed, data[pos..][0..48]);
            pos += 48;
        }
    }

    // V4 has no commission byte (replaced by commission_bps fields above)
    if (vs.version != 3) {
        vs.commission = data[pos];
        pos += 1;
    }

    // Lockouts
    const lockout_count = readU64(data, &pos) orelse return null;
    if (lockout_count > MAX_LOCKOUT_HISTORY) return null;
    vs.lockout_count = @intCast(lockout_count);

    const lockout_size: usize = if (vs.version == 1) 12 else 13; // V2, V3 (V4) all use 13-byte LandedVote
    if (data.len < pos + lockout_count * lockout_size) return null;

    for (0..vs.lockout_count) |i| {
        if (vs.version >= 2) {
            vs.latencies[i] = data[pos];
            pos += 1;
        }
        vs.lockouts[i] = .{
            .slot = readU64(data, &pos) orelse return null,
            .confirmation_count = readU32(data, &pos) orelse return null,
        };
    }

    // Root slot (Option<u64>)
    if (pos >= data.len) return null;
    const has_root = data[pos];
    pos += 1;
    if (has_root != 0) {
        vs.root_slot = readU64(data, &pos) orelse return null;
    } else {
        vs.root_slot = null;
    }

    // Authorized voters: u64 len, then {u64 epoch, [32]u8 pubkey} entries
    const av_count = readU64(data, &pos) orelse return null;
    if (av_count > MAX_AUTHORIZED_VOTERS) return null;
    vs.av_count = @intCast(av_count);
    for (0..vs.av_count) |i| {
        vs.authorized_voters[i].epoch = readU64(data, &pos) orelse return null;
        if (data.len < pos + 32) return null;
        @memcpy(&vs.authorized_voters[i].pubkey, data[pos..][0..32]);
        pos += 32;
    }

    // Prior voters: fixed-size CircBuf, copy raw bytes (v1/v2 only; v4 removed prior_voters)
    if (vs.version != 3) {
        if (data.len < pos + PRIOR_VOTERS_SIZE) return null;
        @memcpy(&vs.prior_voters_raw, data[pos..][0..PRIOR_VOTERS_SIZE]);
        pos += PRIOR_VOTERS_SIZE;
    }

    // Epoch credits: u64 len, then {u64 epoch, u64 credits, u64 prev_credits}
    const ec_count = readU64(data, &pos) orelse return null;
    if (ec_count > MAX_EPOCH_CREDITS_HISTORY) return null;
    vs.ec_count = @intCast(ec_count);
    for (0..vs.ec_count) |i| {
        vs.epoch_credits[i] = .{
            .epoch = readU64(data, &pos) orelse return null,
            .credits = readU64(data, &pos) orelse return null,
            .prev_credits = readU64(data, &pos) orelse return null,
        };
    }

    // Block timestamp: u64 slot, i64 timestamp
    vs.last_timestamp.slot = readU64(data, &pos) orelse return null;
    vs.last_timestamp.timestamp = readI64(data, &pos) orelse return null;

    return vs;
}

// ═══════════════════════════════════════════════════════════════════════════
// SERIALIZATION: VoteState struct → raw bytes
// ═══════════════════════════════════════════════════════════════════════════

/// Serialize a VoteState struct back to raw bytes.
/// Returns the number of bytes written, or null on error.
pub fn serializeVoteState(vs: *const VoteState, out: []u8) ?usize {
    var pos: usize = 0;

    // Version
    writeU32(out, &pos, vs.version) orelse return null;

    // Pubkeys + commission
    if (out.len < pos + 65) return null;
    @memcpy(out[pos..][0..32], &vs.node_pubkey);
    pos += 32;
    @memcpy(out[pos..][0..32], &vs.authorized_withdrawer);
    pos += 32;

    // V4 extra fields
    if (vs.version == 3) {
        if (out.len < pos + 77) return null;
        @memcpy(out[pos..][0..32], &vs.inflation_rewards_collector);
        pos += 32;
        @memcpy(out[pos..][0..32], &vs.block_revenue_collector);
        pos += 32;
        std.mem.writeInt(u16, out[pos..][0..2], vs.inflation_rewards_commission_bps, .little);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], vs.block_revenue_commission_bps, .little);
        pos += 2;
        writeU64(out, &pos, vs.pending_delegator_rewards) orelse return null;
        if (vs.has_bls_pubkey_compressed) {
            out[pos] = 1;
            pos += 1;
            if (out.len < pos + 48) return null;
            @memcpy(out[pos..][0..48], &vs.bls_pubkey_compressed);
            pos += 48;
        } else {
            out[pos] = 0;
            pos += 1;
        }
    }

    // V4 has no commission byte (uses commission_bps instead)
    if (vs.version != 3) {
        out[pos] = vs.commission;
        pos += 1;
    }

    // Lockouts
    writeU64(out, &pos, @as(u64, vs.lockout_count)) orelse return null;
    for (0..vs.lockout_count) |i| {
        if (vs.version >= 2) {
            if (pos >= out.len) return null;
            out[pos] = vs.latencies[i];
            pos += 1;
        }
        writeU64(out, &pos, vs.lockouts[i].slot) orelse return null;
        writeU32(out, &pos, vs.lockouts[i].confirmation_count) orelse return null;
    }

    // Root slot
    if (pos >= out.len) return null;
    if (vs.root_slot) |root| {
        out[pos] = 1;
        pos += 1;
        writeU64(out, &pos, root) orelse return null;
    } else {
        out[pos] = 0;
        pos += 1;
    }

    // Authorized voters
    writeU64(out, &pos, @as(u64, vs.av_count)) orelse return null;
    for (0..vs.av_count) |i| {
        writeU64(out, &pos, vs.authorized_voters[i].epoch) orelse return null;
        if (out.len < pos + 32) return null;
        @memcpy(out[pos..][0..32], &vs.authorized_voters[i].pubkey);
        pos += 32;
    }

    // Prior voters (raw bytes, unchanged; v4 removed prior_voters)
    if (vs.version != 3) {
        if (out.len < pos + PRIOR_VOTERS_SIZE) return null;
        @memcpy(out[pos..][0..PRIOR_VOTERS_SIZE], &vs.prior_voters_raw);
        pos += PRIOR_VOTERS_SIZE;
    }

    // Epoch credits
    writeU64(out, &pos, @as(u64, vs.ec_count)) orelse return null;
    for (0..vs.ec_count) |i| {
        writeU64(out, &pos, vs.epoch_credits[i].epoch) orelse return null;
        writeU64(out, &pos, vs.epoch_credits[i].credits) orelse return null;
        writeU64(out, &pos, vs.epoch_credits[i].prev_credits) orelse return null;
    }

    // Block timestamp
    writeU64(out, &pos, vs.last_timestamp.slot) orelse return null;
    writeI64(out, &pos, vs.last_timestamp.timestamp) orelse return null;

    return pos;
}

// ═══════════════════════════════════════════════════════════════════════════
// SIMD-0185 V4 UP-CONVERSION (carrier #50)
// ═══════════════════════════════════════════════════════════════════════════

/// Convert a deserialized vote state of ANY version to V4 (tag 3) in-place,
/// matching Agave `try_convert_to_vote_state_v4` (handler.rs:624-666) + the
/// unconditional `target_version = V4` (vote_processor.rs:119). Agave/Firedancer
/// ALWAYS rewrite a vote account as V4 on every successful mutation once SIMD-0185
/// is active (testnet: since slot 387596256). Vexor previously serialized the
/// account back at its ORIGINAL version → a dormant tag-1/tag-2 account resuming
/// voting diverged byte-0 + whole layout from the cluster's V4 (carrier #50).
///
/// MUST be called right after deserializeVoteState and BEFORE any mutation or
/// authorized-voter update in EVERY vote-account WRITE path, so that:
///   (A) serialize always emits V4 (tag 3);
///   (B) getAndUpdateAuthorizedVoter sees version==3 → V4 purge bound
///       (current_epoch-1), keeping the previous-epoch voter (byte-blocker B);
///   (C) V1 latency garbage is zeroed (byte-blocker A).
/// Identity for an already-V4 account (Agave V4 arm = *state) → NO-OP for the 956
/// actively-voting (already-V4) accounts; cannot regress at-tip V4→V4 parity.
/// `vote_pubkey` = the vote account's OWN key (inflation_rewards_collector default).
pub fn convertToV4(vs: *VoteState, vote_pubkey: [32]u8) void {
    if (vs.version == 3) return; // already V4 — identity (Agave V4 arm: *state)

    // Byte-blocker A: V1_14_11 (version==1) carried no latency bytes; Agave
    // From<Lockout> sets latency=0. (V2/Current already carry latency.)
    if (vs.version == 1) {
        for (0..vs.lockout_count) |i| vs.latencies[i] = 0;
    }

    // SIMD-0185 default field-map (Agave handler.rs:630-659). node_pubkey /
    // authorized_withdrawer / votes / root_slot / authorized_voters /
    // epoch_credits / last_timestamp are carried over unchanged by deserialize;
    // only the NEW V4 fields get defaults:
    vs.inflation_rewards_collector = vote_pubkey; // = *vote_pubkey
    vs.block_revenue_collector = vs.node_pubkey; // = old.node_pubkey
    // = u16::from(commission).saturating_mul(100). NO clamp (commission is
    // 0..=100 in practice → bps 0..=10000); match Agave's raw saturating_mul.
    vs.inflation_rewards_commission_bps = @as(u16, vs.commission) *| @as(u16, 100);
    vs.block_revenue_commission_bps = 10_000;
    vs.pending_delegator_rewards = 0;
    vs.has_bls_pubkey_compressed = false; // bls = None
    @memset(&vs.bls_pubkey_compressed, 0);
    // prior_voters is DROPPED for V4 (serialize skips it when version==3).
    vs.version = 3; // ALWAYS emit V4 (tag 3)
}

// ═══════════════════════════════════════════════════════════════════════════
// TOWER REPLACEMENT: Full round-trip for TowerSync/UpdateVoteState
// ═══════════════════════════════════════════════════════════════════════════

/// Replace the entire lockout tower using full deserialization → mutation → re-serialization.
/// This is the correct approach matching Agave's process_new_vote_state.
///
/// Returns true if tower was replaced, false if rejected.
/// SlotHashes sysvar layout: u64 LE count + (u64 slot + [32]u8 hash) * count, newest-first.
/// Returns true if `proposed_last_slot` exists in slot_hashes AND its hash matches `proposed_hash`.
/// Returns false on any structural problem or mismatch (= reject the IX). False also if
/// `proposed_last_slot` is older than the oldest entry in slot_hashes (Agave's SlotsMismatch).
/// Recorder helper: returns the 8-byte big-endian prefix of the hash stored
/// for `target_slot` in a SlotHashes blob, or 0 if not present. Used to give
/// the recorder a comparable "what was our hash here vs what voter sent" pair
/// for SlotHashMismatch attribution. Cheap — walks the same way as
/// `slotHashesContains` but stops at slot match without comparing the hash.
fn lookupSlotHashPrefix(slot_hashes_data: []const u8, target_slot: u64) u64 {
    if (slot_hashes_data.len < 8) return 0;
    const count = std.mem.readInt(u64, slot_hashes_data[0..8], .little);
    if (count == 0) return 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const off: usize = @intCast(8 + i * 40);
        if (off + 40 > slot_hashes_data.len) return 0;
        const slot = std.mem.readInt(u64, slot_hashes_data[off..][0..8], .little);
        if (slot == target_slot) {
            return std.mem.readInt(u64, slot_hashes_data[off + 8 ..][0..8], .big);
        }
        if (slot < target_slot) return 0; // newest-first ordering: past it
    }
    return 0;
}

fn slotHashesContains(
    slot_hashes_data: []const u8,
    proposed_last_slot: u64,
    proposed_hash: *const [32]u8,
) bool {
    if (slot_hashes_data.len < 8) return false;
    const count = std.mem.readInt(u64, slot_hashes_data[0..8], .little);
    if (count == 0) return false;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const off: usize = @intCast(8 + i * 40);
        if (off + 40 > slot_hashes_data.len) return false;
        const slot = std.mem.readInt(u64, slot_hashes_data[off..][0..8], .little);
        if (slot == proposed_last_slot) {
            return std.mem.eql(u8, slot_hashes_data[off + 8 .. off + 40], proposed_hash);
        }
        // Newest-first ordering: once we pass the proposed slot, we know it's not present.
        if (slot < proposed_last_slot) return false;
    }
    return false; // walked off the end without finding
}

pub fn replaceTowerState(
    data: []u8,
    proposed_lockouts: []const Lockout,
    proposed_root: ?u64,
    timestamp: ?i64,
    current_slot: u64,
) bool {
    return replaceTowerStateChecked(data, proposed_lockouts, proposed_root, timestamp, current_slot, null, null);
}

/// r75-bug-class-d12 (2026-05-07): port of Agave's `check_and_filter_proposed_vote_state`
/// (programs/vote/src/vote_state/mod.rs:89-329). Two pre-flight checks BEFORE any
/// mutation, BOTH of which Agave runs at the top of `process_tower_sync` and which
/// abort the IX with no state mutation, no credit increment, and no rollback (atomic).
///
///   1. **VoteTooOld** (mod.rs:106-110): if `proposed_lockouts.last().slot <= current
///      vote_state.last_voted_slot`, reject — the proposed tower's tip is at-or-below
///      what's already recorded.
///   2. **SlotHashMismatch / SlotsMismatch** (mod.rs:263-304): the proposed tower's
///      tip slot must exist in SlotHashes sysvar AND its accompanying hash must match
///      that entry's hash — otherwise Agave rejects (the validator voted on a forked
///      version of that slot we don't agree with).
///
/// These were missing from Vexor's `replaceTowerState`, causing it to mutate state for
/// TowerSyncs that Agave would reject with `Custom(0)` (VoteTooOld) or `Custom(2)`
/// (SlotHashMismatch). Slot 406,444,720 carrier: account `BfXryoEG…` had 3 cluster-
/// failing TowerSyncs — Agave kept its slot-719 state; Vexor accepted IX1 and IX3,
/// mutating lockouts (offset 144-560) + credits (2180-2208) + last_timestamp.
///
/// Pass `slot_hashes_data == null` and `proposed_last_slot_hash == null` to bypass
/// these checks (legacy tests, contexts without sysvar access). Production callers in
/// `replay_stage.zig:executeVoteInstruction` MUST pass both.
/// Phase F (2026-05-17): per-reject-path counters for replaceTowerStateChecked.
/// `mutate_fail` (VoteDbg in replay_stage.zig) is a single aggregate. With 88%
/// fail rate (1.96M / 2.22M) post-Phase-E, we need to know WHICH check is
/// rejecting to design the next fix. This struct + log line breaks it down.
pub const RejectDbg = struct {
    var total: u64 = 0;
    var slot_hash_mismatch: u64 = 0;
    var ascending_fail: u64 = 0;
    var lockouts_too_many: u64 = 0;
    var empty_lockouts: u64 = 0;
    var zero_conf: u64 = 0;
    var conf_too_large: u64 = 0;
    var slot_smaller_than_root: u64 = 0;
    var slots_not_ordered: u64 = 0;
    var conf_not_ordered: u64 = 0;
    var lockout_mm: u64 = 0;
    var deser_fail: u64 = 0;
    var vote_too_old: u64 = 0;
    var root_rollback: u64 = 0;
    /// PR-5j (2026-05-18): Custom 13 — same-slot lower-confirmation reject.
    var confirmation_roll_back: u64 = 0;
    /// PR-5k (2026-05-18): Custom 6 — dropped-lockout still-locked-out reject.
    var lockout_conflict: u64 = 0;
    /// PR-5ab (2026-05-19): Custom 1 — proposed lockout slot is in SH range but
    /// not in SH (e.g., Phase-J DEAD slot referenced by deep tower).
    var slots_mismatch: u64 = 0;
    /// PR-5ag (2026-05-24): Custom 17 — proposed_root is in SH range but not in
    /// SH (root lives on a sibling fork). Agave RootOnDifferentFork (mod.rs:230).
    var root_on_different_fork: u64 = 0;
    var timestamp_too_old: u64 = 0;
    var ser_fail: u64 = 0;
    /// TIER 2 (defect C): canonical AV get_and_update returned no authorized
    /// voter for clock.epoch (av empty of any entry <= current_epoch) — Agave
    /// INVALID_ACC_DATA. EXECUTION-body reject (after the FIX#54 prologue).
    var no_auth_voter_av: u64 = 0;
    /// FIX #54 (2026-05-26): semantics changed from "actually accepted via
    /// cluster fallback" to "would have been accepted by the removed Phase
    /// G-2 fallback". Diagnostic only — votes with local mismatch are now
    /// rejected unconditionally per Agave mod.rs:292-305. A non-zero value
    /// here means the canonical reject is firing where pre-FIX #54 we'd
    /// have phantom-accepted.
    pub var cluster_fallback_accepts: u64 = 0;
};

fn rej(ctr: *u64) bool {
    ctr.* += 1;
    RejectDbg.total += 1;
    if (RejectDbg.total > 0 and RejectDbg.total % 100_000 == 0) {
        std.log.warn(
            "[VOTE-CHECK-REJECTS] total={d} slot_hash_mm={d} cluster_fb_would_accept={d} asc={d} too_many={d} empty={d} zero_conf={d} conf_too_large={d} slot_lt_root={d} slots_unord={d} conf_unord={d} lockout_mm={d} deser={d} vote_too_old={d} rollback={d} conf_rollback={d} lockout_conflict={d} slots_mm={d} rofork={d} ts_too_old={d} ser={d}",
            .{
                RejectDbg.total,                  RejectDbg.slot_hash_mismatch, RejectDbg.cluster_fallback_accepts, RejectDbg.ascending_fail,
                RejectDbg.lockouts_too_many,      RejectDbg.empty_lockouts,     RejectDbg.zero_conf,                RejectDbg.conf_too_large,
                RejectDbg.slot_smaller_than_root, RejectDbg.slots_not_ordered,  RejectDbg.conf_not_ordered,         RejectDbg.lockout_mm,
                RejectDbg.deser_fail,             RejectDbg.vote_too_old,       RejectDbg.root_rollback,            RejectDbg.confirmation_roll_back,
                RejectDbg.lockout_conflict,       RejectDbg.slots_mismatch,     RejectDbg.root_on_different_fork,   RejectDbg.timestamp_too_old,
                RejectDbg.ser_fail,
            },
        );
    }
    return false;
}

pub fn replaceTowerStateChecked(
    data: []u8,
    proposed_lockouts: []const Lockout,
    proposed_root: ?u64,
    timestamp: ?i64,
    current_slot: u64,
    slot_hashes_data: ?[]const u8,
    proposed_last_slot_hash: ?*const [32]u8,
) bool {
    return replaceTowerStateCheckedWithFallback(
        data,
        proposed_lockouts,
        proposed_root,
        timestamp,
        current_slot,
        slot_hashes_data,
        proposed_last_slot_hash,
        null,
    );
}

/// Phase G-2 (2026-05-17): same as replaceTowerStateChecked but accepts an
/// optional `cluster_slot_hashes_fallback`. When our local SlotHashes doesn't
/// contain the proposed (slot, hash), check the cluster's view as a 2nd
/// chance. Only reject if BOTH miss. Closes the cascading SlotHashMismatch
/// carrier without Phase G's bug (Phase G used cluster's view as PRIMARY
/// which broke catchup because cluster's 512-slot window doesn't cover old
/// slots).
///
/// Safety: cluster's SlotHashes is the authoritative view of canonical
/// (slot, hash) pairs. If a vote's hash matches cluster's record, it IS a
/// legitimate vote — accepting it converges our vote-state toward cluster's
/// vote-state. The check still rejects votes that miss BOTH views, so this
/// is strictly additive — no new attack surface.
pub fn replaceTowerStateCheckedWithFallback(
    data: []u8,
    proposed_lockouts: []const Lockout,
    proposed_root: ?u64,
    timestamp: ?i64,
    current_slot: u64,
    slot_hashes_data: ?[]const u8,
    proposed_last_slot_hash: ?*const [32]u8,
    cluster_slot_hashes_fallback: ?[]const u8,
) bool {
    return replaceTowerStateCheckedWithFallbackTraced(
        data,
        proposed_lockouts,
        proposed_root,
        timestamp,
        current_slot,
        slot_hashes_data,
        proposed_last_slot_hash,
        cluster_slot_hashes_fallback,
        null,
        // current_epoch=null: this wrapper preserves the legacy (test/null-filter)
        // contract — get_and_update is skipped. Production passes it via …Traced.
        null,
    );
}

/// Same as `replaceTowerStateCheckedWithFallback` but accepts an optional
/// `voter_pk` for recorder attribution. When the recorder is enabled and a
/// SlotHashMismatch event occurs (rejected or accepted-via-fallback), emits
/// a structured vote_mismatches.jsonl record so the oracle can correlate
/// vote-state divergence with specific voter pubkeys and slot/hash deltas.
pub fn replaceTowerStateCheckedWithFallbackTraced(
    data: []u8,
    proposed_lockouts: []const Lockout,
    proposed_root: ?u64,
    timestamp: ?i64,
    current_slot: u64,
    slot_hashes_data: ?[]const u8,
    proposed_last_slot_hash: ?*const [32]u8,
    cluster_slot_hashes_fallback: ?[]const u8,
    voter_pk: ?*const [32]u8,
    // TIER 2 (defect C): clock.epoch for the canonical AV get_and_update run on
    // EVERY vote (fd_vote_program.c:1333/1436/1513). `null` = skip (legacy
    // null-filter test callers). Production replay passes bank.epoch_schedule
    // .getEpoch(bank.slot). NO-OP at slot 757 (exact-hit epoch 968).
    current_epoch: ?u64,
) bool {
    // GAP G: SlotHashMismatch / SlotsMismatch (Agave mod.rs:263-304).
    // Run BEFORE deserialize so a malformed `data` doesn't even reach mutation.
    if (slot_hashes_data) |sh_data| {
        if (proposed_last_slot_hash) |proposed_hash| {
            if (proposed_lockouts.len == 0) return rej(&RejectDbg.empty_lockouts);
            const proposed_last_slot = proposed_lockouts[proposed_lockouts.len - 1].slot;
            const local_ok = slotHashesContains(sh_data, proposed_last_slot, proposed_hash);
            if (!local_ok) {
                // FIX #54 (2026-05-26): Phase G-2 removal. Agave
                // (programs/vote/src/vote_state/mod.rs:292-305) rejects
                // unconditionally on SlotHashMismatch — there is NO cluster
                // fallback acceptance in canonical. Cluster-fallback acceptance
                // was an amplifier carrier: 121,963 phantom accepts across 212
                // slots in the 2026-05-26 wedge recorder (slot 411171752+),
                // each one a state mutation Agave never performs → bank_hash
                // divergence → DELINQUENT. cluster_slot_hashes_fallback is
                // still computed below for diagnostic attribution only — we
                // no longer accept on its match.
                const cluster_ok = if (cluster_slot_hashes_fallback) |cluster_sh|
                    slotHashesContains(cluster_sh, proposed_last_slot, proposed_hash)
                else
                    false;

                // Recorder attribution (diagnostic only — does NOT accept).
                // The `accepted_via_cluster_fallback` outcome label is kept as
                // "would-have-been-accepted" signal so the oracle can still
                // measure how often the buggy fallback would have fired.
                if (voter_pk) |vk| {
                    const proposed_prefix = std.mem.readInt(u64, proposed_hash[0..8], .big);
                    const local_prefix = lookupSlotHashPrefix(sh_data, proposed_last_slot);
                    const cluster_prefix = if (cluster_slot_hashes_fallback) |cs|
                        lookupSlotHashPrefix(cs, proposed_last_slot)
                    else
                        0;
                    const outcome = if (cluster_ok)
                        recorder.VoteMismatchOutcome.accepted_via_cluster_fallback
                    else
                        recorder.VoteMismatchOutcome.rejected;
                    recorder.emitVoteMismatch(vk, proposed_last_slot, proposed_prefix, local_prefix, cluster_prefix, outcome);
                }

                if (cluster_ok) RejectDbg.cluster_fallback_accepts += 1;
                return rej(&RejectDbg.slot_hash_mismatch);
            }
        }
    }

    // Debug: track deserialization failures
    const Dbg = struct {
        var count: u32 = 0;
    };
    Dbg.count += 1;
    // Validate proposed lockouts are in ascending slot order
    if (proposed_lockouts.len > 1) {
        var i: usize = 0;
        while (i < proposed_lockouts.len - 1) : (i += 1) {
            if (proposed_lockouts[i].slot >= proposed_lockouts[i + 1].slot) {
                if (Dbg.count <= 5) {
                    std.log.debug("[VOTE-SERDE] ASCENDING FAIL i={d} len={d} slots:", .{ i, proposed_lockouts.len });
                    for (proposed_lockouts) |lk| {
                        std.log.debug(" {d}", .{lk.slot});
                    }
                    std.log.debug("\n", .{});
                }
                return rej(&RejectDbg.ascending_fail);
            }
        }
    }
    if (proposed_lockouts.len > MAX_LOCKOUT_HISTORY) return rej(&RejectDbg.lockouts_too_many);
    // Agave canonical (programs/vote/src/vote_state/mod.rs:470-473): empty
    // proposed state is asserted via assert!(!new_state.is_empty()), which
    // panics → tx fails. Mirror as fail-loud rejection here so we don't
    // mutate state for a degenerate IX.
    if (proposed_lockouts.len == 0) return rej(&RejectDbg.empty_lockouts);

    // r75-bug-class-d5 (2026-05-06): per-vote validation rules from Agave
    // canonical (programs/vote/src/vote_state/mod.rs:493-509). These three
    // rules are NEVER triggered by a real validator's well-formed TowerSync
    // (validators never emit zero-conf, >31-conf, or vote-below-root). But
    // Vexor's catchup-replay can encounter malformed/replay-residual IXs
    // that Agave silently rejects — Vexor's lack of these checks made it
    // accept them, producing 31 consecutive lockouts where oracle-node had 31
    // skip-distributed lockouts (tip-root=31 vs 35). That tower-shape diff
    // = the 42 residual divergences at slot 500.
    //
    // SAFETY: each rule mirrors Agave word-for-word; cannot reject valid
    // production TowerSyncs. Per-vote check; loops at O(31).
    for (proposed_lockouts, 0..) |vote, i| {
        if (vote.confirmation_count == 0) return rej(&RejectDbg.zero_conf);
        if (vote.confirmation_count > MAX_LOCKOUT_HISTORY) return rej(&RejectDbg.conf_too_large);
        // SlotSmallerThanRoot: per Agave mod.rs:498-508, reject if vote.slot
        // <= new_root AND new_root != 0.
        if (proposed_root) |new_root| {
            if (vote.slot <= new_root and new_root != 0) return rej(&RejectDbg.slot_smaller_than_root);
        }
        // GAP B (Agave mod.rs:511-518): inter-vote invariants.
        if (i > 0) {
            const prev = &proposed_lockouts[i - 1];
            // SlotsNotOrdered (also covered by separate ascending check above)
            if (prev.slot >= vote.slot) return rej(&RejectDbg.slots_not_ordered);
            // ConfirmationsNotOrdered: confirmation count must STRICTLY decrease
            // as we walk down the tower (older votes deeper). Catches malformed
            // TowerSyncs whose conf_count is non-monotonic.
            if (prev.confirmation_count <= vote.confirmation_count) return rej(&RejectDbg.conf_not_ordered);
            // NewVoteStateLockoutMismatch: vote.slot must NOT exceed prev's
            // last_locked_out_slot (= prev.slot + 2^prev.confirmation_count).
            // last_locked_out is the latest slot prev's lockout extends to.
            const shift = @min(prev.confirmation_count, 63);
            const prev_locked_out = prev.slot +| (@as(u64, 1) << @intCast(shift));
            if (vote.slot > prev_locked_out) return rej(&RejectDbg.lockout_mm);
        }
    }

    // Step 1: Deserialize
    var vs = deserializeVoteState(data) orelse {
        if (Dbg.count <= 3) {
            std.log.debug("[VOTE-SERDE] deserialize FAILED for data_len={d}\n", .{data.len});
        }
        return rej(&RejectDbg.deser_fail);
    };

    // SIMD-0185 (carrier #50): up-convert to V4 IMMEDIATELY after deserialize and
    // BEFORE getAndUpdateAuthorizedVoter / tower processing — so serialize emits V4
    // (tag 3) and the AV purge below uses the V4 bound (ce-1). `voter_pk` here is the
    // vote ACCOUNT's own key (replay_stage passes &account_keys[vote_acct_idx]), which
    // is exactly inflation_rewards_collector's default. Identity for already-V4
    // accounts (no-op for the active set; cannot regress at-tip V4 parity). `null` only
    // for legacy null-filter test callers → skip (those assert pre-V4 round-trip).
    if (voter_pk) |vp| convertToV4(&vs, vp.*);

    // TIER 2 (defect C): canonical AV get_and_update on EVERY vote, run BEFORE
    // tower processing (Agave mod.rs:1224/1248/1299 do_process_*; FD
    // fd_vote_program.c:1333/1436/1513). Carry-forward + epoch-bounded purge on
    // `vs` (persisted iff the IX serializes & commits below). Inserted in the
    // EXECUTION body — AFTER the FIX#54 SlotHashes prologue (lines ~790-835),
    // never inside it. NO-OP at slot 757 (exact-hit epoch 968). `null` skips
    // (legacy null-filter test callers).
    if (current_epoch) |ce| {
        if (!getAndUpdateAuthorizedVoter(&vs, ce)) return rej(&RejectDbg.no_auth_voter_av);
    }

    // GAP G: VoteTooOld (Agave mod.rs:106-110). Run AFTER deserialize so we have
    // access to `vs.lastVotedSlot()`. Reject if proposed tower's tip <= current.
    // Only applies when the SlotHash filter was enabled (i.e. production caller
    // path); legacy null-filter callers skip to preserve existing test contracts.
    if (slot_hashes_data != null and proposed_last_slot_hash != null) {
        const proposed_last_slot = proposed_lockouts[proposed_lockouts.len - 1].slot;
        if (vs.lastVotedSlot()) |cur_last| {
            if (proposed_last_slot <= cur_last) return rej(&RejectDbg.vote_too_old);
        }
    }

    // r75-bug-class-d-root-rollback: Agave's process_new_vote_state
    // (programs/vote/src/vote_state/mod.rs:475-485) rejects any TowerSync
    // whose proposed_root is below the current root, OR proposed_root is
    // None when current root is Some, with VoteError::RootRollBack. Without
    // this check Vexor accepted fork-rolling rollback TowerSyncs that
    // mutate state with junk lockouts, then the FOLLOWING TowerSync at the
    // same bank slot saw a corrupted old tower → preservation lookup
    // missed for slots that got dropped by the rollback → fresh latency
    // recomputation = bank.slot - lk.slot for slots that should have been
    // preserved at lat=1. Empirically observed at testnet slot 406443276
    // for LiFi (050cae56…): 1st TowerSync had proposed_root=241 < current
    // root=243; Vexor accepted, mutated to junk state with lat=34/33; 2nd
    // TowerSync at same slot then re-added slots 273/274/275 with lat=3/2/1.
    // This was the carrier behind 10 V4 vote-account data hash divergences
    // at slot 300.
    if (vs.root_slot) |current_root| {
        if (proposed_root) |new_root| {
            if (new_root < current_root) return rej(&RejectDbg.root_rollback);
        } else {
            // proposed_root None while current_root Some → rollback.
            return rej(&RejectDbg.root_rollback);
        }
    }

    // PR-5u (2026-05-19): port of `check_and_filter_proposed_vote_state` FILTER
    // step (Agave programs/vote/src/vote_state/mod.rs:124-329 + Firedancer
    // fd_vote_program.c:194-330). The earlier d12 port (a95b8a6) added the
    // VoteTooOld + SlotHashMismatch REJECTION paths but never wired the
    // FILTERING / CLAMPING step — line 930 aliased `filtered_lockouts =
    // proposed_lockouts` verbatim. Effect at testnet slot 409440662: validators
    // with deep towers (lockouts older than the 512-slot SlotHashes window)
    // sent TowerSync IXs where:
    //   - Agave clamps proposed_root to a tower entry < earliest_slot_hash AND
    //   - Agave filters proposed_lockouts entries whose slot < earliest AND
    //     not already in current vote_state.votes
    // Vexor's pre-PR-5u code accepted the IX as-is → mutated vote-state with
    // extra (filterable) lockouts → byte-divergent vote-account post-state →
    // lthash diverged per-slot → bank_hash diverged per-slot.
    //
    // Implementation: build `filtered_lockouts_buf` once, propagate it through
    // PR-5j (confirmation_roll_back), PR-5k (lockout_conflict), and the
    // downstream apply loop. Same for `filtered_root_local`.
    //
    // Refs: Agave 4.0.0-rc.0 mod.rs:89-329; Firedancer fd_vote_program.c:154-330;
    //       memory project_pr5j_pr5k_landed_hyperlane_carrier_2026_05_18.
    var filtered_lockouts_buf: [MAX_LOCKOUT_HISTORY]Lockout = undefined;
    var filtered_count: usize = 0;
    var filtered_root_local: ?u64 = proposed_root;
    if (slot_hashes_data) |sh_data| filter_block: {
        // Read earliest_slot_hash_in_history (slot of OLDEST entry = last in
        // SlotHashes layout: [count u64][entries: (slot u64, hash [32]u8)...]).
        if (sh_data.len < 8) break :filter_block;
        const sh_count = std.mem.readInt(u64, sh_data[0..8], .little);
        if (sh_count == 0) break :filter_block;
        const sh_count_usize: usize = @intCast(sh_count);
        const last_off = 8 + (sh_count_usize - 1) * 40;
        if (sh_data.len < last_off + 8) break :filter_block;
        const earliest_slot_hash_in_history = std.mem.readInt(u64, sh_data[last_off..][0..8], .little);

        // Step 1: clamp proposed_root if < earliest_slot_hash (Agave 124-142).
        // First overwrite with vote_state.root_slot; then if any current
        // vote_state lockout has slot <= proposed_root, use the latest such.
        if (proposed_root) |orig_root| {
            if (orig_root < earliest_slot_hash_in_history) {
                filtered_root_local = vs.root_slot;
                // Walk current lockouts in reverse (highest first).
                var ci: usize = vs.lockout_count;
                while (ci > 0) {
                    ci -= 1;
                    if (vs.lockouts[ci].slot <= orig_root) {
                        filtered_root_local = vs.lockouts[ci].slot;
                        break;
                    }
                }
            }
        }

        // Step 2: filter proposed_lockouts (Agave 198-205, 308-323). Drop
        // entries with slot < earliest_slot_hash_in_history that are ALSO
        // not present in current vote_state.votes (vs.lockouts).
        for (proposed_lockouts) |new_lk| {
            const keep = blk: {
                if (new_lk.slot >= earliest_slot_hash_in_history) break :blk true;
                // Too old — keep only if already in vs.lockouts.
                for (vs.lockouts[0..vs.lockout_count]) |cur_lk| {
                    if (cur_lk.slot == new_lk.slot) break :blk true;
                }
                break :blk false;
            };
            if (keep) {
                if (filtered_count >= MAX_LOCKOUT_HISTORY) break :filter_block;
                filtered_lockouts_buf[filtered_count] = new_lk;
                filtered_count += 1;
            }
        }
        // If we filtered everything out, treat as empty (caller already
        // covered by the empty_lockouts reject at line 749 but that ran on
        // the unfiltered list; mirror Agave's EmptySlots behavior here).
        if (filtered_count == 0) return rej(&RejectDbg.empty_lockouts);

        // PR-5ag (2026-05-24): RootOnDifferentFork (Custom 17) MEMBERSHIP check.
        //
        // Agave's check_and_filter_proposed_vote_state walks the proposed_root
        // FIRST in its dual-cursor merge (mod.rs:147-260, `root_to_check`).
        // After the PR-5u too-old clamp, if the (clamped) root is in the SH
        // range [earliest, newest] but is NOT itself present in SH, the root
        // lives on a sibling fork → Agave returns `RootOnDifferentFork`
        // (mod.rs:229-230) and does NOT mutate. Roots BELOW earliest are
        // handled by the clamp (mod.rs:124-142), never reach this arm.
        //
        // Pre-PR-5ag Vexor validated lockout membership (PR-5ab) and the
        // proposed_last_slot+hash (Gap G) but NEVER the root, so it ACCEPTED
        // these TowerSyncs → phantom vote-state write absent from Agave's
        // writeset → lthash + bank_hash divergence cascade.
        //
        // Empirical carrier (HIGH-confidence, 3-way verified 2026-05-24:
        // decoded IX bytes via RPC + Vexor check-sequence simulation on real
        // prior-state + line-by-line Agave 4.0.0 walk): testnet slot
        // 410648248 tx_idx=336, voter BfXryoEG8XEsdi4YBpSA7iWgs2BZfVxBM6xXCnreDC8n,
        // proposed_root=410648214 — the ONLY slot missing from SH[212..247]
        // (skipped/dead on the canonical fork). Agave → Custom(17); Vexor
        // pre-fix accepted → phantom write seeding the divergence at 248.
        //
        // Scope: strictly ADDITIVE, same shape as PR-5ab (order-independent
        // descending binary search). Only adds rejections Agave also makes;
        // never changes the PR-5u filter outcome. Does NOT reintroduce PR-5i's
        // full-dual-cursor ordering regression.
        if (filtered_root_local) |root_check| {
            if (root_check >= earliest_slot_hash_in_history) {
                var rlo: usize = 0;
                var rhi: usize = sh_count_usize;
                var root_found = false;
                while (rlo < rhi) {
                    const rmid = rlo + (rhi - rlo) / 2;
                    const rmid_off = 8 + rmid * 40;
                    const rmid_slot = std.mem.readInt(u64, sh_data[rmid_off..][0..8], .little);
                    if (rmid_slot == root_check) {
                        root_found = true;
                        break;
                    }
                    if (rmid_slot > root_check) {
                        rlo = rmid + 1;
                    } else {
                        rhi = rmid;
                    }
                }
                if (!root_found) return rej(&RejectDbg.root_on_different_fork);
            }
        }

        // PR-5ab (2026-05-19): SlotHashes MEMBERSHIP check.
        //
        // After Step 2 filtering, every kept lockout with slot >=
        // earliest_slot_hash_in_history MUST be present in SlotHashes. If a
        // slot is in the SH range [earliest, newest] but NOT in SH, it was
        // skipped on cluster's fork (e.g., Phase-J DEAD slot or sibling-fork
        // miss). Vote-state mutation on such a vote would diverge from
        // cluster — cluster rejects with Custom 1 (SlotsMismatch); we must
        // match.
        //
        // Empirical carrier: testnet slot 409551518 tx[39] voter
        // `41AxBRZvzxx7D5feBye9mNckJFv6Lbbfcboz2eSb9MF9` TowerSync included
        // lockout[28] slot=409551512 — a Phase-J DEAD slot (skipped 512-515).
        // SH at 518 spans [earliest, 517] with 512-515 missing. Cluster
        // getBlock(409551518): err `Custom(1)`. Vexor pre-PR-5ab accepted
        // and produced one phantom vote-state write — sole vex-only pk in
        // Agave's bank_hash_details diff. Bug magnitude 0x651452c3813bc959
        // initiated a 3500+ slot lthash chain contamination (carrier F).
        //
        // Scope: surgical addition. Mirrors only the SlotsMismatch arm of
        // Agave's `check_and_filter_proposed_vote_state` dual-cursor walk
        // (`programs/vote/src/vote_state/mod.rs:225-233`); does NOT replicate
        // the filter logic that PR-5u already implements. PR-5i (2026-05-15)
        // ported the FULL walk and catastrophically regressed parity
        // (mutate_fail=246799 ok=0); PR-5ab is strictly additive — runs
        // after PR-5u filter, only ADDS rejections, never changes filter
        // outcomes.
        //
        // SH layout: [count u64][entries: (slot u64, hash [32]u8)...] sorted
        // DESCENDING by slot (SH[0]=newest, SH[count-1]=oldest). Binary
        // search:
        //   - SH[mid] > target → target is LATER (higher idx) → lo = mid+1
        //   - SH[mid] < target → target is EARLIER (lower idx) → hi = mid
        var k: usize = 0;
        while (k < filtered_count) : (k += 1) {
            const slot = filtered_lockouts_buf[k].slot;
            if (slot < earliest_slot_hash_in_history) continue; // legacy in vs.lockouts; skip
            var lo: usize = 0;
            var hi: usize = sh_count_usize;
            var found = false;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                const mid_off = 8 + mid * 40;
                const mid_slot = std.mem.readInt(u64, sh_data[mid_off..][0..8], .little);
                if (mid_slot == slot) {
                    found = true;
                    break;
                }
                if (mid_slot > slot) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if (!found) return rej(&RejectDbg.slots_mismatch);
        }
    } else {
        // No SlotHashes context (test paths) — pass through unfiltered.
        if (proposed_lockouts.len > MAX_LOCKOUT_HISTORY) return rej(&RejectDbg.lockouts_too_many);
        for (proposed_lockouts, 0..) |lk, i| filtered_lockouts_buf[i] = lk;
        filtered_count = proposed_lockouts.len;
    }
    const proposed_lockouts_after_filter: []const Lockout = filtered_lockouts_buf[0..filtered_count];

    // PR-5j (2026-05-18): VoteError.confirmation_roll_back (Custom 13).
    // Port of the same-slot check from Sig state.zig:2522-2529 (= Agave
    // process_new_vote_state). When a proposed lockout has the SAME slot as
    // an existing landed lockout, the proposed confirmation_count MUST NOT
    // be lower than current — otherwise the voter is rolling back a prior
    // confirmation, which is invalid per consensus.
    //
    // Empirical carrier: first divergent slot 409308456 (Vexor boot
    // 1779140004). Per-pubkey lthash diff vs cluster ledger-tool
    // bank_hash_details: 1125 match / 0 diff / 1 vex_only. The vex_only pk
    // 5KDxhfG5uZn4zzGBNj3pfJEnK6hYvbZqaSXc9JCmDgUF maps to tx[181] which
    // cluster rejected with InstructionError Custom 13. Vexor's wholesale
    // overwrite at line 873-886 below succeeded → phantom write → lthash
    // delta → cascading bank_hash divergence from this slot onward.
    //
    // Scope: ONLY the confirmation_roll_back reject. The nested O(n²) match
    // (max 31×31 = 961 cmps/vote) is order-independent, sidestepping PR-5i's
    // 100%-rejection failure (PR-5i 2026-05-15 ported the full dual-cursor
    // walk which assumed ascending ordering matching Sig's `self.votes.items`
    // convention — that triggered mutate_fail=246799 ok=0 at boot, root
    // cause unlocalized, code reverted). lockout_conflict (Custom 6) is a
    // separate code shape (`.lt` branch of Sig's dual cursor) and is held
    // for a future PR after this carrier closes and any next first-divergent
    // exposes it as still-extant.
    //
    // Safety: per Vexor's existing ConfirmationsNotOrdered check at line 774
    // (strict-decreasing conf as slot ascends), `proposed_lockouts` and
    // `vs.lockouts[0..lockout_count]` both have strictly decreasing
    // confirmation_count along ascending slot, so the same-slot case here
    // is unambiguous: exactly one pair (if any) shares a slot, and the
    // proposed conf must be ≥ current conf.
    for (proposed_lockouts_after_filter) |new_lk| {
        for (vs.lockouts[0..vs.lockout_count]) |cur_lk| {
            if (cur_lk.slot == new_lk.slot) {
                if (new_lk.confirmation_count < cur_lk.confirmation_count) {
                    return rej(&RejectDbg.confirmation_roll_back);
                }
                break;
            }
        }
    }

    // PR-5k (2026-05-18, fixed 2026-05-18 ~18:25 MDT):
    // VoteError.lockout_conflict (Custom 6).
    // Port of Sig state.zig:2512-2521 `.lt` arm. When a current lockout is
    // being dropped from the tower (no same-slot match in proposed) AND
    // there exists at least one proposed lockout with greater slot, the
    // current lockout's last-locked-out slot MUST be strictly less than
    // that greater proposed slot — else the validator is dropping a still-
    // locked vote, violating Tower BFT.
    //
    // CRITICAL: skip current lockouts whose slot <= proposed_root. Those
    // are being ROOTED by this vote and are LEGITIMATELY dropped from the
    // active tower (they move into self.root_slot). Per Agave canonical
    // (programs/vote/src/vote_state/mod.rs:570-572 and Sig state.zig's
    // checkAndFilterProposedVoteState preflight): when proposed_root is
    // set, the current tower entries at-or-below the new root are popped
    // BEFORE the dual-cursor merge runs, so the .lt arm never sees them.
    //
    // Without this filter, ANY tower-update that roots a previously-deep
    // vote (conf>=20, lastLockedOut > all subsequent active slots) trips
    // the check on the SAME-fork case where it should pass. Empirically:
    // first PR-5k deploy showed RejectDbg.lockout_conflict=723,775 out of
    // 1,500,000 total vote rejects — that's ~48% of votes wrongly rejected
    // because every well-formed root-and-vote tx hit the missing-filter
    // path.
    //
    // Same nested-loop shape as PR-5j (order-independent).
    for (vs.lockouts[0..vs.lockout_count]) |cur_lk| {
        // Skip lockouts being rooted by this vote — they're legitimately
        // dropped from the active tower. PR-5u: use clamped root.
        if (filtered_root_local) |new_root| {
            if (cur_lk.slot <= new_root) continue;
        }
        var has_same_slot = false;
        var min_greater_new_slot: ?u64 = null;
        for (proposed_lockouts_after_filter) |new_lk| {
            if (new_lk.slot == cur_lk.slot) {
                has_same_slot = true;
                break;
            }
            if (new_lk.slot > cur_lk.slot) {
                if (min_greater_new_slot == null or new_lk.slot < min_greater_new_slot.?) {
                    min_greater_new_slot = new_lk.slot;
                }
            }
        }
        if (!has_same_slot) {
            if (min_greater_new_slot) |next_new_slot| {
                const shift: u6 = @intCast(@min(cur_lk.confirmation_count, 63));
                const cur_last_locked = cur_lk.slot +| (@as(u64, 1) << shift);
                if (cur_last_locked >= next_new_slot) {
                    return rej(&RejectDbg.lockout_conflict);
                }
            }
        }
    }

    // PR-5u (2026-05-19): pass filter+clamp output to the apply step. Pre-PR-5u
    // these aliases pointed at the unfiltered parameter slices, defeating the
    // check_and_filter port. See PR-5u block above for full reasoning.
    const filtered_lockouts: []const Lockout = proposed_lockouts_after_filter;
    const filtered_root: ?u64 = filtered_root_local;

    // Save old lockout state for credit calculation
    const old_lockout_count = vs.lockout_count;
    var old_lockouts: [MAX_LOCKOUT_HISTORY]Lockout = undefined;
    var old_latencies: [MAX_LOCKOUT_HISTORY]u8 = undefined;
    for (0..old_lockout_count) |i| {
        old_lockouts[i] = vs.lockouts[i];
        if (vs.version >= 2) old_latencies[i] = vs.latencies[i];
    }

    // Step 2: Replace tower lockouts
    //
    // r71 lthash carrier fix: Agave's process_new_vote_state preserves latency
    // for slots that already exist in the old tower; only newly-landed slots
    // get a freshly-computed latency. See agave/programs/vote/src/vote_state/
    // mod.rs:521-622 — "Copy the vote slot latency in from the current state
    // to the new state" + final loop "for new_vote in new_state.iter_mut() {
    // if new_vote.latency == 0 { new_vote.latency = compute_vote_latency(...) }
    // }". Pre-r71 Vexor recomputed latency for EVERY tower entry on every
    // vote, producing latencies (1,2,3,…N) instead of Agave's mostly-1 values
    // — every Vote111 write byte-diverged in offsets 153-552 (LandedVote
    // tower latency byte) and the lthash diverged on every replayed slot.
    // Same-slot diff at 404,692,482 named the carrier (vault/diag/r71/
    // CARRIER_NAMED_VOTE_BYTE_SERIALIZATION.md).
    // r75-bug-class-d5 (2026-05-06): port Agave's TWO-PASS latency structure
    // from mod.rs:595-596 (Equal arm copies old latency) + 621-625 (final pass
    // recomputes any latency still 0). Pre-fix Vexor used single-pass
    // `preserved orelse compute(...)` which preserved Some(0) old latencies
    // forever, leaking through creditsForVote(0)=1 vs canonical 14-16 at next
    // root. Manifested as 42 residual vote-account divergences at slot 500
    // after credit-accounting fix closed 531/573 — the residual carrier was
    // these legacy-zero latencies on top-staker accounts whose old tower had
    // stored latency=0 from earlier vote_state migrations.
    //
    // Pass 1: for each new lockout, copy old latency by slot match (or 0 if
    //         no match — matches Agave's LandedVote::from(Lockout) init).
    vs.lockout_count = @intCast(filtered_lockouts.len);
    for (filtered_lockouts, 0..) |lk, idx| {
        vs.lockouts[idx] = lk;
        if (vs.version >= 2) {
            var preserved: u8 = 0;
            for (0..old_lockout_count) |oi| {
                if (old_lockouts[oi].slot == lk.slot) {
                    preserved = old_latencies[oi];
                    break;
                }
            }
            vs.latencies[idx] = preserved;
        }
    }
    // Pass 2 (Agave mod.rs:621-625): recompute any latency that is still 0.
    // This catches BOTH (a) genuinely new slots (no old match) AND (b) slots
    // whose stored old latency was 0 (legacy migration / pre-timely-vote-credit
    // accounts). The single-pass form leaked case (b).
    if (vs.version >= 2) {
        for (0..vs.lockout_count) |idx| {
            if (vs.latencies[idx] == 0) {
                vs.latencies[idx] = @intCast(@min(current_slot -| vs.lockouts[idx].slot, 255));
            }
        }
    }

    // Step 3: Replace root and increment credits for ROOTED lockouts only.
    //
    // r75-bug-class-d4 (2026-05-06): byte-exact port of Agave canonical
    // (programs/vote/src/vote_state/mod.rs:528-548 + 627-632). Pre-fix Vexor
    // counted credit for any old lockout above old_root that wasn't in new
    // tower — including lockouts popped by FORK CONFLICT (where new_vote.slot
    // < current_vote.lockout.last_locked_out_slot, mod.rs:578-587). Agave
    // ONLY credits slots that get ROOTED (slot ≤ new_root). The fork-conflict
    // pop case has no credit because that vote never reached finality. Vexor's
    // over-credit accumulated ~+0.x credits per slot per voting validator,
    // manifesting as 573 vote-account data hash divergences at slot 500
    // (epoch_credits LSB byte drift growing over time).
    var credits_earned: u64 = 0;
    if (filtered_root) |new_root| {
        // Iterate old lockouts in ascending order. Solana invariant: lockouts
        // are sorted by slot, so once we hit a slot > new_root we stop —
        // no later lockout can be at-or-below new_root.
        for (0..old_lockout_count) |li| {
            if (old_lockouts[li].slot > new_root) break;
            // Timely vote credits: use latency for v2+ (Current/V4) accounts.
            if (vs.version >= 2 and li < MAX_LOCKOUT_HISTORY) {
                credits_earned += creditsForVote(old_latencies[li]);
            } else {
                credits_earned += 1;
            }
        }
    }

    // Agave mod.rs:627-632: only call increment_credits when the root actually
    // changed. Compare the OLD root (vs.root_slot, not yet overwritten) with
    // the NEW proposed root.
    const root_changed = blk: {
        if (vs.root_slot) |old_r| {
            if (filtered_root) |new_r| break :blk new_r != old_r;
            break :blk true; // old=Some, new=None (shouldn't happen due to RootRollBack check)
        } else {
            break :blk filtered_root != null;
        }
    };
    if (root_changed) {
        // FIX-2: clock.epoch semantics — Agave increment_credits(epoch_from
        // (clock)) where clock.epoch = bank.epoch_schedule.get_epoch(slot).
        // Production threads `current_epoch` (replay_stage passes
        // bank.epoch_schedule.getEpoch(bank.slot)); the DEFAULT-schedule
        // fallback serves only legacy null-epoch test wrappers
        // (replaceTowerState / replaceTowerStateChecked) and is the same
        // canonical math, not a divergent hardcode.
        const epoch = current_epoch orelse epoch_schedule_mod.EpochSchedule.DEFAULT.getEpoch(current_slot);
        vs.incrementCredits(epoch, credits_earned);
    }
    vs.root_slot = filtered_root;

    // Step 4: Update timestamp if provided.
    // PR-5h (2026-05-15): port Agave process_timestamp validation
    // (handler.rs:172-183). Reject the entire mutation by returning false
    // (caller doesn't commit data write — matches Agave's atomic revert)
    // when the proposed timestamp violates monotonicity vs the existing
    // last_timestamp. Pre-PR-5h, Vexor unconditionally overwrote last_timestamp
    // — which silently mutated 16 tail bytes when a TowerSync arrived with
    // stale or out-of-order timestamps that Agave would have rejected. Carrier
    // surfaced at slot 408486017 (vote-state data byte divergence with all
    // pubkey/lamports/dlen/owner matching cluster).
    if (timestamp) |ts| {
        const proposed_slot: u64 = if (filtered_lockouts.len > 0)
            filtered_lockouts[filtered_lockouts.len - 1].slot
        else
            current_slot;
        const last = vs.last_timestamp;
        const reject = (proposed_slot < last.slot or ts < last.timestamp) or
            (proposed_slot == last.slot and ts != last.timestamp and last.slot != 0);
        if (reject) {
            return rej(&RejectDbg.timestamp_too_old); // VoteError::TimestampTooOld — abort entire instruction
        }
        vs.last_timestamp = .{
            .slot = proposed_slot,
            .timestamp = ts,
        };
    }

    // Step 5: Re-serialize entire state back to buffer
    const written = serializeVoteState(&vs, data) orelse {
        if (Dbg.count <= 6) {
            std.log.debug("[VOTE-SERDE] serialize FAILED version={d} lockouts={d} data_len={d}\n", .{
                vs.version, vs.lockout_count, data.len,
            });
        }
        return rej(&RejectDbg.ser_fail);
    };
    // Zero remaining bytes only for v1/v2 — v4 accounts have a tail of old
    // prior_voters data from v3→v4 migration that must be preserved for LtHash.
    if (vs.version != 3 and written < data.len) {
        @memset(data[written..], 0);
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// SIMPLE VOTE APPEND: For old Vote/VoteSwitch instructions
// Also uses round-trip to avoid surgical offset issues on root promotion
// ═══════════════════════════════════════════════════════════════════════════

/// TIER 2 (defect C): run the canonical AV get_and_update ONCE on `data` for a
/// Vote/VoteSwitch instruction. Agave/FD run get_and_update a single time per
/// instruction (mod.rs runs it before do_process_*); `applyVoteToState` is
/// called per-slot in the Vote loop, so we hoist get_and_update here to avoid
/// re-running it per slot. Deserialize → mutate AV → re-serialize, preserving
/// the v4 leftover tail. Returns false on the no-voter reject (Agave
/// INVALID_ACC_DATA) so the caller aborts the whole IX with no state change.
pub fn applyAuthorizedVoterUpdate(data: []u8, current_epoch: u64) bool {
    var vs = deserializeVoteState(data) orelse return false;
    if (!getAndUpdateAuthorizedVoter(&vs, current_epoch)) return false;
    const written = serializeVoteState(&vs, data) orelse return false;
    if (vs.version != 3 and written < data.len) @memset(data[written..], 0);
    return true;
}

/// Apply a single vote to the tower (for old Vote/VoteSwitch instructions).
/// Correct Tower BFT order (matches Agave's process_vote_unchecked):
///   1. Pop expired lockouts from the front (lockout_expiry = slot + 2^confirmation_count)
///   2. Increment confirmation_count for ALL remaining lockouts by 1 ("double lockouts")
///   3. Push new lockout with confirmation_count = 1
/// Returns true if the vote was applied, false if rejected (VoteTooOld etc.)
///
/// FIX-2 (2026-06-10): `current_epoch` is THREADED from the caller
/// (clock.epoch = bank.epoch_schedule.getEpoch(bank.slot)); `null` (legacy
/// test callers) falls back to the canonical DEFAULT schedule. Replaces the
/// deleted hardcoded slotToEpoch helper.
pub fn applyVoteToState(data: []u8, vote_slot: u64, current_slot: u64, timestamp: ?i64, current_epoch: ?u64) bool {
    // Deserialize
    var vs = deserializeVoteState(data) orelse return false;

    // VoteTooOld check
    if (vs.lockout_count > 0) {
        if (vote_slot <= vs.lockouts[vs.lockout_count - 1].slot) return false;
    }

    const epoch = current_epoch orelse epoch_schedule_mod.EpochSchedule.DEFAULT.getEpoch(current_slot);

    // Step 1: Pop expired lockouts from the FRONT (oldest first).
    // A lockout at slot S with confirmation_count C expires when:
    //   vote_slot >= S + 2^C
    while (vs.lockout_count > 0) {
        const lk = vs.lockouts[0];
        const shift_amt: u6 = @intCast(@min(lk.confirmation_count, 63));
        const lockout_expiry = lk.slot +| (@as(u64, 1) << shift_amt);
        if (vote_slot >= lockout_expiry) {
            // Expired — promote to root, earn credit (timely credits for v2)
            vs.root_slot = lk.slot;
            if (vs.version >= 2) {
                vs.incrementCredits(epoch, creditsForVote(vs.latencies[0]));
            } else {
                vs.incrementCredits(epoch, 1);
            }
            // Shift remaining lockouts left
            var j: u32 = 0;
            while (j < vs.lockout_count - 1) : (j += 1) {
                vs.lockouts[j] = vs.lockouts[j + 1];
                if (vs.version >= 2) vs.latencies[j] = vs.latencies[j + 1];
            }
            vs.lockout_count -= 1;
            // Don't break — re-check position 0 with the next lockout
        } else {
            break; // Lockouts are ordered; if this one hasn't expired, none after have
        }
    }

    // Step 2: Increment confirmation_count for ALL remaining lockouts by 1.
    // This is Agave's "double_lockouts()" — the lockout DURATION doubles (2^count),
    // but confirmation_count itself increments by 1.
    {
        var idx: u32 = 0;
        while (idx < vs.lockout_count) : (idx += 1) {
            vs.lockouts[idx].confirmation_count += 1;
        }
    }

    // Step 3: If tower is full after pops, force-promote bottom to root
    if (vs.lockout_count >= MAX_LOCKOUT_HISTORY) {
        vs.root_slot = vs.lockouts[0].slot;
        if (vs.version >= 2) {
            vs.incrementCredits(epoch, creditsForVote(vs.latencies[0]));
        } else {
            vs.incrementCredits(epoch, 1);
        }
        var j: u32 = 0;
        while (j < vs.lockout_count - 1) : (j += 1) {
            vs.lockouts[j] = vs.lockouts[j + 1];
            if (vs.version >= 2) vs.latencies[j] = vs.latencies[j + 1];
        }
        vs.lockout_count -= 1;
    }

    // Step 4: Push new lockout with confirmation_count = 1
    vs.lockouts[vs.lockout_count] = .{
        .slot = vote_slot,
        .confirmation_count = 1,
    };
    if (vs.version >= 2) {
        vs.latencies[vs.lockout_count] = @intCast(@min(current_slot -| vote_slot, 255));
    }
    vs.lockout_count += 1;

    // Update timestamp
    if (timestamp) |ts| {
        vs.last_timestamp = .{ .slot = vote_slot, .timestamp = ts };
    }

    // Re-serialize
    const written = serializeVoteState(&vs, data) orelse return false;
    // Preserve tail for v4 accounts (old prior_voters data is part of LtHash)
    if (vs.version != 3 and written < data.len) {
        @memset(data[written..], 0);
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// QUERY HELPERS (read-only, no deserialization needed)
// ═══════════════════════════════════════════════════════════════════════════

/// Read the version discriminant from raw vote account data
pub fn getVersion(data: []const u8) ?u32 {
    if (data.len < 4) return null;
    return std.mem.readInt(u32, data[0..4], .little);
}

/// Get the last voted slot from raw vote account data (quick read without full deserialization).
///
/// Layouts (Phase-2 fork-choice feed needs this for V4 accounts — SIMD-0185 active
/// on testnet since slot 387,596,256; mainnet at activation time). Each variant
/// places the lockout-count u64 at a different offset:
///
///   V1 (version=1, V1_14_11):  4 + 32 + 32 + 1 (commission) = offset 69
///       lockout entries are 12 bytes each (slot u64 + conf_count u32, NO latency).
///   V2 (version=2, "Current"): 4 + 32 + 32 + 1 (commission) = offset 69
///       lockout entries are 13 bytes each (latency u8 + slot u64 + conf_count u32).
///   V4 (version=3, SIMD-0185): 4 + 32 + 32 + V4_extras = offset 145 (no BLS) or 193 (with BLS)
///       V4_extras = 32 (inflation_rewards_collector) + 32 (block_revenue_collector)
///                 + 2 (inflation_rewards_commission_bps) + 2 (block_revenue_commission_bps)
///                 + 8 (pending_delegator_rewards) + 1 (has_bls) [+ 48 (bls_pubkey)]
///                 = 77 or 125 bytes. V4 has NO commission byte (replaced by commission_bps).
///       Lockout entries are 13 bytes each (same as V2 — latency u8 + slot u64 + conf_count u32).
///
/// Returns null on any layout violation. Returns the most-recently-voted slot
/// (the highest-indexed lockout entry's slot field).
pub fn getLastVotedSlot(data: []const u8) ?u64 {
    if (data.len < 4) return null;
    const version = std.mem.readInt(u32, data[0..4], .little);
    if (version != 1 and version != 2 and version != 3) return null;

    // Cursor advance: version(4) + node_pubkey(32) + auth_withdrawer(32) = 68.
    var pos: usize = 68;

    if (version == 3) {
        // V4 extras layout (mirrors deserializeVoteState 290-326).
        // inflation_rewards_collector(32) + block_revenue_collector(32)
        // + inflation_rewards_commission_bps(2) + block_revenue_commission_bps(2)
        // + pending_delegator_rewards(8) + has_bls(1) [+ bls_pubkey(48) if has_bls]
        // NO commission byte (replaced by *_commission_bps fields above).
        if (data.len < pos + 32 + 32 + 2 + 2 + 8 + 1) return null;
        pos += 32 + 32 + 2 + 2 + 8;
        const has_bls = data[pos] != 0;
        pos += 1;
        if (has_bls) {
            if (data.len < pos + 48) return null;
            pos += 48;
        }
    } else {
        // V1/V2: 1-byte commission.
        if (data.len < pos + 1) return null;
        pos += 1;
    }

    // Lockout count (u64).
    if (data.len < pos + 8) return null;
    const count = std.mem.readInt(u64, data[pos..][0..8], .little);
    pos += 8;
    if (count == 0 or count > 32) return null; // Tower depth ≤31; allow 32 for safety.

    const lockout_size: usize = if (version == 1) 12 else 13;
    const last_idx: usize = @intCast(count - 1);
    const last_offset = pos + last_idx * lockout_size;

    if (version >= 2) {
        // V2/V4: skip leading latency byte to reach slot u64.
        if (data.len < last_offset + 1 + 8) return null;
        return std.mem.readInt(u64, data[last_offset + 1 ..][0..8], .little);
    } else {
        // V1: slot u64 is at the start of the lockout entry.
        if (data.len < last_offset + 8) return null;
        return std.mem.readInt(u64, data[last_offset..][0..8], .little);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BINARY READ/WRITE HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn readU32(data: []const u8, pos: *usize) ?u32 {
    if (data.len < pos.* + 4) return null;
    const val = std.mem.readInt(u32, data[pos.*..][0..4], .little);
    pos.* += 4;
    return val;
}

fn readU64(data: []const u8, pos: *usize) ?u64 {
    if (data.len < pos.* + 8) return null;
    const val = std.mem.readInt(u64, data[pos.*..][0..8], .little);
    pos.* += 8;
    return val;
}

fn readI64(data: []const u8, pos: *usize) ?i64 {
    if (data.len < pos.* + 8) return null;
    const val = std.mem.readInt(i64, data[pos.*..][0..8], .little);
    pos.* += 8;
    return val;
}

fn writeU32(out: []u8, pos: *usize, val: u32) ?void {
    if (out.len < pos.* + 4) return null;
    std.mem.writeInt(u32, out[pos.*..][0..4], val, .little);
    pos.* += 4;
}

fn writeU64(out: []u8, pos: *usize, val: u64) ?void {
    if (out.len < pos.* + 8) return null;
    std.mem.writeInt(u64, out[pos.*..][0..8], val, .little);
    pos.* += 8;
}

fn writeI64(out: []u8, pos: *usize, val: i64) ?void {
    if (out.len < pos.* + 8) return null;
    std.mem.writeInt(i64, out[pos.*..][0..8], val, .little);
    pos.* += 8;
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

test "v1 getVersion" {
    var data: [100]u8 = undefined;
    @memset(&data, 0);
    std.mem.writeInt(u32, data[0..4], 1, .little);
    try std.testing.expectEqual(@as(u32, 1), getVersion(&data).?);
}

test "v1 round-trip serialize/deserialize" {
    // Create a minimal v1 vote state (V1_14_11, 12-byte lockouts)
    var vs = VoteState.init();
    vs.version = 1;
    @memset(&vs.node_pubkey, 0xAA);
    @memset(&vs.authorized_withdrawer, 0xBB);
    vs.commission = 10;
    // Add 2 lockouts
    vs.lockout_count = 2;
    vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 3 };
    vs.lockouts[1] = .{ .slot = 101, .confirmation_count = 1 };
    vs.root_slot = 99;
    // Add 1 authorized voter
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 5, .pubkey = [_]u8{0xCC} ** 32 };
    // Add 1 epoch credit
    vs.ec_count = 1;
    vs.epoch_credits[0] = .{ .epoch = 5, .credits = 100, .prev_credits = 50 };
    vs.last_timestamp = .{ .slot = 101, .timestamp = 1711000000 };

    // Serialize
    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    const written = serializeVoteState(&vs, &buf).?;
    try std.testing.expect(written > 0);

    // Deserialize back
    const vs2 = deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 1), vs2.version);
    try std.testing.expectEqual(@as(u8, 0xAA), vs2.node_pubkey[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), vs2.authorized_withdrawer[0]);
    try std.testing.expectEqual(@as(u8, 10), vs2.commission);
    try std.testing.expectEqual(@as(u32, 2), vs2.lockout_count);
    try std.testing.expectEqual(@as(u64, 100), vs2.lockouts[0].slot);
    try std.testing.expectEqual(@as(u32, 3), vs2.lockouts[0].confirmation_count);
    try std.testing.expectEqual(@as(u64, 101), vs2.lockouts[1].slot);
    try std.testing.expectEqual(@as(u64, 99), vs2.root_slot.?);
    try std.testing.expectEqual(@as(u32, 1), vs2.av_count);
    try std.testing.expectEqual(@as(u64, 5), vs2.authorized_voters[0].epoch);
    try std.testing.expectEqual(@as(u32, 1), vs2.ec_count);
    try std.testing.expectEqual(@as(u64, 100), vs2.epoch_credits[0].credits);
    try std.testing.expectEqual(@as(i64, 1711000000), vs2.last_timestamp.timestamp);
}

test "v2 (Current) round-trip serialize/deserialize" {
    var vs = VoteState.init();
    vs.version = 2;
    @memset(&vs.node_pubkey, 0x11);
    @memset(&vs.authorized_withdrawer, 0x22);
    vs.commission = 5;
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 500, .confirmation_count = 2 };
    vs.latencies[0] = 3;
    vs.root_slot = null;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 10, .pubkey = [_]u8{0x33} ** 32 };
    vs.ec_count = 0;
    vs.last_timestamp = .{ .slot = 500, .timestamp = 1234567890 };

    var buf: [VOTE_STATE_V3_SZ]u8 = undefined;
    @memset(&buf, 0);
    const written = serializeVoteState(&vs, &buf).?;
    try std.testing.expect(written > 0);

    const vs2 = deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 2), vs2.version);
    try std.testing.expectEqual(@as(u32, 1), vs2.lockout_count);
    try std.testing.expectEqual(@as(u64, 500), vs2.lockouts[0].slot);
    try std.testing.expectEqual(@as(u8, 3), vs2.latencies[0]);
    try std.testing.expect(vs2.root_slot == null);
}

test "v1 replaceTowerState round-trip" {
    // Create a buffer with an initial vote state
    var vs = VoteState.init();
    vs.version = 1;
    @memset(&vs.node_pubkey, 0xAA);
    @memset(&vs.authorized_withdrawer, 0xBB);
    vs.commission = 10;
    vs.lockout_count = 5;
    for (0..5) |i| {
        vs.lockouts[i] = .{ .slot = @intCast(100 + i), .confirmation_count = @intCast(5 - i) };
    }
    vs.root_slot = 99;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 5, .pubkey = [_]u8{0xCC} ** 32 };
    vs.ec_count = 1;
    vs.epoch_credits[0] = .{ .epoch = 5, .credits = 100, .prev_credits = 50 };
    vs.last_timestamp = .{ .slot = 104, .timestamp = 1711000000 };

    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    _ = serializeVoteState(&vs, &buf).?;

    // Now replace tower with 3 lockouts (fewer than before)
    const new_lockouts = [_]Lockout{
        .{ .slot = 200, .confirmation_count = 3 },
        .{ .slot = 201, .confirmation_count = 2 },
        .{ .slot = 202, .confirmation_count = 1 },
    };
    try std.testing.expect(replaceTowerState(&buf, &new_lockouts, 199, 1712000000, 203));

    // Deserialize and verify EVERYTHING is intact
    const vs2 = deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 1), vs2.version);
    try std.testing.expectEqual(@as(u8, 0xAA), vs2.node_pubkey[0]);
    try std.testing.expectEqual(@as(u8, 10), vs2.commission);
    try std.testing.expectEqual(@as(u32, 3), vs2.lockout_count);
    try std.testing.expectEqual(@as(u64, 200), vs2.lockouts[0].slot);
    try std.testing.expectEqual(@as(u64, 202), vs2.lockouts[2].slot);
    try std.testing.expectEqual(@as(u64, 199), vs2.root_slot.?);
    // Authorized voters preserved!
    try std.testing.expectEqual(@as(u32, 1), vs2.av_count);
    try std.testing.expectEqual(@as(u8, 0xCC), vs2.authorized_voters[0].pubkey[0]);
    // Epoch credits: original entry preserved, PLUS a new entry for the 5 consumed lockouts
    try std.testing.expectEqual(@as(u32, 2), vs2.ec_count);
    try std.testing.expectEqual(@as(u64, 100), vs2.epoch_credits[0].credits); // Original
    try std.testing.expectEqual(@as(u64, 105), vs2.epoch_credits[1].credits); // 100 + 5 new credits
    // Timestamp updated
    try std.testing.expectEqual(@as(i64, 1712000000), vs2.last_timestamp.timestamp);
}

test "replaceTowerState rejects out-of-order" {
    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u32, buf[0..4], 1, .little);
    // Need at least a minimal serialized state
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
    _ = serializeVoteState(&vs, &buf);

    const bad_lockouts = [_]Lockout{
        .{ .slot = 102, .confirmation_count = 1 },
        .{ .slot = 101, .confirmation_count = 2 },
    };
    try std.testing.expect(!replaceTowerState(&buf, &bad_lockouts, null, null, 103));
}

// PR-5j (2026-05-18): VoteError.confirmation_roll_back (Custom 13). Empirical
// carrier first divergent at testnet slot 409308456 (Vexor boot 1779140004).
// The three tests below pin the reject case AND the two surrounding allow
// cases — important because PR-5i (2026-05-15) ported the full dual-cursor
// merge and rejected 100% of votes (mutate_fail=246799 ok=0). These positive
// tests are the regression guard.
test "replaceTowerState rejects confirmation_roll_back (same slot, lower conf)" {
    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 4 };
    _ = serializeVoteState(&vs, &buf);

    const rollback_lockouts = [_]Lockout{
        .{ .slot = 100, .confirmation_count = 3 },
    };
    try std.testing.expect(!replaceTowerState(&buf, &rollback_lockouts, null, null, 105));
}

test "replaceTowerState allows same-slot equal or higher confirmation" {
    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 4 };
    _ = serializeVoteState(&vs, &buf);

    // Equal confirmation — must NOT reject.
    const equal_lockouts = [_]Lockout{
        .{ .slot = 100, .confirmation_count = 4 },
    };
    try std.testing.expect(replaceTowerState(&buf, &equal_lockouts, null, null, 105));

    // Reset and try higher confirmation — must NOT reject.
    @memset(&buf, 0);
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 4 };
    _ = serializeVoteState(&vs, &buf);
    const higher_lockouts = [_]Lockout{
        .{ .slot = 100, .confirmation_count = 5 },
    };
    try std.testing.expect(replaceTowerState(&buf, &higher_lockouts, null, null, 105));
}

test "replaceTowerState allows disjoint slots (no same-slot match)" {
    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 4 };
    _ = serializeVoteState(&vs, &buf);

    // Different slot — even with lower confirmation, must NOT reject
    // confirmation_roll_back. With cur.slot=100, conf=4 → lastLockedOut=116;
    // proposed slot=200 > 116, so lockout_conflict also passes (cur expired).
    const disjoint_lockouts = [_]Lockout{
        .{ .slot = 200, .confirmation_count = 1 },
    };
    try std.testing.expect(replaceTowerState(&buf, &disjoint_lockouts, null, null, 205));
}

// PR-5k (2026-05-18): VoteError.lockout_conflict (Custom 6).
// Three tests mirror the PR-5j regression-guard pattern.
test "replaceTowerState rejects lockout_conflict (still-locked-out cur dropped)" {
    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
    // Current lockout slot=100 conf=5 → lastLockedOut = 100 + 2^5 = 132.
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 5 };
    _ = serializeVoteState(&vs, &buf);

    // Proposed tower drops slot=100 and introduces slot=120 (within cur's
    // lockout window 100..132) → Tower BFT violation, must reject.
    const conflict_lockouts = [_]Lockout{
        .{ .slot = 120, .confirmation_count = 1 },
    };
    try std.testing.expect(!replaceTowerState(&buf, &conflict_lockouts, null, null, 121));
}

test "replaceTowerState allows dropped-cur when lockout expired" {
    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
    // Current lockout slot=100 conf=2 → lastLockedOut = 100 + 4 = 104.
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 2 };
    _ = serializeVoteState(&vs, &buf);

    // Proposed drops slot=100, introduces slot=200. cur expired well before
    // (104 < 200), so dropping is legitimate — must NOT reject.
    const expired_drop_lockouts = [_]Lockout{
        .{ .slot = 200, .confirmation_count = 1 },
    };
    try std.testing.expect(replaceTowerState(&buf, &expired_drop_lockouts, null, null, 205));
}

test "replaceTowerState allows dropped-cur with no greater proposed slot" {
    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
    // Current lockout slot=200 conf=5 → lastLockedOut = 232.
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 200, .confirmation_count = 5 };
    _ = serializeVoteState(&vs, &buf);

    // Proposed has only slot=100 (less than cur's slot). The dual cursor
    // would never enter `.lt` for cur=200 because new=100 is less.
    // Equivalently: no min_greater_new_slot exists → no check fires.
    const lower_proposed = [_]Lockout{
        .{ .slot = 100, .confirmation_count = 1 },
    };
    try std.testing.expect(replaceTowerState(&buf, &lower_proposed, null, null, 205));
}

test "v1 applyVoteToState basic" {
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };

    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    _ = serializeVoteState(&vs, &buf);

    // Apply vote for slot 100
    try std.testing.expect(applyVoteToState(&buf, 100, 101, null, null));

    const vs2 = deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 1), vs2.lockout_count);
    try std.testing.expectEqual(@as(u64, 100), vs2.lockouts[0].slot);
    try std.testing.expectEqual(@as(u32, 1), vs2.lockouts[0].confirmation_count);

    // Apply second vote
    try std.testing.expect(applyVoteToState(&buf, 101, 102, null, null));
    const vs3 = deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 2), vs3.lockout_count);
    // First lockout should have incremented confirmation_count
    try std.testing.expectEqual(@as(u32, 2), vs3.lockouts[0].confirmation_count);
}

test "applyVoteToState rejects VoteTooOld" {
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };

    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    _ = serializeVoteState(&vs, &buf);

    try std.testing.expect(applyVoteToState(&buf, 100, 101, null, null));
    try std.testing.expect(!applyVoteToState(&buf, 99, 101, null, null));
    try std.testing.expect(!applyVoteToState(&buf, 100, 101, null, null));
    try std.testing.expect(applyVoteToState(&buf, 101, 102, null, null));
}

test "getLastVotedSlot v1" {
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };

    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    _ = serializeVoteState(&vs, &buf);

    try std.testing.expect(getLastVotedSlot(&buf) == null);

    _ = applyVoteToState(&buf, 42, 43, null, null);
    try std.testing.expectEqual(@as(u64, 42), getLastVotedSlot(&buf).?);

    _ = applyVoteToState(&buf, 43, 44, null, null);
    try std.testing.expectEqual(@as(u64, 43), getLastVotedSlot(&buf).?);
}

test "getLastVotedSlot v2" {
    // V2 layout = same as V1 for offsets up to lockout_count, but lockouts are
    // 13-byte LandedVote (latency + slot + conf_count) instead of 12-byte Lockout.
    var vs = VoteState.init();
    vs.version = 2;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };

    var buf: [VOTE_STATE_V3_SZ]u8 = undefined;
    @memset(&buf, 0);
    _ = serializeVoteState(&vs, &buf);

    // Empty state → no votes yet.
    try std.testing.expect(getLastVotedSlot(&buf) == null);

    _ = applyVoteToState(&buf, 100, 101, null, null);
    try std.testing.expectEqual(@as(u64, 100), getLastVotedSlot(&buf).?);

    _ = applyVoteToState(&buf, 101, 102, null, null);
    try std.testing.expectEqual(@as(u64, 101), getLastVotedSlot(&buf).?);
}

test "getLastVotedSlot v4 (SIMD-0185, version=3)" {
    // V4 layout (version=3) inserts 77 or 125 bytes of extras between
    // auth_withdrawer and lockout_count, has NO commission byte, and uses
    // 13-byte LandedVote entries like V2. Phase-2 fork-choice feed needs this.
    //
    // This is the discriminator test for the V4 offset fix. Round-trip via the
    // existing serializer (which is byte-tested against Agave at the
    // replaceTowerState level) and confirm the parser extracts the same slot.
    var vs = VoteState.init();
    vs.version = 3;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
    // V4 fields — set non-default values to ensure layout offsets are honored.
    @memset(&vs.inflation_rewards_collector, 0x11);
    @memset(&vs.block_revenue_collector, 0x22);
    vs.inflation_rewards_commission_bps = 0x3344;
    vs.block_revenue_commission_bps = 0x5566;
    vs.pending_delegator_rewards = 0x778899AABBCCDDEE;
    // Two lockouts to verify "last" (highest-indexed) is returned.
    vs.lockout_count = 2;
    vs.lockouts[0] = .{ .slot = 410_000_000, .confirmation_count = 31 };
    vs.lockouts[1] = .{ .slot = 410_000_001, .confirmation_count = 30 };
    vs.latencies[0] = 1;
    vs.latencies[1] = 1;

    // Case A: has_bls = false (V4 extras = 77 bytes, no BLS pubkey).
    vs.has_bls_pubkey_compressed = false;
    var buf_no_bls: [VOTE_STATE_V3_SZ]u8 = undefined;
    @memset(&buf_no_bls, 0);
    const wrote_no_bls = serializeVoteState(&vs, &buf_no_bls);
    try std.testing.expect(wrote_no_bls != null);
    try std.testing.expectEqual(@as(u64, 410_000_001), getLastVotedSlot(&buf_no_bls).?);

    // Case B: has_bls = true (V4 extras = 125 bytes, +48 for bls_pubkey).
    vs.has_bls_pubkey_compressed = true;
    @memset(&vs.bls_pubkey_compressed, 0xCC);
    var buf_with_bls: [VOTE_STATE_V3_SZ]u8 = undefined;
    @memset(&buf_with_bls, 0);
    const wrote_with_bls = serializeVoteState(&vs, &buf_with_bls);
    try std.testing.expect(wrote_with_bls != null);
    try std.testing.expectEqual(@as(u64, 410_000_001), getLastVotedSlot(&buf_with_bls).?);

    // Negative case: empty lockout list (count=0) → null.
    vs.lockout_count = 0;
    vs.has_bls_pubkey_compressed = false;
    var buf_empty: [VOTE_STATE_V3_SZ]u8 = undefined;
    @memset(&buf_empty, 0);
    _ = serializeVoteState(&vs, &buf_empty);
    try std.testing.expect(getLastVotedSlot(&buf_empty) == null);
}

test "convertToV4: V1_14_11 -> V4 (SIMD-0185 carrier #50) field-map + byte round-trip" {
    const vote_pk = [_]u8{0xA1} ** 32;
    const node_pk = [_]u8{0xB2} ** 32;
    const withdrawer = [_]u8{0xC3} ** 32;

    var vs = VoteState.init();
    vs.version = 1; // V1_14_11
    vs.node_pubkey = node_pk;
    vs.authorized_withdrawer = withdrawer;
    vs.commission = 7; // → inflation_rewards_commission_bps = 700
    // V1 lockouts (no latency byte on the wire); convertToV4 must zero latency.
    vs.lockout_count = 2;
    vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 2 };
    vs.lockouts[1] = .{ .slot = 101, .confirmation_count = 1 };
    vs.latencies[0] = 0xFF; // garbage — convertToV4 must overwrite with 0 for V1
    vs.latencies[1] = 0xFF;
    vs.root_slot = 42;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 9, .pubkey = [_]u8{0xD4} ** 32 };
    vs.ec_count = 1;
    vs.epoch_credits[0] = .{ .epoch = 9, .credits = 1234, .prev_credits = 1000 };
    vs.last_timestamp = .{ .slot = 101, .timestamp = 1_700_000_000 };

    convertToV4(&vs, vote_pk);

    // SIMD-0185 default field-map (verified 521/521 vs real cluster @414098450):
    try std.testing.expectEqual(@as(u32, 3), vs.version);
    try std.testing.expectEqualSlices(u8, &vote_pk, &vs.inflation_rewards_collector);
    try std.testing.expectEqualSlices(u8, &node_pk, &vs.block_revenue_collector);
    try std.testing.expectEqual(@as(u16, 700), vs.inflation_rewards_commission_bps);
    try std.testing.expectEqual(@as(u16, 10_000), vs.block_revenue_commission_bps);
    try std.testing.expectEqual(@as(u64, 0), vs.pending_delegator_rewards);
    try std.testing.expectEqual(false, vs.has_bls_pubkey_compressed);
    try std.testing.expectEqual(@as(u8, 0), vs.latencies[0]); // byte-blocker A: 0 not 0xFF
    try std.testing.expectEqual(@as(u8, 0), vs.latencies[1]);
    // carried-over fields unchanged
    try std.testing.expectEqual(@as(?u64, 42), vs.root_slot);
    try std.testing.expectEqual(@as(u32, 1), vs.av_count);
    try std.testing.expectEqual(@as(u64, 1234), vs.epoch_credits[0].credits);

    // Byte round-trip: serialize as V4 into a 3762 buffer, deserialize back, expect
    // tag 3 + identical V4 fields + carried tower. Validates the V1-input path end-to-end.
    var buf: [3762]u8 = undefined;
    @memset(&buf, 0);
    const written = serializeVoteState(&vs, &buf);
    try std.testing.expect(written != null);
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, buf[0..4], .little)); // wire tag 3
    const rt = deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u32, 3), rt.version);
    try std.testing.expectEqualSlices(u8, &vote_pk, &rt.inflation_rewards_collector);
    try std.testing.expectEqualSlices(u8, &node_pk, &rt.block_revenue_collector);
    try std.testing.expectEqual(@as(u16, 700), rt.inflation_rewards_commission_bps);
    try std.testing.expectEqual(@as(u16, 10_000), rt.block_revenue_commission_bps);
    try std.testing.expectEqual(@as(?u64, 42), rt.root_slot);
    try std.testing.expectEqual(@as(u64, 101), rt.lockouts[rt.lockout_count - 1].slot);
}

test "convertToV4: V3(Current) -> V4 + idempotent on already-V4" {
    const vote_pk = [_]u8{0x1A} ** 32;
    const node_pk = [_]u8{0x2B} ** 32;

    var vs = VoteState.init();
    vs.version = 2; // Current / V3 (has latency bytes already)
    vs.node_pubkey = node_pk;
    vs.commission = 100; // → 10000 bps (max)
    vs.lockout_count = 1;
    vs.lockouts[0] = .{ .slot = 500, .confirmation_count = 1 };
    vs.latencies[0] = 3; // V3 latency must be PRESERVED (not zeroed — only V1 zeroes)
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 1, .pubkey = node_pk };

    convertToV4(&vs, vote_pk);
    try std.testing.expectEqual(@as(u32, 3), vs.version);
    try std.testing.expectEqualSlices(u8, &vote_pk, &vs.inflation_rewards_collector);
    try std.testing.expectEqual(@as(u16, 10_000), vs.inflation_rewards_commission_bps);
    try std.testing.expectEqual(@as(u8, 3), vs.latencies[0]); // V3 latency preserved

    // Idempotent: convertToV4 on an already-V4 account is identity (Agave V4 arm).
    var vs2 = vs;
    convertToV4(&vs2, [_]u8{0x99} ** 32); // different pubkey must NOT change anything
    try std.testing.expectEqualSlices(u8, &vote_pk, &vs2.inflation_rewards_collector);
    try std.testing.expectEqual(@as(u16, 10_000), vs2.inflation_rewards_commission_bps);
}

// SIMD-0185 V4 serialize-fidelity gate (2026-06-09, carrier #50): round-trip 521 REAL cluster
// V4 (tag-3) vote accounts captured at slot 414098450 (bank_hash
// Cm7fJYqtzsHVshscGpdXt5aSJUsY5tTCNDCsRSYaVv2j) — all 3762 bytes. We serialize INTO a copy of
// the golden (mirrors the live path: mutable_data = dupe(current_data)), so the post-`written`
// residue tail is the account's own bytes — exactly what serializeVoteState preserves for
// version==3. A byte-exact round-trip on all 521 proves the V4 serialize layout (field order +
// lengths + tail preservation) matches the cluster on REAL layouts. Offline discriminator for the
// 2026-06-09 freeze: 521/521 pass ⇒ the V4 in-place serialize is correct ⇒ a tag-2→V4 conversion
// is byte-correct ⇒ the remaining divergence surface is the tag-1 realloc (replay_stage.zig).
// (Caveat: this validates SERIALIZE fidelity on real V4 layouts; it does NOT replay a real
// conversion's intervening votes — that needs consecutive-slot oracle-node ground truth.)
test "V4 serialize fidelity: 521 real cluster goldens @414098450 round-trip byte-exact" {
    const blob = @embedFile("kat_goldens_414098450.bin");
    const REC: usize = VOTE_STATE_V3_SZ; // 3762
    try std.testing.expectEqual(@as(usize, 0), blob.len % REC);
    const n = blob.len / REC;
    var buf: [VOTE_STATE_V3_SZ]u8 = undefined;
    var ok: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const golden = blob[i * REC ..][0..REC];
        @memcpy(&buf, golden); // serialize into a copy → residue tail = account's own bytes
        var vs = deserializeVoteState(golden) orelse {
            std.debug.print("[V4-FIDELITY] deserialize FAILED at record {d}\n", .{i});
            return error.DeserializeFailed;
        };
        const written = serializeVoteState(&vs, &buf) orelse {
            std.debug.print("[V4-FIDELITY] serialize FAILED at record {d}\n", .{i});
            return error.SerializeFailed;
        };
        if (!std.mem.eql(u8, &buf, golden)) {
            var d: usize = 0;
            while (d < REC and buf[d] == golden[d]) : (d += 1) {}
            std.debug.print("[V4-FIDELITY] BYTE DIFF record {d} offset {d} written={d} got=0x{x:0>2} want=0x{x:0>2}\n", .{ i, d, written, buf[d], golden[d] });
            return error.RoundTripMismatch;
        }
        ok += 1;
    }
    try std.testing.expectEqual(n, ok);
    std.debug.print("[V4-FIDELITY] {d}/{d} real cluster V4 goldens round-trip byte-exact\n", .{ ok, n });
}

// SIMD-0185 conversion gate (2026-06-09, carrier #50): exercise the tag-1 (V1_14_11, 3731B) AND
// tag-2 (Current, 3762B) DESERIALIZE layouts (12-byte vs 13-byte lockouts; commission byte; prior_voters)
// → convertToV4 → serialize (+ tag-1 realloc to 3762 with zero tail) on 100+100 REAL testnet vote
// accounts (pulled live via getProgramAccounts dataSize filter). The 521-golden fidelity test only
// covers tag-3 deserialize; THIS covers the conversion source layouts. Asserts: deserialize succeeds,
// convertToV4 field-map (collectors/bps/pending/bls), realloc tail bytes ([written..old_len]=residue,
// [old_len..3762]=0), and a V4 round-trip (the produced bytes re-deserialize to the converted state).
// Blob record: [32 pubkey][u64 lamports LE][u32 dlen LE][dlen data].
fn runConversionBlob(comptime blob: []const u8, rent_rejected_out: *usize) !usize {
    var pos: usize = 0;
    var n: usize = 0;
    var rent_rejected: usize = 0;
    while (pos + 44 <= blob.len) {
        var pk: [32]u8 = undefined;
        @memcpy(&pk, blob[pos..][0..32]);
        pos += 32;
        const lamports = std.mem.readInt(u64, blob[pos..][0..8], .little);
        pos += 8;
        const dlen = std.mem.readInt(u32, blob[pos..][0..4], .little);
        pos += 4;
        const data = blob[pos..][0..dlen];
        pos += dlen;

        var vs = deserializeVoteState(data) orelse {
            std.debug.print("[V4-CONV] deserialize FAILED rec {d} dlen={d} tag={d}\n", .{ n, dlen, std.mem.readInt(u32, data[0..4], .little) });
            return error.DeserializeFailed;
        };
        const orig_node = vs.node_pubkey;
        const orig_commission = vs.commission;
        const orig_lockouts = vs.lockout_count;

        convertToV4(&vs, pk);

        try std.testing.expectEqual(@as(u32, 3), vs.version);
        try std.testing.expectEqualSlices(u8, &pk, &vs.inflation_rewards_collector);
        try std.testing.expectEqualSlices(u8, &orig_node, &vs.block_revenue_collector);
        try std.testing.expectEqual(@as(u16, 10_000), vs.block_revenue_commission_bps);
        try std.testing.expectEqual(@as(u16, @as(u16, orig_commission) *| 100), vs.inflation_rewards_commission_bps);
        try std.testing.expectEqual(@as(u64, 0), vs.pending_delegator_rewards);
        try std.testing.expect(!vs.has_bls_pubkey_compressed);
        try std.testing.expectEqual(orig_lockouts, vs.lockout_count); // tower carried over

        // serialize into a COPY of the original bytes (mirrors live mutable_data=dupe), then apply the
        // replay_stage realloc: grow to V4 size with a zero tail when tag==3 && len<3762.
        var buf: [VOTE_STATE_V3_SZ]u8 = undefined;
        @memcpy(buf[0..dlen], data);
        const written = serializeVoteState(&vs, buf[0..dlen]) orelse return error.SerializeFailed;
        try std.testing.expect(written <= dlen);
        if (dlen < VOTE_STATE_V3_SZ) {
            const v4_min: u64 = (VOTE_STATE_V3_SZ + 128) * 3480 * 2; // 27_074_400
            if (lamports < v4_min) {
                // RENT-POOR tag-1 (43% of testnet tag-1 sit at exactly the 3731 rent minimum
                // 26_858_640 < 27_074_400): Agave set_vote_account_state returns AccountNotRentExempt
                // → vote REJECTED, account UNCHANGED. The replay_stage rent guard matches (no write),
                // so there are no converted/committed bytes to validate. Count + skip.
                rent_rejected += 1;
                n += 1;
                continue;
            }
            // rent-exempt tag-1 realloc: [written..dlen]=preserved residue, [dlen..3762]=0
            try std.testing.expect(std.mem.eql(u8, buf[written..dlen], data[written..dlen]));
            @memset(buf[dlen..], 0);
        }

        // V4 round-trip: the produced 3762 bytes re-deserialize to the converted state.
        const vs2 = deserializeVoteState(&buf) orelse return error.RoundTripDeserFail;
        try std.testing.expectEqual(@as(u32, 3), vs2.version);
        try std.testing.expectEqualSlices(u8, &vs.node_pubkey, &vs2.node_pubkey);
        try std.testing.expectEqualSlices(u8, &vs.authorized_withdrawer, &vs2.authorized_withdrawer);
        try std.testing.expectEqualSlices(u8, &pk, &vs2.inflation_rewards_collector);
        try std.testing.expectEqualSlices(u8, &orig_node, &vs2.block_revenue_collector);
        try std.testing.expectEqual(vs.inflation_rewards_commission_bps, vs2.inflation_rewards_commission_bps);
        try std.testing.expectEqual(@as(u16, 10_000), vs2.block_revenue_commission_bps);
        try std.testing.expectEqual(orig_lockouts, vs2.lockout_count);
        try std.testing.expectEqual(vs.av_count, vs2.av_count);
        try std.testing.expectEqual(vs.ec_count, vs2.ec_count);
        try std.testing.expectEqual(vs.root_slot, vs2.root_slot);
        try std.testing.expectEqual(vs.last_timestamp.slot, vs2.last_timestamp.slot);
        n += 1;
    }
    rent_rejected_out.* = rent_rejected;
    return n;
}

test "V4 conversion: 100 real tag-1 + 100 real tag-2 deserialize->convertToV4->serialize(+realloc)" {
    var rr1: usize = 0;
    var rr2: usize = 0;
    const n1 = try runConversionBlob(@embedFile("kat_tag1_samples.bin"), &rr1);
    const n2 = try runConversionBlob(@embedFile("kat_tag2_samples.bin"), &rr2);
    try std.testing.expect(n1 >= 100);
    try std.testing.expect(n2 >= 100);
    // tag-2 are 3762B already → never rent-rejected by the grow guard.
    try std.testing.expectEqual(@as(usize, 0), rr2);
    std.debug.print("[V4-CONV] tag-1 {d} (rent-exempt-converted {d}, rent-rejected {d}) + tag-2 {d} real accounts OK\n", .{ n1, n1 - rr1, rr1, n2 });
}

test "timestamp update via round-trip" {
    var vs = VoteState.init();
    vs.version = 1;
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };

    var buf: [VOTE_STATE_V2_SZ]u8 = undefined;
    @memset(&buf, 0);
    _ = serializeVoteState(&vs, &buf);

    try std.testing.expect(applyVoteToState(&buf, 100, 101, 1711000000, null));

    const vs2 = deserializeVoteState(&buf).?;
    try std.testing.expectEqual(@as(u64, 100), vs2.last_timestamp.slot);
    try std.testing.expectEqual(@as(i64, 1711000000), vs2.last_timestamp.timestamp);
}

// MVT-1 (2026-05-06 carrier hunt): V4 round-trip test against a real testnet
// vote-account. Per AGAVE_VS_VEXOR_VOTE_DISPATCH.md (vault baseline 1953Z),
// no V4 round-trip test exists in tree; the first time Vexor mutates+writes
// a V4 vote-account is in production. If our serialize layout differs from
// Agave's by even 1 byte, every V4 vote tx writes wrong bytes → bank_hash
// divergence → 92.5% Custom=2 SlotHashMismatch.
//
// Fixture: live testnet vote-account `HWNLEHFYu23Tn5US6Qmxi1JnzLg2fNnt7ygqKvUAGRm2`
// captured 2026-05-06. 3762 bytes, disc=3 (V4 per SIMD-0185).
//
// Expected: deserialize → serialize produces byte-identical output to input.
// On FAIL: report first differing offset; that locates the layout drift.
test "V4 round-trip byte-identity (real testnet account)" {
    const original = @embedFile("v4_vote_account.bin");

    // Sanity: fixture is correct shape.
    try std.testing.expectEqual(@as(usize, 3762), original.len);
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, original[0..4], .little));

    // Deserialize via Vexor.
    const vs = deserializeVoteState(original) orelse {
        std.debug.print("DESERIALIZE FAILED on real V4 vote-account\n", .{});
        return error.DeserializeFailed;
    };
    try std.testing.expectEqual(@as(u32, 3), vs.version);

    // Serialize back into a buffer pre-loaded with the original bytes.
    // This emulates production: replaceTowerState reads the existing account
    // data, mutates the structured prefix (≤2213B for V4), and the trailing
    // 1549 bytes are PRESERVED (SIMD-0185 LtHash chain). A correct serializer
    // overwrites only the structured prefix.
    var roundtrip: [VOTE_STATE_V3_SZ]u8 = undefined;
    @memcpy(&roundtrip, original);
    const written = serializeVoteState(&vs, &roundtrip) orelse {
        std.debug.print("SERIALIZE FAILED on round-trip\n", .{});
        return error.SerializeFailed;
    };

    std.debug.print("V4 round-trip: original_len={d} written={d}\n", .{ original.len, written });

    // Find first differing byte.
    var first_diff: ?usize = null;
    var diff_count: usize = 0;
    for (0..@min(original.len, roundtrip.len)) |i| {
        if (original[i] != roundtrip[i]) {
            if (first_diff == null) first_diff = i;
            diff_count += 1;
        }
    }

    if (first_diff) |off| {
        const start = if (off >= 8) off - 8 else 0;
        const end = @min(off + 24, original.len);
        std.debug.print(
            "FIRST DIFF at offset {d} (total {d} differing bytes)\n  orig[{d}..{d}]: {x}\n  vexr[{d}..{d}]: {x}\n",
            .{ off, diff_count, start, end, original[start..end], start, end, roundtrip[start..end] },
        );
        return error.RoundTripDiverged;
    }

    std.debug.print("V4 round-trip: BYTE-IDENTICAL ✓\n", .{});
}
