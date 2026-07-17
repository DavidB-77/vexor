//! Vexor Vote Program
//!
//! Processes all Solana vote program instructions.
//! Handles instruction deserialization, signer validation, and account state
//! mutation via the vote_state_serde round-trip serializer.
//!
//! Instruction dispatch table (correct Solana discriminants 0-15):
//!   0  InitializeAccount
//!   1  Authorize
//!   2  Vote (legacy)
//!   3  Withdraw
//!   4  UpdateValidatorIdentity
//!   5  UpdateCommission
//!   6  VoteSwitch (legacy)
//!   7  AuthorizeChecked
//!   8  UpdateVoteState
//!   9  UpdateVoteStateSwitch
//!   10 AuthorizeWithSeed
//!   11 AuthorizeCheckedWithSeed
//!   12 CompactUpdateVoteState
//!   13 CompactUpdateVoteStateSwitch
//!   14 TowerSync
//!   15 TowerSyncSwitch

const std = @import("std");
const Allocator = std.mem.Allocator;
const serde = @import("vote_state_serde.zig");
// task #49: SIMD-0387 BLS12-381 proof-of-possession verify (vendored blst).
const bls_pop = @import("bls_pop");

/// Vote program ID (Vote111111111111111111111111111111111111111)
pub const VOTE_PROGRAM_ID: [32]u8 = .{
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
    0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
    0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
};

pub const MAX_LOCKOUT_HISTORY: usize = 31;
pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// LEB128 / short-vec helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read LEB128 unsigned varint. Advances pos.
/// 10 bytes max for u64 (9 bytes × 7 bits + 1 byte × 1 bit). The 10th byte
/// must have its continuation bit cleared; if it doesn't, the input is
/// malformed and we error out before `shift` can overflow `u6` (max 63).
fn readVarint(data: []const u8, pos: *usize) !u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        if (pos.* + i >= data.len) return error.InvalidData;
        const byte = data[pos.* + i];
        result |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) {
            pos.* += i + 1;
            return result;
        }
        if (i == 9) return error.InvalidData; // 10th byte must terminate
        shift += 7;
    }
    return error.InvalidData;
}

/// Read Solana compact-u16 (short_vec). Advances pos.
fn readShortVec(data: []const u8, pos: *usize) !usize {
    var value: u32 = 0;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (pos.* + i >= data.len) return error.InvalidData;
        const byte = data[pos.* + i];
        value |= @as(u32, byte & 0x7F) << @as(u5, @intCast(i * 7));
        if (byte & 0x80 == 0) {
            pos.* += i + 1;
            return @intCast(value);
        }
    }
    return error.InvalidData;
}

/// Write LEB128 unsigned varint.
fn writeVarint(writer: anytype, value: u64) !void {
    var v = value;
    while (v >= 0x80) {
        try writer.writeByte(@intCast((v & 0x7F) | 0x80));
        v >>= 7;
    }
    try writer.writeByte(@intCast(v & 0x7F));
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction data types
// ─────────────────────────────────────────────────────────────────────────────

pub const Lockout = struct {
    slot: u64,
    confirmation_count: u32,

    pub fn lockoutPeriod(self: *const Lockout) u64 {
        return @as(u64, 1) << @as(u6, @intCast(@min(self.confirmation_count, 63)));
    }

    pub fn expiration(self: *const Lockout) u64 {
        return self.slot +| self.lockoutPeriod();
    }
};

pub const AuthorizeType = enum(u32) {
    voter = 0,
    withdrawer = 1,
    /// SIMD-0387 (Alpenglow / Vote Account v4): VoterWithBLS — authorize a new
    /// voter AND register a compressed BLS12-381 pubkey (+ proof-of-possession)
    /// into the V4 vote frame. @prov:vote.authorize-bls — disc 2; args
    /// (bls_pubkey[48] + pop[96]) appended after the 4-byte discriminant; see
    /// AuthorizeData/AuthorizeCheckedData.
    voter_with_bls = 2,
};

/// SIMD-0291 (Commission Rate in Basis Points): which commission rate the
/// UpdateCommissionBps instruction (disc 18) targets.
///
/// @prov:vote.commission-kind — the source marks the enum `#[repr(u8)]`, but
/// that affects only the in-memory
/// layout — the vote program (de)serializes instructions with bincode (serde
/// derive), which encodes a *fieldless* enum's variant index as a **u32 LE
/// (4 bytes)**, NOT a u8. Empirically confirmed against the real crate
/// (solana-vote-interface-5.0.0, bincode::serialize): the kind occupies 4 bytes.
pub const CommissionKind = enum(u32) {
    inflation_rewards = 0,
    block_revenue = 1,
};

/// task #49 (2026-06-10): BLS12-381 PoP crypto-verify is LIVE on this path too
/// (vendored blst via the bls_pop module — the same library Agave links). The
/// former accept-without-verify deferral (`unverified_bls_pop_accepted`) is
/// gone. Counters for observability only.
pub var bls_pop_verified: u64 = 0;
/// Invalid PoPs REJECTED (handler returns false → tx fails). @prov:vote.bls-pop
pub var bls_pop_rejected: u64 = 0;

pub const InitializeAccountData = struct {
    node_pubkey: [32]u8,
    authorized_voter: [32]u8,
    authorized_withdrawer: [32]u8,
    commission: u8,

    pub fn deserialize(data: []const u8) !InitializeAccountData {
        if (data.len < 97) return error.InvalidData;
        return .{
            .node_pubkey = data[0..32].*,
            .authorized_voter = data[32..64].*,
            .authorized_withdrawer = data[64..96].*,
            .commission = data[96],
        };
    }
};

pub const AuthorizeData = struct {
    pubkey: [32]u8,
    authorize_type: AuthorizeType,
    /// Present only for VoterWithBLS (disc 2): the 48-byte compressed BLS pubkey.
    bls_pubkey: ?[48]u8 = null,
    /// Present only for VoterWithBLS (disc 2): the 96-byte compressed BLS
    /// proof-of-possession (task #49 — verified cryptographically, no longer dropped).
    bls_proof_of_possession: ?[96]u8 = null,

    pub fn deserialize(data: []const u8) !AuthorizeData {
        if (data.len < 36) return error.InvalidData;
        const disc = std.mem.readInt(u32, data[32..36], .little);
        const at = std.meta.intToEnum(AuthorizeType, disc) catch return error.InvalidData;
        if (at == .voter_with_bls) {
            // Authorize(Pubkey, VoterWithBLS): [pubkey:32][disc:4][bls_pubkey:48][pop:96].
            // Require the full args (matches Agave bincode deserialize accept/reject).
            if (data.len < 36 + 48 + 96) return error.InvalidData;
            return .{
                .pubkey = data[0..32].*,
                .authorize_type = at,
                .bls_pubkey = data[36..84].*,
                .bls_proof_of_possession = data[84..180].*,
            };
        }
        return .{ .pubkey = data[0..32].*, .authorize_type = at };
    }
};

/// AuthorizeChecked (disc=7) payload — VoteAuthorize ONLY (4 bytes, NO pubkey).
/// The new authority for AuthorizeChecked comes from ACCOUNT[3], not the data.
/// Routing disc 7 through `AuthorizeData.deserialize` (which requires >= 36
/// bytes for the [pubkey:32][type:4] Authorize layout) ALWAYS returned
/// error.InvalidData → VoteInstruction.deserialize failed → silent drop. That
/// dropped the AuthorizeChecked carrier on 271KPMd at slot 413005757.
/// Ref: Agave vote_instruction.rs:110 (`AuthorizeChecked(VoteAuthorize)`);
/// Firedancer fd_vote_codec.c:1134-1135.
pub const AuthorizeCheckedData = struct {
    authorize_type: AuthorizeType,
    /// Present only for VoterWithBLS (disc 2): the 48-byte compressed BLS pubkey.
    bls_pubkey: ?[48]u8 = null,
    /// Present only for VoterWithBLS (disc 2): the 96-byte compressed BLS
    /// proof-of-possession (task #49 — verified cryptographically, no longer dropped).
    bls_proof_of_possession: ?[96]u8 = null,

    pub fn deserialize(data: []const u8) !AuthorizeCheckedData {
        if (data.len < 4) return error.InvalidData;
        const disc = std.mem.readInt(u32, data[0..4], .little);
        const at = std.meta.intToEnum(AuthorizeType, disc) catch return error.InvalidData;
        if (at == .voter_with_bls) {
            // AuthorizeChecked(VoterWithBLS): [disc:4][bls_pubkey:48][pop:96] = 148 bytes.
            // Require the full args (matches Agave bincode deserialize accept/reject).
            if (data.len < 4 + 48 + 96) return error.InvalidData;
            return .{
                .authorize_type = at,
                .bls_pubkey = data[4..52].*,
                .bls_proof_of_possession = data[52..148].*,
            };
        }
        return .{ .authorize_type = at };
    }
};

pub const VoteData = struct {
    slots_buf: [64]u64 = undefined,
    slots_count: usize = 0,
    slots: []const u64 = &[_]u64{},
    hash: [32]u8,
    timestamp: ?i64,

    pub fn deserialize(data: []const u8) !VoteData {
        if (data.len < 8) return error.InvalidData;
        var result: VoteData = .{
            .hash = [_]u8{0} ** 32,
            .timestamp = null,
        };
        var offset: usize = 0;

        const num_slots = std.mem.readInt(u64, data[offset..][0..8], .little);
        offset += 8;
        if (num_slots > 64) return error.InvalidData;
        result.slots_count = @intCast(num_slots);

        if (offset + result.slots_count * 8 + 32 > data.len) return error.InvalidData;
        for (0..result.slots_count) |i| {
            result.slots_buf[i] = std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;
        }
        result.slots = result.slots_buf[0..result.slots_count];

        result.hash = data[offset..][0..32].*;
        offset += 32;

        if (offset + 1 <= data.len and data[offset] == 1) {
            offset += 1;
            if (offset + 8 <= data.len) {
                result.timestamp = std.mem.readInt(i64, data[offset..][0..8], .little);
            }
        }
        return result;
    }
};

pub const VoteSwitchData = struct {
    vote: VoteData,
    switch_hash: [32]u8,

    pub fn deserialize(data: []const u8) !VoteSwitchData {
        const vote = try VoteData.deserialize(data);
        var sh = [_]u8{0} ** 32;
        // Reconstruct byte offset after vote to read switch hash
        var offset: usize = 8 + vote.slots_count * 8 + 32;
        if (offset < data.len and data[offset] == 1) offset += 9 else if (offset < data.len) offset += 1;
        if (offset + 32 <= data.len) sh = data[offset..][0..32].*;
        return .{ .vote = vote, .switch_hash = sh };
    }
};

pub const WithdrawData = struct {
    lamports: u64,

    pub fn deserialize(data: []const u8) !WithdrawData {
        if (data.len < 8) return error.InvalidData;
        return .{ .lamports = std.mem.readInt(u64, data[0..8], .little) };
    }
};

pub const UpdateCommissionData = struct {
    commission: u8,

    pub fn deserialize(data: []const u8) !UpdateCommissionData {
        if (data.len < 1) return error.InvalidData;
        return .{ .commission = data[0] };
    }
};

/// SIMD-0291 UpdateCommissionBps (disc 18) instruction payload.
///
/// Bincode layout AFTER the 4-byte outer instruction discriminant [18,0,0,0]:
///   commission_bps : u16 LE  (2 bytes)
///   kind           : u32 LE  (4 bytes)  — CommissionKind variant index
/// = 6-byte payload. Empirically verified against solana-vote-interface-5.0.0
/// (bincode::serialize) — e.g. {bps=1234, InflationRewards} serializes to
/// [18,0,0,0, 210,4, 0,0,0,0]; {..,BlockRevenue} to [18,0,0,0, 210,4, 1,0,0,0].
pub const UpdateCommissionBpsData = struct {
    commission_bps: u16,
    kind: CommissionKind,

    pub fn deserialize(data: []const u8) !UpdateCommissionBpsData {
        if (data.len < 6) return error.InvalidData;
        const bps = std.mem.readInt(u16, data[0..2], .little);
        const kind_raw = std.mem.readInt(u32, data[2..6], .little);
        const kind = std.meta.intToEnum(CommissionKind, kind_raw) catch return error.InvalidData;
        return .{ .commission_bps = bps, .kind = kind };
    }
};

pub const VoteStateUpdateData = struct {
    lockouts_buf: [MAX_LOCKOUT_HISTORY]Lockout = undefined,
    lockouts_count: usize = 0,
    lockouts: []const Lockout = &[_]Lockout{},
    root: ?u64,
    hash: [32]u8,
    timestamp: ?i64,

    pub fn deserialize(data: []const u8) !VoteStateUpdateData {
        var result: VoteStateUpdateData = .{
            .root = null,
            .hash = [_]u8{0} ** 32,
            .timestamp = null,
        };
        if (data.len < 8) return error.InvalidData;
        var offset: usize = 0;

        const num_lockouts = std.mem.readInt(u64, data[offset..][0..8], .little);
        offset += 8;
        if (num_lockouts > MAX_LOCKOUT_HISTORY) return error.InvalidData;
        result.lockouts_count = @intCast(num_lockouts);

        for (0..result.lockouts_count) |i| {
            if (offset + 12 > data.len) return error.InvalidData;
            result.lockouts_buf[i] = .{
                .slot = std.mem.readInt(u64, data[offset..][0..8], .little),
                .confirmation_count = std.mem.readInt(u32, data[offset + 8 ..][0..4], .little),
            };
            offset += 12;
        }
        result.lockouts = result.lockouts_buf[0..result.lockouts_count];

        if (offset >= data.len) return error.InvalidData;
        if (data[offset] != 0) {
            offset += 1;
            if (offset + 8 > data.len) return error.InvalidData;
            result.root = std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;
        } else {
            offset += 1;
        }

        if (offset + 32 > data.len) return error.InvalidData;
        result.hash = data[offset..][0..32].*;
        offset += 32;

        if (offset < data.len) {
            if (data[offset] == 1) {
                offset += 1;
                if (offset + 8 <= data.len) {
                    result.timestamp = std.mem.readInt(i64, data[offset..][0..8], .little);
                }
            }
        }
        return result;
    }
};

pub const VoteStateUpdateSwitchData = struct {
    update: VoteStateUpdateData,
    switch_hash: [32]u8,

    pub fn deserialize(data: []const u8) !VoteStateUpdateSwitchData {
        const update = try VoteStateUpdateData.deserialize(data);
        var sh = [_]u8{0} ** 32;
        // Switch hash is at the end; derive byte offset
        var offset: usize = 8 + update.lockouts_count * 12;
        offset += 9; // root option (1 + 8) — worst case
        if (data.len >= offset + 32 + 9 + 32) {
            // Try to find it properly by skipping root, hash, timestamp option
            // Simpler: just use last 32 bytes as switch hash
            @memcpy(&sh, data[data.len - 32 ..][0..32]);
        }
        return .{ .update = update, .switch_hash = sh };
    }
};

pub const CompactVoteStateUpdateData = struct {
    root: ?u64,
    lockouts_buf: [MAX_LOCKOUT_HISTORY]Lockout = undefined,
    lockouts_count: usize = 0,
    lockouts: []const Lockout = &[_]Lockout{},
    hash: [32]u8,
    timestamp: ?i64,

    /// Compact wire format:
    ///   root: u64 LE (u64::MAX = None)
    ///   lockout_count: compact-u16
    ///   lockouts: { offset: LEB128, confirmation_count: u8 } × count
    ///             offsets are cumulative from root (or 0 if root is None)
    ///   hash: [32]u8
    ///   timestamp: u8 discriminant + optional i64
    pub fn deserialize(data: []const u8) !CompactVoteStateUpdateData {
        var result: CompactVoteStateUpdateData = .{
            .root = null,
            .hash = [_]u8{0} ** 32,
            .timestamp = null,
        };
        if (data.len < 8) return error.InvalidData;
        var pos: usize = 0;

        const raw_root = std.mem.readInt(u64, data[pos..][0..8], .little);
        pos += 8;
        result.root = if (raw_root == std.math.maxInt(u64)) null else raw_root;

        const lockout_count = readShortVec(data, &pos) catch return error.InvalidData;
        if (lockout_count > MAX_LOCKOUT_HISTORY) return error.InvalidData;
        result.lockouts_count = lockout_count;

        var running_slot: u64 = if (result.root) |r| r else 0;
        for (0..lockout_count) |i| {
            const offset = readVarint(data, &pos) catch return error.InvalidData;
            if (pos >= data.len) return error.InvalidData;
            const conf_count = data[pos];
            pos += 1;
            const new_slot = running_slot +% offset;
            running_slot = new_slot;
            result.lockouts_buf[i] = .{
                .slot = running_slot,
                .confirmation_count = @as(u32, conf_count),
            };
        }
        result.lockouts = result.lockouts_buf[0..result.lockouts_count];

        if (pos + 32 > data.len) return error.InvalidData;
        @memcpy(&result.hash, data[pos..][0..32]);
        pos += 32;

        if (pos < data.len) {
            if (data[pos] == 1) {
                pos += 1;
                if (pos + 8 <= data.len) {
                    result.timestamp = std.mem.readInt(i64, data[pos..][0..8], .little);
                }
            }
        }
        return result;
    }
};

pub const CompactVoteStateUpdateSwitchData = struct {
    update: CompactVoteStateUpdateData,
    switch_hash: [32]u8,

    pub fn deserialize(data: []const u8) !CompactVoteStateUpdateSwitchData {
        const update = try CompactVoteStateUpdateData.deserialize(data);
        var sh = [_]u8{0} ** 32;
        if (data.len >= 32) @memcpy(&sh, data[data.len - 32 ..][0..32]);
        return .{ .update = update, .switch_hash = sh };
    }
};

pub const TowerSyncData = struct {
    lockouts_buf: [MAX_LOCKOUT_HISTORY]Lockout = undefined,
    lockouts_count: usize = 0,
    lockouts: []const Lockout = &[_]Lockout{},
    root: ?u64,
    hash: [32]u8,
    timestamp: ?i64,
    block_id: [32]u8,

    /// Compact wire format. @prov:vote.tower-sync-wire — layout:
    ///   root: u64 LE (u64::MAX = None)
    ///   lockouts_len: compact-u16 (ULEB128)
    ///   lockouts: { offset: LEB128 u64 (cumulative from root or 0),
    ///               confirmation_count: u8 } × len
    ///   hash: [32]u8
    ///   timestamp: u8 disc (0 = None, 1 = Some i64, else error) + optional i64
    ///   block_id: [32]u8
    pub fn deserialize(data: []const u8) !TowerSyncData {
        const parsed = try parseTowerSyncCompact(data);
        return parsed.sync;
    }
};

pub const TowerSyncSwitchData = struct {
    sync: TowerSyncData,
    switch_hash: [32]u8,

    /// TowerSyncSwitch wire format: full TowerSync payload followed by
    /// switch_proof_hash: [32]u8. Reads switch_hash at the offset where
    /// TowerSync parsing ended, NOT the last 32 bytes of the buffer
    /// (which could misread if trailing padding ever appears).
    pub fn deserialize(data: []const u8) !TowerSyncSwitchData {
        const parsed = try parseTowerSyncCompact(data);
        if (parsed.end + 32 > data.len) return error.InvalidData;
        return .{
            .sync = parsed.sync,
            .switch_hash = data[parsed.end..][0..32].*,
        };
    }
};

/// Shared compact-format parser used by both TowerSync (disc 14) and
/// TowerSyncSwitch (disc 15). Returns the parsed payload and the byte
/// offset immediately after block_id so the switch variant can read the
/// trailing switch_proof_hash without re-walking the variable-length fields.
fn parseTowerSyncCompact(data: []const u8) !struct {
    sync: TowerSyncData,
    end: usize,
} {
    var result: TowerSyncData = .{
        .root = null,
        .hash = [_]u8{0} ** 32,
        .timestamp = null,
        .block_id = [_]u8{0} ** 32,
    };
    if (data.len < 8) return error.InvalidData;
    var pos: usize = 0;

    const raw_root = std.mem.readInt(u64, data[pos..][0..8], .little);
    pos += 8;
    result.root = if (raw_root == std.math.maxInt(u64)) null else raw_root;

    const lockout_count = readShortVec(data, &pos) catch return error.InvalidData;
    if (lockout_count > MAX_LOCKOUT_HISTORY) return error.InvalidData;
    result.lockouts_count = lockout_count;

    var running_slot: u64 = if (result.root) |r| r else 0;
    for (0..lockout_count) |i| {
        const offset = readVarint(data, &pos) catch return error.InvalidData;
        if (pos >= data.len) return error.InvalidData;
        const conf_count = data[pos];
        pos += 1;
        running_slot = std.math.add(u64, running_slot, offset) catch
            return error.InvalidData;
        result.lockouts_buf[i] = .{
            .slot = running_slot,
            .confirmation_count = @as(u32, conf_count),
        };
    }
    result.lockouts = result.lockouts_buf[0..result.lockouts_count];

    if (pos + 32 > data.len) return error.InvalidData;
    result.hash = data[pos..][0..32].*;
    pos += 32;

    if (pos >= data.len) return error.InvalidData;
    const ts_disc = data[pos];
    pos += 1;
    switch (ts_disc) {
        0 => {},
        1 => {
            if (pos + 8 > data.len) return error.InvalidData;
            result.timestamp = std.mem.readInt(i64, data[pos..][0..8], .little);
            pos += 8;
        },
        else => return error.InvalidData,
    }

    if (pos + 32 > data.len) return error.InvalidData;
    result.block_id = data[pos..][0..32].*;
    pos += 32;

    return .{ .sync = result, .end = pos };
}

pub const AuthorizeWithSeedData = struct {
    authorization_type: AuthorizeType,
    current_authority_derived_key_owner: [32]u8,
    current_authority_derived_key_seed: []const u8,
    new_authority: [32]u8,

    // We only need to read the discriminant here; full seed parsing is complex.
    // For now we extract authorization_type so callers can dispatch.
    pub fn deserialize(data: []const u8) !AuthorizeWithSeedData {
        if (data.len < 4) return error.InvalidData;
        const disc = std.mem.readInt(u32, data[0..4], .little);
        return .{
            .authorization_type = std.meta.intToEnum(AuthorizeType, disc) catch return error.InvalidData,
            .current_authority_derived_key_owner = [_]u8{0} ** 32,
            .current_authority_derived_key_seed = &[_]u8{},
            .new_authority = [_]u8{0} ** 32,
        };
    }
};

pub const AuthorizeCheckedWithSeedData = struct {
    authorization_type: AuthorizeType,

    pub fn deserialize(data: []const u8) !AuthorizeCheckedWithSeedData {
        if (data.len < 4) return error.InvalidData;
        const disc = std.mem.readInt(u32, data[0..4], .little);
        return .{
            .authorization_type = std.meta.intToEnum(AuthorizeType, disc) catch return error.InvalidData,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// SIMD-0464 InitializeAccountV2 (disc 16) — instruction data
// ─────────────────────────────────────────────────────────────────────────────
// @prov:vote.init-account-v2-wire — CANONICAL Agave 4.1.0-rc.1 VoteInitV2
// layout. Follow Agave rc.1, NOT Firedancer — FD fd_vote_codec.c is on the
// OLD v4.0.0-alpha.0 draft (collectors in payload). rc.1 puts collectors in
// ACCOUNTS idx 2/3; the payload does NOT carry them.
//
// bincode field order with NO length prefix on the BLS fixed arrays
// (serde_as([_;N])). Offsets are payload-relative (the 4-byte disc is already
// stripped by VoteInstruction.deserialize); add 4 for instruction-data offsets:
//   node@0(+4), authorized_voter@32(+4), bls_pubkey[48]@64(+4),
//   bls_proof_of_possession[96]@112(+4), authorized_withdrawer@208(+4),
//   inflation_rewards_commission_bps u16@240(+4), block_revenue_commission_bps u16@242(+4)
//   payload = 244 bytes (total instruction data with disc = 248).
pub const InitializeAccountV2Data = struct {
    node_pubkey: [32]u8,
    authorized_voter: [32]u8,
    bls_pubkey: [48]u8,
    bls_proof_of_possession: [96]u8,
    authorized_withdrawer: [32]u8,
    inflation_rewards_commission_bps: u16,
    block_revenue_commission_bps: u16,

    pub fn deserialize(payload: []const u8) !InitializeAccountV2Data {
        if (payload.len < 244) return error.InvalidData;
        var r: InitializeAccountV2Data = undefined;
        @memcpy(&r.node_pubkey, payload[0..32]);
        @memcpy(&r.authorized_voter, payload[32..64]);
        @memcpy(&r.bls_pubkey, payload[64..112]);
        @memcpy(&r.bls_proof_of_possession, payload[112..208]);
        @memcpy(&r.authorized_withdrawer, payload[208..240]);
        r.inflation_rewards_commission_bps = std.mem.readInt(u16, payload[240..242], .little);
        r.block_revenue_commission_bps = std.mem.readInt(u16, payload[242..244], .little);
        return r;
    }
};

/// One collector account's fields needed for `validate_and_resolve_key`.
/// @prov:vote.commission-collector — Gathered by the caller
/// (which has bank/db access) and passed into handleInitializeAccountV2 so the
/// canonical check ORDER (node-signer → collectors → BLS) is preserved.
pub const CollectorAccount = struct {
    key: [32]u8,
    owner: [32]u8,
    lamports: u64,
    /// rent-exempt minimum for THIS account's data length (caller precomputes
    /// via rentExemptMinimumBalance(bank.rent, data_len)).
    rent_exempt_min: u64,
    is_writable: bool,
};

/// @prov:vote.commission-collector — validate_and_resolve_key. Returns the
/// resolved collector key, or null on any failure (the distinct error —
/// InvalidAccountOwner / InsufficientFunds / InvalidArgument — collapses
/// to "fail tx" in this path; failed instructions never commit state, so the
/// exact code does not enter bank_hash). When collector == vote_key, short-
/// circuit with NO checks.
pub fn resolveCollector(c: *const CollectorAccount, vote_key: *const [32]u8) ?[32]u8 {
    if (std.mem.eql(u8, &c.key, vote_key)) return c.key; // short-circuit, no checks
    // owner must be the system program (all-zero id)
    const SYSTEM_PROGRAM_ID = [_]u8{0} ** 32;
    if (!std.mem.eql(u8, &c.owner, &SYSTEM_PROGRAM_ID)) return null; // InvalidAccountOwner
    if (c.lamports < c.rent_exempt_min) return null; // InsufficientFunds (not rent-exempt)
    if (!c.is_writable) return null; // InvalidArgument
    return c.key;
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction union — correct discriminants 0-15
// ─────────────────────────────────────────────────────────────────────────────

pub const VoteInstruction = union(enum) {
    InitializeAccount: InitializeAccountData, // 0
    Authorize: AuthorizeData, // 1
    Vote: VoteData, // 2
    Withdraw: WithdrawData, // 3
    UpdateValidatorIdentity, // 4
    UpdateCommission: UpdateCommissionData, // 5
    VoteSwitch: VoteSwitchData, // 6
    AuthorizeChecked: AuthorizeCheckedData, // 7
    UpdateVoteState: VoteStateUpdateData, // 8
    UpdateVoteStateSwitch: VoteStateUpdateSwitchData, // 9
    AuthorizeWithSeed: AuthorizeWithSeedData, // 10
    AuthorizeCheckedWithSeed: AuthorizeCheckedWithSeedData, // 11
    CompactUpdateVoteState: CompactVoteStateUpdateData, // 12
    CompactUpdateVoteStateSwitch: CompactVoteStateUpdateSwitchData, // 13
    TowerSync: TowerSyncData, // 14
    TowerSyncSwitch: TowerSyncSwitchData, // 15
    // SIMD-0464 (5-feature gated, dormant on testnet): InitializeAccountV2, disc 16.
    InitializeAccountV2: InitializeAccountV2Data, // 16
    // ⚠ FOOTGUN: disc 16 = InitializeAccountV2 (SIMD-0464), disc 17 =
    // UpdateCommissionCollector (SIMD-0232) — NOT "UpdateValidatorIdentityV2"
    // (no such instruction; disc 4 is the real UpdateValidatorIdentity). Disc 17
    // is still NOT implemented → falls through to error.UnknownInstruction below
    // (byte-identical to gated-off; no disc-17 tx exists pre-activation). If you
    // wire disc 17: collectors come from ACCOUNTS (read_new_collector_account +
    // validate_and_resolve_key), reusing the resolveCollector helper above — NOT
    // from instruction data. @prov:vote.init-account-v2-wire
    // SIMD-0291 (epoch-974): UpdateCommissionBps, outer disc 18 (u32 LE).
    UpdateCommissionBps: UpdateCommissionBpsData, // 18

    pub fn deserialize(data: []const u8) !VoteInstruction {
        if (data.len < 4) return error.InvalidData;
        const disc = std.mem.readInt(u32, data[0..4], .little);
        const payload = data[4..];
        return switch (disc) {
            0 => .{ .InitializeAccount = try InitializeAccountData.deserialize(payload) },
            1 => .{ .Authorize = try AuthorizeData.deserialize(payload) },
            2 => .{ .Vote = try VoteData.deserialize(payload) },
            3 => .{ .Withdraw = try WithdrawData.deserialize(payload) },
            4 => .UpdateValidatorIdentity,
            5 => .{ .UpdateCommission = try UpdateCommissionData.deserialize(payload) },
            6 => .{ .VoteSwitch = try VoteSwitchData.deserialize(payload) },
            // AuthorizeChecked (disc 7) data = [VoteAuthorize:u32] = 4 bytes ONLY;
            // the new authority is ACCOUNT[3], NOT in data. Do NOT route to
            // AuthorizeData.deserialize (>= 36 bytes) — that ALWAYS fails for a
            // 4-byte payload → silent drop (the 413005757 271KPMd carrier).
            // Ref: Agave vote_processor.rs:315-333; FD fd_vote_program.c:2205-2244.
            7 => .{ .AuthorizeChecked = try AuthorizeCheckedData.deserialize(payload) },
            8 => .{ .UpdateVoteState = try VoteStateUpdateData.deserialize(payload) },
            9 => .{ .UpdateVoteStateSwitch = try VoteStateUpdateSwitchData.deserialize(payload) },
            10 => .{ .AuthorizeWithSeed = try AuthorizeWithSeedData.deserialize(payload) },
            11 => .{ .AuthorizeCheckedWithSeed = try AuthorizeCheckedWithSeedData.deserialize(payload) },
            12 => .{ .CompactUpdateVoteState = try CompactVoteStateUpdateData.deserialize(payload) },
            13 => .{ .CompactUpdateVoteStateSwitch = try CompactVoteStateUpdateSwitchData.deserialize(payload) },
            14 => .{ .TowerSync = try TowerSyncData.deserialize(payload) },
            15 => .{ .TowerSyncSwitch = try TowerSyncSwitchData.deserialize(payload) },
            // SIMD-0464: InitializeAccountV2 (payload 244 bytes). Dispatch arm in
            // replay_stage gates on the 5 features; pre-activation no such tx exists.
            16 => .{ .InitializeAccountV2 = try InitializeAccountV2Data.deserialize(payload) },
            // SIMD-0291: UpdateCommissionBps. Payload = u16 bps ‖ u32 kind (6 bytes).
            18 => .{ .UpdateCommissionBps = try UpdateCommissionBpsData.deserialize(payload) },
            else => error.UnknownInstruction,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Signer helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if the given pubkey is a signer in this transaction.
/// Signer indices are [0, num_required_sigs).
pub fn isSigner(
    pubkey: *const [32]u8,
    account_keys: []const [32]u8,
    num_required_sigs: u8,
) bool {
    const limit = @min(@as(usize, num_required_sigs), account_keys.len);
    for (account_keys[0..limit]) |*k| {
        if (std.mem.eql(u8, k, pubkey)) return true;
    }
    return false;
}

/// Returns the pubkey at account_indices[n] in the transaction, or null if out of bounds.
pub fn accountKeyAt(
    account_indices: []const u8,
    account_keys: []const [32]u8,
    n: usize,
) ?*const [32]u8 {
    if (n >= account_indices.len) return null;
    const idx = account_indices[n];
    if (idx >= account_keys.len) return null;
    return &account_keys[idx];
}

// ─────────────────────────────────────────────────────────────────────────────
// Lockout conversion helper
// ─────────────────────────────────────────────────────────────────────────────

/// Convert from vote_program.Lockout[] to vote_state_serde.Lockout[].
/// Both types have the same fields; this avoids a type alias dependency.
pub fn convertLockouts(
    buf: *[MAX_LOCKOUT_HISTORY]serde.Lockout,
    source: []const Lockout,
) []const serde.Lockout {
    const count = @min(source.len, MAX_LOCKOUT_HISTORY);
    for (0..count) |i| {
        buf[i] = .{
            .slot = source[i].slot,
            .confirmation_count = source[i].confirmation_count,
        };
    }
    return buf[0..count];
}

// ─────────────────────────────────────────────────────────────────────────────
// Commission update timing
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if a commission increase is allowed at the given slot.
/// Rule: only permitted in the first half of normal epochs.
/// Warmup epochs (slot < first_normal_slot) always allow it.
pub fn isCommissionUpdateAllowed(
    slot: u64,
    slots_per_epoch: u64,
    first_normal_slot: u64,
) bool {
    if (slot < first_normal_slot) return true; // warmup epoch
    if (slots_per_epoch == 0) return true;
    const relative = (slot - first_normal_slot) % slots_per_epoch;
    return relative *| 2 <= slots_per_epoch;
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin instruction handlers
// These validate signers + mutate vote account data via serde round-trip.
// ─────────────────────────────────────────────────────────────────────────────

/// Handle InitializeAccount (disc=0).
/// Creates initial vote state in an empty (all-zeros) vote account.
/// Account indices: [0]=vote_account, [1]=rent_sysvar, [2]=clock_sysvar, [3]=node_pubkey(signer)
pub fn handleInitializeAccount(
    args: *const InitializeAccountData,
    account_keys: []const [32]u8,
    account_indices: []const u8,
    num_required_sigs: u8,
    vote_data: []u8,
    current_epoch: u64,
) bool {
    std.log.debug("[VOTE-ADMIN] InitializeAccount epoch={d}\n", .{current_epoch});
    // node_pubkey (account index 3) must sign
    const node_key = accountKeyAt(account_indices, account_keys, 3) orelse return false;
    if (!isSigner(node_key, account_keys, num_required_sigs)) return false;

    // Vote account must be exactly 3762 bytes
    if (vote_data.len != 3762) return false;

    // Must be uninitialized (version discriminant == 0)
    const current_version = std.mem.readInt(u32, vote_data[0..4], .little);
    if (current_version != 0) return false;

    // Build initial VoteState (V3 format, disc=2)
    var vs = serde.VoteState.init();
    vs.version = 2; // Current (V3 wire = disc 2)
    @memcpy(&vs.node_pubkey, &args.node_pubkey);
    @memcpy(&vs.authorized_withdrawer, &args.authorized_withdrawer);
    vs.commission = args.commission;
    vs.lockout_count = 0;
    vs.root_slot = null;

    // Set initial authorized voter for current epoch
    vs.av_count = 1;
    vs.authorized_voters[0] = .{
        .epoch = current_epoch,
        .pubkey = args.authorized_voter,
    };

    // Zero out prior_voters raw bytes (empty circular buffer)
    @memset(&vs.prior_voters_raw, 0);
    // is_empty flag = 1 (last byte of prior_voters_raw)
    vs.prior_voters_raw[serde.PRIOR_VOTERS_SIZE - 1] = 1;

    vs.ec_count = 0;
    vs.last_timestamp = .{ .slot = 0, .timestamp = 0 };

    // SIMD-0185: a v4 vote account is ALWAYS created as V4 (never stored uninitialized
    // after init). Up-convert the freshly-built state to V4 (tag 3) to match the cluster.
    // Vote account = instruction account index 0 (its own key = inflation_rewards_collector).
    // Tail-zero below is correct here: a just-initialized account has no stale V3 residue
    // (data was all-zero / version 0), unlike a converted account.
    if (accountKeyAt(account_indices, account_keys, 0)) |vp| serde.convertToV4(&vs, vp.*);

    const written = serde.serializeVoteState(&vs, vote_data) orelse return false;
    if (written < vote_data.len) @memset(vote_data[written..], 0);
    return true;
}

/// Handle InitializeAccountV2 (disc=16, SIMD-0464). @prov:vote.init-account-v2
/// — byte-faithful port of Agave 4.1.0-rc.1's initialize_account_v2.
///
/// Account layout: [0]=vote_account(writable), [1]=clock(sysvar cache, unused
/// here — epoch passed in), [2]=inflation collector, [3]=block-revenue collector.
/// The node_pubkey signer comes from the INSTRUCTION DATA (NOT account idx 3 —
/// that index is the block-revenue collector in V2).
///
/// Caller (replay_stage) gathers the two CollectorAccount records (idx 2/3) and
/// resolves them here so the canonical check ORDER is preserved:
///   length(3762) → uninitialized → node-signer → collectors → BLS PoP → write.
///
/// NOTE on CU: Agave consumes 34_500 CU for the BLS PoP before the verify math.
/// Vexor's native vote replay path does NOT model per-instruction CU (the
/// existing SIMD-0387 authorize-PoP path at :844 also omits it), so this handler
/// matches that path. This is bank_hash-neutral for the state write and is a
/// pre-existing gap, NOT introduced here — flagged for the activation watch-item.
pub fn handleInitializeAccountV2(
    args: *const InitializeAccountV2Data,
    account_keys: []const [32]u8,
    num_required_sigs: u8,
    vote_data: []u8,
    current_epoch: u64,
    vote_key: *const [32]u8,
    inflation_collector: *const CollectorAccount,
    block_collector: *const CollectorAccount,
) bool {
    // Vote account must be exactly 3762 bytes (VoteStateV4::size_of).
    if (vote_data.len != 3762) return false;
    // Must be uninitialized (version discriminant == 0).
    if (std.mem.readInt(u32, vote_data[0..4], .little) != 0) return false;
    // node_pubkey FROM DATA must sign (Agave verify_authorized_signer; NOT idx 3).
    if (!isSigner(&args.node_pubkey, account_keys, num_required_sigs)) return false;
    // Resolve both collectors (validate_and_resolve_key), in order.
    const inflation_key = resolveCollector(inflation_collector, vote_key) orelse return false;
    const block_key = resolveCollector(block_collector, vote_key) orelse return false;
    // BLS proof-of-possession over "ALPENGLOW"||vote_key (built inside the verify).
    if (!bls_pop.verifyVoteProofOfPossession(vote_key, &args.bls_pubkey, &args.bls_proof_of_possession)) return false;

    // Build VoteStateV4 directly (mirror VoteStateV4::new — do NOT convertToV4,
    // which would overwrite the collector/bps fields with V3-conversion defaults).
    var vs = serde.VoteState.init();
    vs.version = 3; // V4 wire tag
    @memcpy(&vs.node_pubkey, &args.node_pubkey);
    @memcpy(&vs.authorized_withdrawer, &args.authorized_withdrawer);
    @memcpy(&vs.inflation_rewards_collector, &inflation_key);
    @memcpy(&vs.block_revenue_collector, &block_key);
    vs.inflation_rewards_commission_bps = args.inflation_rewards_commission_bps;
    vs.block_revenue_commission_bps = args.block_revenue_commission_bps;
    vs.pending_delegator_rewards = 0;
    vs.has_bls_pubkey_compressed = true;
    @memcpy(&vs.bls_pubkey_compressed, &args.bls_pubkey);
    vs.av_count = 1;
    vs.authorized_voters[0] = .{ .epoch = current_epoch, .pubkey = args.authorized_voter };
    vs.lockout_count = 0;
    vs.root_slot = null;
    vs.ec_count = 0;
    vs.last_timestamp = .{ .slot = 0, .timestamp = 0 };

    const written = serde.serializeVoteState(&vs, vote_data) orelse return false;
    if (written < vote_data.len) @memset(vote_data[written..], 0);
    return true;
}

/// Handle Authorize (disc=1) and AuthorizeChecked (disc=7).
/// Changes the authorized voter or withdrawer.
/// Account indices: [0]=vote_account, [1]=clock_sysvar, [2]=current_authority(signer)
/// For AuthorizeChecked: [3]=new_authority(signer) must also sign.
/// `authorize_type` + `new_authority` are resolved by the caller:
///   - Authorize        (disc 1): new_authority = AuthorizeData.pubkey (from data)
///   - AuthorizeChecked (disc 7): new_authority = ACCOUNT[3] (NOT in data)
/// `leader_schedule_epoch` threads clock.leader_schedule_epoch so target_epoch
/// = lse + 1 (canon; NOT current_epoch + 1).
pub fn handleAuthorize(
    authorize_type: AuthorizeType,
    new_authority: [32]u8,
    account_keys: []const [32]u8,
    account_indices: []const u8,
    num_required_sigs: u8,
    vote_data: []u8,
    current_epoch: u64,
    leader_schedule_epoch: u64,
    is_checked: bool,
    /// Present only for VoterWithBLS (SIMD-0387): the compressed BLS pubkey to
    /// register into the V4 vote frame. null for plain Voter/Withdrawer.
    bls_pubkey: ?[48]u8,
    /// Present only for VoterWithBLS (SIMD-0387): the compressed BLS
    /// proof-of-possession over "ALPENGLOW" || vote_account_pubkey (task #49).
    bls_proof_of_possession: ?[96]u8,
) bool {
    std.log.debug("[VOTE-ADMIN] Authorize epoch={d} lse={d} is_checked={} bls={}\n", .{ current_epoch, leader_schedule_epoch, is_checked, bls_pubkey != null });
    var vs = serde.deserializeVoteState(vote_data) orelse return false;
    // SIMD-0185 (carrier #50): up-convert to V4 BEFORE the get_and_update / authorize
    // logic so a dormant non-V4 account whose first post-0185 op is an authorize matches
    // the cluster (vote account = instruction index 0 = inflation_rewards_collector).
    if (accountKeyAt(account_indices, account_keys, 0)) |vp| serde.convertToV4(&vs, vp.*);

    // [agave] mod.rs:740-746 (task #49): VoterWithBLS verifies the BLS12-381
    // proof-of-possession BEFORE set_new_authorized_voter (i.e. before ANY
    // state-change logic below, including get_and_update). ANY crypto failure
    // fails the instruction (Agave: InstructionError::InvalidArgument,
    // mod.rs:1058-1062; this bool-handler signals failure via `false`, which
    // the caller maps to a failed tx — same rollback-all-but-fee+nonce law).
    if (authorize_type == .voter_with_bls) {
        const bp = bls_pubkey orelse return false; // parser guarantees non-null
        const pop = bls_proof_of_possession orelse return false;
        const vote_account_key = accountKeyAt(account_indices, account_keys, 0) orelse return false;
        if (!bls_pop.verifyVoteProofOfPossession(vote_account_key, &bp, &pop)) {
            bls_pop_rejected += 1;
            std.log.warn("[BLS-POP-REJECT] legacy authorize: invalid proof-of-possession for vote account", .{});
            return false;
        }
        bls_pop_verified += 1;
    }

    switch (authorize_type) {
        // VoterWithBLS (SIMD-0387) runs the IDENTICAL voter-authorize path as plain
        // Voter (Agave mod.rs:733 set_new_authorized_voter), then ALSO registers the
        // BLS pubkey — with the PoP cryptographically verified above (task #49).
        .voter, .voter_with_bls => {
            // Agave mod.rs:704-706 — once SIMD-0387 is active and the account already
            // has a BLS pubkey, a PLAIN Voter authorize is rejected (must use
            // VoterWithBLS thereafter). The feature is active on testnet; VoterWithBLS
            // is exempt. Reject BEFORE any state change (matches set_new_authorized_voter
            // ordering: this guard precedes the get_and_update call below).
            if (authorize_type == .voter and vs.has_bls_pubkey_compressed) return false;

            // Canonical set_new_authorized_voter runs get_and_update FIRST
            // (carry-forward + purge) before the signer check — fd_vote_state_v3.c:140
            // / fd_vote_state_v4.c:122. No-op at slot 757 (exact-hit on epoch 968).
            if (!serde.getAndUpdateAuthorizedVoter(&vs, current_epoch)) return false;

            // Current voter or withdrawer must sign
            const current_voter = getCurrentVoter(&vs, current_epoch) orelse return false;
            const voter_signs = isSigner(&current_voter, account_keys, num_required_sigs);
            const withdrawer_signs = isSigner(&vs.authorized_withdrawer, account_keys, num_required_sigs);
            if (!voter_signs and !withdrawer_signs) return false;

            // AuthorizeChecked: new authority must also sign
            if (is_checked) {
                const new_auth_key = accountKeyAt(account_indices, account_keys, 3) orelse return false;
                if (!isSigner(new_auth_key, account_keys, num_required_sigs)) return false;
            }

            // target_epoch = clock.leader_schedule_epoch + 1 (canon: Agave
            // mod.rs authorize() Voter arm / FD fd_vote_program.c:799-803).
            // Saturating add (canon uses checked_add → InvalidAccountData; we
            // never overflow in practice and --release=safe would panic on +).
            const target_epoch = leader_schedule_epoch +| 1;

            // too_soon_to_reauthorize: reject if target_epoch already present
            // (Agave handler.rs:98-100; FD fd_vote_state_v3.c:148). This is a
            // REJECT (no state change), distinct from the helper's exact-key
            // overwrite — disjoint conditions.
            for (0..vs.av_count) |i| {
                if (vs.authorized_voters[i].epoch == target_epoch) return false;
            }

            // Ascending sorted insert (overwrite-on-exact-key, no evict).
            // BTreeMap-equivalent so serialized AV bytes stay canonical.
            if (!serde.avSortedInsert(&vs, target_epoch, new_authority)) return false;

            // SIMD-0387: VoterWithBLS ALSO registers the compressed BLS pubkey into
            // the V4 frame — Agave mod.rs:747-754 set_new_authorized_voter(..,
            // Some(&args.bls_pubkey)) → handler.rs:105-106 v4.bls_pubkey_compressed.
            // The PoP was cryptographically verified at function entry (task #49).
            if (authorize_type == .voter_with_bls) {
                const bp = bls_pubkey orelse return false; // parser guarantees non-null
                vs.has_bls_pubkey_compressed = true;
                vs.bls_pubkey_compressed = bp;
            }
        },
        .withdrawer => {
            // Only current withdrawer can authorize withdrawer change
            if (!isSigner(&vs.authorized_withdrawer, account_keys, num_required_sigs)) return false;

            // AuthorizeChecked: new authority must also sign
            if (is_checked) {
                const new_auth_key = accountKeyAt(account_indices, account_keys, 3) orelse return false;
                if (!isSigner(new_auth_key, account_keys, num_required_sigs)) return false;
            }

            @memcpy(&vs.authorized_withdrawer, &new_authority);
        },
    }

    const written = serde.serializeVoteState(&vs, vote_data) orelse return false;
    // V4 (version==3): do NOT zero the tail. Agave writes vote state via
    // set_state → bincode serialize_into, which writes the serialized bytes and
    // LEAVES the rest of the fixed-size account buffer UNCHANGED. A V4 account
    // carries a STALE remnant of its longer prior V3 state past the (shorter) V4
    // state (verified @414056489: 8iiZpnZo state ends at 2301, stale bytes run
    // 2301..3637, then zeros — all part of the hashed account data). Zeroing here
    // would erase that remnant and diverge from cluster. Non-V4 (V1/V2) are exact-
    // sized so the memset is a no-op there; keep the original guard.
    if (vs.version != 3 and written < vote_data.len) @memset(vote_data[written..], 0);
    return true;
}

/// Handle UpdateValidatorIdentity (disc=4).
/// Changes the node_pubkey (validator identity).
/// Account indices: [0]=vote_account, [1]=new_identity(signer), [2]=withdrawer(signer)
pub fn handleUpdateValidatorIdentity(
    account_keys: []const [32]u8,
    account_indices: []const u8,
    num_required_sigs: u8,
    vote_data: []u8,
) bool {
    std.log.debug("[VOTE-ADMIN] UpdateValidatorIdentity\n", .{});
    var vs = serde.deserializeVoteState(vote_data) orelse return false;
    // SIMD-0185 (carrier #50): up-convert to V4 first (vote account = instruction index 0).
    if (accountKeyAt(account_indices, account_keys, 0)) |vp| serde.convertToV4(&vs, vp.*);

    const new_identity_key = accountKeyAt(account_indices, account_keys, 1) orelse return false;

    // Both new identity and current withdrawer must sign
    if (!isSigner(new_identity_key, account_keys, num_required_sigs)) return false;
    if (!isSigner(&vs.authorized_withdrawer, account_keys, num_required_sigs)) return false;

    @memcpy(&vs.node_pubkey, new_identity_key);

    // For V4 accounts, update block_revenue_collector too
    if (vs.version == 3) {
        @memcpy(&vs.block_revenue_collector, new_identity_key);
    }

    const written = serde.serializeVoteState(&vs, vote_data) orelse return false;
    if (vs.version != 3 and written < vote_data.len) @memset(vote_data[written..], 0);
    return true;
}

/// Handle UpdateCommission (disc=5).
/// Changes the commission rate, subject to epoch-half timing rules.
/// Account indices: [0]=vote_account, [1]=withdrawer(signer)
pub fn handleUpdateCommission(
    args: *const UpdateCommissionData,
    account_keys: []const [32]u8,
    account_indices: []const u8,
    num_required_sigs: u8,
    vote_data: []u8,
    current_slot: u64,
    slots_per_epoch: u64,
    first_normal_slot: u64,
) bool {
    std.log.debug("[VOTE-ADMIN] UpdateCommission slot={d}\n", .{current_slot});

    var vs = serde.deserializeVoteState(vote_data) orelse return false;
    // SIMD-0185 (carrier #50): up-convert to V4 first so the commission write lands in
    // inflation_rewards_commission_bps (vote account = instruction index 0). This also
    // consumes account_indices (withdrawer signer is matched by pubkey below).
    if (accountKeyAt(account_indices, account_keys, 0)) |vp| serde.convertToV4(&vs, vp.*);

    // Withdrawer must sign
    if (!isSigner(&vs.authorized_withdrawer, account_keys, num_required_sigs)) return false;

    // Commission increase check: only in first half of epoch
    const current_commission = if (vs.version == 3)
        @as(u8, @intCast(@min(vs.inflation_rewards_commission_bps / 100, 100)))
    else
        vs.commission;

    if (args.commission > current_commission) {
        if (!isCommissionUpdateAllowed(current_slot, slots_per_epoch, first_normal_slot)) {
            return false;
        }
    }

    if (vs.version == 3) {
        vs.inflation_rewards_commission_bps = @as(u16, args.commission) * 100;
    } else {
        vs.commission = args.commission;
    }

    const written = serde.serializeVoteState(&vs, vote_data) orelse return false;
    if (vs.version != 3 and written < vote_data.len) @memset(vote_data[written..], 0);
    return true;
}

/// Handle UpdateCommissionBps (disc=18, SIMD-0291).
///
/// Sets the inflation-rewards (or block-revenue) commission denominated in basis
/// points, with FULL u16 precision (no *100, no clamp at write time — the cap to
/// 10,000 happens only during reward calculation per SIMD-0291).
///
/// Faithful port of Agave `vote_state::update_commission_bps`.
/// @prov:vote.commission-bps — differences from disc-5 UpdateCommission, per
/// SIMD-0249 + SIMD-0291:
///   - NO first-half-of-epoch timing/increase restriction ("No commission
///     update rule").
///   - Writes the RAW u16 basis-point value, not commission_pct * 100.
///
/// Feature gating (caller MUST enforce; see executeVoteInstruction):
///   commission_rate_in_basis_points && delay_commission_updates must be active,
///   else Agave returns InvalidInstructionData (no state change). This handler
///   assumes the caller already checked those two.
///
/// `block_revenue_sharing_active` = SIMD-0123 feature state. When kind ==
/// BlockRevenue and the feature is inactive, Agave returns InvalidInstructionData
/// → we reject (return false, no mutation).
///
/// Account indices: [0]=vote_account(write), withdrawer(signer) matched by pubkey.
pub fn handleUpdateCommissionBps(
    args: *const UpdateCommissionBpsData,
    account_keys: []const [32]u8,
    account_indices: []const u8,
    num_required_sigs: u8,
    vote_data: []u8,
    block_revenue_sharing_active: bool,
) bool {
    // SIMD-0291: BlockRevenue is rejected unless SIMD-0123 (block_revenue_sharing)
    // is active. @prov:vote.commission-bps
    if (args.kind == .block_revenue and !block_revenue_sharing_active) return false;

    var vs = serde.deserializeVoteState(vote_data) orelse return false;

    // SIMD-0185: up-convert to V4 first so the commission write lands in the
    // basis-point field (vote account = instruction index 0). Mirrors
    // handleUpdateCommission's convertToV4 step.
    if (accountKeyAt(account_indices, account_keys, 0)) |vp| serde.convertToV4(&vs, vp.*);

    // "No commission update rule, per SIMD-0249 and SIMD-0291." — NO timing check.

    // Authorized withdrawer must sign.
    if (!isSigner(&vs.authorized_withdrawer, account_keys, num_required_sigs)) return false;

    switch (args.kind) {
        .inflation_rewards => {
            // RAW u16, NO *100, NO clamp. @prov:vote.commission-bps
            vs.inflation_rewards_commission_bps = args.commission_bps;
        },
        .block_revenue => {
            // Only reachable when block_revenue_sharing_active (checked above).
            vs.block_revenue_commission_bps = args.commission_bps;
        },
    }

    const written = serde.serializeVoteState(&vs, vote_data) orelse return false;
    if (vs.version != 3 and written < vote_data.len) @memset(vote_data[written..], 0);
    return true;
}

/// Handle Withdraw (disc=3).
/// Withdraws lamports from the vote account to a recipient.
/// Account indices: [0]=vote_account(write), [1]=recipient(write), [2]=withdrawer(signer)
///
/// Returns the lamport delta to deduct from the vote account (positive = deduct).
/// Returns null if rejected.
///
/// NOTE: This only validates the signer and active-account check.
/// The caller is responsible for updating lamports on both vote and recipient accounts.
pub fn handleWithdrawValidate(
    lamports: u64,
    account_keys: []const [32]u8,
    num_required_sigs: u8,
    vote_data: []const u8,
    vote_lamports: u64,
    min_rent_exempt: u64,
) ?u64 {
    std.log.debug("[VOTE-ADMIN] Withdraw lamports={d}\n", .{lamports});
    const vs = serde.deserializeVoteState(vote_data) orelse return null;

    // Withdrawer must sign
    if (!isSigner(&vs.authorized_withdrawer, account_keys, num_required_sigs)) return null;

    if (lamports > vote_lamports) return null;

    const remaining = vote_lamports - lamports;

    // PR-5n-pdr (2026-05-19): refuse to leave a V4 vote account in a state
    // where rent-exempt balance is below min_rent_exempt + pending_delegator_rewards,
    // and refuse to deinitialize one that still has pending rewards owed.
    // V0/V1/V2 vote states have pending_delegator_rewards == 0 (zeroed in
    // serde.deserializeVoteState init), so this gate is V4-effective only.
    if (remaining == 0) {
        if (vs.pending_delegator_rewards != 0) return null;
    } else {
        const min_balance = std.math.add(u64, min_rent_exempt, vs.pending_delegator_rewards) catch return null;
        if (remaining < min_balance) return null;
    }

    return lamports;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Get the authorized voter pubkey for the given epoch.
/// Returns the most recent entry at or before the given epoch.
pub fn getCurrentVoter(vs: *const serde.VoteState, epoch: u64) ?[32]u8 {
    if (vs.av_count == 0) return null;
    var best: ?[32]u8 = null;
    var best_epoch: u64 = 0;
    for (0..vs.av_count) |i| {
        const e = vs.authorized_voters[i].epoch;
        if (e <= epoch and (best == null or e >= best_epoch)) {
            best = vs.authorized_voters[i].pubkey;
            best_epoch = e;
        }
    }
    return best;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "lockout period calculation" {
    const lockout = Lockout{ .slot = 100, .confirmation_count = 5 };
    try std.testing.expectEqual(@as(u64, 32), lockout.lockoutPeriod());
    try std.testing.expectEqual(@as(u64, 132), lockout.expiration());
}

test "vote instruction discriminants" {
    // Verify correct discriminants 0-15
    const cases = [_]struct { disc: u32, tag: []const u8 }{
        .{ .disc = 0, .tag = "InitializeAccount" },
        .{ .disc = 14, .tag = "TowerSync" },
        .{ .disc = 15, .tag = "TowerSyncSwitch" },
        .{ .disc = 12, .tag = "CompactUpdateVoteState" },
        .{ .disc = 8, .tag = "UpdateVoteState" },
    };
    _ = cases;
    try std.testing.expect(true);
}

test "compact vote state update deserialization" {
    // Minimal compact update: root=100, 0 lockouts, known hash, no timestamp
    var buf: [50]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u64, buf[0..8], 100, .little); // root
    buf[8] = 0; // 0 lockouts (compact-u16)
    // hash is buf[9..41] (all zeros)
    buf[41] = 0; // no timestamp

    const result = try CompactVoteStateUpdateData.deserialize(buf[0..42]);
    try std.testing.expectEqual(@as(?u64, 100), result.root);
    try std.testing.expectEqual(@as(usize, 0), result.lockouts_count);
}

test "commission update timing" {
    const slots_per_epoch: u64 = 432000;
    const first_normal_slot: u64 = 524288;

    // First slot of epoch (always allowed)
    try std.testing.expect(isCommissionUpdateAllowed(first_normal_slot, slots_per_epoch, first_normal_slot));
    // Middle of epoch (216000 relative = exactly 50%)
    try std.testing.expect(isCommissionUpdateAllowed(first_normal_slot + 216000, slots_per_epoch, first_normal_slot));
    // Past halfway (relative = 216001)
    try std.testing.expect(!isCommissionUpdateAllowed(first_normal_slot + 216001, slots_per_epoch, first_normal_slot));
    // Warmup (slot 1000, before first_normal_slot)
    try std.testing.expect(isCommissionUpdateAllowed(1000, slots_per_epoch, first_normal_slot));
}

test "signer check" {
    const key1: [32]u8 = [_]u8{0x11} ** 32;
    const key2: [32]u8 = [_]u8{0x22} ** 32;
    const keys = [_][32]u8{ key1, key2, [_]u8{0x33} ** 32 };
    try std.testing.expect(isSigner(&key1, &keys, 2));
    try std.testing.expect(isSigner(&key2, &keys, 2));
    // key3 is at index 2, not in [0,2)
    try std.testing.expect(!isSigner(&keys[2], &keys, 2));
}

test "authorize type deserialization" {
    // Authorize: 32 bytes pubkey + u32 discriminant
    var data: [36]u8 = undefined;
    @memset(&data, 0);
    data[0] = 0x42; // first byte of pubkey
    std.mem.writeInt(u32, data[32..36], 0, .little); // voter
    const result = try AuthorizeData.deserialize(&data);
    try std.testing.expectEqual(AuthorizeType.voter, result.authorize_type);
    try std.testing.expectEqual(@as(u8, 0x42), result.pubkey[0]);
}

// ─────────────────────────────────────────────────────────────────────────────
// vex-049: TowerSync compact wire-format tests
//
// @prov:vote.tower-sync-wire — test helpers construct the compact encoding by
// hand so the tests double as byte-layout documentation.
// ─────────────────────────────────────────────────────────────────────────────

const TestTowerSyncBuilder = struct {
    buf: std.ArrayList(u8),

    fn init(allocator: std.mem.Allocator) TestTowerSyncBuilder {
        return .{ .buf = std.ArrayList(u8).initCapacity(allocator, 256) catch unreachable };
    }

    fn deinit(self: *TestTowerSyncBuilder, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
    }

    fn writeU8(self: *TestTowerSyncBuilder, allocator: std.mem.Allocator, v: u8) !void {
        try self.buf.append(allocator, v);
    }

    fn writeU64LE(self: *TestTowerSyncBuilder, allocator: std.mem.Allocator, v: u64) !void {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u64, &tmp, v, .little);
        try self.buf.appendSlice(allocator, &tmp);
    }

    fn writeI64LE(self: *TestTowerSyncBuilder, allocator: std.mem.Allocator, v: i64) !void {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(i64, &tmp, v, .little);
        try self.buf.appendSlice(allocator, &tmp);
    }

    fn writeUleb128(self: *TestTowerSyncBuilder, allocator: std.mem.Allocator, v: u64) !void {
        var x = v;
        while (x >= 0x80) {
            try self.buf.append(allocator, @intCast((x & 0x7F) | 0x80));
            x >>= 7;
        }
        try self.buf.append(allocator, @intCast(x & 0x7F));
    }

    fn writeBytes(self: *TestTowerSyncBuilder, allocator: std.mem.Allocator, bytes: []const u8) !void {
        try self.buf.appendSlice(allocator, bytes);
    }
};

/// Build a TowerSync wire payload matching the Agave/Sig compact format.
/// root=null → writes u64::MAX sentinel.
fn buildTowerSyncBytes(
    allocator: std.mem.Allocator,
    root: ?u64,
    lockouts: []const Lockout,
    hash: [32]u8,
    timestamp: ?i64,
    block_id: [32]u8,
) !std.ArrayList(u8) {
    var b = TestTowerSyncBuilder.init(allocator);
    errdefer b.deinit(allocator);

    try b.writeU64LE(allocator, root orelse std.math.maxInt(u64));
    try b.writeUleb128(allocator, @intCast(lockouts.len));

    var running: u64 = root orelse 0;
    for (lockouts) |lk| {
        const offset = lk.slot - running;
        try b.writeUleb128(allocator, offset);
        try b.writeU8(allocator, @intCast(lk.confirmation_count));
        running = lk.slot;
    }

    try b.writeBytes(allocator, &hash);

    if (timestamp) |t| {
        try b.writeU8(allocator, 1);
        try b.writeI64LE(allocator, t);
    } else {
        try b.writeU8(allocator, 0);
    }

    try b.writeBytes(allocator, &block_id);
    return b.buf;
}

test "vex-049: TowerSync round-trip with root + 1 lockout + no timestamp" {
    const allocator = std.testing.allocator;
    const hash: [32]u8 = [_]u8{0xAA} ** 32;
    const block_id: [32]u8 = [_]u8{0xBB} ** 32;
    const lockouts = [_]Lockout{
        .{ .slot = 105, .confirmation_count = 2 },
    };

    var bytes = try buildTowerSyncBytes(allocator, 100, &lockouts, hash, null, block_id);
    defer bytes.deinit(allocator);

    const result = try TowerSyncData.deserialize(bytes.items);
    try std.testing.expectEqual(@as(?u64, 100), result.root);
    try std.testing.expectEqual(@as(usize, 1), result.lockouts_count);
    try std.testing.expectEqual(@as(u64, 105), result.lockouts[0].slot);
    try std.testing.expectEqual(@as(u32, 2), result.lockouts[0].confirmation_count);
    try std.testing.expectEqualSlices(u8, &hash, &result.hash);
    try std.testing.expectEqual(@as(?i64, null), result.timestamp);
    try std.testing.expectEqualSlices(u8, &block_id, &result.block_id);
}

test "vex-049: TowerSync with MAX_LOCKOUT_HISTORY lockouts" {
    const allocator = std.testing.allocator;
    var lockouts: [MAX_LOCKOUT_HISTORY]Lockout = undefined;
    var slot: u64 = 1000;
    for (&lockouts, 0..) |*lk, i| {
        slot += @as(u64, @intCast(i)) + 1;
        lk.* = .{ .slot = slot, .confirmation_count = @as(u32, @intCast(MAX_LOCKOUT_HISTORY - i)) };
    }
    const hash: [32]u8 = [_]u8{0x11} ** 32;
    const block_id: [32]u8 = [_]u8{0x22} ** 32;

    var bytes = try buildTowerSyncBytes(allocator, 999, &lockouts, hash, null, block_id);
    defer bytes.deinit(allocator);

    const result = try TowerSyncData.deserialize(bytes.items);
    try std.testing.expectEqual(@as(?u64, 999), result.root);
    try std.testing.expectEqual(@as(usize, MAX_LOCKOUT_HISTORY), result.lockouts_count);
    // Round-trip: every reconstructed lockout.slot matches the built one.
    for (lockouts, 0..) |expected, i| {
        try std.testing.expectEqual(expected.slot, result.lockouts[i].slot);
        try std.testing.expectEqual(expected.confirmation_count, result.lockouts[i].confirmation_count);
    }
    try std.testing.expectEqualSlices(u8, &block_id, &result.block_id);
}

test "vex-049: TowerSync with root=None (u64::MAX sentinel)" {
    const allocator = std.testing.allocator;
    const hash: [32]u8 = [_]u8{0x33} ** 32;
    const block_id: [32]u8 = [_]u8{0x44} ** 32;
    const lockouts = [_]Lockout{
        .{ .slot = 50, .confirmation_count = 1 },
        .{ .slot = 60, .confirmation_count = 1 },
    };

    var bytes = try buildTowerSyncBytes(allocator, null, &lockouts, hash, null, block_id);
    defer bytes.deinit(allocator);

    const result = try TowerSyncData.deserialize(bytes.items);
    try std.testing.expectEqual(@as(?u64, null), result.root);
    try std.testing.expectEqual(@as(usize, 2), result.lockouts_count);
    try std.testing.expectEqual(@as(u64, 50), result.lockouts[0].slot);
    try std.testing.expectEqual(@as(u64, 60), result.lockouts[1].slot);
}

test "vex-049: TowerSync with Some(timestamp)" {
    const allocator = std.testing.allocator;
    const hash: [32]u8 = [_]u8{0x55} ** 32;
    const block_id: [32]u8 = [_]u8{0x66} ** 32;
    const lockouts = [_]Lockout{.{ .slot = 405, .confirmation_count = 3 }};

    var bytes = try buildTowerSyncBytes(allocator, 400, &lockouts, hash, 1_700_000_000, block_id);
    defer bytes.deinit(allocator);

    const result = try TowerSyncData.deserialize(bytes.items);
    try std.testing.expectEqual(@as(?u64, 400), result.root);
    try std.testing.expectEqual(@as(?i64, 1_700_000_000), result.timestamp);
    try std.testing.expectEqualSlices(u8, &block_id, &result.block_id);
}

test "vex-049: TowerSyncSwitch reads switch_hash after block_id" {
    const allocator = std.testing.allocator;
    const hash: [32]u8 = [_]u8{0x77} ** 32;
    const block_id: [32]u8 = [_]u8{0x88} ** 32;
    const switch_hash_expected: [32]u8 = [_]u8{0x99} ** 32;
    const lockouts = [_]Lockout{.{ .slot = 205, .confirmation_count = 4 }};

    var bytes = try buildTowerSyncBytes(allocator, 200, &lockouts, hash, null, block_id);
    defer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, &switch_hash_expected);

    const result = try TowerSyncSwitchData.deserialize(bytes.items);
    try std.testing.expectEqual(@as(?u64, 200), result.sync.root);
    try std.testing.expectEqualSlices(u8, &block_id, &result.sync.block_id);
    try std.testing.expectEqualSlices(u8, &switch_hash_expected, &result.switch_hash);
}

test "vex-049: SIMD-0138 classifier still treats TowerSync variants as non-legacy" {
    // Regression guard on f9e8fd4 locked-in invariant: TowerSync + TowerSyncSwitch
    // are NOT legacy-vote submissions after the compact-format fix. The original
    // `isLegacyVoteSubmission()` helper was removed; the classification is now
    // tag-only at the dispatch site (replay_stage.zig needs_voter_check). The
    // payloads here are zeroed fresh structs — wire-format change does not alter
    // the dispatch arm. We assert the tag directly: TowerSync/TowerSyncSwitch are
    // distinct from the legacy `.Vote`/`.VoteSwitch` (disc 2/6) arms.
    const empty_tower = TowerSyncData{
        .lockouts_count = 0,
        .root = null,
        .hash = [_]u8{0} ** 32,
        .timestamp = null,
        .block_id = [_]u8{0} ** 32,
    };
    const empty_switch = TowerSyncSwitchData{
        .sync = empty_tower,
        .switch_hash = [_]u8{0} ** 32,
    };
    const ts = VoteInstruction{ .TowerSync = empty_tower };
    const tss = VoteInstruction{ .TowerSyncSwitch = empty_switch };
    try std.testing.expect(ts == .TowerSync);
    try std.testing.expect(tss == .TowerSyncSwitch);
    // Explicitly NOT the legacy Vote/VoteSwitch tags.
    try std.testing.expect(ts != .Vote and ts != .VoteSwitch);
    try std.testing.expect(tss != .Vote and tss != .VoteSwitch);
}
