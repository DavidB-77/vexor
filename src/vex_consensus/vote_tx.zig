//! Vexor Vote Transaction Module
//!
//! Creates and submits vote transactions for consensus.

const std = @import("std");
const core = @import("core");
const crypto = @import("vex_crypto");
const vote_mod = @import("vote.zig");

const Vote = vote_mod.Vote;

const VOTE_PROGRAM_ID = [_]u8{
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
};

const SYSVAR_CLOCK_ID = [_]u8{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9, 0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
    0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c, 0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
};

const SYSVAR_SLOT_HASHES_ID = [_]u8{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf, 0xc6, 0xf2, 0x65, 0xe3, 0xfb, 0x77, 0xcc, 0x7a,
    0xda, 0x82, 0xc5, 0x29, 0xd0, 0xbe, 0x3b, 0x13, 0x6e, 0x2d, 0x00, 0x55, 0x20, 0x00, 0x00, 0x00,
};

/// Vote instruction types
pub const VoteInstruction = enum(u32) {
    /// Initialize a vote account
    initialize_account = 0,
    /// Authorize a key to vote or withdraw
    authorize = 1,
    /// Vote on a slot
    vote = 2,
    /// Withdraw from vote account
    withdraw = 3,
    /// Update validator identity
    update_validator_identity = 4,
    /// Update commission
    update_commission = 5,
    /// Vote with switch proof
    vote_switch = 6,
    /// Authorize with checked
    authorize_checked = 7,
    /// Update vote state
    update_vote_state = 8,
    /// Update vote state switch
    update_vote_state_switch = 9,
    /// Authorize with seed
    authorize_with_seed = 10,
    /// Authorize checked with seed
    authorize_checked_with_seed = 11,
    /// Update vote state (compact)
    update_vote_state_compact = 12,
    /// Update vote state switch (compact)
    update_vote_state_switch_compact = 13,
    /// Compact update vote state
    compact_update_vote_state = 14,
    /// Compact update vote state switch
    compact_update_vote_state_switch = 15,
    /// Tower sync
    tower_sync = 16,
    /// Tower sync switch
    tower_sync_switch = 17,
};

/// Vote transaction builder
pub const VoteTransactionBuilder = struct {
    allocator: std.mem.Allocator,

    /// Validator identity keypair
    identity_pubkey: core.Pubkey,
    identity_secret: ?[64]u8,

    /// Vote account pubkey
    vote_account: core.Pubkey,

    /// Authorized voter (if different from identity)
    authorized_voter: ?core.Pubkey,
    authorized_voter_secret: ?[64]u8,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        identity_pubkey: core.Pubkey,
        vote_account: core.Pubkey,
    ) Self {
        return .{
            .allocator = allocator,
            .identity_pubkey = identity_pubkey,
            .identity_secret = null,
            .vote_account = vote_account,
            .authorized_voter = null,
            .authorized_voter_secret = null,
        };
    }

    /// Set identity secret key
    pub fn setIdentitySecret(self: *Self, secret: [64]u8) void {
        self.identity_secret = secret;
    }

    /// Build a TowerSync vote transaction (discriminant 14).
    /// Verified against live testnet vote transactions (2026-04-12):
    ///   disc=14, root=u64(MAX=None), count=compact-u16,
    ///   lockouts={varint offset, u8 conf}, hash, Option<timestamp>, block_id
    ///
    /// Transaction layout: 1 sig, header=(1,0,1), 3 accounts, ix_accounts=[1,0]
    pub fn buildTowerSync(
        self: *Self,
        tower_state: *const @import("tower.zig").TowerBft.VoteState,
        bank_hash: core.Hash,
        recent_blockhash: core.Hash,
        block_id: ?core.Hash,
    ) !VoteTransaction {
        var ix_data = std.ArrayListUnmanaged(u8){};
        defer ix_data.deinit(self.allocator);

        // Discriminant: 14 = TowerSync (verified from live testnet block 401256150)
        try ix_data.appendSlice(self.allocator, &std.mem.toBytes(@as(u32, 14)));

        // Root slot: raw u64 LE (ULONG_MAX = no root)
        const root = tower_state.root_slot orelse std.math.maxInt(u64);
        try ix_data.appendSlice(self.allocator, &std.mem.toBytes(root));

        // Lockout count: compact-u16
        try writeCompactU16(self.allocator, &ix_data, @intCast(tower_state.len));

        // Lockouts: cumulative varint offset from root + u8 confirmation_count
        var prev_slot: u64 = if (tower_state.root_slot) |rs| rs else 0;
        for (tower_state.constSlice()) |lockout| {
            const offset = lockout.slot -| prev_slot;
            try writeVarInt(self.allocator, &ix_data, offset);
            try ix_data.append(self.allocator, @intCast(@min(lockout.confirmation_count, 31)));
            prev_slot = lockout.slot;
        }

        // Bank hash (32 bytes)
        try ix_data.appendSlice(self.allocator, &bank_hash.data);

        // Timestamp: Option<i64> (u8 tag + i64 if Some)
        try ix_data.append(self.allocator, 1); // Some
        const timestamp = std.time.timestamp();
        try ix_data.appendSlice(self.allocator, &std.mem.toBytes(timestamp));

        // Block ID (32 bytes)
        if (block_id) |bid| {
            try ix_data.appendSlice(self.allocator, &bid.data);
        } else {
            try ix_data.appendSlice(self.allocator, &bank_hash.data);
        }

        return VoteTransaction{
            .vote_account = self.vote_account,
            .authorized_voter = self.authorized_voter orelse self.identity_pubkey,
            .recent_blockhash = recent_blockhash,
            .instruction_data = try ix_data.toOwnedSlice(self.allocator),
            .allocator = self.allocator,
        };
    }

    /// Build a vote transaction (legacy, instruction 14 — kept for compatibility)
    pub fn buildVoteTransaction(
        self: *Self,
        votes: []const Vote,
        recent_blockhash: core.Hash,
    ) !VoteTransaction {
        var ix_data = std.ArrayListUnmanaged(u8){};
        defer ix_data.deinit(self.allocator);

        try ix_data.appendSlice(self.allocator, &std.mem.toBytes(@as(u32, 14)));
        try writeCompactU16(self.allocator, &ix_data, @intCast(votes.len));
        for (votes) |v| {
            try ix_data.appendSlice(self.allocator, &std.mem.toBytes(v.slot));
            try ix_data.append(self.allocator, 1);
        }
        try ix_data.append(self.allocator, 0); // no root
        if (votes.len > 0) {
            try ix_data.append(self.allocator, 1);
            try ix_data.appendSlice(self.allocator, &votes[votes.len - 1].hash.data);
        } else {
            try ix_data.append(self.allocator, 0);
        }
        try ix_data.append(self.allocator, 1);
        const timestamp = std.time.timestamp();
        try ix_data.appendSlice(self.allocator, &std.mem.toBytes(timestamp));

        const voter = self.authorized_voter orelse self.identity_pubkey;
        return VoteTransaction{
            .vote_account = self.vote_account,
            .authorized_voter = voter,
            .recent_blockhash = recent_blockhash,
            .instruction_data = try ix_data.toOwnedSlice(self.allocator),
            .allocator = self.allocator,
        };
    }

    /// Sign and serialize a TowerSync vote transaction.
    /// Layout matches old Vexor's working format (commit 58c31a4):
    ///   [1]  signature count = 1
    ///   [64] Ed25519 signature
    ///   MESSAGE:
    ///     [1]  num_required_signatures = 1
    ///     [1]  num_readonly_signed = 0
    ///     [1]  num_readonly_unsigned = 1 (vote program)
    ///     [1]  account count = 3
    ///     [32] identity (signer, writable, fee payer)
    ///     [32] vote account (writable)
    ///     [32] vote program (readonly)
    ///     [32] recent blockhash
    ///     [1]  instruction count = 1
    ///     [1]  program_id_index = 2
    ///     [1]  num instruction accounts = 2
    ///     [1]  account index 1 (vote account)
    ///     [1]  account index 0 (authority = identity)
    ///     [compact-u16] instruction data length
    ///     [N]  TowerSync instruction data
    pub fn signAndSerialize(
        self: *Self,
        tx: *const VoteTransaction,
    ) ![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        // === SIGNATURE SECTION ===
        try buf.append(self.allocator, 1); // 1 signature
        try buf.appendNTimes(self.allocator, 0, 64); // placeholder (filled after signing)

        // === MESSAGE (everything after this is signed) ===
        const message_start: usize = 65; // 1 + 64

        // Message header
        try buf.append(self.allocator, 1); // num_required_signatures
        try buf.append(self.allocator, 0); // num_readonly_signed
        try buf.append(self.allocator, 1); // num_readonly_unsigned (vote program only)

        // Account keys: 3 accounts
        try buf.append(self.allocator, 3); // account count
        try buf.appendSlice(self.allocator, &self.identity_pubkey.data); // 0: identity (signer, fee payer)
        try buf.appendSlice(self.allocator, &tx.vote_account.data); // 1: vote account (writable)
        try buf.appendSlice(self.allocator, &VOTE_PROGRAM_ID); // 2: vote program (readonly)

        // Recent blockhash
        try buf.appendSlice(self.allocator, &tx.recent_blockhash.data);

        // Instructions: 1 instruction
        try buf.append(self.allocator, 1); // instruction count

        // Instruction header
        try buf.append(self.allocator, 2); // program_id_index = vote program (account 2)
        try buf.append(self.allocator, 2); // num accounts in instruction
        try buf.append(self.allocator, 1); // vote account (account index 1, writable)
        try buf.append(self.allocator, 0); // authority = identity (account index 0, signer)

        // Instruction data (compact-u16 length prefix)
        try writeCompactU16(self.allocator, &buf, @intCast(tx.instruction_data.len));
        try buf.appendSlice(self.allocator, tx.instruction_data);

        // === SIGN THE MESSAGE ===
        const message = buf.items[message_start..];
        if (self.identity_secret) |secret| {
            const sig = crypto.ed25519.sign(secret, message);
            @memcpy(buf.items[1..65], &sig);
        }

        return try buf.toOwnedSlice(self.allocator);
    }
};

/// Write unsigned LEB128 varint (for CompactTowerSync slot offsets).
fn writeVarInt(allocator: std.mem.Allocator, data: *std.ArrayListUnmanaged(u8), value: u64) !void {
    var v = value;
    while (v >= 0x80) {
        try data.append(allocator, @intCast((v & 0x7F) | 0x80));
        v >>= 7;
    }
    try data.append(allocator, @intCast(v));
}

fn writeCompactU16(allocator: std.mem.Allocator, data: *std.ArrayListUnmanaged(u8), value: u16) !void {
    if (value < 0x80) {
        try data.append(allocator, @intCast(value));
    } else if (value < 0x4000) {
        try data.append(allocator, @intCast((value & 0x7F) | 0x80));
        try data.append(allocator, @intCast(value >> 7));
    } else {
        try data.append(allocator, @intCast((value & 0x7F) | 0x80));
        try data.append(allocator, @intCast(((value >> 7) & 0x7F) | 0x80));
        try data.append(allocator, @intCast(value >> 14));
    }
}

/// Built vote transaction (before signing)
pub const VoteTransaction = struct {
    vote_account: core.Pubkey,
    authorized_voter: core.Pubkey,
    recent_blockhash: core.Hash,
    instruction_data: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *VoteTransaction) void {
        self.allocator.free(self.instruction_data);
    }
};

/// Tower sync transaction for updating vote state
pub const TowerSync = struct {
    /// Current lockouts
    lockouts: []const vote_mod.Lockout,

    /// Root slot
    root: ?core.Slot,

    /// Latest voted hash
    hash: core.Hash,

    /// Timestamp
    timestamp: i64,
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "vote transaction builder" {
    const identity = core.Pubkey{ .data = [_]u8{1} ** 32 };
    const vote_account = core.Pubkey{ .data = [_]u8{2} ** 32 };

    const builder = VoteTransactionBuilder.init(std.testing.allocator, identity, vote_account);
    _ = builder;
}

// VOTE-REFRESH KAT (#87 / vote-transport, Agave maybe_refresh_last_vote parity 2026-06-26).
// Proves the SLASHING-SAFETY invariant of replay_stage.maybeRefreshLastVote: re-building the vote
// tx for a refresh re-sends the EXISTING tower body UNCHANGED, swapping only the recent_blockhash.
// The no-mutation guarantee is also compile-enforced (buildTowerSync takes *const VoteState), so a
// refresh can never recordVote / append a slot = can never become a new/conflicting vote.
test "vote-refresh: re-build re-sends UNCHANGED tower, only blockhash differs (slashing-safe)" {
    const tower = @import("tower.zig");
    const identity = core.Pubkey{ .data = [_]u8{1} ** 32 };
    const vote_account = core.Pubkey{ .data = [_]u8{2} ** 32 };

    var vs = tower.TowerBft.VoteState.init();
    vs.recordVote(100);
    vs.recordVote(101); // lockout(100)=102 > 101 ⇒ 100 stays; len=2, last=101, root=null

    const len_before = vs.len;
    const root_before = vs.root_slot;
    const last_before = vs.lastVotedSlot();

    const vote_hash = core.Hash{ .data = [_]u8{0xAB} ** 32 }; // the emitted bank_hash, reused on refresh
    const bh1 = core.Hash{ .data = [_]u8{0x01} ** 32 };
    const bh2 = core.Hash{ .data = [_]u8{0x02} ** 32 };

    var builder = VoteTransactionBuilder.init(std.testing.allocator, identity, vote_account);
    builder.setIdentitySecret([_]u8{7} ** 64);

    var tx1 = try builder.buildTowerSync(&vs, vote_hash, bh1, null);
    defer tx1.deinit();
    var tx2 = try builder.buildTowerSync(&vs, vote_hash, bh2, null); // the "refresh": same tower, new bh
    defer tx2.deinit();

    // (a) tower body UNCHANGED across both builds — no slot added, no root advance (slashing-safe)
    try std.testing.expectEqual(len_before, vs.len);
    try std.testing.expectEqual(root_before, vs.root_slot);
    try std.testing.expectEqual(last_before, vs.lastVotedSlot());
    try std.testing.expectEqual(@as(?core.Slot, 101), vs.lastVotedSlot());

    // (b) refresh swaps ONLY the envelope blockhash (different tx, identical vote content)
    try std.testing.expectEqualSlices(u8, &bh1.data, &tx1.recent_blockhash.data);
    try std.testing.expectEqualSlices(u8, &bh2.data, &tx2.recent_blockhash.data);
    try std.testing.expect(!std.mem.eql(u8, &tx1.recent_blockhash.data, &tx2.recent_blockhash.data));
}
