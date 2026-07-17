//! VOTEFORGE Stage 1 — codec layer: fixed-offset, allocation-free V3/V4
//! vote-state serde (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 1).
//!
//! Derived DIRECTLY from Agave 4.2.0-beta.0 (semantics authority) — wire =
//! bincode(fixint,LE) of the struct behind a u32 version tag from
//! vote_state_versions.rs (0=V0_23_5, 1=V1_14_11, 2=V3/current, 3=V4).
//! @prov:voteforge.wire-format — exact V4/V3 field-order upstream citations.
//! Shape follows a Firedancer-style flat fixed-capacity layout: stack-resident
//! structs, direct offset reads/writes, zero heap. NOT derived from Sig — the
//! transplant is only the differential oracle in the KATs (kat_vote_codec.zig).
//!
//! BYTE-EXACTNESS CONTRACT (the @414056489 / SIMD-0464 "stale tail" landmine):
//! a vote account's data buffer is FIXED-SIZE (3762 for V3-era accounts; V4
//! serialized content is shorter than the buffer). serialize() writes exactly
//! the serialized prefix and MUST NOT touch trailing bytes — Agave's
//! serializeIntoAccountData overwrites only the prefix, and the cluster's
//! lt_hash covers the full account data including any stale tail.
//!
//! CAPACITY POLICY (documented divergence-risk note): parse() rejects
//! collection counts beyond the fixed capacities below with
//! error.InvalidAccountData. Canonical on-chain vote accounts can never
//! exceed them (the vote program itself enforces votes<=31 via pop/push,
//! authorized_voters<=4 via the purge invariants, epoch_credits<=64 via
//! MAX_EPOCH_CREDITS_HISTORY); a hand-crafted account exceeding a cap would
//! parse further under Agave's unbounded Vec/BTreeMap deserialize while we
//! reject — accepted for Stage 1 (vote accounts are only ever written by the
//! vote program), re-reviewed at Stage 5 sign-off.

const std = @import("std");

pub const VERSION_TAG_V0_23_5: u32 = 0;
pub const VERSION_TAG_V1_14_11: u32 = 1;
pub const VERSION_TAG_V3: u32 = 2;
pub const VERSION_TAG_V4: u32 = 3;

pub const MAX_LOCKOUT_HISTORY: usize = 31;
/// @prov:voteforge.wire-format — MAX_EPOCH_CREDITS_HISTORY
pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;
/// V4 invariant: [current_epoch-1, current_epoch+2] => <=4 live entries; V3's
/// purge keeps <=3. Cap 8 = generous headroom, still stack-trivial.
pub const MAX_AUTHORIZED_VOTERS: usize = 8;
pub const BLS_PUBKEY_COMPRESSED_SIZE: usize = 48;
/// @prov:voteforge.wire-format — prior_voters: CircBuf<(Pubkey,Epoch,Epoch)> — 32 x 48B + idx u64 +
/// is_empty bool = 1545 bytes. Kept OPAQUE (raw blob): V4 dropped the field,
/// no state-transition logic reads inside it, and opacity makes the
/// round-trip trivially byte-exact.
pub const PRIOR_VOTERS_BLOB_LEN: usize = 32 * 48 + 8 + 1;

pub const CodecError = error{InvalidAccountData};

pub const Lockout = struct {
    slot: u64,
    confirmation_count: u32,
};

pub const LandedVote = struct {
    latency: u8,
    lockout: Lockout,
};

pub const EpochCredit = struct {
    epoch: u64,
    credits: u64,
    prev_credits: u64,
};

pub const AuthorizedVoterEntry = struct {
    epoch: u64,
    pubkey: [32]u8,
};

pub const BlockTimestamp = struct {
    slot: u64,
    timestamp: i64,
};

// ─────────────────────────────────────────────────────────────────────────────
// Little-endian cursor helpers (fixint bincode == raw LE scalars).
// ─────────────────────────────────────────────────────────────────────────────

const Reader = struct {
    buf: []const u8,
    off: usize = 0,

    fn need(self: *Reader, n: usize) CodecError!void {
        if (self.buf.len - self.off < n) return error.InvalidAccountData;
    }
    fn u8v(self: *Reader) CodecError!u8 {
        try self.need(1);
        defer self.off += 1;
        return self.buf[self.off];
    }
    fn u16v(self: *Reader) CodecError!u16 {
        try self.need(2);
        defer self.off += 2;
        return std.mem.readInt(u16, self.buf[self.off..][0..2], .little);
    }
    fn u32v(self: *Reader) CodecError!u32 {
        try self.need(4);
        defer self.off += 4;
        return std.mem.readInt(u32, self.buf[self.off..][0..4], .little);
    }
    fn u64v(self: *Reader) CodecError!u64 {
        try self.need(8);
        defer self.off += 8;
        return std.mem.readInt(u64, self.buf[self.off..][0..8], .little);
    }
    fn i64v(self: *Reader) CodecError!i64 {
        return @bitCast(try self.u64v());
    }
    fn bytes(self: *Reader, comptime n: usize) CodecError!*const [n]u8 {
        try self.need(n);
        defer self.off += n;
        return self.buf[self.off..][0..n];
    }
    /// bincode Option<T> presence byte: 0=None, 1=Some. Any other value is
    /// invalid (Agave's bincode rejects it too).
    fn optFlag(self: *Reader) CodecError!bool {
        const b = try self.u8v();
        return switch (b) {
            0 => false,
            1 => true,
            else => error.InvalidAccountData,
        };
    }
};

const Writer = struct {
    buf: []u8,
    off: usize = 0,

    fn need(self: *Writer, n: usize) CodecError!void {
        if (self.buf.len - self.off < n) return error.InvalidAccountData;
    }
    fn u8v(self: *Writer, v: u8) CodecError!void {
        try self.need(1);
        self.buf[self.off] = v;
        self.off += 1;
    }
    fn u16v(self: *Writer, v: u16) CodecError!void {
        try self.need(2);
        std.mem.writeInt(u16, self.buf[self.off..][0..2], v, .little);
        self.off += 2;
    }
    fn u32v(self: *Writer, v: u32) CodecError!void {
        try self.need(4);
        std.mem.writeInt(u32, self.buf[self.off..][0..4], v, .little);
        self.off += 4;
    }
    fn u64v(self: *Writer, v: u64) CodecError!void {
        try self.need(8);
        std.mem.writeInt(u64, self.buf[self.off..][0..8], v, .little);
        self.off += 8;
    }
    fn i64v(self: *Writer, v: i64) CodecError!void {
        try self.u64v(@bitCast(v));
    }
    fn bytes(self: *Writer, src: []const u8) CodecError!void {
        try self.need(src.len);
        @memcpy(self.buf[self.off..][0..src.len], src);
        self.off += src.len;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared variable-tail parse/serialize (votes / root / authorized_voters /
// epoch_credits / last_timestamp — IDENTICAL layout in V3 and V4;
// prior_voters is V3-only and handled by the V3 functions).
// ─────────────────────────────────────────────────────────────────────────────

pub const Tail = struct {
    votes_len: usize,
    votes: [MAX_LOCKOUT_HISTORY]LandedVote,
    root_slot: ?u64,
    authorized_voters_len: usize,
    authorized_voters: [MAX_AUTHORIZED_VOTERS]AuthorizedVoterEntry,
    epoch_credits_len: usize,
    epoch_credits: [MAX_EPOCH_CREDITS_HISTORY]EpochCredit,
    last_timestamp: BlockTimestamp,

    pub const EMPTY: Tail = .{
        .votes_len = 0,
        .votes = undefined,
        .root_slot = null,
        .authorized_voters_len = 0,
        .authorized_voters = undefined,
        .epoch_credits_len = 0,
        .epoch_credits = undefined,
        .last_timestamp = .{ .slot = 0, .timestamp = 0 },
    };
};

fn parseTail(r: *Reader) CodecError!Tail {
    var t: Tail = Tail.EMPTY;

    const n_votes = try r.u64v();
    if (n_votes > MAX_LOCKOUT_HISTORY) return error.InvalidAccountData;
    t.votes_len = @intCast(n_votes);
    for (0..t.votes_len) |i| {
        t.votes[i] = .{
            .latency = try r.u8v(),
            .lockout = .{ .slot = try r.u64v(), .confirmation_count = try r.u32v() },
        };
    }

    t.root_slot = if (try r.optFlag()) try r.u64v() else null;

    const n_av = try r.u64v();
    if (n_av > MAX_AUTHORIZED_VOTERS) return error.InvalidAccountData;
    t.authorized_voters_len = @intCast(n_av);
    for (0..t.authorized_voters_len) |i| {
        t.authorized_voters[i] = .{ .epoch = try r.u64v(), .pubkey = (try r.bytes(32)).* };
    }

    return t;
}

fn parseTailCreditsAndTs(r: *Reader, t: *Tail) CodecError!void {
    const n_ec = try r.u64v();
    if (n_ec > MAX_EPOCH_CREDITS_HISTORY) return error.InvalidAccountData;
    t.epoch_credits_len = @intCast(n_ec);
    for (0..t.epoch_credits_len) |i| {
        t.epoch_credits[i] = .{
            .epoch = try r.u64v(),
            .credits = try r.u64v(),
            .prev_credits = try r.u64v(),
        };
    }
    t.last_timestamp = .{ .slot = try r.u64v(), .timestamp = try r.i64v() };
}

fn writeTail(w: *Writer, t: *const Tail) CodecError!void {
    try w.u64v(@intCast(t.votes_len));
    for (t.votes[0..t.votes_len]) |v| {
        try w.u8v(v.latency);
        try w.u64v(v.lockout.slot);
        try w.u32v(v.lockout.confirmation_count);
    }
    if (t.root_slot) |rs| {
        try w.u8v(1);
        try w.u64v(rs);
    } else try w.u8v(0);
    try w.u64v(@intCast(t.authorized_voters_len));
    for (t.authorized_voters[0..t.authorized_voters_len]) |av| {
        try w.u64v(av.epoch);
        try w.bytes(&av.pubkey);
    }
}

fn writeTailCreditsAndTs(w: *Writer, t: *const Tail) CodecError!void {
    try w.u64v(@intCast(t.epoch_credits_len));
    for (t.epoch_credits[0..t.epoch_credits_len]) |ec| {
        try w.u64v(ec.epoch);
        try w.u64v(ec.credits);
        try w.u64v(ec.prev_credits);
    }
    try w.u64v(t.last_timestamp.slot);
    try w.i64v(t.last_timestamp.timestamp);
}

// ─────────────────────────────────────────────────────────────────────────────
// V4 (version tag 3). @prov:voteforge.wire-format — fixed head offsets
// (independently confirmed against a real cluster account, see
// kat_vote_codec.zig): tag@0, node@4, withdrawer@36, inflation_collector@68,
// block_collector@100, infl_bps@132, block_bps@134, pending_rewards@136,
// bls Option flag@144 (+48 payload), then the variable tail.
// ─────────────────────────────────────────────────────────────────────────────

pub const VoteStateV4 = struct {
    node_pubkey: [32]u8,
    authorized_withdrawer: [32]u8,
    inflation_rewards_collector: [32]u8,
    block_revenue_collector: [32]u8,
    inflation_rewards_commission_bps: u16,
    block_revenue_commission_bps: u16,
    pending_delegator_rewards: u64,
    bls_pubkey_compressed: ?[BLS_PUBKEY_COMPRESSED_SIZE]u8,
    tail: Tail,

    /// Parse V4 account data (must begin with tag 3). Returns the parsed state
    /// and the number of bytes consumed (the serialized-prefix length; the
    /// caller's buffer may be longer — stale tail).
    pub fn parse(data: []const u8) CodecError!struct { state: VoteStateV4, consumed: usize } {
        var r = Reader{ .buf = data };
        if (try r.u32v() != VERSION_TAG_V4) return error.InvalidAccountData;

        var s: VoteStateV4 = undefined;
        s.node_pubkey = (try r.bytes(32)).*;
        s.authorized_withdrawer = (try r.bytes(32)).*;
        s.inflation_rewards_collector = (try r.bytes(32)).*;
        s.block_revenue_collector = (try r.bytes(32)).*;
        s.inflation_rewards_commission_bps = try r.u16v();
        s.block_revenue_commission_bps = try r.u16v();
        s.pending_delegator_rewards = try r.u64v();
        s.bls_pubkey_compressed = if (try r.optFlag())
            (try r.bytes(BLS_PUBKEY_COMPRESSED_SIZE)).*
        else
            null;

        s.tail = try parseTail(&r);
        try parseTailCreditsAndTs(&r, &s.tail);
        return .{ .state = s, .consumed = r.off };
    }

    /// Serialize into `out` (an account-data buffer). Writes EXACTLY the
    /// serialized prefix, leaves all trailing bytes untouched (the stale-tail
    /// contract). Returns bytes written.
    pub fn serialize(self: *const VoteStateV4, out: []u8) CodecError!usize {
        var w = Writer{ .buf = out };
        try w.u32v(VERSION_TAG_V4);
        try w.bytes(&self.node_pubkey);
        try w.bytes(&self.authorized_withdrawer);
        try w.bytes(&self.inflation_rewards_collector);
        try w.bytes(&self.block_revenue_collector);
        try w.u16v(self.inflation_rewards_commission_bps);
        try w.u16v(self.block_revenue_commission_bps);
        try w.u64v(self.pending_delegator_rewards);
        if (self.bls_pubkey_compressed) |bls| {
            try w.u8v(1);
            try w.bytes(&bls);
        } else try w.u8v(0);
        try writeTail(&w, &self.tail);
        try writeTailCreditsAndTs(&w, &self.tail);
        return w.off;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// V3 / "current" (version tag 2). @prov:voteforge.wire-format —
// VoteState field order: node_pubkey, authorized_withdrawer, commission(u8),
// votes(VecDeque<LandedVote>), root_slot, authorized_voters,
// prior_voters(CircBuf — opaque 1545B blob here), epoch_credits,
// last_timestamp.
// ─────────────────────────────────────────────────────────────────────────────

pub const VoteStateV3 = struct {
    node_pubkey: [32]u8,
    authorized_withdrawer: [32]u8,
    commission: u8,
    /// Opaque prior_voters CircBuf image (see PRIOR_VOTERS_BLOB_LEN doc).
    prior_voters_blob: [PRIOR_VOTERS_BLOB_LEN]u8,
    tail: Tail,

    pub fn parse(data: []const u8) CodecError!struct { state: VoteStateV3, consumed: usize } {
        var r = Reader{ .buf = data };
        if (try r.u32v() != VERSION_TAG_V3) return error.InvalidAccountData;

        var s: VoteStateV3 = undefined;
        s.node_pubkey = (try r.bytes(32)).*;
        s.authorized_withdrawer = (try r.bytes(32)).*;
        s.commission = try r.u8v();

        s.tail = try parseTail(&r);
        s.prior_voters_blob = (try r.bytes(PRIOR_VOTERS_BLOB_LEN)).*;
        try parseTailCreditsAndTs(&r, &s.tail);
        return .{ .state = s, .consumed = r.off };
    }

    pub fn serialize(self: *const VoteStateV3, out: []u8) CodecError!usize {
        var w = Writer{ .buf = out };
        try w.u32v(VERSION_TAG_V3);
        try w.bytes(&self.node_pubkey);
        try w.bytes(&self.authorized_withdrawer);
        try w.u8v(self.commission);
        try writeTail(&w, &self.tail);
        try w.bytes(&self.prior_voters_blob);
        try writeTailCreditsAndTs(&w, &self.tail);
        return w.off;
    }
};

/// Read just the version tag (cheap dispatch for callers).
pub fn versionTag(data: []const u8) CodecError!u32 {
    if (data.len < 4) return error.InvalidAccountData;
    return std.mem.readInt(u32, data[0..4], .little);
}

// ─────────────────────────────────────────────────────────────────────────────
// V3 -> V4 in-memory migration. @prov:voteforge.v3-v4-migration
// (commission pct -> bps x100,
// collectors default to vote-account pubkey (inflation) / node pubkey (block
// revenue), block_revenue_commission_bps = 10_000, no BLS key, prior_voters
// dropped). Pure function, no allocation.
// ─────────────────────────────────────────────────────────────────────────────

pub fn migrateV3ToV4(v3: *const VoteStateV3, vote_account_pubkey: [32]u8) VoteStateV4 {
    return .{
        .node_pubkey = v3.node_pubkey,
        .authorized_withdrawer = v3.authorized_withdrawer,
        .inflation_rewards_collector = vote_account_pubkey,
        .block_revenue_collector = v3.node_pubkey,
        .inflation_rewards_commission_bps = @as(u16, v3.commission) * 100,
        .block_revenue_commission_bps = 10_000,
        .pending_delegator_rewards = 0,
        .bls_pubkey_compressed = null,
        .tail = v3.tail,
    };
}
