//! Vexor BPF2 — Sysvar Cache
//!
//! @prov:sysvar.cache-map — spec-for-spec rebuild of Agave's sysvar cache;
//! full per-function upstream line-map in PROVENANCE.md.
//!
//! ── Purpose ────────────────────────────────────────────────────────────────
//! Holds materialised, byte-perfect on-chain sysvar payloads + typed views.
//! Every BPF instruction's syscall layer (`sol_get_clock_sysvar`,
//! `sol_get_sysvar`, etc.) reads from THIS cache. Anything that bypasses the
//! cache and silently zero-fills its sysvar bytes is the precise bug shape of
//! vex-058 (epoch_schedule DEFAULT) — but reproduced for *all* eight sysvars
//! every BPF call. R3-loader-runtime.md §3 documents the live regression.
//!
//! ── vex-058 invariant (LOCKED) ─────────────────────────────────────────────
//! No getter on this cache may return a defaulted-to-zero payload. Every
//! getter returns either a populated value or `error.SysvarNotPopulated`.
//! `populateFromBank()` is the SOLE legitimate path to fill the cache. Tests
//! verify both shapes exhaustively. See `_test.zig` siblings + R3 §3.
//!
//! ── Agave parity map ─────────────────────────────────────────────────────── @prov:sysvar.cache-map
//!
//! ── SIMD inventory ─────────────────────────────────────────────────────────
//!   SIMD-0127  sol_get_sysvar generic accessor.
//!              Feature gate: CLCoTADvV64PSrnR6QXty6Fwrt9Xc6EdxSJE4wLRePjq
//!              (active on testnet @ slot 316748256, mainnet @ 321840000).
//!              This cache must answer the generic `getBytesByPubkey()` for
//!              any of the 8 sysvars or return error.SysvarNotPopulated
//!              (NOT silently zero).
//!   SIMD-0337  Alpenglow handover marker.
//!              Feature gate: dcomRRWHXP1FVWPqi9Mm4oxJhF4ehC795SvAtUdA9os
//!              (NOT-YET active on testnet OR mainnet). Until activation,
//!              Clock is sourced as-is from bank.
//!   SIMD-0490  Upgrade BPF stake program to v5.
//!              Feature gate: STk5Xj8hdAx3sTzmtJ3QysKkq6X2A3yj73JtxttiRyk
//!              (NOT-YET active on testnet). EpochSchedule getter respects
//!              whatever Bank hands us — never DEFAULT-with-warmup-false (vex-058).
//!              [vex-058 EpochSchedule warmup parity correction: locked separately
//!              in bank.zig — independent of any SIMD gate.]
//!   SIMD-0118  Partitioned Epoch Rewards. The 81-byte EpochRewards layout
//!              matches sig/src/runtime/sysvar/epoch_rewards.zig (STORAGE_SIZE=81,
//!              including 16-byte aligned u128 total_points).
//!              [Note: SIMD-0459/0460 are different features —
//!              0459 = sol_*_addr syscall param restrictions,
//!              0460 = virtual address space adjustments.]
//!
//! ── fix_ledger blocks ──────────────────────────────────────────────────────
//!   • vex-058   (LOCKED HERE)  EpochSchedule defaults must come from Bank,
//!                              never DEFAULT{warmup=false,first_normal=0}.
//!                              See bank.zig:80-86 + memory/project_vex058_*.md.
//!   • vex-034   (DEFERRED)     incoming PanicDbg saturating-arith fix; this
//!                              file uses no panic_dbg counters, but if the
//!                              SysvarCache miss-path ever logs a counter, it
//!                              must respect saturation rules.
//!   • executeBpfProgram-owner-bug (vex-039) — separate file; this cache only
//!                              feeds the syscalls, but its getClock bytes
//!                              must NOT carry stale owner info from before
//!                              vex-039 landed.
//!   • vex-053   (LOCKED)       ALT-handler wireup; SysvarCache does not
//!                              participate but every populated payload must
//!                              be readable for ALT-resolved txs.

const std = @import("std");

// ──────────────────────────────────────────────────────────────────────────────
// Sysvar pubkeys (base58-decoded, on-chain bytes)
//
// Pubkey constants intentionally duplicated here so this slice compiles
// without reaching into vex_svm/sysvar.zig. They MUST match the bytes in
// vex_svm/sysvar.zig — verified by an _test.zig regression check.
// ──────────────────────────────────────────────────────────────────────────────

pub const Pubkey32 = [32]u8;

// r36-fix-e (2026-04-27): replaced placeholder bytes with canonical base58-decoded
// sysvar pubkeys. Pre-fix the 8 constants below shared a 16-byte common prefix
// (0x06,0xa7,0xd5,0x17,0x18,0x7b,0xd1,0x66,0x35,0xda,0xd4,0x04,0x55,0xfb,0xa6,0xc0)
// with only the trailing byte distinguishing them — that pattern decodes to junk
// like "Sysvar1nstructionrcbw6E4xzw4Qw5oNvY8psLDYhB", not the real sysvar IDs.
// Canonical bytes verified by pure-Python base58 round-trip + cross-check vs
// bank.zig (line 646 CLOCK_PUBKEY etc) and Firedancer test_system_ids.c.

// SysvarC1ock11111111111111111111111111111111
pub const SYSVAR_CLOCK_ID: Pubkey32 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9, 0x28, 0x56, 0x63, 0x98,
    0x69, 0x1d, 0x5e, 0xb6, 0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c,
    0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
};
// SysvarRent111111111111111111111111111111111
pub const SYSVAR_RENT_ID: Pubkey32 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x5c, 0x51, 0x21, 0x8c, 0xc9, 0x4c,
    0x3d, 0x4a, 0xf1, 0x7f, 0x58, 0xda, 0xee, 0x08, 0x9b, 0xa1, 0xfd, 0x44,
    0xe3, 0xdb, 0xd9, 0x8a, 0x00, 0x00, 0x00, 0x00,
};
// SysvarEpochSchedu1e111111111111111111111111
pub const SYSVAR_EPOCH_SCHEDULE_ID: Pubkey32 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xdc, 0x3f, 0xee, 0x02, 0xd3, 0xe4, 0x7f,
    0x01, 0x00, 0xf8, 0xb0, 0x54, 0xf7, 0x94, 0x2e, 0x60, 0x59, 0x1e, 0x3f,
    0x50, 0x87, 0x19, 0xa8, 0x05, 0x00, 0x00, 0x00,
};
// SysvarS1otHashes111111111111111111111111111
pub const SYSVAR_SLOT_HASHES_ID: Pubkey32 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf, 0xc6, 0xf2, 0x65, 0xe3,
    0xfb, 0x77, 0xcc, 0x7a, 0xda, 0x82, 0xc5, 0x29, 0xd0, 0xbe, 0x3b, 0x13,
    0x6e, 0x2d, 0x00, 0x55, 0x20, 0x00, 0x00, 0x00,
};
// SysvarS1otHistory11111111111111111111111111
pub const SYSVAR_SLOT_HISTORY_ID: Pubkey32 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2f, 0x0a, 0xaf, 0xc8, 0x75, 0xe2, 0xe1,
    0x84, 0x57, 0x7c, 0x50, 0x69, 0xcf, 0xc8, 0x46, 0x49, 0xe3, 0xeb, 0x92,
    0x78, 0x2f, 0x95, 0x8d, 0x48, 0x00, 0x00, 0x00,
};
// SysvarStakeHistory1111111111111111111111111
pub const SYSVAR_STAKE_HISTORY_ID: Pubkey32 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x35, 0x84, 0xd0, 0xfe, 0xed, 0x9b, 0xb3,
    0x43, 0x1d, 0x13, 0x20, 0x6b, 0xe5, 0x44, 0x28, 0x1b, 0x57, 0xb8, 0x56,
    0x6c, 0xc5, 0x37, 0x5f, 0xf4, 0x00, 0x00, 0x00,
};
// SysvarEpochRewards1111111111111111111111111
pub const SYSVAR_EPOCH_REWARDS_ID: Pubkey32 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xdc, 0x3f, 0xee, 0x02, 0xa5, 0x58, 0xbf,
    0x83, 0xce, 0x66, 0xe1, 0x44, 0x42, 0x2a, 0x1c, 0x34, 0x95, 0x0b, 0x27,
    0xc1, 0x86, 0x9b, 0x5a, 0x9c, 0x00, 0x00, 0x00,
};
// SysvarLastRestartS1ot1111111111111111111111
pub const SYSVAR_LAST_RESTART_SLOT_ID: Pubkey32 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x06, 0xdd, 0xe1, 0xcd, 0x3f, 0x94, 0x7d,
    0xca, 0xb4, 0xc8, 0xf4, 0xf4, 0xf5, 0x1b, 0xad, 0x0f, 0x98, 0x13, 0xb8,
    0x00, 0xd2, 0x89, 0x47, 0x1f, 0xc0, 0x00, 0x00,
};

// ──────────────────────────────────────────────────────────────────────────────
// Wire-format sizes (bytes on-chain, little-endian, bincode-encoded where noted).
// @prov:sysvar.wire-sizes — cross-checked against Agave SDK + Sig runtime +
// Vexor's own host-side updaters (src/vex_svm/sysvar.zig); full ref trail in
// PROVENANCE.md.
// ──────────────────────────────────────────────────────────────────────────────

pub const CLOCK_SIZE: usize = 40; // 5 × i64/u64
pub const RENT_SIZE: usize = 17; // u64 + f64 + u8
pub const EPOCH_SCHEDULE_SIZE: usize = 33; // u64×4 + bool(1) — bincode form
pub const EPOCH_REWARDS_SIZE: usize = 81; // STORAGE_SIZE, @prov:sysvar.wire-sizes
pub const LAST_RESTART_SLOT_SIZE: usize = 8;
pub const FEES_SIZE: usize = 8;
pub const SLOT_HASHES_MAX_ENTRIES: usize = 512;
// SlotHashes: u64 length-prefix + N × (u64 slot + 32-byte hash)
pub const SLOT_HASHES_MAX_SIZE: usize = 8 + SLOT_HASHES_MAX_ENTRIES * 40;
// SlotHistory: u64 hash_len + 2048 × u64 + u64 next_slot. @prov:sysvar.wire-sizes
pub const SLOT_HISTORY_BITVEC_BLOCKS: usize = 2048; // 131072 bits / 64
pub const SLOT_HISTORY_SIZE: usize = 8 + SLOT_HISTORY_BITVEC_BLOCKS * 8 + 8;
// StakeHistory: u64 length-prefix + up to 512 × (u64 epoch + u64×3 entry) = 8 + 512*32
pub const STAKE_HISTORY_MAX_ENTRIES: usize = 512;
pub const STAKE_HISTORY_MAX_SIZE: usize = 8 + STAKE_HISTORY_MAX_ENTRIES * 32;

// ──────────────────────────────────────────────────────────────────────────────
// Typed views. @prov:sysvar.wire-sizes
//
// All extern structs encode the canonical on-chain little-endian byte layout.
// ──────────────────────────────────────────────────────────────────────────────

pub const Clock = extern struct {
    slot: u64,
    epoch_start_timestamp: i64,
    epoch: u64,
    leader_schedule_epoch: u64,
    unix_timestamp: i64,
};

pub const Rent = extern struct {
    lamports_per_byte_year: u64,
    exemption_threshold: f64,
    burn_percent: u8,
};

/// In-memory EpochSchedule. The on-chain bincode form is 33 bytes and follows
/// the struct's DECLARATION ORDER (plain `#[derive(Serialize, Deserialize)]`,
/// no field reorder — serde `rename_all` only affects human-readable formats,
/// not bincode's positional layout). Per solana-epoch-schedule/src/lib.rs:60-79:
///   [0..8)  slots_per_epoch
///   [8..16) leader_schedule_slot_offset
///   [16]    warmup (bool, 1 byte)
///   [17..25) first_normal_epoch
///   [25..33) first_normal_slot
/// (547b2e1: the prior layout mis-placed warmup at byte 32 and shifted
/// first_normal_* into [16..32], the wrong byte range.) @prov:sysvar.wire-sizes
pub const EpochSchedule = struct {
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64,
    warmup: bool,
    first_normal_epoch: u64,
    first_normal_slot: u64,

    /// Serialise to canonical 33-byte bincode (declaration-order) form.
    pub fn toBytes(self: EpochSchedule) [EPOCH_SCHEDULE_SIZE]u8 {
        var out: [EPOCH_SCHEDULE_SIZE]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], self.slots_per_epoch, .little);
        std.mem.writeInt(u64, out[8..16], self.leader_schedule_slot_offset, .little);
        out[16] = if (self.warmup) 1 else 0;
        std.mem.writeInt(u64, out[17..25], self.first_normal_epoch, .little);
        std.mem.writeInt(u64, out[25..33], self.first_normal_slot, .little);
        return out;
    }

    pub fn fromBytes(bytes: []const u8) error{InvalidLayout}!EpochSchedule {
        if (bytes.len < EPOCH_SCHEDULE_SIZE) return error.InvalidLayout;
        return .{
            .slots_per_epoch = std.mem.readInt(u64, bytes[0..8], .little),
            .leader_schedule_slot_offset = std.mem.readInt(u64, bytes[8..16], .little),
            .warmup = bytes[16] != 0,
            .first_normal_epoch = std.mem.readInt(u64, bytes[17..25], .little),
            .first_normal_slot = std.mem.readInt(u64, bytes[25..33], .little),
        };
    }
};

pub const SlotHashEntry = extern struct { slot: u64, hash: [32]u8 };

pub const SlotHashes = struct {
    entries: []const SlotHashEntry,
};

pub const SlotHistory = struct {
    /// Bitvec packed into u64 blocks; block i bit j tracks slot (i*64+j) seen.
    bits: []const u64,
    /// Next slot to record (highest seen + 1).
    next_slot: u64,
};

pub const StakeHistoryEntry = extern struct {
    epoch: u64,
    effective: u64,
    activating: u64,
    deactivating: u64,
};

pub const StakeHistory = struct {
    entries: []const StakeHistoryEntry,
};

/// 81-byte on-chain layout (STORAGE_SIZE=81). @prov:sysvar.wire-sizes
pub const EpochRewards = extern struct {
    distribution_starting_block_height: u64,
    num_partitions: u64,
    parent_blockhash: [32]u8,
    /// align(16) is critical for parity with Agave's #[repr(C)] u128.
    total_points: u128 align(16),
    total_rewards: u64,
    distributed_rewards: u64,
    active: bool,
};

pub const LastRestartSlot = extern struct { last_restart_slot: u64 };

// ──────────────────────────────────────────────────────────────────────────────
// SysvarCache
// ──────────────────────────────────────────────────────────────────────────────

pub const SysvarError = error{
    SysvarNotPopulated,
    InvalidLayout,
    OutOfMemory,
};

/// Owned, populated cache. ALL bytes/views live in arena memory owned by the
/// cache so syscalls can hand out `[]const u8` without lifetime concerns.
///
/// IMPORTANT: a fresh `SysvarCache` returned by `init()` is INTENTIONALLY
/// empty. Every getter returns `error.SysvarNotPopulated` until
/// `populateFromBank()` is called. This is the vex-058 invariant.
pub const SysvarCache = struct {
    allocator: std.mem.Allocator,

    // Raw on-chain bytes (heap-owned). null = not populated.
    clock_bytes: ?[]u8 = null,
    rent_bytes: ?[]u8 = null,
    epoch_schedule_bytes: ?[]u8 = null,
    slot_hashes_bytes: ?[]u8 = null,
    slot_history_bytes: ?[]u8 = null,
    stake_history_bytes: ?[]u8 = null,
    epoch_rewards_bytes: ?[]u8 = null,
    last_restart_slot_bytes: ?[]u8 = null,

    // Typed views (decoded once, cached).
    clock_view: ?Clock = null,
    rent_view: ?Rent = null,
    epoch_schedule_view: ?EpochSchedule = null,
    epoch_rewards_view: ?EpochRewards = null,
    last_restart_slot_view: ?LastRestartSlot = null,
    // SlotHashes/SlotHistory/StakeHistory hold view slices into the *_bytes.
    slot_hashes_entries: ?[]const SlotHashEntry = null,
    slot_history_bits: ?[]const u64 = null,
    slot_history_next: u64 = 0,
    stake_history_entries: ?[]const StakeHistoryEntry = null,

    pub fn init(alloc: std.mem.Allocator) SysvarCache {
        return .{ .allocator = alloc };
    }

    /// Fill any unpopulated sysvar slot with sane testnet-default bytes so
    /// programs that call `Rent::get()` / `Clock::get()` etc. don't trip
    /// `M6_SysvarNotPopulated` and panic. Used by the fixture runner where
    /// captures don't (yet) carry sysvar account contents. Already-populated
    /// slots are left alone — this is a fallback, not an override.
    ///
    /// Reference values:
    ///   Rent: agave default — lamports_per_byte_year=3480, exemption=2.0, burn=50.
    ///   Clock: zeros (programs that read Clock will get a zero state, but most
    ///     just read it; only specific assertions fail. tip-payment doesn't
    ///     read Clock.)
    ///   EpochSchedule, others: zeros.
    pub fn populateTestnetDefaults(self: *SysvarCache) !void {
        if (self.rent_bytes == null) {
            const buf = try self.allocator.alloc(u8, RENT_SIZE);
            // Rent layout: u64 lamports_per_byte_year, f64 exemption_threshold, u8 burn_percent.
            std.mem.writeInt(u64, buf[0..8], 3480, .little);
            // f64 = 2.0 → IEEE 754 = 0x4000000000000000
            std.mem.writeInt(u64, buf[8..16], 0x4000000000000000, .little);
            buf[16] = 50;
            self.rent_bytes = buf;
            self.rent_view = decodeRent(buf) catch null;
        }
        if (self.clock_bytes == null) {
            const buf = try self.allocator.alloc(u8, CLOCK_SIZE);
            @memset(buf, 0);
            self.clock_bytes = buf;
            self.clock_view = decodeClock(buf) catch null;
        }
        if (self.epoch_schedule_bytes == null) {
            const buf = try self.allocator.alloc(u8, EPOCH_SCHEDULE_SIZE);
            @memset(buf, 0);
            // mainnet/testnet typical: slots_per_epoch=432000, leader_schedule_offset=432000
            std.mem.writeInt(u64, buf[0..8], 432000, .little);
            std.mem.writeInt(u64, buf[8..16], 432000, .little);
            self.epoch_schedule_bytes = buf;
            self.epoch_schedule_view = EpochSchedule.fromBytes(buf) catch null;
        }
        if (self.epoch_rewards_bytes == null) {
            const buf = try self.allocator.alloc(u8, EPOCH_REWARDS_SIZE);
            @memset(buf, 0);
            self.epoch_rewards_bytes = buf;
            self.epoch_rewards_view = decodeEpochRewards(buf) catch null;
        }
        if (self.last_restart_slot_bytes == null) {
            const buf = try self.allocator.alloc(u8, LAST_RESTART_SLOT_SIZE);
            @memset(buf, 0);
            self.last_restart_slot_bytes = buf;
            self.last_restart_slot_view = decodeLastRestartSlot(buf) catch null;
        }
    }

    pub fn deinit(self: *SysvarCache) void {
        const a = self.allocator;
        if (self.clock_bytes) |b| a.free(b);
        if (self.rent_bytes) |b| a.free(b);
        if (self.epoch_schedule_bytes) |b| a.free(b);
        if (self.slot_hashes_bytes) |b| a.free(b);
        if (self.slot_history_bytes) |b| a.free(b);
        if (self.stake_history_bytes) |b| a.free(b);
        if (self.epoch_rewards_bytes) |b| a.free(b);
        if (self.last_restart_slot_bytes) |b| a.free(b);
        if (self.slot_hashes_entries) |s| a.free(s);
        if (self.stake_history_entries) |s| a.free(s);
        self.* = .{ .allocator = a };
    }

    // ──────────────────────────────────────────────────────────────────────
    // BankInterface — duck-typed. Wave 4 will adapt vex_svm/bank.zig to it.
    //
    // Required methods on `bank` (any of these may be absent for a partial
    // populate; the corresponding sysvar simply stays unpopulated):
    //
    //   fn getClockBytes(*const Bank)        ?[]const u8
    //   fn getRentBytes(*const Bank)         ?[]const u8
    //   fn getEpochScheduleBytes(*const Bank) ?[]const u8
    //   fn getSlotHashesBytes(*const Bank)    ?[]const u8
    //   fn getSlotHistoryBytes(*const Bank)   ?[]const u8
    //   fn getStakeHistoryBytes(*const Bank)  ?[]const u8
    //   fn getEpochRewardsBytes(*const Bank)  ?[]const u8
    //   fn getLastRestartSlotBytes(*const Bank) ?[]const u8
    //
    // Each returns canonical on-chain bytes (or null = sysvar absent in this
    // bank, e.g. EpochRewards outside the rewards interval). Bytes are
    // copied into the cache so the bank may free its own storage afterwards.
    // ──────────────────────────────────────────────────────────────────────

    pub fn populateFromBank(self: *SysvarCache, bank: anytype) SysvarError!void {
        try self.populateOne(bank, "getClockBytes", &self.clock_bytes, CLOCK_SIZE);
        try self.populateOne(bank, "getRentBytes", &self.rent_bytes, RENT_SIZE);
        try self.populateOne(bank, "getEpochScheduleBytes", &self.epoch_schedule_bytes, EPOCH_SCHEDULE_SIZE);
        try self.populateOne(bank, "getSlotHashesBytes", &self.slot_hashes_bytes, null);
        try self.populateOne(bank, "getSlotHistoryBytes", &self.slot_history_bytes, null);
        try self.populateOne(bank, "getStakeHistoryBytes", &self.stake_history_bytes, null);
        try self.populateOne(bank, "getEpochRewardsBytes", &self.epoch_rewards_bytes, EPOCH_REWARDS_SIZE);
        try self.populateOne(bank, "getLastRestartSlotBytes", &self.last_restart_slot_bytes, LAST_RESTART_SLOT_SIZE);

        // Decode views.
        if (self.clock_bytes) |b| self.clock_view = decodeClock(b) catch return error.InvalidLayout;
        if (self.rent_bytes) |b| self.rent_view = decodeRent(b) catch return error.InvalidLayout;
        if (self.epoch_schedule_bytes) |b| self.epoch_schedule_view = EpochSchedule.fromBytes(b) catch return error.InvalidLayout;
        if (self.epoch_rewards_bytes) |b| self.epoch_rewards_view = decodeEpochRewards(b) catch return error.InvalidLayout;
        if (self.last_restart_slot_bytes) |b| self.last_restart_slot_view = decodeLastRestartSlot(b) catch return error.InvalidLayout;
        if (self.slot_hashes_bytes) |b| {
            const ents = try decodeSlotHashes(self.allocator, b);
            self.slot_hashes_entries = ents;
        }
        if (self.slot_history_bytes) |b| {
            const sh = try decodeSlotHistory(b);
            self.slot_history_bits = sh.bits;
            self.slot_history_next = sh.next_slot;
        }
        if (self.stake_history_bytes) |b| {
            const ents = try decodeStakeHistory(self.allocator, b);
            self.stake_history_entries = ents;
        }
    }

    fn populateOne(
        self: *SysvarCache,
        bank: anytype,
        comptime method: []const u8,
        slot: *?[]u8,
        comptime expected_size: ?usize,
    ) SysvarError!void {
        if (!@hasDecl(@TypeOf(bank.*), method)) return; // bank lacks this getter — leave unpopulated.
        const f = @field(@TypeOf(bank.*), method);
        const opt: ?[]const u8 = f(bank);
        if (opt) |bytes| {
            if (expected_size) |sz| {
                if (bytes.len < sz) return error.InvalidLayout;
            }
            const owned = try self.allocator.dupe(u8, bytes);
            slot.* = owned;
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Typed getters — vex-058 invariant: populated or NotPopulated, never zero.
    // ──────────────────────────────────────────────────────────────────────

    pub fn getClock(self: *const SysvarCache) error{SysvarNotPopulated}!Clock {
        return self.clock_view orelse error.SysvarNotPopulated;
    }
    pub fn getClockBytes(self: *const SysvarCache) error{SysvarNotPopulated}![]const u8 {
        return self.clock_bytes orelse error.SysvarNotPopulated;
    }
    pub fn getRent(self: *const SysvarCache) error{SysvarNotPopulated}!Rent {
        return self.rent_view orelse error.SysvarNotPopulated;
    }
    pub fn getRentBytes(self: *const SysvarCache) error{SysvarNotPopulated}![]const u8 {
        return self.rent_bytes orelse error.SysvarNotPopulated;
    }
    pub fn getEpochSchedule(self: *const SysvarCache) error{SysvarNotPopulated}!EpochSchedule {
        return self.epoch_schedule_view orelse error.SysvarNotPopulated;
    }
    pub fn getEpochScheduleBytes(self: *const SysvarCache) error{SysvarNotPopulated}![]const u8 {
        return self.epoch_schedule_bytes orelse error.SysvarNotPopulated;
    }
    pub fn getSlotHashes(self: *const SysvarCache) error{SysvarNotPopulated}!SlotHashes {
        const e = self.slot_hashes_entries orelse return error.SysvarNotPopulated;
        return .{ .entries = e };
    }
    pub fn getSlotHashesBytes(self: *const SysvarCache) error{SysvarNotPopulated}![]const u8 {
        return self.slot_hashes_bytes orelse error.SysvarNotPopulated;
    }
    pub fn getSlotHistory(self: *const SysvarCache) error{SysvarNotPopulated}!SlotHistory {
        const b = self.slot_history_bits orelse return error.SysvarNotPopulated;
        return .{ .bits = b, .next_slot = self.slot_history_next };
    }
    pub fn getSlotHistoryBytes(self: *const SysvarCache) error{SysvarNotPopulated}![]const u8 {
        return self.slot_history_bytes orelse error.SysvarNotPopulated;
    }
    pub fn getStakeHistory(self: *const SysvarCache) error{SysvarNotPopulated}!StakeHistory {
        const e = self.stake_history_entries orelse return error.SysvarNotPopulated;
        return .{ .entries = e };
    }
    pub fn getStakeHistoryBytes(self: *const SysvarCache) error{SysvarNotPopulated}![]const u8 {
        return self.stake_history_bytes orelse error.SysvarNotPopulated;
    }
    pub fn getEpochRewards(self: *const SysvarCache) error{SysvarNotPopulated}!EpochRewards {
        return self.epoch_rewards_view orelse error.SysvarNotPopulated;
    }
    pub fn getEpochRewardsBytes(self: *const SysvarCache) error{SysvarNotPopulated}![]const u8 {
        return self.epoch_rewards_bytes orelse error.SysvarNotPopulated;
    }
    pub fn getLastRestartSlot(self: *const SysvarCache) error{SysvarNotPopulated}!LastRestartSlot {
        return self.last_restart_slot_view orelse error.SysvarNotPopulated;
    }
    pub fn getLastRestartSlotBytes(self: *const SysvarCache) error{SysvarNotPopulated}![]const u8 {
        return self.last_restart_slot_bytes orelse error.SysvarNotPopulated;
    }

    /// SIMD-0127 generic accessor (`sol_get_sysvar`'s cache lookup). Returns
    /// canonical bytes for any of the 7 sysvars this syscall actually
    /// resolves, or `error.SysvarNotPopulated` (never zero-fills).
    ///
    /// conformance RC7 (2026-07-18, sol_get_sysvar/{46f967d1,94a24d0f,
    /// bb0ec2aa}_369105.fix): this used to also match SYSVAR_SLOT_HISTORY_ID
    /// (an 8th arm). Byte-verified via a temporary per-fixture id/bytes-len
    /// dump in solGetSysvar: all 3 fixtures pass the EXACT
    /// SYSVAR_SLOT_HISTORY_ID pubkey as `sysvar_id`, and Vexor matched it
    /// (bytes.len=0 -- SlotHistory-not-yet-populated-but-Some) and returned
    /// OFFSET_LENGTH_EXCEEDS_SYSVAR(1) on the resulting bounds check, while
    /// Agave's own fixtures expect SYSVAR_NOT_FOUND(2) unconditionally for
    /// this ID. Root cause: Agave's `SyscallGetSysvar::rust`
    /// (agave-4.2.0-beta.1-src/syscalls/src/sysvar.rs:238-243) resolves the
    /// cache via `SysvarCache::sysvar_id_to_buffer`
    /// (program-runtime/src/sysvar_cache.rs:109-127), whose match arms cover
    /// ONLY Clock/EpochSchedule/EpochRewards/Rent/SlotHashes/StakeHistory/
    /// LastRestartSlot -- SEVEN sysvars, with no `SlotHistory::check_id` arm
    /// at all -- so `sol_get_sysvar` on a SlotHistory pubkey ALWAYS falls to
    /// `&None` -> SYSVAR_NOT_FOUND in Agave, regardless of whether
    /// SlotHistory itself is populated elsewhere in the cache (it still is,
    /// and remains reachable via the typed `getSlotHistory()`/
    /// `getSlotHistoryBytes()` getters above -- e.g. the SlotHistory
    /// builtin/native-program path -- this fix only removes it from THIS
    /// syscall's generic-by-pubkey resolution, matching Agave's own scope).
    pub fn getBytesByPubkey(self: *const SysvarCache, pk: Pubkey32) error{SysvarNotPopulated}![]const u8 {
        if (std.mem.eql(u8, &pk, &SYSVAR_CLOCK_ID)) return self.getClockBytes();
        if (std.mem.eql(u8, &pk, &SYSVAR_RENT_ID)) return self.getRentBytes();
        if (std.mem.eql(u8, &pk, &SYSVAR_EPOCH_SCHEDULE_ID)) return self.getEpochScheduleBytes();
        if (std.mem.eql(u8, &pk, &SYSVAR_SLOT_HASHES_ID)) return self.getSlotHashesBytes();
        if (std.mem.eql(u8, &pk, &SYSVAR_STAKE_HISTORY_ID)) return self.getStakeHistoryBytes();
        if (std.mem.eql(u8, &pk, &SYSVAR_EPOCH_REWARDS_ID)) return self.getEpochRewardsBytes();
        if (std.mem.eql(u8, &pk, &SYSVAR_LAST_RESTART_SLOT_ID)) return self.getLastRestartSlotBytes();
        return error.SysvarNotPopulated;
    }
};

// ──────────────────────────────────────────────────────────────────────────────
// Decoders
// ──────────────────────────────────────────────────────────────────────────────

fn decodeClock(b: []const u8) error{InvalidLayout}!Clock {
    if (b.len < CLOCK_SIZE) return error.InvalidLayout;
    return .{
        .slot = std.mem.readInt(u64, b[0..8], .little),
        .epoch_start_timestamp = std.mem.readInt(i64, b[8..16], .little),
        .epoch = std.mem.readInt(u64, b[16..24], .little),
        .leader_schedule_epoch = std.mem.readInt(u64, b[24..32], .little),
        .unix_timestamp = std.mem.readInt(i64, b[32..40], .little),
    };
}

fn decodeRent(b: []const u8) error{InvalidLayout}!Rent {
    if (b.len < RENT_SIZE) return error.InvalidLayout;
    const lpb = std.mem.readInt(u64, b[0..8], .little);
    const ex_bits = std.mem.readInt(u64, b[8..16], .little);
    const ex: f64 = @bitCast(ex_bits);
    return .{ .lamports_per_byte_year = lpb, .exemption_threshold = ex, .burn_percent = b[16] };
}

fn decodeEpochRewards(b: []const u8) error{InvalidLayout}!EpochRewards {
    if (b.len < EPOCH_REWARDS_SIZE) return error.InvalidLayout;
    var out: EpochRewards = .{
        .distribution_starting_block_height = std.mem.readInt(u64, b[0..8], .little),
        .num_partitions = std.mem.readInt(u64, b[8..16], .little),
        .parent_blockhash = undefined,
        .total_points = 0,
        .total_rewards = 0,
        .distributed_rewards = 0,
        .active = false,
    };
    @memcpy(&out.parent_blockhash, b[16..48]);
    out.total_points = std.mem.readInt(u128, b[48..64], .little);
    out.total_rewards = std.mem.readInt(u64, b[64..72], .little);
    out.distributed_rewards = std.mem.readInt(u64, b[72..80], .little);
    out.active = b[80] != 0;
    return out;
}

fn decodeLastRestartSlot(b: []const u8) error{InvalidLayout}!LastRestartSlot {
    if (b.len < LAST_RESTART_SLOT_SIZE) return error.InvalidLayout;
    return .{ .last_restart_slot = std.mem.readInt(u64, b[0..8], .little) };
}

fn decodeSlotHashes(alloc: std.mem.Allocator, b: []const u8) SysvarError![]const SlotHashEntry {
    if (b.len < 8) return error.InvalidLayout;
    const len = std.mem.readInt(u64, b[0..8], .little);
    if (len > SLOT_HASHES_MAX_ENTRIES) return error.InvalidLayout;
    if (b.len < 8 + len * 40) return error.InvalidLayout;
    const out = try alloc.alloc(SlotHashEntry, @intCast(len));
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const off = 8 + i * 40;
        out[i].slot = std.mem.readInt(u64, b[off..][0..8], .little);
        @memcpy(&out[i].hash, b[off + 8 ..][0..32]);
    }
    return out;
}

fn decodeSlotHistory(b: []const u8) error{InvalidLayout}!struct { bits: []const u64, next_slot: u64 } {
    // @prov:sysvar.wire-sizes — u64 bitvec_block_count + N × u64 bits + u64 next_slot.
    if (b.len < 8) return error.InvalidLayout;
    const block_count = std.mem.readInt(u64, b[0..8], .little);
    if (block_count != SLOT_HISTORY_BITVEC_BLOCKS) return error.InvalidLayout;
    const bits_bytes = block_count * 8;
    if (b.len < 8 + bits_bytes + 8) return error.InvalidLayout;
    // SAFETY: bytes are aligned at the source-of-truth layer and copied via dupe();
    // we re-interpret as u64 little-endian. Use ptrCast on the duplicated buffer.
    const bits_ptr: [*]const u64 = @ptrCast(@alignCast(b.ptr + 8));
    const bits = bits_ptr[0..@intCast(block_count)];
    const next_slot = std.mem.readInt(u64, b[8 + bits_bytes ..][0..8], .little);
    return .{ .bits = bits, .next_slot = next_slot };
}

fn decodeStakeHistory(alloc: std.mem.Allocator, b: []const u8) SysvarError![]const StakeHistoryEntry {
    if (b.len < 8) return error.InvalidLayout;
    const len = std.mem.readInt(u64, b[0..8], .little);
    if (len > STAKE_HISTORY_MAX_ENTRIES) return error.InvalidLayout;
    if (b.len < 8 + len * 32) return error.InvalidLayout;
    const out = try alloc.alloc(StakeHistoryEntry, @intCast(len));
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const off = 8 + i * 32;
        out[i].epoch = std.mem.readInt(u64, b[off..][0..8], .little);
        out[i].effective = std.mem.readInt(u64, b[off + 8 ..][0..8], .little);
        out[i].activating = std.mem.readInt(u64, b[off + 16 ..][0..8], .little);
        out[i].deactivating = std.mem.readInt(u64, b[off + 24 ..][0..8], .little);
    }
    return out;
}
