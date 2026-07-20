//! Vexor Ledger Storage
//!
//! Persistent storage for the blockchain ledger data:
//! - Shreds (block fragments)
//! - Slots and slot metadata
//! - Block production data
//!
//! Uses RocksDB-style key-value storage optimized for sequential reads.

const std = @import("std");
const core = @import("core");

/// Main ledger database
pub const LedgerDb = struct {
    allocator: std.mem.Allocator,
    ledger_path: []const u8,

    /// Slot metadata storage
    slot_meta: SlotMetaStore,

    /// Shred data storage
    shred_data: ShredDataStore,

    /// Block time storage
    block_time: BlockTimeStore,

    /// RwLock protecting slot_meta, shred_data, and block_time.
    /// Shared for reads (get), exclusive for writes (insert, purge).
    ledger_lock: std.Thread.RwLock,

    /// Latest confirmed/finalized slot (highest slot seen from shreds/gossip)
    latest_slot: std.atomic.Value(u64),
    finalized_slot: std.atomic.Value(u64),

    /// Last slot that was fully replayed (matches Firedancer's semantics: only counts replayed slots)
    last_replayed_slot: std.atomic.Value(u64),

    /// Block height: increments by 1 for each non-skipped slot. Always <= slot number.
    /// Initialized from snapshot, incremented by replay stage.
    block_height: std.atomic.Value(u64),

    /// Latest blockhash from replay (32 bytes, base58-encoded for RPC)
    /// Updated by replay stage after each successful slot replay.
    latest_blockhash: [44]u8 = [_]u8{0} ** 44,
    latest_blockhash_len: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Transaction count (cumulative, updated by replay)
    transaction_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Blocks produced as leader (incremented by replay stage on leader slots)
    blocks_produced: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Total leader slots scheduled this epoch (set from leader schedule)
    leader_slots_scheduled: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !*Self {
        const db = try allocator.create(Self);
        db.* = .{
            .allocator = allocator,
            .ledger_path = path,
            .slot_meta = SlotMetaStore.init(allocator),
            .shred_data = ShredDataStore.init(allocator),
            .block_time = BlockTimeStore.init(allocator),
            .ledger_lock = .{},
            .latest_slot = std.atomic.Value(u64).init(0),
            .finalized_slot = std.atomic.Value(u64).init(0),
            .last_replayed_slot = std.atomic.Value(u64).init(0),
            .block_height = std.atomic.Value(u64).init(0),
        };
        return db;
    }

    pub fn deinit(self: *Self) void {
        self.slot_meta.deinit();
        self.shred_data.deinit();
        self.block_time.deinit();
        self.allocator.destroy(self);
    }

    /// Get slot metadata
    pub fn getSlotMeta(self: *Self, slot: core.Slot) ?SlotMeta {
        self.ledger_lock.lockShared();
        defer self.ledger_lock.unlockShared();
        return self.slot_meta.get(slot);
    }

    /// Insert slot metadata
    pub fn insertSlotMeta(self: *Self, slot: core.Slot, meta: SlotMeta) !void {
        self.ledger_lock.lock();
        defer self.ledger_lock.unlock();
        try self.slot_meta.insert(slot, meta);

        // Update latest slot if necessary
        const current_latest = self.latest_slot.load(.seq_cst);
        if (slot > current_latest) {
            _ = self.latest_slot.cmpxchgStrong(current_latest, slot, .seq_cst, .seq_cst);
        }
    }

    /// Insert a shred
    pub fn insertShred(self: *Self, slot: core.Slot, shred_index: u32, data: []const u8) !void {
        self.ledger_lock.lock();
        defer self.ledger_lock.unlock();
        try self.shred_data.insert(slot, shred_index, data);
    }

    /// Get a shred
    pub fn getShred(self: *Self, slot: core.Slot, shred_index: u32) ?[]const u8 {
        self.ledger_lock.lockShared();
        defer self.ledger_lock.unlockShared();
        return self.shred_data.get(slot, shred_index);
    }

    /// Check if a slot is complete (has all shreds)
    pub fn isSlotComplete(self: *Self, slot: core.Slot) bool {
        self.ledger_lock.lockShared();
        defer self.ledger_lock.unlockShared();
        if (self.getSlotMetaInternal(slot)) |meta| {
            return meta.is_full;
        }
        return false;
    }

    /// Internal unlocked get (caller must hold lock)
    fn getSlotMetaInternal(self: *Self, slot: core.Slot) ?SlotMeta {
        return self.slot_meta.get(slot);
    }

    /// Get range of slots
    pub fn getSlotRange(self: *Self, start_slot: core.Slot, end_slot: core.Slot) ![]core.Slot {
        self.ledger_lock.lockShared();
        defer self.ledger_lock.unlockShared();

        var slots = std.ArrayListUnmanaged(core.Slot){};
        defer slots.deinit(self.allocator);

        var slot = start_slot;
        while (slot <= end_slot) : (slot += 1) {
            if (self.getSlotMeta(slot) != null) {
                try slots.append(self.allocator, slot);
            }
        }

        return try slots.toOwnedSlice(self.allocator);
    }

    /// Set slot as finalized
    pub fn setFinalized(self: *Self, slot: core.Slot) void {
        _ = self.finalized_slot.store(slot, .seq_cst);
    }

    /// Purge old slots to limit ledger size
    pub fn purge(self: *Self, limit_slots: u64) !usize {
        const finalized = self.finalized_slot.load(.seq_cst);
        if (finalized < limit_slots) return 0;

        const purge_before = finalized - limit_slots;

        self.ledger_lock.lock();
        defer self.ledger_lock.unlock();

        var purged: usize = 0;

        // Purge slot metadata
        purged += self.slot_meta.purgeBefore(purge_before);

        // Purge shred data
        purged += self.shred_data.purgeBefore(purge_before);

        return purged;
    }

    /// Get ledger statistics
    pub fn getStats(self: *const Self) LedgerStats {
        return .{
            .latest_slot = self.latest_slot.load(.seq_cst),
            .finalized_slot = self.finalized_slot.load(.seq_cst),
            .slot_count = self.slot_meta.count(),
            .shred_count = self.shred_data.count(),
        };
    }
};

/// Slot metadata
pub const SlotMeta = struct {
    /// Parent slot
    parent_slot: ?core.Slot,

    /// Number of shreds received
    received_shred_count: u32,

    /// Number of shreds expected (from last shred)
    expected_shred_count: ?u32,

    /// Index of first complete shred
    first_shred_timestamp_ns: u64,

    /// Index of last complete shred
    last_shred_timestamp_ns: u64,

    /// Whether all shreds have been received
    is_full: bool,

    /// Whether this slot has been processed
    is_connected: bool,

    /// Block hash (available after slot is full)
    blockhash: ?core.Hash,

    /// Leader pubkey for this slot
    leader: ?core.Pubkey,

    pub fn init(parent: ?core.Slot) SlotMeta {
        return .{
            .parent_slot = parent,
            .received_shred_count = 0,
            .expected_shred_count = null,
            .first_shred_timestamp_ns = 0,
            .last_shred_timestamp_ns = 0,
            .is_full = false,
            .is_connected = false,
            .blockhash = null,
            .leader = null,
        };
    }
};

/// Ledger statistics
pub const LedgerStats = struct {
    latest_slot: u64,
    finalized_slot: u64,
    slot_count: usize,
    shred_count: usize,
};

/// In-memory slot metadata store (backed by persistent KV store in production)
pub const SlotMetaStore = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMap(core.Slot, SlotMeta),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .entries = std.AutoHashMap(core.Slot, SlotMeta).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.entries.deinit();
    }

    pub fn get(self: *Self, slot: core.Slot) ?SlotMeta {
        return self.entries.get(slot);
    }

    pub fn insert(self: *Self, slot: core.Slot, meta: SlotMeta) !void {
        try self.entries.put(slot, meta);
    }

    pub fn count(self: *const Self) usize {
        return self.entries.count();
    }

    pub fn purgeBefore(self: *Self, slot: core.Slot) usize {
        var purged: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < slot) {
                _ = self.entries.remove(entry.key_ptr.*);
                purged += 1;
            }
        }
        return purged;
    }
};

/// Shred key for storage
pub const ShredKey = struct {
    slot: core.Slot,
    index: u32,

    pub fn encode(self: ShredKey) [12]u8 {
        var buf: [12]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.slot, .big);
        std.mem.writeInt(u32, buf[8..12], self.index, .big);
        return buf;
    }
};

/// In-memory shred data store
pub const ShredDataStore = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMap(ShredKey, []u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .entries = std.AutoHashMap(ShredKey, []u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.entries.valueIterator();
        while (it.next()) |data| {
            self.allocator.free(data.*);
        }
        self.entries.deinit();
    }

    pub fn get(self: *Self, slot: core.Slot, index: u32) ?[]const u8 {
        const key = ShredKey{ .slot = slot, .index = index };
        return self.entries.get(key);
    }

    pub fn insert(self: *Self, slot: core.Slot, index: u32, data: []const u8) !void {
        const key = ShredKey{ .slot = slot, .index = index };
        const copy = try self.allocator.dupe(u8, data);
        try self.entries.put(key, copy);
    }

    pub fn count(self: *const Self) usize {
        return self.entries.count();
    }

    pub fn purgeBefore(self: *Self, slot: core.Slot) usize {
        var purged: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.slot < slot) {
                self.allocator.free(entry.value_ptr.*);
                _ = self.entries.remove(entry.key_ptr.*);
                purged += 1;
            }
        }
        return purged;
    }
};

/// Block time store
pub const BlockTimeStore = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMap(core.Slot, i64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .entries = std.AutoHashMap(core.Slot, i64).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.entries.deinit();
    }

    pub fn get(self: *Self, slot: core.Slot) ?i64 {
        return self.entries.get(slot);
    }

    pub fn insert(self: *Self, slot: core.Slot, time: i64) !void {
        try self.entries.put(slot, time);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "ledger db init" {
    var db = try LedgerDb.init(std.testing.allocator, "/tmp/test_ledger");
    defer db.deinit();

    try std.testing.expectEqual(@as(u64, 0), db.latest_slot.load(.seq_cst));
}

test "slot meta" {
    var store = SlotMetaStore.init(std.testing.allocator);
    defer store.deinit();

    const meta = SlotMeta.init(99);
    try store.insert(100, meta);

    const found = store.get(100);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(@as(?core.Slot, 99), found.?.parent_slot);
}

test "shred data" {
    var store = ShredDataStore.init(std.testing.allocator);
    defer store.deinit();

    try store.insert(100, 0, "shred data");
    const found = store.get(100, 0);

    try std.testing.expect(found != null);
    try std.testing.expectEqualSlices(u8, "shred data", found.?);
}

