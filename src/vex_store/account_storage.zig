//! Vexor Accounts Database — AccountStorage store-management / rotation layer.
//! SPLIT from accounts.zig (rebuild module 25). Owns AccountStorage plus the
//! store_rotations_prevented and g_av_reclaimed_* counters. Depends only on the
//! appendvec.zig leaf layer.
const std = @import("std");
const core = @import("core");
const appendvec = @import("appendvec.zig");
const AppendVec = appendvec.AppendVec;
const AccountLocation = appendvec.AccountLocation;
const Account = appendvec.Account;
const AccountView = appendvec.AccountView;

/// Perf (#1A): identity-hash context for the store_id → *AppendVec map.
/// store_id is a DENSE MONOTONIC counter (next_store_id, only ever += 1, never
/// reset), so running Wyhash over the 4 key bytes on every readAccount is pure
/// overhead. A Fibonacci multiply (Knuth's multiplicative hash) spreads the
/// dense keys across the table's power-of-two bucket array just as well while
/// costing a single `imul`. Pure mechanism swap: same store_id → same bucket →
/// same *AppendVec, so returned account bytes are byte-identical.
const StoreIdCtx = struct {
    pub fn hash(_: StoreIdCtx, k: u32) u64 {
        return @as(u64, k) *% 0x9E3779B97F4A7C15; // Fibonacci, no Wyhash
    }
    pub fn eql(_: StoreIdCtx, a: u32, b: u32) bool {
        return a == b;
    }
};
const StoreIdMap = std.HashMap(u32, *AppendVec, StoreIdCtx, std.hash_map.default_max_load_percentage);

/// CARRIER-FIRED signal (advisor 2026-06-07): incremented at the EXACT fall-through in
/// `getOrCreateStore` where a slot's mapped store is full — precisely the pre-fix
/// silent-drop condition (pre-fix the AppendVecFull retry returned this same full store
/// and `promoteRingEntry` dropped the write). A NONZERO value during a live soak =
/// the store-rotation carrier WAS live (each count = one rooted-write drop the fix
/// prevented); ~0 at the tip = the carrier was NOT the steady-tip mechanism (→ pivot to
/// op1 per-account oracle). This is the honest production signal that answers "did the
/// fix matter?" — distinct from `lost_rooted_writes` (regression tripwire) and from the
/// real divergence gate (tip bank_hash vs cluster-attested).
pub var store_rotations_prevented: u64 = 0;

// Task #71 fix candidate: stores reclaimed (shrunk away or purged) + bytes freed.
pub var g_av_reclaimed_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var g_av_reclaimed_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Account storage using append vectors
pub const AccountStorage = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,
    lock: std.Thread.RwLock,
    /// Active append vectors by slot
    stores: StoreIdMap,
    slot_to_store: std.AutoHashMap(core.Slot, u32),
    next_store_id: u32,
    default_capacity: u64,
    /// During snapshot loading, we use a shared store to avoid creating thousands of allocations
    current_bulk_store_id: ?u32 = null,
    bulk_store_bytes_used: u64 = 0,
    /// When true, bypass slot_to_store lookups to avoid routing to full stores
    bulk_mode: bool = false,
    /// Task #71 (2026-06-10) store-reclaim QUARANTINE. Stores replaced by
    /// shrinkSlot are RETIRED here instead of freed: they stay present in
    /// `stores` so any in-flight reader holding a stale AccountLocation (the
    /// index.get → readAccount TOCTOU gap) or a borrowed AccountView slice
    /// (the `getRooted` contract returns BORROWED views into AppendVec heap
    /// memory) keeps resolving byte-identical content. `reapRetired` frees a
    /// retired store only once the root has advanced `quarantine_slots` past
    /// its retirement — far longer than any legitimate borrow lives (borrows
    /// are bounded by "until the next re-entrant write", i.e. ~a slot). This
    /// preserves the append-only borrow-safety invariant that
    /// never-freeing-stores used to provide, while finally reclaiming dead
    /// 64MB heap stores (the 28-30 GB/h RSS-leak class).
    retired_stores: std.ArrayListUnmanaged(RetiredStore) = .{},

    pub const RetiredStore = struct {
        store_id: u32,
        retired_at_root: core.Slot,
    };

    const DEFAULT_APPEND_VEC_CAPACITY: u64 = 64 * 1024 * 1024; // 64MB

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, path: []const u8, default_capacity: u64) !Self {
        const base_path_copy = try allocator.dupe(u8, path);
        return .{
            .allocator = allocator,
            .base_path = base_path_copy,
            .lock = .{},
            .stores = StoreIdMap.init(allocator),
            .slot_to_store = std.AutoHashMap(core.Slot, u32).init(allocator),
            .next_store_id = 0,
            .default_capacity = if (default_capacity > 0) default_capacity else DEFAULT_APPEND_VEC_CAPACITY,
        };
    }

    pub fn deinit(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();
        var iter = self.stores.valueIterator();
        while (iter.next()) |av| {
            av.*.deinit();
        }
        self.stores.deinit();
        self.slot_to_store.deinit();
        // Task #71: retired stores' AppendVecs are still in `stores` (freed
        // above); only the bookkeeping list itself needs freeing here.
        self.retired_stores.deinit(self.allocator);
        self.allocator.free(self.base_path);
    }

    /// Task #71: retire a store (quarantine). Caller must hold `lock`
    /// EXCLUSIVE. The store stays in `stores` (readable via stale locations)
    /// until reapRetired frees it after the quarantine window.
    pub fn retireStoreUnlocked(self: *Self, store_id: u32, retired_at_root: core.Slot) !void {
        try self.retired_stores.append(self.allocator, .{
            .store_id = store_id,
            .retired_at_root = retired_at_root,
        });
    }

    /// Task #71: free retired stores whose quarantine has expired
    /// (current_root advanced >= quarantine_slots past retirement). Deletes
    /// the tmpfs .av mirror file too (the SECOND unbounded RAM sink). The
    /// `dirty` flag is cleared first so AppendVec.deinit's flush-on-deinit
    /// cannot resurrect the file we just deleted.
    pub fn reapRetired(self: *Self, current_root: core.Slot, quarantine_slots: u64) void {
        self.lock.lock();
        defer self.lock.unlock();
        var i: usize = 0;
        while (i < self.retired_stores.items.len) {
            const r = self.retired_stores.items[i];
            if (current_root >= r.retired_at_root + quarantine_slots) {
                if (self.stores.fetchRemove(r.store_id)) |store| {
                    const av = store.value;
                    _ = g_av_reclaimed_count.fetchAdd(1, .monotonic);
                    _ = g_av_reclaimed_bytes.fetchAdd(av.capacity, .monotonic);
                    av.dirty = false; // suppress deinit's flush-to-disk (no resurrection)
                    std.fs.cwd().deleteFile(av.file_path) catch {};
                    av.deinit();
                }
                _ = self.retired_stores.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    pub fn flushMetadata(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();
        var iter = self.stores.valueIterator();
        while (iter.next()) |av| {
            av.*.flushMeta() catch {};
        }
    }

    pub fn readAccount(self: *Self, location: AccountLocation) ?AccountView {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.readAccountUnlocked(location);
    }

    pub fn readAccountUnlocked(self: *Self, location: AccountLocation) ?AccountView {
        if (self.stores.get(location.store_id)) |av| {
            return av.getAccount(location.offset);
        }
        return null;
    }

    /// Perf (#4a): owner-only fast path for scanByOwner Phase B. Resolves the
    /// store + record like readAccount but returns ONLY a borrowed pointer to
    /// the 32 owner bytes in the mmap/heap buffer — skipping lamports/rent_epoch
    /// integer loads, data slicing, and (for heap stores) the pubkey copy.
    /// Same shared-lock discipline as readAccount (dereferences store buffers).
    /// Byte-identical safety: returns the SAME 32 owner bytes readAccount would
    /// have produced, so the scanByOwner candidate set is unchanged.
    pub fn readOwner(self: *Self, location: AccountLocation) ?*const [32]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.stores.get(location.store_id)) |av| {
            return av.getOwner(location.offset);
        }
        return null;
    }

    /// Serialize an account to bytes (for bulk loading with minimal lock time)
    pub fn serializeAccountToBytes(self: *Self, pubkey: *const core.Pubkey, account: *const Account) ![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, &pubkey.data);
        try buf.writer(self.allocator).writeInt(u64, account.lamports, .little);
        try buf.appendSlice(self.allocator, &account.owner.data);
        try buf.append(self.allocator, @intFromBool(account.executable));
        try buf.writer(self.allocator).writeInt(u64, account.rent_epoch, .little);
        try buf.writer(self.allocator).writeInt(u32, @intCast(account.data.len), .little);
        try buf.appendSlice(self.allocator, account.data);

        return buf.toOwnedSlice(self.allocator);
    }

    /// Write pre-serialized account data (faster, minimizes lock time)
    pub fn writeAccountBytes(self: *Self, data: []const u8, slot: core.Slot) !AccountLocation {
        self.lock.lock();
        defer self.lock.unlock();
        var store_id = try self.getOrCreateStore(slot, @intCast(data.len));
        var av = self.stores.get(store_id) orelse return error.StoreNotFound;

        const offset = av.append(data) catch |err| switch (err) {
            error.AppendVecFull => {
                // Room-aware getOrCreateStore should make this unreachable; if it
                // still fires, log loudly and rotate to a fresh store (NEVER silent).
                std.log.err("[STORE-ROTATE] writeAccountBytes AppendVecFull store={d} slot={d} need={d} — rotating to fresh store", .{ store_id, slot, data.len });
                self.current_bulk_store_id = null;
                self.bulk_store_bytes_used = 0;
                store_id = try self.getOrCreateStore(slot, @intCast(data.len));
                av = self.stores.get(store_id) orelse return error.StoreNotFound;
                return .{
                    .store_id = store_id,
                    .offset = try av.append(data),
                    .slot = slot,
                };
            },
            else => return err,
        };

        // Track bytes written for bulk store rotation
        self.trackBulkWrite(@intCast(data.len));

        return AccountLocation{
            .store_id = store_id,
            .offset = offset,
            .slot = slot,
        };
    }

    pub fn writeAccount(self: *Self, pubkey: *const core.Pubkey, account: *const Account, slot: core.Slot) !AccountLocation {
        self.lock.lock();
        defer self.lock.unlock();
        // Encoded record size = fixed header (pubkey+lamports+owner+exec+rent+len) + data.
        // Passing it to getOrCreateStore guarantees the returned store has room, so the
        // AppendVecFull retry below can never silently drop the rooted write.
        const needed: u64 = @intCast(AppendVec.record_header_len + account.data.len);
        var store_id = try self.getOrCreateStore(slot, needed);
        // FIX: Avoid forced unwrap - return error if store not found (shouldn't happen but safer)
        var av = self.stores.get(store_id) orelse return error.StoreNotFound;

        var buf = std.ArrayListUnmanaged(u8){};
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, &pubkey.data);
        try buf.writer(self.allocator).writeInt(u64, account.lamports, .little);
        try buf.appendSlice(self.allocator, &account.owner.data);
        try buf.append(self.allocator, @intFromBool(account.executable));
        try buf.writer(self.allocator).writeInt(u64, account.rent_epoch, .little);
        try buf.writer(self.allocator).writeInt(u32, @intCast(account.data.len), .little);
        try buf.appendSlice(self.allocator, account.data);

        const offset = av.append(buf.items) catch |err| switch (err) {
            error.AppendVecFull => {
                // Room-aware getOrCreateStore should make this unreachable; if it
                // still fires, log loudly and rotate to a fresh store (NEVER silent).
                std.log.err("[STORE-ROTATE] writeAccount AppendVecFull store={d} slot={d} need={d} — rotating to fresh store", .{ store_id, slot, needed });
                self.current_bulk_store_id = null;
                self.bulk_store_bytes_used = 0;
                store_id = try self.getOrCreateStore(slot, needed);
                av = self.stores.get(store_id) orelse return error.StoreNotFound;
                return .{
                    .store_id = store_id,
                    .offset = try av.append(buf.items),
                    .slot = slot,
                };
            },
            else => return err,
        };

        // Track bytes written for bulk store rotation
        self.trackBulkWrite(@intCast(buf.items.len));

        return AccountLocation{
            .store_id = store_id,
            .offset = offset,
            .slot = slot,
        };
    }

    /// Return a store that has room for `needed` bytes (the encoded record length),
    /// creating/rotating one if necessary. `needed` is REQUIRED so the normal-mode
    /// mapped path can NEVER return a store that lacks room — the canonical Agave
    /// invariant (`write_accounts_to_storage` never appends to a store without room;
    /// it creates a new store and retries). This fixes the PROVEN store-rotation
    /// carrier: pre-fix the `AppendVecFull` retry re-called `getOrCreateStore(slot)`
    /// which returned the SAME full store via `slot_to_store.get(slot)`, the second
    /// append threw again, and `promoteRingEntry`'s silent catch dropped the rooted
    /// write → stale rooted index → lt divergence → vote-freeze.
    fn getOrCreateStore(self: *Self, slot: core.Slot, needed: u64) !u32 {
        const capacity = if (self.default_capacity > 0) self.default_capacity else DEFAULT_APPEND_VEC_CAPACITY;

        // In bulk mode (snapshot load), bypass slot_to_store entirely.
        // All threads share the current bulk store and rotate when full.
        // UNCHANGED — this path already rotates correctly during bootstrap.
        if (self.bulk_mode) {
            // Check if current bulk store has room (leave 10% headroom)
            const headroom: u64 = capacity / 10;
            if (self.current_bulk_store_id) |bulk_id| {
                if (self.bulk_store_bytes_used + headroom < capacity) {
                    return bulk_id;
                }
            }

            // Need a new bulk store
            const store_id = self.next_store_id;
            self.next_store_id += 1;
            const new_av = try AppendVec.init(self.allocator, self.base_path, store_id, slot, capacity);
            try self.stores.put(store_id, new_av);

            self.current_bulk_store_id = store_id;
            self.bulk_store_bytes_used = 0;

            return store_id;
        }

        // Normal mode: per-slot store mapping — but NEVER return a store lacking
        // room for this write. A full mapped store falls through to rotate + remap
        // (the create-new branch's `slot_to_store.put(slot, store_id)` overwrites the
        // stale mapping). `needed` includes the per-record header (record_header_len).
        if (self.slot_to_store.get(slot)) |store_id| {
            if (self.stores.get(store_id)) |av| {
                if (av.current_len.load(.acquire) + needed <= av.capacity) {
                    return store_id;
                }
                // mapped store is full for THIS write — this is EXACTLY the pre-fix
                // silent-drop condition (the AppendVecFull retry returned this same full
                // store via slot_to_store.get(slot)). Count it as the carrier-fired
                // signal, then fall through to rotate + remap (never drop).
                store_rotations_prevented += 1;
                if (store_rotations_prevented <= 20 or store_rotations_prevented % 256 == 0) {
                    std.log.warn("[STORE-ROTATE-PREVENTED] slot={d} store={d} used={d} need={d} cap={d} total={d}", .{ slot, store_id, av.current_len.load(.acquire), needed, av.capacity, store_rotations_prevented });
                }
            } else {
                // Defensive: a mapping without a backing store should never happen.
                return store_id;
            }
        }

        // Reuse the current shared store only if it actually has room for `needed`.
        if (self.current_bulk_store_id) |bulk_id| {
            if (self.stores.get(bulk_id)) |av| {
                if (av.current_len.load(.acquire) + needed <= av.capacity) {
                    try self.slot_to_store.put(slot, bulk_id);
                    return bulk_id;
                }
            }
        }

        // Need a new store
        const store_id = self.next_store_id;
        self.next_store_id += 1;
        const new_av = try AppendVec.init(self.allocator, self.base_path, store_id, slot, capacity);
        try self.stores.put(store_id, new_av);
        try self.slot_to_store.put(slot, store_id);

        self.current_bulk_store_id = store_id;
        self.bulk_store_bytes_used = 0;

        return store_id;
    }

    /// Call this after writing to update bulk store usage tracking
    fn trackBulkWrite(self: *Self, bytes_written: u64) void {
        self.bulk_store_bytes_used += bytes_written;
    }

    pub fn createStoreForSlotUnlocked(self: *Self, slot: core.Slot, capacity: u64) !struct { store_id: u32, av: *AppendVec } {
        const store_id = self.next_store_id;
        self.next_store_id += 1;
        const av = try AppendVec.init(self.allocator, self.base_path, store_id, slot, capacity);
        try self.stores.put(store_id, av);
        return .{ .store_id = store_id, .av = av };
    }

    pub fn purgeSlot(self: *Self, slot: core.Slot) void {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.slot_to_store.fetchRemove(slot)) |entry| {
            const store_id = entry.value;
            if (self.stores.fetchRemove(store_id)) |store| {
                const av = store.value;
                std.fs.cwd().deleteFile(av.file_path) catch {};
                av.deinit();
            }
        }
    }

    /// Register a mmap'd Agave-format AppendVec for read-only access.
    /// Returns the store_id for use in AccountLocation entries.
    pub fn registerAgaveMmap(self: *Self, data: []u8, file_size: u64) !u32 {
        self.lock.lock();
        defer self.lock.unlock();
        const store_id = self.next_store_id;
        self.next_store_id += 1;
        const av = try AppendVec.initFromAgaveMmap(self.allocator, data, file_size);
        try self.stores.put(store_id, av);
        return store_id;
    }
};
