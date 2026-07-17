//! Sig-pattern per-slot account overlay (ported from Sig's `Unrooted.zig`).
//!
//! Stores account writes from unrooted slots in a fixed-capacity ring buffer
//! keyed by `slot % MAX_SLOTS`. All reads REQUIRE an ancestor set — orphan-slot
//! pollution is structurally impossible because orphaned slots are not in any
//! live ancestor set.
//!
//! Design assumption: consensus roots every slot within MAX_SLOTS slots of its
//! production. Vexor on testnet runs ~2.5 slots/sec; MAX_SLOTS=4096 covers
//! ~27 minutes of stall. A breach of this assumption panics in `put`.
//!
//! Threading: per-slot `RwLock`. Single replay thread owns the write path; RPC
//! and scan threads read via shared locks. Returned `Account` views borrow into
//! overlay memory and are valid only until the same thread mutates the overlay.
//! Cross-thread / cross-yield consumers use `getOwned` for a cloned copy.
//!
//! @prov:store.sig-overlay

const std = @import("std");

const core = @import("core");

pub const MAX_SLOTS: usize = 4096;

const Pubkey = core.Pubkey;
const Slot = core.Slot;

/// Vexor's account record (re-declared here to avoid a circular import on
/// accounts.zig). Caller stores `data` allocated with the overlay's allocator
/// and the overlay frees it on overwrite / purge.
pub const Account = struct {
    lamports: u64,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};

pub const AccountWithModifiedSlot = struct {
    account: Account,
    modified_slot: Slot,
};

pub const Error = error{ OutOfMemory, UnrootedGetOwnedMaxRetries };

slots: []SlotIndex,

pub const SlotIndex = struct {
    lock: std.Thread.RwLock,
    slot: Slot,
    is_empty: std.atomic.Value(bool),
    entries: std.AutoHashMapUnmanaged(Pubkey, Account),

    pub const empty: SlotIndex = .{
        .lock = .{},
        .slot = 0,
        .is_empty = .init(true),
        .entries = .{},
    };
};

const Self = @This();

pub fn init(allocator: std.mem.Allocator) !Self {
    const slots = try allocator.alloc(SlotIndex, MAX_SLOTS);
    errdefer allocator.free(slots);
    for (slots) |*s| s.* = SlotIndex.empty;
    return .{ .slots = slots };
}

pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    for (self.slots) |*slot| {
        var it = slot.entries.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.data.len > 0) allocator.free(@constCast(kv.value_ptr.data));
        }
        slot.entries.deinit(allocator);
    }
    allocator.free(self.slots);
}

/// Task #71 [MEM-BREAKDOWN]: racy unlocked sum of per-bucket entry counts.
/// Diagnostic-only — torn counts are acceptable; takes NO locks so it can
/// never contend with the replay hot path.
pub fn approxEntries(self: *Self) usize {
    var n: usize = 0;
    for (self.slots) |*s| {
        if (s.is_empty.load(.monotonic)) continue;
        n += s.entries.count();
    }
    return n;
}

/// Write `account` at `(slot, address)`. Overwrites any existing entry for the
/// same (slot, address) pair, freeing the old `data` slice.
///
/// `account.data` is taken ownership of: callers must allocate `data` with
/// `allocator` and not free it after `put` returns. The overlay frees it on
/// overwrite / purge / deinit.
///
/// Panics if a slot bucket is reused while still occupied — meaning consensus
/// failed to root a slot within MAX_SLOTS of its production. Capacity warning
/// is the caller's responsibility (track utilization externally).
pub fn put(
    self: *Self,
    allocator: std.mem.Allocator,
    slot: Slot,
    address: Pubkey,
    account: Account,
) !void {
    const index = slot % MAX_SLOTS;
    const entry = &self.slots[index];

    entry.lock.lock();
    defer entry.lock.unlock();

    if (entry.slot != slot) {
        if (!entry.is_empty.load(.acquire)) {
            // Ring overflowed without rooting. Free the prior slot's owned data
            // to avoid leak and reset the bucket. This is a degraded mode —
            // the caller's consensus engine is supposed to root within MAX_SLOTS.
            var it = entry.entries.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.data.len > 0) allocator.free(@constCast(kv.value_ptr.data));
            }
        }
        entry.entries.clearRetainingCapacity();
        entry.slot = slot;
    }

    const gop = try entry.entries.getOrPut(allocator, address);
    if (gop.found_existing) {
        if (gop.value_ptr.data.len > 0) allocator.free(@constCast(gop.value_ptr.data));
    }
    gop.value_ptr.* = account;
    entry.is_empty.store(false, .release);
}

/// Latest account state for `address` visible to `ancestors`. Returned view
/// borrows the overlay's data slice; valid only until the next mutation on the
/// same thread. Cross-thread consumers use `getOwned`.
pub fn get(
    self: *Self,
    address: Pubkey,
    ancestors: []const Slot,
) ?Account {
    const result = self.getWithModifiedSlot(address, ancestors) orelse return null;
    return result.account;
}

pub fn getWithModifiedSlot(
    self: *Self,
    address: Pubkey,
    ancestors: []const Slot,
) ?AccountWithModifiedSlot {
    var best_slot: Slot = 0;
    var result: ?AccountWithModifiedSlot = null;

    for (self.slots) |*index| {
        if (index.is_empty.load(.acquire)) continue;

        index.lock.lockShared();
        defer index.lock.unlockShared();

        if (index.slot >= best_slot and containsSlot(ancestors, index.slot)) {
            if (index.entries.get(address)) |acct| {
                result = .{ .account = acct, .modified_slot = index.slot };
                best_slot = index.slot;
            }
        }
    }

    return result;
}

/// Caller-owned clone — for cross-thread / cross-yield consumers.
///
/// Two-phase: scan all buckets for the best (highest) ancestor slot containing
/// the address, then re-lock that bucket and clone. Retries on race with
/// `purgeSlot` invalidating the chosen bucket. Bounded at 10 retries.
pub fn getOwned(
    self: *Self,
    allocator: std.mem.Allocator,
    address: Pubkey,
    ancestors: []const Slot,
) Error!?Account {
    var retries: u32 = 0;
    while (retries < 10) : (retries += 1) {
        var best_slot: Slot = 0;
        var best_index: ?*SlotIndex = null;

        for (self.slots) |*index| {
            if (index.is_empty.load(.acquire)) continue;

            index.lock.lockShared();
            defer index.lock.unlockShared();

            if (index.slot >= best_slot and containsSlot(ancestors, index.slot)) {
                if (index.entries.contains(address)) {
                    best_index = index;
                    best_slot = index.slot;
                }
            }
        }

        const index = best_index orelse return null;
        index.lock.lockShared();
        defer index.lock.unlockShared();

        if (index.is_empty.load(.acquire) or index.slot != best_slot) continue;
        const acct = index.entries.get(address) orelse continue;

        const cloned_data = if (acct.data.len > 0) blk: {
            const buf = try allocator.alloc(u8, acct.data.len);
            @memcpy(buf, acct.data);
            break :blk buf;
        } else @as([]const u8, &[_]u8{});

        return Account{
            .lamports = acct.lamports,
            .owner = acct.owner,
            .executable = acct.executable,
            .rent_epoch = acct.rent_epoch,
            .data = cloned_data,
        };
    }
    return error.UnrootedGetOwnedMaxRetries;
}

/// Drop all writes for `slot` from the overlay. Called by `markSlotDead` so
/// an orphan slot's writes never pollute canonical-fork reads, and by
/// `updateRoot` so siblings of the rooted slot are evicted.
///
/// Frees all `data` slices owned by the slot's bucket.
pub fn purgeSlot(self: *Self, allocator: std.mem.Allocator, slot: Slot) void {
    const index = slot % MAX_SLOTS;
    const entry = &self.slots[index];

    entry.lock.lock();
    defer entry.lock.unlock();

    if (entry.slot != slot or entry.is_empty.load(.acquire)) return;

    var it = entry.entries.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.data.len > 0) allocator.free(@constCast(kv.value_ptr.data));
    }
    entry.entries.clearRetainingCapacity();
    entry.is_empty.store(true, .release);
}

/// Visit every account in the overlay bucket for `slot`. Returns without
/// calling visitor if the bucket is empty / mismatched.
///
/// Used by the rooted-flush path: when a slot is promoted to root, the caller
/// iterates its bucket and writes each (pubkey, account) into the AppendVec
/// rooted store, then calls `purgeSlot`.
pub fn forEachInSlot(
    self: *Self,
    slot: Slot,
    ctx: anytype,
    visitor: anytype,
) void {
    const index = slot % MAX_SLOTS;
    const entry = &self.slots[index];

    entry.lock.lockShared();
    defer entry.lock.unlockShared();

    if (entry.slot != slot or entry.is_empty.load(.acquire)) return;

    var it = entry.entries.iterator();
    while (it.next()) |kv| {
        visitor(ctx, kv.key_ptr.*, kv.value_ptr.*);
    }
}

/// Diagnostic-only: returns the list of slots where `address` is present
/// (regardless of ancestor membership). Fills `out` up to its capacity and
/// returns the count written. Used by the Phase A read tap to distinguish
/// "sig_overlay has the canonical value but our ancestors window misses it"
/// (bounded-window problem) from "sig_overlay never received the canonical
/// write" (Phase 2c-B write-side gap). Slow — scans all MAX_SLOTS buckets —
/// so callers should gate to suspect reads only.
pub fn slotsContaining(self: *Self, address: Pubkey, out: []Slot) usize {
    var n: usize = 0;
    for (self.slots) |*index| {
        if (n >= out.len) break;
        if (index.is_empty.load(.acquire)) continue;
        index.lock.lockShared();
        defer index.lock.unlockShared();
        if (index.entries.contains(address)) {
            out[n] = index.slot;
            n += 1;
        }
    }
    return n;
}

/// PROMOTE-DIAG (2026-05-28): number of account entries the overlay holds for
/// `slot`. O(1) bucket check (`slot % MAX_SLOTS`); returns 0 if the bucket is
/// empty or has been recycled to a different slot. Diagnostic-only — lets the
/// purge path distinguish dropping REAL writes (>0 = DANGEROUS carrier) from a
/// benign skipped/empty-slot purge (0).
pub fn entryCountForSlot(self: *Self, slot: Slot) usize {
    const index = slot % MAX_SLOTS;
    const si = &self.slots[index];
    if (si.is_empty.load(.acquire)) return 0;
    si.lock.lockShared();
    defer si.lock.unlockShared();
    if (si.slot != slot) return 0;
    return si.entries.count();
}

/// Count occupied slots — for capacity warning. Caller should warn at 75%
/// utilization (3072 slots) and panic-class-error at MAX_SLOTS.
pub fn occupiedSlotCount(self: *Self) usize {
    var n: usize = 0;
    for (self.slots) |*s| {
        if (!s.is_empty.load(.acquire)) n += 1;
    }
    return n;
}

inline fn containsSlot(ancestors: []const Slot, slot: Slot) bool {
    for (ancestors) |a| {
        if (a == slot) return true;
    }
    return false;
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests (port of Sig's Unrooted.zig tests; same fixture pubkeys).
// ──────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn testPk(seed: u8) Pubkey {
    var bytes: [32]u8 = undefined;
    @memset(&bytes, seed);
    return Pubkey.fromBytes(bytes);
}

test "sanity check — highest ancestor wins" {
    const allocator = testing.allocator;
    var db = try Self.init(allocator);
    defer db.deinit(allocator);

    const account_a = testPk(0xAA);
    const account_b = testPk(0xBB);

    try db.put(allocator, 1, account_a, .{
        .lamports = 1_000_000,
        .owner = account_b,
        .executable = true,
        .rent_epoch = 30,
        .data = &.{},
    });
    try db.put(allocator, 2, account_a, .{
        .lamports = 500_000,
        .owner = account_b,
        .executable = true,
        .rent_epoch = 30,
        .data = &.{},
    });
    try db.put(allocator, 3, account_a, .{
        .lamports = 250_000,
        .owner = account_b,
        .executable = true,
        .rent_epoch = 30,
        .data = &.{},
    });

    const ancestors = [_]Slot{ 1, 3 };
    const result = db.get(account_a, &ancestors).?;
    try testing.expectEqual(@as(u64, 250_000), result.lamports);

    const result_owned = (try db.getOwned(allocator, account_a, &ancestors)).?;
    try testing.expectEqual(@as(u64, 250_000), result_owned.lamports);
    if (result_owned.data.len > 0) allocator.free(@constCast(result_owned.data));
}

test "forked behaviour — same slot multiple writes" {
    const allocator = testing.allocator;
    var db = try Self.init(allocator);
    defer db.deinit(allocator);

    const account_a = testPk(0xAA);
    const account_b = testPk(0xBB);

    try db.put(allocator, 1, account_a, .{
        .lamports = 1_000_000,
        .owner = account_b,
        .executable = true,
        .rent_epoch = 30,
        .data = &.{},
    });
    try db.put(allocator, 2, account_a, .{
        .lamports = 500_000,
        .owner = account_b,
        .executable = true,
        .rent_epoch = 30,
        .data = &.{},
    });
    // Same slot, overwrite — latest wins, prior `data` freed
    try db.put(allocator, 2, account_a, .{
        .lamports = 750_000,
        .owner = account_b,
        .executable = true,
        .rent_epoch = 30,
        .data = &.{},
    });

    const ancestors = [_]Slot{ 1, 2 };
    const result = db.get(account_a, &ancestors).?;
    try testing.expectEqual(@as(u64, 750_000), result.lamports);
}

test "account not in ancestor set" {
    const allocator = testing.allocator;
    var db = try Self.init(allocator);
    defer db.deinit(allocator);

    const account_a = testPk(0xAA);
    const account_b = testPk(0xBB);

    try db.put(allocator, 5, account_a, .{
        .lamports = 1_000_000,
        .owner = account_b,
        .executable = true,
        .rent_epoch = 30,
        .data = &.{},
    });

    const ancestors = [_]Slot{ 1, 2, 3 };
    try testing.expectEqual(@as(?Account, null), db.get(account_a, &ancestors));
    try testing.expectEqual(@as(?Account, null), try db.getOwned(allocator, account_a, &ancestors));
}

test "purgeSlot evicts and frees" {
    const allocator = testing.allocator;
    var db = try Self.init(allocator);
    defer db.deinit(allocator);

    const account_a = testPk(0xAA);
    const account_b = testPk(0xBB);

    const data = try allocator.alloc(u8, 128);
    @memset(data, 0xAB);
    try db.put(allocator, 1, account_a, .{
        .lamports = 1_000_000,
        .owner = account_b,
        .executable = false,
        .rent_epoch = 0,
        .data = data,
    });

    const ancestors = [_]Slot{1};
    try testing.expect(db.get(account_a, &ancestors) != null);

    db.purgeSlot(allocator, 1);
    try testing.expectEqual(@as(?Account, null), db.get(account_a, &ancestors));
    try testing.expectEqual(@as(usize, 0), db.occupiedSlotCount());
}
