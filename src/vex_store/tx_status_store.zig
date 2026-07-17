//! SB-2 (parity backlog, shared blocker): signature → location/status index — the index half of the
//! block store. Maps a transaction signature to (slot, index-in-block, err) so `getTransaction` and
//! `getSignatureStatuses` resolve in O(1), and (optionally) an address → signatures index for
//! `getSignaturesForAddress`. The transaction BYTES live in `block_store.zig`; this is the index that
//! points into it.
//!
//! Written by BOTH the replay path (txs we executed in received blocks) and the producer path (txs in
//! blocks we made), read by RPC. ADDITIVE + KAT-gated; NOT wired into the live path yet.

const std = @import("std");
const core = @import("core");
const block_store = @import("block_store.zig");

const Pubkey = core.Pubkey;
pub const TxError = block_store.TxError; // shared err model (no duplication)

/// Commitment level of a transaction's slot, derived at read time from the current root/confirmed tip.
/// Mirrors the RPC `confirmationStatus` string.
pub const ConfirmationStatus = enum {
    processed,
    confirmed,
    finalized,

    pub fn toString(self: ConfirmationStatus) []const u8 {
        return switch (self) {
            .processed => "processed",
            .confirmed => "confirmed",
            .finalized => "finalized",
        };
    }
};

/// Where a signature lives + its outcome. `index_in_block` selects the tx inside the block's
/// `transactions[]` for getTransaction.
pub const TxLocation = struct {
    slot: u64,
    index_in_block: u32,
    err: ?TxError,
};

/// The getSignatureStatuses value-element for one signature.
pub const SigStatus = struct {
    slot: u64,
    /// distance from the tx's slot up to the confirmed tip (Agave: `confirmations`); null once rooted.
    confirmations: ?u64,
    err: ?TxError,
    confirmation_status: ConfirmationStatus,
};

pub const TxStatusStore = struct {
    allocator: std.mem.Allocator,
    /// signature → location/outcome.
    by_sig: std.AutoHashMapUnmanaged([64]u8, TxLocation) = .{},
    /// address → list of (slot, signature), newest-first is imposed at read time. Optional: only
    /// populated if the writer calls `indexAddress`. Owned slices freed on purge/deinit.
    by_addr: std.AutoHashMapUnmanaged(Pubkey, std.ArrayListUnmanaged(AddrSig)) = .{},
    lock: std.Thread.RwLock = .{},

    pub const AddrSig = struct { slot: u64, signature: [64]u8 };

    pub fn init(allocator: std.mem.Allocator) TxStatusStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *TxStatusStore) void {
        self.by_sig.deinit(self.allocator);
        var it = self.by_addr.valueIterator();
        while (it.next()) |list| list.deinit(self.allocator);
        self.by_addr.deinit(self.allocator);
        self.* = undefined;
    }

    /// Record a transaction's location + outcome. Overwrites any prior entry for the same signature
    /// (a re-rooted block at the same slot, or the rare legitimate sig reuse on a new slot).
    pub fn put(self: *TxStatusStore, signature: [64]u8, slot: u64, index_in_block: u32, err: ?TxError) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.by_sig.put(self.allocator, signature, .{ .slot = slot, .index_in_block = index_in_block, .err = err });
    }

    /// Add `signature` to `address`'s signature list (for getSignaturesForAddress). Writer calls this
    /// once per (writable/readable) account key it wants indexed.
    pub fn indexAddress(self: *TxStatusStore, address: Pubkey, slot: u64, signature: [64]u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        const gop = try self.by_addr.getOrPut(self.allocator, address);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(self.allocator, .{ .slot = slot, .signature = signature });
    }

    /// getTransaction: resolve a signature to (slot, index-in-block). Caller then reads the block from
    /// `BlockStore`. null if unknown.
    pub fn locate(self: *TxStatusStore, signature: [64]u8) ?TxLocation {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.by_sig.get(signature);
    }

    /// getSignatureStatuses for one signature. `rooted_slot` = highest finalized (db.rooted_slot);
    /// `confirmed_slot` = highest cluster-confirmed (for the confirmations count + confirmed level).
    /// Returns null if the signature is unknown (RPC emits `null` for that slot in the value array).
    pub fn status(self: *TxStatusStore, signature: [64]u8, rooted_slot: u64, confirmed_slot: u64) ?SigStatus {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const loc = self.by_sig.get(signature) orelse return null;
        return classify(loc, rooted_slot, confirmed_slot);
    }

    /// Pure status classification — extracted so it is unit-testable without the map/lock.
    pub fn classify(loc: TxLocation, rooted_slot: u64, confirmed_slot: u64) SigStatus {
        if (loc.slot <= rooted_slot) {
            return .{ .slot = loc.slot, .confirmations = null, .err = loc.err, .confirmation_status = .finalized };
        }
        if (loc.slot <= confirmed_slot) {
            return .{ .slot = loc.slot, .confirmations = confirmed_slot - loc.slot, .err = loc.err, .confirmation_status = .confirmed };
        }
        return .{ .slot = loc.slot, .confirmations = 0, .err = loc.err, .confirmation_status = .processed };
    }

    /// getSignaturesForAddress: signatures touching `address` with slot in (start, end], newest-first,
    /// up to `limit`. Caller owns the returned slice. Empty if the address was never indexed.
    pub fn signaturesForAddress(self: *TxStatusStore, address: Pubkey, min_slot_excl: u64, max_slot_incl: u64, limit: usize) ![]AddrSig {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var out = std.ArrayListUnmanaged(AddrSig){};
        errdefer out.deinit(self.allocator);
        if (self.by_addr.get(address)) |list| {
            for (list.items) |e| {
                if (e.slot > min_slot_excl and e.slot <= max_slot_incl) try out.append(self.allocator, e);
            }
        }
        // newest-first
        std.mem.sort(AddrSig, out.items, {}, struct {
            fn gt(_: void, a: AddrSig, b: AddrSig) bool {
                return a.slot > b.slot;
            }
        }.gt);
        if (out.items.len > limit) out.shrinkRetainingCapacity(limit);
        return out.toOwnedSlice(self.allocator);
    }

    /// Drop all entries below `min_slot` (rooted-prune cadence). Returns sig-entries dropped.
    pub fn purgeBelow(self: *TxStatusStore, min_slot: u64) usize {
        self.lock.lock();
        defer self.lock.unlock();
        var drop_sigs = std.ArrayListUnmanaged([64]u8){};
        defer drop_sigs.deinit(self.allocator);
        var sit = self.by_sig.iterator();
        while (sit.next()) |e| {
            if (e.value_ptr.slot < min_slot) drop_sigs.append(self.allocator, e.key_ptr.*) catch {};
        }
        for (drop_sigs.items) |s| _ = self.by_sig.remove(s);
        // Compact the per-address lists (drop stale entries; free emptied lists).
        var drop_addrs = std.ArrayListUnmanaged(Pubkey){};
        defer drop_addrs.deinit(self.allocator);
        var ait = self.by_addr.iterator();
        while (ait.next()) |e| {
            var w: usize = 0;
            for (e.value_ptr.items) |item| {
                if (item.slot >= min_slot) {
                    e.value_ptr.items[w] = item;
                    w += 1;
                }
            }
            e.value_ptr.shrinkRetainingCapacity(w);
            if (w == 0) drop_addrs.append(self.allocator, e.key_ptr.*) catch {};
        }
        for (drop_addrs.items) |addr| {
            if (self.by_addr.fetchRemove(addr)) |kv| {
                var list = kv.value;
                list.deinit(self.allocator);
            }
        }
        return drop_sigs.items.len;
    }

    pub fn count(self: *TxStatusStore) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.by_sig.count();
    }
};

// ─────────────────────────────── KATs ───────────────────────────────

const testing = std.testing;

test "TxStatusStore: locate + classify (processed/confirmed/finalized + confirmations)" {
    const a = testing.allocator;
    var s = TxStatusStore.init(a);
    defer s.deinit();

    const sig_ok = [_]u8{0xAA} ** 64;
    const sig_err = [_]u8{0xBB} ** 64;
    try s.put(sig_ok, 1000, 3, null);
    try s.put(sig_err, 1050, 0, .{ .code = 8, .instruction_index = 2, .instruction_error = 1 });

    // locate → getTransaction's (slot, index)
    const loc = s.locate(sig_ok).?;
    try testing.expectEqual(@as(u64, 1000), loc.slot);
    try testing.expectEqual(@as(u32, 3), loc.index_in_block);
    try testing.expect(s.locate([_]u8{0xFF} ** 64) == null);

    // rooted=1000, confirmed=1100. sig_ok.slot(1000) <= rooted → finalized, confirmations null.
    const st_ok = s.status(sig_ok, 1000, 1100).?;
    try testing.expectEqual(ConfirmationStatus.finalized, st_ok.confirmation_status);
    try testing.expect(st_ok.confirmations == null);
    try testing.expect(st_ok.err == null);

    // sig_err.slot(1050): rooted=1000 (>1000 so not finalized), confirmed=1100 (<=1100 → confirmed),
    // confirmations = 1100-1050 = 50; err propagated.
    const st_err = s.status(sig_err, 1000, 1100).?;
    try testing.expectEqual(ConfirmationStatus.confirmed, st_err.confirmation_status);
    try testing.expectEqual(@as(?u64, 50), st_err.confirmations);
    try testing.expectEqual(@as(u32, 8), st_err.err.?.code);

    // processed: slot above both rooted and confirmed.
    try testing.expectEqual(ConfirmationStatus.processed, TxStatusStore.classify(.{ .slot = 2000, .index_in_block = 0, .err = null }, 1000, 1100).confirmation_status);

    // unknown sig → null (RPC emits null element).
    try testing.expect(s.status([_]u8{0x00} ** 64, 1000, 1100) == null);
}

test "TxStatusStore: signaturesForAddress newest-first + range + limit" {
    const a = testing.allocator;
    var s = TxStatusStore.init(a);
    defer s.deinit();
    const addr = Pubkey{ .data = [_]u8{0x42} ** 32 };
    const other = Pubkey{ .data = [_]u8{0x99} ** 32 };
    try s.indexAddress(addr, 10, [_]u8{1} ** 64);
    try s.indexAddress(addr, 30, [_]u8{3} ** 64);
    try s.indexAddress(addr, 20, [_]u8{2} ** 64);
    try s.indexAddress(other, 25, [_]u8{9} ** 64);

    // (5, 100], newest-first = slots 30,20,10
    const r = try s.signaturesForAddress(addr, 5, 100, 100);
    defer a.free(r);
    try testing.expectEqual(@as(usize, 3), r.len);
    try testing.expectEqual(@as(u64, 30), r[0].slot);
    try testing.expectEqual(@as(u64, 20), r[1].slot);
    try testing.expectEqual(@as(u64, 10), r[2].slot);

    // limit 1 → only newest
    const r2 = try s.signaturesForAddress(addr, 5, 100, 1);
    defer a.free(r2);
    try testing.expectEqual(@as(usize, 1), r2.len);
    try testing.expectEqual(@as(u64, 30), r2[0].slot);

    // range excludes slot 10 (min_slot_excl=10 is exclusive)
    const r3 = try s.signaturesForAddress(addr, 10, 100, 100);
    defer a.free(r3);
    try testing.expectEqual(@as(usize, 2), r3.len);

    // unindexed address → empty
    const r4 = try s.signaturesForAddress(Pubkey{ .data = [_]u8{0x00} ** 32 }, 0, 1000, 100);
    defer a.free(r4);
    try testing.expectEqual(@as(usize, 0), r4.len);
}

test "TxStatusStore: purgeBelow drops sigs + compacts/removes address lists" {
    const a = testing.allocator;
    var s = TxStatusStore.init(a);
    defer s.deinit();
    const addr = Pubkey{ .data = [_]u8{0x42} ** 32 };
    try s.put([_]u8{1} ** 64, 100, 0, null);
    try s.put([_]u8{2} ** 64, 200, 0, null);
    try s.put([_]u8{3} ** 64, 300, 0, null);
    try s.indexAddress(addr, 100, [_]u8{1} ** 64);
    try s.indexAddress(addr, 300, [_]u8{3} ** 64);

    try testing.expectEqual(@as(usize, 2), s.purgeBelow(250)); // drops slots 100,200
    try testing.expectEqual(@as(usize, 1), s.count());
    try testing.expect(s.locate([_]u8{3} ** 64) != null and s.locate([_]u8{1} ** 64) == null);
    // address list compacted to just slot 300
    const r = try s.signaturesForAddress(addr, 0, 1000, 100);
    defer a.free(r);
    try testing.expectEqual(@as(usize, 1), r.len);
    try testing.expectEqual(@as(u64, 300), r[0].slot);
}
