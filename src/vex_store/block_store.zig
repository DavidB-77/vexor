//! SB-2 (parity backlog, shared blocker): canonical block persistence store — slot → block.
//!
//! The store that `getBlock` / `getBlocks` / `getBlocksWithLimit` read and that the block producer's
//! `finishSlot` (and the replay path, for blocks we received) write. Today `LedgerDb` holds only
//! slot_meta/shreds/block_time — there is NO block or transaction store, so every block/tx RPC is a
//! stub (`rpc_methods.zig:getBlock` returns a hardcoded empty block). This module is the data half;
//! `tx_status_store.zig` is the signature→location index half (getTransaction / getSignatureStatuses).
//!
//! Model mirrors Agave `ConfirmedBlock` / `TransactionWithStatusMeta` (storage-proto) but holds only
//! what the four block RPCs need; richer fields (inner instructions, token balances, return data) are
//! additive later. ADDITIVE + KAT-gated; NOT wired into the live replay/producer path yet — wiring is
//! a separate, careful step (same discipline as the BP staging modules).
//!
//! Ownership: the store OWNS every byte it holds. `putBlock` deep-copies the caller's transient block;
//! `purgeBelow` / `deinit` free it. The caller's input buffers are never retained.

const std = @import("std");
const core = @import("core");

const Pubkey = core.Pubkey;

/// A transaction's execution outcome. `err == null` ⇒ the transaction succeeded.
/// `err` mirrors the discriminant of Agave `TransactionError`; `instruction_index` is set for the
/// `InstructionError` variant (the common case). Full JSON encoding lives in the RPC handler.
pub const TxError = struct {
    /// Agave TransactionError discriminant (0 = AccountInUse, … ; 8 = InstructionError, …).
    code: u32,
    /// For InstructionError: the failing instruction index. null otherwise.
    instruction_index: ?u8 = null,
    /// For InstructionError: the inner InstructionError discriminant.
    instruction_error: ?u32 = null,
};

/// One transaction as stored in a block: its signature, raw wire bytes, and execution meta.
pub const StoredTx = struct {
    /// First signature = the transaction id used by getTransaction / getSignatureStatuses.
    signature: [64]u8,
    /// Serialized transaction (the exact bytes that were in the entry), store-owned.
    wire: []u8,
    err: ?TxError,
    fee: u64,
    compute_units_consumed: ?u64,
    /// Lamport balances of each account before / after the tx (store-owned, parallel to the
    /// tx's account keys). Empty slices are valid (older blocks / not captured).
    pre_balances: []u64,
    post_balances: []u64,
};

/// A block reward (fee/rent/staking/voting). Matches the getBlock `rewards[]` element.
pub const StoredReward = struct {
    pubkey: Pubkey,
    lamports: i64,
    post_balance: u64,
    /// 0=Fee 1=Rent 2=Staking 3=Voting (Agave RewardType ordinal; 255 = unspecified).
    reward_type: u8,
    /// Vote commission for staking/voting rewards; null otherwise.
    commission: ?u8 = null,
};

/// A complete stored block. All slices are store-owned.
pub const StoredBlock = struct {
    slot: u64,
    parent_slot: u64,
    blockhash: [32]u8,
    previous_blockhash: [32]u8,
    /// Non-skipped block height (null if unknown / not yet computed).
    block_height: ?u64,
    /// Unix seconds estimate (null if unknown).
    block_time: ?i64,
    transactions: []StoredTx,
    rewards: []StoredReward,

    fn deinit(self: *StoredBlock, allocator: std.mem.Allocator) void {
        for (self.transactions) |tx| {
            allocator.free(tx.wire);
            allocator.free(tx.pre_balances);
            allocator.free(tx.post_balances);
        }
        allocator.free(self.transactions);
        allocator.free(self.rewards);
        self.* = undefined;
    }
};

/// slot → StoredBlock. Thread-safe (RwLock: shared reads, exclusive writes).
pub const BlockStore = struct {
    allocator: std.mem.Allocator,
    blocks: std.AutoHashMapUnmanaged(u64, StoredBlock) = .{},
    lock: std.Thread.RwLock = .{},

    pub fn init(allocator: std.mem.Allocator) BlockStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *BlockStore) void {
        var it = self.blocks.valueIterator();
        while (it.next()) |b| b.deinit(self.allocator);
        self.blocks.deinit(self.allocator);
        self.* = undefined;
    }

    /// Deep-copy `block` into the store under `block.slot`. Replaces any existing block at that slot
    /// (freeing the old one — e.g. a re-rooted/corrected block). The caller's buffers are NOT retained.
    pub fn putBlock(self: *BlockStore, block: StoredBlock) !void {
        // Deep-copy transactions + their owned slices.
        const txs = try self.allocator.alloc(StoredTx, block.transactions.len);
        errdefer self.allocator.free(txs);
        var built: usize = 0;
        errdefer for (txs[0..built]) |t| {
            self.allocator.free(t.wire);
            self.allocator.free(t.pre_balances);
            self.allocator.free(t.post_balances);
        };
        for (block.transactions, 0..) |src, i| {
            const wire = try self.allocator.dupe(u8, src.wire);
            errdefer self.allocator.free(wire);
            const pre = try self.allocator.dupe(u64, src.pre_balances);
            errdefer self.allocator.free(pre);
            const post = try self.allocator.dupe(u64, src.post_balances);
            txs[i] = .{
                .signature = src.signature,
                .wire = wire,
                .err = src.err,
                .fee = src.fee,
                .compute_units_consumed = src.compute_units_consumed,
                .pre_balances = pre,
                .post_balances = post,
            };
            built = i + 1;
        }
        const rewards = try self.allocator.dupe(StoredReward, block.rewards);
        errdefer self.allocator.free(rewards);

        var owned = block;
        owned.transactions = txs;
        owned.rewards = rewards;

        self.lock.lock();
        defer self.lock.unlock();
        const gop = try self.blocks.getOrPut(self.allocator, block.slot);
        if (gop.found_existing) gop.value_ptr.deinit(self.allocator);
        gop.value_ptr.* = owned;
    }

    /// Borrow the block at `slot` under the read lock and pass it to `reader`. The pointer is valid
    /// only for the duration of the callback (the lock is held across it). Returns whatever `reader`
    /// returns, or null if no block at `slot`. This avoids copying a whole block out for every read.
    pub fn withBlock(
        self: *BlockStore,
        slot: u64,
        context: anytype,
        comptime reader: fn (@TypeOf(context), *const StoredBlock) void,
    ) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const b = self.blocks.getPtr(slot) orelse return false;
        reader(context, b);
        return true;
    }

    /// True if a block exists at `slot`.
    pub fn hasBlock(self: *BlockStore, slot: u64) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.blocks.contains(slot);
    }

    /// Collect up to `limit` slot numbers with a stored block in [start, end] (inclusive), ascending.
    /// Mirrors getBlocks / getBlocksWithLimit. Caller owns the returned slice.
    pub fn getBlocksInRange(self: *BlockStore, start: u64, end: u64, limit: usize) ![]u64 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var out = std.ArrayListUnmanaged(u64){};
        errdefer out.deinit(self.allocator);
        var it = self.blocks.keyIterator();
        while (it.next()) |k| {
            if (k.* >= start and k.* <= end) try out.append(self.allocator, k.*);
        }
        std.mem.sort(u64, out.items, {}, std.sort.asc(u64));
        if (out.items.len > limit) out.shrinkRetainingCapacity(limit);
        return out.toOwnedSlice(self.allocator);
    }

    /// Drop every block with slot < `min_slot` (called at the rooted-prune cadence). Returns the count
    /// dropped. Keeps the store bounded to the unpruned window — Agave's blockstore purges similarly.
    pub fn purgeBelow(self: *BlockStore, min_slot: u64) usize {
        self.lock.lock();
        defer self.lock.unlock();
        var drop = std.ArrayListUnmanaged(u64){};
        defer drop.deinit(self.allocator);
        var it = self.blocks.keyIterator();
        while (it.next()) |k| {
            if (k.* < min_slot) drop.append(self.allocator, k.*) catch {};
        }
        for (drop.items) |s| {
            if (self.blocks.fetchRemove(s)) |kv| {
                var b = kv.value;
                b.deinit(self.allocator);
            }
        }
        return drop.items.len;
    }

    pub fn count(self: *BlockStore) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.blocks.count();
    }
};

// ─────────────────────────────── KATs ───────────────────────────────

const testing = std.testing;

fn mkTx(sig_byte: u8, wire: []const u8, err: ?TxError, fee: u64) StoredTx {
    return .{
        .signature = [_]u8{sig_byte} ** 64,
        .wire = @constCast(wire),
        .err = err,
        .fee = fee,
        .compute_units_consumed = 100,
        .pre_balances = @constCast(&[_]u64{ 1000, 0 }),
        .post_balances = @constCast(&[_]u64{ 900, 100 }),
    };
}

test "BlockStore: put → withBlock round-trip (deep copy, store-owned)" {
    const a = testing.allocator;
    var store = BlockStore.init(a);
    defer store.deinit();

    var txs = [_]StoredTx{
        mkTx(0xAA, "transaction-one-wire", null, 5000),
        mkTx(0xBB, "tx2", .{ .code = 8, .instruction_index = 1, .instruction_error = 3 }, 5000),
    };
    var rewards = [_]StoredReward{
        .{ .pubkey = .{ .data = [_]u8{0x11} ** 32 }, .lamports = 12345, .post_balance = 99999, .reward_type = 1, .commission = 5 },
    };
    try store.putBlock(.{
        .slot = 415000000,
        .parent_slot = 414999999,
        .blockhash = [_]u8{0xCD} ** 32,
        .previous_blockhash = [_]u8{0xAB} ** 32,
        .block_height = 400000000,
        .block_time = 1700000000,
        .transactions = &txs,
        .rewards = &rewards,
    });

    // Mutate the caller's buffers AFTER put — the store must be unaffected (proves deep copy).
    txs[0].fee = 0;
    rewards[0].lamports = 0;

    const Probe = struct {
        var tx_count: usize = 0;
        var reward_lamports: i64 = 0;
        var first_fee: u64 = 0;
        var second_err_code: u32 = 0;
        var wire0: [32]u8 = undefined;
        var wire0_len: usize = 0;
        var parent: u64 = 0;
        fn read(_: void, b: *const StoredBlock) void {
            tx_count = b.transactions.len;
            reward_lamports = b.rewards[0].lamports;
            first_fee = b.transactions[0].fee;
            second_err_code = b.transactions[1].err.?.code;
            @memcpy(wire0[0..b.transactions[0].wire.len], b.transactions[0].wire);
            wire0_len = b.transactions[0].wire.len;
            parent = b.parent_slot;
        }
    };
    try testing.expect(store.withBlock(415000000, {}, Probe.read));
    try testing.expectEqual(@as(usize, 2), Probe.tx_count);
    try testing.expectEqual(@as(i64, 12345), Probe.reward_lamports); // NOT 0 → deep-copied
    try testing.expectEqual(@as(u64, 5000), Probe.first_fee); // NOT 0 → deep-copied
    try testing.expectEqual(@as(u32, 8), Probe.second_err_code);
    try testing.expectEqualStrings("transaction-one-wire", Probe.wire0[0..Probe.wire0_len]);
    try testing.expectEqual(@as(u64, 414999999), Probe.parent);

    // Missing slot → false.
    try testing.expect(!store.withBlock(999, {}, Probe.read));
}

test "BlockStore: replace at same slot frees the old block (no leak, new wins)" {
    const a = testing.allocator;
    var store = BlockStore.init(a);
    defer store.deinit();
    var txs1 = [_]StoredTx{mkTx(0x01, "old-block-tx", null, 1)};
    try store.putBlock(.{ .slot = 5, .parent_slot = 4, .blockhash = [_]u8{1} ** 32, .previous_blockhash = [_]u8{0} ** 32, .block_height = 5, .block_time = null, .transactions = &txs1, .rewards = &[_]StoredReward{} });
    var txs2 = [_]StoredTx{ mkTx(0x02, "new-block-tx-a", null, 2), mkTx(0x03, "new-block-tx-b", null, 2) };
    try store.putBlock(.{ .slot = 5, .parent_slot = 4, .blockhash = [_]u8{2} ** 32, .previous_blockhash = [_]u8{0} ** 32, .block_height = 5, .block_time = null, .transactions = &txs2, .rewards = &[_]StoredReward{} });
    try testing.expectEqual(@as(usize, 1), store.count()); // still one slot
    const Probe = struct {
        var n: usize = 0;
        fn read(_: void, b: *const StoredBlock) void {
            n = b.transactions.len;
        }
    };
    _ = store.withBlock(5, {}, Probe.read);
    try testing.expectEqual(@as(usize, 2), Probe.n); // the NEW block (2 txs) won
}

test "BlockStore: getBlocksInRange + getBlocksWithLimit ordering + purgeBelow" {
    const a = testing.allocator;
    var store = BlockStore.init(a);
    defer store.deinit();
    const slots = [_]u64{ 100, 105, 103, 110, 99, 250 };
    for (slots) |s| {
        var t = [_]StoredTx{mkTx(@truncate(s), "x", null, 0)};
        try store.putBlock(.{ .slot = s, .parent_slot = s - 1, .blockhash = [_]u8{0} ** 32, .previous_blockhash = [_]u8{0} ** 32, .block_height = s, .block_time = null, .transactions = &t, .rewards = &[_]StoredReward{} });
    }
    // range [100,110] ascending = {100,103,105,110}
    const r = try store.getBlocksInRange(100, 110, 1000);
    defer a.free(r);
    try testing.expectEqualSlices(u64, &[_]u64{ 100, 103, 105, 110 }, r);
    // limit applies after sort
    const r2 = try store.getBlocksInRange(0, 1_000_000, 2);
    defer a.free(r2);
    try testing.expectEqualSlices(u64, &[_]u64{ 99, 100 }, r2);
    // purge below 105 drops {99,100,103}
    try testing.expectEqual(@as(usize, 3), store.purgeBelow(105));
    try testing.expectEqual(@as(usize, 3), store.count()); // {105,110,250}
    try testing.expect(store.hasBlock(105) and store.hasBlock(250) and !store.hasBlock(100));
}
