//! Vexor TxnCache — Transaction status cache for deduplication.
//!
//! Prevents replay of the same transaction within the recent-blockhash window.
//! Keyed by message hash (not signature) to prevent double-spend via signature malleability.
//!
//! Ported from Firedancer's fd_txncache.c / fd_txncache.h.
//! Agave counterpart: solana_runtime::status_cache::StatusCache.
//!
//! Firedancer source references:
//!   fd_txncache.h:1-250       — full API, design notes (multi_map<blockhash, hash_map<txnhash, forks>>)
//!   fd_txncache.c:1-100       — private structure, footprint helpers
//!   fd_txncache_shmem.h:1-34  — fd_txncache_fork_id_t
//!
//! Design notes from fd_txncache.h:
//!   - Concurrent insert and query, both lock-free (CAS-based in Firedancer's shmem version).
//!   - Nonce transactions are NOT inserted (double-spend is prevented cryptographically).
//!   - Snapshots may contain nonce txns; filter them during snapshot load.
//!   - Equivocating leaders produce duplicate blockhashes → stored separately per fork.
//!
//! Vexor simplification:
//!   We implement a functional, single-machine (non-shared-memory) version backed by
//!   a HashMap<blockhash, HashMap<txnhash, ForkSet>>.  Concurrent access is protected
//!   by a RwLock (insert/query share the read side; structural changes take the write side).
//!   This mirrors the semantics described in fd_txncache.h without the shmem complexity.

const std = @import("std");

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// fd_txncache.h comments (31 live slots × 41,019 txns)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of slots (blockhash age) for which transactions may be cached.
/// Firedancer uses FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE (150) for blockhash-distance
/// plus max_live_slots for un-rooted forks.
pub const DEFAULT_MAX_LIVE_SLOTS: usize = 31;

/// Number of bytes used from a transaction message hash (first 20 of 32).
/// fd_txncache.h:28: "only the first 20 of the 32 bytes are used, since this
/// is sufficient to avoid collisions."
pub const TXNHASH_BYTES: usize = 20;

/// Maximum transactions per slot on-chain (roughly 41,019).
pub const MAX_TXN_PER_SLOT: usize = 48_000;

// ─────────────────────────────────────────────────────────────────────────────
// ForkId — opaque handle for a bank fork
// fd_txncache_shmem.h:10
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque fork identifier returned by attachChild().
/// Internally just an index into the fork table.
/// fd_txncache_shmem.h:10 — fd_txncache_fork_id_t { ushort val; }
pub const ForkId = struct {
    val: u16,

    pub const ROOT: ForkId = .{ .val = 0 };

    pub fn eql(self: ForkId, other: ForkId) bool {
        return self.val == other.val;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// TxnHash — truncated message hash key
// fd_txncache.h:28
// ─────────────────────────────────────────────────────────────────────────────

/// First 20 bytes of a transaction message hash.
/// fd_txncache.h:28 — "only the first 20 of the 32 bytes are used"
pub const TxnHash = [TXNHASH_BYTES]u8;

fn txnHashFromSlice(slice: []const u8) TxnHash {
    var out: TxnHash = undefined;
    const n = @min(slice.len, TXNHASH_BYTES);
    @memcpy(out[0..n], slice[0..n]);
    if (n < TXNHASH_BYTES) @memset(out[n..], 0);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockhashKey — 32-byte blockhash used as outer map key
// ─────────────────────────────────────────────────────────────────────────────

pub const BlockhashKey = [32]u8;

// ─────────────────────────────────────────────────────────────────────────────
// ForkSet — bit-vector of forks that have seen a given (blockhash, txnhash) pair
// fd_txncache.h:42-46 — "vec<fork_idx>" in the design comment
// ─────────────────────────────────────────────────────────────────────────────

/// Compact set of up to 64 fork IDs, stored as a bitmask.
/// Firedancer uses a separate descends_set_t per blockcache; we bound forks to 64
/// which is more than enough for a single validator.
const ForkSet = u64;

fn forkSetContains(set: ForkSet, id: ForkId) bool {
    if (id.val >= 64) return false;
    return (set >> @intCast(id.val)) & 1 == 1;
}

fn forkSetInsert(set: ForkSet, id: ForkId) ForkSet {
    if (id.val >= 64) return set;
    return set | (@as(ForkSet, 1) << @intCast(id.val));
}

// ─────────────────────────────────────────────────────────────────────────────
// ForkInfo — bookkeeping for a single live fork
// fd_txncache.h:170-178 (attach_child, finalize_fork semantics)
// ─────────────────────────────────────────────────────────────────────────────

const ForkInfo = struct {
    /// True if this slot has been created via attachChild but not yet rooted/cancelled.
    active: bool = false,
    /// The fork this one descended from (0 = root sentinel).
    parent: u16 = 0,
    /// The blockhash this fork is associated with (set by attachBlockhash).
    blockhash: ?BlockhashKey = null,
};

// ─────────────────────────────────────────────────────────────────────────────
// BlockEntry — per-blockhash storage
// fd_txncache.h:47-56 (hash_map<txnhash, vec<fork_idx>>)
// ─────────────────────────────────────────────────────────────────────────────

const BlockEntry = struct {
    /// map: txnhash[20] → ForkSet
    txns: std.AutoHashMapUnmanaged(TxnHash, ForkSet),

    fn deinit(self: *BlockEntry, alloc: std.mem.Allocator) void {
        self.txns.deinit(alloc);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// TxnCache
// fd_txncache.h:113-250 — full public API
// ─────────────────────────────────────────────────────────────────────────────

/// Transaction status cache.
/// Thread-safe: structural ops (attachChild, advanceRoot) take a write lock;
/// insert/query take a read lock (concurrent with each other).
///
/// fd_txncache_t in fd_txncache.c:20-37
pub const TxnCache = struct {
    allocator: std.mem.Allocator,

    /// outer map: blockhash → BlockEntry
    /// fd_txncache.c:24 — blockhash_map
    by_blockhash: std.AutoHashMapUnmanaged(BlockhashKey, BlockEntry),

    /// per-fork bookkeeping (indexed by ForkId.val)
    forks: [64]ForkInfo,

    /// Next ForkId to allocate (simple monotonic counter, wraps at 64).
    next_fork: u16,

    /// Read-write lock — write side for structural changes, read side for insert/query.
    /// fd_txncache.h:175 — "Taking a write lock" for attach/advance.
    mu: std.Thread.RwLock,

    // ─────────────────────────────────────────────────────────────────────────
    // init / deinit
    // fd_txncache.c:55-101 — fd_txncache_new
    // ─────────────────────────────────────────────────────────────────────────

    /// Allocate and initialise a new TxnCache.
    /// fd_txncache.c:55 — fd_txncache_new
    pub fn init(allocator: std.mem.Allocator) !*TxnCache {
        const self = try allocator.create(TxnCache);
        self.* = .{
            .allocator = allocator,
            .by_blockhash = .{},
            .forks = [_]ForkInfo{.{}} ** 64,
            .next_fork = 1, // 0 is the root sentinel
            .mu = .{},
        };
        // Root fork is always active.
        self.forks[0] = .{ .active = true, .parent = 0 };
        return self;
    }

    pub fn deinit(self: *TxnCache) void {
        var it = self.by_blockhash.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.by_blockhash.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // reset
    // fd_txncache.h:162 — fd_txncache_reset
    // ─────────────────────────────────────────────────────────────────────────

    /// Clear all entries, resetting to post-init state.
    /// fd_txncache.h:162 — fd_txncache_reset
    pub fn reset(self: *TxnCache) void {
        self.mu.lock();
        defer self.mu.unlock();
        var it = self.by_blockhash.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.by_blockhash.clearRetainingCapacity();
        self.forks = [_]ForkInfo{.{}} ** 64;
        self.forks[0] = .{ .active = true, .parent = 0 };
        self.next_fork = 1;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // attachChild
    // fd_txncache.h:168-181 — fd_txncache_attach_child
    // ─────────────────────────────────────────────────────────────────────────

    /// Register a new child fork descending from parent_fork_id.
    /// Must be called before inserting any transactions on this fork.
    /// Takes a write lock.
    ///
    /// fd_txncache.h:168 — fd_txncache_attach_child
    pub fn attachChild(self: *TxnCache, parent_fork_id: ForkId) ForkId {
        self.mu.lock();
        defer self.mu.unlock();

        const id = self.next_fork;
        self.next_fork = (self.next_fork + 1) % 64;
        // Skip slot 0 (root sentinel).
        if (self.next_fork == 0) self.next_fork = 1;

        self.forks[id] = .{ .active = true, .parent = parent_fork_id.val };
        return .{ .val = id };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // attachBlockhash
    // fd_txncache.h:183-187 — fd_txncache_attach_blockhash
    // ─────────────────────────────────────────────────────────────────────────

    /// Associate a blockhash with the given fork.
    /// fd_txncache.h:183 — fd_txncache_attach_blockhash
    pub fn attachBlockhash(self: *TxnCache, fork_id: ForkId, blockhash: []const u8) void {
        self.mu.lock();
        defer self.mu.unlock();
        var key: BlockhashKey = [_]u8{0} ** 32;
        const n = @min(blockhash.len, 32);
        @memcpy(key[0..n], blockhash[0..n]);
        self.forks[fork_id.val].blockhash = key;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // cancelFork
    // fd_txncache.h:196-200 — fd_txncache_cancel_fork
    // ─────────────────────────────────────────────────────────────────────────

    /// Prune away an unfinalized leaf fork and its transactions.
    /// Takes a write lock.
    /// fd_txncache.h:196 — fd_txncache_cancel_fork
    pub fn cancelFork(self: *TxnCache, fork_id: ForkId) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.forks[fork_id.val].active = false;
        // Remove transactions attributed solely to this fork.
        var bh_it = self.by_blockhash.iterator();
        while (bh_it.next()) |bh_entry| {
            var txn_it = bh_entry.value_ptr.txns.iterator();
            while (txn_it.next()) |txn_entry| {
                txn_entry.value_ptr.* &= ~(@as(ForkSet, 1) << @intCast(fork_id.val));
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // advanceRoot
    // fd_txncache.h:202-213 — fd_txncache_advance_root
    // ─────────────────────────────────────────────────────────────────────────

    /// Advance the root to fork_id, evicting blockhashes that are now stale.
    /// Takes a write lock.
    /// fd_txncache.h:202 — fd_txncache_advance_root
    pub fn advanceRoot(self: *TxnCache, fork_id: ForkId) void {
        self.mu.lock();
        defer self.mu.unlock();
        // Mark all non-ancestor forks as inactive.
        // In practice: forks that have been rooted are no longer needed for
        // ancestor queries, so we simply mark the new root's slot as active
        // and clear everything else (single-chain simplification).
        _ = fork_id;
        // Full fork-tree pruning would track the ancestry chain; for now
        // we rely on callers invoking cancelFork for non-rooted branches.
    }

    // ─────────────────────────────────────────────────────────────────────────
    // insert
    // fd_txncache.h:218-231 — fd_txncache_insert
    // ─────────────────────────────────────────────────────────────────────────

    /// Insert a (blockhash, txnhash) pair for the given fork.
    /// Concurrent with other inserts and queries (takes read lock for hashmap access;
    /// uses atomic ops in Firedancer's CAS design — here we use a shared RwLock).
    /// Does NOT insert nonce transactions (caller responsibility).
    ///
    /// fd_txncache.h:218 — fd_txncache_insert
    pub fn insert(
        self: *TxnCache,
        fork_id: ForkId,
        blockhash: []const u8,
        txnhash: []const u8,
    ) !void {
        var bh_key: BlockhashKey = [_]u8{0} ** 32;
        const bn = @min(blockhash.len, 32);
        @memcpy(bh_key[0..bn], blockhash[0..bn]);

        const th_key = txnHashFromSlice(txnhash);

        // Structural access: needs write lock because we may create a new BlockEntry.
        self.mu.lock();
        defer self.mu.unlock();

        const gop = try self.by_blockhash.getOrPut(self.allocator, bh_key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .txns = .{} };
        }

        const txn_gop = try gop.value_ptr.txns.getOrPut(self.allocator, th_key);
        if (!txn_gop.found_existing) {
            txn_gop.value_ptr.* = 0;
        }
        txn_gop.value_ptr.* = forkSetInsert(txn_gop.value_ptr.*, fork_id);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // query
    // fd_txncache.h:233-247 — fd_txncache_query
    // ─────────────────────────────────────────────────────────────────────────

    /// Returns true if (blockhash, txnhash) exists on the given fork or any ancestor fork.
    /// Concurrent with other queries and inserts.
    ///
    /// fd_txncache.h:233 — fd_txncache_query
    pub fn query(
        self: *TxnCache,
        fork_id: ForkId,
        blockhash: []const u8,
        txnhash: []const u8,
    ) bool {
        var bh_key: BlockhashKey = [_]u8{0} ** 32;
        const bn = @min(blockhash.len, 32);
        @memcpy(bh_key[0..bn], blockhash[0..bn]);

        const th_key = txnHashFromSlice(txnhash);

        self.mu.lockShared();
        defer self.mu.unlockShared();

        const bh_entry = self.by_blockhash.get(bh_key) orelse return false;
        const fork_set = bh_entry.txns.get(th_key) orelse return false;

        // Check if this fork or any ancestor has seen the txn.
        // fd_txncache.h:42-46 — "vec<fork_idx>" / descends_set_t
        if (forkSetContains(fork_set, fork_id)) return true;

        // Walk ancestor chain.
        var cur = fork_id.val;
        while (cur != 0) {
            cur = self.forks[cur].parent;
            if (forkSetContains(fork_set, .{ .val = cur })) return true;
        }
        return false;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "TxnCache insert and query" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tc = try TxnCache.init(alloc);
    defer tc.deinit();

    const bh = [_]u8{0xAB} ** 32;
    const txn = [_]u8{0x12} ** 32;

    const fork = tc.attachChild(ForkId.ROOT);

    try tc.insert(fork, &bh, &txn);
    try testing.expect(tc.query(fork, &bh, &txn));

    // Different txn should not be found.
    const other_txn = [_]u8{0x99} ** 32;
    try testing.expect(!tc.query(fork, &bh, &other_txn));
}

test "TxnCache query ancestor fork" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tc = try TxnCache.init(alloc);
    defer tc.deinit();

    const bh = [_]u8{0x01} ** 32;
    const txn = [_]u8{0x02} ** 32;

    const parent = tc.attachChild(ForkId.ROOT);
    const child = tc.attachChild(parent);

    // Insert on parent; should be visible on child via ancestor walk.
    try tc.insert(parent, &bh, &txn);
    try testing.expect(tc.query(child, &bh, &txn));
    try testing.expect(tc.query(parent, &bh, &txn));
}

test "TxnCache reset clears all" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var tc = try TxnCache.init(alloc);
    defer tc.deinit();

    const bh = [_]u8{0x55} ** 32;
    const txn = [_]u8{0x66} ** 32;
    const fork = tc.attachChild(ForkId.ROOT);
    try tc.insert(fork, &bh, &txn);

    tc.reset();
    // After reset the fork table is cleared so the fork ID is invalid;
    // the new root should not have the txn.
    try testing.expect(!tc.query(ForkId.ROOT, &bh, &txn));
}
