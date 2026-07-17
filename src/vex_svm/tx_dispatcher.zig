//! DAG Transaction Dispatcher — fd_rdisp port for Vexor (single-lane)
//!
//! This file implements the core data structures for a dependency-tracking
//! DAG scheduler, ported from Firedancer's fd_rdisp.c.  See the design spec:
//!   vault/sessions/2026-04-14-fd-rdisp-port-design.md
//!
//! ## Conceptual Overview
//!
//! Solana blocks must *appear* to execute transactions in serial order (the
//! "serial fiction"), but two transactions that touch disjoint accounts can
//! execute in any order or in parallel.  Two transactions conflict when one
//! writes to an account the other reads or writes.
//!
//! The dispatcher builds a DAG of per-account conflict chains.  Each account
//! has a "last reference" pointer.  When a new transaction references an
//! account, it is linked as a successor of the previous reference.  A
//! transaction's in_degree is the number of predecessor edges that have not
//! yet completed.  When in_degree reaches zero the transaction is READY and
//! is pushed onto the min-heap priority queue.
//!
//! ## Simplifications vs. fd_rdisp
//!
//! Vexor replays one fork at a time — we do not need:
//!   • multi-lane (4-lane) staging
//!   • promote/demote block (no fork management)
//!   • EMA scoring (use FIFO / barrier ordering instead)
//!   • ZOMBIE state (no async post-execution tasks)
//!   • free_acct_map / EMA cache
//!
//! ## Phase Plan
//!
//!   Phase 1 (this file): Data structures — TxnNode, AcctInfo, ReadyQueue,
//!                         TxnDispatcher, edge helpers, init/deinit.
//!   Phase 2: addEdges / addTxn / getNextReady / completeTxn logic.
//!   Phase 3: Multi-threaded execution with atomic in_degree.
//!
//! References:
//!   firedancer/src/discof/replay/fd_rdisp.c (1484 lines)
//!   firedancer/src/discof/replay/fd_rdisp.h

const std = @import("std");

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of account references a single transaction may have.
/// Matches Firedancer's MAX_ACCT_PER_TXN (fd_rdisp.c line 74).
pub const MAX_ACCT_PER_TXN: usize = 128;

// ─────────────────────────────────────────────────────────────────────────────
// Edge bit-packing
// ─────────────────────────────────────────────────────────────────────────────

/// An outgoing edge in the per-account conflict DAG.
///
/// The bit layout (identical to Firedancer's edge_t) is:
///
///   High bit SET   → IS_LAST: this transaction is the last referencing the
///                    account.  Lower 31 bits = AcctInfo pool index.
///
///   High bit CLEAR → NOT last: bits [30:8] = target txn_idx (23 bits),
///                               bits  [7:0] = target acct_idx (8 bits).
///
/// For read references each account slot uses THREE consecutive edge entries:
///   [0] child edge (same as a write edge — the forward dependency)
///   [1] next sibling (circular linked list)
///   [2] prev sibling (circular linked list)
///
/// For write references only ONE edge entry is used.
pub const Edge = u32;

/// Bit-packing helpers for Edge values.
pub const EdgeHelper = struct {
    /// IS_LAST sentinel bit.
    pub const LAST_BIT: Edge = 0x8000_0000;

    /// Returns true when e is the "last" sentinel — this transaction is the
    /// last node in this account's DAG.
    pub inline fn isLast(e: Edge) bool {
        return (e & LAST_BIT) != 0;
    }

    /// Extracts the AcctInfo pool index from a LAST edge.
    /// Caller must ensure isLast(e) is true.
    pub inline fn acctPoolIdx(e: Edge) u32 {
        return e & 0x7FFF_FFFF;
    }

    /// Extracts the target transaction index from a non-LAST edge (bits [30:8]).
    pub inline fn targetTxnIdx(e: Edge) u32 {
        return e >> 8;
    }

    /// Extracts the account index within the target transaction (bits [7:0]).
    pub inline fn targetAcctIdx(e: Edge) u8 {
        return @truncate(e & 0xFF);
    }

    /// Constructs an edge that points to a specific (txn_idx, acct_idx) pair.
    /// txn_idx must fit in 23 bits; acct_idx in 8 bits.
    pub inline fn make(txn_idx: u32, acct_idx: u8) Edge {
        return (txn_idx << 8) | @as(u32, acct_idx);
    }

    /// Constructs a LAST sentinel edge storing an AcctInfo pool index.
    pub inline fn makeLast(acct_pool_idx: u32) Edge {
        return LAST_BIT | acct_pool_idx;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// TxnNode
// ─────────────────────────────────────────────────────────────────────────────

/// A transaction as a node in the per-account conflict DAG.
/// Mirrors fd_rdisp_txn_t from fd_rdisp.c (lines 111-171).
///
/// Pool index 0 is a SENTINEL — it is never a real transaction but its edge
/// slots are written by addEdges() as a dummy parent for the "first reference
/// to this account" case.  Do NOT omit sentinel edge storage.
pub const TxnNode = struct {
    /// Number of predecessor edges (across all account DAGs) that have not
    /// yet completed.  Zero means READY.  Special sentinel values below.
    ///
    /// Life-cycle:
    ///   FREE       → addTxn() → PENDING (in_degree > 0) or READY (in_degree = 0)
    ///   READY      → getNextReady() → DISPATCHED
    ///   DISPATCHED → completeTxn()  → FREE
    in_degree: u32,

    /// Scheduling priority.  Integer part = number of serialization-point
    /// transactions that must complete before this one can be scheduled
    /// (from the "serializing" flag in fd_rdisp_add_txn).  We use u32
    /// instead of a float EMA — FIFO within the same barrier level.
    ///
    /// Lower score = schedule sooner.
    score: u32,

    /// Number of writable account references in this transaction.
    /// Write edges occupy one slot in edges[].
    write_count: u8,

    /// Number of read-only account references in this transaction.
    /// Read edges occupy three consecutive slots in edges[].
    read_count: u8,

    /// Block-local insertion sequence number.  Used by the priority queue
    /// to break ties between transactions at the same barrier level (FIFO).
    block_seq: u16,

    /// Per-account outgoing edges (same layout as Firedancer).
    ///
    /// Index layout:
    ///   writes: edges[0 .. write_count]           (1 slot per write)
    ///   reads:  edges[write_count .. write_count + 3*read_count]
    ///                                              (3 slots per read: child, next, prev)
    ///
    /// Maximum used: write_count + 3 * read_count ≤ 3 * MAX_ACCT_PER_TXN
    edges: [3 * MAX_ACCT_PER_TXN]Edge,

    // ── Special in_degree sentinel values ────────────────────────────────────

    /// This slot is free (not currently tracking a transaction).
    pub const IN_DEGREE_FREE: u32 = std.math.maxInt(u32);

    /// This transaction has been popped from the ready queue and is currently
    /// executing (or waiting for a worker).
    pub const IN_DEGREE_DISPATCHED: u32 = std.math.maxInt(u32) - 1;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Returns the edge array index for account index `acct_idx`.
    /// Write accounts: one slot, index = acct_idx.
    /// Read accounts:  three slots, first index = write_count + 3*(acct_idx-write_count).
    ///
    /// Caller passes the acct_idx in [0, write_count+read_count).
    pub fn edgeIdx(self: *const TxnNode, acct_idx: u32) u32 {
        const wc: u32 = self.write_count;
        if (acct_idx < wc) {
            return acct_idx;
        } else {
            return wc + 3 * (acct_idx - wc);
        }
    }

    /// Zero-initialises the node as FREE.  Called during pool init.
    pub fn initFree(self: *TxnNode) void {
        self.in_degree = IN_DEGREE_FREE;
        // Other fields are undefined until the node is acquired.
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// AcctInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Per-account metadata for the conflict DAG.
/// Mirrors acct_info_t from fd_rdisp.c (lines 262-322), simplified for
/// single-lane (no per-lane last_reference[4] array, no EMA fields).
pub const AcctInfo = struct {
    /// Account pubkey (raw 32 bytes — avoids Pubkey type-mismatch pitfalls).
    key: [32]u8,

    /// Edge pointing to the last transaction node that references this account
    /// in the current DAG.  Zero means no current reference.
    ///
    /// EDGE_IS_LAST(last_reference) is always true when last_reference != 0.
    last_reference: Edge,

    /// Per-account DAG state flags.  Two bits (single lane variant):
    ///   LAST_REF_WAS_WRITE (bit 0): the most recent reference was a write.
    ///   ANY_WRITERS        (bit 1): at least one writer exists in the current DAG.
    ///
    /// These flags determine which of the 4 add_edges cases applies and
    /// whether in_degree should be incremented for read-read chains.
    flags: u8,

    /// Intrusive hash-map chain pointer (next index in chain, 0 = end).
    /// Used by AcctMap for open-addressing or chained collision resolution.
    map_next: u32,

    // ── Flag constants ────────────────────────────────────────────────────────

    /// The last reference to this account was a write.
    pub const FLAG_LAST_REF_WAS_WRITE: u8 = 1 << 0;

    /// There is at least one writer in the current DAG referencing this account.
    pub const FLAG_ANY_WRITERS: u8 = 1 << 1;

    // ── Helpers ───────────────────────────────────────────────────────────────

    pub inline fn lastRefWasWrite(self: *const AcctInfo) bool {
        return (self.flags & FLAG_LAST_REF_WAS_WRITE) != 0;
    }

    pub inline fn anyWriters(self: *const AcctInfo) bool {
        return (self.flags & FLAG_ANY_WRITERS) != 0;
    }

    pub fn initFree(self: *AcctInfo) void {
        self.key = std.mem.zeroes([32]u8);
        self.last_reference = 0;
        self.flags = 0;
        self.map_next = 0;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// AcctMap — open-addressing hash map for account info
// ─────────────────────────────────────────────────────────────────────────────

/// Maps a 32-byte account pubkey to an AcctInfo pool index.
///
/// Implemented as a std.AutoHashMapUnmanaged([32]u8, u32) for simplicity.
/// The pool index is into TxnDispatcher.acct_pool.
/// Pool index 0 is a sentinel; valid indices start at 1.
pub const AcctMap = std.AutoHashMapUnmanaged([32]u8, u32);

// ─────────────────────────────────────────────────────────────────────────────
// ReadyEntry / ReadyQueue
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the READY priority queue.
/// Mirrors pending_prq_ele_t from fd_rdisp.c (lines 345-362), simplified:
///   • No float score / EMA — use u32 barrier_threshold + block_seq for FIFO.
///   • No linear_block_number — single-block context; block_seq gives order.
pub const ReadyEntry = struct {
    /// Transactions cannot be dispatched until dispatcher.completed_count
    /// reaches this value.  Equal to the serialisation-point count at the
    /// time this transaction was inserted.  Lower = sooner.
    barrier_threshold: u32,

    /// Block-local insertion sequence number (FIFO tie-breaking within same
    /// barrier_threshold level).
    block_seq: u16,

    /// Index of this transaction in TxnDispatcher.pool.
    txn_idx: u32,
};

/// Comparator for the ready queue: minimum barrier_threshold first,
/// then minimum block_seq (FIFO).
fn readyEntryLessThan(_: void, a: ReadyEntry, b: ReadyEntry) std.math.Order {
    if (a.barrier_threshold != b.barrier_threshold) {
        return std.math.order(a.barrier_threshold, b.barrier_threshold);
    }
    return std.math.order(a.block_seq, b.block_seq);
}

/// Min-heap priority queue for READY transactions.
/// Pop returns the entry with the lowest barrier_threshold (and block_seq
/// as a tiebreaker).
///
/// getNextReady() must also check:
///   entry.barrier_threshold <= dispatcher.completed_count
/// to enforce serialisation barriers — transactions whose predecessors
/// have not yet completed must stay in the queue even if in_degree == 0.
pub const ReadyQueue = std.PriorityQueue(ReadyEntry, void, readyEntryLessThan);

// ─────────────────────────────────────────────────────────────────────────────
// ParsedTxn — stub for transaction data stored alongside each pool slot
// ─────────────────────────────────────────────────────────────────────────────

/// Wire-format transaction data stored in the dispatcher's tx_store[] array.
/// Indexed by txn_idx (same as pool).  Workers read this to execute the
/// transaction without the dispatcher needing to retain a pointer.
///
/// This is a stub for Phase 1 (data-structures only).  Replay integration
/// will fill in the fields in Phase 2.
pub const ParsedTxn = struct {
    /// Pointer into the entry wire bytes (NOT owned — points into entry buffer).
    /// Length is wire_len bytes.
    wire_ptr: ?[*]const u8 = null,
    wire_len: u32 = 0,

    /// Account key list (ordered: writables first, then read-onlys).
    /// Indices match the order passed to addTxn().
    account_keys: [MAX_ACCT_PER_TXN][32]u8 = undefined,

    /// Writability flags parallel to account_keys.
    account_writable: [MAX_ACCT_PER_TXN]bool = undefined,

    /// Number of valid entries in account_keys / account_writable.
    account_count: u8 = 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// TxnDispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// The main DAG transaction dispatcher.
/// Mirrors fd_rdisp_t from fd_rdisp.c (lines 457-480), single-lane variant.
///
/// ## Memory layout
///
///   pool[0]       — sentinel (never used as a real transaction; edge slots
///                   are written by addEdges() as a dummy parent)
///   pool[1..depth] — transaction nodes, managed as a free list
///
///   acct_pool[0]       — sentinel
///   acct_pool[1..acct_depth] — AcctInfo objects; managed by acct_map
///
///   tx_store[0..depth] — ParsedTxn parallel array (indexed by txn_idx)
///
/// ## Usage (Phase 1, single-threaded)
///
///   var d = try TxnDispatcher.init(allocator, depth);
///   defer d.deinit();
///
///   d.beginBlock();
///   for each tx in entry:
///       const idx = try d.addTxn(acct_keys, acct_writable);
///       d.tx_store[idx] = parsed_tx;
///   while (d.completed_count < d.inserted_count):
///       if d.getNextReady() |idx|:
///           execute(d.tx_store[idx])
///           d.completeTxn(idx)
///   d.endBlock();
pub const TxnDispatcher = struct {
    allocator: std.mem.Allocator,

    // ── Transaction pool ──────────────────────────────────────────────────────

    /// Pre-allocated transaction node pool, size = depth + 1.
    /// pool[0] is the sentinel.  pool[1..] are managed as a singly-linked
    /// free list: when free, pool[i].edges[0] stores the next free index
    /// (or FREE_LIST_END when it is the tail).
    pool: []TxnNode,

    /// Head of the free list in pool (index into pool[]).
    /// FREE_LIST_END when the pool is exhausted.
    free_head: u32,

    /// Maximum concurrent transactions (pool capacity - 1, excluding sentinel).
    depth: u32,

    // ── Account info ──────────────────────────────────────────────────────────

    /// Hash map from pubkey to AcctInfo pool index.
    /// Only accounts currently referenced by at least one in-flight transaction
    /// appear in this map.
    acct_map: AcctMap,

    /// Pre-allocated AcctInfo pool, size = depth * MAX_ACCT_PER_TXN + 1.
    /// Index 0 is a sentinel.  Free entries are chained via acct_info.map_next.
    acct_pool: []AcctInfo,

    /// Head of the free AcctInfo list (index into acct_pool[]).
    free_acct_head: u32,

    /// Number of free AcctInfo slots remaining.
    /// Maintained by acctAcquire/acctRelease for O(1) capacity checks.
    free_acct_count: u32,

    // ── Ready queue ───────────────────────────────────────────────────────────

    /// Min-heap of transactions in the READY state ordered by
    /// (barrier_threshold, block_seq).
    ready_queue: ReadyQueue,

    // ── Block-level counters ──────────────────────────────────────────────────

    /// Total transactions inserted into the current block.
    inserted_count: u32,

    /// Total transactions that have been popped from the ready queue and are
    /// currently in the DISPATCHED state (or completed).
    dispatched_count: u32,

    /// Total transactions that have completed (completeTxn() called).
    /// Used to gate serialisation barriers.
    completed_count: u32,

    /// Serialisation barrier level: the last seen serializing transaction's
    /// block_seq value.  All transactions inserted after a serializing tx
    /// get barrier_threshold = last_serializing + 1, meaning they cannot
    /// be dispatched until that serializing tx has completed.
    last_serializing: u32,

    // ── Parsed transaction store ──────────────────────────────────────────────

    /// Parallel array to pool.  tx_store[txn_idx] holds the parsed transaction
    /// data that workers need to execute the transaction.
    /// Indexed by txn_idx (same as pool).  Size = depth + 1.
    tx_store: []ParsedTxn,

    // ── Sentinel values ───────────────────────────────────────────────────────

    const FREE_LIST_END: u32 = 0;

    // ── init / deinit ─────────────────────────────────────────────────────────

    /// Allocate and initialise the dispatcher for at most `depth` concurrent
    /// transactions.
    ///
    /// Pool size:      depth + 1  (slot 0 = sentinel)
    /// AcctInfo size:  depth * MAX_ACCT_PER_TXN + 1  (slot 0 = sentinel)
    /// tx_store size:  depth + 1
    pub fn init(allocator: std.mem.Allocator, depth: u32) !TxnDispatcher {
        const pool_size: usize = @as(usize, depth) + 1;
        const acct_depth: usize = @as(usize, depth) * MAX_ACCT_PER_TXN;
        const acct_pool_size: usize = acct_depth + 1;

        // Allocate pools
        const pool = try allocator.alloc(TxnNode, pool_size);
        errdefer allocator.free(pool);

        const acct_pool = try allocator.alloc(AcctInfo, acct_pool_size);
        errdefer allocator.free(acct_pool);

        const tx_store = try allocator.alloc(ParsedTxn, pool_size);
        errdefer allocator.free(tx_store);

        // Initialise sentinel slots (index 0)
        pool[0].initFree();
        // Sentinel in_degree must be FREE so we never accidentally dispatch it.
        pool[0].in_degree = TxnNode.IN_DEGREE_FREE;
        // Zero the sentinel's edges — addEdges() uses pool[0].edges[0..2] as a
        // dummy parent when inserting the first reference for an account.
        @memset(&pool[0].edges, 0);
        // Sentinel must have valid write_count/read_count for followEdge().
        pool[0].write_count = 0;
        pool[0].read_count = 0;

        acct_pool[0].initFree();

        // Build transaction free list: pool[1] → pool[2] → … → pool[depth]
        for (1..pool_size) |i| {
            pool[i].initFree();
            // Link to next; last entry points to FREE_LIST_END (0 = sentinel,
            // we repurpose its absence as end-of-list sentinel).
            const next: u32 = if (i + 1 < pool_size) @intCast(i + 1) else FREE_LIST_END;
            pool[i].edges[0] = next;
        }

        // Build AcctInfo free list: acct_pool[1] → … → acct_pool[acct_depth]
        for (1..acct_pool_size) |i| {
            acct_pool[i].initFree();
            const next: u32 = if (i + 1 < acct_pool_size) @intCast(i + 1) else FREE_LIST_END;
            acct_pool[i].map_next = next;
        }

        // Zero tx_store
        @memset(tx_store, std.mem.zeroes(ParsedTxn));

        // Pre-allocate ready queue to avoid allocation failures during dispatch.
        var ready_queue = ReadyQueue.init(allocator, {});
        try ready_queue.ensureTotalCapacity(@intCast(pool_size));

        return TxnDispatcher{
            .allocator = allocator,
            .pool = pool,
            .free_head = if (depth > 0) 1 else FREE_LIST_END,
            .depth = depth,
            .acct_map = AcctMap{},
            .acct_pool = acct_pool,
            .free_acct_head = if (acct_depth > 0) 1 else FREE_LIST_END,
            .free_acct_count = @intCast(acct_depth),
            .ready_queue = ready_queue,
            .inserted_count = 0,
            .dispatched_count = 0,
            .completed_count = 0,
            .last_serializing = 0,
            .tx_store = tx_store,
        };
    }

    /// Free all memory owned by the dispatcher.
    pub fn deinit(self: *TxnDispatcher) void {
        self.ready_queue.deinit();
        self.acct_map.deinit(self.allocator);
        self.allocator.free(self.tx_store);
        self.allocator.free(self.acct_pool);
        self.allocator.free(self.pool);
    }

    // ── Pool helpers ──────────────────────────────────────────────────────────

    /// Acquire a free TxnNode from the pool.  Returns 0 on failure (pool full).
    /// The returned index is valid in pool[].
    pub fn poolAcquire(self: *TxnDispatcher) u32 {
        const idx = self.free_head;
        if (idx == FREE_LIST_END) return 0; // pool exhausted
        // Advance free list head using the embedded next pointer in edges[0].
        self.free_head = self.pool[idx].edges[0];
        return idx;
    }

    /// Release a TxnNode back to the free pool.
    /// idx must be a valid non-sentinel pool index previously acquired.
    pub fn poolRelease(self: *TxnDispatcher, idx: u32) void {
        std.debug.assert(idx != 0);
        std.debug.assert(idx < self.pool.len);
        self.pool[idx].in_degree = TxnNode.IN_DEGREE_FREE;
        self.pool[idx].edges[0] = self.free_head;
        self.free_head = idx;
    }

    /// Acquire a free AcctInfo slot from the acct_pool.  Returns 0 on failure.
    pub fn acctAcquire(self: *TxnDispatcher) u32 {
        const idx = self.free_acct_head;
        if (idx == FREE_LIST_END) return 0;
        self.free_acct_head = self.acct_pool[idx].map_next;
        self.acct_pool[idx].map_next = 0;
        self.free_acct_count -= 1;
        return idx;
    }

    /// Release an AcctInfo slot back to the free pool.
    pub fn acctRelease(self: *TxnDispatcher, idx: u32) void {
        std.debug.assert(idx != 0);
        std.debug.assert(idx < self.acct_pool.len);
        self.acct_pool[idx].initFree();
        self.acct_pool[idx].map_next = self.free_acct_head;
        self.free_acct_head = idx;
        self.free_acct_count += 1;
    }

    /// Return number of free transaction pool slots (O(n), diagnostic only).
    pub fn countFreePool(self: *const TxnDispatcher) u32 {
        var count: u32 = 0;
        var idx = self.free_head;
        while (idx != FREE_LIST_END) {
            count += 1;
            idx = self.pool[idx].edges[0];
        }
        return count;
    }

    // ── Block lifecycle ───────────────────────────────────────────────────────

    /// Reset all block-level counters before processing a new block's entries.
    /// Call once per block (or per entry batch if using entry-level granularity).
    /// Does NOT clear account map — account references persist until completeTxn.
    pub fn beginBlock(self: *TxnDispatcher) void {
        self.inserted_count = 0;
        self.dispatched_count = 0;
        self.completed_count = 0;
        self.last_serializing = 0;
    }

    /// Assert that the block is fully drained then reset state.
    /// All transactions must have been completed before calling this.
    pub fn endBlock(self: *TxnDispatcher) void {
        std.debug.assert(self.completed_count == self.inserted_count);
        std.debug.assert(self.acct_map.count() == 0);
        std.debug.assert(self.ready_queue.count() == 0);
        self.beginBlock();
    }

    /// Drain all in-flight transactions without executing them.
    /// Used when abandoning a block mid-flight (e.g. on fork switch).
    pub fn abandonBlock(self: *TxnDispatcher) void {
        // Release all non-sentinel pool slots that are not FREE.
        for (1..self.pool.len) |i| {
            const node = &self.pool[i];
            if (node.in_degree != TxnNode.IN_DEGREE_FREE) {
                self.poolRelease(@intCast(i));
            }
        }
        // Clear account map — remove all entries and release acct_pool slots.
        var it = self.acct_map.keyIterator();
        while (it.next()) |key| {
            if (self.acct_map.get(key.*)) |acct_idx| {
                self.acctRelease(acct_idx);
            }
        }
        self.acct_map.clearRetainingCapacity();
        // Drain the ready queue.
        while (self.ready_queue.removeOrNull()) |_| {}
        // Reset counters.
        self.beginBlock();
    }

    // ── Core DAG logic (Phase 2) ─────────────────────────────────────────────

    pub const DispatchError = error{
        PoolExhausted,
        AcctPoolExhausted,
        OutOfMemory,
    };

    /// Result of followEdge: locates the edge slot in the target transaction.
    const FollowEdgeResult = struct {
        txn_idx: u32,
        edge_idx: u32,
        is_writer: bool,
    };

    /// Follows an edge value to locate the target transaction's edge slot.
    /// Equivalent to Firedancer's FOLLOW_EDGE macro (fd_rdisp.c lines 202-209).
    ///
    /// Given an edge encoding (txn_idx << 8 | acct_idx), returns the pool index,
    /// the physical edge index within that transaction's edges[], and whether
    /// the target account is writable.
    fn followEdge(self: *const TxnDispatcher, e: Edge) FollowEdgeResult {
        const txn_idx: u32 = e >> 8;
        const acct_idx: u32 = e & 0xFF;
        const txn = &self.pool[txn_idx];
        const w_cnt: u32 = txn.write_count;
        const is_writer = acct_idx < w_cnt;
        // edge_idx = acct_idx + 2 * max(0, acct_idx - w_cnt)
        const offset: u32 = if (acct_idx >= w_cnt) acct_idx - w_cnt else 0;
        const edge_idx: u32 = acct_idx + 2 * offset;
        return .{
            .txn_idx = txn_idx,
            .edge_idx = edge_idx,
            .is_writer = is_writer,
        };
    }

    /// Look up or create an AcctInfo entry for the given account key.
    /// Returns the acct_pool index. On creation, the AcctInfo is initialized
    /// with zeroed state and inserted into acct_map.
    fn getOrCreateAcct(self: *TxnDispatcher, key: *const [32]u8) DispatchError!u32 {
        const gop = self.acct_map.getOrPut(self.allocator, key.*) catch return error.OutOfMemory;
        if (gop.found_existing) {
            return gop.value_ptr.*;
        }
        // Allocate a new AcctInfo slot
        const idx = self.acctAcquire();
        if (idx == FREE_LIST_END) {
            _ = self.acct_map.remove(key.*);
            return error.AcctPoolExhausted;
        }
        const ai = &self.acct_pool[idx];
        ai.key = key.*;
        ai.last_reference = 0;
        ai.flags = 0;
        ai.map_next = 0;
        gop.value_ptr.* = idx;
        return idx;
    }

    /// The 4-case edge addition logic, ported from fd_rdisp.c lines 927-1084.
    ///
    /// Called once for writable accounts, then once for readonly accounts.
    /// MUST call writable accounts first (edge layout depends on write_count).
    ///
    /// Parameters:
    ///   node      - the transaction node being added
    ///   txn_idx   - pool index of the transaction node
    ///   addrs     - account keys to process
    ///   writable  - true if these accounts are writable
    fn addEdges(
        self: *TxnDispatcher,
        node: *TxnNode,
        txn_idx: u32,
        addrs: []const [32]u8,
        writable: bool,
    ) DispatchError!void {
        // Current logical account index and physical edge index
        var acct_idx: u32 = @as(u32, node.write_count) + @as(u32, node.read_count);
        var edge_idx: u32 = @as(u32, node.write_count) + @as(u32, 3) * @as(u32, node.read_count);

        for (addrs) |*addr| {
            // Step 1: Look up or create AcctInfo
            const acct_pool_idx = try self.getOrCreateAcct(addr);
            const ai = &self.acct_pool[acct_pool_idx];

            // Step 2: Compute edge values
            const ref_to_me: Edge = (txn_idx << 8) | @as(u32, acct_idx & 0xFF);
            const ref_to_pa: Edge = ai.last_reference;

            // Follow the previous last reference to get parent's edge location
            const pa = self.followEdge(ref_to_pa);
            // me is at edge_idx in the current node

            // Step 3: Set up sentinel for this iteration (pool[0] edges)
            // fd_rdisp.c lines 1023-1025
            self.pool[0].edges[0] = EdgeHelper.LAST_BIT | acct_pool_idx;
            self.pool[0].edges[1] = if (writable) 0 else ref_to_me;
            self.pool[0].edges[2] = if (writable) 0 else ref_to_me;

            // Copy flags to local (match C pattern: line 1027)
            var flags: u8 = ai.flags;

            if (writable) {
                if ((flags & AcctInfo.FLAG_LAST_REF_WAS_WRITE) != 0) {
                    // Case 1: W-W
                    // me inherits IS_LAST from parent; parent points to me
                    node.edges[edge_idx] = self.pool[pa.txn_idx].edges[pa.edge_idx];
                    self.pool[pa.txn_idx].edges[pa.edge_idx] = ref_to_me;
                } else {
                    // Case 2: R-W
                    // me inherits IS_LAST from parent; parent points to me
                    node.edges[edge_idx] = self.pool[pa.txn_idx].edges[pa.edge_idx];
                    self.pool[pa.txn_idx].edges[pa.edge_idx] = ref_to_me;

                    // Traverse sibling chain, skip first (handled by general increment)
                    const pa_next_sibling = self.pool[pa.txn_idx].edges[pa.edge_idx + 1];
                    var pb = self.followEdge(pa_next_sibling);
                    while (pb.txn_idx != pa.txn_idx or pb.edge_idx != pa.edge_idx) {
                        self.pool[pb.txn_idx].edges[pb.edge_idx] = ref_to_me;
                        node.in_degree += 1;
                        const next_sib = self.pool[pb.txn_idx].edges[pb.edge_idx + 1];
                        pb = self.followEdge(next_sib);
                    }
                    flags |= AcctInfo.FLAG_LAST_REF_WAS_WRITE | AcctInfo.FLAG_ANY_WRITERS;
                }
            } else {
                if ((flags & AcctInfo.FLAG_LAST_REF_WAS_WRITE) != 0) {
                    // Case 3: W-R
                    // me inherits IS_LAST from parent; parent points to me
                    node.edges[edge_idx] = self.pool[pa.txn_idx].edges[pa.edge_idx];
                    self.pool[pa.txn_idx].edges[pa.edge_idx] = ref_to_me;
                    // Initialize circular list of 1 (next = prev = self)
                    node.edges[edge_idx + 1] = ref_to_me;
                    node.edges[edge_idx + 2] = ref_to_me;
                    flags &= ~AcctInfo.FLAG_LAST_REF_WAS_WRITE;
                } else {
                    // Case 4: R-R
                    // me inherits child edge from parent (all readers share same child)
                    node.edges[edge_idx] = self.pool[pa.txn_idx].edges[pa.edge_idx];
                    // prev->next->prev = me
                    const pa_next = self.pool[pa.txn_idx].edges[pa.edge_idx + 1];
                    const pnn = self.followEdge(pa_next);
                    self.pool[pnn.txn_idx].edges[pnn.edge_idx + 2] = ref_to_me;
                    // me->next = prev->next (old head)
                    node.edges[edge_idx + 1] = pa_next;
                    // me->prev = prev
                    node.edges[edge_idx + 2] = ref_to_pa;
                    // prev->next = me
                    self.pool[pa.txn_idx].edges[pa.edge_idx + 1] = ref_to_me;
                }
            }

            // Step 4: General in_degree increment (fd_rdisp.c line 1077)
            // Adds 1 if: there was a prior reference AND there are any writers
            const had_prior: u32 = if (ai.last_reference != 0) 1 else 0;
            const has_writers: u32 = if ((flags & AcctInfo.FLAG_ANY_WRITERS) != 0) 1 else 0;
            node.in_degree += had_prior & has_writers;

            // Step 5: Update AcctInfo (fd_rdisp.c lines 1078-1079)
            ai.last_reference = ref_to_me;
            ai.flags = flags;

            // Advance indices
            if (writable) {
                edge_idx += 1;
                node.write_count += 1;
            } else {
                edge_idx += 3;
                node.read_count += 1;
            }
            acct_idx += 1;
        }
    }

    /// Add a transaction to the DAG.
    ///
    /// The caller provides parallel arrays of account keys and writability flags.
    /// Writable accounts MUST come before readonly accounts in the arrays.
    ///
    /// Returns the txn_idx (pool index) for the transaction.
    /// Returns error.PoolExhausted if the transaction pool is full.
    pub fn addTxn(
        self: *TxnDispatcher,
        accounts: []const [32]u8,
        writability: []const bool,
    ) DispatchError!u32 {
        std.debug.assert(accounts.len == writability.len);
        std.debug.assert(accounts.len <= MAX_ACCT_PER_TXN);

        // Verify writable-first ordering: all writables before all readonlys
        if (std.debug.runtime_safety) {
            var seen_readonly = false;
            for (writability) |w| {
                if (!w) seen_readonly = true;
                if (w and seen_readonly) {
                    @panic("addTxn: writable accounts must come before readonly accounts");
                }
            }
        }

        // Acquire a free slot from the pool
        const txn_idx = self.poolAcquire();
        if (txn_idx == FREE_LIST_END) return error.PoolExhausted;

        // Pre-validate acct pool capacity BEFORE touching DAG state.
        var new_accts_needed: u32 = 0;
        for (accounts) |*key| {
            if (self.acct_map.get(key.*) == null) {
                new_accts_needed += 1;
            }
        }
        if (new_accts_needed > self.free_acct_count) {
            self.poolRelease(txn_idx);
            return error.AcctPoolExhausted;
        }
        self.acct_map.ensureUnusedCapacity(self.allocator, new_accts_needed) catch {
            self.poolRelease(txn_idx);
            return error.OutOfMemory;
        };

        const node = &self.pool[txn_idx];

        // Initialize node
        node.in_degree = 0;
        node.score = 0;
        node.write_count = 0;
        node.read_count = 0;
        node.block_seq = @truncate(self.inserted_count & 0xFFFF);

        // Count writable accounts
        var write_end: usize = 0;
        for (writability) |w| {
            if (w) write_end += 1 else break;
        }

        // Add writable accounts first (MANDATORY ordering for edge layout)
        if (write_end > 0) {
            try self.addEdges(node, txn_idx, accounts[0..write_end], true);
        }

        // Then readonly accounts
        if (write_end < accounts.len) {
            try self.addEdges(node, txn_idx, accounts[write_end..], false);
        }

        // Serialization barrier logic (fd_rdisp.c lines 1179-1183)
        // For simplicity, we don't support serializing transactions in Phase 2.
        // All transactions get barrier_threshold = last_serializing.
        node.score = self.last_serializing;

        self.inserted_count += 1;

        // If no dependencies, push to ready queue immediately
        if (node.in_degree == 0) {
            self.ready_queue.add(.{
                .barrier_threshold = node.score,
                .block_seq = node.block_seq,
                .txn_idx = txn_idx,
            }) catch return error.OutOfMemory;
        }

        return txn_idx;
    }

    /// Pop the next ready transaction from the priority queue.
    ///
    /// Returns the txn_idx of the transaction to execute, or null if no
    /// transaction is ready (either the queue is empty or the head is
    /// blocked by a serialization barrier).
    ///
    /// The returned transaction is marked DISPATCHED. The caller must
    /// eventually call completeTxn(txn_idx) when execution finishes.
    pub fn getNextReady(self: *TxnDispatcher) ?u32 {
        // Peek at the head of the priority queue
        const entry = self.ready_queue.peek() orelse return null;

        // Check serialization barrier gate (fd_rdisp.c line 1210)
        // score >= completed_count + 1 means "not ready yet"
        if (entry.barrier_threshold > self.completed_count) return null;

        // Pop and dispatch
        _ = self.ready_queue.remove();
        const node = &self.pool[entry.txn_idx];
        node.in_degree = TxnNode.IN_DEGREE_DISPATCHED;
        self.dispatched_count += 1;
        return entry.txn_idx;
    }

    /// Complete a dispatched transaction: walk outgoing edges, decrement
    /// successors' in_degree, push newly-ready successors to the queue,
    /// and release the TxnNode back to the pool.
    ///
    /// Ported from fd_rdisp.c lines 1226-1404 (staged path only).
    pub fn completeTxn(self: *TxnDispatcher, txn_idx: u32) void {
        const node = &self.pool[txn_idx];
        std.debug.assert(node.in_degree == TxnNode.IN_DEGREE_DISPATCHED);

        const w_cnt: u32 = node.write_count;
        const r_cnt: u32 = node.read_count;
        var edge_idx: u32 = 0;

        for (0..@as(usize, w_cnt) + @as(usize, r_cnt)) |i| {
            const e0: Edge = node.edges[edge_idx];
            const ref_to_me: Edge = (txn_idx << 8) | @as(u32, @truncate(i));

            if (EdgeHelper.isLast(e0)) {
                // This transaction is the LAST in this account's DAG.
                const acct_pool_idx = EdgeHelper.acctPoolIdx(e0);
                const ai = &self.acct_pool[acct_pool_idx];

                if (i < w_cnt or node.edges[edge_idx + 1] == ref_to_me) {
                    // Writer, or sole remaining reader (next == self).
                    // Clear last_reference and all flags.
                    ai.last_reference = 0;
                    ai.flags &= ~(AcctInfo.FLAG_ANY_WRITERS | AcctInfo.FLAG_LAST_REF_WAS_WRITE);
                } else {
                    // Reader in a group — remove self from circular DLL.
                    const e1 = node.edges[edge_idx + 1]; // me->next
                    const e2 = node.edges[edge_idx + 2]; // me->prev
                    // me->next->prev = me->prev
                    const next_loc = self.followEdge(e1);
                    self.pool[next_loc.txn_idx].edges[next_loc.edge_idx + 2] = e2;
                    // me->prev->next = me->next
                    const prev_loc = self.followEdge(e2);
                    self.pool[prev_loc.txn_idx].edges[prev_loc.edge_idx + 1] = e1;
                    // If last_reference pointed to me, update to me->next
                    if (ai.last_reference == ref_to_me) {
                        ai.last_reference = e1;
                    }
                }

                // If no more references to this account, remove from map and free
                if (ai.last_reference == 0) {
                    _ = self.acct_map.remove(ai.key);
                    self.acctRelease(acct_pool_idx);
                }
            } else {
                // There is a successor. Decrement its in_degree.
                // For a writer completing with reader successors, traverse the sibling chain.
                var next_e: Edge = e0;
                var last_child_edge: Edge = undefined;

                while (true) {
                    const child = self.followEdge(next_e);
                    const child_txn = &self.pool[child.txn_idx];

                    // Read the child's own child edge (for loop termination and flag update)
                    last_child_edge = child_txn.edges[child.edge_idx];

                    std.debug.assert(child_txn.in_degree > 0);
                    std.debug.assert(child_txn.in_degree < TxnNode.IN_DEGREE_DISPATCHED);

                    child_txn.in_degree -= 1;
                    if (child_txn.in_degree == 0) {
                        // Child is now READY — push to priority queue
                        self.ready_queue.add(.{
                            .barrier_threshold = child_txn.score,
                            .block_seq = child_txn.block_seq,
                            .txn_idx = child.txn_idx,
                        }) catch unreachable; // pre-allocated in init()
                    }

                    // If child is a writer, or we've gone around the full sibling ring, stop.
                    if (child.is_writer) break;
                    // For readers: check if the next sibling loops back to the original edge
                    if (child_txn.edges[child.edge_idx + 1] == e0) break;
                    next_e = child_txn.edges[child.edge_idx + 1]; // advance to next sibling
                }

                // Update AcctInfo flags if the last child's own edge is IS_LAST
                // (fd_rdisp.c lines 1363-1378)
                // Sets ANY_WRITERS = LAST_REF_WAS_WRITE
                if (EdgeHelper.isLast(last_child_edge)) {
                    const child_acct_idx = EdgeHelper.acctPoolIdx(last_child_edge);
                    const ai = &self.acct_pool[child_acct_idx];
                    var flags: u8 = ai.flags;
                    flags &= ~AcctInfo.FLAG_ANY_WRITERS;
                    // ANY_WRITERS (bit 1) = LAST_REF_WAS_WRITE (bit 0) shifted left 1
                    flags |= (flags & AcctInfo.FLAG_LAST_REF_WAS_WRITE) << 1;
                    ai.flags = flags;
                }
            }

            edge_idx += if (i < w_cnt) 1 else 3;
        }

        // Bookkeeping
        self.completed_count += 1;

        // Release txn_idx back to pool
        self.poolRelease(txn_idx);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "TxnDispatcher: init and deinit" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();

    try std.testing.expectEqual(@as(u32, 64), d.depth);
    try std.testing.expectEqual(@as(u32, 0), d.inserted_count);
    try std.testing.expectEqual(@as(u32, 0), d.completed_count);
    // pool[0] is sentinel, free_head should point to first real slot
    try std.testing.expectEqual(@as(u32, 1), d.free_head);
    try std.testing.expectEqual(TxnNode.IN_DEGREE_FREE, d.pool[0].in_degree);
}

test "TxnDispatcher: pool acquire/release" {
    var d = try TxnDispatcher.init(std.testing.allocator, 4);
    defer d.deinit();

    const a = d.poolAcquire();
    const b = d.poolAcquire();
    try std.testing.expect(a != 0);
    try std.testing.expect(b != 0);
    try std.testing.expect(a != b);

    d.poolRelease(a);
    const a2 = d.poolAcquire();
    try std.testing.expectEqual(a, a2); // LIFO free list
}

test "TxnDispatcher: pool exhaustion returns 0" {
    var d = try TxnDispatcher.init(std.testing.allocator, 2);
    defer d.deinit();

    _ = d.poolAcquire();
    _ = d.poolAcquire();
    const should_be_zero = d.poolAcquire();
    try std.testing.expectEqual(@as(u32, 0), should_be_zero);
}

test "TxnDispatcher: acct acquire/release" {
    var d = try TxnDispatcher.init(std.testing.allocator, 4);
    defer d.deinit();

    const idx = d.acctAcquire();
    try std.testing.expect(idx != 0);
    d.acctRelease(idx);
    const idx2 = d.acctAcquire();
    try std.testing.expectEqual(idx, idx2);
}

test "TxnDispatcher: beginBlock/endBlock resets counters" {
    var d = try TxnDispatcher.init(std.testing.allocator, 4);
    defer d.deinit();

    d.inserted_count = 5;
    d.completed_count = 5;
    d.dispatched_count = 5;
    d.last_serializing = 3;

    d.endBlock();

    try std.testing.expectEqual(@as(u32, 0), d.inserted_count);
    try std.testing.expectEqual(@as(u32, 0), d.completed_count);
    try std.testing.expectEqual(@as(u32, 0), d.last_serializing);
}

test "Edge helpers: bit-packing round-trip" {
    const e = EdgeHelper.make(0x1F_FFFF, 0xFF);
    try std.testing.expect(!EdgeHelper.isLast(e));
    try std.testing.expectEqual(@as(u32, 0x1F_FFFF), EdgeHelper.targetTxnIdx(e));
    try std.testing.expectEqual(@as(u8, 0xFF), EdgeHelper.targetAcctIdx(e));

    const last = EdgeHelper.makeLast(0x7FFF_FFFF);
    try std.testing.expect(EdgeHelper.isLast(last));
    try std.testing.expectEqual(@as(u32, 0x7FFF_FFFF), EdgeHelper.acctPoolIdx(last));
}

test "ReadyQueue: min-heap ordering" {
    var q = ReadyQueue.init(std.testing.allocator, {});
    defer q.deinit();

    try q.add(.{ .barrier_threshold = 2, .block_seq = 0, .txn_idx = 10 });
    try q.add(.{ .barrier_threshold = 0, .block_seq = 1, .txn_idx = 20 });
    try q.add(.{ .barrier_threshold = 1, .block_seq = 0, .txn_idx = 30 });

    try std.testing.expectEqual(@as(u32, 20), q.remove().txn_idx); // barrier 0 first
    try std.testing.expectEqual(@as(u32, 30), q.remove().txn_idx); // barrier 1
    try std.testing.expectEqual(@as(u32, 10), q.remove().txn_idx); // barrier 2
}

test "ReadyQueue: FIFO within same barrier_threshold" {
    var q = ReadyQueue.init(std.testing.allocator, {});
    defer q.deinit();

    try q.add(.{ .barrier_threshold = 0, .block_seq = 3, .txn_idx = 1 });
    try q.add(.{ .barrier_threshold = 0, .block_seq = 1, .txn_idx = 2 });
    try q.add(.{ .barrier_threshold = 0, .block_seq = 2, .txn_idx = 3 });

    try std.testing.expectEqual(@as(u32, 2), q.remove().txn_idx); // block_seq 1 first
    try std.testing.expectEqual(@as(u32, 3), q.remove().txn_idx); // block_seq 2
    try std.testing.expectEqual(@as(u32, 1), q.remove().txn_idx); // block_seq 3
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 Tests: Core DAG Logic
// ─────────────────────────────────────────────────────────────────────────────

fn makeKey(seed: u8) [32]u8 {
    var k: [32]u8 = .{0} ** 32;
    k[0] = seed;
    return k;
}

test "addTxn: single write-only transaction is immediately ready" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const accounts = [_][32]u8{acctA};
    const writable = [_]bool{true};

    const idx = try d.addTxn(&accounts, &writable);
    try std.testing.expect(idx != 0);
    try std.testing.expectEqual(@as(u32, 1), d.inserted_count);

    // Should be ready immediately (no predecessors)
    const ready = d.getNextReady();
    try std.testing.expect(ready != null);
    try std.testing.expectEqual(idx, ready.?);

    // Complete it
    d.completeTxn(idx);
    try std.testing.expectEqual(@as(u32, 1), d.completed_count);
}

test "addTxn: W-W chain creates dependency" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const accounts = [_][32]u8{acctA};
    const writable = [_]bool{true};

    // Tx1 writes to A — should be ready immediately
    const tx1 = try d.addTxn(&accounts, &writable);
    const ready1 = d.getNextReady();
    try std.testing.expectEqual(tx1, ready1.?);

    // Tx2 writes to A — should NOT be ready (depends on tx1)
    const tx2 = try d.addTxn(&accounts, &writable);
    try std.testing.expectEqual(@as(u32, 1), d.pool[tx2].in_degree);

    // Nothing else ready
    try std.testing.expect(d.getNextReady() == null);

    // Complete tx1 — tx2 should become ready
    d.completeTxn(tx1);
    const ready2 = d.getNextReady();
    try std.testing.expectEqual(tx2, ready2.?);

    d.completeTxn(tx2);
    try std.testing.expectEqual(@as(u32, 2), d.completed_count);
}

test "addTxn: R-R no dependency (parallel readers)" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const accounts = [_][32]u8{acctA};
    const readonly = [_]bool{false};

    // Tx1 reads A — ready
    const tx1 = try d.addTxn(&accounts, &readonly);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx1].in_degree);

    // Tx2 reads A — also ready (no conflict with reader)
    const tx2 = try d.addTxn(&accounts, &readonly);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx2].in_degree);

    // Tx3 reads A — also ready
    const tx3 = try d.addTxn(&accounts, &readonly);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx3].in_degree);

    // All three should be ready
    const r1 = d.getNextReady().?;
    const r2 = d.getNextReady().?;
    const r3 = d.getNextReady().?;
    try std.testing.expect(d.getNextReady() == null);

    // Complete in any order
    d.completeTxn(r1);
    d.completeTxn(r2);
    d.completeTxn(r3);
    try std.testing.expectEqual(@as(u32, 3), d.completed_count);
}

test "addTxn: W-R chain (reader depends on writer)" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const w_accounts = [_][32]u8{acctA};
    const w_writable = [_]bool{true};
    const r_accounts = [_][32]u8{acctA};
    const r_readonly = [_]bool{false};

    // Tx1 writes A — ready
    const tx1 = try d.addTxn(&w_accounts, &w_writable);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx1].in_degree);

    // Tx2 reads A — depends on tx1
    const tx2 = try d.addTxn(&r_accounts, &r_readonly);
    try std.testing.expectEqual(@as(u32, 1), d.pool[tx2].in_degree);

    // Tx3 reads A — also depends on tx1 (Case 4 R-R after W, ANY_WRITERS set)
    const tx3 = try d.addTxn(&r_accounts, &r_readonly);
    try std.testing.expectEqual(@as(u32, 1), d.pool[tx3].in_degree);

    // Dispatch tx1
    _ = d.getNextReady();
    try std.testing.expect(d.getNextReady() == null);

    // Complete tx1 — both readers should become ready
    d.completeTxn(tx1);

    const r2 = d.getNextReady().?;
    const r3 = d.getNextReady().?;
    try std.testing.expect(d.getNextReady() == null);

    d.completeTxn(r2);
    d.completeTxn(r3);
    try std.testing.expectEqual(@as(u32, 3), d.completed_count);
}

test "addTxn: R-W chain (writer depends on all readers)" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const r_accounts = [_][32]u8{acctA};
    const r_readonly = [_]bool{false};
    const w_accounts = [_][32]u8{acctA};
    const w_writable = [_]bool{true};

    // Tx1 reads A — ready
    const tx1 = try d.addTxn(&r_accounts, &r_readonly);
    // Tx2 reads A — ready (R-R, no dependency)
    const tx2 = try d.addTxn(&r_accounts, &r_readonly);
    // Tx3 reads A — ready (R-R, no dependency)
    const tx3 = try d.addTxn(&r_accounts, &r_readonly);

    try std.testing.expectEqual(@as(u32, 0), d.pool[tx1].in_degree);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx2].in_degree);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx3].in_degree);

    // Tx4 writes A — depends on ALL 3 readers (Case 2: R-W)
    const tx4 = try d.addTxn(&w_accounts, &w_writable);
    try std.testing.expectEqual(@as(u32, 3), d.pool[tx4].in_degree);

    // Dispatch and complete all 3 readers
    _ = d.getNextReady();
    _ = d.getNextReady();
    _ = d.getNextReady();
    try std.testing.expect(d.getNextReady() == null); // tx4 blocked

    d.completeTxn(tx1);
    try std.testing.expect(d.getNextReady() == null); // still 2 deps

    d.completeTxn(tx2);
    try std.testing.expect(d.getNextReady() == null); // still 1 dep

    d.completeTxn(tx3);
    // Now tx4 should be ready
    const r4 = d.getNextReady().?;
    try std.testing.expectEqual(tx4, r4);

    d.completeTxn(tx4);
    try std.testing.expectEqual(@as(u32, 4), d.completed_count);
}

test "addTxn: disjoint accounts run in parallel" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const acctB = makeKey(2);
    const acc_a = [_][32]u8{acctA};
    const acc_b = [_][32]u8{acctB};
    const w = [_]bool{true};

    // Tx1 writes A — ready
    const tx1 = try d.addTxn(&acc_a, &w);
    // Tx2 writes B — ready (disjoint)
    const tx2 = try d.addTxn(&acc_b, &w);

    try std.testing.expectEqual(@as(u32, 0), d.pool[tx1].in_degree);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx2].in_degree);

    const r1 = d.getNextReady().?;
    const r2 = d.getNextReady().?;
    try std.testing.expect(d.getNextReady() == null);

    d.completeTxn(r1);
    d.completeTxn(r2);
    try std.testing.expectEqual(@as(u32, 2), d.completed_count);
}

test "addTxn: multi-account transaction creates multiple dependencies" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const acctB = makeKey(2);

    // Tx1 writes A
    const acc_a = [_][32]u8{acctA};
    const w1 = [_]bool{true};
    const tx1 = try d.addTxn(&acc_a, &w1);

    // Tx2 writes B
    const acc_b = [_][32]u8{acctB};
    const w2 = [_]bool{true};
    const tx2 = try d.addTxn(&acc_b, &w2);

    // Tx3 writes both A and B — depends on both tx1 (for A) and tx2 (for B)
    const acc_ab = [_][32]u8{ acctA, acctB };
    const w3 = [_]bool{ true, true };
    const tx3 = try d.addTxn(&acc_ab, &w3);
    try std.testing.expectEqual(@as(u32, 2), d.pool[tx3].in_degree);

    // Dispatch and complete tx1 and tx2
    _ = d.getNextReady();
    _ = d.getNextReady();
    try std.testing.expect(d.getNextReady() == null);

    d.completeTxn(tx1);
    try std.testing.expect(d.getNextReady() == null); // still 1 dep

    d.completeTxn(tx2);
    const r3 = d.getNextReady().?;
    try std.testing.expectEqual(tx3, r3);

    d.completeTxn(tx3);
    try std.testing.expectEqual(@as(u32, 3), d.completed_count);
}

test "addTxn: mixed read/write accounts" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const acctB = makeKey(2);

    // Tx1: writes A, reads B
    const acc1 = [_][32]u8{ acctA, acctB };
    const w1 = [_]bool{ true, false };
    const tx1 = try d.addTxn(&acc1, &w1);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx1].in_degree);

    // Tx2: reads A, writes B — depends on tx1 for both A (W-R) and B (R-W)
    const acc2 = [_][32]u8{ acctB, acctA };
    const w2 = [_]bool{ true, false };
    const tx2 = try d.addTxn(&acc2, &w2);
    try std.testing.expectEqual(@as(u32, 2), d.pool[tx2].in_degree);

    _ = d.getNextReady();
    try std.testing.expect(d.getNextReady() == null);

    d.completeTxn(tx1);
    const r2 = d.getNextReady().?;
    try std.testing.expectEqual(tx2, r2);

    d.completeTxn(tx2);
    try std.testing.expectEqual(@as(u32, 2), d.completed_count);
}

test "addTxn: W-R-W chain" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const acc = [_][32]u8{acctA};
    const w = [_]bool{true};
    const r = [_]bool{false};

    // Tx1: writes A (ready)
    const tx1 = try d.addTxn(&acc, &w);
    // Tx2: reads A (depends on tx1)
    const tx2 = try d.addTxn(&acc, &r);
    // Tx3: reads A (depends on tx1 via ANY_WRITERS)
    const tx3 = try d.addTxn(&acc, &r);
    // Tx4: writes A (depends on tx2 AND tx3 — R-W case)
    const tx4 = try d.addTxn(&acc, &w);

    try std.testing.expectEqual(@as(u32, 0), d.pool[tx1].in_degree);
    try std.testing.expectEqual(@as(u32, 1), d.pool[tx2].in_degree);
    try std.testing.expectEqual(@as(u32, 1), d.pool[tx3].in_degree);
    try std.testing.expectEqual(@as(u32, 2), d.pool[tx4].in_degree);

    // Dispatch and complete tx1
    _ = d.getNextReady();
    d.completeTxn(tx1);

    // tx2 and tx3 should both be ready now
    const r2 = d.getNextReady().?;
    const r3 = d.getNextReady().?;
    try std.testing.expect(d.getNextReady() == null);

    d.completeTxn(r2);
    try std.testing.expect(d.getNextReady() == null); // tx4 still has 1 dep

    d.completeTxn(r3);
    // tx4 should be ready now
    const r4 = d.getNextReady().?;
    try std.testing.expectEqual(tx4, r4);

    d.completeTxn(tx4);
    try std.testing.expectEqual(@as(u32, 4), d.completed_count);
}

test "addTxn: pool exhaustion returns error" {
    var d = try TxnDispatcher.init(std.testing.allocator, 2);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const acctB = makeKey(2);
    const acctC = makeKey(3);
    const w = [_]bool{true};

    _ = try d.addTxn(&[_][32]u8{acctA}, &w);
    _ = try d.addTxn(&[_][32]u8{acctB}, &w);

    // Third should fail — pool is full
    const result = d.addTxn(&[_][32]u8{acctC}, &w);
    try std.testing.expectError(TxnDispatcher.DispatchError.PoolExhausted, result);
}

test "completeTxn: reader removes self from sibling DLL when IS_LAST" {
    // Test the IS_LAST reader completion path: when a reader group is the
    // last in the DAG and one reader completes, it must unlink from the DLL.
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const acc = [_][32]u8{acctA};
    const r = [_]bool{false};

    // Three pure readers — no writers, so they are IS_LAST
    _ = try d.addTxn(&acc, &r);
    _ = try d.addTxn(&acc, &r);
    _ = try d.addTxn(&acc, &r);

    // All should be ready (pure R-R, no writers)
    const r1 = d.getNextReady().?;
    const r2 = d.getNextReady().?;
    const r3 = d.getNextReady().?;
    try std.testing.expect(d.getNextReady() == null);

    // Complete in order — each should unlink from DLL correctly
    d.completeTxn(r1);
    d.completeTxn(r2);
    d.completeTxn(r3);
    try std.testing.expectEqual(@as(u32, 3), d.completed_count);

    // Verify account was cleaned up
    try std.testing.expectEqual(@as(u32, 0), d.acct_map.count());
}

test "addTxn: full block lifecycle (begin, add, dispatch, complete, end)" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();

    d.beginBlock();

    const acctA = makeKey(1);
    const acctB = makeKey(2);
    const w = [_]bool{true};

    // Add two independent writes
    const tx1 = try d.addTxn(&[_][32]u8{acctA}, &w);
    const tx2 = try d.addTxn(&[_][32]u8{acctB}, &w);

    // Dispatch and complete both
    const r1 = d.getNextReady().?;
    const r2 = d.getNextReady().?;
    _ = r1;
    _ = r2;
    d.completeTxn(tx1);
    d.completeTxn(tx2);

    // End block should not panic (assertions pass)
    d.endBlock();
}

test "followEdge: correct edge index calculation" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();

    // Set up a node with 2 writers and 1 reader
    d.pool[1].write_count = 2;
    d.pool[1].read_count = 1;

    // Edge for (txn_idx=1, acct_idx=0) — first writer, edge_idx = 0
    const r0 = d.followEdge(EdgeHelper.make(1, 0));
    try std.testing.expectEqual(@as(u32, 1), r0.txn_idx);
    try std.testing.expectEqual(@as(u32, 0), r0.edge_idx);
    try std.testing.expect(r0.is_writer);

    // Edge for (txn_idx=1, acct_idx=1) — second writer, edge_idx = 1
    const r1 = d.followEdge(EdgeHelper.make(1, 1));
    try std.testing.expectEqual(@as(u32, 1), r1.edge_idx);
    try std.testing.expect(r1.is_writer);

    // Edge for (txn_idx=1, acct_idx=2) — first reader, edge_idx = 2 + 2*(2-2) = 2
    const r2 = d.followEdge(EdgeHelper.make(1, 2));
    try std.testing.expectEqual(@as(u32, 2), r2.edge_idx);
    try std.testing.expect(!r2.is_writer);
}

test "getNextReady: returns null when queue is empty" {
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    try std.testing.expect(d.getNextReady() == null);
}

test "completeTxn: ANY_WRITERS flag update on W-R-last completion" {
    // Test that completing a writer whose child is a reader group (the
    // last in the DAG) correctly updates ANY_WRITERS = LAST_REF_WAS_WRITE.
    var d = try TxnDispatcher.init(std.testing.allocator, 64);
    defer d.deinit();
    d.beginBlock();

    const acctA = makeKey(1);
    const w = [_]bool{true};
    const r = [_]bool{false};

    // Tx1: write A (ready)
    const tx1 = try d.addTxn(&[_][32]u8{acctA}, &w);
    // Tx2: read A (depends on tx1)
    const tx2 = try d.addTxn(&[_][32]u8{acctA}, &r);

    _ = d.getNextReady();
    d.completeTxn(tx1);

    // After completing the writer, the AcctInfo for A should have:
    // LAST_REF_WAS_WRITE = 0 (the child is a reader)
    // ANY_WRITERS = 0 (should be set to LAST_REF_WAS_WRITE = 0)
    // This means adding another reader now should NOT increment in_degree.
    const tx3 = try d.addTxn(&[_][32]u8{acctA}, &r);
    try std.testing.expectEqual(@as(u32, 0), d.pool[tx3].in_degree);

    // Clean up
    _ = d.getNextReady();
    _ = d.getNextReady();
    _ = d.getNextReady();
    d.completeTxn(tx2);
    d.completeTxn(tx3);
}
