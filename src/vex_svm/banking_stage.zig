//! Vexor Banking Stage
//!
//! Receives transactions from TPU, prioritizes by fee, and feeds
//! them to the block producer for inclusion during leader slots.
//!
//! Pipeline: TPU → SigVerify → Banking Stage → Block Producer → Shred → Turbine

const std = @import("std");
// NOTE: banking_stage is std-only — the former `types.zig`/`Pubkey` import was dead (Pubkey unused).
// Keeping it std-only lets banking_stage.zig be ONE dedicated module shared by vex_svm, block_produce,
// quic_ingest_adapter, and vex_network without `types.zig` being claimed by two modules (task #13).

/// Banking stage configuration
pub const BankingConfig = struct {
    /// Maximum transactions in queue before dropping
    max_queue_size: usize = 10_000,
    /// Batch size for processing
    batch_size: usize = 128,
    /// Enable priority fee sorting
    enable_priority_fees: bool = true,
};

/// Transaction in the queue
pub const QueuedTransaction = struct {
    /// Raw wire bytes
    data: []const u8,
    /// Priority score (higher = process first)
    priority: u64,
    /// Timestamp when received (ms)
    received_at: i64,
    /// Source of the transaction
    source: Source,

    pub const Source = enum {
        tpu,
        tpu_vote,
        gossip,
        rpc,
        forward,
    };

    /// Calculate priority from compute unit price.
    /// Higher CU price = higher priority. Votes always get max priority.
    pub fn calculatePriority(cu_price: u64, is_vote: bool) u64 {
        if (is_vote) return std.math.maxInt(u64);
        return cu_price *| 1000;
    }
};

/// Priority comparator — higher priority first, ties broken by arrival time
fn priorityCompare(_: void, a: QueuedTransaction, b: QueuedTransaction) std.math.Order {
    if (a.priority > b.priority) return .lt;
    if (a.priority < b.priority) return .gt;
    if (a.received_at < b.received_at) return .lt;
    if (a.received_at > b.received_at) return .gt;
    return .eq;
}

/// Banking stage — priority queue of transactions waiting for leader slot
pub const BankingStage = struct {
    allocator: std.mem.Allocator,
    config: BankingConfig,

    /// Priority-sorted transaction queue
    tx_queue: std.PriorityQueue(QueuedTransaction, void, priorityCompare),

    /// Separate vote queue (always processed first)
    vote_queue: std.PriorityQueue(QueuedTransaction, void, priorityCompare),

    /// Queue mutex
    lock: std.Thread.Mutex,

    /// Statistics
    stats: Stats,

    pub const Stats = struct {
        txs_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        txs_queued: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        txs_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        votes_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        batches_drained: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    pub fn init(allocator: std.mem.Allocator, config: BankingConfig) BankingStage {
        return .{
            .allocator = allocator,
            .config = config,
            .tx_queue = std.PriorityQueue(QueuedTransaction, void, priorityCompare).init(allocator, {}),
            .vote_queue = std.PriorityQueue(QueuedTransaction, void, priorityCompare).init(allocator, {}),
            .lock = .{},
            .stats = .{},
        };
    }

    pub fn deinit(self: *BankingStage) void {
        // Free all queued transaction data
        while (self.tx_queue.removeOrNull()) |qt| {
            self.allocator.free(qt.data);
        }
        while (self.vote_queue.removeOrNull()) |qt| {
            self.allocator.free(qt.data);
        }
        self.tx_queue.deinit();
        self.vote_queue.deinit();
    }

    /// Queue a transaction for inclusion in the next leader block.
    /// Takes ownership of tx_data (deep-copies internally).
    pub fn queueTransaction(
        self: *BankingStage,
        tx_data: []const u8,
        cu_price: u64,
        is_vote: bool,
        source: QueuedTransaction.Source,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

        const total = self.tx_queue.count() + self.vote_queue.count();
        if (total >= self.config.max_queue_size) {
            _ = self.stats.txs_dropped.fetchAdd(1, .monotonic);
            return error.QueueFull;
        }

        // Deep copy
        const copy = try self.allocator.alloc(u8, tx_data.len);
        @memcpy(copy, tx_data);

        const queued = QueuedTransaction{
            .data = copy,
            .priority = QueuedTransaction.calculatePriority(cu_price, is_vote),
            .received_at = std.time.milliTimestamp(),
            .source = source,
        };

        if (is_vote) {
            try self.vote_queue.add(queued);
            _ = self.stats.votes_received.fetchAdd(1, .monotonic);
        } else {
            try self.tx_queue.add(queued);
            _ = self.stats.txs_received.fetchAdd(1, .monotonic);
        }
        _ = self.stats.txs_queued.store(@intCast(total + 1), .monotonic);
    }

    /// Drain up to batch_size transactions from the queue (votes first).
    /// Returns owned slice — caller must free each .data and the slice.
    pub fn drainBatch(self: *BankingStage) ![]QueuedTransaction {
        self.lock.lock();
        defer self.lock.unlock();

        var batch = std.ArrayListUnmanaged(QueuedTransaction){};
        errdefer {
            for (batch.items) |qt| self.allocator.free(qt.data);
            batch.deinit(self.allocator);
        }

        // Drain votes first
        while (batch.items.len < self.config.batch_size) {
            const qt = self.vote_queue.removeOrNull() orelse break;
            try batch.append(self.allocator, qt);
        }

        // Then regular transactions
        while (batch.items.len < self.config.batch_size) {
            const qt = self.tx_queue.removeOrNull() orelse break;
            try batch.append(self.allocator, qt);
        }

        if (batch.items.len > 0) {
            _ = self.stats.batches_drained.fetchAdd(1, .monotonic);
        }

        return batch.toOwnedSlice(self.allocator);
    }

    /// Get current queue depth
    pub fn queueDepth(self: *BankingStage) usize {
        self.lock.lock();
        defer self.lock.unlock();
        return self.tx_queue.count() + self.vote_queue.count();
    }

    /// 2026-07-17 (M2b, produce-tile safe gating): NON-DESTRUCTIVE peek, up to
    /// `max` entries (vote_queue items first, then tx_queue items — mirrors
    /// `drainBatch`'s own ordering, though NOT necessarily the same subset:
    /// `.items` is heap-array order, not priority-sorted order; callers that
    /// need a superset of what `drainBatch` might actually drain should pass a
    /// `max` no smaller than `config.batch_size`). Calls `cb(ctx, tx_wire)`
    /// once per peeked entry WHILE `self.lock` IS HELD, and does not remove
    /// anything from either queue — `drainBatch` (above) remains the sole
    /// DESTRUCTIVE consumer (the produce tile's, unchanged by this addition).
    ///
    /// CALLER CONTRACT: `cb` must not retain `tx_wire` past the call — the
    /// bytes are queue-owned, and a concurrent `drainBatch` (on a different
    /// thread; the tile is the sole such caller today) could free them the
    /// instant `unlock()` returns. Copy anything needed into `cb`'s own VALUE
    /// outputs before returning. `cb` should also avoid acquiring any other
    /// lock — this method is called from the REPLAY thread (dispatching a
    /// become-leader record) and the lock here is meant to be held only for
    /// cheap, pure work (parsing a tx to extract a fee-payer pubkey / first
    /// signature), not for a nested lookup against a second lock (e.g.
    /// accounts_db) — do that AFTER this call returns.
    ///
    /// Kept intentionally std-only (no tx-parsing here) so this file stays the
    /// ONE BankingStage module shared by vex_svm, block_produce,
    /// quic_ingest_adapter, and vex_network (file banner) without pulling
    /// tx_ingest into all of them.
    pub fn peekEach(self: *BankingStage, max: usize, ctx: *anyopaque, cb: *const fn (ctx: *anyopaque, tx_wire: []const u8) void) void {
        self.lock.lock();
        defer self.lock.unlock();
        var n: usize = 0;
        for (self.vote_queue.items) |qt| {
            if (n >= max) return;
            cb(ctx, qt.data);
            n += 1;
        }
        for (self.tx_queue.items) |qt| {
            if (n >= max) return;
            cb(ctx, qt.data);
            n += 1;
        }
    }
};
