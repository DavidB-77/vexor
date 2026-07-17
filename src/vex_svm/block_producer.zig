//! Vexor Block Producer
//!
//! Produces blocks when we are the scheduled leader.
//!
//! Pipeline:
//! 1. Start PoH recorder at slot boundary
//! 2. Pull transactions from banking stage queue
//! 3. Execute transactions in batches
//! 4. Record entries with transactions (mix sigs into PoH)
//! 5. Record ticks for empty time
//! 6. Generate shreds and broadcast via turbine

const std = @import("std");
const types = @import("types.zig");
const Hash = types.Hash;
const Pubkey = types.Pubkey;

/// Block production configuration
pub const ProducerConfig = struct {
    /// Maximum transactions per entry
    max_transactions_per_entry: usize = 64,
    /// Ticks per slot (Solana mainnet/testnet = 64)
    ticks_per_slot: u64 = 64,
    /// Hashes per tick. DEFAULT = effective TESTNET value 62500 (task #28). The genesis value is
    /// 12500 but it was raised to 62500 by the long-activated update_hashes_per_tick feature; Agave
    /// 4.x carries it forward in the snapshot. Production MUST override this from the snapshot
    /// manifest (parallel_snapshot.snapshot_hashes_per_tick) when wiring the producer — different
    /// clusters/genesis carry different values. Hardcoding 12500 here produced 5x-wrong PoH.
    hashes_per_tick: u64 = 62500,
    /// Maximum CU per block — testnet block limit (SIMD-0256 active, re-verified 2026-06-13 via RPC;
    /// SIMD-0286/100M INACTIVE). Was a stale 48M guess. See cost_tracker.zig for the full model.
    max_block_cu: u64 = 60_000_000,
    /// Shred streaming interval (ms) — flush entries to shreds at this cadence
    stream_interval_ms: i64 = 50,
};

/// Entry produced for the block
pub const ProducedEntry = struct {
    /// Number of PoH hashes since previous entry
    num_hashes: u64,
    /// PoH hash after mixing
    hash: [32]u8,
    /// Raw transaction bytes for this entry (serialized wire format)
    /// Empty slice = tick entry (no transactions)
    tx_data: []const u8,
    /// Number of transactions in this entry
    tx_count: u64,
};

/// Block being produced
pub const ProducingBlock = struct {
    allocator: std.mem.Allocator,
    slot: u64,
    parent_slot: u64,

    /// Current PoH hash — continuously hashed forward
    poh_hash: [32]u8,
    /// Hashes since last recorded entry
    hashes_since_entry: u64,

    /// Entries produced so far
    entries: std.ArrayListUnmanaged(ProducedEntry),

    /// Current tick count (64 ticks = slot complete)
    tick_count: u64,
    /// Compute units consumed this block
    cu_used: u64,

    /// Start time for elapsed tracking
    start_time_ns: i128,

    pub fn init(allocator: std.mem.Allocator, slot: u64, parent_slot: u64, start_hash: [32]u8) ProducingBlock {
        return .{
            .allocator = allocator,
            .slot = slot,
            .parent_slot = parent_slot,
            .poh_hash = start_hash,
            .hashes_since_entry = 0,
            .entries = .{},
            .tick_count = 0,
            .cu_used = 0,
            .start_time_ns = std.time.nanoTimestamp(),
        };
    }

    pub fn deinit(self: *ProducingBlock) void {
        for (self.entries.items) |entry| {
            if (entry.tx_data.len > 0) {
                self.allocator.free(entry.tx_data);
            }
        }
        self.entries.deinit(self.allocator);
    }

    /// Hash forward once (PoH tick)
    pub fn hashOnce(self: *ProducingBlock) void {
        std.crypto.hash.sha2.Sha256.hash(&self.poh_hash, &self.poh_hash, .{});
        self.hashes_since_entry += 1;
    }

    /// Record a tick (empty entry — no transactions)
    pub fn recordTick(self: *ProducingBlock) !void {
        try self.entries.append(self.allocator, .{
            .num_hashes = self.hashes_since_entry,
            .hash = self.poh_hash,
            .tx_data = &[_]u8{},
            .tx_count = 0,
        });
        self.hashes_since_entry = 0;
        self.tick_count += 1;
    }

    /// Record an entry with transaction data mixed into PoH.
    /// tx_sigs: signature bytes for each tx (64 bytes each) — mixed into PoH chain.
    /// tx_data: serialized transaction bytes to include in the entry.
    pub fn recordEntry(self: *ProducingBlock, tx_sigs: []const [64]u8, tx_data: []const u8, tx_count: u64) !void {
        // Mix each transaction signature into PoH
        for (tx_sigs) |sig| {
            var combined: [96]u8 = undefined;
            @memcpy(combined[0..32], &self.poh_hash);
            @memcpy(combined[32..96], &sig);
            std.crypto.hash.sha2.Sha256.hash(&combined, &self.poh_hash, .{});
        }

        // Deep copy tx_data
        const owned_data = try self.allocator.alloc(u8, tx_data.len);
        @memcpy(owned_data, tx_data);

        try self.entries.append(self.allocator, .{
            .num_hashes = self.hashes_since_entry,
            .hash = self.poh_hash,
            .tx_data = owned_data,
            .tx_count = tx_count,
        });
        self.hashes_since_entry = 0;
    }

    /// Check if slot is complete (all ticks recorded)
    pub fn isComplete(self: *const ProducingBlock, ticks_per_slot: u64) bool {
        return self.tick_count >= ticks_per_slot;
    }

    /// Elapsed time since startSlot in ms
    pub fn elapsedMs(self: *const ProducingBlock) i64 {
        const now = std.time.nanoTimestamp();
        return @intCast(@divTrunc(now - self.start_time_ns, 1_000_000));
    }
};

/// Block producer — manages the leader-mode pipeline
pub const BlockProducer = struct {
    allocator: std.mem.Allocator,
    config: ProducerConfig,

    /// Our identity pubkey
    identity: [32]u8,

    /// Current block being produced (null when not leader)
    current_block: ?ProducingBlock,

    /// Transaction receive queue (lock-free from TPU → producer)
    tx_queue: std.ArrayListUnmanaged([]const u8),
    tx_queue_lock: std.Thread.Mutex,

    /// Callback for broadcasting shreds
    broadcast_fn: ?*const fn (shreds: []const []const u8) void,

    /// Entries already sent to shredder
    entries_shredded: usize,

    /// Last shred broadcast time
    last_broadcast_ns: i128,

    /// Statistics
    stats: Stats,

    pub const Stats = struct {
        slots_started: u64 = 0,
        blocks_produced: u64 = 0,
        entries_produced: u64 = 0,
        shreds_produced: u64 = 0,
        txs_received: u64 = 0,
        txs_included: u64 = 0,
        txs_failed: u64 = 0,
        ticks_produced: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, identity: [32]u8, config: ProducerConfig) BlockProducer {
        return .{
            .allocator = allocator,
            .config = config,
            .identity = identity,
            .current_block = null,
            .tx_queue = .{},
            .tx_queue_lock = .{},
            .broadcast_fn = null,
            .entries_shredded = 0,
            .last_broadcast_ns = 0,
            .stats = .{},
        };
    }

    pub fn deinit(self: *BlockProducer) void {
        if (self.current_block) |*block| block.deinit();
        for (self.tx_queue.items) |tx| self.allocator.free(tx);
        self.tx_queue.deinit(self.allocator);
    }

    /// Set broadcast callback (wired from turbine)
    pub fn setBroadcastFn(self: *BlockProducer, f: *const fn (shreds: []const []const u8) void) void {
        self.broadcast_fn = f;
    }

    /// Start producing a block for a leader slot
    pub fn startSlot(self: *BlockProducer, slot: u64, parent_slot: u64, start_hash: [32]u8) void {
        // Clean up previous block
        if (self.current_block) |*block| block.deinit();

        self.current_block = ProducingBlock.init(self.allocator, slot, parent_slot, start_hash);
        self.entries_shredded = 0;
        self.last_broadcast_ns = std.time.nanoTimestamp();
        self.stats.slots_started += 1;

        std.log.debug("[LEADER] Started producing slot {d}\n", .{slot});
    }

    /// Submit a raw transaction (wire bytes) for inclusion
    pub fn submitTransaction(self: *BlockProducer, tx_bytes: []const u8) !void {
        self.tx_queue_lock.lock();
        defer self.tx_queue_lock.unlock();

        const copy = try self.allocator.alloc(u8, tx_bytes.len);
        @memcpy(copy, tx_bytes);
        try self.tx_queue.append(self.allocator, copy);
        self.stats.txs_received += 1;
    }

    /// Process pending transactions — execute on bank, record entries.
    /// Called in a loop during leader mode.
    pub fn processPending(self: *BlockProducer) !void {
        const block = &(self.current_block orelse return);
        _ = block;

        // Drain tx queue
        self.tx_queue_lock.lock();
        const pending = self.tx_queue.items;
        // Move ownership — reset queue without freeing items
        const owned = try self.allocator.alloc([]const u8, pending.len);
        @memcpy(owned, pending);
        self.tx_queue.items.len = 0;
        self.tx_queue_lock.unlock();

        defer {
            for (owned) |tx| self.allocator.free(tx);
            self.allocator.free(owned);
        }

        if (owned.len == 0) return;

        // TODO: Execute transactions on bank, collect successful ones
        // For now, we record them as-is (need bank.processTransaction wiring)
        // This will be wired when banking stage is connected

        self.stats.txs_included += owned.len;
    }

    /// Advance PoH by one tick. Returns true if the slot is now complete.
    pub fn tick(self: *BlockProducer) !bool {
        const block = &(self.current_block orelse return false);

        // Hash forward hashes_per_tick times
        for (0..self.config.hashes_per_tick) |_| {
            block.hashOnce();
        }

        // Record tick entry
        try block.recordTick();
        self.stats.ticks_produced += 1;

        // Check if slot is complete
        if (block.isComplete(self.config.ticks_per_slot)) {
            try self.finishSlot();
            return true;
        }

        return false;
    }

    /// Finish the current slot — freeze bank, generate final shreds
    fn finishSlot(self: *BlockProducer) !void {
        const block = &(self.current_block orelse return);

        self.stats.blocks_produced += 1;
        self.stats.entries_produced += block.entries.items.len;

        std.log.debug("[LEADER] Finished slot {d}: {d} entries, {d} ticks, {d}ms\n", .{
            block.slot,
            block.entries.items.len,
            block.tick_count,
            block.elapsedMs(),
        });

        // TODO: Generate shreds from entries and broadcast
        // Will wire to shredder.zig when available
    }

    /// Check if currently producing a block
    pub fn isProducing(self: *const BlockProducer) bool {
        return self.current_block != null;
    }

    /// Get current producing slot
    pub fn currentSlot(self: *const BlockProducer) ?u64 {
        if (self.current_block) |block| return block.slot;
        return null;
    }
};
