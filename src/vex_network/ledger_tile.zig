//! LedgerTile — moves VexLedger I/O off the consensus hot path.
//!
//! The four shred-completion sites (8 verify workers / AF_XDP insert / kernel-UDP
//! recv / repair, all on different threads) ENQUEUE shred + FINISH messages into a
//! bounded MPSC ring. Enqueue is NON-BLOCKING and DROPS on full — the ledger is
//! best-effort and must NEVER stall consensus (a dropped-into slot self-identifies
//! as a gap on offline replay; it just can't be re-replayed). A single dedicated
//! consumer tile, pinned to a cold core, drains the ring and performs
//! putShred/finishSlot — including the fsync — entirely off the consensus threads.
//!
//! Concurrency model: a mutex-guarded MPSC ring. The lock is held ONLY for a
//! ~1.3 KB memcpy (claim + copy a message in/out), never for the fsync — which is
//! the whole point of the tile. With four brief-holding producers + one consumer
//! the contention is negligible vs. the inline fsync it replaces. (A lock-free
//! Vyukov queue would shave the enqueue further, but correctness/auditability wins
//! here — the win is moving fsync off-thread, not enqueue latency.)
//!
//! Gated exactly as the inline path: comptime `-Dvex_ledger` + the `VEX_LEDGER`
//! env. When the tile is wired, the producer enqueues instead of writing inline;
//! the tile owns every VexLedger write. Dormant + byte-identical when off.

const std = @import("std");
const vex_ledger = @import("vex_ledger");
const VexLedger = vex_ledger.VexLedger;
const FinishBlob = vex_ledger.FinishBlob;
const SlotMeta = vex_ledger.SlotMeta;

pub const MSG_DATA: u8 = 0;
pub const MSG_CODE: u8 = 1;
pub const MSG_FINISH: u8 = 2;

/// Inline ring-slot payload bound. Must hold the largest shred wire (~1232 B) and
/// the largest FinishBlob (HEADER_LEN 69 + 4·num_completed). A FINISH that would
/// exceed this is dropped+logged at enqueue (never truncated) — see enqueueFinish.
/// 4096 holds (4096−69)/4 = 1006 completed-data indexes — covers realistic large
/// blocks (LEDG cross-review Q3). Pathological 32k-shred slots still drop, SAFELY:
/// the slot's shreds enqueue fine and offline replay RE-DERIVES SlotMeta from the
/// shreds (Boot-B proved bank-exact without stored SlotMeta) — only the stored
/// meta CF is absent for that big slot. The live FINISH sampler (enqueueFinish)
/// logs the real `completed_data_indexes.len` distribution so we can right-size.
pub const MAX_MSG: usize = 4096;

/// Default ring capacity (messages). One completed slot enqueues N_data_shreds + 1
/// messages; at 4 KB/slot of inline buffers this sizes the disk-hiccup window.
/// 8192 × 4096 B ≈ 32 MB, absorbing a multi-second stall across many slots.
pub const DEFAULT_CAPACITY: usize = 8192;

/// Parse a u64 env var; returns 0 when unset or unparseable (the disabled sentinel
/// for the prune knobs — `--limit-ledger-size` is opt-in).
fn parseEnvU64(name: []const u8) u64 {
    const v = std.posix.getenv(name) orelse return 0;
    return std.fmt.parseInt(u64, v, 10) catch 0;
}

const RingMsg = struct {
    kind: u8 = 0,
    slot: u64 = 0,
    index: u32 = 0,
    len: u32 = 0,
    buf: [MAX_MSG]u8 = undefined,
};

pub const LedgerTile = struct {
    ring: []RingMsg,
    head: usize = 0, // consumer dequeues here
    tail: usize = 0, // producer enqueues here
    count: usize = 0,
    mutex: std.Thread.Mutex = .{},
    dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    enqueued: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    applied: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Live sampler of completed_data_indexes.len (LEDG Q3): logs each new high so
    /// we can right-size MAX_MSG from the real distribution after the soak.
    max_completed: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    vl: *VexLedger,
    allocator: std.mem.Allocator,
    /// Bounded-ledger prune config (`--limit-ledger-size` semantics). Read ONCE in
    /// init from env; 0 = DISABLED (unbounded — the prior behavior; opt-in safe
    /// default). VEX_LEDGER_MAX_BYTES (disk budget) takes precedence over
    /// VEX_LEDGER_KEEP_SLOTS (slot window). The periodic prune fires from the single
    /// consumer thread (apply→MSG_FINISH), so these are consumer-only (no atomics)
    /// and a prune never races another prune.
    prune_max_bytes: u64 = 0,
    prune_keep_slots: u64 = 0,
    prune_every_slots: u64 = 64, // run a prune at most once per this many completed slots
    finishes_since_prune: u64 = 0,
    pruned_segments_total: u64 = 0,
    pruned_bytes_total: u64 = 0,
    /// Instrumentation (perf-tuning telemetry). ring_high_water = peak ring occupancy
    /// since the last stats window (mutex-protected, written by producers); reset per
    /// window. finishes_total drives the stats cadence (consumer-only).
    ring_high_water: usize = 0,
    finishes_total: u64 = 0,
    /// Per-slot persist latency (finishSlot = serialize meta + append + fsync; the
    /// fsync dominates → this is the fsync-cadence tuning signal). ns, reset per window.
    finish_ns_max: u64 = 0,
    finish_ns_sum: u64 = 0,
    finish_ns_count: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, vl: *VexLedger, capacity: usize) !*LedgerTile {
        const self = try allocator.create(LedgerTile);
        errdefer allocator.destroy(self);
        const ring = try allocator.alloc(RingMsg, capacity);
        // --limit-ledger-size: bound the on-disk ledger. Unset/0 → pruning DISABLED
        // (unbounded = prior behavior). Whole-segment unlink is O(1) + near-zero
        // write-amp (no compaction). Off the consensus path → bank-hash-neutral.
        const max_bytes = parseEnvU64("VEX_LEDGER_MAX_BYTES");
        const keep_slots = parseEnvU64("VEX_LEDGER_KEEP_SLOTS");
        self.* = .{
            .ring = ring,
            .vl = vl,
            .allocator = allocator,
            .prune_max_bytes = max_bytes,
            .prune_keep_slots = keep_slots,
        };
        if (max_bytes != 0 or keep_slots != 0) {
            std.log.warn("[LEDGER-TILE] prune ARMED: max_bytes={d} keep_slots={d} every={d}slots", .{ max_bytes, keep_slots, self.prune_every_slots });
        } else {
            std.log.warn("[LEDGER-TILE] prune DISABLED (VEX_LEDGER_MAX_BYTES / VEX_LEDGER_KEEP_SLOTS unset) — ledger grows unbounded", .{});
        }
        return self;
    }

    pub fn deinit(self: *LedgerTile) void {
        self.allocator.free(self.ring);
        self.allocator.destroy(self);
    }

    // ---- producer side (any of the 4 completion threads) ----

    /// Claim a ring slot and copy `payload` in. Returns false (no enqueue) if the
    /// payload is oversized or the ring is full. Lock held only for the memcpy.
    fn tryEnqueue(self: *LedgerTile, kind: u8, slot: u64, index: u32, payload: []const u8) bool {
        if (payload.len > MAX_MSG) return false;
        self.mutex.lock();
        if (self.count == self.ring.len) {
            self.mutex.unlock();
            return false;
        }
        const i = self.tail;
        const m = &self.ring[i];
        m.kind = kind;
        m.slot = slot;
        m.index = index;
        m.len = @intCast(payload.len);
        @memcpy(m.buf[0..payload.len], payload);
        self.tail = (i + 1) % self.ring.len;
        self.count += 1;
        if (self.count > self.ring_high_water) self.ring_high_water = self.count; // peak occupancy (under lock)
        self.mutex.unlock();
        _ = self.enqueued.fetchAdd(1, .monotonic);
        return true;
    }

    fn enqueueDrop(self: *LedgerTile, kind: u8, slot: u64, index: u32, payload: []const u8) void {
        if (!self.tryEnqueue(kind, slot, index, payload)) {
            const d = self.dropped.fetchAdd(1, .monotonic) + 1;
            if (d % 1000 == 1) {
                std.log.warn("[LEDGER-TILE] dropped {d} msgs (ring full / disk backpressure) — ledger best-effort, consensus unaffected", .{d});
            }
        }
    }

    pub fn enqueueShred(self: *LedgerTile, slot: u64, index: u32, wire: []const u8) void {
        self.enqueueDrop(MSG_DATA, slot, index, wire);
    }

    pub fn enqueueCodingShred(self: *LedgerTile, slot: u64, index: u32, wire: []const u8) void {
        self.enqueueDrop(MSG_CODE, slot, index, wire);
    }

    /// Encode the producer-derived SlotMeta into a FINISH message. If the meta is
    /// larger than the inline buffer it is DROPPED+logged (never truncated); the
    /// slot then self-identifies as a gap on replay (received>stored).
    pub fn enqueueFinish(self: *LedgerTile, slot: u64, meta: SlotMeta) void {
        // Sample completed_data_indexes.len — log each new high to right-size MAX_MSG.
        const ncomp: u32 = @intCast(meta.completed_data_indexes.len);
        if (ncomp > self.max_completed.load(.monotonic)) {
            self.max_completed.store(ncomp, .monotonic);
            std.log.warn("[LEDGER-TILE] new max completed_data_indexes={d} (slot {d}); FINISH={d}B, MAX_MSG={d}", .{ ncomp, slot, FinishBlob.encodedLen(meta), MAX_MSG });
        }
        var fbuf: [MAX_MSG]u8 = undefined;
        const enc = FinishBlob.encode(&fbuf, meta) catch {
            const d = self.dropped.fetchAdd(1, .monotonic) + 1;
            std.log.warn("[LEDGER-TILE] FINISH meta slot {d} exceeds {d}B inline buf — dropped (gap on replay); total dropped {d}", .{ slot, MAX_MSG, d });
            return;
        };
        self.enqueueDrop(MSG_FINISH, slot, 0, enc);
    }

    // ---- consumer side (the single tile thread) ----

    /// Copy one message OUT under the lock; the caller applies it (putShred /
    /// finishSlot incl. fsync) OUTSIDE the lock so the I/O never holds the ring.
    fn dequeue(self: *LedgerTile, out: *RingMsg) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.count == 0) return false;
        const i = self.head;
        const m = &self.ring[i];
        out.kind = m.kind;
        out.slot = m.slot;
        out.index = m.index;
        out.len = m.len;
        @memcpy(out.buf[0..m.len], m.buf[0..m.len]);
        self.head = (i + 1) % self.ring.len;
        self.count -= 1;
        return true;
    }

    /// Apply one drained message to VexLedger (off the consensus thread). Errors
    /// are swallowed (best-effort), exactly as the prior inline path did.
    fn apply(self: *LedgerTile, m: *const RingMsg) void {
        switch (m.kind) {
            MSG_DATA => self.vl.putShred(m.slot, m.index, m.buf[0..m.len]) catch {},
            MSG_CODE => self.vl.putCodingShred(m.slot, m.index, m.buf[0..m.len]) catch {},
            MSG_FINISH => {
                const meta = FinishBlob.decode(self.allocator, m.buf[0..m.len]) catch return;
                defer self.allocator.free(meta.completed_data_indexes);
                const t0 = std.time.nanoTimestamp();
                self.vl.finishSlot(m.slot, meta) catch {};
                const dt: u64 = @intCast(@max(0, std.time.nanoTimestamp() - t0));
                self.finish_ns_sum += dt;
                self.finish_ns_count += 1;
                if (dt > self.finish_ns_max) self.finish_ns_max = dt;
                self.maybePrune();
                self.maybeLogStats();
            },
            else => {},
        }
        _ = self.applied.fetchAdd(1, .monotonic);
    }

    /// Perf telemetry, emitted once per 512 completed slots (~3.5 min at 2.5 slots/s).
    /// Consumer-thread-only. Surfaces ring backpressure (high-water vs capacity →
    /// the ring-capacity tuning signal), drop count (producer outran consumer), and
    /// prune reclaim. Logging only — zero effect on ingest or bank_hash.
    fn maybeLogStats(self: *LedgerTile) void {
        self.finishes_total += 1;
        if (self.finishes_total % 512 != 0) return;
        self.mutex.lock();
        const hw = self.ring_high_water;
        self.ring_high_water = self.count; // reset watermark to current for the next window
        self.mutex.unlock();
        const avg_us: u64 = if (self.finish_ns_count != 0) (self.finish_ns_sum / self.finish_ns_count) / 1000 else 0;
        const max_us: u64 = self.finish_ns_max / 1000;
        std.log.warn("[LEDGER-TILE-STATS] slots={d} enq={d} applied={d} dropped={d} ring_high_water={d}/{d} persist_us(avg/max)={d}/{d} pruned={d}seg/{d}MiB", .{ self.finishes_total, self.enqueued.load(.monotonic), self.applied.load(.monotonic), self.dropped.load(.monotonic), hw, self.ring.len, avg_us, max_us, self.pruned_segments_total, self.pruned_bytes_total >> 20 });
        // reset per-window latency accumulators
        self.finish_ns_max = 0;
        self.finish_ns_sum = 0;
        self.finish_ns_count = 0;
    }

    /// Periodic bounded-ledger prune (`--limit-ledger-size`). Consumer-thread-ONLY
    /// (called from apply→MSG_FINISH), so the counter needs no atomics and a prune
    /// never races another prune. Runs at most once per `prune_every_slots` completed
    /// slots when a limit is configured. Whole-segment unlink is O(1); errors are
    /// swallowed (best-effort, never fatal to ingest) exactly like apply(). The prune
    /// touches the ledger store ONLY (off the consensus path) → bank-hash-neutral.
    /// Reads (repair-serve / RPC) take the shared lock and tolerate a concurrent prune.
    fn maybePrune(self: *LedgerTile) void {
        if (self.prune_max_bytes == 0 and self.prune_keep_slots == 0) return;
        self.finishes_since_prune += 1;
        if (self.finishes_since_prune < self.prune_every_slots) return;
        self.finishes_since_prune = 0;
        const stats = if (self.prune_max_bytes != 0)
            (self.vl.pruneToByteLimit(self.prune_max_bytes) catch return)
        else
            (self.vl.pruneToSlotWindow(self.prune_keep_slots) catch return);
        if (stats.segments_unlinked != 0) {
            self.pruned_segments_total += stats.segments_unlinked;
            self.pruned_bytes_total += stats.bytes_freed;
            std.log.warn("[LEDGER-TILE] prune: unlinked {d} seg ({d} MiB), lowest_kept={?d}; cumulative {d} seg / {d} MiB", .{ stats.segments_unlinked, stats.bytes_freed >> 20, stats.lowest_kept, self.pruned_segments_total, self.pruned_bytes_total >> 20 });
        }
    }

    /// The tile main loop — spawn this on a cold core. Drains until `running` is
    /// cleared AND the ring is fully flushed (graceful shutdown).
    pub fn run(self: *LedgerTile) void {
        var msg: RingMsg = undefined;
        while (true) {
            if (self.dequeue(&msg)) {
                self.apply(&msg);
            } else {
                if (!self.running.load(.acquire)) break;
                std.Thread.sleep(50 * std.time.ns_per_us); // 50µs idle poll on the cold core
            }
        }
    }

    pub fn stop(self: *LedgerTile) void {
        self.running.store(false, .release);
    }

    fn pinSelf(core_id: u32) void {
        var cpu_set = [_]usize{0} ** 16;
        const idx = core_id / @bitSizeOf(usize);
        const bit: u6 = @intCast(core_id % @bitSizeOf(usize));
        cpu_set[idx] = @as(usize, 1) << bit;
        _ = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
    }

    /// Spawn the consumer loop on its own thread, pinned to `core_id` (a cold core).
    /// Returns the thread handle for a graceful stop()+join at shutdown (Q4).
    pub fn spawnPinned(self: *LedgerTile, core_id: u32) !std.Thread {
        const Entry = struct {
            fn run(t: *LedgerTile, core: u32) void {
                pinSelf(core);
                t.run();
            }
        };
        return std.Thread.spawn(.{}, Entry.run, .{ self, core_id });
    }
};

// ----------------------------------------------------------------------------
// KATs (ring concurrency — the new, consensus-adjacent code). The apply→VexLedger
// path is covered by the module's KAT 25 (tileDrain reference); these prove the
// MPSC ring itself is loss/dup/corruption-free under concurrent producers and
// drops cleanly when full.
// ----------------------------------------------------------------------------

// Construct a ring-only tile (vl unused — these tests never call apply/run).
fn testRing(allocator: std.mem.Allocator, capacity: usize) !*LedgerTile {
    const self = try allocator.create(LedgerTile);
    self.* = .{ .ring = try allocator.alloc(RingMsg, capacity), .vl = undefined, .allocator = allocator };
    return self;
}

test "MPSC ring: concurrent producers — no loss, no dup, no corruption" {
    const A = std.testing.allocator;
    const tile = try testRing(A, 256); // small ring forces wraparound + backpressure
    defer {
        A.free(tile.ring);
        A.destroy(tile);
    }

    const NP: u32 = 4;
    const PER: u32 = 5000;

    const Producer = struct {
        fn run(t: *LedgerTile, pid: u32) void {
            var i: u32 = 0;
            while (i < PER) : (i += 1) {
                var payload: [8]u8 = undefined;
                std.mem.writeInt(u32, payload[0..4], pid, .little);
                std.mem.writeInt(u32, payload[4..8], i, .little);
                // retry-until-enqueued so the test asserts ZERO loss under concurrency
                while (!t.tryEnqueue(MSG_DATA, pid, i, &payload)) {
                    std.Thread.yield() catch {};
                }
            }
        }
    };

    var threads: [NP]std.Thread = undefined;
    for (0..NP) |p| threads[p] = try std.Thread.spawn(.{}, Producer.run, .{ tile, @as(u32, @intCast(p)) });
    // join on ANY exit (incl. a failed assertion) so producers never outlive the ring
    defer for (threads) |t| t.join();

    // single consumer drains concurrently; track (pid,i) keys for dup/loss/corruption
    var seen = std.AutoHashMap(u64, void).init(A);
    defer seen.deinit();
    var got: usize = 0;
    const total: usize = NP * PER;
    var msg: RingMsg = undefined;
    while (got < total) {
        if (tile.dequeue(&msg)) {
            try std.testing.expectEqual(MSG_DATA, msg.kind);
            try std.testing.expectEqual(@as(u32, 8), msg.len);
            const pid = std.mem.readInt(u32, msg.buf[0..4], .little);
            const i = std.mem.readInt(u32, msg.buf[4..8], .little);
            try std.testing.expect(pid < NP and i < PER); // not corrupted
            try std.testing.expectEqual(i, msg.index); // header index preserved (producer set index=i)
            try std.testing.expectEqual(@as(u64, pid), msg.slot); // header slot preserved (producer set slot=pid)
            const key = (@as(u64, pid) << 32) | i;
            try std.testing.expect(!seen.contains(key)); // no duplicate
            try seen.put(key, {});
            got += 1;
        } else {
            std.Thread.yield() catch {};
        }
    }
    try std.testing.expectEqual(total, seen.count()); // every msg arrived exactly once
    try std.testing.expectEqual(@as(u64, 0), tile.dropped.load(.monotonic)); // retry path => no drops
}

test "MPSC ring: drops cleanly when full, no block, survivors intact" {
    const A = std.testing.allocator;
    const cap: usize = 16;
    const tile = try testRing(A, cap);
    defer {
        A.free(tile.ring);
        A.destroy(tile);
    }

    // fill exactly to capacity
    var i: u32 = 0;
    while (i < cap) : (i += 1) {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], i, .little);
        try std.testing.expect(tile.tryEnqueue(MSG_DATA, i, i, &p));
    }
    // next K must DROP (never block), counted
    const K: u32 = 100;
    var k: u32 = 0;
    while (k < K) : (k += 1) {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], 9999, .little);
        tile.enqueueDrop(MSG_DATA, 9999, 9999, &p);
    }
    try std.testing.expectEqual(@as(u64, K), tile.dropped.load(.monotonic));
    try std.testing.expectEqual(cap, tile.count);

    // the cap survivors are the FIRST cap, in order, uncorrupted (no overwrite)
    var msg: RingMsg = undefined;
    var expect: u32 = 0;
    while (tile.dequeue(&msg)) : (expect += 1) {
        try std.testing.expectEqual(expect, msg.index);
        try std.testing.expectEqual(expect, std.mem.readInt(u32, msg.buf[0..4], .little));
    }
    try std.testing.expectEqual(@as(u32, cap), expect);
}

test "FINISH oversize meta is dropped, not truncated" {
    const A = std.testing.allocator;
    const tile = try testRing(A, 8);
    defer {
        A.free(tile.ring);
        A.destroy(tile);
    }
    // a meta whose completed_data_indexes overflow MAX_MSG must drop, not enqueue
    const huge = try A.alloc(u32, MAX_MSG); // 4·MAX_MSG bytes >> MAX_MSG
    defer A.free(huge);
    const meta = SlotMeta{ .completed_data_indexes = huge };
    tile.enqueueFinish(1234, meta);
    try std.testing.expectEqual(@as(usize, 0), tile.count); // nothing enqueued
    try std.testing.expectEqual(@as(u64, 1), tile.dropped.load(.monotonic));
}
