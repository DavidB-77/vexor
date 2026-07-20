//! Vexor Verify Tile
//!
//! High-performance shred signature verification pipeline.
//! Receives raw shred payloads from the TVU recv loop, verifies Ed25519
//! signatures using a pool of worker threads, and batch-inserts verified
//! shreds into the ShredAssembler.
//!
//! Architecture:
//!   UDP Recv Loop ──► ShredQueue (bounded ring) ──► Verify Workers (N threads)
//!                                                       │
//!                                                       ▼
//!                                                 ShredAssembler.insertBatch()
//!
//! The verify workers are the ONLY path into the assembler. Unverified
//! shreds never reach the assembler — closing the security hole.

const std = @import("std");
const core = @import("core");
const build_options = @import("build_options"); // Phase 9: legacy_pins escape hatch
const vex_topo = @import("vex_topo"); // Phase 9: declarative tile→core topology table
const runtime = @import("vex_svm");
const shred_mod = @import("shred.zig");
const consensus = @import("vex_consensus");

/// Maximum shred payload size (Solana Merkle V2)
pub const MAX_SHRED_SIZE: usize = 1232;

/// Default queue capacity (must be power of 2)
pub const DEFAULT_QUEUE_CAPACITY: u32 = 65536; // 4x larger to absorb burst shred traffic

// Ed25519 FEC-set signature dedup (canonical Agave rc.1 port; -Dfec_dedup gate).
// Types + safety rationale + KATs live in fec_dedup.zig (std-only, directly testable).
const fec_dedup = @import("fec_dedup.zig");
const DedupKey = fec_dedup.DedupKey;
const DedupCache = fec_dedup.DedupCache;
const FEC_DEDUP_CAP = fec_dedup.FEC_DEDUP_CAP;

/// Default number of verify worker threads
pub const DEFAULT_NUM_WORKERS: usize = 8; // 8 workers on cores 8-15 (CCD2-3), leaves core 16 clean for Replay

// Phase 9 anti-drift tripwire: the verify range in vex_topo.LIVE
// (verify_base .. verify_base + NUM_VERIFY_WORKERS) MUST stay coupled to the
// worker count here. If they ever diverge, this becomes a BUILD ERROR rather
// than a silent mis-pin of a verify worker.
comptime {
    std.debug.assert(vex_topo.NUM_VERIFY_WORKERS == @as(u32, @intCast(DEFAULT_NUM_WORKERS)));
}

// ═══════════════════════════════════════════════════════════════════════════════
// ShredQueue: Bounded ring buffer for raw shred payloads
// ═══════════════════════════════════════════════════════════════════════════════

pub const QueueEntry = struct {
    data: [MAX_SHRED_SIZE]u8 = undefined,
    len: u16 = 0,
    is_zero_copy: bool = false,
    frame_ref: ?@import("af_xdp/socket.zig").UmemFrameRef = null,
    zc_index: u32 = 0,
    zc_is_last: bool = false,
    fm_ptr: usize = 0,
};

/// Thread-safe bounded queue. Single producer (TVU recv), multiple consumers
/// (verify workers). Uses a mutex + condition variable for simplicity —
/// contention is minimal because workers spend ~50μs in Ed25519 per shred.
pub const ShredQueue = struct {
    entries: []QueueEntry,
    head: u32 = 0, // Next write position (producer)
    tail: u32 = 0, // Next read position (consumers)
    count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    capacity: u32,
    mutex: std.Thread.Mutex = .{},
    not_empty: std.Thread.Condition = .{},

    // Stats
    push_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    drop_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    // Option A (2026-06-14): count of tryLock misses (a worker held the mutex when
    // the recv thread tried to submit). High value = the lock-convoy was real.
    trylock_fail: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, capacity: u32) !*Self {
        const q = try allocator.create(Self);
        const entries = try allocator.alloc(QueueEntry, capacity);
        @memset(entries, QueueEntry{});

        q.* = Self{
            .entries = entries,
            .capacity = capacity,
        };
        return q;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        allocator.destroy(self);
    }

    /// Push a raw shred payload into the queue. Returns false if full (drops shred).
    pub fn push(self: *Self, payload: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const current_count = self.count.load(.monotonic);
        if (current_count >= self.capacity) {
            _ = self.drop_count.fetchAdd(1, .monotonic);
            return false; // Queue full — drop
        }

        const idx = self.head % self.capacity;
        const copy_len = @min(payload.len, MAX_SHRED_SIZE);
        @memcpy(self.entries[idx].data[0..copy_len], payload[0..copy_len]);
        self.entries[idx].len = @intCast(copy_len);

        self.head +%= 1;
        _ = self.count.fetchAdd(1, .monotonic);
        const new_push = self.push_count.fetchAdd(1, .monotonic) + 1;

        // FIX #76 (2026-05-28): periodic diagnostic emission every 4096 pushes.
        // Reveals queue depth + drop count for FIX #72/#75 leak investigation.
        // Looking for: queue.count growing toward capacity = workers behind ingest,
        // drop_count climbing = queue overflow already happening.
        if (new_push & 4095 == 0) {
            const cur = self.count.load(.monotonic);
            const drops = self.drop_count.load(.monotonic);
            std.log.info("[VerifyTile-Queue] push#={d} depth={d}/{d} drops={d} (FIX #76 diag)", .{
                new_push, cur, self.capacity, drops,
            });
        }

        self.not_empty.signal();
        return true;
    }

    /// Pop a batch of entries. Returns count of entries popped.
    /// Caller provides the output buffer.
    pub fn popBatch(self: *Self, out: []QueueEntry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var popped: usize = 0;
        const max = out.len;
        const available = self.count.load(.monotonic);

        const to_pop = @min(max, available);
        while (popped < to_pop) : (popped += 1) {
            const idx = self.tail % self.capacity;
            out[popped] = self.entries[idx];
            self.tail +%= 1;
        }

        if (popped > 0) {
            _ = self.count.fetchSub(@intCast(popped), .monotonic);
        }
        return popped;
    }

    /// Block until data is available or timeout expires.
    pub fn waitForData(self: *Self, timeout_ns: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.count.load(.monotonic) > 0) return;
        self.not_empty.timedWait(&self.mutex, timeout_ns) catch {};
    }

    pub fn len(self: *const Self) u32 {
        return self.count.load(.monotonic);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// SpscRing: lock-free verify handoff (Option B) — defined in spsc_ring.zig so its
// KATs run standalone (zig build test-verify-ring) without dragging the tvu.zig graph.
// ═══════════════════════════════════════════════════════════════════════════════
pub const spsc = @import("spsc_ring.zig");
pub const SpscRing = spsc.SpscRing;
pub const ZcRingEntry = spsc.ZcRingEntry;
pub const ZC_RING_CAPACITY = spsc.ZC_RING_CAPACITY;

// ═══════════════════════════════════════════════════════════════════════════════
// LeaderLookupCache: Per-thread slot→leader cache
// ═══════════════════════════════════════════════════════════════════════════════

const LeaderLookupCache = struct {
    cached_slot: u64 = 0,
    cached_leader: ?core.Pubkey = null,
    hits: u64 = 0,
    misses: u64 = 0,

    fn getLeader(
        self: *LeaderLookupCache,
        slot: u64,
        cache: ?*consensus.leader_schedule.LeaderScheduleCache,
    ) ?core.Pubkey {
        if (slot == self.cached_slot and self.cached_leader != null) {
            self.hits += 1;
            return self.cached_leader;
        }
        self.misses += 1;
        self.cached_slot = slot;
        self.cached_leader = if (cache) |c| c.getSlotLeader(slot) else null;
        return self.cached_leader;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// VerifyTile: Main verify pipeline coordinator
// ═══════════════════════════════════════════════════════════════════════════════

pub const VerifyStats = struct {
    verified: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    rejected: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    no_leader: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    parse_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    inserted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    completed_slots: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    batches_processed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const VerifyTile = struct {
    allocator: std.mem.Allocator,

    /// Input queue: raw shred payloads from TVU recv loop
    queue: *ShredQueue,

    /// Shred assembler: verify workers insert directly
    assembler: *shred_mod.ShredAssembler,

    /// Leader schedule cache (for signature verification)
    leader_cache: ?*consensus.leader_schedule.LeaderScheduleCache,

    /// Static leader pubkey fallback (for testing)
    static_leader: ?core.Pubkey,

    /// TVU stats pointer (for updating shreds_inserted, slots_completed, etc.)
    tvu_stats: *@import("tvu.zig").TvuService.Stats,

    /// r49-B-rev-fix-2: Reference to TvuService for dispatching completed slots
    /// to replay_stage. Set by tvu.setReplayStage() after replay_stage is wired.
    /// Without this, completed slots are silently swallowed by VerifyTile path
    /// (per /tmp/vexor_skip_carrier_audit.md).
    tvu_ref: ?*@import("tvu.zig").TvuService = null,

    /// Consensus tracker for diagnostic tracing
    consensus_tracker: ?*anyopaque,

    /// Worker threads
    workers: std.ArrayListUnmanaged(std.Thread),

    /// Number of worker threads
    num_workers: usize,

    /// Option B (2026-06-14): per-worker lock-free SPSC rings for the AF_XDP
    /// zero-copy hot path. `zc_rings[i]` is drained ONLY by worker `i`; the recv
    /// thread is the sole producer (round-robins across all rings). Null on the
    /// kernel-UDP path (workers fall back to the shared mutex ShredQueue, byte-
    /// identical to the proven path). Allocated when enable_zc_rings is set.
    zc_rings: ?[]*SpscRing = null,

    /// Recv-thread-only round-robin cursor for submitZeroCopyRing (no atomic — a
    /// single producer touches it).
    rr_cursor: u32 = 0,

    /// Frames dropped because ALL worker rings were full (genuine verify-
    /// parallelism overrun). The advisor's discriminator: if this stays ≈0 yet
    /// AF_XDP still wedges (bridge slots missing, root stuck) → the wedge is the
    /// repair path (NEXT-2 net-tile split), NOT the verify handoff — do not re-spin
    /// Option B. High during catch-up → a verify-worker-count limit, not handoff.
    zc_overrun: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Running flag
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Verify-specific stats
    stats: VerifyStats = .{},

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        assembler: *shred_mod.ShredAssembler,
        leader_cache: ?*consensus.leader_schedule.LeaderScheduleCache,
        static_leader: ?core.Pubkey,
        tvu_stats: *@import("tvu.zig").TvuService.Stats,
        consensus_tracker: ?*anyopaque,
        num_workers: usize,
        // Option B (2026-06-14): allocate the per-worker lock-free SPSC rings for
        // the AF_XDP zero-copy hot path. Pass true only when AF_XDP zero-copy is
        // configured (config.enable_af_xdp and config.xdp_zero_copy). On the
        // kernel-UDP path leave false → workers use the shared ShredQueue exactly
        // as the proven path does (zero behavioral change there).
        enable_zc_rings: bool,
    ) !*Self {
        const queue = try ShredQueue.init(allocator, DEFAULT_QUEUE_CAPACITY);

        var zc_rings: ?[]*SpscRing = null;
        if (enable_zc_rings) {
            const rings = try allocator.alloc(*SpscRing, num_workers);
            for (rings) |*r| r.* = try SpscRing.init(allocator, ZC_RING_CAPACITY);
            zc_rings = rings;
            std.log.info("[VerifyTile] Option B: {d} lock-free SPSC verify rings (cap {d} each) — recv never blocks/drops on handoff", .{ num_workers, ZC_RING_CAPACITY });
        }

        const tile = try allocator.create(Self);
        tile.* = Self{
            .allocator = allocator,
            .queue = queue,
            .assembler = assembler,
            .leader_cache = leader_cache,
            .static_leader = static_leader,
            .tvu_stats = tvu_stats,
            .consensus_tracker = consensus_tracker,
            .workers = .empty,
            .num_workers = num_workers,
            .zc_rings = zc_rings,
        };

        return tile;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.queue.deinit(self.allocator);
        if (self.zc_rings) |rings| {
            for (rings) |r| r.deinit(self.allocator);
            self.allocator.free(rings);
        }
        self.workers.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// r49-B-rev-fix-2: Wire TvuService reference so workers can dispatch
    /// completed slots to replay_stage (called by tvu.setReplayStage).
    pub fn setTvuRef(self: *Self, tvu: *@import("tvu.zig").TvuService) void {
        self.tvu_ref = tvu;
    }

    /// Start verify worker threads
    pub fn start(self: *Self) !void {
        if (self.running.load(.seq_cst)) return;
        self.running.store(true, .seq_cst);

        std.log.info("[VerifyTile] Starting {d} verify workers (queue capacity: {d})", .{
            self.num_workers,
            self.queue.capacity,
        });

        for (0..self.num_workers) |i| {
            const t = try std.Thread.spawn(.{}, verifyWorkerLoop, .{ self, i });
            try self.workers.append(self.allocator, t);
        }

        std.log.info("[VerifyTile] All {d} workers spawned ✓", .{self.num_workers});
    }

    /// Stop all workers and wait for them to finish
    pub fn stop(self: *Self) void {
        if (!self.running.load(.seq_cst)) return;
        self.running.store(false, .seq_cst);

        // Wake all workers so they see the flag
        {
            self.queue.mutex.lock();
            defer self.queue.mutex.unlock();
            self.queue.not_empty.broadcast();
        }

        for (self.workers.items) |t| {
            t.join();
        }
        self.workers.clearRetainingCapacity();

        std.log.info("[VerifyTile] Stopped. verified={d} rejected={d} no_leader={d} inserted={d}", .{
            self.stats.verified.load(.monotonic),
            self.stats.rejected.load(.monotonic),
            self.stats.no_leader.load(.monotonic),
            self.stats.inserted.load(.monotonic),
        });
    }

    /// Submit a raw shred payload for verification. Called from TVU recv loop.
    /// Returns false if the queue is full (shred dropped).
    pub fn submit(self: *Self, payload: []const u8) bool {
        return self.queue.push(payload);
    }

    /// Result of a non-blocking zero-copy submit (Option A, 2026-06-14).
    /// `.contended` means a verify worker holds queue.mutex right now — the recv
    /// thread must NOT block on it (the 212ms lock-convoy that wedged AF_XDP
    /// catch-up); instead it stages the frame and retries. `.queue_full` = the
    /// queue is genuinely full (overrun → release). `.submitted` = enqueued.
    pub const SubmitResult = enum { submitted, queue_full, contended };

    /// Submit a zero-copy frame for verification. Called from TVU zero-copy loop.
    /// NON-BLOCKING: uses tryLock so the latency-critical recv thread never blocks
    /// on a verify-worker-held queue.mutex (Firedancer net-tile principle: RX must
    /// never share fate with a descheduled consumer).
    pub fn submitZeroCopy(self: *Self, index: u32, is_last: bool, ref: @import("af_xdp/socket.zig").UmemFrameRef, fm_ptr: usize) SubmitResult {
        if (!self.queue.mutex.tryLock()) {
            _ = self.queue.trylock_fail.fetchAdd(1, .monotonic);
            return .contended;
        }
        defer self.queue.mutex.unlock();

        const current_count = self.queue.count.load(.monotonic);
        if (current_count >= self.queue.capacity) {
            _ = self.queue.drop_count.fetchAdd(1, .monotonic);
            return .queue_full;
        }

        const idx = self.queue.head % self.queue.capacity;
        self.queue.entries[idx].is_zero_copy = true;
        self.queue.entries[idx].frame_ref = ref;
        self.queue.entries[idx].zc_index = index;
        self.queue.entries[idx].zc_is_last = is_last;
        self.queue.entries[idx].fm_ptr = fm_ptr;

        self.queue.head +%= 1;
        _ = self.queue.count.fetchAdd(1, .monotonic);
        _ = self.queue.push_count.fetchAdd(1, .monotonic);

        self.queue.not_empty.signal();
        return .submitted;
    }

    /// Option B (2026-06-14): submit a zero-copy frame via the per-worker lock-free
    /// SPSC rings. PRODUCER-ONLY — called ONLY from the recv thread (sole producer).
    /// Round-robins across rings; if the chosen worker's ring is full it tries the
    /// next (a single descheduled worker never causes a global drop — recv keeps
    /// feeding the others). Only when ALL rings are full does it return .queue_full
    /// (caller overrun-drops + releases the frame) and bump zc_overrun. NEVER blocks,
    /// NEVER touches a mutex → the recv hot path is fully lock-free.
    pub fn submitZeroCopyRing(self: *Self, index: u32, is_last: bool, ref: @import("af_xdp/socket.zig").UmemFrameRef, fm_ptr: usize) SubmitResult {
        const rings = self.zc_rings orelse return .queue_full;
        const n: u32 = @intCast(rings.len);
        const entry = ZcRingEntry{ .frame_ref = ref, .index = index, .is_last = is_last, .fm_ptr = fm_ptr };
        var tries: u32 = 0;
        while (tries < n) : (tries += 1) {
            const w = (self.rr_cursor + tries) % n;
            if (rings[w].tryPush(entry)) {
                self.rr_cursor = (w + 1) % n;
                return .submitted;
            }
        }
        self.rr_cursor = (self.rr_cursor + 1) % n;
        _ = self.zc_overrun.fetchAdd(1, .monotonic);
        return .queue_full; // all rings full → caller releases the frame
    }

    /// Worker loop: pop shreds, verify signatures, batch-insert into assembler.
    fn verifyWorkerLoop(self: *Self, worker_id: usize) void {
        // Pin verify worker to dedicated core (cores 8+, CCD-aware layout).
        // Phase 9: default = vex_topo table (.verify_base + worker_id == 8 + worker_id,
        // byte-identical cpu_set); VEX_LEGACY_PINS / -Dlegacy_pins reverts to the inline
        // open-coded syscall below. Either way the rc drives the same info/warn log —
        // this is the ONE pin site that checks the syscall return.
        const target_core: u32 = @intCast(8 + worker_id);
        const rc: usize = if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) blk: {
            var cpu_set = [_]usize{0} ** 16;
            cpu_set[target_core / 64] = @as(usize, 1) << @intCast(target_core % 64);
            break :blk std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
        } else vex_topo.pinTile(vex_topo.LIVE, .verify_base, @intCast(worker_id));
        if (rc == 0) {
            std.log.info("[VerifyTile] Worker {d} pinned to core {d}", .{ worker_id, target_core });
        } else {
            std.log.warn("[VerifyTile] Worker {d} CPU pin to core {d} failed", .{ worker_id, target_core });
        }

        var leader_cache_local = LeaderLookupCache{};
        var batch_buf: [64]QueueEntry = undefined;
        var verified_shreds: [64]shred_mod.Shred = undefined;

        var local_verified: u64 = 0;
        var local_rejected: u64 = 0;
        var local_fec_discarded: u64 = 0;

        // FEC-set sig dedup (comptime -Dfec_dedup). When the flag is OFF, fec_dedup_built
        // is false, sig_cache has type `void` (zero size, no allocation) and the dedup
        // branch in the gate is comptime-pruned ⇒ this worker is byte-identical to today.
        // When ON, the cache is armed only if VEXOR_ED25519_FEC_DEDUP is set (runtime gate).
        const fec_dedup_built = build_options.fec_dedup;
        const fec_dedup_active = fec_dedup_built and core.envFlagValueArmed(std.posix.getenv("VEXOR_ED25519_FEC_DEDUP"));
        var sig_cache: if (fec_dedup_built) DedupCache else void =
            if (fec_dedup_built) DedupCache.init(self.allocator) else {};
        defer if (comptime fec_dedup_built) sig_cache.deinit();
        var local_dedup_hits: u64 = 0;
        if (fec_dedup_active) {
            // WARN (was INFO) so the activation is VISIBLE in the normal WARN-level log without
            // VEX_LOG_INFO=1 — lets us positively confirm FEC-dedup is live at a glance (2026-06-28).
            // One-time per worker at startup, so not spammy. The per-batch hit stat (below) stays INFO.
            std.log.warn("[VerifyTile-{d}] FEC-set sig dedup ACTIVE (tuple-keyed cache, cap={d})", .{ worker_id, FEC_DEDUP_CAP });
        }

        // Option B: this worker owns exactly one lock-free SPSC ring (no shared
        // mutex on the AF_XDP hot path). Null on the kernel-UDP path → the worker
        // drains the shared ShredQueue exactly as the proven path does.
        const my_ring: ?*SpscRing = if (self.zc_rings) |rings| rings[worker_id] else null;

        // Adaptive idle backoff (2026-07-08, live-profile fix): 8 verify tiles each
        // napping a FIXED 50µs when the AF_XDP ring was empty hammered the kernel
        // hrtimer/spinlock (native_queued_spin_lock_slowpath ~19% CPU at tip). Grow
        // the nap on sustained idle to cut the timer-setup rate; reset to the
        // responsive floor the instant work arrives. The ring buffers shreds during
        // the nap so nothing is lost; at-tip idle headroom makes the latency nil.
        const MIN_IDLE_NAP_NS: u64 = 50 * std.time.ns_per_us;
        // Cap raised 512µs→1ms (2026-07-08 batch): residual timer-lock contention was
        // still 2.8% at tip; ~2× fewer naps halves it. 1ms wake latency on deep idle is
        // negligible at tip (ring buffers shreds; ~48ms work per 400ms slot).
        const MAX_IDLE_NAP_NS: u64 = 1000 * std.time.ns_per_us;
        var idle_nap_ns: u64 = MIN_IDLE_NAP_NS;

        while (self.running.load(.seq_cst)) {
            var popped: usize = 0;

            // (1) Drain THIS worker's lock-free ring (AF_XDP zero-copy hot path).
            if (my_ring) |ring| {
                var zce: ZcRingEntry = undefined;
                while (popped < batch_buf.len and ring.tryPop(&zce)) : (popped += 1) {
                    batch_buf[popped] = .{
                        .is_zero_copy = true,
                        .frame_ref = zce.frame_ref,
                        .zc_index = zce.index,
                        .zc_is_last = zce.is_last,
                        .fm_ptr = zce.fm_ptr,
                    };
                }
            }

            // (2) Also drain the shared ShredQueue. On the kernel-UDP path this is
            // the only source; under AF_XDP it carries the rare non-zero-copy
            // kernel-socket shreds (turbine rides the XSK) so it is near-empty — a
            // brief mutex touch only when this worker has spare batch room.
            if (popped < batch_buf.len) {
                popped += self.queue.popBatch(batch_buf[popped..]);
            }

            if (popped == 0) {
                if (my_ring != null) {
                    // AF_XDP idle: poll-when-empty (fully lock-free, no condvar).
                    // Under load the ring is never empty so this never fires; when
                    // caught up a 50µs nap keeps the dedicated core from spinning
                    // hot while staying sub-ms responsive to the next shred.
                    std.Thread.sleep(idle_nap_ns);
                    idle_nap_ns = @min(idle_nap_ns *| 2, MAX_IDLE_NAP_NS);
                } else {
                    // Kernel-UDP: block on the condvar (10ms timeout to re-check running).
                    self.queue.waitForData(10 * std.time.ns_per_ms);
                }
                continue;
            }

            // Work arrived → reset the idle backoff to the responsive floor.
            idle_nap_ns = MIN_IDLE_NAP_NS;

            // Verify each shred
            var verified_count: usize = 0;

            for (batch_buf[0..popped]) |*entry| {
                const is_zero_copy = entry.is_zero_copy;
                const payload = if (is_zero_copy) entry.frame_ref.?.data[0..entry.frame_ref.?.len] else entry.data[0..entry.len];

                // Re-clear the entry for the next use
                entry.is_zero_copy = false;

                // Parse shred header
                const shred = shred_mod.parseShred(payload) catch {
                    _ = self.stats.parse_errors.fetchAdd(1, .monotonic);
                    if (is_zero_copy and entry.fm_ptr != 0) {
                        const fm: *@import("af_xdp/socket.zig").UmemFrameManager = @ptrFromInt(entry.fm_ptr);
                        fm.release(entry.frame_ref.?.frame_addr);
                    }
                    continue;
                };

                // DIAGNOSTIC (2026-06-15): checksum the frame bytes NOW (as parsed +
                // about to be verified). insertFrameWithFec re-checks at the copy point;
                // a mismatch proves the umem frame was overwritten mid-worker-processing
                // (the zero-copy tip-divergence / bug#2 race). Only meaningful zc-side.
                const verified_cksum: u64 = if (is_zero_copy) std.hash.Wyhash.hash(0, shred.payload) else 0;

                // Leader lookup (cached per slot — ~400 shreds per slot)
                const slot = shred.slot();

                // Update max_slot_seen for repair system (moved from main recv loop)
                if (slot < 1_000_000_000) {
                    var current_max = self.tvu_stats.max_slot_seen.load(.monotonic);
                    while (slot > current_max) {
                        const cmpxchg_result = self.tvu_stats.max_slot_seen.cmpxchgWeak(current_max, slot, .monotonic, .monotonic);
                        if (cmpxchg_result) |val| {
                            current_max = val;
                        } else break;
                    }
                }

                var leader_pubkey = leader_cache_local.getLeader(slot, self.leader_cache);
                if (leader_pubkey == null) {
                    leader_pubkey = self.static_leader;
                }

                if (leader_pubkey) |leader| {
                    // ═══════════════════════════════════════════════
                    // THE GATE: Ed25519 signature verification
                    // This is the ONLY place shreds are verified.
                    // Invalid shreds are DROPPED — never reach assembler.
                    // ═══════════════════════════════════════════════
                    // When -Dfec_dedup is OFF (default), the whole inner block is
                    // comptime-pruned and sig_ok == shred.verifySignature(&leader),
                    // i.e. byte-identical to the original gate.
                    const sig_ok = sig_blk: {
                        if (comptime fec_dedup_built) {
                            if (fec_dedup_active and shred.isMerkle()) {
                                // Reconstruct this shred's merkle root (the signed message).
                                // null ⇒ malformed proof ⇒ reject, exactly as verifySignature does.
                                const root = shred.merkleRoot() orelse break :sig_blk false;
                                const key = DedupKey{
                                    .sig = shred.common.signature.data,
                                    .pubkey = leader.data,
                                    .root = root,
                                };
                                if (sig_cache.contains(key)) {
                                    // HIT: this exact (sig, leader, root) was already
                                    // ed25519-verified by an earlier FEC-set shred. Accept.
                                    local_dedup_hits += 1;
                                    break :sig_blk true;
                                }
                                // MISS: run the canonical full verify (recomputes root + ed25519).
                                if (!shred.verifySignature(&leader)) break :sig_blk false;
                                if (sig_cache.count() >= FEC_DEDUP_CAP) sig_cache.clearRetainingCapacity();
                                sig_cache.put(key, {}) catch {}; // OOM ⇒ skip caching, still correct
                                break :sig_blk true;
                            }
                        }
                        break :sig_blk shred.verifySignature(&leader);
                    };
                    if (!sig_ok) {
                        local_rejected += 1;
                        if (@mod(local_rejected, 500) == 0) {
                            std.log.warn("[VerifyTile-{d}] Rejected shred: slot={d} idx={d} (total_rejected={d})", .{
                                worker_id, slot, shred.index(), local_rejected,
                            });
                        }
                        if (is_zero_copy and entry.fm_ptr != 0) {
                            const fm: *@import("af_xdp/socket.zig").UmemFrameManager = @ptrFromInt(entry.fm_ptr);
                            fm.release(entry.frame_ref.?.frame_addr);
                        }
                        continue; // DROP — do not insert
                    }

                    // Report to consensus tracker (TODO: Implement actual ConsensusTracker interface)
                    if (self.consensus_tracker) |_| {
                        // tracker.report(slot, .received);
                        // tracker.report(slot, .verified);
                    }

                    local_verified += 1;
                    if (comptime fec_dedup_built) {
                        if (fec_dedup_active and @mod(local_verified, 50000) == 0) {
                            std.log.info("[VerifyTile-{d}] FEC-dedup: verified={d} ed25519_skipped(hits)={d} cache_sz={d}", .{
                                worker_id, local_verified, local_dedup_hits, sig_cache.count(),
                            });
                        }
                    }
                } else {
                    // No leader known for this slot — accept the shred.
                    // During early bootstrap or epoch transitions, the leader
                    // schedule may not yet cover this slot. Accepting is safe
                    // because replay will validate the full block anyway.
                    _ = self.stats.no_leader.fetchAdd(1, .monotonic);
                }

                // ── Agave should_discard_shred / Firedancer fd_fec_resolver.c:544 ──
                // Canonical port of check_last_data_shred_index
                // (agave-4.1.0-beta.1 ledger/src/shred/filter.rs:344-349,
                // UNCONDITIONAL — not feature-gated) and FD fd_fec_resolver.c:544
                // ((1+idx) % FD_FEC_SHRED_CNT != 0). In the merkle shred format EVERY
                // FEC set, including the final one, holds exactly 32 data shreds —
                // the producer PADS the remainder set up to 32 (Agave merkle.rs:1225
                // `.chain(repeat(&[][..])).take(DATA_SHREDS_PER_FEC_BLOCK)`; FD
                // fd_shredder.c:169 fixed 32). So a DATA shred carrying the
                // LAST_IN_SLOT / SLOT_COMPLETE flag is canonical ONLY at a 32-boundary
                // ((index+1) % 32 == 0). An off-boundary last-flag is structurally
                // impossible on an honest block (spurious / equivocated / corrupt);
                // BOTH clients DISCARD the shred outright — never into the FEC set,
                // never into the block. We do the same here at the canonical ingress
                // filter point (after Ed25519 sigverify, before the assembler/FEC),
                // matching Agave/FD byte-for-byte. This is THE fix for the recurring
                // TooFewTicks dead-slot: an off-boundary last (e.g. slot 413204194,
                // 0xC0 at idx 258, real last 287) previously sealed a short last_index
                // → 61-tick premature freeze → tick-gate markSlotDead → fork-choice
                // collapse → delinquent. Discarding it keeps the slot incomplete so
                // repair/turbine fetch the true tail (259..287) and it freezes at the
                // full tick count == canonical.
                if (shred.isData() and shred.isLastInSlot() and
                    (shred.index() + 1) % shred_mod.ShredAssembler.SlotAssembly.DATA_SHREDS_PER_FEC_BLOCK != 0)
                {
                    local_fec_discarded += 1;
                    local_rejected += 1; // accounted as a rejection in stats
                    // Positive-assertion log (advisor): a real off-boundary event is
                    // rare (~1/hr live). Soak success = this fired ≥1× AND the slot
                    // later FROZE. First occurrence always logged, then rate-limited.
                    if (local_fec_discarded == 1 or @mod(local_fec_discarded, 100) == 0) {
                        std.log.warn("[FEC-BOUNDARY-DISCARD] worker={d} slot={d} idx={d}: off-boundary LAST_IN_SLOT ((idx+1)%32={d}≠0) discarded (Agave filter.rs:344 / FD fd_fec_resolver:544); repair fetches tail (total={d})", .{
                            worker_id, slot, shred.index(), (shred.index() + 1) % 32, local_fec_discarded,
                        });
                    }
                    if (is_zero_copy and entry.fm_ptr != 0) {
                        const fm: *@import("af_xdp/socket.zig").UmemFrameManager = @ptrFromInt(entry.fm_ptr);
                        fm.release(entry.frame_ref.?.frame_addr);
                    }
                    continue; // DROP — never reaches FEC or assembler
                }

                // ── SIMD-0337 discard_unexpected_data_complete_shreds (TURBINE) ──
                // Agave should_discard_shred DATA_COMPLETE block (filter.rs:327-342)
                // + epoch-delayed check_feature_activation (filter.rs:390-402),
                // applied here at the canonical turbine ingress filter point (after
                // sigverify, before FEC/assembler), mirroring the REPAIR-path hook
                // in tvu.zig:processShred. A DATA shred with DATA_COMPLETE (0x40)
                // at an index other than fec_set_index+31 is "unexpected"; it is
                // DISCARDED only once the feature is EFFECTIVE for the shred's slot
                // (one full epoch after activation — NOT per-slot, so the gate does
                // not fire during the activation epoch and cannot fork). This
                // BROADENS the LAST_IN_SLOT discard above (0xC0) to mid-slot
                // batch-complete (0x40-alone) shreds, exactly as Agave.
                //
                // Feature access: the verify tile reaches the root bank via
                // tvu_ref → replay_stage → root_bank (the same precedent
                // tvu.zig:processShred uses). DEFAULT-KEEP on every uncertain path:
                // no tvu_ref / no replay_stage / no root bank / feature absent or
                // not yet epoch-effective → fall through and insert. Never
                // over-discards. Coding shreds are exempt (isUnexpectedDataComplete
                // → false via its isData guard).
                if (shred_mod.isUnexpectedDataComplete(&shred)) {
                    var simd0337_discard = false;
                    if (self.tvu_ref) |tvu| {
                        if (tvu.slot_sink) |rs| {
                            if (rs.rootBank()) |rb| {
                                simd0337_discard = rb.discardUnexpectedDataCompleteEffective(shred.slot());
                            }
                        }
                    }
                    if (simd0337_discard) {
                        local_fec_discarded += 1;
                        local_rejected += 1;
                        if (local_fec_discarded == 1 or @mod(local_fec_discarded, 100) == 0) {
                            std.log.warn("[SIMD0337-DISCARD] worker={d} slot={d} idx={d} fec_set={d}: unexpected DATA_COMPLETE discarded (Agave filter.rs:330; expected idx={d}, total={d})", .{
                                worker_id, slot, shred.index(), shred.fecSetIndex(), shred.fecSetIndex() + 31, local_fec_discarded,
                            });
                        }
                        if (is_zero_copy and entry.fm_ptr != 0) {
                            const fm: *@import("af_xdp/socket.zig").UmemFrameManager = @ptrFromInt(entry.fm_ptr);
                            fm.release(entry.frame_ref.?.frame_addr);
                        }
                        continue; // DROP — never reaches FEC or assembler
                    }
                }

                // Shred passed verification (or was accepted without leader)
                if (is_zero_copy) {
                    // Net-tile Stage 2 (2026-06-14): FEC + chain observation moved
                    // OFF the recv thread (core 4) onto this worker. The recv path
                    // used to call fec_resolver.addShred + observeChainForShred
                    // per shred inline (the residual recv stall); it now only
                    // version-filters + submits to the ring. insertFrameWithFec
                    // does the FEC (data AND coding), the recovered-shred pull, the
                    // chain observation (chain_mutex-guarded — 8 workers race it
                    // now), and releases the UMEM frame on every exit path (the
                    // Task #72 copy-on-receive release). Replaces insertFrame,
                    // which did assembly-copy ONLY (no FEC, no coding handling,
                    // no chain). The worker already parsed `shred`, so pass it
                    // (the ring-carried zc_index/zc_is_last were data-shred
                    // vestigial and are no longer used — insertFrameWithFec reads
                    // the parsed shred's own fields, which is also correct for
                    // coding shreds, which now flow through here too).
                    // RESTORE r49-B-rev-fix-2 on the zc single-shred FEC path: c529159
                    // ("net-tile Stage 2") switched this site from insertFrame to
                    // insertFrameWithFec (which RETURNS .completed_slot on FEC recovery)
                    // but DISCARDED the result and never ported the dispatchCompletedSlot
                    // call its two sibling sites carry (batch path :679-684, recv path
                    // tvu.zig:1233-1246). Result under AF_XDP: every FEC-RECOVERED slot
                    // completion was orphaned — marked complete (leaves in-progress) but
                    // NEVER enqueued for replay → never froze → freeze frontier wedged at
                    // the first slot needing worker-FEC recovery (415427020). Capture the
                    // result and dispatch the completed slot, mirroring the sibling sites.
                    const ires = self.assembler.insertFrameWithFec(shred, entry.frame_ref.?, verified_cksum) catch shred_mod.ShredAssembler.InsertResult.inserted;
                    if (ires == .completed_slot) {
                        _ = self.stats.completed_slots.fetchAdd(1, .monotonic);
                        _ = self.tvu_stats.slots_completed.fetchAdd(1, .monotonic);
                        if (self.tvu_ref) |tvu| tvu.dispatchCompletedSlot(shred.slot());
                    }

                    // FIX 2026-07-07: a frame dropped on copy-time checksum mismatch
                    // (NIC recycled the UMEM frame) was never inserted — don't count
                    // it as "inserted" (the frame_overwrite_dropped counter tracks it).
                    if (ires != .dropped_frame_overwrite) {
                        _ = self.stats.inserted.fetchAdd(1, .monotonic);
                        _ = self.tvu_stats.shreds_inserted.fetchAdd(1, .monotonic);
                    }
                } else {
                    if (verified_count < 64) {
                        verified_shreds[verified_count] = shred;
                        verified_count += 1;
                    }
                }
            }

            // Batch insert verified shreds into assembler
            if (verified_count > 0) {
                const result = self.assembler.insertBatch(verified_shreds[0..verified_count]);

                // Update TVU stats (same counters the old path used)
                _ = self.tvu_stats.shreds_inserted.fetchAdd(
                    @intCast(result.inserted + result.completed_slots),
                    .monotonic,
                );
                _ = self.tvu_stats.shreds_duplicate.fetchAdd(
                    @intCast(result.duplicates),
                    .monotonic,
                );

                // Update verify tile stats
                _ = self.stats.inserted.fetchAdd(
                    @intCast(result.inserted + result.completed_slots),
                    .monotonic,
                );

                if (result.completed_slots > 0) {
                    _ = self.stats.completed_slots.fetchAdd(
                        @intCast(result.completed_slots),
                        .monotonic,
                    );
                    _ = self.tvu_stats.slots_completed.fetchAdd(
                        @intCast(result.completed_slots),
                        .monotonic,
                    );
                    // r49-B-rev-fix-2: dispatch each newly-completed slot to replay
                    // stage. Without this, slots assemble but never replay (12.1%
                    // intrinsic skip per /tmp/vexor_skip_carrier_audit.md).
                    if (self.tvu_ref) |tvu| {
                        const cap = @min(result.completed_slots, result.completed_slot_list.len);
                        for (result.completed_slot_list[0..cap]) |slot| {
                            tvu.dispatchCompletedSlot(slot);
                        }
                    }
                }
            }

            // Flush local counters to shared atomics periodically
            if (local_verified >= 100) {
                _ = self.stats.verified.fetchAdd(local_verified, .monotonic);
                local_verified = 0;
            }
            if (local_rejected >= 100) {
                _ = self.stats.rejected.fetchAdd(local_rejected, .monotonic);
                local_rejected = 0;
            }

            _ = self.stats.batches_processed.fetchAdd(1, .monotonic);
        }

        // Flush remaining counters on exit
        _ = self.stats.verified.fetchAdd(local_verified, .monotonic);
        _ = self.stats.rejected.fetchAdd(local_rejected, .monotonic);

        std.log.info("[VerifyTile] Worker {d} exiting (verified={d}, rejected={d})", .{
            worker_id,
            self.stats.verified.load(.monotonic),
            self.stats.rejected.load(.monotonic),
        });
    }
};
