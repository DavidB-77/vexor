//! wave_pool.zig — persistent worker pool for wave-barrier parallel tx execution.
//!
//! Stage B (parallel-exec) primitive. See VEXOR-PARALLEL-EXEC-PORT-PLAN-2026-06-22.md.
//!
//! WHY THIS EXISTS
//! ───────────────
//! The replay Phase-2 execute loop (`while (disp.getNextReady()) |txn_idx|`,
//! replay_stage.zig:6093) dispatches conflict-free transactions one at a time on the
//! replay thread. The conflict DAG (tx_dispatcher.zig, an fd_rdisp port) guarantees
//! that all txns with `in_degree==0` at any instant have DISJOINT write sets, so they
//! can execute concurrently and commit deterministically (B0 finding: lthash is a
//! commutative freeze-time fold, so wave-order merge is byte-exact vs serial).
//!
//! This pool is the execution substrate for that: a FIXED set of OS threads, each
//! pinned to a configured core and each owning its OWN ArenaAllocator (B0 seam #6 —
//! the slot-wide `batch_arena` is shared + NOT thread-safe; per-worker arenas remove
//! that race). The pool persists across waves AND across slots (spawn cost paid once).
//!
//! MODEL (a SAFE simplification of FD's continuous async execrp dispatch):
//!   main: collect ready set → dispatchWave(items) → [workers execute] → BARRIER →
//!         main merges per-worker write buffers in wave order → completeTxn the wave.
//! The barrier makes the parallel path trivially provable bank-exact (no continuous
//! in-flight reordering to reason about). Continuous dispatch is a later optimization
//! ONLY if the barrier proves to be the bottleneck.
//!
//! CONCURRENCY DESIGN (generation counter + WaitGroup barrier — the safe pattern):
//!   - Workers sleep on `work_cond` until `generation` advances (or shutdown).
//!   - dispatchWave bumps `generation` (under mutex) and broadcasts; workers wake,
//!     work-steal items via an atomic claim index, run the callback, then each locks
//!     the mutex to decrement `active_workers` and (last one) signals `done_cond`.
//!   - main waits on `done_cond` until `active_workers == 0`.
//!   - Every worker AND main lock the SAME mutex around their completion bookkeeping,
//!     so the mutex acquire/release chain establishes happens-before from EVERY
//!     worker's writes to main after dispatchWave returns. (A bare atomic on the
//!     done-count would only synchronize main with the LAST worker — insufficient
//!     for the merge, which must see all workers' buffers.)
//!
//! WHAT THIS MODULE DOES NOT DO (caller's responsibility, in B2 wiring):
//!   - Setting the threadlocal `bank_mod.worker_writes_override` per worker (the
//!     callback does that, so writes land in the worker's own buffer not pending_writes).
//!   - Keeping cost accounting sequential (B0 seam #7) and the recorder off (seam #8).
//!   - The actual merge of per-worker buffers into bank.pending_writes in wave order.

const std = @import("std");
const builtin = @import("builtin");

/// Pin the calling thread to `core_id` via sched_setaffinity (Linux). Best-effort:
/// a failed syscall (invalid core, non-Linux) is silently ignored — pinning is an
/// optimization, never a correctness requirement. Mirrors replay_stage.zig:132.
fn pinToCore(core_id: u32) void {
    if (builtin.os.tag != .linux) return;
    var cpu_set = [_]usize{0} ** 16;
    const idx = core_id / @bitSizeOf(usize);
    const bit: u6 = @intCast(core_id % @bitSizeOf(usize));
    cpu_set[idx] = @as(usize, 1) << bit;
    _ = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
}

/// Type-erased per-item work callback. Runs on a worker thread.
///   ctx        — opaque pointer to caller state (cast back inside the callback).
///   worker_idx — 0..n_workers-1, stable for the life of the pool. The callback uses
///                this to select its own per-worker write buffer.
///   arena      — this worker's PRIVATE arena allocator. CORRECTED LIFETIME (2026-06-22,
///                advisor #4): the native executors allocate their AccountWrite.data
///                payloads from THIS allocator (the passed `alloc`), NOT bank.allocator —
///                exactly like the serial path's batch_arena. So these payloads MUST
///                survive the barrier-merge AND remain valid until the per-call
///                flushPendingWritesToDb deep-copies them; the arena is reset only AFTER
///                that flush (see resetArenas). Per-item transient scratch lives here too.
///   item_idx   — 0..n_items-1 for this wave; the callback indexes its own ready[] with it.
pub const WorkFn = *const fn (ctx: *anyopaque, worker_idx: usize, arena: std.mem.Allocator, item_idx: usize) void;

pub const WavePool = struct {
    allocator: std.mem.Allocator,
    threads: []std.Thread,
    arenas: []std.heap.ArenaAllocator,
    cores: []u32, // owned copy; cores[i] is worker i's pinned core
    n_workers: usize,

    mutex: std.Thread.Mutex = .{},
    work_cond: std.Thread.Condition = .{}, // workers wait here for a new wave
    done_cond: std.Thread.Condition = .{}, // main waits here for wave completion

    // Wave state — all written under `mutex` at dispatch, read by workers after they
    // observe a generation change (also under mutex), so they are stable for the wave.
    generation: u64 = 0,
    shutdown: bool = false,
    n_items: usize = 0,
    ctx: ?*anyopaque = null,
    callback: ?WorkFn = null,

    // Work-stealing claim index + completion barrier counter.
    next_item: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    active_workers: usize = 0, // protected by mutex

    const Self = @This();

    /// Spawn a worker per entry in `cores`. Each worker pins to its core and owns an
    /// arena backed by page_allocator. Caller owns the returned pool (call deinit).
    pub fn init(allocator: std.mem.Allocator, cores: []const u32) !*Self {
        std.debug.assert(cores.len > 0);
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const cores_copy = try allocator.dupe(u32, cores);
        errdefer allocator.free(cores_copy);

        const arenas = try allocator.alloc(std.heap.ArenaAllocator, cores.len);
        errdefer allocator.free(arenas);
        for (arenas) |*a| a.* = std.heap.ArenaAllocator.init(std.heap.page_allocator);

        const threads = try allocator.alloc(std.Thread, cores.len);
        errdefer allocator.free(threads);

        self.* = .{
            .allocator = allocator,
            .threads = threads,
            .arenas = arenas,
            .cores = cores_copy,
            .n_workers = cores.len,
        };

        // Spawn workers. If a spawn fails midway, signal shutdown + join the ones we
        // started so we never leak running threads.
        var spawned: usize = 0;
        errdefer {
            self.mutex.lock();
            self.shutdown = true;
            self.work_cond.broadcast();
            self.mutex.unlock();
            for (0..spawned) |i| self.threads[i].join();
            for (arenas) |*a| a.deinit();
        }
        while (spawned < cores.len) : (spawned += 1) {
            self.threads[spawned] = try std.Thread.spawn(.{}, workerLoop, .{ self, spawned });
        }

        return self;
    }

    /// Signal shutdown, join all workers, free arenas + buffers. Idempotent-safe only
    /// once (do not call twice).
    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        self.shutdown = true;
        self.work_cond.broadcast();
        self.mutex.unlock();
        for (self.threads) |t| t.join();
        for (self.arenas) |*a| a.deinit();
        self.allocator.free(self.threads);
        self.allocator.free(self.arenas);
        self.allocator.free(self.cores);
        self.allocator.destroy(self);
    }

    /// Reset every worker's arena (retain capacity). Call ONCE per replayEntriesInternal
    /// call, AFTER flushPendingWritesToDb — NEVER between waves or between entries within a
    /// call. CORRECTED LIFETIME (2026-06-22, advisor #4): wave-executed AccountWrite.data
    /// payloads are allocated from the worker arena (the executors use the passed allocator,
    /// not bank.allocator), so they remain referenced from bank.pending_writes until the
    /// per-call flush deep-copies them. Resetting earlier would be a use-after-free. Mirrors
    /// the serial path's `defer batch_arena.deinit()` timing (flush, then drop the arena).
    pub fn resetArenas(self: *Self) void {
        for (self.arenas) |*a| _ = a.reset(.retain_capacity);
    }

    /// Run `n_items` work items across the pool and BLOCK until all complete. After
    /// return, every worker's writes are visible to the caller (full barrier via the
    /// shared mutex). `ctx` + `callback` are borrowed for the duration of the call.
    /// n_items == 0 returns immediately (no wave dispatched).
    pub fn dispatchWave(self: *Self, ctx: *anyopaque, n_items: usize, callback: WorkFn) void {
        if (n_items == 0) return;

        self.mutex.lock();
        self.ctx = ctx;
        self.callback = callback;
        self.n_items = n_items;
        self.next_item.store(0, .monotonic);
        self.active_workers = self.n_workers;
        self.generation +%= 1;
        self.work_cond.broadcast();

        // Barrier: wait until every worker has finished draining and decremented.
        while (self.active_workers != 0) {
            self.done_cond.wait(&self.mutex);
        }
        self.mutex.unlock();
    }

    fn workerLoop(self: *Self, worker_idx: usize) void {
        pinToCore(self.cores[worker_idx]);
        const arena = self.arenas[worker_idx].allocator();
        var last_gen: u64 = 0;

        while (true) {
            // Wait for a new wave (generation advance) or shutdown.
            self.mutex.lock();
            while (self.generation == last_gen and !self.shutdown) {
                self.work_cond.wait(&self.mutex);
            }
            if (self.shutdown) {
                self.mutex.unlock();
                return;
            }
            last_gen = self.generation;
            const ctx = self.ctx.?;
            const cb = self.callback.?;
            const n_items = self.n_items;
            self.mutex.unlock();

            // Work-steal: claim items until exhausted. fetchAdd is the only
            // contention point during the wave; the callback runs lock-free.
            while (true) {
                const i = self.next_item.fetchAdd(1, .monotonic);
                if (i >= n_items) break;
                cb(ctx, worker_idx, arena, i);
            }

            // Completion barrier: decrement under the mutex so main (which also locks)
            // observes a happens-before with THIS worker's callback writes.
            self.mutex.lock();
            self.active_workers -= 1;
            if (self.active_workers == 0) self.done_cond.signal();
            self.mutex.unlock();
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// KAT — standalone correctness tests (no replay, no bank). Build: test-wave-pool.
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

// Shared test context for the simple "each item runs exactly once" check.
const CountCtx = struct {
    hits: []std.atomic.Value(u32), // per-item hit count
    total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    worker_seen: []std.atomic.Value(u32), // per-worker item count
};

fn countCb(ctx_ptr: *anyopaque, worker_idx: usize, arena: std.mem.Allocator, item_idx: usize) void {
    const ctx: *CountCtx = @ptrCast(@alignCast(ctx_ptr));
    // Touch the arena to exercise per-worker allocation isolation.
    const buf = arena.alloc(u8, 64) catch unreachable;
    @memset(buf, @intCast(item_idx & 0xff));
    std.debug.assert(buf[0] == @as(u8, @intCast(item_idx & 0xff)));
    _ = ctx.hits[item_idx].fetchAdd(1, .acq_rel);
    _ = ctx.total.fetchAdd(1, .acq_rel);
    _ = ctx.worker_seen[worker_idx].fetchAdd(1, .acq_rel);
}

test "wave_pool: each item runs exactly once, single wave" {
    const alloc = testing.allocator;
    const cores = [_]u32{ 1, 2, 3, 1 }; // 4 workers (pinning best-effort)
    const pool = try WavePool.init(alloc, &cores);
    defer pool.deinit();

    const N = 1000;
    const hits = try alloc.alloc(std.atomic.Value(u32), N);
    defer alloc.free(hits);
    for (hits) |*h| h.* = std.atomic.Value(u32).init(0);
    const wseen = try alloc.alloc(std.atomic.Value(u32), cores.len);
    defer alloc.free(wseen);
    for (wseen) |*w| w.* = std.atomic.Value(u32).init(0);

    var ctx = CountCtx{ .hits = hits, .worker_seen = wseen };
    pool.dispatchWave(@ptrCast(&ctx), N, countCb);

    // Every item exactly once.
    for (hits) |*h| try testing.expectEqual(@as(u32, 1), h.load(.acquire));
    try testing.expectEqual(@as(u64, N), ctx.total.load(.acquire));
    // Work was distributed (each worker did >0 of 1000 items — overwhelmingly likely).
    var distributed: usize = 0;
    for (wseen) |*w| {
        if (w.load(.acquire) > 0) distributed += 1;
    }
    try testing.expect(distributed >= 2);
}

test "wave_pool: many waves reuse the same threads (persistent), counts exact" {
    const alloc = testing.allocator;
    const cores = [_]u32{ 1, 2, 3 };
    const pool = try WavePool.init(alloc, &cores);
    defer pool.deinit();

    const N = 200;
    const hits = try alloc.alloc(std.atomic.Value(u32), N);
    defer alloc.free(hits);
    const wseen = try alloc.alloc(std.atomic.Value(u32), cores.len);
    defer alloc.free(wseen);
    for (wseen) |*w| w.* = std.atomic.Value(u32).init(0);

    const WAVES = 50;
    var ctx = CountCtx{ .hits = hits, .worker_seen = wseen };
    for (0..WAVES) |_| {
        for (hits) |*h| h.* = std.atomic.Value(u32).init(0);
        pool.resetArenas();
        pool.dispatchWave(@ptrCast(&ctx), N, countCb);
        for (hits) |*h| try testing.expectEqual(@as(u32, 1), h.load(.acquire));
    }
    try testing.expectEqual(@as(u64, N * WAVES), ctx.total.load(.acquire));
}

test "wave_pool: empty wave is a no-op, does not hang" {
    const alloc = testing.allocator;
    const cores = [_]u32{ 1, 2 };
    const pool = try WavePool.init(alloc, &cores);
    defer pool.deinit();

    var hits = [_]std.atomic.Value(u32){};
    var wseen = [_]std.atomic.Value(u32){ std.atomic.Value(u32).init(0), std.atomic.Value(u32).init(0) };
    var ctx = CountCtx{ .hits = hits[0..], .worker_seen = wseen[0..] };
    pool.dispatchWave(@ptrCast(&ctx), 0, countCb); // must return immediately
    try testing.expectEqual(@as(u64, 0), ctx.total.load(.acquire));
}

// Barrier-publish test: each item is written by exactly one worker into a PLAIN
// (non-atomic) slot; main reads every slot AFTER the barrier. This validates the
// property the B2 merge depends on — that dispatchWave's return establishes
// happens-before from ALL workers' writes to main (not just the last worker). A
// broken barrier would surface as a stale/zero slot. Repeated over many waves to
// shake out scheduling races.
const PublishCtx = struct {
    out: []u64, // plain, non-atomic — written by one worker per index, read by main post-barrier
    base: u64,
};

fn publishCb(ctx_ptr: *anyopaque, worker_idx: usize, arena: std.mem.Allocator, item_idx: usize) void {
    _ = worker_idx;
    _ = arena;
    const ctx: *PublishCtx = @ptrCast(@alignCast(ctx_ptr));
    ctx.out[item_idx] = ctx.base +% (@as(u64, item_idx) *% 0x9E3779B97F4A7C15); // deterministic per-item value
}

test "wave_pool: barrier publishes ALL worker writes (non-atomic), many waves" {
    const alloc = testing.allocator;
    const cores = [_]u32{ 1, 2, 3, 1, 2 }; // 5 workers
    const pool = try WavePool.init(alloc, &cores);
    defer pool.deinit();

    const N = 777;
    const out = try alloc.alloc(u64, N);
    defer alloc.free(out);

    const WAVES = 100;
    for (0..WAVES) |w| {
        @memset(out, 0); // poison: any unwritten slot stays 0
        var ctx = PublishCtx{ .out = out, .base = @as(u64, w) *% 0x100000001B3 +% 1 };
        pool.dispatchWave(@ptrCast(&ctx), N, publishCb);
        // Every slot must hold this wave's expected value — no stragglers, no stale reads.
        for (out, 0..) |v, i| {
            const expect = ctx.base +% (@as(u64, i) *% 0x9E3779B97F4A7C15);
            try testing.expectEqual(expect, v);
        }
    }
}

test "wave_pool: single worker still runs all items (degenerate pool)" {
    const alloc = testing.allocator;
    const cores = [_]u32{1};
    const pool = try WavePool.init(alloc, &cores);
    defer pool.deinit();

    const N = 64;
    const hits = try alloc.alloc(std.atomic.Value(u32), N);
    defer alloc.free(hits);
    for (hits) |*h| h.* = std.atomic.Value(u32).init(0);
    var wseen = [_]std.atomic.Value(u32){std.atomic.Value(u32).init(0)};
    var ctx = CountCtx{ .hits = hits, .worker_seen = wseen[0..] };
    pool.dispatchWave(@ptrCast(&ctx), N, countCb);
    for (hits) |*h| try testing.expectEqual(@as(u32, 1), h.load(.acquire));
    try testing.expectEqual(@as(u64, N), wseen[0].load(.acquire));
}
