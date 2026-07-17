//! Lock-free single-producer / single-consumer verify handoff ring (Option B).
//!
//! 2026-06-14 — THE AF_XDP throughput fix. The shared mutex ShredQueue convoyed the
//! recv thread: popBatch (verify_tile.zig) holds queue.mutex while bulk-copying up to
//! 64 full QueueEntry structs — and QueueEntry carries the 1232-byte `data` array even
//! on the zero-copy path where only frame_ref matters (~79 KB copied under the lock per
//! popBatch, ×8 workers). Under tip load that made recv's submitZeroCopy tryLock FAIL →
//! the drop-on-contended path DROPPED the shred → incomplete slots → chain-defer wedge →
//! delinquent. Option B retires the mutex on the hot path: N lock-free SPSC rings, one
//! per worker. Recv (the SOLE producer to the verify path — processPackets runs only on
//! the pinToCore(4) recv thread) round-robins frames into worker[i]'s ring; each worker
//! drains its OWN ring (single consumer). No shared mutex → recv NEVER contends and NEVER
//! drops on the handoff. If one worker is transiently descheduled its ring backs up while
//! recv keeps feeding the others; only when ALL rings are full do we overrun-drop
//! (turbine/repair re-fetch).
//!
//! Memory ordering mirrors the proven AF_XDP free_ring (af_xdp/socket.zig): producer
//! writes the slot then publishes head with .release; consumer reads head with .acquire
//! before the slot read, advances tail with .release; producer reads tail with .acquire
//! to test fullness. head/tail are free-running u32 (wrap via &mask) so wraparound is
//! correct as long as capacity ≤ 2^31.

const std = @import("std");

/// One zero-copy frame handed to a verify worker. SLIM (~32B) — only the UMEM frame
/// reference + shred coordinates, NEVER the 1232-byte payload (which lives in the UMEM
/// frame, referenced by frame_ref). This slimness is the whole point: it removes the
/// ~79 KB-under-lock copy that the shared QueueEntry forced.
pub const ZcRingEntry = struct {
    frame_ref: @import("af_xdp/socket.zig").UmemFrameRef,
    index: u32 = 0,
    is_last: bool = false,
    fm_ptr: usize = 0,
};

/// Default per-worker SPSC ring capacity (power of 2). 16384 × ~32B = ~512 KB per ring
/// × 8 workers = ~4 MB total (negligible vs host RAM). At ~12.5k turbine pps spread over
/// N workers each ring fills at ~1.5k/s → ~10s of cover for a single worker stall before
/// overrun — far more than any scheduling hiccup on a dedicated core.
pub const ZC_RING_CAPACITY: u32 = 16384;

pub const SpscRing = struct {
    entries: []ZcRingEntry,
    capacity: u32,
    mask: u32,
    head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // producer cursor (recv)
    tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // consumer cursor (worker)

    // Stats (monotonic; depth_max is a racy high-water mark, fine for a gauge)
    pushed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    popped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    depth_max: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, capacity: u32) !*Self {
        std.debug.assert(std.math.isPowerOfTwo(capacity));
        const ring = try allocator.create(Self);
        const entries = try allocator.alloc(ZcRingEntry, capacity);
        ring.* = Self{
            .entries = entries,
            .capacity = capacity,
            .mask = capacity - 1,
        };
        return ring;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        allocator.destroy(self);
    }

    /// PRODUCER-ONLY (the recv thread). Returns false if the ring is full — the caller
    /// decides whether to try another worker or overrun-drop. Does NOT count overrun here
    /// (a full ring is not necessarily a global drop — recv may place the frame in another
    /// worker's ring).
    pub fn tryPush(self: *Self, entry: ZcRingEntry) bool {
        const head = self.head.load(.monotonic); // producer owns head
        const tail = self.tail.load(.acquire); // observe consumer progress
        const depth = head -% tail;
        if (depth >= self.capacity) return false; // full
        self.entries[head & self.mask] = entry;
        self.head.store(head +% 1, .release); // publish the slot write
        _ = self.pushed.fetchAdd(1, .monotonic);
        const d = depth + 1;
        if (d > self.depth_max.load(.monotonic)) self.depth_max.store(d, .monotonic);
        return true;
    }

    /// CONSUMER-ONLY (this ring's one verify worker). Returns false if empty.
    pub fn tryPop(self: *Self, out: *ZcRingEntry) bool {
        const tail = self.tail.load(.monotonic); // consumer owns tail
        const head = self.head.load(.acquire); // observe producer publish
        if (head == tail) return false; // empty
        out.* = self.entries[tail & self.mask];
        self.tail.store(tail +% 1, .release);
        _ = self.popped.fetchAdd(1, .monotonic);
        return true;
    }

    pub fn len(self: *const Self) u32 {
        return self.head.load(.monotonic) -% self.tail.load(.monotonic);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// KATs — run with: zig build test-verify-ring
// ═══════════════════════════════════════════════════════════════════════════════

fn testEntry(addr: u64) ZcRingEntry {
    // Frame conservation in the ring is keyed on frame_addr (the UMEM offset that must
    // be released to the fill ring exactly once). `data` is irrelevant to the ring
    // contract, so a zero-length slice is fine for the unit test.
    return .{ .frame_ref = .{ .frame_addr = addr, .data = &[_]u8{}, .len = 0 }, .index = @intCast(addr & 0xffff_ffff), .is_last = false, .fm_ptr = 0 };
}

test "SpscRing: fill/drain FIFO, full→false, empty→false" {
    const a = std.testing.allocator;
    const cap: u32 = 8;
    const ring = try SpscRing.init(a, cap);
    defer ring.deinit(a);

    // Empty → pop fails.
    var out: ZcRingEntry = undefined;
    try std.testing.expect(!ring.tryPop(&out));

    // Fill to capacity.
    var i: u64 = 0;
    while (i < cap) : (i += 1) try std.testing.expect(ring.tryPush(testEntry(1000 + i)));
    try std.testing.expectEqual(@as(u32, cap), ring.len());

    // Full → push fails (no overwrite).
    try std.testing.expect(!ring.tryPush(testEntry(9999)));

    // Drain in FIFO order.
    i = 0;
    while (i < cap) : (i += 1) {
        try std.testing.expect(ring.tryPop(&out));
        try std.testing.expectEqual(@as(u64, 1000 + i), out.frame_ref.frame_addr);
    }
    try std.testing.expectEqual(@as(u32, 0), ring.len());
    try std.testing.expect(!ring.tryPop(&out));
}

test "SpscRing: wraparound preserves FIFO + no loss over many cycles" {
    const a = std.testing.allocator;
    const cap: u32 = 16;
    const ring = try SpscRing.init(a, cap);
    defer ring.deinit(a);

    // Push 3, pop 2 each round, repeated — exercises head/tail wrap (&mask) and the
    // depth arithmetic. Net depth grows by 1 each round until it would exceed cap, then
    // pushes start failing (we re-pop the backlog at the end).
    var next_push: u64 = 0;
    var next_expect: u64 = 0;
    var round: u64 = 0;
    while (round < 100_000) : (round += 1) {
        var p: u32 = 0;
        while (p < 3) : (p += 1) {
            if (ring.tryPush(testEntry(next_push))) next_push += 1;
        }
        var q: u32 = 0;
        var out: ZcRingEntry = undefined;
        while (q < 2) : (q += 1) {
            if (ring.tryPop(&out)) {
                try std.testing.expectEqual(next_expect, out.frame_ref.frame_addr);
                next_expect += 1;
            }
        }
        try std.testing.expect(ring.len() <= cap);
    }
    // Drain the remainder; total popped must equal total pushed (no loss/dup).
    var out: ZcRingEntry = undefined;
    while (ring.tryPop(&out)) {
        try std.testing.expectEqual(next_expect, out.frame_ref.frame_addr);
        next_expect += 1;
    }
    try std.testing.expectEqual(next_push, next_expect); // conservation
    try std.testing.expectEqual(ring.pushed.load(.monotonic), ring.popped.load(.monotonic));
}

test "SpscRing: threaded producer/consumer — every frame delivered exactly once" {
    const a = std.testing.allocator;
    const cap: u32 = 1024;
    const ring = try SpscRing.init(a, cap);
    defer ring.deinit(a);

    const N: u64 = 1_000_000;

    const Consumer = struct {
        fn run(r: *SpscRing, n: u64, seen_sum: *u64, count: *u64) void {
            var got: u64 = 0;
            var sum: u64 = 0;
            var out: ZcRingEntry = undefined;
            while (got < n) {
                if (r.tryPop(&out)) {
                    sum +%= out.frame_ref.frame_addr;
                    got += 1;
                } else {
                    std.atomic.spinLoopHint();
                }
            }
            seen_sum.* = sum;
            count.* = got;
        }
    };

    var seen_sum: u64 = 0;
    var count: u64 = 0;
    const t = try std.Thread.spawn(.{}, Consumer.run, .{ ring, N, &seen_sum, &count });

    // Producer: push 0..N-1, retrying (spin) when the ring is full.
    var i: u64 = 0;
    while (i < N) {
        if (ring.tryPush(testEntry(i))) {
            i += 1;
        } else {
            std.atomic.spinLoopHint();
        }
    }
    t.join();

    // Conservation: exactly N delivered, and the sum of frame_addrs == 0+1+..+N-1 (proves
    // no loss, no duplication, no corruption across the lock-free boundary).
    try std.testing.expectEqual(N, count);
    try std.testing.expectEqual(N * (N - 1) / 2, seen_sum);
    try std.testing.expectEqual(N, ring.pushed.load(.monotonic));
    try std.testing.expectEqual(N, ring.popped.load(.monotonic));
}

test "round-robin handoff: spreads across rings, overrun only when ALL full" {
    const a = std.testing.allocator;
    const n: u32 = 4;
    const rings = try a.alloc(*SpscRing, n);
    for (rings) |*r| r.* = try SpscRing.init(a, 2); // tiny cap=2 → 8 total slots
    defer {
        for (rings) |r| r.deinit(a);
        a.free(rings);
    }

    var rr: u32 = 0;
    var overrun: u64 = 0;
    // Mirrors exactly VerifyTile.submitZeroCopyRing: try rings[(rr+t)%n] for t in 0..n;
    // first success advances rr; all-full → overrun-drop.
    const submit = struct {
        fn go(rs: []*SpscRing, cur: *u32, ovr: *u64, addr: u64) bool {
            const nn: u32 = @intCast(rs.len);
            var t: u32 = 0;
            while (t < nn) : (t += 1) {
                const w = (cur.* + t) % nn;
                if (rs[w].tryPush(testEntry(addr))) {
                    cur.* = (w + 1) % nn;
                    return true;
                }
            }
            cur.* = (cur.* + 1) % nn;
            ovr.* += 1;
            return false;
        }
    }.go;

    // 8 submits fill all 4 rings (2 each) — every one accepted.
    var k: u64 = 0;
    while (k < 8) : (k += 1) try std.testing.expect(submit(rings, &rr, &overrun, k));
    for (rings) |r| try std.testing.expectEqual(@as(u32, 2), r.len());
    // 9th: all rings full → overrun-drop.
    try std.testing.expect(!submit(rings, &rr, &overrun, 99));
    try std.testing.expectEqual(@as(u64, 1), overrun);
}
