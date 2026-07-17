//! Geyser-style streaming plugin sink (Vexor-native).
//!
//! Streams replay-side notifications (Stage 1a: slot status; Stage 1b: account updates) to an
//! external consumer over a unix-domain socket, in length-prefixed binary frames. Modeled on Agave's
//! GeyserPlugin callback surface (slot status / account update / tx / block-meta) but Zig-native and
//! structurally decoupled from consensus.
//!
//! ── Consensus-safety (the load-bearing rule) ────────────────────────────────────────────────────
//! The whole module is comptime-gated behind `build_options.geyser`. With `-Dgeyser` OFF the hooks are
//! comptime-dead → the replay/freeze/root path is byte-for-byte the proven binary (same proof the
//! rpc_store gate carries). With it ON, every producer call (on the replay thread, core 16) does ONLY
//! a wait-free enqueue and returns — it never serializes, never does socket I/O, never blocks. The ring
//! is bounded; on full it DROPS the event (a streaming-quality concern) rather than ever stalling
//! replay. All serialization + socket I/O happen on a dedicated consumer thread pinned to cold CCX0
//! (core 2), disjoint from every hot tile (recv4/quic6/verify8-15/replay16/produce20/gossip24/repair30/
//! txsend28/sysvar29), so streaming can neither CPU-preempt nor back-pressure consensus.
//!
//! Stage 1a (this file) wires SLOT events only (low-frequency ~2.5/s → per-event alloc is negligible and
//! the ring never fills). Account events (Stage 1b) need an owned-copy pool to stay alloc-free on the
//! hot path and are declared but not yet pushed.

const std = @import("std");

/// Canonical-ish slot status (mirrors Agave gossip SlotStatus ordering for the common cases).
pub const SlotStatus = enum(u8) {
    processed = 0, // bank frozen
    confirmed = 1, // optimistic / duplicate-confirmed (Stage 3)
    rooted = 2, // tower supermajority root advanced
    dead = 3, // slot marked dead
    first_shred = 4,
    completed = 5,
    created_bank = 6,
};

/// A streamed event. Owned (deep-copied) at enqueue time so the producer's slot-arena pointers can die
/// without affecting the queued event. Slot events carry no heap data; account events (Stage 1b) will.
pub const GeyserEvent = union(enum) {
    slot: struct {
        slot: u64,
        parent: u64,
        has_parent: bool,
        status: SlotStatus,
    },
    // Stage 1b (declared, not yet pushed): owned account update.
    account: struct {
        slot: u64,
        pubkey: [32]u8,
        lamports: u64,
        owner: [32]u8,
        executable: bool,
        rent_epoch: u64,
        write_version: u64,
        data: []u8, // owned; freed by the consumer after serialization
    },
};

/// Wait-free single-producer/single-consumer ring of owned `*GeyserEvent`. Clone of the proven
/// spsc_ring.zig algorithm (monotonic head/tail, power-of-two mask). Producer = replay thread;
/// consumer = the cold-core geyser thread. `tryPush` returns false when full (caller drops + frees).
const EventRing = struct {
    entries: []?*GeyserEvent,
    mask: u32,
    capacity: u32,
    head: std.atomic.Value(u64) = std.atomic.Value(u64).init(0), // producer writes
    tail: std.atomic.Value(u64) = std.atomic.Value(u64).init(0), // consumer writes
    pushed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    popped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn init(allocator: std.mem.Allocator, capacity: u32) !EventRing {
        std.debug.assert(std.math.isPowerOfTwo(capacity));
        const entries = try allocator.alloc(?*GeyserEvent, capacity);
        @memset(entries, null);
        return .{ .entries = entries, .mask = capacity - 1, .capacity = capacity };
    }

    fn deinit(self: *EventRing, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
    }

    /// Producer side (replay thread). Wait-free. Returns false if full (caller must free the event).
    fn tryPush(self: *EventRing, ev: *GeyserEvent) bool {
        const head = self.head.load(.acquire);
        const tail = self.tail.load(.acquire);
        if (head -% tail >= self.capacity) {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return false; // full → drop
        }
        self.entries[@intCast(head & self.mask)] = ev;
        self.head.store(head +% 1, .release);
        _ = self.pushed.fetchAdd(1, .monotonic);
        return true;
    }

    /// Consumer side (geyser thread). Returns null when empty.
    fn tryPop(self: *EventRing) ?*GeyserEvent {
        const tail = self.tail.load(.acquire);
        const head = self.head.load(.acquire);
        if (tail == head) return null; // empty
        const ev = self.entries[@intCast(tail & self.mask)];
        self.tail.store(tail +% 1, .release);
        _ = self.popped.fetchAdd(1, .monotonic);
        return ev;
    }
};

/// Default ring capacity (power of two). Slot events are ~2.5/s; this is generous headroom.
pub const GEYSER_RING_CAPACITY: u32 = 4096;

/// Consumer-thread core: 26 — a FREE core in the hot taskset (1-3,5-27) that is NOT a static tile and
/// is NOT reserved. Per the tile→core topology (src/vex_topo.zig): CCX6 (24-27) hosts only gossip=24 +
/// rpc=27, so 25/26 are free and low-contention. Deliberately NOT on CCX0 {0-3}: core 0 = OS/main and
/// cores 1-3 are the cold reserve EARMARKED for the future parallel-exec worker pool — putting geyser
/// there would collide with that. 26 is off the hot pipeline (recv4/quic6/verify8-15/replay16/produce20)
/// so the streaming consumer can neither preempt nor share L3 with consensus-critical tiles. Self-
/// contained pin (no vex_topo import → keeps the module's test graph dependency-free; identical cpu_set
/// math to vex_topo.pinCore).
const GEYSER_CONSUMER_CORE: u32 = 26;

fn pinSelfTo(core_id: u32) void {
    var cpu_set = [_]usize{0} ** 16;
    cpu_set[core_id / @bitSizeOf(usize)] = @as(usize, 1) << @intCast(core_id % @bitSizeOf(usize));
    _ = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
}

pub const GeyserService = struct {
    allocator: std.mem.Allocator,
    ring: EventRing,
    socket_path: []const u8,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    const Self = @This();

    /// Default unix-socket path (overridable via VEX_GEYSER_SOCKET).
    pub const DEFAULT_SOCKET = "/tmp/vexor-geyser.sock";

    pub fn init(allocator: std.mem.Allocator, socket_path: []const u8) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .ring = try EventRing.init(allocator, GEYSER_RING_CAPACITY),
            .socket_path = socket_path,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.ring.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn start(self: *Self) !void {
        if (self.running.swap(true, .seq_cst)) return; // already running
        self.thread = std.Thread.spawn(.{}, consumerLoop, .{self}) catch |err| {
            self.running.store(false, .seq_cst);
            return err;
        };
        std.log.warn("[GEYSER] streaming sink started → {s} (consumer pinned core {d}, ring={d})", .{ self.socket_path, GEYSER_CONSUMER_CORE, GEYSER_RING_CAPACITY });
    }

    pub fn stop(self: *Self) void {
        if (!self.running.swap(false, .seq_cst)) return;
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        // Drain + free any events left in the ring.
        while (self.ring.tryPop()) |ev| self.freeEvent(ev);
    }

    fn freeEvent(self: *Self, ev: *GeyserEvent) void {
        switch (ev.*) {
            .account => |a| self.allocator.free(a.data),
            .slot => {},
        }
        self.allocator.destroy(ev);
    }

    // ── Producer API (called on the replay thread; wait-free) ───────────────────────────────────────
    /// Emit a slot-status event. Wait-free: allocates + enqueues; on a full ring (or OOM) it DROPS the
    /// event rather than blocking the replay thread. Never touches consensus state.
    pub fn onSlotStatus(self: *Self, slot: u64, parent: ?u64, status: SlotStatus) void {
        const ev = self.allocator.create(GeyserEvent) catch return; // OOM → drop, never block
        ev.* = .{ .slot = .{
            .slot = slot,
            .parent = parent orelse 0,
            .has_parent = parent != null,
            .status = status,
        } };
        if (!self.ring.tryPush(ev)) self.allocator.destroy(ev); // full → drop + free
    }

    // ── Consumer (cold-core thread) ─────────────────────────────────────────────────────────────────
    fn consumerLoop(self: *Self) void {
        pinSelfTo(GEYSER_CONSUMER_CORE);
        // Best-effort unix-socket connect; if no consumer is listening we still drain (drop) so the ring
        // never backs up. Reconnect lazily. Stage 4 hardens transport/backpressure.
        var sock: ?std.posix.socket_t = null;
        defer if (sock) |s| std.posix.close(s);

        var backoff_ticks: u32 = 0;
        while (self.running.load(.acquire)) {
            // Lazy (re)connect.
            if (sock == null) {
                if (backoff_ticks == 0) {
                    sock = connectUnix(self.socket_path) catch null;
                    if (sock == null) backoff_ticks = 200; // ~2s before retry
                } else backoff_ticks -= 1;
            }

            const ev = self.ring.tryPop() orelse {
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            };
            defer self.freeEvent(ev);

            var frame: [128]u8 = undefined;
            const n = serializeEvent(ev, &frame);
            if (sock) |s| {
                _ = std.posix.send(s, frame[0..n], std.posix.MSG.NOSIGNAL) catch {
                    std.posix.close(s);
                    sock = null; // drop connection; reconnect later
                    backoff_ticks = 200;
                };
            }
        }
    }

    fn connectUnix(path: []const u8) !std.posix.socket_t {
        const s = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
        errdefer std.posix.close(s);
        var addr = std.posix.sockaddr.un{ .family = std.posix.AF.UNIX, .path = undefined };
        @memset(&addr.path, 0);
        if (path.len >= addr.path.len) return error.PathTooLong;
        @memcpy(addr.path[0..path.len], path);
        try std.posix.connect(s, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.un));
        return s;
    }
};

/// Length-prefixed binary frame: [u32 LE total-len-after-this][u8 type][payload].
/// type 1 = slot: slot(u64 LE) parent(u64 LE) has_parent(u8) status(u8).
/// Returns bytes written into `out`.
fn serializeEvent(ev: *const GeyserEvent, out: []u8) usize {
    switch (ev.*) {
        .slot => |s| {
            // payload = type(1) + 8 + 8 + 1 + 1 = 19
            const payload_len: u32 = 19;
            std.mem.writeInt(u32, out[0..4], payload_len, .little);
            out[4] = 1; // type = slot
            std.mem.writeInt(u64, out[5..13], s.slot, .little);
            std.mem.writeInt(u64, out[13..21], s.parent, .little);
            out[21] = @intFromBool(s.has_parent);
            out[22] = @intFromEnum(s.status);
            return 23;
        },
        .account => {
            // Stage 1b: not emitted yet. Serialized form will be type=2 with owned data appended.
            return 0;
        },
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────────────────────────
test "geyser ring: wait-free push/pop + drop-on-full" {
    const a = std.testing.allocator;
    var ring = try EventRing.init(a, 4);
    defer ring.deinit(a);

    // Fill to capacity (4).
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const ev = try a.create(GeyserEvent);
        ev.* = .{ .slot = .{ .slot = 100 + i, .parent = 0, .has_parent = false, .status = .processed } };
        try std.testing.expect(ring.tryPush(ev));
    }
    // 5th push must fail (full) — caller owns/frees.
    const overflow = try a.create(GeyserEvent);
    overflow.* = .{ .slot = .{ .slot = 999, .parent = 0, .has_parent = false, .status = .processed } };
    try std.testing.expect(!ring.tryPush(overflow));
    a.destroy(overflow);
    try std.testing.expectEqual(@as(u64, 1), ring.dropped.load(.monotonic));

    // Drain in FIFO order.
    i = 0;
    while (ring.tryPop()) |ev| : (i += 1) {
        try std.testing.expectEqual(@as(u64, 100 + i), ev.slot.slot);
        a.destroy(ev);
    }
    try std.testing.expectEqual(@as(usize, 4), i);
}

test "geyser slot frame serialization" {
    const ev = GeyserEvent{ .slot = .{ .slot = 417002272, .parent = 417002271, .has_parent = true, .status = .rooted } };
    var buf: [128]u8 = undefined;
    const n = serializeEvent(&ev, &buf);
    try std.testing.expectEqual(@as(usize, 23), n);
    try std.testing.expectEqual(@as(u32, 19), std.mem.readInt(u32, buf[0..4], .little));
    try std.testing.expectEqual(@as(u8, 1), buf[4]); // slot type
    try std.testing.expectEqual(@as(u64, 417002272), std.mem.readInt(u64, buf[5..13], .little));
    try std.testing.expectEqual(@as(u64, 417002271), std.mem.readInt(u64, buf[13..21], .little));
    try std.testing.expectEqual(@as(u8, 1), buf[21]); // has_parent
    try std.testing.expectEqual(@as(u8, @intFromEnum(SlotStatus.rooted)), buf[22]);
}
