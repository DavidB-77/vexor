//! AF_XDP Socket Implementation
//! High-performance kernel bypass networking using Linux AF_XDP.
//!
//! AF_XDP provides:
//! - Zero-copy packet processing
//! - Direct NIC → userspace path
//! - UMEM ring buffers shared with kernel
//! - 10M+ packets/sec capability
//!
//! Memory layout:
//! ┌─────────────────────────────────────────────────────────────┐
//! │                         UMEM                                 │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │ Frame 0 │ Frame 1 │ Frame 2 │ ... │ Frame N          │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Fill Ring (kernel → user): frames ready to receive         │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │ producer │ consumer │ [addr] [addr] [addr] ...       │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Completion Ring (kernel → user): TX frames completed       │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │ producer │ consumer │ [addr] [addr] [addr] ...       │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! ├─────────────────────────────────────────────────────────────┤
//! │  RX Ring (kernel → user): received packets                  │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │ producer │ consumer │ [desc] [desc] [desc] ...       │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! ├─────────────────────────────────────────────────────────────┤
//! │  TX Ring (user → kernel): packets to send                   │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │ producer │ consumer │ [desc] [desc] [desc] ...       │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

/// AF_XDP socket address family (Linux specific)
pub const AF_XDP: u16 = 44;

/// XDP socket options
pub const SOL_XDP: u32 = 283;
pub const XDP_MMAP_OFFSETS: u32 = 1;
pub const XDP_RX_RING: u32 = 2;
pub const XDP_TX_RING: u32 = 3;
pub const XDP_UMEM_REG: u32 = 4;
pub const XDP_UMEM_FILL_RING: u32 = 5;
pub const XDP_UMEM_COMPLETION_RING: u32 = 6;
pub const XDP_STATISTICS: u32 = 7;
pub const XDP_OPTIONS: u32 = 8;

/// XDP flags
pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
pub const XDP_FLAGS_HW_MODE: u32 = 1 << 3;
pub const XDP_FLAGS_REPLACE: u32 = 1 << 4;

/// XDP bind flags
pub const XDP_SHARED_UMEM: u16 = 1 << 0;
pub const XDP_COPY: u16 = 1 << 1;
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

/// XDP ring flags (checked at runtime to avoid unnecessary wakeups)
pub const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

/// XDP mmap page offsets for ring buffers
pub const XDP_PGOFF_RX_RING: u64 = 0;
pub const XDP_PGOFF_TX_RING: u64 = 0x80000000;
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x180000000;

/// UMEM registration structure
pub const XdpUmemReg = extern struct {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
};

/// Ring offset structure
pub const XdpRingOffset = extern struct {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
};

/// Mmap offsets
pub const XdpMmapOffsets = extern struct {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset, // fill ring
    cr: XdpRingOffset, // completion ring
};

/// Socket address for AF_XDP
pub const SockaddrXdp = extern struct {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
};

/// RX/TX descriptor
pub const XdpDesc = extern struct {
    addr: u64,
    len: u32,
    options: u32,
};

/// XDP statistics
pub const XdpStatistics = extern struct {
    rx_dropped: u64,
    rx_invalid_descs: u64,
    tx_invalid_descs: u64,
    rx_ring_full: u64,
    rx_fill_ring_empty_descs: u64,
    tx_ring_empty_descs: u64,
};

/// Configuration for XDP socket
pub const XdpConfig = struct {
    /// Network interface name (empty = auto-detect)
    interface: []const u8 = "",
    /// Queue ID
    queue_id: u32 = 0,
    /// Number of frames in UMEM
    /// 16384 frames × 4KB = 64MB — sufficient for zero-copy assembly
    /// of ~50 active slots × 300 shreds without frame starvation.
    frame_count: u32 = 16384,
    /// Frame size
    frame_size: u32 = 4096,
    /// RX ring size (must be power of 2, matches frame budget)
    /// 2026-05-26: 2048 → 8192 (ConnectX-6 Dx HW max per `ethtool -g`).
    /// Avoids descriptor overflow during catchup bursts. Smaller value was
    /// LOST during 2026-05-25 baseline restart from f2a4507.
    rx_size: u32 = 8192,
    /// TX ring size
    tx_size: u32 = 2048,
    /// Fill ring size (must be power of 2, matches frame budget)
    /// 2026-05-26: 2048 → 16384 (2× rx_size). Fill ring must not starve before
    /// kernel returns frames via completion ring. Root cause of 2026-05-26 wedge.
    /// 2026-05-29 RESTORED to 16384 (the proven ce14d227 / 2026-05-26 value that
    /// sustained 167 BANK-FROZEN/min, gap=-30, alloc_err Δ=0). FIX #79 raised it
    /// to 65536 and 198abc2 reverted UMEM 131072→32768 but LEFT fill at 65536 —
    /// creating fill(65536) > UMEM(32768), an imbalanced state never tested
    /// healthy. Measured 2026-05-29: alloc_err +4065/s, rx_xsk_packets stalled →
    /// fill-ring starvation. The old FIX #79 comment (65536 healthier) was the
    /// misattribution corrected by project-fix79-buffer-attribution-wrong: that
    /// run's health came from the BPF nuke, not the buffer. Fill must be < UMEM
    /// frame_count so spare frames exist for in-flight RX (headroom, matching Firedancer's sizing discipline).
    fill_size: u32 = 16384,
    /// Completion ring size
    comp_size: u32 = 2048,
    /// Use zero-copy mode
    /// SAFETY: Disabled by default — crashes ixgbe driver on some firmware
    zero_copy: bool = false,
    /// Headroom for metadata
    headroom: u32 = 0,
};

// ═══════════════════════════════════════════════════════════════════════════════
// ZERO-COPY UMEM FRAME MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

/// Reference to a UMEM frame — the core zero-copy primitive.
/// Consumers hold these instead of copying data. The frame remains valid in UMEM
/// until released back to the UmemFrameManager.
pub const UmemFrameRef = struct {
    /// Offset of this frame within the UMEM region (used for Fill Ring return)
    frame_addr: u64,
    /// Direct pointer into the UMEM memory for the packet payload
    data: []u8,
    /// Actual packet length within the frame
    len: u32,
    /// Source IP (extracted from L3 header before handoff)
    src_ip: [4]u8 = .{ 0, 0, 0, 0 },
    /// Timestamp when received
    timestamp_ns: u64 = 0,

    /// Get the payload slice (convenience, same as data[0..len])
    pub fn payload(self: *const UmemFrameRef) []const u8 {
        return self.data[0..self.len];
    }
};

/// Manages UMEM frame lifecycle with atomic reference counting.
/// Frames are only returned to the AF_XDP Fill Ring when all consumers release them.
///
/// Flow:
///   recvZeroCopy() → acquire(frame) → refcount=1
///   consumer holds frame during assembly...
///   consumer calls release(frame) → refcount=0 → frame goes to free ring
///   replenishFillRing() drains free ring → frames available for kernel again
pub const UmemFrameManager = struct {
    /// Per-frame reference count. Frame at UMEM offset (i * frame_size) uses refcounts[i].
    refcounts: []std.atomic.Value(u16),

    /// Free ring: frame indices ready to be returned to Fill Ring.
    /// D4 (AFXDP-REWORK RC7): this is MPSC, not SPSC — release() runs on 8 verify workers +
    /// TVU + sweeper (producers); replenishFillRing() on the TVU loop (single consumer).
    /// free_mutex serializes ring enqueue/dequeue so a producer's head-advance can't race
    /// ahead of its slot write (a naive lock-free fetchAdd lets the consumer read free_ring[N]
    /// before producer N has written it). Refcounts stay atomic/lock-free. (The FD single-RX-
    /// loop-owns-return model avoids MPSC entirely — the lock-free durable alternative.)
    free_ring: []u32,
    free_ring_mask: u32,
    free_head: std.atomic.Value(u32), // producer cursor (guarded by free_mutex)
    free_tail: std.atomic.Value(u32), // consumer cursor (guarded by free_mutex)
    free_mutex: std.Thread.Mutex,

    /// Configuration
    frame_size: u32,
    frame_count: u32,

    /// Stats
    frames_acquired: std.atomic.Value(u64),
    frames_released: std.atomic.Value(u64),
    frames_replenished: std.atomic.Value(u64),
    spill_events: std.atomic.Value(u64),

    allocator: std.mem.Allocator,

    const Self = @This();

    /// High-water mark: if more than 75% of frames are held, trigger spill to copy path
    pub const SPILL_THRESHOLD_PERCENT: u32 = 75;

    pub fn init(allocator: std.mem.Allocator, frame_count: u32, frame_size: u32) !Self {
        const refcounts = try allocator.alloc(std.atomic.Value(u16), frame_count);
        for (refcounts) |*rc| rc.* = std.atomic.Value(u16).init(0);

        // Free ring must be power-of-2 for masking. Use next power of 2 >= frame_count.
        const ring_size = std.math.ceilPowerOfTwo(u32, frame_count) catch frame_count;
        const free_ring = try allocator.alloc(u32, ring_size);
        @memset(free_ring, 0);

        return Self{
            .refcounts = refcounts,
            .free_ring = free_ring,
            .free_ring_mask = ring_size - 1,
            .free_head = std.atomic.Value(u32).init(0),
            .free_tail = std.atomic.Value(u32).init(0),
            .free_mutex = .{},
            .frame_size = frame_size,
            .frame_count = frame_count,
            .frames_acquired = std.atomic.Value(u64).init(0),
            .frames_released = std.atomic.Value(u64).init(0),
            .frames_replenished = std.atomic.Value(u64).init(0),
            .spill_events = std.atomic.Value(u64).init(0),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.refcounts);
        self.allocator.free(self.free_ring);
    }

    /// Acquire a frame: increment refcount (called by recvZeroCopy)
    pub fn acquire(self: *Self, frame_addr: u64) void {
        const idx = @as(u32, @intCast(frame_addr / self.frame_size));
        if (idx < self.frame_count) {
            _ = self.refcounts[idx].fetchAdd(1, .acq_rel);
            _ = self.frames_acquired.fetchAdd(1, .monotonic);
        }
    }

    /// Release a frame: decrement refcount. If it hits zero, enqueue for Fill Ring return.
    pub fn release(self: *Self, frame_addr: u64) void {
        const idx = @as(u32, @intCast(frame_addr / self.frame_size));
        if (idx >= self.frame_count) return;

        const prev = self.refcounts[idx].fetchSub(1, .acq_rel);
        _ = self.frames_released.fetchAdd(1, .monotonic);

        if (prev == 1) {
            // Last reference dropped — enqueue frame index to free ring.
            // D4: MPSC (≥2 producers) → serialize under free_mutex so the head advance
            // (visible to the consumer) cannot precede the slot write.
            self.free_mutex.lock();
            const head = self.free_head.load(.monotonic);
            self.free_ring[head & self.free_ring_mask] = idx;
            self.free_head.store(head +% 1, .release);
            self.free_mutex.unlock();
        }
    }

    /// Drain free ring and push frame addresses back into the XDP Fill Ring.
    /// Call this periodically from the main receive loop.
    pub fn replenishFillRing(self: *Self, fill_ring: *UmemRing) usize {
        // D4: serialize free-ring access vs the multi-producer release() path. The fill_ring
        // ops below are single-consumer (TVU loop) so holding free_mutex across them is safe.
        //
        // FD-ALIGNED RECV-HOLD FIX (A1, 2026-06-14): the recv thread must NEVER BLOCK on this
        // lock. free_mutex is contended by 8 verify workers + TVU + sweeper via release(); a
        // producer descheduled while holding it would HANG replenishFillRing → the recv loop
        // stalls → AFXDP-PHASE freezes → fall behind → wedge (the HARD recv stall that survived
        // Fix1's drop-on-contended). FD's net tile has ZERO mutexes on the frame path
        // (FILL→RX→mcache→FREE is pure pointer math; firedancer net_tile.md:226-249). Minimal
        // analog: tryLock + skip. If a producer holds it, skip refill THIS iteration — the free
        // ring keeps the frames; the next loop drains them in a burst. Best-effort refill, never
        // block (a missed refill is bounded; a hung recv thread is fatal).
        if (!self.free_mutex.tryLock()) return 0;
        defer self.free_mutex.unlock();
        var replenished: usize = 0;
        const tail = self.free_tail.load(.acquire);
        const head = self.free_head.load(.acquire);
        const available = head -% tail;

        if (available == 0) return 0;

        // Try to reserve space in the Fill Ring
        const to_replenish = @min(available, fill_ring.free());
        if (to_replenish == 0) return 0;

        const fill_idx = fill_ring.reserve(to_replenish) orelse return 0;

        var i: u32 = 0;
        while (i < to_replenish) : (i += 1) {
            const free_idx = self.free_ring[(tail +% i) & self.free_ring_mask];
            const frame_addr = @as(u64, free_idx) * self.frame_size;
            const ring_pos = (fill_idx + i) & fill_ring.mask;
            fill_ring.ring[ring_pos] = frame_addr;
            replenished += 1;
        }

        fill_ring.submit(to_replenish);
        self.free_tail.store(tail +% to_replenish, .release);
        _ = self.frames_replenished.fetchAdd(replenished, .monotonic);

        return replenished;
    }

    /// Check if we should spill to copy path (frame pressure too high).
    /// Returns true if more than 75% of frames are currently held.
    pub fn shouldSpill(self: *const Self) bool {
        const acquired = self.frames_acquired.load(.monotonic);
        const released = self.frames_released.load(.monotonic);
        const held = if (acquired > released) acquired - released else 0;
        const threshold = (@as(u64, self.frame_count) * SPILL_THRESHOLD_PERCENT) / 100;
        return held > threshold;
    }

    /// Get the number of frames currently held by consumers.
    pub fn framesHeld(self: *const Self) u64 {
        const acquired = self.frames_acquired.load(.monotonic);
        const released = self.frames_released.load(.monotonic);
        return if (acquired > released) acquired - released else 0;
    }

    /// Occupancy instrumentation (2026-06-13): frames sitting in the recycle
    /// reservoir waiting to be pushed back into the Fill Ring. High value while
    /// fill_free is also high ⇒ replenish cadence is starving (the TVU thread
    /// isn't calling replenishFillRing/recvZeroCopy often enough = occupancy stall).
    pub fn freeDepth(self: *const Self) u64 {
        const head = self.free_head.load(.acquire);
        const tail = self.free_tail.load(.acquire);
        return head -% tail;
    }

    /// UMEM backpressure gate (2026-07-07, carrier 420258409 follow-up / task #42
    /// option (c)). `freeDepth()` is the recycle reservoir the NIC draws fresh
    /// frames from (via replenishFillRing → the Fill Ring); when it collapses to
    /// 0 the NIC has nowhere to put a new packet EXCEPT recycle an in-flight frame
    /// a verify worker is still reading — silent corruption ([FRAME-OVERWRITE] in
    /// shred.zig), not a clean loss. Sustained free_depth=0 (259 [FRAME-DROP] in
    /// 20min, tonight's spiral) means the recv path is handing frames downstream
    /// faster than the pool recycles them.
    ///
    /// This is the FD-canonical shape (fd_stem.c:442-460 cr_avail/min_cr_avail):
    /// before pulling a NEW fragment in, check downstream capacity with a cheap
    /// lock-free read and refuse to accept more work if it's exhausted — FD checks
    /// consumer sequence-number deltas every `before_credit` call; we check this
    /// pool's recycle depth. Explicit early shed of a NEW packet is strictly
    /// better than the alternative (accept it, let the NIC recycle a frame still
    /// in flight): turbine/repair already recover a dropped shred exactly like a
    /// network loss, whereas an in-flight overwrite corrupts verified bytes.
    ///
    /// `reserve` is the caller-supplied low-water mark (VEX_UMEM_RESERVE, default
    /// a small FIXED constant — see tvu.zig umemReserveFrames() for the full
    /// rationale and the 2026-07-07 correction: the original `frame_count/16`
    /// formula scaled with pool size instead of the actual protected quantity
    /// (frames_held) and would have compounded a 2026-07-07 pool regrow into an
    /// even worse over-shed rate; a fixed constant decouples the two). NOTE the
    /// FD cross-check is not exact: Firedancer's fd_xsk fill ring itself carries
    /// NO reserve at all (a reused frame is "immediately sent to the FILL ring",
    /// net_tile.md) — FD's cr_avail/min_cr_avail credit system in fd_stem.c
    /// operates one layer downstream, on the mcache a tile hands frames to, not
    /// on the UMEM pool. Pure read: two atomic loads (via freeDepth()), no lock
    /// — safe to call on every received frame from the single recv thread.
    pub fn shouldShed(self: *const Self, reserve: u32) bool {
        return self.freeDepth() < reserve;
    }

    /// D5 (AFXDP-REWORK RC6): pre-seed the recycle reservoir with frame indices
    /// [start_idx, end_idx) — the frames that don't fit in the fill ring (fill_size <
    /// frame_count). Without this, frames fill_size..frame_count never enter circulation
    /// (64MB orphaned for a 32768/16384 layout). Single-threaded INIT ONLY (no concurrency).
    pub fn seedFreeFrames(self: *Self, start_idx: u32, end_idx: u32) void {
        var idx = start_idx;
        while (idx < end_idx and idx < self.frame_count) : (idx += 1) {
            const head = self.free_head.load(.monotonic);
            self.free_ring[head & self.free_ring_mask] = idx;
            self.free_head.store(head +% 1, .monotonic);
        }
    }
};

/// UMEM ring buffer
pub const UmemRing = struct {
    producer: *u32,
    consumer: *u32,
    flags: ?*u32, // Ring flags for need_wakeup optimization
    ring: []u64,
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,

    pub fn reserve(self: *UmemRing, count: u32) ?u32 {
        if (self.free() < count) return null;
        const idx = self.cached_prod;
        self.cached_prod += count;
        return idx;
    }

    pub fn submit(self: *UmemRing, count: u32) void {
        @atomicStore(u32, self.producer, self.producer.* + count, .release);
    }

    pub fn peek(self: *UmemRing, count: u32) ?u32 {
        const available = @atomicLoad(u32, self.producer, .acquire) - self.cached_cons;
        if (available < count) return null;
        const idx = self.cached_cons;
        self.cached_cons += count;
        return idx;
    }

    pub fn release(self: *UmemRing, count: u32) void {
        @atomicStore(u32, self.consumer, self.consumer.* + count, .release);
    }

    pub fn free(self: *UmemRing) u32 {
        return @intCast(self.ring.len - (self.cached_prod - @atomicLoad(u32, self.consumer, .acquire)));
    }
    
    /// Check if kernel needs wakeup (for ~30M pps optimization)
    pub fn needWakeup(self: *UmemRing) bool {
        if (self.flags) |f| {
            return (@atomicLoad(u32, f, .acquire) & XDP_RING_NEED_WAKEUP) != 0;
        }
        return true; // Conservative: always wakeup if flags not available
    }
};

/// Descriptor ring buffer
pub const DescRing = struct {
    producer: *u32,
    consumer: *u32,
    flags: ?*u32, // Ring flags for need_wakeup optimization
    ring: []XdpDesc,
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,

    pub fn reserve(self: *DescRing, count: u32) ?u32 {
        if (self.free() < count) return null;
        const idx = self.cached_prod;
        self.cached_prod += count;
        return idx;
    }

    pub fn submit(self: *DescRing, count: u32) void {
        @atomicStore(u32, self.producer, self.producer.* + count, .release);
    }

    /// Peek up to `count` descriptors. Returns the start index + the ACTUAL number
    /// reserved (= @min(count, available)); advances cached_cons by that actual count.
    /// Returns null only when the ring is empty. C3 fix (AFXDP-REWORK RC5): was
    /// all-or-nothing — returned null unless available>=count, so trickle traffic of
    /// <count descriptors parked in the RX ring forever (and shunted batches onto the
    /// frame-destroying legacy path). af_xdp.zig:194-199 had the correct @min semantics.
    pub fn peek(self: *DescRing, count: u32) ?struct { idx: u32, n: u32 } {
        const available = @atomicLoad(u32, self.producer, .acquire) - self.cached_cons;
        if (available == 0) return null;
        const n = @min(count, available);
        const idx = self.cached_cons;
        self.cached_cons += n;
        return .{ .idx = idx, .n = n };
    }

    pub fn release(self: *DescRing, count: u32) void {
        @atomicStore(u32, self.consumer, self.consumer.* + count, .release);
    }

    pub fn free(self: *DescRing) u32 {
        return @intCast(self.ring.len - (self.cached_prod - @atomicLoad(u32, self.consumer, .acquire)));
    }
    
    /// Check if kernel needs wakeup (for ~30M pps optimization)
    pub fn needWakeup(self: *DescRing) bool {
        if (self.flags) |f| {
            return (@atomicLoad(u32, f, .acquire) & XDP_RING_NEED_WAKEUP) != 0;
        }
        return true; // Conservative: always wakeup if flags not available
    }
};

/// AF_XDP Socket
pub const XdpSocket = struct {
    /// Socket file descriptor
    fd: posix.fd_t,
    /// UMEM memory region
    umem: []align(std.heap.page_size_min) u8,
    /// Fill ring
    fill_ring: UmemRing,
    /// Completion ring
    comp_ring: UmemRing,
    /// RX ring
    rx_ring: DescRing,
    /// TX ring
    tx_ring: DescRing,
    /// Configuration
    config: XdpConfig,
    /// Statistics
    stats: XdpStatistics,
    /// Interface index
    ifindex: u32,
    /// Allocator
    allocator: Allocator,
    /// Is initialized
    initialized: bool,
    /// Frame manager for zero-copy lifecycle (initialized lazily on first recvZeroCopy call)
    frame_manager: ?UmemFrameManager = null,

    pub fn init(allocator: Allocator, config: XdpConfig) !XdpSocket {
        var sock = XdpSocket{
            .fd = -1,
            .umem = &[_]u8{},
            .fill_ring = undefined,
            .comp_ring = undefined,
            .rx_ring = undefined,
            .tx_ring = undefined,
            .config = config,
            .stats = std.mem.zeroes(XdpStatistics),
            .ifindex = 0,
            .allocator = allocator,
            .initialized = false,
        };

        try sock.setup();
        return sock;
    }

    pub fn deinit(self: *XdpSocket) void {
        if (self.frame_manager) |*fm| {
            fm.deinit();
        }
        if (self.fd >= 0) {
            posix.close(self.fd);
        }
        if (self.umem.len > 0) {
            posix.munmap(self.umem);
        }
    }

    fn setup(self: *XdpSocket) !void {
        std.log.debug("[XDP Setup] Getting interface index for: {s}\n", .{self.config.interface});
        // Get interface index
        self.ifindex = getInterfaceIndex(self.config.interface) catch |err| {
            std.log.err("[AF_XDP] Failed to get interface index: {}", .{err});
            return err;
        };

        // Create AF_XDP socket
        self.fd = posix.socket(AF_XDP, posix.SOCK.RAW, 0) catch |err| {
            std.log.err("[AF_XDP] Socket creation failed: {}", .{err});
            return err;
        };
        errdefer posix.close(self.fd);

        // Allocate UMEM — try hugepages first for reduced TLB pressure (~8 TLB entries
        // vs ~4096 with 4KB pages for 16MB UMEM). Critical under heavy shred floods.
        const umem_size = @as(usize, self.config.frame_count) * self.config.frame_size;
        var got_hugepages = true;
        self.umem = posix.mmap(
            null,
            umem_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .HUGETLB = true },
            -1,
            0,
        ) catch blk: {
            // Hugepages not available — fall back to standard 4KB pages
            got_hugepages = false;
            break :blk posix.mmap(
                null,
                umem_size,
                posix.PROT.READ | posix.PROT.WRITE,
                .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
                -1,
                0,
            ) catch |err| {
                std.log.err("[AF_XDP] UMEM mmap failed: {}", .{err});
                return err;
            };
        };
        if (got_hugepages) {
            std.log.info("[AF_XDP] UMEM allocated with 2MB hugepages: {d} bytes ({d} frames)", .{
                umem_size, self.config.frame_count,
            });
        } else {
            std.log.info("[AF_XDP] UMEM allocated with 4KB pages: {d} bytes (tip: echo 64 > /proc/sys/vm/nr_hugepages for TLB optimization)", .{
                umem_size,
            });
        }
        errdefer posix.munmap(self.umem);

        // Register UMEM
        const umem_reg = XdpUmemReg{
            .addr = @intFromPtr(self.umem.ptr),
            .len = umem_size,
            .chunk_size = self.config.frame_size,
            .headroom = self.config.headroom,
            .flags = 0,
        };

        std.log.debug("[AF_XDP] Registering UMEM", .{});
        setsockopt(self.fd, SOL_XDP, XDP_UMEM_REG, std.mem.asBytes(&umem_reg)) catch |err| {
            std.log.err("[AF_XDP] UMEM registration failed: {}", .{err});
            return err;
        };

        // Set up ring sizes
        try setsockopt(self.fd, SOL_XDP, XDP_UMEM_FILL_RING, std.mem.asBytes(&self.config.fill_size));
        try setsockopt(self.fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, std.mem.asBytes(&self.config.comp_size));
        try setsockopt(self.fd, SOL_XDP, XDP_RX_RING, std.mem.asBytes(&self.config.rx_size));
        try setsockopt(self.fd, SOL_XDP, XDP_TX_RING, std.mem.asBytes(&self.config.tx_size));

        // Get mmap offsets
        var offsets: XdpMmapOffsets = undefined;
        var len: u32 = @sizeOf(XdpMmapOffsets);
        try getsockopt(self.fd, SOL_XDP, XDP_MMAP_OFFSETS, std.mem.asBytes(&offsets), &len);

        // Memory map the rings
        try self.mmapRings(&offsets);

        // Bind to interface with optimizations for ~30M pps:
        // - XDP_ZEROCOPY: Eliminates memcpy between kernel and userspace
        // - XDP_USE_NEED_WAKEUP: Avoids unnecessary wakeup syscalls
        std.log.debug("[AF_XDP] Binding to interface {d} queue {d}", .{ self.ifindex, self.config.queue_id });
        var bind_flags: u16 = XDP_USE_NEED_WAKEUP; // Always use need_wakeup optimization
        if (self.config.zero_copy) {
            bind_flags |= XDP_ZEROCOPY;
        } else {
            bind_flags |= XDP_COPY;
        }
        var addr = SockaddrXdp{
            .sxdp_family = AF_XDP,
            .sxdp_flags = bind_flags,
            .sxdp_ifindex = self.ifindex,
            .sxdp_queue_id = self.config.queue_id,
            .sxdp_shared_umem_fd = 0,
        };

        var actual_mode: []const u8 = if ((bind_flags & XDP_ZEROCOPY) != 0) "zero-copy" else "copy mode";
        posix.bind(self.fd, @ptrCast(&addr), @sizeOf(SockaddrXdp)) catch |err| {
            // If zero-copy fails, try with copy mode as fallback
            if (self.config.zero_copy) {
                std.log.warn("[AF_XDP] Zero-copy bind failed ({}), falling back to copy mode", .{err});
                addr.sxdp_flags = XDP_USE_NEED_WAKEUP | XDP_COPY;
                // C5 (AFXDP-REWORK): reflect the ACTUAL bound mode so downstream banners and the
                // recvZeroCopy gating don't claim zero-copy when the NIC/driver fell back to copy.
                self.config.zero_copy = false;
                actual_mode = "copy mode (zero-copy not supported by NIC/driver)";
                posix.bind(self.fd, @ptrCast(&addr), @sizeOf(SockaddrXdp)) catch |err2| {
                    std.log.err("[AF_XDP] Bind to queue {d} failed: {} - queue may already be in use", .{ self.config.queue_id, err2 });
                    return err2;
                };
            } else {
                std.log.err("[AF_XDP] Bind to queue {d} failed: {} - queue may already be in use", .{ self.config.queue_id, err });
                return err;
            }
        };
        std.log.info("[AF_XDP] Bound to interface {d} queue {d} with {s}", .{ self.ifindex, self.config.queue_id, actual_mode });

        // Populate fill ring with initial frames
        try self.populateFillRing();

        // D7 (AFXDP-REWORK RC3): eager-init the frame manager HERE, not lazily on first
        // recvZeroCopy. TVU wires the fm into the ShredAssembler at init time; if the fm
        // is still null then, setFrameManager is silently skipped and EVERY verified shred
        // leaks its frame (shred.zig defer-release becomes a no-op) → fill ring starves.
        // Safe across init()'s by-value return: fm state lives in heap slices; no concurrency
        // during init. Inert in kernel-UDP (getXdpSocket() is null there → fm path unused).
        if (self.frame_manager == null) {
            self.frame_manager = try UmemFrameManager.init(self.allocator, self.config.frame_count, self.config.frame_size);
            // D5 (RC6): seed the recycle reservoir with frames that don't fit in the fill
            // ring (fill_size..frame_count) so ALL of UMEM circulates.
            self.frame_manager.?.seedFreeFrames(self.config.fill_size, self.config.frame_count);
            std.log.info("[AF_XDP] frame manager eager-init: {d} frames, {d} pre-seeded into recycle reservoir", .{ self.config.frame_count, self.config.frame_count -| self.config.fill_size });
        }

        self.initialized = true;
    }

    fn mmapRings(self: *XdpSocket, offsets: *const XdpMmapOffsets) !void {
        // Mmap RX ring
        const rx_map_size = offsets.rx.desc + @as(usize, self.config.rx_size) * @sizeOf(XdpDesc);
        const rx_map = posix.mmap(
            null,
            rx_map_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            self.fd,
            @intCast(XDP_PGOFF_RX_RING),
        ) catch |err| {
            std.log.err("[AF_XDP] RX ring mmap failed: {}", .{err});
            return err;
        };
        
        // Set up RX ring pointers (including flags for need_wakeup optimization)
        self.rx_ring = .{
            .producer = @ptrFromInt(@intFromPtr(rx_map.ptr) + offsets.rx.producer),
            .consumer = @ptrFromInt(@intFromPtr(rx_map.ptr) + offsets.rx.consumer),
            .flags = if (offsets.rx.flags != 0) @ptrFromInt(@intFromPtr(rx_map.ptr) + offsets.rx.flags) else null,
            .ring = @as([*]XdpDesc, @ptrFromInt(@intFromPtr(rx_map.ptr) + offsets.rx.desc))[0..self.config.rx_size],
            .cached_prod = 0,
            .cached_cons = 0,
            .mask = self.config.rx_size - 1,
        };
        
        // Mmap TX ring
        const tx_map_size = offsets.tx.desc + @as(usize, self.config.tx_size) * @sizeOf(XdpDesc);
        const tx_map = posix.mmap(
            null,
            tx_map_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            self.fd,
            @intCast(XDP_PGOFF_TX_RING),
        ) catch |err| {
            std.log.err("[AF_XDP] TX ring mmap failed: {}", .{err});
            return err;
        };
        
        // Set up TX ring pointers (including flags for need_wakeup optimization)
        self.tx_ring = .{
            .producer = @ptrFromInt(@intFromPtr(tx_map.ptr) + offsets.tx.producer),
            .consumer = @ptrFromInt(@intFromPtr(tx_map.ptr) + offsets.tx.consumer),
            .flags = if (offsets.tx.flags != 0) @ptrFromInt(@intFromPtr(tx_map.ptr) + offsets.tx.flags) else null,
            .ring = @as([*]XdpDesc, @ptrFromInt(@intFromPtr(tx_map.ptr) + offsets.tx.desc))[0..self.config.tx_size],
            .cached_prod = 0,
            .cached_cons = 0,
            .mask = self.config.tx_size - 1,
        };
        
        // Mmap Fill ring
        const fill_map_size = offsets.fr.desc + @as(usize, self.config.fill_size) * @sizeOf(u64);
        const fill_map = posix.mmap(
            null,
            fill_map_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            self.fd,
            @intCast(XDP_UMEM_PGOFF_FILL_RING),
        ) catch |err| {
            std.log.err("[AF_XDP] Fill ring mmap failed: {}", .{err});
            return err;
        };
        
        // Set up Fill ring pointers (including flags for need_wakeup optimization)
        self.fill_ring = .{
            .producer = @ptrFromInt(@intFromPtr(fill_map.ptr) + offsets.fr.producer),
            .consumer = @ptrFromInt(@intFromPtr(fill_map.ptr) + offsets.fr.consumer),
            .flags = if (offsets.fr.flags != 0) @ptrFromInt(@intFromPtr(fill_map.ptr) + offsets.fr.flags) else null,
            .ring = @as([*]u64, @ptrFromInt(@intFromPtr(fill_map.ptr) + offsets.fr.desc))[0..self.config.fill_size],
            .cached_prod = 0,
            .cached_cons = 0,
            .mask = self.config.fill_size - 1,
        };
        
        // Mmap Completion ring
        const comp_map_size = offsets.cr.desc + @as(usize, self.config.comp_size) * @sizeOf(u64);
        const comp_map = posix.mmap(
            null,
            comp_map_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            self.fd,
            @intCast(XDP_UMEM_PGOFF_COMPLETION_RING),
        ) catch |err| {
            std.log.err("[AF_XDP] Completion ring mmap failed: {}", .{err});
            return err;
        };
        
        // Set up Completion ring pointers (including flags for need_wakeup optimization)
        self.comp_ring = .{
            .producer = @ptrFromInt(@intFromPtr(comp_map.ptr) + offsets.cr.producer),
            .consumer = @ptrFromInt(@intFromPtr(comp_map.ptr) + offsets.cr.consumer),
            .flags = if (offsets.cr.flags != 0) @ptrFromInt(@intFromPtr(comp_map.ptr) + offsets.cr.flags) else null,
            .ring = @as([*]u64, @ptrFromInt(@intFromPtr(comp_map.ptr) + offsets.cr.desc))[0..self.config.comp_size],
            .cached_prod = 0,
            .cached_cons = 0,
            .mask = self.config.comp_size - 1,
        };
        
        std.log.debug("[AF_XDP] Rings mapped successfully", .{});
    }

    fn populateFillRing(self: *XdpSocket) !void {
        // Add frames to fill ring for RX - kernel needs frame addresses to receive into
        const frames_to_add = @min(self.config.fill_size, self.config.frame_count);
        
        const idx = self.fill_ring.reserve(frames_to_add);
        if (idx) |start_idx| {
            for (0..frames_to_add) |i| {
                const ring_idx = (start_idx + @as(u32, @intCast(i))) & self.fill_ring.mask;
                self.fill_ring.ring[ring_idx] = @as(u64, i) * self.config.frame_size;
            }
            self.fill_ring.submit(frames_to_add);
            std.log.debug("[AF_XDP] Populated fill ring with {d} frames", .{frames_to_add});
        } else {
            std.log.warn("[AF_XDP] Failed to reserve space in fill ring", .{});
        }
    }

    /// Receive packets
    /// In AF_XDP copy mode, the kernel needs a poll() wakeup to copy packets
    /// from the NIC into UMEM. Without this, the RX ring stays empty.
    pub fn recv(self: *XdpSocket, packets: []Packet) !usize {
        if (!self.initialized) return error.NotInitialized;

        // In copy mode, the kernel needs a wakeup to deliver packets.
        // Check if the fill ring's need_wakeup flag is set, or always poll
        // briefly to trigger the kernel's copy path.
        if (self.fill_ring.needWakeup()) {
            var poll_fd = [_]std.posix.pollfd{.{
                .fd = self.fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            // Non-blocking poll (timeout=0) just triggers the wakeup
            _ = std.posix.poll(&poll_fd, 0) catch {};
        }

        var received: usize = 0;
        // C3: process the ACTUAL available count (partial batch), not all-or-nothing.
        if (self.rx_ring.peek(@intCast(packets.len))) |res| {
            for (0..res.n) |i| {
                const desc_idx = (res.idx + @as(u32, @intCast(i))) & self.rx_ring.mask;
                const desc = self.rx_ring.ring[desc_idx];

                packets[i] = .{
                    .data = self.umem[desc.addr..][0..desc.len],
                    .len = desc.len,
                };
                received += 1;
            }

            self.rx_ring.release(@intCast(received));

            // Replenish Fill Ring with frames from frame manager (if active)
            if (self.frame_manager) |*fm| {
                _ = fm.replenishFillRing(&self.fill_ring);
            }
        }

        return received;
    }

    /// Zero-copy receive: returns frame descriptors pointing directly into UMEM.
    ///
    /// Unlike recv(), this does NOT copy data. The returned UmemFrameRef.data slices
    /// point directly into the mmap'd UMEM region. Frames are held via the
    /// UmemFrameManager and are NOT returned to the Fill Ring until release().
    ///
    /// Caller MUST call frame_manager.release(ref.frame_addr) on each ref when done.
    /// Caller SHOULD check frame_manager.shouldSpill() and fall back to recv() copy
    /// path if true (75% frame pressure threshold).
    pub fn recvZeroCopy(self: *XdpSocket, out: []UmemFrameRef) !usize {
        if (!self.initialized) return error.NotInitialized;

        // Lazy-init frame manager on first zero-copy call
        if (self.frame_manager == null) {
            self.frame_manager = try UmemFrameManager.init(
                self.allocator,
                self.config.frame_count,
                self.config.frame_size,
            );
            std.log.info("[AF_XDP] UmemFrameManager initialized: {d} frames, spill at {d}%", .{
                self.config.frame_count,
                UmemFrameManager.SPILL_THRESHOLD_PERCENT,
            });
        }

        var fm = &(self.frame_manager.?);

        // Sub-step timing (2026-06-14): localize the 224ms recv spike to
        // replenish (free_mutex contention) vs poll (syscall) vs the per-frame loop.
        const t_rz0 = std.time.nanoTimestamp();

        // Replenish Fill Ring from previously-released frames before receiving
        _ = fm.replenishFillRing(&self.fill_ring);
        const t_rz_repl = std.time.nanoTimestamp();

        // ── FD-canonical kernel wakeup (firedancer fd_xsk.c:244,271) ──────────
        // With XDP_USE_NEED_WAKEUP set (socket.zig:571,590), after submitting
        // frames to the Fill Ring we MUST wake the kernel so it consumes them.
        // Without this, the kernel keeps seeing an empty Fill Ring and bumps
        // rx_xsk_buff_alloc_err on every NAPI poll → it drops the XDP-redirected
        // packet → rx_xsk_packets stays flat (kernel-UDP XDP_PASS silently carries).
        // Copy-mode recv() already does this at :739; recvZeroCopy (the zero-copy
        // path AF_XDP actually uses) was missing it — the 2026-05-29 Cutover-B
        // carrier: framesHeld=0, redirect=16697, but alloc_err +52K/s, rx_xsk Δ910.
        if (self.fill_ring.needWakeup()) {
            var poll_fd = [_]std.posix.pollfd{.{
                .fd = self.fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            _ = std.posix.poll(&poll_fd, 0) catch {};
        }
        const t_rz_poll = std.time.nanoTimestamp();

        // Safety valve: check frame pressure before acquiring more
        if (fm.shouldSpill()) {
            _ = fm.spill_events.fetchAdd(1, .monotonic);
            return error.FramePressure; // Caller should fall back to copy path
        }

        // C3: process the ACTUAL available count (partial batch), not all-or-nothing.
        const res = self.rx_ring.peek(@intCast(out.len)) orelse return 0;
        var received: usize = 0;

        for (0..res.n) |i| {
            const desc_idx = (res.idx + @as(u32, @intCast(i))) & self.rx_ring.mask;
            const desc = self.rx_ring.ring[desc_idx];
            const frame_data = self.umem[desc.addr..][0..desc.len];

            // ── Dynamic L2/L3/L4 header stripping ──────────────────────────
            // AF_XDP delivers raw L2 frames. We must advance past headers
            // to expose the UDP payload (the Turbine shred) to consumers.
            //
            // Layout: [ETH 14B] [VLAN 4B?] [IPv4 20-60B] [UDP 8B] [PAYLOAD]
            //
            const hdr_result = parseHeaderOffset(frame_data);

            // Extract source IP from L3 header
            var src_ip: [4]u8 = .{ 0, 0, 0, 0 };
            if (hdr_result.ip_offset + 16 <= desc.len) {
                @memcpy(&src_ip, frame_data[hdr_result.ip_offset + 12 ..][0..4]);
            }

            out[i] = .{
                .frame_addr = desc.addr,
                // Point data PAST headers, directly at the UDP payload (shred data)
                .data = frame_data[hdr_result.payload_offset..],
                .len = if (desc.len > hdr_result.payload_offset)
                    desc.len - hdr_result.payload_offset
                else
                    0,
                .src_ip = src_ip,
                .timestamp_ns = @intCast(std.time.nanoTimestamp()),
            };

            // Acquire: mark frame as in-use (refcount = 1)
            fm.acquire(desc.addr);
            received += 1;
        }

        // Release RX ring entries (kernel can reuse descriptor slots, NOT the UMEM frames)
        self.rx_ring.release(@intCast(received));

        // Slow-call breakdown (2026-06-14): on a >50ms recvZeroCopy, attribute the
        // stall to replenish (free_mutex held by a descheduled verify worker?) vs
        // poll (kernel) vs the per-frame loop (UMEM page-fault / parse).
        const t_rz_end = std.time.nanoTimestamp();
        const total_us = @divTrunc(t_rz_end - t_rz0, 1000);
        if (total_us > 50_000) {
            std.log.warn("[ZC-RECV-SLOW] total={d}us replenish={d}us poll={d}us loop={d}us n={d}", .{
                total_us,
                @divTrunc(t_rz_repl - t_rz0, 1000),
                @divTrunc(t_rz_poll - t_rz_repl, 1000),
                @divTrunc(t_rz_end - t_rz_poll, 1000),
                received,
            });
        }

        return received;
    }

    /// Parse Ethernet + IP + UDP headers to find the exact byte offset where
    /// the UDP payload (shred data) begins. Handles:
    ///   - Standard Ethernet II (14 bytes)
    ///   - Single 802.1Q VLAN tag (+4 bytes)
    ///   - QinQ / double VLAN (+8 bytes)
    ///   - IPv4 with variable IHL (header options)
    ///   - UDP header (8 bytes)
    ///
    /// Returns the offset into the frame where payload starts.
    /// If the frame is malformed or too short, returns 0 (full frame as data).
    const HeaderParseResult = struct {
        payload_offset: u32,
        ip_offset: u32,
    };

    fn parseHeaderOffset(frame: []const u8) HeaderParseResult {
        // Minimum: ETH(14) + IPv4(20) + UDP(8) = 42 bytes
        if (frame.len < 42) return .{ .payload_offset = 0, .ip_offset = 14 };

        // ── Layer 2: Ethernet II ──
        // Bytes 12-13: EtherType (or TPID for VLAN)
        var eth_hdr_len: u32 = 14;
        const ethertype_raw = @as(u16, frame[12]) << 8 | frame[13];

        if (ethertype_raw == 0x8100) {
            // 802.1Q VLAN tag: 4 extra bytes (TPID + TCI)
            eth_hdr_len = 18;
            // Check for QinQ (double VLAN)
            if (frame.len >= 22) {
                const inner_type = @as(u16, frame[16]) << 8 | frame[17];
                if (inner_type == 0x8100 or inner_type == 0x88A8) {
                    eth_hdr_len = 22;
                }
            }
        } else if (ethertype_raw == 0x88A8) {
            // 802.1ad Provider VLAN (S-VLAN) — at least one more VLAN follows
            eth_hdr_len = 22;
        }

        // Check the final EtherType is IPv4 (0x0800)
        const final_ethertype_off = eth_hdr_len - 2;
        if (frame.len < eth_hdr_len + 20) return .{ .payload_offset = 0, .ip_offset = eth_hdr_len };
        const final_ethertype = @as(u16, frame[final_ethertype_off]) << 8 | frame[final_ethertype_off + 1];
        if (final_ethertype != 0x0800) {
            // Not IPv4 (could be IPv6 0x86DD, ARP, etc.) — return full frame
            return .{ .payload_offset = 0, .ip_offset = eth_hdr_len };
        }

        // ── Layer 3: IPv4 ──
        // Byte 0 of IP header: version (high nibble) + IHL (low nibble, in 32-bit words)
        const ip_offset = eth_hdr_len;
        const ip_byte0 = frame[ip_offset];
        const ip_version = ip_byte0 >> 4;
        if (ip_version != 4) return .{ .payload_offset = 0, .ip_offset = ip_offset };

        const ihl: u32 = @as(u32, ip_byte0 & 0x0F) * 4; // IHL in bytes (min 20, max 60)
        if (ihl < 20 or ihl > 60) return .{ .payload_offset = 0, .ip_offset = ip_offset };

        // Check protocol is UDP (17)
        if (frame.len < ip_offset + ihl + 8) return .{ .payload_offset = 0, .ip_offset = ip_offset };
        const protocol = frame[ip_offset + 9];
        if (protocol != 17) return .{ .payload_offset = 0, .ip_offset = ip_offset }; // Not UDP

        // ── Layer 4: UDP (always 8 bytes) ──
        const payload_offset = ip_offset + ihl + 8;

        return .{
            .payload_offset = payload_offset,
            .ip_offset = ip_offset,
        };
    }

    /// Get the frame manager (for consumers to call release())
    pub fn getFrameManager(self: *XdpSocket) ?*UmemFrameManager {
        return if (self.frame_manager != null) &(self.frame_manager.?) else null;
    }

    /// Occupancy/health snapshot for AF_XDP instrumentation (2026-06-13).
    /// Read-only; safe to call from the TVU loop once/sec. Used to prove (or
    /// refute) the single-thread occupancy stall: at collapse we expect
    /// rx_avail pinned near rx ring depth (kernel has packets we aren't
    /// draining) AND fill_free high (we stopped replenishing) — i.e. the loop
    /// stopped calling recvZeroCopy because some other phase monopolized it.
    pub const XdpDiag = struct {
        frames_held: u64 = 0,
        free_depth: u64 = 0, // frames in recycle reservoir awaiting fill-ring return
        fill_free: u32 = 0, // empty slots in Fill Ring (kernel-consumable)
        rx_avail: u32 = 0, // packets sitting in RX ring waiting for us (occupancy)
        spill_events: u64 = 0,
    };
    pub fn diag(self: *XdpSocket) XdpDiag {
        if (self.frame_manager == null) return .{};
        const fm = &(self.frame_manager.?);
        const rx_prod = @atomicLoad(u32, self.rx_ring.producer, .acquire);
        const rx_cons = @atomicLoad(u32, self.rx_ring.consumer, .acquire);
        return .{
            .frames_held = fm.framesHeld(),
            .free_depth = fm.freeDepth(),
            .fill_free = self.fill_ring.free(),
            .rx_avail = rx_prod -% rx_cons,
            .spill_events = fm.spill_events.load(.monotonic),
        };
    }

    /// Send packets
    pub fn send(self: *XdpSocket, packets: []const Packet) !usize {
        if (!self.initialized) return error.NotInitialized;

        var sent: usize = 0;
        const available = self.tx_ring.reserve(@intCast(packets.len));

        if (available) |idx| {
            for (packets) |pkt| {
                const desc_idx = (idx + @as(u32, @intCast(sent))) & self.tx_ring.mask;

                // Find a free frame
                const frame_addr = sent * self.config.frame_size;

                // Copy data to UMEM frame
                @memcpy(self.umem[frame_addr..][0..pkt.len], pkt.data[0..pkt.len]);

                self.tx_ring.ring[desc_idx] = .{
                    .addr = frame_addr,
                    .len = pkt.len,
                    .options = 0,
                };

                sent += 1;
            }

            self.tx_ring.submit(@intCast(sent));

            // Only kick the kernel if needed (XDP_USE_NEED_WAKEUP optimization for ~30M pps)
            if (self.tx_ring.needWakeup()) {
                _ = try sendto(self.fd, &[_]u8{}, 0, null, 0);
            }
        }

        return sent;
    }

    /// Poll for events
    pub fn poll(self: *XdpSocket, timeout_ms: i32) !bool {
        var fds = [_]posix.pollfd{.{
            .fd = self.fd,
            .events = posix.POLL.IN | posix.POLL.OUT,
            .revents = 0,
        }};

        const result = try posix.poll(&fds, timeout_ms);
        return result > 0;
    }

    /// Get statistics
    pub fn getStats(self: *XdpSocket) !XdpStatistics {
        var stats: XdpStatistics = undefined;
        var len: u32 = @sizeOf(XdpStatistics);
        try getsockopt(self.fd, SOL_XDP, XDP_STATISTICS, std.mem.asBytes(&stats), &len);
        self.stats = stats;
        return stats;
    }
};

/// Packet representation
pub const Packet = struct {
    data: []u8,
    len: u32,
};

/// Get interface index by name
pub fn getInterfaceIndex(name: []const u8) !u32 {
    // Use ioctl SIOCGIFINDEX
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(sock);

    var ifr: extern struct {
        name: [16]u8,
        ifindex: i32,
        _padding: [20]u8,
    } = undefined;

    @memset(&ifr.name, 0);
    const copy_len = @min(name.len, 15);
    @memcpy(ifr.name[0..copy_len], name[0..copy_len]);

    // SIOCGIFINDEX = 0x8933
    const SIOCGIFINDEX: u32 = 0x8933;

    // Use C library ioctl since std.posix doesn't expose it
    const rc = std.c.ioctl(sock, SIOCGIFINDEX, &ifr);
    if (rc < 0) {
        return error.IoctlFailed;
    }

    return @intCast(ifr.ifindex);
}

fn setsockopt(fd: posix.fd_t, level: u32, optname: u32, optval: []const u8) !void {
    const rc = std.c.setsockopt(fd, @intCast(level), @intCast(optname), optval.ptr, @intCast(optval.len));
    if (rc < 0) {
        const errno = std.c._errno().*;
        std.log.err("[AF_XDP] setsockopt(level={d}, opt={d}) failed: errno={d} ({s})", .{
            level,
            optname,
            errno,
            switch (errno) {
                1 => "EPERM",
                12 => "ENOMEM",
                13 => "EACCES",
                14 => "EFAULT",
                22 => "EINVAL",
                28 => "ENOSPC",
                95 => "ENOTSUP",
                else => "unknown",
            },
        });
        return error.SetSockOptFailed;
    }
}

fn getsockopt(fd: posix.fd_t, level: u32, optname: u32, optval: []u8, optlen: *u32) !void {
    const rc = std.c.getsockopt(fd, @intCast(level), @intCast(optname), optval.ptr, optlen);
    if (rc < 0) {
        return error.GetSockOptFailed;
    }
}

fn sendto(fd: posix.fd_t, buf: []const u8, flags: u32, addr: ?*const posix.sockaddr, addrlen: posix.socklen_t) !usize {
    const rc = std.c.sendto(fd, buf.ptr, buf.len, @intCast(flags), addr, addrlen);
    if (rc < 0) {
        return error.SendToFailed;
    }
    return @intCast(rc);
}

// ============================================================================
// Tests
// ============================================================================

test "XdpConfig: defaults" {
    const config = XdpConfig{};
    try std.testing.expectEqual(@as(u32, 16384), config.frame_count);
    try std.testing.expectEqual(@as(u32, 4096), config.frame_size);
}

test "UmemFrameManager: acquire and release" {
    const allocator = std.testing.allocator;
    var fm = try UmemFrameManager.init(allocator, 64, 4096);
    defer fm.deinit();

    // Acquire frame 0
    fm.acquire(0);
    try std.testing.expectEqual(@as(u64, 1), fm.framesHeld());

    // Acquire frame 1
    fm.acquire(4096);
    try std.testing.expectEqual(@as(u64, 2), fm.framesHeld());

    // Release frame 0 — should go to free ring
    fm.release(0);
    try std.testing.expectEqual(@as(u64, 1), fm.framesHeld());

    // Release frame 1
    fm.release(4096);
    try std.testing.expectEqual(@as(u64, 0), fm.framesHeld());
}

test "UmemFrameManager: spill threshold" {
    const allocator = std.testing.allocator;
    var fm = try UmemFrameManager.init(allocator, 100, 4096);
    defer fm.deinit();

    // Acquire 74 frames — should be under threshold (75%)
    for (0..74) |i| fm.acquire(@as(u64, @intCast(i)) * 4096);
    try std.testing.expect(!fm.shouldSpill());

    // Acquire 2 more (76 total) — should trigger spill
    fm.acquire(74 * 4096);
    fm.acquire(75 * 4096);
    try std.testing.expect(fm.shouldSpill());
}

test "DescRing.peek: returns partial batch, not all-or-nothing (C3/RC5)" {
    var prod: u32 = 0;
    var cons: u32 = 0;
    var ring: [16]XdpDesc = undefined;
    var dr = DescRing{ .producer = &prod, .consumer = &cons, .flags = null, .ring = &ring, .cached_prod = 0, .cached_cons = 0, .mask = 15 };

    // 5 descriptors available; peek 8 must return a PARTIAL batch (idx=0, n=5), not null.
    @atomicStore(u32, &prod, 5, .release);
    const r = dr.peek(8) orelse return error.UnexpectedNull;
    try std.testing.expectEqual(@as(u32, 0), r.idx);
    try std.testing.expectEqual(@as(u32, 5), r.n);
    try std.testing.expectEqual(@as(u32, 5), dr.cached_cons); // advanced by ACTUAL count

    // Ring now empty → null.
    try std.testing.expect(dr.peek(8) == null);

    // Exactly-count case: 3 more available, peek 3 → idx=5, n=3.
    @atomicStore(u32, &prod, 8, .release);
    const r2 = dr.peek(3) orelse return error.UnexpectedNull;
    try std.testing.expectEqual(@as(u32, 5), r2.idx);
    try std.testing.expectEqual(@as(u32, 3), r2.n);
}

test "UmemFrameManager.seedFreeFrames: pre-seeds the recycle reservoir (D5/RC6)" {
    const allocator = std.testing.allocator;
    var fm = try UmemFrameManager.init(allocator, 32, 4096);
    defer fm.deinit();

    // Seed the frames that don't fit in the fill ring: indices [16, 32).
    fm.seedFreeFrames(16, 32);
    try std.testing.expectEqual(@as(u32, 16), fm.free_head.load(.monotonic));
    // The 16 seeded slots hold frame indices 16..31 (the previously-orphaned half).
    for (0..16) |i| {
        try std.testing.expectEqual(@as(u32, @intCast(16 + i)), fm.free_ring[i & fm.free_ring_mask]);
    }
    // Out-of-range guard: end past frame_count seeds nothing extra.
    fm.seedFreeFrames(40, 50);
    try std.testing.expectEqual(@as(u32, 16), fm.free_head.load(.monotonic));
}

test "UmemFrameManager.release: 8 concurrent producers, zero frame loss/dup (D4/RC7)" {
    const allocator = std.testing.allocator;
    var fm = try UmemFrameManager.init(allocator, 256, 4096);
    defer fm.deinit();

    // Acquire all 256 frames (refcount 1 each).
    for (0..256) |i| fm.acquire(@as(u64, @intCast(i)) * 4096);

    // 8 threads each release 32 DISTINCT frames concurrently → the MPSC free ring.
    // Without free_mutex (RC7) this races: head advances before the slot is written,
    // so frames are lost/duplicated. With D4 every frame lands exactly once.
    const Worker = struct {
        fn run(f: *UmemFrameManager, start: usize) void {
            for (0..32) |k| f.release(@as(u64, @intCast(start + k)) * 4096);
        }
    };
    var threads: [8]std.Thread = undefined;
    for (0..8) |t| threads[t] = try std.Thread.spawn(.{}, Worker.run, .{ &fm, t * 32 });
    for (threads) |th| th.join();

    try std.testing.expectEqual(@as(u64, 0), fm.framesHeld());
    try std.testing.expectEqual(@as(u32, 256), fm.free_head.load(.monotonic));
    // Every frame index 0..255 appears EXACTLY once in the ring (no loss, no dup).
    var seen = [_]bool{false} ** 256;
    for (0..256) |i| {
        const idx = fm.free_ring[i & fm.free_ring_mask];
        try std.testing.expect(idx < 256 and !seen[idx]);
        seen[idx] = true;
    }
}

test "UmemFrameManager.shouldShed: gates on recycle-reservoir depth vs reserve (2026-07-07 backpressure)" {
    const allocator = std.testing.allocator;
    // Mock pool: 32 frames, reserve (low-water mark) = 8.
    var fm = try UmemFrameManager.init(allocator, 32, 4096);
    defer fm.deinit();
    const reserve: u32 = 8;

    // Empty reservoir (free_depth=0, the tonight's-spiral precondition) → SHED.
    try std.testing.expectEqual(@as(u64, 0), fm.freeDepth());
    try std.testing.expect(fm.shouldShed(reserve));

    // Seed exactly `reserve` frames into the reservoir → AT the boundary, still
    // shed (strictly-less semantics: free_depth < reserve sheds, == does not).
    fm.seedFreeFrames(0, reserve);
    try std.testing.expectEqual(@as(u64, reserve), fm.freeDepth());
    try std.testing.expect(!fm.shouldShed(reserve));

    // One frame short of the mark → SHED (below-reserve is the common case
    // during the spiral: reservoir draining faster than it refills).
    var fm2 = try UmemFrameManager.init(allocator, 32, 4096);
    defer fm2.deinit();
    fm2.seedFreeFrames(0, reserve - 1); // one short of the mark
    try std.testing.expectEqual(@as(u64, reserve - 1), fm2.freeDepth());
    try std.testing.expect(fm2.shouldShed(reserve));

    // Comfortably above the mark → do NOT shed (submit).
    var fm3 = try UmemFrameManager.init(allocator, 32, 4096);
    defer fm3.deinit();
    fm3.seedFreeFrames(0, 20);
    try std.testing.expectEqual(@as(u64, 20), fm3.freeDepth());
    try std.testing.expect(!fm3.shouldShed(reserve));
}

test "XdpStatistics: size" {
    // Ensure struct is packed correctly for kernel interface
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(XdpStatistics));
}

test "XdpDesc: size" {
    // Ensure descriptor struct matches kernel definition
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(XdpDesc));
}

test "parseHeaderOffset: standard ETH + IPv4 + UDP" {
    // Craft a minimal valid frame: ETH(14) + IPv4(IHL=5, protocol=17/UDP) + UDP(8) + payload
    var frame: [50]u8 = [_]u8{0} ** 50;
    // ETH: bytes 12-13 = EtherType 0x0800 (IPv4)
    frame[12] = 0x08;
    frame[13] = 0x00;
    // IPv4: byte 0 = version 4, IHL 5 (20 bytes)
    frame[14] = 0x45;
    // IPv4: byte 9 = protocol 17 (UDP)
    frame[14 + 9] = 17;
    // Expected: ETH(14) + IPv4(20) + UDP(8) = 42
    const result = XdpSocket.parseHeaderOffset(&frame);
    try std.testing.expectEqual(@as(u32, 42), result.payload_offset);
    try std.testing.expectEqual(@as(u32, 14), result.ip_offset);
}

test "parseHeaderOffset: VLAN tagged (802.1Q)" {
    // Frame with single VLAN tag: ETH(14) + VLAN(4) = 18 bytes L2
    var frame: [54]u8 = [_]u8{0} ** 54;
    // ETH: bytes 12-13 = TPID 0x8100 (VLAN)
    frame[12] = 0x81;
    frame[13] = 0x00;
    // VLAN tag: bytes 14-15 = TCI, bytes 16-17 = real EtherType 0x0800
    frame[16] = 0x08;
    frame[17] = 0x00;
    // IPv4 starts at byte 18: version 4, IHL 5
    frame[18] = 0x45;
    // IPv4: protocol = UDP
    frame[18 + 9] = 17;
    // Expected: ETH(14) + VLAN(4) + IPv4(20) + UDP(8) = 46
    const result = XdpSocket.parseHeaderOffset(&frame);
    try std.testing.expectEqual(@as(u32, 46), result.payload_offset);
    try std.testing.expectEqual(@as(u32, 18), result.ip_offset);
}

test "parseHeaderOffset: IPv4 with options (IHL=8)" {
    // IPv4 IHL=8 means 32 bytes of IP header (has 12 bytes of options)
    var frame: [62]u8 = [_]u8{0} ** 62;
    frame[12] = 0x08;
    frame[13] = 0x00;
    // IPv4: version 4, IHL 8 (32 bytes)
    frame[14] = 0x48;
    frame[14 + 9] = 17; // UDP
    // Expected: ETH(14) + IPv4(32) + UDP(8) = 54
    const result = XdpSocket.parseHeaderOffset(&frame);
    try std.testing.expectEqual(@as(u32, 54), result.payload_offset);
}

test "parseHeaderOffset: too short" {
    // Frame shorter than minimum 42 bytes — should return offset 0
    var frame: [30]u8 = [_]u8{0} ** 30;
    const result = XdpSocket.parseHeaderOffset(&frame);
    try std.testing.expectEqual(@as(u32, 0), result.payload_offset);
}

test "parseHeaderOffset: non-UDP protocol" {
    // Valid ETH + IPv4, but protocol = TCP (6) not UDP (17)
    var frame: [50]u8 = [_]u8{0} ** 50;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45; // IPv4, IHL=5
    frame[14 + 9] = 6; // TCP
    const result = XdpSocket.parseHeaderOffset(&frame);
    try std.testing.expectEqual(@as(u32, 0), result.payload_offset);
}
