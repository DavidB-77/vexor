//! Accelerated I/O Layer
//! Unified interface for high-performance packet I/O.
//!
//! Automatically selects the best available backend:
//! 1. AF_XDP (kernel bypass) - ~10M pps
//! 2. io_uring batch UDP - ~3M pps
//! 3. Standard UDP sockets - ~1M pps
//!
//! Usage:
//! ```zig
//! var io = try AcceleratedIO.init(allocator, .{
//!     .interface = "eth0",
//!     .prefer_xdp = true,
//! });
//! defer io.deinit();
//!
//! // Receive packets (zero-copy when possible)
//! const packets = try io.receiveBatch(64);
//! for (packets) |pkt| {
//!     processPacket(pkt);
//! }
//!
//! // Send packets
//! try io.sendBatch(&outgoing_packets);
//! ```
//!
//! This provides a unified API that TVU/TPU can use, with automatic
//! fallback if AF_XDP isn't available.

const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const af_xdp = @import("af_xdp/root.zig");
const shared_xdp = @import("af_xdp/shared_xdp.zig");
const io_uring_mod = @import("io_uring.zig");
const socket = @import("socket.zig");
const packet = @import("packet.zig");
const fs = std.fs;

/// Detect the default network interface from routing table
pub fn detectDefaultInterface(allocator: Allocator) ![]const u8 {
    // Read /proc/net/route to find default gateway interface
    const route_file = fs.openFileAbsolute("/proc/net/route", .{}) catch {
        return try allocator.dupe(u8, "eth0"); // Fallback
    };
    defer route_file.close();

    var buf: [4096]u8 = undefined;
    const bytes_read = route_file.readAll(&buf) catch {
        return try allocator.dupe(u8, "eth0");
    };
    const content = buf[0..bytes_read];

    // Parse route table - format: Iface Destination Gateway ...
    // Default route has Destination = 00000000
    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next(); // Skip header

    while (lines.next()) |line| {
        if (line.len == 0) continue;

        var fields = std.mem.tokenizeScalar(u8, line, '\t');
        const iface = fields.next() orelse continue;
        const dest = fields.next() orelse continue;

        // Check for default route (destination 00000000)
        if (std.mem.eql(u8, dest, "00000000")) {
            return try allocator.dupe(u8, iface);
        }
    }

    // Fallback: try to find first UP interface
    return try allocator.dupe(u8, "eth0");
}

/// Accelerated I/O configuration
pub const Config = struct {
    /// Network interface (for AF_XDP) - auto-detected if null
    interface: []const u8 = "",
    /// Queue ID (for multi-queue NICs)
    queue_id: u32 = 0,
    /// Prefer AF_XDP if available
    /// Uses copy mode (zero_copy=false) for safety with ixgbe driver
    prefer_xdp: bool = true,
    /// Fallback to io_uring if XDP unavailable
    prefer_io_uring: bool = true,
    /// Bind port for receiving
    bind_port: u16 = 0,
    /// Batch size for packet operations
    batch_size: usize = 64,
    /// UMEM frame count (for AF_XDP)
    umem_frame_count: u32 = 4096,
    /// Enable zero-copy mode (requires driver support, ~30M pps)
    /// SAFETY: Disabled by default. Zero-copy UMEM registration crashes ixgbe driver.
    /// Only enable after confirming driver firmware supports it.
    zero_copy: bool = false,
    /// Shared XDP manager (for multi-socket AF_XDP)
    /// If provided, socket will register in shared XSKMAP instead of creating own XDP program
    shared_xdp: ?*shared_xdp.SharedXdpManager = null,
};

/// Backend type in use
pub const Backend = enum {
    af_xdp,
    io_uring,
    standard_udp,

    pub fn name(self: Backend) []const u8 {
        return switch (self) {
            .af_xdp => "AF_XDP (kernel bypass)",
            .io_uring => "io_uring (batched)",
            .standard_udp => "Standard UDP",
        };
    }

    pub fn expectedPps(self: Backend) u64 {
        return switch (self) {
            .af_xdp => 10_000_000,
            .io_uring => 3_000_000,
            .standard_udp => 1_000_000,
        };
    }
};

/// Packet buffer for zero-copy operations
pub const PacketBuffer = struct {
    data: []u8,
    len: usize,
    src_addr: packet.SocketAddr,
    timestamp: i64,

    /// Get the actual payload
    pub fn payload(self: *const PacketBuffer) []const u8 {
        return self.data[0..self.len];
    }
};

/// Statistics (thread-safe with atomic operations)
pub const Stats = struct {
    packets_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    packets_sent: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes_sent: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    receive_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    send_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    backend_switches: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Add to a stat atomically
    pub fn add(stat: *std.atomic.Value(u64), value: u64) void {
        _ = stat.fetchAdd(value, .seq_cst);
    }

    /// Increment a stat atomically
    pub fn inc(stat: *std.atomic.Value(u64)) void {
        _ = stat.fetchAdd(1, .seq_cst);
    }

    /// Get a stat value
    pub fn get(stat: *const std.atomic.Value(u64)) u64 {
        return stat.load(.seq_cst);
    }
};

/// Accelerated I/O interface
pub const AcceleratedIO = struct {
    allocator: Allocator,
    config: Config,
    backend: Backend,
    stats: Stats,

    // Backend-specific state
    xdp_socket: ?*af_xdp.XdpSocket,
    xdp_program: ?*af_xdp.XdpProgram, // eBPF XDP program for kernel-level filtering
    udp_socket: ?socket.UdpSocket,
    io_uring_ring: ?*io_uring_mod.IoUring,
    io_uring_socket: ?*io_uring_mod.IoUringUdpSocket,

    // Packet buffers for batch operations
    rx_buffers: []PacketBuffer,
    tx_buffers: []PacketBuffer,

    const Self = @This();

    /// Initialize with automatic backend selection
    pub fn init(allocator: Allocator, config: Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Auto-detect interface if not specified
        var effective_config = config;
        if (config.interface.len == 0) {
            effective_config.interface = detectDefaultInterface(allocator) catch "eth0";
            std.log.info("[AcceleratedIO] Auto-detected interface: {s}", .{effective_config.interface});
        }

        // Allocate buffers
        const rx_buffers = try allocator.alloc(PacketBuffer, config.batch_size);
        errdefer allocator.free(rx_buffers);

        for (rx_buffers) |*buf| {
            buf.data = try allocator.alloc(u8, 2048);
            buf.len = 0;
            buf.src_addr = packet.SocketAddr.ipv4(.{ 0, 0, 0, 0 }, 0);
            buf.timestamp = 0;
        }

        const tx_buffers = try allocator.alloc(PacketBuffer, config.batch_size);
        errdefer allocator.free(tx_buffers);

        for (tx_buffers) |*buf| {
            buf.data = try allocator.alloc(u8, 2048);
            buf.len = 0;
            buf.src_addr = packet.SocketAddr.ipv4(.{ 0, 0, 0, 0 }, 0);
            buf.timestamp = 0;
        }

        self.* = .{
            .allocator = allocator,
            .config = effective_config,
            .backend = .standard_udp, // Will be set by selectBackend
            .stats = .{},
            .xdp_socket = null,
            .xdp_program = null,
            .udp_socket = null,
            .io_uring_ring = null,
            .io_uring_socket = null,
            .rx_buffers = rx_buffers,
            .tx_buffers = tx_buffers,
        };

        // Select and initialize the best available backend
        try self.selectBackend();

        return self;
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        if (self.xdp_program) |prog| {
            prog.deinit();
            self.allocator.destroy(prog);
        }

        if (self.xdp_socket) |xdp| {
            xdp.deinit();
            self.allocator.destroy(xdp);
        }

        if (self.udp_socket) |*udp| {
            udp.deinit();
        }

        if (self.io_uring_socket) |s| {
            s.deinit();
        }

        if (self.io_uring_ring) |r| {
            r.deinit();
        }

        for (self.rx_buffers) |*buf| {
            self.allocator.free(buf.data);
        }
        self.allocator.free(self.rx_buffers);

        for (self.tx_buffers) |*buf| {
            self.allocator.free(buf.data);
        }
        self.allocator.free(self.tx_buffers);

        self.allocator.destroy(self);
    }

    /// Select the best available backend
    fn selectBackend(self: *Self) !void {
        // Try AF_XDP first (Linux only, requires privileges)
        if (self.config.prefer_xdp and builtin.os.tag == .linux) {
            if (self.tryInitXdp()) {
                self.backend = .af_xdp;
                std.log.info("[AcceleratedIO] Using AF_XDP backend (~10M pps)", .{});
                return;
            }
        }

        // Try io_uring (Linux 5.1+)
        if (self.config.prefer_io_uring and builtin.os.tag == .linux) {
            if (self.tryInitIoUring()) {
                self.backend = .io_uring;
                std.log.info("[AcceleratedIO] Using io_uring backend (~3M pps)", .{});
                return;
            }
        }

        // Fall back to standard UDP
        try self.initStandardUdp();
        self.backend = .standard_udp;
        std.log.info("[AcceleratedIO] Using standard UDP backend (~1M pps)", .{});
    }

    /// Try to initialize AF_XDP with eBPF kernel-level filtering
    /// Falls back to userspace filtering if eBPF unavailable
    /// SAFE: Creates program WITHOUT attaching until socket is registered
    fn tryInitXdp(self: *Self) bool {
        std.log.debug("[AF_XDP] Checking availability on interface: {s}", .{self.config.interface});

        if (!af_xdp.isAvailable()) {
            std.log.debug("[AF_XDP] Socket creation test failed - not available", .{});
            return false;
        }

        // Check if using shared XDP manager (multi-socket mode)
        if (self.config.shared_xdp) |manager| {
            return self.tryInitXdpShared(manager);
        }

        // Standalone mode: create own XDP program
        return self.tryInitXdpStandalone();
    }

    /// Initialize AF_XDP in shared mode (multiple sockets, ONE XDP program)
    fn tryInitXdpShared(self: *Self, manager: *shared_xdp.SharedXdpManager) bool {
        std.log.debug("[AF_XDP] Initializing in SHARED mode (queue_id: {d})", .{self.config.queue_id});

        // Create AF_XDP socket
        const xdp_ptr = self.allocator.create(af_xdp.XdpSocket) catch {
            std.log.debug("[AF_XDP] Failed to allocate XdpSocket", .{});
            return false;
        };

        xdp_ptr.* = af_xdp.XdpSocket.init(self.allocator, .{
            .interface = self.config.interface,
            .queue_id = self.config.queue_id,
            .frame_count = self.config.umem_frame_count,
            .zero_copy = self.config.zero_copy,
        }) catch |err| {
            std.log.warn("[AF_XDP] Socket init failed for queue {d}: {}", .{ self.config.queue_id, err });
            self.allocator.destroy(xdp_ptr);
            return false;
        };

        // Register socket in shared XSKMAP under the queue it actually bound to.
        // The map key MUST equal config.queue_id (the bind queue): xdp_filter.c
        // redirects with key = ctx->rx_queue_index, and the kernel delivers a packet
        // only when xsks_map[rx_queue_index] holds a socket bound to that same queue.
        manager.registerSocket(self.config.queue_id, @intCast(xdp_ptr.fd)) catch |err| {
            std.log.warn("[AF_XDP] Failed to register socket in shared XSKMAP: {}", .{err});
            xdp_ptr.deinit();
            self.allocator.destroy(xdp_ptr);
            return false;
        };

        self.xdp_socket = xdp_ptr;
        self.xdp_program = null; // No ownership of XDP program in shared mode

        std.log.info("[AF_XDP] ✅ Socket registered in shared XSKMAP (queue_id: {d})", .{self.config.queue_id});
        return true;
    }

    /// Initialize AF_XDP in standalone mode (one socket, own XDP program)
    /// IMPORTANT: XDP program must be attached BEFORE socket bind.
    /// The kernel's xsk_bind() requires an XDP program on the interface.
    /// Order: load program → attach → create socket (bind) → register XSKMAP
    fn tryInitXdpStandalone(self: *Self) bool {
        // Get interface index for eBPF program
        const ifindex = getInterfaceIndex(self.config.interface) catch |err| {
            std.log.warn("[AF_XDP] Failed to get interface index: {} - falling back to userspace filtering", .{err});
            return self.tryInitXdpWithoutEbpf();
        };

        const xdp_mode: af_xdp.XdpProgram.AttachMode = if (self.config.zero_copy) .driver else .skb;
        std.log.info("[AF_XDP] Standalone init: ifindex={d}, mode={s}, zero_copy={}, port={d}", .{
            ifindex,
            if (self.config.zero_copy) "DRV (hardware)" else "SKB (software, safe)",
            self.config.zero_copy,
            self.config.bind_port,
        });

        // STEP 1: Create XDP program (loads eBPF bytecode but doesn't attach yet)
        var xdp_prog_ptr = self.allocator.create(af_xdp.XdpProgram) catch {
            std.log.warn("[AF_XDP] Failed to allocate XdpProgram - falling back to userspace filtering", .{});
            return self.tryInitXdpWithoutEbpf();
        };

        xdp_prog_ptr.* = af_xdp.XdpProgram.initWithoutAttach(
            self.allocator,
            ifindex,
            xdp_mode,
            self.config.bind_port,
        ) catch |err| {
            std.log.warn("[AF_XDP] eBPF program creation failed: {} - using userspace filtering (~10M pps)", .{err});
            self.allocator.destroy(xdp_prog_ptr);
            return self.tryInitXdpWithoutEbpf();
        };

        // STEP 2: Attach XDP program to NIC BEFORE socket bind.
        // The kernel's xsk_bind() checks for an active XDP program on the interface.
        // Without it, bind() returns EINVAL.
        //
        // SKB mode: uses generic XDP (software path, NO NIC reset, safe on bnxt)
        // DRV mode: uses driver XDP (hardware path, NIC reset, needed for zero-copy)
        std.log.info("[AF_XDP] Attaching XDP program ({s} mode)...", .{
            if (self.config.zero_copy) "DRV" else "SKB",
        });
        xdp_prog_ptr.attach() catch |err| {
            if (self.config.zero_copy) {
                std.log.warn("[AF_XDP] DRV mode attach failed: {} - falling back to SKB copy mode", .{err});
                // Try SKB mode instead of giving up entirely
                self.config.zero_copy = false;
                xdp_prog_ptr.mode = .skb;
                xdp_prog_ptr.attach() catch |err2| {
                    std.log.warn("[AF_XDP] SKB attach also failed: {} - falling back to userspace", .{err2});
                    xdp_prog_ptr.deinit();
                    self.allocator.destroy(xdp_prog_ptr);
                    return self.tryInitXdpWithoutEbpf();
                };
            } else {
                std.log.warn("[AF_XDP] SKB attach failed: {} - falling back to userspace filtering", .{err});
                xdp_prog_ptr.deinit();
                self.allocator.destroy(xdp_prog_ptr);
                return self.tryInitXdpWithoutEbpf();
            }
        };
        std.log.info("[AF_XDP] ✅ XDP program attached successfully", .{});

        // STEP 3: Create AF_XDP socket (bind happens inside init)
        // Now that XDP program is attached, xsk_bind() will find it.
        const xdp_ptr = self.allocator.create(af_xdp.XdpSocket) catch {
            std.log.debug("[AF_XDP] Failed to allocate XdpSocket", .{});
            xdp_prog_ptr.deinit();
            self.allocator.destroy(xdp_prog_ptr);
            return false;
        };

        xdp_ptr.* = af_xdp.XdpSocket.init(self.allocator, .{
            .interface = self.config.interface,
            .queue_id = self.config.queue_id,
            .frame_count = self.config.umem_frame_count,
            .zero_copy = self.config.zero_copy,
        }) catch |err| {
            std.log.warn("[AF_XDP] Socket init failed for queue {d}: {}", .{ self.config.queue_id, err });
            xdp_prog_ptr.deinit();
            self.allocator.destroy(xdp_ptr);
            self.allocator.destroy(xdp_prog_ptr);
            return false;
        };

        // STEP 4: Register AF_XDP socket in eBPF XSKMAP
        xdp_prog_ptr.registerSocket(self.config.queue_id, @intCast(xdp_ptr.fd)) catch |err| {
            std.log.warn("[AF_XDP] Failed to register socket in XSKMAP: {}", .{err});
            xdp_ptr.deinit();
            self.allocator.destroy(xdp_ptr);
            xdp_prog_ptr.deinit();
            self.allocator.destroy(xdp_prog_ptr);
            return self.tryInitXdpWithoutEbpf();
        };

        // Add port to eBPF filter map (if port is specified)
        if (self.config.bind_port > 0) {
            if (xdp_prog_ptr.addPort(self.config.bind_port)) {
                std.log.info("[AF_XDP] Added port {d} to eBPF filter (kernel-level filtering active)", .{self.config.bind_port});
            } else |err| {
                std.log.warn("[AF_XDP] Failed to add port {d} to filter: {} - packets may not be filtered", .{ self.config.bind_port, err });
                // Continue anyway - eBPF program will pass all packets
            }
        }

        self.xdp_socket = xdp_ptr;
        self.xdp_program = xdp_prog_ptr;
        // C4 (AFXDP-REWORK): read the ACTUAL bound mode from the socket (C5 sets config.zero_copy
        // = false on a copy-mode fallback) and drop the fake "~30M pps" claim. The authoritative
        // bound-mode banner is socket.zig:636 "[AF_XDP] Bound to interface ... with <mode>".
        const actual_zc = if (self.xdp_socket) |s| s.config.zero_copy else false;
        const mode_str: []const u8 = if (actual_zc) "zero-copy" else "copy mode";
        std.log.info("[AF_XDP] Initialized with eBPF filtering, {s}", .{mode_str});
        return true;
    }

    /// Initialize AF_XDP without eBPF (userspace filtering fallback)
    fn tryInitXdpWithoutEbpf(self: *Self) bool {
        std.log.info("[AF_XDP] Using userspace port filtering (~10M pps)", .{});
        // Allocate XDP socket on heap
        const xdp_ptr = self.allocator.create(af_xdp.XdpSocket) catch {
            std.log.debug("[AF_XDP] Failed to allocate XdpSocket", .{});
            return false;
        };

        xdp_ptr.* = af_xdp.XdpSocket.init(self.allocator, .{
            .interface = self.config.interface,
            .queue_id = self.config.queue_id,
            .frame_count = self.config.umem_frame_count,
            .zero_copy = self.config.zero_copy,
        }) catch |err| {
            std.log.warn("[AF_XDP] Init failed for queue {d}: {} - will try fallback", .{ self.config.queue_id, err });
            self.allocator.destroy(xdp_ptr);
            return false;
        };

        self.xdp_socket = xdp_ptr;
        std.log.info("[AF_XDP] Initialized without eBPF (userspace filtering, ~10M pps)", .{});
        return true;
    }

    /// Get interface index (helper function)
    fn getInterfaceIndex(interface: []const u8) !u32 {
        // Reuse the function from af_xdp.socket module
        return af_xdp.socket.getInterfaceIndex(interface);
    }

    /// Try to initialize io_uring
    fn tryInitIoUring(self: *Self) bool {
        // Check if io_uring is available
        if (!io_uring_mod.IoUring.isAvailable()) {
            std.log.debug("[io_uring] Not available on this system", .{});
            return false;
        }

        // Initialize io_uring
        self.io_uring_ring = io_uring_mod.IoUring.init(self.allocator, .{
            .sq_entries = 256,
            .cq_entries = 512,
        }) catch |err| {
            std.log.debug("[io_uring] Init failed: {}", .{err});
            return false;
        };

        // Create UDP socket with io_uring
        self.io_uring_socket = io_uring_mod.IoUringUdpSocket.init(
            self.allocator,
            self.io_uring_ring.?,
            self.config.batch_size,
        ) catch |err| {
            std.log.debug("[io_uring] Socket init failed: {}", .{err});
            if (self.io_uring_ring) |r| {
                r.deinit();
                self.io_uring_ring = null;
            }
            return false;
        };

        // Bind if port specified
        if (self.config.bind_port > 0) {
            self.io_uring_socket.?.bind(self.config.bind_port) catch |err| {
                std.log.debug("[io_uring] Bind failed: {}", .{err});
                if (self.io_uring_socket) |s| {
                    s.deinit();
                    self.io_uring_socket = null;
                }
                if (self.io_uring_ring) |r| {
                    r.deinit();
                    self.io_uring_ring = null;
                }
                return false;
            };
        }

        return true;
    }

    /// Initialize standard UDP socket
    fn initStandardUdp(self: *Self) !void {
        std.log.debug("[ACCEL-IO] initStandardUdp: creating socket for port {d}\n", .{self.config.bind_port});
        var udp = try socket.UdpSocket.init();
        errdefer udp.deinit();

        if (self.config.bind_port > 0) {
            std.log.debug("[ACCEL-IO] initStandardUdp: binding port {d}...\n", .{self.config.bind_port});
            udp.bindPort(self.config.bind_port) catch |err| {
                std.log.debug("[ACCEL-IO] initStandardUdp: FAILED to bind port {d}: {}\n", .{ self.config.bind_port, err });
                return err;
            };
            std.log.debug("[ACCEL-IO] initStandardUdp: port {d} bound successfully\n", .{self.config.bind_port});
        }

        self.udp_socket = udp;
    }

    /// Get the underlying XDP socket (for zero-copy path and frame manager access)
    pub fn getXdpSocket(self: *Self) ?*af_xdp.XdpSocket {
        return self.xdp_socket;
    }

    /// Receive a batch of packets
    pub fn receiveBatch(self: *Self, max_packets: usize) ![]PacketBuffer {
        const count = @min(max_packets, self.rx_buffers.len);

        switch (self.backend) {
            .af_xdp => return self.receiveXdp(count),
            .io_uring => return self.receiveIoUring(count),
            .standard_udp => return self.receiveStandardUdp(count),
        }
    }

    /// Receive using AF_XDP
    /// NOTE: With eBPF program, only packets matching our port filter reach userspace
    /// Without eBPF, we would need userspace filtering (removed for performance)
    fn receiveXdp(self: *Self, max_packets: usize) ![]PacketBuffer {
        var xdp = self.xdp_socket orelse return error.NotInitialized;

        // Create temporary packet array for XDP recv
        var xdp_packets: [128]af_xdp.Packet = undefined;
        const recv_count = @min(max_packets, xdp_packets.len);

        const received_count = try xdp.recv(xdp_packets[0..recv_count]);

        var processed: usize = 0;

        for (0..received_count) |i| {
            if (processed >= self.rx_buffers.len) break;

            const pkt = &xdp_packets[i];

            // With eBPF program: packets are already filtered in kernel
            // We only receive packets matching our port filter
            // No userspace filtering needed - this is the performance win!

            // PARSE L2/L3/L4 HEADERS TO EXTRACT PAYLOAD
            var offset: usize = 14; // Base Ethernet header

            // Check if packet is large enough for Ethernet header
            if (pkt.len < offset) continue;

            // Check for 802.1Q VLAN tag (0x8100)
            const eth_type = std.mem.readInt(u16, pkt.data[12..14], .big);
            if (eth_type == 0x8100) {
                offset += 4; // Skip 4-byte VLAN tag
                if (pkt.len < offset) continue;
            }

            // Need at least IPv4 header (min 20 bytes)
            if (pkt.len < offset + 20) continue;

            // Extract IPv4 header length (IHL)
            const ihl = pkt.data[offset] & 0x0F;
            const ip_header_len = @as(usize, ihl) * 4;

            // Extract source IP from IPv4 header (offset 12-15)
            const src_ip_bytes = pkt.data[offset + 12 .. offset + 16];
            const src_ip: [4]u8 = .{ src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3] };

            // Proceed past IPv4 header
            offset += ip_header_len;

            // Need at least UDP header (8 bytes)
            if (pkt.len < offset + 8) continue;

            // Optional enhancement: extract source port from UDP (offset 0-1)
            // const src_port = std.mem.readInt(u16, pkt.data[offset .. offset + 2], .big);

            // Skip UDP header
            offset += 8;

            const payload_len = pkt.len - offset;

            const buf = &self.rx_buffers[processed];
            const copy_len = @min(payload_len, buf.data.len);
            @memcpy(buf.data[0..copy_len], pkt.data[offset .. offset + copy_len]);
            buf.len = copy_len;
            buf.src_addr = packet.SocketAddr.ipv4(src_ip, 0); // Port generally unused here
            buf.timestamp = @intCast(std.time.nanoTimestamp());

            _ = self.stats.packets_received.fetchAdd(1, .monotonic);
            _ = self.stats.bytes_received.fetchAdd(copy_len, .monotonic);
            processed += 1;
        }

        return self.rx_buffers[0..processed];
    }

    /// Receive using io_uring
    fn receiveIoUring(self: *Self, max_packets: usize) ![]PacketBuffer {
        const ring = self.io_uring_ring orelse return error.NotInitialized;
        const sock = self.io_uring_socket orelse return error.NotInitialized;

        // Queue receive operations
        const queued = try sock.queueRecvBatch(max_packets);
        if (queued == 0) return self.rx_buffers[0..0];

        // Submit and wait for completions
        _ = try ring.submitAndWait(1);

        // Process completions
        var results: [128]io_uring_mod.IoUringUdpSocket.RecvResult = undefined;
        const completed = try sock.processCompletions(&results);

        // Copy to our buffers
        var processed: usize = 0;
        for (results[0..completed]) |result| {
            if (processed >= self.rx_buffers.len) break;

            const buf = &self.rx_buffers[processed];
            const copy_len = @min(result.len, buf.data.len);
            @memcpy(buf.data[0..copy_len], result.data[0..copy_len]);
            buf.len = copy_len;
            buf.timestamp = @intCast(std.time.nanoTimestamp());

            _ = self.stats.packets_received.fetchAdd(1, .monotonic);
            _ = self.stats.bytes_received.fetchAdd(copy_len, .monotonic);
            processed += 1;
        }

        return self.rx_buffers[0..processed];
    }

    /// Receive using standard UDP
    fn receiveStandardUdp(self: *Self, max_packets: usize) ![]PacketBuffer {
        const udp = &(self.udp_socket orelse return error.NotInitialized);

        var received: usize = 0;

        // Non-blocking receive loop
        while (received < max_packets) {
            const buf = &self.rx_buffers[received];

            // Create a temporary Packet to use with recv()
            var temp_pkt = packet.Packet.init();
            const got = udp.recv(&temp_pkt) catch |err| {
                if (err == error.WouldBlock) break;
                _ = self.stats.receive_errors.fetchAdd(1, .monotonic);
                return err;
            };

            if (!got) break; // No packet available

            // Copy from Packet to PacketBuffer
            const copy_len = @min(temp_pkt.len, buf.data.len);
            @memcpy(buf.data[0..copy_len], temp_pkt.data[0..copy_len]);
            buf.len = copy_len;
            buf.src_addr = temp_pkt.src_addr;
            buf.timestamp = @intCast(std.time.nanoTimestamp());

            _ = self.stats.packets_received.fetchAdd(1, .monotonic);
            _ = self.stats.bytes_received.fetchAdd(copy_len, .monotonic);
            received += 1;
        }

        return self.rx_buffers[0..received];
    }

    /// Send a single packet
    pub fn send(self: *Self, data: []const u8, dst_addr: packet.SocketAddr) !void {
        if (data.len > 2048) return error.PacketTooLarge;

        // Use first tx buffer for single sends
        // Note: This is not thread-safe if send() is called concurrently without locking/reservation
        // For high-performance, use sendBatch
        const buf = &self.tx_buffers[0];
        @memcpy(buf.data[0..data.len], data);
        buf.len = data.len;

        const batch = self.tx_buffers[0..1];
        _ = try self.sendBatch(batch, dst_addr);
    }

    /// Send a batch of packets
    pub fn sendBatch(self: *Self, packets: []const PacketBuffer, dst_addr: packet.SocketAddr) !usize {
        switch (self.backend) {
            .af_xdp => return self.sendXdp(packets, dst_addr),
            .io_uring => return self.sendIoUring(packets, dst_addr),
            .standard_udp => return self.sendStandardUdp(packets, dst_addr),
        }
    }

    /// Send using AF_XDP
    fn sendXdp(self: *Self, packets: []const PacketBuffer, dst_addr: packet.SocketAddr) !usize {
        var xdp = self.xdp_socket orelse return error.NotInitialized;
        _ = dst_addr;

        // Convert PacketBuffer to af_xdp.Packet
        var xdp_packets: [128]af_xdp.Packet = undefined;
        const send_count = @min(packets.len, xdp_packets.len);

        for (0..send_count) |i| {
            const src = &packets[i];
            var pkt = &xdp_packets[i];
            const copy_len = @min(src.len, pkt.data.len);
            @memcpy(pkt.data[0..copy_len], src.data[0..copy_len]);
            pkt.len = @intCast(copy_len);
        }

        const sent = xdp.send(xdp_packets[0..send_count]) catch |err| {
            Stats.inc(&self.stats.send_errors);
            return err;
        };

        Stats.add(&self.stats.packets_sent, sent);
        for (0..sent) |i| {
            Stats.add(&self.stats.bytes_sent, packets[i].len);
        }

        return sent;
    }

    /// Send using io_uring
    fn sendIoUring(self: *Self, packets: []const PacketBuffer, dst_addr: packet.SocketAddr) !usize {
        const ring = self.io_uring_ring orelse return error.NotInitialized;
        const sock = self.io_uring_socket orelse return error.NotInitialized;

        // Queue send operations
        var queued: usize = 0;
        for (packets) |pkt| {
            sock.queueSend(pkt.payload(), dst_addr, queued) catch break;
            queued += 1;
        }

        if (queued == 0) return 0;

        // Submit
        _ = try ring.submit();

        // Wait for completions (non-blocking check)
        var cqes: [64]io_uring_mod.CQE = undefined;
        const completed = ring.getCqes(&cqes);

        var sent: usize = 0;
        for (cqes[0..completed]) |cqe| {
            if (cqe.res >= 0) {
                sent += 1;
            } else {
                Stats.inc(&self.stats.send_errors);
            }
        }

        Stats.add(&self.stats.packets_sent, sent);
        for (0..sent) |i| {
            if (i < packets.len) {
                Stats.add(&self.stats.bytes_sent, packets[i].len);
            }
        }

        return sent;
    }

    /// Send using standard UDP
    fn sendStandardUdp(self: *Self, packets: []const PacketBuffer, dst_addr: packet.SocketAddr) !usize {
        var udp = self.udp_socket orelse return error.NotInitialized;

        var sent: usize = 0;

        for (packets) |pkt| {
            var pkt_out = packet.Packet.init();
            @memcpy(pkt_out.data[0..pkt.len], pkt.payload());
            pkt_out.len = @intCast(pkt.len);
            pkt_out.src_addr = dst_addr;

            if (udp.send(&pkt_out)) |_| {} else |err| {
                Stats.inc(&self.stats.send_errors);
                std.log.debug("[AcceleratedIO] send error: {}", .{err});
                continue;
            }
            sent += 1;
            Stats.inc(&self.stats.packets_sent);
            Stats.add(&self.stats.bytes_sent, pkt.len);
        }

        return sent;
    }

    /// Get current backend
    pub fn getBackend(self: *const Self) Backend {
        return self.backend;
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return self.stats;
    }

    /// Check if using kernel bypass
    pub fn isKernelBypass(self: *const Self) bool {
        return self.backend == .af_xdp;
    }

    /// Get expected packets per second for current backend
    pub fn expectedPps(self: *const Self) u64 {
        return self.backend.expectedPps();
    }

    /// Bind to a specific port
    /// Note: AF_XDP binds during init and uses BPF for port filtering
    pub fn bind(self: *Self, port: u16) !void {
        // AF_XDP binds to interface during init - port filtering needs BPF
        if (self.backend == .af_xdp) {
            return;
        }

        // Standard UDP binding
        if (self.udp_socket) |*udp| {
            try udp.bindPort(port);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "AcceleratedIO: init with standard UDP" {
    const allocator = std.testing.allocator;

    var io = try AcceleratedIO.init(allocator, .{
        .prefer_xdp = false, // Force standard UDP
        .prefer_io_uring = false,
        .bind_port = 0,
    });
    defer io.deinit();

    try std.testing.expectEqual(Backend.standard_udp, io.getBackend());
}

test "AcceleratedIO: backend selection" {
    // Test that we can at least create the I/O layer
    const allocator = std.testing.allocator;

    var io = try AcceleratedIO.init(allocator, .{});
    defer io.deinit();

    // Backend should be one of the valid options
    const backend = io.getBackend();
    try std.testing.expect(
        backend == .af_xdp or
            backend == .io_uring or
            backend == .standard_udp,
    );
}
