//! Vexor Socket Abstraction
//!
//! High-performance UDP socket implementation optimized for validator workloads.
//! Supports:
//! - Non-blocking I/O
//! - Batch receive/send (recvmmsg/sendmmsg on Linux)
//! - Socket options for validator performance

const std = @import("std");
const posix = std.posix;
const packet = @import("packet.zig");
const builtin = @import("builtin");

const SO_BUSY_POLL: u32 = 46;
const SO_PREFER_BUSY_POLL: u32 = 69;
const SO_BUSY_POLL_BUDGET: u32 = 70;

var busy_poll_enabled: bool = true;

pub fn setBusyPollEnabled(enabled: bool) void {
    busy_poll_enabled = enabled;
}

/// UDP socket wrapper with performance optimizations
pub const UdpSocket = struct {
    fd: posix.socket_t,
    bound_addr: ?posix.sockaddr,
    recv_buffer_size: usize,
    send_buffer_size: usize,

    const Self = @This();

    /// Default buffer sizes optimized for Solana validator
    pub const DEFAULT_RECV_BUFFER: usize = 128 * 1024 * 1024; // 128MB
    pub const DEFAULT_SEND_BUFFER: usize = 128 * 1024 * 1024; // 128MB

    /// Create a new UDP socket
    pub fn init() !Self {
        const fd = try posix.socket(
            posix.AF.INET,
            posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
            0,
        );
        errdefer posix.close(fd);

        var socket = Self{
            .fd = fd,
            .bound_addr = null,
            .recv_buffer_size = 0,
            .send_buffer_size = 0,
        };

        // Apply performance optimizations
        try socket.setBufferSizes(DEFAULT_RECV_BUFFER, DEFAULT_SEND_BUFFER);
        try socket.setReuseAddr(true);
        if (busy_poll_enabled) {
            socket.setBusyPoll(true, 50, 64);
        }

        return socket;
    }

    /// Close the socket
    pub fn deinit(self: *Self) void {
        posix.close(self.fd);
        self.fd = -1;
    }

    /// Bind to an address
    pub fn bind(self: *Self, addr: std.net.Address) !void {
        const sockaddr = addr.any;
        try posix.bind(self.fd, &sockaddr, @sizeOf(@TypeOf(sockaddr)));
        self.bound_addr = sockaddr;
    }

    /// Bind to a port on all interfaces
    pub fn bindPort(self: *Self, port: u16) !void {
        const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        try self.bind(addr);
    }

    /// Set socket buffer sizes
    pub fn setBufferSizes(self: *Self, recv_size: usize, send_size: usize) !void {
        // Set receive buffer — use SO_RCVBUFFORCE to bypass rmem_max cap if we have CAP_NET_ADMIN
        const recv_val: i32 = @intCast(@min(recv_size, std.math.maxInt(i32)));
        // Try FORCE first (bypasses rmem_max), fall back to normal
        const SO_RCVBUFFORCE: u32 = 33;
        posix.setsockopt(self.fd, posix.SOL.SOCKET, SO_RCVBUFFORCE, &std.mem.toBytes(recv_val)) catch {
            posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(recv_val)) catch |err| {
                std.log.debug("Warning: Could not set RCVBUF to {}: {}\n", .{ recv_size, err });
            };
        };

        // Read back actual value (kernel doubles it)
        var actual_recv: i32 = 0;
        var optlen: u32 = @sizeOf(i32);
        _ = std.os.linux.syscall5(.getsockopt, @intCast(self.fd), posix.SOL.SOCKET, posix.SO.RCVBUF, @intFromPtr(&actual_recv), @intFromPtr(&optlen));
        std.log.debug("[SOCKET] fd={d} RCVBUF requested={d} actual={d}\n", .{ self.fd, recv_val, actual_recv });

        // Set send buffer
        const send_val: i32 = @intCast(@min(send_size, std.math.maxInt(i32)));
        posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(send_val)) catch |err| {
            std.log.debug("Warning: Could not set SNDBUF to {}: {}\n", .{ send_size, err });
        };

        self.recv_buffer_size = recv_size;
        self.send_buffer_size = send_size;
    }

    /// Enable address reuse
    pub fn setReuseAddr(self: *Self, enable: bool) !void {
        const val: i32 = if (enable) 1 else 0;
        try posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(val));
    }

    /// Enable busy polling for lower latency (Linux only)
    pub fn setBusyPoll(self: *Self, prefer: bool, busy_poll_us: u32, busy_poll_budget: u32) void {
        if (builtin.os.tag != .linux) return;

        const prefer_val: i32 = if (prefer) 1 else 0;
        posix.setsockopt(self.fd, posix.SOL.SOCKET, SO_PREFER_BUSY_POLL, &std.mem.toBytes(prefer_val)) catch |err| {
            std.log.debug("Warning: Could not set SO_PREFER_BUSY_POLL: {}\n", .{err});
        };

        const poll_us: i32 = @intCast(@min(busy_poll_us, @as(u32, std.math.maxInt(i32))));
        posix.setsockopt(self.fd, posix.SOL.SOCKET, SO_BUSY_POLL, &std.mem.toBytes(poll_us)) catch |err| {
            std.log.debug("Warning: Could not set SO_BUSY_POLL: {}\n", .{err});
        };

        const budget_val: i32 = @intCast(@min(busy_poll_budget, @as(u32, std.math.maxInt(i32))));
        posix.setsockopt(self.fd, posix.SOL.SOCKET, SO_BUSY_POLL_BUDGET, &std.mem.toBytes(budget_val)) catch |err| {
            std.log.debug("Warning: Could not set SO_BUSY_POLL_BUDGET: {}\n", .{err});
        };
    }

    /// Receive a single packet
    pub fn recv(self: *Self, pkt: *packet.Packet) !bool {
        var src_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const result = posix.recvfrom(
            self.fd,
            &pkt.data,
            0,
            @ptrCast(&src_addr),
            &addr_len,
        );

        if (result) |bytes| {
            // std.log.debug("[Socket] recv: got {d} bytes from {any}\n", .{ bytes, src_addr });
            pkt.len = @intCast(bytes);
            pkt.src_addr = sockaddrToPacketAddr(&src_addr);
            pkt.timestamp_ns = @intCast(std.time.nanoTimestamp());
            return true;
        } else |err| {
            if (err == error.WouldBlock) {
                return false;
            }
            // std.log.debug("[Socket] recv error: {}\n", .{err});
            return err;
        }
    }

    /// Receive multiple packets into a batch
    pub fn recvBatch(self: *Self, batch: *packet.PacketBatch) !usize {
        if (builtin.os.tag == .linux) {
            return self.recvBatchLinux(batch);
        } else {
            return self.recvBatchGeneric(batch);
        }
    }

    fn recvBatchGeneric(self: *Self, batch: *packet.PacketBatch) !usize {
        var received: usize = 0;

        while (!batch.isFull()) {
            if (batch.push()) |pkt| {
                const got = try self.recv(pkt);
                if (got) {
                    received += 1;
                } else {
                    // Would block - restore batch state and return
                    batch.len -= 1;
                    break;
                }
            }
        }

        return received;
    }

    // Perf (2026-07-08 batch3): recvmmsg scratch was [512]mmsghdr+[512]iovec+
    // [512]sockaddr on the STACK (~44KB) → tripped __zig_probe_stack (2.9% via
    // drainRepairPackets inlining) AND the per-call full struct-init memset'd
    // mmsghdr padding 512-wide (4.8% at tip). Move to THREAD-LOCAL (off the stack →
    // no probe; per-thread → race-free no matter which callers share a socket), wire
    // the constant fields once per thread, and per-call rewrite ONLY the variable
    // iovec.base + the kernel-clobbered namelen — no memset.
    threadlocal var tl_hdrs: [packet.MAX_BATCH_SIZE]std.os.linux.mmsghdr = undefined;
    threadlocal var tl_iovecs: [packet.MAX_BATCH_SIZE]posix.iovec = undefined;
    threadlocal var tl_addrs: [packet.MAX_BATCH_SIZE]posix.sockaddr.in = undefined;
    threadlocal var tl_wired: bool = false;

    fn recvBatchLinux(self: *Self, batch: *packet.PacketBatch) !usize {
        const MAX_BATCH = packet.MAX_BATCH_SIZE;

        // One-time per-thread: wire the constant mmsghdr/iovec fields (name/iov ptrs
        // into this thread's own tl_addrs/tl_iovecs, iovlen, iov.len, control/flags).
        if (!tl_wired) {
            for (0..MAX_BATCH) |i| {
                tl_iovecs[i].len = packet.MAX_PACKET_SIZE;
                tl_hdrs[i] = .{
                    .hdr = .{
                        .name = @ptrCast(&tl_addrs[i]),
                        .namelen = @sizeOf(posix.sockaddr.in),
                        .iov = @as([*]posix.iovec, @ptrCast(&tl_iovecs[i])),
                        .iovlen = 1,
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    },
                    .len = 0,
                };
            }
            tl_wired = true;
        }

        const start_idx = batch.len;
        const count = batch.packets.len - start_idx;
        if (count == 0) return 0;

        // Cap batch size to local buffer limits
        const batch_size = @min(count, MAX_BATCH);

        // Per-call: only the variable base pointer (this batch/offset) + reset the
        // namelen the kernel overwrites (input = name-buffer size). iov.len/wiring
        // stay from the one-time init; hdr.len is a kernel output.
        for (0..batch_size) |i| {
            tl_iovecs[i].base = &batch.packets[start_idx + i].data;
            tl_hdrs[i].hdr.namelen = @sizeOf(posix.sockaddr.in);
        }

        // Safe fd cast: fd<0 means socket was closed (prevents integer overflow panic)
        if (self.fd < 0) return error.SocketError;
        const fd_u: usize = @intCast(self.fd);
        const rc = std.os.linux.syscall5(.recvmmsg, fd_u, @intFromPtr(&tl_hdrs), @intCast(batch_size), 0, 0);

        // CRITICAL FIX: Raw syscalls return error as negative values in the usize result.
        // We must use E.init() (not posix.errno()) to properly extract the error code.
        const err = std.os.linux.E.init(rc);
        const received: usize = switch (err) {
            .SUCCESS => rc,
            .AGAIN => 0,
            else => return error.SocketError,
        };

        const now = @as(u64, @intCast(std.time.nanoTimestamp()));
        for (0..received) |i| {
            const pkt_idx = start_idx + i;
            batch.packets[pkt_idx].len = @intCast(tl_hdrs[i].len);
            batch.packets[pkt_idx].src_addr = sockaddrToPacketAddr(&tl_addrs[i]);
            batch.packets[pkt_idx].timestamp_ns = now;
        }
        batch.len += received;
        return received;
    }

    /// Send a single packet
    pub fn send(self: *Self, pkt: *const packet.Packet) !bool {
        const dest_addr = packetAddrToSockaddr(&pkt.src_addr);

        const result = posix.sendto(
            self.fd,
            pkt.data[0..pkt.len],
            0,
            @ptrCast(&dest_addr),
            @sizeOf(posix.sockaddr.in),
        );

        if (result) |_| {
            return true;
        } else |err| {
            if (err == error.WouldBlock) {
                return false;
            }
            return err;
        }
    }

    /// Send to a specific address
    pub fn sendTo(self: *Self, data: []const u8, addr: std.net.Address) !bool {
        const sockaddr = addr.any;

        const result = posix.sendto(
            self.fd,
            data,
            0,
            &sockaddr,
            @sizeOf(@TypeOf(sockaddr)),
        );

        if (result) |_| {
            return true;
        } else |err| {
            if (err == error.WouldBlock) {
                return false;
            }
            return err;
        }
    }

    /// Send multiple packets from a batch
    pub fn sendBatch(self: *Self, batch: *const packet.PacketBatch) !usize {
        if (builtin.os.tag == .linux) {
            return self.sendBatchLinux(batch);
        } else {
            return self.sendBatchGeneric(batch);
        }
    }

    fn sendBatchGeneric(self: *Self, batch: *const packet.PacketBatch) !usize {
        var sent: usize = 0;
        for (batch.slice()) |*pkt| {
            const success = try self.send(pkt);
            if (success) {
                sent += 1;
            } else {
                break;
            }
        }
        return sent;
    }

    fn sendBatchLinux(self: *Self, batch: *const packet.PacketBatch) !usize {
        const MAX_BATCH = packet.MAX_BATCH_SIZE;
        var hdrs: [MAX_BATCH]std.os.linux.mmsghdr = undefined;
        var iovecs: [MAX_BATCH]posix.iovec = undefined;
        var addrs: [MAX_BATCH]posix.sockaddr.in = undefined;

        const count = batch.len;
        if (count == 0) return 0;

        // We only support batch sending if all packets will fit in our stack buffers
        const batch_size = @min(count, MAX_BATCH);

        for (0..batch_size) |i| {
            const pkt = &batch.packets[i];
            addrs[i] = packetAddrToSockaddr(&pkt.src_addr); // src_addr in Packet is actually dest when sending

            iovecs[i] = .{
                .base = @constCast(&pkt.data),
                .len = pkt.len,
            };

            hdrs[i] = .{
                .hdr = .{
                    .name = @ptrCast(&addrs[i]),
                    .namelen = @sizeOf(posix.sockaddr.in),
                    .iov = @as([*]posix.iovec, @ptrCast(&iovecs[i])),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }

        // Safe fd cast: fd<0 means socket was closed (prevents integer overflow panic)
        if (self.fd < 0) return error.SocketError;
        const fd_u: usize = @intCast(self.fd);
        const rc = std.os.linux.syscall4(.sendmmsg, fd_u, @intFromPtr(&hdrs), @intCast(batch_size), 0);
        const sent = switch (posix.errno(rc)) {
            .SUCCESS => @as(usize, @intCast(rc)),
            .AGAIN => return 0,
            else => return error.SocketError,
        };

        return sent;
    }

    /// Get the bound port
    pub fn boundPort(self: *const Self) ?u16 {
        var addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(self.fd, @ptrCast(&addr), &addr_len) catch return null;
        return std.mem.bigToNative(u16, addr.port);
    }

    /// Get the actual OS-level bound address (IP + port) via getsockname. 2026-07-21
    /// dual-NIC TPU-ingest bind_addr KAT: lets tests assert the kernel really bound the
    /// requested IP (not just that the config field carried the right value).
    pub fn boundAddr(self: *const Self) ?packet.SocketAddr {
        var addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(self.fd, @ptrCast(&addr), &addr_len) catch return null;
        return sockaddrToPacketAddr(&addr);
    }

    // Helper conversions
    fn sockaddrToPacketAddr(sa: *const posix.sockaddr.in) packet.SocketAddr {
        var result = packet.SocketAddr{
            .family_port = (@as(u32, std.mem.bigToNative(u16, sa.port)) << 16) | 2,
            .addr = [_]u8{0} ** 16,
        };
        const addr_bytes = std.mem.asBytes(&sa.addr);
        @memcpy(result.addr[0..4], addr_bytes);
        return result;
    }

    fn packetAddrToSockaddr(pa: *const packet.SocketAddr) posix.sockaddr.in {
        return posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, @intCast(pa.port())),
            .addr = @bitCast(pa.addr[0..4].*),
            .zero = [_]u8{0} ** 8,
        };
    }
};

/// Multi-socket manager for handling multiple UDP endpoints
pub const SocketSet = struct {
    allocator: std.mem.Allocator,
    sockets: std.ArrayList(*UdpSocket),
    poll_fds: std.ArrayList(posix.pollfd),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .sockets = .empty,
            .poll_fds = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.sockets.items) |sock| {
            sock.deinit();
            self.allocator.destroy(sock);
        }
        self.sockets.deinit(self.allocator);
        self.poll_fds.deinit(self.allocator);
    }

    /// Add a socket to the set
    pub fn add(self: *Self, socket: *UdpSocket) !void {
        try self.sockets.append(self.allocator, socket);
        try self.poll_fds.append(self.allocator, .{
            .fd = socket.fd,
            .events = posix.POLL.IN,
            .revents = 0,
        });
    }

    /// Create and add a socket bound to a port
    pub fn addBoundSocket(self: *Self, port: u16) !*UdpSocket {
        const socket = try self.allocator.create(UdpSocket);
        errdefer self.allocator.destroy(socket);

        socket.* = try UdpSocket.init();
        errdefer socket.deinit();

        try socket.bindPort(port);
        try self.add(socket);

        return socket;
    }

    /// Poll all sockets for activity
    pub fn poll(self: *Self, timeout_ms: i32) !usize {
        if (self.poll_fds.items.len == 0) return 0;

        const ready = try posix.poll(self.poll_fds.items, timeout_ms);
        return @intCast(ready);
    }

    /// Check if a socket has data ready
    pub fn isReadable(self: *const Self, index: usize) bool {
        if (index >= self.poll_fds.items.len) return false;
        return (self.poll_fds.items[index].revents & posix.POLL.IN) != 0;
    }

    /// Get socket by index
    pub fn get(self: *const Self, index: usize) ?*UdpSocket {
        if (index >= self.sockets.items.len) return null;
        return self.sockets.items[index];
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "udp socket create and bind" {
    var socket = try UdpSocket.init();
    defer socket.deinit();

    // Bind to ephemeral port
    try socket.bindPort(0);

    const port = socket.boundPort();
    try std.testing.expect(port != null);
    try std.testing.expect(port.? > 0);
}

test "socket set" {
    var set = SocketSet.init(std.testing.allocator);
    defer set.deinit();

    const sock1 = try set.addBoundSocket(0);
    const sock2 = try set.addBoundSocket(0);

    try std.testing.expect(sock1.boundPort() != sock2.boundPort());
    try std.testing.expectEqual(@as(usize, 2), set.sockets.items.len);
}

test "send and receive" {
    // Create two sockets
    var sender = try UdpSocket.init();
    defer sender.deinit();
    try sender.bindPort(0);

    var receiver = try UdpSocket.init();
    defer receiver.deinit();
    try receiver.bindPort(0);

    const recv_port = receiver.boundPort().?;

    // Send a packet
    const test_data = "Hello, Vexor!";
    const dest = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, recv_port);
    _ = try sender.sendTo(test_data, dest);

    // Small delay for packet to arrive
    std.Thread.sleep(1_000_000); // 1ms

    // Receive
    var pkt = packet.Packet.init();
    const received = try receiver.recv(&pkt);

    try std.testing.expect(received);
    try std.testing.expectEqualSlices(u8, test_data, pkt.data[0..pkt.len]);
}
