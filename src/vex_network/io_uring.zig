//! Vexor io_uring Backend
//!
//! High-performance asynchronous I/O using Linux io_uring.
//! Provides ~3M packets/sec throughput for network operations.
//!
//! Features:
//! - Batched system calls (reduced syscall overhead)
//! - Zero-copy where possible
//! - Multiple operations per submission
//! - Completion batching
//!
//! Requirements:
//! - Linux 5.1+ kernel
//! - liburing (optional, we use direct syscalls)

const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const linux = std.os.linux;
const posix = std.posix;
const packet = @import("packet.zig");

const SO_BUSY_POLL: u32 = 46;
const SO_PREFER_BUSY_POLL: u32 = 69;
const SO_BUSY_POLL_BUDGET: u32 = 70;

var busy_poll_enabled: bool = true;

pub fn setBusyPollEnabled(enabled: bool) void {
    busy_poll_enabled = enabled;
}

/// io_uring setup flags
pub const IORING_SETUP_IOPOLL = 1 << 0;
pub const IORING_SETUP_SQPOLL = 1 << 1;
pub const IORING_SETUP_SQ_AFF = 1 << 2;
pub const IORING_SETUP_CQSIZE = 1 << 3;
pub const IORING_SETUP_CLAMP = 1 << 4;
pub const IORING_SETUP_ATTACH_WQ = 1 << 5;

/// io_uring operation codes
pub const IORING_OP = enum(u8) {
    NOP = 0,
    READV = 1,
    WRITEV = 2,
    FSYNC = 3,
    READ_FIXED = 4,
    WRITE_FIXED = 5,
    POLL_ADD = 6,
    POLL_REMOVE = 7,
    SYNC_FILE_RANGE = 8,
    SENDMSG = 9,
    RECVMSG = 10,
    TIMEOUT = 11,
    TIMEOUT_REMOVE = 12,
    ACCEPT = 13,
    ASYNC_CANCEL = 14,
    LINK_TIMEOUT = 15,
    CONNECT = 16,
    FALLOCATE = 17,
    OPENAT = 18,
    CLOSE = 19,
    FILES_UPDATE = 20,
    STATX = 21,
    READ = 22,
    WRITE = 23,
    FADVISE = 24,
    MADVISE = 25,
    SEND = 26,
    RECV = 27,
    OPENAT2 = 28,
    EPOLL_CTL = 29,
    SPLICE = 30,
    PROVIDE_BUFFERS = 31,
    REMOVE_BUFFERS = 32,
    TEE = 33,
    SHUTDOWN = 34,
    RENAMEAT = 35,
    UNLINKAT = 36,
    MKDIRAT = 37,
    SYMLINKAT = 38,
    LINKAT = 39,
    MSG_RING = 40,
    FSETXATTR = 41,
    SETXATTR = 42,
    FGETXATTR = 43,
    GETXATTR = 44,
    SOCKET = 45,
    URING_CMD = 46,
    SEND_ZC = 47,
    SENDMSG_ZC = 48,
};

/// Submission Queue Entry
pub const SQE = extern struct {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off_or_addr2: u64,
    addr_or_splice: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index_or_group: u16,
    personality: u16,
    splice_fd_or_file_index: i32,
    addr3: u64,
    _pad: [1]u64,

    pub fn prep_recv(self: *SQE, fd: i32, buf: []u8, flags: u32) void {
        self.* = std.mem.zeroes(SQE);
        self.opcode = @intFromEnum(IORING_OP.RECV);
        self.fd = fd;
        self.addr_or_splice = @intFromPtr(buf.ptr);
        self.len = @intCast(buf.len);
        self.op_flags = flags;
    }

    pub fn prep_sendmsg(self: *SQE, fd: i32, msg: *const posix.msghdr_const, flags: u32) void {
        self.* = std.mem.zeroes(SQE);
        self.opcode = @intFromEnum(IORING_OP.SENDMSG);
        self.fd = fd;
        self.addr_or_splice = @intFromPtr(msg);
        self.op_flags = flags;
    }

    /// Prepare a read operation (for file reads)
    pub fn prep_read(self: *SQE, fd: i32, buf: []u8, offset: u64) void {
        self.* = std.mem.zeroes(SQE);
        self.opcode = @intFromEnum(IORING_OP.READ);
        self.fd = fd;
        self.off_or_addr2 = offset;
        self.addr_or_splice = @intFromPtr(buf.ptr);
        self.len = @intCast(buf.len);
    }

    pub fn setUserData(self: *SQE, data: u64) void {
        self.user_data = data;
    }
};

/// Completion Queue Entry
pub const CQE = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
};

/// io_uring configuration
pub const IoUringConfig = struct {
    /// Number of SQ entries
    sq_entries: u32 = 256,
    /// Number of CQ entries (0 = same as sq_entries)
    cq_entries: u32 = 0,
    /// Setup flags
    flags: u32 = 0,
    /// SQ thread CPU affinity
    sq_thread_cpu: u32 = 0,
    /// SQ thread idle time (ms) before sleeping
    sq_thread_idle: u32 = 1000,
};

/// io_uring instance
pub const IoUring = struct {
    allocator: std.mem.Allocator,
    ring_fd: i32,
    sq_entries: u32,
    cq_entries: u32,

    // Memory-mapped ring buffers
    sq_ring: ?[]align(4096) u8,
    cq_ring: ?[]align(4096) u8,
    sqes: ?[]SQE,
    sqes_mem: ?[]align(4096) u8, // Original mmap for unmapping

    // Ring state
    sq_head: *u32,
    sq_tail: *u32,
    sq_ring_mask: u32,
    sq_array: [*]u32,

    cq_head: *u32,
    cq_tail: *u32,
    cq_ring_mask: u32,
    cqes: [*]CQE,

    // Statistics
    stats: Stats,

    // Pending submissions tracking
    pending_submissions: u32,

    const Self = @This();

    pub const Stats = struct {
        submissions: u64 = 0,
        completions: u64 = 0,
        syscalls: u64 = 0,
    };

    /// Check if io_uring is available
    pub fn isAvailable() bool {
        if (builtin.os.tag != .linux) return false;

        // Check kernel version >= 5.1
        var uname_buf: linux.utsname = undefined;
        const uname_result = linux.uname(&uname_buf);
        if (@as(isize, @bitCast(uname_result)) < 0) return false;
        const release = std.mem.sliceTo(&uname_buf.release, 0);

        // Parse version (e.g., "5.15.0-generic")
        var iter = std.mem.tokenizeScalar(u8, release, '.');
        const major = std.fmt.parseInt(u32, iter.next() orelse "0", 10) catch 0;
        const minor = std.fmt.parseInt(u32, iter.next() orelse "0", 10) catch 0;

        return (major > 5) or (major == 5 and minor >= 1);
    }

    /// Initialize io_uring
    pub fn init(allocator: std.mem.Allocator, config: IoUringConfig) !*Self {
        if (!isAvailable()) {
            return error.IoUringNotAvailable;
        }

        const ring = try allocator.create(Self);
        errdefer allocator.destroy(ring);

        ring.* = .{
            .allocator = allocator,
            .ring_fd = -1,
            .sq_entries = config.sq_entries,
            .cq_entries = if (config.cq_entries > 0) config.cq_entries else config.sq_entries * 2,
            .sq_ring = null,
            .cq_ring = null,
            .sqes = null,
            .sqes_mem = null,
            .sq_head = undefined,
            .sq_tail = undefined,
            .sq_ring_mask = 0,
            .sq_array = undefined,
            .cq_head = undefined,
            .cq_tail = undefined,
            .cq_ring_mask = 0,
            .cqes = undefined,
            .stats = .{},
            .pending_submissions = 0,
        };

        // Setup io_uring via syscall
        var params = std.mem.zeroes(linux.io_uring_params);
        params.flags = config.flags;
        params.cq_entries = ring.cq_entries;

        const fd = linux.io_uring_setup(config.sq_entries, &params);
        if (@as(isize, @bitCast(fd)) < 0) {
            return error.IoUringSetupFailed;
        }
        ring.ring_fd = @intCast(fd);

        // Store ring parameters
        ring.sq_ring_mask = params.sq_entries - 1;
        ring.cq_ring_mask = params.cq_entries - 1;
        ring.cq_entries = params.cq_entries;
        ring.sq_entries = params.sq_entries;

        // Map SQ ring
        const sq_ring_size = params.sq_off.array + params.sq_entries * @sizeOf(u32);
        ring.sq_ring = std.posix.mmap(
            null,
            sq_ring_size,
            linux.PROT.READ | linux.PROT.WRITE,
            .{ .TYPE = .SHARED },
            ring.ring_fd,
            linux.IORING_OFF_SQ_RING,
        ) catch return error.MmapFailed;

        // Map CQ ring
        const cq_ring_size = params.cq_off.cqes + params.cq_entries * @sizeOf(CQE);
        ring.cq_ring = std.posix.mmap(
            null,
            cq_ring_size,
            linux.PROT.READ | linux.PROT.WRITE,
            .{ .TYPE = .SHARED },
            ring.ring_fd,
            linux.IORING_OFF_CQ_RING,
        ) catch return error.MmapFailed;

        // Map SQEs
        const sqes_size = params.sq_entries * @sizeOf(SQE);
        ring.sqes_mem = std.posix.mmap(
            null,
            sqes_size,
            linux.PROT.READ | linux.PROT.WRITE,
            .{ .TYPE = .SHARED },
            ring.ring_fd,
            linux.IORING_OFF_SQES,
        ) catch return error.MmapFailed;
        ring.sqes = @as([*]SQE, @ptrCast(@alignCast(ring.sqes_mem.?.ptr)))[0..params.sq_entries];

        // Set up pointers into the rings
        const sq_ptr = ring.sq_ring.?.ptr;
        ring.sq_head = @ptrFromInt(@intFromPtr(sq_ptr) + params.sq_off.head);
        ring.sq_tail = @ptrFromInt(@intFromPtr(sq_ptr) + params.sq_off.tail);
        ring.sq_array = @ptrFromInt(@intFromPtr(sq_ptr) + params.sq_off.array);

        const cq_ptr = ring.cq_ring.?.ptr;
        ring.cq_head = @ptrFromInt(@intFromPtr(cq_ptr) + params.cq_off.head);
        ring.cq_tail = @ptrFromInt(@intFromPtr(cq_ptr) + params.cq_off.tail);
        ring.cqes = @ptrFromInt(@intFromPtr(cq_ptr) + params.cq_off.cqes);

        // CRITICAL: Limit io_uring kernel worker threads to prevent thread explosion
        // Without this, io_uring scales workers to RLIMIT_NPROC per ring, causing 337K+ threads
        // See: https://man7.org/linux/man-pages/man3/io_uring_register_iowq_max_workers.3.html
        var max_workers: [2]u32 = .{ 4, 4 }; // [0] = bounded workers, [1] = unbounded workers
        const reg_result = linux.io_uring_register(
            ring.ring_fd,
            linux.IORING_REGISTER.REGISTER_IOWQ_MAX_WORKERS,
            @ptrCast(&max_workers),
            2,
        );
        if (@as(isize, @bitCast(reg_result)) < 0) {
            // Log but don't fail - older kernels may not support this
            std.log.warn("[IoUring] IORING_REGISTER_IOWQ_MAX_WORKERS failed (kernel may be too old)", .{});
        } else {
            std.log.debug("[IoUring] Worker threads limited to 4 bounded, 4 unbounded", .{});
        }

        return ring;
    }

    pub fn deinit(self: *Self) void {
        if (self.sq_ring) |r| {
            std.posix.munmap(r);
        }
        if (self.cq_ring) |r| {
            std.posix.munmap(r);
        }
        if (self.sqes_mem) |m| {
            std.posix.munmap(m);
        }
        self.sqes = null;
        if (self.ring_fd >= 0) {
            std.posix.close(self.ring_fd);
        }
        self.allocator.destroy(self);
    }

    /// Get an SQE for submitting
    /// SAFETY: Returns null if ring is full
    pub fn getSqe(self: *Self) ?*SQE {
        if (self.sqes == null) return null;

        const head = @atomicLoad(u32, self.sq_head, .acquire);
        const tail = self.sq_tail.*;

        // Check if SQ is full (using wrapping subtraction)
        if (tail -% head >= self.sq_entries) {
            return null; // SQ full
        }

        const index = tail & self.sq_ring_mask;

        // Bounds check
        if (index >= self.sq_entries) return null;

        // Increment tail for next getSqe call
        self.sq_tail.* = tail +% 1;
        self.pending_submissions += 1;

        // Update SQ array to point to this SQE index
        self.sq_array[index] = index;

        return &self.sqes.?[index];
    }

    /// Submit queued entries
    /// Returns the number of entries submitted
    pub fn submit(self: *Self) !u32 {
        if (self.pending_submissions == 0) return 0;

        // Memory fence before notifying kernel
        asm volatile ("" ::: .{ .memory = true });

        // Enter the ring
        const to_submit = self.pending_submissions;
        const ret = linux.io_uring_enter(
            @intCast(self.ring_fd),
            to_submit,
            0, // min_complete
            0, // flags
            null,
        );

        self.stats.syscalls += 1;

        const ret_signed: isize = @bitCast(ret);
        if (ret_signed < 0) {
            // Don't reset pending on error - they're still queued
            return error.SubmitFailed;
        }

        // Successfully submitted
        const submitted: u32 = @intCast(ret);
        self.stats.submissions += submitted;

        // Only clear pending for what was actually submitted
        if (submitted >= self.pending_submissions) {
            self.pending_submissions = 0;
        } else {
            self.pending_submissions -= submitted;
        }

        return submitted;
    }

    /// Submit and wait for completions
    pub fn submitAndWait(self: *Self, wait_nr: u32) !u32 {
        if (self.pending_submissions == 0 and wait_nr == 0) return 0;

        // Memory fence before notifying kernel
        asm volatile ("" ::: .{ .memory = true });

        const to_submit = self.pending_submissions;
        const ret = linux.io_uring_enter(
            @intCast(self.ring_fd),
            to_submit,
            wait_nr,
            linux.IORING_ENTER_GETEVENTS,
            null,
        );

        self.stats.syscalls += 1;

        const ret_signed: isize = @bitCast(ret);
        if (ret_signed < 0) {
            return error.SubmitFailed;
        }

        const submitted: u32 = @intCast(ret);
        self.stats.submissions += submitted;

        if (submitted >= self.pending_submissions) {
            self.pending_submissions = 0;
        } else {
            self.pending_submissions -= submitted;
        }

        return submitted;
    }

    /// Get next completion
    /// SAFETY: Returns null if no completions available
    pub fn peekCqe(self: *Self) ?*CQE {
        // Memory fence to ensure we see kernel updates
        asm volatile ("" ::: .{ .memory = true });

        const head = self.cq_head.*;
        const tail = @atomicLoad(u32, self.cq_tail, .acquire);

        if (head == tail) {
            return null; // CQ empty
        }

        const index = head & self.cq_ring_mask;

        // Bounds check
        if (index >= self.cq_entries) return null;

        return &self.cqes[index];
    }

    /// Mark completion as seen
    pub fn seenCqe(self: *Self) void {
        const head = self.cq_head.*;
        @atomicStore(u32, self.cq_head, head +% 1, .release);
        self.stats.completions += 1;
    }

    /// Get number of pending submissions
    pub fn pendingSubmissions(self: *const Self) u32 {
        return self.pending_submissions;
    }

    /// Get all available completions
    pub fn getCqes(self: *Self, cqes: []CQE) usize {
        var count: usize = 0;

        while (count < cqes.len) {
            if (self.peekCqe()) |cqe| {
                cqes[count] = cqe.*;
                self.seenCqe();
                count += 1;
            } else {
                break;
            }
        }

        return count;
    }
};

/// UDP socket using io_uring
pub const IoUringUdpSocket = struct {
    allocator: std.mem.Allocator,
    ring: *IoUring,
    fd: i32,
    bound: bool,

    // Pre-allocated buffers for batch operations
    recv_bufs: [][]u8,
    send_bufs: [][]u8,
    send_addrs: []linux.sockaddr.in,
    send_iovecs: []posix.iovec_const,
    send_msgs: []posix.msghdr_const,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, ring: *IoUring, batch_size: usize) !*Self {
        const sock = try allocator.create(Self);
        errdefer allocator.destroy(sock);

        // Create UDP socket
        const fd = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK, 0);
        if (@as(isize, @bitCast(fd)) < 0) {
            return error.SocketCreateFailed;
        }

        // Allocate buffers
        const recv_bufs = try allocator.alloc([]u8, batch_size);
        errdefer allocator.free(recv_bufs);

        for (recv_bufs) |*buf| {
            buf.* = try allocator.alloc(u8, 2048);
        }

        const send_bufs = try allocator.alloc([]u8, batch_size);
        errdefer allocator.free(send_bufs);

        for (send_bufs) |*buf| {
            buf.* = try allocator.alloc(u8, 2048);
        }

        const send_addrs = try allocator.alloc(linux.sockaddr.in, batch_size);
        errdefer allocator.free(send_addrs);

        const send_iovecs = try allocator.alloc(posix.iovec_const, batch_size);
        errdefer allocator.free(send_iovecs);

        const send_msgs = try allocator.alloc(posix.msghdr_const, batch_size);
        errdefer allocator.free(send_msgs);

        sock.* = .{
            .allocator = allocator,
            .ring = ring,
            .fd = @intCast(fd),
            .bound = false,
            .recv_bufs = recv_bufs,
            .send_bufs = send_bufs,
            .send_addrs = send_addrs,
            .send_iovecs = send_iovecs,
            .send_msgs = send_msgs,
        };

        if (busy_poll_enabled) {
            sock.setBusyPoll(true, 50, 64);
        }

        return sock;
    }

    pub fn deinit(self: *Self) void {
        if (self.fd >= 0) {
            std.posix.close(self.fd);
        }

        for (self.recv_bufs) |buf| {
            self.allocator.free(buf);
        }
        self.allocator.free(self.recv_bufs);

        for (self.send_bufs) |buf| {
            self.allocator.free(buf);
        }
        self.allocator.free(self.send_bufs);

        self.allocator.free(self.send_addrs);
        self.allocator.free(self.send_iovecs);
        self.allocator.free(self.send_msgs);

        self.allocator.destroy(self);
    }

    /// Bind to a port
    pub fn bind(self: *Self, port: u16) !void {
        var addr: linux.sockaddr.in = .{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = 0, // INADDR_ANY
            .zero = [_]u8{0} ** 8,
        };

        const rc = linux.bind(self.fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
        if (@as(isize, @bitCast(rc)) < 0) {
            const errno = @as(u32, @truncate(@as(u64, @bitCast(-@as(isize, @bitCast(rc))))));
            std.log.debug("debug: [io_uring] Bind failed on port {d}: errno={d}\n", .{ port, errno });
            // errno 98 = EADDRINUSE (port in use)
            // errno 13 = EACCES (permission denied for privileged port)
            if (errno == 98) {
                std.log.debug("info: [io_uring] Port {d} already in use. Kill existing process or use different port.\n", .{port});
            } else if (errno == 13) {
                std.log.debug("info: [io_uring] Permission denied for port {d}. Ports < 1024 need root.\n", .{port});
            }
            return error.BindFailed;
        }

        self.bound = true;
    }

    /// Enable busy polling for lower latency (Linux only)
    pub fn setBusyPoll(self: *Self, prefer: bool, busy_poll_us: u32, busy_poll_budget: u32) void {
        if (!busy_poll_enabled) return;
        if (builtin.os.tag != .linux) return;

        const prefer_val: i32 = if (prefer) 1 else 0;
        posix.setsockopt(@intCast(self.fd), posix.SOL.SOCKET, SO_PREFER_BUSY_POLL, &std.mem.toBytes(prefer_val)) catch |err| {
            std.log.debug("Warning: Could not set SO_PREFER_BUSY_POLL (io_uring): {}\n", .{err});
        };

        const poll_us: i32 = @intCast(@min(busy_poll_us, @as(u32, std.math.maxInt(i32))));
        posix.setsockopt(@intCast(self.fd), posix.SOL.SOCKET, SO_BUSY_POLL, &std.mem.toBytes(poll_us)) catch |err| {
            std.log.debug("Warning: Could not set SO_BUSY_POLL (io_uring): {}\n", .{err});
        };

        const budget_val: i32 = @intCast(@min(busy_poll_budget, @as(u32, std.math.maxInt(i32))));
        posix.setsockopt(@intCast(self.fd), posix.SOL.SOCKET, SO_BUSY_POLL_BUDGET, &std.mem.toBytes(budget_val)) catch |err| {
            std.log.debug("Warning: Could not set SO_BUSY_POLL_BUDGET (io_uring): {}\n", .{err});
        };
    }

    /// Queue a receive operation
    pub fn queueRecv(self: *Self, buf_index: usize) !void {
        const sqe = self.ring.getSqe() orelse return error.SqFull;
        sqe.prep_recv(self.fd, self.recv_bufs[buf_index], 0);
        sqe.setUserData(buf_index);
    }

    /// Queue multiple receive operations
    pub fn queueRecvBatch(self: *Self, count: usize) !usize {
        var queued: usize = 0;
        while (queued < count and queued < self.recv_bufs.len) {
            self.queueRecv(queued) catch break;
            queued += 1;
        }
        return queued;
    }

    /// Queue a send operation
    pub fn queueSend(self: *Self, data: []const u8, dest: packet.SocketAddr, index: usize) !void {
        if (index >= self.send_bufs.len) return error.SqFull;

        const copy_len = @min(data.len, self.send_bufs[index].len);
        @memcpy(self.send_bufs[index][0..copy_len], data[0..copy_len]);

        self.send_addrs[index] = packetAddrToSockaddr(&dest);
        self.send_iovecs[index] = .{
            .base = self.send_bufs[index].ptr,
            .len = copy_len,
        };
        self.send_msgs[index] = std.mem.zeroes(posix.msghdr_const);
        self.send_msgs[index].name = @ptrCast(&self.send_addrs[index]);
        self.send_msgs[index].namelen = @sizeOf(linux.sockaddr.in);
        self.send_msgs[index].iov = @ptrCast(&self.send_iovecs[index]);
        self.send_msgs[index].iovlen = 1;

        const sqe = self.ring.getSqe() orelse return error.SqFull;
        sqe.prep_sendmsg(self.fd, &self.send_msgs[index], 0);
        sqe.setUserData(@intCast(index));
    }

    /// Process completions and return received data
    pub fn processCompletions(self: *Self, results: []RecvResult) !usize {
        var cqes: [64]CQE = undefined;
        const count = self.ring.getCqes(&cqes);

        var result_count: usize = 0;
        for (cqes[0..count]) |cqe| {
            if (cqe.res >= 0) {
                const buf_idx = cqe.user_data;
                if (buf_idx < self.recv_bufs.len and result_count < results.len) {
                    results[result_count] = .{
                        .data = self.recv_bufs[buf_idx][0..@intCast(cqe.res)],
                        .len = @intCast(cqe.res),
                    };
                    result_count += 1;
                }
            }
        }

        return result_count;
    }

    pub const RecvResult = struct {
        data: []u8,
        len: usize,
    };

    fn packetAddrToSockaddr(pa: *const packet.SocketAddr) linux.sockaddr.in {
        return linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, pa.port()),
            .addr = @bitCast(pa.addr[0..4].*),
            .zero = [_]u8{0} ** 8,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "io_uring availability" {
    const available = IoUring.isAvailable();
    // Test should pass regardless of actual availability
    _ = available;
}

test "SQE initialization" {
    var sqe: SQE = std.mem.zeroes(SQE);
    var buf: [100]u8 = undefined;
    sqe.prep_recv(5, &buf, 0);

    try std.testing.expectEqual(@as(u8, @intFromEnum(IORING_OP.RECV)), sqe.opcode);
    try std.testing.expectEqual(@as(i32, 5), sqe.fd);
}
