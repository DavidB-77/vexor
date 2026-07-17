// Async I/O Support using io_uring
//
// Provides non-blocking file I/O for:
// - Parallel snapshot chunk writes
// - Async account loading
// - Buffered ledger writes
//
// Falls back to blocking I/O if io_uring is not available

const std = @import("std");
const Allocator = std.mem.Allocator;
const fs = std.fs;
const os = std.os;
const linux = os.linux;

/// io_uring operation result
pub const IoResult = struct {
    bytes_transferred: i32,
    user_data: u64,
    success: bool,
};

/// Configuration for async I/O
pub const AsyncIoConfig = struct {
    /// Number of submission queue entries
    queue_depth: u32 = 256,
    /// Enable SQPOLL for kernel-side polling (requires CAP_SYS_ADMIN)
    enable_sqpoll: bool = false,
    /// SQPOLL idle timeout in milliseconds
    sqpoll_idle_ms: u32 = 1000,
    /// Enable registered file descriptors for faster ops
    register_fds: bool = true,
    /// Maximum registered files
    max_registered_files: u32 = 64,
};

/// Async I/O manager using io_uring
pub const AsyncIoManager = struct {
    allocator: Allocator,
    ring: ?*linux.IoUring,
    config: AsyncIoConfig,
    registered_fds: std.ArrayListUnmanaged(fs.File),
    pending_ops: u32,
    is_available: bool,
    completions: std.AutoHashMap(u64, IoResult),
    mutex: std.Thread.Mutex,
    next_id: std.atomic.Value(u64),

    const Self = @This();

    /// Initialize async I/O manager
    pub fn init(allocator: Allocator, config: AsyncIoConfig) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .ring = null,
            .config = config,
            .registered_fds = std.ArrayListUnmanaged(fs.File){},
            .pending_ops = 0,
            .is_available = false,
            .completions = std.AutoHashMap(u64, IoResult).init(allocator),
            .mutex = std.Thread.Mutex{},
            .next_id = std.atomic.Value(u64).init(1),
        };

        // Try to initialize io_uring
        const flags: u32 = if (config.enable_sqpoll) linux.IORING_SETUP_SQPOLL else 0;
        const ring_ptr = try allocator.create(linux.IoUring);
        errdefer allocator.destroy(ring_ptr);

        ring_ptr.* = linux.IoUring.init(@intCast(config.queue_depth), flags) catch |err| {
            allocator.destroy(ring_ptr);
            // io_uring not available, will fall back to blocking I/O
            std.log.warn("io_uring not available ({s}), using blocking I/O", .{@errorName(err)});
            return self;
        };
        self.ring = ring_ptr;

        // CRITICAL: Limit io_uring kernel worker threads to prevent thread explosion
        // Without this, io_uring scales workers to RLIMIT_NPROC per ring, causing 337K+ threads
        var max_workers: [2]u32 = .{ 4, 4 }; // [0] = bounded workers, [1] = unbounded workers
        _ = linux.io_uring_register(
            ring_ptr.fd,
            linux.IORING_REGISTER.REGISTER_IOWQ_MAX_WORKERS,
            @ptrCast(&max_workers),
            2,
        );
        // Note: Failure is OK on older kernels, but we don't need to log it here

        self.is_available = true;
        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.ring) |ring| {
            ring.deinit();
            self.allocator.destroy(ring);
        }
        self.completions.deinit();
        self.registered_fds.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Check if async I/O is available
    pub fn available(self: *const Self) bool {
        return self.is_available;
    }

    /// Register a file for faster operations
    pub fn registerFile(self: *Self, file: fs.File) !u32 {
        if (!self.is_available) return error.NotAvailable;

        const index: u32 = @intCast(self.registered_fds.items.len);
        try self.registered_fds.append(self.allocator, file);

        // TODO: Actually register with io_uring
        // linux.io_uring_register_files(...)

        return index;
    }

    /// Queue an async write operation
    pub fn queueWrite(
        self: *Self,
        file: fs.File,
        buffer: []const u8,
        offset: u64,
        _: u64,
    ) !u64 {
        if (!self.is_available) {
            // Fallback to blocking write
            _ = try file.pwrite(buffer, offset);
            return 0; // ID 0 means synchronous completion
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        const ring = self.ring orelse return error.NotInitialized;

        // Get a submission queue entry
        const sqe = try ring.get_sqe();

        // Generate unique ID
        const id = self.next_id.fetchAdd(1, .seq_cst);

        // Prepare write operation
        sqe.opcode = .WRITE;
        sqe.fd = file.handle;
        sqe.off = offset;
        sqe.addr = @intFromPtr(buffer.ptr);
        sqe.len = @intCast(buffer.len);
        sqe.flags = 0;
        sqe.ioprio = 0;
        sqe.user_data = id;

        self.pending_ops += 1;
        return id;
    }

    /// Submit all queued operations
    pub fn submit(self: *Self) !u32 {
        if (!self.is_available or self.ring == null) return 0;

        return try self.ring.?.submit();
    }

    /// Wait for a specific operation to complete
    pub fn waitFor(self: *Self, id: u64) !IoResult {
        if (!self.is_available) return IoResult{ .bytes_transferred = 0, .user_data = id, .success = true };

        while (true) {
            self.mutex.lock();

            // Check if already completed
            if (self.completions.fetchRemove(id)) |kv| {
                self.mutex.unlock();
                return kv.value;
            }

            // Check ring for new completions
            const ring = self.ring.?;
            // copy_cqe returns by value and advances
            const cqe = ring.copy_cqe() catch |err| {
                self.mutex.unlock();
                return err;
            };

            const result = IoResult{
                .bytes_transferred = cqe.res,
                .user_data = cqe.user_data,
                .success = cqe.res >= 0,
            };
            self.pending_ops -= 1;

            if (cqe.user_data == id) {
                self.mutex.unlock();
                return result;
            }

            // Store for others
            self.completions.put(cqe.user_data, result) catch {};
            self.mutex.unlock();
        }
    }
};

/// High-level async file writer
pub const AsyncFileWriter = struct {
    io_manager: *AsyncIoManager,
    file: fs.File,
    file_index: ?u32,

    const Self = @This();

    pub fn init(io_manager: *AsyncIoManager, path: []const u8) !Self {
        const file = try fs.cwd().createFile(path, .{});

        var self = Self{
            .io_manager = io_manager,
            .file = file,
            .file_index = null,
        };

        // Register file if possible
        if (io_manager.available()) {
            self.file_index = io_manager.registerFile(file) catch null;
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.file.close();
    }
};

/// Batch I/O operations for efficient bulk writes
pub const BatchIoQueue = struct {
    allocator: Allocator,
    io_manager: *AsyncIoManager,
    pending_writes: std.ArrayListUnmanaged(WriteOp),
    inflight_ids: std.ArrayListUnmanaged(u64),
    batch_size: u32,

    const WriteOp = struct {
        file: fs.File,
        data: []const u8,
        offset: u64,
        user_data: u64,
    };

    const Self = @This();

    pub fn init(allocator: Allocator, io_manager: *AsyncIoManager, batch_size: u32) Self {
        return .{
            .allocator = allocator,
            .io_manager = io_manager,
            .pending_writes = std.ArrayListUnmanaged(WriteOp){},
            .inflight_ids = std.ArrayListUnmanaged(u64){},
            .batch_size = batch_size,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pending_writes.deinit(self.allocator);
        self.inflight_ids.deinit(self.allocator);
    }

    /// Add a write to the batch
    pub fn add(self: *Self, file: fs.File, data: []const u8, offset: u64, user_data: u64) !void {
        try self.pending_writes.append(self.allocator, .{
            .file = file,
            .data = data,
            .offset = offset,
            .user_data = user_data,
        });

        // Auto-flush if batch is full
        if (self.pending_writes.items.len >= self.batch_size) {
            try self.flush();
        }
    }

    /// Flush all pending writes
    pub fn flush(self: *Self) !void {
        for (self.pending_writes.items) |op| {
            const id = try self.io_manager.queueWrite(op.file, op.data, op.offset, op.user_data);
            try self.inflight_ids.append(self.allocator, id);
        }

        _ = try self.io_manager.submit();
        self.pending_writes.clearRetainingCapacity();
    }
};

/// Check if io_uring is supported on this system
pub fn isIoUringSupported() bool {
    // Try to create a minimal ring
    var ring = linux.IoUring.init(1, 0) catch {
        return false;
    };
    ring.deinit();
    return true;
}

/// Get recommended queue depth for this system
pub fn recommendedQueueDepth() u32 {
    // Get CPU count for sizing
    const cpu_count = std.Thread.getCpuCount() catch 4;

    // Recommended: 32-64 per CPU, capped at 4096, must be power of two
    const target = @min(@as(u32, @intCast(cpu_count)) * 64, 4096);
    return std.math.ceilPowerOfTwo(u32, target) catch 256;
}

// Tests
test "async io manager initialization" {
    const allocator = std.testing.allocator;

    const manager = try AsyncIoManager.init(allocator, .{});
    defer manager.deinit();

    // May or may not be available depending on kernel
    _ = manager.available();
}

test "io_uring support check" {
    const supported = isIoUringSupported();
    // Just verify it doesn't crash
    _ = supported;
}

test "recommended queue depth" {
    const depth = recommendedQueueDepth();
    try std.testing.expect(depth >= 32);
    try std.testing.expect(depth <= 4096);
}
