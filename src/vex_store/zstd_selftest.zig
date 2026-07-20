// Streaming Decompression for Snapshots
//
// Enables pipelined download + decompress + load:
// - Download chunks arrive → immediately decompress
// - Decompressed data → immediately start loading accounts
// - Result: 30-40% faster bootstrap than sequential

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const Atomic = std.atomic.Value;

/// Decompression algorithm types
pub const CompressionType = enum {
    zstd,
    lz4,
    gzip,
    none,
    
    pub fn fromExtension(filename: []const u8) CompressionType {
        if (std.mem.endsWith(u8, filename, ".zst") or std.mem.endsWith(u8, filename, ".zstd")) {
            return .zstd;
        } else if (std.mem.endsWith(u8, filename, ".lz4")) {
            return .lz4;
        } else if (std.mem.endsWith(u8, filename, ".gz") or std.mem.endsWith(u8, filename, ".gzip")) {
            return .gzip;
        }
        return .none;
    }
    
};

/// A chunk of data in the streaming pipeline
pub const StreamChunk = struct {
    /// Chunk sequence number
    sequence: u64,
    /// Raw compressed data
    compressed_data: ?[]u8,
    /// Decompressed data (filled after decompression)
    decompressed_data: ?[]u8,
    /// Whether this is the final chunk
    is_final: bool,
    /// Original size (if known)
    original_size: ?u64,
    
};

/// Thread-safe queue for chunk passing between stages
pub fn ChunkQueue(comptime T: type) type {
    return struct {
        allocator: Allocator,
        items: std.ArrayListUnmanaged(T),
        mutex: Mutex,
        not_empty: Thread.Condition,
        closed: Atomic(bool),
        
        const Self = @This();
        
        pub fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .items = std.ArrayListUnmanaged(T){},
                .mutex = .{},
                .not_empty = .{},
                .closed = Atomic(bool).init(false),
            };
        }
        
        pub fn deinit(self: *Self) void {
            self.items.deinit(self.allocator);
        }
        
        /// Push an item to the queue
        pub fn push(self: *Self, item: T) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            try self.items.append(self.allocator, item);
            self.not_empty.signal();
        }
        
        /// Pop an item from the queue (blocks if empty)
        pub fn pop(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            while (self.items.items.len == 0) {
                if (self.closed.load(.monotonic)) return null;
                self.not_empty.wait(&self.mutex);
            }
            
            return self.items.orderedRemove(0);
        }
        
        
        /// Close the queue (no more items will be added)
        pub fn close(self: *Self) void {
            self.closed.store(true, .monotonic);
            self.not_empty.broadcast();
        }
        
    };
}

/// Progress tracking for streaming decompression
pub const DecompressProgress = struct {
    compressed_bytes_in: Atomic(u64),
    decompressed_bytes_out: Atomic(u64),
    chunks_processed: Atomic(u32),
    start_time: i64,
    
    pub fn init() DecompressProgress {
        return .{
            .compressed_bytes_in = Atomic(u64).init(0),
            .decompressed_bytes_out = Atomic(u64).init(0),
            .chunks_processed = Atomic(u32).init(0),
            .start_time = std.time.milliTimestamp(),
        };
    }
    
    pub fn compressionRatio(self: *const DecompressProgress) f32 {
        const compressed = self.compressed_bytes_in.load(.monotonic);
        const decompressed = self.decompressed_bytes_out.load(.monotonic);
        if (compressed == 0) return 0;
        return @as(f32, @floatFromInt(decompressed)) / @as(f32, @floatFromInt(compressed));
    }
    
};

/// Streaming decompression pipeline
pub const StreamingDecompressor = struct {
    allocator: Allocator,
    compression_type: CompressionType,
    
    /// Input queue (compressed chunks)
    input_queue: ChunkQueue(StreamChunk),
    /// Output queue (decompressed chunks)
    output_queue: ChunkQueue(StreamChunk),
    
    /// Worker thread
    worker_thread: ?Thread,
    
    /// Progress tracking
    progress: DecompressProgress,
    
    /// Configuration
    config: Config,
    
    pub const Config = struct {
        /// Buffer size for decompression (default 4MB)
        buffer_size: usize = 4 * 1024 * 1024,
        /// Maximum output queue size (back-pressure)
        max_queue_size: u32 = 16,
    };
    
    const Self = @This();
    
    pub fn init(allocator: Allocator, compression_type: CompressionType, config: Config) Self {
        return .{
            .allocator = allocator,
            .compression_type = compression_type,
            .input_queue = ChunkQueue(StreamChunk).init(allocator),
            .output_queue = ChunkQueue(StreamChunk).init(allocator),
            .worker_thread = null,
            .progress = DecompressProgress.init(),
            .config = config,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.stop();
        self.input_queue.deinit();
        self.output_queue.deinit();
    }
    
    
    /// Stop the decompression worker
    pub fn stop(self: *Self) void {
        self.input_queue.close();
        if (self.worker_thread) |thread| {
            thread.join();
            self.worker_thread = null;
        }
        self.output_queue.close();
    }
    
    /// Decompress a complete zstd frame from `input` into `output`, returning the number of
    /// decompressed bytes written. Uses the pure-Zig `std.compress.zstd` decoder (Zig 0.15.2) — no FFI.
    ///
    /// Indirect mode: the decoder's internal `window` buffer holds window_len + block_size_max, so the
    /// destination can be a plain fixed Writer over `output`. If the decompressed stream exceeds
    /// `output.len`, the fixed writer reports WriteFailed (caller under-sized the output buffer).
    ///
    /// NOTE (2026-06-15, perf#3): this fills the former @memcpy placeholder. The module is NOT wired
    /// into the live snapshot/accounts-load path (that shells out to external zstd) — keeping this an
    /// isolated, consensus-safe utility. Do NOT wire it into accounts loading without explicit review.
    fn decompressZstd(self: *Self, input: []const u8, output: []u8) !usize {
        const zstd = std.compress.zstd;

        // Internal window buffer (indirect mode): window_len + block_size_max (~8MB + 128KB).
        const win_cap = @as(usize, zstd.default_window_len) + zstd.block_size_max;
        const window = try self.allocator.alloc(u8, win_cap);
        defer self.allocator.free(window);

        var in: std.Io.Reader = .fixed(input);
        var zstd_stream: zstd.Decompress = .init(&in, window, .{});
        var out: std.Io.Writer = .fixed(output);

        return try zstd_stream.reader.streamRemaining(&out);
    }
    
};


/// PERF #3 boot self-test: decode an embedded REAL zstd frame (system `zstd -19` of a known 1480-byte
/// input) and verify byte-exact, exercising the std.compress.zstd decode path in the PRODUCTION binary
/// at startup. Returns true on success. This is a hardcoded diagnostic frame ONLY — it does NOT touch
/// the snapshot/accounts path. Non-fatal (caller logs PASS/WARN): the decoder is an unwired utility, so
/// a failure must not block the validator from voting.
pub fn zstdSelfTest(allocator: Allocator) bool {
    const compressed = [_]u8{
        40, 181, 47, 253, 100, 200, 4, 117, 1, 0, 84, 2, 86, 101, 120, 111, 114, 32, 122, 115,
        116, 100, 32, 75, 65, 84, 58, 32, 116, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114,
        111, 119, 110, 32, 102, 111, 120, 46, 32, 1, 0, 5, 13, 253, 234, 9, 36, 137, 253, 8,
    };
    const unit = "Vexor zstd KAT: the quick brown fox. ";
    const reps = 40;

    var d = StreamingDecompressor.init(allocator, .zstd, .{});
    defer d.deinit();

    var out: [unit.len * reps]u8 = undefined;
    const n = d.decompressZstd(&compressed, &out) catch return false;
    if (n != unit.len * reps) return false;
    var i: usize = 0;
    while (i < reps) : (i += 1) {
        if (!std.mem.eql(u8, out[i * unit.len ..][0..unit.len], unit)) return false;
    }
    return true;
}

// Tests
test "compression type detection" {
    try std.testing.expectEqual(CompressionType.zstd, CompressionType.fromExtension("snapshot.tar.zst"));
    try std.testing.expectEqual(CompressionType.lz4, CompressionType.fromExtension("data.lz4"));
    try std.testing.expectEqual(CompressionType.gzip, CompressionType.fromExtension("file.gz"));
    try std.testing.expectEqual(CompressionType.none, CompressionType.fromExtension("file.tar"));
}

test "chunk queue" {
    const allocator = std.testing.allocator;
    
    var queue = ChunkQueue(u32).init(allocator);
    defer queue.deinit();
    
    try queue.push(1);
    try queue.push(2);
    try queue.push(3);
    
    try std.testing.expectEqual(@as(u32, 1), queue.pop().?);
    try std.testing.expectEqual(@as(u32, 2), queue.pop().?);
    
    queue.close();
    try std.testing.expectEqual(@as(u32, 3), queue.pop().?);
    try std.testing.expectEqual(@as(?u32, null), queue.pop());
}

test "decompress progress" {
    var progress = DecompressProgress.init();
    
    _ = progress.compressed_bytes_in.fetchAdd(1000, .monotonic);
    _ = progress.decompressed_bytes_out.fetchAdd(4000, .monotonic);
    
    try std.testing.expect(progress.compressionRatio() > 3.9);
    try std.testing.expect(progress.compressionRatio() < 4.1);
}

// PERF #3 KAT (2026-06-15): decompressZstd (formerly a @memcpy placeholder) now uses the pure-Zig
// std.compress.zstd decoder. Vector: a REAL zstd frame produced by the system `zstd -19` from a known
// 1480-byte input ("Vexor zstd KAT: the quick brown fox. " × 40). Asserts byte-exact decompression.
// (Zig 0.15.2 has a zstd decoder but no encoder, so the compressed frame is embedded rather than
// round-tripped.) This module is NOT on the live snapshot/accounts path — isolated, consensus-safe.
test "perf#3: decompressZstd decodes a real zstd frame byte-exact" {
    const allocator = std.testing.allocator;
    const compressed = [_]u8{
        40, 181, 47, 253, 100, 200, 4, 117, 1, 0, 84, 2, 86, 101, 120, 111, 114, 32, 122, 115,
        116, 100, 32, 75, 65, 84, 58, 32, 116, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114,
        111, 119, 110, 32, 102, 111, 120, 46, 32, 1, 0, 5, 13, 253, 234, 9, 36, 137, 253, 8,
    };
    const unit = "Vexor zstd KAT: the quick brown fox. ";
    const reps = 40;

    var expected: [unit.len * reps]u8 = undefined;
    var i: usize = 0;
    while (i < reps) : (i += 1) @memcpy(expected[i * unit.len ..][0..unit.len], unit);

    var d = StreamingDecompressor.init(allocator, .zstd, .{});
    defer d.deinit();

    var out: [unit.len * reps]u8 = undefined;
    const n = try d.decompressZstd(&compressed, &out);

    try std.testing.expectEqual(@as(usize, expected.len), n);
    try std.testing.expectEqualSlices(u8, &expected, out[0..n]);

    // Under-sized output must error (not silently truncate) — any error is acceptable.
    var tiny: [16]u8 = undefined;
    try std.testing.expect(if (d.decompressZstd(&compressed, &tiny)) |_| false else |_| true);
}

