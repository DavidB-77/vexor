//! Vexor Accounts Database — AppendVec storage layer.
//! SPLIT from accounts.zig (rebuild module 25): leaf storage types + AppendVec.
//! Owns Account / AccountView / AccountLocation / SlotOverlay, the AppendVec heap
//! store, and the g_av_* heap/mmap live-store accounting atomics. Import-free of
//! its siblings (leaf layer) so account_storage.zig and accounts_db.zig depend on it.
const std = @import("std");
const core = @import("core");
const build_options = @import("build_options");

// Shadow-verify the tail-write flush: after each flush, read the whole .av file
// back and assert it byte-matches the heap buffer. Armed by `-Dverify_av_flush`.
// `@hasDecl`-guarded so the file compiles under any build_options lacking the flag.
// Default OFF → comptime-dead, zero cost, byte-identical.
const verify_av_flush: bool = if (@hasDecl(build_options, "verify_av_flush"))
    build_options.verify_av_flush
else
    false;

// Perf (#5): Vexor is x86-64 only. On little-endian the record integer fields
// are stored in native byte order, so an aligned-relaxed load reproduces the
// exact value `std.mem.readInt(..., .little)` returns — without the byte-shuffle
// loop. Guarded by this comptime endian assert so a big-endian build fails to
// compile rather than silently returning byte-swapped account fields.
comptime {
    std.debug.assert(@import("builtin").cpu.arch.endian() == .little);
}
inline fn loadLE(comptime T: type, p: [*]const u8) T {
    return @as(*align(1) const T, @ptrCast(p)).*;
}

// ── Task #71 (2026-06-10) [MEM-BREAKDOWN] live store accounting ──────────────
// RSS-leak diagnosis (28-30 GB/h anon growth at-tip) pinned the leak to rooted
// AppendVec stores: 64MB c_allocator heap buffers created by getOrCreateStore as
// roots advance (~4MB of mostly-vote-account records per slot), retained FOREVER
// in `AccountStorage.stores` because the GC ticks are unwired + env-gated off.
// These global atomics let the once-a-minute [MEM-BREAKDOWN] log line report the
// store footprint WITHOUT walking `stores` (94k+ entries) or taking
// `storage.lock`. Updated at the AppendVec create/destroy/append chokepoints.
// `g_av_appended_bytes` is monotonic (lifetime bytes appended); the others are
// live gauges.
pub var g_av_heap_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var g_av_heap_cap_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var g_av_appended_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var g_av_mmap_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var g_av_mmap_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
/// Account data structure
pub const Account = struct {
    lamports: u64,
    owner: core.Pubkey,
    executable: bool,
    rent_epoch: core.Epoch,
    data: []const u8,

    pub fn dataLen(self: *const Account) usize {
        return self.data.len;
    }
};

/// Zero-copy account view from storage
pub const AccountView = struct {
    lamports: u64,
    owner: core.Pubkey,
    executable: bool,
    rent_epoch: core.Epoch,
    data: []const u8,
};

/// Per-slot overlay of writes for fork-isolation. Owns the Account `data`
/// slices (allocated via `std.heap.page_allocator`). Freed by
/// `purgeUnrootedSlot`/`advanceRoot` when the slot leaves the overlay.
pub const SlotOverlay = std.AutoHashMap(core.Pubkey, Account);

/// Location of an account in storage
pub const AccountLocation = struct {
    /// Storage file ID
    store_id: u32,
    /// Offset within file
    offset: u64,
    /// Slot this version is from
    slot: core.Slot,
};

/// Append-only vector for account storage
/// NOTE: Following Sig's design, we use heap allocation instead of mmap to avoid SIGBUS
/// issues when loading thousands of files during snapshot loading.
pub const AppendVec = struct {
    allocator: std.mem.Allocator,
    file_path: []const u8,
    file: ?std.fs.File,
    data: []u8, // Heap-allocated buffer (not mmap)
    current_len: std.atomic.Value(u64),
    capacity: u64,
    last_meta_len: u64,
    dirty: bool, // Track if we need to flush to disk
    agave_format: bool, // True for mmap'd Agave snapshot files (read-only)
    owns_data: bool, // False for mmap'd data (don't free on deinit)
    flushed_len: u64 = 0, // bytes already persisted to the .av file (tail-write cursor)

    const Self = @This();
    pub const header_size: usize = 32;
    const header_magic: [8]u8 = [_]u8{ 'V', 'E', 'X', 'A', 'V', '1', 0, 0 };
    pub const record_header_len: usize = 32 + 8 + 32 + 1 + 8 + 4;
    const meta_flush_interval: u64 = 1 * 1024 * 1024; // 1MB

    // Agave AppendVec record layout constants
    const AGAVE_STORED_META_SIZE: usize = 48; // write_version(8) + data_len(8) + pubkey(32)
    const AGAVE_ACCOUNT_META_SIZE: usize = 56; // lamports(8) + rent_epoch(8) + owner(32) + executable(1) + padding(7)
    const AGAVE_HASH_SIZE: usize = 32;
    const AGAVE_MIN_RECORD: usize = AGAVE_STORED_META_SIZE + AGAVE_ACCOUNT_META_SIZE + AGAVE_HASH_SIZE; // 136

    const Record = struct {
        pubkey: core.Pubkey,
        account: AccountView,
        total_len: u64,
    };

    /// Create a read-only AppendVec wrapping mmap'd Agave-format data.
    /// Does NOT allocate or copy data — just wraps the existing buffer.
    pub fn initFromAgaveMmap(allocator: std.mem.Allocator, data: []u8, file_size: u64) !*Self {
        const av = try allocator.create(Self);
        av.* = .{
            .allocator = allocator,
            .file_path = "",
            .file = null,
            .data = data,
            .current_len = std.atomic.Value(u64).init(file_size),
            .capacity = data.len,
            .last_meta_len = 0,
            .dirty = false,
            .agave_format = true,
            .owns_data = false,
        };
        // Task #71 [MEM-BREAKDOWN]: file-backed (snapshot mmap) gauge — bounded
        // class, tracked separately from the leaking heap-store class.
        _ = g_av_mmap_count.fetchAdd(1, .monotonic);
        _ = g_av_mmap_bytes.fetchAdd(data.len, .monotonic);
        return av;
    }

    pub fn init(allocator: std.mem.Allocator, base_path: []const u8, store_id: u32, slot: core.Slot, capacity: u64) !*Self {
        const av = try allocator.create(Self);
        errdefer allocator.destroy(av);

        const accounts_dir = try std.fmt.allocPrint(allocator, "{s}/accounts", .{base_path});
        defer allocator.free(accounts_dir);
        try std.fs.cwd().makePath(accounts_dir);

        const file_path = try std.fmt.allocPrint(allocator, "{s}/{d}.{d}.av", .{ accounts_dir, slot, store_id });
        errdefer allocator.free(file_path);

        // Heap-allocate the data buffer instead of mmap
        // This avoids SIGBUS issues and follows Sig's approach
        const data = try allocator.alloc(u8, @intCast(capacity));
        errdefer allocator.free(data);

        av.* = .{
            .allocator = allocator,
            .file_path = file_path,
            .file = null,
            .data = data,
            .current_len = std.atomic.Value(u64).init(header_size),
            .capacity = capacity,
            .last_meta_len = header_size,
            .dirty = false,
            .agave_format = false,
            .owns_data = true,
        };

        // Initialize header in memory
        @memcpy(av.data[0..8], &header_magic);
        std.mem.writeInt(u32, av.data[8..12], 1, .little); // version
        std.mem.writeInt(u64, av.data[12..20], header_size, .little); // length
        @memset(av.data[20..header_size], 0); // padding

        // Task #71 [MEM-BREAKDOWN]: account for the heap buffer (the RSS-leak class).
        _ = g_av_heap_count.fetchAdd(1, .monotonic);
        _ = g_av_heap_cap_bytes.fetchAdd(capacity, .monotonic);

        return av;
    }

    pub fn deinit(self: *Self) void {
        if (!self.agave_format) {
            // Flush to disk before cleanup (only for writable stores)
            self.flushToDisk() catch |err| {
                std.log.warn("[AppendVec] Failed to flush on deinit: {}", .{err});
            };
        }

        if (self.file) |f| f.close();
        if (self.owns_data) {
            // Task #71 [MEM-BREAKDOWN]: heap-store gauge decrement.
            _ = g_av_heap_count.fetchSub(1, .monotonic);
            _ = g_av_heap_cap_bytes.fetchSub(self.capacity, .monotonic);
            self.allocator.free(self.data);
        } else {
            _ = g_av_mmap_count.fetchSub(1, .monotonic);
            _ = g_av_mmap_bytes.fetchSub(self.capacity, .monotonic);
        }
        if (self.file_path.len > 0) self.allocator.free(self.file_path);
        self.allocator.destroy(self);
    }

    pub fn getAccount(self: *Self, offset: u64) ?AccountView {
        if (self.agave_format) {
            return self.readAgaveRecord(offset);
        }
        // Perf (#2): the heap-store read only wants the AccountView; the pubkey
        // that readRecord copies out is discarded here, so skip the 32-byte copy.
        return self.readRecordAccount(offset);
    }

    /// Perf (#2): pubkey-skipping variant of readRecord for the heap-store read
    /// path (getAccount). Identical field parsing to readRecord, but starts the
    /// cursor 32 bytes past the pubkey so the pubkey @memcpy is never performed.
    /// Byte-identical safety: AccountView never contained the pubkey, so the
    /// returned lamports/owner/executable/rent_epoch/data are the exact same
    /// bytes readRecord would have placed in `record.account`.
    fn readRecordAccount(self: *Self, offset: u64) ?AccountView {
        const current_len = self.current_len.load(.acquire);
        if (offset < header_size) return null;
        if (offset + record_header_len > current_len) return null;
        var cursor = offset + 32; // skip pubkey (discarded by getAccount)
        const lamports = loadLE(u64, self.data[cursor..].ptr);
        cursor += 8;
        var owner = core.Pubkey{ .data = undefined };
        @memcpy(&owner.data, self.data[cursor..][0..32]);
        cursor += 32;
        const executable = self.data[cursor] != 0;
        cursor += 1;
        const rent_epoch = loadLE(u64, self.data[cursor..].ptr);
        cursor += 8;
        const data_len = loadLE(u32, self.data[cursor..].ptr);
        cursor += 4;
        if (cursor + data_len > current_len) return null;
        const data = self.data[cursor..][0..data_len];
        return .{
            .lamports = lamports,
            .owner = owner,
            .executable = executable,
            .rent_epoch = rent_epoch,
            .data = data,
        };
    }

    /// Perf (#4a): owner-only fast path. Returns a borrowed pointer to the 32
    /// owner bytes at `offset`, doing only the bounds checks needed to prove the
    /// owner field is in-bounds (never touches lamports/rent_epoch/data or the
    /// pubkey). Handles both record layouts. Byte-identical safety: points at
    /// the exact same 32 owner bytes readAgaveRecord/readRecord would return.
    pub fn getOwner(self: *Self, offset: u64) ?*const [32]u8 {
        const current_len = self.current_len.load(.acquire);
        if (self.agave_format) {
            if (offset + AGAVE_MIN_RECORD > current_len) return null;
            const meta_offset = offset + AGAVE_STORED_META_SIZE;
            return self.data[meta_offset + 16 ..][0..32];
        }
        if (offset < header_size) return null;
        if (offset + record_header_len > current_len) return null;
        // heap layout: pubkey(32) + lamports(8) → owner at offset+40
        return self.data[offset + 40 ..][0..32];
    }

    /// Read an account from Agave-format AppendVec data at the given offset.
    /// Layout: StoredMeta(48) + AccountMeta(56) + Hash(32) + data
    fn readAgaveRecord(self: *Self, offset: u64) ?AccountView {
        const current_len = self.current_len.load(.acquire);
        if (offset + AGAVE_MIN_RECORD > current_len) return null;

        const data_len = loadLE(u64, self.data[offset + 8 ..].ptr);
        if (data_len > 10 * 1024 * 1024) return null;

        const meta_offset = offset + AGAVE_STORED_META_SIZE;
        const data_offset = meta_offset + AGAVE_ACCOUNT_META_SIZE + AGAVE_HASH_SIZE;
        const data_end = data_offset + @as(usize, @intCast(data_len));
        if (data_end > current_len) return null;

        const lamports = loadLE(u64, self.data[meta_offset..].ptr);
        const rent_epoch = loadLE(u64, self.data[meta_offset + 8 ..].ptr);
        var owner = core.Pubkey{ .data = undefined };
        @memcpy(&owner.data, self.data[meta_offset + 16 ..][0..32]);
        const executable = self.data[meta_offset + 48] != 0;

        const account_data = if (data_len > 0)
            self.data[data_offset..data_end]
        else
            &[_]u8{};

        return AccountView{
            .lamports = lamports,
            .owner = owner,
            .executable = executable,
            .rent_epoch = rent_epoch,
            .data = account_data,
        };
    }

    pub fn append(self: *Self, data: []const u8) !u64 {
        const offset = self.current_len.fetchAdd(data.len, .seq_cst);
        if (offset + data.len > self.capacity) {
            // Rollback the atomic add
            _ = self.current_len.fetchSub(data.len, .seq_cst);
            return error.AppendVecFull;
        }

        // Write to heap buffer (no SIGBUS risk)
        @memcpy(self.data[offset..][0..data.len], data);
        self.dirty = true;
        // Task #71 [MEM-BREAKDOWN]: lifetime appended bytes (monotonic) — the
        // expected dirty-RSS slope of the heap-store class.
        _ = g_av_appended_bytes.fetchAdd(data.len, .monotonic);

        const new_len = offset + data.len;
        self.updateHeaderLen(new_len);

        // Periodically flush to disk
        if (new_len - self.last_meta_len >= meta_flush_interval) {
            self.flushToDisk() catch {};
            self.last_meta_len = new_len;
        }
        return offset;
    }

    /// Flush the in-memory buffer to disk
    pub fn flushToDisk(self: *Self) !void {
        if (!self.dirty) return;

        // Open/create file if not already open
        if (self.file == null) {
            self.file = try std.fs.cwd().createFile(self.file_path, .{ .read = true, .truncate = true });
        }

        const current_len = self.current_len.load(.acquire);
        const file = self.file.?;

        // Append-only tail write. The .av buffer only ever grows, so bytes below
        // flushed_len are immutable EXCEPT the 8-byte header length field at
        // offset 12 (updateHeaderLen rewrites it in the buffer on every append).
        // Rewriting the whole buffer from 0 on each 1 MB flush was O(n^2) write
        // amplification into tmpfs (a 66 MB store rewrote ~2.2 GB). Write just the
        // new tail at its offset and refresh the header length separately. The
        // resulting file is byte-identical to the full-rewrite path.
        if (current_len > self.flushed_len) {
            try file.pwriteAll(self.data[self.flushed_len..current_len], self.flushed_len);
            if (self.flushed_len >= header_size) {
                // Tail didn't cover the header; refresh the on-disk length field.
                try file.pwriteAll(self.data[12..20], 12);
            }
            try file.sync();
            self.flushed_len = current_len;
        }

        if (verify_av_flush) try self.shadowVerifyFile(current_len);

        self.dirty = false;
    }

    /// Shadow check (`-Dverify_av_flush`): read the whole .av file back and assert
    /// it byte-matches the heap buffer. Proves the incremental tail-write produces
    /// the identical file the old full-rewrite did. comptime-dead when disarmed.
    fn shadowVerifyFile(self: *Self, current_len: u64) !void {
        const file = self.file.?;
        const buf = try self.allocator.alloc(u8, @intCast(current_len));
        defer self.allocator.free(buf);
        const n = try file.preadAll(buf, 0);
        if (n != current_len) std.debug.panic(
            "[AppendVec verify] {s}: file len {d} != expected {d}",
            .{ self.file_path, n, current_len },
        );
        if (!std.mem.eql(u8, buf, self.data[0..@intCast(current_len)])) {
            var i: usize = 0;
            while (i < current_len) : (i += 1) {
                if (buf[i] != self.data[i]) break;
            }
            std.debug.panic(
                "[AppendVec verify] {s}: byte mismatch at offset {d} (file=0x{x:0>2} buf=0x{x:0>2}), flushed_len={d}",
                .{ self.file_path, i, buf[i], self.data[i], self.flushed_len },
            );
        }
    }

    pub fn readRecord(self: *Self, offset: u64) ?Record {
        const current_len = self.current_len.load(.acquire);
        if (offset < header_size) return null;
        if (offset + record_header_len > current_len) return null;
        var cursor = offset;
        var pubkey = core.Pubkey{ .data = undefined };
        @memcpy(&pubkey.data, self.data[cursor..][0..32]);
        cursor += 32;
        const lamports = loadLE(u64, self.data[cursor..].ptr);
        cursor += 8;
        var owner = core.Pubkey{ .data = undefined };
        @memcpy(&owner.data, self.data[cursor..][0..32]);
        cursor += 32;
        const executable = self.data[cursor] != 0;
        cursor += 1;
        const rent_epoch = loadLE(u64, self.data[cursor..].ptr);
        cursor += 8;
        const data_len = loadLE(u32, self.data[cursor..].ptr);
        cursor += 4;
        const total_len = record_header_len + @as(usize, data_len);
        if (cursor + data_len > current_len) return null;
        const data = self.data[cursor..][0..data_len];
        return .{
            .pubkey = pubkey,
            .account = .{
                .lamports = lamports,
                .owner = owner,
                .executable = executable,
                .rent_epoch = rent_epoch,
                .data = data,
            },
            .total_len = @intCast(total_len),
        };
    }

    pub fn firstRecordOffset(_: *Self) u64 {
        return @intCast(header_size);
    }

    fn writeHeader(_: *Self, file: std.fs.File, len: u64) !void {
        var header: [header_size]u8 = .{0} ** header_size;
        @memcpy(header[0..8], &header_magic);
        std.mem.writeInt(u32, header[8..][0..4], 1, .little);
        std.mem.writeInt(u64, header[12..][0..8], len, .little);
        try file.pwriteAll(&header, 0);
        try file.sync();
    }

    fn readHeaderLen(_: *Self, file: std.fs.File) !u64 {
        var header: [header_size]u8 = undefined;
        _ = try file.preadAll(&header, 0);
        if (!std.mem.eql(u8, header[0..8], &header_magic)) {
            return error.InvalidHeader;
        }
        return std.mem.readInt(u64, header[12..][0..8], .little);
    }

    fn updateHeaderLen(self: *Self, len: u64) void {
        if (self.data.len < header_size) return;
        std.mem.writeInt(u64, self.data[12..][0..8], len, .little);
    }

    pub fn flushMeta(self: *Self) !void {
        const len = self.current_len.load(.acquire);
        try self.persistMeta(len);
    }

    fn metaPath(self: *Self) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}.len", .{self.file_path});
    }

    fn persistMeta(self: *Self, len: u64) !void {
        const meta_path = try self.metaPath();
        defer self.allocator.free(meta_path);
        const file = try std.fs.cwd().createFile(meta_path, .{ .truncate = true });
        defer file.close();
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, len, .little);
        try file.writeAll(&buf);
        self.last_meta_len = len;
    }

    fn readMeta(self: *Self) ?u64 {
        const meta_path = self.metaPath() catch return null;
        defer self.allocator.free(meta_path);
        var file = std.fs.cwd().openFile(meta_path, .{ .mode = .read_only }) catch return null;
        defer file.close();
        var buf: [8]u8 = undefined;
        const n = file.readAll(&buf) catch return null;
        if (n != buf.len) return null;
        return std.mem.readInt(u64, &buf, .little);
    }
};
