//! sBPF virtual memory map
//!
//! Provides address translation between VM virtual addresses and host pointers.
//! Two modes match Agave/rbpf exactly:
//!   aligned   — regions are power-of-two aligned; fast index by upper bits
//!   unaligned — sequential region list; needed for legacy programs
//!
//! References:
//!   fd_vm_private.h (fd_vm_mem_haddr, region tables)
//!   sig/src/vm/memory.zig (tagged-union MemoryMap, Region)
//!   agave: sbpf/src/memory_region.rs

const std = @import("std");
const sbpf = @import("vm_sbpf.zig");

// ── Region ────────────────────────────────────────────────────────────────────

/// A single contiguous mapping from [vm_addr, vm_addr+len) → host memory.
/// fd_vm_private.h:fd_vm_input_region_t / sig/src/vm/memory.zig:Region
pub const Region = struct {
    vm_addr: u64, // inclusive start in VM address space
    len: u64, // byte length
    host_ptr: [*]u8, // writable pointer; set is_mutable=false to enforce RO
    is_mutable: bool,

    /// Construct from a mutable slice (rw).
    pub fn fromSlice(vm_addr: u64, buf: []u8) Region {
        return .{ .vm_addr = vm_addr, .len = buf.len, .host_ptr = buf.ptr, .is_mutable = true };
    }

    /// Construct from a read-only slice (RO enforced at translate time).
    pub fn fromConst(vm_addr: u64, buf: []const u8) Region {
        return .{ .vm_addr = vm_addr, .len = buf.len, .host_ptr = @constCast(buf.ptr), .is_mutable = false };
    }

    pub inline fn vmEnd(self: Region) u64 {
        return self.vm_addr +% self.len;
    }

    /// True if vm_addr falls within this region.
    pub inline fn contains(self: Region, vm_addr: u64) bool {
        return vm_addr >= self.vm_addr and vm_addr < self.vmEnd();
    }
};

// ── Memory state (access type) ────────────────────────────────────────────────
pub const MemoryState = enum {
    constant, // read-only
    mutable, // read-write

    pub fn Slice(comptime self: MemoryState) type {
        return if (self == .constant) []const u8 else []u8;
    }
};

// ── Access errors ─────────────────────────────────────────────────────────────
pub const AccessError = error{
    AccessViolation,
    StackAccessViolation,
};

// ── Tagged-union MemoryMap ────────────────────────────────────────────────────
// cf. sig/src/vm/memory.zig:MemoryMap (same union trick, different naming)

pub const MemoryMap = union(enum) {
    aligned: AlignedMemoryMap,
    unaligned: UnalignedMemoryMap,

    pub fn initAligned(regions: []const Region) error{OutOfMemory}!MemoryMap {
        return .{ .aligned = AlignedMemoryMap.init(regions) };
    }

    pub fn initUnaligned(
        allocator: std.mem.Allocator,
        regions: []const Region,
    ) error{OutOfMemory}!MemoryMap {
        return .{ .unaligned = try UnalignedMemoryMap.init(allocator, regions) };
    }

    pub fn deinit(self: *MemoryMap, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .aligned => {},
            .unaligned => |*u| u.deinit(allocator),
        }
    }

    /// Translate a VM virtual address to a writable host slice.
    /// Equivalent to fd_vm_mem_haddr + bounds check.
    pub fn vmap(
        self: MemoryMap,
        comptime access: MemoryState,
        vm_addr: u64,
        len: u64,
    ) AccessError!access.Slice() {
        return switch (self) {
            .aligned => |a| a.vmap(access, vm_addr, len),
            .unaligned => |u| u.vmap(access, vm_addr, len),
        };
    }

    /// Load a value of type T from vm_addr (little-endian).
    pub fn load(self: MemoryMap, comptime T: type, vm_addr: u64) AccessError!T {
        const bytes = try self.vmap(.constant, vm_addr, @sizeOf(T));
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
    }

    /// Store a value of type T at vm_addr (little-endian).
    pub fn store(self: MemoryMap, comptime T: type, vm_addr: u64, value: T) AccessError!void {
        const bytes = try self.vmap(.mutable, vm_addr, @sizeOf(T));
        std.mem.writeInt(T, bytes[0..@sizeOf(T)], value, .little);
    }

    /// Translate a typed pointer (single T) at vm_addr.
    /// cf. sig/src/vm/memory.zig:MemoryMap.translateType
    pub fn translateType(
        self: MemoryMap,
        comptime T: type,
        comptime access: MemoryState,
        vm_addr: u64,
    ) AccessError!if (access == .constant) *const T else *T {
        const raw = try self.vmap(access, vm_addr, @sizeOf(T));
        return @ptrCast(@alignCast(raw.ptr));
    }

    /// Translate a slice of n elements of type T.
    pub fn translateSlice(
        self: MemoryMap,
        comptime T: type,
        comptime access: MemoryState,
        vm_addr: u64,
        n: u64,
    ) AccessError!if (access == .constant) []const T else []T {
        const byte_len = std.math.mul(u64, @sizeOf(T), n) catch return AccessError.AccessViolation;
        const raw = try self.vmap(access, vm_addr, byte_len);
        const ptr: [*]T = @ptrCast(@alignCast(raw.ptr));
        return ptr[0..@intCast(n)];
    }
};

// ── AlignedMemoryMap ──────────────────────────────────────────────────────────
// Regions are indexed by the upper 32 bits of the virtual address.
// fd_vm_mem_haddr in fd_vm_private.h uses the same region-index trick.
// Exactly 5 fixed slots: rodata(1), stack(2), heap(3), input(4), bytecode(0=V3).

const MAX_REGIONS = 6;

pub const AlignedMemoryMap = struct {
    // regions[i] covers vm_addr with upper bits == i (i.e., i * 0x100000000)
    regions: [MAX_REGIONS]?Region,

    pub fn init(regions: []const Region) AlignedMemoryMap {
        var self = AlignedMemoryMap{ .regions = [_]?Region{null} ** MAX_REGIONS };
        for (regions) |r| {
            const idx = r.vm_addr >> 32;
            if (idx < MAX_REGIONS) self.regions[@intCast(idx)] = r;
        }
        return self;
    }

    /// fd_vm_mem_haddr equivalent — O(1) lookup.
    pub fn vmap(
        self: AlignedMemoryMap,
        comptime access: MemoryState,
        vm_addr: u64,
        len: u64,
    ) AccessError!access.Slice() {
        const idx = vm_addr >> 32;
        if (idx >= MAX_REGIONS) return AccessError.AccessViolation;
        const r = self.regions[@intCast(idx)] orelse return AccessError.AccessViolation;
        const off = vm_addr - r.vm_addr;
        const end = off +% len;
        if (end < off or end > r.len) return AccessError.AccessViolation;
        if (access == .mutable and !r.is_mutable) return AccessError.AccessViolation;
        // Stack region gets a special error on write violation for diagnostics
        if (access == .mutable and idx == sbpf.STACK_START >> 32 and !r.is_mutable)
            return AccessError.StackAccessViolation;
        return r.host_ptr[@intCast(off)..@intCast(off + len)];
    }
};

// ── UnalignedMemoryMap ────────────────────────────────────────────────────────
// Linear search through region list — correct for legacy programs with
// arbitrary segment layouts.  cf. sig/src/vm/memory.zig:UnalignedMemoryMap.

pub const UnalignedMemoryMap = struct {
    regions: []Region,

    pub fn init(allocator: std.mem.Allocator, regions: []const Region) error{OutOfMemory}!UnalignedMemoryMap {
        const owned = try allocator.dupe(Region, regions);
        return .{ .regions = owned };
    }

    pub fn deinit(self: *UnalignedMemoryMap, allocator: std.mem.Allocator) void {
        allocator.free(self.regions);
    }

    pub fn vmap(
        self: UnalignedMemoryMap,
        comptime access: MemoryState,
        vm_addr: u64,
        len: u64,
    ) AccessError!access.Slice() {
        for (self.regions) |r| {
            if (vm_addr < r.vm_addr or vm_addr >= r.vmEnd()) continue;
            const off = vm_addr - r.vm_addr;
            const end = off +% len;
            if (end < off or end > r.len) return AccessError.AccessViolation;
            if (access == .mutable and !r.is_mutable) return AccessError.AccessViolation;
            return r.host_ptr[@intCast(off)..@intCast(off + len)];
        }
        return AccessError.AccessViolation;
    }
};

// ── VmSlice (helper type for sol_log_data / CPI) ─────────────────────────────
// Matches the Rust &[u8] fat-pointer ABI (ptr + len, each u64).
// sig/src/vm/memory.zig:VmSlice
pub const VmSlice = extern struct {
    ptr: u64,
    len: u64,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "aligned map: basic load/store" {
    var buf = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0 };
    const regions = [_]Region{
        Region.fromSlice(sbpf.INPUT_START, &buf),
    };
    const mm = AlignedMemoryMap.init(&regions);
    const map = MemoryMap{ .aligned = mm };

    const v = try map.load(u32, sbpf.INPUT_START);
    try std.testing.expectEqual(@as(u32, 0xEFBEADDE), v);

    try map.store(u32, sbpf.INPUT_START + 4, 0x11223344);
    try std.testing.expectEqual(@as(u8, 0x44), buf[4]);
}

test "aligned map: access violation on OOB" {
    var buf = [_]u8{0} ** 8;
    const regions = [_]Region{Region.fromSlice(sbpf.INPUT_START, &buf)};
    const mm = AlignedMemoryMap.init(&regions);
    const map = MemoryMap{ .aligned = mm };
    // Accessing 1 byte past end should fail
    const err = map.load(u8, sbpf.INPUT_START + 9);
    try std.testing.expectError(AccessError.AccessViolation, err);
}

test "unaligned map: lookup across regions" {
    var a = [_]u8{0xAA} ** 4;
    var b = [_]u8{0xBB} ** 4;
    const regs = [_]Region{
        Region.fromSlice(0x100, &a),
        Region.fromSlice(0x200, &b),
    };
    const map = try MemoryMap.initUnaligned(std.testing.allocator, &regs);
    defer @constCast(&map).deinit(std.testing.allocator);
    const slice = try map.vmap(.constant, 0x202, 2);
    try std.testing.expectEqual(@as(u8, 0xBB), slice[0]);
}
