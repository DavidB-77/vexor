//! eBPF XDP Program Loader
//! Uses direct bpf() syscalls instead of libbpf
//! Generates eBPF bytecode at runtime (no external compiler needed!)
//!
//! Inspired by high-performance Solana validator implementations.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const ebpf_gen = @import("ebpf_gen.zig");

// Only compile on Linux
comptime {
    if (builtin.target.os.tag != .linux) {
        @compileError("eBPF XDP programs only supported on Linux");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BPF SYSCALL INTERFACE (direct bpf(2) syscalls, no libbpf — same approach Firedancer takes)
// ═══════════════════════════════════════════════════════════════════════════════

// We'll define the BPF structures manually to avoid C union issues
const c = @cImport({
    @cInclude("linux/bpf.h");
    @cInclude("linux/if_link.h");
    @cInclude("sys/syscall.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
});

// Manual definition of union_bpf_attr to avoid opaque type issues
const BpfAttr = extern union {
    map_create: extern struct {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        inner_map_fd: u32,
        numa_node: u32,
        map_name: [16]u8,
        map_ifindex: u32,
        btf_fd: u32,
        btf_key_type_id: u32,
        btf_value_type_id: u32,
        btf_vmlinux_value_type_id: u32,
    },
    prog_load: extern struct {
        prog_type: u32,
        insn_cnt: u32,
        insns: usize,
        license: usize,
        log_level: u32,
        log_size: u32,
        log_buf: usize,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [16]u8,
        prog_ifindex: u32,
        expected_attach_type: u32,
        prog_btf_fd: u32,
        func_info_rec_size: u32,
        func_info: usize,
        func_info_cnt: u32,
        line_info_rec_size: u32,
        line_info: usize,
        line_info_cnt: u32,
        attach_btf_id: u32,
        attach_prog_fd: u32,
        fd_array: usize, // Pointer to array of map FDs
    },
    map_update_elem: extern struct {
        map_fd: u32,
        _pad0: u32, // padding for alignment
        key: usize,
        value: usize,
        flags: u64, // flags comes AFTER key and value!
    },
    map_delete_elem: extern struct {
        map_fd: u32,
        _pad0: u32, // padding for alignment
        key: usize,
    },
    link_create: extern struct {
        prog_fd: u32,
        target_ifindex: u32,
        attach_type: u32,
        flags: u32,
        target_btf_id: u32,
    },
};

// BPF syscall wrapper (serves the same role as Firedancer's bpf() helper)
// Use C syscall function
extern "c" fn syscall(number: c_long, ...) c_long;

fn bpf(cmd: c_int, attr: *const BpfAttr, size: usize) c_long {
    const SYS_bpf = 321; // Linux x86_64 syscall number for bpf
    return syscall(SYS_bpf, @as(c_long, cmd), @intFromPtr(attr), @as(c_long, @intCast(size)));
}

// BPF command constants
const BPF_MAP_CREATE = 0;
const BPF_PROG_LOAD = 5;
const BPF_MAP_UPDATE_ELEM = 2;
const BPF_MAP_DELETE_ELEM = 3;
const BPF_LINK_CREATE = 28;
const BPF_OBJ_GET = 5; // Note: same as PROG_LOAD, distinguished by union_bpf_attr fields

// BPF map types
const BPF_MAP_TYPE_XSKMAP = 17;
const BPF_MAP_TYPE_HASH = 1;

// BPF program types
const BPF_PROG_TYPE_XDP = 6;

// XDP flags (must match kernel uapi/linux/if_link.h)
const XDP_FLAGS_UPDATE_IF_NOEXIST = 1 << 0;
const XDP_FLAGS_SKB_MODE = 1 << 1;
const XDP_FLAGS_DRV_MODE = 1 << 2; // Driver mode for zero-copy support
const XDP_FLAGS_HW_MODE = 1 << 3;

// BPF attach types
const BPF_XDP = 37;

// BPF map update flags
const BPF_ANY = 0;
const BPF_NOEXIST = 1;
const BPF_EXIST = 2;

// ═══════════════════════════════════════════════════════════════════════════════
// XDP PROGRAM (using direct syscalls)
// ═══════════════════════════════════════════════════════════════════════════════

pub const XdpProgram = struct {
    /// XSKMAP file descriptor
    xsks_map_fd: i32,
    /// Port filter map file descriptor
    port_filter_map_fd: i32,
    /// Program file descriptor
    prog_fd: i32,
    /// Link file descriptor (from BPF_LINK_CREATE)
    link_fd: i32,
    /// Interface index
    ifindex: u32,
    /// Attachment mode
    mode: AttachMode,
    /// Allocator
    allocator: Allocator,
    /// Is attached
    attached: bool,

    pub const AttachMode = enum(u32) {
        skb = XDP_FLAGS_SKB_MODE, // SKB mode (slower, more compatible)
        driver = XDP_FLAGS_DRV_MODE, // Driver mode (faster, zero-copy capable)
        hardware = XDP_FLAGS_HW_MODE, // Hardware offload (fastest, limited support)
        update_only = XDP_FLAGS_UPDATE_IF_NOEXIST,
    };

    const Self = @This();

    /// Initialize XDP program by loading from compiled BPF object file
    /// This uses bpftool to load the program, then retrieves the FD
    /// For now, we'll create maps manually and load a simple program
    /// TODO: Parse ELF file to extract program and maps
    pub fn init(allocator: Allocator, ifindex: u32, mode: AttachMode, bind_port: u16) !Self {
        // Create XSKMAP (matches Firedancer's XSKMAP setup)
        var xsks_map_attr: BpfAttr = std.mem.zeroes(BpfAttr);
        xsks_map_attr.map_create.map_type = BPF_MAP_TYPE_XSKMAP;
        xsks_map_attr.map_create.key_size = 4;
        xsks_map_attr.map_create.value_size = 4;
        xsks_map_attr.map_create.max_entries = 256;
        @memset(&xsks_map_attr.map_create.map_name, 0);
        const map_name = "vx_xsks_map";
        @memcpy(xsks_map_attr.map_create.map_name[0..map_name.len], map_name);

        const xsks_map_fd = bpf(BPF_MAP_CREATE, &xsks_map_attr, @sizeOf(BpfAttr));
        if (xsks_map_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(xsks_map_fd)));
            std.log.err("[XDP] Failed to create XSKMAP: {s}", .{@tagName(err)});
            return error.XskMapCreateFailed;
        }

        // Create port filter map
        var port_filter_attr: BpfAttr = std.mem.zeroes(BpfAttr);
        port_filter_attr.map_create.map_type = BPF_MAP_TYPE_HASH;
        port_filter_attr.map_create.key_size = 2; // u16 port
        port_filter_attr.map_create.value_size = 1; // u8 action
        port_filter_attr.map_create.max_entries = 16;
        @memset(&port_filter_attr.map_create.map_name, 0);
        const filter_name = "port_filter";
        @memcpy(port_filter_attr.map_create.map_name[0..filter_name.len], filter_name);

        const port_filter_map_fd = bpf(BPF_MAP_CREATE, &port_filter_attr, @sizeOf(BpfAttr));
        if (port_filter_map_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(port_filter_map_fd)));
            std.log.err("[XDP] Failed to create port filter map: {s}", .{@tagName(err)});
            _ = posix.close(@intCast(xsks_map_fd));
            return error.PortFilterMapCreateFailed;
        }

        // Load eBPF program from compiled .o file
        // For now, we'll use a helper: load via bpftool or parse ELF
        // TODO: Implement ELF parsing to extract program instructions
        // For now, return error - we need to implement program loading
        const prog_fd_long = try loadBpfProgram(allocator, @intCast(xsks_map_fd), @intCast(port_filter_map_fd), bind_port);
        const prog_fd = @as(i32, @intCast(prog_fd_long));
        errdefer _ = posix.close(@intCast(xsks_map_fd));
        errdefer _ = posix.close(@intCast(port_filter_map_fd));

        // Attach program to interface
        var link_attr: BpfAttr = std.mem.zeroes(BpfAttr);
        link_attr.link_create.prog_fd = @intCast(prog_fd);
        link_attr.link_create.target_ifindex = ifindex;
        link_attr.link_create.attach_type = BPF_XDP;
        link_attr.link_create.flags = @intCast(@intFromEnum(mode));

        const link_fd = bpf(BPF_LINK_CREATE, &link_attr, @sizeOf(BpfAttr));
        if (link_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(link_fd)));
            std.log.err("[XDP] Failed to attach program to interface {d}: {s}", .{ ifindex, @tagName(err) });
            _ = posix.close(@intCast(prog_fd));
            return error.AttachFailed;
        }

        // Add port to filter map
        var port_key: u16 = bind_port;
        var port_value: u8 = 1;
        var update_attr: BpfAttr = std.mem.zeroes(BpfAttr);
        update_attr.map_update_elem.map_fd = @intCast(port_filter_map_fd);
        update_attr.map_update_elem.key = @intFromPtr(&port_key);
        update_attr.map_update_elem.value = @intFromPtr(&port_value);
        update_attr.map_update_elem.flags = BPF_ANY;

        const update_result = bpf(BPF_MAP_UPDATE_ELEM, &update_attr, @sizeOf(BpfAttr));
        if (update_result < 0) {
            std.log.warn("[XDP] Failed to add port {d} to filter (continuing anyway)", .{bind_port});
        }

        return Self{
            .xsks_map_fd = @intCast(xsks_map_fd),
            .port_filter_map_fd = @intCast(port_filter_map_fd),
            .prog_fd = @intCast(prog_fd),
            .link_fd = @intCast(link_fd),
            .ifindex = ifindex,
            .mode = mode,
            .allocator = allocator,
            .attached = true,
        };
    }

    /// Initialize XDP program WITHOUT attaching to NIC (safe initialization)
    /// Call attach() separately after registering sockets in XSKMAP
    pub fn initWithoutAttach(allocator: Allocator, ifindex: u32, mode: AttachMode, bind_port: u16) !Self {
        // Create XSKMAP (matches Firedancer's XSKMAP setup)
        var xsks_map_attr: BpfAttr = std.mem.zeroes(BpfAttr);
        xsks_map_attr.map_create.map_type = BPF_MAP_TYPE_XSKMAP;
        xsks_map_attr.map_create.key_size = 4;
        xsks_map_attr.map_create.value_size = 4;
        xsks_map_attr.map_create.max_entries = 256;
        @memset(&xsks_map_attr.map_create.map_name, 0);
        const map_name = "vx_xsks_map";
        @memcpy(xsks_map_attr.map_create.map_name[0..map_name.len], map_name);

        const xsks_map_fd = bpf(BPF_MAP_CREATE, &xsks_map_attr, @sizeOf(BpfAttr));
        if (xsks_map_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(xsks_map_fd)));
            std.log.err("[XDP] Failed to create XSKMAP: {s}", .{@tagName(err)});
            return error.XskMapCreateFailed;
        }

        // Create port filter map
        var port_filter_attr: BpfAttr = std.mem.zeroes(BpfAttr);
        port_filter_attr.map_create.map_type = BPF_MAP_TYPE_HASH;
        port_filter_attr.map_create.key_size = 2;
        port_filter_attr.map_create.value_size = 1;
        port_filter_attr.map_create.max_entries = 16;
        @memset(&port_filter_attr.map_create.map_name, 0);
        const filter_name = "port_filter";
        @memcpy(port_filter_attr.map_create.map_name[0..filter_name.len], filter_name);

        const port_filter_map_fd = bpf(BPF_MAP_CREATE, &port_filter_attr, @sizeOf(BpfAttr));
        if (port_filter_map_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(port_filter_map_fd)));
            std.log.err("[XDP] Failed to create port filter map: {s}", .{@tagName(err)});
            _ = posix.close(@intCast(xsks_map_fd));
            return error.PortFilterMapCreateFailed;
        }

        // Load eBPF program (but DON'T attach yet)
        const prog_fd_long = try loadBpfProgram(allocator, @intCast(xsks_map_fd), @intCast(port_filter_map_fd), bind_port);
        const prog_fd = @as(i32, @intCast(prog_fd_long));
        errdefer _ = posix.close(@intCast(xsks_map_fd));
        errdefer _ = posix.close(@intCast(port_filter_map_fd));

        std.log.info("[XDP] Program loaded but NOT attached yet (safe mode)", .{});

        return Self{
            .xsks_map_fd = @intCast(xsks_map_fd),
            .port_filter_map_fd = @intCast(port_filter_map_fd),
            .prog_fd = @intCast(prog_fd),
            .link_fd = -1, // Not attached yet
            .ifindex = ifindex,
            .mode = mode,
            .allocator = allocator,
            .attached = false, // Not attached
        };
    }

    /// Attach the XDP program to the network interface
    /// ONLY call this AFTER registering sockets in XSKMAP!
    pub fn attach(self: *Self) !void {
        if (self.attached) {
            return error.AlreadyAttached;
        }

        var link_attr: BpfAttr = std.mem.zeroes(BpfAttr);
        link_attr.link_create.prog_fd = @intCast(self.prog_fd);
        link_attr.link_create.target_ifindex = self.ifindex;
        link_attr.link_create.attach_type = BPF_XDP;
        // d27i (2026-05-11): BPF_LINK_CREATE flags field accepts ONLY
        // BPF_F_LINK / BPF_F_REPLACE (or 0). The XDP_FLAGS_{SKB,DRV,HW}_MODE
        // constants are netlink RTM_SETLINK semantics — invalid here. Most
        // kernels reject the call with -EINVAL when a netlink-mode flag is
        // passed, but some silently drop the bits, falling back to SKB mode
        // (and our standalone attach then "succeeds" but produces no
        // rx_xdp_redirect activity). Per Linux 6.12 sources the kernel
        // auto-picks DRV mode for mlx5 (which registers ndo_bpf) when
        // flags=0. To force DRV-only-fail-if-not-supported we'd need to
        // switch to the netlink path. For now: let the kernel auto-pick.
        link_attr.link_create.flags = 0;

        const link_fd = bpf(BPF_LINK_CREATE, &link_attr, @sizeOf(BpfAttr));
        if (link_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(link_fd)));
            std.log.err("[XDP] Failed to attach program to interface {d}: {s} (requested_mode={s})", .{ self.ifindex, @tagName(err), @tagName(self.mode) });
            return error.AttachFailed;
        }

        self.link_fd = @intCast(link_fd);
        self.attached = true;
        std.log.warn("[XDP] ✅ Program attached to interface {d} via BPF_LINK_CREATE (kernel chose mode; verify via 'bpftool net list')", .{self.ifindex});
    }

    /// Generate and load BPF program at runtime (runtime bytecode generation,
    /// the same approach Firedancer takes). No need for clang/LLVM - bytecode
    /// is generated directly!
    fn loadBpfProgram(allocator: Allocator, xsks_map_fd: i32, port_filter_map_fd: i32, bind_port: u16) !i32 {
        _ = port_filter_map_fd; // Not used - we embed ports directly in bytecode

        // Generate eBPF bytecode at runtime
        var code_buf: [512]u64 = undefined;
        const ports = [_]u16{bind_port};

        const code_cnt = ebpf_gen.generateXdpProgram(&code_buf, xsks_map_fd, &ports) catch |err| {
            std.log.err("[XDP] Failed to generate eBPF program: {any}", .{err});
            return error.ProgramGenerationFailed;
        };

        // Convert to bytes for BPF_PROG_LOAD
        var byte_buf: [4096]u8 = undefined;
        const prog_bytes = ebpf_gen.codeToBytes(code_buf[0..code_cnt], &byte_buf) catch |err| {
            std.log.err("[XDP] Failed to convert eBPF program to bytes: {any}", .{err});
            return error.ProgramGenerationFailed;
        };

        // Allocate log buffer for verifier output
        const log_buf = try allocator.alloc(u8, 32768);
        defer allocator.free(log_buf);
        @memset(log_buf, 0);

        // Load program using BPF_PROG_LOAD
        var load_attr: BpfAttr = std.mem.zeroes(BpfAttr);
        load_attr.prog_load.prog_type = BPF_PROG_TYPE_XDP;
        load_attr.prog_load.insn_cnt = @intCast(code_cnt);
        load_attr.prog_load.insns = @intFromPtr(prog_bytes.ptr);
        load_attr.prog_load.license = @intFromPtr("GPL");
        load_attr.prog_load.log_level = 1;
        load_attr.prog_load.log_size = 32768;
        load_attr.prog_load.log_buf = @intFromPtr(log_buf.ptr);

        const prog_fd = bpf(BPF_PROG_LOAD, &load_attr, @sizeOf(BpfAttr));
        if (prog_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(prog_fd)));
            std.log.err("[XDP] Failed to load BPF program: {s}", .{@tagName(err)});
            if (log_buf[0] != 0) {
                // Find null terminator
                var log_len: usize = 0;
                while (log_len < log_buf.len and log_buf[log_len] != 0) : (log_len += 1) {}
                std.log.err("[XDP] eBPF verifier log:\n{s}", .{log_buf[0..log_len]});
            }
            return error.ProgramLoadFailed;
        }

        std.log.info("[XDP] eBPF program loaded successfully (FD: {d}, {d} instructions, port: {d})", .{ prog_fd, code_cnt, bind_port });
        return @intCast(prog_fd);
    }

    /// Detach XDP program from network interface
    pub fn detach(self: *Self) !void {
        if (!self.attached) {
            return;
        }

        // Close link FD (this detaches the program)
        _ = posix.close(self.link_fd);
        // SENTINEL RESET (bug #40): after closing, invalidate link_fd so a
        // subsequent deinit() cannot close the SAME fd a second time. Without
        // this, deinit()'s `if (attached) detach()` closed link_fd here, then
        // deinit()'s trailing `if (link_fd >= 0) close(link_fd)` closed it
        // again → EBADF → std.posix.close hits `unreachable` → SIGABRT. This
        // fired on the rapid kill→relaunch fallback (attach succeeds, XdpSocket
        // bind fails, fallback calls deinit on the attached-but-unbound object).
        // Matches sibling shared_xdp.zig:233 and Firedancer fd_xsk_fini
        // (close(fd); fd = -1;).
        self.link_fd = -1;
        self.attached = false;
        self.ifindex = 0;

        std.log.info("[XDP] Program detached from interface", .{});
    }

    /// Register AF_XDP socket in XSKMAP
    pub fn registerSocket(self: *Self, queue_id: u32, socket_fd: i32) !void {
        var key: u32 = queue_id;
        var value: u32 = @intCast(socket_fd);

        var attr: BpfAttr = std.mem.zeroes(BpfAttr);
        attr.map_update_elem.map_fd = @intCast(self.xsks_map_fd);
        attr.map_update_elem.key = @intFromPtr(&key);
        attr.map_update_elem.value = @intFromPtr(&value);
        attr.map_update_elem.flags = BPF_ANY;

        const result = bpf(BPF_MAP_UPDATE_ELEM, &attr, @sizeOf(BpfAttr));
        if (result < 0) {
            const err = std.posix.errno(@as(i32, @intCast(result)));
            std.log.err("[XDP] Failed to register socket {d} in XSKMAP for queue {d}: {s}", .{ socket_fd, queue_id, @tagName(err) });
            return error.RegisterSocketFailed;
        }

        std.log.debug("[XDP] Registered socket {d} in XSKMAP for queue {d}", .{ socket_fd, queue_id });
    }

    /// Add port to filter (enable redirect for this port)
    pub fn addPort(self: *Self, port: u16) !void {
        var key: u16 = port;
        var value: u8 = 1;

        var attr: BpfAttr = std.mem.zeroes(BpfAttr);
        attr.map_update_elem.map_fd = @intCast(self.port_filter_map_fd);
        attr.map_update_elem.key = @intFromPtr(&key);
        attr.map_update_elem.value = @intFromPtr(&value);
        attr.map_update_elem.flags = BPF_ANY;

        const result = bpf(BPF_MAP_UPDATE_ELEM, &attr, @sizeOf(BpfAttr));
        if (result < 0) {
            const err = std.posix.errno(@as(i32, @intCast(result)));
            std.log.err("[XDP] Failed to add port {d} to filter map: {s}", .{ port, @tagName(err) });
            return error.AddPortFailed;
        }

        std.log.debug("[XDP] Added port {d} to eBPF filter map", .{port});
    }

    /// Cleanup and deinitialize.
    ///
    /// Bug #40 root fix: idempotent and tolerant of EVERY partial-init state
    /// (never-attached, attach-failed, socket-bind-failed, double-deinit). Each
    /// resource is guarded on its own validity, closed, then reset to the -1
    /// sentinel so no fd is ever closed twice (a second close returns EBADF and
    /// std.posix.close turns EBADF into `unreachable` → SIGABRT). Discipline
    /// matches Firedancer fd_xsk_fini() — `if (fd>=0) { close(fd); fd = -1; }`.
    pub fn deinit(self: *Self) void {
        if (self.attached) {
            // detach() closes link_fd and resets it to -1 (see above).
            self.detach() catch {};
        }

        if (self.prog_fd >= 0) {
            _ = posix.close(self.prog_fd);
            self.prog_fd = -1;
        }
        if (self.xsks_map_fd >= 0) {
            _ = posix.close(self.xsks_map_fd);
            self.xsks_map_fd = -1;
        }
        if (self.port_filter_map_fd >= 0) {
            _ = posix.close(self.port_filter_map_fd);
            self.port_filter_map_fd = -1;
        }
        if (self.link_fd >= 0) {
            _ = posix.close(self.link_fd);
            self.link_fd = -1;
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════════

pub const XdpProgramError = error{
    XskMapCreateFailed,
    PortFilterMapCreateFailed,
    ProgramLoadNotImplemented,
    AttachFailed,
    RegisterSocketFailed,
    UnregisterSocketFailed,
    AddPortFailed,
    RemovePortFailed,
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS — bug #40: deinit() must be safe for every partial-initialization state
// (rapid kill→relaunch: attach succeeds but AF_XDP socket bind fails, so the
// fallback path calls deinit() on an attached-but-unbound XdpProgram).
// ═══════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

/// Allocate a real, open fd so posix.close() actually closes something (and a
/// second close would legitimately return EBADF).
fn testOpenFd() !i32 {
    return try posix.eventfd(0, 0);
}

/// True iff `fd` is currently a valid open descriptor (F_GETFD returns 0).
fn fdIsOpen(fd: i32) bool {
    const rc = std.os.linux.fcntl(fd, std.os.linux.F.GETFD, 0);
    return std.os.linux.E.init(rc) == .SUCCESS;
}

// Mechanism proof (deterministic, no NIC): closing the SAME fd twice returns
// EBADF on the second close. This is exactly the condition that std.posix.close
// converts into `unreachable` → SIGABRT — i.e. the pre-fix crash. We observe it
// via the raw linux syscall so we can assert on errno instead of aborting.
test "bug40: double-close of one fd yields EBADF (pre-fix crash precondition)" {
    const fd = try testOpenFd();
    try testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.E.init(std.os.linux.close(fd)));
    // Second close of the now-stale fd number → EBADF (what deinit used to do
    // to link_fd after detach() had already closed it).
    try testing.expectEqual(std.os.linux.E.BADF, std.os.linux.E.init(std.os.linux.close(fd)));
}

test "bug40: deinit on never-attached object is clean and leaves sentinels" {
    var prog = XdpProgram{
        .xsks_map_fd = try testOpenFd(),
        .port_filter_map_fd = try testOpenFd(),
        .prog_fd = try testOpenFd(),
        .link_fd = -1, // never attached (initWithoutAttach state)
        .ifindex = 3,
        .mode = .skb,
        .allocator = testing.allocator,
        .attached = false,
    };
    prog.deinit();
    try testing.expectEqual(@as(i32, -1), prog.prog_fd);
    try testing.expectEqual(@as(i32, -1), prog.xsks_map_fd);
    try testing.expectEqual(@as(i32, -1), prog.port_filter_map_fd);
    try testing.expectEqual(@as(i32, -1), prog.link_fd);
}

test "bug40: deinit on attached-but-bind-failed does NOT double-close link_fd" {
    // This is the exact crash state: attach() succeeded (link_fd valid,
    // attached=true) but the subsequent XdpSocket bind failed, so the fallback
    // path calls deinit(). Pre-fix: detach() closes link_fd, then the trailing
    // block closes it again → EBADF → unreachable → SIGABRT.
    const link_fd = try testOpenFd();
    var prog = XdpProgram{
        .xsks_map_fd = try testOpenFd(),
        .port_filter_map_fd = try testOpenFd(),
        .prog_fd = try testOpenFd(),
        .link_fd = link_fd,
        .ifindex = 3,
        .mode = .skb,
        .allocator = testing.allocator,
        .attached = true,
    };
    prog.deinit(); // must not abort
    try testing.expectEqual(@as(i32, -1), prog.link_fd);
    try testing.expect(!prog.attached);
    // link_fd was closed exactly once (still closed, not re-openable here).
    try testing.expect(!fdIsOpen(link_fd));
}

test "bug40: detach() resets link_fd sentinel and is followed by clean deinit" {
    const link_fd = try testOpenFd();
    var prog = XdpProgram{
        .xsks_map_fd = try testOpenFd(),
        .port_filter_map_fd = try testOpenFd(),
        .prog_fd = try testOpenFd(),
        .link_fd = link_fd,
        .ifindex = 3,
        .mode = .skb,
        .allocator = testing.allocator,
        .attached = true,
    };
    try prog.detach();
    try testing.expectEqual(@as(i32, -1), prog.link_fd);
    try testing.expect(!prog.attached);
    prog.deinit(); // link_fd already -1 → trailing block skips it, no double close
    try testing.expectEqual(@as(i32, -1), prog.prog_fd);
}

test "bug40: double-deinit is idempotent (no double-close)" {
    var prog = XdpProgram{
        .xsks_map_fd = try testOpenFd(),
        .port_filter_map_fd = try testOpenFd(),
        .prog_fd = try testOpenFd(),
        .link_fd = try testOpenFd(),
        .ifindex = 3,
        .mode = .driver,
        .allocator = testing.allocator,
        .attached = true,
    };
    prog.deinit();
    prog.deinit(); // second call: all fds already -1 → every guard skips, no abort
    try testing.expectEqual(@as(i32, -1), prog.link_fd);
    try testing.expectEqual(@as(i32, -1), prog.prog_fd);
}
