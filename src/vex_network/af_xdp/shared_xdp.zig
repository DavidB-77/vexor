//! Shared XDP Program Manager
//!
//! Manages ONE XDP program and XSKMAP for multiple AF_XDP sockets.
//! Uses pre-compiled and pinned BPF program (loaded by setup-xdp.sh).
//!
//! Architecture:
//! 1. Get pinned XSKMAP FD from /sys/fs/bpf/vexor/xsks_map
//! 2. Get pinned program FD from /sys/fs/bpf/vexor/prog
//! 3. Multiple sockets register in the SAME XSKMAP with different queue_ids
//! 4. Attach program ONCE after all sockets are registered
//!
//! Prerequisites:
//!   Run: sudo /home/sol/vexor/scripts/setup-xdp.sh

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

// BPF syscall constants
const BPF_MAP_UPDATE_ELEM: c_int = 2;
const BPF_OBJ_GET: c_int = 7;
const BPF_LINK_CREATE: c_int = 28;

const BPF_XDP: u32 = 37;
const BPF_ANY: u64 = 0;

// Pinned object paths (set up by setup-xdp.sh)
const PINNED_PROG = "/sys/fs/bpf/vexor/prog";
const PINNED_XSKS_MAP = "/sys/fs/bpf/vexor/xsks_map";
const PINNED_PORT_FILTER = "/sys/fs/bpf/vexor/port_filter";

const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

// BPF attribute structures (simplified for our use cases)
const ObjGetAttr = extern struct {
    pathname: u64,
    bpf_fd: u32 = 0,
    file_flags: u32 = 0,
};

const MapUpdateAttr = extern struct {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64,
};

const LinkCreateAttr = extern struct {
    prog_fd: u32,
    target_ifindex: u32 = 0, // Union with target_fd in kernel - must be at offset 4
    attach_type: u32,
    flags: u32 = 0,
    // Padding to match kernel struct size
    _pad: [48]u8 = [_]u8{0} ** 48,
};

// Use C syscall function
extern "c" fn syscall(number: c_long, ...) c_long;

const SYS_bpf: c_long = 321;

fn bpf_obj_get(path: [*:0]const u8) c_long {
    var attr = ObjGetAttr{ .pathname = @intFromPtr(path) };
    return syscall(SYS_bpf, @as(c_long, BPF_OBJ_GET), @intFromPtr(&attr), @as(c_long, @sizeOf(ObjGetAttr)));
}

fn bpf_map_update(map_fd: i32, key: *const anyopaque, value: *const anyopaque) c_long {
    var attr = MapUpdateAttr{
        .map_fd = @intCast(map_fd),
        .key = @intFromPtr(key),
        .value = @intFromPtr(value),
        .flags = BPF_ANY,
    };
    return syscall(SYS_bpf, @as(c_long, BPF_MAP_UPDATE_ELEM), @intFromPtr(&attr), @as(c_long, @sizeOf(MapUpdateAttr)));
}

fn bpf_link_create(prog_fd: i32, ifindex: u32, mode: u32) c_long {
    var attr = LinkCreateAttr{
        .prog_fd = @intCast(prog_fd),
        .attach_type = BPF_XDP,
        .target_ifindex = ifindex,
        .flags = mode,
    };
    return syscall(SYS_bpf, @as(c_long, BPF_LINK_CREATE), @intFromPtr(&attr), @as(c_long, @sizeOf(LinkCreateAttr)));
}

pub const AttachMode = enum(u32) {
    skb = XDP_FLAGS_SKB_MODE,
    driver = XDP_FLAGS_DRV_MODE,
};

pub const SharedXdpManager = struct {
    allocator: Allocator,
    ifindex: u32,
    interface: []const u8,
    ports: []u16, // Owned copy
    xsks_map_fd: i32,
    port_filter_fd: i32,
    prog_fd: i32,
    link_fd: i32,
    mode: AttachMode,
    attached: bool,

    const Self = @This();

    /// Initialize shared XDP manager using pre-loaded pinned BPF objects
    /// Prerequisites: Run setup-xdp.sh first to load and pin the XDP program
    pub fn init(allocator: Allocator, interface: []const u8, ports: []const u16, mode: AttachMode) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Get interface index
        const ifindex = try getInterfaceIndex(interface);

        // Create owned copy of ports
        const ports_copy = try allocator.alloc(u16, ports.len);
        errdefer allocator.free(ports_copy);
        @memcpy(ports_copy, ports);

        // Get pinned XSKMAP
        const xsks_map_fd = bpf_obj_get(PINNED_XSKS_MAP);
        if (xsks_map_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(xsks_map_fd)));
            std.log.err("[SharedXDP] Failed to get pinned xsks_map at {s}: {s}", .{ PINNED_XSKS_MAP, @tagName(err) });
            std.log.err("[SharedXDP] Run setup-xdp.sh first: sudo /home/sol/vexor/scripts/setup-xdp.sh", .{});
            return error.PinnedMapNotFound;
        }
        errdefer _ = posix.close(@intCast(xsks_map_fd));

        // Get pinned port_filter map
        const port_filter_fd = bpf_obj_get(PINNED_PORT_FILTER);
        if (port_filter_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(port_filter_fd)));
            std.log.err("[SharedXDP] Failed to get pinned port_filter at {s}: {s}", .{ PINNED_PORT_FILTER, @tagName(err) });
            return error.PinnedMapNotFound;
        }
        errdefer _ = posix.close(@intCast(port_filter_fd));

        // Get pinned XDP program
        const prog_fd = bpf_obj_get(PINNED_PROG);
        if (prog_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(prog_fd)));
            std.log.err("[SharedXDP] Failed to get pinned program at {s}: {s}", .{ PINNED_PROG, @tagName(err) });
            return error.PinnedProgramNotFound;
        }
        errdefer _ = posix.close(@intCast(prog_fd));

        // Add ports to the port filter map
        for (ports) |port| {
            var port_key: u16 = port;
            var action: u8 = 1; // 1 = redirect to AF_XDP
            const result = bpf_map_update(@intCast(port_filter_fd), &port_key, &action);
            if (result < 0) {
                const err = std.posix.errno(@as(i32, @intCast(result)));
                std.log.warn("[SharedXDP] Failed to add port {d} to filter: {s}", .{ port, @tagName(err) });
            } else {
                std.log.debug("[SharedXDP] Added port {d} to filter map", .{port});
            }
        }

        self.* = Self{
            .allocator = allocator,
            .ifindex = ifindex,
            .interface = interface,
            .ports = ports_copy,
            .xsks_map_fd = @intCast(xsks_map_fd),
            .prog_fd = @intCast(prog_fd),
            .link_fd = -1,
            .mode = mode,
            .attached = false,
            .port_filter_fd = @intCast(port_filter_fd),
        };

        std.log.info("[SharedXDP] ✅ Using pre-loaded XDP program from {s}", .{PINNED_PROG});
        std.log.info("[SharedXDP] Interface: {s} (ifindex: {d}), ports: {any}", .{ interface, ifindex, ports });

        return self;
    }

    /// Register an AF_XDP socket in the shared XSKMAP under the queue it bound to.
    ///
    /// The map key MUST equal the socket's bind queue_id. The XDP program redirects
    /// with key = ctx->rx_queue_index (bpf/xdp_filter.c:81-85), and the kernel only
    /// delivers a packet when xsks_map[rx_queue_index] holds a socket that is itself
    /// bound to that same queue. Keying by anything else (e.g. a registration-order
    /// counter) only works by luck when registration order happens to match bind
    /// order, and silently breaks delivery the moment it doesn't. This mirrors
    /// Firedancer, which uses a single if_queue_id for both the bind (fd_xsk.c:248)
    /// and the redirect-map key (fd_xdp_redirect_user.c:14) so they cannot diverge.
    pub fn registerSocket(self: *Self, queue_id: u32, socket_fd: i32) !void {
        var key: u32 = queue_id;
        var value: u32 = @intCast(socket_fd);

        const result = bpf_map_update(self.xsks_map_fd, &key, &value);
        if (result < 0) {
            const err = std.posix.errno(@as(i32, @intCast(result)));
            std.log.err("[SharedXDP] Failed to register socket (queue_id={d}): {s}", .{ queue_id, @tagName(err) });
            return error.SocketRegistrationFailed;
        }

        std.log.info("[SharedXDP] Socket registered: fd={d} → queue_id={d}", .{ socket_fd, queue_id });
    }

    /// Attach the shared XDP program to the network interface
    /// Should be called AFTER all sockets are registered
    pub fn attach(self: *Self) !void {
        if (self.attached) {
            return; // Already attached
        }

        const link_fd = bpf_link_create(self.prog_fd, self.ifindex, @intFromEnum(self.mode));
        if (link_fd < 0) {
            const err = std.posix.errno(@as(i32, @intCast(link_fd)));
            std.log.err("[SharedXDP] Failed to attach program to interface {d}: {s}", .{ self.ifindex, @tagName(err) });
            return error.AttachFailed;
        }

        self.link_fd = @intCast(link_fd);
        self.attached = true;

        std.log.info("[SharedXDP] ✅ XDP attached to {s} (ifindex: {d})", .{ self.interface, self.ifindex });
    }

    /// Detach the shared XDP program from the network interface
    pub fn detach(self: *Self) !void {
        if (!self.attached) {
            return;
        }

        _ = posix.close(self.link_fd);
        self.attached = false;
        self.link_fd = -1;

        std.log.info("[SharedXDP] Program detached from {s}", .{self.interface});
    }

    pub fn deinit(self: *Self) void {
        if (self.attached) {
            self.detach() catch {};
        }

        if (self.link_fd >= 0) {
            _ = posix.close(self.link_fd);
        }
        if (self.prog_fd >= 0) {
            _ = posix.close(self.prog_fd);
        }
        if (self.xsks_map_fd >= 0) {
            _ = posix.close(self.xsks_map_fd);
        }
        if (self.port_filter_fd >= 0) {
            _ = posix.close(self.port_filter_fd);
        }

        self.allocator.free(self.ports);
        self.allocator.destroy(self);
    }
};

/// Get network interface index from name
fn getInterfaceIndex(interface: []const u8) !u32 {
    const if_nametoindex = struct {
        extern "c" fn if_nametoindex(ifname: [*:0]const u8) c_uint;
    }.if_nametoindex;

    // Need null-terminated string
    var buf: [std.posix.IFNAMESIZE]u8 = undefined;
    if (interface.len >= buf.len) return error.InterfaceNameTooLong;
    @memcpy(buf[0..interface.len], interface);
    buf[interface.len] = 0;

    const idx = if_nametoindex(buf[0..interface.len :0]);
    if (idx == 0) {
        std.log.err("[SharedXDP] Interface '{s}' not found", .{interface});
        return error.InterfaceNotFound;
    }

    return idx;
}
