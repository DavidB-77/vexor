//! AF_XDP Kernel Bypass Networking
//! High-performance networking using Linux XDP (eXpress Data Path).
//!
//! Requirements:
//! - Linux kernel 4.18+ (5.3+ recommended)
//! - CAP_NET_RAW or root privileges
//! - NIC driver with XDP support (most modern NICs)
//!
//! Usage:
//! ```zig
//! const af_xdp = @import("af_xdp/root.zig");
//!
//! if (af_xdp.isAvailable()) {
//!     var xsk = try af_xdp.XdpSocket.init(allocator, .{
//!         .interface = "eth0",
//!         .queue_id = 0,
//!     });
//!     defer xsk.deinit();
//! }
//! ```

const std = @import("std");
const builtin = @import("builtin");

pub const socket = @import("socket.zig");
pub const xdp_program = @import("xdp_program.zig");

// Socket types
pub const XdpSocket = socket.XdpSocket;
pub const XdpConfig = socket.XdpConfig;
pub const XdpStatistics = socket.XdpStatistics;
pub const Packet = socket.Packet;
pub const XdpDesc = socket.XdpDesc;
pub const UmemRing = socket.UmemRing;
pub const DescRing = socket.DescRing;

// eBPF XDP Program
pub const XdpProgram = xdp_program.XdpProgram;

/// Check if AF_XDP is available on this system
pub fn isAvailable() bool {
    // Check if we're on Linux
    if (builtin.os.tag != .linux) {
        std.log.debug("debug: [AF_XDP] Not available: not Linux\n", .{});
        return false;
    }

    // Try to create an AF_XDP socket without triggering unexpectedErrno (EPERM)
    const rc = std.posix.system.socket(socket.AF_XDP, std.posix.SOCK.RAW, 0);
    switch (std.posix.errno(rc)) {
        .SUCCESS => {
            const fd: std.posix.fd_t = @intCast(rc);
            std.posix.close(fd);
        },
        .ACCES, .PERM => {
            std.log.debug("debug: [AF_XDP] Socket creation test failed - not available\n", .{});
            std.log.debug("info: [AF_XDP] Permission denied. Fix with: sudo setcap cap_net_raw,cap_net_admin+ep /path/to/vexor\n", .{});
            return false;
        },
        .AFNOSUPPORT => {
            std.log.debug("debug: [AF_XDP] Socket creation test failed - not available\n", .{});
            std.log.debug("info: [AF_XDP] Kernel doesn't support AF_XDP. Need kernel 4.18+\n", .{});
            return false;
        },
        .PROTONOSUPPORT => {
            std.log.debug("debug: [AF_XDP] Socket creation test failed - not available\n", .{});
            std.log.debug("info: [AF_XDP] Protocol not supported for AF_XDP\n", .{});
            return false;
        },
        else => |err| {
            std.log.debug("debug: [AF_XDP] Socket creation test failed - errno={d}\n", .{@intFromEnum(err)});
            return false;
        },
    }

    std.log.debug("debug: [AF_XDP] Available and working\n", .{});
    return true;
}

/// Get XDP capabilities for an interface
pub fn getInterfaceCaps(interface: []const u8) InterfaceCaps {
    _ = interface;
    return .{
        .xdp_supported = isAvailable(),
        .zero_copy = false, // Would need to check driver
        .hw_offload = false,
        .max_queues = 1,
    };
}

/// Interface capabilities
pub const InterfaceCaps = struct {
    xdp_supported: bool,
    zero_copy: bool,
    hw_offload: bool,
    max_queues: u32,
};

// ============================================================================
// Tests
// ============================================================================

test "imports compile" {
    _ = socket;
}

test "isAvailable: check" {
    // This will be false in non-Linux environments
    const available = isAvailable();
    _ = available;
}

test "getInterfaceCaps: basic" {
    const caps = getInterfaceCaps("eth0");
    _ = caps;
}
