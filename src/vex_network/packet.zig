//! Vexor Packet Types
//!
//! Core packet structures for network communication.
//! Optimized for zero-copy processing and cache efficiency.

const std = @import("std");
const core = @import("core");

/// Maximum packet size (Solana uses 1232 bytes for UDP-safe payloads, increased for PMTUD)
pub const MAX_PACKET_SIZE: usize = 1500;

/// Maximum number of packets in a batch (tuned for high-throughput shred reception)
pub const MAX_BATCH_SIZE: usize = 512;

/// Network packet with metadata
pub const Packet = extern struct {
    /// Raw packet data
    data: [MAX_PACKET_SIZE]u8 align(64), // Cache-line aligned

    /// Actual length of data
    len: u16,

    /// Source address (for routing responses)
    src_addr: SocketAddr,

    /// Packet flags
    flags: PacketFlags,

    /// Timestamp when received (nanoseconds since epoch)
    timestamp_ns: u64,

    pub const PacketFlags = packed struct {
        is_from_staked: bool = false,
        is_tracer: bool = false,
        discard: bool = false,
        forwarded: bool = false,
        repair: bool = false,
        _padding: u3 = 0,
    };

    pub fn init() Packet {
        return .{
            .data = undefined,
            .len = 0,
            .src_addr = SocketAddr.UNSPECIFIED,
            .flags = .{},
            .timestamp_ns = 0,
        };
    }

    pub fn payload(self: *const Packet) []const u8 {
        return self.data[0..self.len];
    }

    pub fn payloadMut(self: *Packet) []u8 {
        return self.data[0..self.len];
    }

    /// Reset packet for reuse
    pub fn reset(self: *Packet) void {
        self.len = 0;
        self.flags = .{};
        self.timestamp_ns = 0;
    }
};

/// Batch of packets for efficient processing
pub const PacketBatch = struct {
    packets: []Packet,
    len: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
        const packets = try allocator.alloc(Packet, capacity);
        return .{
            .packets = packets,
            .len = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.packets);
    }

    pub fn push(self: *Self) ?*Packet {
        if (self.len >= self.packets.len) return null;
        const pkt = &self.packets[self.len];
        self.len += 1;
        return pkt;
    }

    pub fn clear(self: *Self) void {
        self.len = 0;
    }

    pub fn slice(self: *const Self) []Packet {
        return self.packets[0..self.len];
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.len == 0;
    }

    pub fn isFull(self: *const Self) bool {
        return self.len >= self.packets.len;
    }
};

/// Socket address (IPv4 or IPv6)
pub const SocketAddr = extern struct {
    /// Address family and port combined
    family_port: u32,
    /// IPv4 address or first 4 bytes of IPv6
    addr: [16]u8,

    pub const UNSPECIFIED = SocketAddr{
        .family_port = 0,
        .addr = [_]u8{0} ** 16,
    };

    pub fn ipv4(addr: [4]u8, port_num: u16) SocketAddr {
        var result = SocketAddr{
            .family_port = (@as(u32, port_num) << 16) | 2, // AF_INET = 2
            .addr = [_]u8{0} ** 16,
        };
        @memcpy(result.addr[0..4], &addr);
        return result;
    }

    pub fn toStd(self: SocketAddr) std.net.Address {
        var ip: [4]u8 = undefined;
        @memcpy(&ip, self.addr[0..4]);
        const p = @as(u16, @truncate(self.family_port >> 16));
        return std.net.Address.initIp4(ip, p);
    }

    pub fn port(self: *const SocketAddr) u16 {
        return @truncate(self.family_port >> 16);
    }

    pub fn format(
        self: *const SocketAddr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        const family = self.family_port & 0xFFFF;
        if (family == 2) { // AF_INET
            try writer.print("{}.{}.{}.{}:{}", .{
                self.addr[0],
                self.addr[1],
                self.addr[2],
                self.addr[3],
                self.port(),
            });
        } else {
            try writer.writeAll("[unknown]");
        }
    }
};

/// Shred packet type (for TVU)
pub const ShredPacket = struct {
    packet: Packet,
    slot: core.Slot,
    shred_index: core.ShredIndex,
    is_data: bool,
    is_last_in_slot: bool,
};

/// Transaction packet type (for TPU)
pub const TransactionPacket = struct {
    packet: Packet,
    signature: core.Signature,
    priority_fee: u64,
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "packet init" {
    const pkt = Packet.init();
    try std.testing.expectEqual(@as(u16, 0), pkt.len);
    try std.testing.expect(!pkt.flags.is_from_staked);
}

test "packet batch" {
    var batch = try PacketBatch.init(std.testing.allocator, 64);
    defer batch.deinit();

    try std.testing.expect(batch.isEmpty());

    const pkt = batch.push();
    try std.testing.expect(pkt != null);
    try std.testing.expectEqual(@as(usize, 1), batch.len);

    batch.clear();
    try std.testing.expect(batch.isEmpty());
}

test "socket addr ipv4" {
    const addr = SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 8001);
    try std.testing.expectEqual(@as(u16, 8001), addr.port());
}
