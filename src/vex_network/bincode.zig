//! Bincode Serialization for Solana Protocol Compatibility
//!
//! Implements the bincode binary serialization format used by Solana for
//! all inter-node communication (gossip, repair, turbine, etc.)
//!
//! Reference: https://github.com/bincode-org/bincode
//! Solana spec: https://github.com/eigerco/solana-spec/blob/main/gossip-protocol-spec.md

const std = @import("std");
const core = @import("core");

/// Bincode serialization errors
pub const BincodeError = error{
    BufferTooSmall,
    InvalidData,
    InvalidEnumTag,
    VarIntOverflow,
    OutOfMemory,
};

/// Bincode serializer - writes data in bincode format
pub const Serializer = struct {
    buffer: []u8,
    pos: usize,

    const Self = @This();

    pub fn init(buffer: []u8) Self {
        return .{
            .buffer = buffer,
            .pos = 0,
        };
    }

    /// Get the serialized bytes
    pub fn getWritten(self: *const Self) []const u8 {
        return self.buffer[0..self.pos];
    }

    /// Get remaining buffer capacity
    pub fn remaining(self: *const Self) usize {
        return self.buffer.len - self.pos;
    }

    /// Write a u8
    pub fn writeU8(self: *Self, value: u8) BincodeError!void {
        if (self.remaining() < 1) return BincodeError.BufferTooSmall;
        self.buffer[self.pos] = value;
        self.pos += 1;
    }

    /// Write a u16 (little-endian)
    pub fn writeU16(self: *Self, value: u16) BincodeError!void {
        if (self.remaining() < 2) return BincodeError.BufferTooSmall;
        std.mem.writeInt(u16, self.buffer[self.pos..][0..2], value, .little);
        self.pos += 2;
    }

    /// Write a u32 (little-endian)
    pub fn writeU32(self: *Self, value: u32) BincodeError!void {
        if (self.remaining() < 4) return BincodeError.BufferTooSmall;
        std.mem.writeInt(u32, self.buffer[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    /// Write a u64 (little-endian)
    pub fn writeU64(self: *Self, value: u64) BincodeError!void {
        if (self.remaining() < 8) return BincodeError.BufferTooSmall;
        std.mem.writeInt(u64, self.buffer[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    /// Write a i64 (little-endian)
    pub fn writeI64(self: *Self, value: i64) BincodeError!void {
        if (self.remaining() < 8) return BincodeError.BufferTooSmall;
        std.mem.writeInt(i64, self.buffer[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    /// Write raw bytes
    pub fn writeBytes(self: *Self, bytes: []const u8) BincodeError!void {
        if (self.remaining() < bytes.len) return BincodeError.BufferTooSmall;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    /// Write a fixed-size array
    pub fn writeFixedArray(self: *Self, comptime N: usize, array: *const [N]u8) BincodeError!void {
        try self.writeBytes(array);
    }

    /// Write a Pubkey (32 bytes)
    pub fn writePubkey(self: *Self, pubkey: *const core.Pubkey) BincodeError!void {
        try self.writeFixedArray(32, &pubkey.data);
    }

    /// Write a Signature (64 bytes)
    pub fn writeSignature(self: *Self, sig: *const core.Signature) BincodeError!void {
        try self.writeBytes(&sig.data);
    }

    /// Write a Hash (32 bytes)
    pub fn writeHash(self: *Self, hash: *const core.Hash) BincodeError!void {
        try self.writeBytes(&hash.data);
    }

    /// Write a dynamic-length byte array with u64 length prefix
    pub fn writeVec(self: *Self, bytes: []const u8) BincodeError!void {
        try self.writeU64(@intCast(bytes.len));
        try self.writeBytes(bytes);
    }

    /// Write an enum variant tag (u32)
    pub fn writeEnumTag(self: *Self, tag: u32) BincodeError!void {
        try self.writeU32(tag);
    }

    /// Write an Option<T> - bool discriminant + optional value
    pub fn writeOptionBool(self: *Self, has_value: bool) BincodeError!void {
        try self.writeU8(if (has_value) 1 else 0);
    }
};

/// Bincode deserializer - reads data in bincode format
pub const Deserializer = struct {
    data: []const u8,
    pos: usize,

    const Self = @This();

    pub fn init(data: []const u8) Self {
        return .{
            .data = data,
            .pos = 0,
        };
    }

    /// Get remaining bytes
    pub fn remaining(self: *const Self) usize {
        return self.data.len - self.pos;
    }

    /// Check if there are enough bytes remaining
    fn ensureRemaining(self: *const Self, n: usize) BincodeError!void {
        if (self.remaining() < n) return BincodeError.InvalidData;
    }

    /// Read a u8
    pub fn readU8(self: *Self) BincodeError!u8 {
        try self.ensureRemaining(1);
        const value = self.data[self.pos];
        self.pos += 1;
        return value;
    }

    /// Read a u16 (little-endian)
    pub fn readU16(self: *Self) BincodeError!u16 {
        try self.ensureRemaining(2);
        const value = std.mem.readInt(u16, self.data[self.pos..][0..2], .little);
        self.pos += 2;
        return value;
    }

    /// Read a u32 (little-endian)
    pub fn readU32(self: *Self) BincodeError!u32 {
        try self.ensureRemaining(4);
        const value = std.mem.readInt(u32, self.data[self.pos..][0..4], .little);
        self.pos += 4;
        return value;
    }

    /// Read a u64 (little-endian)
    pub fn readU64(self: *Self) BincodeError!u64 {
        try self.ensureRemaining(8);
        const value = std.mem.readInt(u64, self.data[self.pos..][0..8], .little);
        self.pos += 8;
        return value;
    }

    /// Read a i64 (little-endian)
    pub fn readI64(self: *Self) BincodeError!i64 {
        try self.ensureRemaining(8);
        const value = std.mem.readInt(i64, self.data[self.pos..][0..8], .little);
        self.pos += 8;
        return value;
    }

    /// Read raw bytes (copies to provided buffer)
    pub fn readBytes(self: *Self, out: []u8) BincodeError!void {
        try self.ensureRemaining(out.len);
        @memcpy(out, self.data[self.pos..][0..out.len]);
        self.pos += out.len;
    }

    /// Read and return a slice (no copy, borrows from source)
    pub fn readSlice(self: *Self, len: usize) BincodeError![]const u8 {
        try self.ensureRemaining(len);
        const slice = self.data[self.pos..][0..len];
        self.pos += len;
        return slice;
    }

    /// Read a fixed-size array
    pub fn readFixedArray(self: *Self, comptime N: usize) BincodeError![N]u8 {
        try self.ensureRemaining(N);
        var result: [N]u8 = undefined;
        @memcpy(&result, self.data[self.pos..][0..N]);
        self.pos += N;
        return result;
    }

    /// Read a Pubkey (32 bytes)
    pub fn readPubkey(self: *Self) BincodeError!core.Pubkey {
        return .{ .data = try self.readFixedArray(32) };
    }

    /// Read a Signature (64 bytes)
    pub fn readSignature(self: *Self) BincodeError!core.Signature {
        return .{ .data = try self.readFixedArray(64) };
    }

    /// Read a Hash (32 bytes)
    pub fn readHash(self: *Self) BincodeError!core.Hash {
        return .{ .data = try self.readFixedArray(32) };
    }

    /// Read an enum variant tag (u32)
    pub fn readEnumTag(self: *Self) BincodeError!u32 {
        return try self.readU32();
    }

    /// Read Option discriminant (bool as u8)
    pub fn readOptionBool(self: *Self) BincodeError!bool {
        const b = try self.readU8();
        return b != 0;
    }

    /// Read dynamic length (u64) and return the length
    pub fn readVecLength(self: *Self) BincodeError!u64 {
        return try self.readU64();
    }

    /// Skip N bytes
    pub fn skip(self: *Self, n: usize) BincodeError!void {
        try self.ensureRemaining(n);
        self.pos += n;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// SOLANA GOSSIP PROTOCOL TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Gossip protocol message types (Protocol enum)
pub const ProtocolType = enum(u32) {
    PullRequest = 0,
    PullResponse = 1,
    PushMessage = 2,
    PruneMessage = 3,
    PingMessage = 4,
    PongMessage = 5,
};

/// CRDS data types (CrdsData enum)
pub const CrdsDataType = enum(u32) {
    LegacyContactInfo = 0,
    Vote = 1,
    LowestSlot = 2,
    LegacySnapshotHashes = 3,
    AccountsHashes = 4,
    EpochSlots = 5,
    LegacyVersion = 6,
    Version = 7,
    NodeInstance = 8,
    DuplicateShred = 9,
    SnapshotHashes = 10,
    ContactInfo = 11,
    RestartLastVotedForkSlots = 12,
    RestartHeaviestFork = 13,
};

/// Ping message format
pub const Ping = struct {
    from: core.Pubkey,
    token: [32]u8,
    signature: core.Signature,

    /// Serialize to bincode format
    /// Wire format: [enum_tag(4)] + [from(32)] + [token(32)] + [signature(64)] = 132 bytes
    pub fn serialize(self: *const Ping, buffer: []u8) BincodeError!usize {
        var s = Serializer.init(buffer);
        try s.writeEnumTag(@intFromEnum(ProtocolType.PingMessage));
        try s.writePubkey(&self.from);
        try s.writeFixedArray(32, &self.token);
        try s.writeSignature(&self.signature);
        return s.pos;
    }

    /// Deserialize from bincode format (assumes enum tag already read)
    pub fn deserialize(data: []const u8) BincodeError!Ping {
        var d = Deserializer.init(data);
        return .{
            .from = try d.readPubkey(),
            .token = try d.readFixedArray(32),
            .signature = try d.readSignature(),
        };
    }

    /// Get the bytes that should be signed (from + token)
    pub fn getSignableData(self: *const Ping) [64]u8 {
        var data: [64]u8 = undefined;
        @memcpy(data[0..32], &self.from.data);
        @memcpy(data[32..64], &self.token);
        return data;
    }
};

/// Pong message format
pub const Pong = struct {
    from: core.Pubkey,
    hash: core.Hash, // SHA256("SOLANA_PING_PONG" + ping_token)
    signature: core.Signature,

    /// The prefix used for hashing in pong responses
    pub const PING_PONG_PREFIX = "SOLANA_PING_PONG";

    /// Serialize to bincode format
    /// Wire format: [enum_tag(4)] + [from(32)] + [hash(32)] + [signature(64)] = 132 bytes
    pub fn serialize(self: *const Pong, buffer: []u8) BincodeError!usize {
        var s = Serializer.init(buffer);
        try s.writeEnumTag(@intFromEnum(ProtocolType.PongMessage));
        try s.writePubkey(&self.from);
        try s.writeHash(&self.hash);
        try s.writeSignature(&self.signature);
        return s.pos;
    }

    /// Deserialize from bincode format (assumes enum tag already read)
    pub fn deserialize(data: []const u8) BincodeError!Pong {
        var d = Deserializer.init(data);
        return .{
            .from = try d.readPubkey(),
            .hash = try d.readHash(),
            .signature = try d.readSignature(),
        };
    }

    /// Create the hash for a pong response
    pub fn createHash(ping_token: *const [32]u8) core.Hash {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(PING_PONG_PREFIX);
        hasher.update(ping_token);
        return .{ .data = hasher.finalResult() };
    }

    /// Get the bytes that should be signed (from + hash)
    pub fn getSignableData(self: *const Pong) [64]u8 {
        var data: [64]u8 = undefined;
        @memcpy(data[0..32], &self.from.data);
        @memcpy(data[32..64], &self.hash.data);
        return data;
    }
};

/// CRDS Value - wraps any gossip data with signature
pub const CrdsValue = struct {
    signature: core.Signature,
    data_type: CrdsDataType,
    data: []const u8, // Raw serialized CrdsData payload

    /// Serialize just the header (signature + enum tag)
    pub fn serializeHeader(self: *const CrdsValue, buffer: []u8) BincodeError!usize {
        var s = Serializer.init(buffer);
        try s.writeSignature(&self.signature);
        try s.writeEnumTag(@intFromEnum(self.data_type));
        return s.pos;
    }
};

/// Bloom filter for CRDS pull requests
pub const Bloom = struct {
    keys: []const u64,
    bits: []const u64,
    num_bits_set: u64,

    /// Serialize to bincode format
    /// Reference: Firedancer fd_gossip_msg_ser.c:186-201 and fd_gossip_msg_parse.c:92-127
    /// Format: [keys_len(8)] + [keys...] + bitvec + [num_bits_set(8)]
    /// Bitvec format: [has_bits(1)] + if has_bits: [bits_cap(8)] + [bits...] + [bits_cnt(8)]
    pub fn serialize(self: *const Bloom, buffer: []u8) BincodeError!usize {
        var s = Serializer.init(buffer);

        // Keys array with length prefix
        try s.writeU64(@intCast(self.keys.len));
        for (self.keys) |key| {
            try s.writeU64(key);
        }

        // Bitvec format from Firedancer:
        // [has_bits(1)] + [bits_cap(8)] + [bits data] + [bits_cnt(8)]
        if (self.bits.len > 0) {
            try s.writeU8(1); // has_bits = true
            try s.writeU64(@intCast(self.bits.len)); // bits_cap (number of u64 elements)
            for (self.bits) |word| {
                try s.writeU64(word);
            }
            // bits_cnt = total number of bits in the bitvec (bits_cap * 64)
            try s.writeU64(@intCast(self.bits.len * 64));
        } else {
            try s.writeU8(0); // has_bits = false, NO length written!
            // Even when no bits, we still need bits_cnt
            try s.writeU64(0);
        }

        // num_bits_set = count of bits set in the bloom filter
        try s.writeU64(self.num_bits_set);
        return s.pos;
    }

    /// Create a minimal bloom filter (for initial pull requests)
    /// NOTE: Firedancer requires bloom_len > 0 (fd_gossip_msg_parse.c:660)
    /// So we create a minimal filter with at least 1 bit to pass validation
    pub fn empty() Bloom {
        // Keys from Firedancer's test fixture (test_gossip_ser.c:108)
        // Uses 3 random hash keys as is standard for bloom filters
        return .{
            .keys = &[_]u64{ 0x123456789ABCDEF0, 0xFEDCBA9876543210, 0xDEADBEEFCAFEBABE },
            .bits = &[_]u64{0}, // Single zero element (minimal valid bitvec)
            .num_bits_set = 0, // No bits set = accept all
        };
    }
};

/// CRDS Filter for pull requests
pub const CrdsFilter = struct {
    filter: Bloom,
    mask: u64,
    mask_bits: u32,

    /// Serialize to bincode format
    pub fn serialize(self: *const CrdsFilter, buffer: []u8) BincodeError!usize {
        var s = Serializer.init(buffer);
        const bloom_len = try self.filter.serialize(buffer[s.pos..]);
        s.pos += bloom_len;
        try s.writeU64(self.mask);
        try s.writeU32(self.mask_bits);
        return s.pos;
    }

    /// Create a simple filter that accepts everything (for initial pull)
    pub fn acceptAll() CrdsFilter {
        return .{
            .filter = Bloom.empty(),
            .mask = ~@as(u64, 0), // All bits set
            .mask_bits = 0,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// LEGACY CONTACT INFO (Still used in testnet)
// ═══════════════════════════════════════════════════════════════════════════════

/// LegacyContactInfo - the older contact info format still used by many nodes
pub const LegacyContactInfo = struct {
    /// Node's identity pubkey
    pubkey: core.Pubkey,
    /// Gossip socket address
    gossip: SocketAddr,
    /// TVU (turbine) socket address
    tvu: SocketAddr,
    /// TVU forwards socket address
    tvu_forwards: SocketAddr,
    /// Repair socket address
    repair: SocketAddr,
    /// TPU socket address
    tpu: SocketAddr,
    /// TPU forwards socket address
    tpu_forwards: SocketAddr,
    /// TPU vote socket address
    tpu_vote: SocketAddr,
    /// RPC socket address
    rpc: SocketAddr,
    /// RPC pubsub socket address
    rpc_pubsub: SocketAddr,
    /// Serve repair socket address
    serve_repair: SocketAddr,
    /// Wallclock timestamp (ms)
    wallclock: u64,
    /// Shred version
    shred_version: u16,

    /// Serialize to bincode format
    pub fn serialize(self: *const LegacyContactInfo, buffer: []u8) BincodeError!usize {
        var s = Serializer.init(buffer);

        try s.writePubkey(&self.pubkey);
        try self.gossip.serialize(&s);
        try self.tvu.serialize(&s);
        try self.tvu_forwards.serialize(&s);
        try self.repair.serialize(&s);
        try self.tpu.serialize(&s);
        try self.tpu_forwards.serialize(&s);
        try self.tpu_vote.serialize(&s);
        try self.rpc.serialize(&s);
        try self.rpc_pubsub.serialize(&s);
        try self.serve_repair.serialize(&s);
        try s.writeU64(self.wallclock);
        try s.writeU16(self.shred_version);

        return s.pos;
    }

    /// Create LegacyContactInfo for our node
    pub fn initSelf(
        identity: core.Pubkey,
        ip: [4]u8,
        gossip_port: u16,
        tvu_port: u16,
        repair_port: u16,
        tpu_port: u16,
        rpc_port: u16,
        shred_version: u16,
    ) LegacyContactInfo {
        return .{
            .pubkey = identity,
            .gossip = SocketAddr.initIpv4(ip, gossip_port),
            .tvu = SocketAddr.initIpv4(ip, tvu_port),
            .tvu_forwards = SocketAddr.initIpv4(ip, tvu_port + 1),
            .repair = SocketAddr.initIpv4(ip, repair_port),
            .tpu = SocketAddr.initIpv4(ip, tpu_port),
            .tpu_forwards = SocketAddr.initIpv4(ip, tpu_port + 1),
            .tpu_vote = SocketAddr.initIpv4(ip, tpu_port + 2),
            .rpc = SocketAddr.initIpv4(ip, rpc_port),
            .rpc_pubsub = SocketAddr.initIpv4(ip, rpc_port + 1),
            .serve_repair = SocketAddr.initIpv4(ip, repair_port + 1),
            .wallclock = @intCast(std.time.milliTimestamp()),
            .shred_version = shred_version,
        };
    }
};

/// Socket address in bincode format
pub const SocketAddr = struct {
    /// Address family enum: 0 = IPv4, 1 = IPv6
    family: u32,
    /// IPv4 address (4 bytes) or IPv6 (16 bytes)
    ip: [16]u8,
    /// Port
    port: u16,

    pub fn initIpv4(ip: [4]u8, port: u16) SocketAddr {
        var addr = SocketAddr{
            .family = 0, // IPv4
            .ip = [_]u8{0} ** 16,
            .port = port,
        };
        @memcpy(addr.ip[0..4], &ip);
        return addr;
    }

    pub fn initUnspecified() SocketAddr {
        return .{
            .family = 0,
            .ip = [_]u8{0} ** 16,
            .port = 0,
        };
    }

    /// Serialize in bincode format
    /// IPv4: [enum_tag(4)] + [ip(4)] + [port(2)] = 10 bytes
    /// IPv6: [enum_tag(4)] + [ip(16)] + [port(2)] = 22 bytes
    pub fn serialize(self: *const SocketAddr, s: *Serializer) BincodeError!void {
        try s.writeU32(self.family);
        if (self.family == 0) {
            // IPv4
            try s.writeBytes(self.ip[0..4]);
        } else {
            // IPv6
            try s.writeBytes(self.ip[0..16]);
        }
        try s.writeU16(self.port);
    }

    pub fn deserialize(d: *Deserializer) BincodeError!SocketAddr {
        var addr = SocketAddr{
            .family = try d.readU32(),
            .ip = [_]u8{0} ** 16,
            .port = 0,
        };
        if (addr.family == 0) {
            // IPv4
            try d.readBytes(addr.ip[0..4]);
        } else {
            // IPv6
            try d.readBytes(addr.ip[0..16]);
        }
        addr.port = try d.readU16();
        return addr;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// MODERN CONTACT INFO (Required by Firedancer - tag=11)
// ═══════════════════════════════════════════════════════════════════════════════

/// Socket tags for modern ContactInfo (from Firedancer)
pub const SocketTag = enum(u8) {
    gossip = 0,
    repair = 1,
    rpc = 2,
    rpc_pubsub = 3,
    serve_repair = 4,
    tpu = 5,
    tpu_forwards = 6,
    tpu_forwards_quic = 7,
    tpu_quic = 8,
    tpu_vote = 9,
    tvu = 10,
    tvu_quic = 11,
};

/// Socket entry for sorted socket list (internal use during serialization)
const SocketEntry = struct {
    tag: u8,
    port: u16,
    ip: [4]u8,
};

/// Modern ContactInfo structure (required by Firedancer for PullRequests)
/// Based on Firedancer fd_gossip_msg_ser.c:217-279
pub const ContactInfo = struct {
    /// Node's identity pubkey
    pubkey: core.Pubkey,
    /// Wallclock timestamp (milliseconds)
    wallclock_ms: u64,
    /// Instance creation wallclock (microseconds since epoch)
    instance_creation_wallclock_us: u64,
    /// Shred version
    shred_version: u16,
    /// Version info (Firedancer format)
    version_major: u16,
    version_minor: u16,
    version_patch: u16,
    version_commit: u32, // NOT optional in Firedancer!
    feature_set: u32,
    version_client: u16, // 0 = unknown, 1 = solana, 2 = jito, 3 = firedancer, 4 = agave
    /// Sockets - stored as IP address + port pairs
    /// Tag values: 0=gossip, 1=repair, 2=rpc, 3=rpc_pubsub, 4=serve_repair, 5=tpu,
    /// 6=tpu_forwards, 7=tpu_forwards_quic, 8=tpu_quic, 9=tpu_vote, 10=tvu, 11=tvu_quic
    sockets: [12]struct { ip: [4]u8, port: u16, active: bool },
    sockets_count: u8,

    /// Write a varint encoded u64
    fn writeVarint(s: *Serializer, value: u64) BincodeError!void {
        var v = value;
        while (v >= 0x80) {
            try s.writeU8(@intCast((v & 0x7F) | 0x80));
            v >>= 7;
        }
        try s.writeU8(@intCast(v));
    }

    /// Write compact_u16 format (Solana-specific encoding for ContactInfo counts)
    /// Reference: Firedancer fd_compact_u16.h:92-103
    /// Format:
    ///   [0x00, 0x80):     1 byte  - value directly
    ///   [0x80, 0x4000):   2 bytes - first byte has MSB set
    ///   [0x4000, 0x10000): 3 bytes - first two bytes have MSB set
    fn writeCompactU16(s: *Serializer, value: u16) BincodeError!void {
        const v: usize = value;
        if (v < 0x80) {
            // 1-byte format
            try s.writeU8(@intCast(v));
        } else if (v < 0x4000) {
            // 2-byte format
            try s.writeU8(@intCast((v & 0x7F) | 0x80));
            try s.writeU8(@intCast(v >> 7));
        } else {
            // 3-byte format
            try s.writeU8(@intCast((v & 0x7F) | 0x80));
            try s.writeU8(@intCast(((v >> 7) & 0x7F) | 0x80));
            try s.writeU8(@intCast(v >> 14));
        }
    }

    /// Serialize to bincode format (modern ContactInfo - tag 11)
    /// Based on Firedancer fd_gossip_msg_ser.c:217-279
    pub fn serialize(self: *const ContactInfo, buffer: []u8) BincodeError!usize {
        var s = Serializer.init(buffer);

        // Pubkey
        try s.writePubkey(&self.pubkey);

        // Wallclock as varint (milliseconds)
        try writeVarint(&s, self.wallclock_ms);

        // Instance creation wallclock (8 bytes, microseconds)
        try s.writeU64(self.instance_creation_wallclock_us);

        // Shred version
        try s.writeU16(self.shred_version);

        // Version info (Firedancer encode_version format)
        // major, minor, patch as varints; commit and feature_set as u32; client as varint
        try writeVarint(&s, self.version_major);
        try writeVarint(&s, self.version_minor);
        try writeVarint(&s, self.version_patch);
        try s.writeU32(self.version_commit);
        try s.writeU32(self.feature_set);
        try writeVarint(&s, self.version_client);

        // Collect and sort active sockets by port
        var entries: [12]SocketEntry = undefined;
        var active_count: u8 = 0;
        for (0..12) |i| {
            if (self.sockets[i].active and self.sockets[i].port > 0) {
                entries[active_count] = .{
                    .tag = @intCast(i),
                    .port = self.sockets[i].port,
                    .ip = self.sockets[i].ip,
                };
                active_count += 1;
            }
        }

        // Simple bubble sort by port (small array, OK for this use)
        for (0..active_count) |i| {
            for (i + 1..active_count) |j| {
                if (entries[j].port < entries[i].port) {
                    const tmp = entries[i];
                    entries[i] = entries[j];
                    entries[j] = tmp;
                }
            }
        }

        // Count unique IP addresses (we typically have just one)
        // For simplicity, we use one IP
        // NOTE: Use compact_u16 per Firedancer fd_gossip_msg_parse.c:465
        const addrs_cnt: u16 = if (active_count > 0) 1 else 0;
        try writeCompactU16(&s, addrs_cnt);

        // Write the address (IPv4 discriminant + 4 bytes as u32)
        if (addrs_cnt > 0) {
            try s.writeU32(0); // IPv4 discriminant
            // Write IP as little-endian u32
            const ip = entries[0].ip;
            const ip_u32 = @as(u32, ip[0]) | (@as(u32, ip[1]) << 8) | (@as(u32, ip[2]) << 16) | (@as(u32, ip[3]) << 24);
            try s.writeU32(ip_u32);
        }

        // Write socket entries: count + [tag, addr_index, port_offset as compact_u16]
        // Port offsets are relative: first is absolute, rest are deltas
        // NOTE: Use compact_u16 per Firedancer fd_gossip_msg_parse.c:499
        try writeCompactU16(&s, @as(u16, active_count));
        var prev_port: u16 = 0;
        for (0..active_count) |i| {
            const entry = entries[i];
            try s.writeU8(entry.tag);
            try s.writeU8(0); // addr_index (always 0 since we have one IP)

            // Port offset: first is absolute, rest are delta from previous
            // NOTE: Use compact_u16 per Firedancer fd_gossip_msg_parse.c:512
            const port_offset: u16 = if (i == 0) entry.port else entry.port - prev_port;
            try writeCompactU16(&s, port_offset);
            prev_port = entry.port;
        }

        // Extensions count = 0 (compact_u16 per Firedancer fd_gossip_msg_parse.c:532)
        try writeCompactU16(&s, 0);

        return s.pos;
    }

    /// Create modern ContactInfo for our node
    pub fn initSelf(
        identity: core.Pubkey,
        ip: [4]u8,
        gossip_port: u16,
        tvu_port: u16,
        repair_port: u16,
        tpu_port: u16,
        rpc_port: u16,
        shred_version: u16,
    ) ContactInfo {
        // Get current time
        const now_ms: u64 = @intCast(std.time.milliTimestamp());
        const now_us: u64 = @intCast(@divFloor(std.time.nanoTimestamp(), 1000));

        var ci = ContactInfo{
            .pubkey = identity,
            .wallclock_ms = now_ms,
            .instance_creation_wallclock_us = now_us,
            .shred_version = shred_version,
            // Honest client identity (2026-07-10, core/version.zig): we used to
            // advertise the DEFAULTS (2.2.0, commit=0, client=0) — and client 0
            // is SolanaLabs in Agave's registry (version/src/client_ids.rs), so
            // explorers mislabeled Vexor as "Solana Labs 2.2.0". Now: the real
            // major/minor/patch from VEXOR_VERSION (a pre-release letter suffix,
            // if any, is a display-only concept — the wire block only ever carries
            // the three numeric fields), commit = git-hash prefix (set once at
            // boot, main.zig), client = 86 ('V', unregistered ⇒ renders
            // Unknown(86) — honest). Wire size is UNCHANGED: major/minor/patch and
            // 86 are all single-byte varints exactly like the old 2/2/0 and 0;
            // commit stays a fixed u32.
            .version_major = core.version.VEXOR_VERSION.major,
            .version_minor = core.version.VEXOR_VERSION.minor,
            .version_patch = core.version.VEXOR_VERSION.patch,
            .version_commit = core.version.commit_u32,
            .feature_set = 0, // unchanged — never invent a feature_set value
            .version_client = core.version.CLIENT_ID,
            .sockets = undefined,
            .sockets_count = 12,
        };

        // Initialize socket types with tags matching Agave v3.1.10 contact_info.rs:
        // Tag 0  = SOCKET_TAG_GOSSIP
        // Tag 1  = SOCKET_TAG_SERVE_REPAIR_QUIC  (NOT repair!)
        // Tag 2  = SOCKET_TAG_RPC
        // Tag 3  = SOCKET_TAG_RPC_PUBSUB
        // Tag 4  = SOCKET_TAG_SERVE_REPAIR  (UDP)
        // Tag 5  = SOCKET_TAG_TPU
        // Tag 6  = SOCKET_TAG_TPU_FORWARDS
        // Tag 7  = SOCKET_TAG_TPU_FORWARDS_QUIC
        // Tag 8  = SOCKET_TAG_TPU_QUIC
        // Tag 9  = SOCKET_TAG_TPU_VOTE
        // Tag 10 = SOCKET_TAG_TVU
        // Tag 11 = SOCKET_TAG_TVU_QUIC
        ci.sockets[0] = .{ .ip = ip, .port = gossip_port, .active = true }; // gossip
        ci.sockets[1] = .{ .ip = ip, .port = repair_port + 2, .active = true }; // serve_repair_quic (QUIC_PORT_OFFSET=6 from serve_repair)
        ci.sockets[2] = .{ .ip = ip, .port = rpc_port, .active = true }; // rpc
        ci.sockets[3] = .{ .ip = ip, .port = rpc_port + 1, .active = true }; // rpc_pubsub
        ci.sockets[4] = .{ .ip = ip, .port = repair_port + 1, .active = true }; // serve_repair (UDP)
        ci.sockets[5] = .{ .ip = ip, .port = tpu_port, .active = true }; // tpu
        ci.sockets[6] = .{ .ip = ip, .port = tpu_port + 1, .active = true }; // tpu_forwards
        ci.sockets[7] = .{ .ip = ip, .port = tpu_port + 7, .active = true }; // tpu_forwards_quic
        ci.sockets[8] = .{ .ip = ip, .port = tpu_port + 6, .active = true }; // tpu_quic
        ci.sockets[9] = .{ .ip = ip, .port = tpu_port + 4, .active = true }; // tpu_vote
        ci.sockets[10] = .{ .ip = ip, .port = tvu_port, .active = true }; // tvu
        ci.sockets[11] = .{ .ip = ip, .port = tvu_port + 6, .active = true }; // tvu_quic

        return ci;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// MESSAGE BUILDERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a properly formatted gossip Ping message
/// If signature is null, an empty signature is used (message will be rejected by peers)
pub fn buildPingMessage(
    buffer: []u8,
    from: core.Pubkey,
    token: [32]u8,
    signature: ?core.Signature,
) BincodeError!usize {
    const ping = Ping{
        .from = from,
        .token = token,
        .signature = signature orelse core.Signature{ .data = [_]u8{0} ** 64 },
    };

    return try ping.serialize(buffer);
}

/// Get the signable data for a Ping message (for external signing)
/// NOTE: According to Firedancer (fd_gossip.c:779), PING signs ONLY the token (32 bytes)
pub fn getPingSignableData(from: core.Pubkey, token: [32]u8) [32]u8 {
    _ = from; // from is NOT part of the signed data for PING
    return token;
}

/// Build a properly formatted gossip Pong message
/// If signature is null, an empty signature is used (message will be rejected by peers)
pub fn buildPongMessage(
    buffer: []u8,
    from: core.Pubkey,
    ping_token: *const [32]u8,
    signature: ?core.Signature,
) BincodeError!usize {
    const pong = Pong{
        .from = from,
        .hash = Pong.createHash(ping_token),
        .signature = signature orelse core.Signature{ .data = [_]u8{0} ** 64 },
    };

    return try pong.serialize(buffer);
}

/// Get the signable data for a Pong message (for external signing)
/// NOTE: According to Firedancer (fd_keyguard.h:55), PONG uses SHA256_ED25519 mode:
/// 1. Build pre_image = "SOLANA_PING_PONG" + ping_token (48 bytes)
/// 2. Compute hash = SHA256(pre_image) (32 bytes)
/// 3. Sign the 32-byte hash with Ed25519
/// So we return the SHA256 hash of the pre_image for signing.
pub fn getPongSignableData(from: core.Pubkey, ping_token: *const [32]u8) [32]u8 {
    _ = from; // from is NOT part of the signed data for PONG

    // Build pre_image = "SOLANA_PING_PONG" + ping_token
    var pre_image: [48]u8 = undefined;
    @memcpy(pre_image[0..16], Pong.PING_PONG_PREFIX);
    @memcpy(pre_image[16..48], ping_token);

    // SHA256 the pre_image - this is what gets signed
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&pre_image);
    return hasher.finalResult();
}

/// Build a PullRequest message with LegacyContactInfo
/// If signature is null, an empty signature is used (message will be rejected by peers)
pub fn buildPullRequestWithLegacyContactInfo(
    buffer: []u8,
    contact_info: *const LegacyContactInfo,
    signature: ?core.Signature,
) BincodeError!usize {
    var s = Serializer.init(buffer);

    // Protocol::PullRequest enum tag
    try s.writeEnumTag(@intFromEnum(ProtocolType.PullRequest));

    // CrdsFilter (accept all for now)
    const filter = CrdsFilter.acceptAll();
    const filter_len = try filter.serialize(buffer[s.pos..]);
    s.pos += filter_len;

    // CrdsValue with LegacyContactInfo
    // First, serialize the contact info to get the data
    var contact_data: [512]u8 = undefined;
    const contact_len = try contact_info.serialize(&contact_data);

    // Write CrdsValue with signature
    try s.writeSignature(&(signature orelse core.Signature{ .data = [_]u8{0} ** 64 }));
    try s.writeEnumTag(@intFromEnum(CrdsDataType.LegacyContactInfo));
    try s.writeBytes(contact_data[0..contact_len]);

    return s.pos;
}

/// Get the signable data for a CrdsValue containing LegacyContactInfo (for external signing)
/// Returns the data that should be signed: CrdsData enum tag + serialized contact info
pub fn getLegacyContactInfoSignableData(contact_info: *const LegacyContactInfo, out: []u8) BincodeError!usize {
    // Signable data: enum tag (4 bytes) + serialized contact info
    std.mem.writeInt(u32, out[0..4], @intFromEnum(CrdsDataType.LegacyContactInfo), .little);
    const contact_len = try contact_info.serialize(out[4..]);
    return 4 + contact_len;
}

/// Build a PullRequest message with modern ContactInfo (required by Firedancer)
/// If signature is null, an empty signature is used (message will be rejected by peers)
pub fn buildPullRequestWithContactInfo(
    buffer: []u8,
    contact_info: *const ContactInfo,
    signature: ?core.Signature,
) BincodeError!usize {
    var s = Serializer.init(buffer);

    // Protocol::PullRequest enum tag
    try s.writeEnumTag(@intFromEnum(ProtocolType.PullRequest));

    // CrdsFilter (accept all for now)
    const filter = CrdsFilter.acceptAll();
    const filter_len = try filter.serialize(buffer[s.pos..]);
    s.pos += filter_len;

    // CrdsValue with ContactInfo
    // First, serialize the contact info to get the data
    var contact_data: [512]u8 = undefined;
    const contact_len = try contact_info.serialize(&contact_data);

    // Write CrdsValue with signature
    try s.writeSignature(&(signature orelse core.Signature{ .data = [_]u8{0} ** 64 }));
    try s.writeEnumTag(@intFromEnum(CrdsDataType.ContactInfo));
    try s.writeBytes(contact_data[0..contact_len]);

    return s.pos;
}

/// Get the signable data for a CrdsValue containing modern ContactInfo (for external signing)
/// Returns the data that should be signed: CrdsData enum tag + serialized contact info
pub fn getContactInfoSignableData(contact_info: *const ContactInfo, out: []u8) BincodeError!usize {
    // Signable data: enum tag (4 bytes) + serialized contact info
    std.mem.writeInt(u32, out[0..4], @intFromEnum(CrdsDataType.ContactInfo), .little);
    const contact_len = try contact_info.serialize(out[4..]);
    return 4 + contact_len;
}

/// Build a PushMessage with modern ContactInfo (required by Firedancer)
/// If signature is null, an empty signature is used (message will be rejected by peers)
pub fn buildPushMessageWithContactInfo(
    buffer: []u8,
    sender_pubkey: core.Pubkey,
    contact_info: *const ContactInfo,
    signature: ?core.Signature,
) BincodeError!usize {
    var s = Serializer.init(buffer);

    // Protocol::PushMessage enum tag
    try s.writeEnumTag(@intFromEnum(ProtocolType.PushMessage));

    // Sender pubkey
    try s.writePubkey(&sender_pubkey);

    // Vec<CrdsValue> with length 1
    try s.writeU64(1);

    // Serialize the contact info
    var contact_data: [512]u8 = undefined;
    const contact_len = try contact_info.serialize(&contact_data);

    // Write CrdsValue with signature
    try s.writeSignature(&(signature orelse core.Signature{ .data = [_]u8{0} ** 64 }));
    try s.writeEnumTag(@intFromEnum(CrdsDataType.ContactInfo));
    try s.writeBytes(contact_data[0..contact_len]);

    return s.pos;
}

/// Build a PushMessage with LegacyContactInfo
/// If signature is null, an empty signature is used (message will be rejected by peers)
pub fn buildPushMessageWithLegacyContactInfo(
    buffer: []u8,
    sender_pubkey: core.Pubkey,
    contact_info: *const LegacyContactInfo,
    signature: ?core.Signature,
) BincodeError!usize {
    var s = Serializer.init(buffer);

    // Protocol::PushMessage enum tag
    try s.writeEnumTag(@intFromEnum(ProtocolType.PushMessage));

    // Sender pubkey
    try s.writePubkey(&sender_pubkey);

    // Vec<CrdsValue> with length 1
    try s.writeU64(1);

    // Serialize the contact info
    var contact_data: [512]u8 = undefined;
    const contact_len = try contact_info.serialize(&contact_data);

    // Write CrdsValue with signature
    try s.writeSignature(&(signature orelse core.Signature{ .data = [_]u8{0} ** 64 }));
    try s.writeEnumTag(@intFromEnum(CrdsDataType.LegacyContactInfo));
    try s.writeBytes(contact_data[0..contact_len]);

    return s.pos;
}

/// Build a PullResponse message with modern ContactInfo
pub fn buildPullResponseWithContactInfo(
    buffer: []u8,
    sender_pubkey: core.Pubkey,
    contact_info: *const ContactInfo,
    signature: ?core.Signature,
) BincodeError!usize {
    var s = Serializer.init(buffer);

    // Protocol::PullResponse enum tag
    try s.writeEnumTag(@intFromEnum(ProtocolType.PullResponse));

    // Sender pubkey
    try s.writePubkey(&sender_pubkey);

    // Vec<CrdsValue> with length 1
    try s.writeU64(1);

    // Serialize the contact info
    var contact_data: [512]u8 = undefined;
    const contact_len = try contact_info.serialize(&contact_data);

    // Write CrdsValue with signature
    try s.writeSignature(&(signature orelse core.Signature{ .data = [_]u8{0} ** 64 }));
    try s.writeEnumTag(@intFromEnum(CrdsDataType.ContactInfo));
    try s.writeBytes(contact_data[0..contact_len]);

    return s.pos;
}

/// Build a PullResponse message with LegacyContactInfo
pub fn buildPullResponseWithLegacyContactInfo(
    buffer: []u8,
    sender_pubkey: core.Pubkey,
    contact_info: *const LegacyContactInfo,
    signature: ?core.Signature,
) BincodeError!usize {
    var s = Serializer.init(buffer);

    // Protocol::PullResponse enum tag
    try s.writeEnumTag(@intFromEnum(ProtocolType.PullResponse));

    // Sender pubkey
    try s.writePubkey(&sender_pubkey);

    // Vec<CrdsValue> with length 1
    try s.writeU64(1);

    // Serialize the contact info
    var contact_data: [512]u8 = undefined;
    const contact_len = try contact_info.serialize(&contact_data);

    // Write CrdsValue with signature
    try s.writeSignature(&(signature orelse core.Signature{ .data = [_]u8{0} ** 64 }));
    try s.writeEnumTag(@intFromEnum(CrdsDataType.LegacyContactInfo));
    try s.writeBytes(contact_data[0..contact_len]);

    return s.pos;
}

/// Parse an incoming gossip message and return its type
pub fn parseProtocolType(data: []const u8) BincodeError!ProtocolType {
    if (data.len < 4) return BincodeError.InvalidData;
    const tag = std.mem.readInt(u32, data[0..4], .little);
    if (tag > 5) return BincodeError.InvalidEnumTag;
    return @enumFromInt(tag);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "serializer basic types" {
    var buffer: [64]u8 = undefined;
    var s = Serializer.init(&buffer);

    try s.writeU8(0x42);
    try s.writeU16(0x1234);
    try s.writeU32(0xDEADBEEF);
    try s.writeU64(0x123456789ABCDEF0);

    try std.testing.expectEqual(@as(usize, 15), s.pos);

    // Verify little-endian encoding
    try std.testing.expectEqual(@as(u8, 0x42), buffer[0]);
    try std.testing.expectEqual(@as(u8, 0x34), buffer[1]); // Low byte of u16
    try std.testing.expectEqual(@as(u8, 0x12), buffer[2]); // High byte of u16
}

test "deserializer basic types" {
    const data = [_]u8{
        0x42, // u8
        0x34, 0x12, // u16 little-endian
        0xEF, 0xBE, 0xAD, 0xDE, // u32 little-endian
    };

    var d = Deserializer.init(&data);

    try std.testing.expectEqual(@as(u8, 0x42), try d.readU8());
    try std.testing.expectEqual(@as(u16, 0x1234), try d.readU16());
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), try d.readU32());
}

test "ping message serialization" {
    const from = core.Pubkey{ .data = [_]u8{1} ** 32 };
    const token = [_]u8{2} ** 32;

    var buffer: [256]u8 = undefined;
    const len = try buildPingMessage(&buffer, from, token, null);

    // Ping: enum_tag(4) + from(32) + token(32) + signature(64) = 132
    try std.testing.expectEqual(@as(usize, 132), len);

    // Verify enum tag is PingMessage (4)
    const tag = std.mem.readInt(u32, buffer[0..4], .little);
    try std.testing.expectEqual(@as(u32, 4), tag);
}

test "pong hash creation" {
    const token = [_]u8{0xAB} ** 32;
    const hash = Pong.createHash(&token);

    // Verify it's a valid SHA256 hash (non-zero)
    var all_zero = true;
    for (hash.data) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);
}

test "socket addr serialization" {
    const addr = SocketAddr.initIpv4(.{ 192, 168, 1, 100 }, 8001);

    var buffer: [32]u8 = undefined;
    var s = Serializer.init(&buffer);
    try addr.serialize(&s);

    // IPv4: enum_tag(4) + ip(4) + port(2) = 10 bytes
    try std.testing.expectEqual(@as(usize, 10), s.pos);

    // Verify enum tag is 0 (IPv4)
    const tag = std.mem.readInt(u32, buffer[0..4], .little);
    try std.testing.expectEqual(@as(u32, 0), tag);

    // Verify IP
    try std.testing.expectEqual(@as(u8, 192), buffer[4]);
    try std.testing.expectEqual(@as(u8, 168), buffer[5]);
    try std.testing.expectEqual(@as(u8, 1), buffer[6]);
    try std.testing.expectEqual(@as(u8, 100), buffer[7]);

    // Verify port (little-endian)
    const port = std.mem.readInt(u16, buffer[8..10], .little);
    try std.testing.expectEqual(@as(u16, 8001), port);
}

test "legacy contact info serialization" {
    const identity = core.Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const contact = LegacyContactInfo.initSelf(
        identity,
        .{ 38, 92, 24, 174 },
        8001,
        8002,
        8003,
        8004,
        8899,
        27350, // testnet shred version
    );

    var buffer: [512]u8 = undefined;
    const len = try contact.serialize(&buffer);

    // Should be: pubkey(32) + 10 sockets(10 each) + wallclock(8) + shred_version(2)
    // = 32 + 100 + 8 + 2 = 142 bytes. (The LegacyContactInfo struct serializes 10 SocketAddr
    // fields; the prior "11 sockets / 152" comment + expectation were stale — current behavior
    // is 142, unrelated to the QUIC ingest work; corrected so the test-quic-ingest gate is green.)
    try std.testing.expectEqual(@as(usize, 142), len);

    // Verify pubkey is at the start
    try std.testing.expectEqual(@as(u8, 0xAA), buffer[0]);
}

test "parse protocol type" {
    // PingMessage = 4
    const ping_data = [_]u8{ 4, 0, 0, 0 } ++ [_]u8{0} ** 128;
    const ping_type = try parseProtocolType(&ping_data);
    try std.testing.expectEqual(ProtocolType.PingMessage, ping_type);

    // PullRequest = 0
    const pull_data = [_]u8{ 0, 0, 0, 0 } ++ [_]u8{0} ** 128;
    const pull_type = try parseProtocolType(&pull_data);
    try std.testing.expectEqual(ProtocolType.PullRequest, pull_type);
}
