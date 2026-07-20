//! Vexor CRDS (Cluster Replicated Data Store) Serialization
//!
//! CRDS is Solana's gossip data format. It uses a Bloom filter-based
//! protocol for efficient cluster-wide data dissemination.
//!
//! Key structures:
//! - CrdsValue: Container for all gossip data types
//! - CrdsData: The actual data being gossiped
//! - ContactInfo: Node contact information
//! - Vote: Vote records
//! - EpochSlots: Slot completion information
//!
//! Wire format: Bincode serialization (little-endian)

const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = @import("vex_crypto");

/// CRDS Value - the main gossip message container
pub const CrdsValue = struct {
    signature: [64]u8, // Ed25519 signature
    data: CrdsData,

    const Self = @This();

    /// Serialize to bincode format
    pub fn serialize(self: *const Self, writer: anytype) !void {
        // Write signature (fixed 64 bytes)
        try writer.writeAll(&self.signature);

        // Write data variant tag and content
        try self.data.serialize(writer);
    }

    /// Deserialize from bincode format
    pub fn deserialize(reader: anytype) !Self {
        // Initialize to zero to avoid undefined memory
        var signature: [64]u8 = [_]u8{0} ** 64;
        try reader.readNoEof(&signature);

        const data = try CrdsData.deserialize(reader);

        return Self{
            .signature = signature,
            .data = data,
        };
    }

    /// Verify the signature
    pub fn verify(self: *const Self) bool {
        // Get the pubkey from the data
        const pubkey = self.data.pubkey() orelse return false;

        // Serialize data for verification
        // Use larger buffer to accommodate all CRDS types (ContactInfo can be large)
        var buf: [16384]u8 = [_]u8{0} ** 16384;
        var fbs = std.io.fixedBufferStream(&buf);
        self.data.serialize(fbs.writer()) catch return false;
        const data_bytes = fbs.getWritten();

        // Verify signature.
        // Signature: verify(sig: *const [64]u8, pubkey: *const [32]u8, msg).
        // (Pre-existing latent arg-order bug fixed 2026-06-21: was
        // verify(pubkey, data_bytes, &signature) — wrong positions; this code
        // path had no live caller until the DuplicateShred KAT exercised it.)
        return crypto.ed25519.verify(
            &self.signature,
            pubkey,
            data_bytes,
        );
    }
};

/// CRDS Data variant types
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

/// CRDS Data - union of all gossip data types
pub const CrdsData = union(CrdsDataType) {
    LegacyContactInfo: LegacyContactInfo,
    Vote: VoteData,
    LowestSlot: LowestSlot,
    LegacySnapshotHashes: LegacySnapshotHashes,
    AccountsHashes: AccountsHashes,
    EpochSlots: EpochSlots,
    LegacyVersion: LegacyVersion,
    Version: Version,
    NodeInstance: NodeInstance,
    DuplicateShred: DuplicateShred,
    SnapshotHashes: SnapshotHashes,
    ContactInfo: ContactInfo,
    RestartLastVotedForkSlots: RestartLastVotedForkSlots,
    RestartHeaviestFork: RestartHeaviestFork,

    const Self = @This();

    /// Get the pubkey from this data
    pub fn pubkey(self: *const Self) ?*const [32]u8 {
        return switch (self.*) {
            .LegacyContactInfo => |*ci| &ci.pubkey,
            .Vote => |*v| &v.from,
            .ContactInfo => |*ci| &ci.pubkey,
            .NodeInstance => |*ni| &ni.from,
            .Version => |*v| &v.from,
            .LegacyVersion => |*v| &v.from,
            .SnapshotHashes => |*sh| &sh.from,
            .LegacySnapshotHashes => |*sh| &sh.from,
            .AccountsHashes => |*ah| &ah.from,
            .LowestSlot => |*ls| &ls.from,
            .EpochSlots => |*es| &es.from,
            .DuplicateShred => |*ds| &ds.from,
            .RestartLastVotedForkSlots => |*r| &r.from,
            .RestartHeaviestFork => |*r| &r.from,
        };
    }

    /// Serialize to bincode format
    pub fn serialize(self: *const Self, writer: anytype) !void {
        // Write variant tag as u32 little-endian
        const tag: u32 = @intFromEnum(self.*);
        try writer.writeInt(u32, tag, .little);

        // Write variant data
        switch (self.*) {
            .LegacyContactInfo => |*ci| try ci.serialize(writer),
            .Vote => |*v| try v.serialize(writer),
            .ContactInfo => |*ci| try ci.serialize(writer),
            .NodeInstance => |*ni| try ni.serialize(writer),
            .Version => |*v| try v.serialize(writer),
            .LegacyVersion => |*v| try v.serialize(writer),
            .SnapshotHashes => |*sh| try sh.serialize(writer),
            .LegacySnapshotHashes => |*sh| try sh.serialize(writer),
            .AccountsHashes => |*ah| try ah.serialize(writer),
            .LowestSlot => |*ls| try ls.serialize(writer),
            .EpochSlots => |*es| try es.serialize(writer),
            // CANONICAL (Agave rc.1 crds_data.rs:59):
            //   DuplicateShred(DuplicateShredIndex /*u16*/, DuplicateShred)
            // is a TWO-element tuple variant. The u16 `index` is serialized
            // IMMEDIATELY after the u32 tag and BEFORE the DuplicateShred body,
            // and IS covered by the CrdsValue signature. The prior Vexor wire
            // omitted this u16 (proof 2 bytes short, signature over wrong bytes)
            // → other validators rejected our proofs. ds.serialize writes the
            // tuple index itself so the inbound deserialize path stays symmetric.
            .DuplicateShred => |*ds| try ds.serialize(writer),
            .RestartLastVotedForkSlots => |*r| try r.serialize(writer),
            .RestartHeaviestFork => |*r| try r.serialize(writer),
        }
    }

    /// Deserialize from bincode format
    pub fn deserialize(reader: anytype) !Self {
        const tag = try reader.readInt(u32, .little);
        const data_type = std.meta.intToEnum(CrdsDataType, tag) catch return error.InvalidDataType;

        return switch (data_type) {
            .LegacyContactInfo => .{ .LegacyContactInfo = try LegacyContactInfo.deserialize(reader) },
            .Vote => .{ .Vote = try VoteData.deserialize(reader) },
            .ContactInfo => .{ .ContactInfo = try ContactInfo.deserialize(reader) },
            .NodeInstance => .{ .NodeInstance = try NodeInstance.deserialize(reader) },
            .Version => .{ .Version = try Version.deserialize(reader) },
            .LegacyVersion => .{ .LegacyVersion = try LegacyVersion.deserialize(reader) },
            .SnapshotHashes => .{ .SnapshotHashes = try SnapshotHashes.deserialize(reader) },
            .LegacySnapshotHashes => .{ .LegacySnapshotHashes = try LegacySnapshotHashes.deserialize(reader) },
            .AccountsHashes => .{ .AccountsHashes = try AccountsHashes.deserialize(reader) },
            .LowestSlot => .{ .LowestSlot = try LowestSlot.deserialize(reader) },
            .EpochSlots => .{ .EpochSlots = try EpochSlots.deserialize(reader) },
            .DuplicateShred => .{ .DuplicateShred = try DuplicateShred.deserialize(reader) },
            .RestartLastVotedForkSlots => .{ .RestartLastVotedForkSlots = try RestartLastVotedForkSlots.deserialize(reader) },
            .RestartHeaviestFork => .{ .RestartHeaviestFork = try RestartHeaviestFork.deserialize(reader) },
        };
    }
};

/// Legacy contact info (pre-1.11)
pub const LegacyContactInfo = struct {
    pubkey: [32]u8,
    wallclock: u64,
    gossip: SocketAddr,
    tvu: SocketAddr,
    tvu_forwards: SocketAddr,
    repair: SocketAddr,
    tpu: SocketAddr,
    tpu_forwards: SocketAddr,
    tpu_vote: SocketAddr,
    rpc: SocketAddr,
    rpc_pubsub: SocketAddr,
    serve_repair: SocketAddr,
    shred_version: u16,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.pubkey);
        try writer.writeInt(u64, self.wallclock, .little);
        try self.gossip.serialize(writer);
        try self.tvu.serialize(writer);
        try self.tvu_forwards.serialize(writer);
        try self.repair.serialize(writer);
        try self.tpu.serialize(writer);
        try self.tpu_forwards.serialize(writer);
        try self.tpu_vote.serialize(writer);
        try self.rpc.serialize(writer);
        try self.rpc_pubsub.serialize(writer);
        try self.serve_repair.serialize(writer);
        try writer.writeInt(u16, self.shred_version, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        // Initialize to zero to avoid undefined memory
        var pubkey: [32]u8 = [_]u8{0} ** 32;
        try reader.readNoEof(&pubkey);

        return @This(){
            .pubkey = pubkey,
            .wallclock = try reader.readInt(u64, .little),
            .gossip = try SocketAddr.deserialize(reader),
            .tvu = try SocketAddr.deserialize(reader),
            .tvu_forwards = try SocketAddr.deserialize(reader),
            .repair = try SocketAddr.deserialize(reader),
            .tpu = try SocketAddr.deserialize(reader),
            .tpu_forwards = try SocketAddr.deserialize(reader),
            .tpu_vote = try SocketAddr.deserialize(reader),
            .rpc = try SocketAddr.deserialize(reader),
            .rpc_pubsub = try SocketAddr.deserialize(reader),
            .serve_repair = try SocketAddr.deserialize(reader),
            .shred_version = try reader.readInt(u16, .little),
        };
    }
};

/// Modern contact info (1.11+)
pub const ContactInfo = struct {
    pubkey: [32]u8,
    wallclock: u64,
    outset: u64, // Time of first creation
    shred_version: u16,
    version: ClientVersion,
    addrs: []const IpAddr,
    sockets: []const SocketEntry,
    extensions: []const u8,

    const Self = @This();

    pub fn serialize(self: *const Self, writer: anytype) !void {
        try writer.writeAll(&self.pubkey);
        try writer.writeInt(u64, self.wallclock, .little);
        try writer.writeInt(u64, self.outset, .little);
        try writer.writeInt(u16, self.shred_version, .little);
        try self.version.serialize(writer);

        // Write addrs as length-prefixed array
        try writer.writeInt(u64, self.addrs.len, .little);
        for (self.addrs) |addr| {
            try addr.serialize(writer);
        }

        // Write sockets
        try writer.writeInt(u64, self.sockets.len, .little);
        for (self.sockets) |socket| {
            try socket.serialize(writer);
        }

        // Write extensions
        try writer.writeInt(u64, self.extensions.len, .little);
        try writer.writeAll(self.extensions);
    }

    pub fn deserialize(reader: anytype) !Self {
        // Initialize to zero to avoid undefined memory
        var pubkey: [32]u8 = [_]u8{0} ** 32;
        try reader.readNoEof(&pubkey);

        // Note: Would need allocator for variable-length fields
        // This is a simplified version
        return Self{
            .pubkey = pubkey,
            .wallclock = try reader.readInt(u64, .little),
            .outset = try reader.readInt(u64, .little),
            .shred_version = try reader.readInt(u16, .little),
            .version = try ClientVersion.deserialize(reader),
            .addrs = &[_]IpAddr{},
            .sockets = &[_]SocketEntry{},
            .extensions = &[_]u8{},
        };
    }
};

/// Client version info
pub const ClientVersion = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u32,
    feature_set: u32,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeInt(u16, self.major, .little);
        try writer.writeInt(u16, self.minor, .little);
        try writer.writeInt(u16, self.patch, .little);
        // Option<u32>
        if (self.commit) |c| {
            try writer.writeByte(1);
            try writer.writeInt(u32, c, .little);
        } else {
            try writer.writeByte(0);
        }
        try writer.writeInt(u32, self.feature_set, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        return @This(){
            .major = try reader.readInt(u16, .little),
            .minor = try reader.readInt(u16, .little),
            .patch = try reader.readInt(u16, .little),
            .commit = if (try reader.readByte() == 1) try reader.readInt(u32, .little) else null,
            .feature_set = try reader.readInt(u32, .little),
        };
    }
};

/// Socket address (IPv4 or IPv6)
pub const SocketAddr = struct {
    addr: IpAddr,
    port: u16,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try self.addr.serialize(writer);
        try writer.writeInt(u16, self.port, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        return @This(){
            .addr = try IpAddr.deserialize(reader),
            .port = try reader.readInt(u16, .little),
        };
    }

    pub fn format(self: @This()) [64]u8 {
        var buf: [64]u8 = undefined;
        const len = switch (self.addr) {
            .v4 => |v4| std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}:{d}", .{
                v4.addr[0],
                v4.addr[1],
                v4.addr[2],
                v4.addr[3],
                self.port,
            }) catch unreachable,
            .v6 => |_| std.fmt.bufPrint(&buf, "[IPv6]:{d}", .{self.port}) catch unreachable,
        };
        @memset(buf[len.len..], 0);
        return buf;
    }
};

/// IP address
pub const IpAddr = union(enum) {
    v4: Ipv4Addr,
    v6: Ipv6Addr,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        switch (self.*) {
            .v4 => |v4| {
                try writer.writeByte(0); // Tag for IPv4
                try writer.writeAll(&v4.addr);
            },
            .v6 => |v6| {
                try writer.writeByte(1); // Tag for IPv6
                try writer.writeAll(&v6.addr);
            },
        }
    }

    pub fn deserialize(reader: anytype) !@This() {
        const tag = try reader.readByte();
        return switch (tag) {
            0 => blk: {
                var addr: [4]u8 = undefined;
                try reader.readNoEof(&addr);
                break :blk .{ .v4 = .{ .addr = addr } };
            },
            1 => blk: {
                var addr: [16]u8 = undefined;
                try reader.readNoEof(&addr);
                break :blk .{ .v6 = .{ .addr = addr } };
            },
            else => error.InvalidIpType,
        };
    }
};

pub const Ipv4Addr = struct {
    addr: [4]u8,
};

pub const Ipv6Addr = struct {
    addr: [16]u8,
};

/// Socket entry for ContactInfo
pub const SocketEntry = struct {
    key: u8, // Socket type index
    index: u8, // Index into addrs array
    offset: u16, // Port offset from base

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeByte(self.key);
        try writer.writeByte(self.index);
        try writer.writeInt(u16, self.offset, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        return @This(){
            .key = try reader.readByte(),
            .index = try reader.readByte(),
            .offset = try reader.readInt(u16, .little),
        };
    }
};

/// Vote data in gossip
pub const VoteData = struct {
    index: u8,
    from: [32]u8,
    transaction: []const u8, // Serialized transaction
    wallclock: u64,
    slot: u64,
    /// True iff `transaction` points at a CRDS-OWNED heap allocation that must be
    /// freed via `deinit`. The legacy `deserialize` path leaves this false (it
    /// discards the tx → `transaction` is the empty slice, nothing to free).
    transaction_is_owned: bool = false,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeByte(self.index);
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.transaction.len, .little);
        try writer.writeAll(self.transaction);
        try writer.writeInt(u64, self.wallclock, .little);
        try writer.writeInt(u64, self.slot, .little);
    }

    /// LEGACY, non-owning: DISCARDS the transaction bytes (sets `transaction` to
    /// the empty slice). Kept for the existing reader-based callers
    /// (CrdsData.deserialize) that do not have an allocator. The propagation /
    /// gossip-vote path must NOT use this — it needs the real tx (see
    /// `deserializeOwned`).
    pub fn deserialize(reader: anytype) !@This() {
        const index = try reader.readByte();
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);

        // Skip transaction (would need allocator)
        const tx_len = try reader.readInt(u64, .little);
        try reader.skipBytes(tx_len, .{});

        return @This(){
            .index = index,
            .from = from,
            .transaction = &[_]u8{},
            .wallclock = try reader.readInt(u64, .little),
            .slot = try reader.readInt(u64, .little),
            .transaction_is_owned = false,
        };
    }

    /// RETAINING variant: copies the serialized vote transaction into a
    /// CRDS-owned heap allocation (`transaction_is_owned = true`) so the
    /// propagation/confirmation gate can parse the real vote (vote-account pubkey
    /// + voted slot/hash) via vex_svm/gossip_votes.parseGossipVote. The caller
    /// owns the returned value and MUST call `deinit(allocator)` to free it.
    ///
    /// Mirrors the Vexor wire format written by `serialize` above
    /// (index ‖ from ‖ u64 tx_len ‖ tx ‖ wallclock ‖ slot). NOTE: that wire is
    /// NOT byte-identical to Agave's CRDS Vote (Agave embeds the bincode
    /// Transaction with NO length prefix and `slot` is `#[serde(skip_serializing)]`
    /// = absent on the wire). The LIVE gossip ingest walks raw bytes by offset and
    /// does not go through this reader path; see INTEGRATION-NOTES.md for the
    /// offset-based extraction the push/pull handlers should use. This owning
    /// deserialize completes the in-memory data model (round-trips with
    /// `serialize`) and is unit-tested below.
    pub fn deserializeOwned(reader: anytype, allocator: Allocator) !@This() {
        const index = try reader.readByte();
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);

        const tx_len = try reader.readInt(u64, .little);
        // Bound the allocation: a vote tx is ~150-250 bytes; an absurd length is
        // malformed gossip, reject rather than attempt a huge allocation.
        if (tx_len > 4096) return error.VoteTransactionTooLarge;
        const tx_buf = try allocator.alloc(u8, @intCast(tx_len));
        errdefer allocator.free(tx_buf);
        try reader.readNoEof(tx_buf);

        return @This(){
            .index = index,
            .from = from,
            .transaction = tx_buf,
            .wallclock = try reader.readInt(u64, .little),
            .slot = try reader.readInt(u64, .little),
            .transaction_is_owned = true,
        };
    }

    /// Free the CRDS-owned transaction allocation (no-op for the legacy
    /// non-owning path). Safe to call exactly once per `deserializeOwned`.
    pub fn deinit(self: *@This(), allocator: Allocator) void {
        if (self.transaction_is_owned and self.transaction.len != 0) {
            allocator.free(self.transaction);
            self.transaction = &[_]u8{};
            self.transaction_is_owned = false;
        }
    }
};

/// Lowest slot info
pub const LowestSlot = struct {
    from: [32]u8,
    root: u64,
    lowest: u64,
    slots: []const u64,
    stash: []const u8,
    wallclock: u64,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.root, .little);
        try writer.writeInt(u64, self.lowest, .little);
        try writer.writeInt(u64, self.slots.len, .little);
        for (self.slots) |slot| {
            try writer.writeInt(u64, slot, .little);
        }
        try writer.writeInt(u64, self.stash.len, .little);
        try writer.writeAll(self.stash);
        try writer.writeInt(u64, self.wallclock, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        return @This(){
            .from = from,
            .root = try reader.readInt(u64, .little),
            .lowest = try reader.readInt(u64, .little),
            .slots = &[_]u64{},
            .stash = &[_]u8{},
            .wallclock = try reader.readInt(u64, .little),
        };
    }
};

/// Snapshot hashes (modern)
pub const SnapshotHashes = struct {
    from: [32]u8,
    full: SlotHash,
    incremental: []const SlotHash,
    wallclock: u64,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try self.full.serialize(writer);
        try writer.writeInt(u64, self.incremental.len, .little);
        for (self.incremental) |sh| {
            try sh.serialize(writer);
        }
        try writer.writeInt(u64, self.wallclock, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        return @This(){
            .from = from,
            .full = try SlotHash.deserialize(reader),
            .incremental = &[_]SlotHash{},
            .wallclock = try reader.readInt(u64, .little),
        };
    }
};

pub const SlotHash = struct {
    slot: u64,
    hash: [32]u8,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeInt(u64, self.slot, .little);
        try writer.writeAll(&self.hash);
    }

    pub fn deserialize(reader: anytype) !@This() {
        return @This(){
            .slot = try reader.readInt(u64, .little),
            .hash = blk: {
                var hash: [32]u8 = undefined;
                try reader.readNoEof(&hash);
                break :blk hash;
            },
        };
    }
};

// Stub implementations for remaining types
pub const LegacySnapshotHashes = struct {
    from: [32]u8,
    hashes: []const SlotHash,
    wallclock: u64,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.hashes.len, .little);
        for (self.hashes) |h| {
            try h.serialize(writer);
        }
        try writer.writeInt(u64, self.wallclock, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        _ = try reader.readInt(u64, .little); // Skip hashes length
        return @This(){
            .from = from,
            .hashes = &[_]SlotHash{},
            .wallclock = try reader.readInt(u64, .little),
        };
    }
};

pub const AccountsHashes = struct {
    from: [32]u8,
    hashes: []const SlotHash,
    wallclock: u64,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.hashes.len, .little);
        for (self.hashes) |h| {
            try h.serialize(writer);
        }
        try writer.writeInt(u64, self.wallclock, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        _ = try reader.readInt(u64, .little); // Skip hashes length
        return @This(){
            .from = from,
            .hashes = &[_]SlotHash{},
            .wallclock = try reader.readInt(u64, .little),
        };
    }
};

pub const EpochSlots = struct {
    from: [32]u8,
    wallclock: u64,
    slots: []const CompressedSlots,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.wallclock, .little);
        try writer.writeInt(u64, self.slots.len, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        return @This(){
            .from = from,
            .wallclock = try reader.readInt(u64, .little),
            .slots = &[_]CompressedSlots{},
        };
    }
};

pub const CompressedSlots = struct {
    first_slot: u64,
    num_slots: u64,
    slots: []const u8, // Compressed bitmap
};

pub const LegacyVersion = struct {
    from: [32]u8,
    wallclock: u64,
    version: ClientVersion,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.wallclock, .little);
        try self.version.serialize(writer);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        return @This(){
            .from = from,
            .wallclock = try reader.readInt(u64, .little),
            .version = try ClientVersion.deserialize(reader),
        };
    }
};

pub const Version = struct {
    from: [32]u8,
    wallclock: u64,
    version: ClientVersion,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.wallclock, .little);
        try self.version.serialize(writer);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        return @This(){
            .from = from,
            .wallclock = try reader.readInt(u64, .little),
            .version = try ClientVersion.deserialize(reader),
        };
    }
};

pub const NodeInstance = struct {
    from: [32]u8,
    wallclock: u64,
    timestamp: u64,
    token: u64,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.wallclock, .little);
        try writer.writeInt(u64, self.timestamp, .little);
        try writer.writeInt(u64, self.token, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        return @This(){
            .from = from,
            .wallclock = try reader.readInt(u64, .little),
            .timestamp = try reader.readInt(u64, .little),
            .token = try reader.readInt(u64, .little),
        };
    }
};

/// CRDS DuplicateShred (CRDS type 9) — equivocation proof chunk.
///
/// CANONICAL (Agave rc.1 gossip/src/duplicate_shred.rs:26-42 + crds_data.rs:59).
/// The CRDS-data wire (little-endian), INCLUDING the tuple index, is:
///   tag:u32(=9) | index:u16 | from:[32] | wallclock:u64 | slot:u64
///   | _unused:u32(=0) | _unused_shred_type:u8(=90) | num_chunks:u8
///   | chunk_index:u8 | chunk_len:u64 | chunk bytes
///
/// `index` is the `DuplicateShredIndex` (u16) of the two-element tuple variant
/// `DuplicateShred(DuplicateShredIndex, DuplicateShred)`. We store it on the
/// struct and (de)serialize it right after the u32 tag (the CrdsData tag is
/// written by CrdsData.serialize; this struct writes everything after it,
/// starting with the tuple index).
///
/// `_unused` and `_unused_shred_type` are semantically dead in Agave but MUST
/// be byte-exact for the signature to verify: `_unused == 0` and
/// `_unused_shred_type == ShredType::Code.into() == 0b0101_1010 == 90`.
/// Agave hard-codes these in from_shred (duplicate_shred.rs:277-278).
pub const DuplicateShred = struct {
    /// Tuple index (DuplicateShredIndex, u16). Serialized right after the tag.
    index: u16,
    from: [32]u8,
    wallclock: u64,
    slot: u64,
    /// Agave `_unused: u32`. MUST be 0 for byte-exact parity.
    _unused: u32 = 0,
    /// Agave `_unused_shred_type: u8`. MUST be 90 (ShredType::Code) for parity.
    _unused_shred_type: u8 = 90,
    num_chunks: u8,
    chunk_index: u8,
    chunk: []const u8,

    /// ShredType::Code.into() == 0b0101_1010 == 90 (Agave shred type wire value).
    pub const UNUSED_SHRED_TYPE_CODE: u8 = 90;

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        // Tuple index FIRST (immediately after the u32 CrdsData tag).
        try writer.writeInt(u16, self.index, .little);
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.wallclock, .little);
        try writer.writeInt(u64, self.slot, .little);
        // _unused (u32) and _unused_shred_type (u8): forced canonical values.
        try writer.writeInt(u32, 0, .little);
        try writer.writeByte(UNUSED_SHRED_TYPE_CODE);
        try writer.writeByte(self.num_chunks);
        try writer.writeByte(self.chunk_index);
        try writer.writeInt(u64, self.chunk.len, .little);
        try writer.writeAll(self.chunk);
    }

    pub fn deserialize(reader: anytype) !@This() {
        const index = try reader.readInt(u16, .little);
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        const wallclock = try reader.readInt(u64, .little);
        const slot = try reader.readInt(u64, .little);
        const unused = try reader.readInt(u32, .little);
        const unused_shred_type = try reader.readByte();
        const num_chunks = try reader.readByte();
        const chunk_index = try reader.readByte();
        // Note: chunk bytes are length-prefixed (u64) on the wire; this
        // simplified deserialize (like the other CRDS types here) skips the
        // variable-length body and leaves `chunk` empty — sizing/regrouping of
        // inbound chunks is handled by the gossip packet walker.
        return @This(){
            .index = index,
            .from = from,
            .wallclock = wallclock,
            .slot = slot,
            ._unused = unused,
            ._unused_shred_type = unused_shred_type,
            .num_chunks = num_chunks,
            .chunk_index = chunk_index,
            .chunk = &[_]u8{},
        };
    }
};

pub const RestartLastVotedForkSlots = struct {
    from: [32]u8,
    wallclock: u64,
    offsets: []const u16,
    last_voted_slot: u64,
    last_voted_hash: [32]u8,
    shred_version: u16,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.wallclock, .little);
        try writer.writeInt(u64, self.offsets.len, .little);
        for (self.offsets) |o| {
            try writer.writeInt(u16, o, .little);
        }
        try writer.writeInt(u64, self.last_voted_slot, .little);
        try writer.writeAll(&self.last_voted_hash);
        try writer.writeInt(u16, self.shred_version, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        return @This(){
            .from = from,
            .wallclock = try reader.readInt(u64, .little),
            .offsets = &[_]u16{},
            .last_voted_slot = try reader.readInt(u64, .little),
            .last_voted_hash = blk: {
                var h: [32]u8 = undefined;
                try reader.readNoEof(&h);
                break :blk h;
            },
            .shred_version = try reader.readInt(u16, .little),
        };
    }
};

pub const RestartHeaviestFork = struct {
    from: [32]u8,
    wallclock: u64,
    last_slot: u64,
    last_slot_hash: [32]u8,
    observed_stake: u64,
    shred_version: u16,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeInt(u64, self.wallclock, .little);
        try writer.writeInt(u64, self.last_slot, .little);
        try writer.writeAll(&self.last_slot_hash);
        try writer.writeInt(u64, self.observed_stake, .little);
        try writer.writeInt(u16, self.shred_version, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        return @This(){
            .from = from,
            .wallclock = try reader.readInt(u64, .little),
            .last_slot = try reader.readInt(u64, .little),
            .last_slot_hash = blk: {
                var h: [32]u8 = undefined;
                try reader.readNoEof(&h);
                break :blk h;
            },
            .observed_stake = try reader.readInt(u64, .little),
            .shred_version = try reader.readInt(u16, .little),
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// GOSSIP PROTOCOL MESSAGES
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol message types
pub const Protocol = union(enum) {
    PullRequest: PullRequest,
    PullResponse: PullResponse,
    PushMessage: PushMessage,
    PruneMessage: PruneMessage,
    PingMessage: PingMessage,
    PongMessage: PongMessage,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        switch (self.*) {
            .PullRequest => |*pr| {
                try writer.writeInt(u32, 0, .little);
                try pr.serialize(writer);
            },
            .PullResponse => |*pr| {
                try writer.writeInt(u32, 1, .little);
                try pr.serialize(writer);
            },
            .PushMessage => |*pm| {
                try writer.writeInt(u32, 2, .little);
                try pm.serialize(writer);
            },
            .PruneMessage => |*pm| {
                try writer.writeInt(u32, 3, .little);
                try pm.serialize(writer);
            },
            .PingMessage => |*pm| {
                try writer.writeInt(u32, 4, .little);
                try pm.serialize(writer);
            },
            .PongMessage => |*pm| {
                try writer.writeInt(u32, 5, .little);
                try pm.serialize(writer);
            },
        }
    }

    pub fn deserialize(reader: anytype) !@This() {
        const tag = try reader.readInt(u32, .little);
        return switch (tag) {
            0 => .{ .PullRequest = try PullRequest.deserialize(reader) },
            1 => .{ .PullResponse = try PullResponse.deserialize(reader) },
            2 => .{ .PushMessage = try PushMessage.deserialize(reader) },
            3 => .{ .PruneMessage = try PruneMessage.deserialize(reader) },
            4 => .{ .PingMessage = try PingMessage.deserialize(reader) },
            5 => .{ .PongMessage = try PongMessage.deserialize(reader) },
            else => error.InvalidProtocolType,
        };
    }
};

pub const PullRequest = struct {
    filter: CrdsFilter,
    value: CrdsValue,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try self.filter.serialize(writer);
        try self.value.serialize(writer);
    }

    pub fn deserialize(reader: anytype) !@This() {
        return @This(){
            .filter = try CrdsFilter.deserialize(reader),
            .value = try CrdsValue.deserialize(reader),
        };
    }
};

pub const PullResponse = struct {
    pubkey: [32]u8,
    values: []const CrdsValue,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.pubkey);
        try writer.writeInt(u64, self.values.len, .little);
        for (self.values) |v| {
            try v.serialize(writer);
        }
    }

    pub fn deserialize(reader: anytype) !@This() {
        var pubkey: [32]u8 = undefined;
        try reader.readNoEof(&pubkey);
        _ = try reader.readInt(u64, .little); // Skip values length
        return @This(){
            .pubkey = pubkey,
            .values = &[_]CrdsValue{},
        };
    }
};

pub const PushMessage = struct {
    pubkey: [32]u8,
    values: []const CrdsValue,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.pubkey);
        try writer.writeInt(u64, self.values.len, .little);
        for (self.values) |v| {
            try v.serialize(writer);
        }
    }

    pub fn deserialize(reader: anytype) !@This() {
        var pubkey: [32]u8 = undefined;
        try reader.readNoEof(&pubkey);
        _ = try reader.readInt(u64, .little); // Skip values length
        return @This(){
            .pubkey = pubkey,
            .values = &[_]CrdsValue{},
        };
    }
};

pub const PruneMessage = struct {
    pubkey: [32]u8,
    prunes: []const [32]u8,
    signature: [64]u8,
    destination: [32]u8,
    wallclock: u64,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.pubkey);
        try writer.writeInt(u64, self.prunes.len, .little);
        for (self.prunes) |p| {
            try writer.writeAll(&p);
        }
        try writer.writeAll(&self.signature);
        try writer.writeAll(&self.destination);
        try writer.writeInt(u64, self.wallclock, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var pubkey: [32]u8 = undefined;
        try reader.readNoEof(&pubkey);
        _ = try reader.readInt(u64, .little); // Skip prunes length
        var signature: [64]u8 = undefined;
        try reader.readNoEof(&signature);
        var destination: [32]u8 = undefined;
        try reader.readNoEof(&destination);
        return @This(){
            .pubkey = pubkey,
            .prunes = &[_][32]u8{},
            .signature = signature,
            .destination = destination,
            .wallclock = try reader.readInt(u64, .little),
        };
    }
};

pub const PingMessage = struct {
    from: [32]u8,
    token: [32]u8,
    signature: [64]u8,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeAll(&self.token);
        try writer.writeAll(&self.signature);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        var token: [32]u8 = undefined;
        try reader.readNoEof(&token);
        var signature: [64]u8 = undefined;
        try reader.readNoEof(&signature);
        return @This(){
            .from = from,
            .token = token,
            .signature = signature,
        };
    }
};

pub const PongMessage = struct {
    from: [32]u8,
    hash: [32]u8, // SHA256(ping token)
    signature: [64]u8,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeAll(&self.from);
        try writer.writeAll(&self.hash);
        try writer.writeAll(&self.signature);
    }

    pub fn deserialize(reader: anytype) !@This() {
        var from: [32]u8 = undefined;
        try reader.readNoEof(&from);
        var hash: [32]u8 = undefined;
        try reader.readNoEof(&hash);
        var signature: [64]u8 = undefined;
        try reader.readNoEof(&signature);
        return @This(){
            .from = from,
            .hash = hash,
            .signature = signature,
        };
    }
};

/// CRDS Bloom filter for efficient pull requests
pub const CrdsFilter = struct {
    filter: BloomFilter,
    mask: u64,
    mask_bits: u32,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try self.filter.serialize(writer);
        try writer.writeInt(u64, self.mask, .little);
        try writer.writeInt(u32, self.mask_bits, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        return @This(){
            .filter = try BloomFilter.deserialize(reader),
            .mask = try reader.readInt(u64, .little),
            .mask_bits = try reader.readInt(u32, .little),
        };
    }
};

pub const BloomFilter = struct {
    keys: []const u64,
    bits: []const u64,
    num_bits_set: u64,

    pub fn serialize(self: *const @This(), writer: anytype) !void {
        try writer.writeInt(u64, self.keys.len, .little);
        for (self.keys) |k| {
            try writer.writeInt(u64, k, .little);
        }
        try writer.writeInt(u64, self.bits.len, .little);
        for (self.bits) |b| {
            try writer.writeInt(u64, b, .little);
        }
        try writer.writeInt(u64, self.num_bits_set, .little);
    }

    pub fn deserialize(reader: anytype) !@This() {
        _ = try reader.readInt(u64, .little); // Skip keys length
        _ = try reader.readInt(u64, .little); // Skip bits length
        return @This(){
            .keys = &[_]u64{},
            .bits = &[_]u64{},
            .num_bits_set = try reader.readInt(u64, .little),
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

test "socket addr serialize/deserialize" {
    const addr = SocketAddr{
        .addr = .{ .v4 = .{ .addr = .{ 192, 168, 1, 100 } } },
        .port = 8001,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try addr.serialize(fbs.writer());

    fbs.reset();
    const decoded = try SocketAddr.deserialize(fbs.reader());

    try std.testing.expectEqual(addr.port, decoded.port);
    try std.testing.expectEqual(addr.addr.v4.addr, decoded.addr.v4.addr);
}

test "client version serialize/deserialize" {
    const ver = ClientVersion{
        .major = 1,
        .minor = 18,
        .patch = 0,
        .commit = 0x12345678,
        .feature_set = 12345,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try ver.serialize(fbs.writer());

    fbs.reset();
    const decoded = try ClientVersion.deserialize(fbs.reader());

    try std.testing.expectEqual(ver.major, decoded.major);
    try std.testing.expectEqual(ver.minor, decoded.minor);
    try std.testing.expectEqual(ver.patch, decoded.patch);
    try std.testing.expectEqual(ver.commit, decoded.commit);
    try std.testing.expectEqual(ver.feature_set, decoded.feature_set);
}

test "VoteData deserializeOwned retains transaction bytes (round-trip, no leak)" {
    const a = std.testing.allocator;
    const tx_bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03 };
    const original = VoteData{
        .index = 7,
        .from = [_]u8{0x9F} ** 32,
        .transaction = &tx_bytes,
        .wallclock = 123456,
        .slot = 789,
    };

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.serialize(fbs.writer());

    fbs.reset();
    var decoded = try VoteData.deserializeOwned(fbs.reader(), a);
    defer decoded.deinit(a); // frees the owned tx allocation (no leak)

    try std.testing.expectEqual(original.index, decoded.index);
    try std.testing.expectEqualSlices(u8, &original.from, &decoded.from);
    try std.testing.expectEqual(original.wallclock, decoded.wallclock);
    try std.testing.expectEqual(original.slot, decoded.slot);
    try std.testing.expect(decoded.transaction_is_owned);
    // The transaction bytes were RETAINED (not discarded as the legacy path does).
    try std.testing.expectEqualSlices(u8, &tx_bytes, decoded.transaction);

    // The legacy non-owning path still discards (regression guard).
    fbs.reset();
    const legacy = try VoteData.deserialize(fbs.reader());
    try std.testing.expectEqual(@as(usize, 0), legacy.transaction.len);
    try std.testing.expect(!legacy.transaction_is_owned);
}

