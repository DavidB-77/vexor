//! Vexor Gossip Protocol
//!
//! Implementation of Solana's CRDS (Cluster Replicated Data Store) gossip protocol.
//! Handles:
//! - Validator discovery and cluster membership
//! - Node health/contact info propagation
//! - Vote and epoch stake distribution
//!
//! @prov:gossip.module

const std = @import("std");
const socket = @import("socket.zig");
const packet = @import("packet.zig");
const core = @import("core");
const bincode = @import("bincode.zig");
const cluster_slots_mod = @import("cluster_slots.zig");
const build_options = @import("build_options");
const crds = @import("crds.zig");
const dupshred = @import("duplicate_shred.zig");
const fec_resolver_mod = @import("fec_resolver.zig");

/// Gossip protocol message types (matches Solana bincode format)
/// See bincode.zig for full protocol implementation
pub const MessageType = enum(u32) {
    pull_request = 0,
    pull_response = 1,
    push_message = 2,
    prune_message = 3,
    ping = 4,
    pong = 5,
    _,
};

/// Mainnet shred version (passed via --expected-shred-version at launch)
pub const TESTNET_SHRED_VERSION: u16 = 27350;

/// Contact info for a cluster node
pub const ContactInfo = struct {
    /// Node's identity pubkey
    pubkey: core.Pubkey,

    /// Gossip address
    gossip_addr: packet.SocketAddr,

    /// TPU address (for transactions)
    tpu_addr: packet.SocketAddr,

    /// TPU forward address
    tpu_fwd_addr: packet.SocketAddr,

    /// TPU vote address (dedicated port for vote transactions)
    tpu_vote_addr: packet.SocketAddr,

    /// TVU address (for shreds)
    tvu_addr: packet.SocketAddr,

    /// TVU forward address
    tvu_fwd_addr: packet.SocketAddr,

    /// Repair address
    repair_addr: packet.SocketAddr,

    /// RPC address
    rpc_addr: packet.SocketAddr,

    /// Serve repair address
    serve_repair_addr: packet.SocketAddr,

    /// TPU QUIC address (explicitly advertised via Tag 8)
    tpu_quic_addr: packet.SocketAddr,

    /// Dedicated TPU vote QUIC address (explicitly advertised via Tag 12).
    /// Canonical clients send vote transactions here in preference to the
    /// regular tpu_quic (Tag 8) port. @prov:gossip.socket-tags
    tpu_vote_quic_addr: packet.SocketAddr,

    /// TVU QUIC address (explicitly advertised via Tag 11)
    tvu_quic_addr: packet.SocketAddr,

    /// Wallclock timestamp
    wallclock: u64,

    /// Shred version (for compatibility check)
    shred_version: u16,

    /// Software version
    version: Version,

    pub const Version = struct {
        major: u16,
        minor: u16,
        patch: u16,
        commit: ?u32,

        pub fn format(self: Version, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try writer.print("{}.{}.{}", .{ self.major, self.minor, self.patch });
        }
    };

    /// Create contact info for our node
    /// IMPORTANT: `ip` MUST be the validator's public IP for the network to send shreds!
    pub fn initSelf(
        identity: core.Pubkey,
        ip: [4]u8,
        gossip_port: u16,
        tpu_port: u16,
        tvu_port: u16,
        repair_port: u16,
        rpc_port: u16,
    ) ContactInfo {
        return .{
            .pubkey = identity,
            .gossip_addr = packet.SocketAddr.ipv4(ip, gossip_port),
            .tpu_addr = packet.SocketAddr.ipv4(ip, tpu_port),
            .tpu_fwd_addr = packet.SocketAddr.ipv4(ip, tpu_port + 1),
            .tpu_vote_addr = packet.SocketAddr.ipv4(ip, tpu_port + 4), // TPU vote port
            .tvu_addr = packet.SocketAddr.ipv4(ip, tvu_port),
            .tvu_fwd_addr = packet.SocketAddr.ipv4(ip, tvu_port + 1),
            .repair_addr = packet.SocketAddr.ipv4(ip, repair_port),
            .rpc_addr = packet.SocketAddr.ipv4(ip, rpc_port),
            .serve_repair_addr = packet.SocketAddr.ipv4(ip, repair_port + 1),
            .tpu_quic_addr = packet.SocketAddr.ipv4(ip, tpu_port + 6), // Default heuristic
            .tpu_vote_quic_addr = packet.SocketAddr.UNSPECIFIED, // populated only from parsed Tag 12 (in-memory)
            .tvu_quic_addr = packet.SocketAddr.ipv4(ip, tvu_port + 6), // Default heuristic
            .wallclock = @intCast(std.time.milliTimestamp()),
            .shred_version = 0,
            // In-memory self version — same single source as the wire path
            // (core/version.zig; the serialized advertisement lives in
            // bincode.ContactInfo.initSelf).
            .version = .{
                .major = core.version.VEXOR_VERSION.major,
                .minor = core.version.VEXOR_VERSION.minor,
                .patch = core.version.VEXOR_VERSION.patch,
                .commit = if (core.version.commit_u32 != 0) core.version.commit_u32 else null,
            },
        };
    }

    /// Check if contact info is stale
    pub fn isStale(self: *const ContactInfo, now_ms: u64, timeout_ms: u64) bool {
        // Saturating sub: peer wallclocks can be ahead due to clock skew
        return (now_ms -| self.wallclock) > timeout_ms;
    }
};

/// CRDS data types that can be gossiped
pub const CrdsValueKind = enum(u32) {
    contact_info = 0,
    vote = 1,
    lowest_slot = 2,
    snapshot_hashes = 3,
    accounts_hashes = 4,
    epoch_slots = 5,
    legacy_version = 6,
    version = 7,
    node_instance = 8,
    duplicate_shred = 9,
    incremental_snapshot_hashes = 10,
    _,
};

/// CRDS Value - a piece of gossip data
pub const CrdsValue = struct {
    /// The pubkey that created this value
    pubkey: core.Pubkey,

    /// Signature over the data
    signature: core.Signature,

    /// Wallclock when created
    wallclock: u64,

    /// Type of value
    kind: CrdsValueKind,

    /// Serialized value data
    data: []const u8,

    /// Hash of the value (for deduplication)
    pub fn hash(self: *const CrdsValue) core.Hash {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(std.mem.asBytes(&self.kind));
        hasher.update(&self.pubkey);
        hasher.update(self.data);
        return hasher.finalResult();
    }
};

/// Gossip table - stores received gossip data
pub const GossipTable = struct {
    allocator: std.mem.Allocator,

    /// RwLock protecting contacts HashMap for cross-thread access.
    /// Writer: gossip thread (upsertContact, pruneStale).
    /// Readers: VoteSender, TVU, TPU client.
    contacts_rw: std.Thread.RwLock = .{},

    /// Contact info for all known nodes
    contacts: std.AutoHashMap(core.Pubkey, ContactInfo),

    /// All received CRDS values by hash
    values: std.AutoHashMap(core.Hash, CrdsValue),

    /// A3b snapshot-trust: known-validator pubkey → advertised FULL snapshot
    /// (slot,hash) from its gossip SnapshotHashes (tag 10). Written on the gossip
    /// thread (handlePush/handlePullResponse, VERIFIED-at-ingest), read by the boot
    /// thread's pre-vote gate — protected by its OWN RwLock (independent of
    /// contacts_rw). Only populated when VEX_SNAPSHOT_TRUST != off (else untouched
    /// = byte-identical). Bounded by the #known-validators (overwrite = latest wins).
    snapshot_hashes: std.AutoHashMap([32]u8, crds.SlotHash),
    snapshot_hashes_rw: std.Thread.RwLock = .{},

    /// Our own contact info
    self_info: ?ContactInfo,

    /// Statistics
    stats: Stats,

    const Self = @This();

    pub const Stats = struct {
        values_received: u64 = 0,
        values_inserted: u64 = 0,
        values_expired: u64 = 0,
        pull_requests_sent: u64 = 0,
        pull_responses_received: u64 = 0,
        push_messages_received: u64 = 0,
        pings_sent: u64 = 0,
        pongs_received: u64 = 0,
        packets_received: u64 = 0,
        unknown_messages: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .contacts = std.AutoHashMap(core.Pubkey, ContactInfo).init(allocator),
            .values = std.AutoHashMap(core.Hash, CrdsValue).init(allocator),
            .snapshot_hashes = std.AutoHashMap([32]u8, crds.SlotHash).init(allocator),
            .self_info = null,
            .stats = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.contacts.deinit();
        self.values.deinit();
        self.snapshot_hashes.deinit();
    }

    /// A3b: store a known-validator's full snapshot (slot,hash) — write-locked
    /// (gossip thread). Overwrite = latest wins; bounded by #known-validators.
    pub fn putSnapshotHash(self: *Self, pubkey: [32]u8, sh: crds.SlotHash) void {
        self.snapshot_hashes_rw.lock();
        defer self.snapshot_hashes_rw.unlock();
        self.snapshot_hashes.put(pubkey, sh) catch {};
    }

    /// A3b: read a known-validator's advertised full snapshot (slot,hash) — read-locked
    /// (boot thread's pre-vote gate). Null if that validator hasn't advertised yet.
    pub fn getSnapshotHash(self: *Self, pubkey: [32]u8) ?crds.SlotHash {
        self.snapshot_hashes_rw.lockShared();
        defer self.snapshot_hashes_rw.unlockShared();
        return self.snapshot_hashes.get(pubkey);
    }

    /// Insert or update contact info (writer-locked for cross-thread safety)
    pub fn upsertContact(self: *Self, info_in: ContactInfo) !void {
        self.contacts_rw.lock();
        defer self.contacts_rw.unlock();
        // 2026-04-17: parseLegacyContactInfo / parseModernContactInfo currently
        // skip past the wallclock bytes without reading them, so every
        // incoming ContactInfo has wallclock=0. That made isStale() treat every
        // peer as infinitely stale and pruneStale() wiped the table after the
        // first prune cycle. Until the parsers are fixed, stamp our own local
        // wallclock at insert time so peers survive prune cycles based on how
        // long WE have known them, not on unparsed remote metadata.
        var info = info_in;
        // Always stamp with local receive time. Parser returns unreliable
        // wallclocks (sometimes 0, sometimes garbage bytes), and staleness
        // should be "how long since WE heard from this peer" anyway — not
        // "what timestamp the peer self-reported at some earlier push".
        info.wallclock = @intCast(std.time.milliTimestamp());
        const existing = self.contacts.get(info.pubkey);
        if (existing) |ex| {
            if (info.wallclock > ex.wallclock) {
                try self.contacts.put(info.pubkey, info);
            }
        } else {
            try self.contacts.put(info.pubkey, info);
        }
    }

    /// Get contact info for a pubkey
    pub fn getContact(self: *const Self, pubkey: core.Pubkey) ?ContactInfo {
        return self.contacts.get(pubkey);
    }

    /// Get all known node pubkeys
    pub fn knownNodes(self: *const Self) []const core.Pubkey {
        return self.contacts.keys();
    }

    /// Get count of known contacts
    pub fn contactCount(self: *const Self) usize {
        return self.contacts.count();
    }

    /// Prune stale contacts (writer-locked for cross-thread safety)
    pub fn pruneStale(self: *Self, timeout_ms: u64) usize {
        self.contacts_rw.lock();
        defer self.contacts_rw.unlock();
        const now = @as(u64, @intCast(std.time.milliTimestamp()));
        var pruned: usize = 0;

        var keys_to_remove: [256]core.Pubkey = undefined;
        var remove_count: usize = 0;

        var it = self.contacts.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isStale(now, timeout_ms) and remove_count < 256) {
                keys_to_remove[remove_count] = entry.key_ptr.*;
                remove_count += 1;
            }
        }

        for (keys_to_remove[0..remove_count]) |key| {
            _ = self.contacts.remove(key);
            pruned += 1;
            self.stats.values_expired +|= 1;
        }

        return pruned;
    }
};

/// Gossip service - manages gossip protocol communication
pub const GossipService = struct {
    allocator: std.mem.Allocator,

    /// Our identity
    identity: core.Pubkey,

    /// Our keypair for signing (optional - needed for full gossip)
    keypair: ?*const core.Keypair = null,

    /// Gossip UDP socket
    sock: ?socket.UdpSocket,

    /// Gossip data table
    table: GossipTable,

    /// Entrypoint addresses to connect to
    entrypoints: std.ArrayListUnmanaged(packet.SocketAddr),

    /// Random number generator
    rng: std.Random.DefaultPrng,

    /// Configuration
    config: Config,

    /// A3b snapshot-trust: the trusted --known-validator set (slice owned by the
    /// core Config; lives for the validator lifetime). Default empty ⇒ snapshot-trust
    /// inert. Set via setKnownValidators at wiring time. Membership is checked only on
    /// the gated tag-10 ingest path (linear scan over a handful of keys).
    known_validators: []const [32]u8 = &.{},

    /// Running state
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Last action timestamps
    last_pull_time: i64 = 0,
    last_push_time: i64 = 0,
    last_ping_time: i64 = 0,

    /// Our public IP address
    public_ip: [4]u8 = .{ 0, 0, 0, 0 },

    /// Shred version (for cluster compatibility)
    shred_version: u16 = 0,

    /// Our LegacyContactInfo in bincode format (deprecated, but kept for Agave compat)
    legacy_contact_info: ?bincode.LegacyContactInfo = null,

    /// Our modern ContactInfo (required by Firedancer)
    modern_contact_info: ?bincode.ContactInfo = null,

    /// SLOT-AWARE REPAIR (2026-06-14): bounded slot->{advertiser peers} index,
    /// owned by TvuService. EpochSlots (CrdsData tag 5) ingest in handlePush/
    /// handlePullResponse feeds advertisers here so getRepairPeers can prefer
    /// peers that actually hold a slot. Null until cross-linked at wiring time
    /// (setClusterSlots), and every ingest insert null-guards on it — so a
    /// kernel-UDP boot without the index set is byte-identical to before. The
    /// index has its OWN mutex (independent of contacts_rw and the tvu repair
    /// mutex); EpochSlots ingest therefore never contends the contacts lock.
    cluster_slots: ?*cluster_slots_mod.ClusterSlots = null,

    /// GOSSIP-VOTE bridge (2026-07-01): real-time CRDS Vote (tag 1) observation for
    /// the gossip-fed prop_retarget confirmation gate. Decoupled exactly like
    /// `cluster_slots` — vex_network imports NO vote-program / replay types:
    ///   * `on_gossip_vote` — sink called with the raw embedded vote-tx bytes on
    ///     every ingested CRDS Vote (handlePush/handlePullResponse). Null until
    ///     cross-linked at wiring time → byte-identical boot when unset.
    ///   * `parse_vote_tx` — injected tx-length parser (gossip_votes.parseTxConsumed)
    ///     for the P2 fix: a CRDS Vote embeds a length-PREFIX-FREE Transaction, so
    ///     getCrdsValueSize needs the real consumed length to avoid desyncing every
    ///     subsequent value in a multi-value packet. Null → legacy estimate (the
    ///     pre-fix behavior, preserved so an unwired build is byte-identical).
    on_gossip_vote: ?GossipVoteSink = null,
    parse_vote_tx: ?*const fn ([]const u8) ?usize = null,

    /// DUPLICATE-SHRED (CRDS type 9) PUSH bridge. The FEC resolver detects
    /// equivocations (always compiled) into its bounded conflict queue; this
    /// optional handle lets the gossip loop drain that queue and PUSH signed
    /// DuplicateShred proofs. The DRAIN+PUSH only runs when BOTH the comptime
    /// flag `-Dduplicate_shred` AND env `VEX_DUPLICATE_SHRED=1` are set
    /// (dormant-by-default, same pattern as -Dfec_dedup). Null until wired.
    dup_shred_resolver: ?*fec_resolver_mod.FecResolver = null,
    /// Slots we've already pushed a DuplicateShred proof for (once-per-slot
    /// guard). @prov:gossip.dup-shred-push — small
    /// bounded ring; collisions just re-allow a push (harmless).
    dup_shred_pushed_slots: [64]u64 = [_]u64{0} ** 64,
    dup_shred_pushed_head: usize = 0,
    dup_shred_pushed_count: u64 = 0,
    /// Monotonic DuplicateShredIndex cursor. Each proof's chunks get
    /// (cursor + k) % MAX_DUPLICATE_SHREDS as their tuple index; advanced by the
    /// chunk count after each proof. @prov:gossip.dup-shred-push so
    /// consecutive slots' proofs occupy DISTINCT CRDS
    /// labels (Pubkey, DuplicateShredIndex) — otherwise slot B's chunk-0 would
    /// overwrite slot A's chunk-0 in a receiver's table and slot A's proof would
    /// be lost (SlotMismatch on reassembly).
    dup_shred_index_cursor: u16 = 0,

    const Self = @This();

    pub const Config = struct {
        /// Gossip port to bind
        gossip_port: u16 = 8000,

        /// Bind the gossip socket to this specific IPv4 (dual-NIC hosts).
        /// Empty = 0.0.0.0. See core/config.zig gossip_bind_addr (2026-07-06
        /// source-IP fix: egress must originate from the ADVERTISED IP or
        /// peers' ping-pong source check fails and our ContactInfo is never
        /// retained cluster-wide → turbine stops delivering to us).
        gossip_bind_addr: []const u8 = "",

        /// How often to pull from peers (ms)
        pull_interval_ms: u64 = 15_000,

        /// How often to push to peers (ms)
        push_interval_ms: u64 = 500,

        /// How often to ping peers (ms)
        ping_interval_ms: u64 = 2_000,

        /// Timeout for stale contacts (ms)
        // 2026-04-17: bumped 120_000 → 3_600_000 (1h). Upstream wallclock
        // check was dropping 100% of peers every prune cycle (~30s) after
        // they accumulated; same reason tvu.zig disabled its own wallclock
        // filter. Real fix is time-source reconciliation; 1h timeout is
        // operational until that lands.
        contact_timeout_ms: u64 = 3_600_000,

        /// Max peers to push to
        max_push_fanout: usize = 6,

        /// TPU port
        tpu_port: u16 = 8004,

        /// TVU port
        tvu_port: u16 = 8001,

        /// Repair port
        repair_port: u16 = 8003,

        /// RPC port
        rpc_port: u16 = 8899,
    };

    pub fn init(allocator: std.mem.Allocator, identity: core.Pubkey, config: Config) Self {
        return .{
            .allocator = allocator,
            .identity = identity,
            .sock = null,
            .table = GossipTable.init(allocator),
            .entrypoints = std.ArrayListUnmanaged(packet.SocketAddr){},
            .rng = std.Random.DefaultPrng.init(@intCast(std.time.nanoTimestamp())),
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.sock) |*s| {
            s.deinit();
        }
        self.table.deinit();
        self.entrypoints.deinit(self.allocator);
    }

    /// Cross-link the slot-aware-repair index (owned by TvuService). Called at
    /// wiring time after both services exist (mirrors TvuService.setGossipService).
    pub fn setClusterSlots(self: *Self, cs: *cluster_slots_mod.ClusterSlots) void {
        self.cluster_slots = cs;
    }

    /// Type-erased sink for observed gossip votes (decouples vex_network from the
    /// replay/vote-program types — mirrors the cluster_slots cross-link).
    pub const GossipVoteSink = struct {
        ctx: *anyopaque,
        func: *const fn (*anyopaque, []const u8) void,
    };

    /// Cross-link the gossip-vote sink (called at wiring time from main.zig).
    pub fn setGossipVoteSink(self: *Self, s: GossipVoteSink) void {
        self.on_gossip_vote = s;
    }

    /// Inject the vote-tx length parser (gossip_votes.parseTxConsumed) — required
    /// for the P2 exact-length CRDS Vote delimiting.
    pub fn setParseVoteTx(self: *Self, f: *const fn ([]const u8) ?usize) void {
        self.parse_vote_tx = f;
    }

    /// Start the gossip service
    pub fn start(self: *Self) !void {
        // Create and bind gossip socket
        var sock = try socket.UdpSocket.init();
        errdefer sock.deinit();

        if (self.config.gossip_bind_addr.len > 0) blk: {
            // Dual-NIC: bind to the advertised IP so egress source == advertised
            // addr (mirrors the tvu.zig repair_bind_addr fix). Parse + fallback.
            var ip_parts: [4]u8 = .{ 0, 0, 0, 0 };
            var part_idx: usize = 0;
            var current: u16 = 0;
            for (self.config.gossip_bind_addr) |ch| {
                if (ch == '.') {
                    if (part_idx < 4) {
                        ip_parts[part_idx] = @intCast(current);
                        part_idx += 1;
                        current = 0;
                    }
                } else if (ch >= '0' and ch <= '9') {
                    current = current * 10 + (ch - '0');
                }
            }
            if (part_idx < 4) ip_parts[part_idx] = @intCast(current);
            const bind_addr = std.net.Address.initIp4(ip_parts, self.config.gossip_port);
            sock.bind(bind_addr) catch |err| {
                std.log.warn("[GOSSIP] bind({s}:{d}) failed: {} — falling back to 0.0.0.0", .{ self.config.gossip_bind_addr, self.config.gossip_port, err });
                try sock.bindPort(self.config.gossip_port);
                break :blk;
            };
            std.log.warn("[GOSSIP] socket bound to {s}:{d} (dual-NIC source-IP fix) ✓", .{ self.config.gossip_bind_addr, self.config.gossip_port });
        } else {
            try sock.bindPort(self.config.gossip_port);
        }

        // CRITICAL: Verify the port was actually bound correctly
        const actual_port = sock.boundPort();
        std.log.debug("[Gossip] Socket fd={d} bound, requested port={d}, actual port={any}\n", .{
            sock.fd, self.config.gossip_port, actual_port,
        });

        if (actual_port) |port| {
            if (port != self.config.gossip_port) {
                std.log.debug("[Gossip] ❌ PORT MISMATCH! Requested {d} but got {d}\n", .{
                    self.config.gossip_port, port,
                });
                return error.PortBindFailed;
            }
        } else {
            std.log.debug("[Gossip] ❌ Could not verify bound port!\n", .{});
            return error.PortBindFailed;
        }

        self.sock = sock;
        self.running.store(true, .release);

        std.log.debug("[Gossip] ✅ Gossip service started on port {d} (fd={d})\n", .{
            self.config.gossip_port, sock.fd,
        });
    }

    /// Add an entrypoint address (supports hostnames and IPs)
    pub fn addEntrypoint(self: *Self, host: []const u8, port: u16) !void {
        // Try parsing as IP first
        if (std.net.Address.parseIp4(host, port)) |ip| {
            const addr = packet.SocketAddr.ipv4(
                @as([4]u8, @bitCast(ip.in.sa.addr)),
                port,
            );
            try self.entrypoints.append(self.allocator, addr);
            std.log.info("[Gossip] Added entrypoint (IP): {s}:{d}", .{ host, port });
            return;
        } else |_| {}

        // If not an IP, try DNS resolution using getAddressList
        std.log.info("[Gossip] Resolving hostname: {s}:{d}", .{ host, port });

        // Use getAddressList for proper DNS resolution
        const list = std.net.getAddressList(self.allocator, host, port) catch |err| {
            std.log.warn("[Gossip] DNS resolution failed for {s}: {}", .{ host, err });
            return err;
        };
        defer list.deinit();

        // Use the first resolved address
        if (list.addrs.len > 0) {
            const resolved = list.addrs[0];
            if (resolved.any.family == std.posix.AF.INET) {
                const ipv4 = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&resolved.any)));
                const ip_bytes: [4]u8 = @bitCast(ipv4.addr);
                const addr = packet.SocketAddr.ipv4(ip_bytes, port);
                try self.entrypoints.append(self.allocator, addr);
                std.log.info("[Gossip] Resolved {s} -> {d}.{d}.{d}.{d}:{d}", .{
                    host, ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port,
                });
            } else {
                std.log.warn("[Gossip] Resolved address is not IPv4 for {s}", .{host});
            }
        } else {
            std.log.warn("[Gossip] No addresses resolved for {s}", .{host});
        }
    }

    /// Send a ping to a node (bincode format with proper signature)
    pub fn sendPing(self: *Self, target: packet.SocketAddr) !void {
        if (self.sock == null) return error.NotStarted;

        // Build ping message in proper bincode format
        var pkt = packet.Packet.init();

        // Generate random token
        var token: [32]u8 = undefined;
        const random = self.rng.random();
        random.bytes(&token);

        // Sign the ping message
        var signature: ?core.Signature = null;
        if (self.keypair) |kp| {
            const signable = bincode.getPingSignableData(self.identity, token);
            signature = kp.sign(&signable);
        }

        // Build bincode-formatted ping message
        const len = bincode.buildPingMessage(
            &pkt.data,
            self.identity,
            token,
            signature,
        ) catch {
            std.log.debug("[Gossip] Failed to build ping message\n", .{});
            return;
        };

        pkt.len = @intCast(len);
        pkt.src_addr = target;

        _ = try self.sock.?.send(&pkt);
        self.table.stats.pings_sent +|= 1;
    }

    /// Process received gossip packets
    pub fn processPackets(self: *Self, batch: *packet.PacketBatch) !void {
        for (batch.slice()) |*pkt| {
            try self.processPacket(pkt);
        }
    }

    fn processPacket(self: *Self, pkt: *const packet.Packet) !void {
        if (pkt.len < 4) return; // Too short

        const msg_type_raw = std.mem.readInt(u32, pkt.data[0..4], .little);
        const msg_type: MessageType = @enumFromInt(msg_type_raw);

        switch (msg_type) {
            .ping => {
                try self.handlePing(pkt);
            },
            .pong => {
                std.log.debug("[Gossip] Received PONG from {}.{}.{}.{}:{}\n", .{
                    pkt.src_addr.addr[0], pkt.src_addr.addr[1], pkt.src_addr.addr[2], pkt.src_addr.addr[3],
                    pkt.src_addr.port(),
                });
                self.handlePong(pkt);
            },
            .push_message => {
                // std.log.debug("[Gossip] Received PUSH ({} bytes) from {}.{}.{}.{}:{}\n", .{
                //     pkt.len,
                //     pkt.src_addr.addr[0],
                //     pkt.src_addr.addr[1],
                //     pkt.src_addr.addr[2],
                //     pkt.src_addr.addr[3],
                //     pkt.src_addr.port(),
                // });
                try self.handlePush(pkt);
            },
            .pull_request => {
                try self.handlePullRequest(pkt);
            },
            .pull_response => {
                // std.log.debug("[Gossip] Received PULL_RESPONSE ({} bytes) from {}.{}.{}.{}:{}\n", .{
                //     pkt.len,
                //     pkt.src_addr.addr[0],
                //     pkt.src_addr.addr[1],
                //     pkt.src_addr.addr[2],
                //     pkt.src_addr.addr[3],
                //     pkt.src_addr.port(),
                // });
                try self.handlePullResponse(pkt);
            },
            .prune_message => {
                std.log.debug("[Gossip] Received PRUNE from {}.{}.{}.{}:{}\n", .{
                    pkt.src_addr.addr[0], pkt.src_addr.addr[1], pkt.src_addr.addr[2], pkt.src_addr.addr[3],
                    pkt.src_addr.port(),
                });
            },
            _ => {
                // Debug: Show first 16 bytes to diagnose the wire format issue
                self.table.stats.unknown_messages +|= 1;
                std.log.debug("[Gossip] Unknown type {} ({} bytes) from {}.{}.{}.{}:{}\n", .{
                    msg_type_raw,         pkt.len,
                    pkt.src_addr.addr[0], pkt.src_addr.addr[1],
                    pkt.src_addr.addr[2], pkt.src_addr.addr[3],
                    pkt.src_addr.port(),
                });
                std.log.debug("[Gossip] First 16 bytes: ", .{});
                const debug_len = @min(16, pkt.len);
                for (pkt.data[0..debug_len]) |b| {
                    std.log.debug("{x:0>2} ", .{b});
                }
                std.log.debug("\n", .{});
            },
        }
    }

    fn handlePing(self: *Self, pkt: *const packet.Packet) !void {
        // Bincode format: [enum_tag(4)] + [from(32)] + [token(32)] + [signature(64)] = 132 bytes
        if (pkt.len < 132) {
            std.log.debug("[Gossip] Ping too short: {} bytes (need 132)\n", .{pkt.len});
            return;
        }

        // Extract ping token (at offset 36, after enum_tag + from pubkey)
        const ping_token = pkt.data[36..68];

        // Sign the pong response
        var signature: ?core.Signature = null;
        if (self.keypair) |kp| {
            const signable = bincode.getPongSignableData(self.identity, ping_token[0..32]);
            signature = kp.sign(&signable);
        }

        // Build pong response in proper bincode format
        var response = packet.Packet.init();
        const len = bincode.buildPongMessage(
            &response.data,
            self.identity,
            ping_token[0..32],
            signature,
        ) catch {
            std.log.debug("[Gossip] Failed to build pong message\n", .{});
            return;
        };

        response.len = @intCast(len);
        response.src_addr = pkt.src_addr;

        _ = try self.sock.?.send(&response);

        // Log PONG reply (CRITICAL for debugging ping cache verification)
        std.log.debug("[Gossip] Received PING from {}.{}.{}.{}:{}, sent signed PONG ({d} bytes, sig={s})\n", .{
            pkt.src_addr.addr[0], pkt.src_addr.addr[1], pkt.src_addr.addr[2],                   pkt.src_addr.addr[3],
            pkt.src_addr.port(),  len,                  if (signature != null) "YES" else "NO",
        });
    }

    fn handlePong(self: *Self, pkt: *const packet.Packet) void {
        self.table.stats.pongs_received +|= 1;
        _ = pkt;
        // std.log.debug("[Gossip] Received PONG ({} bytes) from {}.{}.{}.{}:{}\n", .{
        //     pkt.len,
        //     pkt.src_addr.addr[0],
        //     pkt.src_addr.addr[1],
        //     pkt.src_addr.addr[2],
        //     pkt.src_addr.addr[3],
        //     pkt.src_addr.port(),
        // });
    }

    fn handlePush(self: *Self, pkt: *const packet.Packet) !void {
        self.table.stats.push_messages_received +|= 1;

        // Parse PUSH message: [enum_tag(4)] + [sender_pubkey(32)] + [vec_len(8)] + [crds_values...]
        if (pkt.len < 44) return; // Minimum: 4 + 32 + 8

        const data = pkt.data[0..pkt.len];
        var offset: usize = 4; // Skip enum tag

        // Skip sender pubkey
        offset += 32;

        // Read number of CrdsValues
        if (offset + 8 > data.len) return;
        const num_values = std.mem.readInt(u64, data[offset..][0..8], .little);
        offset += 8;

        // @prov:gossip.crds-vals-parse — parse each CrdsValue to get its exact size
        var values_parsed: u64 = 0;
        var contact_infos_found: u64 = 0;
        var i: u64 = 0;

        while (i < num_values and offset + 68 < data.len) : (i += 1) {
            // Each CrdsValue: [signature(64)] + [enum_tag(4)] + [data...]
            const crds_tag = std.mem.readInt(u32, data[offset + 64 ..][0..4], .little);

            // Exact size FIRST — needed for both the sig-verify signable bound and offset advance.
            const value_size = getCrdsValueSize(data[offset..], crds_tag, self.parse_vote_tx) orelse break;
            if (offset + value_size > data.len) break;

            // #41 CRDS sig-verify (gated; off => sig_ok stays true => byte-identical ingest).
            // Verify the two INGESTED types vs the pubkey embedded in the value (ContactInfo
            // 0/11 @ +68, EpochSlots 5 @ +69 after the u8 index — cluster_slots.zig:229).
            var sig_ok = true;
            const vmode = CrdsVerify.mode();
            if (vmode != .off) {
                if ((crds_tag == 0 or crds_tag == 11) and offset + 100 <= data.len) {
                    sig_ok = crdsSigOk(data[offset .. offset + value_size], data[offset + 68 ..][0..32]);
                    CrdsVerify.note(crds_tag, sig_ok);
                } else if (crds_tag == 5 and offset + 101 <= data.len) {
                    sig_ok = crdsSigOk(data[offset .. offset + value_size], data[offset + 69 ..][0..32]);
                    CrdsVerify.note(crds_tag, sig_ok);
                }
            }
            const drop = (vmode == .reject) and !sig_ok;

            if (!drop) {
                // Try to parse ContactInfo
                if (crds_tag == 0 or crds_tag == 11) {
                    if (try self.parseCrdsValue(data[offset..])) |peer_info| {
                        self.table.upsertContact(peer_info) catch {};
                        contact_infos_found += 1;
                    }
                } else if (crds_tag == 5) {
                    // SLOT-AWARE REPAIR: ingest EpochSlots advertisers into the index.
                    if (self.cluster_slots) |cs| {
                        if (GossipService.walkEpochSlots(data[offset..], cs) != null) {
                            cluster_slots_mod.logIngestStats(2000);
                        }
                    }
                } else if (crds_tag == 10 and SnapTrust.active()) {
                    // A3b snapshot-trust: ingest SnapshotHashes from known-validators
                    // only, verified-at-ingest. Gated ⇒ off = no work = byte-identical.
                    self.ingestSnapshotHashes(data[offset .. offset + value_size]);
                } else if (crds_tag == 1) {
                    // GOSSIP VOTE: hand the embedded vote-tx bytes to the sink (null ⇒
                    // no-op = byte-identical). Value = sig(64)+tag(4)+index(1)+from(32)+tx+wallclock(8).
                    if (self.on_gossip_vote) |cb| {
                        const hdr = 68 + 1 + 32; // sig+tag(68) + index(1) + from(32)
                        if (value_size >= hdr + 8) // room for header + trailing wallclock:u64
                            cb.func(cb.ctx, data[offset + hdr .. offset + value_size - 8]);
                    }
                }
            }
            values_parsed += 1;
            offset += value_size;
        }

        if (contact_infos_found > 0) {
            self.table.stats.values_received +|= contact_infos_found;
        }
    }

    /// #41 CRDS signature verification (gated VEX_CRDS_VERIFY=off|log|reject).
    ///   off  (default) — byte-identical to pre-#41: no verify, ingest as before.
    ///   log  — verify + per-tag pass/fail counters, STILL ingest (observe live fail-rate).
    ///   reject — drop the bad VALUE only (good values in the same batch still ingest).
    /// @prov:gossip.crds-sig-verify — upstream verifies CRDS sigs on ingest and
    /// drops invalid values. The signed bytes = the CrdsData
    /// bincode = value[64..value_size] (enum tag + fields), exactly what the originator signed.
    /// Reject must only be enabled after a live log window shows per-tag fail≈0 (our
    /// getCrdsValueSize must be byte-exact or a wrong signable would false-reject valid gossip).
    const CrdsVerify = struct {
        const Mode = enum { off, log, reject };
        var cached: ?Mode = null;
        var pass: [16]u64 = [_]u64{0} ** 16;
        var fail: [16]u64 = [_]u64{0} ** 16;
        fn mode() Mode {
            if (cached) |m| return m;
            const s = std.posix.getenv("VEX_CRDS_VERIFY") orelse "off";
            const m: Mode = if (std.mem.eql(u8, s, "reject")) .reject else if (std.mem.eql(u8, s, "log")) .log else .off;
            cached = m;
            if (m != .off) std.log.warn("[CRDS-VERIFY] mode={s} — per-tag pass/fail counters; reject drops bad VALUES only", .{s});
            return m;
        }
        fn note(tag: u32, ok: bool) void {
            const idx: usize = if (tag < 16) @intCast(tag) else 15;
            if (ok) pass[idx] +|= 1 else fail[idx] +|= 1;
            if (!ok and (fail[idx] <= 5 or fail[idx] % 500 == 0))
                std.log.warn("[CRDS-VERIFY] FAIL tag={d} fail={d} pass={d}", .{ tag, fail[idx], pass[idx] });
        }
    };

    /// ed25519-verify one parsed CRDS value. `value` MUST be trimmed to its exact size
    /// (data[offset..offset+value_size]); signable = value[64..], sig = value[0..64].
    fn crdsSigOk(value: []const u8, pubkey: *const [32]u8) bool {
        if (value.len < 64) return false;
        const Ed = std.crypto.sign.Ed25519;
        const sig = Ed.Signature.fromBytes(value[0..64].*);
        const pk = Ed.PublicKey.fromBytes(pubkey.*) catch return false;
        sig.verify(value[64..], pk) catch return false;
        return true;
    }

    /// A3b snapshot-trust gate mode (VEX_SNAPSHOT_TRUST=off|log|reject). off (default)
    /// ⇒ NO tag-10 ingest work AND no pre-vote gate ⇒ byte-identical. log ⇒ ingest +
    /// gate, present-and-mismatched only LOGS. reject ⇒ same but a present-and-mismatched
    /// vouch ABORTS before the first vote. Cached once. pub so main.zig's pre-vote gate
    /// reads the SAME mode. @prov:gossip.snapshot-trust — applied here POST-load/
    /// PRE-vote (validate the loaded snapshot) vs the canonical pre-download (choose the snapshot).
    pub const SnapTrust = struct {
        pub const Mode = enum { off, log, reject };
        var cached: ?Mode = null;
        pub fn mode() Mode {
            if (cached) |m| return m;
            const s = std.posix.getenv("VEX_SNAPSHOT_TRUST") orelse "off";
            const m: Mode = if (std.mem.eql(u8, s, "reject")) .reject else if (std.mem.eql(u8, s, "log")) .log else .off;
            cached = m;
            if (m != .off) std.log.warn("[SNAPSHOT-TRUST] mode={s} (known-validator gossip agreement; reject aborts pre-vote on mismatch)", .{s});
            return m;
        }
        pub fn active() bool {
            return mode() != .off;
        }
    };

    /// A3b: point at the trusted --known-validator set (slice owned by core Config;
    /// lives for the validator lifetime). Empty ⇒ snapshot-trust inert.
    pub fn setKnownValidators(self: *Self, kvs: []const [32]u8) void {
        self.known_validators = kvs;
    }

    /// A3b: ingest a SnapshotHashes (CRDS tag 10) value from a KNOWN-VALIDATOR,
    /// VERIFIED-at-ingest (store only sig-verified), FULL (slot,hash) only. `value`
    /// is the exact-size CrdsValue: [sig 64][tag 4][from 32 @68][full_slot u64 @100]
    /// [full_hash 32 @108][inc_len u64 @140]... Caller gates on SnapTrust.active().
    /// Verify is done HERE (independent of #41's VEX_CRDS_VERIFY) so the gate only
    /// ever trusts sig-verified known-validator values (ARCH constraint b).
    fn ingestSnapshotHashes(self: *Self, value: []const u8) void {
        if (value.len < 140) return; // need through full_hash (108+32)
        const pubkey: [32]u8 = value[68..100].*;
        // known-validator only (linear scan; a handful of keys, gated/rare path)
        var known = false;
        for (self.known_validators) |kv| {
            if (std.mem.eql(u8, &kv, &pubkey)) {
                known = true;
                break;
            }
        }
        if (!known) return;
        // verify-at-ingest, store-only-verified (independent of #41 mode)
        if (!crdsSigOk(value, &pubkey)) return;
        const full_slot = std.mem.readInt(u64, value[100..108], .little);
        const full_hash: [32]u8 = value[108..140].*;
        self.table.putSnapshotHash(pubkey, .{ .slot = full_slot, .hash = full_hash });
    }

    /// A3b: a known-validator's advertised full snapshot (slot,hash), or null if it
    /// hasn't advertised yet. Read-locked. Consumed by main.zig's pre-vote gate.
    pub fn getSnapshotHashes(self: *Self, pubkey: [32]u8) ?crds.SlotHash {
        return self.table.getSnapshotHash(pubkey);
    }

    /// Calculate the exact size of a CrdsValue by parsing its structure
    /// @prov:gossip.crds-value-size
    fn getCrdsValueSize(data: []const u8, crds_tag: u32, parse_vote_tx: ?*const fn ([]const u8) ?usize) ?usize {
        @setRuntimeSafety(false);
        // CrdsValue = signature(64) + tag(4) + data
        const header_size: usize = 64 + 4;
        if (data.len < header_size) return null;

        var offset: usize = header_size;

        switch (crds_tag) {
            0 => { // LegacyContactInfo: pubkey(32) + 10x sockets + wallclock(8) + shred_version(2)
                // Each socket: family(4) + ip4(4)+port(2) or ip6(16)+port(2)+flowinfo(4)+scope(4)
                offset += 32; // pubkey
                var socket_idx: usize = 0;
                while (socket_idx < 10) : (socket_idx += 1) {
                    if (offset + 4 > data.len) return null;
                    const is_ip6 = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;
                    if (is_ip6 == 0) {
                        offset += 4 + 2; // ip4 + port
                    } else {
                        offset += 16 + 2 + 4 + 4; // ip6 + port + flowinfo + scope
                    }
                }
                offset += 8 + 2; // wallclock + shred_version
            },
            11 => { // ContactInfo (modern) - variable size with compact_u16
                offset += 32; // pubkey
                // Skip varint wallclock
                while (offset < data.len) {
                    const byte = data[offset];
                    offset += 1;
                    if ((byte & 0x80) == 0) break;
                }
                offset += 8 + 2; // instance_creation + shred_version
                // Skip version (3 varints + 2 u32s + 1 varint)
                var vi: usize = 0;
                while (vi < 4) : (vi += 1) { // major, minor, patch, client
                    while (offset < data.len) {
                        const byte = data[offset];
                        offset += 1;
                        if ((byte & 0x80) == 0) break;
                    }
                    if (vi == 2) offset += 8; // commit + feature_set after patch
                }
                // Skip addresses (compact_u16 len + entries)
                if (offset >= data.len) return null;
                const addr_count = readCompactU16(data[offset..]) orelse return null;
                offset += compactU16Size(addr_count);
                var ai: u16 = 0;
                while (ai < addr_count) : (ai += 1) {
                    if (offset + 4 > data.len) return null;
                    const is_ip6 = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;
                    offset += if (is_ip6 == 0) 4 else 16;
                }
                // Skip sockets (compact_u16 len + entries)
                if (offset >= data.len) return null;
                const socket_count = readCompactU16(data[offset..]) orelse return null;
                offset += compactU16Size(socket_count);
                var si: u16 = 0;
                while (si < socket_count) : (si += 1) {
                    offset += 2; // tag + addr_idx
                    if (offset >= data.len) return null;
                    const port_offset = readCompactU16(data[offset..]) orelse return null;
                    offset += compactU16Size(port_offset);
                }
                // Skip extensions
                if (offset >= data.len) return null;
                const ext_count = readCompactU16(data[offset..]) orelse return null;
                offset += compactU16Size(ext_count);
                const ext_bytes = @as(usize, ext_count) *| 4;
                offset +|= ext_bytes;
            },
            1 => { // Vote: index(1) + pubkey(32) + txn(variable, NO length prefix) + wallclock(8)
                const tx_start = offset + 1 + 32; // index:u8 + from[32]
                if (parse_vote_tx) |pf| {
                    if (tx_start > data.len) return null;
                    const consumed = pf(data[tx_start..]) orelse return null; // exact tx length
                    offset = tx_start + consumed + 8; // + trailing wallclock:u64
                } else {
                    offset = tx_start + 100 + 8; // legacy estimate (no parser injected → pre-fix behavior)
                }
            },
            2 => { // LowestSlot: index(1) + pubkey(32) + root(8) + slot(8) + slots_len(8) + stash_len(8) + wallclock(8)
                offset += 1 + 32 + 8 + 8 + 8 + 8 + 8;
            },
            3, 4 => { // AccountHashes/LegacySnapshotHashes: pubkey(32) + hashes_len(8) + hashes + wallclock(8)
                offset += 32;
                if (offset + 8 > data.len) return null;
                const hashes_len = std.mem.readInt(u64, data[offset..][0..8], .little);
                if (hashes_len > 10000) return null; // sanity check
                offset +|= 8 +| (@as(usize, @intCast(hashes_len)) *| 40) +| 8;
            },
            5 => { // EpochSlots: walk the exact wire size (was a wrong `+= 200`
                // estimate that desynced every subsequent CrdsValue in any
                // packet containing an EpochSlots). Layout verified against
                // Agave 4.1.0-beta.3 bincode dump (see walkEpochSlots).
                // MUST pass the FULL CrdsValue slice `data` (starting at the
                // signature) — parseEpochSlotsInto skips sig+tag(+index) itself.
                // Passing data[offset..] (offset already == header_size, past
                // sig+tag) caused a DOUBLE-skip → mis-read → null → the packet
                // walk's `orelse break` TRUNCATED, silently dropping every
                // trailing CrdsValue (ContactInfos + later EpochSlots). The walker
                // returns the full value size, so early-return it directly.
                return GossipService.walkEpochSlots(data, null);
            },
            6 => { // LegacyVersion: pubkey(32) + wallclock(8) + version(6) + has_commit(1) + commit?(4)
                offset += 32 + 8 + 6 + 1;
                if (offset < data.len and data[offset - 1] != 0) offset += 4;
            },
            7 => { // Version: LegacyVersion + feature_set(4)
                offset += 32 + 8 + 6 + 1;
                if (offset < data.len and data[offset - 1] != 0) offset += 4;
                offset += 4;
            },
            8 => { // NodeInstance: pubkey(32) + wallclock(8) + timestamp(8) + token(8)
                offset += 32 + 8 + 8 + 8;
            },
            9 => { // DuplicateShred (CRDS type 9) — EXACT walk.
                // @prov:gossip.dup-shred-wire
                //   DuplicateShred(DuplicateShredIndex /*u16*/, DuplicateShred).
                // After the u32 tag (already consumed in `header_size`) the wire is:
                //   index:u16 | from:[32] | wallclock:u64 | slot:u64 | _unused:u32
                //   | _unused_shred_type:u8 | num_chunks:u8 | chunk_index:u8
                //   | chunk_len:u64 | chunk bytes.
                // The OLD `+= 200` placeholder mis-sized any packet carrying a
                // tag-9 value, truncating (via the caller's `orelse break`) every
                // trailing CrdsValue. Fixed header = 2+32+8+8+4+1+1+1 = 57 bytes,
                // then a u64 chunk_len + chunk bytes.
                offset += 2 + 32 + 8 + 8 + 4 + 1 + 1 + 1; // = 57 (index..chunk_index)
                if (offset + 8 > data.len) return null;
                const chunk_len = std.mem.readInt(u64, data[offset..][0..8], .little);
                // Sanity bound: a single chunk is at most DUPLICATE_SHRED_MAX
                // (1232 - 115 = 1117); reject absurd lengths to avoid overflow.
                if (chunk_len > 4096) return null;
                offset +|= 8 +| @as(usize, @intCast(chunk_len));
            },
            10 => { // SnapshotHashes: pubkey(32) + full(40) + inc_len(8) + incs + wallclock(8)
                offset += 32 + 40;
                if (offset + 8 > data.len) return null;
                const inc_len = std.mem.readInt(u64, data[offset..][0..8], .little);
                if (inc_len > 10000) return null; // sanity check
                offset +|= 8 +| (@as(usize, @intCast(inc_len)) *| 40) +| 8;
            },
            else => {
                // Unknown type - can't determine size
                return null;
            },
        }

        return if (offset <= data.len) offset else null;
    }

    /// SLOT-AWARE REPAIR (2026-06-14): thin wrapper over the pure wire walker in
    /// cluster_slots.zig (kept there so it is unit-testable without dragging the
    /// socket-heavy gossip module into a `zig test` graph). Returns the exact
    /// CrdsValue byte size (or null on short/hostile input), and ingests
    /// advertisers when `cs` is non-null. See cluster_slots.parseEpochSlotsInto.
    fn walkEpochSlots(data: []const u8, cs: ?*cluster_slots_mod.ClusterSlots) ?usize {
        return cluster_slots_mod.parseEpochSlotsInto(data, cs);
    }

    /// Read a compact_u16 value
    fn readCompactU16(data: []const u8) ?u16 {
        if (data.len == 0) return null;
        if (data[0] & 0x80 == 0) {
            return data[0];
        }
        if (data.len < 2) return null;
        if (data[1] & 0x80 == 0) {
            return @as(u16, @intCast(data[0] & 0x7F)) | (@as(u16, @intCast(data[1])) << 7);
        }
        if (data.len < 3) return null;
        return @as(u16, @intCast(data[0] & 0x7F)) |
            (@as(u16, @intCast(data[1] & 0x7F)) << 7) |
            (@as(u16, @intCast(data[2])) << 14);
    }

    /// Get size of compact_u16 encoding
    fn compactU16Size(value: u16) usize {
        if (value < 0x80) return 1;
        if (value < 0x4000) return 2;
        return 3;
    }

    fn handlePullRequest(self: *Self, pkt: *const packet.Packet) !void {
        if (self.sock == null) return;
        if (self.modern_contact_info == null) return;

        const now_ms = std.time.milliTimestamp();
        if (self.modern_contact_info) |*info| {
            info.wallclock_ms = @intCast(now_ms);
        }

        var pkt_out = packet.Packet.init();
        const sender_pubkey = self.identity;

        // Respond with modern ContactInfo only (LegacyContactInfo is deprecated in v3.1.10+)
        if (self.modern_contact_info) |*modern| {
            var modern_sig: ?core.Signature = null;
            if (self.keypair) |kp| {
                var signable: [512]u8 = undefined;
                const signable_len = bincode.getContactInfoSignableData(modern, &signable) catch 0;
                if (signable_len > 0) {
                    modern_sig = kp.sign(signable[0..signable_len]);
                }
            }
            const len = bincode.buildPullResponseWithContactInfo(
                &pkt_out.data,
                sender_pubkey,
                modern,
                modern_sig,
            ) catch |err| {
                std.log.debug("[Gossip] Failed to build pull response: {}\n", .{err});
                return;
            };
            pkt_out.len = @intCast(len);
            pkt_out.src_addr = pkt.src_addr;
            _ = self.sock.?.send(&pkt_out) catch {};
        }
    }

    fn handlePullResponse(self: *Self, pkt: *const packet.Packet) !void {
        self.table.stats.pull_responses_received +|= 1;

        // Parse PULL_RESPONSE: [enum_tag(4)] + [pubkey(32)] + [vec_len(8)] + [crds_values...]
        // Note: PULL_RESPONSE has pubkey after tag (unlike PUSH which has it before vec_len)
        if (pkt.len < 44) return; // 4 + 32 + 8

        const data = pkt.data[0..pkt.len];
        var offset: usize = 4; // Skip enum tag

        // Skip sender pubkey (PULL_RESPONSE has pubkey here)
        offset += 32;

        // Read number of CrdsValues
        if (offset + 8 > data.len) return;
        const num_values = std.mem.readInt(u64, data[offset..][0..8], .little);
        offset += 8;

        // @prov:gossip.crds-vals-parse — parse each CrdsValue to get its exact size
        var values_parsed: u64 = 0;
        var contact_infos_found: u64 = 0;
        var i: u64 = 0;

        while (i < num_values and offset + 68 < data.len) : (i += 1) {
            // Each CrdsValue: [signature(64)] + [enum_tag(4)] + [data...]
            const crds_tag = std.mem.readInt(u32, data[offset + 64 ..][0..4], .little);

            // Exact size FIRST — needed for both the sig-verify signable bound and offset advance.
            const value_size = getCrdsValueSize(data[offset..], crds_tag, self.parse_vote_tx) orelse break;
            if (offset + value_size > data.len) break;

            // #41 CRDS sig-verify (gated; off => byte-identical). Same as handlePush.
            var sig_ok = true;
            const vmode = CrdsVerify.mode();
            if (vmode != .off) {
                if ((crds_tag == 0 or crds_tag == 11) and offset + 100 <= data.len) {
                    sig_ok = crdsSigOk(data[offset .. offset + value_size], data[offset + 68 ..][0..32]);
                    CrdsVerify.note(crds_tag, sig_ok);
                } else if (crds_tag == 5 and offset + 101 <= data.len) {
                    sig_ok = crdsSigOk(data[offset .. offset + value_size], data[offset + 69 ..][0..32]);
                    CrdsVerify.note(crds_tag, sig_ok);
                }
            }
            const drop = (vmode == .reject) and !sig_ok;

            if (!drop) {
                // Try to parse ContactInfo
                if (crds_tag == 0 or crds_tag == 11) {
                    if (try self.parseCrdsValue(data[offset..])) |peer_info| {
                        self.table.upsertContact(peer_info) catch {};
                        contact_infos_found += 1;
                    }
                } else if (crds_tag == 5) {
                    // SLOT-AWARE REPAIR: ingest EpochSlots advertisers into the index.
                    if (self.cluster_slots) |cs| {
                        if (GossipService.walkEpochSlots(data[offset..], cs) != null) {
                            cluster_slots_mod.logIngestStats(2000);
                        }
                    }
                } else if (crds_tag == 10 and SnapTrust.active()) {
                    // A3b snapshot-trust: ingest SnapshotHashes from known-validators
                    // only, verified-at-ingest. Gated ⇒ off = no work = byte-identical.
                    self.ingestSnapshotHashes(data[offset .. offset + value_size]);
                } else if (crds_tag == 1) {
                    // GOSSIP VOTE: hand the embedded vote-tx bytes to the sink (null ⇒
                    // no-op = byte-identical). Value = sig(64)+tag(4)+index(1)+from(32)+tx+wallclock(8).
                    if (self.on_gossip_vote) |cb| {
                        const hdr = 68 + 1 + 32; // sig+tag(68) + index(1) + from(32)
                        if (value_size >= hdr + 8) // room for header + trailing wallclock:u64
                            cb.func(cb.ctx, data[offset + hdr .. offset + value_size - 8]);
                    }
                }
            }
            values_parsed += 1;
            offset += value_size;
        }

        if (contact_infos_found > 0) {
            const total = self.table.stats.values_received + contact_infos_found;
            if (total < 20 or total % 100 == 0) {
                std.log.debug("[Gossip] PULL_RESPONSE: found {} ContactInfos ({} values scanned, {} total peers)\n", .{ contact_infos_found, values_parsed, self.table.contactCount() });
            }
        }

        self.table.stats.values_received +|= contact_infos_found;
    }

    /// Parse a CrdsValue and extract ContactInfo if it's a ContactInfo type
    fn parseCrdsValue(self: *Self, data: []const u8) !?ContactInfo {
        _ = self;

        // CrdsValue format: [signature(64)] + [enum_tag(4)] + [data...]
        if (data.len < 68) return null;

        // Skip signature
        var offset: usize = 64;

        // Read CrdsData enum tag
        const crds_tag = std.mem.readInt(u32, data[offset..][0..4], .little);
        offset += 4;

        // Debug: track tags we see (only first few times)
        const S = struct {
            var tag_counts: [20]u32 = [_]u32{0} ** 20;
            var logged: bool = false;
        };
        if (crds_tag < 20) {
            S.tag_counts[crds_tag] +|= 1;
            if (!S.logged and S.tag_counts[0] +| S.tag_counts[11] > 50) {
                S.logged = true;
                std.log.debug("[Gossip] CRDS tag stats: tag0={} tag11={} tag1={} tag2={} tag3={}\n", .{
                    S.tag_counts[0], S.tag_counts[11], S.tag_counts[1], S.tag_counts[2], S.tag_counts[3],
                });
            }
        }

        // Only parse ContactInfo (tag 11) and LegacyContactInfo (tag 0)
        // These parse untrusted network data — catch ALL errors and return null
        if (crds_tag == 11) {
            return parseModernContactInfo(data[offset..]) catch return null;
        } else if (crds_tag == 0) {
            return parseLegacyContactInfo(data[offset..]) catch return null;
        }

        return null;
    }

    /// Parse LegacyContactInfo to extract peer address
    /// Safety disabled: untrusted network data (same rationale as parseModernContactInfo)
    fn parseLegacyContactInfo(data: []const u8) !?ContactInfo {
        @setRuntimeSafety(false);
        // Format: pubkey(32) + 10x sockets + wallclock(8) + shred_version(2)
        if (data.len < 134) {
            // Debug: track why parsing fails
            const S = struct {
                var too_short: u32 = 0;
            };
            S.too_short += 1;
            if (S.too_short < 5) {
                std.log.debug("[Gossip] LegacyContactInfo too short: {} bytes (need 134)\n", .{data.len});
            }
            return null;
        }

        var info = ContactInfo{
            .pubkey = undefined,
            .gossip_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_fwd_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_vote_addr = packet.SocketAddr.UNSPECIFIED,
            .tvu_addr = packet.SocketAddr.UNSPECIFIED,
            .tvu_fwd_addr = packet.SocketAddr.UNSPECIFIED,
            .repair_addr = packet.SocketAddr.UNSPECIFIED,
            .serve_repair_addr = packet.SocketAddr.UNSPECIFIED,
            .rpc_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_quic_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_vote_quic_addr = packet.SocketAddr.UNSPECIFIED,
            .tvu_quic_addr = packet.SocketAddr.UNSPECIFIED,
            .wallclock = 0,
            .shred_version = 0,
            .version = .{ .major = 0, .minor = 0, .patch = 0, .commit = null },
        };

        @memcpy(&info.pubkey.data, data[0..32]);

        var offset: usize = 32;

        // Parse sockets in LegacyContactInfo order:
        // 0=gossip, 1=tvu, 2=tvu_fwd, 3=repair, 4=tpu, 5=tpu_fwd, 6=tpu_vote, 7=rpc, 8=rpc_pubsub, 9=serve_repair
        inline for (0..10) |i| {
            if (offset + 6 > data.len) return null;
            const family = std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;

            if (family == 0) { // IPv4
                if (offset + 6 > data.len) return null;
                const ip = data[offset..][0..4].*;
                offset += 4;
                const port_val = std.mem.readInt(u16, data[offset..][0..2], .little);
                offset += 2;

                const addr = packet.SocketAddr.ipv4(ip, port_val);

                switch (i) {
                    0 => info.gossip_addr = addr,
                    1 => info.tvu_addr = addr,
                    3 => info.repair_addr = addr,
                    4 => info.tpu_addr = addr,
                    6 => info.tpu_vote_addr = addr, // TPU vote port
                    7 => info.rpc_addr = addr,
                    9 => info.serve_repair_addr = addr,
                    else => {},
                }
            } else {
                // IPv6 - skip
                offset += 22;
            }
        }

        // Parse wallclock and shred_version
        if (offset + 10 <= data.len) {
            info.wallclock = std.mem.readInt(u64, data[offset..][0..8], .little);
            offset += 8;
            info.shred_version = std.mem.readInt(u16, data[offset..][0..2], .little);
        }

        // Initialize QUIC ports based on heuristic for legacy nodes
        if (info.tpu_addr.port() != 0) {
            info.tpu_quic_addr = packet.SocketAddr.ipv4(info.tpu_addr.addr[0..4].*, info.tpu_addr.port() + 6);
        }
        if (info.tvu_addr.port() != 0) {
            info.tvu_quic_addr = packet.SocketAddr.ipv4(info.tvu_addr.addr[0..4].*, info.tvu_addr.port() + 6);
        }

        // Validate - must have valid gossip address
        if (info.gossip_addr.port() == 0) {
            const S = struct {
                var no_gossip: u32 = 0;
            };
            S.no_gossip += 1;
            if (S.no_gossip < 5) {
                std.log.debug("[Gossip] LegacyContactInfo has no gossip port\n", .{});
            }
            return null;
        }

        return info;
    }

    /// Parse modern ContactInfo to extract peer address
    /// @prov:gossip.parse-modern-contact-info
    /// @setRuntimeSafety(false): This function processes untrusted network data.
    /// Malformed packets can trigger integer overflows in compact_u16 decoding,
    /// varint parsing, and port accumulation. We have manual bounds checks throughout,
    /// but ReleaseSafe's panic-on-overflow would crash the entire validator for a
    /// single bad gossip packet. All parse errors are treated as
    /// "skip this value" rather than crashing.
    fn parseModernContactInfo(data: []const u8) !?ContactInfo {
        @setRuntimeSafety(false);
        if (data.len < 32) return null; // Need at least pubkey

        var info = ContactInfo{
            .pubkey = undefined,
            .gossip_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_fwd_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_vote_addr = packet.SocketAddr.UNSPECIFIED,
            .tvu_addr = packet.SocketAddr.UNSPECIFIED,
            .tvu_fwd_addr = packet.SocketAddr.UNSPECIFIED,
            .repair_addr = packet.SocketAddr.UNSPECIFIED,
            .serve_repair_addr = packet.SocketAddr.UNSPECIFIED,
            .rpc_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_quic_addr = packet.SocketAddr.UNSPECIFIED,
            .tpu_vote_quic_addr = packet.SocketAddr.UNSPECIFIED,
            .tvu_quic_addr = packet.SocketAddr.UNSPECIFIED,
            .wallclock = 0,
            .shred_version = 0,
            .version = .{ .major = 0, .minor = 0, .patch = 0, .commit = null },
        };

        var offset: usize = 0;

        // 1. Pubkey (32 bytes)
        @memcpy(&info.pubkey.data, data[offset..][0..32]);
        offset += 32;

        // 2. Wallclock varint (milliseconds)
        var wallclock_varint: u64 = 0;
        var shift: u32 = 0;
        while (offset < data.len) {
            if (shift >= 64) return null; // Varint too large
            const byte = data[offset];
            offset += 1;
            wallclock_varint |= (@as(u64, byte & 0x7F) << @intCast(shift));
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        info.wallclock = wallclock_varint;

        // 3. Instance creation wallclock (8 bytes, microseconds)
        if (offset + 8 > data.len) return null;
        _ = std.mem.readInt(u64, data[offset..][0..8], .little); // Skip for now
        offset += 8;

        // 4. Shred version (2 bytes)
        if (offset + 2 > data.len) return null;
        info.shred_version = std.mem.readInt(u16, data[offset..][0..2], .little);
        offset += 2;

        // 5. Version info (varints + u32s) - parse to skip correctly
        // @prov:gossip.parse-modern-contact-info — version_parse()
        // Format: major(varint) + minor(varint) + patch(varint) + commit(u32) + feature_set(u32) + client(varint)
        // Skip major varint
        while (offset < data.len) {
            const byte = data[offset];
            offset += 1;
            if ((byte & 0x80) == 0) break;
        }
        // Skip minor varint
        while (offset < data.len) {
            const byte = data[offset];
            offset += 1;
            if ((byte & 0x80) == 0) break;
        }
        // Skip patch varint
        while (offset < data.len) {
            const byte = data[offset];
            offset += 1;
            if ((byte & 0x80) == 0) break;
        }
        // Skip commit (u32) + feature_set (u32) = 8 bytes
        if (offset + 8 > data.len) return null;
        offset += 8;
        // Skip client varint
        while (offset < data.len) {
            const byte = data[offset];
            offset += 1;
            if ((byte & 0x80) == 0) break;
        }

        // 6. Addresses array: [count(compact_u16)] + [addresses...]
        // @prov:gossip.parse-modern-contact-info — compact_u16, NOT regular varint!
        if (offset >= data.len) return null;
        var addr_count: u16 = 0;
        var addr_count_bytes: usize = 0;
        // Compact_u16 decoding — decode in u32 to prevent overflow, then truncate safely
        if (data[offset] & 0x80 == 0) {
            addr_count = data[offset];
            addr_count_bytes = 1;
        } else if (offset + 1 < data.len and (data[offset + 1] & 0x80) == 0) {
            const wide = @as(u32, data[offset] & 0x7F) | (@as(u32, data[offset + 1]) << 7);
            if (wide > 65535) return null;
            addr_count = @intCast(wide);
            addr_count_bytes = 2;
        } else if (offset + 2 < data.len) {
            const wide = @as(u32, data[offset] & 0x7F) |
                (@as(u32, data[offset + 1] & 0x7F) << 7) |
                (@as(u32, data[offset + 2]) << 14);
            if (wide > 65535) return null;
            addr_count = @intCast(wide);
            addr_count_bytes = 3;
        } else {
            return null;
        }
        offset += addr_count_bytes;

        // Each address: [enum_discriminant(4)] + [ip(4 or 16)]
        // @prov:gossip.parse-modern-contact-info
        var addresses: [16][4]u8 = undefined;
        var addr_idx: u16 = 0;
        // Parse up to 16 addresses (array size limit)
        while (addr_idx < addr_count and addr_idx < 16 and offset + 8 <= data.len) : (addr_idx += 1) {
            const is_ip6 = std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;
            if (is_ip6 == 0) {
                // IPv4
                @memcpy(&addresses[@intCast(addr_idx)], data[offset..][0..4]);
                offset += 4;
            } else {
                // IPv6 - skip for now
                offset += 16;
                addresses[@intCast(addr_idx)] = .{ 0, 0, 0, 0 }; // Mark as null
            }
        }
        // Track actual addresses parsed (may be less than addr_count)
        const actual_addr_count = addr_idx;

        // 7. Socket entries: [count(compact_u16)] + [entries...]
        // @prov:gossip.parse-modern-contact-info — compact_u16, NOT regular varint!
        if (offset >= data.len) return null;
        var socket_count: u16 = 0;
        var socket_count_bytes: usize = 0;
        // Compact_u16 decoding — decode in u32 to prevent overflow, then truncate safely
        if (data[offset] & 0x80 == 0) {
            socket_count = data[offset];
            socket_count_bytes = 1;
        } else if (offset + 1 < data.len and (data[offset + 1] & 0x80) == 0) {
            const wide = @as(u32, data[offset] & 0x7F) | (@as(u32, data[offset + 1]) << 7);
            if (wide > 65535) return null;
            socket_count = @intCast(wide);
            socket_count_bytes = 2;
        } else if (offset + 2 < data.len) {
            const wide = @as(u32, data[offset] & 0x7F) |
                (@as(u32, data[offset + 1] & 0x7F) << 7) |
                (@as(u32, data[offset + 2]) << 14);
            if (wide > 65535) return null;
            socket_count = @intCast(wide);
            socket_count_bytes = 3;
        } else {
            return null;
        }
        offset += socket_count_bytes;

        // Each socket entry: [tag(1)] + [addr_index(1)] + [port_offset(compact_u16)]
        // @prov:gossip.parse-modern-contact-info — ports are cumulative offsets
        var cur_port: u16 = 0;
        var i: u16 = 0;
        while (i < socket_count and offset < data.len) : (i += 1) {
            if (offset >= data.len) break;
            const tag = data[offset];
            offset += 1;
            if (offset >= data.len) break;
            const addr_index = data[offset];
            offset += 1;

            // @prov:gossip.parse-modern-contact-info — port_offset as compact_u16
            if (offset >= data.len) break;
            var port_offset: u16 = 0;
            var port_offset_bytes: usize = 0;
            // Compact_u16 decoding — u32 first, truncate safely
            if (data[offset] & 0x80 == 0) {
                port_offset = data[offset];
                port_offset_bytes = 1;
            } else if (offset + 1 < data.len and (data[offset + 1] & 0x80) == 0) {
                const wide = @as(u32, data[offset] & 0x7F) | (@as(u32, data[offset + 1]) << 7);
                if (wide > 65535) break;
                port_offset = @intCast(wide);
                port_offset_bytes = 2;
            } else if (offset + 2 < data.len) {
                const wide = @as(u32, data[offset] & 0x7F) |
                    (@as(u32, data[offset + 1] & 0x7F) << 7) |
                    (@as(u32, data[offset + 2]) << 14);
                if (wide > 65535) break;
                port_offset = @intCast(wide);
                port_offset_bytes = 3;
            } else {
                break;
            }
            offset += port_offset_bytes;

            // @prov:gossip.parse-modern-contact-info — ports are cumulative offsets,
            // ALWAYS accumulate. This must happen BEFORE the validity check.
            // Use saturating add to prevent overflow from malformed network data
            const wide_port = @as(u32, cur_port) +| @as(u32, port_offset);
            cur_port = if (wide_port > 65535) 65535 else @as(u16, @intCast(wide_port));

            // @prov:gossip.socket-tags — map socket tag to ContactInfo field.
            // Use actual_addr_count (addresses actually parsed) not addr_count (declared in wire format)
            // Also bounds check against array size (16) to prevent out-of-bounds access
            if (addr_index < actual_addr_count and addr_index < 16 and addresses[addr_index][0] != 0) {
                const ip = addresses[addr_index];
                const addr = packet.SocketAddr.ipv4(ip, cur_port);

                // Modern SocketTag values:
                // 0=gossip, 1=repair, 2=rpc, 3=rpc_pubsub, 4=serve_repair,
                // 5=tpu, 6=tpu_forwards, 7=tpu_forwards_quic, 8=tpu_quic,
                // 9=tpu_vote, 10=turbine_recv (tvu), 11=turbine_recv_quic,
                // 12=tpu_vote_quic (dedicated vote QUIC port)
                switch (tag) {
                    0 => info.gossip_addr = addr, // gossip
                    1 => info.repair_addr = addr, // repair
                    2 => info.rpc_addr = addr, // rpc
                    4 => info.serve_repair_addr = addr, // serve_repair
                    5 => info.tpu_addr = addr, // tpu
                    8 => info.tpu_quic_addr = addr, // tpu_quic
                    9 => info.tpu_vote_addr = addr, // tpu_vote
                    10 => info.tvu_addr = addr, // turbine_recv (tvu)
                    11 => info.tvu_quic_addr = addr, // turbine_recv_quic
                    12 => info.tpu_vote_quic_addr = addr, // tpu_vote_quic (dedicated vote QUIC port)
                    else => {},
                }
            }
        }

        // Validate - must have valid gossip address
        if (info.gossip_addr.port() == 0) return null;

        return info;
    }

    /// Run one iteration of the gossip protocol
    pub fn tick(self: *Self) !void {
        if (self.sock == null) return error.NotStarted;

        // Receive and process incoming packets
        var batch = try packet.PacketBatch.init(self.allocator, 64);
        defer batch.deinit();

        _ = try self.sock.?.recvBatch(&batch);
        try self.processPackets(&batch);

        // Prune stale contacts periodically
        _ = self.table.pruneStale(self.config.contact_timeout_ms);
    }
    /// Process incoming messages (called from main loop)
    /// This does the full gossip communication cycle
    pub fn processMessages(self: *Self) !void {
        if (self.sock == null) return;

        // Non-blocking receive
        var batch = packet.PacketBatch.init(self.allocator, 16) catch return;
        defer batch.deinit();

        // Try to receive packets (do not skip periodic tasks on WouldBlock)
        const received = self.sock.?.recvBatch(&batch) catch |err| blk: {
            if (err == error.WouldBlock) break :blk 0;
            return err;
        };

        // Process received packets — track stats (was missing in processMessages path!)
        if (received > 0) {
            self.table.stats.packets_received += received;

            // Diagnostic: log every packet type we receive (first 200 packets)
            if (self.table.stats.packets_received < 200 or self.table.stats.packets_received % 100 == 0) {
                for (batch.slice()) |*pkt| {
                    if (pkt.len >= 4) {
                        const msg_type_raw = std.mem.readInt(u32, pkt.data[0..4], .little);
                        std.log.debug("[Gossip] RX packet: type={d} len={d} from={d}.{d}.{d}.{d}:{d}\n", .{
                            msg_type_raw,         pkt.len,
                            pkt.src_addr.addr[0], pkt.src_addr.addr[1],
                            pkt.src_addr.addr[2], pkt.src_addr.addr[3],
                            pkt.src_addr.port(),
                        });
                    }
                }
            }

            self.processPackets(&batch) catch {};
        }

        // Do periodic gossip tasks with timing
        const now = std.time.milliTimestamp();

        // Send pull requests every 1 second (to discover peers)
        if (now - self.last_pull_time >= 1000) {
            self.sendPullRequests() catch {};
            self.last_pull_time = now;

            // Log pull attempt for debugging
            if (self.table.contactCount() == 0 and self.entrypoints.items.len > 0) {
                std.log.debug("[Gossip] Sending pull to {d} entrypoints (no peers yet)\n", .{self.entrypoints.items.len});
            }
        }

        // Push our contact info every 2 seconds
        if (now - self.last_push_time >= 2000) {
            self.pushToPeers() catch {};
            self.last_push_time = now;
        }

        // Ping entrypoints every 5 seconds
        if (now - self.last_ping_time >= 5000) {
            self.pingEntrypoints() catch {};
            self.last_ping_time = now;

            // Diagnostic: print gossip health every 10 seconds
            const S2 = struct {
                var last_diag: i64 = 0;
            };
            if (now - S2.last_diag >= 10000) {
                S2.last_diag = now;
                const stats = self.table.stats;
                const sock_fd = if (self.sock) |s| s.fd else -1;
                const bound = if (self.sock) |s| s.boundPort() else null;
                std.log.debug(
                    \\[Gossip] ═══ HEALTH ═══
                    \\  fd={d} bound_port={any}
                    \\  entrypoints={d} contacts={d}
                    \\  pings_sent={d} pongs_rcvd={d}
                    \\  pulls_sent={d} pull_resp_rcvd={d}
                    \\  push_rcvd={d} packets_rcvd={d}
                    \\  unknown={d}
                    \\════════════════════════
                    \\
                , .{
                    sock_fd,                      bound,
                    self.entrypoints.items.len,   self.table.contactCount(),
                    stats.pings_sent,             stats.pongs_received,
                    stats.pull_requests_sent,     stats.pull_responses_received,
                    stats.push_messages_received, stats.packets_received,
                    stats.unknown_messages,
                });
            }
        }
    }

    /// Ping all entrypoints
    fn pingEntrypoints(self: *Self) !void {
        for (self.entrypoints.items) |ep| {
            self.sendPing(ep) catch {};
            std.log.debug("[Gossip] Sent PING to {}.{}.{}.{}:{}\n", .{
                ep.addr[0], ep.addr[1], ep.addr[2], ep.addr[3], ep.port(),
            });
        }
    }

    /// Stop the gossip service
    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
        if (self.sock) |*s| {
            s.deinit();
            self.sock = null;
        }
    }

    /// Get statistics
    pub fn getStats(self: *const Self) GossipTable.Stats {
        return self.table.stats;
    }

    /// Get number of known peers
    pub fn peerCount(self: *const Self) usize {
        return self.table.contactCount();
    }

    /// Run the gossip service loop (call from a dedicated thread)
    /// Optimized: Pre-converts interval configs and caches timestamp
    pub fn run(self: *Self) !void {
        self.running.store(true, .release);

        std.log.info("[Gossip] Starting gossip loop", .{});

        // Pre-convert config intervals to i64 to avoid repeated casts
        const pull_interval: i64 = @intCast(self.config.pull_interval_ms);
        const push_interval: i64 = @intCast(self.config.push_interval_ms);
        const ping_interval: i64 = @intCast(self.config.ping_interval_ms);

        // Pre-allocate packet batch to avoid per-iteration allocation
        var batch = packet.PacketBatch.init(self.allocator, 64) catch {
            std.log.err("[Gossip] Failed to allocate packet batch", .{});
            return error.OutOfMemory;
        };
        defer batch.deinit();

        while (self.running.load(.acquire)) {
            // Single timestamp call per iteration
            const now = std.time.milliTimestamp();

            // 1. DRAIN incoming packets — keep reading until socket is empty.
            //    Bounded at 64 passes for fairness (periodic tasks below still run).
            //    @prov:gossip.drain-loop
            //
            //    Math: batch capacity 64 × cap 64 passes = 4096 packets/iter.
            //    At 2ms cadence ⇒ 2 MPPS ceiling. Typical cluster gossip <100 KPPS,
            //    so we drain into idle within ~32 passes during normal load.
            //
            //    Bug fixed (2026-05-26): old code did ONE recvBatch then sleep(10ms).
            //    `recvBatch` is single-syscall (`recvmmsg` in socket.zig:228), so
            //    socket buffer overflowed between polls — kernel UDP queue 8001 was
            //    seen at 206 MB with 810K drops, starving gossip → can't find peers
            //    → repair stalls → CHAIN-DEFER terminal. See vault/GOSSIP_DRAIN_LOOP_FIX_DRAFT_2026_05_26.md.
            var drain_passes: usize = 0;
            while (drain_passes < 64) : (drain_passes += 1) {
                const got = self.receiveAndProcessWithBatch(&batch) catch |err| {
                    std.log.warn("[Gossip] Receive error: {}", .{err});
                    break;
                };
                if (got == 0) break; // socket drained
            }

            // 2. Periodic pull from peers
            if (now - self.last_pull_time >= pull_interval) {
                self.sendPullRequests() catch {};
                self.last_pull_time = now;
            }

            // 3. Periodic push to peers
            if (now - self.last_push_time >= push_interval) {
                self.pushToPeers() catch {};
                self.last_push_time = now;
            }

            // 3b. DUPLICATE-SHRED (CRDS type 9) PUSH. Drain detected equivocations
            //     and push signed proofs. Gated comptime (-Dduplicate_shred) AND
            //     by env (VEX_DUPLICATE_SHRED=1) — dormant by default. Detection in
            //     the FEC resolver always runs; only this outbound push is gated.
            //     comptime-skipped entirely when the flag is off (zero overhead).
            if (comptime build_options.duplicate_shred) {
                if (dupShredPushEnabled()) {
                    self.drainAndPushDuplicateShreds();
                }
            }

            // 4. Periodic ping (health check)
            if (now - self.last_ping_time >= ping_interval) {
                self.pingEntrypoints() catch {};
                self.last_ping_time = now;
            }

            // 5. Prune stale contacts (only occasionally - every 10 seconds)
            if (@mod(now, 10000) < 100) {
                _ = self.table.pruneStale(self.config.contact_timeout_ms);
            }

            // Tight cadence — drain loop above keeps socket buffer empty;
            // this sleep is just CPU friendliness. Reduced from 10ms→2ms.
            // Future: replace with std.posix.poll() on socket fd for true
            // Agave-canonical wake-on-data semantics.
            std.Thread.sleep(2 * std.time.ns_per_ms);
        }

        std.log.info("[Gossip] Gossip loop stopped", .{});
    }

    /// Receive and process with reusable batch (avoids allocation).
    /// Returns: number of packets received this pass (0 = socket drained / WouldBlock).
    ///
    /// @prov:gossip.recv-batch — non-blocking
    /// recvmmsg ⇒ caller drives outer drain loop until socket reports empty.
    fn receiveAndProcessWithBatch(self: *Self, batch: *packet.PacketBatch) !usize {
        if (self.sock == null) return 0;

        // Clear the batch for reuse
        batch.clear();

        // Non-blocking receive
        const received = self.sock.?.recvBatch(batch) catch |err| {
            if (err == error.WouldBlock) return 0;
            return err;
        };

        if (received > 0) {
            self.table.stats.packets_received += received;
            if (self.table.stats.packets_received % 50 == 0) {
                const first = batch.slice()[0];
                std.log.debug(
                    "[Gossip] Received {d} packets (last from {d}.{d}.{d}.{d}:{d})",
                    .{
                        self.table.stats.packets_received,
                        first.src_addr.addr[0],
                        first.src_addr.addr[1],
                        first.src_addr.addr[2],
                        first.src_addr.addr[3],
                        first.src_addr.port(),
                    },
                );
            }
            try self.processPackets(batch);
        }
        return received;
    }

    /// Receive and process incoming packets
    fn receiveAndProcess(self: *Self) !void {
        if (self.sock == null) return;

        var batch = try packet.PacketBatch.init(self.allocator, 64);
        defer batch.deinit();

        // Non-blocking receive
        const received = self.sock.?.recvBatch(&batch) catch |err| {
            if (err == error.WouldBlock) return;
            return err;
        };

        if (received > 0) {
            try self.processPackets(&batch);
        }
    }

    /// Send pull requests to random peers
    fn sendPullRequests(self: *Self) !void {
        if (self.sock == null) return;

        // Pull from entrypoints if no peers yet
        if (self.table.contactCount() == 0) {
            for (self.entrypoints.items) |ep| {
                self.sendPullRequest(ep) catch |err| {
                    std.log.debug("[Gossip] Pull request to entrypoint FAILED: {}\n", .{err});
                };
            }
            self.table.stats.pull_requests_sent += self.entrypoints.items.len;
            return;
        }

        // Pull from random peers
        var iter = self.table.contacts.iterator();
        var count: usize = 0;
        while (iter.next()) |entry| {
            if (count >= 3) break; // Pull from max 3 peers
            try self.sendPullRequest(entry.value_ptr.gossip_addr);
            count += 1;
        }

        self.table.stats.pull_requests_sent += count;
    }

    /// Send a pull request to a peer (bincode format with modern ContactInfo, properly signed)
    /// @prov:gossip.legacy-deprecated — LegacyContactInfo (tag=0) is fully deprecated
    /// and filtered out by peers. We MUST use modern ContactInfo (tag=11) exclusively.
    fn sendPullRequest(self: *Self, target: packet.SocketAddr) !void {
        // ENTRY DIAGNOSTIC
        const EntryDiag = struct {
            var call_count: u32 = 0;
        };
        EntryDiag.call_count += 1;
        if (EntryDiag.call_count <= 5) {
            std.log.debug("[Gossip] ENTRY sendPullRequest #{d}: sock={}, modern_ci={}, keypair={}\n", .{
                EntryDiag.call_count,
                self.sock != null,
                self.modern_contact_info != null,
                self.keypair != null,
            });
        }
        if (self.sock == null) return;
        if (self.modern_contact_info == null) {
            std.log.debug("[Gossip] WARN: No modern ContactInfo set, cannot send pull request\n", .{});
            return;
        }

        // CRITICAL: Update wallclock before each send (nodes reject wallclock >15s old)
        const now_ms = std.time.milliTimestamp();
        if (self.modern_contact_info) |*info| {
            info.wallclock_ms = @intCast(now_ms);
        }

        var pkt = packet.Packet.init();

        // Send modern ContactInfo (tag=11) - the ONLY format accepted by current mainnet
        if (self.modern_contact_info) |*modern| {
            var signature: ?core.Signature = null;
            if (self.keypair) |kp| {
                var signable: [520]u8 = undefined;
                const signable_len = bincode.getContactInfoSignableData(
                    modern,
                    &signable,
                ) catch 0;
                if (signable_len > 0) {
                    signature = kp.sign(signable[0..signable_len]);

                    // DIAGNOSTIC: Verify our own signature
                    const S2 = struct {
                        var diag_count: u32 = 0;
                    };
                    S2.diag_count += 1;
                    if (S2.diag_count <= 3) {
                        const self_verify = kp.verify(&(signature.?), signable[0..signable_len]);
                        std.log.debug("[Gossip] DIAG: signable_len={d}, self_verify={}, pubkey={x:0>2}{x:0>2}..{x:0>2}{x:0>2}\n", .{
                            signable_len,
                            self_verify,
                            kp.public.data[0],
                            kp.public.data[1],
                            kp.public.data[30],
                            kp.public.data[31],
                        });
                        // Show first 8 bytes of signable data (should be CrdsData enum tag)
                        std.log.debug("[Gossip] DIAG: signable[0..8]={x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{
                            signable[0], signable[1], signable[2], signable[3],
                            signable[4], signable[5], signable[6], signable[7],
                        });
                    }
                }
            }
            const len = bincode.buildPullRequestWithContactInfo(
                &pkt.data,
                modern,
                signature,
            ) catch |err| {
                std.log.debug("[Gossip] Failed to build pull request: {}\n", .{err});
                return;
            };
            pkt.len = @intCast(len);
            pkt.src_addr = target;

            // Diagnostic: log pull request with hex dump for first sends
            const S = struct {
                var pull_log_count: u32 = 0;
            };
            S.pull_log_count += 1;
            if (S.pull_log_count <= 10) {
                std.log.debug("[Gossip] TX PullRequest (modern/tag11): {d} bytes -> {d}.{d}.{d}.{d}:{d} (sig={s})\n", .{
                    len,
                    target.addr[0],
                    target.addr[1],
                    target.addr[2],
                    target.addr[3],
                    target.port(),
                    if (signature != null) "YES" else "NO",
                });
            }
            if (S.pull_log_count == 1) {
                // Full hex dump of first packet for protocol debugging
                std.log.debug("[Gossip] HEXDUMP PullRequest ({d} bytes):\n", .{len});
                var line_buf: [80]u8 = undefined;
                var offset: usize = 0;
                while (offset < len) {
                    var line_pos: usize = 0;
                    const off_str = std.fmt.bufPrint(line_buf[0..8], "{x:0>4}: ", .{offset}) catch break;
                    line_pos = off_str.len;
                    var i: usize = 0;
                    while (i < 16 and offset + i < len) : (i += 1) {
                        const hex = std.fmt.bufPrint(line_buf[line_pos .. line_pos + 3], "{x:0>2} ", .{pkt.data[offset + i]}) catch break;
                        line_pos += hex.len;
                    }
                    std.log.debug("{s}\n", .{line_buf[0..line_pos]});
                    offset += 16;
                }
            }

            _ = try self.sock.?.send(&pkt);
        }
    }

    /// Push our CRDS values to random peers
    fn pushToPeers(self: *Self) !void {
        if (self.sock == null) return;
        if (self.table.self_info == null) return;

        // Get random peers to push to
        const fanout = @min(self.config.max_push_fanout, self.table.contactCount());
        if (fanout == 0) {
            // Push to entrypoints if no peers
            for (self.entrypoints.items) |ep| {
                try self.sendContactInfo(ep);
            }
            return;
        }

        var iter = self.table.contacts.iterator();
        var count: usize = 0;
        while (iter.next()) |entry| {
            if (count >= fanout) break;
            try self.sendContactInfo(entry.value_ptr.gossip_addr);
            count += 1;
        }
    }

    /// Send our contact info to a peer (push message with modern ContactInfo, properly signed)
    fn sendContactInfo(self: *Self, target: packet.SocketAddr) !void {
        if (self.sock == null) return;
        if (self.modern_contact_info == null) return;

        // @prov:gossip.wallclock-freshness — CRITICAL: update wallclock before each send
        self.modern_contact_info.?.wallclock_ms = @intCast(std.time.milliTimestamp());

        var pkt = packet.Packet.init();

        // Sign the CrdsValue (CrdsData = modern ContactInfo for Firedancer)
        var signature: ?core.Signature = null;
        if (self.keypair) |kp| {
            var signable: [520]u8 = undefined;
            const signable_len = bincode.getContactInfoSignableData(
                &self.modern_contact_info.?,
                &signable,
            ) catch 0;
            if (signable_len > 0) {
                signature = kp.sign(signable[0..signable_len]);
            }
        }

        // Build proper bincode-formatted push message with modern ContactInfo (for Firedancer)
        const len = bincode.buildPushMessageWithContactInfo(
            &pkt.data,
            self.identity,
            &self.modern_contact_info.?,
            signature,
        ) catch |err| {
            std.log.debug("[Gossip] Failed to build push message: {}\n", .{err});
            return;
        };

        pkt.len = @intCast(len);
        pkt.src_addr = target;

        _ = try self.sock.?.send(&pkt);
    }

    /// Set our own contact info
    /// IMPORTANT: `ip` MUST be the validator's public IP for the network to send shreds!
    pub fn setSelfInfo(self: *Self, ip: [4]u8, gossip_port: u16, tpu_port: u16, tvu_port: u16, repair_port: u16, rpc_port: u16) void {
        self.public_ip = ip;

        self.table.self_info = ContactInfo.initSelf(
            self.identity,
            ip,
            gossip_port,
            tpu_port,
            tvu_port,
            repair_port,
            rpc_port,
        );

        // Create bincode-formatted LegacyContactInfo for Agave compatibility
        self.legacy_contact_info = bincode.LegacyContactInfo.initSelf(
            self.identity,
            ip,
            gossip_port,
            tvu_port,
            repair_port,
            tpu_port,
            rpc_port,
            self.shred_version,
        );

        // Create modern ContactInfo (required by Firedancer - tag 11)
        self.modern_contact_info = bincode.ContactInfo.initSelf(
            self.identity,
            ip,
            gossip_port,
            tvu_port,
            repair_port,
            tpu_port,
            rpc_port,
            self.shred_version,
        );

        // Log the advertised addresses
        std.log.debug("[Gossip] Advertising contact info (modern format for Firedancer):\n", .{});
        std.log.debug("   IP: {d}.{d}.{d}.{d}\n", .{ ip[0], ip[1], ip[2], ip[3] });
        std.log.debug("   Gossip: port {d}\n", .{gossip_port});
        std.log.debug("   TPU: port {d}\n", .{tpu_port});
        std.log.debug("   TVU: port {d}\n", .{tvu_port});
        std.log.debug("   Repair: port {d}\n", .{repair_port});
        std.log.debug("   RPC: port {d}\n", .{rpc_port});
        std.log.debug("   Shred Version: {d}\n", .{self.shred_version});
    }

    pub fn updateShredVersionFromRpc(self: *Self, rpc_url: []const u8) void {
        // Use native HTTP instead of curl to avoid FD inheritance issues
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const uri = std.Uri.parse(rpc_url) catch return;
        const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getClusterNodes\"}";

        var server_header_buffer: [4096]u8 = undefined;
        var req = client.open(.POST, uri, .{
            .server_header_buffer = &server_header_buffer,
        }) catch return;
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = body.len };
        req.send() catch return;
        req.writeAll(body) catch return;
        req.finish() catch return;
        req.wait() catch return;

        var response_buf: [8192]u8 = undefined;
        const response_len = req.reader().readAll(&response_buf) catch return;
        const response = response_buf[0..response_len];
        if (response.len == 0) return;

        const key = "\"shredVersion\":";
        const key_start = std.mem.indexOf(u8, response, key) orelse return;
        var idx = key_start + key.len;
        while (idx < response.len and (response[idx] == ' ' or response[idx] == '\t')) : (idx += 1) {}
        var end = idx;
        while (end < response.len and response[end] >= '0' and response[end] <= '9') : (end += 1) {}
        if (end == idx) return;

        const parsed = std.fmt.parseInt(u16, response[idx..end], 10) catch return;
        if (parsed == self.shred_version) return;

        self.shred_version = parsed;
        if (self.legacy_contact_info) |*info| {
            info.shred_version = parsed;
        }
        if (self.modern_contact_info) |*info| {
            info.shred_version = parsed;
        }

        std.log.info("[Gossip] Updated shred version from RPC: {d}", .{parsed});
    }

    /// Set the shred version (for cluster compatibility)
    pub fn setShredVersion(self: *Self, version: u16) void {
        self.shred_version = version;
        std.log.debug("[Gossip] Set shred version to {d}\n", .{version});

        // Update legacy contact info if already set
        if (self.legacy_contact_info) |*info| {
            info.shred_version = version;
        }
        // Update modern contact info if already set
        if (self.modern_contact_info) |*info| {
            info.shred_version = version;
        }
    }

    /// Set the keypair for signing gossip messages
    /// CRITICAL: Without a keypair, messages won't be signed and will be ignored by peers!
    pub fn setKeypair(self: *Self, keypair: *const core.Keypair) void {
        self.keypair = keypair;
        std.log.debug("[Gossip] Keypair set - messages will now be signed\n", .{});
    }

    /// Wire the FEC resolver so the gossip loop can drain detected equivocations
    /// and PUSH DuplicateShred proofs. Detection ALWAYS runs in the resolver;
    /// this only enables the OUTBOUND push (further gated by flag+env).
    pub fn setDuplicateShredResolver(self: *Self, resolver: *fec_resolver_mod.FecResolver) void {
        self.dup_shred_resolver = resolver;
    }

    /// Comptime+env gate for the DuplicateShred PUSH (dormant by default).
    fn dupShredPushEnabled() bool {
        if (!build_options.duplicate_shred) return false;
        return std.posix.getenv("VEX_DUPLICATE_SHRED") != null;
    }

    /// Once-per-slot guard: returns true if we've already pushed a proof for
    /// `slot`, else records it and returns false.
    fn dupShredAlreadyPushed(self: *Self, slot: u64) bool {
        for (self.dup_shred_pushed_slots) |s| {
            if (s == slot and s != 0) return true;
        }
        self.dup_shred_pushed_slots[self.dup_shred_pushed_head] = slot;
        self.dup_shred_pushed_head = (self.dup_shred_pushed_head + 1) % self.dup_shred_pushed_slots.len;
        return false;
    }

    /// Drain ALL pending equivocation conflicts from the resolver and PUSH a
    /// signed DuplicateShred proof for each (subject to the once-per-slot guard).
    /// Called from the gossip loop ONLY when dupShredPushEnabled().
    /// @prov:gossip.dup-shred-push — build chunks via from_shred, assign
    /// tuple indices (offset + k) % MAX_DUPLICATE_SHREDS, insert into the local
    /// crds table, and push to peers.
    fn drainAndPushDuplicateShreds(self: *Self) void {
        const resolver = self.dup_shred_resolver orelse return;
        const kp = self.keypair orelse return;

        while (resolver.popConflict()) |conflict_const| {
            var conflict = conflict_const;
            defer conflict.deinit(resolver.allocator);

            if (self.dupShredAlreadyPushed(conflict.slot)) continue;

            // @prov:gossip.dup-shred-push — index_offset = monotonic cursor.
            // Distinct labels per proof so cross-slot proofs
            // don't overwrite each other in a receiver's CRDS table.
            const index_offset: u16 = self.dup_shred_index_cursor;
            const wallclock: u64 = @intCast(std.time.milliTimestamp());

            const secret_key = kp.secret; // Solana format [seed(32)][pubkey(32)]
            const self_pubkey = self.identity.data;

            const chunks = dupshred.buildSignedProofChunks(
                self.allocator,
                conflict.shred1,
                conflict.shred2,
                secret_key,
                self_pubkey,
                wallclock,
                conflict.slot,
                index_offset,
            ) catch |err| {
                std.log.warn("[DUP-SHRED] build proof failed slot={d}: {}", .{ conflict.slot, err });
                continue;
            };
            defer {
                for (chunks) |*c| c.deinit();
                self.allocator.free(chunks);
            }

            var pushed: usize = 0;
            for (chunks) |*c| {
                self.pushDuplicateShredValue(&c.value) catch |err| {
                    std.log.warn("[DUP-SHRED] push chunk failed slot={d}: {}", .{ conflict.slot, err });
                    continue;
                };
                pushed += 1;
            }
            // Advance the label cursor past this proof's chunks (mod MAX).
            self.dup_shred_index_cursor = @intCast((@as(u32, self.dup_shred_index_cursor) + @as(u32, @intCast(chunks.len))) % @as(u32, dupshred.MAX_DUPLICATE_SHREDS));
            self.dup_shred_pushed_count += 1;
            std.log.info(
                "[DUP-SHRED] pushed equivocation proof slot={d}: {d}/{d} chunks to peers",
                .{ conflict.slot, pushed, chunks.len },
            );
        }
    }

    /// Serialize a single DuplicateShred CrdsValue into a PushMessage and send it
    /// to our push-fanout peers. Wire: [tag=2][sender(32)][vec_len=1][CrdsValue].
    /// CrdsValue.serialize already emits [sig(64)][CrdsData].
    fn pushDuplicateShredValue(self: *Self, value: *const crds.CrdsValue) !void {
        if (self.sock == null) return;

        var pkt = packet.Packet.init();
        var fbs = std.io.fixedBufferStream(&pkt.data);
        const w = fbs.writer();

        try w.writeInt(u32, 2, .little); // Protocol::PushMessage
        try w.writeAll(&self.identity.data); // sender pubkey
        try w.writeInt(u64, 1, .little); // Vec<CrdsValue> len = 1
        try value.serialize(w); // [sig][CrdsData(DuplicateShred)]

        pkt.len = @intCast(fbs.pos);

        // Fan out to peers (same selection as pushToPeers).
        const fanout = @min(self.config.max_push_fanout, self.table.contactCount());
        if (fanout == 0) {
            for (self.entrypoints.items) |ep| {
                pkt.src_addr = ep;
                _ = self.sock.?.send(&pkt) catch {};
            }
            return;
        }
        var iter = self.table.contacts.iterator();
        var count: usize = 0;
        while (iter.next()) |entry| {
            if (count >= fanout) break;
            pkt.src_addr = entry.value_ptr.gossip_addr;
            _ = self.sock.?.send(&pkt) catch {};
            count += 1;
        }
    }

    /// Sign data using our keypair (called by bincode message builders)
    /// Returns a valid signature if keypair is set, otherwise returns zero signature
    fn signData(self: *const Self, data: []const u8) core.Signature {
        if (self.keypair) |kp| {
            return kp.sign(data);
        }
        // No keypair - return zero signature (messages will likely be rejected)
        std.log.debug("[Gossip] WARNING: No keypair set, message unsigned!\n", .{});
        return core.Signature{ .data = [_]u8{0} ** 64 };
    }
};

/// Cluster type enum (matches core.Config.Cluster)
pub const ClusterType = enum {
    mainnet,
    testnet,
    devnet,
    localnet,
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "contact info init" {
    const identity = core.Pubkey{ .data = [_]u8{1} ** 32 };
    const info = ContactInfo.initSelf(identity, .{ 127, 0, 0, 1 }, 8001, 8002, 8003, 8004, 8899);

    try std.testing.expectEqual(@as(u16, 8001), info.gossip_addr.port());
    try std.testing.expectEqual(@as(u16, 8002), info.tpu_addr.port());
}

test "gossip table" {
    var table = GossipTable.init(std.testing.allocator);
    defer table.deinit();

    const identity = core.Pubkey{ .data = [_]u8{1} ** 32 };
    const info = ContactInfo.initSelf(identity, .{ 127, 0, 0, 1 }, 8001, 8002, 8003, 8004, 8899);

    try table.upsertContact(info);
    try std.testing.expectEqual(@as(usize, 1), table.contactCount());

    const retrieved = table.getContact(identity);
    try std.testing.expect(retrieved != null);
}

test "gossip service init" {
    const identity = core.Pubkey{ .data = [_]u8{0} ** 32 };
    var service = GossipService.init(std.testing.allocator, identity, .{});
    defer service.deinit();

    try std.testing.expectEqual(@as(usize, 0), service.table.contactCount());
}

test "modern contact info parses Tag 12 tpu_vote_quic and resolution prefers it over Tag 8" {
    // Build a minimal valid modern (CRDS v2) ContactInfo byte stream carrying a
    // dedicated tpu_vote_quic socket entry (Tag 12) alongside the regular
    // tpu_quic entry (Tag 8). @prov:gossip.socket-tags — canonical clients
    // prefer Tag 12 for votes.
    //
    // Layout (all multi-byte values little-endian; varints/compact_u16 are
    // single-byte for values < 128, matching parseModernContactInfo):
    //   pubkey[32] | wallclock(varint) | instance(8) | shred_version(2) |
    //   major(varint) minor(varint) patch(varint) | commit(4) feature_set(4) |
    //   client(varint) | addr_count(compact_u16) | [ipv4_disc(4) ip(4)] |
    //   socket_count(compact_u16) | { tag(1) addr_idx(1) port_off(compact_u16) }*
    var buf: [128]u8 = undefined;
    var n: usize = 0;
    // pubkey
    @memset(buf[0..32], 7);
    n = 32;
    buf[n] = 1;
    n += 1; // wallclock varint = 1
    @memset(buf[n .. n + 8], 0);
    n += 8; // instance creation us
    std.mem.writeInt(u16, buf[n..][0..2], 1234, .little);
    n += 2; // shred_version
    buf[n] = 0;
    n += 1; // major varint
    buf[n] = 5;
    n += 1; // minor varint
    buf[n] = 0;
    n += 1; // patch varint
    @memset(buf[n .. n + 8], 0);
    n += 8; // commit(4) + feature_set(4)
    buf[n] = 0;
    n += 1; // client varint
    buf[n] = 1;
    n += 1; // addr_count compact_u16 = 1
    std.mem.writeInt(u32, buf[n..][0..4], 0, .little);
    n += 4; // ipv4 discriminant
    buf[n + 0] = 10;
    buf[n + 1] = 1;
    buf[n + 2] = 2;
    buf[n + 3] = 3;
    n += 4; // ip 10.1.2.3
    buf[n] = 3;
    n += 1; // socket_count = 3
    // Ports are CUMULATIVE deltas. parseModernContactInfo rejects a value whose
    // gossip_addr (Tag 0) port is 0, so a Tag-0 entry is required.
    // Entry 1: Tag 0 (gossip), addr_idx 0, port 8000 absolute (>127 → 2-byte compact_u16)
    buf[n] = 0;
    n += 1;
    buf[n] = 0;
    n += 1;
    buf[n] = @as(u8, @intCast(8000 & 0x7F)) | 0x80;
    buf[n + 1] = @intCast((8000 >> 7) & 0x7F);
    n += 2; // cumulative port = 8000
    // Entry 2: Tag 8 (tpu_quic), addr_idx 0, port delta +1000 → cumulative 9000
    buf[n] = 8;
    n += 1;
    buf[n] = 0;
    n += 1;
    buf[n] = @as(u8, @intCast(1000 & 0x7F)) | 0x80;
    buf[n + 1] = @intCast((1000 >> 7) & 0x7F);
    n += 2;
    // Entry 3: Tag 12 (tpu_vote_quic), addr_idx 0, port delta +6 → cumulative 9006
    buf[n] = 12;
    n += 1;
    buf[n] = 0;
    n += 1;
    buf[n] = 6;
    n += 1; // delta 6, single byte

    const info = (try GossipService.parseModernContactInfo(buf[0..n])) orelse {
        return error.ParseReturnedNull;
    };

    // Tag 8 and Tag 12 both populated, distinct ports.
    try std.testing.expectEqual(@as(u16, 9000), info.tpu_quic_addr.port());
    try std.testing.expectEqual(@as(u16, 9006), info.tpu_vote_quic_addr.port());

    // Resolution preference (mirrors tpu_client.getLeaderTpuQuicNoLock step 1):
    // prefer Tag 12, fall back to Tag 8.
    const resolved = if (info.tpu_vote_quic_addr.port() != 0)
        info.tpu_vote_quic_addr
    else
        info.tpu_quic_addr;
    try std.testing.expectEqual(@as(u16, 9006), resolved.port());

    // When a leader does NOT advertise Tag 12, resolution falls back to Tag 8.
    var info_no12 = info;
    info_no12.tpu_vote_quic_addr = packet.SocketAddr.UNSPECIFIED;
    const resolved_fb = if (info_no12.tpu_vote_quic_addr.port() != 0)
        info_no12.tpu_vote_quic_addr
    else
        info_no12.tpu_quic_addr;
    try std.testing.expectEqual(@as(u16, 9000), resolved_fb.port());
}

test "gossip pull response parse" {
    const allocator = std.testing.allocator;
    var service = GossipService.init(allocator, core.Pubkey{ .data = [_]u8{1} ** 32 }, .{});
    defer service.deinit();

    const peer_pubkey = core.Pubkey{ .data = [_]u8{2} ** 32 };
    var contact = bincode.ContactInfo.initSelf(
        peer_pubkey,
        .{ 127, 0, 0, 1 },
        8000,
        8001,
        8003,
        8004,
        8899,
        TESTNET_SHRED_VERSION,
    );

    var pkt = packet.Packet.init();
    const len = try bincode.buildPullResponseWithContactInfo(&pkt.data, peer_pubkey, &contact, null);
    pkt.len = @intCast(len);

    try service.handlePullResponse(&pkt);
    try std.testing.expect(service.table.contactCount() > 0);
}

test "client identity: serialized ContactInfo carries 0.9.0 + client 86 + commit, round-trips, no size regression" {
    // 2026-07-10 honest-client-id fix (core/version.zig): the wire advertisement
    // must carry OUR version block, not the old defaults (2.2.0/commit=0/client=0
    // = "Solana Labs" on explorers). Asserts byte-level wire content AND that the
    // existing parser still accepts our serialization (varint widths unchanged →
    // the 128-byte buffer paths are safe).
    core.version.setGitHash("3c63bbd");
    defer core.version.setGitHash(""); // reset global for other tests

    const self_pubkey = core.Pubkey{ .data = [_]u8{7} ** 32 };
    var contact = bincode.ContactInfo.initSelf(
        self_pubkey,
        .{ 10, 0, 0, 1 },
        8000, // gossip
        8001, // tvu
        8003, // repair
        8004, // tpu
        8899, // rpc
        TESTNET_SHRED_VERSION,
    );

    var buf: [128]u8 = undefined; // the historical serialize buffer size — must still fit
    const n = try contact.serialize(&buf);
    try std.testing.expect(n <= 128);

    // ── byte-level: walk to the version block and assert exact wire content ──
    var off: usize = 32; // pubkey
    while (buf[off] & 0x80 != 0) off += 1; // wallclock varint
    off += 1;
    off += 8; // instance_creation u64
    off += 2; // shred_version u16
    try std.testing.expectEqual(@as(u8, 0), buf[off]); // major = 0 (single-byte varint)
    off += 1;
    try std.testing.expectEqual(@as(u8, 9), buf[off]); // minor = 9
    off += 1;
    try std.testing.expectEqual(@as(u8, 0), buf[off]); // patch = 0
    off += 1;
    const commit = std.mem.readInt(u32, buf[off..][0..4], .little);
    try std.testing.expectEqual(@as(u32, 0x3c63bbd), commit); // git-hash prefix
    off += 4;
    const feature_set = std.mem.readInt(u32, buf[off..][0..4], .little);
    try std.testing.expectEqual(@as(u32, 0), feature_set); // unchanged — never invented
    off += 4;
    try std.testing.expectEqual(@as(u8, 86), buf[off]); // client = 86 (single-byte varint) — NOT 0/SolanaLabs

    // ── round-trip: our own parser must still accept the serialization ──
    const parsed = (try GossipService.parseModernContactInfo(buf[0..n])) orelse return error.ParseRejected;
    try std.testing.expectEqualSlices(u8, &self_pubkey.data, &parsed.pubkey.data);
    try std.testing.expectEqual(TESTNET_SHRED_VERSION, parsed.shred_version);
    try std.testing.expectEqual(@as(u16, 8000), parsed.gossip_addr.port());
}

test "#41 crdsSigOk: ed25519 round-trip over value[64..] + negatives" {
    // Validates the verify PRIMITIVE used by the gated CRDS sig-verify (handlePush/handlePullResponse).
    // signable = value[64..] (the CrdsData bincode the originator signs); sig = value[0..64].
    const Ed = std.crypto.sign.Ed25519;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, idx| b.* = @intCast((idx * 7 + 1) & 0xff);
    const kp = try Ed.KeyPair.generateDeterministic(seed);
    const pk: [32]u8 = kp.public_key.bytes;

    var signable: [48]u8 = undefined; // arbitrary CrdsData bytes (content irrelevant to the crypto)
    for (&signable, 0..) |*b, idx| b.* = @intCast((idx * 3) & 0xff);
    const sig = (try kp.sign(&signable, null)).toBytes();

    var value: [112]u8 = undefined; // [sig(64)][signable(48)]
    @memcpy(value[0..64], &sig);
    @memcpy(value[64..], &signable);

    // round-trip: correct sig + pubkey
    try std.testing.expect(GossipService.crdsSigOk(value[0..], &pk));
    // negative: corrupted signature byte
    var bad_sig = value;
    bad_sig[5] ^= 0xff;
    try std.testing.expect(!GossipService.crdsSigOk(bad_sig[0..], &pk));
    // negative: tampered message (signable) byte
    var bad_msg = value;
    bad_msg[80] ^= 0xff;
    try std.testing.expect(!GossipService.crdsSigOk(bad_msg[0..], &pk));
    // negative: wrong pubkey
    var wrong_pk = pk;
    wrong_pk[0] ^= 0xff;
    try std.testing.expect(!GossipService.crdsSigOk(value[0..], &wrong_pk));
    // negative: too short to hold a signature
    try std.testing.expect(!GossipService.crdsSigOk(value[0..40], &pk));
}
