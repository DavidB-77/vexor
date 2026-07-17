//! Solana-Compatible QUIC Transport
//! Wire format and protocol compatibility for Solana network.
//!
//! This module bridges our QUIC transport to Solana's actual protocol:
//! - Transaction submission via QUIC streams
//! - Shred propagation via UDP datagrams
//! - Gossip protocol compatibility
//! - RPC over QUIC
//!
//! Solana QUIC Specifics:
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │ SOLANA QUIC PROTOCOL                                                │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Transaction Submission (TPU):                                       │
//! │   - QUIC stream per transaction batch                               │
//! │   - Max 128 connections per IP                                      │
//! │   - Max 8 streams per connection                                    │
//! │   - Transaction serialized as bincode                               │
//! │                                                                      │
//! │ Shred Propagation (Turbine):                                        │
//! │   - UDP datagrams (1228 bytes)                                      │
//! │   - Not QUIC (too much overhead for small packets)                  │
//! │                                                                      │
//! │ Gossip Protocol:                                                    │
//! │   - UDP datagrams                                                   │
//! │   - Ping/Pong, Pull, Push, Prune messages                          │
//! └─────────────────────────────────────────────────────────────────────┘

const std = @import("std");
const Allocator = std.mem.Allocator;
const core = @import("core");
const packet = @import("packet.zig");
const quic = @import("quic.zig");
const tpu_client = @import("tpu_client.zig");

/// Solana packet sizes
pub const PACKET_DATA_SIZE: usize = 1232;
pub const SHRED_SIZE: usize = 1228;
pub const MAX_TX_SIZE: usize = 1232;
pub const MTU: usize = 1280;

/// Solana QUIC configuration (matches validator defaults)
pub const SolanaQuicConfig = struct {
    /// Maximum concurrent connections from a single IP
    max_connections_per_ip: u32 = 128,
    /// Maximum streams per connection (for TPU)
    max_streams_per_connection: u32 = 8,
    /// Maximum pending connections
    max_pending_connections: u32 = 1024,
    /// Connection idle timeout (seconds)
    idle_timeout_secs: u32 = 10,
    /// Maximum transaction batch size
    max_tx_batch_size: usize = 128,
    /// Staked connection multiplier (2x for staked validators)
    staked_connection_multiplier: u32 = 2,
    /// Allow self-signed certs (local testing only)
    allow_insecure: bool = false,
    /// Local port to bind to (0 = ephemeral)
    bind_port: u16 = 0,
    /// Bind the underlying QUIC endpoint socket to this specific IPv4 (dual-NIC
    /// hosts). Empty = 0.0.0.0 (kernel picks egress source by route). 2026-07-06:
    /// on this host that's the WRONG NIC for the vote client — see
    /// core/config.zig quic_bind_addr for the full mechanism. Only meaningful for
    /// the client (is_server=false); a server listening on 0.0.0.0 has no
    /// source-IP problem, so server callers should leave this empty.
    bind_addr: []const u8 = "",
    /// Act as a server (accept incoming connections)
    is_server: bool = true,
    /// Validator Ed25519 identity seed for Solana mTLS client cert (staked QoS). null = no client
    /// auth. Threaded into the QUIC EndpointConfig so client connections present the identity cert.
    identity_seed: ?[32]u8 = null,
};

/// Transaction wire format (Solana bincode serialization)
pub const TransactionWireFormat = struct {
    /// Number of signatures
    signature_count: u8,
    /// Signatures (64 bytes each)
    signatures: []const [64]u8,
    /// Message (compact format)
    message: MessageFormat,

    pub const MessageFormat = struct {
        /// Header
        num_required_signatures: u8,
        num_readonly_signed: u8,
        num_readonly_unsigned: u8,
        /// Account keys (32 bytes each)
        account_keys: []const [32]u8,
        /// Recent blockhash
        recent_blockhash: [32]u8,
        /// Instructions
        instructions: []const InstructionFormat,
    };

    pub const InstructionFormat = struct {
        program_id_index: u8,
        accounts: []const u8,
        data: []const u8,
    };

    /// Serialize to bytes (bincode format)
    pub fn serialize(self: *const TransactionWireFormat, allocator: Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        const writer = buffer.writer();

        // Signature count (compact-u16)
        try writeCompactU16(writer, @intCast(self.signatures.len));

        // Signatures
        for (self.signatures) |sig| {
            try writer.writeAll(&sig);
        }

        // Message header
        try writer.writeByte(self.message.num_required_signatures);
        try writer.writeByte(self.message.num_readonly_signed);
        try writer.writeByte(self.message.num_readonly_unsigned);

        // Account keys
        try writeCompactU16(writer, @intCast(self.message.account_keys.len));
        for (self.message.account_keys) |key| {
            try writer.writeAll(&key);
        }

        // Recent blockhash
        try writer.writeAll(&self.message.recent_blockhash);

        // Instructions
        try writeCompactU16(writer, @intCast(self.message.instructions.len));
        for (self.message.instructions) |ix| {
            try writer.writeByte(ix.program_id_index);
            try writeCompactU16(writer, @intCast(ix.accounts.len));
            try writer.writeAll(ix.accounts);
            try writeCompactU16(writer, @intCast(ix.data.len));
            try writer.writeAll(ix.data);
        }

        return buffer.toOwnedSlice();
    }

    /// Deserialize from bytes
    pub fn deserialize(allocator: Allocator, data: []const u8) !TransactionWireFormat {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        // Signature count
        const sig_count = try readCompactU16(reader);
        const signatures = try allocator.alloc([64]u8, sig_count);
        for (signatures) |*sig| {
            _ = try reader.readAll(sig);
        }

        // Message header
        const num_required_signatures = try reader.readByte();
        const num_readonly_signed = try reader.readByte();
        const num_readonly_unsigned = try reader.readByte();

        // Account keys
        const key_count = try readCompactU16(reader);
        const account_keys = try allocator.alloc([32]u8, key_count);
        for (account_keys) |*key| {
            _ = try reader.readAll(key);
        }

        // Recent blockhash
        var recent_blockhash: [32]u8 = undefined;
        _ = try reader.readAll(&recent_blockhash);

        // Instructions
        const ix_count = try readCompactU16(reader);
        const instructions = try allocator.alloc(InstructionFormat, ix_count);
        for (instructions) |*ix| {
            ix.program_id_index = try reader.readByte();
            const acc_len = try readCompactU16(reader);
            const accounts = try allocator.alloc(u8, acc_len);
            _ = try reader.readAll(accounts);
            ix.accounts = accounts;
            const data_len = try readCompactU16(reader);
            const ix_data = try allocator.alloc(u8, data_len);
            _ = try reader.readAll(ix_data);
            ix.data = ix_data;
        }

        return .{
            .signature_count = @intCast(sig_count),
            .signatures = signatures,
            .message = .{
                .num_required_signatures = num_required_signatures,
                .num_readonly_signed = num_readonly_signed,
                .num_readonly_unsigned = num_readonly_unsigned,
                .account_keys = account_keys,
                .recent_blockhash = recent_blockhash,
                .instructions = instructions,
            },
        };
    }
};

/// Shred wire format
pub const ShredWireFormat = struct {
    /// Shred header
    pub const Header = extern struct {
        signature: [64]u8,
        variant: u8,
        slot: u64,
        index: u32,
        version: u16,
        fec_set_index: u32,
    };

    /// Shred types
    pub const ShredType = enum(u2) {
        data = 0b10,
        code = 0b01,
    };

    header: Header,
    payload: []const u8,

    pub const MAX_PAYLOAD_SIZE: usize = SHRED_SIZE - @sizeOf(Header);
};

/// Gossip message types (bincode serialized)
pub const GossipMessageType = enum(u32) {
    pull_request = 0,
    pull_response = 1,
    push_message = 2,
    prune_message = 3,
    ping = 4,
    pong = 5,
};

/// Solana QUIC endpoint for TPU
pub const SolanaTpuQuic = struct {
    allocator: Allocator,
    config: SolanaQuicConfig,
    client: *quic.QuicClient,
    connections: std.AutoHashMap(u64, *quic.Connection),
    /// hashTarget(ip,port) -> connection-created milliTimestamp. Parallel to `connections`; lets
    /// pruneDeadConnections age out never-completing handshakes (bounded conn pool, Agave model).
    conn_created: std.AutoHashMap(u64, i64),
    /// NEGATIVE-ENDORSEMENT memory (2026-07-10 vote-fanout hygiene): hashTarget(ip,port) ->
    /// milliTimestamp of the LAST dead-handshake prune for that target. pruneDeadConnections stamps
    /// it whenever it ages out a never-completing handshake (leader not running QUIC / unreachable /
    /// cert-rejected). The vote-send pre-filter (TpuClient.enqueueVote) consults isDeadCached() so it
    /// STOPS re-enqueueing votes to a target that just failed its handshake — otherwise a dead leader
    /// is re-connected every ~8s forever (conn → 8s no handshake → prune → conn_created erased → no
    /// memory → reconnect), polluting the 256-deep pending ring + the 128-slot conn pool. Keyed by the
    /// SAME hashTarget the connection maps use (reuse, not a parallel per-peer tracker). TTL-bounded so
    /// a leader that later comes up (or a stale gossip port that gets refreshed) is retried after the
    /// window. Canonical: Firedancer fd_txsend/fd_quic drop a peer whose handshake fails and do not
    /// hot-loop reconnect; Agave ConnectionCache establishes async and does not spin on dead peers.
    dead_targets: std.AutoHashMap(u64, i64),
    mutex: std.Thread.Mutex,
    stats: Stats,
    running: std.atomic.Value(bool),
    transaction_callback: ?*const fn (ctx: ?*anyopaque, data: []const u8) void = null,
    transaction_callback_ctx: ?*anyopaque = null,

    pub const ConnectionState = struct {
        streams_used: u32,
        bytes_sent: u64,
        last_activity: i64,
        is_staked: bool,
    };

    pub const Stats = struct {
        transactions_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        transactions_sent: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        connections_accepted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        connections_rejected: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        rate_limited: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        /// 2026-06-23 wedge-fix signal: count of evict-on-full evictions. A climbing value under leader
        /// rotation = the bounded pool is recycling (the fix actively working); paired with a bounded
        /// pool size it proves the pool can never saturate (the old refuse-on-full delinquency cause).
        connections_evicted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        /// 2026-06-28 vote-landing diag: connections pruned for NEVER completing their QUIC handshake
        /// within DEAD_HANDSHAKE_MS (leader not running QUIC / unreachable / cert-rejected). High value
        /// relative to conn_pool_size ⟹ a "dead-handshake tail" (many leaders never accept our vote
        /// stream) — distinct from connections that DO complete but a few slots late (a warmth problem
        /// the prewarm targets). Lets us tell the two apart instead of guessing.
        handshakes_pruned_dead: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    pub fn init(allocator: Allocator, config: SolanaQuicConfig) !*SolanaTpuQuic {
        const self = try allocator.create(SolanaTpuQuic);
        errdefer allocator.destroy(self);

        const client = try quic.QuicClient.init(allocator, config.bind_port, .{
            .max_connections = config.max_pending_connections,
            .max_streams_per_connection = config.max_streams_per_connection,
            .initial_max_data = 10 * 1024 * 1024,
            .initial_max_stream_data = 1024 * 1024,
            .max_idle_timeout_ms = config.idle_timeout_secs * 1000,
            .identity_seed = config.identity_seed,
            .bind_addr = config.bind_addr,
        });

        // If configured as server, ensure the underlying endpoint is in server mode
        client.endpoint.is_server = config.is_server;

        self.* = .{
            .allocator = allocator,
            .config = config,
            .client = client,
            .connections = std.AutoHashMap(u64, *quic.Connection).init(allocator),
            .conn_created = std.AutoHashMap(u64, i64).init(allocator),
            .dead_targets = std.AutoHashMap(u64, i64).init(allocator),
            .mutex = .{},
            .stats = .{},
            .running = std.atomic.Value(bool).init(false),
        };

        return self;
    }

    pub fn deinit(self: *SolanaTpuQuic) void {
        self.client.deinit();
        self.connections.deinit();
        self.conn_created.deinit();
        self.dead_targets.deinit();
        self.allocator.destroy(self);
    }

    /// Max QUIC vote connections to keep. 2026-06-23: lowered 1024→128 to match Firedancer's txsend tile
    /// (fd_txsend_tile.c conn_cnt=128) — a small pool bounds fds + poll() cost and, combined with
    /// evict-on-full below, can NEVER saturate. The OLD 1024 + refuse-on-full + prune-only-dead-handshake
    /// caused a DELINQUENCY: completed conns to rotated-away leaders were never pruned, the pool saturated
    /// over ~1hr of leader rotation, getOrConnectNonBlocking then REFUSED the current leader → QUIC votes
    /// wedged (sent=frozen, failed=0, no fallback). Canonical fix (RULE#16): Agave ConnectionCache
    /// (connection_cache.rs:216-232) EVICTS on full to always admit the current leader; FD closes conns to
    /// out-of-window leaders. We now evict-oldest-on-full. See memory quic-vote-wedge-rootcause-2026-06-23.
    pub const MAX_VOTE_CONNS: usize = 128;
    /// A handshake that hasn't completed in this long is treated as dead (leader not running QUIC /
    /// unreachable) and pruned. ~8s > the 5s handshake timeout, so live-but-slow peers aren't pruned.
    pub const DEAD_HANDSHAKE_MS: i64 = 8000;
    /// How long a dead-handshake target stays in the negative-endorsement cache (`dead_targets`). Within
    /// this window the vote pre-filter skips QUIC enqueue for that target (UDP still carries the vote);
    /// after it, the target is retried (a recovered leader / refreshed gossip port re-handshakes). 2 min
    /// ≈ leader rotates out of our ~7-rotation fanout window many times over, so a genuinely-dead leader
    /// is skipped for the whole time it's relevant, while a transient failure heals within one window.
    pub const DEAD_LEADER_TTL_MS: i64 = 120_000;

    /// Prune never-completing (dead-handshake) QUIC vote connections, freeing them from both endpoint
    /// indexes + the local maps. Bounds the connection pool over long uptime. MUST run on the vote
    /// poller thread (the only thread that connect()s / poll()s the vote endpoint — verified: the
    /// blocking sendVote/sendTransaction chain has no live callers; the live path is
    /// queueTransaction→processPending→getOrConnectNonBlocking, all poller-thread). A !handshake_complete
    /// connection is never returned to any caller, so freeing it is reference-safe.
    pub fn pruneDeadConnections(self: *SolanaTpuQuic) void {
        const now = std.time.milliTimestamp();
        self.mutex.lock();
        defer self.mutex.unlock();
        var dead: [128]u64 = undefined;
        var nd: usize = 0;
        var it = self.connections.iterator();
        while (it.next()) |e| {
            if (nd >= dead.len) break;
            const conn = e.value_ptr.*;
            if (!conn.tls.handshake_complete) {
                const ts = self.conn_created.get(e.key_ptr.*) orelse now;
                if (now - ts > DEAD_HANDSHAKE_MS) {
                    dead[nd] = e.key_ptr.*;
                    nd += 1;
                }
            }
        }
        var i: usize = 0;
        while (i < nd) : (i += 1) {
            const key = dead[i];
            if (self.connections.get(key)) |conn| {
                self.client.endpoint.removeConnection(conn); // both endpoint maps + deinit
                _ = self.connections.remove(key);
                _ = self.conn_created.remove(key);
            }
            // NEGATIVE-ENDORSEMENT: remember this target just failed its handshake so the vote
            // pre-filter skips re-enqueueing to it for DEAD_LEADER_TTL_MS (else we reconnect it
            // every ~8s forever). Same hashTarget key the conn maps use — reuse, not duplicate.
            self.dead_targets.put(key, now) catch {};
        }
        // Bound dead_targets: drop entries older than the TTL on every sweep (~2s) so the map
        // can't grow without limit under long uptime / high leader churn.
        var dit = self.dead_targets.iterator();
        var expired: [128]u64 = undefined;
        var ne: usize = 0;
        while (dit.next()) |e| {
            if (ne >= expired.len) break;
            if (now - e.value_ptr.* > DEAD_LEADER_TTL_MS) {
                expired[ne] = e.key_ptr.*;
                ne += 1;
            }
        }
        var e_i: usize = 0;
        while (e_i < ne) : (e_i += 1) _ = self.dead_targets.remove(expired[e_i]);
        if (nd > 0) _ = self.stats.handshakes_pruned_dead.fetchAdd(nd, .monotonic);
    }

    /// Pure TTL decision for the dead-target cache — unit-testable without a live endpoint (mirrors
    /// oldestConnKey). Returns true iff `key` is present in `map` AND its stamp is within `ttl_ms` of
    /// `now` (i.e. still a recent dead handshake → skip). Absent OR expired → false (retry the target).
    fn isDeadTarget(map: *const std.AutoHashMap(u64, i64), key: u64, now: i64, ttl_ms: i64) bool {
        const ts = map.get(key) orelse return false;
        return (now - ts) <= ttl_ms;
    }

    /// True iff (host,port) failed its QUIC handshake within DEAD_LEADER_TTL_MS. The vote pre-filter
    /// calls this at enqueue time to skip QUIC for a known-dead leader (UDP still carries the vote).
    pub fn isDeadCached(self: *SolanaTpuQuic, host: []const u8, port: u16) bool {
        const key = hashTarget(host, port);
        const now = std.time.milliTimestamp();
        self.mutex.lock();
        defer self.mutex.unlock();
        return isDeadTarget(&self.dead_targets, key, now, DEAD_LEADER_TTL_MS);
    }

    /// Start listening for TPU QUIC connections on the given port
    pub fn listen(self: *SolanaTpuQuic, port: u16) !void {
        _ = port; // Port was set correctly in init() via config.bind_port (fixed in tpu.zig)
        self.running.store(true, .release);
        std.log.info("[TPU-QUIC] Listening on port {d}", .{self.config.bind_port});
    }

    /// Set callback for incoming transactions
    pub fn setTransactionCallback(
        self: *SolanaTpuQuic,
        ctx: ?*anyopaque,
        cb: *const fn (ctx: ?*anyopaque, data: []const u8) void,
    ) void {
        self.transaction_callback_ctx = ctx;
        self.transaction_callback = cb;
    }

    /// Poll for events and process incoming transactions
    pub fn poll(self: *SolanaTpuQuic) !void {
        try self.client.poll();

        // Process incoming streams across all connections
        var conn_it = self.client.endpoint.connections.valueIterator();
        while (conn_it.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            var stream_it = conn.streams.iterator();
            while (stream_it.next()) |entry| {
                const stream = entry.value_ptr.*;

                // Solana TPU sends each transaction batch on a separate stream.
                // When we receive FIN, the batch is complete.
                if (stream.fin_received and stream.recv_buffer.items.len > 0) {
                    if (self.transaction_callback) |cb| {
                        cb(self.transaction_callback_ctx, stream.recv_buffer.items);
                    }
                    _ = self.stats.transactions_received.fetchAdd(1, .monotonic);

                    // Clear buffer after processing.
                    // Note: In a production client we'd want to remove the stream from the map
                    // once it's fully processed/closed to avoid memory buildup.
                    stream.recv_buffer.clearAndFree(self.allocator);
                }
            }
        }
    }

    /// Retire a CLIENT uni-stream the instant `conn.send` returns. `conn.send` transmits
    /// SYNCHRONOUSLY — `endpoint.sendStreamData(...)` puts the tx bytes + FIN on the wire inside
    /// send(), then `stream.sendFin()` — and there is NO stream-data retransmit anywhere (loss
    /// recovery's SentPacket stores only packet_number + frame TYPES + size, never a stream
    /// ref/data; sendStreamData is called ONLY from the live send path). So a fire-and-forget TPU
    /// uni-stream can be removed from `conn.streams` immediately after send. WITHOUT this the map
    /// grows unbounded and `openUniStream` returns error.TooManyStreams once
    /// `streams.count() >= max_streams_per_connection` (=8) → every vote QUIC connection JAMS after
    /// ~8 sends (live fingerprint: txs_sent_quic ≈ 8 × pool). `Stream.deinit` frees recv_buffer +
    /// send_buffer + destroys the Stream (self-contained). A lost vote is superseded by the next.
    /// Mirrors the `fetchRemove` KV-by-value pattern at quic.zig:2856.
    fn retireUniStream(conn: *quic.Connection, stream_id: u64) void {
        if (conn.streams.fetchRemove(stream_id)) |kv| kv.value.deinit();
    }

    /// Send transaction to a TPU endpoint
    pub fn sendTransaction(self: *SolanaTpuQuic, tpu_addr: []const u8, port: u16, tx_data: []const u8) !void {
        if (tx_data.len > MAX_TX_SIZE) return error.TransactionTooLarge;

        const conn = try self.getOrConnect(tpu_addr, port);
        const stream = try conn.openUniStream();
        const sid = stream.id;
        // Retire on BOTH the success path AND the error return from `try conn.send` (a failed send
        // still opened a stream that must be removed, else the map leaks → TooManyStreams jam).
        defer retireUniStream(conn, sid);
        // Send the tx ONCE with FIN (one tx per uni-stream, TPU model). The previous duplicate
        // conn.send doubled the payload on the wire (receiver appended both → corrupt tx bytes).
        try conn.send(stream.id, tx_data, true);

        _ = self.stats.transactions_sent.fetchAdd(1, .monotonic);
    }

    /// Send transaction via QUIC datagram (experimental H3 datagram capsule)
    pub fn sendTransactionDatagram(
        self: *SolanaTpuQuic,
        tpu_addr: []const u8,
        port: u16,
        tx_data: []const u8,
        use_h3_capsule: bool,
    ) !void {
        if (tx_data.len > MAX_TX_SIZE) return error.TransactionTooLarge;

        const conn = try self.getOrConnect(tpu_addr, port);
        const payload = if (use_h3_capsule)
            try encodeH3DatagramCapsule(self.allocator, tx_data)
        else
            try self.allocator.dupe(u8, tx_data);
        defer self.allocator.free(payload);

        const stream = try conn.openUniStream();
        const sid = stream.id;
        defer retireUniStream(conn, sid); // retire on success AND on the `try conn.send` error return
        // Send once with FIN (was duplicated → corrupt payload).
        try conn.send(stream.id, payload, true);

        _ = self.stats.transactions_sent.fetchAdd(1, .monotonic);
    }

    /// Non-blocking connect-ahead: initiate a QUIC connection to an upcoming leader WITHOUT waiting
    /// for the handshake (the drive loop's poll() completes it). No-op if already pooled. Canonical
    /// Agave connect-ahead / FD txsend pre-open — lets votes land at slot start instead of paying the
    /// handshake on the critical path. MUST be called from the same thread that owns the endpoint
    /// (the QUIC drive thread), since it touches the endpoint via client.connect.
    pub fn prewarm(self: *SolanaTpuQuic, tpu_addr: []const u8, port: u16) void {
        const key = hashTarget(tpu_addr, port);
        self.mutex.lock();
        if (self.connections.contains(key)) {
            self.mutex.unlock();
            return; // already pooled — idempotent no-op
        }
        // 2026-06-28 FIX (BLOCKING, found in canonical review): honor the bounded pool MAX_VOTE_CONNS
        // BEFORE connecting — same order as getOrConnectNonBlocking (:555-557) and Firedancer's hard-stop
        // at conn_cnt=128. prewarm was the ONLY path that could push the pool past 128 — the invariant the
        // 2026-06-23 evict-on-full wedge fix depends on (a saturated pool previously refused the current
        // leader → QUIC-vote wedge → delinquency). Evicting BEFORE connect (not after) avoids transiently
        // over-subscribing the endpoint with a 129th connection. CANONICAL: Agave ConnectionCache evicts-
        // on-full; FD hard-stops at 128.
        if (self.connections.count() >= MAX_VOTE_CONNS) {
            self.evictOldestLocked();
        }
        self.mutex.unlock();
        const conn = self.client.connect(tpu_addr, port) catch return; // sends ClientHello, returns now
        self.mutex.lock();
        defer self.mutex.unlock();
        self.connections.put(key, conn) catch {
            // OOM: free the endpoint connection rather than leak it / desync the maps (conn_created not yet
            // written, so the two maps stay parallel). removeConnection drops both endpoint maps + deinits.
            self.client.endpoint.removeConnection(conn);
            return;
        };
        // Record creation time like getOrConnectNonBlocking (:562) so a prewarmed connection whose
        // handshake never completes is aged out by pruneDeadConnections. Keeps the two maps parallel.
        self.conn_created.put(key, std.time.milliTimestamp()) catch {};
    }

    /// Read-only: true iff a handshake-complete connection to (host,port) is already pooled. Does NOT
    /// create one (unlike getOrConnectNonBlocking). Used only by the pending-queue diagnostic to label
    /// a queued vote as ready-to-drain vs blocked-on-handshake.
    pub fn isReadyNonBlocking(self: *SolanaTpuQuic, host: []const u8, port: u16) bool {
        const key = hashTarget(host, port);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.connections.get(key)) |existing| return existing.tls.handshake_complete;
        return false;
    }

    /// Pure gate for the targeted vote-leader prewarm: only prewarm when our replay `frontier` is within
    /// `slack` slots of the cluster `tip` (i.e. we are CAUGHT UP). During catch-up frontier << tip → false
    /// → no prewarm. This is the guard the OLD free-running prewarm lacked: it chased the received-shred
    /// tip during catch-up, churned connections to the cluster's current leaders and starved the repair
    /// REQUEST path → catch-up stall (removed 2026-06-18). Restoring prewarm SAFELY requires exactly this
    /// caught-up gate. frontier/tip==0 (pre-boot) → false.
    pub fn shouldPrewarmCaughtUp(frontier: u64, tip: u64, slack: u64) bool {
        if (frontier == 0 or tip == 0) return false;
        return tip <= frontier + slack;
    }

    fn getOrConnect(self: *SolanaTpuQuic, host: []const u8, port: u16) !*quic.Connection {
        const key = hashTarget(host, port);

        self.mutex.lock();
        if (self.connections.get(key)) |existing| {
            self.mutex.unlock();
            return existing;
        }
        self.mutex.unlock();

        const conn = try self.client.connect(host, port);
        waitForHandshake(self, conn) catch |err| {
            std.log.debug("[QUIC] handshake failed for {s}:{d} stage={s} err={}\n", .{
                host,
                port,
                @tagName(conn.tls.handshake_stage),
                err,
            });
            return err;
        };

        self.mutex.lock();
        defer self.mutex.unlock();
        // 2026-06-28 (canonical review): keep connections/conn_created PARALLEL + honor the 128 cap on
        // ALL insertion paths. The prewarm pool-cap + pruneDeadConnections + evictOldestLocked iterate
        // conn_created; an entry present in `connections` but absent from `conn_created` is un-evictable
        // and, if conn_created emptied while the pool is full, would let a put push count to 129 (breaching
        // the wedge-fix invariant). getOrConnect is the blocking variant (dead on the live vote path), but
        // we maintain the invariant universally so no path can break it.
        if (self.connections.count() >= MAX_VOTE_CONNS and !self.connections.contains(key)) {
            self.evictOldestLocked();
        }
        try self.connections.put(key, conn);
        self.conn_created.put(key, std.time.milliTimestamp()) catch {};
        return conn;
    }

    /// Send transaction batch
    pub fn sendTransactionBatch(self: *SolanaTpuQuic, tpu_addr: []const u8, port: u16, transactions: []const []const u8) !usize {
        var sent: usize = 0;

        for (transactions) |tx| {
            self.sendTransaction(tpu_addr, port, tx) catch continue;
            sent += 1;
        }

        return sent;
    }

    /// Send transaction batch on a single stream (coalesced)
    pub fn sendTransactionBatchCoalesced(
        self: *SolanaTpuQuic,
        tpu_addr: []const u8,
        port: u16,
        transactions: []const []const u8,
    ) !usize {
        if (transactions.len == 0) return 0;

        const conn = try self.getOrConnect(tpu_addr, port);
        var sent: usize = 0;
        for (transactions) |tx| {
            if (tx.len > MAX_TX_SIZE) continue;
            const stream = try conn.openUniStream();
            const sid = stream.id;
            // defer is per-iteration in Zig (runs at loop-body block exit, INCLUDING `continue`) →
            // retires on the send-success path AND the `catch continue` failure path. Without retire
            // the map fills to max_streams_per_connection and openUniStream jams the connection.
            defer retireUniStream(conn, sid);
            conn.send(stream.id, tx, true) catch continue; // one tx per uni-stream, FIN-terminated
            sent += 1;
        }

        _ = self.stats.transactions_sent.fetchAdd(sent, .monotonic);
        return sent;
    }

    /// Non-blocking variant of getOrConnect. Returns the connection ONLY if it already exists AND its
    /// handshake is complete. If the target has no connection yet, initiates a NON-BLOCKING connect
    /// (ClientHello sent; the drive loop's poll() completes the handshake) and returns null. If the
    /// connection exists but is still handshaking, returns null. NEVER blocks on waitForHandshake.
    /// Pick the oldest connection key (min conn_created timestamp) — the evict-on-full victim. Pure over
    /// the conn_created map so it is unit-testable without a live endpoint. Returns null if empty.
    fn oldestConnKey(conn_created: *const std.AutoHashMap(u64, i64)) ?u64 {
        var oldest_key: ?u64 = null;
        var oldest_ts: i64 = std.math.maxInt(i64);
        var it = conn_created.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* < oldest_ts) {
                oldest_ts = e.value_ptr.*;
                oldest_key = e.key_ptr.*;
            }
        }
        return oldest_key;
    }

    /// Evict the oldest connection to free a pool slot for the current leader (caller MUST hold the mutex).
    /// Canonical: Agave ConnectionCache evicts on full to always admit the current leader (random there;
    /// deterministic oldest here). Frees the conn from both endpoint maps + the local maps + bumps the
    /// connections_evicted signal. An evicted recurring leader simply re-handshakes (poll-driven, cheap).
    fn evictOldestLocked(self: *SolanaTpuQuic) void {
        const key = oldestConnKey(&self.conn_created) orelse return;
        if (self.connections.get(key)) |conn| {
            self.client.endpoint.removeConnection(conn); // both endpoint maps + deinit
            _ = self.connections.remove(key);
        }
        _ = self.conn_created.remove(key);
        _ = self.stats.connections_evicted.fetchAdd(1, .monotonic);
    }

    /// Canonical Agave model: ConnectionCache establishes connections OFF the send/critical path
    /// (create_connection_async_thread); the send never blocks on a handshake. The caller leaves the
    /// tx queued and retries on the next poll round once the connection is ready.
    fn getOrConnectNonBlocking(self: *SolanaTpuQuic, host: []const u8, port: u16) ?*quic.Connection {
        const key = hashTarget(host, port);
        self.mutex.lock();
        if (self.connections.get(key)) |existing| {
            self.mutex.unlock();
            return if (existing.tls.handshake_complete) existing else null;
        }
        // Bounded pool: when full, EVICT THE OLDEST connection so the CURRENT leader is ALWAYS admitted —
        // NEVER refuse (refusing wedged QUIC votes → delinquency 2026-06-23). Mirrors Agave ConnectionCache
        // evict-on-full (connection_cache.rs:216-232) with a deterministic oldest-by-conn_created pick
        // instead of Agave's random; FD-style small pool (128) keeps this rare. Re-handshake of an evicted
        // recurring leader is cheap (poll-driven). Holds the mutex across the evict (endpoint maps + maps).
        if (self.connections.count() >= MAX_VOTE_CONNS) {
            self.evictOldestLocked();
        }
        self.mutex.unlock();
        const conn = self.client.connect(host, port) catch return null; // sends ClientHello, returns now
        self.mutex.lock();
        self.connections.put(key, conn) catch {};
        self.conn_created.put(key, std.time.milliTimestamp()) catch {};
        self.mutex.unlock();
        return null; // handshake completes via poll(); ready next round
    }

    /// Non-blocking coalesced batch send. Returns 0 (leaving the batch queued for retry) when the
    /// target connection is not yet handshake-complete — NEVER blocks on the handshake. This is what
    /// the vote drain (TpuClient.processPending) MUST use: processPending holds the TpuClient mutex,
    /// and that mutex is on the replay thread's vote path (queueTransaction). Blocking here (the old
    /// sendTransactionBatchCoalesced → getOrConnect → waitForHandshake, up to 5s) held the mutex
    /// across a blocking handshake and stalled replay → catch-up stall (2026-06-18 root cause).
    pub fn sendTransactionBatchCoalescedNonBlocking(
        self: *SolanaTpuQuic,
        tpu_addr: []const u8,
        port: u16,
        transactions: []const []const u8,
    ) usize {
        if (transactions.len == 0) return 0;
        const conn = self.getOrConnectNonBlocking(tpu_addr, port) orelse return 0;
        var sent: usize = 0;
        for (transactions) |tx| {
            if (tx.len > MAX_TX_SIZE) continue;
            const stream = conn.openUniStream() catch continue;
            const sid = stream.id;
            // THE live vote path. defer is per-iteration in Zig (runs at loop-body block exit,
            // INCLUDING `continue`) → retires the uni-stream on the send-success path AND the
            // `catch continue` failure path (a failed send still opened a stream that must be
            // retired). Without retire the connection jams after ~8 sends → QUIC votes stop landing.
            defer retireUniStream(conn, sid);
            conn.send(stream.id, tx, true) catch continue; // one tx per uni-stream, FIN-terminated
            sent += 1;
        }
        _ = self.stats.transactions_sent.fetchAdd(sent, .monotonic);
        return sent;
    }

    pub fn getStats(self: *const SolanaTpuQuic) struct {
        transactions_received: u64,
        transactions_sent: u64,
        connections_accepted: u64,
        connections_rejected: u64,
        rate_limited: u64,
        conn_pool_size: u64, // current pool occupancy — MUST stay <= MAX_VOTE_CONNS (wedge-fix signal)
        connections_evicted: u64, // evict-on-full count — climbing under churn = fix working
        handshakes_pruned_dead: u64, // never-completed-handshake prunes — high vs pool = dead-leader tail
    } {
        return .{
            .transactions_received = self.stats.transactions_received.load(.monotonic),
            .transactions_sent = self.stats.transactions_sent.load(.monotonic),
            .connections_accepted = self.stats.connections_accepted.load(.monotonic),
            .connections_rejected = self.stats.connections_rejected.load(.monotonic),
            .rate_limited = self.stats.rate_limited.load(.monotonic),
            .conn_pool_size = self.connections.count(),
            .connections_evicted = self.stats.connections_evicted.load(.monotonic),
            .handshakes_pruned_dead = self.stats.handshakes_pruned_dead.load(.monotonic),
        };
    }
};

fn waitForHandshake(self: *SolanaTpuQuic, conn: *quic.Connection) !void {
    const start = std.time.milliTimestamp();
    var last_resend = start;
    var resends: u32 = 0;
    while (!conn.tls.handshake_complete) {
        // Use non-blocking poll to keep UI/logs responsive and process other packets
        try self.client.poll();
        const now = std.time.milliTimestamp();

        // Use a more aggressive resend interval (100ms instead of 200ms) for initial packets
        if (now - last_resend >= 100) {
            self.client.resendInitial(conn) catch {};
            last_resend = now;
            resends += 1;
            if (resends % 10 == 0) {
                std.log.debug("[QUIC] handshake progress target={any} stage={s} resends={d}\n", .{
                    conn.peer_addr,
                    @tagName(conn.tls.handshake_stage),
                    resends,
                });
            }
        }
        // Increase timeout to 5 seconds to accommodate slower peers across regions
        if (std.time.milliTimestamp() - start > 5000) {
            std.log.debug("[QUIC] handshake timeout target={any} stage={s} resends={d}\n", .{
                conn.peer_addr,
                @tagName(conn.tls.handshake_stage),
                resends,
            });
            return error.HandshakeTimeout;
        }
        // Reduce sleep time to 1ms for much lower latency polling
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
}

fn hashTarget(host: []const u8, port: u16) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(host);
    h.update(std.mem.asBytes(&port));
    return h.final();
}

fn encodeH3DatagramCapsule(allocator: Allocator, payload: []const u8) ![]u8 {
    // HTTP/3 datagram capsule (RFC 9297):
    // capsule-type (varint) = 0x00
    // capsule-length (varint) = payload length
    const header = try encodeQuicVarInt(allocator, 0);
    defer allocator.free(header);
    const len = try encodeQuicVarInt(allocator, payload.len);
    defer allocator.free(len);

    var out = try allocator.alloc(u8, header.len + len.len + payload.len);
    @memcpy(out[0..header.len], header);
    @memcpy(out[header.len .. header.len + len.len], len);
    @memcpy(out[header.len + len.len ..], payload);
    return out;
}

test "quic stub send" {
    const allocator = std.testing.allocator;
    const enabled = std.process.getEnvVarOwned(allocator, "VEXOR_QUIC_STUB") catch return;
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return;

    var quic_client = try SolanaTpuQuic.init(allocator, .{});
    defer quic_client.deinit();

    try quic_client.sendTransaction("127.0.0.1", 9999, "ping");
}

test "tpu client quic send stub" {
    const allocator = std.testing.allocator;
    const enabled = std.process.getEnvVarOwned(allocator, "VEXOR_QUIC_STUB") catch return;
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return;

    const client = try tpu_client.TpuClient.init(allocator, true, false, true, false, 0, true, 0);
    defer client.deinit();
    client.setQuicTargetOverride(packet.SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 9999));

    try client.sendTransaction("ping", 0, false);
}

fn encodeQuicVarInt(allocator: Allocator, value: usize) ![]u8 {
    var buf: [8]u8 = undefined;
    var len: usize = 0;
    if (value < 64) {
        buf[0] = @as(u8, @intCast(value & 0x3f));
        len = 1;
    } else if (value < 16384) {
        const v: u16 = @intCast(value);
        buf[0] = 0x40 | @as(u8, @intCast((v >> 8) & 0x3f));
        buf[1] = @as(u8, @intCast(v & 0xff));
        len = 2;
    } else if (value < (1 << 30)) {
        const v: u32 = @intCast(value);
        buf[0] = 0x80 | @as(u8, @intCast((v >> 24) & 0x3f));
        buf[1] = @as(u8, @intCast((v >> 16) & 0xff));
        buf[2] = @as(u8, @intCast((v >> 8) & 0xff));
        buf[3] = @as(u8, @intCast(v & 0xff));
        len = 4;
    } else {
        const v: u64 = @intCast(value);
        buf[0] = 0xc0 | @as(u8, @intCast((v >> 56) & 0x3f));
        buf[1] = @as(u8, @intCast((v >> 48) & 0xff));
        buf[2] = @as(u8, @intCast((v >> 40) & 0xff));
        buf[3] = @as(u8, @intCast((v >> 32) & 0xff));
        buf[4] = @as(u8, @intCast((v >> 24) & 0xff));
        buf[5] = @as(u8, @intCast((v >> 16) & 0xff));
        buf[6] = @as(u8, @intCast((v >> 8) & 0xff));
        buf[7] = @as(u8, @intCast(v & 0xff));
        len = 8;
    }

    const out = try allocator.alloc(u8, len);
    @memcpy(out, buf[0..len]);
    return out;
}

/// Solana network client (high-level API)
pub const SolanaNetworkClient = struct {
    allocator: Allocator,
    tpu_quic: *SolanaTpuQuic,
    identity: core.Pubkey,
    cluster: ClusterType,

    pub const ClusterType = enum {
        mainnet_beta,
        testnet,
        devnet,
        localnet,

        pub fn entrypoints(self: ClusterType) []const Entrypoint {
            return switch (self) {
                .mainnet_beta => &[_]Entrypoint{
                    .{ .host = "entrypoint.mainnet-beta.solana.com", .port = 8001 },
                    .{ .host = "entrypoint2.mainnet-beta.solana.com", .port = 8001 },
                    .{ .host = "entrypoint3.mainnet-beta.solana.com", .port = 8001 },
                },
                .testnet => &[_]Entrypoint{
                    .{ .host = "entrypoint.testnet.solana.com", .port = 8001 },
                },
                .devnet => &[_]Entrypoint{
                    .{ .host = "entrypoint.devnet.solana.com", .port = 8001 },
                },
                .localnet => &[_]Entrypoint{
                    .{ .host = "127.0.0.1", .port = 8001 },
                },
            };
        }
    };

    pub const Entrypoint = struct {
        host: []const u8,
        port: u16,
    };

    pub fn init(allocator: Allocator, identity: core.Pubkey, cluster: ClusterType) !*SolanaNetworkClient {
        const self = try allocator.create(SolanaNetworkClient);
        errdefer allocator.destroy(self);

        const tpu_quic = try SolanaTpuQuic.init(allocator, .{});

        self.* = .{
            .allocator = allocator,
            .tpu_quic = tpu_quic,
            .identity = identity,
            .cluster = cluster,
        };

        return self;
    }

    pub fn deinit(self: *SolanaNetworkClient) void {
        self.tpu_quic.deinit();
        self.allocator.destroy(self);
    }

    /// Send a transaction to the cluster
    pub fn sendTransaction(self: *SolanaNetworkClient, tpu_addr: []const u8, port: u16, tx: []const u8) !void {
        try self.tpu_quic.sendTransaction(tpu_addr, port, tx);
    }

    /// Get cluster entrypoints
    pub fn getEntrypoints(self: *const SolanaNetworkClient) []const Entrypoint {
        return self.cluster.entrypoints();
    }
};

// ============================================================================
// Compact-u16 encoding (Solana's variable-length integer format)
// ============================================================================

fn writeCompactU16(writer: anytype, value: u16) !void {
    if (value < 0x80) {
        try writer.writeByte(@truncate(value));
    } else if (value < 0x4000) {
        try writer.writeByte(@as(u8, @truncate(value & 0x7f)) | 0x80);
        try writer.writeByte(@truncate(value >> 7));
    } else {
        try writer.writeByte(@as(u8, @truncate(value & 0x7f)) | 0x80);
        try writer.writeByte(@as(u8, @truncate((value >> 7) & 0x7f)) | 0x80);
        try writer.writeByte(@truncate(value >> 14));
    }
}

fn readCompactU16(reader: anytype) !u16 {
    var result: u16 = 0;
    var shift: u4 = 0;

    while (shift < 16) {
        const byte = try reader.readByte();
        result |= @as(u16, byte & 0x7f) << shift;

        if (byte & 0x80 == 0) {
            break;
        }
        shift += 7;
    }

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "evict-on-full: oldestConnKey picks the min-timestamp connection (wedge fix)" {
    // 2026-06-23 QUIC-vote wedge fix: when the pool is full we evict the OLDEST connection (by
    // conn_created) to admit the current leader — never refuse. This KATs the victim-selection logic
    // (the eviction itself needs a live endpoint; the SELECTION is the fix's correctness core).
    const allocator = std.testing.allocator;
    var cc = std.AutoHashMap(u64, i64).init(allocator);
    defer cc.deinit();

    // empty → null (nothing to evict)
    try std.testing.expectEqual(@as(?u64, null), SolanaTpuQuic.oldestConnKey(&cc));

    // single entry → that key
    try cc.put(0xAAAA, 5000);
    try std.testing.expectEqual(@as(?u64, 0xAAAA), SolanaTpuQuic.oldestConnKey(&cc));

    // multiple → the minimum timestamp wins (oldest = evicted)
    try cc.put(0xBBBB, 1000); // oldest
    try cc.put(0xCCCC, 9000);
    try cc.put(0xDDDD, 3000);
    try std.testing.expectEqual(@as(?u64, 0xBBBB), SolanaTpuQuic.oldestConnKey(&cc));

    // after removing the oldest, the next-oldest is selected (pool recycles in age order)
    _ = cc.remove(0xBBBB);
    try std.testing.expectEqual(@as(?u64, 0xDDDD), SolanaTpuQuic.oldestConnKey(&cc));

    // sanity: the cap is FD-aligned and small enough to never saturate under eviction
    try std.testing.expect(SolanaTpuQuic.MAX_VOTE_CONNS == 128);
}

test "dead-target cache: recent handshake failure skipped, TTL expiry retried (vote-fanout hygiene)" {
    // 2026-07-10 negative-endorsement memory. pruneDeadConnections stamps a dead target; the vote
    // pre-filter (TpuClient.enqueueVote → isDeadCached) skips QUIC enqueue while the stamp is fresh
    // and RETRIES once it ages past DEAD_LEADER_TTL_MS. This KATs the pure TTL decision (isDeadTarget)
    // over the map directly — no live endpoint needed (mirrors the oldestConnKey selection KAT).
    const allocator = std.testing.allocator;
    var dt = std.AutoHashMap(u64, i64).init(allocator);
    defer dt.deinit();
    const ttl = SolanaTpuQuic.DEAD_LEADER_TTL_MS;
    const key: u64 = 0xDEAD_1EA6;

    // absent → not dead (a never-failed leader is always enqueued)
    try std.testing.expect(!SolanaTpuQuic.isDeadTarget(&dt, key, 1_000_000, ttl));

    // just failed at t=1_000_000 → dead-cached → skipped for the whole window
    try dt.put(key, 1_000_000);
    try std.testing.expect(SolanaTpuQuic.isDeadTarget(&dt, key, 1_000_000, ttl)); // same instant
    try std.testing.expect(SolanaTpuQuic.isDeadTarget(&dt, key, 1_000_000 + ttl, ttl)); // TTL boundary (inclusive)
    try std.testing.expect(SolanaTpuQuic.isDeadTarget(&dt, key, 1_000_000 + ttl - 1, ttl)); // inside window

    // one ms past the TTL → no longer dead → the leader is RETRIED
    try std.testing.expect(!SolanaTpuQuic.isDeadTarget(&dt, key, 1_000_000 + ttl + 1, ttl));

    // a DIFFERENT target that never failed is unaffected (per-target, not global)
    try std.testing.expect(!SolanaTpuQuic.isDeadTarget(&dt, 0xF00D, 1_000_000, ttl));

    // sanity: the TTL is the 2-minute window
    try std.testing.expect(SolanaTpuQuic.DEAD_LEADER_TTL_MS == 120_000);
}

test "compact-u16 encoding" {
    const allocator = std.testing.allocator;
    var buffer: std.ArrayListUnmanaged(u8) = .{};
    defer buffer.deinit(allocator);

    // Test small value
    try writeCompactU16(buffer.writer(allocator), 42);
    try std.testing.expectEqual(@as(usize, 1), buffer.items.len);

    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try readCompactU16(stream.reader());
    try std.testing.expectEqual(@as(u16, 42), decoded);
}

test "compact-u16 encoding large" {
    const allocator = std.testing.allocator;
    var buffer: std.ArrayListUnmanaged(u8) = .{};
    defer buffer.deinit(allocator);

    // Test larger value
    try writeCompactU16(buffer.writer(allocator), 16384);

    var stream = std.io.fixedBufferStream(buffer.items);
    const decoded = try readCompactU16(stream.reader());
    try std.testing.expectEqual(@as(u16, 16384), decoded);
}

test "SolanaTpuQuic init" {
    const allocator = std.testing.allocator;

    const tpu = try SolanaTpuQuic.init(allocator, .{});
    defer tpu.deinit();

    try std.testing.expect(!tpu.running.load(.acquire));
}

test "shouldPrewarmCaughtUp gate: prewarm only when frontier is within slack of tip" {
    const slack: u64 = 8;
    // Caught up: frontier at/near the tip → prewarm ON.
    try std.testing.expect(SolanaTpuQuic.shouldPrewarmCaughtUp(1000, 1000, slack)); // exactly at tip
    try std.testing.expect(SolanaTpuQuic.shouldPrewarmCaughtUp(1000, 1008, slack)); // tip-frontier == slack
    try std.testing.expect(SolanaTpuQuic.shouldPrewarmCaughtUp(1000, 1005, slack)); // within slack
    try std.testing.expect(SolanaTpuQuic.shouldPrewarmCaughtUp(1010, 1000, slack)); // frontier ahead of tip
    // Catching up: frontier far behind tip → prewarm OFF (the 2026-06-18 catch-up-stall guard).
    try std.testing.expect(!SolanaTpuQuic.shouldPrewarmCaughtUp(1000, 1009, slack)); // tip-frontier > slack
    try std.testing.expect(!SolanaTpuQuic.shouldPrewarmCaughtUp(1000, 50000, slack)); // deep catch-up
    // Pre-boot guards: either side zero → OFF.
    try std.testing.expect(!SolanaTpuQuic.shouldPrewarmCaughtUp(0, 1000, slack));
    try std.testing.expect(!SolanaTpuQuic.shouldPrewarmCaughtUp(1000, 0, slack));
}

// ── QUIC TPU-INGEST LOOPBACK KAT (2026-06-15) ───────────────────────────────
// Our QUIC client -> our QUIC server on localhost: open a uni-stream, send one tx with FIN, and assert
// the server's transaction_callback fires with the EXACT bytes. This is the end-to-end gate for the
// ingest bring-up (step1 dup-send, step2 FIN, step3 role-aware crypto, step4 server handshake).
// The server self-pumps poll() on a background thread because the client's getOrConnect->waitForHandshake
// polls ONLY the client; the server side must advance its handshake concurrently.
const LoopbackCapture = struct {
    got: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    mutex: std.Thread.Mutex = .{},
    buf: [2048]u8 = undefined,
    len: usize = 0,

    fn onTx(ctx: ?*anyopaque, data: []const u8) void {
        const self: *LoopbackCapture = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        const n = @min(data.len, self.buf.len);
        @memcpy(self.buf[0..n], data[0..n]);
        self.len = n;
        self.got.store(true, .release);
    }
};

const LoopbackServerCtx = struct {
    server: *SolanaTpuQuic,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn loopbackServerPump(ctx: *LoopbackServerCtx) void {
    while (!ctx.stop.load(.acquire)) {
        ctx.server.poll() catch {};
        std.Thread.sleep(200 * std.time.ns_per_us);
    }
}

test "QUIC ingest loopback: client -> server -> callback exact bytes" {
    const allocator = std.testing.allocator;
    const server_port: u16 = 19011;

    var server = try SolanaTpuQuic.init(allocator, .{ .is_server = true, .bind_port = server_port, .allow_insecure = true });
    defer server.deinit();
    try server.listen(server_port);

    var cap = LoopbackCapture{};
    server.setTransactionCallback(&cap, LoopbackCapture.onTx);

    var sctx = LoopbackServerCtx{ .server = server };
    const th = try std.Thread.spawn(.{}, loopbackServerPump, .{&sctx});
    defer {
        sctx.stop.store(true, .release);
        th.join();
    }

    var client = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client.deinit();

    var tx: [256]u8 = undefined;
    for (&tx, 0..) |*b, i| b.* = @intCast((i *% 7 + 3) & 0xff);

    client.sendTransaction("127.0.0.1", server_port, &tx) catch |err| {
        std.debug.print("[loopback KAT] sendTransaction failed: {} (server handshake incomplete?)\n", .{err});
        return err;
    };

    var spins: usize = 0;
    while (!cap.got.load(.acquire) and spins < 5000) : (spins += 1) {
        client.poll() catch {};
        std.Thread.sleep(200 * std.time.ns_per_us);
    }

    try std.testing.expect(cap.got.load(.acquire));
    cap.mutex.lock();
    defer cap.mutex.unlock();
    try std.testing.expectEqual(@as(usize, tx.len), cap.len);
    try std.testing.expectEqualSlices(u8, &tx, cap.buf[0..cap.len]);
}

// ── PREWARM KATs (2026-06-28) ───────────────────────────────────────────────
// Offline validation of the targeted vote-leader prewarm. Test 1 = the SAFETY invariants the
// 2026-06-23 wedge fix depends on (pool never exceeds MAX_VOTE_CONNS; connections/conn_created stay
// parallel so prune ages correctly). Test 2 = the connect-ahead PREMISE (a prewarmed connection reaches
// handshake_complete via poll() ALONE — no send — so a later vote lands at slot-start). Loopback uses
// allow_insecure (no real-leader mTLS) + one local peer, so these prove the connection MECHANICS, not
// real-leader cert acceptance or leader-resolution — that's the inherent offline limit, validated live
// via the credit-rate A/B.

test "prewarm: honors MAX_VOTE_CONNS pool cap + keeps connections/conn_created parallel" {
    const allocator = std.testing.allocator;
    var client = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client.deinit();

    // Prewarm to MAX_VOTE_CONNS+4 DISTINCT targets. connect() is non-blocking — it creates a pool entry
    // even with no peer listening (handshake just never completes). This is the only path that could
    // breach the 128 invariant if prewarm didn't evict-on-full.
    var i: u16 = 0;
    while (i < SolanaTpuQuic.MAX_VOTE_CONNS + 4) : (i += 1) {
        client.prewarm("127.0.0.1", 20000 + i);
    }
    // INVARIANT 1: pool is bounded — prewarm evicted-on-full and NEVER exceeded the cap.
    try std.testing.expect(client.connections.count() <= SolanaTpuQuic.MAX_VOTE_CONNS);
    // INVARIANT 2: the two maps are perfectly parallel (prewarm populates conn_created; evict removes from
    // both). A divergence here is the leak/mis-age bug the conn_created fix closes.
    try std.testing.expectEqual(client.connections.count(), client.conn_created.count());
    // Sanity: connects actually succeeded (else the cap was never exercised).
    try std.testing.expect(client.connections.count() > 0);
    // Idempotent: re-prewarming a still-pooled target neither grows the pool nor desyncs the maps.
    client.prewarm("127.0.0.1", 20000 + SolanaTpuQuic.MAX_VOTE_CONNS + 3); // newest → not yet evicted
    try std.testing.expect(client.connections.count() <= SolanaTpuQuic.MAX_VOTE_CONNS);
    try std.testing.expectEqual(client.connections.count(), client.conn_created.count());
}

test "prewarm: connect-ahead completes the handshake via poll() alone (no send)" {
    const allocator = std.testing.allocator;
    const server_port: u16 = 19031;

    var server = try SolanaTpuQuic.init(allocator, .{ .is_server = true, .bind_port = server_port, .allow_insecure = true });
    defer server.deinit();
    try server.listen(server_port);
    var sctx = LoopbackServerCtx{ .server = server };
    const th = try std.Thread.spawn(.{}, loopbackServerPump, .{&sctx});
    defer {
        sctx.stop.store(true, .release);
        th.join();
    }

    var client = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client.deinit();

    // Prewarm only — NOT a send. The premise: the handshake finishes off the send path.
    client.prewarm("127.0.0.1", server_port);
    try std.testing.expectEqual(@as(usize, 1), client.connections.count());
    try std.testing.expectEqual(@as(usize, 1), client.conn_created.count()); // parallel from the start

    // Drive to completion purely via poll() (what the dedicated poller thread does every 1ms).
    var spins: usize = 0;
    var ready = false;
    while (spins < 5000 and !ready) : (spins += 1) {
        client.poll() catch {};
        ready = client.isReadyNonBlocking("127.0.0.1", server_port);
        std.Thread.sleep(200 * std.time.ns_per_us);
    }
    // The prewarmed connection reached handshake_complete with NO send — so a later vote lands warm.
    try std.testing.expect(ready);
}

// ── EDGE-CASE INGEST KATs (2026-06-15) ──────────────────────────────────────
// Added alongside the base loopback KAT to harden the dormant QUIC TPU-ingest path:
//   B1 max-size tx (MAX_TX_SIZE bytes; QUIC packetization boundary)
//   B2 multiple txs on ONE connection (per-stream FIN/buffer-clear correctness)
//   B3 a second independent client connection to the same server (server demux)
// All reuse LoopbackServerCtx + loopbackServerPump and the server-thread + client.poll
// wait pattern from the base test, with distinct ports to avoid bind conflicts.

test "QUIC ingest loopback B1: max-size tx exact bytes" {
    const allocator = std.testing.allocator;
    const server_port: u16 = 19012;

    var server = try SolanaTpuQuic.init(allocator, .{ .is_server = true, .bind_port = server_port, .allow_insecure = true });
    defer server.deinit();
    try server.listen(server_port);

    var cap = LoopbackCapture{};
    server.setTransactionCallback(&cap, LoopbackCapture.onTx);

    var sctx = LoopbackServerCtx{ .server = server };
    const th = try std.Thread.spawn(.{}, loopbackServerPump, .{&sctx});
    defer {
        sctx.stop.store(true, .release);
        th.join();
    }

    var client = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client.deinit();

    // Exactly MAX_TX_SIZE bytes (the guard rejects only > MAX_TX_SIZE, so == is allowed),
    // filled with a counted pattern so any truncation/corruption is detectable.
    var tx: [MAX_TX_SIZE]u8 = undefined;
    for (&tx, 0..) |*b, i| b.* = @intCast((i *% 31 + 17) & 0xff);

    client.sendTransaction("127.0.0.1", server_port, &tx) catch |err| {
        std.debug.print("[loopback KAT B1] sendTransaction failed: {} (server handshake incomplete?)\n", .{err});
        return err;
    };

    var spins: usize = 0;
    while (!cap.got.load(.acquire) and spins < 10000) : (spins += 1) {
        client.poll() catch {};
        std.Thread.sleep(200 * std.time.ns_per_us);
    }

    try std.testing.expect(cap.got.load(.acquire));
    cap.mutex.lock();
    defer cap.mutex.unlock();
    // If this fails with a SHORT len, the max-size tx was truncated at a QUIC
    // packetization boundary — a real framing bug, not a test artifact.
    try std.testing.expectEqual(@as(usize, tx.len), cap.len);
    try std.testing.expectEqualSlices(u8, &tx, cap.buf[0..cap.len]);
}

// Multi-tx capture: records each received tx independently so we can assert
// count==N and content membership (NOT order — poll() iterates streams via a
// hashmap iterator, so callback fire order is not the send order).
const MultiCapture = struct {
    // 16 ≥ the largest B-series fan-out (B4 sends max_streams_per_connection+4 = 12 distinct txs on
    // ONE connection). MUST stay ≥ N for any test: containsExactly only scans @min(count, MAX_RECORDS)
    // and the onTx overflow path bumps `count` WITHOUT storing, so an undersized cap would let a
    // count assertion pass while silently skipping per-tx content checks for the overflow txs.
    const MAX_RECORDS = 16;
    mutex: std.Thread.Mutex = .{},
    count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    lens: [MAX_RECORDS]usize = [_]usize{0} ** MAX_RECORDS,
    bufs: [MAX_RECORDS][2048]u8 = undefined,

    fn onTx(ctx: ?*anyopaque, data: []const u8) void {
        const self: *MultiCapture = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = self.count.load(.monotonic);
        if (idx >= MAX_RECORDS) {
            // Overflow = more callbacks than expected (e.g. a refire bug). Still bump the
            // count so the test's count assertion catches it rather than silently dropping.
            _ = self.count.fetchAdd(1, .release);
            return;
        }
        const n = @min(data.len, self.bufs[idx].len);
        @memcpy(self.bufs[idx][0..n], data[0..n]);
        self.lens[idx] = n;
        _ = self.count.fetchAdd(1, .release);
    }

    /// Returns true exactly once if `expected` matches one recorded tx by exact bytes.
    fn containsExactly(self: *MultiCapture, expected: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        var hits: usize = 0;
        const n = @min(self.count.load(.monotonic), MAX_RECORDS);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            if (self.lens[i] == expected.len and
                std.mem.eql(u8, self.bufs[i][0..self.lens[i]], expected))
            {
                hits += 1;
            }
        }
        return hits == 1;
    }
};

test "QUIC ingest loopback B2: multiple txs on one connection" {
    const allocator = std.testing.allocator;
    const server_port: u16 = 19013;

    var server = try SolanaTpuQuic.init(allocator, .{ .is_server = true, .bind_port = server_port, .allow_insecure = true });
    defer server.deinit();
    try server.listen(server_port);

    var cap = MultiCapture{};
    server.setTransactionCallback(&cap, MultiCapture.onTx);

    var sctx = LoopbackServerCtx{ .server = server };
    const th = try std.Thread.spawn(.{}, loopbackServerPump, .{&sctx});
    defer {
        sctx.stop.store(true, .release);
        th.join();
    }

    var client = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client.deinit();

    // 3 distinct txs: distinct LENGTHS and distinct PATTERNS so membership matching is
    // unambiguous and concatenation/truncation/buffer-not-cleared bugs surface as wrong length.
    var tx_a: [100]u8 = undefined;
    for (&tx_a, 0..) |*b, i| b.* = @intCast((i *% 7 + 3) & 0xff);
    var tx_b: [777]u8 = undefined;
    for (&tx_b, 0..) |*b, i| b.* = @intCast((i *% 13 + 5) & 0xff);
    var tx_c: [MAX_TX_SIZE]u8 = undefined;
    for (&tx_c, 0..) |*b, i| b.* = @intCast((i *% 251 + 19) & 0xff);

    // 3 separate uni-streams over the SAME connection (getOrConnect caches by host:port).
    try client.sendTransaction("127.0.0.1", server_port, &tx_a);
    try client.sendTransaction("127.0.0.1", server_port, &tx_b);
    try client.sendTransaction("127.0.0.1", server_port, &tx_c);

    var spins: usize = 0;
    while (cap.count.load(.acquire) < 3 and spins < 20000) : (spins += 1) {
        client.poll() catch {};
        std.Thread.sleep(200 * std.time.ns_per_us);
    }

    // Exactly 3, not more: a count > 3 would mean a per-stream refire bug (FIN buffer not cleared).
    try std.testing.expectEqual(@as(usize, 3), cap.count.load(.acquire));
    try std.testing.expect(cap.containsExactly(&tx_a));
    try std.testing.expect(cap.containsExactly(&tx_b));
    try std.testing.expect(cap.containsExactly(&tx_c));
}

test "QUIC ingest loopback B3: two independent connections to one server" {
    const allocator = std.testing.allocator;
    const server_port: u16 = 19014;

    var server = try SolanaTpuQuic.init(allocator, .{ .is_server = true, .bind_port = server_port, .allow_insecure = true });
    defer server.deinit();
    try server.listen(server_port);

    var cap = MultiCapture{};
    server.setTransactionCallback(&cap, MultiCapture.onTx);

    var sctx = LoopbackServerCtx{ .server = server };
    const th = try std.Thread.spawn(.{}, loopbackServerPump, .{&sctx});
    defer {
        sctx.stop.store(true, .release);
        th.join();
    }

    // Two separate client INSTANCES → two distinct QUIC connections to the same server:port,
    // exercising the server's per-connection demux.
    var client1 = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client1.deinit();
    var client2 = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client2.deinit();

    var tx1: [120]u8 = undefined;
    for (&tx1, 0..) |*b, i| b.* = @intCast((i *% 11 + 1) & 0xff);
    var tx2: [340]u8 = undefined;
    for (&tx2, 0..) |*b, i| b.* = @intCast((i *% 17 + 9) & 0xff);

    try client1.sendTransaction("127.0.0.1", server_port, &tx1);
    try client2.sendTransaction("127.0.0.1", server_port, &tx2);

    var spins: usize = 0;
    while (cap.count.load(.acquire) < 2 and spins < 20000) : (spins += 1) {
        client1.poll() catch {};
        client2.poll() catch {};
        std.Thread.sleep(200 * std.time.ns_per_us);
    }

    try std.testing.expectEqual(@as(usize, 2), cap.count.load(.acquire));
    try std.testing.expect(cap.containsExactly(&tx1));
    try std.testing.expect(cap.containsExactly(&tx2));
}

// B4 (2026-06-29) — uni-stream RETIRE fix. Proves the connection no longer JAMS after
// max_streams_per_connection sends. Before the fix, client uni-streams were never removed from
// conn.streams, so openUniStream returned error.TooManyStreams once streams.count() >= 8 → every
// vote QUIC connection stalled after ~8 sends (live fingerprint txs_sent_quic ≈ 8 × pool). The fix
// retires each uni-stream the instant conn.send returns (send is synchronous; no stream-data
// retransmit references the Stream), so an unbounded number of txs flow over ONE connection.
test "QUIC ingest loopback B4: >max_streams_per_connection txs on one connection (uni-stream retire)" {
    const allocator = std.testing.allocator;
    const server_port: u16 = 19015;

    // N MUST EXCEED the CLIENT's max_streams_per_connection (default 8) so the count-gate escape is
    // what's under test. Without the fix, send #9 fails at openUniStream → fewer than N arrive.
    const N: usize = 12; // = default max_streams_per_connection (8) + 4

    var server = try SolanaTpuQuic.init(allocator, .{ .is_server = true, .bind_port = server_port, .allow_insecure = true });
    defer server.deinit();
    try server.listen(server_port);

    var cap = MultiCapture{}; // MAX_RECORDS=16 ≥ N, so per-tx content checks cover all N
    server.setTransactionCallback(&cap, MultiCapture.onTx);

    var sctx = LoopbackServerCtx{ .server = server };
    const th = try std.Thread.spawn(.{}, loopbackServerPump, .{&sctx});
    defer {
        sctx.stop.store(true, .release);
        th.join();
    }

    // Client keeps the DEFAULT max_streams_per_connection=8 — the cap whose count-gate we are proving
    // we can now exceed on a single connection. (The server advertises uni-credit=100, so the RFC
    // peer-credit gate does NOT mask the count-gate fix.)
    var client = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client.deinit();

    // N DISTINCT txs — each a unique LENGTH and PATTERN so containsExactly membership is unambiguous
    // (distinct lengths alone already disambiguate; the pattern is keyed by index for extra safety).
    var txs: [N][512]u8 = undefined;
    var lens: [N]usize = undefined;
    for (0..N) |i| {
        const len = 64 + i * 37; // 64..64+11*37=471 bytes, all <= MAX_TX_SIZE
        lens[i] = len;
        for (0..len) |j| txs[i][j] = @intCast((i *% 37 + j *% 7 + 11) & 0xff);
    }

    // All N over the SAME connection (getOrConnect caches by host:port). Send #9 onward is the proof:
    // without the retire fix, openUniStream returns error.TooManyStreams here and the test fails.
    for (0..N) |i| {
        client.sendTransaction("127.0.0.1", server_port, txs[i][0..lens[i]]) catch |err| {
            std.debug.print("[loopback KAT B4] send {d}/{d} failed: {} (count-gate JAM = retire fix NOT working)\n", .{ i + 1, N, err });
            return err;
        };
    }

    var spins: usize = 0;
    while (cap.count.load(.acquire) < N and spins < 40000) : (spins += 1) {
        client.poll() catch {};
        std.Thread.sleep(200 * std.time.ns_per_us);
    }

    // (a) ALL N arrived at the server callback, byte-exact. Without the fix only ~8 ever send.
    try std.testing.expectEqual(N, cap.count.load(.acquire));
    for (0..N) |i| try std.testing.expect(cap.containsExactly(txs[i][0..lens[i]]));

    // (b) DIRECT proof the streams were retired: the client's connection holds 0 streams after all N
    //     sends (each conn.send retired its uni-stream). Without the fix this would be pinned at 8.
    const conn = client.connections.get(hashTarget("127.0.0.1", server_port)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.streams.count());
}

// ── QUIC INGEST → MEMPOOL INTEGRATION KAT (2026-06-15) ───────────────────────
// The full dormant ingest path, end to end: a real (self-signed, well-formed) Solana transaction
// sent by the QUIC client lands ENQUEUED in the BankingStage mempool, byte-identical, retrievable
// via drainBatch. This is the actual deliverable gate — not "the raw callback fired" (that's the
// loopback KAT above) but "a QUIC-sent tx reached the mempool, parse-validated and byte-correct".
//
//   client.sendTransaction(real_tx)
//       → server FIN → QuicIngestAdapter.onTransaction
//           → tx_ingest.parse (accepts: well-formed) → BankingStage.queueTransaction (deep-copy)
//       → drainBatch() → assert exact bytes
//
// banking_stage + quic_ingest_adapter are imported only inside this test block, so the main build's
// module graph is untouched (Zig analyzes test blocks only in test builds).
const banking_stage = @import("banking_stage");
const quic_ingest_adapter = @import("quic_ingest_adapter");

/// Build a minimal VALID legacy single-signer transaction into `out`, returning the wire slice.
/// Mirrors tx_ingest.buildSingleSignerTx so tx_ingest.parse accepts it (a random byte blob would be
/// rejected as malformed and never reach the queue — the point of this KAT is the accept path).
fn buildValidTx(kp: std.crypto.sign.Ed25519.KeyPair, out: []u8) []u8 {
    var mpos: usize = 1 + 64; // compactU16(1)=0x01 sig-count, then the 64-byte signature
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 0; // num_readonly_unsigned
    mpos += 3;
    out[mpos] = 1; // compactU16: 1 account key
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes); // signer key
    mpos += 32;
    @memset(out[mpos..][0..32], 0); // recent blockhash
    mpos += 32;
    out[mpos] = 0; // compactU16: 0 instructions
    mpos += 1;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1; // compactU16: 1 signature
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

test "QUIC ingest → mempool: QUIC-sent tx is enqueued in BankingStage, byte-correct" {
    const allocator = std.testing.allocator;
    const server_port: u16 = 19015;

    // Real mempool.
    var banking = banking_stage.BankingStage.init(allocator, .{});
    defer banking.deinit();

    // Adapter bridges the QUIC raw-bytes callback into the mempool.
    var adapter = quic_ingest_adapter.QuicIngestAdapter.init(&banking);

    var server = try SolanaTpuQuic.init(allocator, .{ .is_server = true, .bind_port = server_port, .allow_insecure = true });
    defer server.deinit();
    try server.listen(server_port);
    server.setTransactionCallback(&adapter, quic_ingest_adapter.QuicIngestAdapter.onTransaction);

    var sctx = LoopbackServerCtx{ .server = server };
    const th = try std.Thread.spawn(.{}, loopbackServerPump, .{&sctx});
    defer {
        sctx.stop.store(true, .release);
        th.join();
    }

    var client = try SolanaTpuQuic.init(allocator, .{ .is_server = false, .bind_port = 0, .allow_insecure = true });
    defer client.deinit();

    // A real, well-formed, self-signed tx — so tx_ingest.parse accepts it and it reaches the queue.
    const seed = [_]u8{0x5a} ** 32;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var txbuf: [256]u8 = undefined;
    const tx = buildValidTx(kp, &txbuf);

    try client.sendTransaction("127.0.0.1", server_port, tx);

    // Wait for the tx to traverse QUIC → adapter → queueTransaction (the queue depth becomes 1).
    var spins: usize = 0;
    while (banking.queueDepth() == 0 and spins < 10000) : (spins += 1) {
        client.poll() catch {};
        std.Thread.sleep(200 * std.time.ns_per_us);
    }

    // It reached the MEMPOOL (not merely the raw callback).
    try std.testing.expectEqual(@as(usize, 1), banking.queueDepth());

    // Drain it back out and assert it is byte-identical to what the client sent.
    const batch = try banking.drainBatch();
    defer {
        for (batch) |qt| allocator.free(qt.data);
        allocator.free(batch);
    }
    try std.testing.expectEqual(@as(usize, 1), batch.len);
    try std.testing.expectEqual(tx.len, batch[0].data.len);
    try std.testing.expectEqualSlices(u8, tx, batch[0].data);
    try std.testing.expectEqual(banking_stage.QueuedTransaction.Source.tpu, batch[0].source);
}

test "QUIC ingest adapter rejects malformed bytes (does NOT enqueue garbage)" {
    const allocator = std.testing.allocator;
    var banking = banking_stage.BankingStage.init(allocator, .{});
    defer banking.deinit();
    var adapter = quic_ingest_adapter.QuicIngestAdapter.init(&banking);

    // A short random blob is not a well-formed tx → must be rejected, queue stays empty.
    const junk = [_]u8{ 1, 2, 3, 4, 5 };
    try std.testing.expectError(error.Malformed, adapter.ingest(&junk));
    try std.testing.expectEqual(@as(usize, 0), banking.queueDepth());
}
