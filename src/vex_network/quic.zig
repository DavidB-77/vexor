//! Vexor QUIC Transport
//!
//! QUIC/HTTP3 implementation for secure, low-latency communication.
//! Used for TPU (Transaction Processing Unit) connections.
//!
//! Features:
//! - TLS 1.3 encryption
//! - Zero-RTT connection resumption
//! - Multiplexed streams
//! - Flow control
//! - Connection migration
//! - MASQUE proxy support

const std = @import("std");
const packet = @import("packet.zig");
const socket = @import("socket.zig");
const tls13 = @import("tls13.zig");

/// QUIC version constants
pub const QUIC_VERSION_1: u32 = 0x00000001;
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;

/// QUIC frame types
pub const FrameType = enum(u8) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08, // 0x08 - 0x0f
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    datagram = 0x30, // RFC 9221
};

/// QUIC packet types
pub const PacketType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

fn logPacket(direction: []const u8, pkt_type: PacketType, pn: u64, payload_len: usize) void {
    std.log.debug("[QUIC] {s} {s} pn={d} payload={d}\n", .{
        direction,
        @tagName(pkt_type),
        pn,
        payload_len,
    });
}

fn logHex(prefix: []const u8, data: []const u8, max_len: usize) void {
    const len = @min(data.len, max_len);
    std.log.debug("{s}", .{prefix});
    var i: usize = 0;
    while (i < len) : (i += 1) {
        std.log.debug(" {x:0>2}", .{data[i]});
    }
    std.log.debug("\n", .{});
}

fn encodeVarInt(value: u64, buf: []u8) usize {
    if (value < (1 << 6)) {
        buf[0] = @intCast(value & 0x3f);
        return 1;
    }
    if (value < (1 << 14)) {
        buf[0] = @intCast(0x40 | ((value >> 8) & 0x3f));
        buf[1] = @intCast(value & 0xff);
        return 2;
    }
    if (value < (1 << 30)) {
        buf[0] = @intCast(0x80 | ((value >> 24) & 0x3f));
        buf[1] = @intCast((value >> 16) & 0xff);
        buf[2] = @intCast((value >> 8) & 0xff);
        buf[3] = @intCast(value & 0xff);
        return 4;
    }
    buf[0] = @intCast(0xc0 | ((value >> 56) & 0x3f));
    buf[1] = @intCast((value >> 48) & 0xff);
    buf[2] = @intCast((value >> 40) & 0xff);
    buf[3] = @intCast((value >> 32) & 0xff);
    buf[4] = @intCast((value >> 24) & 0xff);
    buf[5] = @intCast((value >> 16) & 0xff);
    buf[6] = @intCast((value >> 8) & 0xff);
    buf[7] = @intCast(value & 0xff);
    return 8;
}

fn reconstructPacketNumber(truncated: u64, pn_len: usize, expected: u64) u64 {
    const pn_window: u64 = @as(u64, 1) << @intCast(pn_len * 8);
    const pn_half = pn_window / 2;
    const mask = pn_window - 1;
    var candidate = (expected & ~mask) | truncated;
    if (candidate + pn_half <= expected and candidate + pn_window <= std.math.maxInt(u64)) {
        candidate += pn_window;
    } else if (candidate > expected + pn_half and candidate >= pn_window) {
        candidate -= pn_window;
    }
    return candidate;
}

fn decodeVarInt(data: []const u8, out: *u64) ?usize {
    if (data.len == 0) return null;
    const first = data[0];
    const tag = first >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        else => 8,
    };
    if (data.len < len) return null;
    var value: u64 = first & 0x3f;
    var i: usize = 1;
    while (i < len) : (i += 1) {
        value = (value << 8) | data[i];
    }
    out.* = value;
    return len;
}

/// QUIC connection ID (up to 20 bytes)
pub const ConnectionId = struct {
    data: [20]u8,
    len: u8,

    pub fn generate() ConnectionId {
        var id = ConnectionId{ .data = undefined, .len = 8 };
        std.crypto.random.bytes(id.data[0..8]);
        return id;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.data[0..self.len];
    }

    pub fn eql(self: *const ConnectionId, other: *const ConnectionId) bool {
        if (self.len != other.len) return false;
        return std.mem.eql(u8, self.slice(), other.slice());
    }
};

/// QUIC connection state
pub const Connection = struct {
    allocator: std.mem.Allocator,
    endpoint: *Endpoint,

    /// Local connection ID
    local_cid: ConnectionId,

    /// Remote connection ID
    remote_cid: ConnectionId,
    /// Initial destination CID used for Initial keys
    initial_dcid: ConnectionId,

    /// Connection state
    state: State,

    /// Peer address
    peer_addr: packet.SocketAddr,

    /// Active streams
    streams: std.AutoHashMap(u64, *Stream),

    /// Next stream ID (client: odd for bidi, even for uni)
    next_bidi_stream_id: u64,
    next_uni_stream_id: u64,

    /// Peer-granted CUMULATIVE max stream counts (RFC 9000 MAX_STREAMS / the
    /// initial_max_streams_* transport params). DEFAULT 0: RFC 9000 §18.2 — an
    /// absent initial_max_streams_uni means the peer grants ZERO streams until it
    /// sends a MAX_STREAMS_UNI (0x13) frame. Real testnet leaders OMIT the param
    /// and grant ~254+ via the frame (captured 2026-06-20), so this MUST start at 0
    /// and grow only on a decoded transport param or a parsed 0x13/0x12 frame —
    /// never an optimistic local guess (which causes STREAM_LIMIT_ERROR → conn death).
    peer_max_streams_uni: u64 = 0,
    peer_max_streams_bidi: u64 = 0,

    /// TLS state
    tls: TlsState,
    /// TLS handshake CRYPTO buffer
    crypto_recv: std.ArrayList(u8),
    /// Cached ClientHello for retransmit
    client_hello: ?[]u8,

    /// Flow control
    max_data_local: u64,
    max_data_remote: u64,
    bytes_sent: u64,
    bytes_received: u64,

    /// Packet numbers
    next_pkt_num: u64,
    largest_acked_pkt: u64,
    largest_rx_pn: u64,
    next_handshake_pkt_num: u64,
    next_app_pkt_num: u64,

    /// Loss detection state
    loss_detector: LossDetector,
    /// Congestion control state
    congestion: CongestionController,

    /// Statistics
    stats: ConnectionStats,

    /// Current Path MTU
    mtu: u16 = 1232, // Default safe UDP payload size
    /// Helper for PMTUD
    pmtud_last_probe_time: i64 = 0,
    pmtud_probes_sent: u8 = 0,

    pub const State = enum {
        initial,
        handshake,
        connected,
        closing,
        draining,
        closed,
    };

    pub const ConnectionStats = struct {
        packets_sent: u64 = 0,
        packets_received: u64 = 0,
        packets_lost: u64 = 0,
        bytes_sent: u64 = 0,
        bytes_received: u64 = 0,
        streams_opened: u64 = 0,
        frames_sent: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, endpoint: *Endpoint, peer_addr: packet.SocketAddr, is_server: bool) !*Self {
        const conn = try allocator.create(Self);
        const initial_dcid = ConnectionId.generate();
        conn.* = .{
            .allocator = allocator,
            .endpoint = endpoint,
            .local_cid = ConnectionId.generate(),
            .remote_cid = initial_dcid,
            .initial_dcid = initial_dcid,
            .state = .initial,
            .peer_addr = peer_addr,
            .streams = std.AutoHashMap(u64, *Stream).init(allocator),
            .next_bidi_stream_id = if (is_server) 1 else 0, // Server: odd, Client: even
            .next_uni_stream_id = if (is_server) 3 else 2,
            .tls = TlsState.init(allocator),
            .crypto_recv = .empty,
            .client_hello = null,
            .max_data_local = 1024 * 1024, // 1MB initial
            .max_data_remote = endpoint.config.initial_max_data,
            .bytes_sent = 0,
            .bytes_received = 0,
            .next_pkt_num = 0,
            .largest_acked_pkt = 0,
            .largest_rx_pn = 0,
            .next_handshake_pkt_num = 0,
            .next_app_pkt_num = 0,
            .loss_detector = LossDetector.init(allocator),
            .congestion = CongestionController.init(),
            .stats = .{},
            .mtu = 1232,
            .pmtud_last_probe_time = 0,
            .pmtud_probes_sent = 0,
        };
        return conn;
    }

    pub fn deinit(self: *Self) void {
        var iter = self.streams.valueIterator();
        while (iter.next()) |stream| {
            stream.*.deinit();
        }
        self.streams.deinit();
        self.loss_detector.deinit();
        self.crypto_recv.deinit(self.allocator);
        if (self.client_hello) |hello| {
            self.allocator.free(hello);
        }
        self.allocator.destroy(self);
    }

    /// Open a new bidirectional stream
    pub fn openBidiStream(self: *Self) !*Stream {
        if (self.streams.count() >= self.endpoint.config.max_streams_per_connection) {
            return error.TooManyStreams;
        }
        const stream_id = self.next_bidi_stream_id;
        self.next_bidi_stream_id += 4; // Increment by 4 for next stream of same type

        const stream = try Stream.init(self.allocator, self, stream_id);
        stream.max_stream_data_remote = self.endpoint.config.initial_max_stream_data;
        try self.streams.put(stream_id, stream);
        self.stats.streams_opened += 1;

        return stream;
    }

    /// Open a new unidirectional stream.
    ///
    /// Gated on the PEER-GRANTED uni-stream credit (RFC 9000 §4.6): the stream
    /// NUMBER (id >> 2, since the low 2 bits are the type) must be < the peer's
    /// cumulative MAX_STREAMS_UNI limit. Exceeding it would make the leader close
    /// the connection with STREAM_LIMIT_ERROR — so when out of credit we return
    /// error.StreamLimitReached and the caller FALLS BACK TO UDP (the curl/UDP vote
    /// relay), never dropping the vote. Credit starts at 0 (RFC absent-default) and
    /// grows only via decoded transport params / parsed MAX_STREAMS_UNI frames.
    pub fn openUniStream(self: *Self) !*Stream {
        if ((self.next_uni_stream_id >> 2) >= self.peer_max_streams_uni) {
            return error.StreamLimitReached;
        }
        if (self.streams.count() >= self.endpoint.config.max_streams_per_connection) {
            return error.TooManyStreams;
        }
        const stream_id = self.next_uni_stream_id;
        self.next_uni_stream_id += 4;

        const stream = try Stream.init(self.allocator, self, stream_id);
        stream.max_stream_data_remote = self.endpoint.config.initial_max_stream_data;
        try self.streams.put(stream_id, stream);
        self.stats.streams_opened += 1;

        return stream;
    }

    /// Send data on a stream. `fin=true` closes the stream (sets the FIN bit on the wire so the
    /// receiver's stream.fin_received fires — required for the TPU one-tx-per-uni-stream model).
    pub fn send(self: *Self, stream_id: u64, data: []const u8, fin: bool) !void {
        if (self.bytes_sent + data.len > self.max_data_remote) {
            return error.FlowControlBlocked;
        }
        const stream = self.streams.get(stream_id) orelse return error.StreamNotFound;
        try stream.send(data);
        self.bytes_sent += data.len;
        self.stats.bytes_sent += data.len;
        try self.endpoint.sendStreamData(self, stream_id, data, fin);
        if (fin) stream.sendFin();
    }

    fn appendCryptoData(self: *Self, data: []const u8) !void {
        try self.crypto_recv.appendSlice(self.allocator, data);
        while (self.crypto_recv.items.len >= 4) {
            const msg_type = self.crypto_recv.items[0];
            const len = (@as(u32, self.crypto_recv.items[1]) << 16) |
                (@as(u32, self.crypto_recv.items[2]) << 8) |
                @as(u32, self.crypto_recv.items[3]);
            const total = 4 + @as(usize, len);
            if (self.crypto_recv.items.len < total) break;

            const msg = self.crypto_recv.items[0..total];
            std.log.debug("[QUIC] handshake msg type=0x{x} len={d} is_server={}\n", .{ msg_type, len, self.endpoint.is_server });
            switch (msg_type) {
                @intFromEnum(tls13.HandshakeType.client_hello) => {
                    // SERVER path: a client sent us its ClientHello. Transcribe it (matching the
                    // client's own transcript of the full message incl. 4-byte header), then run
                    // the full server flight (ServerHello + EE/Cert/CV/Finished). Ignore on the
                    // client (a client never receives a ClientHello).
                    if (self.endpoint.is_server) {
                        // Idempotency guard: the client resends its Initial (containing this
                        // ClientHello) on a timer until handshake_complete, and a real Agave client
                        // retransmits per normal QUIC loss recovery. We must process the ClientHello
                        // EXACTLY ONCE — re-running driveServerHandshake would re-updateTranscript
                        // and re-derive keys, corrupting the transcript so the client's Finished and
                        // 1-RTT data would no longer decrypt. handshake_secrets is the sentinel: it
                        // is null only before the first drive and non-null forever after.
                        if (self.tls.handshake_secrets == null) {
                            self.tls.key_schedule.updateTranscript(msg);
                            // Cache the ClientHello bytes for driveServerHandshake (parses key_share).
                            const ch_copy = try self.allocator.dupe(u8, msg);
                            defer self.allocator.free(ch_copy);
                            self.endpoint.driveServerHandshake(self, ch_copy) catch |err| {
                                std.log.debug("[QUIC] server handshake drive failed: {}\n", .{err});
                                return err;
                            };
                        } else {
                            std.log.debug("[QUIC] ignoring retransmitted ClientHello (already processing)\n", .{});
                        }
                    }
                },
                @intFromEnum(tls13.HandshakeType.server_hello) => {
                    try self.tls.processServerHello(msg);
                },
                @intFromEnum(tls13.HandshakeType.encrypted_extensions) => {
                    try self.tls.processEncryptedExtensions(msg);
                    // Honor the peer's advertised initial uni/bidi stream credit
                    // (RFC 9000 §18.2). ABSENT ⇒ 0, so a real leader that omits
                    // id 0x09 still requires a later MAX_STREAMS_UNI frame; our own
                    // ingest server advertises 100 here, so Vexor→Vexor can open a
                    // uni stream immediately. @max so a frame can only raise it.
                    const lims = tls13.peerStreamLimitsFromEncryptedExtensions(msg);
                    self.peer_max_streams_uni = @max(self.peer_max_streams_uni, lims.uni);
                    self.peer_max_streams_bidi = @max(self.peer_max_streams_bidi, lims.bidi);
                },
                @intFromEnum(tls13.HandshakeType.certificate) => {
                    try self.tls.processCertificate(msg);
                },
                @intFromEnum(tls13.HandshakeType.certificate_verify) => {
                    try self.tls.processCertificateVerify(msg);
                },
                @intFromEnum(tls13.HandshakeType.finished) => {
                    if (self.endpoint.is_server) {
                        // SERVER path: this is the CLIENT's Finished. Verify its MAC against the
                        // raw c hs traffic secret over the transcript CH..server-Finished (the
                        // server already sent its own Finished in driveServerHandshake; do NOT
                        // build/send another). On success the 1-RTT app data path opens.
                        if (msg.len < 4 + 32) return error.InvalidFinished;
                        const client_traffic = self.tls.handshake_traffic_client orelse return error.NoHandshakeSecrets;
                        var finished_key: [32]u8 = undefined;
                        tls13.hkdfExpandLabel(&client_traffic, "finished", "", 32, &finished_key);
                        const transcript_hash = self.tls.key_schedule.getTranscriptHash();
                        var verify_data: [32]u8 = undefined;
                        @memcpy(&verify_data, msg[4..][0..32]);
                        if (!tls13.verifyFinished(finished_key, transcript_hash, verify_data)) {
                            std.log.debug("[QUIC] client Finished verify FAILED\n", .{});
                            return error.FinishedVerificationFailed;
                        }
                        self.tls.key_schedule.updateTranscript(msg);
                        self.tls.handshake_complete = true;
                        self.state = .connected;
                        std.log.debug("[QUIC] server handshake COMPLETE (client Finished verified)\n", .{});
                    } else {
                        // CLIENT path: process server Finished (transcribes it + derives app secrets
                        // at the server-Finished transcript point — correct; the client Cert/CV/Finished
                        // that follow do NOT change app keys).
                        try self.tls.processFinished(msg);
                        // Solana mTLS: if the leader requested a client cert AND we have an identity,
                        // send identity Certificate + CertificateVerify (signed by the identity key)
                        // BEFORE our Finished, as ONE handshake flight (order: Cert -> CV -> Finished;
                        // each updates the transcript in order so the Finished MAC covers Cert+CV).
                        if (self.tls.client_cert_requested and self.tls.identity_seed != null) {
                            const cert_msg = try self.tls.buildClientCertificate();
                            defer self.allocator.free(cert_msg);
                            const cv_msg = try self.tls.buildClientCertificateVerify();
                            defer self.allocator.free(cv_msg);
                            const fin = try self.tls.buildFinished();
                            defer self.allocator.free(fin);
                            const flight = try self.allocator.alloc(u8, cert_msg.len + cv_msg.len + fin.len);
                            defer self.allocator.free(flight);
                            @memcpy(flight[0..cert_msg.len], cert_msg);
                            @memcpy(flight[cert_msg.len..][0..cv_msg.len], cv_msg);
                            @memcpy(flight[cert_msg.len + cv_msg.len ..][0..fin.len], fin);
                            try self.endpoint.sendHandshakeFinished(self, flight);
                        } else {
                            const finished = try self.tls.buildFinished();
                            defer self.allocator.free(finished);
                            try self.endpoint.sendHandshakeFinished(self, finished);
                        }
                        self.state = .connected;
                    }
                },
                @intFromEnum(tls13.HandshakeType.certificate_request) => {
                    // CLIENT path: the leader requires a client cert (Solana mTLS). Capture the
                    // certificate_request_context to echo it in our Certificate message (canonical),
                    // and flag that the client flight must include identity Cert + CertificateVerify.
                    // Transcribe either way (matches the default branch) to keep the transcript synced.
                    if (!self.endpoint.is_server and msg.len >= 5) {
                        const ctx_len = msg[4];
                        if (ctx_len <= 32 and msg.len >= 5 + @as(usize, ctx_len)) {
                            self.tls.cert_req_context_len = ctx_len;
                            if (ctx_len > 0) @memcpy(self.tls.cert_req_context[0..ctx_len], msg[5..][0..ctx_len]);
                            self.tls.client_cert_requested = true;
                        }
                    }
                    self.tls.key_schedule.updateTranscript(msg);
                },
                else => {
                    self.tls.key_schedule.updateTranscript(msg);
                },
            }

            const remaining = self.crypto_recv.items.len - total;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.crypto_recv.items[0..remaining], self.crypto_recv.items[total..]);
            }
            self.crypto_recv.shrinkRetainingCapacity(remaining);
        }
    }

    /// Close connection gracefully
    pub fn close(self: *Self, error_code: u64, reason: []const u8) void {
        _ = error_code;
        _ = reason;
        self.state = .closing;
    }

    /// Update RTT estimate
    pub fn updateRtt(self: *Self, latest_rtt_ns: u64) void {
        if (self.min_rtt_ns > latest_rtt_ns) {
            self.min_rtt_ns = latest_rtt_ns;
        }

        // RFC 9002 RTT calculation
        const rtt_diff = if (self.smoothed_rtt_ns > latest_rtt_ns)
            self.smoothed_rtt_ns - latest_rtt_ns
        else
            latest_rtt_ns - self.smoothed_rtt_ns;

        self.rtt_var_ns = (3 * self.rtt_var_ns + rtt_diff) / 4;
        self.smoothed_rtt_ns = (7 * self.smoothed_rtt_ns + latest_rtt_ns) / 8;
    }

    /// Check if connection is open
    pub fn isOpen(self: *const Self) bool {
        return self.state == .connected;
    }
};

/// TLS 1.3 state for QUIC with real cryptographic operations
/// Canonical Solana TPU client certificate. Byte-identical to Agave's
/// new_dummy_x509_certificate (tls-utils) AND Firedancer's fd_x509_mock_tpl
/// (ballet/x509) — verified by diff + KAT (quic-tpu-cert-kat-2026-06-18.zig):
/// 249-byte fixed X.509 DER template with the identity Ed25519 pubkey spliced at offset 100;
/// the cert signature is deliberately invalid (peer auth is via the TLS 1.3 CertificateVerify,
/// signed by the identity key). Real leaders parse this via get_pubkey_from_tls_certificate to
/// map the QUIC connection to our stake (staked QoS: 128-512 streams vs unstaked crumbs).
fn solanaTpuClientCert(pubkey: [32]u8) [249]u8 {
    const head = [_]u8{
        0x30, 0x81, 0xf6, 0x30, 0x81, 0xa9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x16,
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x53, 0x6f, 0x6c, 0x61,
        0x6e, 0x61, 0x20, 0x6e, 0x6f, 0x64, 0x65, 0x30, 0x20, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x34, 0x30, 0x39, 0x36,
        0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x00, 0x30, 0x2a,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    };
    const tail = [_]u8{
        0xa3, 0x29, 0x30, 0x27, 0x30, 0x17, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04,
        0x0d, 0x30, 0x0b, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30,
        0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00,
    };
    var out: [249]u8 = undefined;
    @memcpy(out[0..head.len], &head);
    @memcpy(out[head.len..][0..32], &pubkey);
    @memcpy(out[head.len + 32 ..][0..tail.len], &tail);
    @memset(out[head.len + 32 + tail.len ..][0..64], 0xff); // invalid signature by design
    return out;
}

pub const TlsState = struct {
    allocator: std.mem.Allocator,
    handshake_complete: bool,
    early_data_accepted: bool,
    alpn: ?[]const u8,

    /// Key schedule for secret derivation
    key_schedule: tls13.KeySchedule,

    /// Current encryption level secrets
    initial_secrets: ?tls13.TrafficSecrets,
    handshake_secrets: ?tls13.TrafficSecrets,
    application_secrets: ?tls13.TrafficSecrets,
    handshake_traffic_client: ?[32]u8,
    handshake_traffic_server: ?[32]u8,

    /// Current cipher suite
    cipher_suite: tls13.CipherSuite,

    /// AEAD contexts for encryption/decryption
    client_aead: ?tls13.AeadContext,
    server_aead: ?tls13.AeadContext,

    /// Header protection keys
    client_hp: [16]u8,
    server_hp: [16]u8,

    /// X25519 key pair for ECDHE
    local_private_key: [32]u8,
    local_public_key: [32]u8,
    remote_public_key: ?[32]u8,

    /// Handshake state
    handshake_stage: HandshakeStage,

    /// Solana mTLS client-auth. identity_seed = validator Ed25519 seed used for BOTH the client
    /// cert's SubjectPublicKey and the CertificateVerify signature (proof of stake identity to the
    /// leader). null = no client auth (loopback / unstaked). client_cert_requested is set when the
    /// peer (leader) sends a CertificateRequest; cert_req_context echoes its request context.
    identity_seed: ?[32]u8,
    client_cert_requested: bool,
    cert_req_context: [32]u8,
    cert_req_context_len: u8,
    /// SNI server_name for the ClientHello = canonical "{ip}.{port}.sol" (set at connect from peer
    /// addr). Empty → no SNI extension emitted (loopback tests).
    sni_host: [40]u8,
    sni_host_len: u8,

    pub const HandshakeStage = enum {
        initial,
        client_hello_sent,
        server_hello_received,
        encrypted_extensions_received,
        certificate_received,
        certificate_verify_received,
        finished_received,
        finished_sent,
        complete,
    };

    pub fn init(allocator: std.mem.Allocator) TlsState {
        // Generate X25519 key pair
        var private_key: [32]u8 = undefined;
        std.crypto.random.bytes(&private_key);

        const public_key = std.crypto.dh.X25519.recoverPublicKey(private_key) catch [_]u8{0} ** 32;

        return .{
            .allocator = allocator,
            .handshake_complete = false,
            .early_data_accepted = false,
            .alpn = null,
            .key_schedule = tls13.KeySchedule.init(),
            .initial_secrets = null,
            .handshake_secrets = null,
            .application_secrets = null,
            .handshake_traffic_client = null,
            .handshake_traffic_server = null,
            .cipher_suite = .TLS_AES_128_GCM_SHA256,
            .client_aead = null,
            .server_aead = null,
            .client_hp = [_]u8{0} ** 16,
            .server_hp = [_]u8{0} ** 16,
            .local_private_key = private_key,
            .local_public_key = public_key,
            .remote_public_key = null,
            .handshake_stage = .initial,
            .identity_seed = null,
            .client_cert_requested = false,
            .cert_req_context = [_]u8{0} ** 32,
            .cert_req_context_len = 0,
            .sni_host = [_]u8{0} ** 40,
            .sni_host_len = 0,
        };
    }

    /// Derive initial secrets from destination connection ID
    pub fn deriveInitialSecrets(self: *TlsState, dcid: []const u8) void {
        self.initial_secrets = tls13.deriveInitialSecrets(dcid);

        if (self.initial_secrets) |secrets| {
            self.client_aead = tls13.AeadContext.init(secrets.client, self.cipher_suite);
            self.server_aead = tls13.AeadContext.init(secrets.server, self.cipher_suite);
            self.client_hp = secrets.client.hp;
            self.server_hp = secrets.server.hp;
        }
    }

    /// Build ClientHello message
    pub fn buildClientHello(self: *TlsState, quic_params: []const u8) ![]u8 {
        var random: [32]u8 = undefined;
        std.crypto.random.bytes(&random);

        const cipher_suites = [_]tls13.CipherSuite{
            .TLS_AES_128_GCM_SHA256,
            .TLS_CHACHA20_POLY1305_SHA256,
        };

        const alpn_protos = [_][]const u8{"solana-tpu"};

        const client_hello = try tls13.buildClientHello(
            self.allocator,
            random,
            &[_]u8{}, // No session ID for QUIC
            &cipher_suites,
            &self.local_public_key,
            &alpn_protos,
            quic_params,
            self.sni_host[0..self.sni_host_len],
        );

        // Update transcript
        self.key_schedule.updateTranscript(client_hello);
        self.handshake_stage = .client_hello_sent;

        return client_hello;
    }

    /// Process ServerHello message
    pub fn processServerHello(self: *TlsState, data: []const u8) !void {
        if (self.handshake_stage != .client_hello_sent and self.handshake_stage != .server_hello_received) {
            return error.InvalidHandshakeState;
        }
        if (self.handshake_stage == .server_hello_received) {
            return;
        }
        // Update transcript with ServerHello
        self.key_schedule.updateTranscript(data);

        const server_hello = try tls13.parseServerHello(data);
        self.cipher_suite = server_hello.cipher_suite;

        // Store remote public key
        if (server_hello.key_share.len >= 32) {
            self.remote_public_key = server_hello.key_share[0..32].*;
        }

        // Compute shared secret using X25519
        if (self.remote_public_key) |remote_pk| {
            const shared_secret = std.crypto.dh.X25519.scalarmult(
                self.local_private_key,
                remote_pk,
            ) catch return error.KeyExchangeFailed;

            // Derive handshake secrets
            self.handshake_secrets = self.key_schedule.deriveHandshakeSecrets(&shared_secret);
            const transcript = self.key_schedule.getTranscriptHash();
            var client_secret: [32]u8 = undefined;
            var server_secret: [32]u8 = undefined;
            tls13.hkdfExpandLabel(&self.key_schedule.handshake_secret, "c hs traffic", &transcript, 32, &client_secret);
            tls13.hkdfExpandLabel(&self.key_schedule.handshake_secret, "s hs traffic", &transcript, 32, &server_secret);
            self.handshake_traffic_client = client_secret;
            self.handshake_traffic_server = server_secret;

            if (self.handshake_secrets) |secrets| {
                self.client_aead = tls13.AeadContext.init(secrets.client, self.cipher_suite);
                self.server_aead = tls13.AeadContext.init(secrets.server, self.cipher_suite);
                self.client_hp = secrets.client.hp;
                self.server_hp = secrets.server.hp;
            }
        }

        self.handshake_stage = .server_hello_received;
    }

    /// Process EncryptedExtensions message
    pub fn processEncryptedExtensions(self: *TlsState, data: []const u8) !void {
        if (self.handshake_stage == .encrypted_extensions_received or
            self.handshake_stage == .certificate_received or
            self.handshake_stage == .certificate_verify_received or
            self.handshake_stage == .finished_received or
            self.handshake_stage == .finished_sent or
            self.handshake_stage == .complete)
        {
            return;
        }
        if (self.handshake_stage != .server_hello_received) {
            return error.InvalidHandshakeState;
        }
        self.key_schedule.updateTranscript(data);
        self.handshake_stage = .encrypted_extensions_received;

        // DIAGNOSTIC (VEX_QUIC_FRAME_DUMP): hexdump the EncryptedExtensions so a real
        // leader's quic_transport_parameters (TLS ext 57 = 0x0039, carrying
        // initial_max_streams_uni id 0x09) can be captured as a golden KAT vector for
        // the decoder. Gated; QUIC stack is comptime/env-dormant on the live path.
        if (std.posix.getenv("VEX_QUIC_FRAME_DUMP") != null) {
            std.debug.print("[QUIC-DUMP] EncryptedExtensions len={d} bytes=", .{data.len});
            for (data) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
        }
    }

    /// Process Certificate message
    pub fn processCertificate(self: *TlsState, data: []const u8) !void {
        if (self.handshake_stage == .certificate_received or
            self.handshake_stage == .certificate_verify_received or
            self.handshake_stage == .finished_received or
            self.handshake_stage == .finished_sent or
            self.handshake_stage == .complete)
        {
            return;
        }
        if (self.handshake_stage != .encrypted_extensions_received) {
            return error.InvalidHandshakeState;
        }
        self.key_schedule.updateTranscript(data);
        self.handshake_stage = .certificate_received;
    }

    /// Process CertificateVerify message
    pub fn processCertificateVerify(self: *TlsState, data: []const u8) !void {
        if (self.handshake_stage == .certificate_verify_received or
            self.handshake_stage == .finished_received or
            self.handshake_stage == .finished_sent or
            self.handshake_stage == .complete)
        {
            return;
        }
        if (self.handshake_stage != .certificate_received) {
            return error.InvalidHandshakeState;
        }
        self.key_schedule.updateTranscript(data);
        self.handshake_stage = .certificate_verify_received;
    }

    /// Process Finished message and derive application secrets
    pub fn processFinished(self: *TlsState, data: []const u8) !void {
        if (self.handshake_stage == .finished_sent or self.handshake_stage == .complete) {
            return;
        }
        if (data.len < 4 + 32) return error.InvalidFinished;
        const transcript_hash = self.key_schedule.getTranscriptHash();
        var finished_key: [32]u8 = undefined;
        const server_traffic_secret = self.handshake_traffic_server orelse return error.NoHandshakeSecrets;
        tls13.hkdfExpandLabel(&server_traffic_secret, "finished", "", 32, &finished_key);
        var verify_data: [32]u8 = undefined;
        @memcpy(&verify_data, data[4..][0..32]);
        if (!tls13.verifyFinished(finished_key, transcript_hash, verify_data)) {
            return error.FinishedVerificationFailed;
        }

        // Update transcript after verification
        self.key_schedule.updateTranscript(data);

        // Derive application secrets
        self.application_secrets = self.key_schedule.deriveApplicationSecrets();

        if (self.application_secrets) |secrets| {
            self.client_aead = tls13.AeadContext.init(secrets.client, self.cipher_suite);
            self.server_aead = tls13.AeadContext.init(secrets.server, self.cipher_suite);
            self.client_hp = secrets.client.hp;
            self.server_hp = secrets.server.hp;
        }

        self.handshake_stage = .finished_received;
    }

    /// Build Finished message
    pub fn buildFinished(self: *TlsState) ![]u8 {
        // Derive finished key from client handshake secret
        var finished_key: [32]u8 = undefined;
        const transcript_hash = self.key_schedule.getTranscriptHash();
        const client_traffic_secret = self.handshake_traffic_client orelse return error.NoHandshakeSecrets;
        tls13.hkdfExpandLabel(&client_traffic_secret, "finished", "", 32, &finished_key);
        const finished_msg = try tls13.buildFinished(self.allocator, finished_key, transcript_hash);

        // Update transcript
        self.key_schedule.updateTranscript(finished_msg);

        self.handshake_stage = .finished_sent;
        self.handshake_complete = true;

        return finished_msg;
    }

    /// Build the CLIENT's Certificate message carrying the canonical Solana identity cert
    /// (Agave new_dummy_x509_certificate / FD fd_x509_mock — identity Ed25519 pubkey @offset 100).
    /// Echoes the server's certificate_request_context. Updates the transcript. Caller frees.
    pub fn buildClientCertificate(self: *TlsState) ![]u8 {
        const seed = self.identity_seed orelse return error.NoIdentity;
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return error.SigningFailed;
        const cert = solanaTpuClientCert(kp.public_key.toBytes());

        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);
        try msg.append(self.allocator, @intFromEnum(tls13.HandshakeType.certificate));
        try msg.appendNTimes(self.allocator, 0, 3); // handshake length placeholder
        // certificate_request_context: echo the server's (empty for Agave/rustls).
        try msg.append(self.allocator, self.cert_req_context_len);
        if (self.cert_req_context_len > 0)
            try msg.appendSlice(self.allocator, self.cert_req_context[0..self.cert_req_context_len]);
        // certificate_list length placeholder
        const list_pos = msg.items.len;
        try msg.appendNTimes(self.allocator, 0, 3);
        // CertificateEntry: cert_data (u24 len + DER) + extensions (empty u16)
        try msg.append(self.allocator, @intCast((cert.len >> 16) & 0xFF));
        try msg.append(self.allocator, @intCast((cert.len >> 8) & 0xFF));
        try msg.append(self.allocator, @intCast(cert.len & 0xFF));
        try msg.appendSlice(self.allocator, &cert);
        try msg.append(self.allocator, 0);
        try msg.append(self.allocator, 0);
        // fill certificate_list length
        const list_len: u24 = @intCast(msg.items.len - list_pos - 3);
        msg.items[list_pos] = @intCast((list_len >> 16) & 0xFF);
        msg.items[list_pos + 1] = @intCast((list_len >> 8) & 0xFF);
        msg.items[list_pos + 2] = @intCast(list_len & 0xFF);
        // fill handshake length
        const body_len: u24 = @intCast(msg.items.len - 4);
        msg.items[1] = @intCast((body_len >> 16) & 0xFF);
        msg.items[2] = @intCast((body_len >> 8) & 0xFF);
        msg.items[3] = @intCast(body_len & 0xFF);

        const out = try msg.toOwnedSlice(self.allocator);
        self.key_schedule.updateTranscript(out);
        return out;
    }

    /// Build the CLIENT's CertificateVerify: Ed25519 signature (by the identity key) over
    /// 64×0x20 + "TLS 1.3, client CertificateVerify" + 0x00 + transcript_hash (RFC 8446 §4.4.3).
    /// Must be called AFTER buildClientCertificate (transcript must include the client cert).
    /// Updates the transcript. Caller frees.
    pub fn buildClientCertificateVerify(self: *TlsState) ![]u8 {
        const seed = self.identity_seed orelse return error.NoIdentity;
        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);
        try msg.append(self.allocator, @intFromEnum(tls13.HandshakeType.certificate_verify));
        try msg.appendNTimes(self.allocator, 0, 3); // handshake length placeholder
        try msg.append(self.allocator, 0x08); // SignatureScheme ed25519 = 0x0807
        try msg.append(self.allocator, 0x07);

        var sign_content: [130]u8 = undefined;
        @memset(sign_content[0..64], 0x20);
        const context = "TLS 1.3, client CertificateVerify";
        @memcpy(sign_content[64..][0..context.len], context);
        sign_content[64 + context.len] = 0x00;
        const transcript = self.key_schedule.getTranscriptHash();
        @memcpy(sign_content[65 + context.len ..][0..32], &transcript);

        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return error.SigningFailed;
        const signature = kp.sign(sign_content[0 .. 65 + context.len + 32], null) catch return error.SigningFailed;

        try msg.append(self.allocator, 0);
        try msg.append(self.allocator, 64); // Ed25519 signature length
        try msg.appendSlice(self.allocator, &signature.toBytes());

        const body_len: u24 = @intCast(msg.items.len - 4);
        msg.items[1] = @intCast((body_len >> 16) & 0xFF);
        msg.items[2] = @intCast((body_len >> 8) & 0xFF);
        msg.items[3] = @intCast(body_len & 0xFF);

        const out = try msg.toOwnedSlice(self.allocator);
        self.key_schedule.updateTranscript(out);
        return out;
    }

    /// Encrypt a QUIC packet payload
    pub fn encryptPacket(
        self: *const TlsState,
        is_client: bool,
        packet_number: u64,
        header: []const u8,
        plaintext: []const u8,
        out_ciphertext: []u8,
        out_tag: *[16]u8,
    ) !void {
        const aead = if (is_client) self.client_aead else self.server_aead;
        if (aead) |ctx| {
            ctx.encrypt(packet_number, header, plaintext, out_ciphertext, out_tag);
        } else {
            return error.NoEncryptionKeys;
        }
    }

    /// Decrypt a QUIC packet payload
    pub fn decryptPacket(
        self: *const TlsState,
        is_from_client: bool,
        packet_number: u64,
        header: []const u8,
        ciphertext: []const u8,
        tag: [16]u8,
        out_plaintext: []u8,
    ) !void {
        // When receiving from client, use client keys; when receiving from server, use server keys
        const aead = if (is_from_client) self.client_aead else self.server_aead;
        if (aead) |ctx| {
            try ctx.decrypt(packet_number, header, ciphertext, tag, out_plaintext);
        } else {
            return error.NoDecryptionKeys;
        }
    }

    /// Apply header protection
    pub fn protectHeader(self: *const TlsState, is_client: bool, header: []u8, pn_offset: usize, pn_length: usize, sample: [16]u8) void {
        const hp_key = if (is_client) self.client_hp else self.server_hp;
        tls13.applyHeaderProtection(hp_key, header, pn_offset, pn_length, sample);
    }

    /// Remove header protection
    pub fn unprotectHeader(self: *const TlsState, is_from_client: bool, header: []u8, pn_offset: usize, sample: [16]u8) usize {
        const hp_key = if (is_from_client) self.client_hp else self.server_hp;
        return tls13.removeHeaderProtection(hp_key, header, pn_offset, sample);
    }
};

/// QUIC stream for bidirectional communication
pub const Stream = struct {
    id: u64,
    conn: *Connection,
    state: State,
    recv_buffer: std.ArrayList(u8),
    send_buffer: std.ArrayList(u8),
    recv_offset: u64,
    send_offset: u64,
    max_stream_data_local: u64,
    max_stream_data_remote: u64,

    /// Flow control blocked
    blocked: bool,

    /// FIN sent/received
    fin_sent: bool,
    fin_received: bool,

    pub const State = enum {
        open,
        half_closed_local,
        half_closed_remote,
        closed,
        reset,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, conn: *Connection, id: u64) !*Self {
        const stream = try allocator.create(Self);
        stream.* = .{
            .id = id,
            .conn = conn,
            .state = .open,
            .recv_buffer = .empty,
            .send_buffer = .empty,
            .recv_offset = 0,
            .send_offset = 0,
            .max_stream_data_local = 256 * 1024, // 256KB
            .max_stream_data_remote = 0,
            .blocked = false,
            .fin_sent = false,
            .fin_received = false,
        };
        return stream;
    }

    pub fn deinit(self: *Self) void {
        self.recv_buffer.deinit(self.conn.allocator);
        self.send_buffer.deinit(self.conn.allocator);
        self.conn.allocator.destroy(self);
    }

    pub fn send(self: *Self, data: []const u8) !void {
        if (self.state == .half_closed_local or self.state == .closed) {
            return error.StreamClosed;
        }
        if (self.send_offset + data.len > self.max_stream_data_remote) {
            self.blocked = true;
            return error.StreamBlocked;
        }
        try self.send_buffer.appendSlice(self.conn.allocator, data);
        self.send_offset += data.len;
    }

    pub fn sendFin(self: *Self) void {
        self.fin_sent = true;
        if (self.state == .open) {
            self.state = .half_closed_local;
        } else if (self.state == .half_closed_remote) {
            self.state = .closed;
        }
    }

    pub fn recv(self: *Self, buf: []u8) !usize {
        const len = @min(buf.len, self.recv_buffer.items.len);
        @memcpy(buf[0..len], self.recv_buffer.items[0..len]);

        // Remove read data from buffer
        const remaining = self.recv_buffer.items.len - len;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.recv_buffer.items[0..remaining], self.recv_buffer.items[len..]);
        }
        self.recv_buffer.shrinkRetainingCapacity(remaining);
        self.recv_offset += len;

        return len;
    }

    pub fn appendRecvData(self: *Self, data: []const u8) !void {
        try self.recv_buffer.appendSlice(self.conn.allocator, data);
    }

    pub fn hasPendingData(self: *const Self) bool {
        return self.send_buffer.items.len > 0;
    }

    pub fn isReadable(self: *const Self) bool {
        return self.recv_buffer.items.len > 0 or self.fin_received;
    }

    pub fn isWritable(self: *const Self) bool {
        return self.state == .open or self.state == .half_closed_remote;
    }
};

/// QUIC endpoint managing multiple connections
pub const Endpoint = struct {
    allocator: std.mem.Allocator,
    connections: std.AutoHashMap(u64, *Connection),
    connections_by_addr: std.AutoHashMap(u64, *Connection), // peer_addr hash -> connection
    bind_addr: packet.SocketAddr,
    is_server: bool,
    sock: ?socket.UdpSocket,
    config: EndpointConfig,
    stats: EndpointStats,
    tx_batch: packet.PacketBatch,

    const Self = @This();

    pub const EndpointConfig = struct {
        max_connections: usize = 10000,
        max_streams_per_connection: usize = 100,
        initial_max_data: u64 = 10 * 1024 * 1024, // 10MB
        initial_max_stream_data: u64 = 1024 * 1024, // 1MB
        max_idle_timeout_ms: u64 = 30000, // 30 seconds
        alpn: []const u8 = "solana-tpu",
        /// Validator Ed25519 identity seed for Solana mTLS client cert (staked QoS). null = no
        /// client auth (the connection presents no cert → leader treats it as unstaked).
        identity_seed: ?[32]u8 = null,
        /// Bind the endpoint socket to this specific IPv4 (dual-NIC hosts). Empty = 0.0.0.0.
        /// 2026-07-06 vote-client source-IP fix: QuicClient.init/QuicServer.init parse this into
        /// the endpoint's bind_addr instead of hardcoding {0,0,0,0} — see Endpoint.bind() below
        /// for where it's actually honored, and core/config.zig quic_bind_addr for the mechanism.
        bind_addr: []const u8 = "",
    };

    pub const EndpointStats = struct {
        connections_total: u64 = 0,
        connections_active: u64 = 0,
        packets_sent: u64 = 0,
        packets_received: u64 = 0,
        bytes_sent: u64 = 0,
        bytes_received: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, bind_addr: packet.SocketAddr, is_server: bool, config: EndpointConfig) !*Self {
        const endpoint = try allocator.create(Self);
        endpoint.* = .{
            .allocator = allocator,
            .connections = std.AutoHashMap(u64, *Connection).init(allocator),
            .connections_by_addr = std.AutoHashMap(u64, *Connection).init(allocator),
            .bind_addr = bind_addr,
            .is_server = is_server,
            .sock = null,
            .config = config,
            .stats = .{},
            .tx_batch = try packet.PacketBatch.init(allocator, packet.MAX_BATCH_SIZE),
        };
        return endpoint;
    }

    pub fn deinit(self: *Self) void {
        self.tx_batch.deinit();
        if (self.sock) |*s| {
            s.deinit();
        }
        var iter = self.connections.valueIterator();
        while (iter.next()) |conn| {
            conn.*.deinit();
        }
        self.connections.deinit();
        self.connections_by_addr.deinit();
        self.allocator.destroy(self);
    }

    /// Bind the endpoint to its address.
    ///
    /// 2026-07-06 dual-NIC vote-client source-IP fix: `self.bind_addr` used to be constructed
    /// with the IP entirely thrown away here — every endpoint (QuicClient AND QuicServer) bound
    /// 0.0.0.0 regardless of what address it was created with. On a dual-NIC host the kernel then
    /// picks the egress source by route, which can differ from the gossip-advertised IP; leaders'
    /// stake-weighted QUIC QoS can't match the connection's source to our staked ContactInfo →
    /// unstaked bucket → starved under load (the vote-ingest carrier this fixes). Mirrors the
    /// gossip.zig / tvu.zig repair_bind_addr bind-with-fallback pattern: honor the IP when the
    /// caller supplied one (via EndpointConfig.bind_addr → QuicClient/QuicServer.init), otherwise
    /// — and on any bind() failure — fall back to the prior 0.0.0.0-on-this-port behavior so a
    /// bad/unreachable address can never take the endpoint down.
    pub fn bind(self: *Self) !void {
        var sock = try socket.UdpSocket.init();
        errdefer sock.deinit();

        const a = self.bind_addr.addr;
        const has_addr = a[0] != 0 or a[1] != 0 or a[2] != 0 or a[3] != 0;
        if (has_addr) {
            sock.bind(self.bind_addr.toStd()) catch |err| {
                std.log.warn("[QUIC-BIND] addr={any} bind failed: {} — falling back to 0.0.0.0:{d}", .{ self.bind_addr, err, self.bind_addr.port() });
                try sock.bindPort(self.bind_addr.port());
                self.sock = sock;
                return;
            };
            std.log.warn("[QUIC-BIND] addr={any} bound (dual-NIC source-IP fix) ✓", .{self.bind_addr});
            self.sock = sock;
            return;
        }

        try sock.bindPort(self.bind_addr.port());
        self.sock = sock;
    }

    /// Connect to a peer (client mode)
    pub fn connect(self: *Self, peer_addr: packet.SocketAddr) !*Connection {
        if (self.connections.count() >= self.config.max_connections) {
            return error.TooManyConnections;
        }

        const conn = try Connection.init(self.allocator, self, peer_addr, false);
        errdefer conn.deinit();

        // Solana mTLS: thread the validator identity seed into the connection's TLS state so the
        // client flight presents the canonical identity cert + CertificateVerify (staked QoS).
        conn.tls.identity_seed = self.config.identity_seed;
        // SNI = canonical Solana "{ip}.{port}.sol" (Agave tls-utils socket_addr_to_quic_server_name).
        {
            const a = peer_addr.addr;
            if (std.fmt.bufPrint(conn.tls.sni_host[0..], "{d}.{d}.{d}.{d}.{d}.sol", .{ a[0], a[1], a[2], a[3], peer_addr.port() })) |s| {
                conn.tls.sni_host_len = @intCast(s.len);
            } else |_| {}
        }

        // Hash the connection ID for lookup
        const cid_hash = hashConnectionId(&conn.local_cid);
        try self.connections.put(cid_hash, conn);

        // Also index by peer address
        const addr_hash = hashSocketAddr(&peer_addr);
        try self.connections_by_addr.put(addr_hash, conn);

        std.log.debug("[QUIC] Created connection: local_cid={any} initial_dcid={any} peer={any}\n", .{
            conn.local_cid.slice(),
            conn.initial_dcid.slice(),
            peer_addr,
        });

        self.stats.connections_total += 1;
        self.stats.connections_active += 1;

        // Send initial packet
        try self.sendInitialPacket(conn);

        return conn;
    }

    /// Accept a new connection (server mode). `client_dcid` is the Destination CID the client put
    /// in its Initial long header — BOTH endpoints derive Initial secrets from this exact value
    /// (the client uses its own chosen DCID in sendInitialPacket), so the server must too.
    fn acceptConnection(self: *Self, peer_addr: packet.SocketAddr, remote_cid: ConnectionId, client_dcid: ConnectionId) !*Connection {
        // Retransmit-safety: `self.connections` is keyed by hashConnectionId(&conn.local_cid) — the
        // SERVER's own freshly-generated CID — never by the client's chosen DCID. So a client Initial
        // retransmitted before it has seen any server reply (real quinn/rustls PTO behavior under WAN
        // jitter or a burst of simultaneous handshakes) still carries its ORIGINAL, never-yet-matched
        // DCID: the caller's `self.connections.get(cid_hash)` lookup misses again and `acceptConnection`
        // runs a second time for the same peer. Unconditionally minting a fresh Connection here would
        // overwrite `connections_by_addr[peer_addr]` — the ONLY index `processShortHeaderPacket`
        // consults for every post-handshake 1-RTT packet, including the FIN-terminated uni-stream
        // carrying a transaction — orphaning the connection object the client actually completed its
        // handshake against. If the peer address already has a connection that hasn't finished
        // handshaking, reuse it instead of minting a second one.
        const addr_hash = hashSocketAddr(&peer_addr);
        if (self.connections_by_addr.get(addr_hash)) |existing| {
            if (!existing.tls.handshake_complete) {
                // Re-derive Initial secrets in case this retransmission's DCID differs from the one we
                // keyed off of previously (normally identical, but harmless/idempotent either way), and
                // refresh remote_cid/initial_dcid to match what this Initial actually carried.
                existing.initial_dcid = client_dcid;
                existing.remote_cid = remote_cid;
                existing.tls.deriveInitialSecrets(client_dcid.slice());
                return existing;
            }
            // Handshake already complete at this address: this is a genuinely new connection attempt
            // from the same peer (e.g. legitimate reconnect after the prior connection closed), not a
            // retransmission race. Fall through and mint a new one, matching pre-fix behavior for that case.
        }

        if (self.connections.count() >= self.config.max_connections) {
            return error.TooManyConnections;
        }

        const conn = try Connection.init(self.allocator, self, peer_addr, true);
        conn.remote_cid = remote_cid; // client's SCID = where we send replies
        // Retain the client's ORIGINAL destination CID (the DCID it chose for its first Initial).
        // RFC 9000 §7.3/§18.2: the server MUST echo this back as the
        // `original_destination_connection_id` (0x00) transport parameter, and a strict client
        // (quinn/Agave) aborts with TRANSPORT_PARAMETER_ERROR "CID authentication failure" if it is
        // missing or does not match. Connection.init seeds initial_dcid with a random value that is
        // unused on the server path (only the client branch of processLongHeaderPacket reads it), so
        // repurposing it here to carry the observed client DCID is safe.
        conn.initial_dcid = client_dcid;

        // Derive Initial secrets from the client's DCID so role-aware RX can decrypt the
        // ClientHello (Initial packets are keyed off the client's original destination CID).
        conn.tls.deriveInitialSecrets(client_dcid.slice());

        const cid_hash = hashConnectionId(&conn.local_cid);
        try self.connections.put(cid_hash, conn);

        // addr_hash already computed above (reuse check); this legitimately replaces any
        // handshake-complete entry that was there (a real reconnect from the same peer).
        try self.connections_by_addr.put(addr_hash, conn);

        self.stats.connections_total += 1;
        self.stats.connections_active += 1;

        return conn;
    }

    /// Remove a connection from BOTH endpoint indexes (cid-hash + addr-hash) and free it.
    /// Caller MUST guarantee no live reference to `conn` remains. This is true for the QUIC vote
    /// client's !handshake_complete connections: they are never returned to any caller (callers only
    /// receive completed connections), so a stuck/never-completing one is reference-free. SINGLE-THREAD:
    /// call only from the endpoint's own poll/drive thread (the vote poller) so it cannot race poll()'s
    /// iteration of `connections`. Used by SolanaTpuQuic.pruneDeadConnections to bound the maps.
    pub fn removeConnection(self: *Self, conn: *Connection) void {
        const cid_hash = hashConnectionId(&conn.local_cid);
        _ = self.connections.remove(cid_hash);
        const addr_hash = hashSocketAddr(&conn.peer_addr);
        if (self.connections_by_addr.get(addr_hash)) |c| {
            if (c == conn) _ = self.connections_by_addr.remove(addr_hash);
        }
        if (self.stats.connections_active > 0) self.stats.connections_active -= 1;
        conn.deinit();
    }

    /// Send initial QUIC packet with TLS ClientHello
    fn sendInitialPacket(self: *Self, conn: *Connection) !void {
        if (self.sock == null) return error.NotBound;

        // Derive initial secrets from destination connection ID
        conn.tls.deriveInitialSecrets(conn.initial_dcid.slice());

        var pkt = packet.Packet.init();

        // Build QUIC Initial packet header
        var header_offset: usize = 0;

        // Long header form + Initial packet type + reserved bits + packet number length (2 bytes)
        pkt.data[header_offset] = 0xc3; // Long header, Initial, 4-byte pkt num
        header_offset += 1;

        // Version
        std.mem.writeInt(u32, pkt.data[header_offset..][0..4], QUIC_VERSION_1, .big);
        header_offset += 4;

        // Destination CID
        pkt.data[header_offset] = conn.remote_cid.len;
        header_offset += 1;
        if (conn.remote_cid.len > 0) {
            @memcpy(pkt.data[header_offset..][0..conn.remote_cid.len], conn.remote_cid.slice());
            header_offset += conn.remote_cid.len;
        }

        // Source CID
        pkt.data[header_offset] = conn.local_cid.len;
        header_offset += 1;
        @memcpy(pkt.data[header_offset..][0..conn.local_cid.len], conn.local_cid.slice());
        header_offset += conn.local_cid.len;

        // Token length (empty for client initial)
        header_offset += encodeVarInt(0, pkt.data[header_offset..][0..8]);

        // Build CRYPTO frame with TLS ClientHello
        var plaintext_buf: [1200]u8 = undefined;
        var plaintext_offset: usize = 0;

        // CRYPTO frame type
        plaintext_buf[plaintext_offset] = @intFromEnum(FrameType.crypto);
        plaintext_offset += 1;

        // CRYPTO frame offset (variable-length integer = 0)
        plaintext_buf[plaintext_offset] = 0;
        plaintext_offset += 1;

        // Build QUIC transport parameters
        var transport_params = tls13.TransportParameters{};
        if (conn.local_cid.len > 0) {
            var scid: [20]u8 = [_]u8{0} ** 20;
            @memcpy(scid[0..conn.local_cid.len], conn.local_cid.slice());
            transport_params.initial_source_cid = scid;
            transport_params.initial_source_cid_len = conn.local_cid.len;
        }

        const quic_params = try transport_params.encode(self.allocator);
        defer self.allocator.free(quic_params);

        // Build ClientHello once and reuse for retransmits
        const client_hello = if (conn.client_hello) |cached| cached else blk: {
            const built = try conn.tls.buildClientHello(quic_params);
            conn.client_hello = built;
            break :blk built;
        };
        std.log.debug("[QUIC] client_hello len={d} first={x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{
            client_hello.len,
            client_hello[0],
            client_hello[1],
            client_hello[2],
            client_hello[3],
        });

        // CRYPTO frame length (QUIC varint)
        plaintext_offset += encodeVarInt(@intCast(client_hello.len), plaintext_buf[plaintext_offset..][0..8]);

        // ClientHello data
        @memcpy(plaintext_buf[plaintext_offset..][0..client_hello.len], client_hello);
        plaintext_offset += client_hello.len;

        // Add PADDING to reach minimum size (1200 bytes for Initial)
        const min_payload = 1200 - header_offset - 20; // Reserve space for length, pkt num, tag
        while (plaintext_offset < min_payload) {
            plaintext_buf[plaintext_offset] = 0; // PADDING frame
            plaintext_offset += 1;
        }

        // Calculate payload length (including 4-byte pkt num + ciphertext + 16-byte auth tag)
        const payload_len = 4 + plaintext_offset + 16;

        // Write payload length as variable-length integer (2 bytes for values up to 16383)
        pkt.data[header_offset] = @intCast(0x40 | ((payload_len >> 8) & 0x3F));
        header_offset += 1;
        pkt.data[header_offset] = @intCast(payload_len & 0xFF);
        header_offset += 1;

        // Record packet number offset for header protection
        const pn_offset = header_offset;

        // Packet number (4 bytes)
        std.mem.writeInt(u32, pkt.data[header_offset..][0..4], @intCast(conn.next_pkt_num), .big);
        header_offset += 4;

        // Encrypt the payload with initial keys (always AES-128-GCM)
        const header = pkt.data[0..header_offset];
        var ciphertext: [1200]u8 = undefined;
        var auth_tag: [16]u8 = undefined;
        const initial_secrets = conn.tls.initial_secrets orelse return error.NoInitialSecrets;
        const initial_aead = tls13.AeadContext.init(initial_secrets.client, .TLS_AES_128_GCM_SHA256);
        initial_aead.encrypt(
            conn.next_pkt_num,
            header,
            plaintext_buf[0..plaintext_offset],
            ciphertext[0..plaintext_offset],
            &auth_tag,
        );

        // Copy ciphertext and tag to packet
        @memcpy(pkt.data[header_offset..][0..plaintext_offset], ciphertext[0..plaintext_offset]);
        header_offset += plaintext_offset;
        @memcpy(pkt.data[header_offset..][0..16], &auth_tag);
        header_offset += 16;

        // Apply header protection
        // Sample is taken from 4 bytes after the packet number
        var sample: [16]u8 = undefined;
        @memcpy(&sample, pkt.data[pn_offset + 4 ..][0..16]);

        tls13.applyHeaderProtection(initial_secrets.client.hp, pkt.data[0..header_offset], pn_offset, 4, sample);

        conn.next_pkt_num += 1;

        pkt.len = @intCast(header_offset);
        pkt.src_addr = conn.peer_addr;

        try self.queuePacket(&pkt);
        conn.stats.packets_sent += 1;
        self.stats.packets_sent += 1;
        logPacket("send", .initial, conn.next_pkt_num - 1, plaintext_offset);
        logHex("[QUIC] initial header:", pkt.data[0..header_offset], 64);
    }

    pub fn resendInitial(self: *Self, conn: *Connection) !void {
        try self.sendInitialPacket(conn);
    }

    fn sendHandshakeFinished(self: *Self, conn: *Connection, finished: []const u8) !void {
        if (self.sock == null) return error.NotBound;

        // Reset MTU state when handshake finishes
        conn.pmtud_last_probe_time = @intCast(std.time.nanoTimestamp());
        conn.pmtud_probes_sent = 0;

        var plaintext_buf: [1200]u8 = undefined;
        var plaintext_offset: usize = 0;

        plaintext_buf[plaintext_offset] = @intFromEnum(FrameType.crypto);
        plaintext_offset += 1;

        var tmp: [16]u8 = undefined;
        plaintext_offset += encodeVarInt(0, plaintext_buf[plaintext_offset..][0..8]);
        const len_len = encodeVarInt(@intCast(finished.len), tmp[0..]);
        @memcpy(plaintext_buf[plaintext_offset..][0..len_len], tmp[0..len_len]);
        plaintext_offset += len_len;
        @memcpy(plaintext_buf[plaintext_offset..][0..finished.len], finished);
        plaintext_offset += finished.len;

        var pkt = packet.Packet.init();
        var header_offset: usize = 0;

        pkt.data[header_offset] = 0xe3; // Long header, Handshake, 4-byte PN
        header_offset += 1;
        std.mem.writeInt(u32, pkt.data[header_offset..][0..4], QUIC_VERSION_1, .big);
        header_offset += 4;

        pkt.data[header_offset] = conn.remote_cid.len;
        header_offset += 1;
        if (conn.remote_cid.len > 0) {
            @memcpy(pkt.data[header_offset..][0..conn.remote_cid.len], conn.remote_cid.slice());
            header_offset += conn.remote_cid.len;
        }

        pkt.data[header_offset] = conn.local_cid.len;
        header_offset += 1;
        if (conn.local_cid.len > 0) {
            @memcpy(pkt.data[header_offset..][0..conn.local_cid.len], conn.local_cid.slice());
            header_offset += conn.local_cid.len;
        }

        const payload_len = 4 + plaintext_offset + 16;
        const payload_len_len = encodeVarInt(@intCast(payload_len), pkt.data[header_offset..][0..8]);
        header_offset += payload_len_len;

        const pn_offset = header_offset;
        std.mem.writeInt(u32, pkt.data[header_offset..][0..4], @intCast(conn.next_handshake_pkt_num), .big);
        header_offset += 4;

        const header = pkt.data[0..header_offset];
        var ciphertext: [1200]u8 = undefined;
        var auth_tag: [16]u8 = undefined;

        const handshake_secrets = conn.tls.handshake_secrets orelse return error.NoHandshakeSecrets;
        const handshake_aead = tls13.AeadContext.init(handshake_secrets.client, conn.tls.cipher_suite);
        handshake_aead.encrypt(
            conn.next_handshake_pkt_num,
            header,
            plaintext_buf[0..plaintext_offset],
            ciphertext[0..plaintext_offset],
            &auth_tag,
        );

        @memcpy(pkt.data[header_offset..][0..plaintext_offset], ciphertext[0..plaintext_offset]);
        header_offset += plaintext_offset;
        @memcpy(pkt.data[header_offset..][0..16], &auth_tag);
        header_offset += 16;

        var sample: [16]u8 = undefined;
        @memcpy(&sample, pkt.data[pn_offset + 4 ..][0..16]);
        tls13.applyHeaderProtection(handshake_secrets.client.hp, pkt.data[0..header_offset], pn_offset, 4, sample);

        conn.next_handshake_pkt_num += 1;
        pkt.len = @intCast(header_offset);
        pkt.src_addr = conn.peer_addr;

        try self.queuePacket(&pkt);
        conn.stats.packets_sent += 1;
        self.stats.packets_sent += 1;
        logPacket("send", .handshake, conn.next_handshake_pkt_num - 1, plaintext_offset);
    }

    /// Server-direction emitter: packetize a TLS handshake message (e.g. ServerHello) as a single
    /// CRYPTO frame inside a long-header QUIC packet, encrypted with the SERVER's keys.
    ///   pkt_type=.initial  -> first byte 0xc3, encrypt with initial_secrets.server (AES-128-GCM)
    ///   pkt_type=.handshake-> first byte 0xe3, encrypt with handshake_secrets.server (cipher_suite)
    /// Mirror of sendInitialPacket/sendHandshakeFinished but with server keys + a caller-supplied
    /// crypto body. crypto_offset is the CRYPTO-frame offset (0 for the first message of a level).
    /// Used only on the server path; the client emitters are untouched.
    fn sendServerCrypto(self: *Self, conn: *Connection, pkt_type: PacketType, crypto_offset: u64, crypto: []const u8) !void {
        if (self.sock == null) return error.NotBound;
        std.debug.assert(pkt_type == .initial or pkt_type == .handshake);

        // Build CRYPTO frame plaintext.
        var plaintext_buf: [1200]u8 = undefined;
        var plaintext_offset: usize = 0;
        plaintext_buf[plaintext_offset] = @intFromEnum(FrameType.crypto);
        plaintext_offset += 1;
        plaintext_offset += encodeVarInt(crypto_offset, plaintext_buf[plaintext_offset..][0..8]);
        plaintext_offset += encodeVarInt(@intCast(crypto.len), plaintext_buf[plaintext_offset..][0..8]);
        if (plaintext_offset + crypto.len > plaintext_buf.len - 16) return error.CryptoTooLarge;
        @memcpy(plaintext_buf[plaintext_offset..][0..crypto.len], crypto);
        plaintext_offset += crypto.len;

        var pkt = packet.Packet.init();
        var header_offset: usize = 0;

        pkt.data[header_offset] = if (pkt_type == .initial) 0xc3 else 0xe3; // long hdr, 4-byte PN
        header_offset += 1;
        std.mem.writeInt(u32, pkt.data[header_offset..][0..4], QUIC_VERSION_1, .big);
        header_offset += 4;

        // Destination CID = the client's source CID (our remote_cid).
        pkt.data[header_offset] = conn.remote_cid.len;
        header_offset += 1;
        if (conn.remote_cid.len > 0) {
            @memcpy(pkt.data[header_offset..][0..conn.remote_cid.len], conn.remote_cid.slice());
            header_offset += conn.remote_cid.len;
        }

        // Source CID = our local CID.
        pkt.data[header_offset] = conn.local_cid.len;
        header_offset += 1;
        if (conn.local_cid.len > 0) {
            @memcpy(pkt.data[header_offset..][0..conn.local_cid.len], conn.local_cid.slice());
            header_offset += conn.local_cid.len;
        }

        // Initial packets carry a 0-length token before the length field.
        if (pkt_type == .initial) {
            header_offset += encodeVarInt(0, pkt.data[header_offset..][0..8]);
        }

        const pn = if (pkt_type == .initial) conn.next_pkt_num else conn.next_handshake_pkt_num;
        const payload_len = 4 + plaintext_offset + 16; // 4-byte PN + ciphertext + 16-byte tag
        header_offset += encodeVarInt(@intCast(payload_len), pkt.data[header_offset..][0..8]);

        const pn_offset = header_offset;
        std.mem.writeInt(u32, pkt.data[header_offset..][0..4], @intCast(pn), .big);
        header_offset += 4;

        const header = pkt.data[0..header_offset];
        var ciphertext: [1200]u8 = undefined;
        var auth_tag: [16]u8 = undefined;
        var hp_key: [16]u8 = undefined;
        if (pkt_type == .initial) {
            const secrets = conn.tls.initial_secrets orelse return error.NoInitialSecrets;
            const aead = tls13.AeadContext.init(secrets.server, .TLS_AES_128_GCM_SHA256);
            aead.encrypt(pn, header, plaintext_buf[0..plaintext_offset], ciphertext[0..plaintext_offset], &auth_tag);
            hp_key = secrets.server.hp;
        } else {
            const secrets = conn.tls.handshake_secrets orelse return error.NoHandshakeSecrets;
            const aead = tls13.AeadContext.init(secrets.server, conn.tls.cipher_suite);
            aead.encrypt(pn, header, plaintext_buf[0..plaintext_offset], ciphertext[0..plaintext_offset], &auth_tag);
            hp_key = secrets.server.hp;
        }

        @memcpy(pkt.data[header_offset..][0..plaintext_offset], ciphertext[0..plaintext_offset]);
        header_offset += plaintext_offset;
        @memcpy(pkt.data[header_offset..][0..16], &auth_tag);
        header_offset += 16;

        var sample: [16]u8 = undefined;
        @memcpy(&sample, pkt.data[pn_offset + 4 ..][0..16]);
        tls13.applyHeaderProtection(hp_key, pkt.data[0..header_offset], pn_offset, 4, sample);

        if (pkt_type == .initial) {
            conn.next_pkt_num += 1;
        } else {
            conn.next_handshake_pkt_num += 1;
        }

        pkt.len = @intCast(header_offset);
        pkt.src_addr = conn.peer_addr;
        try self.queuePacket(&pkt);
        conn.stats.packets_sent += 1;
        self.stats.packets_sent += 1;
        logPacket("send", pkt_type, pn, plaintext_offset);
    }

    /// Drive the full server handshake flight in response to a parsed ClientHello: derive secrets,
    /// build ServerHello (sent as an Initial packet, server initial keys) and the
    /// EncryptedExtensions+Certificate+CertificateVerify+server-Finished flight (sent as one
    /// Handshake packet, server handshake keys). After this the server has set
    /// handshake_traffic_* and application_secrets; it then awaits the client's Finished.
    fn driveServerHandshake(self: *Self, conn: *Connection, client_hello: []const u8) !void {
        // Generate a fresh self-signed Ed25519 identity for this connection. Under allow_insecure
        // the client transcribes (but does not verify) the Certificate/CertificateVerify, so a
        // minimal DER blob + a real Ed25519 keypair suffice (no over-engineering).
        const kp = std.crypto.sign.Ed25519.KeyPair.generate();
        const cert = minimalSelfSignedCert(kp.public_key.toBytes());
        const seed: [32]u8 = kp.secret_key.seed(); // Ed25519 seed regenerates the same KeyPair

        var sh = ServerHandshake.init(self.allocator, &conn.tls, &cert, seed);
        defer sh.deinit();
        sh.selected_alpn = self.config.alpn;
        // RFC 9000 §7.3: advertise our own source CID as `initial_source_connection_id` (0x0f).
        // This MUST equal the SCID the server writes into its Initial packet header — sendServerCrypto
        // uses conn.local_cid, so use the same value here.
        if (conn.local_cid.len > 0) {
            var scid: [20]u8 = [_]u8{0} ** 20;
            @memcpy(scid[0..conn.local_cid.len], conn.local_cid.slice());
            sh.transport_params.initial_source_cid = scid;
            sh.transport_params.initial_source_cid_len = conn.local_cid.len;
        }
        // RFC 9000 §18.2: the server MUST echo the client's original destination CID as
        // `original_destination_connection_id` (0x00). acceptConnection stashed it in initial_dcid.
        // Without this, quinn/Agave abort the handshake with TRANSPORT_PARAMETER_ERROR
        // ("CID authentication failure") before it completes — the tx-ingest handshake blocker.
        if (conn.initial_dcid.len > 0) {
            var odcid: [20]u8 = [_]u8{0} ** 20;
            @memcpy(odcid[0..conn.initial_dcid.len], conn.initial_dcid.slice());
            sh.transport_params.original_dcid = odcid;
            sh.transport_params.original_dcid_len = conn.initial_dcid.len;
        }

        // ClientHello transcript was already appended in appendCryptoData (the client transcribes
        // the full message incl. 4-byte header; mirror that exactly). So DON'T re-transcribe here:
        // run a trimmed processClientHello that only parses the key_share + derives initial secrets.
        const ks = try tls13.parseClientHelloKeyShare(client_hello);
        conn.tls.remote_public_key = ks[0..32].*;
        sh.state = .sending_server_hello;

        // ServerHello -> Initial packet (server initial keys). generateServerHello updates the
        // transcript (CH+SH) and derives handshake secrets + handshake_traffic_*.
        const server_hello = try sh.generateServerHello();
        try self.sendServerCrypto(conn, .initial, 0, server_hello);

        // EncryptedExtensions + Certificate + CertificateVerify + server-Finished. Each generator
        // updates the transcript in order; generateFinished derives application_secrets. Concatenate
        // into ONE Handshake CRYPTO frame at offset 0 (the client reassembles by message length).
        const ee = try sh.generateEncryptedExtensions();
        const cert_msg = try sh.generateCertificate();
        const cv = try sh.generateCertificateVerify();
        const server_fin = try sh.generateFinished();

        var flight: [1024]u8 = undefined;
        var flen: usize = 0;
        for ([_][]const u8{ ee, cert_msg, cv, server_fin }) |m| {
            if (flen + m.len > flight.len) return error.FlightTooLarge;
            @memcpy(flight[flen..][0..m.len], m);
            flen += m.len;
        }
        try self.sendServerCrypto(conn, .handshake, 0, flight[0..flen]);

        // Install the server's application (1-RTT) AEAD so short-header app data decrypts/encrypts.
        // Mirror of the client installing application_secrets in processFinished.
        if (conn.tls.application_secrets) |secrets| {
            conn.tls.client_aead = tls13.AeadContext.init(secrets.client, conn.tls.cipher_suite);
            conn.tls.server_aead = tls13.AeadContext.init(secrets.server, conn.tls.cipher_suite);
            conn.tls.client_hp = secrets.client.hp;
            conn.tls.server_hp = secrets.server.hp;
        }
        std.log.debug("[QUIC] server handshake flight sent (SH initial + EE/Cert/CV/Fin handshake)\n", .{});
    }

    fn sendStreamData(self: *Self, conn: *Connection, stream_id: u64, data: []const u8, fin: bool) !void {
        if (self.sock == null) return error.NotBound;
        if (!conn.tls.handshake_complete) return error.HandshakeIncomplete;

        var payload: [1500]u8 = undefined;
        var offset: usize = 0;
        // STREAM frame: base type | 0x02 (LEN present) | 0x01 (FIN) when closing the stream.
        // Without the FIN bit the receiver's stream.fin_received never fires (perf: QUIC ingest fix).
        payload[offset] = @intFromEnum(FrameType.stream) | 0x02 | (if (fin) @as(u8, 0x01) else 0);
        offset += 1;

        offset += encodeVarInt(stream_id, payload[offset..][0..8]);
        offset += encodeVarInt(@intCast(data.len), payload[offset..][0..8]);
        @memcpy(payload[offset..][0..data.len], data);
        offset += data.len;

        var pkt = packet.Packet.init();
        var header_offset: usize = 0;

        pkt.data[header_offset] = 0x43; // Short header, 4-byte PN
        header_offset += 1;
        @memcpy(pkt.data[header_offset..][0..conn.remote_cid.len], conn.remote_cid.slice());
        header_offset += conn.remote_cid.len;

        const pn_offset = header_offset;
        std.mem.writeInt(u32, pkt.data[header_offset..][0..4], @intCast(conn.next_app_pkt_num), .big);
        header_offset += 4;

        const header = pkt.data[0..header_offset];
        var ciphertext: [1500]u8 = undefined;
        var auth_tag: [16]u8 = undefined;

        // Role-aware TX (1-RTT): a server encrypts as the SERVER (is_from_client=false); a client as the
        // CLIENT (is_from_client=true, the original). !is_srv ⇒ unchanged for the client path.
        const tx_is_client = !self.is_server;
        try conn.tls.encryptPacket(
            tx_is_client,
            conn.next_app_pkt_num,
            header,
            payload[0..offset],
            ciphertext[0..offset],
            &auth_tag,
        );

        @memcpy(pkt.data[header_offset..][0..offset], ciphertext[0..offset]);
        header_offset += offset;
        @memcpy(pkt.data[header_offset..][0..16], &auth_tag);
        header_offset += 16;

        var sample: [16]u8 = undefined;
        @memcpy(&sample, pkt.data[pn_offset + 4 ..][0..16]);
        conn.tls.protectHeader(tx_is_client, pkt.data[0..header_offset], pn_offset, 4, sample);

        conn.next_app_pkt_num += 1;
        pkt.len = @intCast(header_offset);
        pkt.src_addr = conn.peer_addr;

        try self.queuePacket(&pkt);
        conn.stats.packets_sent += 1;
        self.stats.packets_sent += 1;
        logPacket("send", .zero_rtt, conn.next_app_pkt_num - 1, offset);
    }

    fn sendAck(self: *Self, conn: *Connection, packet_number: u64, pkt_type: PacketType) !void {
        if (self.sock == null) return error.NotBound;

        var payload: [64]u8 = undefined;
        var offset: usize = 0;
        payload[offset] = @intFromEnum(FrameType.ack);
        offset += 1;
        offset += encodeVarInt(packet_number, payload[offset..][0..8]); // largest acked
        offset += encodeVarInt(0, payload[offset..][0..8]); // ack delay
        offset += encodeVarInt(0, payload[offset..][0..8]); // ack range count
        offset += encodeVarInt(0, payload[offset..][0..8]); // first ack range

        if (pkt_type == .handshake or pkt_type == .initial) {
            var pkt = packet.Packet.init();
            var header_offset: usize = 0;
            const first_byte: u8 = if (pkt_type == .handshake) 0xe3 else 0xc3;
            pkt.data[header_offset] = first_byte;
            header_offset += 1;
            std.mem.writeInt(u32, pkt.data[header_offset..][0..4], QUIC_VERSION_1, .big);
            header_offset += 4;

            pkt.data[header_offset] = conn.remote_cid.len;
            header_offset += 1;
            if (conn.remote_cid.len > 0) {
                @memcpy(pkt.data[header_offset..][0..conn.remote_cid.len], conn.remote_cid.slice());
                header_offset += conn.remote_cid.len;
            }

            pkt.data[header_offset] = conn.local_cid.len;
            header_offset += 1;
            if (conn.local_cid.len > 0) {
                @memcpy(pkt.data[header_offset..][0..conn.local_cid.len], conn.local_cid.slice());
                header_offset += conn.local_cid.len;
            }

            const payload_len = 4 + offset + 16;
            header_offset += encodeVarInt(@intCast(payload_len), pkt.data[header_offset..][0..8]);

            const pn_offset = header_offset;
            const pn = if (pkt_type == .handshake) conn.next_handshake_pkt_num else conn.next_pkt_num;
            std.mem.writeInt(u32, pkt.data[header_offset..][0..4], @intCast(pn), .big);
            header_offset += 4;

            const header = pkt.data[0..header_offset];
            var ciphertext: [128]u8 = undefined;
            var auth_tag: [16]u8 = undefined;
            var hp_key: [16]u8 = [_]u8{0} ** 16;
            // Role-aware TX: a server ENCRYPTS its ACKs with the SERVER keys; a client with the
            // CLIENT keys (the original, hardcoded behavior). With client keys on the server, the
            // client's removeHeaderProtection (server.hp) would garble the PN and the AEAD verify
            // would fail -> the handshake aborts. is_srv=false reproduces the prior client path.
            const is_srv = self.is_server;
            if (pkt_type == .initial) {
                const initial_secrets = conn.tls.initial_secrets orelse return error.NoInitialSecrets;
                const dir = if (is_srv) initial_secrets.server else initial_secrets.client;
                const initial_aead = tls13.AeadContext.init(dir, .TLS_AES_128_GCM_SHA256);
                initial_aead.encrypt(pn, header, payload[0..offset], ciphertext[0..offset], &auth_tag);
                hp_key = dir.hp;
            } else {
                const handshake_secrets = conn.tls.handshake_secrets orelse return error.NoHandshakeSecrets;
                const dir = if (is_srv) handshake_secrets.server else handshake_secrets.client;
                const handshake_aead = tls13.AeadContext.init(dir, conn.tls.cipher_suite);
                handshake_aead.encrypt(pn, header, payload[0..offset], ciphertext[0..offset], &auth_tag);
                hp_key = dir.hp;
            }
            @memcpy(pkt.data[header_offset..][0..offset], ciphertext[0..offset]);
            header_offset += offset;
            @memcpy(pkt.data[header_offset..][0..16], &auth_tag);
            header_offset += 16;

            var sample: [16]u8 = undefined;
            @memcpy(&sample, pkt.data[pn_offset + 4 ..][0..16]);
            tls13.applyHeaderProtection(hp_key, pkt.data[0..header_offset], pn_offset, 4, sample);

            if (pkt_type == .handshake) {
                conn.next_handshake_pkt_num += 1;
            } else {
                conn.next_pkt_num += 1;
            }

            pkt.len = @intCast(header_offset);
            pkt.src_addr = conn.peer_addr;
            try self.queuePacket(&pkt);
            logPacket("send", pkt_type, pn, offset);
        } else {
            if (!conn.tls.handshake_complete) return;
            var pkt = packet.Packet.init();
            var header_offset: usize = 0;
            pkt.data[header_offset] = 0x43;
            header_offset += 1;
            @memcpy(pkt.data[header_offset..][0..conn.remote_cid.len], conn.remote_cid.slice());
            header_offset += conn.remote_cid.len;
            const pn_offset = header_offset;
            const pn = conn.next_app_pkt_num;
            std.mem.writeInt(u32, pkt.data[header_offset..][0..4], @intCast(pn), .big);
            header_offset += 4;

            const header = pkt.data[0..header_offset];
            var ciphertext: [128]u8 = undefined;
            var auth_tag: [16]u8 = undefined;
            // Role-aware 1-RTT ACK: server encrypts as server (is_client=false), client as client.
            const ack_is_client = !self.is_server;
            try conn.tls.encryptPacket(ack_is_client, pn, header, payload[0..offset], ciphertext[0..offset], &auth_tag);
            @memcpy(pkt.data[header_offset..][0..offset], ciphertext[0..offset]);
            header_offset += offset;
            @memcpy(pkt.data[header_offset..][0..16], &auth_tag);
            header_offset += 16;

            var sample: [16]u8 = undefined;
            @memcpy(&sample, pkt.data[pn_offset + 4 ..][0..16]);
            conn.tls.protectHeader(ack_is_client, pkt.data[0..header_offset], pn_offset, 4, sample);

            conn.next_app_pkt_num += 1;
            pkt.len = @intCast(header_offset);
            pkt.src_addr = conn.peer_addr;
            try self.queuePacket(&pkt);
            logPacket("send", .zero_rtt, pn, offset);
        }
    }

    /// On-wire length of the long-header QUIC packet at data[0..] (header + Length-field payload),
    /// or null if it can't be parsed (Retry — no Length field, never coalesced — or truncation).
    /// Used to walk coalesced packets in a datagram (RFC 9000 §12.2). Read-only; mirrors the header
    /// parse in processLongHeaderPacket up to the Length field.
    fn longHeaderPacketLen(data: []const u8) ?usize {
        if (data.len < 7) return null;
        const first_byte = data[0];
        if ((first_byte & 0x80) == 0) return null; // not a long header
        const pkt_type: PacketType = @enumFromInt((first_byte >> 4) & 0x03);
        if (pkt_type == .retry) return null; // Retry has no Length field and is never coalesced
        var off: usize = 1 + 4; // first byte + version
        if (off + 1 > data.len) return null;
        const dcid_len = data[off];
        off += 1;
        if (dcid_len > 20 or off + dcid_len > data.len) return null;
        off += dcid_len;
        if (off + 1 > data.len) return null;
        const scid_len = data[off];
        off += 1;
        if (scid_len > 20 or off + scid_len > data.len) return null;
        off += scid_len;
        if (pkt_type == .initial) {
            var token_len: u64 = 0;
            const tlb = decodeVarInt(data[off..], &token_len) orelse return null;
            off += tlb;
            if (off + @as(usize, @intCast(token_len)) > data.len) return null;
            off += @intCast(token_len);
        }
        if (off >= data.len) return null;
        var payload_len: u64 = 0;
        const lb = decodeVarInt(data[off..], &payload_len) orelse return null;
        off += lb;
        const total = off + @as(usize, @intCast(payload_len));
        if (total > data.len) return null;
        return total;
    }

    /// Process incoming UDP datagram. RFC 9000 §12.2: a datagram may carry MULTIPLE coalesced QUIC
    /// packets — e.g. a server coalesces Initial(ServerHello) + Handshake(EE/Cert/CV/Finished) into
    /// ONE datagram. Walk and process each in turn (a short-header 1-RTT packet has no length and is
    /// always last). Before this fix only the first packet was processed, so the client missed the
    /// server's Handshake flight in the first response and had to wait for a ~2s PTO retransmit.
    pub fn processPacket(self: *Self, pkt: *const packet.Packet) !void {
        if (pkt.len < 5) return; // Too short

        self.stats.packets_received += 1;
        self.stats.bytes_received += pkt.len;

        var off: usize = 0;
        while (off + 1 <= pkt.len) {
            const fb = pkt.data[off];
            const is_long = (fb & 0x80) != 0;
            if (!is_long) {
                // Short header (1-RTT) — always the last packet. Require the fixed bit (0x40) to be
                // set; anything else (e.g. trailing datagram zero-padding) ends the walk.
                if ((fb & 0x40) == 0) break;
                if (off == 0) {
                    try self.processShortHeaderPacket(pkt);
                } else {
                    var seg = packet.Packet.init();
                    const rem = pkt.len - off;
                    @memcpy(seg.data[0..rem], pkt.data[off..pkt.len]);
                    seg.len = @intCast(rem);
                    seg.src_addr = pkt.src_addr;
                    try self.processShortHeaderPacket(&seg);
                }
                break;
            }
            const seg_len = longHeaderPacketLen(pkt.data[0..pkt.len][off..]) orelse {
                // Unparseable (Retry / truncation). If it's the only packet, process whole (prior
                // behavior); otherwise stop walking.
                if (off == 0) try self.processLongHeaderPacket(pkt);
                break;
            };
            if (off == 0 and seg_len == pkt.len) {
                // Common single-packet datagram — process in place, no copy.
                try self.processLongHeaderPacket(pkt);
                break;
            }
            // Coalesced segment: process just this packet's bytes. Don't let one bad segment drop
            // the rest of the datagram.
            var seg = packet.Packet.init();
            @memcpy(seg.data[0..seg_len], pkt.data[off..][0..seg_len]);
            seg.len = @intCast(seg_len);
            seg.src_addr = pkt.src_addr;
            self.processLongHeaderPacket(&seg) catch |e| {
                std.log.debug("[QUIC] coalesced segment err: {}\n", .{e});
            };
            off += seg_len;
        }
    }

    fn processLongHeaderPacket(self: *Self, pkt: *const packet.Packet) !void {
        var offset: usize = 1;

        // Version
        const version = std.mem.readInt(u32, pkt.data[offset..][0..4], .big);
        offset += 4;

        if (version != QUIC_VERSION_1 and version != QUIC_VERSION_2) {
            // Version negotiation needed
            return;
        }

        // Destination CID
        const dcid_len = pkt.data[offset];
        offset += 1;
        if (dcid_len > 20 or offset + dcid_len > pkt.len) return;
        var dcid = ConnectionId{ .data = undefined, .len = dcid_len };
        @memcpy(dcid.data[0..dcid_len], pkt.data[offset..][0..dcid_len]);
        offset += dcid_len;

        // Source CID
        const scid_len = pkt.data[offset];
        offset += 1;
        if (scid_len > 20 or offset + scid_len > pkt.len) return;
        var scid = ConnectionId{ .data = undefined, .len = scid_len };
        @memcpy(scid.data[0..scid_len], pkt.data[offset..][0..scid_len]);
        offset += scid_len;

        const first_byte = pkt.data[0];
        const pkt_type: PacketType = @enumFromInt((first_byte >> 4) & 0x03);
        std.log.debug("[QUIC] processing long header: type={s} dcid={any} scid={any}\n", .{
            @tagName(pkt_type),
            dcid.slice(),
            scid.slice(),
        });

        // Find connection by DCID (for server responses, DCID = our local CID or our initial DCID)
        const cid_hash = hashConnectionId(&dcid);
        var conn = self.connections.get(cid_hash);

        // For client: server response has DCID = our local CID, which is stored
        // as local_cid in the connection. We need to find by local CID.
        if (conn == null and !self.is_server) {
            // As client, check if DCID matches any connection's initial_dcid
            // (The server echoes back our initial destination CID)
            var conn_iter = self.connections.valueIterator();
            while (conn_iter.next()) |c| {
                if (c.*.initial_dcid.eql(&dcid)) {
                    conn = c.*;
                    std.log.debug("[QUIC] Found connection by initial_dcid match ({s})\n", .{@tagName(pkt_type)});
                    break;
                }
            }
            if (conn == null) {
                std.log.debug("[QUIC] No connection found for dcid: {any} (client mode)\n", .{dcid.slice()});
            }
        }

        if (conn == null and self.is_server) {
            // New connection (server accepting). Pass the parsed client DCID so Initial secrets
            // derive from the same CID bytes the client used.
            conn = try self.acceptConnection(pkt.src_addr, scid, dcid);
        }

        if (conn) |c| {
            if (scid.len > 0 and !c.remote_cid.eql(&scid)) {
                c.remote_cid = scid;
            }
            c.stats.packets_received += 1;

            if (pkt_type == .initial) {
                var token_len: u64 = 0;
                const token_len_bytes = decodeVarInt(pkt.data[offset..], &token_len) orelse return;
                offset += token_len_bytes;
                if (offset + token_len > pkt.len) return;
                offset += @intCast(token_len);
            }

            var payload_len: u64 = 0;
            const len_bytes = decodeVarInt(pkt.data[offset..], &payload_len) orelse return;
            offset += len_bytes;

            const pn_offset = offset;
            if (pn_offset + 4 + 16 > pkt.len) return;
            var sample: [16]u8 = undefined;
            @memcpy(&sample, pkt.data[pn_offset + 4 ..][0..16]);

            const header_len = pn_offset + 4;
            if (header_len > 256) return;
            var header_buf: [256]u8 = undefined;
            @memcpy(header_buf[0..header_len], pkt.data[0..header_len]);
            // Role-aware RX (perf: QUIC server-ingest): we DECRYPT packets the PEER sent. A server
            // receives from a CLIENT → use client keys; a client receives from a SERVER → server keys
            // (the original behavior). is_srv=false reproduces the prior client path byte-for-byte.
            const is_srv = self.is_server;
            const hp_key = switch (pkt_type) {
                .initial => if (c.tls.initial_secrets) |secrets| (if (is_srv) secrets.client.hp else secrets.server.hp) else return,
                .handshake => if (c.tls.handshake_secrets) |secrets| (if (is_srv) secrets.client.hp else secrets.server.hp) else return,
                else => if (is_srv) c.tls.client_hp else c.tls.server_hp,
            };
            const pn_len = tls13.removeHeaderProtection(hp_key, header_buf[0..header_len], pn_offset, sample);
            if (pn_offset + pn_len > pkt.len) return;

            var pn_truncated: u64 = 0;
            var i: usize = 0;
            while (i < pn_len) : (i += 1) {
                pn_truncated = (pn_truncated << 8) | header_buf[pn_offset + i];
            }
            const expected = c.largest_rx_pn + 1;
            const pn = reconstructPacketNumber(pn_truncated, pn_len, expected);
            if (pn > c.largest_rx_pn) c.largest_rx_pn = pn;

            const payload_total = @as(usize, @intCast(payload_len));
            if (payload_total < pn_len + 16) return;
            const ciphertext_len = payload_total - pn_len - 16;
            if (pn_offset + pn_len + ciphertext_len + 16 > pkt.len) return;

            const ciphertext = pkt.data[pn_offset + pn_len ..][0..ciphertext_len];
            const tag = pkt.data[pn_offset + pn_len + ciphertext_len ..][0..16];

            if (ciphertext_len > 1500) return;
            var plaintext_buf: [1500]u8 = undefined;
            var tag_buf: [16]u8 = undefined;
            @memcpy(&tag_buf, tag);

            switch (pkt_type) {
                .initial => {
                    if (c.tls.initial_secrets) |secrets| {
                        const ctx = tls13.AeadContext.init(if (is_srv) secrets.client else secrets.server, .TLS_AES_128_GCM_SHA256);
                        ctx.decrypt(pn, header_buf[0 .. pn_offset + pn_len], ciphertext, tag_buf, plaintext_buf[0..ciphertext_len]) catch |err| {
                            std.log.debug("[QUIC] initial decrypt failed pn={d} err={}\n", .{ pn, err });
                            return err;
                        };
                    } else {
                        std.log.debug("[QUIC] missing initial secrets for decrypt\n", .{});
                        return;
                    }
                },
                .handshake => {
                    if (c.tls.handshake_secrets) |secrets| {
                        const ctx = tls13.AeadContext.init(if (is_srv) secrets.client else secrets.server, c.tls.cipher_suite);
                        ctx.decrypt(pn, header_buf[0 .. pn_offset + pn_len], ciphertext, tag_buf, plaintext_buf[0..ciphertext_len]) catch |err| {
                            std.log.debug("[QUIC] handshake decrypt failed pn={d} err={}\n", .{ pn, err });
                            return err;
                        };
                    } else {
                        std.log.debug("[QUIC] missing handshake secrets for decrypt\n", .{});
                        return;
                    }
                },
                else => {
                    c.tls.decryptPacket(is_srv, pn, header_buf[0 .. pn_offset + pn_len], ciphertext, tag_buf, plaintext_buf[0..ciphertext_len]) catch |err| {
                        std.log.debug("[QUIC] long header decrypt failed pn={d} err={}\n", .{ pn, err });
                        return err;
                    };
                },
            }

            try self.processFrames(c, plaintext_buf[0..ciphertext_len]);
            logPacket("recv", pkt_type, pn, ciphertext_len);
            try self.sendAck(c, pn, pkt_type);
        }
    }

    fn processShortHeaderPacket(self: *Self, pkt: *const packet.Packet) !void {
        // Short header: [flags(1) | dcid(variable) | packet_num(1-4) | payload]
        // For short header, we need to know the DCID length from the connection

        // Try to find connection by peer address
        const addr_hash = hashSocketAddr(&pkt.src_addr);
        const conn = self.connections_by_addr.get(addr_hash) orelse return;

        if (!conn.tls.handshake_complete) {
            std.log.debug("[QUIC] drop short header before handshake\n", .{});
            return;
        }

        conn.stats.packets_received += 1;

        const pn_offset = 1 + conn.local_cid.len;
        if (pn_offset + 4 + 16 > pkt.len) return;
        var sample: [16]u8 = undefined;
        @memcpy(&sample, pkt.data[pn_offset + 4 ..][0..16]);

        const header_len = pn_offset + 4;
        if (header_len > 256) return;
        var header_buf: [256]u8 = undefined;
        @memcpy(header_buf[0..header_len], pkt.data[0..header_len]);
        // Role-aware RX (1-RTT): server unprotects/decrypts what the CLIENT sent (is_from_client=true);
        // client uses server keys (is_from_client=false, the original). is_srv=false ⇒ unchanged.
        const is_srv = self.is_server;
        const pn_len = conn.tls.unprotectHeader(is_srv, header_buf[0..header_len], pn_offset, sample);
        if (pn_offset + pn_len > pkt.len) return;

        var pn_truncated: u64 = 0;
        var i: usize = 0;
        while (i < pn_len) : (i += 1) {
            pn_truncated = (pn_truncated << 8) | header_buf[pn_offset + i];
        }
        const expected = conn.largest_rx_pn + 1;
        const pn = reconstructPacketNumber(pn_truncated, pn_len, expected);
        if (pn > conn.largest_rx_pn) conn.largest_rx_pn = pn;

        const payload_len = pkt.len - (pn_offset + pn_len);
        if (payload_len < 16) return;
        const ciphertext_len = payload_len - 16;
        const ciphertext = pkt.data[pn_offset + pn_len ..][0..ciphertext_len];
        const tag = pkt.data[pn_offset + pn_len + ciphertext_len ..][0..16];

        if (ciphertext_len > 1500) return;
        var plaintext_buf: [1500]u8 = undefined;
        var tag_buf: [16]u8 = undefined;
        @memcpy(&tag_buf, tag);
        conn.tls.decryptPacket(is_srv, pn, header_buf[0 .. pn_offset + pn_len], ciphertext, tag_buf, plaintext_buf[0..ciphertext_len]) catch |err| {
            std.log.debug("[QUIC] short header decrypt failed pn={d} err={}\n", .{ pn, err });
            return err;
        };

        try self.processFrames(conn, plaintext_buf[0..ciphertext_len]);
        logPacket("recv", .zero_rtt, pn, ciphertext_len);
        try self.sendAck(conn, pn, .zero_rtt);
    }

    fn processFrames(self: *Self, conn: *Connection, payload: []const u8) !void {
        var offset: usize = 0;

        while (offset < payload.len) {
            const frame_type = payload[offset];
            offset += 1;
            std.log.debug("[QUIC] frame type=0x{x}\n", .{frame_type});

            // DIAGNOSTIC (VEX_QUIC_FRAME_DUMP): per-frame type + raw tail bytes, so a real
            // leader's NEW_CONNECTION_ID (0x18, 16-byte reset token), MAX_STREAMS_UNI (0x13),
            // MAX_DATA (0x10) and any CONNECTION_CLOSE error code are captured byte-exact as
            // golden KAT vectors. Gated; the QUIC stack is dormant on the live path.
            if (std.posix.getenv("VEX_QUIC_FRAME_DUMP") != null) {
                const tail = payload[offset..@min(payload.len, offset + 40)];
                std.debug.print("[QUIC-DUMP] frame=0x{x:0>2} next{d}=", .{ frame_type, tail.len });
                for (tail) |b| std.debug.print("{x:0>2}", .{b});
                std.debug.print("\n", .{});
            }

            switch (frame_type) {
                @intFromEnum(FrameType.padding) => {
                    // Skip padding
                    continue;
                },
                @intFromEnum(FrameType.ping) => {
                    // Ping - just acknowledge
                    continue;
                },
                @intFromEnum(FrameType.ack), @intFromEnum(FrameType.ack_ecn) => {
                    // Process ACK
                    var largest_acked: u64 = 0;
                    const largest_len = decodeVarInt(payload[offset..], &largest_acked) orelse return;
                    offset += largest_len;

                    var ack_delay: u64 = 0;
                    const delay_len = decodeVarInt(payload[offset..], &ack_delay) orelse return;
                    offset += delay_len;

                    var range_count: u64 = 0;
                    const range_len = decodeVarInt(payload[offset..], &range_count) orelse return;
                    offset += range_len;

                    var first_range: u64 = 0;
                    const first_range_len = decodeVarInt(payload[offset..], &first_range) orelse return;
                    offset += first_range_len;

                    var ranges: [32]AckRange = undefined;
                    var num_ranges: usize = 0;

                    // The first range is [largest_acked - first_range, largest_acked]
                    if (num_ranges < ranges.len) {
                        ranges[num_ranges] = .{
                            .start = if (largest_acked >= first_range) largest_acked - first_range else 0,
                            .end = largest_acked,
                        };
                        num_ranges += 1;
                    }

                    var current_pn = if (largest_acked >= first_range) largest_acked - first_range else 0;
                    var r: u64 = 0;
                    while (r < range_count) : (r += 1) {
                        var gap: u64 = 0;
                        const gap_len = decodeVarInt(payload[offset..], &gap) orelse return;
                        offset += gap_len;

                        var range_len2: u64 = 0;
                        const range_len2_len = decodeVarInt(payload[offset..], &range_len2) orelse return;
                        offset += range_len2_len;

                        if (current_pn > gap + 1) {
                            const end = current_pn - gap - 2;
                            const start = if (end >= range_len2) end - range_len2 else 0;
                            if (num_ranges < ranges.len) {
                                ranges[num_ranges] = .{ .start = start, .end = end };
                                num_ranges += 1;
                            }
                            current_pn = start;
                        }
                    }

                    const result = conn.loss_detector.onAckReceived(
                        largest_acked,
                        ack_delay,
                        ranges[0..num_ranges],
                        &conn.congestion,
                    );

                    // Upgrade MTU if probe was acked
                    if (result.pmtud_probe_acked) {
                        conn.mtu = 1472; // Upgraded to 1500 Ethernet MTU (minus UDP/IP headers)
                        std.log.info("[QUIC] PMTUD: connection {x} upgraded to 1500 MTU", .{hashConnectionId(&conn.local_cid)});
                    }

                    if (frame_type == @intFromEnum(FrameType.ack_ecn)) {
                        var tmp: u64 = 0;
                        const ect0_len = decodeVarInt(payload[offset..], &tmp) orelse return;
                        offset += ect0_len;
                        const ect1_len = decodeVarInt(payload[offset..], &tmp) orelse return;
                        offset += ect1_len;
                        const ce_len = decodeVarInt(payload[offset..], &tmp) orelse return;
                        offset += ce_len;
                    }
                },
                @intFromEnum(FrameType.crypto) => {
                    if (conn.state == .initial) {
                        conn.state = .handshake;
                    }
                    var crypto_offset: u64 = 0;
                    const off_len = decodeVarInt(payload[offset..], &crypto_offset) orelse return;
                    offset += off_len;
                    var crypto_len: u64 = 0;
                    const len_len = decodeVarInt(payload[offset..], &crypto_len) orelse return;
                    offset += len_len;
                    if (offset + crypto_len > payload.len) return;
                    std.log.debug("[QUIC] crypto offset={d} len={d}\n", .{ crypto_offset, crypto_len });
                    try conn.appendCryptoData(payload[offset..][0..@intCast(crypto_len)]);
                    offset += @intCast(crypto_len);
                },
                @intFromEnum(FrameType.handshake_done) => {
                    conn.state = .connected;
                    conn.tls.handshake_complete = true;
                },
                @intFromEnum(FrameType.stream)...(@intFromEnum(FrameType.stream) + 7) => {
                    // STREAM frame
                    const consumed = try self.processStreamFrame(conn, frame_type, payload[offset..]);
                    offset += consumed;
                },
                @intFromEnum(FrameType.connection_close), @intFromEnum(FrameType.connection_close_app) => {
                    var err_code: u64 = 0;
                    const err_len = decodeVarInt(payload[offset..], &err_code) orelse return;
                    offset += err_len;
                    if (frame_type == @intFromEnum(FrameType.connection_close)) {
                        var frame_code: u64 = 0;
                        const frame_len = decodeVarInt(payload[offset..], &frame_code) orelse return;
                        offset += frame_len;
                        var reason_len: u64 = 0;
                        const reason_len_len = decodeVarInt(payload[offset..], &reason_len) orelse return;
                        offset += reason_len_len;
                        if (offset + reason_len <= payload.len) {
                            const reason = payload[offset..][0..@intCast(reason_len)];
                            std.log.debug("[QUIC] close err={d} frame={d} reason={s}\n", .{
                                err_code,
                                frame_code,
                                reason,
                            });
                            offset += @intCast(reason_len);
                        } else {
                            std.log.debug("[QUIC] close err={d} frame={d} reason=<truncated>\n", .{ err_code, frame_code });
                        }
                    } else {
                        var reason_len: u64 = 0;
                        const reason_len_len = decodeVarInt(payload[offset..], &reason_len) orelse return;
                        offset += reason_len_len;
                        if (offset + reason_len <= payload.len) {
                            const reason = payload[offset..][0..@intCast(reason_len)];
                            std.log.debug("[QUIC] app-close err={d} reason={s}\n", .{ err_code, reason });
                            offset += @intCast(reason_len);
                        } else {
                            std.log.debug("[QUIC] app-close err={d} reason=<truncated>\n", .{err_code});
                        }
                    }
                    conn.state = .draining;
                    break;
                },
                // ── Flow-control / stream-management frames (RFC 9000) ───────────
                // These previously fell into `else => break`, which STRANDED every
                // subsequent (coalesced) frame in the packet — including the
                // MAX_STREAMS_UNI (0x13) that grants our uni-stream vote credit, and
                // the HANDSHAKE_DONE that follows it. QUIC frames have NO length
                // prefix, so each MUST be parsed byte-exact to advance `offset`;
                // "skipping" an unparsed frame desyncs the rest of the packet. Layouts
                // verified against real testnet-leader captures (2026-06-20).
                @intFromEnum(FrameType.max_data),
                @intFromEnum(FrameType.data_blocked),
                @intFromEnum(FrameType.streams_blocked_bidi),
                @intFromEnum(FrameType.streams_blocked_uni),
                @intFromEnum(FrameType.retire_connection_id),
                => {
                    // Single varint payload.
                    var v: u64 = 0;
                    const n = decodeVarInt(payload[offset..], &v) orelse return;
                    offset += n;
                },
                @intFromEnum(FrameType.max_streams_bidi) => {
                    // Cumulative max bidi-stream count (monotonic).
                    var v: u64 = 0;
                    const n = decodeVarInt(payload[offset..], &v) orelse return;
                    offset += n;
                    conn.peer_max_streams_bidi = @max(conn.peer_max_streams_bidi, v);
                },
                @intFromEnum(FrameType.max_streams_uni) => {
                    // THE vote-credit frame. Cumulative max uni-stream count the peer
                    // grants us; monotonic (only grows). openUniStream gates on this.
                    var v: u64 = 0;
                    const n = decodeVarInt(payload[offset..], &v) orelse return;
                    offset += n;
                    conn.peer_max_streams_uni = @max(conn.peer_max_streams_uni, v);
                    std.log.debug("[QUIC] MAX_STREAMS_UNI -> credit={d}\n", .{conn.peer_max_streams_uni});
                },
                @intFromEnum(FrameType.max_stream_data),
                @intFromEnum(FrameType.stream_data_blocked),
                @intFromEnum(FrameType.stop_sending),
                => {
                    // Two varints (stream_id + value).
                    var a: u64 = 0;
                    const an = decodeVarInt(payload[offset..], &a) orelse return;
                    offset += an;
                    var b: u64 = 0;
                    const bn = decodeVarInt(payload[offset..], &b) orelse return;
                    offset += bn;
                },
                @intFromEnum(FrameType.reset_stream) => {
                    // Three varints (stream_id + app_error_code + final_size).
                    var i: usize = 0;
                    while (i < 3) : (i += 1) {
                        var v: u64 = 0;
                        const n = decodeVarInt(payload[offset..], &v) orelse return;
                        offset += n;
                    }
                },
                @intFromEnum(FrameType.new_token) => {
                    // token_length (varint) + token.
                    var tlen: u64 = 0;
                    const n = decodeVarInt(payload[offset..], &tlen) orelse return;
                    offset += n;
                    if (offset + tlen > payload.len) return;
                    offset += @intCast(tlen);
                },
                @intFromEnum(FrameType.new_connection_id) => {
                    // seq(varint) retire_prior_to(varint) len(1 byte) CID(len) reset_token(16).
                    // The advisor's "nasty one": the 16-byte reset token has no length
                    // prefix, so a wrong skip strands the rest of the packet.
                    var seq: u64 = 0;
                    const sn = decodeVarInt(payload[offset..], &seq) orelse return;
                    offset += sn;
                    var retire: u64 = 0;
                    const rn = decodeVarInt(payload[offset..], &retire) orelse return;
                    offset += rn;
                    if (offset >= payload.len) return;
                    const cid_len = payload[offset];
                    offset += 1;
                    if (offset + cid_len + 16 > payload.len) return;
                    offset += cid_len; // connection id
                    offset += 16; // stateless reset token
                },
                @intFromEnum(FrameType.path_challenge),
                @intFromEnum(FrameType.path_response),
                => {
                    // 8 bytes of opaque data.
                    if (offset + 8 > payload.len) return;
                    offset += 8;
                },
                else => {
                    // Truly-unknown frame type. QUIC frames are not self-delimiting,
                    // so we cannot skip it — stop processing this packet (RFC 9000
                    // would FRAME_ENCODING_ERROR-close; we conservatively break).
                    std.log.debug("[QUIC] unhandled frame type=0x{x} — stopping packet parse\n", .{frame_type});
                    break;
                },
            }
        }
    }

    fn processStreamFrame(self: *Self, conn: *Connection, frame_type: u8, data: []const u8) !usize {
        _ = self;
        if (data.len == 0) return 0;

        // Parse stream frame
        const has_offset = (frame_type & 0x04) != 0;
        const has_length = (frame_type & 0x02) != 0;
        const has_fin = (frame_type & 0x01) != 0;

        var offset: usize = 0;

        var stream_id: u64 = 0;
        const id_len = decodeVarInt(data[offset..], &stream_id) orelse return 0;
        offset += id_len;

        if (has_offset) {
            var stream_offset: u64 = 0;
            const off_len = decodeVarInt(data[offset..], &stream_offset) orelse return 0;
            offset += off_len;
        }

        var data_len: usize = data.len - offset;
        if (has_length) {
            var stream_len: u64 = 0;
            const len_len = decodeVarInt(data[offset..], &stream_len) orelse return 0;
            offset += len_len;
            if (offset + stream_len > data.len) return 0;
            data_len = @intCast(stream_len);
        }

        // Get or create stream
        var stream = conn.streams.get(stream_id);
        if (stream == null) {
            stream = try Stream.init(conn.allocator, conn, stream_id);
            try conn.streams.put(stream_id, stream.?);
        }

        // Append data
        if (data_len > 0) {
            try stream.?.appendRecvData(data[offset..][0..data_len]);
        }

        if (has_fin) {
            stream.?.fin_received = true;
            if (stream.?.state == .open) {
                stream.?.state = .half_closed_remote;
            } else if (stream.?.state == .half_closed_local) {
                stream.?.state = .closed;
            }
        }
        return offset + data_len;
    }

    /// Flush outgoing packet batch
    pub fn flush(self: *Self) !void {
        if (self.sock) |*s| {
            if (!self.tx_batch.isEmpty()) {
                _ = try s.sendBatch(&self.tx_batch);
                self.tx_batch.clear();
            }
        }
    }

    fn queuePacket(self: *Self, pkt: *const packet.Packet) !void {
        if (self.sock == null) return error.NotBound;

        // If batch is full, flush it
        if (self.tx_batch.isFull()) {
            try self.flush();
        }

        // Push packet (copy)
        if (self.tx_batch.push()) |dest| {
            dest.* = pkt.*;
        }
    }

    /// Poll for events
    pub fn poll(self: *Self) !void {
        // Try to flush any pending packets
        self.flush() catch |err| {
            std.log.debug("[QUIC] poll flush error: {}\n", .{err});
        };

        if (self.sock == null) return;

        // Receive packets
        var batch = try packet.PacketBatch.init(self.allocator, 64);
        defer batch.deinit();

        const received = self.sock.?.recvBatch(&batch) catch |err| {
            std.log.debug("[QUIC] poll: recvBatch error: {}\n", .{err});
            return;
        };

        if (received > 0) {
            std.log.debug("[QUIC] poll: received {d} packets\n", .{received});
        }

        for (batch.slice()) |*pkt| {
            try self.processPacket(pkt);
        }

        // Run PMTUD probes for connected connections
        var it = self.connections.valueIterator();
        const now: i64 = @intCast(std.time.nanoTimestamp());
        while (it.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            if (conn.state == .connected and conn.mtu < 1472) {
                // If we haven't probed for 1 second and we sent less than 3 probes
                if (now - conn.pmtud_last_probe_time > 1000 * std.time.ns_per_ms and conn.pmtud_probes_sent < 3) {
                    try self.sendProbe(conn);
                }
            }
        }
    }

    fn sendProbe(self: *Self, conn: *Connection) !void {
        if (self.sock == null) return error.NotBound;

        // Only probe if we haven't reached 1500 MTU yet
        if (conn.mtu >= 1472) return;

        var pkt = packet.Packet.init();
        pkt.src_addr = conn.peer_addr;

        // Encode Short Header
        var offset: usize = 0;
        pkt.data[offset] = 0x40; // Short header, 1-byte packet number
        offset += 1;

        @memcpy(pkt.data[offset..][0..conn.remote_cid.len], conn.remote_cid.slice());
        offset += conn.remote_cid.len;

        const pn = conn.next_app_pkt_num;
        conn.next_app_pkt_num += 1;
        pkt.data[offset] = @intCast(pn & 0xff);
        offset += 1;

        const header_len = offset;

        // PING frame
        pkt.data[offset] = @intFromEnum(FrameType.ping);
        offset += 1;

        // Padding to target MTU 1472 (UDP payload)
        const target_len = 1472;
        if (offset < target_len - 16) { // 16 for auth tag
            @memset(pkt.data[offset .. target_len - 16], @intFromEnum(FrameType.padding));
            offset = target_len - 16;
        }

        const plaintext_len = offset - header_len;
        _ = plaintext_len;
        var auth_tag: [16]u8 = undefined;
        try conn.tls.encryptPacket(true, pn, pkt.data[0..header_len], pkt.data[header_len..offset], pkt.data[header_len..offset], &auth_tag);
        @memcpy(pkt.data[offset..][0..16], &auth_tag);
        offset += 16;

        pkt.len = @intCast(offset);

        // Track sent packet
        var sent_pkt = SentPacket{
            .packet_number = pn,
            .time_sent = @intCast(std.time.nanoTimestamp()),
            .ack_eliciting = true,
            .in_flight = true,
            .size = @intCast(offset),
            .encryption_level = .application,
            .is_pmtud_probe = true,
            .frames = undefined,
            .frame_count = 0,
        };
        sent_pkt.addFrame(.ping);
        try conn.loss_detector.sent_packets.put(pn, sent_pkt);

        try self.queuePacket(&pkt);
        conn.pmtud_probes_sent += 1;
        conn.pmtud_last_probe_time = @intCast(std.time.nanoTimestamp());
    }

    /// Get connection by ID
    pub fn getConnection(self: *Self, cid: *const ConnectionId) ?*Connection {
        return self.connections.get(hashConnectionId(cid));
    }

    /// Get statistics
    pub fn getStats(self: *const Self) EndpointStats {
        return self.stats;
    }
};

fn hashConnectionId(cid: *const ConnectionId) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(cid.slice());
    return h.final();
}

fn hashSocketAddr(addr: *const packet.SocketAddr) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(std.mem.asBytes(addr));
    return h.final();
}

/// Resolve an EndpointConfig.bind_addr dotted-IPv4 string (e.g. "203.0.113.7") + port into a
/// packet.SocketAddr. Empty string or an unparseable address both fall back to 0.0.0.0 (the exact
/// prior hardcoded behavior) — a config typo can never prevent the endpoint from binding at all;
/// Endpoint.bind() has its own second-layer fallback if the actual bind() syscall then fails.
fn resolveBindAddr(ip_str: []const u8, port: u16) packet.SocketAddr {
    if (ip_str.len == 0) return packet.SocketAddr.ipv4(.{ 0, 0, 0, 0 }, port);
    const parsed = std.net.Address.parseIp4(ip_str, port) catch |err| {
        std.log.warn("[QUIC-BIND] invalid bind_addr '{s}': {} — falling back to 0.0.0.0:{d}", .{ ip_str, err, port });
        return packet.SocketAddr.ipv4(.{ 0, 0, 0, 0 }, port);
    };
    return packet.SocketAddr.ipv4(@as([4]u8, @bitCast(parsed.in.sa.addr)), port);
}

// resolveBindAddr is the shared resolver both QuicClient.init and QuicServer.init feed into
// Endpoint.bind() — cover its two branches directly.
test "resolveBindAddr: empty bind_addr resolves to wildcard 0.0.0.0" {
    const addr = resolveBindAddr("", 8010);
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, addr.addr[0..4].*);
    try std.testing.expectEqual(@as(u16, 8010), addr.port());
}

test "resolveBindAddr: explicit IPv4 string resolves to that address, preserving port" {
    const addr = resolveBindAddr("203.0.113.42", 8010);
    try std.testing.expectEqual([4]u8{ 203, 0, 113, 42 }, addr.addr[0..4].*);
    try std.testing.expectEqual(@as(u16, 8010), addr.port());
}

test "resolveBindAddr: unparseable bind_addr falls back to wildcard, not a crash" {
    const addr = resolveBindAddr("not-an-ip", 8010);
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, addr.addr[0..4].*);
    try std.testing.expectEqual(@as(u16, 8010), addr.port());
}

/// QUIC client for TPU connections
pub const QuicClient = struct {
    allocator: std.mem.Allocator,
    endpoint: *Endpoint,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, bind_port: u16, config: Endpoint.EndpointConfig) !*Self {
        const client = try allocator.create(Self);
        // 2026-07-06: bind_port was previously hardcoded into a 0.0.0.0 SocketAddr — see
        // config.bind_addr (EndpointConfig) / core/config.zig quic_bind_addr for the vote-client
        // dual-NIC source-IP fix this plumbs through.
        const bind_addr = resolveBindAddr(config.bind_addr, bind_port);
        client.* = .{
            .allocator = allocator,
            .endpoint = try Endpoint.init(allocator, bind_addr, false, config),
        };
        try client.endpoint.bind();
        return client;
    }

    pub fn deinit(self: *Self) void {
        self.endpoint.deinit();
        self.allocator.destroy(self);
    }

    pub fn connect(self: *Self, host: []const u8, port: u16) !*Connection {
        // Parse IP
        const ip = std.net.Address.parseIp4(host, port) catch return error.InvalidAddress;
        const addr = packet.SocketAddr.ipv4(
            @as([4]u8, @bitCast(ip.in.sa.addr)),
            port,
        );
        return self.endpoint.connect(addr);
    }

    pub fn poll(self: *Self) !void {
        try self.endpoint.poll();
    }

    pub fn resendInitial(self: *Self, conn: *Connection) !void {
        try self.endpoint.resendInitial(conn);
    }
};

/// QUIC server for TPU
pub const QuicServer = struct {
    allocator: std.mem.Allocator,
    endpoint: *Endpoint,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, port: u16, config: Endpoint.EndpointConfig) !*Self {
        const server = try allocator.create(Self);
        // 2026-07-21 CORRECTION: a listening server does NOT have a free pass on source-IP —
        // its handshake REPLY still egresses via a kernel route lookup when unbound, which on a
        // dual-NIC host can pick a different IP than the one the client dialed, and a peer
        // validating the reply's source against the address it dialed then drops it. Honor
        // config.bind_addr via the same resolver as QuicClient so dual-NIC server callers
        // (main.zig's TPU-ingest server) can pin the reply source to the advertised IP.
        const bind_addr = resolveBindAddr(config.bind_addr, port);
        server.* = .{
            .allocator = allocator,
            .endpoint = try Endpoint.init(allocator, bind_addr, true, config),
        };
        try server.endpoint.bind();
        return server;
    }

    pub fn deinit(self: *Self) void {
        self.endpoint.deinit();
        self.allocator.destroy(self);
    }

    pub fn poll(self: *Self) !void {
        try self.endpoint.poll();
    }

    pub fn getStats(self: *const Self) Endpoint.EndpointStats {
        return self.endpoint.getStats();
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// LOSS DETECTION AND CONGESTION CONTROL (RFC 9002)
// ═══════════════════════════════════════════════════════════════════════════════

/// Sent packet metadata for loss detection and RTT measurement
/// Optimized: Fixed-size frame storage, no allocations on hot path
pub const SentPacket = struct {
    packet_number: u64,
    time_sent: i64, // nanoseconds since epoch
    ack_eliciting: bool,
    in_flight: bool,
    size: u32, // Changed to u32 (packets are < 64KB)
    encryption_level: EncryptionLevel,
    is_pmtud_probe: bool = false,
    /// Fixed-size frame storage (avoids ArrayList allocation)
    frames: [MAX_FRAMES_PER_PACKET]FrameType,
    frame_count: u8,

    pub const EncryptionLevel = enum(u8) {
        initial = 0,
        handshake = 1,
        application = 2,
    };

    /// Maximum frames we track per packet (typically 1-3)
    pub const MAX_FRAMES_PER_PACKET = 8;

    pub fn addFrame(self: *SentPacket, frame: FrameType) void {
        if (self.frame_count < MAX_FRAMES_PER_PACKET) {
            self.frames[self.frame_count] = frame;
            self.frame_count += 1;
        }
    }

    pub fn getFrames(self: *const SentPacket) []const FrameType {
        return self.frames[0..self.frame_count];
    }
};

/// Loss detection state per connection
/// Optimized: Fixed-size ring buffer for lost packets, no allocations on hot path
pub const LossDetector = struct {
    allocator: std.mem.Allocator,

    /// Sent packets awaiting acknowledgment (keyed by packet number)
    sent_packets: std.AutoHashMap(u64, SentPacket),

    /// Largest acknowledged packet number
    largest_acked_packet: ?u64,

    /// Time of the most recent ack-eliciting packet sent
    time_of_last_ack_eliciting_packet: i64,

    /// Loss detection timer
    loss_time: ?i64,

    /// Number of times PTO has been triggered without receiving an ack
    pto_count: u32,

    /// RTT measurements
    latest_rtt: u64,
    min_rtt: u64,
    smoothed_rtt: u64,
    rttvar: u64,

    /// Fixed-size ring buffer for lost packet numbers (avoids allocation)
    lost_packets_ring: [MAX_LOST_PACKETS]u64,
    lost_count: u32,

    /// Cached timestamp to avoid syscalls
    cached_time: i64,

    /// Constants (RFC 9002) - using fixed-point arithmetic
    pub const kPacketThreshold: u32 = 3;
    /// Time threshold as fixed-point: 9/8 = 1.125 = 1125/1000
    pub const kTimeThresholdNum: u64 = 9;
    pub const kTimeThresholdDen: u64 = 8;
    pub const kGranularity: u64 = 1_000_000; // 1ms in nanoseconds
    pub const kInitialRtt: u64 = 333_000_000; // 333ms in nanoseconds

    /// Maximum lost packets tracked per ACK (ring buffer size)
    pub const MAX_LOST_PACKETS = 256;

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .sent_packets = std.AutoHashMap(u64, SentPacket).init(allocator),
            .largest_acked_packet = null,
            .time_of_last_ack_eliciting_packet = 0,
            .loss_time = null,
            .pto_count = 0,
            .latest_rtt = 0,
            .min_rtt = std.math.maxInt(u64),
            .smoothed_rtt = 333_000_000, // Initial 333ms
            .rttvar = 166_000_000, // Initial 166ms
            .lost_packets_ring = undefined,
            .lost_count = 0,
            .cached_time = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        // No frame cleanup needed - SentPacket uses fixed array
        self.sent_packets.deinit();
    }

    /// Called when a packet is sent
    pub fn onPacketSent(
        self: *Self,
        packet_number: u64,
        ack_eliciting: bool,
        in_flight: bool,
        size: u32,
        encryption_level: SentPacket.EncryptionLevel,
    ) !void {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        self.cached_time = now;

        const sent_pkt = SentPacket{
            .packet_number = packet_number,
            .time_sent = now,
            .ack_eliciting = ack_eliciting,
            .in_flight = in_flight,
            .size = size,
            .encryption_level = encryption_level,
            .frames = undefined,
            .frame_count = 0,
        };

        try self.sent_packets.put(packet_number, sent_pkt);

        if (ack_eliciting) {
            self.time_of_last_ack_eliciting_packet = now;
        }
    }

    pub const AckResult = struct {
        lost_packets: []const u64,
        pmtud_probe_acked: bool,
    };

    /// Called when an ACK frame is received
    /// Returns AckResult with lost packets and probe status
    pub fn onAckReceived(
        self: *Self,
        largest_acked: u64,
        ack_delay: u64,
        ack_ranges: []const AckRange,
        congestion: *CongestionController,
    ) AckResult {
        var pmtud_probe_acked = false;
        // Reset lost packet count
        self.lost_count = 0;

        // Update largest acked
        if (self.largest_acked_packet == null or largest_acked > self.largest_acked_packet.?) {
            self.largest_acked_packet = largest_acked;
        }

        // Get current time once (avoid multiple syscalls)
        const now: i64 = @intCast(std.time.nanoTimestamp());
        self.cached_time = now;

        // Process newly acknowledged packets
        var newly_acked_bytes: u64 = 0;
        for (ack_ranges) |range| {
            var pn = range.start;
            while (pn <= range.end) : (pn += 1) {
                if (self.sent_packets.fetchRemove(pn)) |kv| {
                    const sent_pkt = kv.value;

                    // Update RTT (only for largest acked to get accurate sample)
                    if (pn == largest_acked) {
                        const rtt_sample = @as(u64, @intCast(now - sent_pkt.time_sent));
                        self.updateRtt(rtt_sample, ack_delay);
                    }

                    if (sent_pkt.in_flight) {
                        newly_acked_bytes += sent_pkt.size;
                    }
                    if (sent_pkt.is_pmtud_probe) {
                        pmtud_probe_acked = true;
                    }
                    // No frames.deinit() needed - fixed array
                }
            }
        }

        // Update congestion controller
        if (newly_acked_bytes > 0) {
            congestion.onPacketsAcked(newly_acked_bytes);
        }

        // Detect lost packets using fixed-point arithmetic (no floats!)
        // loss_delay = max(latest_rtt * 9/8, kGranularity)
        const loss_delay = @max(
            (self.latest_rtt * kTimeThresholdNum) / kTimeThresholdDen,
            kGranularity,
        );

        const loss_time = now - @as(i64, @intCast(loss_delay));

        var iter = self.sent_packets.iterator();
        while (iter.next()) |entry| {
            const pkt = entry.value_ptr.*;

            // Packet is lost if:
            // 1. It's older than the packet threshold
            // 2. It's been outstanding longer than the time threshold
            const packet_threshold_exceeded = self.largest_acked_packet != null and
                pkt.packet_number + kPacketThreshold <= self.largest_acked_packet.?;
            const time_threshold_exceeded = pkt.time_sent <= loss_time;

            if (packet_threshold_exceeded or time_threshold_exceeded) {
                if (self.lost_count < MAX_LOST_PACKETS) {
                    self.lost_packets_ring[self.lost_count] = pkt.packet_number;
                    self.lost_count += 1;
                }
            }
        }

        // Remove lost packets and update congestion
        for (self.lost_packets_ring[0..self.lost_count]) |pn| {
            if (self.sent_packets.fetchRemove(pn)) |kv| {
                const sent_pkt = kv.value;
                if (sent_pkt.in_flight) {
                    congestion.onPacketLost(sent_pkt.size);
                }
            }
        }

        self.pto_count = 0;

        return .{
            .lost_packets = self.lost_packets_ring[0..self.lost_count],
            .pmtud_probe_acked = pmtud_probe_acked,
        };
    }

    /// Update RTT estimates (RFC 9002 Section 5) - all integer arithmetic
    fn updateRtt(self: *Self, rtt_sample: u64, ack_delay: u64) void {
        self.latest_rtt = rtt_sample;

        if (rtt_sample < self.min_rtt) {
            self.min_rtt = rtt_sample;
        }

        // Adjust for ack delay
        var adjusted_rtt = rtt_sample;
        if (rtt_sample >= self.min_rtt + ack_delay) {
            adjusted_rtt = rtt_sample - ack_delay;
        }

        if (self.smoothed_rtt == kInitialRtt) {
            // First RTT sample
            self.smoothed_rtt = adjusted_rtt;
            self.rttvar = adjusted_rtt >> 1; // Divide by 2
        } else {
            // Subsequent samples (EWMA) - all integer arithmetic
            // rttvar = 3/4 * rttvar + 1/4 * |srtt - rtt|
            // srtt = 7/8 * srtt + 1/8 * rtt
            const rtt_diff = if (self.smoothed_rtt > adjusted_rtt)
                self.smoothed_rtt - adjusted_rtt
            else
                adjusted_rtt - self.smoothed_rtt;

            self.rttvar = (3 * self.rttvar + rtt_diff) >> 2; // Divide by 4
            self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted_rtt) >> 3; // Divide by 8
        }
    }

    /// Get the Probe Timeout (PTO) - using bit shifts instead of pow
    pub fn getPto(self: *const Self) u64 {
        // PTO = smoothed_rtt + max(4*rttvar, kGranularity)
        var pto = self.smoothed_rtt + @max(self.rttvar << 2, kGranularity);
        // Multiply by 2^pto_count using shift
        pto = pto << @min(self.pto_count, 10); // Cap at 2^10 to prevent overflow
        return pto;
    }

    /// Called when PTO timer fires
    pub fn onPtoTimeout(self: *Self) void {
        self.pto_count += 1;
    }

    /// Get cached timestamp (use instead of syscall when precision isn't critical)
    pub fn getCachedTime(self: *const Self) i64 {
        return self.cached_time;
    }
};

/// ACK range for loss detection
pub const AckRange = struct {
    start: u64,
    end: u64,
};

/// Congestion controller (NewReno-style, RFC 9002)
/// Optimized: All fixed-point arithmetic, no floating point operations
pub const CongestionController = struct {
    /// Congestion window in bytes
    cwnd: u64,

    /// Slow start threshold
    ssthresh: u64,

    /// Bytes currently in flight
    bytes_in_flight: u64,

    /// Recovery state
    recovery_start_time: ?i64,

    /// Congestion event occurred
    congestion_recovery_start_time: ?i64,

    /// ECN-CE counter for this path
    ecn_ce_counters: u64,

    /// Cached timestamp to avoid syscalls
    cached_time: i64,

    /// Constants - all compile-time known, no floats
    pub const kInitialWindow: u64 = 14720; // ~10 packets
    pub const kMinimumWindow: u64 = 2 * 1200; // 2 full-size packets
    pub const kMaxSegmentSize: u64 = 1200; // QUIC max payload
    pub const kPersistentCongestionThreshold: u32 = 3;

    const Self = @This();

    pub fn init() Self {
        return .{
            .cwnd = kInitialWindow,
            .ssthresh = std.math.maxInt(u64),
            .bytes_in_flight = 0,
            .recovery_start_time = null,
            .congestion_recovery_start_time = null,
            .ecn_ce_counters = 0,
            .cached_time = 0,
        };
    }

    /// Check if we can send more data (inline for hot path)
    pub inline fn canSend(self: *const Self, bytes: u64) bool {
        return self.bytes_in_flight + bytes <= self.cwnd;
    }

    /// Get available window space
    pub inline fn availableWindow(self: *const Self) u64 {
        return if (self.cwnd > self.bytes_in_flight)
            self.cwnd - self.bytes_in_flight
        else
            0;
    }

    /// Called when a packet is sent
    pub inline fn onPacketSent(self: *Self, bytes: u64) void {
        self.bytes_in_flight +|= bytes; // Saturating add
    }

    /// Called when packets are acknowledged
    pub fn onPacketsAcked(self: *Self, bytes_acked: u64) void {
        // Saturating subtraction
        self.bytes_in_flight = if (self.bytes_in_flight > bytes_acked)
            self.bytes_in_flight - bytes_acked
        else
            0;

        // Don't increase cwnd during recovery
        if (self.congestion_recovery_start_time != null) {
            return;
        }

        if (self.cwnd < self.ssthresh) {
            // Slow start: cwnd += bytes_acked (additive increase)
            self.cwnd +|= bytes_acked; // Saturating add
        } else {
            // Congestion avoidance: cwnd += MSS * bytes_acked / cwnd
            // This approximates cwnd += MSS per RTT
            const increment = @max(1, (kMaxSegmentSize * bytes_acked) / self.cwnd);
            self.cwnd +|= increment;
        }
    }

    /// Called when a packet is lost
    /// Uses bit shift instead of float multiplication (cwnd * 0.5 = cwnd >> 1)
    pub fn onPacketLost(self: *Self, bytes_lost: u32) void {
        // Saturating subtraction
        self.bytes_in_flight = if (self.bytes_in_flight > bytes_lost)
            self.bytes_in_flight - bytes_lost
        else
            0;

        const now: i64 = @intCast(std.time.nanoTimestamp());
        self.cached_time = now;

        // Enter recovery if not already in recovery
        if (self.congestion_recovery_start_time == null or
            now > self.congestion_recovery_start_time.?)
        {
            self.congestion_recovery_start_time = now;

            // Reduce cwnd by half using bit shift (equivalent to * 0.5)
            // cwnd = max(cwnd >> 1, kMinimumWindow)
            self.cwnd = @max(self.cwnd >> 1, kMinimumWindow);
            self.ssthresh = self.cwnd;
        }
    }

    /// Called on ECN-CE (Congestion Experienced)
    /// Uses same fixed-point reduction as packet loss
    pub fn onEcnCe(self: *Self) void {
        self.ecn_ce_counters += 1;

        const now: i64 = @intCast(std.time.nanoTimestamp());
        self.cached_time = now;

        if (self.congestion_recovery_start_time == null or
            now > self.congestion_recovery_start_time.?)
        {
            self.congestion_recovery_start_time = now;
            // Reduce cwnd by half using bit shift
            self.cwnd = @max(self.cwnd >> 1, kMinimumWindow);
            self.ssthresh = self.cwnd;
        }
    }

    /// Reset after persistent congestion
    pub fn onPersistentCongestion(self: *Self) void {
        self.cwnd = kMinimumWindow;
        self.congestion_recovery_start_time = null;
    }

    /// Exit recovery mode (called after recovery period ends)
    pub fn exitRecovery(self: *Self) void {
        self.congestion_recovery_start_time = null;
    }

    /// Get current statistics
    pub fn getStats(self: *const Self) CongestionStats {
        return .{
            .cwnd = self.cwnd,
            .ssthresh = self.ssthresh,
            .bytes_in_flight = self.bytes_in_flight,
            .in_recovery = self.congestion_recovery_start_time != null,
            .available_window = self.availableWindow(),
        };
    }

    pub const CongestionStats = struct {
        cwnd: u64,
        ssthresh: u64,
        bytes_in_flight: u64,
        in_recovery: bool,
        available_window: u64,
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// 0-RTT EARLY DATA SUPPORT
// ═══════════════════════════════════════════════════════════════════════════════

/// Session ticket for 0-RTT resumption
pub const SessionTicket = struct {
    /// Ticket data (encrypted by server)
    ticket: [256]u8,
    ticket_len: u16,

    /// Ticket lifetime in seconds
    lifetime: u32,

    /// Ticket age add (for obfuscation)
    age_add: u32,

    /// Resumption secret
    resumption_secret: [32]u8,

    /// Maximum early data size
    max_early_data_size: u32,

    /// Creation time
    created_at: i64,

    /// Server name (SNI)
    server_name: [256]u8,
    server_name_len: u8,

    /// ALPN protocol
    alpn: [32]u8,
    alpn_len: u8,

    pub fn isValid(self: *const SessionTicket) bool {
        const now = std.time.timestamp();
        const age = now - self.created_at;
        return age >= 0 and @as(u64, @intCast(age)) < self.lifetime;
    }

    pub fn getObfuscatedAge(self: *const SessionTicket) u32 {
        const now = std.time.timestamp();
        const age_ms: u32 = @intCast(@as(u64, @intCast(now - self.created_at)) * 1000);
        return age_ms +% self.age_add;
    }
};

/// 0-RTT state management
pub const ZeroRttState = struct {
    allocator: std.mem.Allocator,

    /// Cached session tickets by server name
    tickets: std.StringHashMap(SessionTicket),

    /// Early data buffer (data sent before handshake completes)
    early_data_buffer: std.ArrayList(u8),

    /// Whether 0-RTT was accepted
    accepted: bool,

    /// Whether we're currently in 0-RTT mode
    in_zero_rtt: bool,

    /// Early data secret
    early_secret: ?[32]u8,

    /// Early data AEAD context
    early_aead: ?tls13.AeadContext,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .tickets = std.StringHashMap(SessionTicket).init(allocator),
            .early_data_buffer = .empty,
            .accepted = false,
            .in_zero_rtt = false,
            .early_secret = null,
            .early_aead = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.tickets.deinit();
        self.early_data_buffer.deinit(self.allocator);
    }

    /// Store a session ticket
    pub fn storeTicket(self: *Self, server_name: []const u8, ticket: SessionTicket) !void {
        try self.tickets.put(server_name, ticket);
    }

    /// Get a valid ticket for a server
    pub fn getTicket(self: *Self, server_name: []const u8) ?*SessionTicket {
        if (self.tickets.getPtr(server_name)) |ticket| {
            if (ticket.isValid()) {
                return ticket;
            } else {
                // Remove expired ticket
                _ = self.tickets.remove(server_name);
            }
        }
        return null;
    }

    /// Prepare for 0-RTT
    pub fn prepareEarlyData(self: *Self, ticket: *const SessionTicket) !void {
        // Derive early traffic secret from resumption secret
        var early_secret: [32]u8 = undefined;
        tls13.hkdfExpandLabel(&ticket.resumption_secret, "c e traffic", "", 32, &early_secret);

        self.early_secret = early_secret;

        // Create AEAD context for early data
        const secrets = tls13.Secrets.derive(&early_secret);
        self.early_aead = tls13.AeadContext.init(secrets, .TLS_AES_128_GCM_SHA256);

        self.in_zero_rtt = true;
    }

    /// Queue early data
    pub fn queueEarlyData(self: *Self, data: []const u8) !void {
        if (!self.in_zero_rtt) return error.NotInZeroRtt;
        try self.early_data_buffer.appendSlice(self.allocator, data);
    }

    /// Called when server accepts 0-RTT
    pub fn onAccepted(self: *Self) void {
        self.accepted = true;
        self.in_zero_rtt = false;
    }

    /// Called when server rejects 0-RTT
    pub fn onRejected(self: *Self) void {
        self.accepted = false;
        self.in_zero_rtt = false;
        self.early_data_buffer.clearRetainingCapacity();
        self.early_secret = null;
        self.early_aead = null;
    }

    /// Get buffered early data for retransmission
    pub fn getBufferedData(self: *const Self) []const u8 {
        return self.early_data_buffer.items;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// CONNECTION MIGRATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Path state for connection migration
pub const PathState = struct {
    /// Remote address for this path
    peer_addr: packet.SocketAddr,

    /// Local address for this path
    local_addr: packet.SocketAddr,

    /// Path validation state
    validation_state: ValidationState,

    /// Challenge data sent (8 bytes)
    challenge_data: [8]u8,

    /// Time challenge was sent
    challenge_sent_time: i64,

    /// Number of challenges sent
    challenges_sent: u32,

    /// Path MTU
    mtu: u16,

    /// ECN capability validated
    ecn_validated: bool,

    /// Is this the active path?
    active: bool,

    /// Path-specific RTT
    rtt: u64,

    /// Path-specific congestion controller
    congestion: CongestionController,

    pub const ValidationState = enum {
        unknown,
        validating,
        validated,
        failed,
    };

    pub fn init(peer_addr: packet.SocketAddr, local_addr: packet.SocketAddr) PathState {
        return .{
            .peer_addr = peer_addr,
            .local_addr = local_addr,
            .validation_state = .unknown,
            .challenge_data = undefined,
            .challenge_sent_time = 0,
            .challenges_sent = 0,
            .mtu = 1200, // Minimum QUIC MTU
            .ecn_validated = false,
            .active = false,
            .rtt = 333_000_000, // 333ms initial
            .congestion = CongestionController.init(),
        };
    }

    /// Start path validation
    pub fn startValidation(self: *PathState) void {
        std.crypto.random.bytes(&self.challenge_data);
        self.validation_state = .validating;
        self.challenge_sent_time = std.time.nanoTimestamp();
        self.challenges_sent += 1;
    }

    /// Check if path challenge response is valid
    pub fn validateResponse(self: *PathState, response: [8]u8) bool {
        if (std.mem.eql(u8, &self.challenge_data, &response)) {
            self.validation_state = .validated;

            // Update RTT based on challenge/response
            const now: i64 = @intCast(std.time.nanoTimestamp());
            self.rtt = @intCast(now - self.challenge_sent_time);

            return true;
        }
        return false;
    }

    /// Check if validation timed out
    pub fn isValidationTimedOut(self: *const PathState, timeout_ns: u64) bool {
        if (self.validation_state != .validating) return false;

        const now: i64 = @intCast(std.time.nanoTimestamp());
        return @as(u64, @intCast(now - self.challenge_sent_time)) > timeout_ns;
    }
};

/// Connection migration manager
pub const MigrationManager = struct {
    allocator: std.mem.Allocator,

    /// All known paths
    paths: std.ArrayList(PathState),

    /// Active path index
    active_path_index: usize,

    /// Available connection IDs
    available_cids: std.ArrayList(ConnectionId),

    /// Retired connection IDs
    retired_cids: std.ArrayList(ConnectionId),

    /// Sequence number for next CID
    next_cid_sequence: u64,

    /// Whether migration is disabled
    migration_disabled: bool,

    /// Maximum paths to probe simultaneously
    max_paths: usize,

    /// Path validation timeout (3x PTO)
    validation_timeout_ns: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, initial_path: PathState) !Self {
        var manager = Self{
            .allocator = allocator,
            .paths = .empty,
            .active_path_index = 0,
            .available_cids = .empty,
            .retired_cids = .empty,
            .next_cid_sequence = 0,
            .migration_disabled = false,
            .max_paths = 4,
            .validation_timeout_ns = 3 * 333_000_000, // 3x initial RTT
        };

        var path = initial_path;
        path.active = true;
        path.validation_state = .validated; // Initial path is assumed valid
        try manager.paths.append(allocator, path);

        return manager;
    }

    pub fn deinit(self: *Self) void {
        self.paths.deinit(self.allocator);
        self.available_cids.deinit(self.allocator);
        self.retired_cids.deinit(self.allocator);
    }

    /// Get the active path
    pub fn getActivePath(self: *Self) *PathState {
        return &self.paths.items[self.active_path_index];
    }

    /// Called when a packet is received from a different address
    pub fn onPacketFromNewAddress(self: *Self, peer_addr: packet.SocketAddr, local_addr: packet.SocketAddr) !?*PathState {
        if (self.migration_disabled) return null;

        // Check if we already know this path
        for (self.paths.items, 0..) |*path, i| {
            if (std.meta.eql(path.peer_addr, peer_addr)) {
                // Existing path, might be address rebinding
                if (path.validation_state == .validated) {
                    // Switch to this path if it's validated
                    self.paths.items[self.active_path_index].active = false;
                    path.active = true;
                    self.active_path_index = i;
                }
                return path;
            }
        }

        // New path - need to validate
        if (self.paths.items.len >= self.max_paths) {
            // Remove oldest non-active path
            for (self.paths.items, 0..) |*path, i| {
                if (!path.active) {
                    _ = self.paths.orderedRemove(i);
                    if (self.active_path_index > i) {
                        self.active_path_index -= 1;
                    }
                    break;
                }
            }
        }

        var new_path = PathState.init(peer_addr, local_addr);
        new_path.startValidation();
        try self.paths.append(self.allocator, new_path);

        return &self.paths.items[self.paths.items.len - 1];
    }

    /// Initiate migration to a new path
    pub fn initiateMigration(self: *Self, new_peer_addr: packet.SocketAddr, local_addr: packet.SocketAddr) !*PathState {
        if (self.migration_disabled) return error.MigrationDisabled;

        var new_path = PathState.init(new_peer_addr, local_addr);
        new_path.startValidation();
        try self.paths.append(self.allocator, new_path);

        return &self.paths.items[self.paths.items.len - 1];
    }

    /// Process PATH_RESPONSE frame
    pub fn onPathResponse(self: *Self, response_data: [8]u8) void {
        for (self.paths.items) |*path| {
            if (path.validation_state == .validating) {
                if (path.validateResponse(response_data)) {
                    // Optionally switch to this path if it's better
                    break;
                }
            }
        }
    }

    /// Build PATH_CHALLENGE frame for a path
    pub fn buildPathChallenge(self: *Self, path_index: usize) ?[8]u8 {
        if (path_index >= self.paths.items.len) return null;

        var path = &self.paths.items[path_index];
        if (path.validation_state != .validating) {
            path.startValidation();
        }

        return path.challenge_data;
    }

    /// Add a new connection ID
    pub fn addConnectionId(self: *Self, cid: ConnectionId) !void {
        try self.available_cids.append(self.allocator, cid);
    }

    /// Get a fresh connection ID for migration
    pub fn getConnectionIdForMigration(self: *Self) ?ConnectionId {
        if (self.available_cids.items.len > 0) {
            return self.available_cids.pop();
        }
        return null;
    }

    /// Retire a connection ID
    pub fn retireConnectionId(self: *Self, cid: ConnectionId) !void {
        try self.retired_cids.append(cid);
    }

    /// Check for path validation timeouts
    pub fn checkTimeouts(self: *Self) void {
        for (self.paths.items) |*path| {
            if (path.isValidationTimedOut(self.validation_timeout_ns)) {
                if (path.challenges_sent < 3) {
                    // Retry validation
                    path.startValidation();
                } else {
                    // Give up on this path
                    path.validation_state = .failed;
                }
            }
        }
    }

    /// Get statistics
    pub fn getStats(self: *const Self) MigrationStats {
        var validated_paths: usize = 0;
        for (self.paths.items) |path| {
            if (path.validation_state == .validated) {
                validated_paths += 1;
            }
        }

        return .{
            .total_paths = self.paths.items.len,
            .validated_paths = validated_paths,
            .active_path_index = self.active_path_index,
            .available_cids = self.available_cids.items.len,
        };
    }

    pub const MigrationStats = struct {
        total_paths: usize,
        validated_paths: usize,
        active_path_index: usize,
        available_cids: usize,
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// SERVER-SIDE HANDSHAKE STATE MACHINE
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a minimal self-signed certificate blob carrying the server's Ed25519 public key.
/// This is NOT a parseable X.509 chain — under QUIC allow_insecure the client only transcribes
/// the Certificate message (processCertificate just updateTranscript) and never validates it, so
/// a compact deterministic blob is sufficient and correct for loopback. The 32-byte public key is
/// embedded so the bytes are tied to this connection's key (genuine, not a constant placeholder).
fn minimalSelfSignedCert(public_key: [32]u8) [40]u8 {
    var cert: [40]u8 = undefined;
    // Tiny pseudo-DER prefix (SEQUENCE tag + length) + raw Ed25519 SubjectPublicKey. Never parsed.
    cert[0] = 0x30; // ASN.1 SEQUENCE
    cert[1] = 0x26; // length = 38
    cert[2] = 0x03; // BIT STRING
    cert[3] = 0x21; // length = 33
    cert[4] = 0x00; // unused bits
    @memcpy(cert[5..][0..32], &public_key);
    cert[37] = 0x00;
    cert[38] = 0x00;
    cert[39] = 0x00;
    return cert;
}

/// Server handshake state machine
pub const ServerHandshake = struct {
    allocator: std.mem.Allocator,

    /// Current handshake state
    state: State,

    /// TLS state
    tls: *TlsState,

    /// Client's initial destination CID (for initial secret derivation)
    original_dcid: ConnectionId,

    /// Server's TLS certificate (DER encoded)
    certificate: []const u8,

    /// Server's private key (for signing)
    private_key: [32]u8,

    /// Received ClientHello data
    client_hello: ?[]u8,

    /// Generated ServerHello
    server_hello: ?[]u8,

    /// Encrypted Extensions
    encrypted_extensions: ?[]u8,

    /// Certificate message
    certificate_msg: ?[]u8,

    /// CertificateVerify message
    certificate_verify: ?[]u8,

    /// Server Finished
    server_finished: ?[]u8,

    /// Client Finished received
    client_finished_received: bool,

    /// Early data accepted
    early_data_accepted: bool,

    /// ALPN protocol selected
    selected_alpn: ?[]const u8,

    /// Transport parameters to send
    transport_params: tls13.TransportParameters,

    pub const State = enum {
        awaiting_client_hello,
        processing_client_hello,
        sending_server_hello,
        sending_encrypted_extensions,
        sending_certificate,
        sending_certificate_verify,
        sending_finished,
        awaiting_client_finished,
        complete,
        failed,
    };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        tls: *TlsState,
        certificate: []const u8,
        private_key: [32]u8,
    ) Self {
        return .{
            .allocator = allocator,
            .state = .awaiting_client_hello,
            .tls = tls,
            .original_dcid = ConnectionId{ .data = undefined, .len = 0 },
            .certificate = certificate,
            .private_key = private_key,
            .client_hello = null,
            .server_hello = null,
            .encrypted_extensions = null,
            .certificate_msg = null,
            .certificate_verify = null,
            .server_finished = null,
            .client_finished_received = false,
            .early_data_accepted = false,
            .selected_alpn = null,
            .transport_params = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.client_hello) |ch| self.allocator.free(ch);
        if (self.server_hello) |sh| self.allocator.free(sh);
        if (self.encrypted_extensions) |ee| self.allocator.free(ee);
        if (self.certificate_msg) |cert| self.allocator.free(cert);
        if (self.certificate_verify) |cv| self.allocator.free(cv);
        if (self.server_finished) |sf| self.allocator.free(sf);
    }

    /// Process incoming ClientHello
    pub fn processClientHello(self: *Self, data: []const u8, original_dcid: ConnectionId) !void {
        if (self.state != .awaiting_client_hello) return error.InvalidState;

        self.original_dcid = original_dcid;

        // Store ClientHello for transcript
        self.client_hello = try self.allocator.dupe(u8, data);

        // Update TLS transcript
        self.tls.key_schedule.updateTranscript(data);

        // Derive initial secrets from original DCID
        self.tls.deriveInitialSecrets(original_dcid.slice());

        self.state = .processing_client_hello;

        // Parse ClientHello to extract the peer's X25519 key_share (the original stub skipped
        // this, leaving remote_public_key null so generateServerHello never derived the ECDHE
        // shared secret). Mirror of the client's processServerHello key_share copy.
        const ks = try tls13.parseClientHelloKeyShare(data);
        self.tls.remote_public_key = ks[0..32].*;

        self.state = .sending_server_hello;
    }

    /// Generate ServerHello
    pub fn generateServerHello(self: *Self) ![]u8 {
        if (self.state != .sending_server_hello) return error.InvalidState;

        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);

        // Handshake header
        try msg.append(self.allocator, @intFromEnum(tls13.HandshakeType.server_hello));
        try msg.appendNTimes(self.allocator, 0, 3); // Length placeholder

        // Server version (TLS 1.2 for compatibility)
        try msg.appendSlice(self.allocator, &[_]u8{ 0x03, 0x03 });

        // Server random
        var server_random: [32]u8 = undefined;
        std.crypto.random.bytes(&server_random);
        try msg.appendSlice(self.allocator, &server_random);

        // Session ID (echo client's)
        try msg.append(self.allocator, 0); // Empty session ID for QUIC

        // Cipher suite
        try msg.append(self.allocator, 0x13);
        try msg.append(self.allocator, 0x01); // TLS_AES_128_GCM_SHA256

        // Compression method
        try msg.append(self.allocator, 0);

        // Extensions length placeholder
        const ext_len_pos = msg.items.len;
        try msg.appendNTimes(self.allocator, 0, 2);

        // Extension: supported_versions (TLS 1.3)
        try msg.appendSlice(self.allocator, &[_]u8{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 });

        // Extension: key_share
        try msg.appendSlice(self.allocator, &[_]u8{ 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 });
        try msg.appendSlice(self.allocator, &self.tls.local_public_key);

        // Fill extension length
        const ext_len: u16 = @intCast(msg.items.len - ext_len_pos - 2);
        msg.items[ext_len_pos] = @intCast((ext_len >> 8) & 0xFF);
        msg.items[ext_len_pos + 1] = @intCast(ext_len & 0xFF);

        // Fill handshake length
        const body_len: u24 = @intCast(msg.items.len - 4);
        msg.items[1] = @intCast((body_len >> 16) & 0xFF);
        msg.items[2] = @intCast((body_len >> 8) & 0xFF);
        msg.items[3] = @intCast(body_len & 0xFF);

        self.server_hello = try msg.toOwnedSlice(self.allocator);

        // Update transcript
        self.tls.key_schedule.updateTranscript(self.server_hello.?);

        // Compute shared secret and derive handshake keys. The transcript now contains
        // ClientHello+ServerHello (updated above), so deriveHandshakeSecrets produces the
        // SAME c/s hs traffic secrets the client derives in processServerHello.
        if (self.tls.remote_public_key) |remote_pk| {
            const shared = std.crypto.dh.X25519.scalarmult(
                self.tls.local_private_key,
                remote_pk,
            ) catch return error.KeyExchangeFailed;

            self.tls.handshake_secrets = self.tls.key_schedule.deriveHandshakeSecrets(&shared);

            // Persist the RAW 32-byte handshake traffic secrets (the c/s hs traffic secrets,
            // NOT the 16-byte AEAD keys). The Finished MAC keys derive from these via
            // hkdfExpandLabel(secret,"finished",...). Mirror of client processServerHello.
            const transcript = self.tls.key_schedule.getTranscriptHash();
            var client_secret: [32]u8 = undefined;
            var server_secret: [32]u8 = undefined;
            tls13.hkdfExpandLabel(&self.tls.key_schedule.handshake_secret, "c hs traffic", &transcript, 32, &client_secret);
            tls13.hkdfExpandLabel(&self.tls.key_schedule.handshake_secret, "s hs traffic", &transcript, 32, &server_secret);
            self.tls.handshake_traffic_client = client_secret;
            self.tls.handshake_traffic_server = server_secret;

            if (self.tls.handshake_secrets) |secrets| {
                self.tls.client_aead = tls13.AeadContext.init(secrets.client, self.tls.cipher_suite);
                self.tls.server_aead = tls13.AeadContext.init(secrets.server, self.tls.cipher_suite);
                self.tls.client_hp = secrets.client.hp;
                self.tls.server_hp = secrets.server.hp;
            }
        }

        self.state = .sending_encrypted_extensions;

        return self.server_hello.?;
    }

    /// Generate EncryptedExtensions
    pub fn generateEncryptedExtensions(self: *Self) ![]u8 {
        if (self.state != .sending_encrypted_extensions) return error.InvalidState;

        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);

        // Handshake type
        try msg.append(self.allocator, @intFromEnum(tls13.HandshakeType.encrypted_extensions));
        try msg.appendNTimes(self.allocator, 0, 3); // Length placeholder

        // Extensions length placeholder
        const ext_len_pos = msg.items.len;
        try msg.appendNTimes(self.allocator, 0, 2);

        // ALPN extension
        if (self.selected_alpn) |alpn| {
            try msg.append(self.allocator, 0x00);
            try msg.append(self.allocator, 0x10); // ALPN extension type
            const alpn_ext_len: u16 = @intCast(3 + alpn.len);
            try msg.append(self.allocator, @intCast((alpn_ext_len >> 8) & 0xFF));
            try msg.append(self.allocator, @intCast(alpn_ext_len & 0xFF));
            try msg.append(self.allocator, @intCast((alpn.len + 1) >> 8));
            try msg.append(self.allocator, @intCast((alpn.len + 1) & 0xFF));
            try msg.append(self.allocator, @intCast(alpn.len));
            try msg.appendSlice(self.allocator, alpn);
        }

        // QUIC transport parameters
        const params = try self.transport_params.encode(self.allocator);
        defer self.allocator.free(params);

        try msg.append(self.allocator, 0x00);
        try msg.append(self.allocator, 0x39); // QUIC transport parameters (57)
        try msg.append(self.allocator, @intCast((params.len >> 8) & 0xFF));
        try msg.append(self.allocator, @intCast(params.len & 0xFF));
        try msg.appendSlice(self.allocator, params);

        // Early data indication (if accepted)
        if (self.early_data_accepted) {
            try msg.appendSlice(self.allocator, &[_]u8{ 0x00, 0x2a, 0x00, 0x00 }); // early_data extension
        }

        // Fill extension length
        const ext_len: u16 = @intCast(msg.items.len - ext_len_pos - 2);
        msg.items[ext_len_pos] = @intCast((ext_len >> 8) & 0xFF);
        msg.items[ext_len_pos + 1] = @intCast(ext_len & 0xFF);

        // Fill handshake length
        const body_len: u24 = @intCast(msg.items.len - 4);
        msg.items[1] = @intCast((body_len >> 16) & 0xFF);
        msg.items[2] = @intCast((body_len >> 8) & 0xFF);
        msg.items[3] = @intCast(body_len & 0xFF);

        self.encrypted_extensions = try msg.toOwnedSlice(self.allocator);
        self.tls.key_schedule.updateTranscript(self.encrypted_extensions.?);

        self.state = .sending_certificate;

        return self.encrypted_extensions.?;
    }

    /// Generate Certificate message
    pub fn generateCertificate(self: *Self) ![]u8 {
        if (self.state != .sending_certificate) return error.InvalidState;

        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);

        // Handshake type
        try msg.append(self.allocator, @intFromEnum(tls13.HandshakeType.certificate));
        try msg.appendNTimes(self.allocator, 0, 3); // Length placeholder

        // Certificate request context (empty for server)
        try msg.append(self.allocator, 0);

        // Certificate list length placeholder
        const cert_list_len_pos = msg.items.len;
        try msg.appendNTimes(self.allocator, 0, 3);

        // Certificate entry
        // Certificate data length
        try msg.append(self.allocator, @intCast((self.certificate.len >> 16) & 0xFF));
        try msg.append(self.allocator, @intCast((self.certificate.len >> 8) & 0xFF));
        try msg.append(self.allocator, @intCast(self.certificate.len & 0xFF));

        // Certificate data
        try msg.appendSlice(self.allocator, self.certificate);

        // Extensions (empty)
        try msg.append(self.allocator, 0);
        try msg.append(self.allocator, 0);

        // Fill certificate list length
        const cert_list_len: u24 = @intCast(msg.items.len - cert_list_len_pos - 3);
        msg.items[cert_list_len_pos] = @intCast((cert_list_len >> 16) & 0xFF);
        msg.items[cert_list_len_pos + 1] = @intCast((cert_list_len >> 8) & 0xFF);
        msg.items[cert_list_len_pos + 2] = @intCast(cert_list_len & 0xFF);

        // Fill handshake length
        const body_len: u24 = @intCast(msg.items.len - 4);
        msg.items[1] = @intCast((body_len >> 16) & 0xFF);
        msg.items[2] = @intCast((body_len >> 8) & 0xFF);
        msg.items[3] = @intCast(body_len & 0xFF);

        self.certificate_msg = try msg.toOwnedSlice(self.allocator);
        self.tls.key_schedule.updateTranscript(self.certificate_msg.?);

        self.state = .sending_certificate_verify;

        return self.certificate_msg.?;
    }

    /// Generate CertificateVerify message
    pub fn generateCertificateVerify(self: *Self) ![]u8 {
        if (self.state != .sending_certificate_verify) return error.InvalidState;

        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);

        // Handshake type
        try msg.append(self.allocator, @intFromEnum(tls13.HandshakeType.certificate_verify));
        try msg.appendNTimes(self.allocator, 0, 3); // Length placeholder

        // Signature algorithm (Ed25519 = 0x0807)
        try msg.append(self.allocator, 0x08);
        try msg.append(self.allocator, 0x07);

        // Build content to sign
        // 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
        var sign_content: [130]u8 = undefined;
        @memset(sign_content[0..64], 0x20); // 64 spaces
        const context = "TLS 1.3, server CertificateVerify";
        @memcpy(sign_content[64..][0..context.len], context);
        sign_content[64 + context.len] = 0x00;
        const transcript = self.tls.key_schedule.getTranscriptHash();
        @memcpy(sign_content[65 + context.len ..][0..32], &transcript);

        // Sign with Ed25519 (0.15.2 API: derive a KeyPair from the 32-byte seed, then sign).
        // Under allow_insecure the client never verifies this signature (processCertificateVerify
        // only transcribes the bytes), but we produce a genuine signature anyway.
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(self.private_key) catch
            return error.SigningFailed;
        const signature = kp.sign(
            sign_content[0 .. 65 + context.len + 32],
            null,
        ) catch return error.SigningFailed;

        // Signature length
        try msg.append(self.allocator, 0);
        try msg.append(self.allocator, 64); // Ed25519 signature is 64 bytes

        // Signature
        try msg.appendSlice(self.allocator, &signature.toBytes());

        // Fill handshake length
        const body_len: u24 = @intCast(msg.items.len - 4);
        msg.items[1] = @intCast((body_len >> 16) & 0xFF);
        msg.items[2] = @intCast((body_len >> 8) & 0xFF);
        msg.items[3] = @intCast(body_len & 0xFF);

        self.certificate_verify = try msg.toOwnedSlice(self.allocator);
        self.tls.key_schedule.updateTranscript(self.certificate_verify.?);

        self.state = .sending_finished;

        return self.certificate_verify.?;
    }

    /// Generate server Finished message
    pub fn generateFinished(self: *Self) ![]u8 {
        if (self.state != .sending_finished) return error.InvalidState;

        // Derive server finished key from the RAW s hs traffic secret (NOT secrets.server.key,
        // which is the 16-byte AEAD key — that was the original bug; the client verifies this
        // MAC using handshake_traffic_server, so both sides must use the same 32-byte secret).
        var finished_key: [32]u8 = undefined;
        const server_traffic = self.tls.handshake_traffic_server orelse return error.NoHandshakeSecrets;
        tls13.hkdfExpandLabel(&server_traffic, "finished", "", 32, &finished_key);

        const transcript = self.tls.key_schedule.getTranscriptHash();
        self.server_finished = try tls13.buildFinished(self.allocator, finished_key, transcript);

        self.tls.key_schedule.updateTranscript(self.server_finished.?);

        // Derive application secrets
        self.tls.application_secrets = self.tls.key_schedule.deriveApplicationSecrets();

        self.state = .awaiting_client_finished;

        return self.server_finished.?;
    }

    /// Process client Finished message
    pub fn processClientFinished(self: *Self, data: []const u8) !void {
        if (self.state != .awaiting_client_finished) return error.InvalidState;

        // Verify client finished using the RAW c hs traffic secret (the client built its MAC
        // from handshake_traffic_client; secrets.client.key is the AEAD key, not the MAC secret).
        var finished_key: [32]u8 = undefined;
        const client_traffic = self.tls.handshake_traffic_client orelse return error.NoHandshakeSecrets;
        tls13.hkdfExpandLabel(&client_traffic, "finished", "", 32, &finished_key);

        const transcript = self.tls.key_schedule.getTranscriptHash();

        if (data.len < 36) return error.InvalidFinished; // 4 byte header + 32 byte verify data

        const verify_data = data[4..36].*;

        if (!tls13.verifyFinished(finished_key, transcript, verify_data)) {
            self.state = .failed;
            return error.FinishedVerificationFailed;
        }

        self.client_finished_received = true;
        self.tls.handshake_complete = true;
        self.state = .complete;
    }

    /// Check if handshake is complete
    pub fn isComplete(self: *const Self) bool {
        return self.state == .complete;
    }

    /// Get current state
    pub fn getState(self: *const Self) State {
        return self.state;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "connection lifecycle" {
    const addr = packet.SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 8443);
    var endpoint = try Endpoint.init(std.testing.allocator, addr, false, .{});
    defer endpoint.deinit();
    var conn = try Connection.init(std.testing.allocator, endpoint, addr, false);
    defer conn.deinit();

    try std.testing.expectEqual(Connection.State.initial, conn.state);
}

test "endpoint management" {
    const addr = packet.SocketAddr.ipv4(.{ 0, 0, 0, 0 }, 8443);
    var endpoint = try Endpoint.init(std.testing.allocator, addr, true, .{});
    defer endpoint.deinit();
    try endpoint.bind();

    const peer = packet.SocketAddr.ipv4(.{ 192, 168, 1, 100 }, 12345);
    const conn = try endpoint.connect(peer);
    _ = conn;

    try std.testing.expectEqual(@as(usize, 1), endpoint.connections.count());
}

// ── acceptConnection retransmit-safety KATs ───────────────────────────────────
// `self.connections` is keyed by the SERVER's own freshly-generated local CID, never by the
// client's chosen DCID, so a client Initial retransmitted before it has seen any server reply
// (real quinn/rustls PTO behavior) always misses that lookup and re-enters acceptConnection.
// Before the fix this unconditionally minted a second Connection object and clobbered
// `connections_by_addr[peer_addr]` — the only index the 1-RTT short-header path consults —
// orphaning the connection the client actually completed its handshake against and silently
// dropping every subsequent stream (including the tx payload).
test "acceptConnection: retransmitted Initial before handshake reuses connection, address map still routes to it" {
    const addr = packet.SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 8443);
    var endpoint = try Endpoint.init(std.testing.allocator, addr, true, .{});
    defer endpoint.deinit();

    const peer = packet.SocketAddr.ipv4(.{ 203, 0, 113, 5 }, 55000);
    const scid = ConnectionId{ .data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 } ++ ([_]u8{0} ** 12), .len = 8 };
    const dcid1 = ConnectionId{ .data = [_]u8{ 10, 10, 10, 10, 10, 10, 10, 10 } ++ ([_]u8{0} ** 12), .len = 8 };

    const conn1 = try endpoint.acceptConnection(peer, scid, dcid1);
    try std.testing.expectEqual(@as(usize, 1), endpoint.connections.count());
    try std.testing.expectEqual(@as(usize, 1), endpoint.connections_by_addr.count());

    const addr_hash = hashSocketAddr(&peer);
    try std.testing.expectEqual(@as(?*Connection, conn1), endpoint.connections_by_addr.get(addr_hash));

    // Client retransmits its Initial before completing the handshake, with a different DCID than
    // its first attempt (some stacks vary it per retransmit; the accept-side bug is identical even
    // when the DCID is unchanged, since `self.connections` never held the client's DCID as a key at
    // all). Must reuse connection A, not mint a second object or clobber the address map.
    const dcid2 = ConnectionId{ .data = [_]u8{ 20, 20, 20, 20, 20, 20, 20, 20 } ++ ([_]u8{0} ** 12), .len = 8 };
    const conn2 = try endpoint.acceptConnection(peer, scid, dcid2);

    try std.testing.expectEqual(conn1, conn2); // same object reused
    try std.testing.expectEqual(@as(usize, 1), endpoint.connections.count()); // no second object minted
    try std.testing.expectEqual(@as(?*Connection, conn1), endpoint.connections_by_addr.get(addr_hash)); // still routes to conn1
    try std.testing.expect(dcid2.eql(&conn1.initial_dcid)); // re-keyed onto the retransmit's DCID
    try std.testing.expect(!conn1.tls.handshake_complete);
}

// Companion KAT: a legitimate reconnect from the same peer address AFTER the prior connection's
// handshake completed must still mint a fresh Connection and re-point the address map — the fix
// must not turn every subsequent Initial from a known address into a permanent reuse.
test "acceptConnection: new Initial from same peer AFTER handshake completion still creates a fresh connection" {
    const addr = packet.SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 8443);
    var endpoint = try Endpoint.init(std.testing.allocator, addr, true, .{});
    defer endpoint.deinit();

    const peer = packet.SocketAddr.ipv4(.{ 203, 0, 113, 9 }, 55001);
    const scid1 = ConnectionId{ .data = [_]u8{ 1, 1, 1, 1, 1, 1, 1, 1 } ++ ([_]u8{0} ** 12), .len = 8 };
    const dcid1 = ConnectionId{ .data = [_]u8{ 2, 2, 2, 2, 2, 2, 2, 2 } ++ ([_]u8{0} ** 12), .len = 8 };

    const conn1 = try endpoint.acceptConnection(peer, scid1, dcid1);
    conn1.tls.handshake_complete = true; // simulate connection A's handshake having completed

    const scid2 = ConnectionId{ .data = [_]u8{ 3, 3, 3, 3, 3, 3, 3, 3 } ++ ([_]u8{0} ** 12), .len = 8 };
    const dcid2 = ConnectionId{ .data = [_]u8{ 4, 4, 4, 4, 4, 4, 4, 4 } ++ ([_]u8{0} ** 12), .len = 8 };
    const conn2 = try endpoint.acceptConnection(peer, scid2, dcid2);

    try std.testing.expect(conn1 != conn2); // genuinely new connection, not reused
    try std.testing.expectEqual(@as(usize, 2), endpoint.connections.count()); // both objects retained (A still completing teardown independently)
    const addr_hash = hashSocketAddr(&peer);
    try std.testing.expectEqual(@as(?*Connection, conn2), endpoint.connections_by_addr.get(addr_hash)); // address map now routes to the new connection
}

// ── MAX_STREAMS_UNI credit / frame-parser KATs (2026-06-21) ──────────────────
// Golden vectors captured byte-exact from live testnet leaders (see
// QUIC-MAX-STREAMS-GOLDEN-VECTORS-2026-06-20.md). Prove that (a) a MAX_STREAMS_UNI
// (0x13) frame grants the real uni-stream vote credit, (b) a real NEW_CONNECTION_ID
// (0x18, the no-length-prefix "nasty one") is skipped byte-exact so a COALESCED
// MAX_STREAMS_UNI after it is NOT stranded (the old `else => break` bug dropped it),
// and (c) openUniStream gates on the credit so we never open an illegal stream that
// the leader would STREAM_LIMIT_ERROR-kill the connection over.

test "MAX_STREAMS_UNI (0x13) grants real uni-stream credit (golden 13 40fe -> 254)" {
    const addr = packet.SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 8443);
    var endpoint = try Endpoint.init(std.testing.allocator, addr, false, .{});
    defer endpoint.deinit();
    var conn = try Connection.init(std.testing.allocator, endpoint, addr, false);
    defer conn.deinit();

    try std.testing.expectEqual(@as(u64, 0), conn.peer_max_streams_uni); // RFC absent-default
    // Real leader frame: type 0x13, varint 0x40fe = 254.
    try endpoint.processFrames(conn, &[_]u8{ 0x13, 0x40, 0xfe });
    try std.testing.expectEqual(@as(u64, 254), conn.peer_max_streams_uni);

    // Monotonic: a larger grant raises it; a smaller one does NOT lower it.
    try endpoint.processFrames(conn, &[_]u8{ 0x13, 0x43, 0xbc }); // 956
    try std.testing.expectEqual(@as(u64, 956), conn.peer_max_streams_uni);
    try endpoint.processFrames(conn, &[_]u8{ 0x13, 0x40, 0xfe }); // 254 (ignored)
    try std.testing.expectEqual(@as(u64, 956), conn.peer_max_streams_uni);
}

test "NEW_CONNECTION_ID (0x18) is skipped byte-exact; coalesced MAX_STREAMS_UNI not stranded" {
    const addr = packet.SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 8443);
    var endpoint = try Endpoint.init(std.testing.allocator, addr, false, .{});
    defer endpoint.deinit();
    var conn = try Connection.init(std.testing.allocator, endpoint, addr, false);
    defer conn.deinit();

    // Real golden NEW_CONNECTION_ID payload: seq=1 retire=0 len=8 CID(8B) token(16B),
    // immediately followed by MAX_STREAMS_UNI(254) and a PADDING byte — exactly the
    // coalescing the old `else => break` dropped.
    const frames = [_]u8{
        0x18, 0x01, 0x00, 0x08, // type, seq, retire_prior_to, cid_len
        0x20, 0x09, 0x5b, 0x4a, 0x5a, 0x45, 0xeb, 0x36, // 8-byte CID
        0x6e, 0x48, 0x48, 0xc6, 0x5e, 0xc2, 0xc2, 0x7d, // 16-byte stateless reset token
        0xdd, 0x3b, 0xb7, 0xc8, 0xa2, 0x04, 0x59, 0x7e,
        0x13, 0x40, 0xfe, // MAX_STREAMS_UNI = 254 (must survive)
        0x00, // PADDING
    };
    try endpoint.processFrames(conn, &frames);
    // If NEW_CONNECTION_ID were mis-skipped, the parser would desync and the credit
    // would stay 0. 254 proves byte-exact skip + no stranding.
    try std.testing.expectEqual(@as(u64, 254), conn.peer_max_streams_uni);
}

test "openUniStream gates on peer credit (0 -> StreamLimitReached; grows with grant)" {
    const addr = packet.SocketAddr.ipv4(.{ 127, 0, 0, 1 }, 8443);
    var endpoint = try Endpoint.init(std.testing.allocator, addr, false, .{});
    defer endpoint.deinit();
    var conn = try Connection.init(std.testing.allocator, endpoint, addr, false);
    defer conn.deinit();

    // Credit 0: cannot open (would be an illegal stream → STREAM_LIMIT_ERROR).
    try std.testing.expectError(error.StreamLimitReached, conn.openUniStream());

    // Grant 2 (stream numbers 0,1 allowed = ids 2,6).
    conn.peer_max_streams_uni = 2;
    const s0 = try conn.openUniStream();
    try std.testing.expectEqual(@as(u64, 2), s0.id);
    const s1 = try conn.openUniStream();
    try std.testing.expectEqual(@as(u64, 6), s1.id);
    // Third exceeds the grant.
    try std.testing.expectError(error.StreamLimitReached, conn.openUniStream());
}

// Decode of the peer's advertised initial stream credit from EncryptedExtensions
// (RFC 9000 §18.2). This is what makes the Vexor→Vexor ingest loopback work: our
// own server encodes initial_max_streams_uni=100 (id 0x09), and the client now
// honors it. A real leader OMITS id 0x09, so the decode yields 0 and the gate
// stays armed (the client must wait for a MAX_STREAMS_UNI frame instead).
test "EncryptedExtensions decode: our server's params grant uni=100/bidi=100" {
    const alloc = std.testing.allocator;
    // Encode our default transport params (initial_max_streams_uni/bidi = 100).
    var tp = tls13.TransportParameters{};
    const params = try tp.encode(alloc);
    defer alloc.free(params);

    // Wrap them in an EncryptedExtensions handshake message:
    //   msg_type(1)=0x08 ‖ length(u24) ‖ ext_block_len(u16)
    //   ‖ ext_type(u16)=57 ‖ ext_len(u16)=params.len ‖ params
    var ee: std.ArrayList(u8) = .empty;
    defer ee.deinit(alloc);
    const ext_block_len: u16 = @intCast(4 + params.len);
    const hs_len: u24 = @intCast(2 + @as(usize, ext_block_len));
    try ee.append(alloc, 0x08);
    try ee.append(alloc, @intCast((hs_len >> 16) & 0xff));
    try ee.append(alloc, @intCast((hs_len >> 8) & 0xff));
    try ee.append(alloc, @intCast(hs_len & 0xff));
    try ee.append(alloc, @intCast((ext_block_len >> 8) & 0xff));
    try ee.append(alloc, @intCast(ext_block_len & 0xff));
    try ee.append(alloc, 0x00); // ext_type 57 (quic_transport_parameters)
    try ee.append(alloc, 0x39);
    try ee.append(alloc, @intCast((params.len >> 8) & 0xff));
    try ee.append(alloc, @intCast(params.len & 0xff));
    try ee.appendSlice(alloc, params);

    const lims = tls13.peerStreamLimitsFromEncryptedExtensions(ee.items);
    try std.testing.expectEqual(@as(u64, 100), lims.uni);
    try std.testing.expectEqual(@as(u64, 100), lims.bidi);
}

test "EncryptedExtensions decode: real leader omits id 0x09 -> uni=0 (gate stays armed)" {
    // Captured live-testnet leader EncryptedExtensions (QUIC-MAX-STREAMS-GOLDEN-
    // VECTORS-2026-06-20.md). Its transport params carry imsd_uni=4096 etc. but
    // NO initial_max_streams_uni (id 0x09) and NO bidi (id 0x08) ⇒ RFC default 0.
    const ee_hex = "0800007e007c0000000010000d000b0a736f6c616e612d747075003900630e01050f083b6d13608070897f06025000d5ab48f2635e653205da5b8a0c0f070250000c006ab2000008df7190c7a4d2f3c804048080000005025000c0000000ff04de1b0243e8030245c00210a03cfdc88f57005e6ba0570756871f61010480007530";
    var ee: [0x82]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&ee, ee_hex);
    const lims = tls13.peerStreamLimitsFromEncryptedExtensions(decoded);
    try std.testing.expectEqual(@as(u64, 0), lims.uni);
    try std.testing.expectEqual(@as(u64, 0), lims.bidi);
}

// DISCRIMINATING KAT (advisor): the real-leader test above asserts uni==0, but 0
// is ALSO the parse-failure return — it cannot tell "correctly walked GREASE and
// found 0x09 absent" from "broke early before reaching 0x09". GREASE params carry
// 8-byte-varint ids (the exact thing that desynced the offline Python parser). This
// proves the param walk SKIPS an 8-byte-id GREASE param and still extracts a
// following 0x09: a non-zero expected value can ONLY come from a correct traversal.
test "EncryptedExtensions decode: 8-byte GREASE id is skipped, trailing 0x09=200 found" {
    // Transport-param body:
    //   GREASE: id = c0 00 00 00 00 00 00 1b (8-byte varint = 27), len = 00, no value
    //   0x09  : id = 09, len = 02, value = 40 c8 (2-byte varint = 200)
    const body = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x09, 0x02, 0x40, 0xc8 };
    // Wrap in EncryptedExtensions: msg_type ‖ u24 len ‖ u16 ext_block ‖ ext57 ‖ u16 len ‖ body
    const ext_block_len: u16 = @intCast(4 + body.len);
    const hs_len: u24 = @intCast(2 + @as(usize, ext_block_len));
    var ee: [64]u8 = undefined;
    var n: usize = 0;
    ee[n] = 0x08;
    n += 1;
    ee[n] = @intCast((hs_len >> 16) & 0xff);
    n += 1;
    ee[n] = @intCast((hs_len >> 8) & 0xff);
    n += 1;
    ee[n] = @intCast(hs_len & 0xff);
    n += 1;
    ee[n] = @intCast((ext_block_len >> 8) & 0xff);
    n += 1;
    ee[n] = @intCast(ext_block_len & 0xff);
    n += 1;
    ee[n] = 0x00; // ext_type 57
    n += 1;
    ee[n] = 0x39;
    n += 1;
    ee[n] = @intCast((body.len >> 8) & 0xff);
    n += 1;
    ee[n] = @intCast(body.len & 0xff);
    n += 1;
    @memcpy(ee[n..][0..body.len], &body);
    n += body.len;

    const lims = tls13.peerStreamLimitsFromEncryptedExtensions(ee[0..n]);
    try std.testing.expectEqual(@as(u64, 200), lims.uni);
}
