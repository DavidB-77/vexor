//! Vexor JSON-RPC Server
//!
//! HTTP JSON-RPC 2.0 server implementing Solana's RPC API.
//! Core methods for wallet/dapp interaction.

const std = @import("std");
const core = @import("core");
const storage = @import("vex_store");
const runtime = @import("vex_svm"); // for the BankingStage type on the sendTransaction handle
// CONSOLIDATION 2026-06-13: this (the live RpcServer transport) now routes through the rich
// rpc_methods dispatch registry (50 methods) instead of the old ~12 if/else stubs. rpc_methods +
// account_encoder + commitment are pulled into the exe graph via this import. The old per-method
// handlers below (handleGet*) are SUPERSEDED and unreferenced — kept only until removed in cleanup.
const rpc_methods = @import("rpc_methods.zig");
const consensus = @import("vex_consensus"); // LeaderScheduleCache for warmup-aware epoch + real slot leaders
const vex_topo = @import("vex_topo"); // Phase-1 topo rework 2026-06-22: pin the RPC listen loop off the hot pipeline
const vex_ledger_mod = @import("vex_ledger"); // VexLedger handle plumbed through to RpcContext (build.zig:288 module edge)

/// RPC Server configuration
pub const RpcConfig = struct {
    /// Bind address
    bind_address: []const u8 = "0.0.0.0",

    /// Port to listen on
    port: u16 = 8899,

    /// Maximum request body size
    max_body_size: usize = 50 * 1024 * 1024, // 50MB

    /// Enable rate limiting
    enable_rate_limiting: bool = true,

    /// Requests per second per IP
    rate_limit_rps: u32 = 100,
};

/// RPC Server
pub const RpcServer = struct {
    allocator: std.mem.Allocator,
    config: RpcConfig,

    /// Reference to storage for queries
    accounts_db: ?*storage.AccountsDb,
    ledger_db: ?*storage.LedgerDb,
    /// Leader schedule cache — set after init in main.zig (mirrors accounts_db pattern). Feeds
    /// the RpcContext so getEpochInfo/getSlotLeaders/getLeaderSchedule report the warmup-aware
    /// epoch + real cluster leaders instead of naive slot/432000 + a placeholder. null → those
    /// methods fall back to the naive values (byte-identical to before this wiring).
    leader_cache: ?*consensus.leader_schedule.LeaderScheduleCache = null,
    /// SB-2 RPC block/transaction-history stores (2026-06-17). Set by main.zig only when the
    /// -Drpc_store/VEX_RPC_STORE gate is on (else null → history reads return Agave-correct empty/null).
    block_store: ?*storage.BlockStore = null,
    tx_status_store: ?*storage.TxStatusStore = null,
    /// VexLedger persistent blockstore handle (2026-06-24). Set by main.zig ONLY under the -Dvex_ledger
    /// build + VEX_LEDGER env gate (null otherwise → the enumeration handlers fall back to prior behavior,
    /// byte-identical to before). buildContext() copies this into the RpcContext.
    /// TODO(LIVE-main.zig): after the `vl` handle is constructed (main.zig ~1197-1204, behind
    ///   `if (comptime build_options.vex_ledger) { if (getenv("VEX_LEDGER")) ... }`), assign
    ///   `rpc_server.vex_ledger = vl;` alongside the existing rpc_server.block_store/leader_cache wiring
    ///   (main.zig:1283-1285). That single assignment is the ONLY main.zig edit this feature needs.
    vex_ledger: ?*vex_ledger_mod.VexLedger = null,
    /// SB-1 sendTransaction: the SAME BankingStage mempool the QUIC TPU ingest seam feeds. Set by
    /// main.zig only when VEX_TPU_INGEST built the mempool (else null → sendTransaction errors).
    banking: ?*runtime.banking_stage.BankingStage = null,
    /// Validator identity (base58) for getIdentity/getClusterNodes/getSlotLeader. Optional — when
    /// null the dispatch handlers fall back to the canonical Vexor identity default.
    identity: ?[]const u8 = null,

    /// Operational (non-consensus) RPC convenience values, config-driven. Set after init in main.zig
    /// (mirrors the `accounts_db`/`identity` field-assignment pattern). Optional with safe defaults so
    /// getClusterNodes/getGenesisHash/buildContext stay byte-identical to the legacy hardcodes when unset.
    public_ip: ?[4]u8 = null,
    gossip_port: u16 = 0,
    tpu_port: u16 = 0,
    rpc_port: u16 = 0,
    genesis_hash: ?[]const u8 = null,
    shred_version: u16 = 0,
    cluster_name: ?[]const u8 = null,
    /// Canonical RPC tier (config.full_rpc_api). Set by main.zig after init. false (default) ⇒ the
    /// dispatcher serves only the 12 Minimal-trait methods; true ⇒ the full API. Keeps the voting
    /// node minimal so heavy RPC never competes with consensus.
    full_rpc_api: bool = false,

    /// Server state
    running: std.atomic.Value(bool),

    /// Statistics
    stats: RpcStats,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, port: u16) !*Self {
        const server = try allocator.create(Self);
        server.* = .{
            .allocator = allocator,
            .config = .{ .port = port },
            .accounts_db = null,
            .ledger_db = null,
            .running = std.atomic.Value(bool).init(false),
            .stats = .{},
        };
        return server;
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.allocator.destroy(self);
    }

    /// Start the RPC server — spawns a background HTTP listener thread
    pub fn start(self: *Self) !void {
        if (self.running.load(.seq_cst)) return;
        self.running.store(true, .seq_cst);

        const thread = std.Thread.spawn(.{}, httpListenLoop, .{self}) catch |err| {
            std.log.debug("[RPC] Failed to spawn listener thread: {any}\n", .{err});
            self.running.store(false, .seq_cst);
            return err;
        };
        thread.detach();
        std.log.debug("[RPC] Server listening on port {d}\n", .{self.config.port});
    }

    fn httpListenLoop(self: *Self) void {
        // Phase-1 topo rework (2026-06-22): pin the RPC HTTP listen loop to its own
        // core (vex_topo.rpc == 27, tail of CCX6, FREE in the static map and inside
        // the widened taskset). This was the ONLY genuinely-unpinned LIVE floater —
        // unpinned it could float onto a consensus core (replay 16 / verify 8-15 /
        // produce 20) and starve it under RPC burst. RPC is diagnostic/bursty
        // (sub-threshold), so co-residency on CCX6's spare core is harmless.
        // NON-CONSENSUS (scheduling only; bank_hash unaffected). VEX_RPC_NO_PIN
        // leaves it unpinned (instant revert to pre-rework behavior).
        if (std.posix.getenv("VEX_RPC_NO_PIN") == null) {
            _ = vex_topo.pinTile(vex_topo.LIVE, .rpc, 0);
        }
        const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, self.config.port);
        var server = addr.listen(.{ .reuse_address = true }) catch |err| {
            std.log.debug("[RPC] Bind failed on port {d}: {any}\n", .{ self.config.port, err });
            return;
        };

        while (self.running.load(.seq_cst)) {
            const conn = server.accept() catch continue;
            // Handle connection in-line (simple single-threaded for now)
            self.handleConnection(conn.stream) catch {};
        }
    }

    /// Hard ceiling on the buffered header block (bytes read while still looking for the
    /// terminating "\r\n\r\n"). Guards a client that never completes its headers. Independent of
    /// `config.max_body_size`, which bounds the JSON-RPC body once a Content-Length header names
    /// one (checked in readFullRequest before any body bytes are buffered).
    const max_header_bytes: usize = 16 * 1024;

    /// Bound on how long a single read() inside readFullRequest may block waiting for more bytes
    /// — including the gap between a header write and a later body write, the same gap this fix
    /// buffers across. readFullRequest's byte ceilings (max_header_bytes / config.max_body_size)
    /// only bound HOW MUCH gets buffered; without this, a client that declares a Content-Length,
    /// sends part of it, then goes silent would block this single-threaded accept loop forever.
    /// PER-READ only, though: it resets on every read() that returns any data at all, so a client
    /// trickling in one byte at a time (each arriving comfortably inside recv_timeout_secs) never
    /// trips it. max_request_read_secs below is what bounds the request as a whole regardless of
    /// how many such reads it takes — see its comment for why that's a separate, necessary bound.
    const recv_timeout_secs: i64 = 10;

    /// Hard ceiling on the TOTAL wall-clock time readFullRequest's read loop may spend on one
    /// request, measured from when that loop starts (immediately after accept — setRecvTimeout is
    /// the only work done first) to when it returns. recv_timeout_secs above only bounds each
    /// individual read(); a slow-drip client that sends a single byte every few seconds (each one
    /// comfortably under recv_timeout_secs) makes every read() succeed, so recv_timeout_secs never
    /// fires and a Content-Length'd request can be held open indefinitely. Because httpListenLoop
    /// calls handleConnection synchronously (single-threaded accept loop), that one connection
    /// then starves every other RPC client behind it — the audit finding this constant closes.
    /// Generous relative to recv_timeout_secs so a legitimate slow-but-steady upload isn't clipped;
    /// worst case wall time before close is this plus one recv_timeout_secs (the read already in
    /// flight when the deadline is checked is left to finish or time out on its own).
    const max_request_read_secs: i64 = 30;

    /// Apply recv_timeout_secs to `stream` so a stalled peer eventually errors out of read()
    /// instead of blocking forever. Best-effort: an unsupported platform/socket type just leaves
    /// the (pre-existing) blocking behavior in place rather than failing the connection.
    fn setRecvTimeout(stream: std.net.Stream, seconds: i64) void {
        const tv = std.posix.timeval{ .sec = seconds, .usec = 0 };
        std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    }

    fn handleConnection(self: *Self, stream: std.net.Stream) !void {
        defer stream.close();
        setRecvTimeout(stream, recv_timeout_secs);

        // Read the HTTP request, buffering across as many read()s as it takes (see
        // readFullRequest's doc comment — this replaced a single-read() version that silently
        // dropped the body whenever a client flushed headers and body as separate TCP writes;
        // see memory/vexor-rpc-http-segmentation-bug-2026-08-03.md).
        const request = self.readFullRequest(stream) catch |err| {
            switch (err) {
                error.RequestTooLarge => sendSimpleError(stream, 413, "Payload Too Large"),
                error.RequestTimedOut => sendSimpleError(stream, 408, "Request Timeout"),
                error.MalformedContentLength => sendSimpleError(stream, 400, "Bad Request"),
                else => {},
            }
            return;
        };
        defer self.allocator.free(request);
        if (request.len == 0) return;

        // Find body after \r\n\r\n
        const body = if (std.mem.indexOf(u8, request, "\r\n\r\n")) |idx|
            request[idx + 4 ..]
        else
            request;

        // Handle JSON-RPC
        const response_body = self.handleRequest(body) catch {
            const err_response = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"},\"id\":null}";
            const header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ";
            var hdr_buf: [256]u8 = undefined;
            const hdr = std.fmt.bufPrint(&hdr_buf, "{s}{d}\r\n\r\n", .{ header, err_response.len }) catch return;
            _ = stream.write(hdr) catch {};
            _ = stream.write(err_response) catch {};
            return;
        };
        defer self.allocator.free(response_body);

        // Write HTTP response
        var hdr_buf: [256]u8 = undefined;
        const header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ";
        const hdr = std.fmt.bufPrint(&hdr_buf, "{s}{d}\r\n\r\n", .{ header, response_body.len }) catch return;
        _ = stream.write(hdr) catch {};
        _ = stream.write(response_body) catch {};
        self.stats.total_requests += 1;
    }

    /// Read a full HTTP request off `stream`, buffering across as many `read()` calls as needed.
    /// Real HTTP clients routinely flush headers and body as separate TCP writes (ureq, Python's
    /// http.client, ...); a single read() only ever sees whatever arrived first, which is why the
    /// old version silently truncated the body away. This reads until the header terminator
    /// ("\r\n\r\n") is seen and, if a Content-Length header names a body, until that many body
    /// bytes have arrived too — bounded throughout (max_header_bytes / config.max_body_size /
    /// max_request_read_secs) so a slow or oversized client can't grow this without limit. A
    /// request with no Content-Length header stops as soon as headers are found, matching the
    /// pre-fix single-read behavior for that case (there is no length to buffer to). A malformed
    /// Content-Length — non-numeric, or duplicated with conflicting values (RFC 7230 §3.3.3) —
    /// fails the request instead of guessing which value to honor. Caller owns the returned slice.
    fn readFullRequest(self: *Self, stream: std.net.Stream) ![]u8 {
        return self.readFullRequestWithDeadline(stream, max_request_read_secs);
    }

    /// readFullRequest's implementation, parameterized on the total-read deadline so the deadline
    /// path itself can be exercised deterministically in a test (see the "total wall-clock
    /// deadline" test below) instead of waiting out the real max_request_read_secs. All production
    /// callers go through readFullRequest, which supplies that named constant.
    fn readFullRequestWithDeadline(self: *Self, stream: std.net.Stream, deadline_secs: i64) ![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        const read_chunk_size: usize = 65536; // matches the old single-shot buffer size
        var chunk: [read_chunk_size]u8 = undefined;
        var header_end: ?usize = null; // index just past the terminating "\r\n\r\n"
        var body_target: ?usize = null; // header_end + Content-Length, once both are known
        const deadline_ms: i64 = std.time.milliTimestamp() + deadline_secs * 1000;

        while (true) {
            // Total-request bound, checked before every read() so a slow-drip client (each read
            // individually within recv_timeout_secs) can't hold this loop open indefinitely — see
            // max_request_read_secs's comment. Reuses the same error/close path as RequestTooLarge.
            if (std.time.milliTimestamp() >= deadline_ms) return error.RequestTimedOut;

            const n = stream.read(&chunk) catch break;
            if (n == 0) break; // peer closed — parse whatever arrived, same posture as before
            try buf.appendSlice(self.allocator, chunk[0..n]);

            if (header_end == null) {
                if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |idx| {
                    header_end = idx + 4;
                    if (try parseContentLength(buf.items[0..idx])) |content_len| {
                        if (content_len > self.config.max_body_size) return error.RequestTooLarge;
                        body_target = header_end.? + content_len;
                    }
                } else if (buf.items.len > max_header_bytes) {
                    return error.RequestTooLarge; // never saw a complete header block
                }
            }

            if (header_end != null and body_target == null) break; // no Content-Length: old single-read behavior
            if (body_target) |target| {
                if (buf.items.len >= target) break; // full declared body buffered
            }
        }

        return buf.toOwnedSlice(self.allocator);
    }

    /// RFC 7230 §3.2.3 optional whitespace (OWS = *( SP / HTAB )) — the space-only skip this
    /// replaced would misparse a legal `Content-Length:\t5` (tab instead of space) as having zero
    /// digits and reject it, a false-positive the hardening itself would have introduced.
    fn isOws(c: u8) bool {
        return c == ' ' or c == '\t';
    }

    /// Case-insensitively find a `Content-Length` header's value within `headers` (the header
    /// block up to but excluding the terminating "\r\n\r\n"). Returns null if the header is absent
    /// entirely. Returns error.MalformedContentLength if it's present but not a plain non-negative
    /// integer, or if it appears more than once with conflicting values — RFC 7230 §3.3.3 requires
    /// rejecting the latter outright rather than picking either value, because a front-end proxy
    /// and this server disagreeing on which of two Content-Length headers to honor is exactly the
    /// desync request smuggling relies on (same-value duplicates are harmless and still accepted,
    /// per that section). Matches only at a line start so it can't fire on some other header whose
    /// name happens to contain the substring.
    fn parseContentLength(headers: []const u8) error{MalformedContentLength}!?usize {
        const key = "content-length";
        var search_start: usize = 0;
        var found: ?usize = null;
        while (std.ascii.indexOfIgnoreCasePos(headers, search_start, key)) |idx| {
            const at_line_start = idx == 0 or headers[idx - 1] == '\n';
            search_start = idx + key.len;
            if (!at_line_start) continue;

            const rest = headers[idx + key.len ..];
            var p: usize = 0;
            while (p < rest.len and isOws(rest[p])) p += 1;
            if (p >= rest.len or rest[p] != ':') continue; // not actually this header (e.g. "Content-Lengthx:")
            p += 1;
            while (p < rest.len and isOws(rest[p])) p += 1;
            var e = p;
            while (e < rest.len and rest[e] >= '0' and rest[e] <= '9') e += 1;
            if (e == p) return error.MalformedContentLength; // zero digits — non-numeric, incl. a leading '-'
            const value = std.fmt.parseInt(usize, rest[p..e], 10) catch return error.MalformedContentLength;

            if (found) |prev| {
                if (prev != value) return error.MalformedContentLength; // duplicate header, conflicting values
            } else {
                found = value;
            }
        }
        return found;
    }

    /// Send a bare HTTP error status line with no body and close (caller's `defer stream.close()`
    /// handles the actual close). Used only for requests rejected before JSON-RPC parsing is even
    /// attempted (currently: oversized request).
    fn sendSimpleError(stream: std.net.Stream, status_code: u16, status_text: []const u8) void {
        var hdr_buf: [128]u8 = undefined;
        const hdr = std.fmt.bufPrint(&hdr_buf, "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{ status_code, status_text }) catch return;
        _ = stream.write(hdr) catch {};
    }

    /// Stop the RPC server
    pub fn stop(self: *Self) void {
        self.running.store(false, .seq_cst);
    }

    /// Handle a JSON-RPC request — routes through the rpc_methods dispatch registry (the canonical,
    /// 50-method implementation). Returns an allocator-owned response body (caller frees).
    pub fn handleRequest(self: *Self, request_body: []const u8) ![]u8 {
        self.stats.total_requests += 1;

        const id = parseId(request_body);
        const method = extractMethod(request_body) orelse
            return buildErr(self.allocator, id, -32600, "Invalid Request");
        const params = extractParams(request_body);

        var ctx = self.buildContext();
        var response = rpc_methods.ResponseBuilder.init(self.allocator);
        defer response.deinit();

        const found = rpc_methods.dispatch(method, &ctx, params, &response) catch
            return buildErr(self.allocator, id, -32603, "Internal error");
        if (!found) return buildErr(self.allocator, id, -32601, "Method not found");

        // Envelope: result XOR error (JSON-RPC 2.0). Handlers signal errors via response.setError.
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.writer(self.allocator).print("{{\"jsonrpc\":\"2.0\",\"id\":{d}", .{id});
        if (response.err_code) |code| {
            try out.writer(self.allocator).print(",\"error\":{{\"code\":{d},\"message\":\"{s}\"}}}}", .{ code, response.err_message });
        } else {
            try out.appendSlice(self.allocator, ",\"result\":");
            try out.appendSlice(self.allocator, response.getWritten());
            try out.appendSlice(self.allocator, "}");
        }
        return out.toOwnedSlice(self.allocator);
    }

    /// Build a per-request RpcContext from the server's live data sources. current_slot is read live
    /// from the rooted slot (AccountsDb) so commitment-default reads see fresh state.
    fn buildContext(self: *Self) rpc_methods.RpcContext {
        const slot: u64 = if (self.accounts_db) |a| a.rooted_slot else 0;
        // Warmup-aware epoch from the leader schedule (testnet warmup: first_normal_epoch=14,
        // first_normal_slot=524256) when the cache is wired; naive slot/432000 fallback otherwise.
        const epoch: u64 = if (self.leader_cache) |lc| lc.generator.getEpoch(slot) else slot / 432000;
        return .{
            .allocator = self.allocator,
            .accounts_db = self.accounts_db,
            .ledger_db = self.ledger_db,
            .leader_cache = self.leader_cache,
            .snapshot_manager = null,
            .snapshot_limiter = rpc_methods.SnapshotLimiter.init(),
            .bank = null,
            .current_slot = slot,
            .current_epoch = epoch,
            .cluster = self.cluster_name orelse "testnet",
            .full_rpc_api = self.full_rpc_api,
            .identity = self.identity,
            .public_ip = self.public_ip,
            .gossip_port = self.gossip_port,
            .tpu_port = self.tpu_port,
            .rpc_port = self.rpc_port,
            .genesis_hash = self.genesis_hash,
            .shred_version = self.shred_version,
            // SB-2 history stores + SB-1 mempool handle. rooted_slot drives finalized classification;
            // confirmed_slot defaults to the rooted slot (best-effort: we expose the rooted tip as the
            // confirmed tip for getSignatureStatuses until a separate cluster-confirmed feed is wired).
            .block_store = self.block_store,
            .tx_status_store = self.tx_status_store,
            .vex_ledger = self.vex_ledger, // VexLedger handle (null unless -Dvex_ledger + VEX_LEDGER + main.zig wiring)
            .banking = self.banking,
            .rooted_slot = slot,
            .confirmed_slot = slot,
        };
    }

    fn buildErr(allocator: std.mem.Allocator, id: i64, code: i32, msg: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"error\":{{\"code\":{d},\"message\":\"{s}\"}}}}", .{ id, code, msg });
    }

    /// Extract the `"method"` string value (the 2nd quoted string after the key).
    fn extractMethod(body: []const u8) ?[]const u8 {
        const idx = std.mem.indexOf(u8, body, "\"method\"") orelse return null;
        const after = body[idx + "\"method\"".len ..];
        const c = std.mem.indexOf(u8, after, ":") orelse return null;
        const v = after[c + 1 ..];
        const q1 = std.mem.indexOf(u8, v, "\"") orelse return null;
        const rest = v[q1 + 1 ..];
        const q2 = std.mem.indexOf(u8, rest, "\"") orelse return null;
        return rest[0..q2];
    }

    /// Return the raw `"params"` value substring (everything after the colon — array/object/null).
    fn extractParams(body: []const u8) ?[]const u8 {
        const idx = std.mem.indexOf(u8, body, "\"params\"") orelse return null;
        const after = body[idx + "\"params\"".len ..];
        const c = std.mem.indexOf(u8, after, ":") orelse return null;
        return after[c + 1 ..];
    }

    /// Parse the numeric `"id"`; defaults to 1 if absent/non-numeric (string ids are coerced to 1).
    fn parseId(body: []const u8) i64 {
        const idx = std.mem.indexOf(u8, body, "\"id\"") orelse return 1;
        const after = body[idx + "\"id\"".len ..];
        const c = std.mem.indexOf(u8, after, ":") orelse return 1;
        var rest = after[c + 1 ..];
        var s: usize = 0;
        while (s < rest.len and (rest[s] == ' ' or rest[s] == '\t')) s += 1;
        var e = s;
        while (e < rest.len and rest[e] >= '0' and rest[e] <= '9') e += 1;
        if (e == s) return 1;
        return std.fmt.parseInt(i64, rest[s..e], 10) catch 1;
    }

    fn parseRequest(self: *Self, body: []const u8) !JsonRpcRequest {
        _ = self;
        // Simple JSON parsing for RPC request
        // In production, use a proper JSON parser

        var request = JsonRpcRequest{
            .jsonrpc = "2.0",
            .method = "",
            .params = null,
            .id = 1,
        };

        // Find method
        if (std.mem.indexOf(u8, body, "\"method\"")) |idx| {
            const quote1 = std.mem.indexOfPos(u8, body, idx, "\"") orelse return error.InvalidJson;
            const quote2 = std.mem.indexOfPos(u8, body, quote1 + 1, "\"") orelse return error.InvalidJson;
            if (std.mem.indexOfPos(u8, body, quote2 + 1, "\"")) |mstart| {
                if (std.mem.indexOfPos(u8, body, mstart + 1, "\"")) |mend| {
                    request.method = body[mstart + 1 .. mend];
                }
            }
        }

        return request;
    }

    fn routeRequest(self: *Self, request: JsonRpcRequest) RpcResult {
        // Route based on method name
        if (std.mem.eql(u8, request.method, "getHealth")) {
            return self.handleGetHealth();
        } else if (std.mem.eql(u8, request.method, "getVersion")) {
            return self.handleGetVersion();
        } else if (std.mem.eql(u8, request.method, "getSlot")) {
            return self.handleGetSlot();
        } else if (std.mem.eql(u8, request.method, "getBlockHeight")) {
            return self.handleGetBlockHeight();
        } else if (std.mem.eql(u8, request.method, "getBalance")) {
            return self.handleGetBalance(request.params);
        } else if (std.mem.eql(u8, request.method, "getAccountInfo")) {
            return self.handleGetAccountInfo(request.params);
        } else if (std.mem.eql(u8, request.method, "getLatestBlockhash")) {
            return self.handleGetLatestBlockhash();
        } else if (std.mem.eql(u8, request.method, "sendTransaction")) {
            return self.handleSendTransaction(request.params);
        } else if (std.mem.eql(u8, request.method, "getSignatureStatuses")) {
            return self.handleGetSignatureStatuses(request.params);
        } else if (std.mem.eql(u8, request.method, "getMinimumBalanceForRentExemption")) {
            return self.handleGetMinimumBalanceForRentExemption(request.params);
        } else {
            return .{ .err = .{ .code = -32601, .message = "Method not found" } };
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RPC METHOD HANDLERS
    // ═══════════════════════════════════════════════════════════════════════════

    fn handleGetHealth(self: *Self) RpcResult {
        _ = self;
        return .{ .result = "\"ok\"" };
    }

    fn handleGetVersion(self: *Self) RpcResult {
        _ = self;
        return .{ .result = "{\"solana-core\":\"0.2.0-vexor\",\"feature-set\":1}" };
    }

    fn handleGetSlot(self: *Self) RpcResult {
        if (self.ledger_db) |db| {
            // Return last replayed slot (matches Firedancer's getSlot semantics), NOT gossip latest_slot
            const slot = db.last_replayed_slot.load(.seq_cst);
            var buf: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&buf, "{d}", .{slot}) catch return .{ .err = .{ .code = -32603, .message = "Internal error" } };
            return .{ .result = s };
        }
        return .{ .result = "0" };
    }

    fn handleGetBlockHeight(self: *Self) RpcResult {
        if (self.ledger_db) |db| {
            // Block height is separate from slot — only counts non-skipped (replayed) slots
            const height = db.block_height.load(.seq_cst);
            var buf: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&buf, "{d}", .{height}) catch return .{ .err = .{ .code = -32603, .message = "Internal error" } };
            return .{ .result = s };
        }
        return .{ .result = "0" };
    }

    fn handleGetBalance(self: *Self, params: ?[]const u8) RpcResult {
        _ = params;
        if (self.accounts_db) |_| {
            // TODO: Parse pubkey from params and look up balance
            return .{ .result = "{\"context\":{\"slot\":0},\"value\":0}" };
        }
        return .{ .result = "{\"context\":{\"slot\":0},\"value\":0}" };
    }

    fn handleGetAccountInfo(self: *Self, params: ?[]const u8) RpcResult {
        _ = params;
        _ = self;
        // TODO: Parse pubkey and return account data
        return .{ .result = "{\"context\":{\"slot\":0},\"value\":null}" };
    }

    fn handleGetLatestBlockhash(self: *Self) RpcResult {
        _ = self;
        // TODO: Return actual latest blockhash
        const fake_hash = "11111111111111111111111111111111";
        return .{ .result = "{\"context\":{\"slot\":0},\"value\":{\"blockhash\":\"" ++ fake_hash ++ "\",\"lastValidBlockHeight\":0}}" };
    }

    fn handleSendTransaction(self: *Self, params: ?[]const u8) RpcResult {
        _ = params;
        self.stats.transactions_received += 1;
        // TODO: Decode and forward to TPU
        return .{ .result = "\"sent\"" };
    }

    fn handleGetSignatureStatuses(self: *Self, params: ?[]const u8) RpcResult {
        _ = params;
        _ = self;
        return .{ .result = "{\"context\":{\"slot\":0},\"value\":[null]}" };
    }

    fn handleGetMinimumBalanceForRentExemption(self: *Self, params: ?[]const u8) RpcResult {
        _ = params;
        _ = self;
        // Calculate rent exemption for a given data size
        // Minimum is ~0.00089 SOL per byte
        return .{ .result = "890880" }; // ~0.00089 SOL for 0 bytes
    }

    fn buildResponse(self: *Self, id: u64, result: RpcResult) ![]u8 {
        var response = std.ArrayListUnmanaged(u8){};
        errdefer response.deinit(self.allocator);

        try response.appendSlice(self.allocator, "{\"jsonrpc\":\"2.0\",\"id\":");
        var id_buf: [20]u8 = undefined;
        const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{id}) catch "0";
        try response.appendSlice(self.allocator, id_str);

        switch (result) {
            .result => |r| {
                try response.appendSlice(self.allocator, ",\"result\":");
                try response.appendSlice(self.allocator, r);
            },
            .err => |e| {
                try response.appendSlice(self.allocator, ",\"error\":{\"code\":");
                var code_buf: [12]u8 = undefined;
                const code_str = std.fmt.bufPrint(&code_buf, "{d}", .{e.code}) catch "0";
                try response.appendSlice(self.allocator, code_str);
                try response.appendSlice(self.allocator, ",\"message\":\"");
                try response.appendSlice(self.allocator, e.message);
                try response.appendSlice(self.allocator, "\"}");
            },
        }

        try response.appendSlice(self.allocator, "}");

        return try response.toOwnedSlice(self.allocator);
    }
};

/// JSON-RPC request
pub const JsonRpcRequest = struct {
    jsonrpc: []const u8,
    method: []const u8,
    params: ?[]const u8,
    id: u64,
};

/// RPC result union
pub const RpcResult = union(enum) {
    result: []const u8,
    err: RpcError,
};

/// RPC error
pub const RpcError = struct {
    code: i32,
    message: []const u8,

    // Standard JSON-RPC errors
    pub const ParseError = RpcError{ .code = -32700, .message = "Parse error" };
    pub const InvalidRequest = RpcError{ .code = -32600, .message = "Invalid Request" };
    pub const MethodNotFound = RpcError{ .code = -32601, .message = "Method not found" };
    pub const InvalidParams = RpcError{ .code = -32602, .message = "Invalid params" };
    pub const InternalError = RpcError{ .code = -32603, .message = "Internal error" };
};

/// RPC statistics
pub const RpcStats = struct {
    total_requests: u64 = 0,
    transactions_received: u64 = 0,
    errors: u64 = 0,
};

/// Simple HTTP request parser for RPC
pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    body: []const u8,

    pub fn parse(data: []const u8) !HttpRequest {
        // Find method
        const method_end = std.mem.indexOf(u8, data, " ") orelse return error.InvalidHttp;
        const method = data[0..method_end];

        // Find path
        const path_start = method_end + 1;
        const path_end = std.mem.indexOfPos(u8, data, path_start, " ") orelse return error.InvalidHttp;
        const path = data[path_start..path_end];

        // Find body (after \r\n\r\n)
        const body_start = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return error.InvalidHttp;
        const body = data[body_start + 4 ..];

        return .{
            .method = method,
            .path = path,
            .body = body,
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "rpc server init" {
    var server = try RpcServer.init(std.testing.allocator, 8899);
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 8899), server.config.port);
}

test "http request parse" {
    const raw = "POST /rpc HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"method\":\"getHealth\"}";
    const req = try HttpRequest.parse(raw);

    try std.testing.expectEqualSlices(u8, "POST", req.method);
    try std.testing.expectEqualSlices(u8, "/rpc", req.path);
}

// ─── segmentation-bug regression tests (2026-08-03) ─────────────────────────────
// Reproduces the T1-07 finding (memory/vexor-rpc-http-segmentation-bug-2026-08-03.md): a real
// HTTP client that flushes headers and body as two separate TCP writes got -32600 Invalid
// Request back, because the old handleConnection did exactly one stream.read() and treated
// whatever arrived in it as the whole request. These drive handleConnection over a real loopback
// TCP connection (not a synthetic buffer) so the two writes are genuinely two separate reads on
// the server side, the same way ureq / Python's http.client / any two-syscall client behaves.

fn testAcceptOnce(server: *RpcServer, listener: *std.net.Server) void {
    const conn = listener.accept() catch return;
    server.handleConnection(conn.stream) catch {};
}

/// Read until the peer closes (EOF). handleConnection's own response write is itself two separate
/// stream.write() calls (headers, then body) — a single client-side read() can just as easily race
/// that split as the server-side read raced the request split this whole test file exists to catch,
/// so this loops rather than trusting one read() to capture the whole response.
fn testReadUntilClose(client: std.net.Stream, resp_buf: []u8) ![]u8 {
    var total: usize = 0;
    while (total < resp_buf.len) {
        const n = try client.read(resp_buf[total..]);
        if (n == 0) break;
        total += n;
    }
    return resp_buf[0..total];
}

/// Sends `first_write` then (after a short delay to force two separate server-side reads instead
/// of the kernel coalescing them) `second_write`, and returns whatever handleConnection wrote
/// back. `second_write` may be empty to model a request that never sends the rest.
fn testSegmentedRequest(allocator: std.mem.Allocator, first_write: []const u8, second_write: []const u8, resp_buf: []u8) ![]u8 {
    var server = try RpcServer.init(allocator, 0);
    defer server.deinit();

    var listener = try std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0).listen(.{ .reuse_address = true });
    defer listener.deinit();
    const port = listener.listen_address.getPort();

    const accept_thread = try std.Thread.spawn(.{}, testAcceptOnce, .{ server, &listener });

    const client = try std.net.tcpConnectToAddress(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port));
    defer client.close();

    _ = try client.write(first_write);
    if (second_write.len > 0) {
        std.Thread.sleep(80 * std.time.ns_per_ms); // let the server's first read() return with headers only
        _ = try client.write(second_write);
    }

    const resp = try testReadUntilClose(client, resp_buf);
    accept_thread.join();
    return resp;
}

test "handleConnection: segmented request (headers, then body, as two separate writes) parses correctly — T1-07 reproducer" {
    const allocator = std.testing.allocator;
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\"}";
    var hdr_buf: [256]u8 = undefined;
    const headers = try std.fmt.bufPrint(&hdr_buf, "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n", .{body.len});

    var resp_buf: [4096]u8 = undefined;
    const resp = try testSegmentedRequest(allocator, headers, body, &resp_buf);

    // Pre-fix this came back as {"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}
    // because the body (sent in the second write) was never seen by the single stream.read().
    try std.testing.expect(std.mem.indexOf(u8, resp, "-32600") == null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"result\":\"ok\"") != null);
}

test "handleConnection: single-write request still succeeds (no regression)" {
    const allocator = std.testing.allocator;
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\"}";
    var full_buf: [512]u8 = undefined;
    const full_request = try std.fmt.bufPrint(&full_buf, "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body });

    var resp_buf: [4096]u8 = undefined;
    const resp = try testSegmentedRequest(allocator, full_request, "", &resp_buf);

    try std.testing.expect(std.mem.indexOf(u8, resp, "\"result\":\"ok\"") != null);
}

test "handleConnection: oversized Content-Length is rejected cleanly (413), not buffered" {
    const allocator = std.testing.allocator;
    var server = try RpcServer.init(allocator, 0);
    defer server.deinit();
    // Declared body far past config.max_body_size (default 50MB) — must be rejected from the
    // header alone, without the server ever trying to read that many bytes.
    try std.testing.expect(server.config.max_body_size + 1 > server.config.max_body_size);
    var hdr_buf: [256]u8 = undefined;
    const headers = try std.fmt.bufPrint(&hdr_buf, "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n", .{server.config.max_body_size + 1});

    var listener = try std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0).listen(.{ .reuse_address = true });
    defer listener.deinit();
    const port = listener.listen_address.getPort();

    const accept_thread = try std.Thread.spawn(.{}, testAcceptOnce, .{ server, &listener });

    const client = try std.net.tcpConnectToAddress(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port));
    defer client.close();
    _ = try client.write(headers); // no body ever sent — server must not block waiting for one

    var resp_buf: [256]u8 = undefined;
    const resp = try testReadUntilClose(client, &resp_buf);
    accept_thread.join();

    try std.testing.expect(std.mem.indexOf(u8, resp, "413") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "Payload Too Large") != null);
}

// ─── hardening audit findings (2026-08-03) ──────────────────────────────────────
// Adversarial audit of 9e22f86 (the segmentation fix above): P1 was the total-read deadline
// (below); these two are the parseContentLength P2s — duplicate conflicting Content-Length and
// non-numeric/negative Content-Length were each silently mishandled instead of rejected.

test "handleConnection: duplicate conflicting Content-Length is rejected (400) — RFC 7230 §3.3.3 smuggling defense" {
    const allocator = std.testing.allocator;
    var server = try RpcServer.init(allocator, 0);
    defer server.deinit();

    var listener = try std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0).listen(.{ .reuse_address = true });
    defer listener.deinit();
    const port = listener.listen_address.getPort();

    const accept_thread = try std.Thread.spawn(.{}, testAcceptOnce, .{ server, &listener });

    const client = try std.net.tcpConnectToAddress(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port));
    defer client.close();
    // Two Content-Length headers naming different lengths: a front-end and this server honoring
    // different ones of the two would disagree about where the request ends, which is exactly the
    // desync request smuggling relies on. Must be rejected outright, not resolved by either value.
    const request = "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\nHELLOHELLO";
    _ = try client.write(request);

    var resp_buf: [256]u8 = undefined;
    const resp = try testReadUntilClose(client, &resp_buf);
    accept_thread.join();

    try std.testing.expect(std.mem.indexOf(u8, resp, "400") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "Bad Request") != null);
}

test "handleConnection: non-numeric Content-Length is rejected (400), not treated as absent" {
    const allocator = std.testing.allocator;
    var server = try RpcServer.init(allocator, 0);
    defer server.deinit();

    var listener = try std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0).listen(.{ .reuse_address = true });
    defer listener.deinit();
    const port = listener.listen_address.getPort();

    const accept_thread = try std.Thread.spawn(.{}, testAcceptOnce, .{ server, &listener });

    const client = try std.net.tcpConnectToAddress(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port));
    defer client.close();
    // Pre-fix this fell through parseContentLength's digit scan (zero digits matched, "e > p"
    // false) without returning, so the header was silently treated as absent and "HELLO" would be
    // left dangling as the start of the next request on the same connection instead of failing.
    const request = "POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nHELLO";
    _ = try client.write(request);

    var resp_buf: [256]u8 = undefined;
    const resp = try testReadUntilClose(client, &resp_buf);
    accept_thread.join();

    try std.testing.expect(std.mem.indexOf(u8, resp, "400") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "Bad Request") != null);
}

test "handleConnection: Content-Length with a tab before the value (legal OWS) is accepted, not rejected" {
    // RFC 7230 §3.2.3 OWS is *( SP / HTAB ) — a space-only skip would hit parseContentLength's
    // zero-digits branch on this and turn a legal request into a false-positive 400.
    const allocator = std.testing.allocator;
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\"}";
    var full_buf: [512]u8 = undefined;
    const full_request = try std.fmt.bufPrint(&full_buf, "POST / HTTP/1.1\r\nContent-Length:\t{d}\r\n\r\n{s}", .{ body.len, body });

    var resp_buf: [4096]u8 = undefined;
    const resp = try testSegmentedRequest(allocator, full_request, "", &resp_buf);

    try std.testing.expect(std.mem.indexOf(u8, resp, "\"result\":\"ok\"") != null);
}

test "readFullRequestWithDeadline: exceeding the total wall-clock deadline returns error.RequestTimedOut" {
    // Exercises the P1 fix (max_request_read_secs) deterministically: deadline_secs=0 expires
    // before the loop's first iteration, so this models a slow-drip client (one that keeps every
    // individual read() under recv_timeout_secs, defeating that per-read bound) without an actual
    // multi-second wait or a fake clock — the real max_request_read_secs=30 default is exercised
    // by construction (same code path), just with the deadline parameter shortened for the test.
    const allocator = std.testing.allocator;
    var server = try RpcServer.init(allocator, 0);
    defer server.deinit();

    var listener = try std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0).listen(.{ .reuse_address = true });
    defer listener.deinit();
    const port = listener.listen_address.getPort();

    const client = try std.net.tcpConnectToAddress(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port));
    defer client.close();
    const conn = try listener.accept();
    defer conn.stream.close();

    const result = server.readFullRequestWithDeadline(conn.stream, 0);
    try std.testing.expectError(error.RequestTimedOut, result);
}
