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

    fn handleConnection(self: *Self, stream: std.net.Stream) !void {
        defer stream.close();

        // Read HTTP request (simple: read until double CRLF, extract body)
        var buf: [65536]u8 = undefined;
        const n = stream.read(&buf) catch return;
        if (n == 0) return;
        const request = buf[0..n];

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
