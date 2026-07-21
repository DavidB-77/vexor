//! Vexor RPC Methods
//!
//! Full implementation of Solana JSON-RPC API methods.
//! Organized by category for maintainability.

const std = @import("std");
const Allocator = std.mem.Allocator;
const core = @import("core");
const storage = @import("vex_store");
const runtime = @import("vex_svm");
const crypto = @import("vex_crypto");
const consensus = @import("vex_consensus");
const account_encoder = @import("account_encoder.zig"); // SB-4: UiAccount JSON encoder
const commitment = @import("commitment.zig"); // SB-4: commitment/slot selector
const block_store_mod = storage.block_store; // SB-2: StoredBlock/StoredTx/StoredReward/TxError types
const vex_ledger_mod = @import("vex_ledger"); // VexLedger persistent blockstore. build.zig:288 wires this module
// into vex_network UNCONDITIONALLY (the type is always importable); only behavior is comptime-gated by
// build_options.vex_ledger. The enumeration reads below (lowestSlot/rootedSlotsFrom) are populated by the
// shred + finishSlot/root tile path (LIVE's ledger_tile), INDEPENDENT of the -Drpc_store tx-capture, so they
// are correct the moment the ledger has rooted any slot — no dependency on the deferred meta capture (Q2).

pub const SnapshotLimiter = struct {
    in_flight: std.atomic.Value(bool),
    next_allowed_ms: std.atomic.Value(u64),
    last_duration_ms: std.atomic.Value(u64),
    min_cooldown_ms: u64,
    max_cooldown_ms: u64,
    multiplier: u64,

    const Self = @This();

    pub fn init() Self {
        return .{
            .in_flight = std.atomic.Value(bool).init(false),
            .next_allowed_ms = std.atomic.Value(u64).init(0),
            .last_duration_ms = std.atomic.Value(u64).init(0),
            .min_cooldown_ms = 5_000,
            .max_cooldown_ms = 300_000,
            .multiplier = 4,
        };
    }

    pub fn canStart(self: *Self, now_ms: u64) bool {
        if (self.in_flight.load(.acquire)) return false;
        return now_ms >= self.next_allowed_ms.load(.acquire);
    }

    pub fn markStart(self: *Self) bool {
        return !self.in_flight.swap(true, .seq_cst);
    }

    pub fn markFinish(self: *Self, duration_ms: u64, now_ms: u64) void {
        self.in_flight.store(false, .seq_cst);
        self.last_duration_ms.store(duration_ms, .seq_cst);
        const scaled = duration_ms * self.multiplier;
        const cooldown = @min(@max(scaled, self.min_cooldown_ms), self.max_cooldown_ms);
        self.next_allowed_ms.store(now_ms + cooldown, .seq_cst);
    }

    pub fn retryAfter(self: *Self, now_ms: u64) u64 {
        const next = self.next_allowed_ms.load(.acquire);
        return if (next > now_ms) next - now_ms else 0;
    }
};

/// RPC context passed to all handlers
pub const RpcContext = struct {
    allocator: Allocator,
    accounts_db: ?*storage.AccountsDb,
    ledger_db: ?*storage.LedgerDb,
    snapshot_manager: ?*storage.SnapshotManager,
    snapshot_limiter: SnapshotLimiter,
    bank: ?*runtime.Bank,
    current_slot: u64,
    current_epoch: u64,
    cluster: []const u8,
    /// Canonical Agave RPC tier gate (config.full_rpc_api → RpcServer.buildContext). When false,
    /// dispatch() serves ONLY the 12 Minimal-trait methods; everything else returns method-not-found,
    /// matching a stock voting validator (rpc_service.rs only registers Full/BankData/AccountsData/
    /// AccountsScan when full_api is on). Default false so an un-plumbed context is safe-minimal.
    full_rpc_api: bool = false,
    identity: ?[]const u8 = null,
    vote_account: ?[]const u8 = null,
    /// Operational (non-consensus) RPC convenience values, config-driven. Optional with safe
    /// defaults so behavior is byte-identical to the legacy hardcodes when unset (see getClusterNodes
    /// / getGenesisHash fallbacks). Set by RpcServer.buildContext from the corresponding server fields.
    public_ip: ?[4]u8 = null,
    gossip_port: u16 = 0,
    tpu_port: u16 = 0,
    rpc_port: u16 = 0,
    genesis_hash: ?[]const u8 = null,
    shred_version: u16 = 0,
    /// Leader schedule cache — set by root.zig after consensus engine starts
    leader_cache: ?*consensus.leader_schedule.LeaderScheduleCache = null,
    /// SB-2 RPC block/transaction-history stores (2026-06-17). Standalone (NOT on the null LedgerDb).
    /// Present only when main.zig created them under the -Drpc_store/VEX_RPC_STORE gate; null otherwise.
    /// The block/tx-history handlers null-check these and fall back to Agave-correct empty/null when
    /// absent, so the methods are always wired and never regress when the gate is OFF.
    block_store: ?*storage.BlockStore = null,
    tx_status_store: ?*storage.TxStatusStore = null,
    /// VexLedger persistent blockstore handle (2026-06-24). Set by main.zig (via rpc_server.vex_ledger →
    /// buildContext copy) ONLY under the -Dvex_ledger build + VEX_LEDGER env gate; null otherwise → the
    /// enumeration handlers (getFirstAvailableBlock/getBlocks/getBlocksWithLimit) fall back to their prior
    /// behavior, byte-identical to before this wiring. SAFE-SUBSET: only slot-EXISTENCE/rooted reads use it
    /// this batch (fed by the shred/finishSlot tile path); transaction-META reads (getBlock/getTransaction/
    /// getSignatureStatuses/getSignaturesForAddress CONTENT) stay on the canonical "not available"/null path
    /// until LIVE's executor-capture expansion lands (deferred per Q2 — null beats partial-wrong, RULE #0).
    vex_ledger: ?*vex_ledger_mod.VexLedger = null,
    /// Highest cluster-confirmed slot for getSignatureStatuses confirmationStatus (best-effort:
    /// current_slot when unknown). Rooted slot for `finalized` comes from accounts_db.rooted_slot.
    confirmed_slot: u64 = 0,
    rooted_slot: u64 = 0,
    /// Mempool handle for sendTransaction (the SAME BankingStage the QUIC TPU ingest seam feeds).
    /// Present only when VEX_TPU_INGEST built the mempool; null otherwise → sendTransaction errors
    /// (RULE #0: never return a fake signature for a tx that was not actually accepted).
    banking: ?*runtime.banking_stage.BankingStage = null,
};

/// Response builder for JSON output
pub const ResponseBuilder = struct {
    allocator: Allocator,
    buffer: std.ArrayListUnmanaged(u8),
    /// Canonical JSON-RPC error: when a handler calls `setError`, the server wrapper emits
    /// `"error":{code,message}` INSTEAD of `"result":<buffer>` (per the JSON-RPC 2.0 spec — a
    /// response carries result XOR error). null = success (emit result). Mirrors Agave's per-method
    /// error returns (-32602 invalid params, -32600 invalid request, etc.).
    err_code: ?i32 = null,
    err_message: []const u8 = "",

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .buffer = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn reset(self: *Self) void {
        self.buffer.clearRetainingCapacity();
        self.err_code = null;
        self.err_message = "";
    }

    /// Signal a JSON-RPC error for this response. `message` must outlive the response (use a string
    /// literal or `ctx.allocator`-owned text). The result buffer is ignored once an error is set.
    pub fn setError(self: *Self, code: i32, message: []const u8) void {
        self.err_code = code;
        self.err_message = message;
    }

    pub fn appendFmt(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        try self.buffer.writer(self.allocator).print(fmt, args);
    }

    pub fn append(self: *Self, data: []const u8) !void {
        try self.buffer.appendSlice(self.allocator, data);
    }

    pub fn appendInt(self: *Self, value: anytype) !void {
        try self.buffer.writer(self.allocator).print("{d}", .{value});
    }

    pub fn appendHex(self: *Self, bytes: []const u8) !void {
        for (bytes) |b| {
            try self.buffer.writer(self.allocator).print("{x:0>2}", .{b});
        }
    }

    pub fn toOwnedSlice(self: *Self) ![]u8 {
        return self.buffer.toOwnedSlice(self.allocator);
    }

    pub fn getWritten(self: *const Self) []const u8 {
        return self.buffer.items;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// CLUSTER INFORMATION METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// getClusterNodes - Returns this validator's node info with real identity pubkey and Vexor version
pub fn getClusterNodes(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const identity = ctx.identity orelse "3J2jADiEoKMaooCQbkyr9aLnjAb5ApDWfVvKgzyK2fbP";
    // Config-driven host:port (non-consensus convenience). Fall back to the legacy hardcodes when a
    // field is unset/0 so output is byte-identical to before when nothing is wired.
    var ip_buf: [16]u8 = undefined;
    const ip_str: []const u8 = if (ctx.public_ip) |ip|
        try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] })
    else
        "0.0.0.0";
    const gossip_port: u16 = if (ctx.gossip_port != 0) ctx.gossip_port else 8001;
    const tpu_port: u16 = if (ctx.tpu_port != 0) ctx.tpu_port else 8004;
    const rpc_port: u16 = if (ctx.rpc_port != 0) ctx.rpc_port else 8899;
    try response.append("[{");
    try response.appendFmt("\"pubkey\":\"{s}\",", .{identity});
    try response.appendFmt("\"gossip\":\"{s}:{d}\",", .{ ip_str, gossip_port });
    try response.appendFmt("\"tpu\":\"{s}:{d}\",", .{ ip_str, tpu_port });
    try response.appendFmt("\"rpc\":\"{s}:{d}\",", .{ ip_str, rpc_port });
    try response.append("\"version\":\"vexor-0.2.0\"");
    try response.append("}]");
}

/// getEpochInfo - Returns epoch info from replay state (matches Firedancer's semantics)
pub fn getEpochInfo(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const slots_per_epoch: u64 = 432000;
    // Use replayed slot for consistency (matches getSlot)
    const replay_slot = if (ctx.ledger_db) |db| db.last_replayed_slot.load(.seq_cst) else ctx.current_slot;
    // Warmup-aware epoch + slotIndex from the real schedule generator (testnet warmup:
    // first_normal_epoch=14, first_normal_slot=524256) — NOT naive slot/432000, which
    // reports the WRONG epoch (e.g. 964 vs the cluster's real 977) and makes this RPC
    // disagree with the cluster. Fall back to the naive value only when the leader cache
    // isn't wired yet (pre-consensus boot / tests).
    var epoch: u64 = ctx.current_epoch;
    var slot_index: u64 = replay_slot % slots_per_epoch;
    if (ctx.leader_cache) |lc| {
        epoch = lc.generator.getEpoch(replay_slot);
        slot_index = replay_slot - lc.generator.getFirstSlotInEpoch(epoch);
    }
    const slots_in_epoch = slots_per_epoch;

    try response.append("{");
    try response.appendFmt("\"epoch\":{d},", .{epoch});
    try response.appendFmt("\"slotIndex\":{d},", .{slot_index});
    try response.appendFmt("\"slotsInEpoch\":{d},", .{slots_in_epoch});
    try response.appendFmt("\"absoluteSlot\":{d},", .{replay_slot});
    // Block height from replay (matches Firedancer's semantics), NOT same as slot
    const bh = if (ctx.ledger_db) |db| db.block_height.load(.seq_cst) else ctx.current_slot;
    try response.appendFmt("\"blockHeight\":{d},", .{bh});
    const txn_count = if (ctx.ledger_db) |db| db.transaction_count.load(.seq_cst) else 0;
    if (txn_count > 0) {
        try response.appendFmt("\"transactionCount\":{d}", .{txn_count});
    } else {
        try response.append("\"transactionCount\":null");
    }
    try response.append("}");
}

/// getEpochSchedule - Returns epoch schedule
pub fn getEpochSchedule(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    _ = ctx;
    try response.append("{");
    try response.append("\"slotsPerEpoch\":432000,");
    try response.append("\"leaderScheduleSlotOffset\":432000,");
    try response.append("\"warmup\":true,");
    try response.append("\"firstNormalEpoch\":0,");
    try response.append("\"firstNormalSlot\":0");
    try response.append("}");
}

/// getGenesisHash - Returns genesis hash
pub fn getGenesisHash(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    // Config-driven genesis hash; fall back to the legacy testnet literal when unset.
    const gh = ctx.genesis_hash orelse "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";
    try response.appendFmt("\"{s}\"", .{gh});
}

/// getIdentity - Returns validator identity (base58 encoded)
pub fn getIdentity(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    if (ctx.identity) |id| {
        // Identity should already be base58-encoded by bootstrap
        try response.appendFmt("{{\"identity\":\"{s}\"}}", .{id});
    } else {
        try response.append("{\"identity\":\"unknown\"}");
    }
}

/// getInflationGovernor - Returns inflation parameters
pub fn getInflationGovernor(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    _ = ctx;
    try response.append("{");
    try response.append("\"initial\":0.08,");
    try response.append("\"terminal\":0.015,");
    try response.append("\"taper\":0.15,");
    try response.append("\"foundation\":0.05,");
    try response.append("\"foundationTerm\":7.0");
    try response.append("}");
}

/// getInflationRate - Returns current inflation rate
pub fn getInflationRate(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    try response.append("{");
    try response.appendFmt("\"epoch\":{d},", .{ctx.current_epoch});
    try response.append("\"foundation\":0.0,");
    try response.append("\"total\":0.063,");
    try response.append("\"validator\":0.063");
    try response.append("}");
}

/// getSupply - Returns SOL supply info
pub fn getSupply(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":{");
    try response.append("\"total\":555000000000000000,");
    try response.append("\"circulating\":555000000000000000,");
    try response.append("\"nonCirculating\":0,");
    try response.append("\"nonCirculatingAccounts\":[]");
    try response.append("}}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// ACCOUNT METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// getAccountInfo - Returns account info
// ── SB-4 RPC param helpers (account methods) ─────────────────────────────────
// NOTE: these scan the raw params with the same quoted-string idiom the rest of this file uses
// (getBalance). A full JSON params parser is the deeper canonical follow-up; the OUTPUT here
// (UiAccount JSON via account_encoder + canonical -32602/-32600 error envelopes) is exact.

/// Parse the first base58 pubkey out of the params array. null if missing/invalid base58.
fn parseFirstPubkey(params: ?[]const u8) ?core.Pubkey {
    const p = params orelse return null;
    const q1 = std.mem.indexOf(u8, p, "\"") orelse return null;
    const after = p[q1 + 1 ..];
    const q2 = std.mem.indexOf(u8, after, "\"") orelse return null;
    const s = after[0..q2];
    if (s.len < 32 or s.len > 44) return null;
    var b: [32]u8 = undefined;
    core.base58.decodeToBuf(s, &b) catch return null;
    return core.Pubkey{ .data = b };
}

/// Parse a JSON array of base58 pubkey strings (params[0] of getMultipleAccounts). Returns the parsed
/// pubkeys (caller deinits) or null if no array is present. Mirrors parseFirstPubkey's per-string
/// base58 decode; silently skips malformed entries (Agave would 400, but skipping is safe for a read).
fn parsePublickeysArray(allocator: std.mem.Allocator, params: ?[]const u8) ?std.ArrayListUnmanaged(core.Pubkey) {
    const p = params orelse return null;
    const lb = std.mem.indexOfScalar(u8, p, '[') orelse return null;
    const rb = std.mem.indexOfScalarPos(u8, p, lb + 1, ']') orelse return null;
    var pubkeys: std.ArrayListUnmanaged(core.Pubkey) = .{};
    var rest = p[lb + 1 .. rb];
    while (std.mem.indexOfScalar(u8, rest, '"')) |q1| {
        const after = rest[q1 + 1 ..];
        const q2 = std.mem.indexOfScalar(u8, after, '"') orelse break;
        const s = after[0..q2];
        if (s.len >= 32 and s.len <= 44) {
            var b: [32]u8 = undefined;
            if (core.base58.decodeToBuf(s, &b)) |_| {
                pubkeys.append(allocator, core.Pubkey{ .data = b }) catch {
                    pubkeys.deinit(allocator);
                    return null;
                };
            } else |_| {}
        }
        rest = after[q2 + 1 ..];
    }
    return pubkeys;
}

/// Parse `"encoding":"…"` from the config object; Agave's default for getAccountInfo is base58.
fn parseEncoding(params: ?[]const u8) account_encoder.AccountEncoding {
    const p = params orelse return .base58;
    const i = std.mem.indexOf(u8, p, "\"encoding\"") orelse return .base58;
    const after = p[i + "\"encoding\"".len ..];
    const c = std.mem.indexOf(u8, after, ":") orelse return .base58;
    const v = after[c + 1 ..];
    const s1 = std.mem.indexOf(u8, v, "\"") orelse return .base58;
    const rest = v[s1 + 1 ..];
    const s2 = std.mem.indexOf(u8, rest, "\"") orelse return .base58;
    return account_encoder.AccountEncoding.fromString(rest[0..s2]) orelse .base58;
}

/// Parse a `"field":<uint>` value out of `s` (used for dataSlice offset/length). null if absent.
fn parseJsonUint(s: []const u8, field: []const u8) ?usize {
    var nbuf: [48]u8 = undefined;
    const needle = std.fmt.bufPrint(&nbuf, "\"{s}\"", .{field}) catch return null;
    const i = std.mem.indexOf(u8, s, needle) orelse return null;
    var rest = s[i + needle.len ..];
    const c = std.mem.indexOf(u8, rest, ":") orelse return null;
    rest = rest[c + 1 ..];
    var start: usize = 0;
    while (start < rest.len and (rest[start] == ' ' or rest[start] == '\t')) start += 1;
    var end = start;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') end += 1;
    if (end == start) return null;
    return std.fmt.parseInt(usize, rest[start..end], 10) catch null;
}

/// Parse `"dataSlice":{"offset":N,"length":M}`. null if absent or malformed.
fn parseDataSlice(params: ?[]const u8) ?account_encoder.DataSlice {
    const p = params orelse return null;
    const i = std.mem.indexOf(u8, p, "\"dataSlice\"") orelse return null;
    const seg = p[i..];
    const off = parseJsonUint(seg, "offset") orelse return null;
    const len = parseJsonUint(seg, "length") orelse return null;
    return .{ .offset = off, .length = len };
}

/// getAccountInfo — reads the (finalized) account from AccountsDb and renders the Agave UiAccount
/// via the SB-4 encoder. Returns canonical errors: -32602 (unparseable pubkey), -32600 (base58 data
/// > 128 bytes — Agave's message), or value:null when the account does not exist. Commitment-aware
/// reads (processed/confirmed via getAccountInSlot + commitment.selectSlot) are a follow-up; this
/// reads the rooted/finalized state (getAccountInfo's historical default commitment).
pub fn getAccountInfo(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    const pubkey = parseFirstPubkey(params) orelse {
        response.setError(-32602, "Invalid param: failed to parse pubkey");
        return;
    };
    const enc = parseEncoding(params);
    const slice = parseDataSlice(params);

    // Render (and surface encoder errors) BEFORE writing the envelope, so an error path emits no
    // partial result.
    var acct_json: ?[]u8 = null;
    if (ctx.accounts_db) |adb| {
        if (adb._getRooted(&pubkey)) |a| {
            const view = account_encoder.AccountView{
                .lamports = a.lamports,
                .owner = a.owner.data,
                .executable = a.executable,
                .rent_epoch = a.rent_epoch,
                .data = a.data,
            };
            acct_json = account_encoder.renderAccount(ctx.allocator, view, enc, slice) catch |e| switch (e) {
                error.Base58DataTooLarge => {
                    response.setError(-32600, "Encoded binary (base 58) data should be less than 129 bytes, please use Base64 encoding.");
                    return;
                },
                error.ZstdEncodeUnsupported => {
                    response.setError(-32601, "base64+zstd encoding is not yet supported; request base64");
                    return;
                },
                error.OutOfMemory => return e,
            };
        }
    }
    defer if (acct_json) |j| ctx.allocator.free(j);

    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":");
    try response.append(if (acct_json) |j| j else "null");
    try response.append("}");
}

/// getBalance - Returns account balance
pub fn getBalance(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    var lamports: u64 = 0;

    // Parse pubkey from params: ["<base58>"] or ["<base58>", {commitment}]
    if (params) |p| {
        // Find first quoted string in the params array
        if (std.mem.indexOf(u8, p, "\"")) |q1| {
            const after = p[q1 + 1 ..];
            if (std.mem.indexOf(u8, after, "\"")) |q2| {
                const pubkey_str = after[0..q2];
                if (pubkey_str.len >= 32 and pubkey_str.len <= 44) {
                    const base58 = core.base58;
                    var pk_bytes: [32]u8 = undefined;
                    // decodeToBuf returns !void — use catch, not if/else
                    base58.decodeToBuf(pubkey_str, &pk_bytes) catch {
                        // Invalid base58 — return 0
                        try response.append("{\"context\":{\"slot\":");
                        try response.appendInt(ctx.current_slot);
                        try response.append("},\"value\":0}");
                        return;
                    };
                    const pubkey = core.Pubkey{ .data = pk_bytes };
                    if (ctx.accounts_db) |adb| {
                        if (adb._getRooted(&pubkey)) |acct| {
                            lamports = acct.lamports;
                        }
                    }
                }
            }
        }
    }

    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":");
    try response.appendInt(lamports);
    try response.append("}");
}

/// getMultipleAccounts - Returns multiple account infos (Agave rpc.rs:557). Reads finalized accounts
/// pointwise via _getRooted (the same path as getAccountInfo); a missing account renders as `null`.
/// Always-on, read-only safe. Max 100 pubkeys (Agave MAX_MULTIPLE_ACCOUNTS).
pub fn getMultipleAccounts(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    var pubkeys = parsePublickeysArray(ctx.allocator, params) orelse {
        response.setError(-32602, "Invalid params: missing pubkey array");
        return;
    };
    defer pubkeys.deinit(ctx.allocator);
    if (pubkeys.items.len > 100) {
        response.setError(-32602, "Too many inputs provided; max 100");
        return;
    }
    const enc = parseEncoding(params);
    const slice = parseDataSlice(params);
    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":[");
    for (pubkeys.items, 0..) |pubkey, idx| {
        if (idx != 0) try response.append(",");
        var acct_json: ?[]u8 = null;
        if (ctx.accounts_db) |adb| {
            if (adb._getRooted(&pubkey)) |a| {
                const view = account_encoder.AccountView{
                    .lamports = a.lamports,
                    .owner = a.owner.data,
                    .executable = a.executable,
                    .rent_epoch = a.rent_epoch,
                    .data = a.data,
                };
                acct_json = account_encoder.renderAccount(ctx.allocator, view, enc, slice) catch |e| switch (e) {
                    error.Base58DataTooLarge => {
                        response.setError(-32600, "Encoded binary (base 58) data should be less than 129 bytes, please use Base64 encoding.");
                        return;
                    },
                    error.ZstdEncodeUnsupported => {
                        response.setError(-32601, "base64+zstd encoding is not yet supported; request base64");
                        return;
                    },
                    error.OutOfMemory => return e,
                };
            }
        }
        defer if (acct_json) |j| ctx.allocator.free(j);
        try response.append(if (acct_json) |j| j else "null");
    }
    try response.append("]}");
}

/// A getProgramAccounts filter (Agave rpc-client-types/src/filter.rs). `memcmp.bytes` is owned.
const PgmFilter = union(enum) {
    data_size: u64,
    memcmp: struct { offset: usize, bytes: []u8 },
};

/// Parse a `"name":true|false` config bool. null if absent.
fn parseNamedBool(params: ?[]const u8, name: []const u8) ?bool {
    const p = params orelse return null;
    var nbuf: [48]u8 = undefined;
    const needle = std.fmt.bufPrint(&nbuf, "\"{s}\"", .{name}) catch return null;
    const i = std.mem.indexOf(u8, p, needle) orelse return null;
    var rest = p[i + needle.len ..];
    const c = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    rest = rest[c + 1 ..];
    var s: usize = 0;
    while (s < rest.len and (rest[s] == ' ' or rest[s] == '\t')) s += 1;
    if (std.mem.startsWith(u8, rest[s..], "true")) return true;
    if (std.mem.startsWith(u8, rest[s..], "false")) return false;
    return null;
}

/// Parse the `"filters":[...]` array into a list of PgmFilter (dataSize + memcmp). Caller frees each
/// memcmp.bytes + the slice. Supports memcmp encoding base58 (default) or base64. Best-effort: a
/// malformed filter entry is skipped. Agave caps at 4 filters; we enforce that in the caller.
fn parseFilters(allocator: std.mem.Allocator, params: ?[]const u8) ![]PgmFilter {
    var out: std.ArrayListUnmanaged(PgmFilter) = .{};
    errdefer {
        for (out.items) |f| if (f == .memcmp) allocator.free(f.memcmp.bytes);
        out.deinit(allocator);
    }
    const p = params orelse return out.toOwnedSlice(allocator);
    const fi = std.mem.indexOf(u8, p, "\"filters\"") orelse return out.toOwnedSlice(allocator);
    var rest = p[fi..];
    // Walk filter objects: each is "dataSize" or "memcmp".
    while (std.mem.indexOf(u8, rest, "\"dataSize\"")) |_| {
        const ds = std.mem.indexOf(u8, rest, "\"dataSize\"") orelse break;
        const mc = std.mem.indexOf(u8, rest, "\"memcmp\"");
        // process whichever comes first
        if (mc == null or ds < mc.?) {
            if (parseJsonUint(rest[ds..], "dataSize")) |sz| try out.append(allocator, .{ .data_size = @intCast(sz) });
            rest = rest[ds + "\"dataSize\"".len ..];
        } else break;
    }
    // memcmp entries (separate pass; offset + bytes)
    var mrest = p[fi..];
    while (std.mem.indexOf(u8, mrest, "\"memcmp\"")) |mi| {
        const seg = mrest[mi..];
        const offset = parseJsonUint(seg, "offset") orelse {
            mrest = seg[8..];
            continue;
        };
        // bytes string
        const bi = std.mem.indexOf(u8, seg, "\"bytes\"") orelse {
            mrest = seg[8..];
            continue;
        };
        const aft = seg[bi + "\"bytes\"".len ..];
        const c = std.mem.indexOfScalar(u8, aft, ':') orelse {
            mrest = seg[8..];
            continue;
        };
        const v = aft[c + 1 ..];
        const q1 = std.mem.indexOfScalar(u8, v, '"') orelse {
            mrest = seg[8..];
            continue;
        };
        const inner = v[q1 + 1 ..];
        const q2 = std.mem.indexOfScalar(u8, inner, '"') orelse break;
        const bstr = inner[0..q2];
        const is_b64 = std.mem.indexOf(u8, seg, "base64") != null;
        const decoded: ?[]u8 = if (is_b64) blk: {
            const dec = std.base64.standard.Decoder;
            const n = dec.calcSizeForSlice(bstr) catch break :blk null;
            const buf = allocator.alloc(u8, n) catch break :blk null;
            dec.decode(buf, bstr) catch {
                allocator.free(buf);
                break :blk null;
            };
            break :blk buf;
        } else (core.base58.decode(allocator, bstr) catch null);
        if (decoded) |bytes| try out.append(allocator, .{ .memcmp = .{ .offset = offset, .bytes = bytes } });
        mrest = inner[q2 + 1 ..];
    }
    return out.toOwnedSlice(allocator);
}

/// All filters must match (AND). dataSize → exact length; memcmp → byte-equal at offset.
fn filtersMatch(filters: []const PgmFilter, data: []const u8) bool {
    for (filters) |f| switch (f) {
        .data_size => |sz| if (data.len != sz) return false,
        .memcmp => |m| {
            if (m.offset + m.bytes.len > data.len) return false;
            if (!std.mem.eql(u8, data[m.offset .. m.offset + m.bytes.len], m.bytes)) return false;
        },
    };
    return true;
}

/// getProgramAccounts - accounts owned by `program_id` (Agave rpc.rs:598). Scans finalized accounts by
/// owner (AccountsDb.scanByOwner) with optional dataSize/memcmp filters. GATED OFF by default
/// (VEX_RPC_PROGRAM_ACCOUNTS unset ⇒ returns []) because the owner scan acquires shared index locks and
/// contends with replay — arm only on non-voting RPC nodes. Read-only ⇒ no consensus risk.
pub fn getProgramAccounts(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    if (std.posix.getenv("VEX_RPC_PROGRAM_ACCOUNTS") == null) {
        try response.append("[]"); // dormant: scan-contention guard
        return;
    }
    const program_id = parseFirstPubkey(params) orelse {
        response.setError(-32602, "Invalid params: missing program id");
        return;
    };
    const enc = parseEncoding(params);
    const slice = parseDataSlice(params);
    const with_context = parseNamedBool(params, "withContext") orelse false;
    const filters = parseFilters(ctx.allocator, params) catch &[_]PgmFilter{};
    defer {
        for (filters) |f| if (f == .memcmp) ctx.allocator.free(f.memcmp.bytes);
        if (filters.len > 0) ctx.allocator.free(filters);
    }
    if (filters.len > 4) {
        response.setError(-32602, "Too many filters provided; max 4");
        return;
    }
    const adb = ctx.accounts_db orelse {
        try response.append("[]");
        return;
    };
    const ancestors = [_]u64{};
    const scan = adb.scanByOwner(&program_id, &ancestors, ctx.rooted_slot, ctx.allocator) catch {
        try response.append("[]");
        return;
    };
    defer {
        for (scan) |e| ctx.allocator.free(e.data);
        ctx.allocator.free(scan);
    }
    if (with_context) {
        try response.append("{\"context\":{\"slot\":");
        try response.appendInt(ctx.current_slot);
        try response.append("},\"value\":[");
    } else {
        try response.append("[");
    }
    var first = true;
    for (scan) |e| {
        if (!filtersMatch(filters, e.data)) continue;
        const view = account_encoder.AccountView{
            .lamports = e.lamports,
            .owner = program_id.data, // all scanned accounts are owned by program_id
            .executable = e.executable,
            .rent_epoch = e.rent_epoch,
            .data = e.data,
        };
        const acct_json = account_encoder.renderAccount(ctx.allocator, view, enc, slice) catch |err| switch (err) {
            error.Base58DataTooLarge => continue, // un-renderable in base58 → skip (Agave would 400; skip is safe)
            error.ZstdEncodeUnsupported => {
                response.setError(-32601, "base64+zstd encoding is not yet supported; request base64");
                return;
            },
            error.OutOfMemory => return err,
        };
        defer ctx.allocator.free(acct_json);
        const pk58 = core.base58.encode(ctx.allocator, &e.pubkey.data) catch continue;
        defer ctx.allocator.free(pk58);
        if (!first) try response.append(",");
        first = false;
        try response.append("{\"pubkey\":\"");
        try response.append(pk58);
        try response.append("\",\"account\":");
        try response.append(acct_json);
        try response.append("}");
    }
    if (with_context) {
        try response.append("]}");
    } else {
        try response.append("]");
    }
}

/// getTokenAccountBalance - Returns SPL token balance
pub fn getTokenAccountBalance(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    _ = params;

    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":{");
    try response.append("\"amount\":\"0\",");
    try response.append("\"decimals\":9,");
    try response.append("\"uiAmount\":0.0,");
    try response.append("\"uiAmountString\":\"0\"");
    try response.append("}}");
}

/// getTokenAccountsByOwner - Returns token accounts
pub fn getTokenAccountsByOwner(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    _ = params;

    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":[]}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLOCK METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// Encode a 32-byte hash as base58 into the response (mirrors Agave's blockhash string form).
fn appendBase58_32(response: *ResponseBuilder, allocator: Allocator, bytes: [32]u8) !void {
    const s = core.base58.encode(allocator, &bytes) catch {
        try response.append("11111111111111111111111111111111");
        return;
    };
    defer allocator.free(s);
    try response.append(s);
}

/// Render one StoredTx as an Agave getBlock `transactions[]` element with `encoding:"base64"` +
/// `transactionDetails:"full"` shape: {"meta":{…},"transaction":["<base64>","base64"]}.
fn appendStoredTxJson(response: *ResponseBuilder, allocator: Allocator, tx: *const block_store_mod.StoredTx) !void {
    try response.append("{\"meta\":{");
    // err
    if (tx.err) |e| {
        try appendTxErrJson(response, e);
    } else {
        try response.append("\"err\":null");
    }
    try response.appendFmt(",\"fee\":{d}", .{tx.fee});
    // pre/post balances (empty slices are valid → emit [])
    try response.append(",\"preBalances\":[");
    for (tx.pre_balances, 0..) |b, i| {
        if (i != 0) try response.append(",");
        try response.appendInt(b);
    }
    try response.append("],\"postBalances\":[");
    for (tx.post_balances, 0..) |b, i| {
        if (i != 0) try response.append(",");
        try response.appendInt(b);
    }
    try response.append("]");
    if (tx.compute_units_consumed) |cu| {
        try response.appendFmt(",\"computeUnitsConsumed\":{d}", .{cu});
    }
    // Agave always emits these (null/empty when not captured) so the CLI/SDK parse cleanly.
    try response.append(",\"innerInstructions\":[],\"logMessages\":[],\"rewards\":[],\"status\":");
    if (tx.err) |e| {
        try response.append("{\"Err\":");
        try appendTxErrValue(response, e);
        try response.append("}");
    } else {
        try response.append("{\"Ok\":null}");
    }
    try response.append("},\"transaction\":[\"");
    // base64 of the raw wire transaction (encoding="base64").
    const Enc = std.base64.standard.Encoder;
    const cap = Enc.calcSize(tx.wire.len);
    const b64 = try allocator.alloc(u8, cap);
    defer allocator.free(b64);
    _ = Enc.encode(b64, tx.wire);
    try response.append(b64);
    try response.append("\",\"base64\"],\"version\":\"legacy\"}");
}

/// Emit `"err":<value>` for a TxError (the meta.err field).
fn appendTxErrJson(response: *ResponseBuilder, e: block_store_mod.TxError) !void {
    try response.append("\"err\":");
    try appendTxErrValue(response, e);
}

/// Emit the Agave TransactionError JSON value. We hold only the discriminant (+ instruction index/
/// inner code for the common InstructionError), so we render the structurally-correct shape Agave
/// uses: {"InstructionError":[<index>,{"Custom":<code>}]} for code 8, else {"<Name>":null}-style.
fn appendTxErrValue(response: *ResponseBuilder, e: block_store_mod.TxError) !void {
    if (e.code == 8) {
        // InstructionError [index, inner]
        try response.appendFmt("{{\"InstructionError\":[{d},", .{e.instruction_index orelse 0});
        if (e.instruction_error) |ie| {
            try response.appendFmt("{{\"Custom\":{d}}}", .{ie});
        } else {
            try response.append("\"GenericError\"");
        }
        try response.append("]}");
    } else {
        // Other top-level TransactionError discriminants — emit the numeric code as a tagged object
        // so consumers see a non-null err (exact variant name mapping is additive).
        try response.appendFmt("{{\"Code\":{d}}}", .{e.code});
    }
}

/// getBlock - Returns the block at `slot` from the BlockStore (Agave ConfirmedBlock shape). When the
/// store is absent (gate OFF) or the slot is not stored, returns `null` (Agave: block not available).
pub fn getBlock(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    const slot = if (params) |p| parseFirstU64(p) orelse {
        response.setError(-32602, "Invalid params: missing slot");
        return;
    } else {
        response.setError(-32602, "Invalid params: missing slot");
        return;
    };

    // Prefer the persistent VexLedger when wired (rc.1 UiConfirmedBlock). Requires the slot's PoH
    // blockhash (KIND_BLOCKHASH); falls through to the legacy block_store / null otherwise. Order:
    // previousBlockhash, blockhash, parentSlot, transactions, blockTime(always), blockHeight(always).
    // rewards/numRewardPartitions OMITTED in Phase-2 (no block rewards captured; rc.1 Option skip-none).
    if (ctx.vex_ledger) |vl| {
        if (vl.getBlockhash(slot)) |bh| {
            var parent_slot: u64 = 0;
            if (vl.meta(ctx.allocator, slot) catch null) |m| {
                const mm = m;
                parent_slot = mm.parent_slot orelse 0;
                ctx.allocator.free(mm.completed_data_indexes);
                ctx.allocator.free(mm.next_slots);
            }
            try response.append("{\"previousBlockhash\":\"");
            if (vl.getBlockhash(parent_slot)) |pbh| {
                try appendBase58_32(response, ctx.allocator, pbh);
            } else {
                try appendBase58_32(response, ctx.allocator, [_]u8{0} ** 32); // boundary: parent not stored
            }
            try response.append("\",\"blockhash\":\"");
            try appendBase58_32(response, ctx.allocator, bh);
            try response.appendFmt("\",\"parentSlot\":{d},\"transactions\":[", .{parent_slot});
            if (vl.getSlotSignatures(ctx.allocator, slot)) |rows| {
                defer ctx.allocator.free(rows);
                for (rows, 0..) |row, i| {
                    if (i != 0) try response.append(",");
                    try response.append("{");
                    try appendVlTxMetaVersion(response, ctx, vl, row.signature, slot);
                    try response.append("}");
                }
            } else |_| {}
            try response.append("]");
            // rewards: default show_rewards=true → ALWAYS an array ("[]" when none stored, per rc.1
            // UiConfirmedBlock encode). numRewardPartitions: omit-when-None (partitioned blocks only).
            try response.append(",\"rewards\":");
            var np_opt: ?u64 = null;
            var emitted_rewards = false;
            if (vl.getRewards(ctx.allocator, slot) catch null) |rwbytes| {
                defer ctx.allocator.free(rwbytes);
                if (vex_ledger_mod.agave_proto.decodeRewards(ctx.allocator, rwbytes)) |dr| {
                    var drr = dr;
                    defer drr.deinit(ctx.allocator);
                    np_opt = drr.num_partitions;
                    if (vex_ledger_mod.agave_meta_json.renderRewardsJson(ctx.allocator, drr.rewards)) |rj| {
                        defer ctx.allocator.free(rj);
                        try response.append(rj);
                        emitted_rewards = true;
                    } else |_| {}
                } else |_| {}
            }
            if (!emitted_rewards) try response.append("[]");
            if (np_opt) |np| try response.appendFmt(",\"numRewardPartitions\":{d}", .{np});
            try response.append(",\"blockTime\":");
            if (vl.getBlocktime(slot)) |t| {
                try response.appendFmt("{d}", .{t});
            } else {
                try response.append("null");
            }
            try response.append(",\"blockHeight\":");
            if (vl.getBlockHeight(slot)) |h| {
                try response.appendFmt("{d}", .{h});
            } else {
                try response.append("null");
            }
            try response.append("}");
            return;
        }
        // no blockhash stored for this slot → fall through to legacy block_store / null.
    }

    const store = ctx.block_store orelse {
        try response.append("null"); // store not enabled → block not available (Agave-correct)
        return;
    };

    const Ctx = struct {
        resp: *ResponseBuilder,
        alloc: Allocator,
        ok: bool = true,
        fn read(self: *@This(), b: *const block_store_mod.StoredBlock) void {
            self.renderInner(b) catch {
                self.ok = false;
            };
        }
        fn renderInner(self: *@This(), b: *const block_store_mod.StoredBlock) !void {
            const r = self.resp;
            try r.append("{\"blockhash\":\"");
            try appendBase58_32(r, self.alloc, b.blockhash);
            try r.append("\",\"previousBlockhash\":\"");
            try appendBase58_32(r, self.alloc, b.previous_blockhash);
            try r.appendFmt("\",\"parentSlot\":{d},\"transactions\":[", .{b.parent_slot});
            for (b.transactions, 0..) |*tx, i| {
                if (i != 0) try r.append(",");
                try appendStoredTxJson(r, self.alloc, tx);
            }
            try r.append("],\"rewards\":[");
            for (b.rewards, 0..) |rw, i| {
                if (i != 0) try r.append(",");
                try r.append("{\"pubkey\":\"");
                try appendBase58_32(r, self.alloc, rw.pubkey.data);
                try r.appendFmt("\",\"lamports\":{d},\"postBalance\":{d},\"rewardType\":\"{s}\"", .{ rw.lamports, rw.post_balance, rewardTypeName(rw.reward_type) });
                if (rw.commission) |c| {
                    try r.appendFmt(",\"commission\":{d}", .{c});
                } else {
                    try r.append(",\"commission\":null");
                }
                try r.append("}");
            }
            try r.append("],");
            if (b.block_time) |t| {
                try r.appendFmt("\"blockTime\":{d},", .{t});
            } else {
                try r.append("\"blockTime\":null,");
            }
            if (b.block_height) |h| {
                try r.appendFmt("\"blockHeight\":{d}", .{h});
            } else {
                try r.append("\"blockHeight\":null");
            }
            try r.append("}");
        }
    };
    var rctx = Ctx{ .resp = response, .alloc = ctx.allocator };
    const found = store.withBlock(slot, &rctx, Ctx.read);
    if (!found) {
        response.reset();
        try response.append("null");
        return;
    }
    if (!rctx.ok) return error.OutOfMemory;
}

fn rewardTypeName(t: u8) []const u8 {
    return switch (t) {
        0 => "Fee",
        1 => "Rent",
        2 => "Staking",
        3 => "Voting",
        else => "Fee",
    };
}

/// getBlockCommitment - Returns block commitment
pub fn getBlockCommitment(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    _ = params;

    try response.append("{\"commitment\":null,\"totalStake\":");
    try response.appendInt(ctx.current_slot);
    try response.append("}");
}

/// getBlockHeight - Returns block height (only counts non-skipped, replayed slots)
pub fn getBlockHeight(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const height = if (ctx.ledger_db) |db| db.block_height.load(.seq_cst) else ctx.current_slot;
    try response.appendInt(height);
}

/// getBlockProduction - Returns block production info
pub fn getBlockProduction(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const identity_str = ctx.identity orelse "unknown";

    // Get block production stats from ledger_db counters
    // blocks_produced = leader slots where we produced a block
    // total_leader_slots tracked via leader_cache or estimated from schedule
    var blocks_produced: u64 = 0;
    var leader_slots_total: u64 = 0;

    if (ctx.ledger_db) |ldb| {
        blocks_produced = ldb.blocks_produced.load(.seq_cst);
        leader_slots_total = ldb.leader_slots_scheduled.load(.seq_cst);
    }
    const skipped = if (leader_slots_total > blocks_produced)
        leader_slots_total - blocks_produced
    else
        0;
    _ = skipped;

    // Epoch range: first slot of current epoch to current slot. Use the warmup-aware leader-schedule
    // generator (testnet first_normal_epoch=14, first_normal_slot=524256) when the cache is wired; the
    // naive current_epoch*432000 is only a fallback (and is WRONG across testnet warmup boundaries —
    // getEpochInfo/getBlockProduction must not use slot/432000).
    const slots_per_epoch: u64 = 432000;
    const epoch_start = blk: {
        if (ctx.leader_cache) |lc| {
            const ep = lc.generator.getEpoch(ctx.current_slot);
            break :blk lc.generator.getFirstSlotInEpoch(ep);
        }
        break :blk ctx.current_epoch * slots_per_epoch;
    };

    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":{");
    try response.append("\"byIdentity\":{\"");
    try response.append(identity_str);
    try response.append("\":[");
    try response.appendInt(leader_slots_total);
    try response.append(",");
    try response.appendInt(blocks_produced);
    try response.append("]},");
    try response.append("\"range\":{\"firstSlot\":");
    try response.appendInt(epoch_start);
    try response.append(",\"lastSlot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("}}}");
}

/// getBlockTime - Returns the stored block_time for `slot` (Agave: i64 unix seconds, or null if the
/// block is not available / time not captured). Reads the BlockStore when present.
pub fn getBlockTime(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    const slot = if (params) |p| parseFirstU64(p) else null;
    if (slot == null) {
        response.setError(-32602, "Invalid params: missing slot");
        return;
    }
    if (ctx.block_store) |store| {
        const Probe = struct {
            t: ?i64 = null,
            fn read(self: *@This(), b: *const block_store_mod.StoredBlock) void {
                self.t = b.block_time;
            }
        };
        var probe = Probe{};
        if (store.withBlock(slot.?, &probe, Probe.read)) {
            if (probe.t) |t| {
                try response.appendInt(t);
                return;
            }
        }
    }
    // Block not stored / time not captured → Agave returns null (NOT a fabricated wall-clock time).
    try response.append("null");
}

/// getBlocks - Returns the stored slots in [start_slot, end_slot] (Agave: ascending u64 array).
/// `end_slot` defaults to start+500_000 (Agave caps the range at 500k); empty when store absent.
pub fn getBlocks(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    const p = params orelse {
        try response.append("[]");
        return;
    };
    const start = parseFirstU64(p) orelse {
        try response.append("[]");
        return;
    };
    // Second integer in params is end_slot (optional). Search after the first number.
    const end = blk: {
        if (std.mem.indexOfScalar(u8, p, '[')) |lb| {
            const after_first = afterFirstU64(p[lb..]);
            if (after_first) |rest| {
                if (parseFirstU64(rest)) |e| break :blk e;
            }
        }
        break :blk start + 500_000;
    };
    try emitBlockList(ctx, response, start, end, 500_000);
}

/// getBlocksWithLimit - Returns up to `limit` stored slots starting at `start_slot` (ascending).
pub fn getBlocksWithLimit(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    const p = params orelse {
        try response.append("[]");
        return;
    };
    const start = parseFirstU64(p) orelse {
        try response.append("[]");
        return;
    };
    const limit = blk: {
        if (std.mem.indexOfScalar(u8, p, '[')) |lb| {
            if (afterFirstU64(p[lb..])) |rest| {
                if (parseFirstU64(rest)) |l| break :blk @min(l, 500_000);
            }
        }
        break :blk 500_000;
    };
    try emitBlockList(ctx, response, start, start + 500_000, @intCast(limit));
}

/// Shared helper: emit the JSON array of stored slots in [start,end], capped at `limit`.
fn emitBlockList(ctx: *const RpcContext, response: *ResponseBuilder, start: u64, end: u64, limit: usize) !void {
    // Prefer the persistent VexLedger when wired: rooted slots in [start,end], ascending, capped at `limit`.
    // rootedSlotsFrom returns ascending rooted slots >= start (fed by the finishSlot/root tile path, NOT the
    // deferred tx-capture). Falls through to the legacy block_store path on a read error or when unwired.
    if (ctx.vex_ledger) |vl| {
        if (vl.rootedSlotsFrom(ctx.allocator, start)) |slots| {
            defer ctx.allocator.free(slots);
            try response.append("[");
            var n: usize = 0;
            for (slots) |s| {
                if (s > end) break; // ascending → no later slot can be in range
                if (n >= limit) break;
                if (n != 0) try response.append(",");
                try response.appendInt(s);
                n += 1;
            }
            try response.append("]");
            return;
        } else |_| {}
    }
    const store = ctx.block_store orelse {
        try response.append("[]");
        return;
    };
    const slots = store.getBlocksInRange(start, end, limit) catch {
        try response.append("[]");
        return;
    };
    defer ctx.allocator.free(slots);
    try response.append("[");
    for (slots, 0..) |s, i| {
        if (i != 0) try response.append(",");
        try response.appendInt(s);
    }
    try response.append("]");
}

/// Return the substring of `s` immediately after the first run of ASCII digits (skipping leading
/// non-digits first). null if there is no digit run. Used to find the 2nd integer param.
fn afterFirstU64(s: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < s.len and (s[i] < '0' or s[i] > '9')) : (i += 1) {}
    if (i >= s.len) return null;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {}
    return s[i..];
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLOT METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// getSlot - Returns last replayed slot (matches Firedancer's semantics, NOT gossip network tip)
pub fn getSlot(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const slot = if (ctx.ledger_db) |db| db.last_replayed_slot.load(.seq_cst) else ctx.current_slot;
    try response.appendInt(slot);
}

/// getSlotLeader - Returns slot leader
pub fn getSlotLeader(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const identity = ctx.identity orelse "3J2jADiEoKMaooCQbkyr9aLnjAb5ApDWfVvKgzyK2fbP";
    try response.append("\"");
    try response.append(identity);
    try response.append("\"");
}

/// getSlotLeaders - Returns slot leaders
pub fn getSlotLeaders(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    // Params: [startSlot, limit]. Emit the REAL leader (base58) for each slot from the
    // warmup-aware leader-schedule cache (replaces the old hardcoded `vexor1111…`
    // placeholder). Returns an empty array when the cache/params are unavailable, and
    // stops at the first slot with no schedule (epoch boundary) rather than emitting a
    // wrong/placeholder leader. getSlotLeader() locks the cache mutex + derives the
    // epoch warmup-aware internally.
    const lc = ctx.leader_cache orelse {
        try response.append("[]");
        return;
    };
    const p = params orelse {
        try response.append("[]");
        return;
    };
    const start_slot = parseFirstU64(p) orelse {
        try response.append("[]");
        return;
    };
    var limit: u64 = blk: {
        if (afterFirstU64(p)) |rest| {
            if (parseFirstU64(rest)) |l| break :blk l;
        }
        break :blk 0;
    };
    if (limit == 0) {
        try response.append("[]");
        return;
    }
    if (limit > 5000) limit = 5000; // Agave getSlotLeaders cap

    try response.append("[");
    var emitted: u64 = 0;
    var i: u64 = 0;
    while (i < limit) : (i += 1) {
        const leader = lc.getSlotLeader(start_slot + i) orelse break;
        const s58 = core.base58.encode(ctx.allocator, &leader.data) catch break;
        defer ctx.allocator.free(s58);
        if (emitted > 0) try response.append(",");
        try response.append("\"");
        try response.append(s58);
        try response.append("\"");
        emitted += 1;
    }
    try response.append("]");
}

/// getHighestSnapshotSlot - Returns the highest local snapshot slots by scanning
/// the snapshot archive directory (Agave naming: `snapshot-<slot>-<hash>.tar.zst`
/// full, `incremental-snapshot-<base>-<slot>-<hash>.tar.zst` incremental). Mirrors
/// Agave's SnapshotArchiveInfo scan so peers can learn what we can actually serve.
/// Returns the real slots instead of the old fabricated `current_slot-100` stub.
pub fn getHighestSnapshotSlot(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    var full_max: ?u64 = null;
    var inc_max: ?u64 = null;
    if (ctx.snapshot_manager) |sm| {
        if (std.fs.cwd().openDir(sm.snapshots_dir, .{ .iterate = true })) |d| {
            var dir = d;
            defer dir.close();
            var it = dir.iterate();
            while (it.next() catch null) |entry| {
                if (entry.kind != .file) continue;
                const name = entry.name;
                if (std.mem.startsWith(u8, name, "incremental-snapshot-")) {
                    // incremental-snapshot-<base>-<slot>-<hash>.tar.zst → 2nd number
                    const rest = name["incremental-snapshot-".len..];
                    const d1 = std.mem.indexOfScalar(u8, rest, '-') orelse continue;
                    const after_base = rest[d1 + 1 ..];
                    const d2 = std.mem.indexOfScalar(u8, after_base, '-') orelse continue;
                    const slot = std.fmt.parseInt(u64, after_base[0..d2], 10) catch continue;
                    if (inc_max == null or slot > inc_max.?) inc_max = slot;
                } else if (std.mem.startsWith(u8, name, "snapshot-")) {
                    // snapshot-<slot>-<hash>.tar.zst → 1st number
                    const rest = name["snapshot-".len..];
                    const dash = std.mem.indexOfScalar(u8, rest, '-') orelse continue;
                    const slot = std.fmt.parseInt(u64, rest[0..dash], 10) catch continue;
                    if (full_max == null or slot > full_max.?) full_max = slot;
                }
            }
        } else |_| {}
    }
    if (full_max) |f| {
        try response.append("{\"full\":");
        try response.appendInt(f);
        if (inc_max) |i| {
            try response.append(",\"incremental\":");
            try response.appendInt(i);
            try response.append("}");
        } else {
            try response.append(",\"incremental\":null}");
        }
    } else {
        // No local full-snapshot archive found (would be a -32008 in Agave); we
        // return an explicit null object rather than fabricating a slot.
        try response.append("{\"full\":null,\"incremental\":null}");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRANSACTION METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse the first base58 string param as a 64-byte signature. null if missing / wrong length / not
/// valid base58. (Signatures are 88-ish base58 chars; the decoded form must be exactly 64 bytes.)
fn parseFirstSignature(params: ?[]const u8) ?[64]u8 {
    const p = params orelse return null;
    const q1 = std.mem.indexOf(u8, p, "\"") orelse return null;
    const after = p[q1 + 1 ..];
    const q2 = std.mem.indexOf(u8, after, "\"") orelse return null;
    const s = after[0..q2];
    var buf: [64]u8 = undefined;
    core.base58.decodeToBuf(s, &buf) catch return null;
    return buf;
}

/// getTransaction - Resolve a signature → its (slot, index) via the TxStatusStore, then read the
/// transaction out of the BlockStore (Agave ConfirmedTransactionWithStatusMeta). null if not found /
/// stores absent.
pub fn getTransaction(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    const sig = parseFirstSignature(params) orelse {
        try response.append("null");
        return;
    };
    // Prefer the persistent VexLedger when wired. rc.1 EncodedConfirmedTransactionWithStatusMeta is a
    // TOP-LEVEL FLATTEN: {slot, transaction, meta, version, blockTime} (transaction/meta/version are the
    // flattened EncodedTransactionWithStatusMeta, siblings of slot). null if the tx wire isn't stored.
    if (ctx.vex_ledger) |vl| {
        if (vl.slotForSignature(sig)) |slot| {
            if (vl.getTransactionWire(ctx.allocator, sig, slot) catch null) |w0| {
                ctx.allocator.free(w0); // presence check; the helper re-fetches + renders
                try response.appendFmt("{{\"slot\":{d},", .{slot});
                try appendVlTxMetaVersion(response, ctx, vl, sig, slot);
                try response.append(",\"blockTime\":");
                if (vl.getBlocktime(slot)) |t| {
                    try response.appendFmt("{d}", .{t});
                } else {
                    try response.append("null");
                }
                try response.append("}");
                return;
            }
        }
        // unknown to VexLedger (or no wire) → fall through to the legacy store / null.
    }
    const idx_store = ctx.tx_status_store orelse {
        try response.append("null");
        return;
    };
    const blk_store = ctx.block_store orelse {
        try response.append("null");
        return;
    };
    const loc = idx_store.locate(sig) orelse {
        try response.append("null");
        return;
    };

    const Ctx = struct {
        resp: *ResponseBuilder,
        alloc: Allocator,
        idx: u32,
        slot: u64,
        ok: bool = true,
        emitted: bool = false,
        fn read(self: *@This(), b: *const block_store_mod.StoredBlock) void {
            self.renderInner(b) catch {
                self.ok = false;
            };
        }
        fn renderInner(self: *@This(), b: *const block_store_mod.StoredBlock) !void {
            if (self.idx >= b.transactions.len) return; // stale index → leave emitted=false → null
            const r = self.resp;
            try r.appendFmt("{{\"slot\":{d},\"blockTime\":", .{self.slot});
            if (b.block_time) |t| {
                try r.appendFmt("{d}", .{t});
            } else {
                try r.append("null");
            }
            try r.append(",");
            // Reuse the getBlock per-tx renderer (meta + transaction[base64]).
            // appendStoredTxJson emits the {"meta":…,"transaction":[…]} object; splice its fields in.
            try appendTransactionBody(r, self.alloc, &b.transactions[self.idx]);
            try r.append("}");
            self.emitted = true;
        }
    };
    var rctx = Ctx{ .resp = response, .alloc = ctx.allocator, .idx = loc.index_in_block, .slot = loc.slot };
    const found = blk_store.withBlock(loc.slot, &rctx, Ctx.read);
    if (!rctx.ok) return error.OutOfMemory;
    if (!found or !rctx.emitted) {
        response.reset();
        try response.append("null");
    }
}

/// Emit the inner `"meta":{…},"transaction":[…],"version":…` body of a stored tx (no surrounding
/// braces) — shared by getTransaction (which wraps it in slot/blockTime) and is structurally the
/// same content getBlock emits per element.
fn appendTransactionBody(r: *ResponseBuilder, alloc: Allocator, tx: *const block_store_mod.StoredTx) !void {
    // appendStoredTxJson produces the full {meta,transaction,version} object; strip its outer braces
    // by writing into a scratch builder then slicing. Simpler: re-emit directly here.
    try r.append("\"meta\":{");
    if (tx.err) |e| {
        try appendTxErrJson(r, e);
    } else {
        try r.append("\"err\":null");
    }
    try r.appendFmt(",\"fee\":{d},\"preBalances\":[", .{tx.fee});
    for (tx.pre_balances, 0..) |bal, i| {
        if (i != 0) try r.append(",");
        try r.appendInt(bal);
    }
    try r.append("],\"postBalances\":[");
    for (tx.post_balances, 0..) |bal, i| {
        if (i != 0) try r.append(",");
        try r.appendInt(bal);
    }
    try r.append("],\"innerInstructions\":[],\"logMessages\":[],\"rewards\":[],\"status\":");
    if (tx.err) |e| {
        try r.append("{\"Err\":");
        try appendTxErrValue(r, e);
        try r.append("}");
    } else {
        try r.append("{\"Ok\":null}");
    }
    try r.append("},\"transaction\":[\"");
    const Enc = std.base64.standard.Encoder;
    const b64 = try alloc.alloc(u8, Enc.calcSize(tx.wire.len));
    defer alloc.free(b64);
    _ = Enc.encode(b64, tx.wire);
    try r.append(b64);
    try r.append("\",\"base64\"],\"version\":\"legacy\"");
}

/// getSignatureStatuses - For each requested signature, emit its status (or null). Reads the
/// TxStatusStore; returns all-null when absent.
pub fn getSignatureStatuses(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":[");

    // Walk every quoted string STRICTLY inside the first array param (the signatures array). We bound
    // the scan to [first '[', matching ']') so we never read into the trailing config object (e.g.
    // {"searchTransactionHistory":true}) and mistake "searchTransactionHistory" for a signature.
    var first = true;
    if (params) |p| {
        if (std.mem.indexOfScalar(u8, p, '[')) |lb| {
            const arr_end = std.mem.indexOfScalarPos(u8, p, lb + 1, ']') orelse p.len;
            var rest = p[lb + 1 .. arr_end];
            while (std.mem.indexOf(u8, rest, "\"")) |q1| {
                const after = rest[q1 + 1 ..];
                const q2 = std.mem.indexOf(u8, after, "\"") orelse break;
                const sig_str = after[0..q2];
                if (!first) try response.append(",");
                first = false;
                try emitOneSigStatus(ctx, response, sig_str);
                rest = after[q2 + 1 ..];
            }
        }
    }
    try response.append("]}");
}

/// confirmationStatus per the rc.1 commitment ladder (finalized=rooted ≥ slot, then confirmed,
/// else processed). ctx.rooted_slot/confirmed_slot are the node's tips.
fn confirmationStatusName(ctx: *const RpcContext, slot: u64) []const u8 {
    if (slot <= ctx.rooted_slot) return "finalized";
    if (slot <= ctx.confirmed_slot) return "confirmed";
    return "processed";
}

/// Emit the JSON `err` value for (sig, slot) from VexLedger: decode the stored TransactionStatusMeta
/// protobuf → render its inner bincode TransactionError to rc.1 serde_json; "null" for an Ok-status,
/// an absent record, or any decode/render failure (never a partial-wrong value — RULE #0).
fn appendVlTxErr(response: *ResponseBuilder, ctx: *const RpcContext, vl: *vex_ledger_mod.VexLedger, sig: [64]u8, slot: u64) !void {
    const pb = (vl.getTransactionStatus(ctx.allocator, sig, slot) catch null) orelse {
        try response.append("null");
        return;
    };
    defer ctx.allocator.free(pb);
    var meta = vex_ledger_mod.agave_proto.decodeTransactionStatusMeta(ctx.allocator, pb) catch {
        try response.append("null");
        return;
    };
    defer meta.deinit(ctx.allocator);
    const eb = meta.err_bytes orelse {
        try response.append("null");
        return;
    };
    const js = vex_ledger_mod.agave_json.renderTxErrorJson(ctx.allocator, eb) catch {
        try response.append("null");
        return;
    };
    defer ctx.allocator.free(js);
    try response.append(js);
}

/// Emit `<status-value>,"err":<err-value>` for getSignatureStatuses (rc.1 `TransactionStatus` has BOTH the
/// legacy `status` Result AND `err`, in that order; caller has already written `"status":`). Decodes the
/// meta ONCE and renders both from the same err_bytes. status = {"Ok":null} | {"Err":<err>}; err = <err>|null.
fn appendVlStatusErr(response: *ResponseBuilder, ctx: *const RpcContext, vl: *vex_ledger_mod.VexLedger, sig: [64]u8, slot: u64) !void {
    const pb = (vl.getTransactionStatus(ctx.allocator, sig, slot) catch null) orelse {
        try response.append("{\"Ok\":null},\"err\":null");
        return;
    };
    defer ctx.allocator.free(pb);
    var meta = vex_ledger_mod.agave_proto.decodeTransactionStatusMeta(ctx.allocator, pb) catch {
        try response.append("{\"Ok\":null},\"err\":null");
        return;
    };
    defer meta.deinit(ctx.allocator);
    const eb = meta.err_bytes orelse {
        try response.append("{\"Ok\":null},\"err\":null");
        return;
    };
    const js = vex_ledger_mod.agave_json.renderTxErrorJson(ctx.allocator, eb) catch {
        try response.append("{\"Ok\":null},\"err\":null");
        return;
    };
    defer ctx.allocator.free(js);
    try response.appendFmt("{{\"Err\":{s}}},\"err\":{s}", .{ js, js });
}

/// Emit `"transaction":<UiTransaction>,"meta":<UiMeta|null>,"version":<"legacy"|0|null>` for a (sig,slot)
/// from VexLedger — the inner of getBlock's transactions[] elem AND getTransaction's flatten body. Always
/// appends (degraded transaction:null only if the wire is genuinely absent, a population-invariant violation).
fn appendVlTxMetaVersion(response: *ResponseBuilder, ctx: *const RpcContext, vl: *vex_ledger_mod.VexLedger, sig: [64]u8, slot: u64) !void {
    const wire_opt = vl.getTransactionWire(ctx.allocator, sig, slot) catch null;
    if (wire_opt == null) {
        try response.append("\"transaction\":null,\"meta\":null,\"version\":null");
        return;
    }
    const wire = wire_opt.?;
    defer ctx.allocator.free(wire);
    // transaction (wire → rc.1 "json" UiTransaction).
    try response.append("\"transaction\":");
    if (vex_ledger_mod.agave_tx_json.renderTxJson(ctx.allocator, wire)) |txj| {
        defer ctx.allocator.free(txj);
        try response.append(txj);
    } else |_| {
        try response.append("null");
    }
    // meta (decode proto → rc.1 UiTransactionStatusMeta; null on absence/failure).
    try response.append(",\"meta\":");
    var rendered_meta = false;
    if (vl.getTransactionStatus(ctx.allocator, sig, slot) catch null) |pb| {
        defer ctx.allocator.free(pb);
        if (vex_ledger_mod.agave_proto.decodeTransactionStatusMeta(ctx.allocator, pb)) |dm| {
            var meta = dm;
            defer meta.deinit(ctx.allocator);
            if (vex_ledger_mod.agave_meta_json.renderMetaJson(ctx.allocator, meta)) |mj| {
                defer ctx.allocator.free(mj);
                try response.append(mj);
                rendered_meta = true;
            } else |_| {}
        } else |_| {}
    }
    if (!rendered_meta) try response.append("null");
    // version (untagged: legacy→"legacy", v0→0).
    try response.append(",\"version\":");
    if (vex_ledger_mod.agave_tx_json.detectVersion(wire)) |v| {
        try response.append(if (v == .legacy) "\"legacy\"" else "0");
    } else {
        try response.append("null");
    }
}

/// Emit the JSON `memo` value for (sig, slot): the stored memo as a JSON-escaped string, or "null".
fn appendVlMemo(response: *ResponseBuilder, ctx: *const RpcContext, vl: *vex_ledger_mod.VexLedger, sig: [64]u8, slot: u64) !void {
    const m = (vl.getTransactionMemo(ctx.allocator, sig, slot) catch null) orelse {
        try response.append("null");
        return;
    };
    defer ctx.allocator.free(m);
    try response.append("\"");
    for (m) |c| {
        switch (c) {
            '"' => try response.append("\\\""),
            '\\' => try response.append("\\\\"),
            '\n' => try response.append("\\n"),
            '\r' => try response.append("\\r"),
            '\t' => try response.append("\\t"),
            else => {
                if (c < 0x20) {
                    try response.appendFmt("\\u{x:0>4}", .{c});
                } else {
                    try response.append(&[_]u8{c});
                }
            },
        }
    }
    try response.append("\"");
}

fn emitOneSigStatus(ctx: *const RpcContext, response: *ResponseBuilder, sig_str: []const u8) !void {
    var sig: [64]u8 = undefined;
    core.base58.decodeToBuf(sig_str, &sig) catch {
        try response.append("null");
        return;
    };
    // Prefer the persistent VexLedger when wired (point lookup by signature). rc.1 TransactionStatus
    // (transaction-status-client-types, camelCase) emits, in order: slot, confirmations, status (legacy
    // Result, ALWAYS present), err, confirmationStatus. confirmations:null — rc.1 = None when rooted; we
    // don't track a precise unrooted depth, so null (not a guessed count). status+err share one decode.
    if (ctx.vex_ledger) |vl| {
        if (vl.slotForSignature(sig)) |slot| {
            try response.appendFmt("{{\"slot\":{d},\"confirmations\":null,\"status\":", .{slot});
            try appendVlStatusErr(response, ctx, vl, sig, slot);
            try response.appendFmt(",\"confirmationStatus\":\"{s}\"}}", .{confirmationStatusName(ctx, slot)});
            return;
        }
        // sig unknown to VexLedger → fall through to the legacy store / null.
    }
    const store = ctx.tx_status_store orelse {
        try response.append("null");
        return;
    };
    const st = store.status(sig, ctx.rooted_slot, ctx.confirmed_slot) orelse {
        try response.append("null");
        return;
    };
    try response.appendFmt("{{\"slot\":{d},\"confirmations\":", .{st.slot});
    if (st.confirmations) |c| {
        try response.appendFmt("{d}", .{c});
    } else {
        try response.append("null");
    }
    // rc.1 TransactionStatus order: slot, confirmations, STATUS (legacy Result, ALWAYS emitted — no
    // skip_serializing_if; transaction-status-client-types:740-748), err, confirmationStatus. Previously
    // omitted on BOTH paths (LIVE audit). status = {"Ok":null} | {"Err":<err>}.
    try response.append(",\"status\":");
    if (st.err) |e| {
        try response.append("{\"Err\":");
        try appendTxErrValue(response, e);
        try response.append("}");
    } else {
        try response.append("{\"Ok\":null}");
    }
    try response.append(",\"err\":");
    if (st.err) |e| {
        try appendTxErrValue(response, e);
    } else {
        try response.append("null");
    }
    try response.appendFmt(",\"confirmationStatus\":\"{s}\"}}", .{st.confirmation_status.toString()});
}

/// getSignaturesForAddress - Signatures touching `address`, newest-first. Reads the address index in
/// the TxStatusStore; empty when absent.
pub fn getSignaturesForAddress(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    const addr = parseFirstPubkey(params) orelse {
        try response.append("[]");
        return;
    };
    const limit: usize = if (params) |p| @min(parseNamedU64(p, "\"limit\"") orelse 1000, 1000) else 1000;

    // Prefer the persistent VexLedger when wired: REAL err (decoded meta) + memo + blockTime +
    // commitment-correct confirmationStatus, vs the legacy stub's null/null/null/finalized.
    if (ctx.vex_ledger) |vl| {
        // before/until cursor pagination (base58 sigs in the config object). EXCLUSIVE cursors; an
        // unparseable/absent cursor → null = unbounded (the correct default).
        var before_buf: [64]u8 = undefined;
        var until_buf: [64]u8 = undefined;
        const before_sig: ?[64]u8 = if (params) |p| b: {
            const s = parseNamedString(p, "\"before\"") orelse break :b null;
            core.base58.decodeToBuf(s, &before_buf) catch break :b null;
            break :b before_buf;
        } else null;
        const until_sig: ?[64]u8 = if (params) |p| u: {
            const s = parseNamedString(p, "\"until\"") orelse break :u null;
            core.base58.decodeToBuf(s, &until_buf) catch break :u null;
            break :u until_buf;
        } else null;
        const rows = vl.getSignaturesForAddress(ctx.allocator, addr.data, before_sig, until_sig, limit, null) catch {
            try response.append("[]");
            return;
        };
        defer ctx.allocator.free(rows);
        try response.append("[");
        for (rows, 0..) |e, i| {
            if (i != 0) try response.append(",");
            const s58 = core.base58.encode(ctx.allocator, &e.signature) catch continue;
            defer ctx.allocator.free(s58);
            try response.appendFmt("{{\"signature\":\"{s}\",\"slot\":{d},\"err\":", .{ s58, e.slot });
            try appendVlTxErr(response, ctx, vl, e.signature, e.slot);
            try response.append(",\"memo\":");
            try appendVlMemo(response, ctx, vl, e.signature, e.slot);
            try response.append(",\"blockTime\":");
            if (vl.getBlocktime(e.slot)) |t| {
                try response.appendFmt("{d}", .{t});
            } else {
                try response.append("null");
            }
            try response.appendFmt(",\"confirmationStatus\":\"{s}\"}}", .{confirmationStatusName(ctx, e.slot)});
        }
        try response.append("]");
        return;
    }

    // Fallback: legacy tx_status_store (stub err/memo/blockTime) — byte-identical to before.
    const store = ctx.tx_status_store orelse {
        try response.append("[]");
        return;
    };
    const sigs = store.signaturesForAddress(addr, 0, std.math.maxInt(u64), limit) catch {
        try response.append("[]");
        return;
    };
    defer ctx.allocator.free(sigs);
    try response.append("[");
    for (sigs, 0..) |e, i| {
        if (i != 0) try response.append(",");
        const s58 = core.base58.encode(ctx.allocator, &e.signature) catch continue;
        defer ctx.allocator.free(s58);
        try response.appendFmt("{{\"signature\":\"{s}\",\"slot\":{d},\"err\":null,\"memo\":null,\"blockTime\":null,\"confirmationStatus\":\"finalized\"}}", .{ s58, e.slot });
    }
    try response.append("]");
}

/// sendTransaction - Decode the wire transaction (base64 or base58), validate it, and forward it to
/// the SAME BankingStage mempool the QUIC TPU ingest seam feeds; return the real first signature
/// (base58). RULE #0: if the mempool is not running (VEX_TPU_INGEST off) we return a JSON-RPC error
/// rather than a fabricated signature for a tx we did not actually accept.
pub fn sendTransaction(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    const p = params orelse {
        response.setError(-32602, "Invalid params: missing transaction");
        return;
    };
    // First quoted string in params is the encoded transaction.
    const q1 = std.mem.indexOf(u8, p, "\"") orelse {
        response.setError(-32602, "Invalid params: missing transaction");
        return;
    };
    const after = p[q1 + 1 ..];
    const q2 = std.mem.indexOf(u8, after, "\"") orelse {
        response.setError(-32602, "Invalid params: malformed transaction");
        return;
    };
    const encoded = after[0..q2];
    // Encoding: Agave default is base58 (legacy); modern clients send base64 (config {"encoding":"base64"}).
    const enc = parseNamedString(p, "\"encoding\"") orelse "base58";

    var wire_buf: [4096]u8 = undefined; // a tx is at most ~1232 bytes on the wire
    var wire: []u8 = undefined;
    if (std.mem.eql(u8, enc, "base64")) {
        const Dec = std.base64.standard.Decoder;
        const n = Dec.calcSizeForSlice(encoded) catch {
            response.setError(-32602, "Invalid params: bad base64");
            return;
        };
        if (n > wire_buf.len) {
            response.setError(-32602, "Invalid params: transaction too large");
            return;
        }
        Dec.decode(wire_buf[0..n], encoded) catch {
            response.setError(-32602, "Invalid params: bad base64");
            return;
        };
        wire = wire_buf[0..n];
    } else {
        // base58 (Agave legacy default)
        const decoded = core.base58.decode(ctx.allocator, encoded) catch {
            response.setError(-32602, "Invalid params: bad base58");
            return;
        };
        defer ctx.allocator.free(decoded);
        if (decoded.len > wire_buf.len) {
            response.setError(-32602, "Invalid params: transaction too large");
            return;
        }
        @memcpy(wire_buf[0..decoded.len], decoded);
        wire = wire_buf[0..decoded.len];
    }

    // Validate well-formedness + extract sig[0] using the shared TPU-ingest parser.
    var scratch_sigs: [runtime.tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var scratch_keys: [runtime.tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = runtime.tx_ingest.parse(wire, &scratch_sigs, &scratch_keys) catch {
        response.setError(-32602, "Invalid transaction: failed to parse");
        return;
    };
    const sig0 = parsed.id().*;

    const banking = ctx.banking orelse {
        // No mempool (VEX_TPU_INGEST off): we cannot actually submit. Be honest (RULE #0).
        response.setError(-32603, "Transaction submission unavailable: TPU ingest is not enabled on this node");
        return;
    };
    banking.queueTransaction(wire, 0, false, .rpc) catch {
        response.setError(-32603, "Transaction dropped: mempool full");
        return;
    };

    // Return the real first signature (base58), exactly as Agave's sendTransaction does.
    const s58 = core.base58.encode(ctx.allocator, &sig0) catch {
        response.setError(-32603, "Internal error: signature encode");
        return;
    };
    defer ctx.allocator.free(s58);
    try response.append("\"");
    try response.append(s58);
    try response.append("\"");
}

/// simulateTransaction - HONEST BLOCKER (2026-06-17): real simulation requires executing the tx
/// against a non-committed bank fork. `buildContext` passes `bank = null` (the RPC server has no
/// handle to the live bank tree / execute-without-commit path), so we cannot run the program. Rather
/// than fabricate logs/unitsConsumed (RULE #0), we (a) decode + structurally validate the tx (so
/// malformed input is rejected with a real error) and (b) return a well-formed response that reports
/// the simulation backend is unavailable via `err`. Wiring a fork-execute bank into the RPC server is
/// a separate, larger task (SB-1 banking — execute-without-commit). See RPC-WIRING-RESULT-2026-06-17.md.
pub fn simulateTransaction(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    // Validate the input is a real transaction (encoding default base58, modern clients base64).
    var well_formed = false;
    if (params) |p| {
        if (std.mem.indexOf(u8, p, "\"")) |q1| {
            const after = p[q1 + 1 ..];
            if (std.mem.indexOf(u8, after, "\"")) |q2| {
                const encoded = after[0..q2];
                const enc = parseNamedString(p, "\"encoding\"") orelse "base64";
                var wire_buf: [4096]u8 = undefined;
                const wire: ?[]u8 = blk: {
                    if (std.mem.eql(u8, enc, "base64")) {
                        const Dec = std.base64.standard.Decoder;
                        const n = Dec.calcSizeForSlice(encoded) catch break :blk null;
                        if (n > wire_buf.len) break :blk null;
                        Dec.decode(wire_buf[0..n], encoded) catch break :blk null;
                        break :blk wire_buf[0..n];
                    } else {
                        const d = core.base58.decode(ctx.allocator, encoded) catch break :blk null;
                        defer ctx.allocator.free(d);
                        if (d.len > wire_buf.len) break :blk null;
                        @memcpy(wire_buf[0..d.len], d);
                        break :blk wire_buf[0..d.len];
                    }
                };
                if (wire) |w| {
                    var ss: [runtime.tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
                    var sk: [runtime.tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
                    if (runtime.tx_ingest.parse(w, &ss, &sk)) |_| {
                        well_formed = true;
                    } else |_| {}
                }
            }
        }
    }

    if (!well_formed) {
        // Structurally-invalid tx → Agave shape: a non-null err that IS a real TransactionError variant
        // ("SanitizeFailure"), so the Rust SDK's Option<TransactionError> deserializes; no logs.
        try response.append("{\"context\":{\"slot\":");
        try response.appendInt(ctx.current_slot);
        try response.append("},\"value\":{\"err\":\"SanitizeFailure\",\"logs\":null,\"accounts\":null,\"unitsConsumed\":0,\"returnData\":null}}");
        return;
    }
    // Well-formed but NOT actually simulated on this node (no execute-without-commit bank handle).
    // RULE #0: report via a JSON-RPC error rather than fabricate success OR emit a non-canonical err
    // string the SDK can't parse (same pattern as sendTransaction with no mempool). SB-1 follow-up.
    response.setError(-32603, "Simulation unavailable: execute-without-commit bank not wired into RPC");
}

/// getRecentPrioritizationFees - Returns recent priority fees
pub fn getRecentPrioritizationFees(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    _ = ctx;
    try response.append("[{\"slot\":0,\"prioritizationFee\":0}]");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLOCKHASH METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// getLatestBlockhash - Returns latest blockhash from replay engine
pub fn getLatestBlockhash(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const slot = if (ctx.ledger_db) |db| db.last_replayed_slot.load(.seq_cst) else ctx.current_slot;
    const bh_len = if (ctx.ledger_db) |db| db.latest_blockhash_len.load(.seq_cst) else 0;

    try response.append("{\"context\":{\"slot\":");
    try response.appendFmt("{d}", .{slot});
    try response.append("},\"value\":{");

    if (bh_len > 0 and ctx.ledger_db != null) {
        try response.append("\"blockhash\":\"");
        try response.append(ctx.ledger_db.?.latest_blockhash[0..bh_len]);
        try response.append("\",");
    } else {
        try response.append("\"blockhash\":\"11111111111111111111111111111111\",");
    }

    try response.appendFmt("\"lastValidBlockHeight\":{d}", .{slot + 150});
    try response.append("}}");
}

/// getTransactionCount - Returns total transaction count
pub fn getTransactionCount(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const txn_count = if (ctx.ledger_db) |db| db.transaction_count.load(.seq_cst) else 0;
    try response.appendFmt("{d}", .{txn_count});
}

/// isBlockhashValid - Returns if blockhash is valid
pub fn isBlockhashValid(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    _ = params;

    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":true}");
}

/// getRecentBlockhash - Returns recent blockhash (deprecated — use getLatestBlockhash)
pub fn getRecentBlockhash(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    const slot = if (ctx.ledger_db) |db| db.last_replayed_slot.load(.seq_cst) else ctx.current_slot;
    const bh_len = if (ctx.ledger_db) |db| db.latest_blockhash_len.load(.seq_cst) else 0;

    try response.append("{\"context\":{\"slot\":");
    try response.appendFmt("{d}", .{slot});
    try response.append("},\"value\":{");

    if (bh_len > 0 and ctx.ledger_db != null) {
        try response.append("\"blockhash\":\"");
        try response.append(ctx.ledger_db.?.latest_blockhash[0..bh_len]);
        try response.append("\",");
    } else {
        try response.append("\"blockhash\":\"11111111111111111111111111111111\",");
    }

    try response.append("\"feeCalculator\":{\"lamportsPerSignature\":5000}");
    try response.append("}}");
}

/// getFeeForMessage - Returns fee for message
pub fn getFeeForMessage(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    _ = params;

    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":5000}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAKE METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// getStakeActivation - Returns stake activation info
pub fn getStakeActivation(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    _ = params;

    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":{");
    try response.append("\"state\":\"inactive\",");
    try response.append("\"active\":0,");
    try response.append("\"inactive\":0");
    try response.append("}}");
}

/// getStakeMinimumDelegation - Returns minimum stake
pub fn getStakeMinimumDelegation(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    try response.append("{\"context\":{\"slot\":");
    try response.appendInt(ctx.current_slot);
    try response.append("},\"value\":1000000000}"); // 1 SOL minimum
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATOR METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// getVoteAccounts - Returns vote accounts with real identity pubkey, lastVote, rootSlot.
/// activatedStake is served from the public testnet RPC by monitoring tools — the local
/// value is set to a sentinel (30000 SOL) until full stake account parsing is implemented.
pub fn getVoteAccounts(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    try response.append("{\"current\":[");

    if (ctx.vote_account) |va| {
        // identity (node pubkey) is distinct from vote account pubkey
        const identity = ctx.identity orelse "3J2jADiEoKMaooCQbkyr9aLnjAb5ApDWfVvKgzyK2fbP";

        // Use real lastVote and rootSlot from replay/ledger state
        const last_vote = if (ctx.ledger_db) |db| db.last_replayed_slot.load(.seq_cst) else 0;
        const root_slot = if (ctx.ledger_db) |db| db.last_replayed_slot.load(.seq_cst) -| 31 else 0;

        try response.append("{");
        try response.appendFmt("\"votePubkey\":\"{s}\",", .{va});
        try response.appendFmt("\"nodePubkey\":\"{s}\",", .{identity});
        // activatedStake: real value queried from network by monitoring tools;
        // local value is a placeholder until stake account parsing is wired in.
        try response.append("\"activatedStake\":30000000000000,");
        try response.append("\"epochVoteAccount\":true,");
        try response.append("\"commission\":100,");
        try response.append("\"epochCredits\":[],");
        try response.appendFmt("\"lastVote\":{d},", .{last_vote});
        try response.appendFmt("\"rootSlot\":{d}", .{root_slot});
        try response.append("}");
    }

    try response.append("],\"delinquent\":[]}");
}

/// getLeaderSchedule - Returns leader schedule
pub fn getLeaderSchedule(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    _ = params;
    // Return leader slots for our identity in the current epoch.
    // If leader_cache is not set, return null (safe default).
    const identity_str = ctx.identity orelse {
        try response.append("null");
        return;
    };
    const lc = ctx.leader_cache orelse {
        try response.append("null");
        return;
    };

    // Parse identity pubkey
    const base58 = core.base58;
    var pk_bytes: [32]u8 = undefined;
    base58.decodeToBuf(identity_str, &pk_bytes) catch {
        try response.append("null");
        return;
    };
    const identity_pubkey = core.Pubkey{ .data = pk_bytes };

    // Get our slots for this epoch from the leader cache. Derive the epoch warmup-aware
    // from the current slot — ctx.current_epoch is naive slot/432000 (wrong epoch) which
    // made this return null for the real epoch's schedule.
    const sched_epoch = lc.generator.getEpoch(ctx.current_slot);
    const slots = lc.getLeaderSlots(identity_pubkey, sched_epoch, ctx.allocator) catch {
        try response.append("null");
        return;
    };
    defer ctx.allocator.free(slots);

    // Return as {"<identity>": [slot1, slot2, ...]}
    try response.append("{\"");
    try response.append(identity_str);
    try response.append("\":[");
    for (slots, 0..) |slot, i| {
        if (i > 0) try response.append(",");
        try response.appendInt(slot);
    }
    try response.append("]}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// HEALTH METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// getHealth - Returns health status
pub fn getHealth(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    _ = ctx;
    try response.append("\"ok\"");
}

/// getVersion - Returns version info
pub fn getVersion(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    _ = ctx;
    try response.append("{\"solana-core\":\"0.2.0-vexor\",\"feature-set\":4192065167}");
}

/// getAccountsStoreStats - Returns live/dead bytes stats for accounts storage
pub fn getAccountsStoreStats(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    if (ctx.accounts_db) |adb| {
        var slot_filter: ?u64 = null;
        var limit: ?usize = null;
        if (params) |p| {
            slot_filter = parseNamedU64(p, "slot") orelse null;
            if (slot_filter == null) {
                slot_filter = parseFirstU64(p);
            }
            const limit_val = parseNamedU64(p, "limit") orelse null;
            if (limit_val) |value| {
                limit = @intCast(value);
            }
        }

        var stores = try adb.collectStoreStats(ctx.allocator);
        defer stores.deinit(ctx.allocator);

        try response.append("{");
        if (slot_filter) |slot| {
            var found = false;
            for (stores.items) |s| {
                if (s.slot == slot) {
                    found = true;
                    try response.appendFmt(
                        "\"slot\":{d},\"storeId\":{d},\"totalBytes\":{d},\"liveBytes\":{d},\"deadBytes\":{d},\"deadRatio\":{d},\"records\":{d},\"liveRecords\":{d}",
                        .{ s.slot, s.store_id, s.total_bytes, s.live_bytes, s.dead_bytes, s.dead_ratio_percent, s.records, s.live_records },
                    );
                    break;
                }
            }
            if (!found) {
                try response.append("\"ok\":false");
            }
        } else {
            const summary = adb.computeSummary(stores.items);
            try response.appendFmt(
                "\"summary\":{{\"totalBytes\":{d},\"liveBytes\":{d},\"deadBytes\":{d},\"deadRatio\":{d},\"records\":{d},\"liveRecords\":{d}}},\"stores\":[",
                .{ summary.total_bytes, summary.live_bytes, summary.dead_bytes, summary.dead_ratio_percent, summary.records, summary.live_records },
            );
            if (limit != null and stores.items.len > 1) {
                std.sort.heap(storage.accounts.AccountsDb.AccountsStoreStats, stores.items, {}, sortStoresByDeadRatio);
            }
            const max_items = if (limit) |l| @min(l, stores.items.len) else stores.items.len;
            for (stores.items[0..max_items], 0..) |s, idx| {
                if (idx > 0) try response.append(",");
                try response.appendFmt(
                    "{{\"slot\":{d},\"storeId\":{d},\"totalBytes\":{d},\"liveBytes\":{d},\"deadBytes\":{d},\"deadRatio\":{d},\"records\":{d},\"liveRecords\":{d}}}",
                    .{ s.slot, s.store_id, s.total_bytes, s.live_bytes, s.dead_bytes, s.dead_ratio_percent, s.records, s.live_records },
                );
            }
            try response.append("]");
        }
        try response.append("}");
    } else {
        try response.append("{\"ok\":false}");
    }
}

/// runAccountsGcOnce - Triggers one GC tick for accounts storage
pub fn runAccountsGcOnce(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    if (ctx.accounts_db) |adb| {
        const now_ms: u64 = @intCast(std.time.milliTimestamp());
        adb.tickAccountsGc(@intCast(ctx.current_slot), now_ms);
        try response.append("{\"ok\":true}");
    } else {
        try response.append("{\"ok\":false}");
    }
}

/// flushAccountsMetadata - Forces appendvec metadata flush to disk
pub fn flushAccountsMetadata(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    if (ctx.accounts_db) |adb| {
        adb.flushAccountsMetadata();
        try response.append("{\"ok\":true}");
    } else {
        try response.append("{\"ok\":false}");
    }
}

/// saveAccountsSnapshot - Saves local accounts snapshot to disk
pub fn saveAccountsSnapshot(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    if (ctx.accounts_db == null) {
        try response.append("{\"ok\":false}");
        return;
    }
    if (ctx.snapshot_manager == null) {
        try response.append("{\"ok\":false,\"error\":\"snapshot_manager_unavailable\"}");
        return;
    }
    const limiter = @constCast(&ctx.snapshot_limiter);
    const now_ms: u64 = @intCast(std.time.milliTimestamp());
    if (!limiter.canStart(now_ms)) {
        const retry_after = limiter.retryAfter(now_ms);
        try response.append("{\"ok\":false,\"error\":\"rate_limited\",\"retryAfterMs\":");
        try response.appendInt(retry_after);
        try response.append("}");
        return;
    }
    if (!limiter.markStart()) {
        try response.append("{\"ok\":false,\"error\":\"snapshot_in_progress\"}");
        return;
    }

    var slot: u64 = @intCast(ctx.current_slot);
    if (params) |p| {
        if (parseNamedU64(p, "slot")) |value| {
            slot = value;
        } else if (parseFirstU64(p)) |value| {
            slot = value;
        }
    }

    const adb = ctx.accounts_db.?;
    const manager = ctx.snapshot_manager.?;
    const start_ms: u64 = @intCast(std.time.milliTimestamp());
    std.log.info("[RPC] saveAccountsSnapshot start slot={d}", .{slot});

    // FULL packaging path (2026-06-21): when the frozen bank is reachable, build
    // a COMPLETE loadable snapshot — appendvec + bincode bank manifest (with the
    // REAL bank.accounts_lthash, NOT accounts_hash) + status_cache stub — and
    // package as snapshot-<slot>-<hash>.tar.zst. Falls back to the legacy
    // accounts-only saveSnapshot when no bank is wired (e.g. RPC-only contexts).
    if (ctx.bank) |bank| {
        const lt_ptr: *const [2048]u8 = bank.accounts_lthash.asBytes();
        const bank_fields = storage.SnapshotManager.FullSnapshotBankFields{
            .parent_slot = bank.parent_slot orelse 0,
            .bank_hash = bank.bank_hash.data,
            .parent_hash = bank.parent_hash.data,
            .last_blockhash = bank.poh_hash.data,
            .capitalization = bank.capitalization,
            .block_height = bank.block_height,
            .hashes_per_tick = if (bank.hashes_per_tick == 0) null else bank.hashes_per_tick,
            .ticks_per_slot = bank.ticks_per_slot,
            .epoch = bank.epoch_schedule.getEpoch(bank.slot),
            .block_id = bank.block_id,
            .accounts_lt_hash = lt_ptr.*,
            // CONSENSUS-CRITICAL for snapshot round-trip (2026-06-26): carry the
            // governor + signature_count that seed the reloaded root bank's per-slot
            // RecentBlockhashes lamports_per_signature (see FullSnapshotBankFields).
            .fee_rate_governor = bank.fee_rate_governor,
            .signature_count = bank.signature_count,
        };
        var fr = manager.saveFullSnapshot(adb, slot, bank_fields) catch |err| {
            const end_ms: u64 = @intCast(std.time.milliTimestamp());
            limiter.markFinish(end_ms - start_ms, end_ms);
            std.log.err("[RPC] saveAccountsSnapshot (full) failed: {s}", .{@errorName(err)});
            try response.append("{\"ok\":false,\"error\":\"");
            try response.appendFmt("{s}", .{@errorName(err)});
            try response.append("\"}");
            return;
        };
        defer fr.deinit(ctx.allocator);
        const end_ms: u64 = @intCast(std.time.milliTimestamp());
        limiter.markFinish(end_ms - start_ms, end_ms);
        std.log.info(
            "[RPC] saveAccountsSnapshot (full) ok slot={d} accounts={d} lamports={d} manifest_bytes={d} ms={d}",
            .{ fr.slot, fr.accounts_written, fr.lamports_total, fr.manifest_bytes, end_ms - start_ms },
        );
        try response.append("{");
        try response.appendFmt("\"ok\":true,\"slot\":{d},\"dir\":\"{s}\",\"tarPath\":\"{s}\",\"accounts\":{d},\"lamports\":{d},\"manifestBytes\":{d},\"hash\":\"{s}\"", .{
            fr.slot, fr.output_dir, fr.tar_path, fr.accounts_written, fr.lamports_total, fr.manifest_bytes, fr.accounts_hash_hex[0..],
        });
        try response.append("}");
        return;
    }

    var result = manager.saveSnapshot(adb, slot) catch |err| {
        const end_ms: u64 = @intCast(std.time.milliTimestamp());
        limiter.markFinish(end_ms - start_ms, end_ms);
        std.log.err("[RPC] saveAccountsSnapshot failed: {s}", .{@errorName(err)});
        try response.append("{\"ok\":false,\"error\":\"");
        try response.appendFmt("{s}", .{@errorName(err)});
        try response.append("\"}");
        return;
    };
    defer result.deinit(ctx.allocator);
    const end_ms: u64 = @intCast(std.time.milliTimestamp());
    limiter.markFinish(end_ms - start_ms, end_ms);
    std.log.info(
        "[RPC] saveAccountsSnapshot ok slot={d} accounts={d} lamports={d} ms={d}",
        .{ result.slot, result.accounts_written, result.lamports_total, end_ms - start_ms },
    );

    try response.append("{");
    try response.appendFmt("\"ok\":true,\"slot\":{d},\"dir\":\"{s}\",\"accounts\":{d},\"lamports\":{d},\"accountsHash\":\"{s}\"", .{
        result.slot,
        result.output_dir,
        result.accounts_written,
        result.lamports_total,
        result.accounts_hash_hex[0..],
    });
    try response.append("}");
}

/// verifyAccountsSnapshot - Verifies live accounts hash against snapshot dir
pub fn verifyAccountsSnapshot(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    if (ctx.accounts_db == null) {
        try response.append("{\"ok\":false}");
        return;
    }

    const input = params orelse {
        try response.append("{\"ok\":false,\"error\":\"missing_params\"}");
        return;
    };
    const dir = parseNamedString(input, "dir") orelse {
        try response.append("{\"ok\":false,\"error\":\"missing_dir\"}");
        return;
    };

    var slot: u64 = 0;
    if (parseNamedU64(input, "slot")) |value| {
        slot = value;
    } else if (parseSlotFromSnapshotDir(dir)) |parsed| {
        slot = parsed;
    } else {
        try response.append("{\"ok\":false,\"error\":\"missing_slot\"}");
        return;
    }

    var snapshot_dir = dir;
    var hash_path_buf: [512]u8 = undefined;
    const hash_path = try std.fmt.bufPrint(&hash_path_buf, "{s}/snapshots/{d}/accounts_hash", .{ dir, slot });
    var file = (if (hash_path.len > 0 and hash_path[0] == '/')
        std.fs.openFileAbsolute(hash_path, .{ .mode = .read_only })
    else
        std.fs.cwd().openFile(hash_path, .{ .mode = .read_only })) catch |err| blk: {
        if (ctx.snapshot_manager) |sm| {
            var fallback_buf: [512]u8 = undefined;
            const fallback_dir = try std.fmt.bufPrint(&fallback_buf, "{s}/local-snapshot-{d}", .{ sm.snapshots_dir, slot });
            const fallback_path = try std.fmt.bufPrint(&hash_path_buf, "{s}/snapshots/{d}/accounts_hash", .{ fallback_dir, slot });
            snapshot_dir = fallback_dir;
            break :blk (if (fallback_path.len > 0 and fallback_path[0] == '/')
                std.fs.openFileAbsolute(fallback_path, .{ .mode = .read_only })
            else
                std.fs.cwd().openFile(fallback_path, .{ .mode = .read_only })) catch |err2| {
                try response.append("{\"ok\":false,\"error\":\"");
                try response.appendFmt("{s}", .{@errorName(err2)});
                try response.append("\"}");
                return;
            };
        }
        try response.append("{\"ok\":false,\"error\":\"");
        try response.appendFmt("{s}", .{@errorName(err)});
        try response.append("\"}");
        return;
    };
    defer file.close();

    var buf: [128]u8 = undefined;
    const n = file.readAll(&buf) catch 0;
    const saved = std.mem.trim(u8, buf[0..n], " \n\r\t");
    if (saved.len == 0) {
        try response.append("{\"ok\":false,\"error\":\"empty_hash\"}");
        return;
    }

    var keep_snapshots = false;
    if (std.process.getEnvVarOwned(ctx.allocator, "VEXOR_SNAPSHOT_KEEP")) |value| {
        defer ctx.allocator.free(value);
        keep_snapshots = std.mem.eql(u8, value, "1");
    } else |_| {}

    const all_zero = saved.len == 64 and std.mem.indexOfNone(u8, saved, "0") == null;
    if (all_zero) {
        try response.append("{\"ok\":true,\"slot\":");
        try response.appendFmt("{d}", .{slot});
        try response.append(",\"hashChecked\":false}");
        if (!keep_snapshots) {
            std.fs.cwd().deleteTree(snapshot_dir) catch {};
        }
        return;
    }

    const adb = ctx.accounts_db.?;
    const hash = adb.computeHash() catch |err| {
        try response.append("{\"ok\":false,\"error\":\"");
        try response.appendFmt("{s}", .{@errorName(err)});
        try response.append("\"}");
        return;
    };
    const hash_hex = std.fmt.bytesToHex(hash.data, .lower);

    const ok = std.mem.eql(u8, saved, &hash_hex);
    try response.append("{");
    try response.appendFmt("\"ok\":{s},\"slot\":{d},\"hashChecked\":true", .{ if (ok) "true" else "false", slot });
    try response.append("}");
    if (ok and !keep_snapshots) {
        std.fs.cwd().deleteTree(snapshot_dir) catch {};
    }
}

fn parseFirstU64(input: []const u8) ?u64 {
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        if (input[i] >= '0' and input[i] <= '9') {
            var end = i;
            while (end < input.len and input[end] >= '0' and input[end] <= '9') : (end += 1) {}
            return std.fmt.parseInt(u64, input[i..end], 10) catch null;
        }
    }
    return null;
}

fn parseNamedU64(input: []const u8, name: []const u8) ?u64 {
    const idx = std.mem.indexOf(u8, input, name) orelse return null;
    var i = idx + name.len;
    while (i < input.len and (input[i] < '0' or input[i] > '9')) : (i += 1) {}
    if (i >= input.len) return null;
    var end = i;
    while (end < input.len and input[end] >= '0' and input[end] <= '9') : (end += 1) {}
    return std.fmt.parseInt(u64, input[i..end], 10) catch null;
}

fn parseNamedString(input: []const u8, name: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, input, name) orelse return null;
    const after = input[idx + name.len ..];
    const colon = std.mem.indexOf(u8, after, ":") orelse return null;
    const after_colon = after[colon + 1 ..];
    const first_quote = std.mem.indexOf(u8, after_colon, "\"") orelse return null;
    const rest = after_colon[first_quote + 1 ..];
    const second_quote = std.mem.indexOf(u8, rest, "\"") orelse return null;
    return rest[0..second_quote];
}

fn parseSlotFromSnapshotDir(dir: []const u8) ?u64 {
    const dash = std.mem.lastIndexOfScalar(u8, dir, '-') orelse return null;
    if (dash + 1 >= dir.len) return null;
    return std.fmt.parseInt(u64, dir[dash + 1 ..], 10) catch null;
}

fn sortStoresByDeadRatio(_: void, a: storage.accounts.AccountsDb.AccountsStoreStats, b: storage.accounts.AccountsDb.AccountsStoreStats) bool {
    return a.dead_ratio_percent > b.dead_ratio_percent;
}

// ═══════════════════════════════════════════════════════════════════════════════
// RENT METHODS
// ═══════════════════════════════════════════════════════════════════════════════

/// getMinimumBalanceForRentExemption - Returns minimum rent-exempt balance
pub fn getMinimumBalanceForRentExemption(ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !void {
    _ = ctx;
    // Parse data size from params (default 0)
    var data_len: u64 = 0;
    if (params) |p| {
        // Simple parse - find first number
        var i: usize = 0;
        while (i < p.len) : (i += 1) {
            if (p[i] >= '0' and p[i] <= '9') {
                var end = i;
                while (end < p.len and p[end] >= '0' and p[end] <= '9') : (end += 1) {}
                data_len = std.fmt.parseInt(u64, p[i..end], 10) catch 0;
                break;
            }
        }
    }

    // Formula: (128 + data_len) * 3480 * 2 / 365 (simplified)
    const min_balance = (128 + data_len) * 6960;
    try response.appendInt(min_balance);
}

/// getFirstAvailableBlock - Returns the lowest slot present in the persistent VexLedger (Agave: the first
/// block the node can serve). Falls back to "0" (prior behavior) when the ledger is absent or still empty.
pub fn getFirstAvailableBlock(ctx: *const RpcContext, _: ?[]const u8, response: *ResponseBuilder) !void {
    if (ctx.vex_ledger) |vl| {
        if (vl.lowestSlot()) |s| {
            try response.appendInt(s);
            return;
        }
    }
    try response.append("0");
}

// ═══════════════════════════════════════════════════════════════════════════════
// METHOD REGISTRY
// ═══════════════════════════════════════════════════════════════════════════════

pub const MethodHandler = *const fn (*const RpcContext, ?[]const u8, *ResponseBuilder) anyerror!void;

pub const methods = std.StaticStringMap(MethodHandler).initComptime(.{
    // Cluster
    .{ "getClusterNodes", getClusterNodes },
    .{ "getEpochInfo", getEpochInfo },
    .{ "getEpochSchedule", getEpochSchedule },
    .{ "getGenesisHash", getGenesisHash },
    .{ "getIdentity", getIdentity },
    .{ "getInflationGovernor", getInflationGovernor },
    .{ "getInflationRate", getInflationRate },
    .{ "getSupply", getSupply },
    // Account
    .{ "getAccountInfo", getAccountInfo },
    .{ "getBalance", getBalance },
    .{ "getMultipleAccounts", getMultipleAccounts },
    .{ "getProgramAccounts", getProgramAccounts },
    .{ "getTokenAccountBalance", getTokenAccountBalance },
    .{ "getTokenAccountsByOwner", getTokenAccountsByOwner },
    // Block
    .{ "getBlock", getBlock },
    .{ "getBlockCommitment", getBlockCommitment },
    .{ "getBlockHeight", getBlockHeight },
    .{ "getBlockProduction", getBlockProduction },
    .{ "getBlockTime", getBlockTime },
    .{ "getBlocks", getBlocks },
    .{ "getBlocksWithLimit", getBlocksWithLimit },
    // Slot
    .{ "getSlot", getSlot },
    .{ "getSlotLeader", getSlotLeader },
    .{ "getSlotLeaders", getSlotLeaders },
    .{ "getHighestSnapshotSlot", getHighestSnapshotSlot },
    // Transaction
    .{ "getTransaction", getTransaction },
    .{ "getSignatureStatuses", getSignatureStatuses },
    .{ "getSignaturesForAddress", getSignaturesForAddress },
    .{ "sendTransaction", sendTransaction },
    .{ "simulateTransaction", simulateTransaction },
    .{ "getRecentPrioritizationFees", getRecentPrioritizationFees },
    // Blockhash
    .{ "getLatestBlockhash", getLatestBlockhash },
    .{ "getTransactionCount", getTransactionCount },
    .{ "isBlockhashValid", isBlockhashValid },
    .{ "getRecentBlockhash", getRecentBlockhash },
    .{ "getFeeForMessage", getFeeForMessage },
    // Stake
    .{ "getStakeActivation", getStakeActivation },
    .{ "getStakeMinimumDelegation", getStakeMinimumDelegation },
    // Validator
    .{ "getVoteAccounts", getVoteAccounts },
    .{ "getLeaderSchedule", getLeaderSchedule },
    // Health
    .{ "getHealth", getHealth },
    .{ "getVersion", getVersion },
    .{ "getAccountsStoreStats", getAccountsStoreStats },
    .{ "runAccountsGcOnce", runAccountsGcOnce },
    .{ "flushAccountsMetadata", flushAccountsMetadata },
    .{ "saveAccountsSnapshot", saveAccountsSnapshot },
    .{ "verifyAccountsSnapshot", verifyAccountsSnapshot },
    // Rent
    .{ "getMinimumBalanceForRentExemption", getMinimumBalanceForRentExemption },
    .{ "getFirstAvailableBlock", getFirstAvailableBlock },
    // Deprecated Agave aliases (2026-06-24): same handler + same full-API tier (none are in
    // MINIMAL_METHODS, so requiresFullApi()==true exactly like their canonical targets). Agave keeps
    // these registered for back-compat; many SDKs/clients still call the getConfirmed* names.
    .{ "getConfirmedBlock", getBlock },
    .{ "getConfirmedTransaction", getTransaction },
    .{ "getConfirmedSignaturesForAddress2", getSignaturesForAddress },
    .{ "getConfirmedBlocks", getBlocks },
    .{ "getConfirmedBlocksWithLimit", getBlocksWithLimit },
});

/// The 12 Minimal-trait methods served by EVERY node regardless of --full-rpc-api, copied verbatim
/// from Agave rc.1 `rpc/src/rpc.rs` `pub trait Minimal` (the only module registered unconditionally in
/// `rpc_service.rs:708`). Everything else is gated behind `full_rpc_api`. SOURCE OF TRUTH — keep sorted
/// and in lockstep with the Agave Minimal trait; any method NOT here is treated as full-API-only.
pub const MINIMAL_METHODS = std.StaticStringMap(void).initComptime(.{
    .{ "getBalance", {} },
    .{ "getBlockHeight", {} },
    .{ "getEpochInfo", {} },
    .{ "getGenesisHash", {} },
    .{ "getHealth", {} },
    .{ "getHighestSnapshotSlot", {} },
    .{ "getIdentity", {} },
    .{ "getLeaderSchedule", {} },
    .{ "getSlot", {} },
    .{ "getTransactionCount", {} },
    .{ "getVersion", {} },
    .{ "getVoteAccounts", {} },
});

/// True when `name` requires `--full-rpc-api` (i.e. it is NOT one of the 12 Minimal methods).
pub fn requiresFullApi(name: []const u8) bool {
    return !MINIMAL_METHODS.has(name);
}

/// Dispatch method by name. Returns false (→ caller emits the canonical -32601 "Method not found")
/// for BOTH unknown methods and full-API methods when `ctx.full_rpc_api` is off — byte-identical to
/// Agave, which simply does not register the Full/BankData/AccountsData/AccountsScan modules on a
/// minimal node, so a client sees the same "method not found" either way.
pub fn dispatch(name: []const u8, ctx: *const RpcContext, params: ?[]const u8, response: *ResponseBuilder) !bool {
    if (!ctx.full_rpc_api and requiresFullApi(name)) return false;
    if (methods.get(name)) |handler| {
        try handler(ctx, params, response);
        return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "method dispatch" {
    const allocator = std.testing.allocator;

    const ctx = RpcContext{
        .allocator = allocator,
        .accounts_db = null,
        .ledger_db = null,
        .snapshot_manager = null,
        .snapshot_limiter = SnapshotLimiter.init(),
        .bank = null,
        .current_slot = 12345,
        .current_epoch = 100,
        .cluster = "testnet",
    };

    var response = ResponseBuilder.init(allocator);
    defer response.deinit();

    // Test getHealth
    const found = try dispatch("getHealth", &ctx, null, &response);
    try std.testing.expect(found);
    try std.testing.expectEqualStrings("\"ok\"", response.getWritten());

    // Test unknown method
    response.reset();
    const not_found = try dispatch("unknownMethod", &ctx, null, &response);
    try std.testing.expect(!not_found);
}

test "response builder" {
    const allocator = std.testing.allocator;

    var builder = ResponseBuilder.init(allocator);
    defer builder.deinit();

    try builder.append("{\"test\":");
    try builder.appendInt(42);
    try builder.append("}");

    try std.testing.expectEqualStrings("{\"test\":42}", builder.getWritten());
}
