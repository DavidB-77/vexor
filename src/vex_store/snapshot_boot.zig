//! Vexor Snapshot Manager
//!
//! Handles downloading, validating, and loading snapshots from the cluster.
//! Snapshots are the primary mechanism for bootstrapping a new validator.
//!
//! Snapshot Types:
//! - Full snapshot: Complete state at a specific slot
//! - Incremental snapshot: Changes since the last full snapshot
//!
//! File Format:
//! snapshot-<slot>-<hash>.tar.zst (full)
//! incremental-snapshot-<base_slot>-<slot>-<hash>.tar.zst (incremental)

const std = @import("std");
const Allocator = std.mem.Allocator;
const fs = std.fs;
const core = @import("core");
const snapshot_writer = @import("snapshot_writer.zig");
/// Minimum acceptable post-download size for a snapshot archive (1 MB).
/// Real testnet incrementals are tens of MB; fulls are GB. 1 MB is conservative
/// enough to leave headroom while still catching the recurring HTTP-200-with-empty-body
/// failure mode where curl exits 0 but the server returned 0 bytes.
/// See bf8bdc98 fix doc: vault/SNAPSHOT_DOWNLOAD_GUARD_FIX_2026_05_05.md
pub const MIN_SNAPSHOT_DOWNLOAD_BYTES: u64 = 1 * 1024 * 1024;

/// RULE #1 (key/endpoint isolation): hosts Vexor must NEVER fetch a snapshot
/// from. The host at 38.92.24.174 is the co-located Agave "oracle-node" validator
/// (separate identity, 9F-prefix keys). Pulling a snapshot — or even a peer
/// list — from it would cross-pollinate consensus-affecting state between two
/// independently-operated validators on the same machine. This has happened
/// before; that is why the rule exists. See CLAUDE.md RULE #1. We deny the
/// HOST (all ports), which is stricter than the documented :8899/:8800 pair.
pub const GOVNODE_DENY_HOSTS = [_][]const u8{
    "38.92.24.174",
};

/// Extract the bare host from a snapshot endpoint/peer address. Accepts any of:
///   "https://api.testnet.solana.com"      -> "api.testnet.solana.com"
///   "http://1.2.3.4:8899/snapshot.tar.zst" -> "1.2.3.4"
///   "1.2.3.4:8899"                          -> "1.2.3.4"  (getClusterNodes "rpc")
///   "1.2.3.4"                               -> "1.2.3.4"
/// Returns a slice into `addr` (no allocation).
pub fn extractHostFromAddr(addr: []const u8) []const u8 {
    var s = addr;
    // Strip scheme.
    if (std.mem.indexOf(u8, s, "://")) |i| s = s[i + 3 ..];
    // Strip path (and query) — host ends at the first '/'.
    if (std.mem.indexOfScalar(u8, s, '/')) |i| s = s[0..i];
    // Strip ":port". IPv6 literals are not used by testnet getClusterNodes,
    // so a single ':' split is correct here.
    if (std.mem.indexOfScalar(u8, s, ':')) |i| s = s[0..i];
    return s;
}

/// True if `addr`'s host is on the RULE #1 deny-list. Matches the full host
/// token exactly (NOT a substring) so "138.92.24.174" does not match
/// "38.92.24.174".
pub fn isDeniedSnapshotHost(addr: []const u8) bool {
    const host = extractHostFromAddr(addr);
    for (GOVNODE_DENY_HOSTS) |denied| {
        if (std.mem.eql(u8, host, denied)) return true;
    }
    return false;
}

test "RULE#1 snapshot deny-list: govnode host blocked, substring trap allowed" {
    // Host extraction across every form a seed / getClusterNodes "rpc" can take.
    try std.testing.expectEqualStrings("api.testnet.solana.com", extractHostFromAddr("https://api.testnet.solana.com"));
    try std.testing.expectEqualStrings("1.2.3.4", extractHostFromAddr("http://1.2.3.4:8899/snapshot.tar.zst"));
    try std.testing.expectEqualStrings("38.92.24.174", extractHostFromAddr("38.92.24.174:8899")); // getClusterNodes "rpc" form

    // DENIED: every scheme/port of the oracle-node host.
    try std.testing.expect(isDeniedSnapshotHost("38.92.24.174"));
    try std.testing.expect(isDeniedSnapshotHost("38.92.24.174:8899")); // RPC
    try std.testing.expect(isDeniedSnapshotHost("38.92.24.174:8800")); // gossip
    try std.testing.expect(isDeniedSnapshotHost("http://38.92.24.174:8899/snapshot-1-a.tar.zst"));

    // ALLOWED: the substring trap + legitimate peers (host-exact match, not substring).
    try std.testing.expect(!isDeniedSnapshotHost("138.92.24.174:8899"));
    try std.testing.expect(!isDeniedSnapshotHost("38.92.24.1740:8899"));
    try std.testing.expect(!isDeniedSnapshotHost("https://api.testnet.solana.com"));
    try std.testing.expect(!isDeniedSnapshotHost("http://64.130.37.162:8899"));
}

test "RULE#1 deny-list filters govnode out of a getClusterNodes response (wiring)" {
    // Exercises the EXACT extraction + skip the peer loops use
    // (discoverSnapshotPairFromCluster / findIncrementalAcrossPeers), over a
    // realistic payload: a null-rpc node (not matched by the pattern), the oracle-node
    // (must be skipped), a substring-trap host + two legit peers (must survive).
    const response =
        \\{"jsonrpc":"2.0","result":[
        \\{"pubkey":"A","rpc":null,"gossip":"1.1.1.1:8001"},
        \\{"pubkey":"GOV","rpc":"38.92.24.174:8899","gossip":"38.92.24.174:8800"},
        \\{"pubkey":"TRAP","rpc":"138.92.24.174:8899"},
        \\{"pubkey":"P1","rpc":"64.130.37.162:8899"},
        \\{"pubkey":"P2","rpc":"5.6.7.8:8899"}
        \\],"id":1}
    ;
    var kept = std.ArrayListUnmanaged([]const u8){};
    defer kept.deinit(std.testing.allocator);
    var pos: usize = 0;
    var govnode_seen = false;
    while (std.mem.indexOf(u8, response[pos..], "\"rpc\":\"")) |idx| {
        const start = pos + idx + 7;
        const end = std.mem.indexOf(u8, response[start..], "\"") orelse break;
        const rpc_addr = response[start .. start + end];
        pos = start + end; // advance BEFORE any skip — no infinite loop / mis-advance
        if (rpc_addr.len == 0 or std.mem.eql(u8, rpc_addr, "null")) continue;
        if (isDeniedSnapshotHost(rpc_addr)) {
            govnode_seen = true;
            continue; // the peer-loop deny skip
        }
        try kept.append(std.testing.allocator, rpc_addr);
    }
    try std.testing.expect(govnode_seen); // govnode WAS present in the blob…
    for (kept.items) |a| try std.testing.expect(!std.mem.eql(u8, a, "38.92.24.174:8899")); // …and filtered out
    try std.testing.expectEqual(@as(usize, 3), kept.items.len); // TRAP + P1 + P2 survive
    try std.testing.expectEqualStrings("138.92.24.174:8899", kept.items[0]); // substring-trap host kept
}

/// Snapshot metadata
pub const SnapshotInfo = struct {
    slot: u64,
    hash: [32]u8,
    base_slot: ?u64, // For incremental snapshots
    lamports: u64,
    capitalization: u64,
    accounts_count: u64,
    size_bytes: u64,
    is_incremental: bool,
    download_url: ?[]const u8,
    /// Original filename (for local snapshots)
    filename: ?[]const u8 = null,
    /// Hash string (Base58) for path reconstruction
    hash_str: [64]u8 = undefined,
    hash_str_len: u8 = 0,

    /// Parse snapshot filename to extract metadata
    pub fn fromFilename(filename: []const u8) ?SnapshotInfo {
        // Full: snapshot-<slot>-<hash>.tar.zst
        // Incr: incremental-snapshot-<base>-<slot>-<hash>.tar.zst

        if (std.mem.startsWith(u8, filename, "incremental-snapshot-")) {
            return parseIncrementalFilename(filename);
        } else if (std.mem.startsWith(u8, filename, "snapshot-")) {
            return parseFullFilename(filename);
        }
        return null;
    }

    fn parseFullFilename(filename: []const u8) ?SnapshotInfo {
        // snapshot-<slot>-<hash>.tar.zst OR snapshot-<slot>-<hash>.tar.bz2
        const prefix_len = "snapshot-".len;

        // Determine suffix
        const suffix_len: usize = if (std.mem.endsWith(u8, filename, ".tar.zst"))
            ".tar.zst".len
        else if (std.mem.endsWith(u8, filename, ".tar.bz2"))
            ".tar.bz2".len
        else
            return null;

        const body = filename[prefix_len .. filename.len - suffix_len];
        var parts = std.mem.splitScalar(u8, body, '-');

        const slot_str = parts.next() orelse return null;
        const hash_str = parts.next() orelse return null;

        const slot = std.fmt.parseInt(u64, slot_str, 10) catch return null;
        const hash = parseHash(hash_str) orelse return null;

        // Store hash string for path reconstruction
        var hash_str_buf: [64]u8 = undefined;
        const hash_len: u8 = @intCast(@min(hash_str.len, 64));
        @memcpy(hash_str_buf[0..hash_len], hash_str[0..hash_len]);

        return SnapshotInfo{
            .slot = slot,
            .hash = hash,
            .base_slot = null,
            .lamports = 0,
            .capitalization = 0,
            .accounts_count = 0,
            .size_bytes = 0,
            .is_incremental = false,
            .download_url = null,
            .filename = null,
            .hash_str = hash_str_buf,
            .hash_str_len = hash_len,
        };
    }

    fn parseIncrementalFilename(filename: []const u8) ?SnapshotInfo {
        // incremental-snapshot-<base>-<slot>-<hash>.tar.zst OR .tar.bz2
        const prefix_len = "incremental-snapshot-".len;

        // Determine suffix
        const suffix_len: usize = if (std.mem.endsWith(u8, filename, ".tar.zst"))
            ".tar.zst".len
        else if (std.mem.endsWith(u8, filename, ".tar.bz2"))
            ".tar.bz2".len
        else
            return null;

        const body = filename[prefix_len .. filename.len - suffix_len];
        var parts = std.mem.splitScalar(u8, body, '-');

        const base_slot_str = parts.next() orelse return null;
        const slot_str = parts.next() orelse return null;
        const hash_str = parts.next() orelse return null;

        const base_slot = std.fmt.parseInt(u64, base_slot_str, 10) catch return null;
        const slot = std.fmt.parseInt(u64, slot_str, 10) catch return null;
        const hash = parseHash(hash_str) orelse return null;

        // Store hash string for path reconstruction
        var hash_str_buf: [64]u8 = undefined;
        const hash_len: u8 = @intCast(@min(hash_str.len, 64));
        @memcpy(hash_str_buf[0..hash_len], hash_str[0..hash_len]);

        return SnapshotInfo{
            .slot = slot,
            .hash = hash,
            .base_slot = base_slot,
            .lamports = 0,
            .capitalization = 0,
            .accounts_count = 0,
            .size_bytes = 0,
            .is_incremental = true,
            .download_url = null,
            .filename = null,
            .hash_str = hash_str_buf,
            .hash_str_len = hash_len,
        };
    }

    fn parseHash(hash_str: []const u8) ?[32]u8 {
        // Base58 decode - simplified (would need full base58 decoder)
        if (hash_str.len < 32 or hash_str.len > 44) return null;
        var result: [32]u8 = undefined;
        @memset(&result, 0);
        // Copy what we can for now (proper base58 decode needed)
        const copy_len = @min(hash_str.len, 32);
        @memcpy(result[0..copy_len], hash_str[0..copy_len]);
        return result;
    }
};

/// Snapshot save result
pub const SaveResult = struct {
    slot: u64,
    output_dir: []const u8,
    accounts_written: u64,
    lamports_total: u64,
    accounts_hash_hex: [64]u8,

    pub fn deinit(self: *SaveResult, allocator: Allocator) void {
        allocator.free(self.output_dir);
    }
};

/// Snapshot download progress
pub const DownloadProgress = struct {
    total_bytes: u64,
    downloaded_bytes: u64,
    elapsed_ns: u64,

    pub fn percentComplete(self: DownloadProgress) f64 {
        if (self.total_bytes == 0) return 0;
        return @as(f64, @floatFromInt(self.downloaded_bytes)) / @as(f64, @floatFromInt(self.total_bytes)) * 100.0;
    }

    pub fn bytesPerSecond(self: DownloadProgress) f64 {
        if (self.elapsed_ns == 0) return 0;
        const elapsed_sec = @as(f64, @floatFromInt(self.elapsed_ns)) / 1_000_000_000.0;
        return @as(f64, @floatFromInt(self.downloaded_bytes)) / elapsed_sec;
    }

    pub fn etaSeconds(self: DownloadProgress) f64 {
        const bps = self.bytesPerSecond();
        if (bps == 0) return 0;
        const remaining = self.total_bytes - self.downloaded_bytes;
        return @as(f64, @floatFromInt(remaining)) / bps;
    }
};

/// Snapshot manager state
pub const SnapshotManager = struct {
    allocator: Allocator,
    snapshots_dir: []const u8,
    rpc_endpoints: std.ArrayListUnmanaged([]const u8),
    known_validators: std.ArrayListUnmanaged([]const u8),
    current_download: ?DownloadProgress,

    const Self = @This();

    pub fn init(allocator: Allocator, snapshots_dir: []const u8) Self {
        return Self{
            .allocator = allocator,
            .snapshots_dir = snapshots_dir,
            .rpc_endpoints = std.ArrayListUnmanaged([]const u8){},
            .known_validators = std.ArrayListUnmanaged([]const u8){},
            .current_download = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.rpc_endpoints.deinit(self.allocator);
        self.known_validators.deinit(self.allocator);
    }

    /// Add an RPC endpoint to try for downloads.
    ///
    /// RULE #1 chokepoint: every snapshot RPC seed funnels through here, so this
    /// is the single place to enforce the oracle-node deny-list for OPERATOR-supplied
    /// seeds (e.g. `--rpc-url`). An explicit operator seed pointing at a denied
    /// host is a hard error — we refuse rather than silently ignore the operator's
    /// instruction, so the misconfiguration is loud at boot. (Discovered cluster
    /// peers are filtered silently in the peer loops; see isDeniedSnapshotHost.)
    pub fn addRpcEndpoint(self: *Self, endpoint: []const u8) !void {
        if (isDeniedSnapshotHost(endpoint)) {
            std.log.err(
                "[Snapshot][RULE#1] REFUSING snapshot RPC endpoint '{s}' — host is on the " ++
                    "oracle-node deny-list. Vexor must never fetch snapshot/state from the " ++
                    "co-located Agave validator. Fix --rpc-url / VEX_RPC_URL.",
                .{endpoint},
            );
            return error.DeniedRpcEndpoint;
        }
        try self.rpc_endpoints.append(self.allocator, endpoint);
    }

    /// Find the best available snapshot from RPC endpoints

    // ── curl-based HTTP helpers (Zig 0.15.2 compatible) ─────────────────────

    /// POST JSON to a URL, return response body. Caller owns returned slice.
    fn curlPost(self: *Self, url: []const u8, json_body: []const u8) ![]u8 {
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "/usr/bin/curl", "-sL",                            "--max-time", "15",
                "-H",            "Content-Type: application/json", "-d",         json_body,
                url,
            },
            .max_output_bytes = 512 * 1024,
        }) catch return error.CurlFailed;
        defer self.allocator.free(result.stderr);
        if (result.stdout.len == 0) {
            self.allocator.free(result.stdout);
            return error.EmptyResponse;
        }
        return result.stdout;
    }

    /// HEAD request — returns HTTP status code and content-length
    fn curlHead(self: *Self, url: []const u8) !struct { status: u32, content_length: u64 } {
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "/usr/bin/curl", "-sL",       "--max-time", "10",
                "-o",            "/dev/null", "-w",         "%{http_code}|%{size_download}|%{content_type}",
                "-I",            url,
            },
            .max_output_bytes = 2048,
        }) catch return error.CurlFailed;
        defer self.allocator.free(result.stderr);
        defer self.allocator.free(result.stdout);

        const raw = std.mem.trim(u8, result.stdout, " \r\n");
        const pipe1 = std.mem.indexOf(u8, raw, "|") orelse return error.ParseError;
        const status = std.fmt.parseInt(u32, raw[0..pipe1], 10) catch return error.ParseError;
        return .{ .status = status, .content_length = 0 };
    }

    /// Download a URL to a file using curl. Two failure modes are guarded:
    ///   Path A — HTTP 4xx/5xx: `--fail-with-body` causes curl to exit non-zero
    ///            with the body preserved on disk for diagnostics. We delete the
    ///            partial file and return error.DownloadFailed.
    ///   Path B — HTTP 200 with empty body: curl exits 0 but writes a 0-byte
    ///            file. `rejectEmptyDownload` stats the result post-curl and
    ///            deletes any sub-1MB output, returning error.EmptyDownload.
    ///
    /// IMPORTANT: --fail-with-body does NOT catch the recurring HTTP 200 +
    /// empty body case — that is what the post-download size check below is
    /// for. Do NOT remove the size check thinking the curl flag covers it;
    /// they guard different failure modes. (See bf8bdc98, 2026-05-05.)
    fn curlDownload(self: *Self, url: []const u8, output_path: []const u8) !void {
        var child = std.process.Child.init(
            &.{ "/usr/bin/curl", "-L", "--fail-with-body", "--max-time", "600", "--retry", "3", "--retry-delay", "5", "-o", output_path, url },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
        child.spawn() catch return error.CurlFailed;
        const term = child.wait() catch return error.CurlFailed;
        if (term.Exited != 0) {
            // Delete the partial/error-body file so a subsequent retry doesn't see
            // it as a "preserved" download. Errors here are intentionally swallowed
            // — best-effort cleanup; the caller will retry or fall back regardless.
            std.fs.cwd().deleteFile(output_path) catch {};
            std.fs.deleteFileAbsolute(output_path) catch {};
            std.log.warn("[Snapshot] curl exit {d} for {s} (deleted partial file)", .{ term.Exited, url });
            return error.DownloadFailed;
        }
        try self.rejectEmptyDownload(output_path, url);
    }

    /// Stat a freshly-downloaded file and reject anything smaller than
    /// MIN_SNAPSHOT_DOWNLOAD_BYTES — the load-bearing guard against the
    /// HTTP-200-with-empty-body failure mode where curl claims success
    /// but the server returned 0 bytes.
    fn rejectEmptyDownload(self: *Self, output_path: []const u8, source_url: []const u8) !void {
        _ = self;
        const stat = blk: {
            if (std.fs.path.isAbsolute(output_path)) {
                break :blk std.fs.cwd().statFile(output_path) catch |err| {
                    std.log.warn("[Snapshot] post-download stat failed for {s}: {any}", .{ output_path, err });
                    return error.DownloadFailed;
                };
            } else {
                break :blk std.fs.cwd().statFile(output_path) catch |err| {
                    std.log.warn("[Snapshot] post-download stat failed for {s}: {any}", .{ output_path, err });
                    return error.DownloadFailed;
                };
            }
        };
        if (stat.size < MIN_SNAPSHOT_DOWNLOAD_BYTES) {
            std.fs.cwd().deleteFile(output_path) catch {};
            std.fs.deleteFileAbsolute(output_path) catch {};
            std.log.warn(
                "[Snapshot] suspiciously small download from {s}: {d} bytes (< {d} threshold) — deleted",
                .{ source_url, stat.size, MIN_SNAPSHOT_DOWNLOAD_BYTES },
            );
            return error.EmptyDownload;
        }
    }

    // ── Snapshot pair: full + optional incremental ────────────────────────────────

    /// A matched pair of full and incremental snapshots from the same peer.
    /// The incremental's base_slot must equal the full's slot.
    pub const SnapshotPair = struct {
        full: SnapshotInfo,
        incremental: ?SnapshotInfo,
    };

    // ── Canonical URL discovery ───────────────────────────────────────────────────

    /// Discover the canonical URL of a snapshot endpoint by following HTTP redirects.
    /// Many validators serve /snapshot.tar.zst → redirect → /snapshot-SLOT-HASH.tar.zst
    /// Returns the final URL (after redirects) or null on failure.
    /// Caller owns the returned slice.
    fn discoverCanonicalUrl(self: *Self, endpoint_url: []const u8) !?[]u8 {
        // curl -sL: follow redirects, output: "STATUS_CODE|FINAL_URL"
        // We check the HTTP status code to detect 404 vs 200 vs redirect.
        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{
                "/usr/bin/curl", "-sL",       "--max-time", "10",
                "-o",            "/dev/null", "-w",         "%{http_code}|%{url_effective}",
                endpoint_url,
            },
            .max_output_bytes = 2048,
        }) catch return null;
        defer self.allocator.free(result.stderr);

        const raw = std.mem.trim(u8, result.stdout, " \r\n");
        defer self.allocator.free(result.stdout);

        // Parse "STATUS|URL"
        const pipe = std.mem.indexOf(u8, raw, "|") orelse return null;
        const status_str = raw[0..pipe];
        const url = raw[pipe + 1 ..];

        const status = std.fmt.parseInt(u32, status_str, 10) catch return null;
        if (status < 200 or status >= 400) {
            // 404, 403, 503, etc — server doesn't have this file
            return null;
        }
        if (url.len == 0 or !std.mem.startsWith(u8, url, "http")) return null;

        return self.allocator.dupe(u8, url) catch null;
    }

    /// Extract the node base URL from a full snapshot download URL.
    /// "http://IP:PORT/snapshot-SLOT-HASH.tar.zst" → "http://IP:PORT"
    fn extractNodeBase(url: []const u8) ?[]const u8 {
        // Skip protocol
        var pos: usize = 0;
        if (std.mem.startsWith(u8, url, "http://")) pos = 7 else if (std.mem.startsWith(u8, url, "https://")) pos = 8 else return null;
        // Find first slash after host:port
        const slash = std.mem.indexOfScalarPos(u8, url, pos, '/') orelse return url;
        return url[0..slash];
    }

    /// Try to discover and download the incremental snapshot from a node,
    /// given we already have the full snapshot at full_slot from that node_base.
    /// Returns SnapshotInfo for the incremental, or null if not available.
    /// Caller must free info.download_url if non-null.
    /// Query a validator node's getHighestSnapshotSlot RPC to get the incremental
    /// slot number. Returns null if the incremental slot doesn't match full_slot
    /// as the base, or if the RPC call fails.
    fn queryIncrementalSlotFromNode(self: *Self, node_url: []const u8, full_slot: u64) ?u64 {
        const body_str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHighestSnapshotSlot\"}";
        const resp = self.curlPost(node_url, body_str) catch return null;
        defer self.allocator.free(resp);

        // Parse: {"result":{"full":397941437,"incremental":398009908}}
        const full_key = "\"full\":";
        const full_idx = std.mem.indexOf(u8, resp, full_key) orelse return null;
        var pos = full_idx + full_key.len;
        while (pos < resp.len and resp[pos] == ' ') pos += 1;
        var end = pos;
        while (end < resp.len and resp[end] >= '0' and resp[end] <= '9') end += 1;
        const resp_full = std.fmt.parseInt(u64, resp[pos..end], 10) catch return null;

        if (resp_full != full_slot) return null; // This node has a different full snapshot base

        const inc_key = "\"incremental\":";
        const inc_idx = std.mem.indexOf(u8, resp, inc_key) orelse return null;
        pos = inc_idx + inc_key.len;
        while (pos < resp.len and resp[pos] == ' ') pos += 1;
        end = pos;
        while (end < resp.len and resp[end] >= '0' and resp[end] <= '9') end += 1;
        return std.fmt.parseInt(u64, resp[pos..end], 10) catch null;
    }

    fn tryNodeIncrementalSnapshot(
        self: *Self,
        node_base: []const u8,
        full_slot: u64,
    ) !?SnapshotInfo {

        // Try both .tar.zst and .tar.bz2 — same approach that works for full snapshots.
        // Some validators redirect to canonical name only on .tar.bz2, not .tar.zst.
        const inc_candidates = [_][]const u8{
            "incremental-snapshot.tar.zst",
            "incremental-snapshot.tar.bz2",
        };

        for (inc_candidates) |inc_suffix| {
            const redirect_url = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ node_base, inc_suffix });
            defer self.allocator.free(redirect_url);

            std.log.debug("[Snapshot] Probing incremental at {s}\n", .{redirect_url});

            // Follow redirect to get canonical filename with slot+hash
            const canonical = (try self.discoverCanonicalUrl(redirect_url)) orelse {
                std.log.debug("[Snapshot] No redirect for {s}\n", .{redirect_url});
                continue; // Try next candidate (.tar.bz2)
            };
            defer self.allocator.free(canonical);

            // Extract just the filename from the canonical URL
            const filename = if (std.mem.lastIndexOf(u8, canonical, "/")) |idx|
                canonical[idx + 1 ..]
            else
                canonical;

            std.log.debug("[Snapshot] Incremental canonical: {s}\n", .{filename});

            // Try to parse slot+hash from canonical filename
            if (SnapshotInfo.fromFilename(filename)) |parsed| {
                // Full canonical URL with slot+hash — verify base matches and return
                if (parsed.base_slot) |base| {
                    if (base != full_slot) {
                        std.log.warn("[Snapshot] Incremental base {d} != full slot {d} — skipping", .{
                            base, full_slot,
                        });
                        return null;
                    }
                } else {
                    return null;
                }

                var info = parsed;
                info.download_url = try self.allocator.dupe(u8, canonical);
                std.log.info("[Snapshot] Incremental found via canonical URL: slot {d} (base {d})", .{
                    info.slot, full_slot,
                });
                return info;
            }

            // Generic URL (no slot/hash in filename) — try querying this node's RPC to get the
            // incremental slot number, then accept the generic URL as the download source.
            // Many validators serve at /incremental-snapshot.tar.zst directly without redirect.
            const rpc_url = try std.fmt.allocPrint(self.allocator, "{s}", .{node_base});
            defer self.allocator.free(rpc_url);

            const inc_slot = self.queryIncrementalSlotFromNode(rpc_url, full_slot) orelse {
                std.log.debug("[Snapshot] Cannot determine incremental slot from {s}\n", .{node_base});
                continue; // Try next candidate
            };

            const download_url = try self.allocator.dupe(u8, canonical);
            errdefer self.allocator.free(download_url);

            std.log.info("[Snapshot] Incremental found via generic URL: slot {d} (base {d}) from {s}", .{
                inc_slot, full_slot, node_base,
            });

            return SnapshotInfo{
                .slot = inc_slot,
                .hash = std.mem.zeroes([32]u8),
                .base_slot = full_slot,
                .lamports = 0,
                .capitalization = 0,
                .accounts_count = 0,
                .size_bytes = 0,
                .is_incremental = true,
                .download_url = download_url,
                .filename = null,
                .hash_str = std.mem.zeroes([64]u8),
                .hash_str_len = 0,
            };
        } // end for inc_candidates
        return null;
    }

    /// Find the best available (full + incremental) snapshot pair.
    /// Checks each cluster node for BOTH full AND incremental in a single pass
    /// so the pair always comes from the same source with the same base slot.
    pub fn findBestSnapshotPair(self: *Self) !?SnapshotPair {
        if (try self.envSnapshotOverride()) |info| {
            return SnapshotPair{ .full = info, .incremental = null };
        }

        for (self.rpc_endpoints.items) |endpoint| {
            std.log.debug("[Snapshot] Querying: {s}\n", .{endpoint});
            if (try self.discoverSnapshotPairFromCluster(endpoint, 0)) |pair| {
                return pair;
            }
        }

        std.log.debug("[Snapshot] No snapshot found from any endpoint\n", .{});
        return null;
    }

    pub fn findBestSnapshot(self: *Self) !?SnapshotInfo {
        std.log.debug("[Snapshot] findBestSnapshot called, {d} endpoints\n", .{self.rpc_endpoints.items.len});

        if (try self.envSnapshotOverride()) |info| {
            return info;
        }

        for (self.rpc_endpoints.items) |endpoint| {
            std.log.debug("[Snapshot] Querying: {s}\n", .{endpoint});

            if (try self.querySnapshotFromRpc(endpoint)) |info| {
                std.log.debug("[Snapshot] Got info for slot {d}\n", .{info.slot});
                return info;
            }
        }
        std.log.debug("[Snapshot] No snapshot found from any endpoint\n", .{});
        return null;
    }

    fn envSnapshotOverride(self: *Self) !?SnapshotInfo {
        const url = std.process.getEnvVarOwned(self.allocator, "VEXOR_SNAPSHOT_URL") catch return null;
        defer self.allocator.free(url);

        // RULE #1 (fourth ingress): VEXOR_SNAPSHOT_URL is the operator's direct
        // download-URL override — it bypasses addRpcEndpoint and the peer loops
        // entirely (findBestSnapshotPair returns it before iterating rpc_endpoints),
        // so the deny-list MUST be enforced here too or a
        // VEXOR_SNAPSHOT_URL=http://38.92.24.174:.../snapshot.tar.zst would pull
        // straight from the oracle-node. Hard-fail (consistent with --rpc-url): refuse
        // rather than silently ignore an explicit operator URL.
        if (isDeniedSnapshotHost(url)) {
            std.log.err(
                "[Snapshot][RULE#1] REFUSING VEXOR_SNAPSHOT_URL '{s}' — host is on the " ++
                    "oracle-node deny-list. Vexor must never fetch snapshot/state from the " ++
                    "co-located Agave validator.",
                .{url},
            );
            return error.DeniedRpcEndpoint;
        }

        var slot: u64 = 0;
        if (std.process.getEnvVarOwned(self.allocator, "VEXOR_SNAPSHOT_SLOT")) |value| {
            defer self.allocator.free(value);
            slot = std.fmt.parseInt(u64, value, 10) catch 0;
        } else |_| {}

        if (slot == 0) {
            if (std.mem.lastIndexOf(u8, url, "/")) |idx| {
                const name = url[idx + 1 ..];
                if (SnapshotInfo.fromFilename(name)) |parsed| {
                    slot = parsed.slot;
                }
            }
        }

        if (slot == 0) {
            std.log.warn("[Snapshot] VEXOR_SNAPSHOT_URL set but slot missing; set VEXOR_SNAPSHOT_SLOT", .{});
            return null;
        }

        const url_copy = try self.allocator.dupe(u8, url);
        errdefer self.allocator.free(url_copy);

        var size_bytes: u64 = 0;
        var max_bytes: u64 = 0;
        if (std.process.getEnvVarOwned(self.allocator, "VEXOR_SNAPSHOT_MAX_BYTES")) |value| {
            defer self.allocator.free(value);
            max_bytes = std.fmt.parseInt(u64, value, 10) catch 0;
        } else |_| {}

        // Try HEAD request via curl to get size
        if (self.curlHead(url_copy)) |head| {
            size_bytes = head.content_length;
        } else |_| {}

        if (max_bytes > 0 and size_bytes > max_bytes) {
            std.log.warn("[Snapshot] Env snapshot too large ({d} bytes) > max {d}", .{ size_bytes, max_bytes });
            self.allocator.free(url_copy);
            return null;
        }

        std.log.info("[Snapshot] Using env snapshot url (slot {d})", .{slot});
        return SnapshotInfo{
            .slot = slot,
            .hash = std.mem.zeroes([32]u8),
            .base_slot = null,
            .lamports = 0,
            .capitalization = 0,
            .accounts_count = 0,
            .size_bytes = size_bytes,
            .is_incremental = false,
            .download_url = url_copy,
            .filename = null,
            .hash_str = undefined,
            .hash_str_len = 0,
        };
    }

    /// Query an RPC endpoint for available snapshots
    /// Uses getHighestSnapshotSlot RPC method then finds snapshot from known providers
    fn querySnapshotFromRpc(self: *Self, endpoint: []const u8) !?SnapshotInfo {
        std.log.debug("[Snapshot] querySnapshotFromRpc: {s}\n", .{endpoint});

        // Determine cluster from endpoint
        const is_testnet = std.mem.indexOf(u8, endpoint, "testnet") != null;
        const is_devnet = std.mem.indexOf(u8, endpoint, "devnet") != null;
        const is_mainnet = std.mem.indexOf(u8, endpoint, "mainnet") != null;
        _ = is_testnet;
        _ = is_devnet;
        _ = is_mainnet;

        // Get highest snapshot slot via RPC (curl-based for Zig 0.15.2 compat)
        const request_body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHighestSnapshotSlot\"}";

        std.log.debug("[Snapshot] Querying getHighestSnapshotSlot via curl...\n", .{});
        const response = self.curlPost(endpoint, request_body) catch |err| {
            std.log.debug("[Snapshot] RPC query failed: {any}\n", .{err});
            return null;
        };
        defer self.allocator.free(response);

        std.log.debug("[Snapshot] Response: {s}\n", .{response[0..@min(response.len, 256)]});

        const slot = self.parseSnapshotSlot(response) orelse {
            std.log.warn("[Snapshot] Failed to parse snapshot slot from response", .{});
            return null;
        };

        std.log.info("[Snapshot] Highest snapshot slot: {d}", .{slot});

        // Try to discover snapshot from cluster nodes via getClusterNodes
        if (try self.discoverSnapshotFromCluster(endpoint, slot)) |info| {
            return info;
        }

        // Fallback: construct a placeholder that will use local catchup via shred repair
        std.log.info("[Snapshot] No snapshot found from cluster nodes - will use FAST CATCHUP mode", .{});

        return SnapshotInfo{
            .slot = slot,
            .hash = std.mem.zeroes([32]u8),
            .base_slot = null,
            .lamports = 0,
            .capitalization = 0,
            .accounts_count = 0,
            .size_bytes = 0,
            .is_incremental = false,
            .download_url = null, // No direct download, will use shred repair catchup
            .filename = null,
            .hash_str = undefined,
            .hash_str_len = 0,
        };
    }

    /// Discover snapshot from cluster nodes using getClusterNodes RPC
    fn discoverSnapshotFromCluster(self: *Self, endpoint: []const u8, target_slot: u64) !?SnapshotInfo {
        // Wrapper: call the pair version and return just the full snapshot
        if (try self.discoverSnapshotPairFromCluster(endpoint, target_slot)) |pair| {
            return pair.full;
        }
        return null;
    }

    /// Discover a matched full+incremental snapshot pair from cluster nodes.
    /// Checks BOTH full and incremental at each node in a single pass,
    /// ensuring the pair is always from the same source (same base slot).
    fn discoverSnapshotPairFromCluster(self: *Self, endpoint: []const u8, target_slot: u64) !?SnapshotPair {
        std.log.debug("[Snapshot] Discovering from cluster nodes...\n", .{});

        const request_body =
            \\{"jsonrpc":"2.0","id":1,"method":"getClusterNodes"}
        ;

        const response = self.curlPost(endpoint, request_body) catch |err| {
            std.log.debug("[Snapshot] getClusterNodes failed: {any}\n", .{err});
            return null;
        };
        defer self.allocator.free(response);

        var nodes_found: usize = 0;
        var nodes_tried: usize = 0;
        var pos: usize = 0;

        while (std.mem.indexOf(u8, response[pos..], "\"rpc\":\"")) |idx| {
            nodes_found += 1;
            const start = pos + idx + 7;
            const end = std.mem.indexOf(u8, response[start..], "\"") orelse break;
            const rpc_addr = response[start .. start + end];
            pos = start + end;

            if (rpc_addr.len == 0 or std.mem.eql(u8, rpc_addr, "null")) continue;
            // RULE #1: never probe/download from the co-located Agave oracle-node.
            // Discovered-peer case → silent skip (normal cluster filtering).
            if (isDeniedSnapshotHost(rpc_addr)) {
                std.log.debug("[Snapshot][RULE#1] skipping deny-listed peer {s}\n", .{rpc_addr});
                continue;
            }
            nodes_tried += 1;
            if (nodes_tried > 15) {
                std.log.debug("[Snapshot] Tried 15 nodes, stopping\n", .{});
                break;
            }

            const node_url = try std.fmt.allocPrint(self.allocator, "http://{s}", .{rpc_addr});
            defer self.allocator.free(node_url);

            std.log.debug("[Snapshot] Trying node: {s}\n", .{rpc_addr});

            // Try to get full snapshot from this node
            const full = (try self.tryNodeSnapshot(node_url, target_slot)) orelse continue;

            std.log.debug("[Snapshot] ✅ Found full from {s}: slot {d}\n", .{ rpc_addr, full.slot });

            // Immediately try incremental from the SAME node (same base slot guaranteed)
            const node_base = extractNodeBase(full.download_url orelse {
                return SnapshotPair{ .full = full, .incremental = null };
            }) orelse return SnapshotPair{ .full = full, .incremental = null };

            if (try self.tryNodeIncrementalSnapshot(node_base, full.slot)) |inc| {
                std.log.debug("[Snapshot] ✅✅ PAIR FOUND: full {d} + incremental {d} from {s}\n", .{ full.slot, inc.slot, rpc_addr });
                return SnapshotPair{ .full = full, .incremental = inc };
            }

            std.log.debug("[Snapshot] Full-only from {s} (no incremental)\n", .{rpc_addr});
            // Keep this as best-so-far but continue looking for a node with both
            // For now return immediately with full-only (can be improved later)
            return SnapshotPair{ .full = full, .incremental = null };
        }

        std.log.debug("[Snapshot] Found {d} nodes, tried {d}\n", .{ nodes_found, nodes_tried });
        return null;
    }

    /// vex-030: find an incremental snapshot with the given base_slot from ANY
    /// peer in the cluster, excluding peers already tried. Used when the
    /// primary peer's incremental download fails but we've already loaded its
    /// full at full_slot.
    ///
    /// Returns null if no peer in the cluster serves an incremental whose
    /// base matches full_slot (within max_peers_to_try attempts).
    pub fn findIncrementalAcrossPeers(
        self: *Self,
        endpoint: []const u8,
        full_slot: u64,
        tried_peers: []const []const u8,
        max_peers_to_try: usize,
    ) !?SnapshotInfo {
        const request_body =
            \\{"jsonrpc":"2.0","id":1,"method":"getClusterNodes"}
        ;

        const response = self.curlPost(endpoint, request_body) catch return null;
        defer self.allocator.free(response);

        var nodes_probed: usize = 0;
        var pos: usize = 0;

        while (std.mem.indexOf(u8, response[pos..], "\"rpc\":\"")) |idx| {
            const start = pos + idx + 7;
            const end = std.mem.indexOf(u8, response[start..], "\"") orelse break;
            const rpc_addr = response[start .. start + end];
            pos = start + end;

            if (rpc_addr.len == 0 or std.mem.eql(u8, rpc_addr, "null")) continue;
            // RULE #1: never rotate to the co-located Agave oracle-node for an
            // incremental — silent skip (discovered-peer case).
            if (isDeniedSnapshotHost(rpc_addr)) continue;

            // Skip peers already tried
            var already_tried = false;
            for (tried_peers) |tp| {
                if (std.mem.eql(u8, tp, rpc_addr)) {
                    already_tried = true;
                    break;
                }
            }
            if (already_tried) continue;

            nodes_probed += 1;
            if (nodes_probed > max_peers_to_try) break;

            const node_url = try std.fmt.allocPrint(self.allocator, "http://{s}", .{rpc_addr});
            defer self.allocator.free(node_url);

            // Note: was std.debug.print pre-2026-05-05; promoted to std.log.warn to avoid
            // the Writer.zig:639 stderr-saturation panic class addressed by anchor 51e0a3a4.
            std.log.warn("[Snapshot] Rotating to peer {s} for incremental (full_slot={d})", .{ rpc_addr, full_slot });

            const inc = (try self.tryNodeIncrementalSnapshot(node_url, full_slot)) orelse continue;
            return inc;
        }

        return null;
    }

    /// Try to get a full snapshot from a specific validator node.
    /// Uses the redirect approach: validators redirect /snapshot.tar.zst
    /// to the canonical URL /snapshot-SLOT-HASH.tar.zst, which gives us
    /// both the slot and hash without needing gossip.
    fn tryNodeSnapshot(self: *Self, node_url: []const u8, target_slot: u64) !?SnapshotInfo {
        _ = target_slot; // We accept any slot — caller filters by recency

        // Try modern .tar.zst redirect first, then legacy .tar.bz2
        const candidates = [_][]const u8{ "snapshot.tar.zst", "snapshot.tar.bz2" };

        for (candidates) |suffix| {
            const probe_url = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ node_url, suffix }) catch continue;
            defer self.allocator.free(probe_url);

            std.log.debug("[Snapshot] Probing full snapshot: {s}\n", .{probe_url});

            // Follow HTTP redirect to get canonical filename with slot+hash.
            // Returns null on 404/403/error. Returns URL (possibly unchanged) on 200.
            const canonical = (self.discoverCanonicalUrl(probe_url) catch continue) orelse {
                std.log.debug("[Snapshot] {s} → 404/error, skipping\n", .{probe_url});
                continue;
            };
            defer self.allocator.free(canonical);

            // Extract filename from canonical URL
            const filename = if (std.mem.lastIndexOf(u8, canonical, "/")) |idx|
                canonical[idx + 1 ..]
            else
                canonical;

            std.log.debug("[Snapshot] Full canonical: {s}\n", .{filename});

            // Case 1: Redirect gave us canonical name with slot+hash
            if (SnapshotInfo.fromFilename(filename)) |info_parsed| {
                if (info_parsed.is_incremental) {
                    std.log.debug("[Snapshot] Skipping incremental file in full probe\n", .{});
                    continue;
                }
                const download_url = self.allocator.dupe(u8, canonical) catch {
                    std.log.debug("[Snapshot] dupe failed for canonical URL\n", .{});
                    continue;
                };
                var info = info_parsed;
                info.download_url = download_url;
                std.log.debug("[Snapshot] ✅ Found full snapshot at {s}: slot {d} (canonical)\n", .{ node_url, info.slot });
                return info;
            }
            std.log.debug("[Snapshot] fromFilename returned null for: {s}\n", .{filename});

            // Case 2: 200 OK but no redirect (server serves directly at generic URL).
            // Get the slot from the node's RPC instead.
            std.log.debug("[Snapshot] Direct serve (no redirect) — querying RPC for slot\n", .{});
            const node_base = extractNodeBase(canonical) orelse node_url;
            const slot: ?u64 = blk: {
                const body_str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHighestSnapshotSlot\"}";
                const resp = self.curlPost(node_base, body_str) catch break :blk null;
                defer self.allocator.free(resp);
                const key = "\"full\":";
                const idx = std.mem.indexOf(u8, resp, key) orelse break :blk null;
                var p = idx + key.len;
                while (p < resp.len and resp[p] == ' ') p += 1;
                var e = p;
                while (e < resp.len and resp[e] >= '0' and resp[e] <= '9') e += 1;
                break :blk std.fmt.parseInt(u64, resp[p..e], 10) catch null;
            };

            if (slot) |s| {
                const download_url = self.allocator.dupe(u8, canonical) catch continue;
                std.log.debug("[Snapshot] ✅ Found full snapshot at {s}: slot {d} (direct serve)\n", .{ node_url, s });
                return SnapshotInfo{
                    .slot = s,
                    .hash = std.mem.zeroes([32]u8),
                    .base_slot = null,
                    .lamports = 0,
                    .capitalization = 0,
                    .accounts_count = 0,
                    .size_bytes = 0,
                    .is_incremental = false,
                    .download_url = download_url,
                    .filename = null,
                    .hash_str = std.mem.zeroes([64]u8),
                    .hash_str_len = 0,
                };
            }
        }
        return null;
    }

    /// Parse snapshot slot from RPC response
    fn parseSnapshotSlot(self: *Self, response: []const u8) ?u64 {
        _ = self;
        // Look for "full": in the response
        const full_key = "\"full\":";
        const idx = std.mem.indexOf(u8, response, full_key) orelse return null;
        const start = idx + full_key.len;

        var end = start;
        while (end < response.len and (response[end] >= '0' and response[end] <= '9')) : (end += 1) {}

        if (end == start) return null;

        return std.fmt.parseInt(u64, response[start..end], 10) catch null;
    }

    /// Download a snapshot using curl (Zig 0.15.2 compatible)
    pub fn download(self: *Self, info: *const SnapshotInfo, progress_callback: ?*const fn (DownloadProgress) void) !void {
        _ = progress_callback; // curl handles its own progress output
        const url = info.download_url orelse return error.NoDownloadUrl;

        // Derive local filename from the download URL
        const url_filename = if (std.mem.lastIndexOf(u8, url, "/")) |idx| url[idx + 1 ..] else url;
        const filename = if (SnapshotInfo.fromFilename(url_filename) != null)
            try self.allocator.dupe(u8, url_filename)
        else
            try self.generateFilename(info);
        defer self.allocator.free(filename);

        const path = try std.fs.path.join(self.allocator, &.{ self.snapshots_dir, filename });
        defer self.allocator.free(path);

        std.log.debug("[Snapshot] Downloading {s} → {s}\n", .{ url, path });
        try self.curlDownload(url, path);
    }

    fn generateFilename(self: *Self, info: *const SnapshotInfo) ![]u8 {
        _ = self;
        // Use the real hash from the parsed canonical URL when available.
        // Falls back to slot-only name when hash wasn't extractable.
        const hash_str: []const u8 = if (info.hash_str_len > 0)
            info.hash_str[0..info.hash_str_len]
        else
            "unknown";

        if (info.is_incremental) {
            return try std.fmt.allocPrint(std.heap.page_allocator, "incremental-snapshot-{d}-{d}-{s}.tar.zst", .{
                info.base_slot.?,
                info.slot,
                hash_str,
            });
        } else {
            return try std.fmt.allocPrint(std.heap.page_allocator, "snapshot-{d}-{s}.tar.zst", .{
                info.slot,
                hash_str,
            });
        }
    }

    // httpDownload replaced by curlDownload helper above

    /// Extract a downloaded snapshot
    /// Supports both .tar.zst and .tar.bz2 formats (auto-detected from extension)
    pub fn extract(self: *Self, snapshot_path: []const u8, output_dir: []const u8) !void {
        _ = self;

        // Create output directory
        try fs.cwd().makePath(output_dir);

        // Auto-detect compression format from file extension
        // Use multi-threaded decompression for maximum throughput:
        //   zstd: -T0 uses ALL CPU cores for parallel decompression (4-8x faster on multi-core)
        //   bzip2: try pbzip2 (parallel) first, fallback to bzip2
        const is_bz2 = std.mem.endsWith(u8, snapshot_path, ".tar.bz2");
        const decompress_prog: []const u8 = if (is_bz2) "pbzip2 -d" else "zstd -T0 -d";
        std.log.info("[Snapshot] Extracting with PARALLEL decompressor '{s}': {s}", .{ decompress_prog, snapshot_path });

        // Use system tar command with multi-threaded decompressor
        var child = std.process.Child.init(
            &.{ "tar", "--use-compress-program", decompress_prog, "-xf", snapshot_path, "-C", output_dir },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        child.spawn() catch |err| {
            std.log.err("[Snapshot] Failed to spawn tar process: {}", .{err});
            return error.ExtractionFailed;
        };
        const term = child.wait() catch |err| {
            std.log.err("[Snapshot] Failed waiting for tar process: {}", .{err});
            return error.ExtractionFailed;
        };
        if (term.Exited != 0) {
            std.log.err("[Snapshot] tar extraction failed with exit code {}", .{term.Exited});
            return error.ExtractionFailed;
        }

        std.log.info("[Snapshot] Extracted snapshot to {s}", .{output_dir});

        // Fix permissions - snapshot archives often have restrictive perms
        // r72-perm-fix (2026-05-05): use u+rwX (was u+r). +write defends against
        // future write paths; X = +execute on directories only (essential —
        // mode-000 dirs without +x can't be entered, mmap fails on contained files).
        const chmod_result = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &.{ "chmod", "-R", "u+rwX", output_dir },
        }) catch |err| {
            std.log.warn("[Snapshot] Failed to fix permissions: {}", .{err});
            return; // Don't fail, just warn
        };

        if (chmod_result.term.Exited != 0) {
            std.log.warn("[Snapshot] chmod failed: {s}", .{chmod_result.stderr});
        }

        std.log.info("[Snapshot] Successfully prepared snapshot in {s}", .{output_dir});
    }

    fn extractTar(self: *Self, reader: anytype, output_dir: []const u8) !void {
        _ = self;
        _ = output_dir;

        // TAR header is 512 bytes
        var header_buf: [512]u8 = undefined;

        while (true) {
            // Read header
            const bytes_read = try reader.readAll(&header_buf);
            if (bytes_read < 512) break;

            // Check for empty header (end of archive)
            var all_zero = true;
            for (header_buf) |b| {
                if (b != 0) {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero) break;

            // Parse TAR header
            const tar_header = parseTarHeader(&header_buf) orelse break;
            _ = tar_header;

            // Would extract file based on header type
            // - Regular file: read content to file
            // - Directory: create directory
            // - Symlink: create symlink
        }
    }

    /// Load snapshot into accounts database
    /// Parsed bank metadata from snapshot binary.
    pub fn loadSnapshot(self: *Self, snapshot_dir: []const u8, accounts_db: anytype) !LoadResult {
        std.log.debug("[DEBUG] loadSnapshot: entering function, dir={s}\n", .{snapshot_dir});

        // Snapshot directory structure:
        // snapshot_dir/
        //   accounts/
        //     <slot>.0  (appendvec files)
        //     <slot>.1
        //     ...
        //   snapshots/
        //     <slot>/
        //       status_cache
        //       <slot>  (bank metadata)
        //   version

        // Read version file
        const version_path = try std.fs.path.join(self.allocator, &.{ snapshot_dir, "version" });
        defer self.allocator.free(version_path);
        std.log.debug("[DEBUG] loadSnapshot: reading version from {s}\n", .{version_path});

        var version_file = fs.cwd().openFile(version_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.debug("[DEBUG] loadSnapshot: version file not found!\n", .{});
                return error.InvalidSnapshot;
            },
            else => return err,
        };
        defer version_file.close();

        var version_buf: [32]u8 = undefined;
        const version_len = try version_file.readAll(&version_buf);
        const version = std.mem.trim(u8, version_buf[0..version_len], " \n\r\t");
        std.log.debug("[DEBUG] loadSnapshot: version={s}\n", .{version});

        // Validate version
        if (!std.mem.eql(u8, version, "1.2.0") and
            !std.mem.eql(u8, version, "1.2.1") and
            !std.mem.eql(u8, version, "1.3.0") and
            !std.mem.eql(u8, version, "1.3.1"))
        {
            std.log.debug("[DEBUG] loadSnapshot: unsupported version!\n", .{});
            return error.UnsupportedSnapshotVersion;
        }

        // Load accounts from append vecs
        const accounts_path = try std.fs.path.join(self.allocator, &.{ snapshot_dir, "accounts" });
        defer self.allocator.free(accounts_path);
        std.log.debug("[DEBUG] loadSnapshot: accounts_path={s}\n", .{accounts_path});

        var accounts_loaded: u64 = 0;
        var lamports_total: u64 = 0;

        var accounts_dir = fs.cwd().openDir(accounts_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.debug("[DEBUG] loadSnapshot: accounts dir not found!\n", .{});
                return error.InvalidSnapshot;
            },
            else => return err,
        };
        defer accounts_dir.close();
        std.log.debug("[DEBUG] loadSnapshot: accounts dir opened, starting iteration\n", .{});

        // Enable bulk loading mode for faster snapshot ingestion
        if (@typeInfo(@TypeOf(accounts_db)) != .null) {
            if (@hasDecl(@TypeOf(accounts_db.*), "enableBulkLoading")) {
                accounts_db.enableBulkLoading();
            }
        }

        var iter = accounts_dir.iterate();
        var files_processed: u64 = 0;
        var max_slot_seen: u64 = 0;
        var last_log_time = std.time.milliTimestamp();

        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;

            // First file - log it
            if (files_processed == 0) {
                std.log.debug("[DEBUG] loadSnapshot: first file={s}\n", .{entry.name});
            }

            const slot = parseSlotFromFilename(entry.name) orelse 0;
            if (slot > max_slot_seen) max_slot_seen = slot;

            // Load append vec file
            const result = self.loadAppendVec(accounts_dir, entry.name, slot, accounts_db) catch |err| {
                std.log.debug("[DEBUG] loadSnapshot: failed to load {s}: {}\n", .{ entry.name, err });
                continue;
            };

            accounts_loaded = accounts_loaded +| result.accounts_count;
            lamports_total = lamports_total +| result.lamports_total;
            files_processed += 1;

            // Log progress every 5 seconds or every 1000 files
            const now = std.time.milliTimestamp();
            if (now - last_log_time > 5000 or files_processed % 1000 == 0) {
                std.log.debug("[DEBUG] loadSnapshot: Progress: {d} files, {d} accounts, {d} lamports\n", .{
                    files_processed, accounts_loaded, lamports_total,
                });
                last_log_time = now;
            }
        }

        // Disable bulk loading mode
        if (@typeInfo(@TypeOf(accounts_db)) != .null) {
            if (@hasDecl(@TypeOf(accounts_db.*), "disableBulkLoading")) {
                accounts_db.disableBulkLoading();
            }
        }

        std.log.info("[Snapshot] Complete: {d} files, {d} accounts, {d} lamports", .{
            files_processed, accounts_loaded, lamports_total,
        });

        // NOTE: Disabled here due to a crash in AutoHashMap iteration under load.
        // We can re-enable once storage map concurrency is hardened.

        return LoadResult{
            .slot = max_slot_seen,
            .accounts_loaded = accounts_loaded,
            .lamports_total = lamports_total,
        };
    }

    /// Save a local snapshot from AccountsDb (Solana-format appendvecs).
    pub fn saveSnapshot(self: *Self, accounts_db: anytype, slot: u64) !SaveResult {
        std.log.info("[Snapshot] saveSnapshot start slot={d}", .{slot});
        const output_dir = try std.fmt.allocPrint(self.allocator, "{s}/local-snapshot-{d}", .{ self.snapshots_dir, slot });
        try fs.cwd().makePath(output_dir);

        var accounts_dir_buf: [512]u8 = undefined;
        const accounts_dir = try std.fmt.bufPrint(&accounts_dir_buf, "{s}/accounts", .{output_dir});
        try fs.cwd().makePath(accounts_dir);

        var slot_str_buf: [64]u8 = undefined;
        const slot_str = try std.fmt.bufPrint(&slot_str_buf, "{d}", .{slot});
        var snapshots_dir_buf: [512]u8 = undefined;
        const snapshots_dir = try std.fmt.bufPrint(&snapshots_dir_buf, "{s}/snapshots/{s}", .{ output_dir, slot_str });
        try fs.cwd().makePath(snapshots_dir);

        // Version file for loader compatibility
        var version_path_buf: [512]u8 = undefined;
        const version_path = try std.fmt.bufPrint(&version_path_buf, "{s}/version", .{output_dir});
        {
            const version_file = try fs.cwd().createFile(version_path, .{ .truncate = true });
            defer version_file.close();
            try version_file.writeAll("1.3.1\n");
        }

        // NOTE: Disabled here due to crash in AutoHashMap iteration under load.
        // Re-enable once storage map concurrency is hardened.

        const accounts_hash = try accounts_db.computeHash();

        const accounts_hash_hex = std.fmt.bytesToHex(accounts_hash.data, .lower);

        var hash_path_buf: [512]u8 = undefined;
        const hash_path = try std.fmt.bufPrint(&hash_path_buf, "{s}/accounts_hash", .{snapshots_dir});
        {
            const hash_file = try fs.cwd().createFile(hash_path, .{ .truncate = true });
            defer hash_file.close();
            try hash_file.writeAll(&accounts_hash_hex);
            try hash_file.writeAll("\n");
        }

        var appendvec_path_buf: [512]u8 = undefined;
        const appendvec_path = try std.fmt.bufPrint(&appendvec_path_buf, "{s}/{d}.0", .{ accounts_dir, slot });
        const av_file = try fs.cwd().createFile(appendvec_path, .{ .truncate = true });
        defer av_file.close();

        // Big-chunk buffered AppendVec write (byte-transparent). Explicit flush
        // BEFORE the file closes / is re-stat'd so no buffered tail is lost.
        var bw = try snapshot_writer.BufferedAvWriter.init(self.allocator, av_file);
        defer bw.deinit();
        const stats = try accounts_db.writeSnapshotAppendVec(&bw);
        try bw.flush();

        std.log.info(
            "[Snapshot] saveSnapshot complete slot={d} accounts={d} lamports={d}",
            .{ slot, stats.accounts_written, stats.lamports_total },
        );
        return SaveResult{
            .slot = slot,
            .output_dir = output_dir,
            .accounts_written = stats.accounts_written,
            .lamports_total = stats.lamports_total,
            .accounts_hash_hex = accounts_hash_hex,
        };
    }

    /// Bank fields needed to build a loadable FULL snapshot manifest. The
    /// caller (RPC) sources these from the frozen bank. `accounts_lt_hash` MUST
    /// be the REAL 2048-byte bank.accounts_lthash ([BANK-FROZEN] lthash_full),
    /// NOT the simple accounts_hash.
    pub const FullSnapshotBankFields = struct {
        parent_slot: u64,
        bank_hash: [32]u8,
        parent_hash: [32]u8 = [_]u8{0} ** 32,
        last_blockhash: ?[32]u8 = null,
        capitalization: u64,
        block_height: u64,
        hashes_per_tick: ?u64 = null,
        ticks_per_slot: u64 = 64,
        epoch: u64 = 0,
        block_id: ?[32]u8 = null,
        accounts_lt_hash: [2048]u8,
        /// CONSENSUS-CRITICAL for round-trip (2026-06-26): the root bank's
        /// `fee_rate_governor` + `signature_count` are seeded from the manifest at
        /// bootstrap (bootstrap.zig:405-407) and drive the per-slot
        /// `FeeRateGovernor.newDerived` → the `lamports_per_signature` pushed into
        /// the RecentBlockhashes sysvar EVERY slot (bank.zig:1571-1573). Omitting
        /// them makes the reloaded governor default (lps=0) → the FIRST replayed
        /// slot's RBH sysvar differs by 8 bytes → accounts-lthash → bank_hash
        /// diverges (the epoch-979 carrier class). MUST be carried.
        fee_rate_governor: ?@import("snapshot_manifest.zig").FeeRateGovernor = null,
        signature_count: ?u64 = null,
    };

    /// The slot + bank metadata captured by `saveFullSnapshotAtTip`'s callback
    /// WHILE the accounts storage lock is held shared (i.e. while replay-writes are
    /// blocked), so the metadata and the walked account state are the SAME slot.
    pub const CapturedTip = struct {
        slot: u64,
        fields: FullSnapshotBankFields,
    };

    pub const FullSnapshotResult = struct {
        slot: u64,
        output_dir: []const u8,
        tar_path: []const u8,
        accounts_written: u64,
        lamports_total: u64,
        manifest_bytes: usize,
        accounts_hash_hex: [64]u8,

        pub fn deinit(self: *FullSnapshotResult, allocator: Allocator) void {
            allocator.free(self.output_dir);
            allocator.free(self.tar_path);
        }
    };

    /// Build a COMPLETE, loadable full snapshot and package it as
    /// `<name>-<slot>-<hash>.tar.zst`.
    ///
    /// Layout assembled under `<snapshots_dir>/local-snapshot-<slot>/`:
    ///   version                       ("1.3.1\n")
    ///   accounts/<slot>.0             (Agave-format AppendVec via writeSnapshotAppendVec)
    ///   snapshots/<slot>/<slot>       (bincode bank MANIFEST, write-side serializer)
    ///   snapshots/status_cache        (empty status-cache stub, documented)
    ///
    /// Then packaged with the SAME shell-tar approach `extract` uses (mirror,
    /// v1): `tar --use-compress-program 'zstd -T0' -cf <out>.tar.zst -C <parent> <dir>`.
    /// (v2 optimization: link system libzstd 1.5.4
    /// /usr/lib/x86_64-linux-gnu/libzstd.{a,so} via FFI for in-process streaming
    /// compression instead of shelling out — Zig 0.15.2 std has a zstd DECODER
    /// only.)
    ///
    /// CONSENSUS-SAFE: reads frozen account state + emits an artifact; never
    /// mutates bank_hash. Caller owns the returned FullSnapshotResult.
    pub fn saveFullSnapshot(
        self: *Self,
        accounts_db: anytype,
        slot: u64,
        bank_fields: FullSnapshotBankFields,
    ) !FullSnapshotResult {
        const snapshot_manifest = @import("snapshot_manifest.zig");
        std.log.info("[Snapshot] saveFullSnapshot start slot={d}", .{slot});

        const dir_name = try std.fmt.allocPrint(self.allocator, "local-snapshot-{d}", .{slot});
        defer self.allocator.free(dir_name);
        const output_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.snapshots_dir, dir_name });
        errdefer self.allocator.free(output_dir);
        try fs.cwd().makePath(output_dir);

        // accounts/  and  snapshots/<slot>/
        const accounts_dir = try std.fmt.allocPrint(self.allocator, "{s}/accounts", .{output_dir});
        defer self.allocator.free(accounts_dir);
        try fs.cwd().makePath(accounts_dir);
        const snaps_slot_dir = try std.fmt.allocPrint(self.allocator, "{s}/snapshots/{d}", .{ output_dir, slot });
        defer self.allocator.free(snaps_slot_dir);
        try fs.cwd().makePath(snaps_slot_dir);

        // version file
        {
            const version_path = try std.fmt.allocPrint(self.allocator, "{s}/version", .{output_dir});
            defer self.allocator.free(version_path);
            const vf = try fs.cwd().createFile(version_path, .{ .truncate = true });
            defer vf.close();
            try vf.writeAll("1.3.1\n");
        }

        // accounts/<slot>.0 — the single AppendVec (id=0).
        const av_id: u64 = 0;
        const appendvec_path = try std.fmt.allocPrint(self.allocator, "{s}/{d}.{d}", .{ accounts_dir, slot, av_id });
        defer self.allocator.free(appendvec_path);
        const stats = blk: {
            const av_file = try fs.cwd().createFile(appendvec_path, .{ .truncate = true });
            defer av_file.close();
            // Big-chunk buffered write (byte-transparent). Flush BEFORE close / the
            // re-stat below reads file_sz for the manifest storages entry.
            var bw = try snapshot_writer.BufferedAvWriter.init(self.allocator, av_file);
            defer bw.deinit();
            const s = try accounts_db.writeSnapshotAppendVec(&bw);
            try bw.flush();
            break :blk s;
        };
        // REAL on-disk byte count for the manifest storages entry (NOT accounts_written).
        const av_file_sz: u64 = blk: {
            const f = try fs.cwd().openFile(appendvec_path, .{});
            defer f.close();
            const st = try f.stat();
            break :blk st.size;
        };

        // Bank MANIFEST: snapshots/<slot>/<slot>
        const storages = [_]snapshot_manifest.StorageEntry{
            .{ .slot = slot, .id = av_id, .file_sz = av_file_sz },
        };
        const manifest_bytes = try snapshot_manifest.writeManifestFile(self.allocator, output_dir, .{
            .slot = slot,
            .parent_slot = bank_fields.parent_slot,
            .bank_hash = bank_fields.bank_hash,
            .parent_hash = bank_fields.parent_hash,
            .last_blockhash = bank_fields.last_blockhash,
            .capitalization = bank_fields.capitalization,
            .block_height = bank_fields.block_height,
            .hashes_per_tick = bank_fields.hashes_per_tick,
            .ticks_per_slot = bank_fields.ticks_per_slot,
            .epoch = bank_fields.epoch,
            .accounts_lt_hash = bank_fields.accounts_lt_hash,
            .block_id = bank_fields.block_id,
            .fee_rate_governor = bank_fields.fee_rate_governor,
            .signature_count = bank_fields.signature_count,
            .storages = &storages,
            // REAL epoch_stakes from the loaded snapshot's frozen tables (the same
            // structure the leader schedule + turbine real-stakes consume). Makes
            // the produced snapshot carry the leader-schedule subset (staked node
            // → vote accounts → stake + total_stake) instead of an empty Vec.
            // CONSENSUS-SAFE: reads frozen state, does not change bank_hash.
            .epoch_stakes = accounts_db.epoch_stakes,
        });

        // status_cache stub: snapshots/status_cache
        try snapshot_manifest.writeStatusCacheFile(output_dir);

        // accounts_hash (kept for the marker / RPC response; NOT the manifest lthash).
        const accounts_hash = try accounts_db.computeHash();
        const accounts_hash_hex = std.fmt.bytesToHex(accounts_hash.data, .lower);

        // Package: <snapshots_dir>/snapshot-<slot>-<hash8>.tar.zst, mirroring
        // extract()'s shell-tar with the zstd -T0 compressor.
        const hash8_hex = std.fmt.bytesToHex(accounts_hash.data[0..8].*, .lower);
        const tar_path = try std.fmt.allocPrint(self.allocator, "{s}/snapshot-{d}-{s}.tar.zst", .{ self.snapshots_dir, slot, hash8_hex });
        errdefer self.allocator.free(tar_path);
        {
            var child = std.process.Child.init(
                &.{ "tar", "--use-compress-program", "zstd -T0", "-cf", tar_path, "-C", self.snapshots_dir, dir_name },
                self.allocator,
            );
            child.stdout_behavior = .Ignore;
            child.stderr_behavior = .Ignore;
            child.spawn() catch return error.PackagingFailed;
            const term = child.wait() catch return error.PackagingFailed;
            if (term != .Exited or term.Exited != 0) return error.PackagingFailed;
        }

        std.log.info("[Snapshot] saveFullSnapshot complete slot={d} accounts={d} lamports={d} manifest_bytes={d} tar={s}", .{
            slot, stats.accounts_written, stats.lamports_total, manifest_bytes, tar_path,
        });

        return FullSnapshotResult{
            .slot = slot,
            .output_dir = output_dir,
            .tar_path = tar_path,
            .accounts_written = stats.accounts_written,
            .lamports_total = stats.lamports_total,
            .manifest_bytes = manifest_bytes,
            .accounts_hash_hex = accounts_hash_hex,
        };
    }

    /// SKEW-FREE forensic full snapshot. Identical artifact to `saveFullSnapshot`,
    /// but the slot + bank_fields are captured by `captureFn` WHILE this function
    /// holds `accounts_db.storage.lock` SHARED — i.e. while replay's account WRITES
    /// are blocked — so the manifest's (slot, bank_hash, accounts_lt_hash) and the
    /// walked AppendVec are the SAME committed slot. `saveFullSnapshot` takes its
    /// bank_fields BEFORE acquiring the lock, which (off a background thread that
    /// races live replay) can tag slot S's manifest over slot S+k's accounts —
    /// empirically a ~20-slot skew under offline replay; this entry point closes it.
    ///
    /// captureFn is invoked exactly once, under the lock, with `ctx`. It must do
    /// nothing but read the current rooted-tip bank fields (cheap, non-blocking) —
    /// it runs inside the critical section that stalls replay.
    ///
    /// CONSENSUS-SAFE: read-only over frozen state; emits an artifact; never mutates
    /// bank_hash. LIVENESS: holds the storage lock shared for the full index walk
    /// (replay-writes block for that duration) — same intrinsic cost as any use of
    /// this writer; keep cadence coarse (HUMAN deploy call, RULE #10).
    pub fn saveFullSnapshotAtTip(
        self: *Self,
        accounts_db: anytype,
        ctx: *anyopaque,
        captureFn: *const fn (*anyopaque) CapturedTip,
    ) !FullSnapshotResult {
        const snapshot_manifest = @import("snapshot_manifest.zig");

        // ── Critical section: capture metadata + walk accounts under ONE shared
        //    lock so no replay slot commits between them. ──────────────────────
        accounts_db.storage.lock.lockShared();
        const lock_t0_ns = std.time.nanoTimestamp(); // GATE(c): measure lock-hold span
        var lock_released = false;
        defer if (!lock_released) accounts_db.storage.lock.unlockShared();

        const captured = captureFn(ctx); // replay-writes blocked → consistent
        const slot = captured.slot;
        const bank_fields = captured.fields;
        std.log.info("[Snapshot] saveFullSnapshotAtTip start slot={d}", .{slot});

        const dir_name = try std.fmt.allocPrint(self.allocator, "local-snapshot-{d}", .{slot});
        defer self.allocator.free(dir_name);
        const output_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.snapshots_dir, dir_name });
        errdefer self.allocator.free(output_dir);
        try fs.cwd().makePath(output_dir);

        const accounts_dir = try std.fmt.allocPrint(self.allocator, "{s}/accounts", .{output_dir});
        defer self.allocator.free(accounts_dir);
        try fs.cwd().makePath(accounts_dir);
        const snaps_slot_dir = try std.fmt.allocPrint(self.allocator, "{s}/snapshots/{d}", .{ output_dir, slot });
        defer self.allocator.free(snaps_slot_dir);
        try fs.cwd().makePath(snaps_slot_dir);

        {
            const version_path = try std.fmt.allocPrint(self.allocator, "{s}/version", .{output_dir});
            defer self.allocator.free(version_path);
            const vf = try fs.cwd().createFile(version_path, .{ .truncate = true });
            defer vf.close();
            try vf.writeAll("1.3.1\n");
        }

        const av_id: u64 = 0;
        const appendvec_path = try std.fmt.allocPrint(self.allocator, "{s}/{d}.{d}", .{ accounts_dir, slot, av_id });
        defer self.allocator.free(appendvec_path);
        const stats = blk: {
            const av_file = try fs.cwd().createFile(appendvec_path, .{ .truncate = true });
            defer av_file.close();
            // Big-chunk buffered write (byte-transparent): collapses the per-account
            // ~10 raw write(2) calls into ~ceil(total_bytes/8MiB) flushes. This is the
            // dominant cost of the index walk, so it also shrinks the held shared-lock
            // span (which stalls replay's exclusive writeAccount) ~10x. Flush BEFORE
            // close so no buffered tail is lost and the manifest file_sz re-stat below
            // sees the complete file.
            var bw = try snapshot_writer.BufferedAvWriter.init(self.allocator, av_file);
            defer bw.deinit();
            const s = try accounts_db.writeSnapshotAppendVecLocked(&bw);
            try bw.flush();
            std.log.warn("[FORENSIC-SNAP] av-write flushes={d} bytes={d} (buf={d}B) — buffered, byte-transparent", .{ bw.flushes, bw.bytes_total, snapshot_writer.BufferedAvWriter.DEFAULT_BUF_BYTES });
            break :blk s;
        };

        // End of critical section — release the storage lock so replay resumes.
        const lock_held_ms: i128 = @divTrunc(std.time.nanoTimestamp() - lock_t0_ns, std.time.ns_per_ms);
        accounts_db.storage.lock.unlockShared();
        lock_released = true;
        std.log.warn("[FORENSIC-SNAP] storage.lock held SHARED for {d} ms (replay writeAccount blocked this long) slot={d} accounts={d}", .{ lock_held_ms, slot, stats.accounts_written });

        const av_file_sz: u64 = blk: {
            const f = try fs.cwd().openFile(appendvec_path, .{});
            defer f.close();
            const st = try f.stat();
            break :blk st.size;
        };

        const storages = [_]snapshot_manifest.StorageEntry{
            .{ .slot = slot, .id = av_id, .file_sz = av_file_sz },
        };
        const manifest_bytes = try snapshot_manifest.writeManifestFile(self.allocator, output_dir, .{
            .slot = slot,
            .parent_slot = bank_fields.parent_slot,
            .bank_hash = bank_fields.bank_hash,
            .parent_hash = bank_fields.parent_hash,
            .last_blockhash = bank_fields.last_blockhash,
            .capitalization = bank_fields.capitalization,
            .block_height = bank_fields.block_height,
            .hashes_per_tick = bank_fields.hashes_per_tick,
            .ticks_per_slot = bank_fields.ticks_per_slot,
            .epoch = bank_fields.epoch,
            .accounts_lt_hash = bank_fields.accounts_lt_hash,
            .block_id = bank_fields.block_id,
            .fee_rate_governor = bank_fields.fee_rate_governor,
            .signature_count = bank_fields.signature_count,
            .storages = &storages,
            .epoch_stakes = accounts_db.epoch_stakes,
        });

        try snapshot_manifest.writeStatusCacheFile(output_dir);

        // accounts_hash for the tar filename ONLY (cosmetic; the manifest's
        // accounts_lt_hash is the consensus-bearing value). computeHash re-locks
        // storage internally — safe now that the lock is released.
        const accounts_hash = try accounts_db.computeHash();
        const accounts_hash_hex = std.fmt.bytesToHex(accounts_hash.data, .lower);

        const hash8_hex = std.fmt.bytesToHex(accounts_hash.data[0..8].*, .lower);
        const tar_path = try std.fmt.allocPrint(self.allocator, "{s}/snapshot-{d}-{s}.tar.zst", .{ self.snapshots_dir, slot, hash8_hex });
        errdefer self.allocator.free(tar_path);
        {
            var child = std.process.Child.init(
                &.{ "tar", "--use-compress-program", "zstd -T0", "-cf", tar_path, "-C", self.snapshots_dir, dir_name },
                self.allocator,
            );
            child.stdout_behavior = .Ignore;
            child.stderr_behavior = .Ignore;
            child.spawn() catch return error.PackagingFailed;
            const term = child.wait() catch return error.PackagingFailed;
            if (term != .Exited or term.Exited != 0) return error.PackagingFailed;
        }

        std.log.info("[Snapshot] saveFullSnapshotAtTip complete slot={d} accounts={d} lamports={d} manifest_bytes={d} tar={s}", .{
            slot, stats.accounts_written, stats.lamports_total, manifest_bytes, tar_path,
        });

        return FullSnapshotResult{
            .slot = slot,
            .output_dir = output_dir,
            .tar_path = tar_path,
            .accounts_written = stats.accounts_written,
            .lamports_total = stats.lamports_total,
            .manifest_bytes = manifest_bytes,
            .accounts_hash_hex = accounts_hash_hex,
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    // fork()-BGSAVE forensic snapshot (task #26, 2026-07-01)
    //
    // Design + datum-by-datum fork-safety audit:
    //   vexor-designs/FORK-BGSAVE-SNAPSHOT-DESIGN-2026-07-01.md
    //   vexor-designs/FORK-BGSAVE-FORK-SAFETY-AUDIT-2026-07-01.md
    //
    // Replaces the ~41 s SHARED hold of accounts_db.storage.lock in
    // `saveFullSnapshotAtTip` (which stalls replay's EXCLUSIVE writeAccount →
    // the recurring ~13-min transient delinquency) with a Redis-BGSAVE-style
    // fork(): the lock is held shared only across captureTip + an 8192-bin
    // shared sweep + fork() itself; the CoW child walks its kernel-frozen view
    // on an isolated core at idle IO priority; replay resumes in milliseconds.
    //
    // The legacy `saveFullSnapshotAtTip` above stays BYTE-FROZEN as the
    // rollback sibling (VEX_FORENSIC_SNAPSHOT_FORK=0 — env flip, no rebuild).
    //
    // computeHash()'s second 87M-account walk is NOT ported: the archive is
    // named base58(BLAKE3(captured accounts_lt_hash)) — exactly Agave rc.1
    // SnapshotHash::new semantics (lattice-hash/src/lt_hash.rs:53
    // checksum()=blake3(lattice)), already KAT'd in-tree by
    // kat_manifest_lthash_verify.zig and verified at every consumer boot by the
    // full-only-boot lt_hash guard (design §5.3-5.4).
    //
    // CONSENSUS-SAFE: read-only over frozen state; emits an artifact; never
    // mutates bank_hash. FAILURE POLICY: every failure is [FORENSIC-SNAP-FORK-
    // FAIL] log-loud + skip — this subsystem may NEVER take down or degrade the
    // validator. The FORK-FAIL lines are deliberately std.log.warn, NOT err:
    // (a) they are skip-and-continue forensic-tool failures, not the
    // bootstrap-fatal class this file reserves log.err for; (b) main.zig's
    // worker logs its own warn summary on every failure anyway; (c) the
    // offline gate + guardian grep the [FORENSIC-SNAP-FORK-FAIL] MARKER, not
    // the level; (d) it keeps the failure paths unit-KAT-able (the std test
    // runner hard-fails any test that emits log.err).
    // ════════════════════════════════════════════════════════════════════════

    /// MUST-FIX #1 (critic 2026-07-01) + operator directive (2026-07-02: the
    /// snapshot tool "CANNOT affect the validator" — it must be armed
    /// EXPLICITLY): three-state arming for the forensic snapshot worker,
    /// resolved from VEX_FORENSIC_SNAPSHOT_FORK. DEFAULT (unset) = DISARMED:
    /// even with VEX_FORENSIC_SNAPSHOT_EVERY>0 NO snapshot path runs — neither
    /// the fork path NOR the legacy ~41 s in-thread staller (the incident that
    /// took the tool offline). Every snapshot path is therefore unreachable
    /// unless the operator sets BOTH envs. Unrecognized values fail SAFE to
    /// disarmed (never "garbage value silently arms the staller").
    pub const ForkArming = enum { disarmed, legacy, fork };

    /// Pure resolver (unit-KAT'd in tests/kat_bgsave_fork.zig):
    ///   null / "" / anything unrecognized -> .disarmed  (default-OFF)
    ///   "0"                               -> .legacy    (explicit opt-in to the
    ///                                        in-thread saver — the rollback sibling)
    ///   "1"                               -> .fork      (fork-BGSAVE, the safe path)
    pub fn resolveForkArming(fork_env: ?[]const u8) ForkArming {
        const raw = fork_env orelse return .disarmed;
        const v = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, v, "1")) return .fork;
        if (std.mem.eql(u8, v, "0")) return .legacy;
        return .disarmed;
    }

    pub const BgsaveOptions = struct {
        /// Isolated core for the CHILD (operator requirement;
        /// VEX_FORENSIC_SNAPSHOT_CORE now pins the child, not the worker).
        /// <0 = no pin. main.zig defaults this to core 31 in fork mode
        /// (re-audit F2: inside the deploy cgroup cpuset 5-31, off the
        /// replay/recv/verify/wave CCXs, off external-forensics cores 28-30;
        /// shared only with the 15 s-poll in-binary watchdog, which always
        /// preempts the SCHED_IDLE child).
        child_core: i64 = -1,
        /// SIGKILL deadline for the child, WALL-CLOCK seconds (counts across a
        /// SIGSTOP — chaos-matrix requirement, design open item (c)).
        /// VEX_FORENSIC_SNAPSHOT_TIMEOUT; default 1800 = 10x normal-case headroom.
        timeout_secs: u64 = 1800,
        /// VEX_FORENSIC_SNAPSHOT_VERIFY: in-child lt_hash re-accumulate gate
        /// (design §5.5). RESERVED — see TODO at the child walk; parsed +
        /// plumbed so arming it later is an env flip, not an ABI change.
        verify: bool = true,
        /// TEST-ONLY (chaos KATs, design §6.4): raw-nanosleep this many ms in
        /// the CHILD immediately after bgsaveChildSetup, BEFORE the walk, so a
        /// KAT can deterministically SIGKILL/SIGSTOP a mid-flight child or
        /// force the wall-clock timeout. NEVER set by production code
        /// (main.zig has no plumbing for it); 0 = no-op. The sleep is a raw
        /// syscall loop — fork-safe subset preserved.
        test_child_stall_ms: u64 = 0,
    };

    /// Fixed-size child→parent result record: ONE atomic pipe write
    /// (48 bytes < PIPE_BUF), read by the parent only after a clean child exit.
    /// entries_seen: EVERY index entry the walk iterated (null-resolving
    /// entries included) — must equal the parent's pre-fork under-lock bin-count
    /// sum (complete-enumeration invariant, design §5.2). accounts_written ≤
    /// entries_seen (null-resolving entries are skipped by the SAME filter as
    /// the legacy walk — see snapshotWalkDiag).
    pub const BgsaveResultRecord = extern struct {
        magic: u64,
        slot: u64,
        entries_seen: u64,
        accounts_written: u64,
        bytes_written: u64,
        lamports_total: u64,

        pub const MAGIC: u64 = 0x5645585F42475356; // ASCII "VEX_BGSV" (BE read)
    };

    comptime {
        std.debug.assert(@sizeOf(BgsaveResultRecord) == 48);
    }

    pub const BGSAVE_PID_FILE = ".bgsave.pid";

    /// Worker-start stale-orphan sweep (design §3 single-child latch): if a
    /// previous INCARNATION of the validator left a bgsave child behind (the
    /// PDEATHSIG covers parent-death, so this is belt-and-braces for e.g. a
    /// SIGKILL'd parent racing the child's own prctl), kill it. Pid-reuse-safe:
    /// only kills a pid whose /proc/<pid>/comm is exactly "vex-bgsave".
    pub fn sweepStaleBgsave(snapshots_dir: []const u8) void {
        var path_buf: [512]u8 = undefined;
        const pid_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ snapshots_dir, BGSAVE_PID_FILE }) catch return;
        const f = fs.cwd().openFile(pid_path, .{}) catch return;
        var num_buf: [32]u8 = undefined;
        const n = f.readAll(&num_buf) catch {
            f.close();
            return;
        };
        f.close();
        defer fs.cwd().deleteFile(pid_path) catch {};
        const pid = std.fmt.parseInt(i32, std.mem.trim(u8, num_buf[0..n], " \t\r\n"), 10) catch return;
        if (pid <= 1) return;
        var comm_path_buf: [64]u8 = undefined;
        const comm_path = std.fmt.bufPrint(&comm_path_buf, "/proc/{d}/comm", .{pid}) catch return;
        const cf = fs.cwd().openFile(comm_path, .{}) catch return;
        var comm_buf: [32]u8 = undefined;
        const cn = cf.readAll(&comm_buf) catch {
            cf.close();
            return;
        };
        cf.close();
        if (!std.mem.eql(u8, std.mem.trim(u8, comm_buf[0..cn], "\n"), "vex-bgsave")) return;
        std.log.warn("[FORENSIC-SNAP] sweeping STALE bgsave child pid={d} from a previous incarnation (SIGKILL)", .{pid});
        std.posix.kill(pid, std.posix.SIG.KILL) catch {};
    }

    /// Startup sweep of crash-orphaned artifacts in the ring dir: `local-snapshot-<slot>/`
    /// staging dirs (tens of GB uncompressed) and `snapshot-*.tar.zst.tmp` partials.
    /// Both are stranded forever if the parent dies mid-cycle (errdefers can't run),
    /// are invisible to pruneOld + all consumer globs by design, and so leak the ring
    /// toward ENOSPC across repeated crashes. Runs ONLY at worker start, before any
    /// cycle — there is no live child whose staging we could race (sweepStaleBgsave
    /// has already killed any stale one).
    pub fn sweepOrphanedStaging(snapshots_dir: []const u8) void {
        var dir = fs.cwd().openDir(snapshots_dir, .{ .iterate = true }) catch return;
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch return) |entry| {
            const is_staging = entry.kind == .directory and
                std.mem.startsWith(u8, entry.name, "local-snapshot-");
            const is_tmp = entry.kind == .file and
                std.mem.startsWith(u8, entry.name, "snapshot-") and
                std.mem.endsWith(u8, entry.name, ".tar.zst.tmp");
            if (!is_staging and !is_tmp) continue;
            std.log.warn("[FORENSIC-SNAP] sweeping crash-orphaned {s} '{s}' from a previous incarnation", .{
                if (is_staging) @as([]const u8, "staging dir") else "partial archive", entry.name,
            });
            if (is_staging) {
                dir.deleteTree(entry.name) catch |err| {
                    std.log.warn("[FORENSIC-SNAP] orphan sweep failed for '{s}': {s} (continuing)", .{ entry.name, @errorName(err) });
                };
            } else {
                dir.deleteFile(entry.name) catch |err| {
                    std.log.warn("[FORENSIC-SNAP] orphan sweep failed for '{s}': {s} (continuing)", .{ entry.name, @errorName(err) });
                };
            }
        }
    }

    fn writeBgsavePidFile(self: *Self, pid: std.posix.pid_t) void {
        var path_buf: [512]u8 = undefined;
        const pid_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.snapshots_dir, BGSAVE_PID_FILE }) catch return;
        const f = fs.cwd().createFile(pid_path, .{ .truncate = true }) catch return;
        defer f.close();
        var num_buf: [16]u8 = undefined;
        const s = std.fmt.bufPrint(&num_buf, "{d}\n", .{pid}) catch return;
        f.writeAll(s) catch {};
    }

    fn deleteBgsavePidFile(self: *Self) void {
        var path_buf: [512]u8 = undefined;
        const pid_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.snapshots_dir, BGSAVE_PID_FILE }) catch return;
        fs.cwd().deleteFile(pid_path) catch {};
    }

    /// fork()-BGSAVE full snapshot. Same artifact class as
    /// `saveFullSnapshotAtTip`; the storage.lock shared hold shrinks from the
    /// whole 87M-account walk (~41 s) to captureTip + bin sweep + fork()
    /// (~100-500 ms est. at 34 GiB RSS ≈ 8.9M PTEs — MEASURE via the fork-cost
    /// probe, design §6.1). The existing `storage.lock held SHARED` log line is
    /// kept verbatim as the regression gate: it must read <1000 ms.
    ///
    /// Errors: `error.BgsaveForkFailed` (fork(2) itself failed) is special-cased
    /// by the caller for the optional VEX_FORENSIC_SNAPSHOT_FORK_FALLBACK=1
    /// legacy retry. Child/arming failures log [FORENSIC-SNAP-FORK-FAIL] at
    /// their site; parent-side classes (tar, manifest, status-cache, fsync,
    /// rename) propagate WITHOUT it — the caller's catch-all warn carries the
    /// marker for those. Staging + .tmp are cleaned by errdefers on ALL paths.
    pub fn saveFullSnapshotForked(
        self: *Self,
        accounts_db: anytype,
        ctx: *anyopaque,
        captureFn: *const fn (*anyopaque) CapturedTip,
        opts: BgsaveOptions,
    ) !FullSnapshotResult {
        const snapshot_manifest = @import("snapshot_manifest.zig");

        // ── PRE-STAGE (NO locks — design §2 "pre-staged by the parent"):
        //    everything the child touches must exist before fork(); everything
        //    slot-named is created from a PRE-lock read of the rooted slot and
        //    RE-VERIFIED under the lock. advanceRoot needs storage.lock
        //    EXCLUSIVE, so the root can only move during this (ms-scale)
        //    prestage window; a mismatch skips the cycle log-visibly rather
        //    than tagging slot S's manifest over slot S+k's accounts. ──────────
        const pre_slot: u64 = accounts_db.rooted_slot;
        if (pre_slot == 0) return error.NoRootedSlot;

        const dir_name = try std.fmt.allocPrint(self.allocator, "local-snapshot-{d}", .{pre_slot});
        defer self.allocator.free(dir_name);
        const output_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.snapshots_dir, dir_name });
        errdefer self.allocator.free(output_dir);
        try fs.cwd().makePath(output_dir);
        errdefer snapshot_writer.bgsaveDeleteTree(output_dir); // any failure below ⇒ no staging leftovers

        const accounts_dir = try std.fmt.allocPrint(self.allocator, "{s}/accounts", .{output_dir});
        defer self.allocator.free(accounts_dir);
        try fs.cwd().makePath(accounts_dir);
        const snaps_slot_dir = try std.fmt.allocPrint(self.allocator, "{s}/snapshots/{d}", .{ output_dir, pre_slot });
        defer self.allocator.free(snaps_slot_dir);
        try fs.cwd().makePath(snaps_slot_dir);

        {
            const version_path = try std.fmt.allocPrint(self.allocator, "{s}/version", .{output_dir});
            defer self.allocator.free(version_path);
            const vf = try fs.cwd().createFile(version_path, .{ .truncate = true });
            defer vf.close();
            try vf.writeAll("1.3.1\n");
        }

        const av_id: u64 = 0;
        const appendvec_path = try std.fmt.allocPrint(self.allocator, "{s}/{d}.{d}", .{ accounts_dir, pre_slot, av_id });
        defer self.allocator.free(appendvec_path);
        const av_file = try fs.cwd().createFile(appendvec_path, .{ .truncate = true });
        var av_open = true;
        errdefer if (av_open) av_file.close();

        // The child's 8 MiB write buffer — allocated by the PARENT pre-fork
        // (the child allocates NOTHING). Freed by the parent post-fork; the
        // child's CoW copy is untouched by that free.
        var bw = try snapshot_writer.BufferedAvWriter.init(self.allocator, av_file);
        errdefer bw.deinit();

        // Result pipe. CLOEXEC is correct AND safe: fork() preserves fds
        // regardless (CLOEXEC bites only on exec), and it keeps the write end
        // out of any CONCURRENT std.process.Child spawn elsewhere in the
        // process (a leaked write end would hold our read side open forever).
        const pipe_fds = try std.posix.pipe2(.{ .CLOEXEC = true });
        var pipe_r_open = true;
        var pipe_w_open = true;
        errdefer if (pipe_r_open) std.posix.close(pipe_fds[0]);
        errdefer if (pipe_w_open) std.posix.close(pipe_fds[1]);

        const parent_pid: std.posix.pid_t = @intCast(std.os.linux.getpid());

        // ── LOCK WINDOW (design §0/§1): capture + sweep + fork, nothing else.
        // Quiesce GC BEFORE taking the lock: a shrink that blocked on storage.lock
        // during the fork window must observe gc_quiesce=true the moment it wakes,
        // or it can pass its re-check and rewrite whole stores while the child
        // walks (review F2: store-after-unlock left that race open).
        accounts_db.gc_quiesce.store(true, .release);
        errdefer accounts_db.gc_quiesce.store(false, .release);
        accounts_db.storage.lock.lockShared();
        const lock_t0_ns = std.time.nanoTimestamp();

        const captured = captureFn(ctx); // replay-writes blocked → consistent
        if (captured.slot == 0 or captured.slot != pre_slot) {
            accounts_db.storage.lock.unlockShared();
            std.log.warn("[FORENSIC-SNAP-FORK-FAIL] captured slot={d} != prestaged {d} (root moved during prestage, or no rooted bank in forks) — skipping this cycle", .{ captured.slot, pre_slot });
            return error.RootMovedDuringPrestage;
        }
        const bank_fields = captured.fields;

        // The ONE active barrier beyond the shared storage hold (design §1
        // row 5): index.insert takes bin locks EXCLUSIVE outside storage.lock,
        // so sweep ALL 8192 bins SHARED and hold them ACROSS fork() — waits out
        // any in-flight hashmap-put so the child's CoW image has no torn bin.
        accounts_db.index.lockAllBinsShared();
        const expected_entries: u64 = accounts_db.index.countAssumeLocked();

        const fork_t0_ns = std.time.nanoTimestamp();
        const child_pid: std.posix.pid_t = std.posix.fork() catch |err| {
            // MUST stay libc fork() (std.posix.fork → c.fork when linking
            // libc): jemalloc's pthread_atfork prefork quiesces the arenas.
            // NEVER convert to raw clone()/SYS_fork.
            accounts_db.index.unlockAllBinsShared();
            accounts_db.storage.lock.unlockShared();
            std.log.warn("[FORENSIC-SNAP-FORK-FAIL] fork() failed: {s} (rooted={d}) — skipping (VEX_FORENSIC_SNAPSHOT_FORK_FALLBACK=1 retries legacy)", .{ @errorName(err), pre_slot });
            return error.BgsaveForkFailed;
        };

        if (child_pid == 0) {
            // ═══ CHILD ═══ single thread by construction. ONLY the fork-safe
            // subset from here: zero alloc, zero std.log, zero locks, zero new
            // fds beyond {av fd, pipe write end, stderr}. Straight-line pump.
            snapshot_writer.bgsaveChildSetup(opts.child_core, parent_pid);
            if (opts.test_child_stall_ms > 0) {
                // TEST-ONLY chaos hook (see BgsaveOptions.test_child_stall_ms):
                // raw nanosleep — no alloc, no lock, no libc sleep machinery.
                var ts = std.os.linux.timespec{
                    .sec = @intCast(opts.test_child_stall_ms / 1000),
                    .nsec = @intCast((opts.test_child_stall_ms % 1000) * std.time.ns_per_ms),
                };
                var rem = std.os.linux.timespec{ .sec = 0, .nsec = 0 };
                while (true) {
                    const rc = std.os.linux.nanosleep(&ts, &rem);
                    if (rc == 0) break;
                    if (std.os.linux.E.init(rc) != .INTR) break; // only resume on EINTR
                    ts = rem;
                }
            }
            var sw = snapshot_writer.SyncingAvWriter{ .inner = &bw, .fd = av_file.handle };
            const stats = accounts_db.writeSnapshotAppendVecNoLock(&sw) catch |err| {
                snapshot_writer.bgsaveRawErr("walk/write failed: {s}", .{@errorName(err)});
                std.os.linux.exit_group(2);
            };
            bw.flush() catch |err| {
                snapshot_writer.bgsaveRawErr("final flush failed: {s}", .{@errorName(err)});
                std.os.linux.exit_group(2);
            };
            std.posix.fdatasync(av_file.handle) catch {};
            // TODO(implementing session, design §5.5, VEX_FORENSIC_SNAPSHOT_VERIFY):
            // optional second no-lock pass re-accumulating the accounts lt_hash
            // (lattice-add of per-account hashes) into a pre-staged 2048 B stack
            // buffer, appended to the result record (or a second pipe write) for
            // the parent to compare against captured.accounts_lt_hash. Needs the
            // per-account lattice-add exposed alloc-free. Exit code 5 reserved
            // for an in-child verify mismatch. `opts.verify` is plumbed already.
            const rec = BgsaveResultRecord{
                .magic = BgsaveResultRecord.MAGIC,
                .slot = pre_slot,
                .entries_seen = stats.entries_seen,
                .accounts_written = stats.accounts_written,
                .bytes_written = bw.bytes_total,
                .lamports_total = stats.lamports_total,
            };
            const wrote = std.posix.write(pipe_fds[1], std.mem.asBytes(&rec)) catch {
                snapshot_writer.bgsaveRawErr("result-pipe write failed", .{});
                std.os.linux.exit_group(2);
            };
            if (wrote != @sizeOf(BgsaveResultRecord)) std.os.linux.exit_group(2);
            // NEVER std.posix.exit (libc atexit + stdio flush over possibly-
            // frozen locks) and never return (Zig defers over copied state).
            std.os.linux.exit_group(0);
        }

        // ═══ PARENT ═══
        const fork_ms: i128 = @divTrunc(std.time.nanoTimestamp() - fork_t0_ns, std.time.ns_per_ms);
        accounts_db.index.unlockAllBinsShared();
        const lock_held_ms: i128 = @divTrunc(std.time.nanoTimestamp() - lock_t0_ns, std.time.ns_per_ms);
        accounts_db.storage.lock.unlockShared();
        // ── REPLAY RESUMES HERE. Same marker text as the legacy path — the
        //    primary regression gate: ~41000 ms → MUST read <1000 ms. ──────────
        std.log.warn("[FORENSIC-SNAP] storage.lock held SHARED for {d} ms (replay writeAccount blocked this long) slot={d} fork_ms={d} expected_entries={d} bgsave_pid={d}", .{ lock_held_ms, pre_slot, fork_ms, expected_entries, child_pid });

        // CoW-amplification quiesce (design §3) was armed BEFORE the lock window
        // above; the defer here is the idempotent backstop for all exits. It is
        // released EXPLICITLY right after the child is reaped (before the tar
        // stage) — holding it across the unbounded idle-priority tar starved
        // live GC for the whole pack (review F1).
        defer accounts_db.gc_quiesce.store(false, .release);

        // Parent-side copies of child-owned resources. The child's descriptors
        // and its CoW copy of the buffer are unaffected.
        std.posix.close(pipe_fds[1]);
        pipe_w_open = false;
        av_file.close();
        av_open = false;
        bw.deinit();

        self.writeBgsavePidFile(child_pid);
        const private_dirty_kb_at_fork = snapshot_writer.readPrivateDirtyKb();
        const child_t0_ms = std.time.milliTimestamp();

        // WNOHANG reap loop + WALL-CLOCK SIGKILL deadline (design §3). The poll
        // (not a blocking wait) is what implements the timeout and keeps this
        // worker responsive. pid-SPECIFIC wait: zero cross-talk with concurrent
        // tar/curl std.process.Child reaping (verified: no wait(-1) in-tree, no
        // SIGCHLD handler installed).
        const deadline_ms: i64 = child_t0_ms + @as(i64, @intCast(@min(opts.timeout_secs, std.math.maxInt(u32)) * 1000));
        var child_status: u32 = 0;
        var timed_out = false;
        while (true) {
            const wr = std.posix.waitpid(child_pid, std.posix.W.NOHANG);
            if (wr.pid == child_pid) {
                child_status = wr.status;
                break;
            }
            if (std.time.milliTimestamp() > deadline_ms) {
                timed_out = true;
                std.posix.kill(child_pid, std.posix.SIG.KILL) catch {};
                const wr2 = std.posix.waitpid(child_pid, 0);
                child_status = wr2.status;
                break;
            }
            std.Thread.sleep(500 * std.time.ns_per_ms);
        }
        self.deleteBgsavePidFile();
        // Child is dead: its CoW view is gone, so GC may resume NOW — the tar
        // stage below reads only the staged copies, never live stores.
        accounts_db.gc_quiesce.store(false, .release);
        const child_wall_ms = std.time.milliTimestamp() - child_t0_ms;
        const cow_delta_kb = snapshot_writer.readPrivateDirtyKb() -| private_dirty_kb_at_fork;

        if (timed_out) {
            std.posix.close(pipe_fds[0]);
            pipe_r_open = false;
            std.log.warn("[FORENSIC-SNAP-FORK-FAIL] timeout after {d}s — killed bgsave pid={d} slot={d}", .{ opts.timeout_secs, child_pid, pre_slot });
            return error.BgsaveTimeout;
        }
        if (!(std.posix.W.IFEXITED(child_status) and std.posix.W.EXITSTATUS(child_status) == 0)) {
            std.posix.close(pipe_fds[0]);
            pipe_r_open = false;
            std.log.warn("[FORENSIC-SNAP-FORK-FAIL] bgsave child pid={d} abnormal exit status=0x{x} slot={d}", .{ child_pid, child_status, pre_slot });
            return error.BgsaveChildFailed;
        }

        // Result record — belt-and-braces: a clean exit WITHOUT a full valid
        // record is still a failure (design §2 error paths).
        var rec: BgsaveResultRecord = undefined;
        const got = std.posix.read(pipe_fds[0], std.mem.asBytes(&rec)) catch 0;
        std.posix.close(pipe_fds[0]);
        pipe_r_open = false;
        if (got != @sizeOf(BgsaveResultRecord) or rec.magic != BgsaveResultRecord.MAGIC or rec.slot != pre_slot) {
            std.log.warn("[FORENSIC-SNAP-FORK-FAIL] bad result record (got={d} bytes) slot={d}", .{ got, pre_slot });
            return error.BgsaveBadRecord;
        }
        // Complete-enumeration invariant (design §5.2): the child must have
        // SEEN every index entry the parent counted inside the lock window.
        if (rec.entries_seen != expected_entries) {
            std.log.warn("[FORENSIC-SNAP-FORK-FAIL] count invariant VIOLATED: child entries_seen={d} != pre-fork expected={d} slot={d} — artifact discarded", .{ rec.entries_seen, expected_entries, pre_slot });
            return error.BgsaveCountMismatch;
        }
        // Structural cross-check: on-disk av size == child's byte count.
        const av_file_sz: u64 = blk: {
            const f = try fs.cwd().openFile(appendvec_path, .{});
            defer f.close();
            const st = try f.stat();
            break :blk st.size;
        };
        if (av_file_sz != rec.bytes_written) {
            std.log.warn("[FORENSIC-SNAP-FORK-FAIL] av size mismatch: stat={d} != child bytes_written={d} slot={d}", .{ av_file_sz, rec.bytes_written, pre_slot });
            return error.BgsaveSizeMismatch;
        }

        // ── Parent post-child tail — identical timing semantics to the legacy
        //    post-unlock tail; all lock-free; inputs = pre-fork `captured`
        //    fields + stat + immutable epoch_stakes (design §3 success path). ──
        const storages = [_]snapshot_manifest.StorageEntry{
            .{ .slot = pre_slot, .id = av_id, .file_sz = av_file_sz },
        };
        const manifest_bytes = try snapshot_manifest.writeManifestFile(self.allocator, output_dir, .{
            .slot = pre_slot,
            .parent_slot = bank_fields.parent_slot,
            .bank_hash = bank_fields.bank_hash,
            .parent_hash = bank_fields.parent_hash,
            .last_blockhash = bank_fields.last_blockhash,
            .capitalization = bank_fields.capitalization,
            .block_height = bank_fields.block_height,
            .hashes_per_tick = bank_fields.hashes_per_tick,
            .ticks_per_slot = bank_fields.ticks_per_slot,
            .epoch = bank_fields.epoch,
            .accounts_lt_hash = bank_fields.accounts_lt_hash,
            .block_id = bank_fields.block_id,
            .fee_rate_governor = bank_fields.fee_rate_governor,
            .signature_count = bank_fields.signature_count,
            .storages = &storages,
            .epoch_stakes = accounts_db.epoch_stakes,
        });

        try snapshot_manifest.writeStatusCacheFile(output_dir);

        // Archive name = base58(BLAKE3(accounts_lt_hash)) — Agave-canonical
        // SnapshotHash::new; replaces computeHash()'s second full walk outright
        // (design §5.3). The boot-time lt_hash guard re-proves this suffix
        // against the loaded accounts at every consumer boot.
        var checksum: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(&bank_fields.accounts_lt_hash, &checksum, .{});
        const hash_b58 = try core.base58.encode(self.allocator, &checksum);
        defer self.allocator.free(hash_b58);
        const accounts_hash_hex = std.fmt.bytesToHex(checksum, .lower);

        const tar_path = try std.fmt.allocPrint(self.allocator, "{s}/snapshot-{d}-{s}.tar.zst", .{ self.snapshots_dir, pre_slot, hash_b58 });
        errdefer self.allocator.free(tar_path);
        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{tar_path});
        defer self.allocator.free(tmp_path);
        errdefer fs.cwd().deleteFile(tmp_path) catch {};
        {
            // Same shell-tar as the legacy path, but to `.tmp` first: partials
            // are INVISIBLE to pruneOld and vex-base-ring.sh (both glob
            // `snapshot-*.tar.zst`) until the atomic rename below.
            //
            // MUST-FIX #2 (critic 2026-07-01) + operator core-isolation
            // directive (2026-07-02): in fork mode this worker thread is
            // UNPINNED, and a bare `zstd -T0` fans across ALL cores (incl.
            // replay 16 / produce 20-23). Confine the whole tar+zstd stage to
            // the isolated snapshot core (taskset — all zstd threads inherit
            // the affinity mask) at idle IO priority (ionice -c 3) + nice 19
            // (explicit belt-and-braces; also inherited from this nice-19
            // worker). zstd -T1: N threads pinned to one core is pure
            // overhead. The byte-frozen LEGACY saveFullSnapshotAtTip tar is
            // deliberately untouched — it is the rollback sibling.
            var core_buf: [16]u8 = undefined;
            var argv_storage: [17][]const u8 = undefined;
            var argv_len: usize = 0;
            if (opts.child_core >= 0) {
                const core_s = std.fmt.bufPrint(&core_buf, "{d}", .{opts.child_core}) catch unreachable;
                argv_storage[0] = "taskset";
                argv_storage[1] = "-c";
                argv_storage[2] = core_s;
                argv_len = 3;
            }
            const tar_tail = [_][]const u8{
                "ionice",           "-c",                     "3",
                "nice",             "-n",                     "19",
                "tar",              "--use-compress-program", "zstd -T1",
                "-cf",              tmp_path,                 "-C",
                self.snapshots_dir, dir_name,
            };
            for (tar_tail) |a| {
                argv_storage[argv_len] = a;
                argv_len += 1;
            }
            var child = std.process.Child.init(argv_storage[0..argv_len], self.allocator);
            child.stdout_behavior = .Ignore;
            child.stderr_behavior = .Ignore;
            child.spawn() catch return error.PackagingFailed;
            const term = child.wait() catch return error.PackagingFailed;
            if (term != .Exited or term.Exited != 0) return error.PackagingFailed;
        }
        {
            const tf = try fs.cwd().openFile(tmp_path, .{});
            defer tf.close();
            try std.posix.fsync(tf.handle);
        }
        try fs.cwd().rename(tmp_path, tar_path);
        {
            // Durable-rename: fsync the parent DIRECTORY so the rename itself
            // survives a crash. MUST open with .iterate=true — a plain
            // openDir on Linux yields an O_PATH fd and fsync(O_PATH) is
            // EBADF, which std.posix.fsync treats as unreachable ⇒ PANIC (a
            // real crash: caught by the test-bgsave-fork forked-round-trip
            // KAT on 2026-07-02, would have fired on the FIRST successful
            // forked snapshot in production).
            var d = try fs.cwd().openDir(self.snapshots_dir, .{ .iterate = true });
            defer d.close();
            std.posix.fsync(d.fd) catch {};
        }

        std.log.warn("[FORENSIC-SNAP] BGSAVE complete slot={d} accounts={d} entries={d} bytes={d} fork_ms={d} child_wall_ms={d} cow_delta_kb={d} tar={s}", .{
            pre_slot, rec.accounts_written, rec.entries_seen, rec.bytes_written, fork_ms, child_wall_ms, cow_delta_kb, tar_path,
        });

        return FullSnapshotResult{
            .slot = pre_slot,
            .output_dir = output_dir,
            .tar_path = tar_path,
            .accounts_written = rec.accounts_written,
            .lamports_total = rec.lamports_total,
            .manifest_bytes = manifest_bytes,
            .accounts_hash_hex = accounts_hash_hex,
        };
    }

    fn writeSnapshotFromAccountsDir(
        accounts_dir_path: []const u8,
        writer: anytype,
    ) !struct { accounts_written: u64, lamports_total: u64 } {
        const header_size: usize = 32;
        const header_magic: [8]u8 = [_]u8{ 'V', 'E', 'X', 'A', 'V', '1', 0, 0 };
        const record_header_len: usize = 32 + 8 + 32 + 1 + 8 + 4;
        const STORED_META_SIZE: usize = 48;
        const ACCOUNT_META_SIZE: usize = 56;
        const write_version: u64 = 1;
        const pad_bytes = [_]u8{0} ** 8;

        var accounts_written: u64 = 0;
        var lamports_total: u64 = 0;

        var nested_buf: [512]u8 = undefined;
        const nested_path = std.fmt.bufPrint(&nested_buf, "{s}/accounts", .{accounts_dir_path}) catch null;
        const selected_path = if (nested_path) |p| blk: {
            if (p.len > 0 and p[0] == '/') {
                if (std.fs.openDirAbsolute(p, .{ .iterate = true })) |nested_dir| {
                    var d = nested_dir;
                    d.close();
                    break :blk p;
                } else |_| {}
            } else {
                if (std.fs.cwd().openDir(p, .{ .iterate = true })) |nested_dir| {
                    var d = nested_dir;
                    d.close();
                    break :blk p;
                } else |_| {}
            }
            break :blk accounts_dir_path;
        } else accounts_dir_path;

        var dir = if (selected_path.len > 0 and selected_path[0] == '/')
            try std.fs.openDirAbsolute(selected_path, .{ .iterate = true })
        else
            try std.fs.cwd().openDir(selected_path, .{ .iterate = true });
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".av")) continue;

            var file = try dir.openFile(entry.name, .{});
            defer file.close();

            const stat = try file.stat();
            if (stat.size < header_size) continue;

            var header: [header_size]u8 = undefined;
            _ = try file.preadAll(&header, 0);
            if (!std.mem.eql(u8, header[0..8], &header_magic)) continue;

            const current_len = std.mem.readInt(u64, header[12..][0..8], .little);
            const file_size: usize = @intCast(stat.size);
            const limit: usize = @min(@as(usize, @intCast(current_len)), file_size);
            if (limit <= header_size) continue;

            var offset: usize = header_size;
            while (offset + record_header_len <= limit) {
                var header_buf: [record_header_len]u8 = undefined;
                _ = try file.preadAll(&header_buf, offset);
                var cursor: usize = 0;
                const pubkey = header_buf[cursor..][0..32];
                cursor += 32;
                const lamports = std.mem.readInt(u64, header_buf[cursor..][0..8], .little);
                cursor += 8;
                const owner = header_buf[cursor..][0..32];
                cursor += 32;
                const executable = header_buf[cursor] != 0;
                cursor += 1;
                const rent_epoch = std.mem.readInt(u64, header_buf[cursor..][0..8], .little);
                cursor += 8;
                const data_len = std.mem.readInt(u32, header_buf[cursor..][0..4], .little);
                cursor += 4;

                const total_len = record_header_len + @as(usize, data_len);
                if (offset + total_len > limit) break;

                var buf8: [8]u8 = undefined;
                std.mem.writeInt(u64, &buf8, write_version, .little);
                try writer.writeAll(&buf8);
                std.mem.writeInt(u64, &buf8, data_len, .little);
                try writer.writeAll(&buf8);
                try writer.writeAll(pubkey);

                std.mem.writeInt(u64, &buf8, lamports, .little);
                try writer.writeAll(&buf8);
                std.mem.writeInt(u64, &buf8, rent_epoch, .little);
                try writer.writeAll(&buf8);
                try writer.writeAll(owner);
                try writer.writeByte(@intFromBool(executable));
                try writer.writeAll(pad_bytes[0..7]);

                // Account hash (32 bytes) - required between AccountMeta and data
                // in Agave's AppendVec format. Use zeros for locally-generated snapshots.
                const zero_hash = [_]u8{0} ** 32;
                try writer.writeAll(&zero_hash);

                var remaining: usize = @intCast(data_len);
                var data_offset: u64 = @intCast(offset + record_header_len);
                var chunk: [8192]u8 = undefined;
                while (remaining > 0) {
                    const take = @min(remaining, chunk.len);
                    _ = try file.preadAll(chunk[0..take], data_offset);
                    try writer.writeAll(chunk[0..take]);
                    data_offset += take;
                    remaining -= take;
                }

                const HASH_SIZE: usize = 32;
                const record_len = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE + @as(usize, data_len);
                const pad = (8 - (record_len % 8)) & 7;
                if (pad != 0) {
                    try writer.writeAll(pad_bytes[0..pad]);
                }

                accounts_written += 1;
                lamports_total = std.math.add(u64, lamports_total, lamports) catch lamports_total;
                offset += total_len;
            }
        }

        return .{
            .accounts_written = accounts_written,
            .lamports_total = lamports_total,
        };
    }

    /// Load accounts from an AppendVec file (Solana snapshot format)
    ///
    /// AppendVec format per account:
    ///   StoredMeta:   write_version(u64) + data_len(u64) + pubkey(32)
    ///   AccountMeta:  lamports(u64) + rent_epoch(u64) + owner(32) + executable(bool) + padding
    ///   Data:         variable length (data_len bytes)
    ///   Hash:         32 bytes (optional, may not be present)
    ///
    /// OPTIMIZATION: Uses mmap for files > 1MB to avoid large heap allocations
    fn loadAppendVec(self: *Self, dir: fs.Dir, filename: []const u8, slot: u64, accounts_db: anytype) !AppendVecLoadResult {
        // Open append vec file
        var file = try dir.openFile(filename, .{});
        defer file.close();

        // Get file size
        const stat = try file.stat();
        const file_size = stat.size;

        if (file_size == 0) {
            return AppendVecLoadResult{
                .accounts_count = 0,
                .lamports_total = 0,
            };
        }

        // Use mmap for large files (> 1MB) to avoid heap pressure
        const USE_MMAP_THRESHOLD: usize = 1024 * 1024;
        const use_mmap = file_size > USE_MMAP_THRESHOLD;

        var buf: []const u8 = undefined;
        const mmap_ptr: ?[]align(std.heap.page_size_min) u8 = null;
        var alloc_ptr: ?[]u8 = null;

        // SIGBUS FIX: Don't use mmap - it can cause SIGBUS if file is truncated/sparse
        // Instead, always read into memory. This is slightly slower but much safer.
        // The kernel can handle sparse files via read() but mmap will SIGBUS.
        _ = use_mmap; // Suppress unused warning

        alloc_ptr = self.allocator.alloc(u8, file_size) catch |err| {
            std.log.warn("[Snapshot] Failed to allocate {d} bytes for {s}: {}", .{ file_size, filename, err });
            return AppendVecLoadResult{ .accounts_count = 0, .lamports_total = 0 };
        };

        const bytes_read = file.readAll(alloc_ptr.?) catch |err| {
            std.log.warn("[Snapshot] Failed to read {s}: {}", .{ filename, err });
            self.allocator.free(alloc_ptr.?);
            return AppendVecLoadResult{ .accounts_count = 0, .lamports_total = 0 };
        };

        if (bytes_read != file_size) {
            std.log.warn("[Snapshot] Short read on {s}: expected {d}, got {d}", .{ filename, file_size, bytes_read });
            self.allocator.free(alloc_ptr.?);
            return AppendVecLoadResult{ .accounts_count = 0, .lamports_total = 0 };
        }
        buf = alloc_ptr.?;

        // Ensure cleanup on exit
        defer {
            if (mmap_ptr) |m| {
                std.posix.munmap(m);
            }
            if (alloc_ptr) |a| {
                self.allocator.free(a);
            }
        }

        // Parse accounts from AppendVec
        var offset: usize = 0;
        var accounts_count: u64 = 0;
        var lamports_total: u64 = 0;

        // Agave AppendVec on-disk record layout (verified against Sig's accounts_file.zig):
        // StoredMeta size: 8 (write_version) + 8 (data_len) + 32 (pubkey) = 48 bytes
        // AccountMeta size: 8 (lamports) + 8 (rent_epoch) + 32 (owner) + 1 (executable) + 7 (padding) = 56 bytes
        // Hash: 32 bytes (account hash, stored between AccountMeta and data)
        // Minimum account entry: 48 + 56 + 32 = 136 bytes (with 0 data)
        const STORED_META_SIZE: usize = 48;
        const ACCOUNT_META_SIZE: usize = 56;
        const HASH_SIZE: usize = 32;
        const MIN_ACCOUNT_SIZE: usize = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE;

        // Maximum reasonable data_len to prevent malicious input
        const MAX_ACCOUNT_DATA_LEN: u64 = 10 * 1024 * 1024; // 10MB max per account

        while (offset + MIN_ACCOUNT_SIZE <= file_size) {
            // Parse StoredMeta
            const write_version = std.mem.readInt(u64, buf[offset..][0..8], .little);
            const data_len = std.mem.readInt(u64, buf[offset + 8 ..][0..8], .little);

            // Sanity checks
            if (write_version == 0 and data_len == 0) {
                // Empty/end marker
                break;
            }

            // Validate data_len to prevent malicious input
            if (data_len > MAX_ACCOUNT_DATA_LEN) {
                std.log.warn("[Snapshot] DIAG: file={s} offset=0x{x} accounts_ok={d} write_ver={d} data_len={d}", .{
                    filename, offset, accounts_count, write_version, data_len,
                });
                // Hexdump first 16 bytes at failing offset for debugging
                if (offset + 16 <= file_size) {
                    std.log.warn("[Snapshot] DIAG: bytes @0x{x}: {x:0>2}", .{ offset, buf[offset..][0..16].* });
                }
                break;
            }

            // Pubkey at offset 16 - explicitly initialize
            var pubkey: [32]u8 = std.mem.zeroes([32]u8);
            @memcpy(&pubkey, buf[offset + 16 ..][0..32]);

            // Parse AccountMeta (starts at offset + STORED_META_SIZE)
            const meta_offset = offset + STORED_META_SIZE;
            if (meta_offset + ACCOUNT_META_SIZE + HASH_SIZE > file_size) break;

            const lamports = std.mem.readInt(u64, buf[meta_offset..][0..8], .little);
            const rent_epoch = std.mem.readInt(u64, buf[meta_offset + 8 ..][0..8], .little);

            // Owner - explicitly initialize
            var owner: [32]u8 = std.mem.zeroes([32]u8);
            @memcpy(&owner, buf[meta_offset + 16 ..][0..32]);

            const executable = buf[meta_offset + 48] != 0;

            // Hash (32 bytes) sits between AccountMeta and data in Agave's format
            // const hash = buf[meta_offset + ACCOUNT_META_SIZE ..][0..HASH_SIZE];
            // Data starts after AccountMeta + Hash
            const data_offset = meta_offset + ACCOUNT_META_SIZE + HASH_SIZE;
            const data_end = data_offset + @as(usize, @intCast(data_len));

            if (data_end > file_size) {
                // Corrupted or truncated file
                break;
            }

            // Extract account data
            const data = buf[data_offset..data_end];

            // Store account in database if provided
            if (@typeInfo(@TypeOf(accounts_db)) != .null) {
                // Create account structure
                const core_pubkey = @as(*const @import("core").Pubkey, @ptrCast(&pubkey));
                const core_owner = @as(*const @import("core").Pubkey, @ptrCast(&owner));

                const account = @import("accounts.zig").Account{
                    .lamports = lamports,
                    .owner = core_owner.*,
                    .executable = executable,
                    .rent_epoch = rent_epoch,
                    .data = data,
                };

                // Use the fastest available bulk path for snapshot loading:
                // 1. storeAccountBulk: skips cache, still uses AppendVec
                // 2. storeAccount: full path (last resort)
                const store_err: ?anyerror = blk: {
                    if (@hasDecl(@TypeOf(accounts_db.*), "storeAccountBulk")) {
                        accounts_db.storeAccountBulk(core_pubkey, &account, slot) catch |err| {
                            break :blk err;
                        };
                        break :blk null;
                    }
                    if (@hasDecl(@TypeOf(accounts_db.*), "storeAccount")) {
                        accounts_db.storeAccount(core_pubkey, &account, slot) catch |err| {
                            break :blk err;
                        };
                        break :blk null;
                    }
                    break :blk null;
                };

                if (store_err) |err| {
                    if (accounts_count < 5) {
                        std.log.warn("[Snapshot] storeAccount error: {}", .{err});
                    }
                }
            }

            // Update stats with overflow check
            accounts_count += 1;
            lamports_total = std.math.add(u64, lamports_total, lamports) catch blk: {
                std.log.warn("[Snapshot] Lamports overflow, capping at max", .{});
                break :blk std.math.maxInt(u64);
            };

            // Advance past the entire record (StoredMeta + AccountMeta + Hash + data)
            offset = data_end;

            // Ensure 8-byte alignment for next entry
            offset = (offset + 7) & ~@as(usize, 7);
        }

        return AppendVecLoadResult{
            .accounts_count = accounts_count,
            .lamports_total = lamports_total,
        };
    }

    fn parseSlotFromFilename(filename: []const u8) ?u64 {
        const dot = std.mem.indexOfScalar(u8, filename, '.') orelse return null;
        return std.fmt.parseInt(u64, filename[0..dot], 10) catch null;
    }

    /// Clean up old snapshots
    pub fn cleanupOldSnapshots(self: *Self, keep_count: usize) !void {
        var dir = try fs.cwd().openDir(self.snapshots_dir, .{ .iterate = true });
        defer dir.close();

        var snapshots = std.ArrayListUnmanaged(SnapshotFile){};
        defer snapshots.deinit(self.allocator);

        // Collect all snapshots
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (SnapshotInfo.fromFilename(entry.name)) |info| {
                const stat = try dir.statFile(entry.name);
                try snapshots.append(self.allocator, .{
                    .name = try self.allocator.dupe(u8, entry.name),
                    .slot = info.slot,
                    .mtime = stat.mtime,
                });
            }
        }

        // Sort by slot (descending)
        std.mem.sort(SnapshotFile, snapshots.items, {}, struct {
            fn lessThan(_: void, a: SnapshotFile, b: SnapshotFile) bool {
                return a.slot > b.slot;
            }
        }.lessThan);

        // Delete old ones
        var i: usize = keep_count;
        while (i < snapshots.items.len) : (i += 1) {
            dir.deleteFile(snapshots.items[i].name) catch {};
            self.allocator.free(snapshots.items[i].name);
        }

        // Free kept names
        for (snapshots.items[0..@min(keep_count, snapshots.items.len)]) |s| {
            self.allocator.free(s.name);
        }
    }
};

const SnapshotFile = struct {
    name: []const u8,
    slot: u64,
    mtime: i128,
};

const AppendVecLoadResult = struct {
    accounts_count: u64,
    lamports_total: u64,
};

pub const LoadResult = struct {
    slot: u64,
    accounts_loaded: u64,
    lamports_total: u64,
    /// accounts_lt_hash extracted from snapshot manifest. null if not available.
    accounts_lt_hash: ?[2048]u8 = null,
};

/// TAR header structure
const TarHeader = struct {
    name: [100]u8,
    mode: [8]u8,
    uid: [8]u8,
    gid: [8]u8,
    size: u64,
    mtime: [12]u8,
    checksum: [8]u8,
    typeflag: u8,
    linkname: [100]u8,
    magic: [6]u8,
    version: [2]u8,
    uname: [32]u8,
    gname: [32]u8,
    devmajor: [8]u8,
    devminor: [8]u8,
    prefix: [155]u8,
};

fn parseTarHeader(buf: *const [512]u8) ?TarHeader {
    // Check magic
    const magic = buf[257..263];
    if (!std.mem.eql(u8, magic, "ustar\x00") and
        !std.mem.eql(u8, magic, "ustar "))
    {
        return null;
    }

    // Parse size (octal)
    const size_str = buf[124..136];
    const size = parseOctal(size_str);

    return TarHeader{
        .name = buf[0..100].*,
        .mode = buf[100..108].*,
        .uid = buf[108..116].*,
        .gid = buf[116..124].*,
        .size = size,
        .mtime = buf[136..148].*,
        .checksum = buf[148..156].*,
        .typeflag = buf[156],
        .linkname = buf[157..257].*,
        .magic = buf[257..263].*,
        .version = buf[263..265].*,
        .uname = buf[265..297].*,
        .gname = buf[297..329].*,
        .devmajor = buf[329..337].*,
        .devminor = buf[337..345].*,
        .prefix = buf[345..500].*,
    };
}

fn parseOctal(str: []const u8) u64 {
    var result: u64 = 0;
    for (str) |c| {
        if (c >= '0' and c <= '7') {
            result = result * 8 + (c - '0');
        }
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

test "parse snapshot filename" {
    const full = SnapshotInfo.fromFilename("snapshot-123456789-2ZWhY8YEcyG425fp68G43HTUL7HERCvooekkqJvZYoLt.tar.zst");
    try std.testing.expect(full != null);
    try std.testing.expectEqual(@as(u64, 123456789), full.?.slot);
    try std.testing.expect(!full.?.is_incremental);

    const incr = SnapshotInfo.fromFilename("incremental-snapshot-100000000-123456789-2ZWhY8YEcyG425fp68G43HTUL7HERCvooekkqJvZYoLt.tar.zst");
    try std.testing.expect(incr != null);
    try std.testing.expectEqual(@as(u64, 123456789), incr.?.slot);
    try std.testing.expectEqual(@as(u64, 100000000), incr.?.base_slot.?);
    try std.testing.expect(incr.?.is_incremental);
}

test "snapshot save/load roundtrip" {
    const accounts = @import("accounts.zig");
    const core_types = @import("core");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base_path);

    const accounts_path = try std.fs.path.join(std.testing.allocator, &.{ base_path, "accounts" });
    defer std.testing.allocator.free(accounts_path);
    try std.fs.cwd().makePath(accounts_path);

    const accounts_path2 = try std.fs.path.join(std.testing.allocator, &.{ base_path, "accounts2" });
    defer std.testing.allocator.free(accounts_path2);
    try std.fs.cwd().makePath(accounts_path2);

    const snapshots_path = try std.fs.path.join(std.testing.allocator, &.{ base_path, "snapshots" });
    defer std.testing.allocator.free(snapshots_path);
    try std.fs.cwd().makePath(snapshots_path);

    var adb = try accounts.AccountsDb.init(std.testing.allocator, accounts_path, null);
    defer adb.deinit();

    const owner = core_types.Pubkey{ .data = [_]u8{9} ** 32 };
    const pubkey1 = core_types.Pubkey{ .data = [_]u8{1} ** 32 };
    const pubkey2 = core_types.Pubkey{ .data = [_]u8{2} ** 32 };

    const account1 = accounts.Account{
        .lamports = 111,
        .owner = owner,
        .executable = false,
        .rent_epoch = 1,
        .data = "one",
    };
    const account2 = accounts.Account{
        .lamports = 222,
        .owner = owner,
        .executable = true,
        .rent_epoch = 2,
        .data = "two-two",
    };

    try adb.storeAccount(&pubkey1, &account1, 5);
    try adb.storeAccount(&pubkey2, &account2, 5);

    var sm = SnapshotManager.init(std.testing.allocator, snapshots_path);
    defer sm.deinit();

    var save = try sm.saveSnapshot(adb, 5);
    defer save.deinit(std.testing.allocator);

    var adb2 = try accounts.AccountsDb.init(std.testing.allocator, accounts_path2, null);
    defer adb2.deinit();

    const load = try sm.loadSnapshot(save.output_dir, adb2);
    try std.testing.expectEqual(save.accounts_written, load.accounts_loaded);

    const hash2 = try adb2.computeHash();
    var hash2_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hash2_hex, "{s}", .{std.fmt.fmtSliceHexLower(&hash2.data)});
    try std.testing.expectEqualSlices(u8, &save.accounts_hash_hex, &hash2_hex);
}

test "download progress" {
    const progress = DownloadProgress{
        .total_bytes = 1000000,
        .downloaded_bytes = 500000,
        .elapsed_ns = 1_000_000_000, // 1 second
    };

    try std.testing.expectEqual(@as(f64, 50.0), progress.percentComplete());
    try std.testing.expectEqual(@as(f64, 500000.0), progress.bytesPerSecond());
    try std.testing.expectEqual(@as(f64, 1.0), progress.etaSeconds());
}

test "parse octal" {
    try std.testing.expectEqual(@as(u64, 0), parseOctal("0"));
    try std.testing.expectEqual(@as(u64, 7), parseOctal("7"));
    try std.testing.expectEqual(@as(u64, 8), parseOctal("10"));
    try std.testing.expectEqual(@as(u64, 64), parseOctal("100"));
}

// ── bf8bdc98 download-guard smoke tests ──────────────────────────────────────
// These verify rejectEmptyDownload's three invariants without mocking curl:
//   1. 0-byte file → EmptyDownload + file deleted
//   2. file at threshold → returns void, file intact
//   3. missing file → DownloadFailed
// Run: zig test src/vex_store/snapshot.zig --test-filter "rejectEmptyDownload"

fn testTmpPath(comptime name: []const u8) []const u8 {
    return "/tmp/vex-fd-rejectempty-test-" ++ name;
}

test "rejectEmptyDownload deletes 0-byte file and returns EmptyDownload" {
    const path = testTmpPath("zero");
    // setup: create a 0-byte file
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        f.close();
    }
    var sm = SnapshotManager.init(std.testing.allocator, "");
    const result = sm.rejectEmptyDownload(path, "https://example.com/test");
    try std.testing.expectError(error.EmptyDownload, result);
    // file must be gone
    const after = std.fs.cwd().statFile(path);
    try std.testing.expectError(error.FileNotFound, after);
}

test "rejectEmptyDownload accepts file at threshold and leaves it intact" {
    const path = testTmpPath("threshold");
    defer std.fs.cwd().deleteFile(path) catch {};
    // setup: create a file at exactly MIN_SNAPSHOT_DOWNLOAD_BYTES
    {
        const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer f.close();
        const filler = [_]u8{0xAA} ** 4096;
        var written: u64 = 0;
        while (written < MIN_SNAPSHOT_DOWNLOAD_BYTES) {
            const n = try f.write(&filler);
            written += n;
        }
    }
    var sm = SnapshotManager.init(std.testing.allocator, "");
    try sm.rejectEmptyDownload(path, "https://example.com/test");
    // file must still exist + be ≥ threshold
    const stat = try std.fs.cwd().statFile(path);
    try std.testing.expect(stat.size >= MIN_SNAPSHOT_DOWNLOAD_BYTES);
}

test "rejectEmptyDownload returns DownloadFailed when file does not exist" {
    const path = testTmpPath("missing");
    // ensure absent
    std.fs.cwd().deleteFile(path) catch {};
    var sm = SnapshotManager.init(std.testing.allocator, "");
    const result = sm.rejectEmptyDownload(path, "https://example.com/test");
    try std.testing.expectError(error.DownloadFailed, result);
}
