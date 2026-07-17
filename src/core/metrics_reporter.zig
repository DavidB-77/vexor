//! metrics_reporter.zig — Agave-schema-compatible InfluxDB metrics reporter.
//!
//! Submits validator telemetry to the Solana metrics cluster (metrics.solana.com)
//! exactly the way Agave does, so the standard Anza dashboards recognize this node:
//!
//!   • Config:  SOLANA_METRICS_CONFIG="host=<url>,db=<db>,u=<user>,p=<pass>"
//!              (parse mirrors agave metrics/src/metrics.rs get_metrics_config:
//!               split ',', each pair split '=' with EXACTLY 2 parts, keys
//!               host/db/u/p only, all four required).
//!   • URL:     "{host}/write?db={db}&u={u}&p={p}&precision=n"
//!              (agave metrics.rs InfluxDbMetricsWriter::build_write_url — creds in
//!               query string, NOT basic-auth).
//!   • Wire:    InfluxDB line protocol exactly as agave serialize_points emits it:
//!              "measurement,host_id=<id>[,tag=v...] f1=v1[,f2=v2] <ts_ns>\n"
//!              i64 fields get an 'i' suffix; strings are double-quoted with '"'
//!              escaped as '\"'; bools are true/false; f64 plain decimal. host_id
//!              (= identity pubkey base58, agave set_host_id) is ALWAYS the first tag.
//!   • Cadence: one flush per 10 s (agave MetricsAgent write_frequency), 5 s HTTP
//!              timeout, drop-batch-on-failure (never queue, never retry-storm).
//!
//! ZERO-HOT-PATH CONTRACT: this file adds NO instrumentation anywhere. A single
//! background thread (self-niced to 19, floating — never pinned) SAMPLES existing
//! atomic counters via a caller-supplied callback (monotonic loads only) plus
//! /proc//sys system facts, formats one batch, and POSTs it over ONE persistent
//! libcurl easy handle (dlopen'd at thread start; subprocess /usr/bin/curl
//! fallback). Everything here runs on the reporter thread only.
//!
//! OFFLINE GUARD: start() refuses to spawn under VEX_LEDGER_REPLAY or
//! VEX_SNAPSHOT_OFFLINE (golden-gate/offline-replay runs stay network-silent),
//! and when SOLANA_METRICS_CONFIG is unset/invalid (master switch — no VEX_* env).
//!
//! SECURITY: the password is never logged (redacted to p=****) and never baked
//! into the binary — env only.

const std = @import("std");
const builtin = @import("builtin");

// ═════════════════════════════════════════════════════════════════════════════
// Config parsing (KAT'd) — mirrors agave metrics.rs get_metrics_config
// ═════════════════════════════════════════════════════════════════════════════

pub const ConfigError = error{
    Empty,
    InvalidPair,
    UnknownKey,
    Incomplete,
    TooLarge,
};

/// Hard cap on the raw SOLANA_METRICS_CONFIG byte length. Defense-in-depth
/// against a corrupted/oversized env value (e.g. a stray EnvironmentFile
/// concatenation) — the real config is ~110 bytes; 4096 is generous headroom
/// with no plausible legitimate config anywhere near it.
pub const MAX_CONFIG_BYTES: usize = 4096;
/// Hard cap on the number of comma-separated pairs scanned. Backstop only —
/// MAX_CONFIG_BYTES already bounds this to ~4096 in the worst case (all
/// single-byte pairs), this just makes the bound explicit and cheap to check.
pub const MAX_CONFIG_PAIRS: usize = 64;

pub const MetricsConfig = struct {
    host: []const u8 = "",
    db: []const u8 = "",
    username: []const u8 = "",
    password: []const u8 = "",
};

/// Parse "host=...,db=...,u=...,p=..." (any order). Slices reference `s`.
/// Never panics on any input — corrupt config disables metrics, never crashes
/// the validator (caller catches the error set).
///
/// HARDENING (2026-07-11, incident #2): this previously iterated with
/// `std.mem.splitScalar(u8, s, ',')` — i.e. the SHARED generic
/// `std.mem.SplitIterator(u8, .scalar)` monomorphization that every u8-comma
/// split call anywhere in the binary compiles down to. A live boot panicked
/// inside that iterator's `next()` (zig-0.15.2 lib/std/mem.zig:3152,
/// `return self.buffer[start..end];`), reached from this call site while
/// parsing the live SOLANA_METRICS_CONFIG — a shape none of the KAT suite's
/// valid/missing/corrupt strings exercised. Post-incident: the exact live
/// bytes were extracted from deploy.sh:1160 AND cross-checked against two
/// independent /proc/<pid>/environ forensic captures (byte-identical), then
/// replayed against this exact parser in isolation — it did not reproduce
/// (see the "live-shaped repro" KAT below), and `SplitIterator(u8,.scalar
/// ).next()` is provably total for any `[]const u8` input given
/// `indexOfScalarPos`'s own `start_index >= slice.len` guard (verified
/// against the zig-0.15.2 source). Same "unconfirmed trigger" outcome as
/// incident #1's pthread_detach panic (see `detachOrWarn`'s doc comment) —
/// so the same principle applies: stop chasing an unreproduced trigger, make
/// the code correct by construction instead. This rewrite hand-rolls the
/// comma/equals scan with `std.mem.indexOfScalarPos` (a stateless bounded
/// search, not a stateful shared iterator whose safety depends on invariants
/// held across every OTHER call site in the binary) and explicit `pos <=
/// s.len` bookkeeping local to this function, plus hard length/pair caps as
/// defense-in-depth against a corrupted or oversized env value.
pub fn parseConfig(s: []const u8) ConfigError!MetricsConfig {
    if (s.len == 0) return ConfigError.Empty;
    if (s.len > MAX_CONFIG_BYTES) return ConfigError.TooLarge;
    var cfg = MetricsConfig{};
    var pos: usize = 0; // invariant: 0 <= pos <= s.len at the top of every iteration
    var pairs: usize = 0;
    while (true) {
        pairs += 1;
        if (pairs > MAX_CONFIG_PAIRS) return ConfigError.InvalidPair;
        const comma = std.mem.indexOfScalarPos(u8, s, pos, ',') orelse s.len;
        const pair = s[pos..comma]; // pos <= comma <= s.len — always in-bounds
        // Agave: pair.split('=') must yield EXACTLY 2 elements.
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return ConfigError.InvalidPair;
        if (std.mem.indexOfScalarPos(u8, pair, eq + 1, '=') != null) return ConfigError.InvalidPair;
        const k = pair[0..eq];
        const v = pair[eq + 1 ..];
        if (std.mem.eql(u8, k, "host")) {
            cfg.host = v;
        } else if (std.mem.eql(u8, k, "db")) {
            cfg.db = v;
        } else if (std.mem.eql(u8, k, "u")) {
            cfg.username = v;
        } else if (std.mem.eql(u8, k, "p")) {
            cfg.password = v;
        } else {
            return ConfigError.UnknownKey;
        }
        if (comma >= s.len) break; // consumed the whole string
        pos = comma + 1; // comma < s.len here, so pos <= s.len holds
    }
    if (cfg.host.len == 0 or cfg.db.len == 0 or cfg.username.len == 0 or cfg.password.len == 0)
        return ConfigError.Incomplete;
    return cfg;
}

// ═════════════════════════════════════════════════════════════════════════════
// InfluxDB line-protocol point builder + batch (KAT'd)
// ═════════════════════════════════════════════════════════════════════════════

pub const MAX_POINT_BYTES = 2048;
pub const MAX_BATCH_POINTS = 64;
pub const MAX_BATCH_BYTES = 64 * 1024;

/// One line-protocol point, built into a fixed buffer. Overflow marks the point
/// invalid (dropped at commit) — never a crash.
pub const PointBuf = struct {
    buf: [MAX_POINT_BYTES]u8 = undefined,
    len: usize = 0,
    n_fields: usize = 0,
    overflow: bool = false,

    fn appendRaw(self: *PointBuf, bytes: []const u8) void {
        if (self.overflow or self.len + bytes.len > self.buf.len) {
            self.overflow = true;
            return;
        }
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendFmt(self: *PointBuf, comptime fmt: []const u8, args: anytype) void {
        if (self.overflow) return;
        const written = std.fmt.bufPrint(self.buf[self.len..], fmt, args) catch {
            self.overflow = true;
            return;
        };
        self.len += written.len;
    }

    /// Escape a tag value per influx line protocol: '\' before space, comma, equals.
    /// (Agave emits tag values verbatim because it controls them; we escape
    /// defensively — a no-op for every value we actually emit, KAT'd.)
    fn appendTagEscaped(self: *PointBuf, v: []const u8) void {
        for (v) |c| {
            switch (c) {
                ' ', ',', '=' => self.appendRaw(&[2]u8{ '\\', c }),
                else => self.appendRaw(&[1]u8{c}),
            }
        }
    }

    /// begin: "measurement,host_id=<id>" — host_id is always the first tag,
    /// exactly like agave serialize_points.
    pub fn begin(self: *PointBuf, measurement: []const u8, host_id: []const u8) void {
        self.len = 0;
        self.n_fields = 0;
        self.overflow = false;
        self.appendRaw(measurement);
        self.appendRaw(",host_id=");
        self.appendTagEscaped(host_id);
    }

    pub fn tag(self: *PointBuf, name: []const u8, value: []const u8) void {
        self.appendRaw(",");
        self.appendRaw(name);
        self.appendRaw("=");
        self.appendTagEscaped(value);
    }

    fn fieldSep(self: *PointBuf) void {
        self.appendRaw(if (self.n_fields == 0) " " else ",");
        self.n_fields += 1;
    }

    pub fn fieldI64(self: *PointBuf, name: []const u8, v: i64) void {
        self.fieldSep();
        self.appendFmt("{s}={d}i", .{ name, v });
    }

    pub fn fieldU64(self: *PointBuf, name: []const u8, v: u64) void {
        // Agave submits counters as i64 ('i' suffix); saturate to keep schema.
        const clamped: i64 = if (v > std.math.maxInt(i64)) std.math.maxInt(i64) else @intCast(v);
        self.fieldI64(name, clamped);
    }

    pub fn fieldF64(self: *PointBuf, name: []const u8, v: f64) void {
        self.fieldSep();
        self.appendFmt("{s}={d}", .{ name, v });
    }

    pub fn fieldBool(self: *PointBuf, name: []const u8, v: bool) void {
        self.fieldSep();
        self.appendFmt("{s}={s}", .{ name, if (v) "true" else "false" });
    }

    /// String field: double-quoted, '"' escaped as '\"' (agave add_field_str).
    pub fn fieldStr(self: *PointBuf, name: []const u8, v: []const u8) void {
        self.fieldSep();
        self.appendRaw(name);
        self.appendRaw("=\"");
        for (v) |c| {
            if (c == '"') self.appendRaw("\\\"") else self.appendRaw(&[1]u8{c});
        }
        self.appendRaw("\"");
    }

    /// end: " <ts_ns>\n". Returns the finished line or null on overflow/no-fields.
    pub fn end(self: *PointBuf, ts_ns: u64) ?[]const u8 {
        if (self.n_fields == 0) return null; // influx requires >=1 field
        self.appendFmt(" {d}\n", .{ts_ns});
        if (self.overflow) return null;
        return self.buf[0..self.len];
    }
};

/// Fixed-capacity batch: ≤ MAX_BATCH_POINTS points and ≤ MAX_BATCH_BYTES bytes.
/// Over-cap points are DROPPED (counted), never queued — the no-retry-storm rule.
pub const Batch = struct {
    buf: [MAX_BATCH_BYTES]u8 = undefined,
    len: usize = 0,
    points: usize = 0,
    dropped: usize = 0,

    pub fn reset(self: *Batch) void {
        self.len = 0;
        self.points = 0;
        self.dropped = 0;
    }

    pub fn commit(self: *Batch, line: ?[]const u8) void {
        const l = line orelse {
            self.dropped += 1;
            return;
        };
        if (self.points >= MAX_BATCH_POINTS or self.len + l.len > self.buf.len) {
            self.dropped += 1;
            return;
        }
        @memcpy(self.buf[self.len..][0..l.len], l);
        self.len += l.len;
        self.points += 1;
    }

    pub fn body(self: *const Batch) []const u8 {
        return self.buf[0..self.len];
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// Validator counter sample — filled by a main.zig callback from EXISTING atomics
// (monotonic loads only; anything not atomic/thread-safe is skipped by design).
// ═════════════════════════════════════════════════════════════════════════════

pub const ValidatorSample = struct {
    // replay (ReplayStats atomics, replay_stage.zig)
    replay_valid: bool = false,
    shreds_received: u64 = 0,
    invalid_shreds: u64 = 0,
    slots_replayed: u64 = 0,
    successful_txs: u64 = 0,
    failed_txs: u64 = 0,
    votes_sent: u64 = 0,
    blocks_produced: u64 = 0,
    slot_queue_drops: u64 = 0,
    root_slot: u64 = 0, // root_bank atomic ptr → slot (immutable post-freeze)

    // vote-coverage census (file-scope atomics, replay_stage.getVoteCensusSnapshot)
    census_valid: bool = false,
    census_eligible: u64 = 0,
    census_cast: u64 = 0,
    census_fallback_decided: u64 = 0,
    census_fallback_cast: u64 = 0,
    census_silent_withhold: u64 = 0,

    // tvu (TvuService.Stats atomics, tvu.zig)
    tvu_valid: bool = false,
    tvu_shreds_received: u64 = 0,
    tvu_shreds_inserted: u64 = 0,
    tvu_shreds_duplicate: u64 = 0,
    tvu_shreds_invalid: u64 = 0,
    tvu_zc_version_rejects: u64 = 0,
    tvu_repairs_sent: u64 = 0,
    tvu_repairs_received: u64 = 0,
    tvu_repairs_served: u64 = 0,
    tvu_repair_requests_received: u64 = 0,
    tvu_slots_completed: u64 = 0,
    tvu_max_slot_seen: u64 = 0,
    tvu_shreds_retransmitted: u64 = 0,
    tvu_repairs_dropped_ratelimit: u64 = 0,
    tvu_rx_shed: u64 = 0,

    // AF_XDP: kernel socket fd; the reporter does its own read-only
    // getsockopt(SOL_XDP, XDP_STATISTICS) — no Vexor state is touched.
    afxdp_fd: ?std.posix.fd_t = null,
};

pub const SampleFn = *const fn (ctx: ?*anyopaque, out: *ValidatorSample) void;

pub const InitOpts = struct {
    host_id: []const u8, // identity pubkey base58 (copied)
    version: []const u8, // "vexor-<githash>" (copied)
    cluster_type: i64 = 0, // agave ClusterType as u32: Testnet=0
    shred_version: i64 = 0,
    waited_for_supermajority: bool = false,
    boot_elapsed_ms: i64 = 0,
    ledger_path: []const u8 = "", // disk-usage sampling (copied)
    accounts_path: []const u8 = "",
    snapshots_path: []const u8 = "",
    sample_fn: ?SampleFn = null,
    sample_ctx: ?*anyopaque = null,
};

// ═════════════════════════════════════════════════════════════════════════════
// HTTP writer — ONE persistent libcurl easy handle (dlopen; connection reuse
// across the 10 s flushes), subprocess /usr/bin/curl fallback. Reporter-thread-only.
// ═════════════════════════════════════════════════════════════════════════════

const CURLOPT_URL: c_int = 10002;
const CURLOPT_POSTFIELDS: c_int = 10015;
const CURLOPT_POSTFIELDSIZE: c_int = 60;
const CURLOPT_TIMEOUT_MS: c_int = 155;
const CURLOPT_CONNECTTIMEOUT_MS: c_int = 156;
const CURLOPT_NOSIGNAL: c_int = 99;
const CURLOPT_WRITEFUNCTION: c_int = 20011;
const CURLINFO_RESPONSE_CODE: c_int = 2097154;

const CurlGlobalInitFn = *const fn (c_long) callconv(.c) c_int;
const CurlEasyInitFn = *const fn () callconv(.c) ?*anyopaque;
const CurlEasySetoptFn = *const fn (?*anyopaque, c_int, ...) callconv(.c) c_int;
const CurlEasyPerformFn = *const fn (?*anyopaque) callconv(.c) c_int;
const CurlEasyGetinfoFn = *const fn (?*anyopaque, c_int, ...) callconv(.c) c_int;

fn curlDiscardWrite(ptr: ?*anyopaque, size: usize, nmemb: usize, ud: ?*anyopaque) callconv(.c) usize {
    _ = ptr;
    _ = ud;
    return size *% nmemb;
}

pub const CurlWriter = struct {
    handle: ?*anyopaque = null,
    setopt: CurlEasySetoptFn = undefined,
    perform: CurlEasyPerformFn = undefined,
    getinfo: CurlEasyGetinfoFn = undefined,

    /// Try to bring up the persistent handle. Failure → subprocess fallback (caller).
    pub fn init(url_z: [*:0]const u8) ?CurlWriter {
        var lib = std.DynLib.open("libcurl.so.4") catch
            (std.DynLib.open("libcurl.so") catch return null);
        // Intentionally never closed — the handle lives for the process lifetime.
        const global_init = lib.lookup(CurlGlobalInitFn, "curl_global_init") orelse return null;
        const easy_init = lib.lookup(CurlEasyInitFn, "curl_easy_init") orelse return null;
        const setopt = lib.lookup(CurlEasySetoptFn, "curl_easy_setopt") orelse return null;
        const perform = lib.lookup(CurlEasyPerformFn, "curl_easy_perform") orelse return null;
        const getinfo = lib.lookup(CurlEasyGetinfoFn, "curl_easy_getinfo") orelse return null;
        _ = global_init(3); // CURL_GLOBAL_DEFAULT
        const h = easy_init() orelse return null;
        _ = setopt(h, CURLOPT_URL, url_z);
        _ = setopt(h, CURLOPT_NOSIGNAL, @as(c_long, 1)); // mandatory in threads
        _ = setopt(h, CURLOPT_TIMEOUT_MS, @as(c_long, 5000));
        _ = setopt(h, CURLOPT_CONNECTTIMEOUT_MS, @as(c_long, 3000));
        _ = setopt(h, CURLOPT_WRITEFUNCTION, &curlDiscardWrite);
        return .{ .handle = h, .setopt = setopt, .perform = perform, .getinfo = getinfo };
    }

    /// POST `body_bytes`; returns HTTP status (0 on transport failure).
    pub fn post(self: *CurlWriter, body_bytes: []const u8) u32 {
        const h = self.handle orelse return 0;
        _ = self.setopt(h, CURLOPT_POSTFIELDS, body_bytes.ptr);
        _ = self.setopt(h, CURLOPT_POSTFIELDSIZE, @as(c_long, @intCast(body_bytes.len)));
        if (self.perform(h) != 0) return 0;
        var code: c_long = 0;
        _ = self.getinfo(h, CURLINFO_RESPONSE_CODE, &code);
        return if (code > 0) @intCast(code) else 0;
    }
};

/// Subprocess fallback (same /usr/bin/curl the snapshot bootstrap uses).
/// "{host}/write?db={db}&u={u}&p={p}&precision=n" — agave build_write_url, exactly.
pub fn buildWriteUrlZ(allocator: std.mem.Allocator, cfg: MetricsConfig) ![:0]u8 {
    return std.fmt.allocPrintSentinel(allocator, "{s}/write?db={s}&u={s}&p={s}&precision=n", .{ cfg.host, cfg.db, cfg.username, cfg.password }, 0);
}

fn postViaSubprocess(allocator: std.mem.Allocator, url: []const u8, body_bytes: []const u8) u32 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            "/usr/bin/curl", "-s", "-o",            "/dev/null", "-w", "%{http_code}",
            "--max-time",    "5",  "--data-binary", body_bytes,  url,
        },
        .max_output_bytes = 256,
    }) catch return 0;
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);
    const trimmed = std.mem.trim(u8, result.stdout, " \r\n");
    return std.fmt.parseInt(u32, trimmed, 10) catch 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// System stats (/proc, /sys) — Agave system-monitor-service schema
// ═════════════════════════════════════════════════════════════════════════════

fn readSmallFile(path: []const u8, buf: []u8) ?[]const u8 {
    const f = std.fs.cwd().openFile(path, .{}) catch return null;
    defer f.close();
    const n = f.readAll(buf) catch return null;
    return buf[0..n];
}

/// /proc/meminfo value in kB for a "Key:" prefix.
fn meminfoKb(content: []const u8, key: []const u8) ?u64 {
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, key)) {
            var toks = std.mem.tokenizeAny(u8, line[key.len..], " \tkB");
            const v = toks.next() orelse return null;
            return std.fmt.parseInt(u64, v, 10) catch null;
        }
    }
    return null;
}

const UdpStats = struct {
    in_datagrams: u64 = 0,
    no_ports: u64 = 0,
    in_errors: u64 = 0,
    out_datagrams: u64 = 0,
    rcvbuf_errors: u64 = 0,
    sndbuf_errors: u64 = 0,
    in_csum_errors: u64 = 0,
    ignored_multi: u64 = 0,
};

/// /proc/net/snmp "Udp:" header+value rows (agave read_udp_stats).
fn readUdpStats() ?UdpStats {
    var buf: [16384]u8 = undefined;
    const content = readSmallFile("/proc/net/snmp", &buf) orelse return null;
    var header: ?[]const u8 = null;
    var values: ?[]const u8 = null;
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "Udp:")) {
            if (header == null) header = line else {
                values = line;
                break;
            }
        }
    }
    const h = header orelse return null;
    const v = values orelse return null;
    var s = UdpStats{};
    var ht = std.mem.tokenizeScalar(u8, h[4..], ' ');
    var vt = std.mem.tokenizeScalar(u8, v[4..], ' ');
    while (ht.next()) |name| {
        const val_s = vt.next() orelse break;
        const val = std.fmt.parseInt(u64, val_s, 10) catch continue;
        if (std.mem.eql(u8, name, "InDatagrams")) s.in_datagrams = val;
        if (std.mem.eql(u8, name, "NoPorts")) s.no_ports = val;
        if (std.mem.eql(u8, name, "InErrors")) s.in_errors = val;
        if (std.mem.eql(u8, name, "OutDatagrams")) s.out_datagrams = val;
        if (std.mem.eql(u8, name, "RcvbufErrors")) s.rcvbuf_errors = val;
        if (std.mem.eql(u8, name, "SndbufErrors")) s.sndbuf_errors = val;
        if (std.mem.eql(u8, name, "InCsumErrors")) s.in_csum_errors = val;
        if (std.mem.eql(u8, name, "IgnoredMulti")) s.ignored_multi = val;
    }
    return s;
}

const NetDevStats = struct {
    rx_bytes: u64 = 0,
    rx_packets: u64 = 0,
    rx_errs: u64 = 0,
    rx_drops: u64 = 0,
    rx_fifo: u64 = 0,
    rx_frame: u64 = 0,
    tx_bytes: u64 = 0,
    tx_packets: u64 = 0,
    tx_errs: u64 = 0,
    tx_drops: u64 = 0,
    tx_fifo: u64 = 0,
    tx_colls: u64 = 0,
};

/// /proc/net/dev summed across all non-loopback interfaces (agave parse_net_dev_stats).
fn readNetDevStats() ?NetDevStats {
    var buf: [16384]u8 = undefined;
    const content = readSmallFile("/proc/net/dev", &buf) orelse return null;
    var s = NetDevStats{};
    var line_no: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        line_no += 1;
        if (line_no <= 2) continue; // headers
        var toks = std.mem.tokenizeAny(u8, line, " \t");
        const ifname = toks.next() orelse continue;
        if (std.mem.eql(u8, ifname, "lo:")) continue;
        var vals: [16]u64 = [_]u64{0} ** 16;
        var i: usize = 0;
        while (toks.next()) |t| : (i += 1) {
            if (i >= 16) break;
            vals[i] = std.fmt.parseInt(u64, t, 10) catch 0;
        }
        if (i < 16) continue;
        s.rx_bytes += vals[0];
        s.rx_packets += vals[1];
        s.rx_errs += vals[2];
        s.rx_drops += vals[3];
        s.rx_fifo += vals[4];
        s.rx_frame += vals[5];
        s.tx_bytes += vals[8];
        s.tx_packets += vals[9];
        s.tx_errs += vals[10];
        s.tx_drops += vals[11];
        s.tx_fifo += vals[12];
        s.tx_colls += vals[13];
    }
    return s;
}

const DiskStats = struct {
    reads_completed: u64 = 0,
    reads_merged: u64 = 0,
    sectors_read: u64 = 0,
    time_reading_ms: u64 = 0,
    writes_completed: u64 = 0,
    writes_merged: u64 = 0,
    sectors_written: u64 = 0,
    time_writing_ms: u64 = 0,
    io_in_progress: u64 = 0,
    time_io_ms: u64 = 0,
    time_io_weighted_ms: u64 = 0,
    discards_completed: u64 = 0,
    discards_merged: u64 = 0,
    sectors_discarded: u64 = 0,
    time_discarding: u64 = 0,
    flushes_completed: u64 = 0,
    time_flushing: u64 = 0,
    num_disks: u64 = 0,
};

/// /sys/block/*/stat accumulated across physical disks, skipping loop/dm/md
/// (agave read_disk_stats).
fn readDiskStats() ?DiskStats {
    var dir = std.fs.cwd().openDir("/sys/block", .{ .iterate = true }) catch return null;
    defer dir.close();
    var s = DiskStats{};
    var it = dir.iterate();
    while (it.next() catch return null) |entry| {
        if (std.mem.startsWith(u8, entry.name, "loop") or
            std.mem.startsWith(u8, entry.name, "dm") or
            std.mem.startsWith(u8, entry.name, "md")) continue;
        var pathbuf: [256]u8 = undefined;
        const p = std.fmt.bufPrint(&pathbuf, "/sys/block/{s}/stat", .{entry.name}) catch continue;
        var fbuf: [512]u8 = undefined;
        const content = readSmallFile(p, &fbuf) orelse continue;
        var vals: [17]u64 = [_]u64{0} ** 17;
        var toks = std.mem.tokenizeAny(u8, content, " \t\n");
        var i: usize = 0;
        while (toks.next()) |t| : (i += 1) {
            if (i >= 17) break;
            vals[i] = std.fmt.parseInt(u64, t, 10) catch 0;
        }
        if (i < 11) continue; // pre-4.18 kernels have 11 fields minimum
        s.reads_completed += vals[0];
        s.reads_merged += vals[1];
        s.sectors_read += vals[2];
        s.time_reading_ms += vals[3];
        s.writes_completed += vals[4];
        s.writes_merged += vals[5];
        s.sectors_written += vals[6];
        s.time_writing_ms += vals[7];
        s.io_in_progress += vals[8];
        s.time_io_ms += vals[9];
        s.time_io_weighted_ms += vals[10];
        s.discards_completed += vals[11];
        s.discards_merged += vals[12];
        s.sectors_discarded += vals[13];
        s.time_discarding += vals[14];
        s.flushes_completed += vals[15];
        s.time_flushing += vals[16];
        s.num_disks += 1;
    }
    if (s.num_disks == 0) return null;
    return s;
}

/// Minimal x86_64 statfs(2) — Zig 0.15.2 std has no statfs wrapper.
const StatfsBuf = extern struct {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [4]i64,
};

const DiskUsage = struct { total: u64, avail: u64 };

fn statfsPath(path: []const u8) ?DiskUsage {
    if (path.len == 0 or path.len >= 512) return null;
    var zbuf: [512]u8 = undefined;
    @memcpy(zbuf[0..path.len], path);
    zbuf[path.len] = 0;
    var st: StatfsBuf = undefined;
    const rc = std.os.linux.syscall2(.statfs, @intFromPtr(&zbuf), @intFromPtr(&st));
    if (std.os.linux.E.init(rc) != .SUCCESS) return null;
    const bsize: u64 = @intCast(@max(st.f_bsize, 0));
    return .{ .total = st.f_blocks * bsize, .avail = st.f_bavail * bsize };
}

const ProcSelf = struct {
    utime_ticks: u64 = 0,
    stime_ticks: u64 = 0,
    num_threads: u64 = 0,
    rss_bytes: u64 = 0,
    vsize_bytes: u64 = 0,
};

fn readProcSelf() ?ProcSelf {
    var buf: [4096]u8 = undefined;
    const content = readSmallFile("/proc/self/stat", &buf) orelse return null;
    // fields after the ")" of comm: state=1 ... utime=12 stime=13 ... num_threads=18 ... vsize=21 rss=22 (0-indexed post-comm)
    const close_paren = std.mem.lastIndexOfScalar(u8, content, ')') orelse return null;
    var toks = std.mem.tokenizeScalar(u8, content[close_paren + 1 ..], ' ');
    var vals: [24][]const u8 = undefined;
    var i: usize = 0;
    while (toks.next()) |t| : (i += 1) {
        if (i >= 24) break;
        vals[i] = t;
    }
    if (i < 23) return null;
    var s = ProcSelf{};
    s.utime_ticks = std.fmt.parseInt(u64, vals[11], 10) catch 0;
    s.stime_ticks = std.fmt.parseInt(u64, vals[12], 10) catch 0;
    s.num_threads = std.fmt.parseInt(u64, vals[17], 10) catch 0;
    s.vsize_bytes = std.fmt.parseInt(u64, vals[20], 10) catch 0;
    const rss_pages = std.fmt.parseInt(u64, vals[21], 10) catch 0;
    s.rss_bytes = rss_pages * std.heap.pageSize();
    return s;
}

/// Process age in ms (validator-new elapsed_ms): /proc/uptime minus
/// /proc/self/stat starttime (field 22, USER_HZ=100 ticks since boot).
fn procAgeMs() i64 {
    var ubuf: [128]u8 = undefined;
    const up = readSmallFile("/proc/uptime", &ubuf) orelse return 0;
    var ut = std.mem.tokenizeAny(u8, up, " \n");
    const uptime_s = std.fmt.parseFloat(f64, ut.next() orelse return 0) catch return 0;
    var sbuf: [4096]u8 = undefined;
    const stat = readSmallFile("/proc/self/stat", &sbuf) orelse return 0;
    const close_paren = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return 0;
    var toks = std.mem.tokenizeScalar(u8, stat[close_paren + 1 ..], ' ');
    var i: usize = 0;
    var starttime_ticks: u64 = 0;
    while (toks.next()) |t| : (i += 1) {
        if (i == 19) { // starttime = field 22 overall = index 19 post-comm
            starttime_ticks = std.fmt.parseInt(u64, t, 10) catch 0;
            break;
        }
    }
    const age_s = uptime_s - @as(f64, @floatFromInt(starttime_ticks)) / 100.0;
    if (age_s <= 0) return 0;
    return @intFromFloat(age_s * 1000.0);
}

const LoadAvg = struct { one: f64, five: f64, fifteen: f64, total_threads: u64 };

fn readLoadAvg() ?LoadAvg {
    var buf: [256]u8 = undefined;
    const content = readSmallFile("/proc/loadavg", &buf) orelse return null;
    var toks = std.mem.tokenizeScalar(u8, content, ' ');
    const one = std.fmt.parseFloat(f64, toks.next() orelse return null) catch return null;
    const five = std.fmt.parseFloat(f64, toks.next() orelse return null) catch return null;
    const fifteen = std.fmt.parseFloat(f64, toks.next() orelse return null) catch return null;
    const ratio = toks.next() orelse return null; // "running/total"
    const slash = std.mem.indexOfScalar(u8, ratio, '/') orelse return null;
    const total = std.fmt.parseInt(u64, ratio[slash + 1 ..], 10) catch 0;
    return .{ .one = one, .five = five, .fifteen = fifteen, .total_threads = total };
}

fn readCpu0FreqMhz() u64 {
    var buf: [65536]u8 = undefined;
    const content = readSmallFile("/proc/cpuinfo", &buf) orelse return 0;
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "cpu MHz")) {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const v = std.mem.trim(u8, line[colon + 1 ..], " \t");
            const f = std.fmt.parseFloat(f64, v) catch continue;
            return @intFromFloat(@max(f, 0));
        }
    }
    return 0;
}

// AF_XDP kernel statistics — read-only getsockopt(SOL_XDP, XDP_STATISTICS).
const SOL_XDP = 283;
const XDP_STATISTICS = 7;
const XdpKernelStats = extern struct {
    rx_dropped: u64,
    rx_invalid_descs: u64,
    tx_invalid_descs: u64,
    rx_ring_full: u64,
    rx_fill_ring_empty_descs: u64,
    tx_ring_empty_descs: u64,
};

fn readXdpStats(fd: std.posix.fd_t) ?XdpKernelStats {
    var st: XdpKernelStats = std.mem.zeroes(XdpKernelStats);
    var len: u32 = @sizeOf(XdpKernelStats);
    const rc = std.os.linux.getsockopt(fd, SOL_XDP, XDP_STATISTICS, @ptrCast(&st), &len);
    if (std.os.linux.E.init(rc) != .SUCCESS) return null;
    return st;
}

// ═════════════════════════════════════════════════════════════════════════════
// Reporter
// ═════════════════════════════════════════════════════════════════════════════

pub const FLUSH_INTERVAL_S = 10; // agave MetricsAgent write_frequency

const Reporter = struct {
    allocator: std.mem.Allocator,
    url_z: [:0]const u8, // full write URL WITH password — never logged
    host_id: []const u8,
    version: []const u8,
    cluster_type: i64,
    shred_version: i64,
    waited_for_supermajority: bool,
    boot_elapsed_ms: i64,
    ledger_path: []const u8,
    accounts_path: []const u8,
    snapshots_path: []const u8,
    sample_fn: ?SampleFn,
    sample_ctx: ?*anyopaque,

    batch: Batch = .{},
    point: PointBuf = .{},
    curl: ?CurlWriter = null,
    curl_tried: bool = false,
    last_post_ok: bool = true, // warn only on state CHANGE (no log spam)
    last_flush_instant: i64 = 0,

    // delta state
    have_prev: bool = false,
    prev_udp: UdpStats = .{},
    prev_netdev: NetDevStats = .{},
    prev_disk: DiskStats = .{},

    fn nowNs() u64 {
        const t: i128 = std.time.nanoTimestamp();
        return if (t > 0) @intCast(@min(t, std.math.maxInt(u64))) else 0;
    }

    fn threadMain(self: *Reporter) void {
        std.debug.print("[MR-CK] T:threadMain-entered\n", .{});
        // Lowest priority for THIS thread only (who=0 targets the calling task
        // for the raw setpriority syscall). Never pinned — floats on whatever
        // cores the scheduler picks; the 10 s cadence makes CPU negligible.
        _ = std.os.linux.syscall3(.setpriority, 0, 0, 19); // (PRIO_PROCESS, self, nice 19)

        // Persistent curl handle is created ON this thread so every libcurl call
        // stays single-threaded.
        self.curl = CurlWriter.init(self.url_z.ptr);
        self.curl_tried = true;
        if (self.curl == null) {
            std.log.warn("[METRICS] libcurl unavailable — falling back to /usr/bin/curl subprocess per flush", .{});
        }

        // Boot announce (agave core/src/validator.rs "validator-new").
        self.batch.reset();
        self.point.begin("validator-new", self.host_id);
        self.point.fieldStr("id", self.host_id);
        self.point.fieldStr("version", self.version);
        self.point.fieldI64("cluster_type", self.cluster_type);
        self.point.fieldI64("elapsed_ms", if (self.boot_elapsed_ms != 0) self.boot_elapsed_ms else procAgeMs());
        self.point.fieldBool("waited_for_supermajority", self.waited_for_supermajority);
        self.point.fieldI64("shred_version", self.shred_version);
        self.batch.commit(self.point.end(nowNs()));
        self.flush();

        while (true) {
            // 10 s cadence in 500 ms slices (keeps thread teardown-friendly).
            var slept_ms: u64 = 0;
            while (slept_ms < FLUSH_INTERVAL_S * 1000) : (slept_ms += 500) {
                std.Thread.sleep(500 * std.time.ns_per_ms);
            }
            self.collectAndFlush();
        }
    }

    fn flush(self: *Reporter) void {
        if (self.batch.len == 0) return;
        const status = if (self.curl) |*c|
            c.post(self.batch.body())
        else
            postViaSubprocess(self.allocator, self.url_z, self.batch.body());
        const ok = status >= 200 and status < 300;
        if (ok != self.last_post_ok) {
            if (ok) {
                std.log.warn("[METRICS] submit recovered (HTTP {d})", .{status});
            } else {
                std.log.warn("[METRICS] submit failing (HTTP {d}) — dropping batches until recovery", .{status});
            }
            self.last_post_ok = ok;
        }
        // Success or failure: batch is DROPPED either way (no queue growth).
        self.batch.reset();
    }

    fn collectAndFlush(self: *Reporter) void {
        const ts = nowNs();
        self.batch.reset();

        // ── layer 1: Agave-compatible system points ─────────────────────────
        if (readLoadAvg()) |la| {
            self.point.begin("cpu-stats", self.host_id);
            self.point.fieldU64("cpu_num", std.Thread.getCpuCount() catch 0);
            self.point.fieldU64("cpu0_freq_mhz", readCpu0FreqMhz());
            self.point.fieldF64("average_load_one_minute", la.one);
            self.point.fieldF64("average_load_five_minutes", la.five);
            self.point.fieldF64("average_load_fifteen_minutes", la.fifteen);
            self.point.fieldU64("total_num_threads", la.total_threads);
            self.batch.commit(self.point.end(ts));
        }

        {
            var mbuf: [16384]u8 = undefined;
            if (readSmallFile("/proc/meminfo", &mbuf)) |mi| {
                const kb = 1024;
                const total = (meminfoKb(mi, "MemTotal:") orelse 0) * kb;
                const free = (meminfoKb(mi, "MemFree:") orelse 0) * kb;
                const avail = (meminfoKb(mi, "MemAvailable:") orelse 0) * kb;
                const buffers = (meminfoKb(mi, "Buffers:") orelse 0) * kb;
                const cached = (meminfoKb(mi, "Cached:") orelse 0) * kb;
                const swap_total = (meminfoKb(mi, "SwapTotal:") orelse 0) * kb;
                const swap_free = (meminfoKb(mi, "SwapFree:") orelse 0) * kb;
                if (total > 0) {
                    const pct = struct {
                        fn f(num: u64, den: u64) f64 {
                            if (den == 0) return 0.0;
                            return @as(f64, @floatFromInt(num)) / @as(f64, @floatFromInt(den)) * 100.0;
                        }
                    }.f;
                    self.point.begin("memory-stats", self.host_id);
                    self.point.fieldU64("total", total);
                    self.point.fieldU64("swap_total", swap_total);
                    self.point.fieldU64("buffers_bytes", buffers);
                    self.point.fieldU64("cached_bytes", cached);
                    self.point.fieldF64("free_percent", pct(free, total));
                    self.point.fieldU64("used_bytes", total -| avail);
                    self.point.fieldF64("avail_percent", pct(avail, total));
                    self.point.fieldF64("buffers_percent", pct(buffers, total));
                    self.point.fieldF64("cached_percent", pct(cached, total));
                    self.point.fieldF64("swap_free_percent", pct(swap_free, swap_total));
                    self.batch.commit(self.point.end(ts));
                }
            }
        }

        // net-stats-validator + disk-stats need deltas — emit from the 2nd tick on.
        const udp_now = readUdpStats();
        const netdev_now = readNetDevStats();
        const disk_now = readDiskStats();
        if (self.have_prev) {
            if (udp_now != null and netdev_now != null) {
                const u = udp_now.?;
                const pu = self.prev_udp;
                const n = netdev_now.?;
                const pn = self.prev_netdev;
                self.point.begin("net-stats-validator", self.host_id);
                self.point.fieldU64("in_datagrams_delta", u.in_datagrams -| pu.in_datagrams);
                self.point.fieldU64("no_ports_delta", u.no_ports -| pu.no_ports);
                self.point.fieldU64("in_errors_delta", u.in_errors -| pu.in_errors);
                self.point.fieldU64("out_datagrams_delta", u.out_datagrams -| pu.out_datagrams);
                self.point.fieldU64("rcvbuf_errors_delta", u.rcvbuf_errors -| pu.rcvbuf_errors);
                self.point.fieldU64("sndbuf_errors_delta", u.sndbuf_errors -| pu.sndbuf_errors);
                self.point.fieldU64("in_csum_errors_delta", u.in_csum_errors -| pu.in_csum_errors);
                self.point.fieldU64("ignored_multi_delta", u.ignored_multi -| pu.ignored_multi);
                self.point.fieldU64("in_errors", u.in_errors);
                self.point.fieldU64("rcvbuf_errors", u.rcvbuf_errors);
                self.point.fieldU64("sndbuf_errors", u.sndbuf_errors);
                self.point.fieldU64("rx_bytes_delta", n.rx_bytes -| pn.rx_bytes);
                self.point.fieldU64("rx_packets_delta", n.rx_packets -| pn.rx_packets);
                self.point.fieldU64("rx_errs_delta", n.rx_errs -| pn.rx_errs);
                self.point.fieldU64("rx_drops_delta", n.rx_drops -| pn.rx_drops);
                self.point.fieldU64("rx_fifo_delta", n.rx_fifo -| pn.rx_fifo);
                self.point.fieldU64("rx_frame_delta", n.rx_frame -| pn.rx_frame);
                self.point.fieldU64("tx_bytes_delta", n.tx_bytes -| pn.tx_bytes);
                self.point.fieldU64("tx_packets_delta", n.tx_packets -| pn.tx_packets);
                self.point.fieldU64("tx_errs_delta", n.tx_errs -| pn.tx_errs);
                self.point.fieldU64("tx_drops_delta", n.tx_drops -| pn.tx_drops);
                self.point.fieldU64("tx_fifo_delta", n.tx_fifo -| pn.tx_fifo);
                self.point.fieldU64("tx_colls_delta", n.tx_colls -| pn.tx_colls);
                self.batch.commit(self.point.end(ts));
            }
            if (disk_now) |d| {
                const pd = self.prev_disk;
                self.point.begin("disk-stats", self.host_id);
                self.point.fieldU64("reads_completed", d.reads_completed -| pd.reads_completed);
                self.point.fieldU64("reads_merged", d.reads_merged -| pd.reads_merged);
                self.point.fieldU64("sectors_read", d.sectors_read -| pd.sectors_read);
                self.point.fieldU64("time_reading_ms", d.time_reading_ms -| pd.time_reading_ms);
                self.point.fieldU64("writes_completed", d.writes_completed -| pd.writes_completed);
                self.point.fieldU64("writes_merged", d.writes_merged -| pd.writes_merged);
                self.point.fieldU64("sectors_written", d.sectors_written -| pd.sectors_written);
                self.point.fieldU64("time_writing_ms", d.time_writing_ms -| pd.time_writing_ms);
                self.point.fieldU64("io_in_progress", d.io_in_progress);
                self.point.fieldU64("time_io_ms", d.time_io_ms -| pd.time_io_ms);
                self.point.fieldU64("time_io_weighted_ms", d.time_io_weighted_ms -| pd.time_io_weighted_ms);
                self.point.fieldU64("discards_completed", d.discards_completed -| pd.discards_completed);
                self.point.fieldU64("discards_merged", d.discards_merged -| pd.discards_merged);
                self.point.fieldU64("sectors_discarded", d.sectors_discarded -| pd.sectors_discarded);
                self.point.fieldU64("time_discarding", d.time_discarding -| pd.time_discarding);
                self.point.fieldU64("flushes_completed", d.flushes_completed -| pd.flushes_completed);
                self.point.fieldU64("time_flushing", d.time_flushing -| pd.time_flushing);
                self.point.fieldU64("num_disks", d.num_disks);
                self.batch.commit(self.point.end(ts));
            }
        }
        if (udp_now) |u| self.prev_udp = u;
        if (netdev_now) |n| self.prev_netdev = n;
        if (disk_now) |d| self.prev_disk = d;
        self.have_prev = true;

        // ── validator counters (existing atomics via callback) ──────────────
        var sample = ValidatorSample{};
        if (self.sample_fn) |f| f(self.sample_ctx, &sample);

        if (sample.replay_valid) {
            // layer 1: optimistic_slot (agave optimistic_confirmation_verifier).
            // Vexor tracks no separate optimistic-confirmation stream; the ROOT
            // slot is a conservative lower bound (a rooted slot is by definition
            // optimistically confirmed), keeping the dashboard line honest.
            if (sample.root_slot > 0) {
                self.point.begin("optimistic_slot", self.host_id);
                self.point.fieldU64("slot", sample.root_slot);
                self.batch.commit(self.point.end(ts));
            }

            // layer 2: vexor-replay
            self.point.begin("vexor-replay", self.host_id);
            self.point.fieldU64("shreds_received", sample.shreds_received);
            self.point.fieldU64("invalid_shreds", sample.invalid_shreds);
            self.point.fieldU64("slots_replayed", sample.slots_replayed);
            self.point.fieldU64("successful_txs", sample.successful_txs);
            self.point.fieldU64("failed_txs", sample.failed_txs);
            self.point.fieldU64("votes_sent", sample.votes_sent);
            self.point.fieldU64("blocks_produced", sample.blocks_produced);
            self.point.fieldU64("slot_queue_drops", sample.slot_queue_drops);
            self.point.fieldU64("root_slot", sample.root_slot);
            self.batch.commit(self.point.end(ts));
        }

        if (sample.census_valid) {
            self.point.begin("vexor-vote-census", self.host_id);
            self.point.fieldU64("eligible", sample.census_eligible);
            self.point.fieldU64("cast", sample.census_cast);
            self.point.fieldU64("fallback_decided", sample.census_fallback_decided);
            self.point.fieldU64("fallback_cast", sample.census_fallback_cast);
            self.point.fieldU64("silent_withhold", sample.census_silent_withhold);
            self.batch.commit(self.point.end(ts));
        }

        if (sample.tvu_valid) {
            self.point.begin("vexor-tvu", self.host_id);
            self.point.fieldU64("shreds_received", sample.tvu_shreds_received);
            self.point.fieldU64("shreds_inserted", sample.tvu_shreds_inserted);
            self.point.fieldU64("shreds_duplicate", sample.tvu_shreds_duplicate);
            self.point.fieldU64("shreds_invalid", sample.tvu_shreds_invalid);
            self.point.fieldU64("zc_version_rejects", sample.tvu_zc_version_rejects);
            self.point.fieldU64("repairs_sent", sample.tvu_repairs_sent);
            self.point.fieldU64("repairs_received", sample.tvu_repairs_received);
            self.point.fieldU64("repairs_served", sample.tvu_repairs_served);
            self.point.fieldU64("repair_requests_received", sample.tvu_repair_requests_received);
            self.point.fieldU64("slots_completed", sample.tvu_slots_completed);
            self.point.fieldU64("max_slot_seen", sample.tvu_max_slot_seen);
            self.point.fieldU64("shreds_retransmitted", sample.tvu_shreds_retransmitted);
            self.point.fieldU64("repairs_dropped_ratelimit", sample.tvu_repairs_dropped_ratelimit);
            self.point.fieldU64("rx_shed", sample.tvu_rx_shed);
            self.batch.commit(self.point.end(ts));
        }

        if (sample.afxdp_fd) |fd| {
            if (readXdpStats(fd)) |x| {
                self.point.begin("vexor-afxdp", self.host_id);
                self.point.fieldU64("rx_dropped", x.rx_dropped);
                self.point.fieldU64("rx_invalid_descs", x.rx_invalid_descs);
                self.point.fieldU64("tx_invalid_descs", x.tx_invalid_descs);
                self.point.fieldU64("rx_ring_full", x.rx_ring_full);
                self.point.fieldU64("rx_fill_ring_empty_descs", x.rx_fill_ring_empty_descs);
                self.point.fieldU64("tx_ring_empty_descs", x.tx_ring_empty_descs);
                self.batch.commit(self.point.end(ts));
            }
        }

        // ── layer 2: process + disk-usage of the validator mounts ───────────
        if (readProcSelf()) |p| {
            self.point.begin("vexor-process", self.host_id);
            self.point.fieldU64("rss_bytes", p.rss_bytes);
            self.point.fieldU64("vsize_bytes", p.vsize_bytes);
            self.point.fieldU64("utime_ticks", p.utime_ticks);
            self.point.fieldU64("stime_ticks", p.stime_ticks);
            self.point.fieldU64("num_threads", p.num_threads);
            self.batch.commit(self.point.end(ts));
        }

        const mounts = [_]struct { role: []const u8, path: []const u8 }{
            .{ .role = "ledger", .path = self.ledger_path },
            .{ .role = "accounts", .path = self.accounts_path },
            .{ .role = "snapshots", .path = self.snapshots_path },
        };
        for (mounts) |m| {
            if (m.path.len == 0) continue;
            if (statfsPath(m.path)) |du| {
                self.point.begin("vexor-disk-usage", self.host_id);
                self.point.tag("mount_role", m.role);
                self.point.fieldU64("total_bytes", du.total);
                self.point.fieldU64("avail_bytes", du.avail);
                const used_pct: f64 = if (du.total == 0) 0.0 else @as(f64, @floatFromInt(du.total - @min(du.avail, du.total))) / @as(f64, @floatFromInt(du.total)) * 100.0;
                self.point.fieldF64("used_percent", used_pct);
                self.batch.commit(self.point.end(ts));
            }
        }

        // ── agave "metrics" bookkeeping point (batch stats, end of every batch) ──
        {
            const points_written = self.batch.points + 1; // incl. this point
            const num_points = points_written + self.batch.dropped;
            const now_s = std.time.timestamp();
            const secs: i64 = if (self.last_flush_instant == 0) FLUSH_INTERVAL_S else now_s - self.last_flush_instant;
            self.last_flush_instant = now_s;
            self.point.begin("metrics", self.host_id);
            self.point.fieldU64("points_written", points_written);
            self.point.fieldU64("num_points", num_points);
            self.point.fieldU64("points_lost", self.batch.dropped);
            self.point.fieldU64("points_buffered", 0);
            self.point.fieldI64("secs_since_last_write", secs);
            self.batch.commit(self.point.end(ts));
        }

        self.flush();
    }
};

/// Redact the password for any log output: "host=..,db=..,u=..,p=****".
/// Returns a slice into `out` (KAT'd — never leaks the password).
///
/// Hardened 2026-07-11 alongside `parseConfig` (see its doc comment for the
/// incident #2 background) — no more dependency on the shared generic
/// `std.mem.SplitIterator`; explicit `pos <= raw.len`-bounded scan instead.
/// `raw` here is untrusted-length (this is also the error-path formatter for
/// a config that already failed `parseConfig`, e.g. via `TooLarge`), so this
/// loop must stay correct even when `raw.len` is arbitrarily large — it only
/// ever reads `raw[pos..]` with `pos` monotonically bounded by `raw.len`,
/// independent of anything `parseConfig` decided.
pub fn redactConfigForLog(raw: []const u8, out: []u8) []const u8 {
    var len: usize = 0;
    var pos: usize = 0; // invariant: 0 <= pos <= raw.len at the top of every iteration
    var first = true;
    while (true) {
        const comma = std.mem.indexOfScalarPos(u8, raw, pos, ',') orelse raw.len;
        const pair = raw[pos..comma]; // pos <= comma <= raw.len — always in-bounds
        const piece = if (std.mem.startsWith(u8, pair, "p=")) "p=****" else pair;
        const need = piece.len + @intFromBool(!first);
        if (len + need > out.len) break;
        if (!first) {
            out[len] = ',';
            len += 1;
        }
        @memcpy(out[len..][0..piece.len], piece);
        len += piece.len;
        first = false;
        if (comma >= raw.len) break; // consumed the whole string
        pos = comma + 1; // comma < raw.len here, so pos <= raw.len holds
    }
    return out[0..len];
}

/// Entry point from main.zig. NEVER errors, NEVER crashes the validator:
/// every failure path logs once and returns with metrics disabled.
///
/// Guards (in order):
///   1. offline-replay / golden-gate mode (VEX_LEDGER_REPLAY / VEX_SNAPSHOT_OFFLINE)
///   2. SOLANA_METRICS_CONFIG unset (master switch)
///   3. config parse failure (redacted warn)
pub fn start(allocator: std.mem.Allocator, opts: InitOpts) void {
    std.debug.print("[MR-CK] A:entered\n", .{});
    if (std.posix.getenv("VEX_LEDGER_REPLAY") != null or std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null) {
        std.log.warn("[METRICS] offline-replay mode — metrics reporter NOT started (offline guard)", .{});
        return;
    }
    std.debug.print("[MR-CK] B:guard-passed\n", .{});
    const raw = std.posix.getenv("SOLANA_METRICS_CONFIG") orelse {
        std.log.info("[METRICS] SOLANA_METRICS_CONFIG unset — metrics reporter disabled", .{});
        return;
    };
    std.debug.print("[MR-CK] C:env-read len={d}\n", .{raw.len});
    const cfg = parseConfig(raw) catch |err| {
        var rbuf: [512]u8 = undefined;
        std.log.warn("[METRICS] SOLANA_METRICS_CONFIG invalid ({s}) — metrics disabled: {s}", .{ @errorName(err), redactConfigForLog(raw, &rbuf) });
        return;
    };
    std.debug.print("[MR-CK] D:parsed\n", .{});

    // Everything below allocates once; any failure → disabled, never fatal.
    startInner(allocator, opts, cfg) catch |err| {
        std.log.warn("[METRICS] reporter init failed ({s}) — metrics disabled", .{@errorName(err)});
    };
    std.debug.print("[MR-CK] K:start-returning\n", .{});
}

fn startInner(allocator: std.mem.Allocator, opts: InitOpts, cfg: MetricsConfig) !void {
    std.debug.print("[MR-CK] E:startInner\n", .{});
    const url_z = try buildWriteUrlZ(allocator, cfg);
    std.debug.print("[MR-CK] F:url-built\n", .{});
    const r = try allocator.create(Reporter);
    std.debug.print("[MR-CK] G:created\n", .{});
    r.* = .{
        .allocator = allocator,
        .url_z = url_z,
        .host_id = try allocator.dupe(u8, opts.host_id),
        .version = try allocator.dupe(u8, opts.version),
        .cluster_type = opts.cluster_type,
        .shred_version = opts.shred_version,
        .waited_for_supermajority = opts.waited_for_supermajority,
        .boot_elapsed_ms = opts.boot_elapsed_ms,
        .ledger_path = try allocator.dupe(u8, opts.ledger_path),
        .accounts_path = try allocator.dupe(u8, opts.accounts_path),
        .snapshots_path = try allocator.dupe(u8, opts.snapshots_path),
        .sample_fn = opts.sample_fn,
        .sample_ctx = opts.sample_ctx,
    };
    std.debug.print("[MR-CK] H:duped\n", .{});
    if (!spawnDetachedOrWarn(r)) {
        std.log.warn("[METRICS] reporter thread did not start — metrics disabled", .{});
        return;
    }
    std.log.warn("[METRICS] reporter STARTED — host={s} db={s} u={s} p=**** host_id={s} version={s} interval={d}s", .{ cfg.host, cfg.db, cfg.username, r.host_id, r.version, @as(u64, FLUSH_INTERVAL_S) });
}

/// Spawn the reporter thread (detached, fire-and-forget) WITHOUT letting a
/// pthread_create(3)-level failure crash the validator.
///
/// HARDENING (2026-07-11, incident #2 root cause): `std.Thread.spawn`'s
/// PosixThreadImpl (zig-0.15.2/lib/std/Thread.zig:773-812, this libc-linked
/// build) is:
///
///     switch (c.pthread_create(&handle, &attr, Instance.entryFn, args_ptr)) {
///         .SUCCESS => return Impl{ .handle = handle },
///         .AGAIN => return error.SystemResources,
///         .PERM => unreachable,
///         .INVAL => unreachable,
///         else => |err| return posix.unexpectedErrno(err),
///     }
///
/// i.e. `pthread_create(3)` returning EPERM or EINVAL is a `reached
/// unreachable code` panic (process abort) by std's design — the exact same
/// footgun class as `std.Thread.detach()`'s EINVAL/ESRCH handling that caused
/// incident #1 (see the retired `detachOrWarn` doc, folded into this one).
/// The live-shaped boot-smoke gate (2026-07-11) bisected incident #2 to
/// EXACTLY this call: checkpointed instrumentation showed every step through
/// `allocator.dupe`-ing the Reporter's fields completing, then the panic
/// firing inside the immediately-following thread-spawn — one function over
/// from incident #1's trigger, same std footgun, on a real boot where this is
/// the ~15th-or-so thread spawned in a tight window (verify tiles ×8, ledger
/// tile, watchdog, sysvar-refresh, gossip, turbine, DAG-dispatch, 2
/// parallel-exec workers, vote sender, QUIC-vote poller — all up within the
/// prior second). Fix follows the exact same principle as incident #1: bypass
/// std's unreachable-on-EPERM/EINVAL wrapper, call `pthread_create`/
/// `pthread_detach` directly, and treat ANY non-SUCCESS result from either as
/// "metrics disabled" — never fatal, matching this file's "never crashes the
/// validator" contract. Returns `true` iff the thread is running (and now
/// detached, so its resources release automatically at exit).
fn spawnDetachedOrWarn(r: *Reporter) bool {
    const Trampoline = struct {
        fn run(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
            const reporter: *Reporter = @ptrCast(@alignCast(arg.?));
            Reporter.threadMain(reporter);
            return null;
        }
    };

    var attr: std.c.pthread_attr_t = undefined;
    if (std.c.pthread_attr_init(&attr) != .SUCCESS) {
        std.log.warn("[METRICS] pthread_attr_init() failed — reporter thread not started, non-fatal", .{});
        return false;
    }
    defer _ = std.c.pthread_attr_destroy(&attr);
    // Non-fatal-if-it-fails sizing hints only; a failure here still leaves a
    // usable (default-sized) attr, so no early return on these two.
    _ = std.c.pthread_attr_setstacksize(&attr, 512 * 1024);
    _ = std.c.pthread_attr_setguardsize(&attr, std.heap.pageSize());

    var handle: std.c.pthread_t = undefined;
    var create_rc = std.c.pthread_create(&handle, &attr, Trampoline.run, @ptrCast(r));
    if (create_rc == .INVAL) {
        // Live-env finding (2026-07-11 boot smoke): the sized attr (512K stack +
        // pageSize() guard) is rejected with EINVAL under the production launch
        // env (hugepage-tuned kernel; guard/stack interaction), while default
        // attrs are accepted everywhere. Defaults cannot EINVAL — retry once.
        std.log.warn("[METRICS] pthread_create rejected sized attr (INVAL; stack=512K guard=pageSize) — retrying with default attrs", .{});
        create_rc = std.c.pthread_create(&handle, null, Trampoline.run, @ptrCast(r));
    }
    if (create_rc != .SUCCESS) {
        std.log.warn("[METRICS] reporter thread pthread_create() failed ({s}) — metrics disabled, non-fatal", .{@tagName(create_rc)});
        return false;
    }
    std.debug.print("[MR-CK] I:spawned\n", .{});

    const detach_rc = std.c.pthread_detach(handle);
    if (detach_rc != .SUCCESS) {
        // The thread is already running at this point (create succeeded) —
        // a failed detach just means its small kernel bookkeeping is held
        // until process exit (same outcome as every other still-running
        // thread at exit); the reporter itself is unaffected. Never fatal.
        std.log.warn("[METRICS] reporter thread pthread_detach() failed ({s}) — non-fatal, thread resources held until process exit", .{@tagName(detach_rc)});
    }
    std.debug.print("[MR-CK] J:detached\n", .{});
    return true;
}

// incident #1 (2026-07-10) history: this file used to detach the reporter
// thread via std.Thread.spawn()+a standalone detachOrWarn() wrapper around
// std.c.pthread_detach. That wrapper is retired — incident #2's fix
// (spawnDetachedOrWarn, above) subsumes it: production now creates the
// thread via a raw pthread_create call in the first place, so there is no
// std.Thread value to hand to a separate detach step; the same
// bypass-std's-unreachable-on-failure + never-fatal treatment now covers
// both pthread_create AND pthread_detach in one place. See
// spawnDetachedOrWarn's doc comment for the full incident #1 + #2 history.

// ═════════════════════════════════════════════════════════════════════════════
// KATs — `zig build test-metrics`
// ═════════════════════════════════════════════════════════════════════════════

test "config: valid full parse (deploy.sh shape)" {
    const cfg = try parseConfig("host=https://metrics.solana.com:8086,db=tds,u=testnet_write,p=secretpw");
    try std.testing.expectEqualStrings("https://metrics.solana.com:8086", cfg.host);
    try std.testing.expectEqualStrings("tds", cfg.db);
    try std.testing.expectEqualStrings("testnet_write", cfg.username);
    try std.testing.expectEqualStrings("secretpw", cfg.password);
}

test "config: any key order" {
    const cfg = try parseConfig("p=x,u=y,db=z,host=h");
    try std.testing.expectEqualStrings("h", cfg.host);
    try std.testing.expectEqualStrings("x", cfg.password);
}

test "config: missing key -> Incomplete" {
    try std.testing.expectError(ConfigError.Incomplete, parseConfig("host=h,db=d,u=u"));
    try std.testing.expectError(ConfigError.Incomplete, parseConfig("host=h,db=d,u=u,p="));
}

test "config: corrupt inputs never crash" {
    try std.testing.expectError(ConfigError.Empty, parseConfig(""));
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig("host"));
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig("host=h,db=d,u=u,p=a=b"));
    try std.testing.expectError(ConfigError.UnknownKey, parseConfig("host=h,db=d,u=u,pw=x"));
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig(",,,"));
}

// ═════════════════════════════════════════════════════════════════════════════
// Incident #2 hardening KATs (2026-07-11) — edge shapes the original
// valid/missing/corrupt trio above didn't cover, plus the two new hard caps.
// ═════════════════════════════════════════════════════════════════════════════

test "config: edge shapes never crash (1-char, empty key/value, whitespace, unicode)" {
    // Bare '=' — empty key AND empty value.
    try std.testing.expectError(ConfigError.UnknownKey, parseConfig("="));
    // Empty value, known key.
    try std.testing.expectError(ConfigError.Incomplete, parseConfig("host="));
    // Empty key, '=' present.
    try std.testing.expectError(ConfigError.UnknownKey, parseConfig("=x"));
    // 1-char inputs.
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig("h"));
    try std.testing.expectError(ConfigError.UnknownKey, parseConfig("="));
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig(","));
    // Whitespace-only / embedded whitespace (not a key we know, but must not crash).
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig(" "));
    try std.testing.expectError(ConfigError.UnknownKey, parseConfig("host =h,db=d,u=u,p=p"));
    // Leading/trailing/doubled commas.
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig(",host=h,db=d,u=u,p=p"));
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig("host=h,db=d,u=u,p=p,"));
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig("host=h,,db=d,u=u,p=p"));
    // Non-ASCII / high bytes in the value (must parse fine — value bytes are opaque).
    {
        const cfg = try parseConfig("host=h\xc3\xa9,db=d,u=u,p=p");
        try std.testing.expectEqualStrings("h\xc3\xa9", cfg.host);
    }
    // Embedded NUL byte inside a value — Zig []const u8 permits it; must not crash.
    try std.testing.expect(!std.meta.isError(parseConfig("host=h\x00x,db=d,u=u,p=p")));
}

test "config: oversized input -> TooLarge, never crashes" {
    const big = [_]u8{'a'} ** (MAX_CONFIG_BYTES + 1);
    try std.testing.expectError(ConfigError.TooLarge, parseConfig(&big));
    // Right at the boundary must NOT hit TooLarge (still fails otherwise since it's
    // not a valid config, but must reach real parsing, not the size gate).
    const boundary = [_]u8{'a'} ** MAX_CONFIG_BYTES;
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig(&boundary));
}

test "config: pathological pair count -> bounded, never hangs or crashes" {
    // 4096 single-char pairs separated by commas ("a,a,a,...") — well past
    // MAX_CONFIG_PAIRS, must terminate with an error, not loop/hang/crash.
    var buf: [MAX_CONFIG_BYTES]u8 = undefined;
    var i: usize = 0;
    while (i < buf.len) : (i += 2) {
        buf[i] = 'a';
        if (i + 1 < buf.len) buf[i + 1] = ',';
    }
    try std.testing.expectError(ConfigError.InvalidPair, parseConfig(&buf));
}

test "config: structured mutation sweep — never panics regardless of parse outcome" {
    // Same shape as the real deploy.sh config (dummy password, real field names).
    const base = "host=https://metrics.solana.com:8086,db=tds,u=testnet_write,p=0123456789abcdef0123456789abcdef01234567";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Mutation 1: drop every '=' one at a time.
    {
        var idx: usize = 0;
        while (idx < base.len) : (idx += 1) {
            if (base[idx] != '=') continue;
            const mutated = try a.dupe(u8, base);
            mutated[idx] = 'X';
            _ = parseConfig(mutated) catch {}; // must not panic
        }
    }
    // Mutation 2: drop every ',' one at a time.
    {
        var idx: usize = 0;
        while (idx < base.len) : (idx += 1) {
            if (base[idx] != ',') continue;
            const mutated = try a.dupe(u8, base);
            mutated[idx] = 'X';
            _ = parseConfig(mutated) catch {};
        }
    }
    // Mutation 3: truncate to every possible prefix length (drops keys/values
    // one byte at a time from the tail, including mid-pair truncation).
    {
        var len: usize = 0;
        while (len <= base.len) : (len += 1) {
            _ = parseConfig(base[0..len]) catch {};
        }
    }
    // Mutation 4: delete each single byte (drops one char from any class:
    // letters, digits, '=', ',', ':', '/', '.').
    {
        var idx: usize = 0;
        while (idx < base.len) : (idx += 1) {
            const mutated = try a.alloc(u8, base.len - 1);
            @memcpy(mutated[0..idx], base[0..idx]);
            @memcpy(mutated[idx..], base[idx + 1 ..]);
            _ = parseConfig(mutated) catch {};
        }
    }
    // Mutation 5: insert an extra '=' at every position.
    {
        var idx: usize = 0;
        while (idx <= base.len) : (idx += 1) {
            const mutated = try a.alloc(u8, base.len + 1);
            @memcpy(mutated[0..idx], base[0..idx]);
            mutated[idx] = '=';
            @memcpy(mutated[idx + 1 ..], base[idx..]);
            _ = parseConfig(mutated) catch {};
        }
    }
    // Mutation 6: insert an extra ',' at every position.
    {
        var idx: usize = 0;
        while (idx <= base.len) : (idx += 1) {
            const mutated = try a.alloc(u8, base.len + 1);
            @memcpy(mutated[0..idx], base[0..idx]);
            mutated[idx] = ',';
            @memcpy(mutated[idx + 1 ..], base[idx..]);
            _ = parseConfig(mutated) catch {};
        }
    }
    // Every mutated variant also round-tripped through redactConfigForLog
    // without panicking, whether or not parseConfig accepted it.
    {
        var out: [256]u8 = undefined;
        var idx: usize = 0;
        while (idx < base.len) : (idx += 1) {
            const mutated = try a.dupe(u8, base);
            mutated[idx] = if (mutated[idx] == ',') 'X' else ',';
            _ = redactConfigForLog(mutated, &out);
        }
    }
    // Reaching here means none of the ~350 mutated variants above panicked.
}

test "config: live-shaped repro (incident #2) — real field names, dummy password shape; uses REAL env bytes if present" {
    // The real deploy.sh:1160 config has this EXACT shape: real (non-secret)
    // host/db/u fields, and a 40-char lowercase-hex password. The password
    // itself is a live credential and must never be committed — this dummy
    // is the same length/charset, everything else is the verbatim live value
    // (host/db/u are not secrets).
    const dummy_shaped = "host=https://metrics.solana.com:8086,db=tds,u=testnet_write,p=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    {
        const cfg = try parseConfig(dummy_shaped);
        try std.testing.expectEqualStrings("https://metrics.solana.com:8086", cfg.host);
        try std.testing.expectEqualStrings("tds", cfg.db);
        try std.testing.expectEqualStrings("testnet_write", cfg.username);
        try std.testing.expectEqual(@as(usize, 40), cfg.password.len);
    }
    {
        var out: [256]u8 = undefined;
        const red = redactConfigForLog(dummy_shaped, &out);
        try std.testing.expect(std.mem.indexOf(u8, red, "aaaaaaaa") == null);
        try std.testing.expect(std.mem.indexOf(u8, red, "p=****") != null);
    }

    // If the REAL SOLANA_METRICS_CONFIG is present in the environment at test
    // time (true on this box during a CI-on-this-box run — skip-if-absent
    // everywhere else), exercise the exact live bytes too. This is how the
    // "real production input" class actually gets covered without ever
    // putting the password in source control.
    if (std.posix.getenv("SOLANA_METRICS_CONFIG")) |live| {
        const cfg = parseConfig(live) catch |err| {
            std.debug.print("[KAT] live SOLANA_METRICS_CONFIG parse error: {s}\n", .{@errorName(err)});
            return err;
        };
        try std.testing.expect(cfg.host.len > 0);
        try std.testing.expect(cfg.db.len > 0);
        try std.testing.expect(cfg.username.len > 0);
        try std.testing.expect(cfg.password.len > 0);
        var out: [256]u8 = undefined;
        const red = redactConfigForLog(live, &out);
        try std.testing.expect(std.mem.indexOf(u8, red, cfg.password) == null);
    }
}

test "line protocol: field types + i64 suffix + host_id first tag" {
    var p = PointBuf{};
    p.begin("vexor-test", "MyPubkey111");
    p.tag("mount_role", "ledger");
    p.fieldI64("count", 42);
    p.fieldF64("ratio", 12.5);
    p.fieldBool("armed", true);
    p.fieldStr("version", "vexor-abc");
    const line = p.end(1234567890).?;
    try std.testing.expectEqualStrings(
        "vexor-test,host_id=MyPubkey111,mount_role=ledger count=42i,ratio=12.5,armed=true,version=\"vexor-abc\" 1234567890\n",
        line,
    );
}

test "line protocol: escaping (tag specials + string quotes)" {
    var p = PointBuf{};
    p.begin("m", "id");
    p.tag("t", "a b,c=d");
    p.fieldStr("s", "say \"hi\"");
    const line = p.end(1).?;
    try std.testing.expectEqualStrings("m,host_id=id,t=a\\ b\\,c\\=d s=\"say \\\"hi\\\"\" 1\n", line);
}

test "line protocol: u64 saturates to i64 max" {
    var p = PointBuf{};
    p.begin("m", "id");
    p.fieldU64("v", std.math.maxInt(u64));
    const line = p.end(1).?;
    try std.testing.expectEqualStrings("m,host_id=id v=9223372036854775807i 1\n", line);
}

test "line protocol: zero fields -> null (influx requires a field)" {
    var p = PointBuf{};
    p.begin("m", "id");
    try std.testing.expect(p.end(1) == null);
}

test "batch: point-count cap drops, never grows" {
    var b = Batch{};
    var p = PointBuf{};
    var i: usize = 0;
    while (i < MAX_BATCH_POINTS + 10) : (i += 1) {
        p.begin("m", "id");
        p.fieldU64("v", i);
        b.commit(p.end(1));
    }
    try std.testing.expectEqual(@as(usize, MAX_BATCH_POINTS), b.points);
    try std.testing.expectEqual(@as(usize, 10), b.dropped);
}

test "batch: byte cap enforced" {
    var b = Batch{};
    var p = PointBuf{};
    // Large string field ~1900 bytes per point → byte cap hits before 64-point cap.
    const big = [_]u8{'x'} ** 1900;
    var i: usize = 0;
    while (i < MAX_BATCH_POINTS) : (i += 1) {
        p.begin("m", "id");
        p.fieldStr("s", &big);
        b.commit(p.end(1));
    }
    try std.testing.expect(b.len <= MAX_BATCH_BYTES);
    try std.testing.expect(b.dropped > 0);
    try std.testing.expect(b.points + b.dropped == MAX_BATCH_POINTS);
}

test "point overflow -> dropped, no crash" {
    var b = Batch{};
    var p = PointBuf{};
    p.begin("m", "id");
    const huge = [_]u8{'y'} ** (MAX_POINT_BYTES + 100);
    p.fieldStr("s", &huge);
    try std.testing.expect(p.end(1) == null);
    b.commit(p.end(1));
    try std.testing.expectEqual(@as(usize, 0), b.points);
    try std.testing.expectEqual(@as(usize, 1), b.dropped);
}

test "redaction: password never appears" {
    var out: [256]u8 = undefined;
    const red = redactConfigForLog("host=https://metrics.solana.com:8086,db=tds,u=testnet_write,p=c4fa841aa918bf82", &out);
    try std.testing.expect(std.mem.indexOf(u8, red, "c4fa841aa918bf82") == null);
    try std.testing.expect(std.mem.indexOf(u8, red, "p=****") != null);
    try std.testing.expect(std.mem.indexOf(u8, red, "host=https://metrics.solana.com:8086") != null);
}

test "url shape matches agave build_write_url" {
    var buf: [256]u8 = undefined;
    const cfg = try parseConfig("host=http://h:8086,db=tds,u=user,p=pw");
    const url = try std.fmt.bufPrint(&buf, "{s}/write?db={s}&u={s}&p={s}&precision=n", .{ cfg.host, cfg.db, cfg.username, cfg.password });
    try std.testing.expectEqualStrings("http://h:8086/write?db=tds&u=user&p=pw&precision=n", url);
}

// ═════════════════════════════════════════════════════════════════════════════
// Spawn-path regression KATs (2026-07-10 incident #1, 2026-07-11 incident #2)
// — the class of bug the config/line-protocol/batch KATs above cannot catch:
// everything above tests pure functions. `start()`'s actual thread spawn
// never ran under golden/offline gates (the VEX_LEDGER_REPLAY/
// VEX_SNAPSHOT_OFFLINE guard at the top of `start()` always short-circuits it
// there) and the live-204 KAT exercised the InfluxDB writer directly, not the
// boot path — so the spawn call in `startInner()` first ever executed on a
// live boot, TWICE: incident #1 hit std.Thread's unreachable
// pthread_detach() failure branch; incident #2 (root-caused via the
// live-shaped boot-smoke gate, not reproducible in isolation — see
// `spawnDetachedOrWarn`'s doc comment) hit the sibling unreachable
// pthread_create() failure branch. Both are now bypassed by
// `spawnDetachedOrWarn`. This KAT drives the REAL public entry point
// (`start()`) end to end: env-parsed config → real `spawnDetachedOrWarn` →
// the spawned thread runs its real threadMain() boot-announce + first
// flush(), through the real dlopen(libcurl)/curl_easy_perform() path. No
// mocks, no test-only seam in the production code.
//
// No real network: the write host is 10.255.255.1 (RFC 5737-adjacent
// unrouted block on this host — confirmed locally: connect fails in ~1-6ms,
// ENETUNREACH/no-route, not a multi-second timeout), so flush() fails fast
// and deterministically offline, same as any other KAT.
// ═════════════════════════════════════════════════════════════════════════════

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "spawn path: start() spawns+detaches the reporter thread and survives (regression: pthread_detach + pthread_create unreachable panics)" {
    // Force past the offline guard regardless of ambient test-runner env —
    // this KAT's entire point is to exercise the path that guard normally
    // skips.
    _ = unsetenv("VEX_LEDGER_REPLAY");
    _ = unsetenv("VEX_SNAPSHOT_OFFLINE");
    _ = setenv("SOLANA_METRICS_CONFIG", "host=http://10.255.255.1:1,db=kat,u=kat,p=kat", 1);
    defer _ = unsetenv("SOLANA_METRICS_CONFIG");

    // std.testing.allocator's leak checker would false-positive here: the
    // Reporter + its duped strings are intentionally never freed (fire-and-
    // forget, process-lifetime thread, exactly like production's
    // std.heap.c_allocator call site in main.zig). Use the same allocator
    // production uses.
    start(std.heap.c_allocator, .{
        .host_id = "KatTestHostId1111111111111111111111111111",
        .version = "vexor-kat-spawn-test",
        .cluster_type = 0,
        .shred_version = 0,
        .waited_for_supermajority = false,
        .ledger_path = "",
        .accounts_path = "",
        .snapshots_path = "",
        .sample_fn = null,
    });

    // Reaching here at all proves spawnDetachedOrWarn() (both incident #1's
    // and incident #2's exact crash sites) survived. Sleep briefly so the
    // detached thread's boot-announce flush() (blackhole connect fails in
    // single-digit ms) has actually run at least once, exercising the real
    // dlopen/curl call chain too — not just the spawn/detach instant.
    std.Thread.sleep(100 * std.time.ns_per_ms);
}

test "spawnDetachedOrWarn: rapid repeated spawn+detach cycles under concurrent thread churn, never panics" {
    // Incident #2 reproduced only on a live boot with ~15 other threads
    // spawned in the preceding second (verify tiles, ledger tile, watchdog,
    // gossip, turbine, DAG-dispatch, parallel-exec workers, vote sender, QUIC
    // poller). Approximate that churn here: many concurrent background
    // threads racing pthread_create/pthread_detach while spawnDetachedOrWarn
    // runs repeatedly. This does not need to reproduce incident #2's exact
    // trigger (unconfirmed, see the doc comment) — it exists so that IF this
    // host/kernel/glibc combination can produce a non-SUCCESS pthread_create
    // or pthread_detach under load, the KAT hits it here, offline, instead of
    // on a live boot.
    var stop = std.atomic.Value(bool).init(false);
    const Churn = struct {
        fn run(s: *std.atomic.Value(bool)) void {
            while (!s.load(.acquire)) {
                const t = std.Thread.spawn(.{}, struct {
                    fn f() void {}
                }.f, .{}) catch continue;
                t.detach();
            }
        }
    };
    var bg: [16]std.Thread = undefined;
    for (&bg) |*t| t.* = try std.Thread.spawn(.{}, Churn.run, .{&stop});
    defer {
        stop.store(true, .release);
        for (bg) |t| t.join();
    }

    // Deliberately leaked (fire-and-forget, matches production's
    // std.heap.c_allocator call site in main.zig) — the point is exercising
    // spawnDetachedOrWarn under load, not memory accounting, so this uses
    // c_allocator (not std.testing.allocator) to avoid a false-positive leak
    // report.
    const gpa = std.heap.c_allocator;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const r = try gpa.create(Reporter);
        r.* = .{
            .allocator = gpa,
            .url_z = try gpa.dupeZ(u8, "http://10.255.255.1:1/write?db=x&u=x&p=x&precision=n"),
            .host_id = try gpa.dupe(u8, "KatChurnHost"),
            .version = try gpa.dupe(u8, "kat-churn"),
            .cluster_type = 0,
            .shred_version = 0,
            .waited_for_supermajority = false,
            .boot_elapsed_ms = 0,
            .ledger_path = "",
            .accounts_path = "",
            .snapshots_path = "",
            .sample_fn = null,
            .sample_ctx = null,
        };
        _ = spawnDetachedOrWarn(r);
    }
}
