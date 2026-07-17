//! vex_bpf2.trace — Wave 3.5 module-boundary trace layer.
//!
//! Replaces the per-module `traceEmit` / `trace` shims in M6 (syscalls),
//! M7 (cpi), and M9 (builtins) with a single global level-filtered emitter
//! plus a small fixed-size ring buffer that downstream tooling (selfTest
//! dashboard, CLI dump) can drain.
//!
//! ── Public surface ─────────────────────────────────────────────────────────
//!
//!   • Level{ off, on_error, verbose }      — global filter, lock-free read.
//!   • setLevel(level) / level()            — runtime control.
//!   • span(module, fn_name, tx, fmt, args) — structured entry; pair with close().
//!   • Span.close(result_str)               — emit exit line; on_error filter
//!                                            only logs if `result_str`
//!                                            starts with `error.`.
//!   • errorEvent(...)                      — always logs at on_error+ regardless.
//!   • drainTo(writer)                      — pour ring buffer into a writer.
//!   • reset()                              — clear state (test-only convenience).
//!   • emitRaw(fmt, args)                   — legacy seam for the per-module
//!                                            inline shims; respects
//!                                            off/verbose only (no on_error
//!                                            filter possible without a
//!                                            paired result).
//!
//! ── Format invariant ───────────────────────────────────────────────────────
//!
//! All emitted lines start with `[VBPF2-TRACE]` to match the format that the
//! M6/M7/M9 shims used pre-Wave 3.5. This is byte-for-byte preserved so log
//! scrapers and existing greps continue to work.
//!
//! ── Cost model ─────────────────────────────────────────────────────────────
//!
//! At Level.off:
//!   • span()        — single atomic load + early return. No formatting.
//!   • errorEvent()  — single atomic load + early return.
//!   • emitRaw()     — single atomic load + early return.
//!   • Span.close()  — short-circuits on the stub's empty module string.
//!
//! At Level.on_error:
//!   • span()        — formats args into the ring buffer (no log emission yet).
//!   • Span.close()  — emits both entry+exit ONLY if result_str begins with
//!                     `error.` (the convention `@errorName` produces).
//!   • errorEvent()  — always emits.
//!
//! At Level.verbose:
//!   • span()        — formats AND emits the entry line.
//!   • Span.close()  — always emits the exit line.
//!
//! ── Concurrency ────────────────────────────────────────────────────────────
//!
//! The level field is a lock-free `std.atomic.Value(u8)`. The ring buffer is
//! protected by a mutex; emit and drain serialize against each other. This is
//! the safe-and-simple choice — single-producer lock-free was an option but
//! span() + close() can interleave from different producers in CPI recursion,
//! so a mutex is the correct primitive.
//!
//! ── Integration ────────────────────────────────────────────────────────────
//!
//! M6/M7/M9 keep their existing inline shim functions as thin forwarders
//! into `emitRaw`. The body of each shim is the only thing that changes.
//! Call sites (~93 in total: M6=67, M7=20+, M9=6) are NOT touched, which
//! keeps format regression risk to zero.

const std = @import("std");

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

pub const Level = enum(u8) {
    off = 0,
    on_error = 1,
    verbose = 2,
};

pub const TraceError = error{BufferFull};

/// Global level. Default `on_error` (legacy + new sites both quiet unless an
/// error flows through a Span).
var g_level: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(Level.on_error));

pub fn setLevel(lvl: Level) void {
    g_level.store(@intFromEnum(lvl), .seq_cst);
}

pub fn level() Level {
    return @enumFromInt(g_level.load(.seq_cst));
}

inline fn levelAtLeast(min: Level) bool {
    return g_level.load(.acquire) >= @intFromEnum(min);
}

inline fn levelIsOff() bool {
    return g_level.load(.acquire) == @intFromEnum(Level.off);
}

// ── Log sink (overridable for tests) ──────────────────────────────────────
//
// Production routes emissions through `std.log.scoped(.vbpf2_trace).err` so
// the existing log infrastructure (rotation, filtering by scope) keeps
// working. Tests override the sink to a silent capture so the Zig test
// runner does not flag legitimate trace output as a failure.

pub const SinkFn = *const fn (line: []const u8) void;

fn defaultSink(line: []const u8) void {
    std.log.scoped(.vbpf2_trace).err("{s}", .{line});
}

fn silentSink(_: []const u8) void {}

var g_sink: SinkFn = defaultSink;

/// Override the log sink. Tests use `silentSinkFn()` to suppress emission
/// to stderr while still exercising the formatting + ring-buffer paths.
pub fn setSink(fn_: SinkFn) void {
    g_sink = fn_;
}

pub fn defaultSinkFn() SinkFn {
    return defaultSink;
}

pub fn silentSinkFn() SinkFn {
    return silentSink;
}

inline fn sinkLog(line: []const u8) void {
    g_sink(line);
}

// Format the first 8 bytes of a tx-signature as 16 hex characters. Avoids
// reliance on `std.fmt.fmtSliceHexLower` (not exported in Zig 0.15.2 stdlib).
fn writeTxHex8(out: []u8, tx_sig: [64]u8) usize {
    if (out.len < 16) return 0;
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        out[i * 2] = hex[(tx_sig[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[tx_sig[i] & 0xf];
    }
    return 16;
}

// ──────────────────────────────────────────────────────────────────────────────
// Ring buffer — fixed 4 KiB, fixed-size records.
// ──────────────────────────────────────────────────────────────────────────────

pub const RECORD_BYTES: usize = 256;
pub const RING_RECORDS: usize = 16; // 16 * 256 = 4096

const Record = struct {
    used: usize, // bytes valid in `bytes`
    bytes: [RECORD_BYTES]u8,
};

var g_ring_mtx: std.Thread.Mutex = .{};
var g_ring: [RING_RECORDS]Record = undefined;
var g_ring_head: usize = 0; // next write slot
var g_ring_count: usize = 0; // how many slots populated (caps at RING_RECORDS)
var g_ring_initialised: bool = false;

fn ensureRingInitialised() void {
    if (g_ring_initialised) return;
    for (&g_ring) |*rec| {
        rec.used = 0;
    }
    g_ring_initialised = true;
}

fn pushRecord(slice: []const u8) void {
    g_ring_mtx.lock();
    defer g_ring_mtx.unlock();
    ensureRingInitialised();
    var rec = &g_ring[g_ring_head];
    const n = @min(slice.len, RECORD_BYTES);
    @memcpy(rec.bytes[0..n], slice[0..n]);
    rec.used = n;
    g_ring_head = (g_ring_head + 1) % RING_RECORDS;
    if (g_ring_count < RING_RECORDS) g_ring_count += 1;
}

/// Drain all records to `writer` in chronological order. Does NOT clear.
pub fn drainTo(writer: anytype) !usize {
    g_ring_mtx.lock();
    defer g_ring_mtx.unlock();
    ensureRingInitialised();
    if (g_ring_count == 0) return 0;
    var emitted: usize = 0;
    // Records are oldest-first starting at (head - count) mod RING_RECORDS.
    const start = (g_ring_head + RING_RECORDS - g_ring_count) % RING_RECORDS;
    var i: usize = 0;
    while (i < g_ring_count) : (i += 1) {
        const idx = (start + i) % RING_RECORDS;
        const rec = &g_ring[idx];
        if (rec.used == 0) continue;
        try writer.writeAll(rec.bytes[0..rec.used]);
        try writer.writeAll("\n");
        emitted += 1;
    }
    return emitted;
}

/// Reset the global state — INTENDED FOR TESTS ONLY.
pub fn reset() void {
    g_ring_mtx.lock();
    defer g_ring_mtx.unlock();
    g_ring_head = 0;
    g_ring_count = 0;
    for (&g_ring) |*rec| rec.used = 0;
    g_ring_initialised = true;
    g_level.store(@intFromEnum(Level.on_error), .seq_cst);
}

// ──────────────────────────────────────────────────────────────────────────────
// Span — paired entry/exit with on_error filtering.
// ──────────────────────────────────────────────────────────────────────────────

pub const Span = struct {
    module: []const u8,
    fn_name: []const u8,
    tx_sig: [64]u8,
    /// Fully formatted entry line (including `[VBPF2-TRACE]` prefix).
    /// Empty when the span is a zero-cost stub (Level.off path).
    entry_buf: [RECORD_BYTES]u8 = undefined,
    entry_len: usize = 0,

    pub fn close(self: *Span, result_str: []const u8) void {
        if (self.entry_len == 0) return; // off-path stub.
        const lvl = level();
        const is_error = std.mem.startsWith(u8, result_str, "error.");
        const should_emit = switch (lvl) {
            .off => false,
            .on_error => is_error,
            .verbose => true,
        };
        if (!should_emit) return;
        // At verbose, span() already emitted+pushed the entry. At on_error
        // the entry was formatted but never emitted; emit it now alongside
        // the exit so the pair is contiguous in the log/ring.
        if (lvl != .verbose) {
            sinkLog(self.entry_buf[0..self.entry_len]);
            pushRecord(self.entry_buf[0..self.entry_len]);
        }
        // Emit exit line.
        var exit_buf: [RECORD_BYTES]u8 = undefined;
        const exit_w = std.fmt.bufPrint(
            &exit_buf,
            "[VBPF2-TRACE] {s}.{s} -> {s}",
            .{ self.module, self.fn_name, result_str },
        ) catch exit_buf[0..0];
        sinkLog(exit_w);
        pushRecord(exit_w);
    }
};

/// Open a structured span. Caller MUST close() it.
///
/// At Level.off this returns a zero-cost stub (entry_len = 0); close() then
/// short-circuits and emits nothing. At on_error the entry line is formatted
/// into a stack-resident buffer but not emitted until close() sees an error.
/// At verbose the entry is emitted immediately AND remembered so the exit
/// line cites the matching invocation context.
pub fn span(
    module: []const u8,
    fn_name: []const u8,
    tx_sig: [64]u8,
    comptime args_fmt: []const u8,
    args: anytype,
) Span {
    if (levelIsOff()) {
        return .{ .module = module, .fn_name = fn_name, .tx_sig = tx_sig, .entry_len = 0 };
    }
    var s: Span = .{ .module = module, .fn_name = fn_name, .tx_sig = tx_sig };
    // Format `[VBPF2-TRACE] tx=<hex16> <module>.<fn>(<args>)` into entry_buf
    // in passes to avoid tuple concatenation and to sidestep stdlib hex helpers.
    var hex_buf: [16]u8 = undefined;
    _ = writeTxHex8(&hex_buf, tx_sig);
    const prefix = std.fmt.bufPrint(
        &s.entry_buf,
        "[VBPF2-TRACE] tx={s} {s}.{s}(",
        .{ hex_buf[0..16], module, fn_name },
    ) catch s.entry_buf[0..0];
    var len: usize = prefix.len;
    if (len < s.entry_buf.len) {
        const rest = std.fmt.bufPrint(s.entry_buf[len..], args_fmt, args) catch s.entry_buf[len..len];
        len += rest.len;
    }
    if (len < s.entry_buf.len) {
        s.entry_buf[len] = ')';
        len += 1;
    }
    s.entry_len = len;
    if (level() == .verbose) {
        sinkLog(s.entry_buf[0..s.entry_len]);
        pushRecord(s.entry_buf[0..s.entry_len]);
    }
    return s;
}

/// Always-on error event (logs at on_error+, ignored at off). This is the
/// path that error returns at module boundaries should call directly when
/// they are not paired with a Span.
pub fn errorEvent(
    module: []const u8,
    fn_name: []const u8,
    tx_sig: [64]u8,
    err: anytype,
    comptime kwargs_fmt: []const u8,
    kwargs: anytype,
) void {
    if (levelIsOff()) return;
    var buf: [RECORD_BYTES]u8 = undefined;
    var hex_buf: [16]u8 = undefined;
    _ = writeTxHex8(&hex_buf, tx_sig);
    const prefix = std.fmt.bufPrint(
        &buf,
        "[VBPF2-TRACE] tx={s} {s}.{s} ERR={s} (",
        .{ hex_buf[0..16], module, fn_name, @errorName(err) },
    ) catch buf[0..0];
    var len: usize = prefix.len;
    if (len < buf.len) {
        const rest = std.fmt.bufPrint(buf[len..], kwargs_fmt, kwargs) catch buf[len..len];
        len += rest.len;
    }
    if (len < buf.len) {
        buf[len] = ')';
        len += 1;
    }
    sinkLog(buf[0..len]);
    pushRecord(buf[0..len]);
}

// ──────────────────────────────────────────────────────────────────────────────
// Legacy shim seam — used by M6/M7/M9 inline shims that weren't migrated to
// the Span API. Respects off/verbose. on_error is treated as silent for these
// (no result-string available to filter on).
// ──────────────────────────────────────────────────────────────────────────────

pub fn emitRaw(comptime fmt: []const u8, args: anytype) void {
    const lvl = level();
    if (lvl == .off) return;
    if (lvl == .on_error) return; // silent at on_error for unpaired emits.
    var buf: [RECORD_BYTES]u8 = undefined;
    const w = std.fmt.bufPrint(&buf, fmt, args) catch buf[0..0];
    sinkLog(w);
    pushRecord(w);
}

/// Force-log path (for the rare case where an unpaired emit MUST land at
/// on_error+ — e.g. SOL_LOG output that programs invoke deterministically).
/// Use sparingly; prefer Span + close() for error filtering.
pub fn emitRawForce(comptime fmt: []const u8, args: anytype) void {
    if (levelIsOff()) return;
    var buf: [RECORD_BYTES]u8 = undefined;
    const w = std.fmt.bufPrint(&buf, fmt, args) catch buf[0..0];
    sinkLog(w);
    pushRecord(w);
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

// Minimal in-memory writer for tests — captures every byte written.
// Avoids std.io.Writer churn between Zig versions.
const TestWriter = struct {
    buf: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,

    pub fn writeAll(self: TestWriter, bytes: []const u8) !void {
        try self.buf.appendSlice(self.gpa, bytes);
    }
};

fn testInit() void {
    reset();
    setSink(silentSinkFn());
}

test "level set/get round-trips" {
    testInit();
    reset();
    try std.testing.expectEqual(Level.on_error, level());
    setLevel(.off);
    try std.testing.expectEqual(Level.off, level());
    setLevel(.verbose);
    try std.testing.expectEqual(Level.verbose, level());
    reset();
}

test "off path is zero-emit" {
    testInit();
    reset();
    setLevel(.off);
    var sp = span("M6", "noop", [_]u8{0} ** 64, "x={d}", .{42});
    sp.close("ok");
    errorEvent("M6", "noop", [_]u8{0} ** 64, error.M6_AccessViolation, "y={d}", .{1});
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    const tw: TestWriter = .{ .buf = &buf, .gpa = std.testing.allocator };
    const n = try drainTo(tw);
    try std.testing.expectEqual(@as(usize, 0), n);
    reset();
}

test "on_error filter only logs error closes" {
    testInit();
    reset();
    setLevel(.on_error);
    var sp_ok = span("M7", "ok_fn", [_]u8{0} ** 64, "", .{});
    sp_ok.close("ok"); // should NOT emit
    var sp_err = span("M7", "err_fn", [_]u8{0} ** 64, "", .{});
    sp_err.close("error.M7_AccessViolation"); // SHOULD emit (entry+exit)
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    const tw: TestWriter = .{ .buf = &buf, .gpa = std.testing.allocator };
    const n = try drainTo(tw);
    // Only the error close pair: entry line + exit line = 2 records.
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "err_fn") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "ok_fn") == null);
    reset();
}

test "errorEvent always logs at on_error" {
    testInit();
    reset();
    setLevel(.on_error);
    errorEvent("M6", "syscall_x", [_]u8{0xab} ** 64, error.M6_InvalidArgument, "r1={x}", .{0xdead});
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    const tw: TestWriter = .{ .buf = &buf, .gpa = std.testing.allocator };
    const n = try drainTo(tw);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "M6_InvalidArgument") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "syscall_x") != null);
    reset();
}

test "verbose emits both entry and exit" {
    testInit();
    reset();
    setLevel(.verbose);
    var sp = span("M9", "system.execute", [_]u8{0} ** 64, "variant={s}", .{"transfer"});
    sp.close("ok");
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    const tw: TestWriter = .{ .buf = &buf, .gpa = std.testing.allocator };
    const n = try drainTo(tw);
    try std.testing.expectEqual(@as(usize, 2), n);
    reset();
}

test "ring buffer wraps at RING_RECORDS" {
    testInit();
    reset();
    setLevel(.verbose);
    // Push more than RING_RECORDS records.
    var i: usize = 0;
    while (i < RING_RECORDS * 3) : (i += 1) {
        emitRaw("[VBPF2-TRACE] test record #{d}", .{i});
    }
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    const tw: TestWriter = .{ .buf = &buf, .gpa = std.testing.allocator };
    const n = try drainTo(tw);
    // Wrapped — exactly RING_RECORDS retained.
    try std.testing.expectEqual(RING_RECORDS, n);
    // The OLDEST retained record is i = (3*RING_RECORDS - RING_RECORDS) = 2*RING_RECORDS.
    const oldest_marker = std.fmt.comptimePrint("test record #{d}", .{RING_RECORDS * 2});
    try std.testing.expect(std.mem.indexOf(u8, buf.items, oldest_marker) != null);
    reset();
}

test "emitRaw silent at on_error (unpaired)" {
    testInit();
    reset();
    setLevel(.on_error);
    emitRaw("[VBPF2-TRACE] M7.foo -> bar", .{});
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    const tw: TestWriter = .{ .buf = &buf, .gpa = std.testing.allocator };
    const n = try drainTo(tw);
    try std.testing.expectEqual(@as(usize, 0), n);
    reset();
}

test "emitRawForce logs at on_error" {
    testInit();
    reset();
    setLevel(.on_error);
    emitRawForce("[VBPF2-PROGRAM-LOG] hello", .{});
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    const tw: TestWriter = .{ .buf = &buf, .gpa = std.testing.allocator };
    const n = try drainTo(tw);
    try std.testing.expectEqual(@as(usize, 1), n);
    reset();
}
