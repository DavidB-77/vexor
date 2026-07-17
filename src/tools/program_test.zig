//! program_test.zig — `vexor-program-test`, a standalone LiteSVM-class harness.
//!
//! M1 (2026-07-12): load a Solana program `.so`, execute ONE instruction against
//! caller-supplied account snapshots inside Vexor's OWN sBPF VM, and report
//! `{ return-code r0, consumed CU, per-account post-state, program logs }`.
//!
//! The execution engine is 100% reused, UNMODIFIED: this file is pure glue over
//! `vex_svm.v2_dispatch.v2DispatchBpfProgramMetered` — the Bank-free /
//! AccountsDb-free, value-in/value-out orchestrator that already runs the full
//! ELF-load → verify → serialize → memory-map → interpreter → writeback →
//! CU-report pipeline (see VEXOR-PROGRAM-TEST-HARNESS-DESIGN-2026-07-12.md).
//!
//! Rooted OUTSIDE `vex_svm` and imports it as an opaque module (the
//! `cpi_carrier_dispatch_test.zig` pattern) to dodge the vex_svm ⇄ replay_stage
//! module cycle.
//!
//! Signature-churn isolation (design risk #1): every call into the engine goes
//! through `runProgramTest` below, the ONE harness-owned adapter. When the
//! dispatch signature drifts, only this function changes.
//!
//! Run:  zig build vexor-program-test         (build the CLI exe)
//!       zig build test-program-test          (run the hello-fixture KAT)

const std = @import("std");
const vex_svm = @import("vex_svm");
const vex_bpf2 = @import("vex_bpf2");
const core = @import("core");

const v2 = vex_svm.v2_dispatch;
const AccountSnapshot = v2.AccountSnapshot;
const AccountMutation = v2.AccountMutation;
const SysvarCache = vex_bpf2.sysvar_cache.SysvarCache;
const V2ProgramCache = vex_bpf2.v2_program_cache.V2ProgramCache;
const trace = vex_bpf2.trace;

// Cut the engine's high-volume std.log.warn probes (PR5AF-MODE-PROBE etc.) from
// the CLI's stderr — program logs travel a SEPARATE channel (the trace sink,
// captured below), so this does not lose any program output.
pub const std_options: std.Options = .{ .log_level = .err };

// Solana compute-budget defaults (Agave execution_budget.rs).
pub const DEFAULT_COMPUTE_BUDGET: u64 = 1_400_000;
const MIN_HEAP_FRAME_BYTES: u32 = 32 * 1024; // free heap baseline (no RequestHeapFrame)
const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024; // VM heap REGION size (matches production caller)

// ── Program-log capture ─────────────────────────────────────────────────────
//
// `sol_log_` routes program output through `trace.emitRaw("[VBPF2-PROGRAM-LOG]
// {s}", ...)`. We raise the trace level to `.verbose` and install a capture
// sink that collects the program-log lines. Single-threaded harness → a plain
// global buffer is safe.

const LOG_PREFIX = "[VBPF2-PROGRAM-LOG] ";
var g_log_alloc: ?std.mem.Allocator = null;
var g_log_lines: std.ArrayListUnmanaged([]u8) = .{};
var g_log_oom: bool = false;

fn captureSink(line: []const u8) void {
    const alloc = g_log_alloc orelse return;
    if (!std.mem.startsWith(u8, line, LOG_PREFIX)) return; // only program logs
    const msg = line[LOG_PREFIX.len..];
    const dup = alloc.dupe(u8, msg) catch {
        g_log_oom = true;
        return;
    };
    g_log_lines.append(alloc, dup) catch {
        alloc.free(dup);
        g_log_oom = true;
    };
}

// ── Result type ─────────────────────────────────────────────────────────────

pub const ProgramTestResult = struct {
    /// r0 on success/revert; undefined when `dispatch_error != null`.
    return_code: u64,
    /// Vexor's measured consumption. NOTE (design risk #4): on ANY failure
    /// (`dispatch_error != null` or a program revert `return_code != 0`) the
    /// engine reports the FULL `compute_budget`, not the true partial burn —
    /// `cu_is_full_budget` flags this so the CLI can caveat it.
    consumed_cu: u64,
    cu_is_full_budget: bool,
    /// `null` = the program ran to EXIT; else the DispatchError name.
    dispatch_error: ?[]const u8,
    /// Detected sBPF version of the loaded ELF (for reporting).
    sbpf_version: []const u8,
    /// Post-state, one per input account (empty when dispatch failed).
    mutations: []AccountMutation,
    /// Captured `sol_log_` program output lines.
    logs: [][]u8,

    alloc: std.mem.Allocator,

    pub fn success(self: *const ProgramTestResult) bool {
        return self.dispatch_error == null and self.return_code == 0;
    }

    pub fn deinit(self: *ProgramTestResult) void {
        for (self.mutations) |*m| self.alloc.free(m.data);
        self.alloc.free(self.mutations);
        for (self.logs) |l| self.alloc.free(l);
        self.alloc.free(self.logs);
    }
};

pub const ProgramTestOptions = struct {
    program_id: [32]u8,
    elf_bytes: []const u8,
    ix_data: []const u8 = &.{},
    accounts: []const AccountSnapshot = &.{},
    compute_budget: u64 = DEFAULT_COMPUTE_BUDGET,
    slot: u64 = 0,
};

// ── The single adapter over the engine (signature-churn firewall) ────────────

/// Drive one instruction through the UNMODIFIED Vexor sBPF engine.
///
/// Feature set = `.{}` (design M1): all SIMD gates evaluate false, i.e.
/// pre-activation / MODE-1 (flat serialization, no VASA/direct-mapping). This
/// is the deliberate documented M1 choice — feature-set currency for live
/// testnet-accurate semantics is a later milestone (design risk #2). The heap
/// REGION is sized to the production 256 KiB; the CU heap-entry charge uses the
/// MIN (32 KiB) request, i.e. a tx that issued no RequestHeapFrame → 0 extra CU.
pub fn runProgramTest(alloc: std.mem.Allocator, opts: ProgramTestOptions) !ProgramTestResult {
    // Local (non-process-global) program cache — avoids the shared-cache
    // collisions the KATs warn about.
    var cache = V2ProgramCache.init(alloc);
    defer cache.deinit();

    // Load + verify + publish the executable into our cache. Mirrors the
    // engine's own load path (v2_dispatch.zig:1051-1071). The dispatch below
    // then hits `getFresh` and reuses this entry.
    const exe = try cache.allocator.create(vex_bpf2.elf.Executable);
    exe.* = vex_bpf2.elf.Executable.load(cache.allocator, opts.elf_bytes, vex_bpf2.elf.Config.DEFAULT) catch |e| {
        cache.allocator.destroy(exe);
        return e;
    };
    vex_bpf2.verifier.verify(
        exe.textBytes(),
        exe.version(),
        vex_bpf2.verifier.VerifyConfig.DEFAULT,
        &exe.function_registry,
    ) catch |e| {
        exe.deinit();
        cache.allocator.destroy(exe);
        return e;
    };
    const sbpf_version = @tagName(exe.version());
    try cache.put(opts.program_id, exe, opts.slot, 0);

    // Sane default sysvars (Rent/Clock/EpochSchedule/EpochRewards/LastRestartSlot).
    var sysvars = SysvarCache.init(alloc);
    defer sysvars.deinit();
    try sysvars.populateTestnetDefaults();

    // Install the program-log capture sink for the duration of the run.
    g_log_alloc = alloc;
    g_log_lines = .{};
    g_log_oom = false;
    const prev_level = trace.level();
    const prev_sink = trace.defaultSinkFn();
    trace.setSink(captureSink);
    trace.setLevel(.verbose);
    defer {
        trace.setSink(prev_sink);
        trace.setLevel(prev_level);
        g_log_alloc = null;
    }

    // Match production routing (harmless for the direct metered call).
    vex_bpf2.dispatch_mode.setMode(.v2);

    var consumed_cu: u64 = 0;
    var dispatch_error: ?[]const u8 = null;

    const muts: []AccountMutation = v2.v2DispatchBpfProgramMetered(
        alloc,
        &opts.program_id,
        opts.ix_data,
        opts.accounts,
        opts.elf_bytes,
        0, // programdata_slot=0 → legacy (non-upgradeable) lookup
        &sysvars,
        &cache,
        .{}, // feature_set: M1 pre-activation (all gates false)
        opts.compute_budget,
        opts.slot,
        MAX_HEAP_FRAME_BYTES, // heap REGION size
        MIN_HEAP_FRAME_BYTES, // requested heap for CU charge (no RequestHeapFrame)
        &.{}, // cpi_extras: none in M1
        &consumed_cu,
    ) catch |e| blk: {
        dispatch_error = @errorName(e);
        break :blk &.{};
    };

    // r0 is not surfaced by the dispatcher on the success return (it returns []
    // mutations); a clean run implies r0==0 (the engine returns M4_RunFailed for
    // r0!=0). So: dispatch_error==null ⇒ return_code 0. On M4_RunFailed we can't
    // distinguish a revert (r0!=0) from a run-trap here, but both report full CU.
    const failed = dispatch_error != null;
    const return_code: u64 = 0;
    const cu_is_full_budget = failed;

    // Take ownership of captured logs into a stable slice.
    const logs = try g_log_lines.toOwnedSlice(alloc);

    return ProgramTestResult{
        .return_code = return_code,
        .consumed_cu = consumed_cu,
        .cu_is_full_budget = cu_is_full_budget,
        .dispatch_error = dispatch_error,
        .sbpf_version = sbpf_version,
        .mutations = muts,
        .logs = logs,
        .alloc = alloc,
    };
}

// ── base58 (encode/decode) + hex helpers ────────────────────────────────────

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58Encode(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var zeros: usize = 0;
    while (zeros < bytes.len and bytes[zeros] == 0) zeros += 1;
    // size = ceil(len * log(256)/log(58)) + 1 ≈ len * 138/100 + 1
    var digits = try alloc.alloc(u8, bytes.len * 138 / 100 + 1);
    defer alloc.free(digits);
    @memset(digits, 0);
    var digit_len: usize = 0;
    for (bytes) |b| {
        var carry: usize = b;
        var i: usize = 0;
        while (i < digit_len or carry != 0) : (i += 1) {
            if (i < digit_len) carry += @as(usize, digits[i]) * 256;
            digits[i] = @intCast(carry % 58);
            carry /= 58;
            if (i + 1 > digit_len) digit_len = i + 1;
        }
    }
    var out = try alloc.alloc(u8, zeros + digit_len);
    var k: usize = 0;
    while (k < zeros) : (k += 1) out[k] = '1';
    var j: usize = 0;
    while (j < digit_len) : (j += 1) out[zeros + j] = B58_ALPHABET[digits[digit_len - 1 - j]];
    return out;
}

fn b58Decode(s: []const u8, out: *[32]u8) !void {
    var bytes: [64]u8 = [_]u8{0} ** 64;
    var len: usize = 0;
    for (s) |c| {
        const di = std.mem.indexOfScalar(u8, B58_ALPHABET, c) orelse return error.BadBase58;
        var carry: usize = di;
        var i: usize = 0;
        while (i < len or carry != 0) : (i += 1) {
            if (i < len) carry += @as(usize, bytes[i]) * 58;
            bytes[i] = @intCast(carry & 0xff);
            carry >>= 8;
            if (i + 1 > len) len = i + 1;
        }
    }
    if (len > 32) return error.TooLong;
    var zeros: usize = 0;
    for (s) |c| {
        if (c == '1') zeros += 1 else break;
    }
    @memset(out, 0);
    var j: usize = 0;
    while (j < len) : (j += 1) out[zeros + (len - 1 - j)] = bytes[j];
}

fn hexDecodeAlloc(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var clean = s;
    if (std.mem.startsWith(u8, clean, "0x") or std.mem.startsWith(u8, clean, "0X")) clean = clean[2..];
    if (clean.len % 2 != 0) return error.OddHexLength;
    const out = try alloc.alloc(u8, clean.len / 2);
    _ = try std.fmt.hexToBytes(out, clean);
    return out;
}

// ── Output rendering ─────────────────────────────────────────────────────────

fn writeHex(w: anytype, bytes: []const u8) !void {
    for (bytes) |b| try w.print("{x:0>2}", .{b});
}

fn renderHuman(w: anytype, alloc: std.mem.Allocator, path: []const u8, elf_len: usize, opts: ProgramTestOptions, r: *const ProgramTestResult) !void {
    try w.print("vexor-program-test  —  Vexor sBPF VM harness (M1)\n", .{});
    try w.print("  program        : {s} ({d} bytes, sBPF {s})\n", .{ path, elf_len, r.sbpf_version });
    const pid58 = try b58Encode(alloc, &opts.program_id);
    defer alloc.free(pid58);
    try w.print("  program_id     : {s}\n", .{pid58});
    try w.print("  compute_budget : {d}\n", .{opts.compute_budget});
    try w.print("  accounts in    : {d}\n", .{opts.accounts.len});
    if (r.dispatch_error) |e| {
        try w.print("  result         : FAILED ({s})\n", .{e});
    } else if (r.return_code == 0) {
        try w.print("  result         : SUCCESS (r0=0)\n", .{});
    } else {
        try w.print("  result         : REVERT (r0={d})\n", .{r.return_code});
    }
    if (r.cu_is_full_budget) {
        try w.print("  consumed_cu    : {d}  [full budget — true partial burn not reported on failure]\n", .{r.consumed_cu});
    } else {
        try w.print("  consumed_cu    : {d}\n", .{r.consumed_cu});
    }
    try w.print("  program logs ({d}):\n", .{r.logs.len});
    for (r.logs) |l| try w.print("    | {s}\n", .{l});
    try w.print("  account mutations ({d} changed):\n", .{r.mutations.len});
    for (r.mutations) |m| {
        const pk58 = try b58Encode(alloc, &m.pubkey.data);
        defer alloc.free(pk58);
        try w.print("    - {s}  lamports={d}  data_len={d}  owner=", .{ pk58, m.new_lamports, m.data.len });
        try writeHex(w, m.owner[0..8]);
        try w.print("..\n", .{});
    }
}

fn renderJson(w: anytype, alloc: std.mem.Allocator, r: *const ProgramTestResult) !void {
    try w.print("{{", .{});
    if (r.dispatch_error) |e| {
        try w.print("\"ok\":false,\"error\":\"{s}\",", .{e});
    } else {
        try w.print("\"ok\":{s},\"error\":null,", .{if (r.return_code == 0) "true" else "false"});
    }
    try w.print("\"return_code\":{d},", .{r.return_code});
    try w.print("\"consumed_cu\":{d},", .{r.consumed_cu});
    try w.print("\"cu_is_full_budget\":{s},", .{if (r.cu_is_full_budget) "true" else "false"});
    try w.print("\"sbpf_version\":\"{s}\",", .{r.sbpf_version});
    try w.print("\"logs\":[", .{});
    for (r.logs, 0..) |l, i| {
        if (i != 0) try w.print(",", .{});
        try w.print("\"", .{});
        for (l) |c| {
            if (c == '"' or c == '\\') try w.print("\\{c}", .{c}) else if (c >= 0x20) try w.print("{c}", .{c}) else try w.print("\\u{x:0>4}", .{c});
        }
        try w.print("\"", .{});
    }
    try w.print("],\"accounts\":[", .{});
    for (r.mutations, 0..) |m, i| {
        if (i != 0) try w.print(",", .{});
        const pk58 = try b58Encode(alloc, &m.pubkey.data);
        defer alloc.free(pk58);
        const owner58 = try b58Encode(alloc, &m.owner);
        defer alloc.free(owner58);
        const data_b64 = try base64Alloc(alloc, m.data);
        defer alloc.free(data_b64);
        try w.print("{{\"pubkey\":\"{s}\",\"lamports\":{d},\"owner\":\"{s}\",\"data\":\"{s}\"}}", .{ pk58, m.new_lamports, owner58, data_b64 });
    }
    try w.print("]}}\n", .{});
}

fn base64Alloc(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try alloc.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data); // calcSize is exact → `out` fully written
    return out;
}

// ── CLI ──────────────────────────────────────────────────────────────────────

const usage =
    \\vexor-program-test — run a Solana .so through Vexor's sBPF VM (M1)
    \\
    \\Usage:
    \\  vexor-program-test <program.so> [options]
    \\
    \\Options:
    \\  --ix <hex>              instruction data (hex, optional 0x prefix)
    \\  --compute-budget <N>    compute-unit budget (default 1400000)
    \\  --slot <N>              execution slot (default 0)
    \\  --program-id <base58>   program id (default: 32 zero bytes)
    \\  --json                  emit machine-readable JSON
    \\  -h, --help              this help
    \\
    \\M1: one program, one instruction, sane-default sysvars, feature_set=none
    \\(pre-activation). A single default writable account is used unless the
    \\program ignores its input.
    \\
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    var path: ?[]const u8 = null;
    var ix_hex: ?[]const u8 = null;
    var compute_budget: u64 = DEFAULT_COMPUTE_BUDGET;
    var slot: u64 = 0;
    var json = false;
    var program_id: [32]u8 = [_]u8{0} ** 32;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            try stdoutPrint("{s}", .{usage});
            return;
        } else if (std.mem.eql(u8, a, "--json")) {
            json = true;
        } else if (std.mem.eql(u8, a, "--ix")) {
            i += 1;
            if (i >= args.len) return failArg("--ix needs a value");
            ix_hex = args[i];
        } else if (std.mem.eql(u8, a, "--compute-budget")) {
            i += 1;
            if (i >= args.len) return failArg("--compute-budget needs a value");
            compute_budget = std.fmt.parseInt(u64, args[i], 10) catch return failArg("bad --compute-budget");
        } else if (std.mem.eql(u8, a, "--slot")) {
            i += 1;
            if (i >= args.len) return failArg("--slot needs a value");
            slot = std.fmt.parseInt(u64, args[i], 10) catch return failArg("bad --slot");
        } else if (std.mem.eql(u8, a, "--program-id")) {
            i += 1;
            if (i >= args.len) return failArg("--program-id needs a value");
            b58Decode(args[i], &program_id) catch return failArg("bad --program-id base58");
        } else if (std.mem.startsWith(u8, a, "-")) {
            return failArg("unknown flag");
        } else {
            path = a;
        }
    }

    const so_path = path orelse {
        try stdoutPrint("{s}", .{usage});
        return failArg("missing <program.so>");
    };

    const elf_bytes = std.fs.cwd().readFileAlloc(alloc, so_path, 16 * 1024 * 1024) catch |e| {
        try stderrPrint("error: cannot read '{s}': {s}\n", .{ so_path, @errorName(e) });
        std.process.exit(2);
    };
    defer alloc.free(elf_bytes);

    var ix_data: []u8 = &.{};
    if (ix_hex) |h| {
        ix_data = hexDecodeAlloc(alloc, h) catch return failArg("bad --ix hex");
    }
    defer if (ix_data.len > 0) alloc.free(ix_data);

    // Default: one writable account so the diff report is non-empty. Programs
    // that ignore their input (e.g. the hello fixture) run regardless.
    const default_accounts = [_]AccountSnapshot{.{
        .pubkey = [_]u8{0x11} ** 32,
        .lamports = 1_000_000,
        .owner = [_]u8{0} ** 32, // System
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = &.{},
        .is_writable = true,
        .is_signer = true,
    }};

    var result = runProgramTest(alloc, .{
        .program_id = program_id,
        .elf_bytes = elf_bytes,
        .ix_data = ix_data,
        .accounts = &default_accounts,
        .compute_budget = compute_budget,
        .slot = slot,
    }) catch |e| {
        try stderrPrint("error: harness setup failed: {s}\n", .{@errorName(e)});
        std.process.exit(3);
    };
    defer result.deinit();

    var buf: [64 * 1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    if (json) {
        try renderJson(w, alloc, &result);
    } else {
        try renderHuman(w, alloc, so_path, elf_bytes.len, .{
            .program_id = program_id,
            .elf_bytes = elf_bytes,
            .ix_data = ix_data,
            .accounts = &default_accounts,
            .compute_budget = compute_budget,
            .slot = slot,
        }, &result);
    }
    try stdoutWrite(fbs.getWritten());

    if (!result.success()) std.process.exit(1);
}

fn failArg(msg: []const u8) noreturn {
    stderrPrint("error: {s}\n", .{msg}) catch {};
    std.process.exit(2);
}

fn stdoutWrite(bytes: []const u8) !void {
    const f = std.fs.File{ .handle = 1 };
    try f.writeAll(bytes);
}
fn stdoutPrint(comptime fmt: []const u8, args: anytype) !void {
    var buf: [8192]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, fmt, args);
    try stdoutWrite(s);
}
fn stderrPrint(comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    const f = std.fs.File{ .handle = 2 };
    try f.writeAll(s);
}

// ── The hello-fixture KAT — FIRST Zig-SDK program ever run in Vexor's VM ──────
//
// tests/bpf_fixtures/hello_zig.so is a Zig-Solana-SDK hello-world built with the
// community solana-zig toolchain (EM_SBF / sBPF v0). Its `entrypoint` ignores
// the input region, calls `sol_log_("Hello world from Zig!")`, and returns 0.
// SUCCESS proves the whole Vexor pipeline runs a Zig-SDK-emitted .so: r0=0,
// the log line is captured, and a stable nonzero CU count is reported.

test "M1 hello-fixture: first Zig-SDK program executes in Vexor's sBPF VM (r0=0, log captured, CU>0)" {
    const alloc = std.testing.allocator;

    const elf_bytes = try std.fs.cwd().readFileAlloc(alloc, "tests/bpf_fixtures/hello_zig.so", 4 * 1024 * 1024);
    defer alloc.free(elf_bytes);

    const accounts = [_]AccountSnapshot{.{
        .pubkey = [_]u8{0x11} ** 32,
        .lamports = 1_000_000,
        .owner = [_]u8{0} ** 32,
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = &.{},
        .is_writable = true,
        .is_signer = true,
    }};

    var result = try runProgramTest(alloc, .{
        .program_id = [_]u8{0x22} ** 32,
        .elf_bytes = elf_bytes,
        .ix_data = &.{},
        .accounts = &accounts,
        .compute_budget = DEFAULT_COMPUTE_BUDGET,
        .slot = 0,
    });
    defer result.deinit();

    std.debug.print(
        "\n[HELLO-FIXTURE] sbpf={s} err={?s} r0={d} consumed_cu={d} logs={d} muts={d}\n",
        .{ result.sbpf_version, result.dispatch_error, result.return_code, result.consumed_cu, result.logs.len, result.mutations.len },
    );
    for (result.logs) |l| std.debug.print("  program log: {s}\n", .{l});

    try std.testing.expect(result.dispatch_error == null); // clean EXIT
    try std.testing.expectEqual(@as(u64, 0), result.return_code); // r0 == 0
    try std.testing.expect(result.consumed_cu > 0); // real CU burn
    try std.testing.expect(!result.cu_is_full_budget); // accurate (not the failure fallback)
    try std.testing.expect(!g_log_oom);
    // The captured program log MUST contain the hello line.
    var found = false;
    for (result.logs) |l| {
        if (std.mem.indexOf(u8, l, "Hello world from Zig!") != null) found = true;
    }
    try std.testing.expect(found);
    // The engine emits a mutation ONLY for a changed account; hello touches
    // nothing → 0 mutations (the input account is left untouched).
    try std.testing.expectEqual(@as(usize, 0), result.mutations.len);
}

test "base58 round-trips" {
    const alloc = std.testing.allocator;
    const pk = [_]u8{0} ** 31 ++ [_]u8{1};
    const enc = try b58Encode(alloc, &pk);
    defer alloc.free(enc);
    var dec: [32]u8 = undefined;
    try b58Decode(enc, &dec);
    try std.testing.expectEqualSlices(u8, &pk, &dec);
}
