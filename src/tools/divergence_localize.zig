//! divergence-localize (M1) — the offline bank_hash-divergence CLASSIFIER CLI.
//!
//! DESIGN: vexor-designs/LEDG-P5-MOAT2-DIVERGENCE-ALARM-DESIGN-2026-06-25.md
//!
//! This is the native, std-only front-end to the pure 4-input localizer engine
//! (`src/vex_ledger/divergence_alarm.zig`). It reads ONE JSON object (from --input <file>
//! or stdin) carrying our slot's frozen bank_hash inputs (from the [BANK-FROZEN] log line /
//! FlightRecord) plus the cluster's canonical inputs (public-testnet-RPC oracle + optional
//! oracle-node bank-hash-details), runs `classify()`, and prints the structured `verdict.json`
//! (design §4.1). It performs NO network I/O and NO replay — the wrapper
//! `tools/divergence-localize.sh` produces the JSON (offline re-replay → [BANK-FROZEN]
//! parse → oracle-node fetch → base58 PoH decode) and consumes this verdict, then appends the
//! account/field/owner from the per-account lt_hash diff for an EXECUTION class.
//!
//! Keeping this front-end pure JSON-in/JSON-out (no vex_svm import) makes it a tiny,
//! fast, dependency-free binary that the gate build compiles cleanly and the wrapper
//! composes — and it is the exact classify seam M2's live alarm thread will reuse.
//!
//! INPUT SCHEMA (all hashes = 64 lowercase hex chars; oracle fields null when unavailable):
//! {
//!   "slot": 420859999,
//!   "flight": { "bank_hash":"..", "parent_hash":"..", "signature_count":128,
//!               "poh_hash":"..", "lthash_digest":".." },
//!   "oracle": { "parent_matches": true, "poh_hash":"..", "signature_count":128,
//!               "bank_hash":".." }
//! }
//!
//! Usage:
//!   divergence-localize --input verdict-inputs.json   # or pipe the JSON on stdin
//!   divergence-localize --self-test                   # run the engine KATs' sibling smoke

const std = @import("std");
const alarm = @import("divergence_alarm");

const InputFlight = struct {
    bank_hash: []const u8,
    parent_hash: []const u8,
    signature_count: u64,
    poh_hash: []const u8,
    lthash_digest: []const u8,
};

const InputOracle = struct {
    parent_matches: ?bool = null,
    poh_hash: ?[]const u8 = null,
    signature_count: ?u64 = null,
    bank_hash: ?[]const u8 = null,
};

const InputDoc = struct {
    slot: u64,
    flight: InputFlight,
    oracle: InputOracle = .{},
};

const ParseError = error{BadHexLen};

fn hex32(s: []const u8) !alarm.Hash32 {
    if (s.len != 64) return ParseError.BadHexLen;
    var out: alarm.Hash32 = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

fn optHex32(s: ?[]const u8) !?alarm.Hash32 {
    return if (s) |v| try hex32(v) else null;
}

fn hexStr(a: alarm.Hash32) [64]u8 {
    return std.fmt.bytesToHex(a, .lower);
}

fn matchStr(m: alarm.Match) []const u8 {
    return switch (m) {
        .match => "match",
        .differ => "differ",
        .unknown => "unknown",
    };
}

/// Render the verdict as pretty JSON to `w`. This is the design §4.1 verdict.json payload
/// (the moat: {slot, class, inputs, ...}); the wrapper injects account/field/owner for
/// EXECUTION and re-emits the enriched bundle.
fn emitVerdict(w: anytype, doc: InputDoc, f: alarm.FlightInputs, o: alarm.OracleInputs, v: alarm.Verdict) !void {
    const bank_hex = hexStr(f.bank_hash);
    const parent_hex = hexStr(f.parent_hash);
    const poh_hex = hexStr(f.poh_hash);
    const lthash_hex = hexStr(f.lthash_digest);

    try w.print("{{\n", .{});
    try w.print("  \"slot\": {d},\n", .{doc.slot});
    try w.print("  \"class\": \"{s}\",\n", .{v.class.asStr()});
    try w.print("  \"needs_account_diff\": {s},\n", .{if (v.needs_account_diff) "true" else "false"});
    try w.print("  \"reanchor_parent\": {s},\n", .{if (v.reanchor_parent) "true" else "false"});
    try w.print("  \"our_bank_hash\": \"{s}\",\n", .{&bank_hex});
    if (o.bank_hash) |cb| {
        const cbh = hexStr(cb);
        try w.print("  \"cluster_bank_hash\": \"{s}\",\n", .{&cbh});
    } else {
        try w.print("  \"cluster_bank_hash\": null,\n", .{});
    }
    try w.print("  \"inputs\": {{\n", .{});

    // parent
    try w.print("    \"parent\": {{ \"ours\": \"{s}\", ", .{&parent_hex});
    if (o.parent_matches) |pm| {
        try w.print("\"cluster\": \"transitive:{s}\", ", .{if (pm) "match" else "differ"});
    } else {
        try w.print("\"cluster\": null, ", .{});
    }
    try w.print("\"match\": \"{s}\" }},\n", .{matchStr(v.parent)});

    // poh
    try w.print("    \"poh\": {{ \"ours\": \"{s}\", ", .{&poh_hex});
    if (o.poh_hash) |cp| {
        const cph = hexStr(cp);
        try w.print("\"cluster\": \"{s}\", ", .{&cph});
    } else {
        try w.print("\"cluster\": null, ", .{});
    }
    try w.print("\"match\": \"{s}\" }},\n", .{matchStr(v.poh)});

    // sigs
    try w.print("    \"sigs\": {{ \"ours\": {d}, ", .{f.signature_count});
    if (o.signature_count) |cs| {
        try w.print("\"cluster\": {d}, ", .{cs});
    } else {
        try w.print("\"cluster\": null, ", .{});
    }
    try w.print("\"match\": \"{s}\" }},\n", .{matchStr(v.sigs)});

    // lthash (never a direct RPC compare)
    try w.print("    \"lthash\": {{ \"ours\": \"{s}\", \"cluster\": \"n/a (not on RPC)\", \"match\": \"{s}\" }}\n", .{ &lthash_hex, matchStr(v.lthash) });

    try w.print("  }},\n", .{});
    // account/field/owner are filled by the wrapper's per-account lt_hash diff (design §3.2)
    // for an EXECUTION class; null here since the pure classifier does not do the account diff.
    try w.print("  \"account\": null,\n", .{});
    try w.print("  \"field\": null,\n", .{});
    try w.print("  \"owner_program\": null\n", .{});
    try w.print("}}\n", .{});
}

fn readAll(gpa: std.mem.Allocator, path: ?[]const u8) ![]u8 {
    if (path) |p| {
        return std.fs.cwd().readFileAlloc(gpa, p, 8 * 1024 * 1024);
    }
    // stdin
    const stdin = std.fs.File{ .handle = 0 };
    return stdin.readToEndAlloc(gpa, 8 * 1024 * 1024);
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var args = try std.process.argsWithAllocator(gpa);
    defer args.deinit();
    _ = args.next(); // argv0

    var input_path: ?[]const u8 = null;
    var self_test = false;
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--input")) {
            input_path = args.next() orelse fatal("--input requires a path", .{});
        } else if (std.mem.eql(u8, a, "--self-test")) {
            self_test = true;
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            printUsage();
            return;
        } else {
            fatal("unknown arg: {s}", .{a});
        }
    }

    var out_buf: [64 * 1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out_buf);
    const w = fbs.writer();

    if (self_test) {
        // Smoke: a synthetic EXECUTION case flows to a well-formed verdict end-to-end.
        const f = alarm.FlightInputs{
            .slot = 1,
            .bank_hash = [_]u8{0x77} ** 32,
            .parent_hash = [_]u8{0xAA} ** 32,
            .signature_count = 128,
            .poh_hash = [_]u8{0xCC} ** 32,
            .lthash_digest = [_]u8{0xDD} ** 32,
        };
        const o = alarm.OracleInputs{ .parent_matches = true, .poh_hash = [_]u8{0xCC} ** 32, .signature_count = 128, .bank_hash = [_]u8{0xBB} ** 32 };
        const v = alarm.classify(f, o);
        const doc = InputDoc{ .slot = 1, .flight = undefined };
        try emitVerdict(w, doc, f, o, v);
        try stdoutWrite(fbs.getWritten());
        if (v.class != .execution) fatal("self-test: expected EXECUTION", .{});
        return;
    }

    const raw = try readAll(gpa, input_path);
    defer gpa.free(raw);

    const parsed = std.json.parseFromSlice(InputDoc, gpa, raw, .{ .ignore_unknown_fields = true }) catch |e| {
        fatal("failed to parse input JSON: {s}", .{@errorName(e)});
    };
    defer parsed.deinit();
    const doc = parsed.value;

    const f = alarm.FlightInputs{
        .slot = doc.slot,
        .bank_hash = mustHex(doc.flight.bank_hash, "flight.bank_hash"),
        .parent_hash = mustHex(doc.flight.parent_hash, "flight.parent_hash"),
        .signature_count = doc.flight.signature_count,
        .poh_hash = mustHex(doc.flight.poh_hash, "flight.poh_hash"),
        .lthash_digest = mustHex(doc.flight.lthash_digest, "flight.lthash_digest"),
    };
    const o = alarm.OracleInputs{
        .parent_matches = doc.oracle.parent_matches,
        .poh_hash = if (doc.oracle.poh_hash) |s| mustHex(s, "oracle.poh_hash") else null,
        .signature_count = doc.oracle.signature_count,
        .bank_hash = if (doc.oracle.bank_hash) |s| mustHex(s, "oracle.bank_hash") else null,
    };

    const v = alarm.classify(f, o);
    try emitVerdict(w, doc, f, o, v);
    try stdoutWrite(fbs.getWritten());
}

/// Parse a required 64-hex field, exiting with a clean message (not a stack trace)
/// on a malformed value — this is an operator CLI, not a library call.
fn mustHex(s: []const u8, field: []const u8) alarm.Hash32 {
    return hex32(s) catch fatal("{s}: expected 64 hex chars, got {d} (\"{s}\")", .{ field, s.len, s });
}

fn stdoutWrite(bytes: []const u8) !void {
    const f = std.fs.File{ .handle = 1 };
    try f.writeAll(bytes);
}

fn printUsage() void {
    const msg =
        \\divergence-localize (M1) — offline bank_hash-divergence classifier
        \\
        \\  divergence-localize --input <inputs.json>   classify from a JSON file
        \\  divergence-localize                          classify from stdin
        \\  divergence-localize --self-test              engine smoke → verdict
        \\
        \\Emits verdict.json to stdout. See tools/divergence-localize.sh for the
        \\full slot->account+field wrapper (offline re-replay + per-account diff).
        \\
    ;
    std.debug.print("{s}", .{msg});
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("divergence-localize: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

// ── CLI-side KATs (the engine truth-table lives in divergence_alarm.zig) ──────
const testing = std.testing;

test "hex32 round-trips a 64-char hex string" {
    const s = "bb" ** 32;
    const parsed = try hex32(s);
    try testing.expectEqualSlices(u8, &([_]u8{0xBB} ** 32), &parsed);
}

test "hex32 rejects wrong length" {
    try testing.expectError(ParseError.BadHexLen, hex32("deadbeef"));
}

test "optHex32 passes null through" {
    try testing.expect((try optHex32(null)) == null);
}

test "end-to-end: parse a CONVERGENT input doc and classify" {
    const gpa = testing.allocator;
    const json =
        \\{ "slot": 420859999,
        \\  "flight": { "bank_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\              "parent_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\              "signature_count": 128,
        \\              "poh_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\              "lthash_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" },
        \\  "oracle": { "parent_matches": true,
        \\              "poh_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\              "signature_count": 128,
        \\              "bank_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } }
    ;
    const parsed = try std.json.parseFromSlice(InputDoc, gpa, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const doc = parsed.value;
    const f = alarm.FlightInputs{
        .slot = doc.slot,
        .bank_hash = try hex32(doc.flight.bank_hash),
        .parent_hash = try hex32(doc.flight.parent_hash),
        .signature_count = doc.flight.signature_count,
        .poh_hash = try hex32(doc.flight.poh_hash),
        .lthash_digest = try hex32(doc.flight.lthash_digest),
    };
    const o = alarm.OracleInputs{
        .parent_matches = doc.oracle.parent_matches,
        .poh_hash = try optHex32(doc.oracle.poh_hash),
        .signature_count = doc.oracle.signature_count,
        .bank_hash = try optHex32(doc.oracle.bank_hash),
    };
    try testing.expectEqual(alarm.CarrierClass.convergent, alarm.classify(f, o).class);
}

test "end-to-end: EXECUTION when bank differs and named inputs match" {
    const gpa = testing.allocator;
    const json =
        \\{ "slot": 1,
        \\  "flight": { "bank_hash": "7777777777777777777777777777777777777777777777777777777777777777",
        \\              "parent_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\              "signature_count": 128,
        \\              "poh_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\              "lthash_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" },
        \\  "oracle": { "parent_matches": true,
        \\              "poh_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\              "signature_count": 128,
        \\              "bank_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } }
    ;
    const parsed = try std.json.parseFromSlice(InputDoc, gpa, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const doc = parsed.value;
    const f = alarm.FlightInputs{
        .slot = doc.slot,
        .bank_hash = try hex32(doc.flight.bank_hash),
        .parent_hash = try hex32(doc.flight.parent_hash),
        .signature_count = doc.flight.signature_count,
        .poh_hash = try hex32(doc.flight.poh_hash),
        .lthash_digest = try hex32(doc.flight.lthash_digest),
    };
    const o = alarm.OracleInputs{
        .parent_matches = doc.oracle.parent_matches,
        .poh_hash = try optHex32(doc.oracle.poh_hash),
        .signature_count = doc.oracle.signature_count,
        .bank_hash = try optHex32(doc.oracle.bank_hash),
    };
    const v = alarm.classify(f, o);
    try testing.expectEqual(alarm.CarrierClass.execution, v.class);
    try testing.expect(v.needs_account_diff);
}
