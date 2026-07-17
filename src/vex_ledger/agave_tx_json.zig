//! agave_tx_json.zig — byte-exact render of a raw Solana transaction WIRE to rc.1's
//! `getTransaction`/`getBlock` `"json"` (non-parsed) `transaction` object:
//!   {"signatures":[base58...],"message":{"header":{...},"accountKeys":[base58...],
//!    "recentBlockhash":base58,"instructions":[{programIdIndex,accounts,data:base58,stackHeight}],
//!    "addressTableLookups"?}}
//!
//! Ground truth (RULE #16) — rc.1 git 5efbb99 + workspace Cargo.lock pins (solana-message 4.1.1,
//! solana-transaction 4.1.1, solana-short-vec 3.0.0). The canonical RPC path is
//! VersionedTransaction::encode_with_meta(Json,..) → json_encode() → UiMessage::Raw(UiRawMessage)
//! (transaction-status/src/lib.rs:528,634). The KAT below is the EXACT serde_json output of that path
//! for a known wire (an executed rc.1 golden vector), so this renderer is verified, not assumed.
//!
//! Shape facts baked in (all camelCase, UiMessage is `untagged` → message serializes FLAT):
//!   - header ALWAYS present (UiRawMessage.header has no skip).
//!   - UiCompiledInstruction.stack_height has NO skip → ALWAYS emitted; top-level = 1.
//!   - signatures/accountKeys/recentBlockhash/instruction.data = base58; accounts/indexes = number arrays.
//!   - addressTableLookups: omitted for legacy (None); for v0 ALWAYS emitted (even []).
//!   - field order follows struct declaration (match for byte-identical output).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const TxJsonError = error{ Truncated, BadShortvec, UnsupportedVersion } || Allocator.Error;

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Append the base58 encoding of `bytes` (Bitcoin/Solana alphabet) to `out`. Pub so the meta-JSON
/// renderer (loadedAddresses / reward pubkeys) shares the same golden-verified encoder.
pub fn appendBase58(a: Allocator, out: *std.ArrayListUnmanaged(u8), bytes: []const u8) Allocator.Error!void {
    var zeros: usize = 0;
    while (zeros < bytes.len and bytes[zeros] == 0) : (zeros += 1) {}
    const cap = bytes.len * 138 / 100 + 1; // ceil(log256/log58) upper bound
    const buf = try a.alloc(u8, cap);
    defer a.free(buf);
    @memset(buf, 0);
    var length: usize = 0;
    for (bytes) |byte| {
        var carry: u32 = byte;
        var k: usize = 0;
        while (k < length or carry != 0) : (k += 1) {
            const idx = cap - 1 - k; // fill from the least-significant end
            carry += 256 * @as(u32, buf[idx]);
            buf[idx] = @intCast(carry % 58);
            carry /= 58;
        }
        length = k;
    }
    var z: usize = 0;
    while (z < zeros) : (z += 1) try out.append(a, '1');
    var i: usize = cap - length;
    while (i < cap) : (i += 1) try out.append(a, B58[buf[i]]);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn u8v(self: *Reader) TxJsonError!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }
    fn take(self: *Reader, n: usize) TxJsonError![]const u8 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
    /// compact-u16 (shortvec): 7-bits/byte LE varint, max 3 bytes.
    fn shortvec(self: *Reader) TxJsonError!u16 {
        var val: u32 = 0;
        var shift: u4 = 0;
        var i: usize = 0;
        while (i < 3) : (i += 1) {
            const b = try self.u8v();
            val |= @as(u32, b & 0x7f) << @intCast(shift);
            if (b & 0x80 == 0) {
                if (val > 0xffff) return error.BadShortvec;
                return @intCast(val);
            }
            shift += 7;
        }
        return error.BadShortvec; // 4th continuation byte → not a u16
    }
};

fn appendNumArray(a: Allocator, out: *std.ArrayListUnmanaged(u8), vals: []const u8) TxJsonError!void {
    try out.append(a, '[');
    for (vals, 0..) |v, i| {
        if (i != 0) try out.append(a, ',');
        var tmp: [3]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable;
        try out.appendSlice(a, s);
    }
    try out.append(a, ']');
}

fn appendQuotedB58(a: Allocator, out: *std.ArrayListUnmanaged(u8), bytes: []const u8) TxJsonError!void {
    try out.append(a, '"');
    try appendBase58(a, out, bytes);
    try out.append(a, '"');
}

fn appendU64(a: Allocator, out: *std.ArrayListUnmanaged(u8), v: u64) TxJsonError!void {
    var tmp: [20]u8 = undefined;
    const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable;
    try out.appendSlice(a, s);
}

/// True (legacy) / false (v0) version of a stored message wire, peeking byte0. Used by getTransaction
/// to render the response-level `version` field ("legacy" | 0). null if the wire is too short.
pub const TxVersion = enum { legacy, v0 };
pub fn detectVersion(wire: []const u8) ?TxVersion {
    // top: shortvec sig count + sigs + message. We must skip to the message byte0.
    var r = Reader{ .buf = wire };
    const sig_count = r.shortvec() catch return null;
    _ = r.take(@as(usize, sig_count) * 64) catch return null;
    const b0 = r.u8v() catch return null;
    if (b0 & 0x80 == 0) return .legacy;
    return if (b0 & 0x7f == 0) .v0 else null; // v1+ unsupported here
}

/// Render the raw tx wire to the rc.1 `"json"` `transaction` object. Caller owns the result.
pub fn renderTxJson(a: Allocator, wire: []const u8) TxJsonError![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(a);
    var r = Reader{ .buf = wire };

    // ── signatures ──
    const sig_count = try r.shortvec();
    try out.appendSlice(a, "{\"signatures\":[");
    var si: usize = 0;
    while (si < sig_count) : (si += 1) {
        if (si != 0) try out.append(a, ',');
        try appendQuotedB58(a, &out, try r.take(64));
    }
    try out.appendSlice(a, "],\"message\":{");

    // ── message version + header ──
    const b0 = try r.u8v();
    var num_req: u8 = undefined;
    var is_v0 = false;
    if (b0 & 0x80 == 0) {
        // legacy: b0 IS num_required_signatures; 2 more header bytes follow.
        num_req = b0;
    } else {
        if (b0 & 0x7f != 0) return error.UnsupportedVersion; // only v0 supported
        is_v0 = true;
        num_req = try r.u8v(); // full 3-byte header follows the prefix
    }
    const num_ro_signed = try r.u8v();
    const num_ro_unsigned = try r.u8v();
    try out.appendSlice(a, "\"header\":{\"numRequiredSignatures\":");
    try appendU64(a, &out, num_req);
    try out.appendSlice(a, ",\"numReadonlySignedAccounts\":");
    try appendU64(a, &out, num_ro_signed);
    try out.appendSlice(a, ",\"numReadonlyUnsignedAccounts\":");
    try appendU64(a, &out, num_ro_unsigned);
    try out.append(a, '}');

    // ── accountKeys ──
    const key_count = try r.shortvec();
    try out.appendSlice(a, ",\"accountKeys\":[");
    var ki: usize = 0;
    while (ki < key_count) : (ki += 1) {
        if (ki != 0) try out.append(a, ',');
        try appendQuotedB58(a, &out, try r.take(32));
    }
    try out.append(a, ']');

    // ── recentBlockhash ──
    try out.appendSlice(a, ",\"recentBlockhash\":");
    try appendQuotedB58(a, &out, try r.take(32));

    // ── instructions ──
    const ix_count = try r.shortvec();
    try out.appendSlice(a, ",\"instructions\":[");
    var ii: usize = 0;
    while (ii < ix_count) : (ii += 1) {
        if (ii != 0) try out.append(a, ',');
        const prog_idx = try r.u8v();
        const acct_count = try r.shortvec();
        const accts = try r.take(acct_count);
        const data_len = try r.shortvec();
        const data = try r.take(data_len);
        try out.appendSlice(a, "{\"programIdIndex\":");
        try appendU64(a, &out, prog_idx);
        try out.appendSlice(a, ",\"accounts\":");
        try appendNumArray(a, &out, accts);
        try out.appendSlice(a, ",\"data\":");
        try appendQuotedB58(a, &out, data);
        // top-level instructions: stackHeight ALWAYS emitted = 1 (TRANSACTION_LEVEL_STACK_HEIGHT).
        try out.appendSlice(a, ",\"stackHeight\":1}");
    }
    try out.append(a, ']');

    // ── addressTableLookups (v0 only; rc.1 emits even when empty) ──
    if (is_v0) {
        const atl_count = try r.shortvec();
        try out.appendSlice(a, ",\"addressTableLookups\":[");
        var ai: usize = 0;
        while (ai < atl_count) : (ai += 1) {
            if (ai != 0) try out.append(a, ',');
            const akey = try r.take(32);
            const w_count = try r.shortvec();
            const w_idx = try r.take(w_count);
            const ro_count = try r.shortvec();
            const ro_idx = try r.take(ro_count);
            try out.appendSlice(a, "{\"accountKey\":");
            try appendQuotedB58(a, &out, akey);
            try out.appendSlice(a, ",\"writableIndexes\":");
            try appendNumArray(a, &out, w_idx);
            try out.appendSlice(a, ",\"readonlyIndexes\":");
            try appendNumArray(a, &out, ro_idx);
            try out.append(a, '}');
        }
        try out.append(a, ']');
    }

    try out.appendSlice(a, "}}"); // close message, close root
    return out.toOwnedSlice(a);
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATs
// ═══════════════════════════════════════════════════════════════════════════════
const testing = std.testing;

test "base58 — known vectors" {
    const a = testing.allocator;
    const cases = .{
        .{ &[_]u8{ 9, 8, 7 }, "42wp" }, // rc.1 golden instruction data
        .{ &[_]u8{ 5, 6 }, "PB" }, // rc.1 v0 golden instruction data
        .{ &[_]u8{0}, "1" }, // single zero → "1"
        .{ &[_]u8{ 0, 0, 1 }, "112" }, // leading zeros preserved as '1'
        .{ &[_]u8{}, "" },
    };
    inline for (cases) |c| {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(a);
        try appendBase58(a, &out, c[0]);
        try testing.expectEqualStrings(c[1], out.items);
    }
}

test "shortvec decode — solana-short-vec test vectors" {
    const cases = .{
        .{ &[_]u8{0x00}, @as(u16, 0x00) },
        .{ &[_]u8{0x7f}, @as(u16, 0x7f) },
        .{ &[_]u8{ 0x80, 0x01 }, @as(u16, 0x80) },
        .{ &[_]u8{ 0xff, 0x01 }, @as(u16, 0xff) },
        .{ &[_]u8{ 0x80, 0x02 }, @as(u16, 0x100) },
        .{ &[_]u8{ 0xff, 0x7f }, @as(u16, 0x3fff) },
        .{ &[_]u8{ 0x80, 0x80, 0x01 }, @as(u16, 0x4000) },
        .{ &[_]u8{ 0xff, 0xff, 0x03 }, @as(u16, 0xffff) },
    };
    inline for (cases) |c| {
        var r = Reader{ .buf = c[0] };
        try testing.expectEqual(c[1], try r.shortvec());
    }
}

test "GOLDEN — legacy tx wire → rc.1 json (executed rc.1 vector)" {
    const a = testing.allocator;
    // Build the 173-byte wire: 1 sig(0x04×64), header 01/00/01, 2 keys(0x01×32, 0x02×32),
    // blockhash(0x03×32), 1 instruction(progIdIdx=1, accounts=[0], data=[9,8,7]).
    var w = std.ArrayListUnmanaged(u8){};
    defer w.deinit(a);
    try w.append(a, 0x01);
    try w.appendNTimes(a, 0x04, 64);
    try w.appendSlice(a, &[_]u8{ 0x01, 0x00, 0x01 });
    try w.append(a, 0x02);
    try w.appendNTimes(a, 0x01, 32);
    try w.appendNTimes(a, 0x02, 32);
    try w.appendNTimes(a, 0x03, 32);
    try w.append(a, 0x01);
    try w.appendSlice(a, &[_]u8{ 0x01, 0x01, 0x00, 0x03, 0x09, 0x08, 0x07 });
    try testing.expectEqual(@as(usize, 173), w.items.len);

    const got = try renderTxJson(a, w.items);
    defer a.free(got);
    const want = "{\"signatures\":[\"5f5r5AjuFd8WwUagQSztAgufUCE6rdYhXmjU5rtnBPsxmfC5fFCUGiqQCcQZmAfFzuo6gyYYm616Roc1HEhREX5\"]," ++
        "\"message\":{\"header\":{\"numRequiredSignatures\":1,\"numReadonlySignedAccounts\":0,\"numReadonlyUnsignedAccounts\":1}," ++
        "\"accountKeys\":[\"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\",\"8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\"]," ++
        "\"recentBlockhash\":\"CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8\"," ++
        "\"instructions\":[{\"programIdIndex\":1,\"accounts\":[0],\"data\":\"42wp\",\"stackHeight\":1}]}}";
    try testing.expectEqualStrings(want, got);

    try testing.expectEqual(TxVersion.legacy, detectVersion(w.items).?);
}

test "GOLDEN — v0 tx wire (addressTableLookups) → rc.1 json" {
    const a = testing.allocator;
    // v0 wire: 1 sig(0x04×64), 0x80 prefix, header 01/00/00, 1 key([1]×32), blockhash([3]×32),
    // 1 instruction(progIdIdx=0, accounts=[], data=[5,6]), 1 ATL(accountKey=[2]×32, writable=[1], readonly=[2,3]).
    // base58 strings are the rc.1-PROVEN mappings from the legacy golden ([4;64], [1;32], [3;32], [2;32]).
    var w = std.ArrayListUnmanaged(u8){};
    defer w.deinit(a);
    try w.append(a, 0x01);
    try w.appendNTimes(a, 0x04, 64);
    try w.append(a, 0x80); // v0 prefix
    try w.appendSlice(a, &[_]u8{ 0x01, 0x00, 0x00 }); // header
    try w.append(a, 0x01); // 1 key
    try w.appendNTimes(a, 0x01, 32);
    try w.appendNTimes(a, 0x03, 32); // blockhash
    try w.append(a, 0x01); // 1 instr
    try w.appendSlice(a, &[_]u8{ 0x00, 0x00, 0x02, 0x05, 0x06 }); // progIdIdx=0, 0 accts, data len 2 [5,6]
    try w.append(a, 0x01); // 1 ATL
    try w.appendNTimes(a, 0x02, 32); // ATL accountKey
    try w.appendSlice(a, &[_]u8{ 0x01, 0x01 }); // writable count 1, [1]
    try w.appendSlice(a, &[_]u8{ 0x02, 0x02, 0x03 }); // readonly count 2, [2,3]

    const got = try renderTxJson(a, w.items);
    defer a.free(got);
    const want = "{\"signatures\":[\"5f5r5AjuFd8WwUagQSztAgufUCE6rdYhXmjU5rtnBPsxmfC5fFCUGiqQCcQZmAfFzuo6gyYYm616Roc1HEhREX5\"]," ++
        "\"message\":{\"header\":{\"numRequiredSignatures\":1,\"numReadonlySignedAccounts\":0,\"numReadonlyUnsignedAccounts\":0}," ++
        "\"accountKeys\":[\"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\"]," ++
        "\"recentBlockhash\":\"CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8\"," ++
        "\"instructions\":[{\"programIdIndex\":0,\"accounts\":[],\"data\":\"PB\",\"stackHeight\":1}]," ++
        "\"addressTableLookups\":[{\"accountKey\":\"8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\",\"writableIndexes\":[1],\"readonlyIndexes\":[2,3]}]}}";
    try testing.expectEqualStrings(want, got);
    try testing.expectEqual(TxVersion.v0, detectVersion(w.items).?);
}

test "strictness — truncated wire" {
    try testing.expectError(error.Truncated, renderTxJson(testing.allocator, &[_]u8{ 0x01, 0x00 }));
}
