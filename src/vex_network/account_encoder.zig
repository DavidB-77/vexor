//! SB-4 (parity backlog, shared blocker — part 1/2): RPC account-data encoder.
//!
//! Every account-returning RPC method (getAccountInfo, getMultipleAccounts, getProgramAccounts, the
//! token methods) renders an account as the Agave `UiAccount` JSON:
//!   {"data":<data-field>,"executable":<bool>,"lamports":<u64>,"owner":"<base58>","rentEpoch":<u64>,"space":<u64>}
//! where <data-field> is `["<encoded>","<encoding>"]` for binary encodings or a parsed object for
//! jsonParsed. This module produces that, with `dataSlice` support. Today every account RPC is a stub
//! (getAccountInfo→null); this is the encoder they need.
//!
//! ADDITIVE + KAT-gated; NOT wired into the live RPC path yet (same discipline as the BP/SB-2 modules).
//!
//! Encoding support (matches Agave behavior):
//!   base58       — full. Agave ERRORS if the (sliced) data exceeds 128 bytes (too slow); we mirror that.
//!   base64       — full.
//!   base64+zstd  — NOT YET: Zig 0.15.2 std.compress.zstd is decompress-only and Vexor has no in-proc
//!                  zstd COMPRESSOR (snapshots shell out to `zstd -d`). Returns error.ZstdEncodeUnsupported
//!                  rather than emit wrong bytes (RULE #0). Follow-up: vendor a zstd compressor.
//!   jsonParsed   — falls back to base64 for now (exactly Agave's behavior for an account whose owner
//!                  program has no parser). Per-program parsers (SPL token / vote / stake) are additive.

const std = @import("std");
const core = @import("core");

pub const AccountEncoding = enum {
    base58,
    base64,
    base64_zstd,
    json_parsed,

    pub fn fromString(s: []const u8) ?AccountEncoding {
        if (std.mem.eql(u8, s, "base58")) return .base58;
        if (std.mem.eql(u8, s, "base64")) return .base64;
        if (std.mem.eql(u8, s, "base64+zstd")) return .base64_zstd;
        if (std.mem.eql(u8, s, "jsonParsed")) return .json_parsed;
        return null;
    }

    /// The encoding label that goes in the `["<data>","<label>"]` tuple. jsonParsed falls back to
    /// base64 (no parser yet) so it reports "base64".
    pub fn label(self: AccountEncoding) []const u8 {
        return switch (self) {
            .base58 => "base58",
            .base64 => "base64",
            .base64_zstd => "base64+zstd",
            .json_parsed => "base64",
        };
    }
};

/// Optional `{offset,length}` dataSlice. Applied to binary encodings only (Agave ignores it for
/// jsonParsed, but since we fall back to base64 we DO honor it — harmless and more useful).
pub const DataSlice = struct { offset: usize, length: usize };

/// The minimal account view the encoder needs (what AccountsDb hands RPC).
pub const AccountView = struct {
    lamports: u64,
    owner: [32]u8,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};

pub const EncodeError = error{ Base58DataTooLarge, ZstdEncodeUnsupported, OutOfMemory };

/// Agave's base58 account-data cap: encoding more than 128 bytes is refused (too slow).
pub const BASE58_MAX_DATA: usize = 128;

/// Apply a dataSlice to `data`, clamping offset/length to bounds (Agave: out-of-range offset → empty).
pub fn applySlice(data: []const u8, slice: ?DataSlice) []const u8 {
    const s = slice orelse return data;
    if (s.offset >= data.len) return data[0..0];
    const end = @min(data.len, s.offset + s.length);
    return data[s.offset..end];
}

/// Encode `data` under `encoding` (after `slice`). Returns an allocator-owned string = the ENCODED
/// PAYLOAD only (no surrounding `[...,"label"]`). Use `renderDataField` / `renderAccount` for the
/// full JSON. Caller frees.
pub fn encodePayload(allocator: std.mem.Allocator, data: []const u8, encoding: AccountEncoding, slice: ?DataSlice) EncodeError![]u8 {
    const view = applySlice(data, slice);
    switch (encoding) {
        .base58 => {
            if (view.len > BASE58_MAX_DATA) return error.Base58DataTooLarge;
            return core.base58.encode(allocator, view) catch error.OutOfMemory;
        },
        .base64, .json_parsed => {
            const enc = std.base64.standard.Encoder;
            const out = try allocator.alloc(u8, enc.calcSize(view.len));
            _ = enc.encode(out, view);
            return out;
        },
        .base64_zstd => return error.ZstdEncodeUnsupported,
    }
}

/// Render the `"data"` field VALUE: `["<encoded>","<label>"]`. Caller frees.
pub fn renderDataField(allocator: std.mem.Allocator, data: []const u8, encoding: AccountEncoding, slice: ?DataSlice) EncodeError![]u8 {
    const payload = try encodePayload(allocator, data, encoding, slice);
    defer allocator.free(payload);
    return std.fmt.allocPrint(allocator, "[\"{s}\",\"{s}\"]", .{ payload, encoding.label() }) catch error.OutOfMemory;
}

/// Render the full Agave `UiAccount` object for `account`. `space` is the FULL (unsliced) data length.
/// Caller frees. This is exactly the JSON `getAccountInfo`'s `value` (and each `getMultipleAccounts`
/// element / `getProgramAccounts` `.account`).
pub fn renderAccount(allocator: std.mem.Allocator, account: AccountView, encoding: AccountEncoding, slice: ?DataSlice) EncodeError![]u8 {
    const data_field = try renderDataField(allocator, account.data, encoding, slice);
    defer allocator.free(data_field);
    const owner_b58 = core.base58.encode(allocator, &account.owner) catch return error.OutOfMemory;
    defer allocator.free(owner_b58);
    return std.fmt.allocPrint(
        allocator,
        "{{\"data\":{s},\"executable\":{s},\"lamports\":{d},\"owner\":\"{s}\",\"rentEpoch\":{d},\"space\":{d}}}",
        .{ data_field, if (account.executable) "true" else "false", account.lamports, owner_b58, account.rent_epoch, account.data.len },
    ) catch error.OutOfMemory;
}

// ─────────────────────────────── KATs ───────────────────────────────

const testing = std.testing;

test "applySlice: clamps offset/length, out-of-range → empty" {
    const d = "0123456789";
    try testing.expectEqualStrings("0123456789", applySlice(d, null));
    try testing.expectEqualStrings("234", applySlice(d, .{ .offset = 2, .length = 3 }));
    try testing.expectEqualStrings("89", applySlice(d, .{ .offset = 8, .length = 100 })); // length clamps
    try testing.expectEqualStrings("", applySlice(d, .{ .offset = 50, .length = 5 })); // offset OOB → empty
}

test "encodePayload: base64 of known bytes" {
    const a = testing.allocator;
    // "foobar" → base64 "Zm9vYmFy"
    const p = try encodePayload(a, "foobar", .base64, null);
    defer a.free(p);
    try testing.expectEqualStrings("Zm9vYmFy", p);
    // base64 with slice "oob" (offset 1 len 3 of "foobar")
    const p2 = try encodePayload(a, "foobar", .base64, .{ .offset = 1, .length = 3 });
    defer a.free(p2);
    try testing.expectEqualStrings("b29i", p2); // base64("oob")
}

test "encodePayload: base58 of known bytes + >128B refusal" {
    const a = testing.allocator;
    // base58([0x00,0x00,0x01]) — leading-zero bytes become '1's: "112"
    const p = try encodePayload(a, &[_]u8{ 0, 0, 1 }, .base58, null);
    defer a.free(p);
    try testing.expectEqualStrings("112", p);
    // 129 bytes → refused
    const big = [_]u8{0xAB} ** 129;
    try testing.expectError(error.Base58DataTooLarge, encodePayload(a, &big, .base58, null));
    // but a 128-byte slice of it is fine
    const ok = try encodePayload(a, &big, .base58, .{ .offset = 0, .length = 128 });
    a.free(ok);
}

test "encodePayload: base64+zstd surfaces unsupported (no silent wrong bytes)" {
    const a = testing.allocator;
    try testing.expectError(error.ZstdEncodeUnsupported, encodePayload(a, "anything", .base64_zstd, null));
}

test "renderAccount: full UiAccount JSON (base64) — space is FULL length even when sliced" {
    const a = testing.allocator;
    const acct = AccountView{
        .lamports = 4_000_000,
        .owner = [_]u8{0} ** 32, // base58 of 32 zero bytes = "111...1" (32 ones)
        .executable = false,
        .rent_epoch = 18446744073709551615,
        .data = "foobar",
    };
    const json = try renderAccount(a, acct, .base64, .{ .offset = 0, .length = 3 });
    defer a.free(json);
    // data sliced to "foo" → base64 "Zm9v"; space stays 6 (full len); owner = 32 '1's.
    const expected = "{\"data\":[\"Zm9v\",\"base64\"],\"executable\":false,\"lamports\":4000000,\"owner\":\"11111111111111111111111111111111\",\"rentEpoch\":18446744073709551615,\"space\":6}";
    try testing.expectEqualStrings(expected, json);
}

test "AccountEncoding.fromString / label (jsonParsed → base64 fallback label)" {
    try testing.expectEqual(AccountEncoding.base64, AccountEncoding.fromString("base64").?);
    try testing.expectEqual(AccountEncoding.base64_zstd, AccountEncoding.fromString("base64+zstd").?);
    try testing.expectEqual(AccountEncoding.json_parsed, AccountEncoding.fromString("jsonParsed").?);
    try testing.expect(AccountEncoding.fromString("bogus") == null);
    try testing.expectEqualStrings("base64", AccountEncoding.json_parsed.label()); // fallback reports base64
}
