// bpf_fixture.zig — Mollusk-style fixture format for the Vexor sBPF VM.
//
// A BpfFixture is a self-contained, replayable input for a single sBPF
// program invocation: program ELF (or hand-built rodata), pre-state of
// every account passed to the program, the instruction data, and the
// expected post-state + return code. It is the test-harness analogue of
// the live executor path in `replay_stage.zig` → `bank.executeBpfProgram`.
//
// FORMAT: JSON, not protobuf.
//
//   Why JSON: std.json is in 0.15.2 stdlib (no new deps), the file is
//   hand-authorable for the no-op seed fixture, and a fixture is *small*
//   (program ELF is the only meaningful payload). The single binary
//   field — the ELF — is base64-encoded inline. Mollusk uses protobuf
//   over a much wider matrix (compute budget, sysvars, return data,
//   logs); we deliberately don't need that surface area yet. When we
//   want cross-client compat with sig/Mollusk, we add a converter, not
//   a second on-disk format.
//
// SCHEMA (one fixture per .fix file):
//
//   {
//     "name": "system_create_account_via_ata",
//     "skip_reason": "<optional, present iff fixture is gated>",
//     "program_id": "<base58 pubkey>",
//     "program_elf_b64": "<base64 ELF bytes, OR \"\" with rodata_hex>",
//     "rodata_hex": "<hex bytes of synthesised rodata if no ELF>",
//     "entry_pc": 0,
//     "ix_data_hex": "<hex bytes>",
//     "accounts_pre":  [ <AccountState>, ... ],
//     "accounts_post": [ <AccountState>, ... ],
//     "return_code_expected": 0,
//     "compute_budget": 1400000
//   }
//
//   AccountState:
//     {
//       "pubkey":      "<base58>",
//       "owner":       "<base58>",
//       "lamports":    0,
//       "data_hex":    "<hex>",
//       "executable":  false,
//       "rent_epoch":  0,
//       "is_signer":   false,
//       "is_writable": true
//     }
//
// All `_hex` fields are lowercase, no `0x` prefix, no whitespace.
// All pubkeys are base58 (32-byte standard Solana encoding).
//
// Caller owns every byte slice on the returned BpfFixture. Free with
// BpfFixture.deinit(allocator).

const std = @import("std");
const core = @import("core");
const base58 = core.base58;

pub const AccountState = struct {
    pubkey: core.Pubkey,
    owner: core.Pubkey,
    lamports: u64,
    data: []u8,
    executable: bool,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
};

/// A single replayable sBPF invocation. Either `program_elf` is non-empty
/// (real ELF, fed through ElfLoader) or `synthesised_rodata` is non-empty
/// (hand-built program text, used by the no-op seed fixture).
pub const BpfFixture = struct {
    name: []u8,
    skip_reason: ?[]u8 = null,
    /// V1-specific skip reason. Honored by V1's bpf_fixture_runner; ignored
    /// by V2's fixture_runner. Use for fixtures whose ELF format V1 cannot
    /// load (e.g. strict SBPFv3) but V2 can.
    v1_skip_reason: ?[]u8 = null,
    program_id: core.Pubkey,
    program_elf: []u8, // may be empty
    synthesised_rodata: []u8, // may be empty; mutually exclusive with elf
    entry_pc: u64,
    ix_data: []u8,
    accounts_pre: []AccountState,
    accounts_post: []AccountState,
    return_code_expected: u64,
    compute_budget: u64,

    pub fn deinit(self: *BpfFixture, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.skip_reason) |sr| allocator.free(sr);
        if (self.v1_skip_reason) |sr| allocator.free(sr);
        allocator.free(self.program_elf);
        allocator.free(self.synthesised_rodata);
        allocator.free(self.ix_data);
        for (self.accounts_pre) |*a| allocator.free(a.data);
        allocator.free(self.accounts_pre);
        for (self.accounts_post) |*a| allocator.free(a.data);
        allocator.free(self.accounts_post);
    }

    pub fn isSkipped(self: *const BpfFixture) bool {
        return self.skip_reason != null or self.v1_skip_reason != null;
    }
};

// ── Loader ───────────────────────────────────────────────────────────────────

pub const FixtureError = error{
    InvalidJson,
    MissingField,
    BadBase58,
    BadHex,
    BadBase64,
    OutOfMemory,
};

const Json = std.json;

/// Load a fixture from a .fix JSON file.
pub fn loadFromFile(
    allocator: std.mem.Allocator,
    path: []const u8,
) !BpfFixture {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    const stat = try f.stat();
    const buf = try allocator.alloc(u8, stat.size);
    defer allocator.free(buf);
    _ = try f.readAll(buf);
    return loadFromSlice(allocator, buf);
}

pub fn loadFromSlice(
    allocator: std.mem.Allocator,
    json_bytes: []const u8,
) !BpfFixture {
    var parsed = Json.parseFromSlice(Json.Value, allocator, json_bytes, .{}) catch
        return FixtureError.InvalidJson;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return FixtureError.InvalidJson,
    };

    const name = try dupString(allocator, obj, "name");
    const skip_reason = try dupOptString(allocator, obj, "skip_reason");
    const v1_skip_reason = try dupOptString(allocator, obj, "v1_skip_reason");
    errdefer allocator.free(name);
    errdefer if (skip_reason) |sr| allocator.free(sr);
    errdefer if (v1_skip_reason) |sr| allocator.free(sr);

    const program_id = try parsePubkeyField(obj, "program_id");

    const elf_b64 = strField(obj, "program_elf_b64") orelse "";
    const program_elf = try decodeB64(allocator, elf_b64);
    errdefer allocator.free(program_elf);

    const rodata_hex = strField(obj, "rodata_hex") orelse "";
    const synth_rodata = try decodeHex(allocator, rodata_hex);
    errdefer allocator.free(synth_rodata);

    const entry_pc = (obj.get("entry_pc") orelse return FixtureError.MissingField)
        .integer;

    const ix_hex = strField(obj, "ix_data_hex") orelse "";
    const ix_data = try decodeHex(allocator, ix_hex);
    errdefer allocator.free(ix_data);

    const pre = try decodeAccountList(allocator, obj, "accounts_pre");
    errdefer freeAccounts(allocator, pre);
    const post = try decodeAccountList(allocator, obj, "accounts_post");
    errdefer freeAccounts(allocator, post);

    const ret = (obj.get("return_code_expected") orelse return FixtureError.MissingField)
        .integer;
    const cu = if (obj.get("compute_budget")) |v| v.integer else 1_400_000;

    return .{
        .name = name,
        .skip_reason = skip_reason,
        .v1_skip_reason = v1_skip_reason,
        .program_id = program_id,
        .program_elf = program_elf,
        .synthesised_rodata = synth_rodata,
        .entry_pc = @intCast(entry_pc),
        .ix_data = ix_data,
        .accounts_pre = pre,
        .accounts_post = post,
        .return_code_expected = @intCast(ret),
        .compute_budget = @intCast(cu),
    };
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn strField(obj: Json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn dupString(
    allocator: std.mem.Allocator,
    obj: Json.ObjectMap,
    key: []const u8,
) ![]u8 {
    const s = strField(obj, key) orelse return FixtureError.MissingField;
    return allocator.dupe(u8, s);
}

fn dupOptString(
    allocator: std.mem.Allocator,
    obj: Json.ObjectMap,
    key: []const u8,
) !?[]u8 {
    const s = strField(obj, key) orelse return null;
    if (s.len == 0) return null;
    return try allocator.dupe(u8, s);
}

fn parsePubkeyField(obj: Json.ObjectMap, key: []const u8) !core.Pubkey {
    const s = strField(obj, key) orelse return FixtureError.MissingField;
    return parsePubkey(s);
}

fn parsePubkey(s: []const u8) !core.Pubkey {
    var pk: core.Pubkey = undefined;
    base58.decodeToBuf(s, &pk.data) catch return FixtureError.BadBase58;
    return pk;
}

fn decodeB64(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len == 0) return try allocator.alloc(u8, 0);
    const Decoder = std.base64.standard.Decoder;
    const out_len = Decoder.calcSizeForSlice(s) catch return FixtureError.BadBase64;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    Decoder.decode(out, s) catch return FixtureError.BadBase64;
    return out;
}

fn decodeHex(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len == 0) return try allocator.alloc(u8, 0);
    if (s.len % 2 != 0) return FixtureError.BadHex;
    const out = try allocator.alloc(u8, s.len / 2);
    errdefer allocator.free(out);
    _ = std.fmt.hexToBytes(out, s) catch return FixtureError.BadHex;
    return out;
}

fn freeAccounts(allocator: std.mem.Allocator, list: []AccountState) void {
    for (list) |*a| allocator.free(a.data);
    allocator.free(list);
}

fn decodeAccountList(
    allocator: std.mem.Allocator,
    obj: Json.ObjectMap,
    key: []const u8,
) ![]AccountState {
    const v = obj.get(key) orelse return FixtureError.MissingField;
    const arr = switch (v) {
        .array => |a| a,
        else => return FixtureError.InvalidJson,
    };
    const out = try allocator.alloc(AccountState, arr.items.len);
    errdefer allocator.free(out);

    var n_decoded: usize = 0;
    errdefer for (out[0..n_decoded]) |*a| allocator.free(a.data);

    for (arr.items, 0..) |item, i| {
        const ao = switch (item) {
            .object => |o| o,
            else => return FixtureError.InvalidJson,
        };
        const data_hex = strField(ao, "data_hex") orelse "";
        const data = try decodeHex(allocator, data_hex);
        out[i] = .{
            .pubkey = try parsePubkeyField(ao, "pubkey"),
            .owner = try parsePubkeyField(ao, "owner"),
            .lamports = @intCast((ao.get("lamports") orelse return FixtureError.MissingField).integer),
            .data = data,
            .executable = (ao.get("executable") orelse return FixtureError.MissingField).bool,
            .rent_epoch = @intCast((ao.get("rent_epoch") orelse return FixtureError.MissingField).integer),
            .is_signer = (ao.get("is_signer") orelse return FixtureError.MissingField).bool,
            .is_writable = (ao.get("is_writable") orelse return FixtureError.MissingField).bool,
        };
        n_decoded = i + 1;
    }
    return out;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "loadFromSlice: minimal valid fixture round-trips" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "name": "t",
        \\  "program_id": "11111111111111111111111111111111",
        \\  "program_elf_b64": "",
        \\  "rodata_hex": "9500000000000000",
        \\  "entry_pc": 0,
        \\  "ix_data_hex": "",
        \\  "accounts_pre": [],
        \\  "accounts_post": [],
        \\  "return_code_expected": 0,
        \\  "compute_budget": 1000
        \\}
    ;
    var fix = try loadFromSlice(allocator, json);
    defer fix.deinit(allocator);
    try std.testing.expectEqualStrings("t", fix.name);
    try std.testing.expectEqual(@as(u64, 0), fix.entry_pc);
    try std.testing.expectEqual(@as(usize, 8), fix.synthesised_rodata.len);
    try std.testing.expect(!fix.isSkipped());
}

test "loadFromSlice: skip_reason marks fixture as skipped" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "name": "skipme",
        \\  "skip_reason": "W3 not landed yet",
        \\  "program_id": "11111111111111111111111111111111",
        \\  "program_elf_b64": "",
        \\  "rodata_hex": "",
        \\  "entry_pc": 0,
        \\  "ix_data_hex": "",
        \\  "accounts_pre": [],
        \\  "accounts_post": [],
        \\  "return_code_expected": 0
        \\}
    ;
    var fix = try loadFromSlice(allocator, json);
    defer fix.deinit(allocator);
    try std.testing.expect(fix.isSkipped());
}
