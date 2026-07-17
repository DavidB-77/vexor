//! agave_json.zig — byte-exact serde_json rendering of Agave rc.1 `TransactionError`
//! (and nested `InstructionError`) for the RPC `err` / `status` fields.
//!
//! Input = the INNER bincode bytes of a Rust `TransactionError` (the proto-wrapper
//! `TransactionError{ bytes err = 1 }` is already stripped by
//! `agave_proto.decodeTransactionStatusMeta`, which returns `err_bytes`). Output =
//! the exact `serde_json::to_string(&TransactionError)` text that rc.1's
//! `getTransaction` / `getSignatureStatuses` emit for that error.
//!
//! Ground truth (RULE #16) — golden-vectored against Agave 4.1.0-rc.1 (git 5efbb99):
//!   solana-transaction-error 3.2.0  src/lib.rs:16-144  (39 variants, idx 0..38)
//!   solana-instruction-error  2.3.0  src/lib.rs:43-215  (54 variants, idx 0..53)
//! Serde uses the DEFAULT externally-tagged enum repr (no rename/tag/untagged):
//!   - unit variant            -> bare string  "AccountInUse"
//!   - 1-field tuple variant   -> bare scalar   {"DuplicateInstruction":7} / {"Custom":42}
//!   - 2-field tuple variant   -> JSON array    {"InstructionError":[3,{"Custom":42}]}
//!   - struct variant          -> object        {"InsufficientFundsForRent":{"account_index":5}}
//! Traps confirmed by golden vectors: `Custom(u32)` renders DECIMAL (not the Display `:#x`);
//! `BorshIoError` (IE idx 44) is a UNIT variant in rc.1 -> bare "BorshIoError"; struct-variant
//! field `account_index` stays snake_case (the meta struct's camelCase rename does NOT reach the
//! error value); the RPC `UiTransactionError` wrapper re-emits identical JSON to this default repr.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const RenderError = error{ Truncated, UnknownTag } || Allocator.Error;

/// `TransactionError` variant names, indexed by the bincode u32 discriminant (rc.1 3.2.0
/// declaration order). The 4 data-carrying variants (8/30/31/35) are handled specially in
/// `renderTxError`; their entries here are only used for the name string.
const TX_ERR_NAMES = [_][]const u8{
    "AccountInUse", // 0
    "AccountLoadedTwice", // 1
    "AccountNotFound", // 2
    "ProgramAccountNotFound", // 3
    "InsufficientFundsForFee", // 4
    "InvalidAccountForFee", // 5
    "AlreadyProcessed", // 6
    "BlockhashNotFound", // 7
    "InstructionError", // 8  (data: u8, InstructionError)
    "CallChainTooDeep", // 9
    "MissingSignatureForFee", // 10
    "InvalidAccountIndex", // 11
    "SignatureFailure", // 12
    "InvalidProgramForExecution", // 13
    "SanitizeFailure", // 14
    "ClusterMaintenance", // 15
    "AccountBorrowOutstanding", // 16
    "WouldExceedMaxBlockCostLimit", // 17
    "UnsupportedVersion", // 18
    "InvalidWritableAccount", // 19
    "WouldExceedMaxAccountCostLimit", // 20
    "WouldExceedAccountDataBlockLimit", // 21
    "TooManyAccountLocks", // 22
    "AddressLookupTableNotFound", // 23
    "InvalidAddressLookupTableOwner", // 24
    "InvalidAddressLookupTableData", // 25
    "InvalidAddressLookupTableIndex", // 26
    "InvalidRentPayingAccount", // 27
    "WouldExceedMaxVoteCostLimit", // 28
    "WouldExceedAccountDataTotalLimit", // 29
    "DuplicateInstruction", // 30 (data: u8)
    "InsufficientFundsForRent", // 31 (data: {account_index:u8})
    "MaxLoadedAccountsDataSizeExceeded", // 32
    "InvalidLoadedAccountsDataSizeLimit", // 33
    "ResanitizationNeeded", // 34
    "ProgramExecutionTemporarilyRestricted", // 35 (data: {account_index:u8})
    "UnbalancedTransaction", // 36
    "ProgramCacheHitMaxLimit", // 37
    "CommitCancelled", // 38
};

/// `InstructionError` variant names, indexed by bincode u32 discriminant (rc.1 2.3.0). The only
/// data-carrying variant is `Custom` (25, u32). `BorshIoError` (44) is a UNIT variant in rc.1.
const INSTR_ERR_NAMES = [_][]const u8{
    "GenericError", // 0
    "InvalidArgument", // 1
    "InvalidInstructionData", // 2
    "InvalidAccountData", // 3
    "AccountDataTooSmall", // 4
    "InsufficientFunds", // 5
    "IncorrectProgramId", // 6
    "MissingRequiredSignature", // 7
    "AccountAlreadyInitialized", // 8
    "UninitializedAccount", // 9
    "UnbalancedInstruction", // 10
    "ModifiedProgramId", // 11
    "ExternalAccountLamportSpend", // 12
    "ExternalAccountDataModified", // 13
    "ReadonlyLamportChange", // 14
    "ReadonlyDataModified", // 15
    "DuplicateAccountIndex", // 16
    "ExecutableModified", // 17
    "RentEpochModified", // 18
    "NotEnoughAccountKeys", // 19
    "AccountDataSizeChanged", // 20
    "AccountNotExecutable", // 21
    "AccountBorrowFailed", // 22
    "AccountBorrowOutstanding", // 23
    "DuplicateAccountOutOfSync", // 24
    "Custom", // 25 (data: u32)
    "InvalidError", // 26
    "ExecutableDataModified", // 27
    "ExecutableLamportChange", // 28
    "ExecutableAccountNotRentExempt", // 29
    "UnsupportedProgramId", // 30
    "CallDepth", // 31
    "MissingAccount", // 32
    "ReentrancyNotAllowed", // 33
    "MaxSeedLengthExceeded", // 34
    "InvalidSeeds", // 35
    "InvalidRealloc", // 36
    "ComputationalBudgetExceeded", // 37
    "PrivilegeEscalation", // 38
    "ProgramEnvironmentSetupFailure", // 39
    "ProgramFailedToComplete", // 40
    "ProgramFailedToCompile", // 41
    "Immutable", // 42
    "IncorrectAuthority", // 43
    "BorshIoError", // 44 (UNIT in rc.1)
    "AccountNotRentExempt", // 45
    "InvalidAccountOwner", // 46
    "ArithmeticOverflow", // 47
    "UnsupportedSysvar", // 48
    "IllegalOwner", // 49
    "MaxAccountsDataAllocationsExceeded", // 50
    "MaxAccountsExceeded", // 51
    "MaxInstructionTraceLengthExceeded", // 52
    "BuiltinProgramsMustConsumeComputeUnits", // 53
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn u32le(self: *Reader) RenderError!u32 {
        if (self.pos + 4 > self.buf.len) return error.Truncated;
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .little);
        self.pos += 4;
        return v;
    }

    fn u8v(self: *Reader) RenderError!u8 {
        if (self.pos + 1 > self.buf.len) return error.Truncated;
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }
};

fn appendQuoted(a: Allocator, out: *std.ArrayListUnmanaged(u8), s: []const u8) RenderError!void {
    try out.append(a, '"');
    try out.appendSlice(a, s);
    try out.append(a, '"');
}

fn appendDec(a: Allocator, out: *std.ArrayListUnmanaged(u8), v: u64) RenderError!void {
    var tmp: [20]u8 = undefined; // u64 max = 20 digits → never overflows
    const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable;
    try out.appendSlice(a, s);
}

/// Render the nested `InstructionError` value (bincode: u32 tag [+ u32 for Custom]).
fn renderInstrError(a: Allocator, out: *std.ArrayListUnmanaged(u8), r: *Reader) RenderError!void {
    const tag = try r.u32le();
    if (tag == 25) { // Custom(u32) → {"Custom":<decimal>}
        const v = try r.u32le();
        try out.appendSlice(a, "{\"Custom\":");
        try appendDec(a, out, v);
        try out.append(a, '}');
        return;
    }
    if (tag >= INSTR_ERR_NAMES.len) return error.UnknownTag;
    try appendQuoted(a, out, INSTR_ERR_NAMES[tag]);
}

/// Render the top-level `TransactionError` value (bincode: u32 tag + variant payload).
fn renderTxError(a: Allocator, out: *std.ArrayListUnmanaged(u8), r: *Reader) RenderError!void {
    const tag = try r.u32le();
    switch (tag) {
        8 => { // InstructionError(u8, InstructionError) → {"InstructionError":[<ix>,<IE>]}
            const ix = try r.u8v();
            try out.appendSlice(a, "{\"InstructionError\":[");
            try appendDec(a, out, ix);
            try out.append(a, ',');
            try renderInstrError(a, out, r);
            try out.appendSlice(a, "]}");
        },
        30 => { // DuplicateInstruction(u8) → {"DuplicateInstruction":<n>}
            const n = try r.u8v();
            try out.appendSlice(a, "{\"DuplicateInstruction\":");
            try appendDec(a, out, n);
            try out.append(a, '}');
        },
        31 => { // InsufficientFundsForRent{account_index:u8}
            const n = try r.u8v();
            try out.appendSlice(a, "{\"InsufficientFundsForRent\":{\"account_index\":");
            try appendDec(a, out, n);
            try out.appendSlice(a, "}}");
        },
        35 => { // ProgramExecutionTemporarilyRestricted{account_index:u8}
            const n = try r.u8v();
            try out.appendSlice(a, "{\"ProgramExecutionTemporarilyRestricted\":{\"account_index\":");
            try appendDec(a, out, n);
            try out.appendSlice(a, "}}");
        },
        else => {
            if (tag >= TX_ERR_NAMES.len) return error.UnknownTag;
            try appendQuoted(a, out, TX_ERR_NAMES[tag]);
        },
    }
}

/// Render the inner bincode `TransactionError` bytes to canonical rc.1 serde_json (the RPC `err`
/// value). `bytes` = the inner bincode (proto wrapper already stripped). Caller owns the result.
pub fn renderTxErrorJson(a: Allocator, bytes: []const u8) RenderError![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(a);
    var r = Reader{ .buf = bytes };
    try renderTxError(a, &out, &r);
    return out.toOwnedSlice(a);
}

/// Render the legacy `status` field: `{"Ok":null}` when `err_bytes == null`, else
/// `{"Err":<renderTxErrorJson>}`. (rc.1 `meta.status` = `Result<(), TransactionError>`.)
pub fn renderStatusJson(a: Allocator, err_bytes: ?[]const u8) RenderError![]u8 {
    if (err_bytes) |b| {
        const inner = try renderTxErrorJson(a, b);
        defer a.free(inner);
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(a);
        try out.appendSlice(a, "{\"Err\":");
        try out.appendSlice(a, inner);
        try out.append(a, '}');
        return out.toOwnedSlice(a);
    }
    return a.dupe(u8, "{\"Ok\":null}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATs — golden vectors are rc.1 `serde_json::to_string(&e)` (evidence-backed: a throwaway
// crate on solana-transaction-error=3.2.0 / solana-instruction-error=2.3.0 printed both the
// bincode hex and the JSON; see LEDG-RPC-CONTENT-FOLLOWUP-SPEC.md provenance).
// ═══════════════════════════════════════════════════════════════════════════════
const testing = std.testing;

fn expectJson(bytes: []const u8, want: []const u8) !void {
    const got = try renderTxErrorJson(testing.allocator, bytes);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "J1 unit variant — AccountInUse (tag 0)" {
    try expectJson(&[_]u8{ 0x00, 0, 0, 0 }, "\"AccountInUse\"");
}

test "J2 unit variant — InsufficientFundsForFee (tag 4)" {
    try expectJson(&[_]u8{ 0x04, 0, 0, 0 }, "\"InsufficientFundsForFee\"");
}

test "J3 InstructionError(3, Custom(0xdeadbeef)) — nested + decimal Custom" {
    // bincode 080000000319000000efbeadde
    try expectJson(
        &[_]u8{ 0x08, 0, 0, 0, 0x03, 0x19, 0, 0, 0, 0xef, 0xbe, 0xad, 0xde },
        "{\"InstructionError\":[3,{\"Custom\":3735928559}]}",
    );
}

test "J4 InstructionError(0, GenericError) — nested unit IE" {
    try expectJson(
        &[_]u8{ 0x08, 0, 0, 0, 0x00, 0x00, 0, 0, 0 },
        "{\"InstructionError\":[0,\"GenericError\"]}",
    );
}

test "J5 InstructionError(2, BorshIoError) — IE 44 is UNIT in rc.1" {
    // bincode 08000000022c000000
    try expectJson(
        &[_]u8{ 0x08, 0, 0, 0, 0x02, 0x2c, 0, 0, 0 },
        "{\"InstructionError\":[2,\"BorshIoError\"]}",
    );
}

test "J6 InsufficientFundsForRent{account_index:5} — struct variant, snake_case" {
    try expectJson(
        &[_]u8{ 0x1f, 0, 0, 0, 0x05 },
        "{\"InsufficientFundsForRent\":{\"account_index\":5}}",
    );
}

test "J7 DuplicateInstruction(7) — 1-field tuple → bare scalar" {
    try expectJson(&[_]u8{ 0x1e, 0, 0, 0, 0x07 }, "{\"DuplicateInstruction\":7}");
}

test "J8 ProgramExecutionTemporarilyRestricted{account_index:9}" {
    try expectJson(
        &[_]u8{ 0x23, 0, 0, 0, 0x09 },
        "{\"ProgramExecutionTemporarilyRestricted\":{\"account_index\":9}}",
    );
}

test "J9 unit variant — CommitCancelled (tag 38, last)" {
    try expectJson(&[_]u8{ 0x26, 0, 0, 0 }, "\"CommitCancelled\"");
}

test "J10 strictness — truncated tag → error.Truncated" {
    try testing.expectError(error.Truncated, renderTxErrorJson(testing.allocator, &[_]u8{ 0x00, 0x00 }));
}

test "J11 strictness — InstructionError missing nested IE → error.Truncated" {
    // tag 8 + ix byte, then nothing (no nested IE tag)
    try testing.expectError(error.Truncated, renderTxErrorJson(testing.allocator, &[_]u8{ 0x08, 0, 0, 0, 0x01 }));
}

test "J12 strictness — unknown TransactionError tag → error.UnknownTag" {
    try testing.expectError(error.UnknownTag, renderTxErrorJson(testing.allocator, &[_]u8{ 0x39, 0, 0, 0 })); // 39 = out of range (0..38)
}

test "J13 strictness — unknown InstructionError tag → error.UnknownTag" {
    // valid TxError InstructionError(0, IE tag 54=out-of-range 0..53)
    try testing.expectError(error.UnknownTag, renderTxErrorJson(testing.allocator, &[_]u8{ 0x08, 0, 0, 0, 0x00, 0x36, 0, 0, 0 }));
}

test "J14 renderStatusJson — Ok and Err shapes" {
    const ok = try renderStatusJson(testing.allocator, null);
    defer testing.allocator.free(ok);
    try testing.expectEqualStrings("{\"Ok\":null}", ok);

    const err = try renderStatusJson(testing.allocator, &[_]u8{ 0x00, 0, 0, 0 });
    defer testing.allocator.free(err);
    try testing.expectEqualStrings("{\"Err\":\"AccountInUse\"}", err);
}

test "table sizes match rc.1 variant counts" {
    try testing.expectEqual(@as(usize, 39), TX_ERR_NAMES.len); // idx 0..38
    try testing.expectEqual(@as(usize, 54), INSTR_ERR_NAMES.len); // idx 0..53
}
