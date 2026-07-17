//! agave_meta_json.zig — render a decoded `TransactionStatusMeta` (the PROTO-READ path) to the rc.1
//! `meta` JSON of getTransaction/getBlock. Input = `agave_proto.DecodedTransactionStatusMeta` (decoded
//! from the stored protobuf). Output = byte-exact `UiTransactionStatusMeta` serde_json.
//!
//! Ground truth (RULE #16) — the HISTORICAL RPC path reads the stored proto → `convert.rs` →
//! `TransactionStatusMeta` → `From` → `UiTransactionStatusMeta`. The None-semantics that matter are set
//! by convert.rs (storage-proto/src/convert.rs), NOT the From<in-memory-meta> path:
//!   - convert.rs:568 inner_instructions = None IFF inner_instructions_none  → JSON null else array
//!   - convert.rs:578 log_messages       = None IFF log_messages_none        → JSON null else array
//!   - convert.rs:583/589/595 pre/post_token_balances + rewards = UNCONDITIONALLY Some(...) → ALWAYS
//!     a JSON array (empty → []), NEVER null
//!   - From (lib.rs:427) loaded_addresses wrapped in Some unconditionally → ALWAYS {"writable","readonly"}
//!   - From (lib.rs:428/431/432) return_data / compute_units_consumed / cost_units = or_skip → OMIT-when-None
//! Field ORDER (declaration / serde): err, status, fee, preBalances, postBalances, innerInstructions,
//! logMessages, preTokenBalances, postTokenBalances, rewards, loadedAddresses, [returnData],
//! [computeUnitsConsumed], [costUnits]. (camelCase.)
//!
//! Phase-2 scope: LIVE's population captures err/fee/balances/account-keys/CU only → it sets
//! inner_instructions_none=log_messages_none=true and stores NO token-balance/reward/inner records. So this
//! renderer renders innerInstructions/logMessages = null, pre/postTokenBalances/rewards = [] (empty Some),
//! loadedAddresses from the split loaded vectors, CU as a value. The NON-EMPTY nested decode of
//! inner_instructions / token_balances / rewards is a documented FOLLOW-UP (never produced in Phase 2); the
//! loops below emit [] for the empty Phase-2 arrays. Byte-locked vs a rc.1 proto→Ui golden before final bake.

const std = @import("std");
const Allocator = std.mem.Allocator;
const agave_proto = @import("agave_proto.zig");
const agave_json = @import("agave_json.zig");
const tx_json = @import("agave_tx_json.zig"); // shared golden-verified base58

pub const MetaJsonError = error{NonEmptyNestedUnsupported} || agave_json.RenderError;

fn appendU64(a: Allocator, out: *std.ArrayListUnmanaged(u8), v: u64) MetaJsonError!void {
    var tmp: [20]u8 = undefined;
    const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable;
    try out.appendSlice(a, s);
}

/// JSON-escaped string (for logMessages).
fn appendJsonString(a: Allocator, out: *std.ArrayListUnmanaged(u8), s: []const u8) MetaJsonError!void {
    try out.append(a, '"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(a, "\\\""),
            '\\' => try out.appendSlice(a, "\\\\"),
            '\n' => try out.appendSlice(a, "\\n"),
            '\r' => try out.appendSlice(a, "\\r"),
            '\t' => try out.appendSlice(a, "\\t"),
            else => {
                if (c < 0x20) {
                    var tmp: [8]u8 = undefined;
                    const e = std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{c}) catch unreachable;
                    try out.appendSlice(a, e);
                } else try out.append(a, c);
            },
        }
    }
    try out.append(a, '"');
}

/// `[base58, base58, ...]` for a slice of 32-byte address byte-slices.
fn appendB58Array(a: Allocator, out: *std.ArrayListUnmanaged(u8), addrs: []const []u8) MetaJsonError!void {
    try out.append(a, '[');
    for (addrs, 0..) |addr, i| {
        if (i != 0) try out.append(a, ',');
        try out.append(a, '"');
        try tx_json.appendBase58(a, out, addr);
        try out.append(a, '"');
    }
    try out.append(a, ']');
}

/// Render the `meta` object. Caller owns the result.
pub fn renderMetaJson(a: Allocator, meta: agave_proto.DecodedTransactionStatusMeta) MetaJsonError![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(a);

    // err (always) + status (always) — share the err_bytes.
    try out.appendSlice(a, "{\"err\":");
    if (meta.err_bytes) |eb| {
        const js = try agave_json.renderTxErrorJson(a, eb);
        defer a.free(js);
        try out.appendSlice(a, js);
        try out.appendSlice(a, ",\"status\":{\"Err\":");
        try out.appendSlice(a, js);
        try out.append(a, '}');
    } else {
        try out.appendSlice(a, "null,\"status\":{\"Ok\":null}");
    }

    // fee, preBalances, postBalances (always).
    try out.appendSlice(a, ",\"fee\":");
    try appendU64(a, &out, meta.fee);
    try out.appendSlice(a, ",\"preBalances\":[");
    for (meta.pre_balances, 0..) |b, i| {
        if (i != 0) try out.append(a, ',');
        try appendU64(a, &out, b);
    }
    try out.appendSlice(a, "],\"postBalances\":[");
    for (meta.post_balances, 0..) |b, i| {
        if (i != 0) try out.append(a, ',');
        try appendU64(a, &out, b);
    }
    try out.append(a, ']');

    // innerInstructions: null IFF inner_instructions_none, else array (Phase-2 empty → []).
    try out.appendSlice(a, ",\"innerInstructions\":");
    if (meta.inner_instructions_none) {
        try out.appendSlice(a, "null");
    } else {
        if (meta.inner_instructions.len != 0) return error.NonEmptyNestedUnsupported;
        try out.appendSlice(a, "[]");
    }

    // logMessages: null IFF log_messages_none, else array of JSON strings.
    try out.appendSlice(a, ",\"logMessages\":");
    if (meta.log_messages_none) {
        try out.appendSlice(a, "null");
    } else {
        try out.append(a, '[');
        for (meta.log_messages, 0..) |m, i| {
            if (i != 0) try out.append(a, ',');
            try appendJsonString(a, &out, m);
        }
        try out.append(a, ']');
    }

    // preTokenBalances / postTokenBalances / rewards: ALWAYS arrays (convert.rs Some) — Phase-2 empty → [].
    try out.appendSlice(a, ",\"preTokenBalances\":");
    if (meta.pre_token_balances.len != 0) return error.NonEmptyNestedUnsupported;
    try out.appendSlice(a, "[],\"postTokenBalances\":");
    if (meta.post_token_balances.len != 0) return error.NonEmptyNestedUnsupported;
    try out.appendSlice(a, "[],\"rewards\":");
    if (meta.rewards.len != 0) return error.NonEmptyNestedUnsupported;
    try out.appendSlice(a, "[]");

    // loadedAddresses: ALWAYS {"writable":[base58...],"readonly":[base58...]}.
    try out.appendSlice(a, ",\"loadedAddresses\":{\"writable\":");
    try appendB58Array(a, &out, meta.loaded_writable_addresses);
    try out.appendSlice(a, ",\"readonly\":");
    try appendB58Array(a, &out, meta.loaded_readonly_addresses);
    try out.append(a, '}');

    // returnData (omit-when-None) — return_data present and not the none-marker.
    if (meta.return_data) |rd| {
        if (!meta.return_data_none) {
            // returnData = {"programId":?, "data":[base64,"base64"]}. Phase 2 never sets it; defer the
            // exact shape to when it's populated (omit here keeps output rc.1-valid for Phase 2).
            _ = rd;
        }
    }
    // computeUnitsConsumed (omit-when-None).
    if (meta.compute_units_consumed) |cu| {
        try out.appendSlice(a, ",\"computeUnitsConsumed\":");
        try appendU64(a, &out, cu);
    }
    // costUnits (omit-when-None).
    if (meta.cost_units) |cost| {
        try out.appendSlice(a, ",\"costUnits\":");
        try appendU64(a, &out, cost);
    }

    try out.append(a, '}');
    return out.toOwnedSlice(a);
}

fn appendI64(a: Allocator, out: *std.ArrayListUnmanaged(u8), v: i64) MetaJsonError!void {
    var tmp: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable;
    try out.appendSlice(a, s);
}

/// proto RewardType (confirmed_block.proto) → rc.1 JSON PascalCase string or null (0=Unspecified→null).
/// Native solana-reward-info serde emits variant names verbatim (NOT the lowercase Display).
fn appendRewardType(a: Allocator, out: *std.ArrayListUnmanaged(u8), rt: u32) MetaJsonError!void {
    const name: ?[]const u8 = switch (rt) {
        1 => "Fee",
        2 => "Rent",
        3 => "Staking",
        4 => "Voting",
        5 => "DeactivatedStake",
        else => null, // 0 = Unspecified → None → null
    };
    if (name) |n| {
        try out.append(a, '"');
        try out.appendSlice(a, n);
        try out.append(a, '"');
    } else {
        try out.appendSlice(a, "null");
    }
}

/// proto `string commission` → JSON NUMBER (rc.1 `parse::<u8>().ok()`): empty/invalid/overflow → null,
/// else the bare number. NEVER a string (the JSON-RPC drift trap — string is the storage path only).
fn appendCommission(a: Allocator, out: *std.ArrayListUnmanaged(u8), s: []const u8) MetaJsonError!void {
    if (s.len == 0) {
        try out.appendSlice(a, "null");
        return;
    }
    const v = std.fmt.parseInt(u8, s, 10) catch {
        try out.appendSlice(a, "null");
        return;
    };
    try appendU64(a, out, v);
}

/// Render the `rewards` JSON array (UiReward elements) from decoded protobuf rewards. rc.1 contract
/// (LIVE-RC1-UIREWARD-GOLDEN): order pubkey,lamports(i64),postBalance(u64),rewardType(PascalCase|null),
/// commission(NUMBER|null), commissionBps(NUMBER, OMIT-when-none). Caller owns the result.
pub fn renderRewardsJson(a: Allocator, rewards: []const agave_proto.DecodedReward) MetaJsonError![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(a);
    try out.append(a, '[');
    for (rewards, 0..) |rw, i| {
        if (i != 0) try out.append(a, ',');
        try out.appendSlice(a, "{\"pubkey\":\"");
        try tx_json.appendBase58(a, &out, rw.pubkey);
        try out.appendSlice(a, "\",\"lamports\":");
        try appendI64(a, &out, rw.lamports);
        try out.appendSlice(a, ",\"postBalance\":");
        try appendU64(a, &out, rw.post_balance);
        try out.appendSlice(a, ",\"rewardType\":");
        try appendRewardType(a, &out, rw.reward_type);
        try out.appendSlice(a, ",\"commission\":");
        try appendCommission(a, &out, rw.commission);
        // commissionBps: NUMBER when present (non-empty parseable), OMITTED when None (empty).
        if (rw.commission_bps.len != 0) {
            if (std.fmt.parseInt(u16, rw.commission_bps, 10)) |bps| {
                try out.appendSlice(a, ",\"commissionBps\":");
                try appendU64(a, &out, bps);
            } else |_| {}
        }
        try out.append(a, '}');
    }
    try out.append(a, ']');
    return out.toOwnedSlice(a);
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATs — structural, to the convert.rs:568-595 source contract. BYTE-LOCK vs LIVE's rc.1 proto→Ui golden
// before final bake (per the standing pin directive).
// ═══════════════════════════════════════════════════════════════════════════════
const testing = std.testing;

test "GOLDEN — rc.1 UiReward rewards array (LIVE-RC1-UIREWARD-GOLDEN value contract)" {
    const a = testing.allocator;
    // 3 rewards covering the golden's cases: Staking/commission-null, Voting/commission-7+bps-750,
    // Fee/negative-lamports. pubkeys are the rc.1-PROVEN base58 mappings ([1;32]/[2;32]/[3;32]).
    var pk1 = [_]u8{0x01} ** 32; // "4vJ9..."
    var pk2 = [_]u8{0x02} ** 32; // "8qbHbw2..."
    var pk3 = [_]u8{0x03} ** 32; // "CktRuQ2m..."
    var c7 = [_]u8{'7'};
    var bps750 = [_]u8{ '7', '5', '0' };
    var rewards = [_]agave_proto.DecodedReward{
        .{ .pubkey = &pk1, .lamports = 2500, .post_balance = 1000002500, .reward_type = 3 }, // Staking, commission "" → null
        .{ .pubkey = &pk2, .lamports = 18000, .post_balance = 500000018000, .reward_type = 4, .commission = &c7, .commission_bps = &bps750 }, // Voting, 7, bps 750
        .{ .pubkey = &pk3, .lamports = -5000, .post_balance = 999995000, .reward_type = 1 }, // Fee, negative, commission null
    };
    const got = try renderRewardsJson(a, &rewards);
    defer a.free(got);
    const want = "[{\"pubkey\":\"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\",\"lamports\":2500,\"postBalance\":1000002500,\"rewardType\":\"Staking\",\"commission\":null}," ++
        "{\"pubkey\":\"8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\",\"lamports\":18000,\"postBalance\":500000018000,\"rewardType\":\"Voting\",\"commission\":7,\"commissionBps\":750}," ++
        "{\"pubkey\":\"CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8\",\"lamports\":-5000,\"postBalance\":999995000,\"rewardType\":\"Fee\",\"commission\":null}]";
    try testing.expectEqualStrings(want, got);
}

test "GOLDEN — rc.1 proto→Ui meta (success/vote tx, RUN through rc.1 crates by LIVE)" {
    // BYTE-LOCK vs LIVE-RC1-META-GOLDEN-2026-06-25.md: a stored generated::TransactionStatusMeta run
    // through real rc.1 solana-storage-proto TryFrom (convert.rs) → solana-transaction-status From →
    // serde_json. Fixture: fee=5000, 2 static accts, no inner/logs/tokens/rewards/CU.
    const a = testing.allocator;
    var pre = [_]u64{ 10000000, 2000000 };
    var post = [_]u64{ 9994999, 2000000 };
    const meta = agave_proto.DecodedTransactionStatusMeta{
        .err_bytes = null,
        .fee = 5000,
        .pre_balances = &pre,
        .post_balances = &post,
        .inner_instructions_none = true, // population sets true (uncaptured) → null
        .log_messages_none = true,
        // token_balances/rewards/loaded_* default empty → [] / {writable:[],readonly:[]}
    };
    const got = try renderMetaJson(a, meta);
    defer a.free(got);
    const want = "{\"err\":null,\"status\":{\"Ok\":null},\"fee\":5000,\"preBalances\":[10000000,2000000],\"postBalances\":[9994999,2000000]," ++
        "\"innerInstructions\":null,\"logMessages\":null,\"preTokenBalances\":[],\"postTokenBalances\":[],\"rewards\":[]," ++
        "\"loadedAddresses\":{\"writable\":[],\"readonly\":[]}}";
    try testing.expectEqualStrings(want, got);
}

test "meta populated: Err(InstructionError(0,Custom(1))), loaded addrs, logs, CU" {
    const a = testing.allocator;
    // err_bytes = bincode TransactionError::InstructionError(0, Custom(1)):
    //   txtag=8, ix=0, ietag=25(Custom), u32=1
    const err_bytes = [_]u8{ 0x08, 0, 0, 0, 0x00, 0x19, 0, 0, 0, 0x01, 0, 0, 0 };
    var wkey = [_]u8{0x01} ** 32; // → "4vJ9..."
    var rkey = [_]u8{0x02} ** 32; // → "8qbHbw2..."
    var w_slices = [_][]u8{&wkey};
    var r_slices = [_][]u8{&rkey};
    var log0 = [_]u8{ 'h', 'i' };
    var logs = [_][]u8{&log0};
    var pre = [_]u64{100};
    var post = [_]u64{90};
    const meta = agave_proto.DecodedTransactionStatusMeta{
        .err_bytes = @constCast(&err_bytes),
        .fee = 5000,
        .pre_balances = &pre,
        .post_balances = &post,
        .inner_instructions_none = false, // Some(empty) → []
        .log_messages = &logs,
        .log_messages_none = false,
        .loaded_writable_addresses = &w_slices,
        .loaded_readonly_addresses = &r_slices,
        .compute_units_consumed = 42,
    };
    const got = try renderMetaJson(a, meta);
    defer a.free(got);
    const want = "{\"err\":{\"InstructionError\":[0,{\"Custom\":1}]},\"status\":{\"Err\":{\"InstructionError\":[0,{\"Custom\":1}]}}," ++
        "\"fee\":5000,\"preBalances\":[100],\"postBalances\":[90],\"innerInstructions\":[],\"logMessages\":[\"hi\"]," ++
        "\"preTokenBalances\":[],\"postTokenBalances\":[],\"rewards\":[]," ++
        "\"loadedAddresses\":{\"writable\":[\"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\"],\"readonly\":[\"8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\"]}," ++
        "\"computeUnitsConsumed\":42}";
    try testing.expectEqualStrings(want, got);
}
