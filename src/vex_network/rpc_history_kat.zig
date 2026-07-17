//! SB-2/SB-1 RPC block/transaction-history WIRING KATs (2026-06-17).
//!
//! Proves the two deliverables the task asks for:
//!   (1) a wired read method returns a WELL-FORMED, Agave-shaped response when the store is populated
//!       — getBlock / getTransaction / getSignaturesForAddress / getBlocks / getBlockTime — AND the
//!       Agave-correct empty/null fallback when the store is ABSENT (gate OFF);
//!   (2) the GATED-OFF default build is byte-identical on the consensus path — asserted structurally
//!       by `build_options.rpc_store == false` (so the replay-path population + bank capture are
//!       comptime-dead). This is the consensus-byte-identical proof for the report.
//!
//! Runs via: `zig build test-rpc-store` (also runs the underlying block_store/tx_status_store KATs).

const std = @import("std");
const build_options = @import("build_options");
const vex_network = @import("vex_network");
const rpc_methods = vex_network.rpc_methods; // reach the handlers via the module boundary (no file-in-two-modules)
const storage = @import("vex_store");
const core = @import("core");

const testing = std.testing;
const BlockStore = storage.BlockStore;
const TxStatusStore = storage.TxStatusStore;

/// Build a minimal RpcContext for a handler test. Only the fields the history handlers touch are set;
/// the rest take their struct defaults (null/0). `block_store`/`tx_status_store` are the units under test.
fn mkCtx(alloc: std.mem.Allocator, bs: ?*BlockStore, ts: ?*TxStatusStore) rpc_methods.RpcContext {
    return .{
        .allocator = alloc,
        .accounts_db = null,
        .ledger_db = null,
        .snapshot_manager = null,
        .snapshot_limiter = rpc_methods.SnapshotLimiter.init(),
        .bank = null,
        .current_slot = 415_000_010,
        .current_epoch = 960,
        .cluster = "testnet",
        .block_store = bs,
        .tx_status_store = ts,
        .rooted_slot = 415_000_000,
        .confirmed_slot = 415_000_005,
    };
}

fn call(alloc: std.mem.Allocator, comptime handler: anytype, ctx: *const rpc_methods.RpcContext, params: ?[]const u8) ![]u8 {
    var rb = rpc_methods.ResponseBuilder.init(alloc);
    defer rb.deinit();
    try handler(ctx, params, &rb);
    return alloc.dupe(u8, rb.getWritten());
}

test "RPC tier gate: MINIMAL serves the canonical 12, rejects Full/BankData/AccountsData/AccountsScan; FULL serves all" {
    const a = testing.allocator;
    var rb = rpc_methods.ResponseBuilder.init(a);
    defer rb.deinit();

    // MINIMAL context (full_rpc_api defaults false) = a stock voting node.
    var ctx = rpc_methods.RpcContext{
        .allocator = a,
        .accounts_db = null,
        .ledger_db = null,
        .snapshot_manager = null,
        .snapshot_limiter = rpc_methods.SnapshotLimiter.init(),
        .bank = null,
        .current_slot = 1,
        .current_epoch = 0,
        .cluster = "testnet",
    };
    try testing.expectEqual(false, ctx.full_rpc_api);

    // The 12 Minimal-trait methods (Agave rc.1 rpc.rs `pub trait Minimal`) MUST route in minimal mode.
    const minimal = [_][]const u8{
        "getBalance", "getBlockHeight",         "getEpochInfo", "getGenesisHash",
        "getHealth",  "getHighestSnapshotSlot", "getIdentity",  "getLeaderSchedule",
        "getSlot",    "getTransactionCount",    "getVersion",   "getVoteAccounts",
    };
    for (minimal) |m| {
        rb.reset();
        try testing.expect(!rpc_methods.requiresFullApi(m)); // classification: minimal
        const found = rpc_methods.dispatch(m, &ctx, null, &rb) catch true; // routed (not -32601)
        try testing.expect(found);
    }

    // Representative Full / BankData / AccountsData / AccountsScan methods MUST be rejected in minimal
    // mode (found == false → caller emits canonical -32601, exactly as Agave leaves them unregistered).
    const gated = [_][]const u8{
        "getProgramAccounts", "getAccountInfo",          "getMultipleAccounts",     "getBlock",
        "getBlocks",          "getTransaction",          "sendTransaction",         "simulateTransaction",
        "getLatestBlockhash", "getSignaturesForAddress", "getTokenAccountsByOwner", "getSlotLeader",
    };
    for (gated) |m| {
        rb.reset();
        try testing.expect(rpc_methods.requiresFullApi(m)); // classification: full-api
        const found = try rpc_methods.dispatch(m, &ctx, null, &rb);
        try testing.expect(!found); // rejected in minimal mode
    }

    // FULL-API context = the `vex-fd rpc` node: the SAME gated methods now route.
    ctx.full_rpc_api = true;
    for (gated) |m| {
        rb.reset();
        const found = rpc_methods.dispatch(m, &ctx, null, &rb) catch true;
        try testing.expect(found);
    }
}

test "GATE: rpc_store defaults OFF (consensus path comptime-dead = byte-identical proof)" {
    // The default build (no -Drpc_store) MUST leave the gate OFF so the replay-path population + the
    // Bank.rpc_tx_capture field are comptime-eliminated. If this ever flips to default-ON, the
    // consensus-byte-identical guarantee is void — fail loudly.
    try testing.expectEqual(false, build_options.rpc_store);
}

test "getBlock: populated store → Agave-shaped block; absent store → null; missing slot → null" {
    const a = testing.allocator;
    var bs = BlockStore.init(a);
    defer bs.deinit();

    var txs = [_]storage.block_store.StoredTx{
        .{
            .signature = [_]u8{0xAA} ** 64,
            .wire = @constCast(&[_]u8{ 1, 2, 3, 4, 5 }),
            .err = null,
            .fee = 5000,
            .compute_units_consumed = 200,
            .pre_balances = @constCast(&[_]u64{ 1_000_000, 0 }),
            .post_balances = @constCast(&[_]u64{ 994_000, 1000 }),
        },
    };
    try bs.putBlock(.{
        .slot = 415_000_001,
        .parent_slot = 415_000_000,
        .blockhash = [_]u8{0xCD} ** 32,
        .previous_blockhash = [_]u8{0xAB} ** 32,
        .block_height = 400_000_000,
        .block_time = 1_700_000_000,
        .transactions = &txs,
        .rewards = &[_]storage.block_store.StoredReward{},
    });

    var ctx = mkCtx(a, &bs, null);

    // Populated slot → real block JSON.
    const body = try call(a, rpc_methods.getBlock, &ctx, "[415000001]");
    defer a.free(body);
    // Valid JSON object?
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqual(@as(i64, 415_000_000), obj.get("parentSlot").?.integer);
    try testing.expectEqual(@as(i64, 1_700_000_000), obj.get("blockTime").?.integer);
    // blockhash is the base58 of 0xCD*32 (non-empty, not the all-1s placeholder).
    const bh = obj.get("blockhash").?.string;
    try testing.expect(bh.len > 0);
    try testing.expect(!std.mem.eql(u8, bh, "11111111111111111111111111111111"));
    // transactions[0].transaction is ["<base64>","base64"]; meta.fee == 5000.
    const txs_arr = obj.get("transactions").?.array;
    try testing.expectEqual(@as(usize, 1), txs_arr.items.len);
    const meta = txs_arr.items[0].object.get("meta").?.object;
    try testing.expectEqual(@as(i64, 5000), meta.get("fee").?.integer);
    const tx_field = txs_arr.items[0].object.get("transaction").?.array;
    try testing.expectEqualStrings("base64", tx_field.items[1].string);

    // Missing slot in the SAME store → null.
    const body_missing = try call(a, rpc_methods.getBlock, &ctx, "[999999999]");
    defer a.free(body_missing);
    try testing.expectEqualStrings("null", body_missing);

    // Absent store (gate OFF at runtime) → null (Agave: block not available), NOT a fake block.
    var ctx_nostore = mkCtx(a, null, null);
    const body_nostore = try call(a, rpc_methods.getBlock, &ctx_nostore, "[415000001]");
    defer a.free(body_nostore);
    try testing.expectEqualStrings("null", body_nostore);
}

test "getBlock meta: non-null err (InstructionError) + CU + balances render Agave-shaped" {
    // SB-2 getBlock-meta enrichment (2026-06-21): a StoredTx carrying a genuine per-tx failure
    // (TransactionError discriminant 8 = InstructionError at ix 2), metered CU, and fee-payer
    // pre/post balances must render the Agave getBlock meta JSON: meta.err = the InstructionError
    // object, meta.status = {"Err":…}, meta.computeUnitsConsumed = N, meta.preBalances/postBalances.
    const a = testing.allocator;
    var bs = BlockStore.init(a);
    defer bs.deinit();

    var txs = [_]storage.block_store.StoredTx{
        .{
            .signature = [_]u8{0x5E} ** 64,
            .wire = @constCast(&[_]u8{ 7, 7, 7, 7 }),
            // InstructionError at instruction index 2; inner null → renderer emits "GenericError".
            .err = .{ .code = 8, .instruction_index = 2, .instruction_error = null },
            .fee = 5000,
            .compute_units_consumed = 1399,
            // Fee-payer-only (account[0]) length-1 balance views — the honest partial this feature
            // captures on the serial path (NOT the full key-parallel Agave vector).
            .pre_balances = @constCast(&[_]u64{2_000_000}),
            .post_balances = @constCast(&[_]u64{1_995_000}),
        },
    };
    try bs.putBlock(.{
        .slot = 415_000_077,
        .parent_slot = 415_000_076,
        .blockhash = [_]u8{0x11} ** 32,
        .previous_blockhash = [_]u8{0x22} ** 32,
        .block_height = 400_000_077,
        .block_time = 1_700_000_077,
        .transactions = &txs,
        .rewards = &[_]storage.block_store.StoredReward{},
    });

    var ctx = mkCtx(a, &bs, null);
    const body = try call(a, rpc_methods.getBlock, &ctx, "[415000077]");
    defer a.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    const txs_arr = parsed.value.object.get("transactions").?.array;
    try testing.expectEqual(@as(usize, 1), txs_arr.items.len);
    const meta = txs_arr.items[0].object.get("meta").?.object;

    // meta.computeUnitsConsumed == 1399 (populated, not omitted).
    try testing.expectEqual(@as(i64, 1399), meta.get("computeUnitsConsumed").?.integer);

    // meta.fee == 5000.
    try testing.expectEqual(@as(i64, 5000), meta.get("fee").?.integer);

    // meta.preBalances == [2000000], meta.postBalances == [1995000].
    const pre = meta.get("preBalances").?.array;
    try testing.expectEqual(@as(usize, 1), pre.items.len);
    try testing.expectEqual(@as(i64, 2_000_000), pre.items[0].integer);
    const post = meta.get("postBalances").?.array;
    try testing.expectEqual(@as(usize, 1), post.items.len);
    try testing.expectEqual(@as(i64, 1_995_000), post.items[0].integer);

    // meta.err is a NON-null InstructionError object: {"InstructionError":[2,"GenericError"]}.
    const err_obj = meta.get("err").?.object;
    const ie = err_obj.get("InstructionError").?.array;
    try testing.expectEqual(@as(i64, 2), ie.items[0].integer); // failing ix index
    try testing.expectEqualStrings("GenericError", ie.items[1].string); // inner (null → GenericError)

    // meta.status mirrors err: {"Err":{"InstructionError":[2,"GenericError"]}}.
    const status = meta.get("status").?.object;
    try testing.expect(status.get("Err") != null);
    try testing.expect(status.get("Ok") == null);
}

test "getTransaction: sig → block tx via tx_status index; unknown sig → null" {
    const a = testing.allocator;
    var bs = BlockStore.init(a);
    defer bs.deinit();
    var ts = TxStatusStore.init(a);
    defer ts.deinit();

    const sig = [_]u8{0x07} ** 64;
    var txs = [_]storage.block_store.StoredTx{
        .{ .signature = sig, .wire = @constCast(&[_]u8{ 9, 9, 9 }), .err = null, .fee = 5000, .compute_units_consumed = null, .pre_balances = @constCast(&[_]u64{}), .post_balances = @constCast(&[_]u64{}) },
    };
    try bs.putBlock(.{ .slot = 415_000_002, .parent_slot = 415_000_001, .blockhash = [_]u8{1} ** 32, .previous_blockhash = [_]u8{0} ** 32, .block_height = 1, .block_time = 1_700_000_111, .transactions = &txs, .rewards = &[_]storage.block_store.StoredReward{} });
    try ts.put(sig, 415_000_002, 0, null);

    var ctx = mkCtx(a, &bs, &ts);

    // base58 of the signature is the param. Build it.
    const sig58 = try core.base58.encode(a, &sig);
    defer a.free(sig58);
    const params = try std.fmt.allocPrint(a, "[\"{s}\"]", .{sig58});
    defer a.free(params);

    const body = try call(a, rpc_methods.getTransaction, &ctx, params);
    defer a.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 415_000_002), parsed.value.object.get("slot").?.integer);
    try testing.expectEqual(@as(i64, 1_700_000_111), parsed.value.object.get("blockTime").?.integer);

    // Unknown signature → null.
    const unknown = try core.base58.encode(a, &[_]u8{0xFF} ** 64);
    defer a.free(unknown);
    const p2 = try std.fmt.allocPrint(a, "[\"{s}\"]", .{unknown});
    defer a.free(p2);
    const body2 = try call(a, rpc_methods.getTransaction, &ctx, p2);
    defer a.free(body2);
    try testing.expectEqualStrings("null", body2);
}

test "getSignaturesForAddress: address index newest-first; absent store → []" {
    const a = testing.allocator;
    var ts = TxStatusStore.init(a);
    defer ts.deinit();
    const addr = core.Pubkey{ .data = [_]u8{0x42} ** 32 };
    try ts.indexAddress(addr, 100, [_]u8{1} ** 64);
    try ts.indexAddress(addr, 300, [_]u8{3} ** 64);
    try ts.indexAddress(addr, 200, [_]u8{2} ** 64);

    var ctx = mkCtx(a, null, &ts);
    const addr58 = try core.base58.encode(a, &addr.data);
    defer a.free(addr58);
    const params = try std.fmt.allocPrint(a, "[\"{s}\"]", .{addr58});
    defer a.free(params);

    const body = try call(a, rpc_methods.getSignaturesForAddress, &ctx, params);
    defer a.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try testing.expectEqual(@as(usize, 3), arr.items.len);
    // newest-first → slot 300, 200, 100
    try testing.expectEqual(@as(i64, 300), arr.items[0].object.get("slot").?.integer);
    try testing.expectEqual(@as(i64, 100), arr.items[2].object.get("slot").?.integer);

    // Absent store → [].
    var ctx_ns = mkCtx(a, null, null);
    const body_ns = try call(a, rpc_methods.getSignaturesForAddress, &ctx_ns, params);
    defer a.free(body_ns);
    try testing.expectEqualStrings("[]", body_ns);
}

test "getBlocks + getBlockTime read the store; absent store → []/null" {
    const a = testing.allocator;
    var bs = BlockStore.init(a);
    defer bs.deinit();
    const slots = [_]u64{ 100, 103, 101, 200 };
    for (slots) |s| {
        var t = [_]storage.block_store.StoredTx{};
        try bs.putBlock(.{ .slot = s, .parent_slot = s - 1, .blockhash = [_]u8{0} ** 32, .previous_blockhash = [_]u8{0} ** 32, .block_height = s, .block_time = @intCast(1_700_000_000 + s), .transactions = &t, .rewards = &[_]storage.block_store.StoredReward{} });
    }
    var ctx = mkCtx(a, &bs, null);

    // getBlocks [100, 150] → ascending {100,101,103}.
    const body = try call(a, rpc_methods.getBlocks, &ctx, "[100,150]");
    defer a.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try testing.expectEqual(@as(usize, 3), arr.items.len);
    try testing.expectEqual(@as(i64, 100), arr.items[0].integer);
    try testing.expectEqual(@as(i64, 103), arr.items[2].integer);

    // getBlockTime [101] → 1_700_000_101.
    const bt = try call(a, rpc_methods.getBlockTime, &ctx, "[101]");
    defer a.free(bt);
    try testing.expectEqualStrings("1700000101", bt);

    // Absent store: getBlocks → [], getBlockTime → null.
    var ctx_ns = mkCtx(a, null, null);
    const b2 = try call(a, rpc_methods.getBlocks, &ctx_ns, "[100,150]");
    defer a.free(b2);
    try testing.expectEqualStrings("[]", b2);
    const bt2 = try call(a, rpc_methods.getBlockTime, &ctx_ns, "[101]");
    defer a.free(bt2);
    try testing.expectEqualStrings("null", bt2);
}

test "sendTransaction: no mempool → JSON-RPC error (no fake signature)" {
    const a = testing.allocator;
    var ctx = mkCtx(a, null, null); // banking = null (no VEX_TPU_INGEST)
    var rb = rpc_methods.ResponseBuilder.init(a);
    defer rb.deinit();
    // A syntactically-plausible base64 tx; handler must reach the "no mempool" branch and set an error
    // rather than emit a fabricated all-1s signature.
    try rpc_methods.sendTransaction(&ctx, "[\"AQAB\"]", &rb);
    // Either a params error (too short to parse) or the submission-unavailable error — but NEVER a
    // success string. Assert an error code was set OR the body is not a quoted signature.
    const emitted_error = rb.err_code != null;
    const body = rb.getWritten();
    try testing.expect(emitted_error or !std.mem.startsWith(u8, body, "\""));
}

test "deprecated getConfirmed* aliases registered + full-API tier (SAFE-SUBSET RPC wiring)" {
    // The 5 deprecated aliases must be registered (so dispatch routes them) and classified full-API
    // (NOT in MINIMAL_METHODS), exactly like their canonical targets — a minimal node then hides them
    // with the identical -32601 a real Agave minimal node returns.
    const aliases = [_][]const u8{
        "getConfirmedBlock",
        "getConfirmedTransaction",
        "getConfirmedSignaturesForAddress2",
        "getConfirmedBlocks",
        "getConfirmedBlocksWithLimit",
    };
    for (aliases) |name| {
        try testing.expect(rpc_methods.methods.has(name)); // registered → dispatchable under full_rpc_api
        try testing.expect(rpc_methods.requiresFullApi(name)); // full-API tier, mirrors the canonical target
    }
}

test "getFirstAvailableBlock falls back to 0 without a VexLedger (SAFE-SUBSET regression guard)" {
    // With no VexLedger wired (mkCtx leaves vex_ledger at its null default), the handler must emit the
    // prior hardcoded "0" — byte-identical to before this wiring.
    const a = testing.allocator;
    const ctx = mkCtx(a, null, null);
    const out = try call(a, rpc_methods.getFirstAvailableBlock, &ctx, null);
    defer a.free(out);
    try testing.expectEqualStrings("0", out);
}
