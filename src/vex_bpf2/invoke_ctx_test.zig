//! Stage-A unit tests for invoke_ctx.zig.
//!
//! Locks all 5 invariant checks per R3 §4 + the vex-058 sysvar invariant.

const std = @import("std");
const ic = @import("invoke_ctx.zig");
const sc = @import("sysvar_cache.zig");

fn mkAccount(pk_byte: u8, lamports: u64, writable: bool, signer: bool, data: []u8) ic.AccountView {
    var pk: sc.Pubkey32 = std.mem.zeroes(sc.Pubkey32);
    pk[0] = pk_byte;
    return .{
        .pubkey = pk,
        .lamports = lamports,
        .owner = std.mem.zeroes(sc.Pubkey32),
        .executable = false,
        .rent_epoch = 0,
        .data = data,
        .is_writable = writable,
        .is_signer = signer,
    };
}

test "currentDepth starts at 0; push/pop increments and decrements" {
    const alloc = std.testing.allocator;
    const data0 = try alloc.alloc(u8, 16);
    defer alloc.free(data0);
    var accounts = [_]ic.AccountView{
        mkAccount(1, 100, true, true, data0),
    };
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 1_000_000);
    defer ctx.deinit();

    try std.testing.expectEqual(@as(u8, 0), ctx.currentDepth());
    const idxs = [_]u16{0};
    try ctx.push(0, &idxs);
    try std.testing.expectEqual(@as(u8, 1), ctx.currentDepth());
    ctx.pop();
    try std.testing.expectEqual(@as(u8, 0), ctx.currentDepth());
}

test "consumeCompute saturating + OutOfCompute" {
    const alloc = std.testing.allocator;
    const data0 = try alloc.alloc(u8, 0);
    defer alloc.free(data0);
    var accounts = [_]ic.AccountView{mkAccount(1, 0, false, false, data0)};
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 100);
    defer ctx.deinit();

    try ctx.consumeCompute(50);
    try std.testing.expectEqual(@as(u64, 50), ctx.computeRemaining());
    try ctx.consumeCompute(50);
    try std.testing.expectEqual(@as(u64, 0), ctx.computeRemaining());
    try std.testing.expectError(error.OutOfCompute, ctx.consumeCompute(1));
    try std.testing.expectEqual(@as(u64, 0), ctx.computeRemaining()); // saturated, never wraps
}

test "vex-058 invariant: getSysvar(Clock) on empty cache returns SysvarNotPopulated" {
    const alloc = std.testing.allocator;
    const data0 = try alloc.alloc(u8, 0);
    defer alloc.free(data0);
    var accounts = [_]ic.AccountView{mkAccount(1, 0, false, false, data0)};
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 100);
    defer ctx.deinit();

    try std.testing.expectError(error.SysvarNotPopulated, ctx.getSysvar(sc.Clock));
    try std.testing.expectError(error.SysvarNotPopulated, ctx.getSysvar(sc.EpochSchedule));
}

test "checkLamportBalance: balanced ⇒ ok; unbalanced ⇒ UnbalancedInstruction" {
    const alloc = std.testing.allocator;
    const data_a = try alloc.alloc(u8, 0);
    defer alloc.free(data_a);
    const data_b = try alloc.alloc(u8, 0);
    defer alloc.free(data_b);
    var accounts = [_]ic.AccountView{
        mkAccount(1, 100, true, false, data_a),
        mkAccount(2, 200, true, false, data_b),
    };
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 1_000_000);
    defer ctx.deinit();

    const idxs = [_]u16{ 0, 1 };
    try ctx.push(0, &idxs);
    // Balanced: move 50 from a→b.
    accounts[0].lamports = 50;
    accounts[1].lamports = 250;
    try ctx.checkLamportBalance();

    // Unbalanced: invent 1 lamport.
    accounts[1].lamports = 251;
    try std.testing.expectError(error.UnbalancedInstruction, ctx.checkLamportBalance());
    ctx.pop();
}

test "carrier 414602449: duplicate metas — lamport conservation counts each UNIQUE account once" {
    // Real-world shape (LayerZero V2 Send, testnet slot 414602449, sig
    // 2mf5pvkq…): the ULN frame lists the fee payer TWICE; inside the frame
    // the payer pays two vault fees. Reality conserves lamports; the OLD
    // per-occurrence sum counted the payer 2× on both sides and broke
    // ∑pre==∑post whenever the duplicated account's lamports CHANGED →
    // false UnbalancedInstruction → Vexor failed a tx the cluster executed
    // → accounts_lt_hash divergence. This KAT FAILS on pre-fix code.
    const alloc = std.testing.allocator;
    const data_a = try alloc.alloc(u8, 0);
    defer alloc.free(data_a);
    const data_b = try alloc.alloc(u8, 0);
    defer alloc.free(data_b);
    const data_c = try alloc.alloc(u8, 0);
    defer alloc.free(data_c);
    var accounts = [_]ic.AccountView{
        mkAccount(1, 10_000_000, true, false, data_a), // payer (duplicated in metas)
        mkAccount(2, 200, true, false, data_b), // vault 1
        mkAccount(3, 300, true, false, data_c), // vault 2
    };
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 1_000_000);
    defer ctx.deinit();

    // Payer appears at positions 0 AND 2 (the duplicate meta).
    const idxs = [_]u16{ 0, 1, 0, 2 };
    try ctx.push(0, &idxs);

    // Conserved move: payer −8_559_888, vaults +5_941_188/+2_618_700
    // (the carrier tx's exact deltas).
    accounts[0].lamports = 10_000_000 - 8_559_888;
    accounts[1].lamports = 200 + 5_941_188;
    accounts[2].lamports = 300 + 2_618_700;
    // PRE-FIX: payer counted twice ⇒ apparent −8_559_888 imbalance ⇒ error.
    try ctx.checkLamportBalance();

    // A REAL imbalance through a duplicated meta must still be caught.
    accounts[0].lamports += 1; // invent 1 lamport
    try std.testing.expectError(error.UnbalancedInstruction, ctx.checkLamportBalance());
    accounts[0].lamports -= 1;
    try ctx.checkLamportBalance(); // restored ⇒ balanced again
    ctx.pop();

    // Dup metas with NO lamport change on the duplicated account: balanced
    // before and after the fix (regression guard for the common case).
    const idxs2 = [_]u16{ 1, 1, 2 };
    try ctx.push(0, &idxs2);
    accounts[1].lamports -= 100;
    accounts[2].lamports += 100;
    try ctx.checkLamportBalance();
    ctx.pop();
}

test "checkReadonlyModified: readonly account data change ⇒ ReadonlyModified" {
    const alloc = std.testing.allocator;
    const data_a = try alloc.alloc(u8, 4);
    defer alloc.free(data_a);
    @memset(data_a, 0);
    var accounts = [_]ic.AccountView{
        mkAccount(1, 100, false, false, data_a), // readonly
    };
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 1_000_000);
    defer ctx.deinit();

    const idxs = [_]u16{0};
    try ctx.push(0, &idxs);
    // Mutate data while readonly.
    data_a[0] = 0xFF;
    try std.testing.expectError(error.ReadonlyModified, ctx.checkReadonlyModified());
    ctx.pop();
}

test "checkProgramIdModified: owner change on program account ⇒ ProgramIdModified" {
    const alloc = std.testing.allocator;
    const data_p = try alloc.alloc(u8, 0);
    defer alloc.free(data_p);
    var accounts = [_]ic.AccountView{
        mkAccount(1, 0, true, false, data_p),
    };
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 1_000_000);
    defer ctx.deinit();

    const idxs = [_]u16{0};
    try ctx.push(0, &idxs);
    // Mutate owner.
    accounts[0].owner[0] = 0xFF;
    try std.testing.expectError(error.ProgramIdModified, ctx.checkProgramIdModified());
    ctx.pop();
}

test "CallDepthExceeded after MAX_INSTRUCTION_STACK_DEPTH pushes" {
    const alloc = std.testing.allocator;
    const data0 = try alloc.alloc(u8, 0);
    defer alloc.free(data0);
    var accounts = [_]ic.AccountView{mkAccount(1, 0, true, false, data0)};
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 1_000_000);
    defer ctx.deinit();

    const idxs = [_]u16{0};
    var i: u8 = 0;
    while (i < ic.MAX_INSTRUCTION_STACK_DEPTH) : (i += 1) {
        try ctx.push(0, &idxs);
    }
    try std.testing.expectError(error.CallDepthExceeded, ctx.push(0, &idxs));
    while (ctx.currentDepth() > 0) ctx.pop();
}

test "SIMD-0268: active max_stack_depth=9 allows 9 pushes, rejects the 10th" {
    // Mirrors Agave execution_budget.rs get_max_instruction_stack_depth: inactive=5
    // (the test above, ctx.max_stack_depth defaults to MAX_INSTRUCTION_STACK_DEPTH),
    // active=9. v2_dispatch sets ctx.max_stack_depth from the RAISE_CPI_NESTING_LIMIT_TO_8
    // gate; here we set it directly to prove the boundary flips correctly.
    const alloc = std.testing.allocator;
    const data0 = try alloc.alloc(u8, 0);
    defer alloc.free(data0);
    var accounts = [_]ic.AccountView{mkAccount(1, 0, true, false, data0)};
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 1_000_000);
    defer ctx.deinit();

    // Default (inactive) must equal the constant 5 — dormant-safe baseline.
    try std.testing.expectEqual(ic.MAX_INSTRUCTION_STACK_DEPTH, ctx.max_stack_depth);

    // Activate SIMD-0268: limit 9.
    ctx.max_stack_depth = ic.MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268;
    const idxs = [_]u16{0};
    var i: u8 = 0;
    while (i < ic.MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268) : (i += 1) {
        try ctx.push(0, &idxs); // pushes at depth 0..8 all succeed
    }
    try std.testing.expectEqual(@as(u8, 9), ctx.currentDepth());
    // 10th push (at depth 9) rejected; stack height unchanged.
    try std.testing.expectError(error.CallDepthExceeded, ctx.push(0, &idxs));
    try std.testing.expectEqual(@as(u8, 9), ctx.currentDepth());
    while (ctx.currentDepth() > 0) ctx.pop();
}

test "checkRentState: RentNotPopulated ⇒ silently passes (cannot evaluate)" {
    const alloc = std.testing.allocator;
    const data0 = try alloc.alloc(u8, 4);
    defer alloc.free(data0);
    var accounts = [_]ic.AccountView{mkAccount(1, 1, true, false, data0)};
    var tx = ic.TransactionContext.init(alloc, &accounts, &.{});
    defer tx.deinit();
    var cache = sc.SysvarCache.init(alloc); // Rent NOT populated
    defer cache.deinit();
    var ctx = ic.InvokeContext.init(alloc, &tx, &cache, 1_000_000);
    defer ctx.deinit();

    const idxs = [_]u16{0};
    try ctx.push(0, &idxs);
    try ctx.checkRentState(); // no rent ⇒ no error
    ctx.pop();
}
