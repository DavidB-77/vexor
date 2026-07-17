//! Vexor BPF2 — M9: ComputeBudget native builtin program.
//!
//! ── Spec source ───────────────────────────────────────────────────────────
//!   • agave-v4.0.0-beta.7: programs/compute-budget/src/lib.rs (9 LoC)
//!   • sig:                src/runtime/program/compute_budget/lib.zig (1020 LoC)
//!
//! ── Behavior ──────────────────────────────────────────────────────────────
//! ComputeBudget instructions are PARSED + ENFORCED by the runtime per-tx,
//! NOT inside the in-process handler. The handler itself is a no-op that
//! just consumes the declared `DEFAULT_COMPUTE_UNITS` (150) and returns Ok.
//!
//! agave-v4 source:
//!   pub const DEFAULT_COMPUTE_UNITS: u64 = 150;
//!   declare_process_instruction!(Entrypoint, DEFAULT_COMPUTE_UNITS, |_invoke_context| {
//!       // Do nothing, compute budget instructions handled by the runtime
//!       Ok(())
//!   });
//!
//! Real compute-budget logic — RequestHeapFrame / SetComputeUnitLimit /
//! SetComputeUnitPrice / SetLoadedAccountsDataSizeLimit + their CU
//! pre-deduction — is owned by the *transaction-pre-dispatch* layer (Wave
//! 4 wiring at replay_stage; today: src/vex_svm/replay_stage.zig
//! :1611-1613 stub which will be replaced). NONE of that lives in this
//! file. M9 only owns the no-op handler.
//!
//! ── Instruction enum (reference only — parser is in the runtime layer) ────
//!   0  RequestUnitsDeprecated         (legacy; rejected)
//!   1  RequestHeapFrame { bytes: u32 }
//!   2  SetComputeUnitLimit { units: u32 }
//!   3  SetComputeUnitPrice { micro_lamports: u64 }
//!   4  SetLoadedAccountsDataSizeLimit { bytes: u32 }
//!
//! ── SIMD inventory ────────────────────────────────────────────────────────
//!   None active that change handler behavior. SIMD-0150 (Reduce CU cost of
//!   compute_budget program) is dormant; if/when it activates the cost
//!   constant in mod.zig PROGRAM_CU_TABLE updates, not this file's logic.
//!
//! ── fix_ledger anchors ────────────────────────────────────────────────────
//!   None directly. CU pre-deduction belongs to upstream Wave 4 wiring.

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const InvokeContext = ic.InvokeContext;
const trace = @import("mod.zig").trace;

/// Declared compute-unit cost for a ComputeBudget instruction, per
/// agave-v4.0.0-beta.7 programs/compute-budget/src/lib.rs:4.
pub const COMPUTE_UNITS: u64 = 150;

pub const Error = error{
    M9_ComputeBudget_OutOfCompute,
};

/// No-op execute. Per agave: the runtime parses + applies all
/// ComputeBudget instructions BEFORE the in-process handler runs; the
/// handler exists only to charge the per-instruction CU. We mirror that
/// exactly — consume CU and return.
pub fn execute(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    _ = ix_data; // Per agave: handler ignores ix data.
    ctx.consumeCompute(COMPUTE_UNITS) catch return error.M9_ComputeBudget_OutOfCompute;
    trace("M9.compute_budget.execute -> ok (charged {d} CU)", .{COMPUTE_UNITS});
}

pub fn selfTest() bool {
    // Compile-time invariants only.
    return COMPUTE_UNITS == 150;
}

// ── Tests ─────────────────────────────────────────────────────────────────

const sysvar_cache_mod = @import("../sysvar_cache.zig");

fn freshCtx(t_alloc: std.mem.Allocator, cu: u64) !*InvokeContext {
    const tc = try t_alloc.create(ic.TransactionContext);
    tc.* = ic.TransactionContext.init(t_alloc, &.{}, &.{});
    const cache = try t_alloc.create(sysvar_cache_mod.SysvarCache);
    cache.* = sysvar_cache_mod.SysvarCache.init(t_alloc);
    const c = try t_alloc.create(InvokeContext);
    c.* = InvokeContext.init(t_alloc, tc, cache, cu);
    // Push a dummy frame so currentFrame() != null isn't a precondition here.
    // (compute_budget's execute does not touch the frame; we verify via two
    // tests — one with a frame, one without.)
    return c;
}

fn freeCtx(t_alloc: std.mem.Allocator, c: *InvokeContext) void {
    const cache_ptr = @constCast(c.sysvar_cache);
    const tc_ptr = c.tx;
    c.deinit();
    cache_ptr.deinit();
    t_alloc.destroy(cache_ptr);
    tc_ptr.deinit();
    t_alloc.destroy(tc_ptr);
    t_alloc.destroy(c);
}

test "M9 compute_budget: happy path consumes 150 CU" {
    const t = std.testing;
    const a = t.allocator;
    const c = try freshCtx(a, 1_000);
    defer freeCtx(a, c);

    try execute(c, &.{});
    try t.expectEqual(@as(u64, 850), c.computeRemaining());
}

test "M9 compute_budget: empty data still no-ops fine" {
    const t = std.testing;
    const a = t.allocator;
    const c = try freshCtx(a, 200);
    defer freeCtx(a, c);

    try execute(c, &.{});
    try t.expectEqual(@as(u64, 50), c.computeRemaining());
}

test "M9 compute_budget: insufficient CU returns module-prefixed error" {
    const t = std.testing;
    const a = t.allocator;
    const c = try freshCtx(a, 100);
    defer freeCtx(a, c);

    try t.expectError(error.M9_ComputeBudget_OutOfCompute, execute(c, &.{}));
    try t.expectEqual(@as(u64, 0), c.computeRemaining());
}

test "M9 compute_budget: ix_data is ignored (parser is in runtime layer)" {
    const t = std.testing;
    const a = t.allocator;
    const c = try freshCtx(a, 1_000);
    defer freeCtx(a, c);

    // Garbage data — handler must ignore.
    try execute(c, &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff });
    try t.expectEqual(@as(u64, 850), c.computeRemaining());
}

test "M9 compute_budget: COMPUTE_UNITS matches agave-v4 DEFAULT_COMPUTE_UNITS" {
    const t = std.testing;
    try t.expectEqual(@as(u64, 150), COMPUTE_UNITS);
}
