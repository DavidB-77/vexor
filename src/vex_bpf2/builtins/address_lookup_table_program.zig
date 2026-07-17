//! Vexor BPF2 — M9: AddressLookupTable native builtin program.
//!
//! ── Spec source ───────────────────────────────────────────────────────────
//!   • agave-3.x (legacy; agave-v4.0.0-beta.7 dropped ALT to Core BPF):
//!       programs/address-lookup-table/src/processor.rs
//!   • sig: src/runtime/program/address_lookup_table/{execute.zig,
//!     instruction.zig, state.zig} — full 1244 LoC reference port.
//!   • Vexor V1 reference (DO NOT MUTATE):
//!     src/vex_svm/native/address_lookup_table.zig
//!
//! ── Instruction enum (bincode tag = u32 LE) ───────────────────────────────
//!     0  CreateLookupTable { recent_slot: Slot, bump_seed: u8 }
//!     1  FreezeLookupTable
//!     2  ExtendLookupTable { new_addresses: Vec<Pubkey> }
//!     3  DeactivateLookupTable
//!     4  CloseLookupTable
//!
//! ── Port status (this session) ────────────────────────────────────────────
//! Skeleton only: parser dispatches by tag; every variant returns
//! `M9_AddressLookupTable_VariantPending_<Name>`. The full port (~1500 LoC)
//! is a follow-up branch deliverable. Critical work for the full port:
//!   - PDA derivation parity with vex-053 (lookup-table address from
//!     authority + recent_slot + bump_seed).
//!   - SlotHashes sysvar read (recent_slot validation): goes through
//!     ctx.sysvar_cache.getSlotHashes() — vex-058 invariant locked.
//!   - LookupTableMeta + addresses serialization parity with state.zig.
//!
//! ── SIMD inventory ────────────────────────────────────────────────────────
//!   • SIMD-0083 (Tx-loading constraints) — affects ALT lookup-resolution
//!     in tx-loader, not handler. Already active.
//!   • Future "ALT to Core BPF" SIMD — TBD; would deactivate this builtin.
//!
//! ── fix_ledger anchors ────────────────────────────────────────────────────
//!   • vex-053 (LOCKED) — ALT lookup resolution lives in the tx-loader,
//!     NOT in this builtin. The `Phase 1` slot-hash validation tracker
//!     and `markSlotDead` paths in tvu.zig + replay_stage are the wired
//!     resolution; THIS builtin does NOT re-resolve.
//!   • vex-058 — SlotHashes read in CreateLookupTable / ExtendLookupTable
//!     goes via ctx.sysvar_cache.getSlotHashes(); never silent-zero.

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const InvokeContext = ic.InvokeContext;
const trace = @import("mod.zig").trace;

pub const COMPUTE_UNITS: u64 = 750; // agave-3.x DEFAULT_COMPUTE_UNITS for ALT

pub const Error = error{
    M9_AddressLookupTable_OutOfCompute,
    M9_AddressLookupTable_NoActiveFrame,
    M9_AddressLookupTable_InvalidInstructionData,
    M9_AddressLookupTable_UnknownInstructionTag,
    M9_AddressLookupTable_VariantPending_CreateLookupTable,
    M9_AddressLookupTable_VariantPending_FreezeLookupTable,
    M9_AddressLookupTable_VariantPending_ExtendLookupTable,
    M9_AddressLookupTable_VariantPending_DeactivateLookupTable,
    M9_AddressLookupTable_VariantPending_CloseLookupTable,
};

pub fn execute(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    ctx.consumeCompute(COMPUTE_UNITS) catch return error.M9_AddressLookupTable_OutOfCompute;
    if (ctx.currentFrame() == null) return error.M9_AddressLookupTable_NoActiveFrame;
    if (ix_data.len < 4) return error.M9_AddressLookupTable_InvalidInstructionData;
    const tag = std.mem.readInt(u32, ix_data[0..4], .little);
    trace("M9.address_lookup_table.execute (tag={d})", .{tag});

    return switch (tag) {
        0 => error.M9_AddressLookupTable_VariantPending_CreateLookupTable,
        1 => error.M9_AddressLookupTable_VariantPending_FreezeLookupTable,
        2 => error.M9_AddressLookupTable_VariantPending_ExtendLookupTable,
        3 => error.M9_AddressLookupTable_VariantPending_DeactivateLookupTable,
        4 => error.M9_AddressLookupTable_VariantPending_CloseLookupTable,
        else => error.M9_AddressLookupTable_UnknownInstructionTag,
    };
}

pub fn selfTest() bool {
    return COMPUTE_UNITS == 750;
}

// ── Tests ─────────────────────────────────────────────────────────────────

const Harness = @import("test_harness.zig").Harness;

test "M9 ALT: empty data rejected" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    try t.expectError(error.M9_AddressLookupTable_InvalidInstructionData, execute(h.ctx, &.{}));
}

test "M9 ALT: unknown tag rejected" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 99, .little);
    try t.expectError(error.M9_AddressLookupTable_UnknownInstructionTag, execute(h.ctx, &data));
}

test "M9 ALT: tag=0 dispatches to VariantPending_CreateLookupTable" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 10_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, data[0..4], 0, .little);
    try t.expectError(error.M9_AddressLookupTable_VariantPending_CreateLookupTable, execute(h.ctx, &data));
}

test "M9 ALT: OutOfCompute when meter short" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100, &.{});
    defer h.deinit();
    try t.expectError(error.M9_AddressLookupTable_OutOfCompute, execute(h.ctx, &.{}));
}
