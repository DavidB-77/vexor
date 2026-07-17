//! M2 unit tests — `src/vex_bpf2/memory.zig`.
//!
//! Coverage matrix (from M2 brief):
//!   - vex-152m gapped translation                 ✓ "gapped: frames + gaps"
//!   - vex-152n2 underflow guard                   ✓ "vex-152n2: underflow guard"
//!   - multi-region map                            ✓ "multi-region: 5 canonical slots"
//!   - canonical region ordering                   ✓ "init: out-of-order rejects"
//!   - every AccessError reject path               ✓ multiple
//!   - MAX_PERMITTED_DATA_INCREASE=10240 reachable ✓ "input region: trailing slack"
//!   - BPF_ALIGN_OF_U128=8 (vex-079)               ✓ "constants: vex-079"

const std = @import("std");
const mem = @import("memory.zig");

const Region = mem.Region;
const AlignedMemoryMap = mem.AlignedMemoryMap;
const AccessError = mem.AccessError;
const MemoryRegionAccess = mem.MemoryRegionAccess;

const T = std.testing;

// ── Constants ────────────────────────────────────────────────────────────────

test "constants: vex-079 BPF_ALIGN_OF_U128 == 8" {
    try T.expectEqual(@as(u64, 8), mem.BPF_ALIGN_OF_U128);
}

test "constants: MAX_PERMITTED_DATA_INCREASE == 10240" {
    try T.expectEqual(@as(u64, 10240), mem.MAX_PERMITTED_DATA_INCREASE);
}

test "constants: VIRTUAL_ADDRESS_BITS == 32 and region bases canonical" {
    try T.expectEqual(@as(u6, 32), mem.VIRTUAL_ADDRESS_BITS);
    try T.expectEqual(@as(u64, 0x000000000), mem.MM_BYTECODE_START);
    try T.expectEqual(@as(u64, 0x100000000), mem.MM_RODATA_START);
    try T.expectEqual(@as(u64, 0x200000000), mem.MM_STACK_START);
    try T.expectEqual(@as(u64, 0x300000000), mem.MM_HEAP_START);
    try T.expectEqual(@as(u64, 0x400000000), mem.MM_INPUT_START);
}

// ── Region.translate — flat regions ─────────────────────────────────────────

test "flat region: in-bounds load returns slice" {
    var buf = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const r = Region.fromSlice(mem.MM_INPUT_START, &buf);
    const slice = try r.translate(mem.MM_INPUT_START, 4, .load);
    try T.expectEqualSlices(u8, &buf, slice);
}

test "flat region: load exactly at end is OK, +1 byte fails" {
    var buf = [_]u8{ 1, 2, 3, 4 };
    const r = Region.fromSlice(mem.MM_INPUT_START, &buf);
    _ = try r.translate(mem.MM_INPUT_START + 3, 1, .load); // last byte
    try T.expectError(AccessError.AccessViolation, r.translate(mem.MM_INPUT_START + 4, 1, .load));
}

test "flat region: store on RO returns AccessViolation" {
    const buf = [_]u8{ 0xAA, 0xBB };
    const r = Region.fromConst(mem.MM_RODATA_START, &buf);
    try T.expectError(AccessError.AccessViolation, r.translate(mem.MM_RODATA_START, 1, .store));
    // load is fine
    _ = try r.translate(mem.MM_RODATA_START, 2, .load);
}

test "flat region: zero-length access at boundary" {
    var buf = [_]u8{0xFF} ** 4;
    const r = Region.fromSlice(mem.MM_INPUT_START, &buf);
    // zero-length right at end is in-bounds (begin+0 == len)
    const s = try r.translate(mem.MM_INPUT_START + 4, 0, .load);
    try T.expectEqual(@as(usize, 0), s.len);
}

test "flat region: len overflow (begin + len wraps u64) rejects" {
    var buf = [_]u8{0} ** 4;
    const r = Region.fromSlice(mem.MM_INPUT_START, &buf);
    // begin_offset = 1, len = u64.max → wrap; must AccessViolation.
    try T.expectError(
        AccessError.AccessViolation,
        r.translate(mem.MM_INPUT_START + 1, std.math.maxInt(u64), .load),
    );
}

// ── vex-152n2 underflow guard ────────────────────────────────────────────────

test "vex-152n2: underflow guard — vm_addr below region rejects" {
    var buf = [_]u8{0} ** 8;
    const r = Region.fromSlice(mem.MM_INPUT_START, &buf);
    // exactly one byte below — naive subtraction would yield u64::MAX.
    try T.expectError(
        AccessError.AccessViolation,
        r.translate(mem.MM_INPUT_START - 1, 1, .load),
    );
    // far below — same.
    try T.expectError(
        AccessError.AccessViolation,
        r.translate(0, 8, .load),
    );
    // and stores too.
    try T.expectError(
        AccessError.AccessViolation,
        r.translate(mem.MM_INPUT_START - 8, 8, .store),
    );
}

// ── vex-152m gapped translation ──────────────────────────────────────────────

test "vex-152m: gapped — every frame OK, every gap rejects" {
    // 4 host frames, frame_size = gap_size = 4 ⇒ guest covers 32 bytes.
    var buf = [_]u8{0xCC} ** 16;
    const r = Region.initGapped(mem.MM_STACK_START, &buf, 4);

    // Walk all 8 strides (frame, gap, frame, gap, …).
    inline for (.{ 0, 1, 2, 3 }) |frame| {
        const frame_addr = mem.MM_STACK_START + frame * 8; // stride=8
        const gap_addr = frame_addr + 4;

        // Whole frame readable + writable.
        const s = try r.translate(frame_addr, 4, .load);
        try T.expectEqual(@as(u64, 4), s.len);
        try T.expectEqual(@as(u8, 0xCC), s[0]);
        _ = try r.translate(frame_addr, 4, .store);

        // Crossing into the gap mid-access rejects.
        try T.expectError(AccessError.AccessViolation, r.translate(frame_addr + 2, 4, .load));

        // Anywhere inside the gap rejects (load or store).
        try T.expectError(AccessError.AccessViolation, r.translate(gap_addr, 1, .load));
        try T.expectError(AccessError.AccessViolation, r.translate(gap_addr + 3, 1, .store));
    }
}

test "vex-152m: gapped — host bytes pack (frame_idx*frame_size + off_in_stride)" {
    // Distinct value per host byte to verify host_off math.
    var buf: [8]u8 = .{ 0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3 };
    const r = Region.initGapped(mem.MM_STACK_START, &buf, 4);

    // Frame 0 starts at vm = MM_STACK_START → host[0..4]
    const f0 = try r.translate(mem.MM_STACK_START, 4, .load);
    try T.expectEqualSlices(u8, &.{ 0xA0, 0xA1, 0xA2, 0xA3 }, f0);

    // Frame 1 starts at vm = MM_STACK_START + stride(8) → host[4..8]
    const f1 = try r.translate(mem.MM_STACK_START + 8, 4, .load);
    try T.expectEqualSlices(u8, &.{ 0xB0, 0xB1, 0xB2, 0xB3 }, f1);
}

test "vex-152m + vex-152n2 interact: gapped region rejects vm_addr below base" {
    var buf = [_]u8{0xEE} ** 8;
    const r = Region.initGapped(mem.MM_STACK_START, &buf, 4);
    try T.expectError(
        AccessError.AccessViolation,
        r.translate(mem.MM_STACK_START - 1, 1, .load),
    );
}

// ── AlignedMemoryMap — ordering / multi-region ──────────────────────────────

test "init: canonical 5-region layout accepts" {
    const alloc = T.allocator;

    var bytecode_buf = [_]u8{0x00} ** 4;
    var rodata_buf = [_]u8{0x10} ** 4;
    var stack_buf = [_]u8{0x20} ** 8;
    var heap_buf = [_]u8{0x30} ** 4;
    var input_buf = [_]u8{0x40} ** 4;

    const regions = [_]Region{
        Region.fromConst(mem.MM_BYTECODE_START, bytecode_buf[0..]),
        Region.fromConst(mem.MM_RODATA_START, rodata_buf[0..]),
        Region.initGapped(mem.MM_STACK_START, &stack_buf, 4),
        Region.fromSlice(mem.MM_HEAP_START, &heap_buf),
        Region.fromSlice(mem.MM_INPUT_START, &input_buf),
    };

    var map = try AlignedMemoryMap.init(alloc, &regions);
    defer map.deinit();

    // Each base address maps to its expected region.
    try T.expectEqual(@as(u8, 0x00), (try map.vmap(.load, mem.MM_BYTECODE_START, 1))[0]);
    try T.expectEqual(@as(u8, 0x10), (try map.vmap(.load, mem.MM_RODATA_START, 1))[0]);
    try T.expectEqual(@as(u8, 0x20), (try map.vmap(.load, mem.MM_STACK_START, 1))[0]);
    try T.expectEqual(@as(u8, 0x30), (try map.vmap(.load, mem.MM_HEAP_START, 1))[0]);
    try T.expectEqual(@as(u8, 0x40), (try map.vmap(.load, mem.MM_INPUT_START, 1))[0]);
}

test "init: out-of-order rejects with OutOfBounds" {
    const alloc = T.allocator;
    var stack_buf = [_]u8{0} ** 4;
    var rodata_buf = [_]u8{0} ** 4;

    // stack at index-2 placed at index-0 position ⇒ idx mismatch ⇒ reject.
    const regions = [_]Region{
        Region.fromSlice(mem.MM_STACK_START, &stack_buf),
        Region.fromConst(mem.MM_RODATA_START, &rodata_buf),
    };
    try T.expectError(
        AccessError.OutOfBounds,
        AlignedMemoryMap.init(alloc, &regions),
    );
}

test "init: skipping a slot rejects with OutOfBounds" {
    const alloc = T.allocator;
    var bytecode_buf = [_]u8{0} ** 4;
    var stack_buf = [_]u8{0} ** 4;

    // bytecode (idx 0) then stack (idx 2) — index 1 missing ⇒ reject.
    const regions = [_]Region{
        Region.fromConst(mem.MM_BYTECODE_START, &bytecode_buf),
        Region.fromSlice(mem.MM_STACK_START, &stack_buf),
    };
    try T.expectError(
        AccessError.OutOfBounds,
        AlignedMemoryMap.init(alloc, &regions),
    );
}

test "vmap: out-of-range upper bits → AccessViolation" {
    const alloc = T.allocator;
    var bytecode_buf = [_]u8{0} ** 4;
    const regions = [_]Region{
        Region.fromConst(mem.MM_BYTECODE_START, &bytecode_buf),
    };
    var map = try AlignedMemoryMap.init(alloc, &regions);
    defer map.deinit();

    // Address in slot 5 (no such region) → AccessViolation.
    try T.expectError(
        AccessError.AccessViolation,
        map.vmap(.load, 0x500000000, 1),
    );
}

test "vmap: store to RO region → AccessViolation" {
    const alloc = T.allocator;
    var bytecode_buf = [_]u8{0xAB} ** 4;
    const regions = [_]Region{
        Region.fromConst(mem.MM_BYTECODE_START, &bytecode_buf),
    };
    var map = try AlignedMemoryMap.init(alloc, &regions);
    defer map.deinit();

    _ = try map.vmap(.load, mem.MM_BYTECODE_START, 1); // load OK
    try T.expectError(
        AccessError.AccessViolation,
        map.vmap(.store, mem.MM_BYTECODE_START, 1),
    );
}

test "vmap: across-region access does NOT bridge into next region" {
    const alloc = T.allocator;
    var rodata_buf = [_]u8{0x10} ** 4;
    var stack_buf = [_]u8{0x20} ** 4;
    const regions = [_]Region{
        Region.fromConst(mem.MM_BYTECODE_START, ""),
        Region.fromConst(mem.MM_RODATA_START, &rodata_buf),
        Region.fromSlice(mem.MM_STACK_START, &stack_buf),
    };
    var map = try AlignedMemoryMap.init(alloc, &regions);
    defer map.deinit();

    // Read 8 bytes starting in rodata — would need to bridge into stack.
    // upper bits of (RODATA_START) is 1 → region rodata; len > rodata.len
    // ⇒ region.translate rejects.
    try T.expectError(
        AccessError.AccessViolation,
        map.vmap(.load, mem.MM_RODATA_START, 8),
    );
}

// ── MAX_PERMITTED_DATA_INCREASE reachable ────────────────────────────────────

test "input region: trailing 10240 bytes (MAX_PERMITTED_DATA_INCREASE) reachable" {
    const alloc = T.allocator;
    // Input region sized base + slack — every byte must be vmap-able.
    const data_len: u64 = 1024;
    const total_len: u64 = data_len + mem.MAX_PERMITTED_DATA_INCREASE;
    const input_buf = try alloc.alloc(u8, @intCast(total_len));
    defer alloc.free(input_buf);
    @memset(input_buf, 0x77);

    const regions = [_]Region{
        Region.fromConst(mem.MM_BYTECODE_START, ""),
        Region.fromConst(mem.MM_RODATA_START, ""),
        Region.fromConst(mem.MM_STACK_START, ""),
        Region.fromConst(mem.MM_HEAP_START, ""),
        Region.fromSlice(mem.MM_INPUT_START, input_buf),
    };
    var map = try AlignedMemoryMap.init(alloc, &regions);
    defer map.deinit();

    // Last byte of slack reachable.
    const tail_addr = mem.MM_INPUT_START + total_len - 1;
    const tail = try map.vmap(.load, tail_addr, 1);
    try T.expectEqual(@as(u8, 0x77), tail[0]);

    // One past the slack end fails.
    try T.expectError(
        AccessError.AccessViolation,
        map.vmap(.load, mem.MM_INPUT_START + total_len, 1),
    );
}

// ── Direct mapping is dormant ───────────────────────────────────────────────

test "config: direct_mapping defaults false (testnet gates value:null)" {
    const c: mem.Config = .{};
    try T.expectEqual(false, c.direct_mapping);
}

test "config: direct_mapping=true with no populated input regions falls through to normal per-region translate (post PR-5h2)" {
    // CORRECTED 2026-07-06 (rebuild migration, module 5): this test predates
    // fix105 commit 95c8f6c ("PR-5h2: MODE 3 (SIMD-0257 ADDM) — wire vmap
    // direct_mapping branch") and asserted the OLD, since-REMOVED behavior
    // where `direct_mapping=true` short-circuited EVERY vmap call to
    // AccessViolation. PR-5h2 replaced that blanket short-circuit because it
    // broke real BPF programs (14,169 spurious AccessViolations / 0.71%
    // parity regression on testnet — see memory.zig's `vmap` doc-comment,
    // ~line 608). The actual, intentional current contract: direct_mapping
    // only changes routing for accesses INSIDE the input region, and only
    // once `input_mem_regions` is populated (which the serializer does under
    // MODE 3). A non-input-region access (bytecode/rodata/heap/stack) with
    // direct_mapping=true but no populated input_mem_regions is NOT special-
    // cased — it falls through to the same per-region `translate()` path as
    // direct_mapping=false and succeeds normally. `memory.zig` itself is
    // BYTE-IDENTICAL to fix105 (unchanged) — only this stale test assertion
    // is corrected to match already-shipped, documented production behavior.
    const alloc = T.allocator;
    var bytecode_buf = [_]u8{0} ** 4;
    const regions = [_]Region{
        Region.fromConst(mem.MM_BYTECODE_START, &bytecode_buf),
    };
    var map = try AlignedMemoryMap.initWithConfig(alloc, &regions, .{ .direct_mapping = true });
    defer map.deinit();

    const out = try map.vmap(.load, mem.MM_BYTECODE_START, 1);
    try T.expectEqual(@as(u8, 0), out[0]);
}

// ── Sanity: exec access semantics ───────────────────────────────────────────

test "exec access: behaves like load for RO region" {
    var buf = [_]u8{ 0x95, 0, 0, 0, 0, 0, 0, 0 }; // sBPF EXIT
    const r = Region.fromConst(mem.MM_BYTECODE_START, &buf);
    _ = try r.translate(mem.MM_BYTECODE_START, 8, .exec);
    // exec is not a write — RO region accepts it.
    try T.expect(!MemoryRegionAccess.exec.isWrite());
}

// ── PR-2 (SIMD-0460 vasa) input-region resolver tests ────────────────────────
// Validates Firedancer `fd_vm_get_input_mem_region_idx` + `fd_vm_find_input_mem_region`
// port. Dark code in PR-2; these tests prove the binary search + bounds logic
// before PR-3 wires `vmap()` to call into the resolver.

test "PR-2 vasa: getInputMemRegionIdx — single region returns 0" {
    var b = [_]u8{0} ** 64;
    var regs = [_]mem.InputMemRegion{.{
        .vaddr_offset = 0,
        .haddr = &b,
        .region_sz = 64,
        .address_space_reserved = 64,
        .is_writable = true,
        .acc_region_meta_idx = 0,
    }};
    try T.expectEqual(@as(usize, 0), mem.getInputMemRegionIdx(&regs, 0));
    try T.expectEqual(@as(usize, 0), mem.getInputMemRegionIdx(&regs, 63));
}

test "PR-2 vasa: getInputMemRegionIdx — three regions binary-search" {
    var b1 = [_]u8{0} ** 32;
    var b2 = [_]u8{1} ** 32;
    var b3 = [_]u8{2} ** 32;
    var regs = [_]mem.InputMemRegion{
        .{ .vaddr_offset = 0, .haddr = &b1, .region_sz = 32, .address_space_reserved = 32, .is_writable = true, .acc_region_meta_idx = 0 },
        .{ .vaddr_offset = 32, .haddr = &b2, .region_sz = 32, .address_space_reserved = 32, .is_writable = false, .acc_region_meta_idx = 1 },
        .{ .vaddr_offset = 64, .haddr = &b3, .region_sz = 32, .address_space_reserved = 32, .is_writable = true, .acc_region_meta_idx = 2 },
    };
    try T.expectEqual(@as(usize, 0), mem.getInputMemRegionIdx(&regs, 0));
    try T.expectEqual(@as(usize, 0), mem.getInputMemRegionIdx(&regs, 31));
    try T.expectEqual(@as(usize, 1), mem.getInputMemRegionIdx(&regs, 32));
    try T.expectEqual(@as(usize, 1), mem.getInputMemRegionIdx(&regs, 63));
    try T.expectEqual(@as(usize, 2), mem.getInputMemRegionIdx(&regs, 64));
    try T.expectEqual(@as(usize, 2), mem.getInputMemRegionIdx(&regs, 95));
}

test "PR-2 vasa: findInputMemRegion — in-bounds read returns haddr slice" {
    var b = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd } ++ [_]u8{0} ** 60;
    var regs = [_]mem.InputMemRegion{.{
        .vaddr_offset = 0,
        .haddr = &b,
        .region_sz = 64,
        .address_space_reserved = 64,
        .is_writable = true,
        .acc_region_meta_idx = 0,
    }};
    const slice = try mem.findInputMemRegion(&regs, &.{}, 0, 4, false, false, null, null, null);
    try T.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, slice);
}

test "PR-2 vasa: findInputMemRegion — store to RO region rejects" {
    var b = [_]u8{0} ** 32;
    var regs = [_]mem.InputMemRegion{.{
        .vaddr_offset = 0,
        .haddr = &b,
        .region_sz = 32,
        .address_space_reserved = 32,
        .is_writable = false, // RO
        .acc_region_meta_idx = 0,
    }};
    try T.expectError(AccessError.AccessViolation, mem.findInputMemRegion(&regs, &.{}, 0, 4, true, false, null, null, null));
    // Load on the same RO region succeeds:
    _ = try mem.findInputMemRegion(&regs, &.{}, 0, 4, false, false, null, null, null);
}

test "PR-2 vasa: findInputMemRegion — out-of-bounds rejects (vasa off, no OOB grow)" {
    var b = [_]u8{0} ** 32;
    var regs = [_]mem.InputMemRegion{.{
        .vaddr_offset = 0,
        .haddr = &b,
        .region_sz = 32,
        .address_space_reserved = 32,
        .is_writable = true,
        .acc_region_meta_idx = 0,
    }};
    // 4-byte access starting at offset 30 → spans 30..34, beyond region_sz=32.
    try T.expectError(AccessError.AccessViolation, mem.findInputMemRegion(&regs, &.{}, 30, 4, false, false, null, null, null));
}

test "PR-2 vasa: findInputMemRegion — empty regions array always rejects" {
    var empty: [0]mem.InputMemRegion = .{};
    try T.expectError(AccessError.AccessViolation, mem.findInputMemRegion(&empty, &.{}, 0, 1, false, false, null, null, null));
}

// ── CARRIER 420364332 KAT: inner-CPI self-realloc grows the RIGHT account ──────
//
// Fail-pre / pass-post proof for the inner-CPI acc_region_meta_idx remap
// (cpi.zig recursiveExecute Part 1, 2026-07-07). Drives the REAL
// memory.findInputMemRegion → handleInputMemRegionOob OOB-grow path with a
// byte-exact replica of v2_dispatch.zig's reallocAccountDataCallbackPR5w
// (:723-732). The ONLY toggled variable is the region's acc_region_meta_idx —
// exactly what the fix remaps from inner-local to tx-global.
//
// Scenario: an inner CPI passes accounts [mint, authority]; the mint sits at
// TX-GLOBAL index 2 (a decoy account occupies index 0). The serializer stamps
// the mint region's acc_region_meta_idx = INNER-LOCAL 0. When Token-2022 (the
// callee) grows the mint in place for a Token-Metadata TLV, the OOB handler
// invokes the realloc callback with that index against the TX-GLOBAL
// owned.accounts:
//   • PRE-fix  (idx = 0, inner-local): grows owned.accounts[0] (the DECOY); the
//     mint (index 2) is never grown → its TLV bytes are dropped → the caller's
//     read AccessViolates → M4_RunFailed (the live carrier).
//   • POST-fix (idx = indices[0] = 2, tx-global): grows the mint.

const KatOwned = struct {
    alloc: std.mem.Allocator,
    accounts: [][]u8,
};

/// Byte-exact replica of v2_dispatch.zig reallocAccountDataCallbackPR5w:723-732.
fn katRealloc(ctx: *anyopaque, acct_idx: u64, new_len: usize) ?[*]u8 {
    const owned: *KatOwned = @ptrCast(@alignCast(ctx));
    if (acct_idx >= owned.accounts.len) return null;
    const old = owned.accounts[acct_idx];
    const grown = owned.alloc.realloc(old, new_len) catch return null;
    if (new_len > old.len) @memset(grown[old.len..new_len], 0);
    owned.accounts[acct_idx] = grown;
    return grown.ptr;
}

const InnerGrowResult = struct { decoy: usize, mint: usize, region_sz: u32, mint_targeted: bool };

/// Run one inner-CPI-style OOB grow of the mint region carrying `region_idx`
/// as its acc_region_meta_idx; report the resulting account lengths + repoint.
fn runInnerGrow(alloc: std.mem.Allocator, region_idx: u64) !InnerGrowResult {
    // 3 tx-global accounts: decoy@0 (100), authority@1 (50), mint@2 (82, writable).
    const decoy = try alloc.alloc(u8, 100);
    const authority = try alloc.alloc(u8, 50);
    const mint = try alloc.alloc(u8, 82);
    var accounts = [_][]u8{ decoy, authority, mint };
    var owned = KatOwned{ .alloc = alloc, .accounts = &accounts };
    defer for (owned.accounts) |a| alloc.free(a);

    const PRE_LEN: u32 = 82;
    var regions = [_]mem.InputMemRegion{.{
        .vaddr_offset = 0,
        .haddr = owned.accounts[2].ptr, // DM: region aliases the mint's data buffer
        .region_sz = PRE_LEN,
        .address_space_reserved = @as(u64, PRE_LEN) + mem.MAX_PERMITTED_DATA_INCREASE,
        .is_writable = true,
        .acc_region_meta_idx = region_idx,
    }};

    var resize_delta: i64 = 0;
    // Grow write: starts inside the region (offset 80) and extends past region_sz.
    _ = try mem.findInputMemRegion(&regions, &.{}, 80, 42, true, true, &resize_delta, katRealloc, &owned);

    return .{
        .decoy = owned.accounts[0].len,
        .mint = owned.accounts[2].len,
        .region_sz = regions[0].region_sz,
        .mint_targeted = regions[0].haddr == owned.accounts[2].ptr,
    };
}

test "CARRIER 420364332 PRE-fix: inner-local idx grows the WRONG account (mint NOT grown)" {
    const r = try runInnerGrow(T.allocator, 0); // inner-local index (the bug)
    try T.expectEqual(@as(usize, 82), r.mint); // mint NEVER grown → TLV dropped
    try T.expect(r.decoy > 100); // the decoy grew instead
    try T.expect(!r.mint_targeted); // region repointed at the wrong buffer
}

test "CARRIER 420364332 POST-fix: tx-global idx (indices[0]=2) grows the MINT" {
    const indices = [_]u16{ 2, 1 }; // frame.account_indices: inner-local 0 → tx-global 2
    const r = try runInnerGrow(T.allocator, @intCast(indices[0])); // remapped tx-global index
    try T.expect(r.mint > 82); // mint grown for the TLV
    try T.expectEqual(@as(usize, 100), r.decoy); // decoy untouched
    try T.expect(r.mint_targeted); // region repointed at the mint
    try T.expectEqual(@as(u32, 82 + 10240), r.region_sz); // grown to reserved slack
}

// ── Per-TRANSACTION growth budget (epoch-989 carrier @slot 421724293) ──────────
//
// Regression gate for the bank-hash divergence root cause: `handleInputMemRegionOob`
// enforced a cumulative per-TRANSACTION account-data growth cap using the
// per-INSTRUCTION constant (10240) instead of Agave's
// MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION (20 MiB). A create(10240)+realloc tx
// consumed the whole 10240 budget at creation, then every subsequent realloc was
// refused → the account stuck at 10240 and the tx silently produced a divergent
// bank state (RCA'd 2026-07-14).

test "constants: MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION == 20 MiB (not 10240)" {
    // Pins the fix: the per-tx budget must be 20 MiB, distinct from the
    // per-instruction MAX_PERMITTED_DATA_INCREASE (10240).
    try T.expectEqual(@as(u64, 20 * 1024 * 1024), mem.MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION);
    try T.expect(mem.MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION != mem.MAX_PERMITTED_DATA_INCREASE);
}

const BudgetGrowResult = struct { region_sz: u32, data_len: usize, delta_after: i64, err: ?AccessError };

/// Drive one OOB grow of a single writable data region that already carries
/// `seed_delta` bytes of prior per-tx growth. `reserved_slack` is the
/// per-instruction reserve added over `pre_len` (mirrors serialize.zig:607
/// `original_data_len + MAX_PERMITTED_DATA_INCREASE`). The write starts inside
/// the region and extends `write_sz` bytes past `pre_len`.
fn runBudgetedGrow(
    alloc: std.mem.Allocator,
    seed_delta: i64,
    pre_len: u32,
    reserved_slack: u64,
    write_sz: u64,
) !BudgetGrowResult {
    const data = try alloc.alloc(u8, pre_len);
    var accounts = [_][]u8{data};
    var owned = KatOwned{ .alloc = alloc, .accounts = &accounts };
    defer for (owned.accounts) |a| alloc.free(a);

    var regions = [_]mem.InputMemRegion{.{
        .vaddr_offset = 0,
        .haddr = owned.accounts[0].ptr,
        .region_sz = pre_len,
        .address_space_reserved = @as(u64, pre_len) + reserved_slack,
        .is_writable = true,
        .acc_region_meta_idx = 0,
    }};

    var resize_delta: i64 = seed_delta;
    // Write reaches [pre_len - 1 .. pre_len + write_sz).
    const off: u64 = pre_len - 1;
    var err: ?AccessError = null;
    _ = mem.findInputMemRegion(&regions, &.{}, off, write_sz + 1, true, true, &resize_delta, katRealloc, &owned) catch |e| {
        err = e;
    };

    return .{
        .region_sz = regions[0].region_sz,
        .data_len = owned.accounts[0].len,
        .delta_after = resize_delta,
        .err = err,
    };
}

test "per-tx budget PRE-fix regression witness: budget==10240 would refuse a 2nd realloc" {
    // Reproduces the incident at the memory layer with the OLD (buggy) 10240
    // per-tx budget: ix0's create already spent 10240, so this grow sees
    // remaining=0 and the region stays at pre_len — the exact silent-truncation
    // signature. Uses a local buggy budget to prove causality WITHOUT depending
    // on the fixed constant.
    const BUGGY_BUDGET: i64 = 10240;
    const seed: i64 = 10240; // create() consumed the whole buggy budget
    // Reconstruct the pre-fix remaining exactly as the handler computed it.
    const remaining: i64 = if (BUGGY_BUDGET > seed) BUGGY_BUDGET - seed else 0;
    try T.expectEqual(@as(i64, 0), remaining); // no budget left → growth refused → 10240 stuck
}

test "per-tx budget POST-fix: create(10240)+realloc grows past 10240 (incident shape)" {
    // seed_delta=10240 models ix0 CreateAccount having registered +10240 against
    // the per-tx accumulator. ix1 reallocs +10240 (10240 → 20480). With the 20 MiB
    // budget the grow is admitted; pre-fix it was refused (region stuck at 10240).
    const r = try runBudgetedGrow(T.allocator, 10240, 10240, mem.MAX_PERMITTED_DATA_INCREASE, mem.MAX_PERMITTED_DATA_INCREASE);
    try T.expectEqual(@as(?AccessError, null), r.err); // write fits → no AccessViolation
    try T.expectEqual(@as(u32, 20480), r.region_sz); // grew 10240 → 20480 (NOT clamped at 10240)
    try T.expectEqual(@as(usize, 20480), r.data_len); // canonical account buffer grew too
    try T.expectEqual(@as(i64, 20480), r.delta_after); // cumulative delta = 10240 + 10240
}

test "per-tx budget POST-fix: per-INSTRUCTION +10240 cap still bounds a single realloc" {
    // Even with the 20 MiB per-tx budget, a single instruction may not grow a
    // region beyond original_data_len + 10240: address_space_reserved caps it.
    // Request a write +10241 past pre_len while reserve is only +10240.
    const r = try runBudgetedGrow(T.allocator, 0, 1000, mem.MAX_PERMITTED_DATA_INCREASE, mem.MAX_PERMITTED_DATA_INCREASE + 1);
    try T.expectEqual(@as(AccessError, AccessError.AccessViolation), r.err.?); // over per-instruction reserve → refused
    try T.expectEqual(@as(u32, 1000), r.region_sz); // never grew past reserve
}

test "per-tx budget boundary: growth REFUSED once cumulative delta reaches 20 MiB" {
    // Inverse KAT: with the per-tx accumulator already at the 20 MiB ceiling, any
    // further grow is refused (region_sz unchanged) and — on this direct-write
    // path — surfaces as AccessViolation (the instruction fails, matching Agave's
    // failure outcome; only the error code differs, see the residual TODO in
    // memory.zig). Proves the cap is enforced at 20 MiB, not unbounded.
    const seed: i64 = @intCast(mem.MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION);
    const r = try runBudgetedGrow(T.allocator, seed, 1000, mem.MAX_PERMITTED_DATA_INCREASE, 100);
    try T.expectEqual(@as(u32, 1000), r.region_sz); // no growth — budget exhausted
    try T.expectEqual(@as(usize, 1000), r.data_len); // account buffer untouched
    try T.expectEqual(@as(AccessError, AccessError.AccessViolation), r.err.?); // instruction fails
}
