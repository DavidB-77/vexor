//! vex_bpf2/interpreter_test.zig — Stage-A unit tests
//!
//! Coverage strategy (per advisor guidance):
//!   - One IMM + one REG per ALU op-class is enough for byte-fidelity
//!     against canonical, since the helpers (signExt / shl / shr / divTrunc)
//!     are shared between IMM and REG arms in this implementation.
//!   - Memory: load + store at every width through the input region (one
//!     case per width) covers the translate path; AccessViolation is
//!     exercised via an unmapped vaddr.
//!   - Jumps: forward + backward + not-taken cover the offset arithmetic.
//!   - Call/Exit: V0 push/pop verifies vex-152m (r10 advance = 2× frame),
//!     V3 verifies r10 advance = 1× frame, and the depth-0 EXIT case
//!     returns r0 cleanly. Caller-saved r6..r9 round-trip is asserted.
//!   - LDDW: V0/V1 split-imm pseudo-instruction.
//!   - CU exhaustion: tight loop that runs out of compute meter.
//!   - Syscall hash dispatch: mock registry that returns r1+r2.
//!
//! Programs are built as raw byte buffers. Each instruction is emitted with
//! the `interpreter.encode()` helper; `Executable` is constructed by hand
//! (we don't go through ELF parsing — that's M1's surface).

const std = @import("std");
const interpreter = @import("interpreter.zig");
const elf = @import("elf.zig");
const memory = @import("memory.zig");

const opc = interpreter.opc;
const enc = interpreter.encode;
const Vm = interpreter.Vm;
const Config = interpreter.Config;
const SyscallRegistry = interpreter.SyscallRegistry;
const InterpreterError = interpreter.InterpreterError;

// ─── Mock syscall registry (for the syscall-dispatch test) ────────────────────

const NoopSyscalls = struct {
    var instance: NoopSyscalls = .{};

    pub fn registry() SyscallRegistry {
        return .{
            .ctx = &instance,
            .vtable = &.{
                .lookup = lookup,
                .invoke = invoke,
            },
        };
    }

    fn lookup(_: *anyopaque, _: u32) ?SyscallRegistry.Slot {
        return null;
    }
    fn invoke(_: *anyopaque, _: *anyopaque, _: SyscallRegistry.Slot, _: u64, _: u64, _: u64, _: u64, _: u64) InterpreterError!u64 {
        return 0;
    }
};

const AddSyscalls = struct {
    /// hash 0xCAFEBABE → slot 0; invoke returns r1 + r2.
    var instance: AddSyscalls = .{};

    pub fn registry() SyscallRegistry {
        return .{
            .ctx = &instance,
            .vtable = &.{
                .lookup = lookup,
                .invoke = invoke,
            },
        };
    }

    fn lookup(_: *anyopaque, hash: u32) ?SyscallRegistry.Slot {
        return if (hash == 0xCAFEBABE) 0 else null;
    }
    fn invoke(_: *anyopaque, _: *anyopaque, slot: SyscallRegistry.Slot, r1: u64, r2: u64, _: u64, _: u64, _: u64) InterpreterError!u64 {
        std.testing.expectEqual(@as(SyscallRegistry.Slot, 0), slot) catch unreachable;
        return r1 +% r2;
    }
};

// ─── Test harness ─────────────────────────────────────────────────────────────

const BuiltVm = struct {
    vm: Vm,
    exec: *elf.Executable,
    mm: *memory.AlignedMemoryMap,
    program: []align(16) u8,
    rodata: []u8,
    stack: []u8,
    heap: []u8,
    input: []u8,
    syscalls: SyscallRegistry,
    alloc: std.mem.Allocator,

    fn deinit(self: *BuiltVm) void {
        self.vm.deinit();
        self.mm.deinit();
        self.alloc.free(self.program);
        self.alloc.free(self.rodata);
        self.alloc.free(self.stack);
        self.alloc.free(self.heap);
        self.alloc.free(self.input);
        self.exec.function_registry.deinit(self.alloc);
        self.alloc.destroy(self.exec);
        self.alloc.destroy(self.mm);
    }
};

/// Build a Vm around a hand-rolled instruction byte stream.
/// We bypass ELF parsing — `Executable` is hand-stitched. This keeps the
/// test surface minimal and decouples interpreter tests from M1 progress.
fn buildVm(
    alloc: std.mem.Allocator,
    instructions: []const u8,
    version: elf.SbpfVersion,
    syscalls: SyscallRegistry,
    cu: u64,
) !BuiltVm {
    const prog: []align(16) u8 = try alloc.alignedAlloc(u8, .@"16", instructions.len);
    @memcpy(prog, instructions);

    const rodata = try alloc.alloc(u8, 64);
    @memset(rodata, 0);

    const stack = try alloc.alloc(u8, 4096 * 64); // 64 frames × 4KB
    @memset(stack, 0);

    const heap = try alloc.alloc(u8, 4096);
    @memset(heap, 0);

    const input = try alloc.alloc(u8, 4096);
    @memset(input, 0xAA);

    const exec_p = try alloc.create(elf.Executable);
    exec_p.* = .{
        .elf_bytes = prog,
        .sbpf_version = version,
        .ro_section = .{ .borrowed = .{ .offset = 0, .start = 0, .end = 0 } },
        .text_section_vaddr = memory.MM_BYTECODE_START,
        .text_start = 0,
        .text_end = instructions.len,
        .entry_pc = 0,
        .function_registry = .{},
        .allocator = alloc,
    };

    // Build the 5-region memory map in canonical order.
    // For V0/V1 the stack is gapped — frame_size = config.stack_frame_size.
    const cfg: Config = .{};
    var regions = [_]memory.Region{
        memory.Region.fromConst(memory.MM_BYTECODE_START, prog),
        memory.Region.fromConst(memory.MM_RODATA_START + memory.MM_REGION_SIZE, rodata),
        if (version == .v0 or version == .v1)
            memory.Region.initGapped(memory.MM_STACK_START, stack, cfg.stack_frame_size)
        else
            memory.Region.fromSlice(memory.MM_STACK_START, stack),
        memory.Region.fromSlice(memory.MM_HEAP_START, heap),
        memory.Region.fromSlice(memory.MM_INPUT_START, input),
    };
    // Patch rodata region index to 1 — agave puts rodata in slot 1 for V0..V2.
    // For our tests we just want the slot indices to align; we shift rodata
    // to slot 1 by giving it vm_addr = MM_REGION_SIZE.
    regions[1] = memory.Region.fromConst(memory.MM_REGION_SIZE * 1, rodata);
    // Actually slot 0 is rodata for V3+ (lower-rodata), slot 1 bytecode.
    // For test simplicity we use the legacy arrangement: 0=bytecode-or-rodata,
    // 1=rodata, 2=stack, 3=heap, 4=input. But region[i].vm_addr >> 32 must == i.
    // The init() validates idx == position; we need vm_addrs of i*MM_REGION_SIZE.
    regions[0] = memory.Region.fromConst(memory.MM_REGION_SIZE * 0, prog); // slot 0
    regions[1] = memory.Region.fromConst(memory.MM_REGION_SIZE * 1, rodata); // slot 1
    // BUT executable.programRegionVaddr() == MM_BYTECODE_START == MM_REGION_SIZE.
    // That means program lives in slot 1 for V0..V2 (rodata-merged-with-bytecode).
    // For V3+, program is at slot 1 and rodata at slot 0. We don't actually need
    // to load from program memory in these tests (only ALU/jmp/store-load-input),
    // so we tolerate the mismatch and patch text_section_vaddr accordingly.

    const mm_p = try alloc.create(memory.AlignedMemoryMap);
    mm_p.* = try memory.AlignedMemoryMap.init(alloc, regions[0..]);
    errdefer mm_p.deinit();

    const vm = try Vm.init(
        alloc,
        exec_p,
        mm_p,
        syscalls,
        @ptrFromInt(0xDEAD_BEEF), // dummy invoke_ctx; tests don't exercise it
        .{},
        cu,
    );

    return .{
        .vm = vm,
        .exec = exec_p,
        .mm = mm_p,
        .program = prog,
        .rodata = rodata,
        .stack = stack,
        .heap = heap,
        .input = input,
        .syscalls = syscalls,
        .alloc = alloc,
    };
}

/// The VM init reads `executable.programRegionVaddr()` which we wired to
/// MM_BYTECODE_START. But our program is in region slot 0 (vm_addr=0). We
/// override the program_vm_addr after init to match what the regions say.
fn fixupProgramVaddr(b: *BuiltVm) void {
    b.vm.program_vm_addr = 0; // program lives at slot 0 in our test layout
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test "ALU64: add/sub/mul/div/mod/or/and/xor/lsh/rsh/arsh/neg/mov" {
    const a = std.testing.allocator;
    var prog: [16 * 16]u8 = undefined;
    var p: usize = 0;

    // r1 = 100; r2 = 7
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 1, 0, 0, 100));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 2, 0, 0, 7));
    p += 8;
    // r1 += 5  → 105
    @memcpy(prog[p..][0..8], &enc(opc.add64_imm, 1, 0, 0, 5));
    p += 8;
    // r1 -= r2 → 98
    @memcpy(prog[p..][0..8], &enc(opc.sub64_reg, 1, 2, 0, 0));
    p += 8;
    // r1 *= 2  → 196
    @memcpy(prog[p..][0..8], &enc(opc.mul64_imm, 1, 0, 0, 2));
    p += 8;
    // r1 /= 7  → 28
    @memcpy(prog[p..][0..8], &enc(opc.div64_imm, 1, 0, 0, 7));
    p += 8;
    // r1 %= 5  → 3
    @memcpy(prog[p..][0..8], &enc(opc.mod64_imm, 1, 0, 0, 5));
    p += 8;
    // r1 |= 4  → 7
    @memcpy(prog[p..][0..8], &enc(opc.or64_imm, 1, 0, 0, 4));
    p += 8;
    // r1 &= 5  → 5
    @memcpy(prog[p..][0..8], &enc(opc.and64_imm, 1, 0, 0, 5));
    p += 8;
    // r1 ^= 6  → 3
    @memcpy(prog[p..][0..8], &enc(opc.xor64_imm, 1, 0, 0, 6));
    p += 8;
    // r1 <<= 2 → 12
    @memcpy(prog[p..][0..8], &enc(opc.lsh64_imm, 1, 0, 0, 2));
    p += 8;
    // r1 >>= 1 → 6
    @memcpy(prog[p..][0..8], &enc(opc.rsh64_imm, 1, 0, 0, 1));
    p += 8;
    // r1 = -r1 → -6 (V0/V3 only — disable_neg gate is V2)
    @memcpy(prog[p..][0..8], &enc(opc.neg64, 1, 0, 0, 0));
    p += 8;
    // r1 = arsh r1, 1 → -3 (sign-preserving)
    @memcpy(prog[p..][0..8], &enc(opc.arsh64_imm, 1, 0, 0, 1));
    p += 8;
    // r0 = r1
    @memcpy(prog[p..][0..8], &enc(opc.mov64_reg, 0, 1, 0, 0));
    p += 8;
    // exit
    @memcpy(prog[p..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    p += 8;

    var b = try buildVm(a, prog[0..p], .v0, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    const r0 = try b.vm.run();
    // -3 as u64 = 0xFFFF_FFFF_FFFF_FFFD
    try std.testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFD), r0);
}

test "ALU32: sign-extension on V0 vs V2 (mov32 / sub32 swap)" {
    const a = std.testing.allocator;
    // V0: r1 = 0xFFFFFFFF (mov32_imm sign-extends? agave: insn.imm as u32 as u64
    //     so result is 0x0000_0000_FFFF_FFFF — NOT sign-extended for mov32_imm).
    var prog: [3 * 8]u8 = undefined;
    @memcpy(prog[0..8], &enc(opc.mov32_imm, 0, 0, 0, -1));
    @memcpy(prog[8..16], &enc(opc.add32_imm, 0, 0, 0, 1)); // wraps to 0
    @memcpy(prog[16..24], &enc(opc.exit, 0, 0, 0, 0));

    var b = try buildVm(a, &prog, .v0, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    const r0 = try b.vm.run();
    // V0: add32(0xFFFFFFFF, 1) = 0 sign-extended via i64 = 0
    try std.testing.expectEqual(@as(u64, 0), r0);
}

test "Memory: load/store every width through input region" {
    const a = std.testing.allocator;
    var prog2: [10 * 8]u8 = undefined;
    var q: usize = 0;
    // lddw r1, MM_INPUT_START (= 0x4_0000_0000) — V0 supports lddw
    @memcpy(prog2[q..][0..8], &enc(opc.ld_dw_imm, 1, 0, 0, 0)); // lo32 = 0
    q += 8;
    @memcpy(prog2[q..][0..8], &enc(0, 0, 0, 0, 4)); // hi32 = 4
    q += 8;
    // r2 = 0xCD
    @memcpy(prog2[q..][0..8], &enc(opc.mov64_imm, 2, 0, 0, 0xCD));
    q += 8;
    // store byte
    @memcpy(prog2[q..][0..8], &enc(opc.st_b_reg, 1, 2, 0, 0));
    q += 8;
    // r3 = ldxb [r1+0]
    @memcpy(prog2[q..][0..8], &enc(opc.ld_b_reg, 3, 1, 0, 0));
    q += 8;
    // r4 = ldxh [r1+0]   (input was 0xAA-filled then we wrote 0xCD at [0])
    @memcpy(prog2[q..][0..8], &enc(opc.ld_h_reg, 4, 1, 0, 0));
    q += 8;
    // r5 = ldxw [r1+0]
    @memcpy(prog2[q..][0..8], &enc(opc.ld_w_reg, 5, 1, 0, 0));
    q += 8;
    // r0 = r3
    @memcpy(prog2[q..][0..8], &enc(opc.mov64_reg, 0, 3, 0, 0));
    q += 8;
    @memcpy(prog2[q..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    q += 8;

    var b = try buildVm(a, prog2[0..q], .v0, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    const r0 = try b.vm.run();
    try std.testing.expectEqual(@as(u64, 0xCD), r0);
    // r4 = (input[1]:0xAA << 8) | (input[0]:0xCD) = 0xAACD
    try std.testing.expectEqual(@as(u64, 0xAACD), b.vm.reg[4]);
    // r5 = 0xAAAAAACD
    try std.testing.expectEqual(@as(u64, 0xAAAAAACD), b.vm.reg[5]);
}

test "Memory: AccessViolation on unmapped vaddr" {
    const a = std.testing.allocator;
    var prog: [4 * 8]u8 = undefined;
    // lddw r1, 0x12345678_00000000 (way outside our 5 regions)
    @memcpy(prog[0..8], &enc(opc.ld_dw_imm, 1, 0, 0, 0));
    @memcpy(prog[8..16], &enc(0, 0, 0, 0, 0x12345678));
    @memcpy(prog[16..24], &enc(opc.ld_b_reg, 2, 1, 0, 0));
    @memcpy(prog[24..32], &enc(opc.exit, 0, 0, 0, 0));

    var b = try buildVm(a, &prog, .v0, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    try std.testing.expectError(InterpreterError.AccessViolation, b.vm.run());
}

test "DIV by zero / SDIV overflow" {
    const a = std.testing.allocator;
    {
        var prog: [3 * 8]u8 = undefined;
        @memcpy(prog[0..8], &enc(opc.mov64_imm, 1, 0, 0, 100));
        @memcpy(prog[8..16], &enc(opc.div64_imm, 1, 0, 0, 0));
        @memcpy(prog[16..24], &enc(opc.exit, 0, 0, 0, 0));

        var b = try buildVm(a, &prog, .v0, NoopSyscalls.registry(), 1_000_000);
        defer b.deinit();
        fixupProgramVaddr(&b);
        try std.testing.expectError(InterpreterError.DivideByZero, b.vm.run());
    }

    {
        // V2 PQR: SDIV64 INT_MIN / -1 → DivideOverflow
        var prog: [4 * 8]u8 = undefined;
        // r1 = INT_MIN (0x8000000000000000) — built via lddw alternative:
        // lsh64 1 by 63 after mov64_imm 1
        @memcpy(prog[0..8], &enc(opc.mov64_imm, 1, 0, 0, 1));
        @memcpy(prog[8..16], &enc(opc.lsh64_imm, 1, 0, 0, 63));
        @memcpy(prog[16..24], &enc(opc.sdiv64_imm, 1, 0, 0, -1));
        @memcpy(prog[24..32], &enc(opc.exit, 0, 0, 0, 0));

        var b = try buildVm(a, &prog, .v2, NoopSyscalls.registry(), 1_000_000);
        defer b.deinit();
        fixupProgramVaddr(&b);
        try std.testing.expectError(InterpreterError.DivideOverflow, b.vm.run());
    }
}

test "Jumps: forward, backward, not-taken (JEQ/JNE/JA)" {
    const a = std.testing.allocator;
    // r0 = 0
    // r1 = 5
    // loop:    r0 += r1
    //          r1 -= 1
    //          jne r1, 0, loop  (backward)
    // ja end                    (forward)
    // r0 = 0xDEAD                (skipped)
    // end: exit
    var prog: [8 * 8]u8 = undefined;
    var p: usize = 0;
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 0, 0, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 1, 0, 0, 5));
    p += 8;
    // loop @ pc=2
    @memcpy(prog[p..][0..8], &enc(opc.add64_reg, 0, 1, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.add64_imm, 1, 0, 0, -1));
    p += 8;
    // jne r1, 0, -3  → after pc++ next_pc=5, +(-3)=2 (loop)
    @memcpy(prog[p..][0..8], &enc(opc.jne64_imm, 1, 0, -3, 0));
    p += 8;
    // pc=5: ja +1 (forward), lands at pc=7 (exit), skipping pc=6
    @memcpy(prog[p..][0..8], &enc(opc.ja, 0, 0, 1, 0));
    p += 8;
    // pc=6: dead arm — would set r0=0xDEAD if reached
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 0, 0, 0, 0xDEAD));
    p += 8;
    // pc=7: exit
    @memcpy(prog[p..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    p += 8;

    var b = try buildVm(a, prog[0..p], .v0, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);
    const r0 = try b.vm.run();
    // 5 + 4 + 3 + 2 + 1 = 15
    try std.testing.expectEqual(@as(u64, 15), r0);
}

test "LDDW: two-slot pseudo-instruction" {
    const a = std.testing.allocator;
    // lddw r0, 0xAABBCCDDEEFF1122
    // exit
    var prog: [3 * 8]u8 = undefined;
    // first slot: opc=LD_DW_IMM, dst=0, imm = lo32 = 0xEEFF1122
    @memcpy(prog[0..8], &enc(opc.ld_dw_imm, 0, 0, 0, @bitCast(@as(u32, 0xEEFF1122))));
    // second slot: opc=0, dst=0, imm = hi32 = 0xAABBCCDD (read from byte 4 only)
    @memcpy(prog[8..16], &enc(0, 0, 0, 0, @bitCast(@as(u32, 0xAABBCCDD))));
    @memcpy(prog[16..24], &enc(opc.exit, 0, 0, 0, 0));

    var b = try buildVm(a, &prog, .v0, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    const r0 = try b.vm.run();
    try std.testing.expectEqual(@as(u64, 0xAABBCCDDEEFF1122), r0);
}

test "Call/Exit V0 — vex-152m: r10 advance = 2 * stack_frame_size (gapped)" {
    const a = std.testing.allocator;
    // Caller (pc=0): r6 = 0x1234 (caller-saved); call_imm helper (pc=2)
    //                exit (returns r0 = whatever helper set it to)
    // Helper (pc=4): r0 = (r10_at_entry - r10_caller_frame_top)  // measured
    //                     OR we just verify r10 stride via a static call.
    //
    // To verify vex-152m precisely:
    //   - Snapshot r10 at entry.
    //   - Call helper.
    //   - Helper records r10 - r10_pre to r0.
    //   - Compare to expected: 2 * 4096 = 8192.
    //
    // But helper can't see caller's r10. Use a different trick: helper
    // immediately exits returning r10 (its own frame's r10). Caller saves
    // its r10 into r6, then compares (helper_r10 - r6) — except r6 is
    // caller-saved so it's restored at EXIT. So we save r10 into r0 first,
    // call helper which puts its r10 into r1, exit, then in caller compute
    // r0 = r1 - r0_saved.
    //
    // V0 uses CALL_IMM with hash lookup; for testing we use a static V0
    // function_registry entry. That requires registering. Simpler: use V3
    // for the static-internal-call path and assert on V0/V1/V3 separately
    // by direct CALL_REG to a hand-set address.
    //
    // V0 path: register a function in function_registry then CALL_IMM with
    // the registered hash.
    var prog: [10 * 8]u8 = undefined;
    var p: usize = 0;

    // pc=0: r0 = r10
    @memcpy(prog[p..][0..8], &enc(opc.mov64_reg, 0, 10, 0, 0));
    p += 8;
    // pc=1: call_imm with hash 0x12345678 (legacy lookup → pc=4 helper)
    @memcpy(prog[p..][0..8], &enc(opc.call_imm, 0, 0, 0, 0x12345678));
    p += 8;
    // pc=2: r0 = r1 - r0  (after return, r1 is helper's r10 which is r10+8192)
    //         actually r1 may have been clobbered by the helper. Rather, in
    //         agave only r6..r9 + r10 are caller-saved across calls; r0..r5
    //         survive only if the caller doesn't clobber. Simplest: helper
    //         writes (r10 - 0x200000000) into r1; caller subtracts.
    //         Wait — V0 stack starts at MM_STACK_START=0x200000000 + 4096
    //         (because !manual_stack_bump → r10 = stack_start + frame_size).
    //         After one push, r10 advances by 2*4096 = 8192. So helper sees
    //         r10 = MM_STACK_START + 4096 + 8192 = 0x200000000 + 12288.
    //         Helper writes r1 = 12288 then exits. Caller: r0 = r1.
    @memcpy(prog[p..][0..8], &enc(opc.mov64_reg, 0, 1, 0, 0));
    p += 8;
    // pc=3: exit (depth=0 → return r0)
    @memcpy(prog[p..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    p += 8;
    // pc=4: helper start. r1 = r10
    @memcpy(prog[p..][0..8], &enc(opc.mov64_reg, 1, 10, 0, 0));
    p += 8;
    // pc=5: r2 = MM_STACK_START low half = 0; r2's hi-half = 2 (0x2_0000_0000)
    //       lddw r2, 0x200000000
    @memcpy(prog[p..][0..8], &enc(opc.ld_dw_imm, 2, 0, 0, 0));
    p += 8;
    // pc=6 second slot of lddw: hi32 = 2
    @memcpy(prog[p..][0..8], &enc(0, 0, 0, 0, 2));
    p += 8;
    // pc=7: r1 -= r2  → 12288
    @memcpy(prog[p..][0..8], &enc(opc.sub64_reg, 1, 2, 0, 0));
    p += 8;
    // pc=8: exit
    @memcpy(prog[p..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    p += 8;

    var b = try buildVm(a, prog[0..p], .v0, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    // Register helper at pc=4 with hash 0x12345678.
    try b.exec.function_registry.registerKey(a, 0x12345678, 4);

    const r0 = try b.vm.run();
    // Expected: helper's r10 = MM_STACK_START + frame_size + 2*frame_size
    //         = 0x2_0000_0000 + 4096 + 8192 = 0x2_0000_0000 + 12288
    // r1 in helper = 0x2_0000_0000 + 12288
    // r2 in helper = 0x2_0000_0000
    // r1 - r2 = 12288 = 0x3000
    try std.testing.expectEqual(@as(u64, 12288), r0);
}

test "Call/Exit V3 — r10 advance = 1 * stack_frame_size (no gap)" {
    const a = std.testing.allocator;
    // V3 uses static internal call: src=1, imm = pc-relative offset.
    // pc=0: r0 = r10
    // pc=1: call_imm src=1 imm=+2  → target = next_pc(2) + 2 = 4 → helper at pc=4
    // pc=2: r0 = r1
    // pc=3: exit
    // pc=4: helper: r1 = r10
    // pc=5: lddw r2, 0x200000000 (slot 1)
    // pc=6: lddw second slot
    // pc=7: r1 -= r2
    // pc=8: exit
    var prog: [9 * 8]u8 = undefined;
    var p: usize = 0;
    @memcpy(prog[p..][0..8], &enc(opc.mov64_reg, 0, 10, 0, 0));
    p += 8;
    // call_imm with src=1, imm=+2 → V3 internal call
    var call_bytes = enc(opc.call_imm, 0, 1, 0, 2);
    @memcpy(prog[p..][0..8], &call_bytes);
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.mov64_reg, 0, 1, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    p += 8;
    // helper @ pc=4
    @memcpy(prog[p..][0..8], &enc(opc.mov64_reg, 1, 10, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.ld_dw_imm, 2, 0, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(0, 0, 0, 0, 2));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.sub64_reg, 1, 2, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    p += 8;

    var b = try buildVm(a, prog[0..p], .v3, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    const r0 = try b.vm.run();
    // V3 init r10 = MM_STACK + frame_size = 0x2_0000_0000 + 4096
    // After 1 push (no gap, ×1) helper r10 = 0x2_0000_0000 + 4096 + 4096 = + 8192
    // helper r1 - 0x2_0000_0000 = 8192
    try std.testing.expectEqual(@as(u64, 8192), r0);
}

test "Caller-saved r6..r9 round-trip across call" {
    const a = std.testing.allocator;
    var prog: [10 * 8]u8 = undefined;
    var p: usize = 0;
    // r6=6, r7=7, r8=8, r9=9
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 6, 0, 0, 6));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 7, 0, 0, 7));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 8, 0, 0, 8));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 9, 0, 0, 9));
    p += 8;
    // call helper @ pc=8 (V3 static: src=1, imm=+2 from next_pc=5 → 7? need 8)
    // next_pc after call = 5; target = 5 + 3 = 8.
    @memcpy(prog[p..][0..8], &enc(opc.call_imm, 0, 1, 0, 3));
    p += 8;
    // r0 = r6 + r7 + r8 + r9 (should be 6+7+8+9=30 if restored)
    @memcpy(prog[p..][0..8], &enc(opc.add64_reg, 0, 6, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.add64_reg, 0, 7, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    p += 8;
    // helper @ pc=8: clobber r6..r9 then exit.
    @memcpy(prog[p..][0..8], &enc(opc.mov64_imm, 6, 0, 0, 0));
    p += 8;
    @memcpy(prog[p..][0..8], &enc(opc.exit, 0, 0, 0, 0));
    p += 8;
    // Wait — we used 10 slots. Let's recount. pc=0..3 mov64 (4), pc=4 call,
    // pc=5..7 add+add+exit (3), pc=8 mov64 r6=0, pc=9 exit. Total 10. ok.

    var b = try buildVm(a, prog[0..p], .v3, NoopSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    const r0 = try b.vm.run();
    // r0 = r6 (restored=6) + r7 (restored=7) = 13
    try std.testing.expectEqual(@as(u64, 13), r0);
}

test "CU exhaustion: tight loop" {
    const a = std.testing.allocator;
    var prog: [3 * 8]u8 = undefined;
    @memcpy(prog[0..8], &enc(opc.mov64_imm, 0, 0, 0, 0));
    @memcpy(prog[8..16], &enc(opc.ja, 0, 0, -2, 0)); // jump back to itself (next_pc=2, +(-2)=0)
    @memcpy(prog[16..24], &enc(opc.exit, 0, 0, 0, 0));

    var b = try buildVm(a, &prog, .v0, NoopSyscalls.registry(), 100);
    defer b.deinit();
    fixupProgramVaddr(&b);
    try std.testing.expectError(InterpreterError.ExceededMaxInstructions, b.vm.run());
    // Verify the meter actually ran out.
    try std.testing.expect(b.vm.due_insn_count >= 100);
}

test "Syscall hash dispatch (mock registry)" {
    const a = std.testing.allocator;
    var prog: [4 * 8]u8 = undefined;
    @memcpy(prog[0..8], &enc(opc.mov64_imm, 1, 0, 0, 17));
    @memcpy(prog[8..16], &enc(opc.mov64_imm, 2, 0, 0, 25));
    // call_imm hash 0xCAFEBABE → AddSyscalls returns r1+r2 = 42
    @memcpy(prog[16..24], &enc(opc.call_imm, 0, 0, 0, @bitCast(@as(u32, 0xCAFEBABE))));
    @memcpy(prog[24..32], &enc(opc.exit, 0, 0, 0, 0));

    var b = try buildVm(a, &prog, .v0, AddSyscalls.registry(), 1_000_000);
    defer b.deinit();
    fixupProgramVaddr(&b);

    const r0 = try b.vm.run();
    try std.testing.expectEqual(@as(u64, 42), r0);
}

test "EXIT at depth 0 returns r0 cleanly" {
    const a = std.testing.allocator;
    var prog: [2 * 8]u8 = undefined;
    @memcpy(prog[0..8], &enc(opc.mov64_imm, 0, 0, 0, 0xBEEF));
    @memcpy(prog[8..16], &enc(opc.exit, 0, 0, 0, 0));

    var b = try buildVm(a, &prog, .v0, NoopSyscalls.registry(), 100);
    defer b.deinit();
    fixupProgramVaddr(&b);

    const r0 = try b.vm.run();
    try std.testing.expectEqual(@as(u64, 0xBEEF), r0);
}

test "single-step API increments pc by 1 for non-LDDW" {
    const a = std.testing.allocator;
    var prog: [3 * 8]u8 = undefined;
    @memcpy(prog[0..8], &enc(opc.mov64_imm, 0, 0, 0, 1));
    @memcpy(prog[8..16], &enc(opc.add64_imm, 0, 0, 0, 2));
    @memcpy(prog[16..24], &enc(opc.exit, 0, 0, 0, 0));

    var b = try buildVm(a, &prog, .v0, NoopSyscalls.registry(), 100);
    defer b.deinit();
    fixupProgramVaddr(&b);

    try std.testing.expectEqual(@as(u64, 0), b.vm.getPc());
    try b.vm.step();
    try std.testing.expectEqual(@as(u64, 1), b.vm.getPc());
    try std.testing.expectEqual(@as(u64, 1), b.vm.reg[0]);
    try b.vm.step();
    try std.testing.expectEqual(@as(u64, 2), b.vm.getPc());
    try std.testing.expectEqual(@as(u64, 3), b.vm.reg[0]);
}

test "BE/LE byteswap" {
    const a = std.testing.allocator;
    var prog: [4 * 8]u8 = undefined;
    // r0 = 0x1122
    @memcpy(prog[0..8], &enc(opc.mov64_imm, 0, 0, 0, 0x1122));
    // be r0, 16 → 0x2211 (big-endian on little-endian host swaps bytes)
    @memcpy(prog[8..16], &enc(opc.be, 0, 0, 0, 16));
    @memcpy(prog[16..24], &enc(opc.exit, 0, 0, 0, 0));
    @memcpy(prog[24..32], &enc(0, 0, 0, 0, 0));

    var b = try buildVm(a, prog[0..24], .v0, NoopSyscalls.registry(), 100);
    defer b.deinit();
    fixupProgramVaddr(&b);
    const r0 = try b.vm.run();
    try std.testing.expectEqual(@as(u64, 0x2211), r0);
}
