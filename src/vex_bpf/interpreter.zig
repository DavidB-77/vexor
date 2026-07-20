//! Vexor SBPF Interpreter — compatibility shim
//!
//! The canonical implementation lives in vm.zig (full V1/V2/V3 support).
//! This file re-exports the symbols that the rest of the codebase relies on,
//! providing backward-compatible BpfVm/VmContext names.
//!
//! New code should import vm.zig directly.

const std = @import("std");
const vm = @import("vm.zig");

// ── Re-export BPF execution types ────────────────────────────────────────────
pub const elf_loader = @import("elf_loader.zig");
pub const vm_syscalls = @import("vm_syscalls.zig"); // carrier #16 probe export
pub const sbpf_executor = @import("sbpf_executor.zig");
pub const bpf_program_cache = @import("bpf_program_cache.zig");
pub const ElfLoader = elf_loader.ElfLoader;
pub const LoadedProgram = elf_loader.LoadedProgram;
pub const SbpfExecutor = sbpf_executor.SbpfExecutor;
pub const AccountEntry = sbpf_executor.AccountEntry;
pub const AccountMutation = sbpf_executor.AccountMutation;
// FIX-1a (2026-06-10, task #65): top-level run classification (genuine
// program error vs Vexor plumbing) read by replay_stage.executeBpfProgramCore.
pub const TopLevelRunOutcome = sbpf_executor.TopLevelRunOutcome;
pub const BpfProgramCache = bpf_program_cache.BpfProgramCache;

// ── Re-export core VM types ──────────────────────────────────────────────────
pub const VmError = vm.VmError;
pub const SyscallFn = vm.SyscallFn;
pub const MemRegion = vm.MemRegion;
pub const MemoryMap = vm.MemoryMap;
pub const Instruction = vm.Instruction;
pub const SbpfVersion = vm.SbpfVersion;

// Region base addresses (legacy names used by syscalls.zig)
pub const VM_PROG_START: u64 = vm.VM_RODATA_START;
pub const VM_STACK_START: u64 = vm.VM_STACK_START;
pub const VM_HEAP_START: u64 = vm.VM_HEAP_START;
pub const VM_INPUT_START: u64 = vm.VM_INPUT_START;

// Constants
pub const STACK_FRAME_SIZE: usize = vm.STACK_FRAME_SIZE;
pub const MAX_CALL_DEPTH: usize = vm.MAX_CALL_DEPTH;
pub const STACK_SIZE: usize = vm.STACK_SIZE;
pub const HEAP_SIZE: usize = vm.HEAP_SIZE;
pub const MAX_INSNS: u64 = vm.MAX_INSNS;

// ── Legacy alias: VmContext = VmState ─────────────────────────────────────────
pub const VmContext = vm.VmState;

// ── Legacy BpfVm wrapper ──────────────────────────────────────────────────────
// sbpf_executor.zig calls BpfVm.execute(ctx, text_bytes, entry_pc).
// vm.zig exposes step()/run() which take []const Instruction.
// This shim bridges the raw-bytes API to the new typed API.
pub const BpfVm = struct {
    /// Execute BPF bytecode from entry_pc.
    /// Returns r0 on clean exit; returns error.Halted on normal program exit
    /// (caller checks ctx.regs[0]) or another VmError on fault.
    pub fn execute(
        ctx: *vm.VmState,
        text_bytes: []const u8,
        entry_pc: u64,
    ) vm.VmError!u64 {
        if (text_bytes.len % 8 != 0) return vm.VmError.InvalidInstruction;
        ctx.pc = entry_pc;
        ctx.insn_ctr = 0;
        ctx.result = .running;

        // Reinterpret raw bytes as typed instructions.
        // std.mem.bytesAsSlice requires slice alignment; force align(1).
        const n = text_bytes.len / 8;
        const insns_ptr: [*]align(1) const vm.Instruction = @ptrCast(text_bytes.ptr);
        const insns: []align(1) const vm.Instruction = insns_ptr[0..n];

        // Drive step() manually to match legacy error-on-halt contract.
        while (true) {
            if (ctx.insn_ctr >= ctx.compute_meter) {
                return vm.VmError.InstructionLimitExceeded;
            }
            ctx.insn_ctr += 1;
            vm.step(ctx, insns) catch |err| switch (err) {
                vm.VmError.Halted => return ctx.regs[0],
                else => return err,
            };
        }
    }
};

// ── Insn — legacy raw-byte instruction view used in older tests ───────────────
pub const Insn = extern struct {
    opcode: u8,
    regs: u8, // low nibble = dst, high nibble = src
    offset: i16,
    imm: i32,

    pub fn dst(self: Insn) u4 {
        return @truncate(self.regs & 0x0f);
    }
    pub fn src(self: Insn) u4 {
        return @truncate(self.regs >> 4);
    }
};
comptime {
    std.debug.assert(@sizeOf(Insn) == 8);
}

// ── Tests (legacy — kept to avoid breaking existing test runs) ─────────────────

test "interpreter: mov64 + exit" {
    const text = [_]u8{
        0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r0, 42
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    };
    var inp: [1]u8 = .{0};
    var ctx = try vm.VmState.init(std.testing.allocator, &[_]u8{}, vm.VM_RODATA_START, &inp, .v0, 0);
    defer ctx.deinit();
    const r = BpfVm.execute(&ctx, &text, 0) catch |e| blk: {
        if (e == error.Halted) break :blk ctx.regs[0];
        return e;
    };
    try std.testing.expectEqual(@as(u64, 42), r);
}

test "interpreter: memory translate roundtrip" {
    var inp: [8]u8 = .{ 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44 };
    var ctx = try vm.VmState.init(std.testing.allocator, &[_]u8{}, vm.VM_RODATA_START, &inp, .v0, 0);
    defer ctx.deinit();
    // Read from input region
    const val = try ctx.memory_map.load(u8, VM_INPUT_START + 0);
    try std.testing.expectEqual(@as(u8, 0xDE), val);
    const val3 = try ctx.memory_map.load(u8, VM_INPUT_START + 3);
    try std.testing.expectEqual(@as(u8, 0xEF), val3);
    // Write through store
    try ctx.memory_map.store(u8, VM_INPUT_START + 4, 0xFF);
    try std.testing.expectEqual(@as(u8, 0xFF), inp[4]);
}
