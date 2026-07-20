//! Vexor sBPF VM — full V1/V2/V3 interpreter
//!
//! Self-contained sBPF virtual machine covering opcode sets defined by:
//!   SIMD-0166 (sBPF v1 — dynamic stack frames)
//!   SIMD-0173 (sBPF v2 — instruction encoding improvements)
//!   SIMD-0174 (sBPF v2 — arithmetic improvements, PQR instructions)
//!   SIMD-0178 (sBPF v3 — static syscalls)
//!   SIMD-0179 (sBPF v3 — stricter verification)
//!   SIMD-0189 (sBPF v3 — stricter ELF headers)
//!
//! @prov:vm.module-map — full per-section upstream line-map (Sig interpreter.zig,
//! Firedancer fd_sbpf_interp.c, Agave rbpf interpreter.rs) in PROVENANCE.md.

const std = @import("std");

// ── Virtual address region bases (matches Agave MM_* constants) ─────────────── @prov:vm.module-map
pub const VM_BYTECODE_START: u64 = 0x000000000; // v3 only: separate text region
pub const VM_RODATA_START:   u64 = 0x100000000; // rodata (+ text until v3)
pub const VM_STACK_START:    u64 = 0x200000000;
pub const VM_HEAP_START:     u64 = 0x300000000;
pub const VM_INPUT_START:    u64 = 0x400000000;

pub const VIRTUAL_ADDRESS_BITS: u6 = 32;

// ── Stack / heap constants ────────────────────────────────────────────────────
pub const STACK_FRAME_SIZE:  usize = 4096;
pub const MAX_CALL_DEPTH:    usize = 64;
pub const STACK_SIZE:        usize = STACK_FRAME_SIZE * MAX_CALL_DEPTH;
pub const HEAP_SIZE:         usize = 256 * 1024;
pub const MAX_INSNS:         u64   = 1_400_000;

// ── sBPF version ────────────────────────────────────────────────────────────── @prov:vm.module-map
pub const SbpfVersion = enum(u32) {
    v0,        // legacy
    v1,        // SIMD-0166: dynamic stack frames
    v2,        // SIMD-0173/0174: encoding + arithmetic
    v3,        // SIMD-0178/0179/0189: static syscalls, strict headers
    _,

    pub fn enableDynamicStackFrames(v: SbpfVersion) bool { return @intFromEnum(v) >= 1; }
    /// Canonical `manual_stack_frame_bump`: ONLY v1/v2 manage the frame pointer
    /// manually — r10 starts at the TOP of the stack (MM_STACK_START + stack_len)
    /// and the program bumps it DOWN. v0/v3 use a fixed first-frame offset.
    /// @prov:vm.module-map — distinct from enableDynamicStackFrames (v>=1)
    /// which wrongly includes v3.
    pub fn manualStackFrameBump(v: SbpfVersion) bool { return v == .v1 or v == .v2; }
    pub fn enablePqr(v: SbpfVersion)                bool { return @intFromEnum(v) >= 2; }
    pub fn callRegUsesSrcReg(v: SbpfVersion)         bool { return @intFromEnum(v) >= 2; }
    pub fn disableLddw(v: SbpfVersion)               bool { return @intFromEnum(v) >= 2; }
    pub fn enableStaticSyscalls(v: SbpfVersion)      bool { return @intFromEnum(v) >= 3; }
    pub fn swapSubImmOperands(v: SbpfVersion)        bool { return @intFromEnum(v) >= 2; }
    pub fn explicitSignExtend(v: SbpfVersion)        bool { return @intFromEnum(v) >= 2; }
    pub fn enableLowerBytecodeVaddr(v: SbpfVersion)  bool { return @intFromEnum(v) >= 3; }

    /// Compute target PC for call_imm: relative in v3, absolute in v0/v1/v2.
    /// @prov:vm.module-map
    pub fn callTargetPc(v: SbpfVersion, pc: u64, imm: u32) u64 {
        if (v.enableStaticSyscalls()) {
            // v3: pc + imm + 1 (relative)
            const delta: i64 = @as(i32, @bitCast(imm));
            return @bitCast(@as(i64, @intCast(pc)) +| delta +| 1);
        }
        // v0/v1/v2: imm is the absolute function key resolved by the function registry
        return imm;
    }
};

// ── Instruction layout (8 bytes packed, little-endian on wire) ──────────────── @prov:vm.module-map
pub const Instruction = packed struct(u64) {
    opcode: u8,
    dst:    u4,
    src:    u4,
    offset: i16,
    imm:    u32,

    /// Decode a raw 8-byte LE value into an Instruction.
    pub fn decode(raw: u64) Instruction {
        return @bitCast(raw);
    }
};

comptime { std.debug.assert(@sizeOf(Instruction) == 8); }

// ── Opcode bit-field constants ──────────────────────────────────────────────── @prov:vm.module-map
pub const CLS_LD:    u8 = 0x00; // load immediate
pub const CLS_LDX:   u8 = 0x01; // load from register
pub const CLS_ST:    u8 = 0x02; // store immediate
pub const CLS_STX:   u8 = 0x03; // store from register
pub const CLS_ALU32: u8 = 0x04; // 32-bit ALU
pub const CLS_JMP:   u8 = 0x05; // 64-bit jump / control flow
pub const CLS_PQR:   u8 = 0x06; // product-quotient-remainder (v2)
pub const CLS_ALU64: u8 = 0x07; // 64-bit ALU

pub const SRC_IMM: u8 = 0x00;
pub const SRC_REG: u8 = 0x08;

// size modifiers
pub const SZ_W:  u8 = 0x00; // 4 bytes
pub const SZ_H:  u8 = 0x08; // 2 bytes
pub const SZ_B:  u8 = 0x10; // 1 byte
pub const SZ_DW: u8 = 0x18; // 8 bytes

// memory addressing mode. @prov:vm.module-map
// All standard sBPF LDX/ST/STX opcodes carry MEM=0x60 in bits 5-6.
// Pre-2026-04-28 the dispatch cases at CLS_LDX/CLS_ST/CLS_STX omitted this
// bit, so `opc & 0xf8` (which preserves bits 3-7) never matched any case
// → every standard memory op returned VmError.InvalidInstruction. The
// `vm: memory store and load` test in this file failed with that bug.
// Fix: include MEM in case literals so 0x61/0x69/0x71/0x79 etc. dispatch.
pub const MEM: u8 = 0x60;
// v2 renamed memory instruction classes
pub const SZ_1B: u8 = 0x20;
pub const SZ_2B: u8 = 0x30;
pub const SZ_4B: u8 = 0x80;
pub const SZ_8B: u8 = 0x90;

// ALU operation codes
pub const ALU_ADD:  u8 = 0x00;
pub const ALU_SUB:  u8 = 0x10;
pub const ALU_MUL:  u8 = 0x20;
pub const ALU_DIV:  u8 = 0x30;
pub const ALU_OR:   u8 = 0x40;
pub const ALU_AND:  u8 = 0x50;
pub const ALU_LSH:  u8 = 0x60;
pub const ALU_RSH:  u8 = 0x70;
pub const ALU_NEG:  u8 = 0x80;
pub const ALU_MOD:  u8 = 0x90;
pub const ALU_XOR:  u8 = 0xa0;
pub const ALU_MOV:  u8 = 0xb0;
pub const ALU_ARSH: u8 = 0xc0;
pub const ALU_END:  u8 = 0xd0;
pub const ALU_HOR:  u8 = 0xf0; // high-or (v1+): dst |= imm << 32

// PQR operation codes (v2). @prov:vm.module-map
pub const PQR_UHMUL: u8 = 0x20;
pub const PQR_UDIV:  u8 = 0x40;
pub const PQR_UREM:  u8 = 0x60;
pub const PQR_LMUL:  u8 = 0x80;
pub const PQR_SHMUL: u8 = 0xa0;
pub const PQR_SDIV:  u8 = 0xc0;
pub const PQR_SREM:  u8 = 0xe0;
pub const PQR_64BIT: u8 = 0x08; // set in opcode when 64-bit PQR

// JMP operation codes
pub const JMP_JA:   u8 = 0x00;
pub const JMP_JEQ:  u8 = 0x10;
pub const JMP_JGT:  u8 = 0x20;
pub const JMP_JGE:  u8 = 0x30;
pub const JMP_JSET: u8 = 0x40;
pub const JMP_JNE:  u8 = 0x50;
pub const JMP_JSGT: u8 = 0x60;
pub const JMP_JSGE: u8 = 0x70;
pub const JMP_CALL: u8 = 0x80;
pub const JMP_EXIT: u8 = 0x90; // also: v3 syscall when src=0
pub const JMP_JLT:  u8 = 0xa0;
pub const JMP_JLE:  u8 = 0xb0;
pub const JMP_JSLT: u8 = 0xc0;
pub const JMP_JSLE: u8 = 0xd0;

// ── VM errors ─────────────────────────────────────────────────────────────────
pub const VmError = error{
    InvalidInstruction,
    DivisionByZero,
    DivideOverflow,
    AccessViolation,
    InvalidMemoryAccess,
    StackOverflow,
    CallDepthExceeded,
    InstructionLimitExceeded,
    CallOutsideTextSegment,
    InvalidSyscall,
    SyscallFailed,
    Halted,
    OutOfMemory,
    CpiRequired,
};

// ── Syscall function signature ────────────────────────────────────────────────
// r1..r5 = arguments, r0 = return value
pub const SyscallFn = *const fn (
    ctx: *VmState,
    r1: u64, r2: u64, r3: u64, r4: u64, r5: u64,
) VmError!u64;

// ── Memory region ───────────────────────────────────────────────────────────── @prov:vm.module-map
//
// A single contiguous virtual-address window backed by a host slice.
// Supports both const (read-only) and mutable regions.
pub const MemRegion = struct {
    vm_start:  u64,
    vm_end:    u64,   // exclusive
    host_ptr:  [*]u8,
    writable:  bool,

    pub fn fromSlice(vm_start: u64, buf: []u8, writable: bool) MemRegion {
        return .{
            .vm_start = vm_start,
            .vm_end   = vm_start + buf.len,
            .host_ptr = buf.ptr,
            .writable = writable,
        };
    }

    pub fn fromConst(vm_start: u64, buf: []const u8) MemRegion {
        return .{
            .vm_start = vm_start,
            .vm_end   = vm_start + buf.len,
            .host_ptr = @constCast(buf.ptr),
            .writable = false,
        };
    }

    /// Translate a VM address+length into a host slice.
    /// Returns null if the range is not fully covered by this region.
    pub fn translate(self: MemRegion, vm_addr: u64, len: u64, write: bool) ?[]u8 {
        if (vm_addr < self.vm_start) return null;
        const end = vm_addr +% len;
        if (end > self.vm_end or end < vm_addr) return null;
        if (write and !self.writable) return null;
        const off = vm_addr - self.vm_start;
        return self.host_ptr[off .. off + len];
    }
};

// ── MemoryMap (tagged union, aligned vs. unaligned) ─────────────────────────── @prov:vm.module-map
//
// We use a simple "aligned" scheme: the upper 32 bits of a VM address select
// the region index (1-based). Region 0 is invalid; region 1 = rodata, 2 = stack,
// 3 = heap, 4 = input.  For v3 with enableLowerBytecodeVaddr, region 0 is used
// for the bytecode segment.
//
// Unaligned mapping (arbitrary region order) is supported via a sorted linear
// scan; we default to aligned since Solana programs always use standard layout.
pub const MemoryMap = struct {
    regions: [5]MemRegion,   // index 0 = bytecode(v3), 1 = rodata, 2 = stack, 3 = heap, 4 = input
    n_regions: u3,           // number of valid regions (typically 4 or 5)
    version: SbpfVersion,

    pub fn init(
        rodata:       []const u8,
        rodata_vaddr: u64,
        stack:        []u8,
        heap:         []u8,
        input:        []u8,
        version:      SbpfVersion,
    ) MemoryMap {
        // @prov:vm.module-map
        var mm: MemoryMap = .{
            .regions   = undefined,
            .n_regions = 0,
            .version   = version,
        };
        if (version.enableLowerBytecodeVaddr()) {
            // v3: bytecode region at 0x000000000 (read-only, handled separately)
            // For now leave slot 0 as rodata — caller supplies a combined slice.
            mm.regions[0] = MemRegion.fromConst(VM_BYTECODE_START, &[_]u8{});
            mm.n_regions = 5;
        } else {
            mm.n_regions = 4;
        }
        // r75-bug-class-b-2026-05-06: rodata mapped at caller-supplied vaddr,
        // not hardcoded VM_RODATA_START. V0/V1/V2 lenient ELFs need
        // VM_RODATA_START + lowest_sh_addr (e.g. 0x100000120 for HistoryJT)
        // so vmaddr-to-host-buf translation cancels the linker's base_vaddr.
        // V3 strict has base_vaddr=0 → rodata_vaddr == VM_RODATA_START. Mirrors
        // vex_bpf2 commit 21298a3 elf.zig:Executable.rodataVaddr().
        mm.regions[1] = MemRegion.fromConst(rodata_vaddr, rodata);
        mm.regions[2] = MemRegion.fromSlice(VM_STACK_START, stack, true);
        mm.regions[3] = MemRegion.fromSlice(VM_HEAP_START,  heap,  true);
        mm.regions[4] = MemRegion.fromSlice(VM_INPUT_START, input, true);
        return mm;
    }

    /// Translate a VM address range to a host slice.
    /// @prov:vm.module-map
    pub fn translate(self: *const MemoryMap, vm_addr: u64, len: u64, write: bool) VmError![]u8 {
        if (len == 0) return @as([*]u8, undefined)[0..0];
        // Fast path: index by upper 32-bit word.
        const idx = vm_addr >> VIRTUAL_ADDRESS_BITS;
        if (idx < self.regions.len) {
            if (self.regions[idx].translate(vm_addr, len, write)) |s| return s;
        }
        // Fallback: linear scan (handles edge cases / unaligned starts).
        for (self.regions[0..self.n_regions]) |r| {
            if (r.translate(vm_addr, len, write)) |s| return s;
        }
        return if (write) VmError.AccessViolation else VmError.InvalidMemoryAccess;
    }

    pub fn load(self: *const MemoryMap, comptime T: type, vm_addr: u64) VmError!T {
        const bytes = try self.translate(vm_addr, @sizeOf(T), false);
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
    }

    pub fn store(self: *const MemoryMap, comptime T: type, vm_addr: u64, val: T) VmError!void {
        const bytes = try self.translate(vm_addr, @sizeOf(T), true);
        std.mem.writeInt(T, bytes[0..@sizeOf(T)], val, .little);
    }
};

// ── Call frame ──────────────────────────────────────────────────────────────── @prov:vm.module-map
const CallFrame = struct {
    /// Saved callee-preserved registers r6-r9.
    saved_regs: [4]u64,
    /// Caller's frame-pointer (r10).
    fp: u64,
    /// Instruction index to return to (pc + 1 at call site).
    return_pc: u64,
};

// ── VmState ─────────────────────────────────────────────────────────────────── @prov:vm.module-map
pub const VmState = struct {
    // Registers r0-r10 (r10 = frame pointer, read-only in most instructions)
    regs:     [11]u64,
    // Program counter (instruction index into text slice).
    pc:       u64,
    // Total instructions executed so far.
    insn_ctr: u64,
    // Compute meter — decremented each instruction when metering enabled.
    compute_meter: u64,

    // Memory layout
    memory_map: MemoryMap,

    // Call stack
    call_frames: std.ArrayListUnmanaged(CallFrame),
    call_depth:  u32,

    // Heap bump allocator cursor (VM virtual address).
    heap_cursor: u64,

    // Owned allocations
    stack_buf: []u8,
    heap_buf:  []u8,

    // Syscall dispatch table: murmur3_32(name) → fn
    syscalls: std.AutoHashMapUnmanaged(u32, SyscallFn),

    // r71-fix-7e: optional pointer to the loaded program's function registry
    // (murmur3_32(symbol_name) → instruction-index PC). Owned by LoadedProgram;
    // VmState only borrows. JMP_CALL !is_reg path consults this when imm is
    // not a registered syscall, before failing with InvalidInstruction. Pre-
    // fix the dispatcher silently fell through to `vm.pc = imm`, which set
    // pc to the murmur3 hash itself (a giant number) and crashed the next
    // step with "out_of_text". Setting null here keeps existing tests valid.
    function_registry: ?*const std.AutoHashMapUnmanaged(u32, u64),

    // sBPF version governs instruction semantics.
    version: SbpfVersion,

    // Execution result written on normal exit.
    result: union(enum) { running, ok: u64, err: VmError },

    allocator: std.mem.Allocator,

    // CPI trampoline (optional — set by higher-level executor).
    cpi_ctx:     ?*anyopaque,
    cpi_handler: ?*const fn (
        cpi_ctx: *anyopaque,
        vm:      *VmState,
        r1: u64, r2: u64, r3: u64, r4: u64, r5: u64,
    ) VmError!u64,

    pub fn init(
        allocator:    std.mem.Allocator,
        rodata:       []const u8,
        rodata_vaddr: u64,
        input:        []u8,
        version:      SbpfVersion,
        entry_pc:     u64,
    ) !VmState {
        const stack_buf = try allocator.alloc(u8, STACK_SIZE);
        errdefer allocator.free(stack_buf);
        @memset(stack_buf, 0);

        const heap_buf = try allocator.alloc(u8, HEAP_SIZE);
        errdefer allocator.free(heap_buf);
        @memset(heap_buf, 0);

        var state = VmState{
            .regs         = [_]u64{0} ** 11,
            .pc           = entry_pc,
            .insn_ctr     = 0,
            .compute_meter = MAX_INSNS,
            .memory_map   = MemoryMap.init(rodata, rodata_vaddr, stack_buf, heap_buf, input, version),
            .call_frames  = .{},
            .call_depth   = 0,
            .heap_cursor  = VM_HEAP_START,
            .stack_buf    = stack_buf,
            .heap_buf     = heap_buf,
            .syscalls     = .{},
            .function_registry = null,
            .version      = version,
            .result       = .running,
            .allocator    = allocator,
            .cpi_ctx      = null,
            .cpi_handler  = null,
        };

        // Solana calling convention:
        //   r1  = VM_INPUT_START (pointer to serialised accounts)
        //   r2  = 0 (instruction data offset — filled by caller when needed)
        //   r10 = frame pointer. Canonical (solana-sbpf vm.rs:385-390 + FD fd_vm.c:662-663):
        //   r10 = MM_STACK_START + (manual_stack_frame_bump(v1/v2) ? stack_len : stack_frame_size).
        //   v1/v2 grow the frame DOWN from the TOP of the stack (manual bump); v0/v3 use a
        //   fixed first-frame offset. PRE-FIX keyed on enableDynamicStackFrames (v>=1) → +0,
        //   so v1/v2 r10 started at the BOTTOM (MM_STACK_START) and the program's first
        //   `sub r10` underflowed below the stack region → AccessViolation on the first
        //   fp-relative stack store (carrier 2026-06-18: PayEntry v1, testnet slot 416083630,
        //   op=0x7b STXDW dst=r10 off=144, r10=0x1fffffec0 below stack base, bank_hash dc05dca0).
        state.regs[1]  = VM_INPUT_START;
        state.regs[10] = VM_STACK_START +
            (if (version.manualStackFrameBump()) @as(u64, STACK_SIZE) else STACK_FRAME_SIZE);
        return state;
    }

    /// Translate a VM address to a host slice (read-only).
    /// Compatibility method for sbpf_executor and syscalls.
    pub fn translateR(self: *const VmState, vm_addr: u64, len: u64) VmError![]const u8 {
        return self.memory_map.translate(vm_addr, len, false);
    }

    /// Translate a VM address to a mutable host slice (read-write).
    /// Matches old VmContext.translate(addr, len, write_flag) signature used by syscalls.
    pub fn translate(self: *VmState, vm_addr: u64, len: u64, write: bool) VmError![]u8 {
        return self.memory_map.translate(vm_addr, len, write);
    }

    pub fn deinit(self: *VmState) void {
        self.allocator.free(self.stack_buf);
        self.allocator.free(self.heap_buf);
        self.call_frames.deinit(self.allocator);
        self.syscalls.deinit(self.allocator);
    }

    pub fn registerSyscall(self: *VmState, id: u32, func: SyscallFn) !void {
        try self.syscalls.put(self.allocator, id, func);
    }

    /// Register a syscall by hashing its canonical name with murmur3_32.
    pub fn registerSyscallByName(self: *VmState, name: []const u8, func: SyscallFn) !void {
        const id = murmur3_32(name);
        try self.registerSyscall(id, func);
    }
};

// ── Murmur3-32 hash for syscall dispatch ───────────────────────────────────── @prov:vm.module-map
// Seed=0 matches Solana's convention for all syscall name hashes.
pub fn murmur3_32(key: []const u8) u32 {
    return std.hash.Murmur3_32.hashWithSeed(key, 0);
}

// ── Helper: sign-extend u32 → u64 (as if it were i32 → i64) ───────────────── @prov:vm.module-map
inline fn signExtend(v: u32) u64 {
    const signed: i32 = @bitCast(v);
    const wide: i64   = signed;
    return @bitCast(wide);
}

// ── Helper: checked integer division (trunc toward zero) ───────────────────── @prov:vm.module-map
inline fn divTrunc(comptime T: type, num: T, den: T) VmError!T {
    @setRuntimeSafety(false);
    if (den == 0) return VmError.DivisionByZero;
    if (comptime @typeInfo(T).int.signedness == .signed) {
        if (num == std.math.minInt(T) and den == -1) return VmError.DivideOverflow;
    }
    return @divTrunc(num, den);
}

inline fn remOp(comptime T: type, num: T, den: T) VmError!T {
    @setRuntimeSafety(false);
    if (den == 0) return VmError.DivisionByZero;
    if (comptime @typeInfo(T).int.signedness == .signed) {
        if (num == std.math.minInt(T) and den == -1) return VmError.DivideOverflow;
    }
    return @rem(num, den);
}

// ── step() — execute one instruction ───────────────────────────────────────── @prov:vm.module-map
// Dispatches on cls/opcode, advances pc, mutates VmState.
pub fn step(vm: *VmState, text: []align(1) const Instruction) VmError!void {
    const pc = vm.pc;
    if (pc >= text.len) return VmError.InvalidInstruction;
    const inst = text[pc];
    const opc  = inst.opcode;
    const cls  = opc & 0x07;

    const dst: u4  = inst.dst;
    const src: u4  = inst.src;
    const off: i16 = inst.offset;
    const imm: u32 = inst.imm;

    // Sign-extended imm for use as a 64-bit operand.
    const imm_se: u64 = signExtend(imm);

    // Whether source operand comes from a register (bit 3 of opcode).
    const is_reg = (opc & SRC_REG) != 0;

    switch (cls) {

        // ── 64-bit ALU ──────────────────────────────────────────────────────
        CLS_ALU64 => {
            const op = opc & 0xf0;
            const rv: u64 = if (is_reg) vm.regs[src] else imm_se;
            const dv: u64 = vm.regs[dst];

            vm.regs[dst] = switch (op) {
                ALU_ADD  => dv +% rv,
                ALU_SUB  => if (!is_reg and vm.version.swapSubImmOperands())
                                rv -% dv   // SIMD-0174: imm - dst
                            else
                                dv -% rv,
                ALU_MUL  => dv *% rv,
                ALU_DIV  => try divTrunc(u64, dv, rv),
                ALU_OR   => dv | rv,
                ALU_AND  => dv & rv,
                ALU_LSH  => dv << @as(u6, @truncate(rv & 63)),
                ALU_RSH  => dv >> @as(u6, @truncate(rv & 63)),
                ALU_NEG  => @bitCast(-@as(i64, @bitCast(dv))),
                ALU_MOD  => try remOp(u64, dv, rv),
                ALU_XOR  => dv ^ rv,
                ALU_MOV  => rv,
                ALU_ARSH => @bitCast(@as(i64, @bitCast(dv)) >> @as(u6, @truncate(rv & 63))),
                ALU_END  => handleEndian(dv, imm, is_reg),
                ALU_HOR  => dv | (@as(u64, imm) << 32),
                else     => return VmError.InvalidInstruction,
            };
            vm.pc = pc + 1;
        },

        // ── 32-bit ALU ──────────────────────────────────────────────────────
        CLS_ALU32 => {
            const op = opc & 0xf0;
            const rv32: u32 = @truncate(if (is_reg) vm.regs[src] else imm_se);
            const dv32: u32 = @truncate(vm.regs[dst]);

            const result32: u32 = switch (op) {
                ALU_ADD  => dv32 +% rv32,
                ALU_SUB  => if (!is_reg and vm.version.swapSubImmOperands())
                                rv32 -% dv32
                            else
                                dv32 -% rv32,
                ALU_MUL  => dv32 *% rv32,
                ALU_DIV  => try divTrunc(u32, dv32, rv32),
                ALU_OR   => dv32 | rv32,
                ALU_AND  => dv32 & rv32,
                ALU_LSH  => dv32 << @as(u5, @truncate(rv32 & 31)),
                ALU_RSH  => dv32 >> @as(u5, @truncate(rv32 & 31)),
                ALU_NEG  => @bitCast(-@as(i32, @bitCast(dv32))),
                ALU_MOD  => try remOp(u32, dv32, rv32),
                ALU_XOR  => dv32 ^ rv32,
                ALU_MOV  => if (is_reg and vm.version.explicitSignExtend())
                                // SIMD-0174 mov32_reg: sign-extend from i32.
                                @truncate(signExtend(rv32))
                            else
                                rv32,
                ALU_ARSH => @bitCast(@as(i32, @bitCast(dv32)) >> @as(u5, @truncate(rv32 & 31))),
                // ALU_END for alu32/be — BE byte-swap with imm width
                ALU_END  => @truncate(handleEndian(vm.regs[dst], imm, is_reg)),
                // v2 renamed memory ops reuse ALU32 class — handled by ALU_MUL/DIV/NEG/MOD
                // cases above (same numeric values). V2 dispatch is in stepV2MemOp
                // called from the outer switch when class matches.
                else => return VmError.InvalidInstruction,
            };

            // @prov:vm.module-map
            // add32/sub32 zero-extend (plain u32→u64); mul32 sign-extends.
            vm.regs[dst] = switch (op) {
                ALU_MUL => signExtend(result32),
                else    => result32,
            };
            vm.pc = pc + 1;
        },

        // ── PQR (product/quotient/remainder, sBPF v2) ─────────────────────── @prov:vm.module-map
        CLS_PQR => {
            if (!vm.version.enablePqr()) return VmError.InvalidInstruction;
            try stepPqr(vm, inst, pc);
        },

        // ── JMP / control flow ───────────────────────────────────────────────
        CLS_JMP => {
            try stepJmp(vm, inst, text, pc);
        },

        // ── LDX: load from memory ────────────────────────────────────────────
        CLS_LDX => {
            const addr: u64 = @bitCast(@as(i64, @bitCast(vm.regs[src])) +% @as(i64, off));
            vm.regs[dst] = switch (opc & 0xf8) {
                MEM | SZ_B  => try vm.memory_map.load(u8,  addr),
                MEM | SZ_H  => try vm.memory_map.load(u16, addr),
                MEM | SZ_W  => try vm.memory_map.load(u32, addr),
                MEM | SZ_DW => try vm.memory_map.load(u64, addr),
                else => return VmError.InvalidInstruction,
            };
            vm.pc = pc + 1;
        },

        // ── ST: store immediate ──────────────────────────────────────────────
        CLS_ST => {
            const addr: u64 = @bitCast(@as(i64, @bitCast(vm.regs[dst])) +% @as(i64, off));
            switch (opc & 0xf8) {
                MEM | SZ_B  => try vm.memory_map.store(u8,  addr, @truncate(imm_se)),
                MEM | SZ_H  => try vm.memory_map.store(u16, addr, @truncate(imm_se)),
                MEM | SZ_W  => try vm.memory_map.store(u32, addr, @truncate(imm_se)),
                MEM | SZ_DW => try vm.memory_map.store(u64, addr, imm_se),
                else => return VmError.InvalidInstruction,
            }
            vm.pc = pc + 1;
        },

        // ── STX: store from register ─────────────────────────────────────────
        CLS_STX => {
            const addr: u64 = @bitCast(@as(i64, @bitCast(vm.regs[dst])) +% @as(i64, off));
            const sv = vm.regs[src];
            switch (opc & 0xf8) {
                MEM | SZ_B  => try vm.memory_map.store(u8,  addr, @truncate(sv)),
                MEM | SZ_H  => try vm.memory_map.store(u16, addr, @truncate(sv)),
                MEM | SZ_W  => try vm.memory_map.store(u32, addr, @truncate(sv)),
                MEM | SZ_DW => try vm.memory_map.store(u64, addr, sv),
                else => return VmError.InvalidInstruction,
            }
            vm.pc = pc + 1;
        },

        // ── LD: LDDW (load 64-bit immediate spanning two instructions) ────────
        CLS_LD => {
            if (vm.version.disableLddw()) return VmError.InvalidInstruction;
            if (opc != 0x18) return VmError.InvalidInstruction;
            // @prov:vm.module-map
            if (pc + 1 >= text.len) return VmError.InvalidInstruction;
            const lo: u64 = imm;
            const hi: u64 = text[pc + 1].imm;
            vm.regs[dst] = lo | (hi << 32);
            vm.pc = pc + 2;
        },

        else => return VmError.InvalidInstruction,
    }
}

// ── Endian byte-swap helper (BE/LE) ────────────────────────────────────────── @prov:vm.module-map
inline fn handleEndian(val: u64, width: u32, big_endian: bool) u64 {
    return switch (width) {
        inline 16, 32, 64 => |w| blk: {
            const T = std.meta.Int(.unsigned, w);
            const truncated: T = @truncate(val);
            break :blk if (big_endian)
                std.mem.nativeToBig(T, truncated)
            else
                std.mem.nativeToLittle(T, truncated);
        },
        else => val, // pass-through; should have been caught in verification
    };
}

// ── v2 memory ops (renamed instruction classes) ─────────────────────────────── @prov:vm.module-map
fn stepV2MemOp(vm: *VmState, inst: Instruction, text: []align(1) const Instruction, pc: u64) VmError!void {
    _ = text;
    const opc  = inst.opcode;
    const cls  = opc & 0x07;
    const sz   = opc & 0xf8; // includes class bits + size field
    const dst  = inst.dst;
    const src  = inst.src;
    const off  = inst.offset;
    const imm  = inst.imm;

    // v2 load (class ALU32, src=reg)
    if (cls == CLS_ALU32 and (opc & SRC_REG) != 0) {
        const addr: u64 = @bitCast(@as(i64, @bitCast(vm.regs[src])) +% @as(i64, off));
        vm.regs[dst] = switch (sz) {
            (CLS_ALU32 | SRC_REG | SZ_1B) => try vm.memory_map.load(u8,  addr),
            (CLS_ALU32 | SRC_REG | SZ_2B) => try vm.memory_map.load(u16, addr),
            (CLS_ALU32 | SRC_REG | SZ_4B) => try vm.memory_map.load(u32, addr),
            (CLS_ALU32 | SRC_REG | SZ_8B) => try vm.memory_map.load(u64, addr),
            else => return VmError.InvalidInstruction,
        };
        vm.pc = pc + 1;
        return;
    }

    // v2 store imm (class ALU64, src=imm)
    if (cls == CLS_ALU64 and (opc & SRC_REG) == 0) {
        const addr: u64 = @bitCast(@as(i64, @bitCast(vm.regs[dst])) +% @as(i64, off));
        const val = signExtend(imm);
        switch (sz) {
            (CLS_ALU64 | SRC_IMM | SZ_1B) => try vm.memory_map.store(u8,  addr, @truncate(val)),
            (CLS_ALU64 | SRC_IMM | SZ_2B) => try vm.memory_map.store(u16, addr, @truncate(val)),
            (CLS_ALU64 | SRC_IMM | SZ_4B) => try vm.memory_map.store(u32, addr, @truncate(val)),
            (CLS_ALU64 | SRC_IMM | SZ_8B) => try vm.memory_map.store(u64, addr, val),
            else => return VmError.InvalidInstruction,
        }
        vm.pc = pc + 1;
        return;
    }

    // v2 store reg (class ALU64, src=reg)
    if (cls == CLS_ALU64 and (opc & SRC_REG) != 0) {
        const addr: u64 = @bitCast(@as(i64, @bitCast(vm.regs[dst])) +% @as(i64, off));
        const sv = vm.regs[src];
        switch (sz) {
            (CLS_ALU64 | SRC_REG | SZ_1B) => try vm.memory_map.store(u8,  addr, @truncate(sv)),
            (CLS_ALU64 | SRC_REG | SZ_2B) => try vm.memory_map.store(u16, addr, @truncate(sv)),
            (CLS_ALU64 | SRC_REG | SZ_4B) => try vm.memory_map.store(u32, addr, @truncate(sv)),
            (CLS_ALU64 | SRC_REG | SZ_8B) => try vm.memory_map.store(u64, addr, sv),
            else => return VmError.InvalidInstruction,
        }
        vm.pc = pc + 1;
        return;
    }

    return VmError.InvalidInstruction;
}

// ── PQR instructions (sBPF v2) ─────────────────────────────────────────────── @prov:vm.module-map
fn stepPqr(vm: *VmState, inst: Instruction, pc: u64) VmError!void {
    const opc    = inst.opcode;
    const is64   = (opc & PQR_64BIT) != 0;
    const is_reg = (opc & SRC_REG) != 0;
    const op     = opc & 0xe0; // top 3 bits of upper nibble

    const dst = inst.dst;
    const src = inst.src;
    const imm = inst.imm;

    if (is64) {
        const lhs: u64 = vm.regs[dst];
        const rhs: u64 = if (is_reg) vm.regs[src] else imm;
        const rhs_se: i64 = if (is_reg) @bitCast(vm.regs[src]) else @bitCast(signExtend(imm));

        vm.regs[dst] = switch (op) {
            PQR_LMUL => lhs *% @as(u64, @bitCast(rhs_se)),
            PQR_UHMUL => @truncate(@as(u128, lhs) * @as(u128, rhs) >> 64),
            PQR_SHMUL => blk: {
                const a: i64 = @bitCast(lhs);
                const b: i64 = rhs_se;
                break :blk @bitCast(@as(i64, @truncate(@as(i128, a) * @as(i128, b) >> 64)));
            },
            PQR_UDIV => try divTrunc(u64, lhs, rhs),
            PQR_UREM => try remOp(u64, lhs, rhs),
            PQR_SDIV => blk: {
                const r = try divTrunc(i64, @bitCast(lhs), rhs_se);
                break :blk @bitCast(r);
            },
            PQR_SREM => blk: {
                const r = try remOp(i64, @bitCast(lhs), rhs_se);
                break :blk @bitCast(r);
            },
            else => return VmError.InvalidInstruction,
        };
    } else {
        // 32-bit PQR: result is zero-extended to u64
        const lhs32: u32 = @truncate(vm.regs[dst]);
        const rhs_raw: u64 = if (is_reg) vm.regs[src] else imm;
        const rhs32: u32 = @truncate(rhs_raw);
        const rhs_se32: i32 = if (is_reg) @truncate(@as(i64, @bitCast(vm.regs[src]))) else @bitCast(imm);

        const result32: u32 = switch (op) {
            PQR_LMUL => lhs32 *% rhs32,
            PQR_UDIV => try divTrunc(u32, lhs32, rhs32),
            PQR_UREM => try remOp(u32, lhs32, rhs32),
            PQR_SDIV => blk: {
                const r = try divTrunc(i32, @bitCast(lhs32), rhs_se32);
                break :blk @bitCast(r);
            },
            PQR_SREM => blk: {
                const r = try remOp(i32, @bitCast(lhs32), rhs_se32);
                break :blk @bitCast(r);
            },
            else => return VmError.InvalidInstruction,
        };
        vm.regs[dst] = result32; // zero-extend
    }

    vm.pc = pc + 1;
}

// r71-fix-7e: resolve a v0/v1/v2 `call imm` target where imm is NOT a
// registered syscall. Returns the target PC (instruction index) if either
// (a) the function_registry contains imm as a key, OR (b) imm interpreted
// as i32 relative offset (target = pc + imm + 1) lands inside text. Returns
// null when neither resolves — caller should fail with InvalidInstruction
// instead of wild-jumping.
//
// Why two resolution modes: programs compiled with debug symbols populate
// the function_registry via STT_FUNC walk in elf_loader.zig; stripped
// programs don't, so we fall through to relative-offset interpretation
// (mirrors sig/src/vm/elf.zig:766-783's load-time bytecode rewrite, but
// applied at runtime since we don't rewrite the bytecode).
fn resolveLocalCallTarget(vm: *VmState, pc: u64, imm: u32, text_len: usize) ?u64 {
    // r71-fix-8 (2026-04-28): imm=0xffffffff is the sBPF "unrelocated CALL"
    // sentinel — Agave's elf.rs:924 explicitly skips relocation for this
    // value, and Agave's interpreter.rs:575 errors with UnsupportedInstruction
    // when neither syscall nor function-registry hits. Pre-fix Vexor fell
    // through to PC-relative which computed target = pc + (-1) + 1 = pc, a
    // self-loop that pushed call frames until StackOverflow (slot 484
    // GJHtFqM9 / Jito tip-distribution / 234+ events per slot replay).
    if (imm == 0xffffffff) return null;
    if (vm.function_registry) |reg| {
        if (reg.get(imm)) |fn_pc| return fn_pc;
    }
    const rel: i64 = @as(i32, @bitCast(imm));
    const target_i: i64 = @as(i64, @intCast(pc)) +| rel +| 1;
    if (target_i < 0) return null;
    const target_u: u64 = @as(u64, @intCast(target_i));
    if (target_u >= @as(u64, @intCast(text_len))) return null;
    // r71-fix-8: defense-in-depth self-loop guard. Even if a non-sentinel
    // imm happens to compute target == pc, that's a guaranteed StackOverflow
    // (push frame → re-execute → push again). Agave/Firedancer's bounds
    // checks and PC-relative ranges effectively prohibit this; we make it
    // explicit here so we error cleanly rather than infinite-recurse.
    if (target_u == pc) return null;
    return target_u;
}

// ── JMP / control flow ──────────────────────────────────────────────────────── @prov:vm.module-map
fn stepJmp(vm: *VmState, inst: Instruction, text: []align(1) const Instruction, pc: u64) VmError!void {
    const opc    = inst.opcode;
    const op     = opc & 0xf0;
    const is_reg = (opc & SRC_REG) != 0;

    const dst = inst.dst;
    const src = inst.src;
    const imm = inst.imm;
    const off = inst.offset;

    switch (op) {
        JMP_CALL => {
            if (is_reg) {
                // callx / call_reg
                try pushCallFrame(vm, pc);
                const target_vm: u64 = if (vm.version.callRegUsesSrcReg())
                    vm.regs[src]
                else
                    vm.regs[imm & 0xf]; // v0/v1: imm encodes register index
                // Convert VM bytecode address to instruction index.
                // Canonical program_vm_addr (solana-sbpf): MM_RODATA_START +
                // text_section_offset. For v0/v1/v2 the .text section sits at its
                // sh_addr (e.g. 0x120) WITHIN the rodata blob — using bare
                // VM_RODATA_START shifts every callx target by text_offset/8 and
                // lands mid-instruction (the slot-630 carrier: target 0x100027e58
                // → index 20427 instead of 20391, Δ=36=0x120/8). Derive the real
                // text vaddr from the live region-1 mapping + text's host offset.
                const text_base: u64 = if (vm.version.enableLowerBytecodeVaddr())
                    VM_BYTECODE_START
                else blk: {
                    const ro = vm.memory_map.regions[1];
                    const text_off = @intFromPtr(text.ptr) - @intFromPtr(ro.host_ptr);
                    break :blk ro.vm_start + text_off;
                };
                const next_pc = (target_vm -% text_base) / 8;
                if (std.posix.getenv("VEX_CALLX_DEBUG") != null) {
                    const S = struct {
                        var n: u32 = 0;
                    };
                    if (S.n < 64) {
                        S.n += 1;
                        std.log.warn("[CALLX-BASE] target_vm=0x{x} text_vaddr=0x{x} next_pc={d} (was=0x{x}/{d})", .{
                            target_vm, text_base, next_pc, VM_RODATA_START, (target_vm -% VM_RODATA_START) / 8,
                        });
                    }
                }
                if (next_pc >= text.len) return VmError.CallOutsideTextSegment;
                // v3 additional check: target must be a function-start marker
                // (add64 r10, imm). @prov:vm.module-map
                if (vm.version.enableStaticSyscalls()) {
                    const t_inst = text[next_pc];
                    const is_marker = (t_inst.opcode == (CLS_ALU64 | SRC_IMM | ALU_ADD)) and
                                      (t_inst.dst == 10);
                    if (!is_marker) return VmError.InvalidInstruction;
                }
                vm.pc = next_pc;
            } else {
                // call_imm: syscall or local function, depending on version
                if (vm.version.enableStaticSyscalls()) {
                    // v3: call_imm is always a local function call (relative PC)
                    // @prov:vm.module-map
                    try pushCallFrame(vm, pc);
                    vm.pc = vm.version.callTargetPc(pc, imm);
                } else {
                    // v0/v1/v2 `call imm` resolution order:
                    //   1. syscall (murmur3_32(name)→handler) — full 32-bit hash
                    //   2. function_registry (murmur3_32(symbol)→PC) — stripped
                    //      ELFs may not have entries here
                    //   3. relative-offset interpretation — sig/src/vm/elf.zig:
                    //      766-783 walks every call_imm at LOAD time and either
                    //      rewrites the imm to a registry key, OR (in our case
                    //      where we don't rewrite) the imm stays as the original
                    //      i32 relative offset and we compute target_pc = pc +
                    //      imm + 1 at runtime. This is the same target_pc formula
                    //      v3 uses (see callTargetPc above) but we apply it for
                    //      v0/v1/v2 fallback when neither registry hits.
                    //   4. otherwise InvalidInstruction (cleaner than wild jump)
                    if (vm.syscalls.get(imm)) |handler| {
                        try dispatchSyscall(vm, handler);
                        vm.pc = pc + 1;
                    } else if (resolveLocalCallTarget(vm, pc, imm, text.len)) |target_pc| {
                        try pushCallFrame(vm, pc);
                        vm.pc = target_pc;
                    } else {
                        return VmError.InvalidInstruction;
                    }
                }
            }
        },

        JMP_EXIT => {
            if (vm.version.enableStaticSyscalls() and is_reg) {
                // v3: `return` opcode (jmp | x | exit_code) — always a return
                // @prov:vm.module-map
                try popCallFrame(vm);
            } else if (vm.version.enableStaticSyscalls() and !is_reg) {
                // v3: `syscall` opcode — static dispatch by imm hash
                // @prov:vm.module-map
                if (vm.syscalls.get(imm)) |handler| {
                    try dispatchSyscall(vm, handler);
                    vm.pc = pc + 1;
                } else {
                    return VmError.InvalidSyscall;
                }
            } else {
                // v0/v1/v2: `exit` — return from function or halt program
                // @prov:vm.module-map
                if (vm.call_depth == 0) {
                    vm.result = .{ .ok = vm.regs[0] };
                    return VmError.Halted;
                }
                try popCallFrame(vm);
            }
        },

        JMP_JA => vm.pc = @intCast(@as(i64, @intCast(pc + 1)) + off),

        else => {
            // Conditional branches
            const dv = vm.regs[dst];
            const rv: u64 = if (is_reg) vm.regs[src] else signExtend(imm);
            const dv_s: i64 = @bitCast(dv);
            const rv_s: i64 = if (is_reg) @bitCast(rv) else @as(i32, @bitCast(imm));

            const taken: bool = switch (op) {
                JMP_JEQ  => dv == rv,
                JMP_JNE  => dv != rv,
                JMP_JGT  => dv >  rv,
                JMP_JGE  => dv >= rv,
                JMP_JLT  => dv <  rv,
                JMP_JLE  => dv <= rv,
                JMP_JSET => (dv & rv) != 0,
                JMP_JSGT => dv_s >  rv_s,
                JMP_JSGE => dv_s >= rv_s,
                JMP_JSLT => dv_s <  rv_s,
                JMP_JSLE => dv_s <= rv_s,
                else     => return VmError.InvalidInstruction,
            };
            vm.pc = if (taken)
                @intCast(@as(i64, @intCast(pc + 1)) + off)
            else
                pc + 1;
        },
    }
}

// ── pushCallFrame / popCallFrame ────────────────────────────────────────────── @prov:vm.module-map
fn pushCallFrame(vm: *VmState, pc: u64) VmError!void {
    if (vm.call_depth >= MAX_CALL_DEPTH) return VmError.CallDepthExceeded;
    try vm.call_frames.append(vm.allocator, .{
        .saved_regs = vm.regs[6..10][0..4].*,
        .fp         = vm.regs[10],
        .return_pc  = pc + 1,
    });
    vm.call_depth += 1;

    if (!vm.version.enableDynamicStackFrames()) {
        // r75-bug-class-b-2026-05-06: scale=2 stack-frame-gap fix.
        // Static frames (V0 ELFs) require a guard-gap between adjacent frames.
        // sig reference: src/vm/interpreter.zig:864-867 multiplies STACK_FRAME_SIZE
        // by 2 when enable_stack_frame_gaps is on. Without this, frame N+1 starts
        // at the same vm-address that frame N's bottom 4KB occupied — RefCell
        // borrow_count bytes saved on caller frame get clobbered by callee →
        // next try_borrow_mut_lamports re-reads garbage → LDX_64 of RefCell ptr
        // produces unmapped address → InvalidMemoryAccess.
        // Empirically caught at pc=39472 opc=0x79 dst=8 src=2 in v0 ELF (Jito
        // tip-payment / change_tip_receiver path) per [BPF-OPC] probe 2026-05-06.
        const FRAME_GAP_SCALE: u64 = 2;
        vm.regs[10] += STACK_FRAME_SIZE * FRAME_GAP_SCALE;
        if (vm.regs[10] > VM_STACK_START + STACK_SIZE) return VmError.StackOverflow;
    }
    // Dynamic frames: r10 is adjusted by the function's prologue via `add r10, imm`.
}

fn popCallFrame(vm: *VmState) VmError!void {
    const frame = vm.call_frames.pop() orelse return VmError.Halted;
    vm.call_depth -= 1;
    vm.regs[10] = frame.fp;
    vm.regs[6..10][0..4].* = frame.saved_regs;
    vm.pc = frame.return_pc;
}

// ── dispatchSyscall ─────────────────────────────────────────────────────────── @prov:vm.module-map
// Saves/restores the compute meter around the syscall.
pub fn dispatchSyscall(vm: *VmState, handler: SyscallFn) VmError!void {
    // Flush the instruction counter into the compute meter before calling.
    vm.compute_meter -|= vm.insn_ctr;
    vm.insn_ctr = 0;
    // Clear r0 before call so an unset return looks like 0.
    vm.regs[0] = 0;
    vm.regs[0] = try handler(vm, vm.regs[1], vm.regs[2], vm.regs[3], vm.regs[4], vm.regs[5]);
}

// ── run() — execute until halt or instruction limit ─────────────────────────── @prov:vm.module-map
pub fn run(vm: *VmState, text: []const Instruction) struct { ok: bool, r0: u64, insns: u64 } {
    const initial_meter = vm.compute_meter;
    while (true) {
        if (vm.insn_ctr >= vm.compute_meter) {
            vm.result = .{ .err = VmError.InstructionLimitExceeded };
            break;
        }
        vm.insn_ctr += 1;
        step(vm, text) catch |err| switch (err) {
            VmError.Halted => break,
            else => {
                vm.result = .{ .err = err };
                break;
            },
        };
    }

    const consumed = initial_meter - vm.compute_meter + vm.insn_ctr;
    return switch (vm.result) {
        .ok     => |r0| .{ .ok = true,  .r0 = r0, .insns = consumed },
        .running => .{ .ok = true, .r0 = vm.regs[0], .insns = consumed },
        .err    => .{ .ok = false, .r0 = 0,  .insns = consumed },
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "vm: mov64 + halt" {
    // mov64 r0, 42  (0xb7 0x00 0x00 0x00  0x2a 0x00 0x00 0x00)
    // exit          (0x95 0x00 0x00 0x00  0x00 0x00 0x00 0x00)
    const raw = [_]u64{
        @as(u64, 0x00_00_00_2a_00_00_00_b7), // mov64 r0, 42  (LE)
        @as(u64, 0x00_00_00_00_00_00_00_95), // exit
    };
    const text = [_]Instruction{ Instruction.decode(raw[0]), Instruction.decode(raw[1]) };
    var inp: [4]u8 = .{0} ** 4;
    var vm = try VmState.init(std.testing.allocator, &[_]u8{}, VM_RODATA_START, &inp, .v0, 0);
    defer vm.deinit();
    const result = run(&vm, &text);
    try std.testing.expect(result.ok);
    try std.testing.expectEqual(@as(u64, 42), result.r0);
}

test "vm: add64 imm" {
    // mov64 r0, 10
    // add64 r0, 5
    // exit
    const text = [_]Instruction{
        Instruction.decode(0x00_00_00_0a_00_00_00_b7), // mov64 r0, 10
        Instruction.decode(0x00_00_00_05_00_00_00_07), // add64 r0, 5
        Instruction.decode(0x00_00_00_00_00_00_00_95), // exit
    };
    var inp: [4]u8 = .{0} ** 4;
    var vm = try VmState.init(std.testing.allocator, &[_]u8{}, VM_RODATA_START, &inp, .v0, 0);
    defer vm.deinit();
    const result = run(&vm, &text);
    try std.testing.expect(result.ok);
    try std.testing.expectEqual(@as(u64, 15), result.r0);
}

test "vm: memory store and load" {
    // Store 0xDEAD to input region, load back, exit with value.
    // stw  [r1+0], 0xDEAD      (0xDE 0xAD 0x00 0x00  as imm = 0x0000ADDE)
    // ldxw r0, [r1+0]
    // exit
    const imm_val: u32 = 0x0000ADDE;
    const text = [_]Instruction{
        // stw [r1+0], imm  — cls=ST(0x02) | sz=W(0x00) = 0x62; dst=r1, src=0, off=0
        .{ .opcode = 0x62, .dst = 1, .src = 0, .offset = 0, .imm = imm_val },
        // ldxw r0, [r1+0] — cls=LDX(0x01) | sz=W(0x00) | src_reg = 0x61; dst=r0, src=r1
        .{ .opcode = 0x61, .dst = 0, .src = 1, .offset = 0, .imm = 0 },
        // exit
        .{ .opcode = 0x95, .dst = 0, .src = 0, .offset = 0, .imm = 0 },
    };
    var inp: [8]u8 = .{0} ** 8;
    var vm = try VmState.init(std.testing.allocator, &[_]u8{}, VM_RODATA_START, &inp, .v0, 0);
    defer vm.deinit();
    const result = run(&vm, &text);
    try std.testing.expect(result.ok);
    try std.testing.expectEqual(@as(u64, imm_val), result.r0);
}

test "vm: jeq branch taken" {
    // mov64 r0, 1
    // jeq  r0, 1, +1   (jump over next instruction)
    // mov64 r0, 99
    // exit
    const text = [_]Instruction{
        .{ .opcode = 0xb7, .dst = 0, .src = 0, .offset = 0,  .imm = 1  },  // mov64 r0, 1
        .{ .opcode = 0x15, .dst = 0, .src = 0, .offset = 1,  .imm = 1  },  // jeq r0, 1, +1
        .{ .opcode = 0xb7, .dst = 0, .src = 0, .offset = 0,  .imm = 99 },  // mov64 r0, 99
        .{ .opcode = 0x95, .dst = 0, .src = 0, .offset = 0,  .imm = 0  },  // exit
    };
    var inp: [4]u8 = .{0} ** 4;
    var vm = try VmState.init(std.testing.allocator, &[_]u8{}, VM_RODATA_START, &inp, .v0, 0);
    defer vm.deinit();
    const result = run(&vm, &text);
    try std.testing.expect(result.ok);
    try std.testing.expectEqual(@as(u64, 1), result.r0);
}

test "vm: division by zero" {
    // mov64 r1, 0
    // div64 r0, r1   (r0 / 0 → DivisionByZero)
    // exit
    const text = [_]Instruction{
        .{ .opcode = 0xb7, .dst = 1, .src = 0, .offset = 0, .imm = 0 }, // mov64 r1, 0
        .{ .opcode = 0x3f, .dst = 0, .src = 1, .offset = 0, .imm = 0 }, // div64 r0, r1
        .{ .opcode = 0x95, .dst = 0, .src = 0, .offset = 0, .imm = 0 }, // exit
    };
    var inp: [4]u8 = .{0} ** 4;
    var vm = try VmState.init(std.testing.allocator, &[_]u8{}, VM_RODATA_START, &inp, .v0, 0);
    defer vm.deinit();
    const result = run(&vm, &text);
    try std.testing.expect(!result.ok);
}
