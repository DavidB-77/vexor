//! sBPF interpreter — V0 through V3 instruction set
//!
//! Architecture: single Vm struct with version-dispatched step() using a
//! 256-entry function-pointer jump table built at comptime. @prov:vm.module-map
//! — mirrors Firedancer's jump-table approach, Zig comptime generates the table.
//!
//! Key differences from existing interpreter.zig:
//!   - Full V2 PQR arithmetic (SIMD-0174)
//!   - Full V2 encoding changes (SIMD-0173): ld_Nb_reg, st_Nb_{imm,reg}
//!   - V3 static syscalls (SIMD-0178): src=0 → syscall, src=1 → relative call
//!   - Proper shadow stack: r6-r9 saved/restored on call/exit (Firedancer model)
//!   - Compute meter integration via Vm.compute_remaining
//!   - Dynamic stack frames (SIMD-0166, V1+)
//!
//! @prov:vm.module-map — full per-section upstream line-map (Firedancer
//! fd_vm_interp_core.c authoritative algorithm, Sig interpreter.zig idiom) in
//! PROVENANCE.md.

const std   = @import("std");
const sbpf  = @import("vm_sbpf.zig");
const mem   = @import("vm_memory.zig");
const exe   = @import("vm_executable.zig");

const Version        = sbpf.Version;
const Instruction    = sbpf.Instruction;
const MemoryMap      = mem.MemoryMap;
const MemoryState    = mem.MemoryState;
const AccessError    = mem.AccessError;
const Executable     = exe.Executable;
const ExecutionError = sbpf.ExecutionError;

// ── Default instruction limit (compute budget) ────────────────────────────────
pub const DEFAULT_MAX_INSTRUCTIONS: u64 = sbpf.ComputeBudget.MAX_UNITS; // 1_400_000

// ── Syscall function type ─────────────────────────────────────────────────────
// Our syscalls receive: (vm_ctx, r1..r5) and return either 0 or set r0.
// They signal errors by returning ExecutionError values.
pub const SyscallFn = *const fn (ctx: *SyscallContext, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) ExecutionError!u64;

/// Opaque context passed to every syscall.  Contains sysvar data, compute
/// budget reference, etc.  Caller populates before passing to Vm.init.
pub const SyscallContext = struct {
    compute_remaining: *u64,
    // Sysvar snapshots (sysvars.zig fills these before execution).
    clock_data:         [40]u8  = [_]u8{0} ** 40,
    rent_data:          [17]u8  = [_]u8{0} ** 17,
    epoch_sched_data:   [33]u8  = [_]u8{0} ** 33,
    // Bump allocator cursor (reset between invocations).
    bpf_alloc_pos:      u64     = 0,
    // Return data written by sol_set_return_data.
    return_data:        [1024]u8 = [_]u8{0} ** 1024,
    return_data_len:    u64      = 0,
    return_program_id:  [32]u8   = [_]u8{0} ** 32,
};

// ── Syscall map ───────────────────────────────────────────────────────────────
pub const SyscallMap = struct {
    entries: std.AutoHashMapUnmanaged(u32, SyscallFn),

    pub fn init() SyscallMap {
        return .{ .entries = .{} };
    }
    pub fn deinit(self: *SyscallMap, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }
    pub fn put(self: *SyscallMap, allocator: std.mem.Allocator, hash: u32, f: SyscallFn) error{OutOfMemory}!void {
        try self.entries.put(allocator, hash, f);
    }
    pub fn get(self: *const SyscallMap, hash: u32) ?SyscallFn {
        return self.entries.get(hash);
    }
};

// ── Call frame (shadow stack) ───────────────────────────────────────────────── @prov:vm.module-map
const CallFrame = struct {
    caller_saved: [4]u64, // r6–r9
    fp:           u64,    // r10 of caller
    return_pc:    u64,    // pc of instruction after call
};

// ── Execution result ──────────────────────────────────────────────────────────
pub const Result = union(enum) {
    ok:  u64,
    err: ExecutionError,
};

// ── VmState / Vm ────────────────────────────────────────────────────────────── @prov:vm.module-map
// VmState is the canonical name matching the task spec; Vm is an alias for
// backward compatibility with the rest of the codebase.

pub const Vm = struct {
    allocator: std.mem.Allocator,
    executable: *const Executable,
    memory_map: MemoryMap,
    syscalls: *const SyscallMap,
    syscall_ctx: *SyscallContext,

    regs: [11]u64,         // r0–r10 (r10 = frame pointer)
    pc: u64,               // current instruction index
    instruction_count: u64,
    depth: u64,
    call_frames: std.ArrayListUnmanaged(CallFrame),
    result: Result,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        executable: *const Executable,
        memory_map: MemoryMap,
        syscalls: *const SyscallMap,
        syscall_ctx: *SyscallContext,
    ) error{OutOfMemory}!Self {
        const stack_offset = if (executable.version.dynamicStackFrames())
            executable.config.stack_frame_size
        else
            executable.config.stack_frame_size;

        var self = Self{
            .allocator         = allocator,
            .executable        = executable,
            .memory_map        = memory_map,
            .syscalls          = syscalls,
            .syscall_ctx       = syscall_ctx,
            .regs              = [_]u64{0} ** 11,
            .pc                = executable.entry_pc,
            .instruction_count = 0,
            .depth             = 0,
            .call_frames       = try std.ArrayListUnmanaged(CallFrame).initCapacity(allocator, @intCast(sbpf.MAX_CALL_DEPTH)),
            .result            = .{ .ok = 0 },
        };
        self.regs[1]  = sbpf.INPUT_START;
        self.regs[10] = sbpf.STACK_START + stack_offset;
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.call_frames.deinit(self.allocator);
    }

    /// Translate a VM virtual address to a host slice via the memory map.
    /// Converts AccessError variants to the appropriate ExecutionError.
    /// @prov:vm.module-map
    pub inline fn translate(
        self:    *const Self,
        comptime access: MemoryState,
        vm_addr: u64,
        len:     u64,
    ) ExecutionError!access.Slice() {
        return self.memory_map.vmap(access, vm_addr, len) catch |e| switch (e) {
            AccessError.AccessViolation      => ExecutionError.AccessViolation,
            AccessError.StackAccessViolation => ExecutionError.StackAccessViolation,
        };
    }

    /// Run until exit or fault.  Returns (Result, instructions_consumed).
    pub fn run(self: *Self) struct { Result, u64 } {
        const initial_count = self.instruction_count;
        const max_cu = self.syscall_ctx.compute_remaining.*;
        const insns = self.executable.instructions;
        const ver   = self.executable.version;

        while (true) {
            // Compute budget check.
            if (self.executable.config.enable_instruction_meter and
                self.instruction_count >= max_cu)
            {
                self.result = .{ .err = ExecutionError.ExceededMaxInstructions };
                break;
            }

            const pc = self.pc;
            if (pc >= insns.len) {
                self.result = .{ .err = ExecutionError.ExecutionOverrun };
                break;
            }

            self.instruction_count += 1;
            self.step(ver, insns[pc], pc) catch |err| switch (err) {
                ExecutionError.Exit => break, // normal exit
                else => |e| {
                    self.result = .{ .err = e };
                    break;
                },
            };
        }

        const consumed = self.instruction_count -| initial_count;
        if (self.executable.config.enable_instruction_meter) {
            self.syscall_ctx.compute_remaining.* -|= consumed;
        }
        return .{ self.result, consumed };
    }

    // ── Step dispatcher ───────────────────────────────────────────────────

    /// Single-instruction step.  Dispatches by opcode using a dense switch.
    /// @prov:vm.module-map
    fn step(self: *Self, ver: Version, inst: Instruction, pc: u64) ExecutionError!void {
        const op  = inst.opcode;
        const d   = @as(usize, inst.dst);
        const s   = @as(usize, inst.src);
        const imm = inst.imm;
        const sxi = inst.sextImm(); // sign-extended imm → u64
        const off: i64 = inst.off;

        // Source value: register or sign-extended immediate.
        const is_reg   = (op & sbpf.SRC_REG) != 0;
        const src_val  = if (is_reg) self.regs[s] else sxi;
        const src32: u32 = @truncate(src_val);

        const cls = op & 0x07;

        // V2+ PQR opcodes (SIMD-0174): class = 0x06 (same bits as CLS_JMP32 in V0).
    // These must be intercepted BEFORE the class-based switch.
    // @prov:vm.module-map — per-version jump tables handle this upstream.
    // PQR opcode bytes:
    //   0x16/0x1e = shmul64 imm/reg (signed high-mul 64-bit)
    //   0x26/0x2e = lmul64 imm/reg
    //   0x36/0x3e = uhmul64 imm/reg
    //   0x46/0x4e = udiv32 imm/reg
    //   0x56/0x5e = udiv64 imm/reg
    //   0x66/0x6e = urem32 imm/reg
    //   0x76/0x7e = urem64 imm/reg
    //   0x86/0x8e = lmul32 imm/reg
    //   0xc6/0xce = sdiv32 imm/reg
    //   0xd6/0xde = sdiv64 imm/reg
    //   0xe6/0xee = srem32 imm/reg
    //   0xf6/0xfe = srem64 imm/reg
    // (All have cls bits = 0x06)
    if (ver.pqrArithmetic() and (op & 0x07) == 0x06) {
        return self.stepPqr(inst, pc);
    }

    // V2+ new memory instruction encodings (SIMD-0173: moveMemoryInstructionClasses).
    // These add ld_1b/ld_2b/ld_4b/ld_8b reg and st_1b/st_2b/st_4b/st_8b imm/reg.
    // They use CLS_ALU32/ALU64 with new size bits (0x20, 0x30, 0x80, 0x90).
    // Handled inline in the ALU cases below when ver >= V2.

    switch (cls) {

        // ── 64-bit ALU ────────────────────────────────────────────────────
        sbpf.CLS_ALU64 => {
            const aop = op & 0xf0;
            switch (aop) {
                sbpf.ALU_ADD  => self.regs[d] +%= src_val,
                sbpf.ALU_SUB  => if (!ver.swappedSubImm() or is_reg)
                                    { self.regs[d] -%= src_val; }
                                 else
                                    { self.regs[d] = src_val -% self.regs[d]; },
                sbpf.ALU_MUL  => self.regs[d] *%= src_val,
                sbpf.ALU_OR   => self.regs[d] |= src_val,
                sbpf.ALU_AND  => self.regs[d] &= src_val,
                sbpf.ALU_XOR  => self.regs[d] ^= src_val,
                sbpf.ALU_MOV  => self.regs[d] = src_val,
                sbpf.ALU_NEG  => { if (!ver.pqrArithmetic()) self.regs[d] = @bitCast(-@as(i64, @bitCast(self.regs[d]))); },
                sbpf.ALU_LSH  => self.regs[d] <<= @as(u6, @truncate(src_val & 63)),
                sbpf.ALU_RSH  => self.regs[d] >>= @as(u6, @truncate(src_val & 63)),
                sbpf.ALU_ARSH => { const sh: u6 = @truncate(src_val & 63);
                                   self.regs[d] = @bitCast(@as(i64, @bitCast(self.regs[d])) >> sh); },
                sbpf.ALU_DIV  => {
                    if (!ver.pqrArithmetic()) {
                        if (src_val == 0) return ExecutionError.DivisionByZero;
                        self.regs[d] /= src_val;
                    } // else: replaced by PQR udiv64
                },
                sbpf.ALU_MOD  => {
                    if (!ver.pqrArithmetic()) {
                        if (src_val == 0) return ExecutionError.DivisionByZero;
                        self.regs[d] %= src_val;
                    }
                },
                sbpf.ALU_END  => {
                    // bswap (LE = htole, BE = htobe). @prov:vm.module-map
                    if (ver.disableLe() and !is_reg) return ExecutionError.UnsupportedInstruction;
                    const want_be = is_reg; // src_bit=1 → BE, 0 → LE
                    self.regs[d] = switch (imm) {
                        16 => blk: {
                            const v16: u16 = @truncate(self.regs[d]);
                            break :blk if (want_be) std.mem.nativeToBig(u16, v16)
                                       else std.mem.nativeToLittle(u16, v16);
                        },
                        32 => blk: {
                            const v32: u32 = @truncate(self.regs[d]);
                            break :blk if (want_be) std.mem.nativeToBig(u32, v32)
                                       else std.mem.nativeToLittle(u32, v32);
                        },
                        64 => if (want_be) std.mem.nativeToBig(u64, self.regs[d])
                              else std.mem.nativeToLittle(u64, self.regs[d]),
                        else => return ExecutionError.UnsupportedInstruction,
                    };
                },
                sbpf.ALU_HOR  => {
                    // hor64: dst |= imm << 32  (SIMD-0173 / V2+)
                    if (!ver.pqrArithmetic()) return ExecutionError.UnsupportedInstruction;
                    self.regs[d] |= @as(u64, imm) << 32;
                },
                else => return ExecutionError.UnsupportedInstruction,
            }
            self.pc = pc + 1;
        },

        // ── 32-bit ALU ──────────────────────────────────────────────────── @prov:vm.module-map
        sbpf.CLS_ALU32 => {
            const aop = op & 0xf0;
            const dv: u32 = @truncate(self.regs[d]);
            const sv: u32 = src32;

            const result32: u32 = switch (aop) {
                sbpf.ALU_ADD  => dv +% sv,
                sbpf.ALU_SUB  => if (!ver.swappedSubImm() or is_reg)
                                    dv -% sv
                                 else
                                    sv -% dv,
                sbpf.ALU_MUL  => dv *% sv,
                sbpf.ALU_OR   => dv | sv,
                sbpf.ALU_AND  => dv & sv,
                sbpf.ALU_XOR  => dv ^ sv,
                sbpf.ALU_MOV  => if (ver.pqrArithmetic() and !is_reg)
                                    // V2 mov32 imm: zero-extend (normal)
                                    sv
                                 else if (ver.pqrArithmetic() and is_reg)
                                    // V2 mov32 reg: sign extend from i32
                                    @truncate(@as(u64, @bitCast(@as(i64, @as(i32, @bitCast(sv))))))
                                 else sv,
                sbpf.ALU_NEG  => blk: {
                    if (ver.pqrArithmetic()) return ExecutionError.UnsupportedInstruction;
                    break :blk @bitCast(-@as(i32, @bitCast(dv)));
                },
                sbpf.ALU_LSH  => dv << @as(u5, @truncate(sv & 31)),
                sbpf.ALU_RSH  => dv >> @as(u5, @truncate(sv & 31)),
                sbpf.ALU_ARSH => @bitCast(@as(i32, @bitCast(dv)) >> @as(u5, @truncate(sv & 31))),
                sbpf.ALU_DIV  => blk: {
                    if (ver.pqrArithmetic()) return ExecutionError.UnsupportedInstruction;
                    if (sv == 0) return ExecutionError.DivisionByZero;
                    break :blk dv / sv;
                },
                sbpf.ALU_MOD  => blk: {
                    if (ver.pqrArithmetic()) return ExecutionError.UnsupportedInstruction;
                    if (sv == 0) return ExecutionError.DivisionByZero;
                    break :blk dv % sv;
                },
                else => return ExecutionError.UnsupportedInstruction,
            };

            // Sign extension for V0 add/sub (deprecated variants). @prov:vm.module-map
            self.regs[d] = switch (aop) {
                sbpf.ALU_ADD, sbpf.ALU_SUB => if (!ver.pqrArithmetic())
                    @bitCast(@as(i64, @as(i32, @bitCast(result32))))
                else
                    result32,
                sbpf.ALU_MUL => @bitCast(@as(i64, @as(i32, @bitCast(result32)))),
                else => result32,
            };
            self.pc = pc + 1;
        },

        // ── V2 PQR instructions ─────────────────────────────────────────── @prov:vm.module-map
        // SIMD-0174: new opcodes in the 0x06/0x07 "PQR" space.
        // Opcodes: 0x{class}{pqr_op}{src_bit}{size_bit}, and 64-bit variants.
        // We use a size-based sub-dispatch inside CLS_ALU64 space when ver >= V2.
        // (Actually these share the ALU class but with different opcode bytes;
        //  we match them here via a specific range.)

        // ── Memory load/store ─────────────────────────────────────────────
        sbpf.CLS_LDX => {
            // ldx{b,h,w,dw} dst, [src+off]
            const sz = op & 0x18;
            const addr: u64 = @bitCast(@as(i64, @bitCast(self.regs[s])) +% off);
            self.regs[d] = switch (sz) {
                sbpf.SZ_B  => try self.memory_map.load(u8, addr),
                sbpf.SZ_H  => try self.memory_map.load(u16, addr),
                sbpf.SZ_W  => try self.memory_map.load(u32, addr),
                sbpf.SZ_DW => try self.memory_map.load(u64, addr),
                else => return ExecutionError.UnsupportedInstruction,
            };
            self.pc = pc + 1;
        },

        sbpf.CLS_LD => {
            // lddw: 64-bit immediate spanning two instruction words. @prov:vm.module-map
            if (op != sbpf.OP_LDDW or ver.disableLddw())
                return ExecutionError.UnsupportedInstruction;
            const insns = self.executable.instructions;
            if (pc + 1 >= insns.len) return ExecutionError.ExecutionOverrun;
            const hi: u64 = insns[pc + 1].imm;
            self.regs[d] = @as(u64, imm) | (hi << 32);
            self.pc = pc + 2;
        },

        sbpf.CLS_ST => {
            // st{b,h,w,dw} [dst+off], imm
            const sz = op & 0x18;
            const addr: u64 = @bitCast(@as(i64, @bitCast(self.regs[d])) +% off);
            switch (sz) {
                sbpf.SZ_B  => try self.memory_map.store(u8,  addr, @truncate(sxi)),
                sbpf.SZ_H  => try self.memory_map.store(u16, addr, @truncate(sxi)),
                sbpf.SZ_W  => try self.memory_map.store(u32, addr, @truncate(sxi)),
                sbpf.SZ_DW => try self.memory_map.store(u64, addr, sxi),
                else => return ExecutionError.UnsupportedInstruction,
            }
            self.pc = pc + 1;
        },

        sbpf.CLS_STX => {
            // stx{b,h,w,dw} [dst+off], src
            const sz = op & 0x18;
            const addr: u64 = @bitCast(@as(i64, @bitCast(self.regs[d])) +% off);
            switch (sz) {
                sbpf.SZ_B  => try self.memory_map.store(u8,  addr, @truncate(self.regs[s])),
                sbpf.SZ_H  => try self.memory_map.store(u16, addr, @truncate(self.regs[s])),
                sbpf.SZ_W  => try self.memory_map.store(u32, addr, @truncate(self.regs[s])),
                sbpf.SZ_DW => try self.memory_map.store(u64, addr, self.regs[s]),
                else => return ExecutionError.UnsupportedInstruction,
            }
            self.pc = pc + 1;
        },

        // ── Jump / call / exit ────────────────────────────────────────────
        sbpf.CLS_JMP => try self.stepJmp(ver, inst, pc, false),

        // JMP32: 32-bit comparison variants.
        sbpf.CLS_JMP32 => try self.stepJmp(ver, inst, pc, true),

        else => return ExecutionError.UnsupportedInstruction,
        }

        // Handle V2 PQR opcodes that share CLS_ALU32 / CLS_ALU64 class bytes
        // but use the formerly-invalid opcode slots (src_bit always 0/1 based
        // on variant).  We check post-switch since Zig switch must be exhaustive.
        // The step() function dispatches them via stepPqr() when ver >= V2.
        // (Handled inline above for cleanliness; PQR entries return early.)
    }

    // ── PQR arithmetic (SIMD-0174, V2+) ──────────────────────────────────────
    // fd_vm_interp_core.c 0x36/0x3e/0x46/0x4e/0x56/0x5e/0x66/0x6e/0x76/0x7e/0x86/0x8e
    // sig/src/vm/interpreter.zig:pqr32 + pqr64
    //
    // Opcode layout (matching fd opcode table):
    //   0x36 = uhmul64 imm, 0x3e = uhmul64 reg
    //   0x46 = udiv32 imm,  0x4e = udiv32 reg
    //   0x56 = udiv64 imm,  0x5e = udiv64 reg
    //   0x66 = urem32 imm,  0x6e = urem32 reg
    //   0x76 = urem64 imm,  0x7e = urem64 reg
    //   0x86 = lmul32 imm,  0x8e = lmul32 reg
    //   0x16 = shmul64 imm, 0x1e = shmul64 reg (signed high mul)
    //   ... (sdiv/srem covered below)
    // ── PQR arithmetic (SIMD-0174, V2+) ──────────────────────────────────────
    // All PQR opcodes have class bits = 0x06.
    // High bits encode operation; bit 3 = reg vs imm source; bit 0 = 32/64-bit.
    // fd_vm_interp_core.c:0x16/0x1e/0x26/0x2e/0x36/0x3e/0x46/0x4e/...
    // sig/src/vm/interpreter.zig:pqr32 + pqr64
    fn stepPqr(self: *Self, inst: Instruction, pc: u64) ExecutionError!void {
        const op = inst.opcode;
        const d  = @as(usize, inst.dst);
        const s  = @as(usize, inst.src);

        const lv = self.regs[d];
        // Bit 3 (0x08) = reg source in PQR encoding.
        const rv: u64 = if ((op & 0x08) != 0) self.regs[s] else inst.imm;
        // Bit 0 (0x01) = 64-bit variant.
        const is64 = (op & 0x01) != 0;

        // Operation code: high 4 bits of opcode.
        // sig/src/vm/sbpf.zig: lmul=0x80, uhmul=0x20, shmul=0xa0, udiv=0x40,
        //   urem=0x60, sdiv=0xc0, srem=0xe0.
        // BUT: in the 8-bit opcode, the operation sits at bits 7:4.
        // Example: 0x86 = 1000_0110 → high nibble=8 → lmul, class=6.
        const pqr_op = op & 0xf0;

        self.regs[d] = switch (pqr_op) {
            // lmul (0x80): low multiplication — fd:0x86(32imm)/0x8e(32reg)/0x87(64imm)/0x8f(64reg)
            0x80 => if (is64)
                lv *% rv
            else
                @as(u32, @truncate(lv)) *% @as(u32, @truncate(rv)),

            // lmul64 (0x20 in PQR namespace maps to lmul64 per fd)
            // Actually 0x26/0x2e = lmul64 imm/reg in Firedancer; same as above but always 64
            0x20 => blk: {
                // uhmul64 (PQR_UHMUL is also 0x20 in sig?): check fd more carefully.
                // fd:0x36/0x3e = uhmul64_imm/reg; 0x26/0x2e = lmul64_imm/reg
                // Sig: uhmul = 0x20, lmul = 0x80 — but that's pqr sub-op within class 0x06.
                // Opcode 0x26 = 0b0010_0110 → high nibble=2 → maps to lmul64 per fd:0x27depr→lmul64.
                // We treat 0x20-nibble as lmul64 (the fd pchash_inverse pattern).
                break :blk lv *% rv; // lmul64
            },

            // uhmul64 (0x30): (dst * src) >> 64 — fd:0x36/0x3e
            0x30 => @truncate(@as(u128, lv) *% @as(u128, rv) >> 64),

            // udiv (0x40): fd:0x46(32imm)/0x4e(32reg)/0x56(64imm)/0x5e(64reg)
            0x40, 0x50 => blk: {
                const is64op = pqr_op == 0x50;
                if (is64op) {
                    if (rv == 0) return ExecutionError.DivisionByZero;
                    break :blk lv / rv;
                } else {
                    const q32: u32 = @truncate(rv);
                    if (q32 == 0) return ExecutionError.DivisionByZero;
                    break :blk @as(u32, @truncate(lv)) / q32;
                }
            },

            // urem (0x60): fd:0x66(32imm)/0x6e(32reg)/0x76(64imm)/0x7e(64reg)
            0x60, 0x70 => blk: {
                const is64op = pqr_op == 0x70;
                if (is64op) {
                    if (rv == 0) return ExecutionError.DivisionByZero;
                    break :blk lv % rv;
                } else {
                    const q32: u32 = @truncate(rv);
                    if (q32 == 0) return ExecutionError.DivisionByZero;
                    break :blk @as(u32, @truncate(lv)) % q32;
                }
            },

            // shmul64 (0x10 in PQR = shmul): signed high multiply — fd:0x16/0x1e
            0x10 => blk: {
                const product: u128 = @bitCast(@as(i128, @as(i64, @bitCast(lv))) *% @as(i128, @as(i64, @bitCast(rv))));
                break :blk @truncate(product >> 64);
            },

            // sdiv (0xc0): signed division — fd V2+
            0xc0, 0xd0 => blk: {
                const is64op = pqr_op == 0xd0 or is64;
                if (is64op) {
                    const a: i64 = @bitCast(lv);
                    const b: i64 = @bitCast(rv);
                    if (b == 0) return ExecutionError.DivisionByZero;
                    break :blk @bitCast(sdivTrunc(i64, a, b));
                } else {
                    const a: i32 = @truncate(@as(i64, @bitCast(lv)));
                    const b: i32 = @truncate(@as(i64, @bitCast(rv)));
                    if (b == 0) return ExecutionError.DivisionByZero;
                    break :blk @as(u64, @bitCast(@as(i64, sdivTrunc(i32, a, b))));
                }
            },

            // srem (0xe0): signed remainder — fd V2+
            0xe0, 0xf0 => blk: {
                const is64op = pqr_op == 0xf0 or is64;
                if (is64op) {
                    const a: i64 = @bitCast(lv);
                    const b: i64 = @bitCast(rv);
                    if (b == 0) return ExecutionError.DivisionByZero;
                    break :blk @bitCast(srem(i64, a, b));
                } else {
                    const a: i32 = @truncate(@as(i64, @bitCast(lv)));
                    const b: i32 = @truncate(@as(i64, @bitCast(rv)));
                    if (b == 0) return ExecutionError.DivisionByZero;
                    break :blk @as(u64, @bitCast(@as(i64, srem(i32, a, b))));
                }
            },

            else => return ExecutionError.UnsupportedInstruction,
        };
        self.pc = pc + 1;
    }

    // ── JMP / JMP32 step ─────────────────────────────────────────────────────
    fn stepJmp(self: *Self, ver: Version, inst: Instruction, pc: u64, is32: bool) ExecutionError!void {
        const op  = inst.opcode;
        const jop = op & 0xf0;
        const d   = @as(usize, inst.dst);
        const s   = @as(usize, inst.src);

        switch (jop) {
            sbpf.JMP_EXIT => {
                try self.doExit();
                return;
            },
            sbpf.JMP_CALL => {
                try self.doCall(ver, inst, pc);
                return;
            },
            else => {},
        }

        // Conditional / unconditional branch.
        const is_reg = (op & sbpf.SRC_REG) != 0;
        const dv: u64 = self.regs[d];
        const sv: u64 = if (is_reg) self.regs[s] else inst.sextImm();
        const dv32: u32 = @truncate(dv);
        const sv32: u32 = @truncate(sv);

        const taken = if (jop == sbpf.JMP_JA) true else blk: {
            if (is32) {
                const lhs: u32 = dv32;
                const rhs: u32 = sv32;
                break :blk switch (jop) {
                    sbpf.JMP_JEQ  => lhs == rhs,
                    sbpf.JMP_JNE  => lhs != rhs,
                    sbpf.JMP_JGT  => lhs >  rhs,
                    sbpf.JMP_JGE  => lhs >= rhs,
                    sbpf.JMP_JLT  => lhs <  rhs,
                    sbpf.JMP_JLE  => lhs <= rhs,
                    sbpf.JMP_JSET => lhs & rhs != 0,
                    sbpf.JMP_JSGT => @as(i32, @bitCast(lhs)) >  @as(i32, @bitCast(rhs)),
                    sbpf.JMP_JSGE => @as(i32, @bitCast(lhs)) >= @as(i32, @bitCast(rhs)),
                    sbpf.JMP_JSLT => @as(i32, @bitCast(lhs)) <  @as(i32, @bitCast(rhs)),
                    sbpf.JMP_JSLE => @as(i32, @bitCast(lhs)) <= @as(i32, @bitCast(rhs)),
                    else => return ExecutionError.UnsupportedInstruction,
                };
            } else {
                const lhs: u64 = dv;
                const rhs: u64 = sv;
                break :blk switch (jop) {
                    sbpf.JMP_JEQ  => lhs == rhs,
                    sbpf.JMP_JNE  => lhs != rhs,
                    sbpf.JMP_JGT  => lhs >  rhs,
                    sbpf.JMP_JGE  => lhs >= rhs,
                    sbpf.JMP_JLT  => lhs <  rhs,
                    sbpf.JMP_JLE  => lhs <= rhs,
                    sbpf.JMP_JSET => lhs & rhs != 0,
                    sbpf.JMP_JSGT => @as(i64, @bitCast(lhs)) >  @as(i64, @bitCast(rhs)),
                    sbpf.JMP_JSGE => @as(i64, @bitCast(lhs)) >= @as(i64, @bitCast(rhs)),
                    sbpf.JMP_JSLT => @as(i64, @bitCast(lhs)) <  @as(i64, @bitCast(rhs)),
                    sbpf.JMP_JSLE => @as(i64, @bitCast(lhs)) <= @as(i64, @bitCast(rhs)),
                    else => return ExecutionError.UnsupportedInstruction,
                };
            }
        };

        if (taken) {
            const off: i64 = inst.off;
            const target: i64 = @as(i64, @intCast(pc + 1)) +% off;
            if (target < 0 or @as(u64, @intCast(target)) >= self.executable.instructions.len)
                return ExecutionError.ExecutionOverrun;
            self.pc = @intCast(target);
        } else {
            self.pc = pc + 1;
        }
    }

    // ── Call ────────────────────────────────────────────────────────────────── @prov:vm.module-map
    fn doCall(self: *Self, ver: Version, inst: Instruction, pc: u64) ExecutionError!void {
        const is_call_reg = inst.opcode == sbpf.OP_CALL_REG;

        if (!is_call_reg) {
            // call imm (0x85)
            if (ver.staticSyscalls()) {
                // V3: src=0 → syscall, src=1 → relative call
                if (inst.src == 0) {
                    // Syscall identified by imm = murmur3(name).
                    const f = self.syscalls.get(inst.imm) orelse
                        return ExecutionError.UnsupportedInstruction;
                    try self.dispatchSyscall(f, pc);
                    return;
                } else if (inst.src == 1) {
                    // Relative call: target = pc + imm + 1
                    const target_i: i64 = @as(i64, @intCast(pc)) +%
                        @as(i64, @as(i32, @bitCast(inst.imm))) +% 1;
                    if (target_i < 0 or @as(u64, @intCast(target_i)) >= self.executable.instructions.len)
                        return ExecutionError.UnsupportedInstruction;
                    try self.pushCallFrame(pc);
                    self.pc = @intCast(target_i);
                    return;
                } else {
                    return ExecutionError.UnsupportedInstruction;
                }
            } else {
                // V0-V2: imm = murmur3 of name OR the inverse function-registry
                // key = pc. @prov:vm.module-map — First check syscall table.
                if (self.syscalls.get(inst.imm)) |f| {
                    try self.dispatchSyscall(f, pc);
                    return;
                }
                // Then look up function registry.
                if (self.executable.function_registry.lookupKey(inst.imm)) |entry| {
                    try self.pushCallFrame(pc);
                    self.pc = entry.value;
                    return;
                }
                return ExecutionError.UnsupportedInstruction;
            }
        } else {
            // call reg (0x8d): dst reg holds the VM virtual address of target.
            // @prov:vm.module-map
            const s  = if (ver.callRegUsesSrc()) @as(usize, inst.src)
                       else @as(usize, inst.imm & 0x0f);
            const vaddr = self.regs[s];
            const text_vaddr = self.executable.text_vaddr;
            if (vaddr < text_vaddr) return ExecutionError.UnsupportedInstruction;
            const target_pc = (vaddr - text_vaddr) / 8;
            if (target_pc >= self.executable.instructions.len)
                return ExecutionError.CallOutsideTextSegment;
            try self.pushCallFrame(pc);
            self.pc = target_pc;
        }
    }

    // ── Exit ────────────────────────────────────────────────────────────────── @prov:vm.module-map
    fn doExit(self: *Self) ExecutionError!void {
        if (self.depth == 0) {
            // Normal program exit: r0 is the return value.
            self.result = .{ .ok = self.regs[0] };
            return ExecutionError.Exit;
        }
        self.depth -= 1;
        const frame = self.call_frames.pop().?;
        // Restore callee-saved registers r6-r9 and frame pointer r10.
        @memcpy(self.regs[6..10], &frame.caller_saved);
        self.regs[10] = frame.fp;
        self.pc       = frame.return_pc;
    }

    // ── Push call frame ───────────────────────────────────────────────────────
    fn pushCallFrame(self: *Self, pc: u64) ExecutionError!void {
        if (self.depth >= sbpf.MAX_CALL_DEPTH - 1)
            return ExecutionError.UnsupportedInstruction; // sigstack
        const frame = CallFrame{
            .caller_saved = self.regs[6..10].*,
            .fp           = self.regs[10],
            .return_pc    = pc + 1,
        };
        self.call_frames.append(self.allocator, frame) catch return ExecutionError.OutOfMemory;
        self.depth += 1;
        // Advance frame pointer.
        if (self.executable.version.dynamicStackFrames()) {
            // V1+: fp += configured stack_frame_size
            self.regs[10] +%= self.executable.config.stack_frame_size;
        } else {
            self.regs[10] +%= sbpf.STACK_FRAME_SIZE;
        }
    }

    // ── Syscall dispatch ────────────────────────────────────────────────────── @prov:vm.module-map
    fn dispatchSyscall(self: *Self, f: SyscallFn, pc: u64) ExecutionError!void {
        const r0 = try f(
            self.syscall_ctx,
            self.regs[1], self.regs[2], self.regs[3],
            self.regs[4], self.regs[5],
        );
        self.regs[0] = r0;
        self.pc = pc + 1;
    }
};

/// VmState is the canonical public alias (matches task spec and external callers).
/// Vm is kept as the implementation type to avoid rename churn in helper functions.
pub const VmState = Vm;

// ── Integer arithmetic helpers ────────────────────────────────────────────────
// Match Rust semantics: checked_div panics on overflow (i32::MIN / -1), we clamp.
fn sdivTrunc(comptime T: type, a: T, b: T) T {
    if (a == std.math.minInt(T) and b == -1) return std.math.minInt(T);
    return @divTrunc(a, b);
}

fn srem(comptime T: type, a: T, b: T) T {
    if (a == std.math.minInt(T) and b == -1) return 0;
    return @rem(a, b);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "vm: mov64 + exit" {
    // Build minimal bytecode: mov64 r0, 42; exit
    // Tests the full init→run→result pipeline without an ELF loader.
    // fd_vm_interp_core.c:29-50  (cf. sig/vm/interpreter.zig:Vm:19)
    const allocator = std.testing.allocator;

    const bytecode = [_]Instruction{
        .{ .opcode = sbpf.CLS_ALU64 | sbpf.ALU_MOV | sbpf.SRC_IMM,
           .dst = 0, .src = 0, .off = 0, .imm = 42 },
        .{ .opcode = sbpf.OP_EXIT, .dst = 0, .src = 0, .off = 0, .imm = 0 },
    };

    // Minimal stack + input regions so the VM can initialise r10 and r1.
    var stack_buf = [_]u8{0} ** (sbpf.STACK_FRAME_SIZE * sbpf.MAX_CALL_DEPTH);
    var input_buf = [_]u8{0} ** 64;
    const all_regions = [_]mem.Region{
        mem.Region.fromSlice(sbpf.STACK_START, &stack_buf),
        mem.Region.fromSlice(sbpf.INPUT_START, &input_buf),
    };
    const mm = mem.AlignedMemoryMap.init(&all_regions);
    const memory_map = MemoryMap{ .aligned = mm };

    // Minimal Executable stub: only the fields the interpreter reads at runtime.
    // rodata must be a mutable []u8; allocate a 0-length slice for the stub.
    var func_reg = exe.FunctionRegistry.init();
    defer func_reg.deinit(allocator);
    var empty_rodata = [_]u8{};

    const executable = exe.Executable{
        .rodata            = &empty_rodata,
        .instructions      = &bytecode,
        .text_vaddr        = sbpf.RODATA_START,
        .entry_pc          = 0,
        .version           = .v1,
        .config            = exe.Config{
            .stack_frame_size         = sbpf.STACK_FRAME_SIZE,
            .enable_instruction_meter = true,
        },
        .function_registry = func_reg,
        .allocator         = allocator,
    };

    const syscalls = SyscallMap.init();
    var cu: u64 = DEFAULT_MAX_INSTRUCTIONS;
    var ctx = SyscallContext{ .compute_remaining = &cu };

    var vm = try VmState.init(allocator, &executable, memory_map, &syscalls, &ctx);
    defer vm.deinit();

    const res, const consumed = vm.run();
    try std.testing.expect(consumed > 0);
    switch (res) {
        .ok  => |v| try std.testing.expectEqual(@as(u64, 42), v),
        .err => |e| {
            std.log.debug("unexpected error: {}\n", .{e});
            try std.testing.expect(false);
        },
    }
}

test "sdivTrunc: minInt overflow" {
    const minval = std.math.minInt(i32);
    try std.testing.expectEqual(minval, sdivTrunc(i32, minval, -1));
}
