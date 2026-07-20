//! Vexor BPF v2 — interpreter (M4)
//!
//! Spec-for-spec rebuild of the sBPF interpreter. Clean-room mirror of
//! `solana-sbpf v0.14.4` `src/interpreter.rs` + `src/ebpf.rs` written in
//! Zig 0.15.2, with idiom guidance from `sig/src/vm/interpreter.zig` and
//! behavioural cross-checks against `vex_bpf/vm_interpreter.zig` (the
//! production v1 interpreter — read-only reference, not a copy source).
//!
//! Reference targets (single source of truth for semantics):
//!   solana-sbpf v0.14.4
//!     solana-sbpf-v0.14.4/src/interpreter.rs
//!         step()                      lines 173-600
//!         push_frame()                lines 128-156
//!         sign_extension()            lines 158-168
//!         macro translate_memory_access lines 24-46
//!         macro throw_error           lines 48-64
//!         macro check_pc              lines 66-74
//!     solana-sbpf-v0.14.4/src/ebpf.rs
//!         opcode constants + Insn     lines 53-554
//!         get_insn_unchecked          lines 674-684
//!         augment_lddw_unchecked      lines 687-690
//!     solana-sbpf-v0.14.4/src/program.rs
//!         SBPFVersion feature flags   lines 11-103
//!     solana-sbpf-v0.14.4/src/vm.rs
//!         Config defaults             lines 56-110
//!
//! Vexor invariants preserved (see `fix_ledger.md`):
//!   vex-152m  V0 stack r10 advance = `stack_frame_size * 2` because
//!             `stack_frame_gaps == true && manual_stack_frame_bump == false`.
//!             V1/V2 = manual (program issues `add64 r10, imm` itself).
//!             V3    = `stack_frame_size * 1`.
//!             Test `pushCallFrame: V0 r10 += 2*frame, V3 r10 += 1*frame`
//!             below proves the math byte-for-byte.
//!   MAX_CALL_DEPTH=64  matches agave / sig / Anza canonical (vm.rs:102).
//!                      Confirmed correct in `project_call_depth_exhaustion_not_a_bug.md`.
//!   vex-079   BPF_ALIGN_OF_U128 = 8. Inherited from M2 (memory.zig:72).
//!             This file is alignment-agnostic — the M2 translator owns it.
//!
//! Brief divergences (with reasoning):
//!   1. `regs: [11]u64; pc: u64` in the brief is implemented as `reg: [12]u64`
//!      with `reg[11]` aliased as PC. interpreter.rs uses index 11 as PC and
//!      its `throw_error!` macro saves `vm.registers[11] = self.reg[11]` on
//!      faults; splitting the field would force a translation at every fault
//!      site and risk semantic drift. We expose `pcRef()/getPc()/setPc()`
//!      helpers for callers that prefer the brief's mental model.
//!   2. Brief asks for "comptime jump-table per sBPF version". interpreter.rs
//!      uses a single `match insn.opc` with `if version.flag()` guards on
//!      version-gated arms. We mirror that with one `switch (insn.opc)` plus
//!      inline `version.flag()` checks. A 4-way comptime specialisation buys
//!      no measurable wins, triples surface area, and complicates audit
//!      against the canonical `match`. Deferred until profiling demands it.
//!   3. Brief lists per-opcode CU costs. `interpreter.rs:181` charges +1 per
//!      instruction; expensive ops (PQR, syscalls) layer additional CU
//!      through the syscall dispatch path which lives in M6+M8 (not here).
//!      We mirror Rust exactly: `due_insn_count += 1` per step, OutOfCompute
//!      when `due_insn_count >= previous_instruction_meter` checked at the
//!      top of `step()`. Per-opcode tables are not in canonical and would
//!      diverge.
//!
//! SIMD inventory (gates that touch this file's semantics):
//!   SIMD-0166 Dynamic stack frames                         ACTIVE testnet+mainnet
//!             SBPFVersion::V1+V2 manual_stack_frame_bump.
//!   SIMD-0173 SBPF instruction encoding improvements       V2 gate
//!             callx_uses_src_reg, disable_lddw, disable_le,
//!             move_memory_instruction_classes (LD_*B_REG / ST_*B_REG class
//!             swap from BPF_LDX/BPF_STX into BPF_ALU32_LOAD/BPF_ALU64_STORE).
//!   SIMD-0174 SBPF arithmetics improvements                V2 gate
//!             enable_pqr, explicit_sign_extension_of_results,
//!             swap_sub_reg_imm_operands, disable_neg.
//!   SIMD-0178 SBPF static syscalls                         V3 gate
//!             call_imm with src==1 → internal direct call;
//!             src==0 → syscall registry lookup.
//!   SIMD-0189 SBPF stricter ELF headers                    V3 gate (in M1).
//!   SIMD-0377 SBPF JMP32 + callx_uses_dst_reg              V3 gate
//!             enable_jmp32, callx_uses_dst_reg.
//!   SIMD-0177 V4                                           dormant — future.
//!
//! Pubkeys / activation status are the SIMD-sweep agent's job; this file
//! only mirrors the per-version dispatch, not the gating.
//!
//! Public surface (matches the M4 brief):
//!     InterpreterError
//!     SyscallRegistry              (3-line trait shape; M6 fills it in)
//!     CallFrame
//!     Config
//!     Vm                           init / run / step / getPc / setPc
//!
//! ---------------------------------------------------------------------------

const std = @import("std");
const elf = @import("elf.zig");
const memory = @import("memory.zig");
const interp_breadcrumb = @import("interp_breadcrumb.zig");
const heap_trace = @import("heap_trace.zig");

// ─── Public types ─────────────────────────────────────────────────────────────

/// All errors the interpreter can surface during `run` / `step`.
/// Mirrors `solana_sbpf::error::EbpfError` with the variants the
/// per-instruction step() can actually raise (no loader / verifier errors).
pub const InterpreterError = error{
    /// Memory translation failed (M2 returned AccessError.AccessViolation).
    AccessViolation,
    /// `due_insn_count >= previous_instruction_meter` at top of step.
    /// interpreter.rs:178-180.
    ExceededMaxInstructions,
    /// `OutOfCompute` is the brief's preferred name for the same condition.
    /// We surface `ExceededMaxInstructions` from `step()` and additionally
    /// alias `OutOfCompute` so callers can pattern-match either name.
    OutOfCompute,
    /// `push_frame` reached `config.max_call_depth`. interpreter.rs:137-139.
    CallDepthExceeded,
    /// Branch / call target is outside `.text`. interpreter.rs:71.
    CallOutsideTextSegment,
    /// `pc * 8 >= program.len()` after fetch. interpreter.rs:182-184.
    ExecutionOverrun,
    /// LE/BE imm not in {16,32,64} or other malformed encoding.
    /// interpreter.rs:317, 327.
    InvalidInstruction,
    /// CALL_IMM that resolved to neither a syscall nor an internal target.
    /// interpreter.rs:574-576.
    UnsupportedInstruction,
    /// `src == 0` in DIV/MOD/UDIV/UREM (or signed analogues' divisor==0).
    DivideByZero,
    /// Signed div/rem with INT::MIN / -1.
    DivideOverflow,
    /// Syscall returned an error (M6 contract — opaque to this layer).
    SyscallError,
    /// Allocator failure inside step (rare — only path is register_trace push,
    /// which we don't enable; reserved for future config flags).
    OutOfMemory,
};

/// Configuration mirrored from `solana-sbpf vm.rs:Config` lines 56-110.
/// Only the fields the interpreter actually reads are present; the rest of
/// the agave Config (verifier knobs, JIT toggles, …) belongs in M3 / M7.
pub const Config = struct {
    /// agave default = 64. Confirmed correct in `project_call_depth_exhaustion_not_a_bug.md`.
    max_call_depth: usize = 64,
    /// agave default = 4096 bytes. Used as r10 stride on V0 (×2) and V3 (×1).
    stack_frame_size: usize = 4096,
    /// agave default = true. V0 stack uses gapped layout; M2 owns the math.
    enable_stack_frame_gaps: bool = true,
    /// agave default = true. interpreter.rs:178.
    enable_instruction_meter: bool = true,
    /// Brief asks the verifier to be wired before run; gate behind this bool
    /// while M3 lands in parallel. Default true; set false in test-only paths.
    require_verified: bool = true,
};

/// One saved BPF-to-BPF caller frame.
/// agave `CallFrame` (vm.rs:268-275) — same field set, same semantics.
pub const CallFrame = struct {
    /// r6..r9 (FIRST_SCRATCH_REG .. FIRST_SCRATCH_REG + SCRATCH_REGS).
    caller_saved_registers: [4]u64 = .{ 0, 0, 0, 0 },
    /// Callee's r10 entry value (snapshot for restore at EXIT).
    frame_pointer: u64 = 0,
    /// PC to resume at after EXIT. agave stores `reg[11] + 1`.
    target_pc: u64 = 0,
};

/// Tiny trait-shape struct so this file compiles and unit-tests in isolation.
/// Wave 3 (M6) replaces the body with the full SyscallRegistry. We commit to
/// a 3-call shape:
///   - lookup(hash) → ?Slot (V0..V2 syscall hash table)
///   - directAt(slot) → ?Slot (V3 static syscalls; slot encodes target index)
///   - invoke(ctx, slot, r1..r5) → InterpreterError!u64
/// All three are vtable-driven so M8 InvokeContext can be stitched in
/// without re-touching this file.
pub const SyscallRegistry = struct {
    pub const Slot = u32;
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        lookup: *const fn (ctx: *anyopaque, hash: u32) ?Slot,
        invoke: *const fn (
            ctx: *anyopaque,
            invoke_ctx: *anyopaque,
            slot: Slot,
            r1: u64,
            r2: u64,
            r3: u64,
            r4: u64,
            r5: u64,
        ) InterpreterError!u64,
        /// CU-METER unification (2026-07-05, carrier 419786142). Canonical
        /// anza-sbpf `dispatch_syscall` (interpreter.rs:612-616) reconciles the
        /// VM instruction meter with the InvokeContext CU meter around every
        /// syscall: consume the owed insn count into the shared meter BEFORE
        /// the syscall runs, then refresh the VM ceiling from what the syscall
        /// left behind. Without this Vexor ran TWO disjoint meters (insn count
        /// vs syscall costs) = up to double the budget. Optional (null) so the
        /// stub registries in unit tests keep their unmetered behavior.
        /// Mirrors rbpf ContextObject::consume — saturating, no error; the
        /// exhaustion surfaces at the next insn-meter check.
        consume: ?*const fn (invoke_ctx: *anyopaque, n: u64) void = null,
        /// Mirrors rbpf ContextObject::get_remaining.
        remaining: ?*const fn (invoke_ctx: *anyopaque) u64 = null,
    };

    pub inline fn lookup(self: SyscallRegistry, hash: u32) ?Slot {
        return self.vtable.lookup(self.ctx, hash);
    }

    pub inline fn invoke(
        self: SyscallRegistry,
        invoke_ctx: *anyopaque,
        slot: Slot,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
    ) InterpreterError!u64 {
        return self.vtable.invoke(self.ctx, invoke_ctx, slot, r1, r2, r3, r4, r5);
    }
};

// ─── ebpf:: opcode constants (mirrored, ebpf.rs:53-527) ───────────────────────
//
// Kept private to this file to avoid pulling a second module dependency.
// Constants verified line-for-line against ebpf.rs.

const INSN_SIZE: u64 = 8;
const FRAME_PTR_REG: usize = 10;
const FIRST_SCRATCH_REG: usize = 6;
const SCRATCH_REGS: usize = 4;

// Class bits (ebpf.rs:58-74)
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU32_LOAD: u8 = 0x04;
const BPF_JMP64: u8 = 0x05;
const BPF_JMP32: u8 = 0x06;
const BPF_ALU64_STORE: u8 = 0x07;

// Size modifiers (ebpf.rs:84-99)
const BPF_W: u8 = 0x00;
const BPF_H: u8 = 0x08;
const BPF_B: u8 = 0x10;
const BPF_DW: u8 = 0x18;
const BPF_1B: u8 = 0x20;
const BPF_2B: u8 = 0x30;
const BPF_4B: u8 = 0x80;
const BPF_8B: u8 = 0x90;

const BPF_IMM: u8 = 0x00;
const BPF_MEM: u8 = 0x60;

const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;

// ALU op codes (ebpf.rs:128-157)
const BPF_ADD: u8 = 0x00;
const BPF_SUB: u8 = 0x10;
const BPF_MUL: u8 = 0x20;
const BPF_DIV: u8 = 0x30;
const BPF_OR: u8 = 0x40;
const BPF_AND: u8 = 0x50;
const BPF_LSH: u8 = 0x60;
const BPF_RSH: u8 = 0x70;
const BPF_NEG: u8 = 0x80;
const BPF_MOD: u8 = 0x90;
const BPF_XOR: u8 = 0xa0;
const BPF_MOV: u8 = 0xb0;
const BPF_ARSH: u8 = 0xc0;
const BPF_END: u8 = 0xd0;
const BPF_HOR: u8 = 0xf0;

// JMP op codes (ebpf.rs:178-206)
const BPF_JA: u8 = 0x00;
const BPF_JEQ: u8 = 0x10;
const BPF_JGT: u8 = 0x20;
const BPF_JGE: u8 = 0x30;
const BPF_JSET: u8 = 0x40;
const BPF_JNE: u8 = 0x50;
const BPF_JSGT: u8 = 0x60;
const BPF_JSGE: u8 = 0x70;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
const BPF_JLT: u8 = 0xa0;
const BPF_JLE: u8 = 0xb0;
const BPF_JSLT: u8 = 0xc0;
const BPF_JSLE: u8 = 0xd0;

// Composite opcodes (ebpf.rs:213-527)
const LD_DW_IMM: u8 = BPF_LD | BPF_IMM | BPF_DW; // 0x18
const LD_B_REG: u8 = BPF_LDX | BPF_MEM | BPF_B; // 0x71
const LD_H_REG: u8 = BPF_LDX | BPF_MEM | BPF_H; // 0x69
const LD_W_REG: u8 = BPF_LDX | BPF_MEM | BPF_W; // 0x61
const LD_DW_REG: u8 = BPF_LDX | BPF_MEM | BPF_DW; // 0x79
const ST_B_IMM: u8 = BPF_ST | BPF_MEM | BPF_B; // 0x72
const ST_H_IMM: u8 = BPF_ST | BPF_MEM | BPF_H; // 0x6a
const ST_W_IMM: u8 = BPF_ST | BPF_MEM | BPF_W; // 0x62
const ST_DW_IMM: u8 = BPF_ST | BPF_MEM | BPF_DW; // 0x7a
const ST_B_REG: u8 = BPF_STX | BPF_MEM | BPF_B; // 0x73
const ST_H_REG: u8 = BPF_STX | BPF_MEM | BPF_H; // 0x6b
const ST_W_REG: u8 = BPF_STX | BPF_MEM | BPF_W; // 0x63
const ST_DW_REG: u8 = BPF_STX | BPF_MEM | BPF_DW; // 0x7b

// V2 SIMD-0173 move_memory_instruction_classes — encodings shift class
// from BPF_LDX→BPF_ALU32_LOAD and BPF_STX→BPF_ALU64_STORE.
const LD_1B_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_1B; // 0x2c
const LD_2B_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_2B; // 0x3c
const LD_4B_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_4B; // 0x8c
const LD_8B_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_8B; // 0x9c
const ST_1B_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_1B; // 0x27
const ST_2B_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_2B; // 0x37
const ST_4B_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_4B; // 0x87
const ST_8B_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_8B; // 0x97
const ST_1B_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_1B; // 0x2f
const ST_2B_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_2B; // 0x3f
const ST_4B_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_4B; // 0x8f
const ST_8B_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_8B; // 0x9f

// ALU32 (ebpf.rs:264-313)
const ADD32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_ADD;
const ADD32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_ADD;
const SUB32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_SUB;
const SUB32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_SUB;
const MUL32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_MUL;
const MUL32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_MUL;
const DIV32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_DIV;
const DIV32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_DIV;
const OR32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_OR;
const OR32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_OR;
const AND32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_AND;
const AND32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_AND;
const LSH32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_LSH;
const LSH32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_LSH;
const RSH32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_RSH;
const RSH32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_RSH;
const NEG32: u8 = BPF_ALU32_LOAD | BPF_NEG;
const MOD32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_MOD;
const MOD32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_MOD;
const XOR32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_XOR;
const XOR32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_XOR;
const MOV32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_MOV;
const MOV32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_MOV;
const ARSH32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_ARSH;
const ARSH32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_ARSH;
const LE: u8 = BPF_ALU32_LOAD | BPF_K | BPF_END;
const BE: u8 = BPF_ALU32_LOAD | BPF_X | BPF_END;

// ALU64 (ebpf.rs:349-400)
const ADD64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_ADD;
const ADD64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_ADD;
const SUB64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_SUB;
const SUB64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_SUB;
const MUL64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_MUL;
const MUL64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_MUL;
const DIV64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_DIV;
const DIV64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_DIV;
const OR64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_OR;
const OR64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_OR;
const AND64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_AND;
const AND64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_AND;
const LSH64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_LSH;
const LSH64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_LSH;
const RSH64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_RSH;
const RSH64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_RSH;
const NEG64: u8 = BPF_ALU64_STORE | BPF_NEG;
const MOD64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_MOD;
const MOD64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_MOD;
const XOR64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_XOR;
const XOR64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_XOR;
const MOV64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_MOV;
const MOV64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_MOV;
const ARSH64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_ARSH;
const ARSH64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_ARSH;
const HOR64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_HOR; // V2 reuse of LDDW slot

// PQR (ebpf.rs:163-176, 316-342, 402-429)
const BPF_PQR: u8 = 0x06; // also BPF_JMP32 — disambiguated by version flag
const BPF_UHMUL: u8 = 0x20;
const BPF_UDIV: u8 = 0x40;
const BPF_UREM: u8 = 0x60;
const BPF_LMUL: u8 = 0x80;
const BPF_SHMUL: u8 = 0xA0;
const BPF_SDIV: u8 = 0xC0;
const BPF_SREM: u8 = 0xE0;

const LMUL32_IMM: u8 = BPF_PQR | BPF_K | BPF_LMUL;
const LMUL32_REG: u8 = BPF_PQR | BPF_X | BPF_LMUL;
const UDIV32_IMM: u8 = BPF_PQR | BPF_K | BPF_UDIV;
const UDIV32_REG: u8 = BPF_PQR | BPF_X | BPF_UDIV;
const UREM32_IMM: u8 = BPF_PQR | BPF_K | BPF_UREM;
const UREM32_REG: u8 = BPF_PQR | BPF_X | BPF_UREM;
const SDIV32_IMM: u8 = BPF_PQR | BPF_K | BPF_SDIV;
const SDIV32_REG: u8 = BPF_PQR | BPF_X | BPF_SDIV;
const SREM32_IMM: u8 = BPF_PQR | BPF_K | BPF_SREM;
const SREM32_REG: u8 = BPF_PQR | BPF_X | BPF_SREM;

const LMUL64_IMM: u8 = BPF_PQR | BPF_B | BPF_K | BPF_LMUL;
const LMUL64_REG: u8 = BPF_PQR | BPF_B | BPF_X | BPF_LMUL;
const UHMUL64_IMM: u8 = BPF_PQR | BPF_B | BPF_K | BPF_UHMUL;
const UHMUL64_REG: u8 = BPF_PQR | BPF_B | BPF_X | BPF_UHMUL;
const UDIV64_IMM: u8 = BPF_PQR | BPF_B | BPF_K | BPF_UDIV;
const UDIV64_REG: u8 = BPF_PQR | BPF_B | BPF_X | BPF_UDIV;
const UREM64_IMM: u8 = BPF_PQR | BPF_B | BPF_K | BPF_UREM;
const UREM64_REG: u8 = BPF_PQR | BPF_B | BPF_X | BPF_UREM;
const SHMUL64_IMM: u8 = BPF_PQR | BPF_B | BPF_K | BPF_SHMUL;
const SHMUL64_REG: u8 = BPF_PQR | BPF_B | BPF_X | BPF_SHMUL;
const SDIV64_IMM: u8 = BPF_PQR | BPF_B | BPF_K | BPF_SDIV;
const SDIV64_REG: u8 = BPF_PQR | BPF_B | BPF_X | BPF_SDIV;
const SREM64_IMM: u8 = BPF_PQR | BPF_B | BPF_K | BPF_SREM;
const SREM64_REG: u8 = BPF_PQR | BPF_B | BPF_X | BPF_SREM;

// JMP32 (ebpf.rs:432-474) — class is BPF_JMP32 which numerically equals
// BPF_PQR (0x06). Disambiguated by sBPF version: enable_jmp32 is V3+ only,
// enable_pqr is V2-only — they never overlap in a valid program.
const JEQ32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JEQ;
const JEQ32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JEQ;
const JGT32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JGT;
const JGT32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JGT;
const JGE32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JGE;
const JGE32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JGE;
const JLT32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JLT;
const JLT32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JLT;
const JLE32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JLE;
const JLE32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JLE;
const JSET32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSET;
const JSET32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSET;
const JNE32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JNE;
const JNE32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JNE;
const JSGT32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSGT;
const JSGT32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSGT;
const JSGE32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSGE;
const JSGE32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSGE;
const JSLT32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSLT;
const JSLT32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSLT;
const JSLE32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSLE;
const JSLE32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSLE;

// JMP64 (ebpf.rs:476-527)
const JA: u8 = BPF_JMP64 | BPF_JA;
const JEQ64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JEQ;
const JEQ64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JEQ;
const JGT64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JGT;
const JGT64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JGT;
const JGE64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JGE;
const JGE64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JGE;
const JLT64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JLT;
const JLT64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JLT;
const JLE64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JLE;
const JLE64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JLE;
const JSET64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSET;
const JSET64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSET;
const JNE64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JNE;
const JNE64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JNE;
const JSGT64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSGT;
const JSGT64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSGT;
const JSGE64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSGE;
const JSGE64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSGE;
const JSLT64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSLT;
const JSLT64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSLT;
const JSLE64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSLE;
const JSLE64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSLE;
const CALL_IMM: u8 = BPF_JMP64 | BPF_CALL; // 0x85
const CALL_REG: u8 = BPF_JMP64 | BPF_X | BPF_CALL; // 0x8d
const EXIT: u8 = BPF_JMP64 | BPF_EXIT; // 0x95

// ─── Decoded instruction (ebpf.rs:541-554) ────────────────────────────────────

const Insn = struct {
    opc: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i64,
};

inline fn getInsnUnchecked(prog: []const u8, pc: u64) Insn {
    const base: usize = @intCast(pc * INSN_SIZE);
    // ebpf.rs:675-684 byte layout. dst is low nibble of byte 1, src is high.
    const b1 = prog[base + 1];
    const off_le = std.mem.readInt(i16, prog[base + 2 ..][0..2], .little);
    const imm_le = std.mem.readInt(i32, prog[base + 4 ..][0..4], .little);
    return .{
        .opc = prog[base],
        .dst = b1 & 0x0f,
        .src = (b1 & 0xf0) >> 4,
        .off = off_le,
        .imm = @as(i64, imm_le),
    };
}

inline fn isPcInProgram(prog_len: usize, pc: u64) bool {
    // ebpf.rs:626-628
    const next = std.math.add(u64, pc, 1) catch return false;
    const bytes = std.math.mul(u64, next, INSN_SIZE) catch return false;
    return bytes <= prog_len;
}

// ─── Vm ───────────────────────────────────────────────────────────────────────

pub const Vm = struct {
    /// reg[0..10] = r0..r10. reg[11] = pc (matches interpreter.rs).
    /// Brief specifies regs/[11] + pc/u64 split; we keep the canonical layout
    /// to minimise drift and expose pc helpers — see header divergence #1.
    reg: [12]u64,

    /// Caller-saved frames. Length = config.max_call_depth (= 64 default).
    /// Allocated in `init`, freed in `deinit`.
    call_frames: []CallFrame,
    call_depth: u8,

    /// Compute meter (interpreter.rs:178). due_insn_count is monotonically
    /// rising, previous_instruction_meter is the per-tx ceiling. Both are
    /// charged inline, no per-opcode table.
    due_insn_count: u64,
    previous_instruction_meter: u64,

    /// External binding.
    mm: *memory.AlignedMemoryMap,
    executable: *const elf.Executable,
    /// Stored by value so the Vm doesn't capture a dangling pointer. The
    /// registry is a thin {ctx, vtable} pair (16 bytes); copying is free.
    syscalls: SyscallRegistry,
    invoke_ctx: *anyopaque,

    /// Fast snapshot of executable state (avoids recomputing each step).
    program: []const u8,
    program_vm_addr: u64,
    sbpf_version: elf.SbpfVersion,

    config: Config,
    allocator: std.mem.Allocator,

    /// Populated by `run` on EXIT-at-depth-0; opaque otherwise.
    program_result: u64,

    /// Default frame for the brief-specified initial state.
    pub fn init(
        allocator: std.mem.Allocator,
        executable: *const elf.Executable,
        mm: *memory.AlignedMemoryMap,
        syscalls: SyscallRegistry,
        invoke_ctx: *anyopaque,
        config: Config,
        compute_meter: u64,
    ) !Vm {
        const frames = try allocator.alloc(CallFrame, config.max_call_depth);
        @memset(frames, .{});

        var reg: [12]u64 = .{0} ** 12;
        // r1 = the initial host_addr / vm_input_addr is set by the caller
        //      (M8 InvokeContext) before `run`. We zero here for determinism.
        // r10 init. Canonical anza-xyz/sbpf v0.21.0 vm.rs:385-390 (= Agave
        // 4.1.0-rc.0 pin; byte-identical in vendored 0.14.4 vm.rs:325-330):
        //   MM_STACK_START + (manual_stack_frame_bump ? stack_len : stack_frame_size)
        // where stack_len = config.stack_size() = stack_frame_size * max_call_depth.
        // V1/V2 (manual) start r10 at the TOP of the flat stack and bump it DOWN
        // themselves; V0/V3 (non-manual) get the first fixed frame pre-positioned.
        //
        // 2026-06-18 FIX: prior code used `manual ? 0 : ...` — a misread of the
        // canonical `stack_len` as `0` — leaving r10 at the stack BASE, so the
        // first manual frame bump went BELOW MM_STACK_START → AccessViolation.
        // Surfaced by slot-416083630 PayEntry (sBPF v1): pc=18519 r10=0x1fffffec0
        // (below MM_STACK_START 0x200000000). v0/v3 took the correct `else`
        // branch, which is why they stayed bank-exact in production. Pairs with
        // the v1 flat-stack-region fix (stack_frame_gaps = V0-only) in
        // v2_dispatch.zig / cpi.zig — both required together for v1.
        const v = executable.version();
        const initial_r10: u64 = blk: {
            const manual = (v == .v1) or (v == .v2);
            const stack_len: u64 = @as(u64, config.stack_frame_size) * @as(u64, config.max_call_depth);
            break :blk memory.MM_STACK_START + if (manual) stack_len else @as(u64, config.stack_frame_size);
        };
        reg[FRAME_PTR_REG] = initial_r10;
        reg[11] = executable.entryPoint();

        return .{
            .reg = reg,
            .call_frames = frames,
            .call_depth = 0,
            .due_insn_count = 0,
            .previous_instruction_meter = compute_meter,
            .mm = mm,
            .executable = executable,
            .syscalls = syscalls,
            .invoke_ctx = invoke_ctx,
            .program = executable.textBytes(),
            .program_vm_addr = executable.programRegionVaddr(),
            .sbpf_version = v,
            .config = config,
            .allocator = allocator,
            .program_result = 0,
        };
    }

    pub fn deinit(self: *Vm) void {
        self.allocator.free(self.call_frames);
        self.call_frames = &.{};
    }

    pub inline fn getPc(self: *const Vm) u64 {
        return self.reg[11];
    }
    pub inline fn setPc(self: *Vm, pc: u64) void {
        self.reg[11] = pc;
    }

    /// Run until EXIT at depth 0 or first error. Returns r0.
    pub fn run(self: *Vm) InterpreterError!u64 {
        while (true) {
            if (try self.stepOnce()) |r0| return r0;
        }
    }

    /// Single-step for the diff harness. Returns void on continue, propagates
    /// errors. For "program halted" in single-step mode, callers should call
    /// `run` instead — `step` is for in-progress trace replay.
    pub fn step(self: *Vm) InterpreterError!void {
        _ = try self.stepOnce();
    }

    // ── Internal: one instruction ────────────────────────────────────────────
    //
    // Returns:
    //   null  → continue (set reg[11] = next_pc).
    //   r0    → program halted (EXIT at depth 0).
    //
    // Errors propagate via Zig's error union — equivalent to interpreter.rs
    // `throw_error!` setting `program_result` and returning false. We don't
    // need a success-vs-halt-vs-error tri-state because Zig errors give us
    // the third channel for free.
    fn stepOnce(self: *Vm) InterpreterError!?u64 {
        const config = &self.config;

        // Compute meter check. interpreter.rs:178-180.
        if (config.enable_instruction_meter and
            self.due_insn_count >= self.previous_instruction_meter)
        {
            return InterpreterError.ExceededMaxInstructions;
        }
        self.due_insn_count += 1;

        // PC bounds check. interpreter.rs:182-184.
        if (self.reg[11] * INSN_SIZE >= self.program.len) {
            return InterpreterError.ExecutionOverrun;
        }

        const insn = getInsnUnchecked(self.program, self.reg[11]);

        // Phase-3: record breadcrumb for panic localization.  Gated here so
        // V1-path and unit tests that don't enter a protected scope pay zero
        // overhead (one TLS load + unpredicted branch = ~1 ns; no stores).
        // Uses interp_breadcrumb (libc-free) so interpreter.zig itself has no
        // libc dependency; shadow_panic_safety.zig manages g_breadcrumb_active.
        if (interp_breadcrumb.g_breadcrumb_active) {
            interp_breadcrumb.recordStep(self.reg[11], insn.opc, self.reg[0..11].*);
        }

        const dst: usize = @intCast(insn.dst);
        const src: usize = @intCast(insn.src);
        var next_pc: u64 = self.reg[11] + 1;
        const v = self.sbpf_version;

        // Convenience version-flag locals (mirror SBPFVersion methods).
        const v_manual_stack_bump = (v == .v1) or (v == .v2);
        const v_stack_frame_gaps = (v == .v0);
        const v_enable_pqr = (v == .v2);
        const v_explicit_sext = (v == .v2);
        const v_swap_sub_imm = (v == .v2);
        const v_disable_neg = (v == .v2);
        const v_callx_uses_src = (v == .v2);
        const v_disable_lddw = (v == .v2);
        const v_disable_le = (v == .v2);
        const v_move_mem_classes = (v == .v2);
        const v_static_syscalls = (@intFromEnum(v) >= @intFromEnum(elf.SbpfVersion.v3));
        const v_enable_jmp32 = (@intFromEnum(v) >= @intFromEnum(elf.SbpfVersion.v3));
        const v_callx_uses_dst = (@intFromEnum(v) >= @intFromEnum(elf.SbpfVersion.v3));

        switch (insn.opc) {
            // ── LDDW ─────────────────────────────────────────────────────────
            // interpreter.rs:195-200. Two-slot pseudo: imm hi half lives in
            // the next 8 bytes' imm field.
            LD_DW_IMM => {
                if (v_disable_lddw) return InterpreterError.UnsupportedInstruction;
                if (!isPcInProgram(self.program.len, self.reg[11] + 1)) {
                    return InterpreterError.ExecutionOverrun;
                }
                const next_imm_off: usize = @intCast((self.reg[11] + 1) * INSN_SIZE + 4);
                const hi = std.mem.readInt(i32, self.program[next_imm_off..][0..4], .little);
                const lo: u64 = @as(u64, @bitCast(insn.imm)) & 0xFFFF_FFFF;
                self.reg[dst] = lo | (@as(u64, @bitCast(@as(i64, hi))) << 32);
                self.reg[11] += 1;
                next_pc += 1;
            },

            // ── BPF_LDX (V0/V1/V3 — V2 swaps class) ──────────────────────────
            LD_B_REG => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] = try self.load(u8, self.reg[src], insn.off);
            },
            LD_H_REG => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] = try self.load(u16, self.reg[src], insn.off);
            },
            LD_W_REG => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] = try self.load(u32, self.reg[src], insn.off);
            },
            LD_DW_REG => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] = try self.load(u64, self.reg[src], insn.off);
            },

            // ── BPF_ST imm ───────────────────────────────────────────────────
            ST_B_IMM => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u8, self.reg[dst], insn.off, @as(u8, @truncate(@as(u64, @bitCast(insn.imm)))));
            },
            ST_H_IMM => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u16, self.reg[dst], insn.off, @as(u16, @truncate(@as(u64, @bitCast(insn.imm)))));
            },
            ST_W_IMM => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u32, self.reg[dst], insn.off, @as(u32, @truncate(@as(u64, @bitCast(insn.imm)))));
            },
            ST_DW_IMM => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u64, self.reg[dst], insn.off, @as(u64, @bitCast(insn.imm)));
            },

            // ── BPF_STX ──────────────────────────────────────────────────────
            ST_B_REG => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u8, self.reg[dst], insn.off, @truncate(self.reg[src]));
            },
            ST_H_REG => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u16, self.reg[dst], insn.off, @truncate(self.reg[src]));
            },
            ST_W_REG => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u32, self.reg[dst], insn.off, @truncate(self.reg[src]));
            },
            ST_DW_REG => {
                if (v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u64, self.reg[dst], insn.off, self.reg[src]);
            },

            // ── ALU32 ────────────────────────────────────────────────────────
            ADD32_IMM => self.reg[dst] = self.signExt(@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) +% @as(i32, @truncate(insn.imm))),
            ADD32_REG => self.reg[dst] = self.signExt(@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) +% @as(i32, @bitCast(@as(u32, @truncate(self.reg[src]))))),
            SUB32_IMM => {
                const d32: i32 = @bitCast(@as(u32, @truncate(self.reg[dst])));
                const k32: i32 = @truncate(insn.imm);
                self.reg[dst] = if (v_swap_sub_imm) self.signExt(k32 -% d32) else self.signExt(d32 -% k32);
            },
            SUB32_REG => self.reg[dst] = self.signExt(@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) -% @as(i32, @bitCast(@as(u32, @truncate(self.reg[src]))))),
            MUL32_IMM => {
                if (v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const r: i32 = @as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) *% @as(i32, @truncate(insn.imm));
                self.reg[dst] = self.signExt(r);
            },
            MUL32_REG => { // == LD_1B_REG (0x2c) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    self.reg[dst] = try self.load(u8, self.reg[src], insn.off);
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    const r: i32 = @as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) *% @as(i32, @bitCast(@as(u32, @truncate(self.reg[src]))));
                    self.reg[dst] = self.signExt(r);
                }
            },
            DIV32_IMM => {
                if (v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const k: u32 = @bitCast(@as(i32, @truncate(insn.imm)));
                if (k == 0) return InterpreterError.DivideByZero;
                self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) / k);
            },
            DIV32_REG => { // == LD_2B_REG (0x3c) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    self.reg[dst] = try self.load(u16, self.reg[src], insn.off);
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    const s: u32 = @truncate(self.reg[src]);
                    if (s == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) / s);
                }
            },
            OR32_IMM => self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) | @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))),
            OR32_REG => self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) | @as(u32, @truncate(self.reg[src]))),
            AND32_IMM => self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) & @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))),
            AND32_REG => self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) & @as(u32, @truncate(self.reg[src]))),
            // SIMD-0173 / sBPF: 32-bit shift amount masked to & 31 (matches x86 SHL/SHR + Rust wrapping_shl/shr).
            LSH32_IMM => {
                const x: u32 = @truncate(self.reg[dst]);
                const n: u5 = @truncate(@as(u32, @bitCast(@as(i32, @truncate(insn.imm)))));
                self.reg[dst] = @as(u64, x << n);
            },
            LSH32_REG => {
                const x: u32 = @truncate(self.reg[dst]);
                const n: u5 = @truncate(self.reg[src]);
                self.reg[dst] = @as(u64, x << n);
            },
            RSH32_IMM => {
                const x: u32 = @truncate(self.reg[dst]);
                const n: u5 = @truncate(@as(u32, @bitCast(@as(i32, @truncate(insn.imm)))));
                self.reg[dst] = @as(u64, x >> n);
            },
            RSH32_REG => {
                const x: u32 = @truncate(self.reg[dst]);
                const n: u5 = @truncate(self.reg[src]);
                self.reg[dst] = @as(u64, x >> n);
            },
            NEG32 => {
                if (v_disable_neg) return InterpreterError.UnsupportedInstruction;
                const x: i32 = @bitCast(@as(u32, @truncate(self.reg[dst])));
                self.reg[dst] = @as(u64, @as(u32, @bitCast(-%x)));
            },
            MOD32_IMM => {
                if (v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const k: u32 = @bitCast(@as(i32, @truncate(insn.imm)));
                if (k == 0) return InterpreterError.DivideByZero;
                self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) % k);
            },
            MOD32_REG => { // == LD_8B_REG (0x9c) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    self.reg[dst] = try self.load(u64, self.reg[src], insn.off);
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    const s: u32 = @truncate(self.reg[src]);
                    if (s == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) % s);
                }
            },
            XOR32_IMM => self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) ^ @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))),
            XOR32_REG => self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) ^ @as(u32, @truncate(self.reg[src]))),
            MOV32_IMM => self.reg[dst] = @as(u64, @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))),
            MOV32_REG => {
                if (v_explicit_sext) {
                    // V2: sign-extend the 32-bit src.
                    const s32: i32 = @bitCast(@as(u32, @truncate(self.reg[src])));
                    self.reg[dst] = @bitCast(@as(i64, s32));
                } else {
                    self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[src])));
                }
            },
            ARSH32_IMM => {
                const x: i32 = @bitCast(@as(u32, @truncate(self.reg[dst])));
                const n: u5 = @truncate(@as(u32, @bitCast(@as(i32, @truncate(insn.imm)))));
                const r: i32 = x >> n;
                self.reg[dst] = @as(u64, @as(u32, @bitCast(r)));
            },
            ARSH32_REG => {
                const x: i32 = @bitCast(@as(u32, @truncate(self.reg[dst])));
                const n: u5 = @truncate(self.reg[src]);
                const r: i32 = x >> n;
                self.reg[dst] = @as(u64, @as(u32, @bitCast(r)));
            },
            LE => {
                if (v_disable_le) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] = switch (insn.imm) {
                    16 => std.mem.nativeToLittle(u16, @as(u16, @truncate(self.reg[dst]))),
                    32 => std.mem.nativeToLittle(u32, @as(u32, @truncate(self.reg[dst]))),
                    64 => std.mem.nativeToLittle(u64, self.reg[dst]),
                    else => return InterpreterError.InvalidInstruction,
                };
            },
            BE => {
                self.reg[dst] = switch (insn.imm) {
                    16 => std.mem.nativeToBig(u16, @as(u16, @truncate(self.reg[dst]))),
                    32 => std.mem.nativeToBig(u32, @as(u32, @truncate(self.reg[dst]))),
                    64 => std.mem.nativeToBig(u64, self.reg[dst]),
                    else => return InterpreterError.InvalidInstruction,
                };
            },

            // ── ALU64 ────────────────────────────────────────────────────────
            ADD64_IMM => self.reg[dst] = self.reg[dst] +% @as(u64, @bitCast(insn.imm)),
            ADD64_REG => self.reg[dst] = self.reg[dst] +% self.reg[src],
            SUB64_IMM => {
                const k: u64 = @bitCast(insn.imm);
                self.reg[dst] = if (v_swap_sub_imm) k -% self.reg[dst] else self.reg[dst] -% k;
            },
            SUB64_REG => self.reg[dst] = self.reg[dst] -% self.reg[src],
            MUL64_IMM => { // == ST_1B_IMM (0x27) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    try self.store(u8, self.reg[dst], insn.off, @truncate(@as(u64, @bitCast(insn.imm))));
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    self.reg[dst] = self.reg[dst] *% @as(u64, @bitCast(insn.imm));
                }
            },
            MUL64_REG => { // == ST_1B_REG (0x2f) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    try self.store(u8, self.reg[dst], insn.off, @truncate(self.reg[src]));
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    self.reg[dst] = self.reg[dst] *% self.reg[src];
                }
            },
            DIV64_IMM => { // == ST_2B_IMM (0x37) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    try self.store(u16, self.reg[dst], insn.off, @truncate(@as(u64, @bitCast(insn.imm))));
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    const k: u64 = @bitCast(insn.imm);
                    if (k == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] /= k;
                }
            },
            DIV64_REG => { // == ST_2B_REG (0x3f) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    try self.store(u16, self.reg[dst], insn.off, @truncate(self.reg[src]));
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    if (self.reg[src] == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] /= self.reg[src];
                }
            },
            OR64_IMM => self.reg[dst] |= @as(u64, @bitCast(insn.imm)),
            OR64_REG => self.reg[dst] |= self.reg[src],
            AND64_IMM => self.reg[dst] &= @as(u64, @bitCast(insn.imm)),
            AND64_REG => self.reg[dst] &= self.reg[src],
            // SIMD-0173 / sBPF: 64-bit shift amount masked to & 63 (matches x86 SHL/SHR + Rust wrapping_shl/shr).
            LSH64_IMM => {
                const n: u6 = @truncate(@as(u64, @bitCast(@as(i64, @as(i32, @truncate(insn.imm))))));
                self.reg[dst] = self.reg[dst] << n;
            },
            LSH64_REG => {
                const n: u6 = @truncate(self.reg[src]);
                self.reg[dst] = self.reg[dst] << n;
            },
            RSH64_IMM => {
                const n: u6 = @truncate(@as(u64, @bitCast(@as(i64, @as(i32, @truncate(insn.imm))))));
                self.reg[dst] = self.reg[dst] >> n;
            },
            RSH64_REG => {
                const n: u6 = @truncate(self.reg[src]);
                self.reg[dst] = self.reg[dst] >> n;
            },
            NEG64 => { // == ST_4B_IMM (0x87) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    try self.store(u32, self.reg[dst], insn.off, @truncate(@as(u64, @bitCast(insn.imm))));
                } else if (v_disable_neg) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    const x: i64 = @bitCast(self.reg[dst]);
                    self.reg[dst] = @bitCast(-%x);
                }
            },
            MOD64_IMM => { // == ST_8B_IMM (0x97) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    try self.store(u64, self.reg[dst], insn.off, @as(u64, @bitCast(insn.imm)));
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    const k: u64 = @bitCast(insn.imm);
                    if (k == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] %= k;
                }
            },
            MOD64_REG => { // == ST_8B_REG (0x9f) under V2 SIMD-0173
                if (v_move_mem_classes) {
                    try self.store(u64, self.reg[dst], insn.off, self.reg[src]);
                } else if (v_enable_pqr) {
                    return InterpreterError.UnsupportedInstruction;
                } else {
                    if (self.reg[src] == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] %= self.reg[src];
                }
            },
            // V2 LD_4B_REG (0x8c) — no non-V2 collision, gated arm.
            LD_4B_REG => {
                if (!v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] = try self.load(u32, self.reg[src], insn.off);
            },
            // V2 ST_4B_REG (0x8f) — no non-V2 collision.
            ST_4B_REG => {
                if (!v_move_mem_classes) return InterpreterError.UnsupportedInstruction;
                try self.store(u32, self.reg[dst], insn.off, @truncate(self.reg[src]));
            },
            XOR64_IMM => self.reg[dst] ^= @as(u64, @bitCast(insn.imm)),
            XOR64_REG => self.reg[dst] ^= self.reg[src],
            MOV64_IMM => self.reg[dst] = @as(u64, @bitCast(insn.imm)),
            MOV64_REG => self.reg[dst] = self.reg[src],
            ARSH64_IMM => {
                const x: i64 = @bitCast(self.reg[dst]);
                const n: u6 = @truncate(@as(u64, @bitCast(@as(i64, @as(i32, @truncate(insn.imm))))));
                self.reg[dst] = @bitCast(x >> n);
            },
            ARSH64_REG => {
                const x: i64 = @bitCast(self.reg[dst]);
                const n: u6 = @truncate(self.reg[src]);
                self.reg[dst] = @bitCast(x >> n);
            },
            HOR64_IMM => {
                if (!v_disable_lddw) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] |= std.math.shl(u64, @as(u64, @bitCast(insn.imm)), 32);
            },

            // ── PQR (V2 only) ────────────────────────────────────────────────
            LMUL32_IMM => {
                if (!v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const r = @as(u32, @truncate(self.reg[dst])) *% @as(u32, @bitCast(@as(i32, @truncate(insn.imm))));
                self.reg[dst] = @as(u64, r);
            },
            LMUL32_REG => {
                if (!v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const r = @as(u32, @truncate(self.reg[dst])) *% @as(u32, @truncate(self.reg[src]));
                self.reg[dst] = @as(u64, r);
            },
            LMUL64_IMM => {
                if (!v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] = self.reg[dst] *% @as(u64, @bitCast(insn.imm));
            },
            LMUL64_REG => {
                if (!v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                self.reg[dst] = self.reg[dst] *% self.reg[src];
            },
            UHMUL64_IMM => { // == JGE32_IMM (0x36) under V3 enable_jmp32
                if (v_enable_pqr) {
                    const a128: u128 = self.reg[dst];
                    const b128: u128 = @as(u32, @bitCast(@as(i32, @truncate(insn.imm))));
                    self.reg[dst] = @truncate((a128 *% b128) >> 64);
                } else if (v_enable_jmp32) {
                    if (@as(u32, @truncate(self.reg[dst])) >= @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UHMUL64_REG => { // == JGE32_REG (0x3e) under V3 enable_jmp32
                if (v_enable_pqr) {
                    const a128: u128 = self.reg[dst];
                    const b128: u128 = self.reg[src];
                    self.reg[dst] = @truncate((a128 *% b128) >> 64);
                } else if (v_enable_jmp32) {
                    if (@as(u32, @truncate(self.reg[dst])) >= @as(u32, @truncate(self.reg[src]))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            SHMUL64_IMM => { // == JLE32_IMM (0xb6) under V3
                if (v_enable_pqr) {
                    const a128: i128 = @as(i64, @bitCast(self.reg[dst]));
                    const b128: i128 = insn.imm;
                    self.reg[dst] = @bitCast(@as(i64, @truncate(@as(i128, @bitCast(@as(u128, @bitCast(a128 *% b128)) >> 64)))));
                } else if (v_enable_jmp32) {
                    if (@as(u32, @truncate(self.reg[dst])) <= @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            SHMUL64_REG => { // == JLE32_REG (0xbe) under V3
                if (v_enable_pqr) {
                    const a128: i128 = @as(i64, @bitCast(self.reg[dst]));
                    const b128: i128 = @as(i64, @bitCast(self.reg[src]));
                    self.reg[dst] = @bitCast(@as(i64, @truncate(@as(i128, @bitCast(@as(u128, @bitCast(a128 *% b128)) >> 64)))));
                } else if (v_enable_jmp32) {
                    if (@as(u32, @truncate(self.reg[dst])) <= @as(u32, @truncate(self.reg[src]))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UDIV32_IMM => { // == JSET32_IMM (0x46) under V3
                if (v_enable_pqr) {
                    const k: u32 = @bitCast(@as(i32, @truncate(insn.imm)));
                    if (k == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) / k);
                } else if (v_enable_jmp32) {
                    if ((@as(u32, @truncate(self.reg[dst])) & @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))) != 0) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UDIV32_REG => { // == JSET32_REG (0x4e) under V3
                if (v_enable_pqr) {
                    const s: u32 = @truncate(self.reg[src]);
                    if (s == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) / s);
                } else if (v_enable_jmp32) {
                    if ((@as(u32, @truncate(self.reg[dst])) & @as(u32, @truncate(self.reg[src]))) != 0) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UDIV64_IMM => { // == JNE32_IMM (0x56) under V3
                if (v_enable_pqr) {
                    const k: u64 = @as(u32, @bitCast(@as(i32, @truncate(insn.imm))));
                    if (k == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] /= k;
                } else if (v_enable_jmp32) {
                    if (@as(u32, @truncate(self.reg[dst])) != @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UDIV64_REG => { // == JNE32_REG (0x5e) under V3
                if (v_enable_pqr) {
                    if (self.reg[src] == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] /= self.reg[src];
                } else if (v_enable_jmp32) {
                    if (@as(u32, @truncate(self.reg[dst])) != @as(u32, @truncate(self.reg[src]))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UREM32_IMM => { // == JSGT32_IMM (0x66) under V3
                if (v_enable_pqr) {
                    const k: u32 = @bitCast(@as(i32, @truncate(insn.imm)));
                    if (k == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) % k);
                } else if (v_enable_jmp32) {
                    if (@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) > @as(i32, @truncate(insn.imm))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UREM32_REG => { // == JSGT32_REG (0x6e) under V3
                if (v_enable_pqr) {
                    const s: u32 = @truncate(self.reg[src]);
                    if (s == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] = @as(u64, @as(u32, @truncate(self.reg[dst])) % s);
                } else if (v_enable_jmp32) {
                    if (@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) > @as(i32, @bitCast(@as(u32, @truncate(self.reg[src]))))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UREM64_IMM => { // == JSGE32_IMM (0x76) under V3
                if (v_enable_pqr) {
                    const k: u64 = @as(u32, @bitCast(@as(i32, @truncate(insn.imm))));
                    if (k == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] %= k;
                } else if (v_enable_jmp32) {
                    if (@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) >= @as(i32, @truncate(insn.imm))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            UREM64_REG => { // == JSGE32_REG (0x7e) under V3
                if (v_enable_pqr) {
                    if (self.reg[src] == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] %= self.reg[src];
                } else if (v_enable_jmp32) {
                    if (@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) >= @as(i32, @bitCast(@as(u32, @truncate(self.reg[src]))))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            SDIV32_IMM => { // == JSLT32_IMM (0xc6) under V3
                if (v_enable_pqr) {
                    const d: i32 = @bitCast(@as(u32, @truncate(self.reg[dst])));
                    const k: i32 = @truncate(insn.imm);
                    if (d == std.math.minInt(i32) and k == -1) return InterpreterError.DivideOverflow;
                    if (k == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] = @as(u64, @as(u32, @bitCast(@divTrunc(d, k))));
                } else if (v_enable_jmp32) {
                    if (@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) < @as(i32, @truncate(insn.imm))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            SDIV32_REG => { // == JSLT32_REG (0xce) under V3
                if (v_enable_pqr) {
                    const d: i32 = @bitCast(@as(u32, @truncate(self.reg[dst])));
                    const s: i32 = @bitCast(@as(u32, @truncate(self.reg[src])));
                    if (s == 0) return InterpreterError.DivideByZero;
                    if (d == std.math.minInt(i32) and s == -1) return InterpreterError.DivideOverflow;
                    self.reg[dst] = @as(u64, @as(u32, @bitCast(@divTrunc(d, s))));
                } else if (v_enable_jmp32) {
                    if (@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) < @as(i32, @bitCast(@as(u32, @truncate(self.reg[src]))))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            SDIV64_IMM => { // == JSLE32_IMM (0xd6) under V3
                if (v_enable_pqr) {
                    const d: i64 = @bitCast(self.reg[dst]);
                    const k: i64 = insn.imm;
                    if (d == std.math.minInt(i64) and k == -1) return InterpreterError.DivideOverflow;
                    if (k == 0) return InterpreterError.DivideByZero;
                    self.reg[dst] = @bitCast(@divTrunc(d, k));
                } else if (v_enable_jmp32) {
                    if (@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) <= @as(i32, @truncate(insn.imm))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            SDIV64_REG => { // == JSLE32_REG (0xde) under V3
                if (v_enable_pqr) {
                    const d: i64 = @bitCast(self.reg[dst]);
                    const s: i64 = @bitCast(self.reg[src]);
                    if (s == 0) return InterpreterError.DivideByZero;
                    if (d == std.math.minInt(i64) and s == -1) return InterpreterError.DivideOverflow;
                    self.reg[dst] = @bitCast(@divTrunc(d, s));
                } else if (v_enable_jmp32) {
                    if (@as(i32, @bitCast(@as(u32, @truncate(self.reg[dst])))) <= @as(i32, @bitCast(@as(u32, @truncate(self.reg[src]))))) {
                        next_pc = jumpTarget(next_pc, insn.off);
                    }
                } else return InterpreterError.UnsupportedInstruction;
            },
            SREM32_IMM => {
                if (!v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const d: i32 = @bitCast(@as(u32, @truncate(self.reg[dst])));
                const k: i32 = @truncate(insn.imm);
                if (d == std.math.minInt(i32) and k == -1) return InterpreterError.DivideOverflow;
                if (k == 0) return InterpreterError.DivideByZero;
                self.reg[dst] = @as(u64, @as(u32, @bitCast(@rem(d, k))));
            },
            SREM32_REG => {
                if (!v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const d: i32 = @bitCast(@as(u32, @truncate(self.reg[dst])));
                const s: i32 = @bitCast(@as(u32, @truncate(self.reg[src])));
                if (s == 0) return InterpreterError.DivideByZero;
                if (d == std.math.minInt(i32) and s == -1) return InterpreterError.DivideOverflow;
                self.reg[dst] = @as(u64, @as(u32, @bitCast(@rem(d, s))));
            },
            SREM64_IMM => {
                if (!v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const d: i64 = @bitCast(self.reg[dst]);
                const k: i64 = insn.imm;
                if (d == std.math.minInt(i64) and k == -1) return InterpreterError.DivideOverflow;
                if (k == 0) return InterpreterError.DivideByZero;
                self.reg[dst] = @bitCast(@rem(d, k));
            },
            SREM64_REG => {
                if (!v_enable_pqr) return InterpreterError.UnsupportedInstruction;
                const d: i64 = @bitCast(self.reg[dst]);
                const s: i64 = @bitCast(self.reg[src]);
                if (s == 0) return InterpreterError.DivideByZero;
                if (d == std.math.minInt(i64) and s == -1) return InterpreterError.DivideOverflow;
                self.reg[dst] = @bitCast(@rem(d, s));
            },

            // ── JMP32 (V3+) — only the arms that DON'T collide with PQR ──
            // Colliding pairs (JGE/JSET/JNE/JSGT/JSGE/JLE/JSLT/JSLE × IMM/REG)
            // are merged into the corresponding PQR arms above.
            JEQ32_IMM => {
                if (!v_enable_jmp32) return InterpreterError.UnsupportedInstruction;
                if (@as(u32, @truncate(self.reg[dst])) == @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))) {
                    next_pc = jumpTarget(next_pc, insn.off);
                }
            },
            JEQ32_REG => {
                if (!v_enable_jmp32) return InterpreterError.UnsupportedInstruction;
                if (@as(u32, @truncate(self.reg[dst])) == @as(u32, @truncate(self.reg[src]))) {
                    next_pc = jumpTarget(next_pc, insn.off);
                }
            },
            JGT32_IMM => {
                if (!v_enable_jmp32) return InterpreterError.UnsupportedInstruction;
                if (@as(u32, @truncate(self.reg[dst])) > @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))) {
                    next_pc = jumpTarget(next_pc, insn.off);
                }
            },
            JGT32_REG => {
                if (!v_enable_jmp32) return InterpreterError.UnsupportedInstruction;
                if (@as(u32, @truncate(self.reg[dst])) > @as(u32, @truncate(self.reg[src]))) {
                    next_pc = jumpTarget(next_pc, insn.off);
                }
            },
            JLT32_IMM => {
                if (!v_enable_jmp32) return InterpreterError.UnsupportedInstruction;
                if (@as(u32, @truncate(self.reg[dst])) < @as(u32, @bitCast(@as(i32, @truncate(insn.imm))))) {
                    next_pc = jumpTarget(next_pc, insn.off);
                }
            },
            JLT32_REG => {
                if (!v_enable_jmp32) return InterpreterError.UnsupportedInstruction;
                if (@as(u32, @truncate(self.reg[dst])) < @as(u32, @truncate(self.reg[src]))) {
                    next_pc = jumpTarget(next_pc, insn.off);
                }
            },

            // ── JMP64 ────────────────────────────────────────────────────────
            JA => next_pc = jumpTarget(next_pc, insn.off),
            JEQ64_IMM => if (self.reg[dst] == @as(u64, @bitCast(insn.imm))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JEQ64_REG => if (self.reg[dst] == self.reg[src]) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JGT64_IMM => if (self.reg[dst] > @as(u64, @bitCast(insn.imm))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JGT64_REG => if (self.reg[dst] > self.reg[src]) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JGE64_IMM => if (self.reg[dst] >= @as(u64, @bitCast(insn.imm))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JGE64_REG => if (self.reg[dst] >= self.reg[src]) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JLT64_IMM => if (self.reg[dst] < @as(u64, @bitCast(insn.imm))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JLT64_REG => if (self.reg[dst] < self.reg[src]) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JLE64_IMM => if (self.reg[dst] <= @as(u64, @bitCast(insn.imm))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JLE64_REG => if (self.reg[dst] <= self.reg[src]) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSET64_IMM => if ((self.reg[dst] & @as(u64, @bitCast(insn.imm))) != 0) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSET64_REG => if ((self.reg[dst] & self.reg[src]) != 0) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JNE64_IMM => if (self.reg[dst] != @as(u64, @bitCast(insn.imm))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JNE64_REG => if (self.reg[dst] != self.reg[src]) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSGT64_IMM => if (@as(i64, @bitCast(self.reg[dst])) > insn.imm) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSGT64_REG => if (@as(i64, @bitCast(self.reg[dst])) > @as(i64, @bitCast(self.reg[src]))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSGE64_IMM => if (@as(i64, @bitCast(self.reg[dst])) >= insn.imm) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSGE64_REG => if (@as(i64, @bitCast(self.reg[dst])) >= @as(i64, @bitCast(self.reg[src]))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSLT64_IMM => if (@as(i64, @bitCast(self.reg[dst])) < insn.imm) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSLT64_REG => if (@as(i64, @bitCast(self.reg[dst])) < @as(i64, @bitCast(self.reg[src]))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSLE64_IMM => if (@as(i64, @bitCast(self.reg[dst])) <= insn.imm) {
                next_pc = jumpTarget(next_pc, insn.off);
            },
            JSLE64_REG => if (@as(i64, @bitCast(self.reg[dst])) <= @as(i64, @bitCast(self.reg[src]))) {
                next_pc = jumpTarget(next_pc, insn.off);
            },

            // ── CALL_REG ─────────────────────────────────────────────────────
            // interpreter.rs:528-540. Target reg differs by version.
            CALL_REG => {
                const which_reg_idx: usize = if (v_callx_uses_src)
                    src
                else if (v_callx_uses_dst)
                    dst
                else
                    @as(usize, @intCast(@as(u32, @bitCast(@as(i32, @truncate(insn.imm))))));
                const target_addr: u64 = self.reg[which_reg_idx];
                try self.pushFrame(v_manual_stack_bump, v_stack_frame_gaps);
                const target_pc: u64 = (target_addr -% self.program_vm_addr) / INSN_SIZE;
                if (!isPcInProgram(self.program.len, target_pc)) {
                    // F6: CallOutsideTextSegment from CALL_REG —
                    // capture caller_pc, target_addr, source_reg for upstream trace.
                    heap_trace.recordCallxFail(self.reg[11], target_addr, @intCast(which_reg_idx), self.reg[1], self.reg[10]);
                    // F8: also dump 64 bytes at r1 vmaddr to
                    // see the struct/&Arguments panic was given.
                    if (self.mm.vmap(.load, self.reg[1], 64)) |r1_slice| {
                        heap_trace.dumpStructAtVaddr("r1", self.reg[11], self.reg[1], r1_slice);
                    } else |_| {}
                    // diag — print version/target-reg semantics for the abort
                    std.log.warn("[CALLX-DIAG] caller_pc={d} v={s} which_reg=r{d} target_addr=0x{x} program_vm_addr=0x{x} target_pc={d} text_len={d} insn.imm={d} insn.src=r{d} insn.dst=r{d}", .{
                        self.reg[11],                 @tagName(v),
                        which_reg_idx,                target_addr,
                        self.program_vm_addr,         target_pc,
                        self.program.len / INSN_SIZE, insn.imm,
                        src,                          dst,
                    });
                    return InterpreterError.CallOutsideTextSegment;
                }
                heap_trace.recordCallxOk(self.reg[11], target_addr, @intCast(which_reg_idx));
                next_pc = target_pc;
            },

            // ── CALL_IMM ─────────────────────────────────────────────────────
            // interpreter.rs:542-577.
            CALL_IMM => {
                var resolved = false;

                // External syscall (legacy hash lookup or static slot=0).
                if (!v_static_syscalls or insn.src == 0) {
                    const hash: u32 = @bitCast(@as(i32, @truncate(insn.imm)));
                    if (self.syscalls.lookup(hash)) |slot| {
                        const r6_before = self.reg[6];
                        heap_trace.recordSyscallEntry(self.reg[11], hash, self.reg[1], self.reg[2], self.reg[3], self.reg[4], self.reg[5], r6_before);
                        // CU-METER settle (anza-sbpf interpreter.rs:612-616):
                        // charge the insns owed since the last reconcile into
                        // the shared CU meter BEFORE the syscall consumes its
                        // own cost from that same meter.
                        if (config.enable_instruction_meter) {
                            if (self.syscalls.vtable.consume) |consume_fn| {
                                consume_fn(self.invoke_ctx, self.due_insn_count);
                                self.due_insn_count = 0;
                            }
                        }
                        const r0 = try self.syscalls.invoke(
                            self.invoke_ctx,
                            slot,
                            self.reg[1],
                            self.reg[2],
                            self.reg[3],
                            self.reg[4],
                            self.reg[5],
                        );
                        // CU-METER refresh: the VM ceiling becomes whatever the
                        // syscall left in the shared meter (0 left ⇒ the next
                        // step's `due >= meter` check aborts, matching the
                        // cluster's "exceeded CUs meter at BPF instruction").
                        if (config.enable_instruction_meter) {
                            if (self.syscalls.vtable.remaining) |remaining_fn| {
                                self.previous_instruction_meter = remaining_fn(self.invoke_ctx);
                            }
                        }
                        self.reg[0] = r0;
                        heap_trace.recordSyscallExit(self.reg[11], hash, r0, self.reg[6]);
                        resolved = true;
                    }
                }

                // Internal call.
                if (!resolved) {
                    if (v_static_syscalls) {
                        if (insn.src == 1) {
                            // V3 static internal call: target = next_pc + imm.
                            const t_signed: i64 = @as(i64, @intCast(next_pc)) +% insn.imm;
                            if (t_signed >= 0) {
                                const t: u64 = @intCast(t_signed);
                                if (isPcInProgram(self.program.len, t)) {
                                    try self.pushFrame(v_manual_stack_bump, v_stack_frame_gaps);
                                    next_pc = t;
                                    const ib: u64 = std.mem.readInt(u64, self.program[(self.reg[11] * INSN_SIZE)..][0..8], .little);
                                    heap_trace.recordCall(self.reg[11], next_pc, self.reg[6], self.reg[10], ib);
                                    if (next_pc == 43636) heap_trace.dumpFn43636Bytes(self.program);
                                    resolved = true;
                                }
                            }
                        }
                    } else {
                        // Legacy: function_registry lookup. M3 verifier will
                        // have populated it; we don't keep our own copy.
                        const hash: u32 = @bitCast(@as(i32, @truncate(insn.imm)));
                        if (self.executable.function_registry.lookupByKey(hash)) |target_pc_usz| {
                            try self.pushFrame(v_manual_stack_bump, v_stack_frame_gaps);
                            const target_pc: u64 = @intCast(target_pc_usz);
                            if (!isPcInProgram(self.program.len, target_pc)) {
                                return InterpreterError.CallOutsideTextSegment;
                            }
                            next_pc = target_pc;
                            const ib: u64 = std.mem.readInt(u64, self.program[(self.reg[11] * INSN_SIZE)..][0..8], .little);
                            heap_trace.recordCall(self.reg[11], next_pc, self.reg[6], self.reg[10], ib);
                            if (next_pc == 43636) heap_trace.dumpFn43636Bytes(self.program);
                            resolved = true;
                        }
                    }
                }

                if (!resolved) return InterpreterError.UnsupportedInstruction;
            },

            // ── EXIT ─────────────────────────────────────────────────────────
            // interpreter.rs:578-594.
            EXIT => {
                if (self.call_depth == 0) {
                    if (config.enable_instruction_meter and
                        self.due_insn_count > self.previous_instruction_meter)
                    {
                        return InterpreterError.ExceededMaxInstructions;
                    }
                    self.program_result = self.reg[0];
                    return self.reg[0];
                }
                self.call_depth -= 1;
                const frame = self.call_frames[self.call_depth];
                self.reg[FRAME_PTR_REG] = frame.frame_pointer;
                @memcpy(
                    self.reg[FIRST_SCRATCH_REG .. FIRST_SCRATCH_REG + SCRATCH_REGS],
                    &frame.caller_saved_registers,
                );
                if (!isPcInProgram(self.program.len, frame.target_pc)) {
                    return InterpreterError.CallOutsideTextSegment;
                }
                next_pc = frame.target_pc;
            },

            else => return InterpreterError.UnsupportedInstruction,
        }

        self.reg[11] = next_pc;
        return null;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    inline fn signExt(self: *const Vm, value: i32) u64 {
        // interpreter.rs:158-168.
        const v_explicit = (self.sbpf_version == .v2);
        if (v_explicit) {
            return @as(u64, @as(u32, @bitCast(value)));
        } else {
            return @bitCast(@as(i64, value));
        }
    }

    inline fn vmAddr(reg_v: u64, off: i16) u64 {
        // (reg as i64).wrapping_add(off as i64) as u64
        const r: i64 = @bitCast(reg_v);
        const o: i64 = off;
        return @bitCast(r +% o);
    }

    fn load(self: *Vm, comptime T: type, base_reg: u64, off: i16) InterpreterError!u64 {
        const va = vmAddr(base_reg, off);
        const slice = self.mm.vmap(.load, va, @sizeOf(T)) catch
            return InterpreterError.AccessViolation;
        const value = std.mem.readInt(T, slice[0..@sizeOf(T)], .little);
        return @as(u64, value);
    }

    fn store(self: *Vm, comptime T: type, base_reg: u64, off: i16, value: T) InterpreterError!void {
        const va = vmAddr(base_reg, off);
        const slice = self.mm.vmap(.store, va, @sizeOf(T)) catch
            return InterpreterError.AccessViolation;
        std.mem.writeInt(T, slice[0..@sizeOf(T)], value, .little);
    }

    /// interpreter.rs:128-156 push_frame.
    /// vex-152m: V0 r10 stride = stack_frame_size * 2 (gapped).
    ///           V1/V2 = manual (program does the bump itself).
    ///           V3 = stack_frame_size * 1.
    fn pushFrame(self: *Vm, v_manual_stack_bump: bool, v_stack_frame_gaps: bool) InterpreterError!void {
        const i = self.call_depth;
        if (@as(usize, i) >= self.config.max_call_depth) {
            return InterpreterError.CallDepthExceeded;
        }
        var frame = &self.call_frames[i];
        @memcpy(
            &frame.caller_saved_registers,
            self.reg[FIRST_SCRATCH_REG .. FIRST_SCRATCH_REG + SCRATCH_REGS],
        );
        frame.frame_pointer = self.reg[FRAME_PTR_REG];
        frame.target_pc = self.reg[11] + 1;

        self.call_depth += 1;
        // agave checks `== max_call_depth` AFTER increment, which means the
        // 64th frame is rejected. Match that.
        if (@as(usize, self.call_depth) == self.config.max_call_depth) {
            return InterpreterError.CallDepthExceeded;
        }

        if (!v_manual_stack_bump) {
            const num_frames: u64 = if (v_stack_frame_gaps and self.config.enable_stack_frame_gaps) 2 else 1;
            const advance: u64 = @as(u64, self.config.stack_frame_size) * num_frames;
            self.reg[FRAME_PTR_REG] = self.reg[FRAME_PTR_REG] +% advance;
        }
    }
};

inline fn jumpTarget(next_pc: u64, off: i16) u64 {
    const np: i64 = @bitCast(next_pc);
    const o: i64 = off;
    return @bitCast(np +% o);
}

// ─── Compile-time exports for tests ───────────────────────────────────────────
//
// The test file (`interpreter_test.zig`) uses these to assemble micro-programs
// without re-deriving opcode constants.

pub const opc = struct {
    pub const ld_dw_imm = LD_DW_IMM;
    pub const ld_b_reg = LD_B_REG;
    pub const ld_h_reg = LD_H_REG;
    pub const ld_w_reg = LD_W_REG;
    pub const ld_dw_reg = LD_DW_REG;
    pub const st_b_reg = ST_B_REG;
    pub const st_h_reg = ST_H_REG;
    pub const st_w_reg = ST_W_REG;
    pub const st_dw_reg = ST_DW_REG;
    pub const ld_8b_reg = LD_8B_REG; // V2

    pub const add32_imm = ADD32_IMM;
    pub const sub32_imm = SUB32_IMM;
    pub const mul32_reg = MUL32_REG;
    pub const div32_imm = DIV32_IMM;
    pub const or32_imm = OR32_IMM;
    pub const and32_imm = AND32_IMM;
    pub const lsh32_imm = LSH32_IMM;
    pub const rsh32_imm = RSH32_IMM;
    pub const arsh32_imm = ARSH32_IMM;
    pub const neg32 = NEG32;
    pub const mod32_imm = MOD32_IMM;
    pub const xor32_imm = XOR32_IMM;
    pub const mov32_imm = MOV32_IMM;
    pub const mov32_reg = MOV32_REG;
    pub const le = LE;
    pub const be = BE;

    pub const add64_imm = ADD64_IMM;
    pub const add64_reg = ADD64_REG;
    pub const sub64_reg = SUB64_REG;
    pub const mul64_imm = MUL64_IMM;
    pub const div64_imm = DIV64_IMM;
    pub const mod64_imm = MOD64_IMM;
    pub const or64_imm = OR64_IMM;
    pub const and64_imm = AND64_IMM;
    pub const lsh64_imm = LSH64_IMM;
    pub const rsh64_imm = RSH64_IMM;
    pub const arsh64_imm = ARSH64_IMM;
    pub const neg64 = NEG64;
    pub const xor64_imm = XOR64_IMM;
    pub const mov64_imm = MOV64_IMM;
    pub const mov64_reg = MOV64_REG;
    pub const hor64_imm = HOR64_IMM;

    pub const sdiv64_imm = SDIV64_IMM;
    pub const udiv64_reg = UDIV64_REG;
    pub const lmul64_reg = LMUL64_REG;

    pub const ja = JA;
    pub const jeq64_imm = JEQ64_IMM;
    pub const jne64_imm = JNE64_IMM;
    pub const jgt64_imm = JGT64_IMM;
    pub const jset64_imm = JSET64_IMM;
    pub const jsgt64_imm = JSGT64_IMM;
    pub const jeq32_imm = JEQ32_IMM; // V3+

    pub const call_imm = CALL_IMM;
    pub const call_reg = CALL_REG;
    pub const exit = EXIT;
};

/// Encode a single 8-byte sBPF instruction into a buffer (test helper).
pub fn encode(opc_b: u8, dst: u4, src: u4, off: i16, imm: i32) [8]u8 {
    var buf: [8]u8 = undefined;
    buf[0] = opc_b;
    buf[1] = (@as(u8, @intCast(src)) << 4) | @as(u8, @intCast(dst));
    std.mem.writeInt(i16, buf[2..4], off, .little);
    std.mem.writeInt(i32, buf[4..8], imm, .little);
    return buf;
}
