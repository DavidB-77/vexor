//! sBPF instruction set definitions — V0 through V3
//!
//! References:
//!   fd_vm_base.h (opcode tables and version flags)
//!   sig/src/vm/sbpf.zig (Zig idiom for packed instruction layout)
//!
//! Version history (SIMDs that changed the ISA):
//!   V0  — legacy rbpf
//!   V1  — SIMD-0166: dynamic stack frames
//!   V2  — SIMD-0174: PQR arithmetic; SIMD-0173: encoding improvements
//!   V3  — SIMD-0178: static syscalls; SIMD-0179/0189: stricter ELF/verify

const std = @import("std");

// ── Virtual address region bases ─────────────────────────────────────────────
// fd_vm_base.h:FD_VM_MEM_MAP_*_REGION_START
pub const RODATA_START:  u64 = 0x100000000;
pub const STACK_START:   u64 = 0x200000000;
pub const HEAP_START:    u64 = 0x300000000;
pub const INPUT_START:   u64 = 0x400000000;
pub const BYTECODE_START:u64 = 0x000000000; // V3 only (SIMD-0189)

// ── VM limits ────────────────────────────────────────────────────────────────
pub const STACK_FRAME_SIZE: u64 = 4096;
pub const MAX_CALL_DEPTH:   u64 = 64;
pub const HEAP_SIZE:        u64 = 256 * 1024;
pub const MAX_FILE_SIZE:    u64 = 10 * 1024 * 1024;

// ── sBPF version (SIMD-0166/0174/0178) ───────────────────────────────────────
// fd_vm_private.h:sbpf_version / sig/src/vm/sbpf.zig:Version
pub const Version = enum(u32) {
    v0 = 0,   // legacy
    v1 = 1,   // SIMD-0166 dynamic frames
    v2 = 2,   // SIMD-0174 PQR, SIMD-0173 encoding
    v3 = 3,   // SIMD-0178 static syscalls, SIMD-0189 ELF

    // Feature predicates — cf. sig/src/vm/sbpf.zig
    pub fn dynamicStackFrames(v: Version) bool { return v.gte(.v1); }
    pub fn pqrArithmetic(v: Version) bool      { return v.gte(.v2); }
    pub fn swappedSubImm(v: Version) bool       { return v.gte(.v2); }
    pub fn disableLddw(v: Version) bool         { return v.gte(.v2); }
    pub fn callRegUsesSrc(v: Version) bool      { return v.gte(.v2); }
    pub fn disableLe(v: Version) bool           { return v.gte(.v2); }
    pub fn staticSyscalls(v: Version) bool      { return v.gte(.v3); }
    pub fn lowerBytecodeVaddr(v: Version) bool  { return v.gte(.v3); }
    pub fn rejectRodataStackOverlap(v: Version) bool { return v != .v0; }
    pub fn enableElfVaddr(v: Version) bool      { return v != .v0; }

    pub fn gte(v: Version, other: Version) bool {
        return @intFromEnum(v) >= @intFromEnum(other);
    }

    /// Compute call-imm target PC (differs between V0/V1 and V3).
    /// fd_vm_interp_core.c:0x85_static / sig/src/vm/sbpf.zig:computeTargetPc
    pub fn callImmTargetPc(v: Version, pc: u64, imm: u32) i64 {
        return if (v.staticSyscalls())
            // V3: pc + sign_extend(imm) + 1
            @as(i64, @intCast(pc)) +% @as(i64, @bitCast(@as(i64, @as(i32, @bitCast(imm))))) +% 1
        else
            // V0-V2: target_pc = fd_pchash_inverse(imm) (resolved at load time)
            @as(i64, @bitCast(@as(u64, imm)));
    }

    /// Text-region vaddr for this version. fd_vm_private.h
    pub fn textVaddr(v: Version) u64 {
        return if (v.lowerBytecodeVaddr()) BYTECODE_START else RODATA_START;
    }
};

// ── Instruction register encoding ────────────────────────────────────────────
// fd_vm_base.h:fd_vm_instr_dst/src / sig/src/vm/sbpf.zig:Register
pub const Register = enum(u4) {
    r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10,
    // pc is not a real sBPF register but we track it alongside
    pc,
};

// ── Packed 8-byte instruction ─────────────────────────────────────────────────
// Layout matches Agave / Firedancer exactly:
//   [7:0]  opcode
//   [11:8] dst register
//   [15:12] src register
//   [31:16] signed offset
//   [63:32] unsigned immediate
// fd_vm_base.h:fd_vm_instr_t / sig/src/vm/sbpf.zig:Instruction
pub const Instruction = packed struct(u64) {
    opcode: u8,
    dst: u4,
    src: u4,
    off: i16,
    imm: u32,

    comptime { std.debug.assert(@sizeOf(@This()) == 8); }

    // Convenience sign-extension: imm treated as i32 → sign-extended to u64.
    // fd_vm_interp_core.c uses (ulong)(long)(int)imm everywhere.
    pub inline fn sextImm(self: Instruction) u64 {
        return @bitCast(@as(i64, @as(i32, @bitCast(self.imm))));
    }
};

// ── Opcode constants (class bits and operation bits) ─────────────────────────
// fd_vm_base.h FD_SBPF_OP_* / sig/src/vm/sbpf.zig Instruction.OpCode

// Instruction class (low 3 bits of opcode)
pub const CLS_LD:    u8 = 0x00;  // 64-bit immediate load (lddw)
pub const CLS_LDX:   u8 = 0x01;  // memory load register
pub const CLS_ST:    u8 = 0x02;  // memory store immediate
pub const CLS_STX:   u8 = 0x03;  // memory store register
pub const CLS_ALU32: u8 = 0x04;  // 32-bit ALU
pub const CLS_JMP:   u8 = 0x05;  // unconditional / conditional jump + call/exit
pub const CLS_JMP32: u8 = 0x06;  // 32-bit conditional jump (V0+)
pub const CLS_ALU64: u8 = 0x07;  // 64-bit ALU

// Source bit: 0 = immediate, 1 = register
pub const SRC_IMM:   u8 = 0x00;
pub const SRC_REG:   u8 = 0x08;

// Size field (bits 4:3 in LD/ST class)
pub const SZ_B:  u8 = 0x00; // 1 byte
pub const SZ_H:  u8 = 0x08; // 2 bytes
pub const SZ_W:  u8 = 0x10; // 4 bytes
pub const SZ_DW: u8 = 0x18; // 8 bytes

// ALU operation (high nibble)
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
pub const ALU_HOR:  u8 = 0xe0; // SIMD-0173: hor64 (dst |= imm<<32)

// PQR class (SIMD-0174, V2+) replaces some formerly-invalid encodings
// CLS byte is still 0x04 (ALU32) but with distinct high bits
pub const PQR_CLS:  u8 = 0x08; // PQR class bit
pub const PQR_LMUL: u8 = 0x00;
pub const PQR_UHMUL:u8 = 0x10;
pub const PQR_SHMUL:u8 = 0x20;  // signed high mul
pub const PQR_UDIV: u8 = 0x40;
pub const PQR_UREM: u8 = 0x60;
pub const PQR_SDIV: u8 = 0x80;  // signed div
pub const PQR_SREM: u8 = 0xa0;  // signed rem
pub const PQR_64:   u8 = 0x01;  // 64-bit variant flag within PQR

// JMP operations (high nibble)
pub const JMP_JA:   u8 = 0x00;  // unconditional jump always
pub const JMP_JEQ:  u8 = 0x10;
pub const JMP_JGT:  u8 = 0x20;
pub const JMP_JGE:  u8 = 0x30;
pub const JMP_JSET: u8 = 0x40;
pub const JMP_JNE:  u8 = 0x50;
pub const JMP_JSGT: u8 = 0x60;
pub const JMP_JSGE: u8 = 0x70;
pub const JMP_CALL: u8 = 0x80;  // call imm / call reg (src selects)
pub const JMP_EXIT: u8 = 0x90;
pub const JMP_JLT:  u8 = 0xa0;
pub const JMP_JLE:  u8 = 0xb0;
pub const JMP_JSLT: u8 = 0xc0;
pub const JMP_JSLE: u8 = 0xd0;

// Full opcode bytes for frequently-used instructions
pub const OP_LDDW:    u8 = CLS_LD | SRC_IMM | SZ_DW; // 0x18 — two-word wide load
pub const OP_CALL_IMM:u8 = CLS_JMP | JMP_CALL | SRC_IMM; // 0x85
pub const OP_CALL_REG:u8 = CLS_JMP | JMP_CALL | SRC_REG; // 0x8d
pub const OP_EXIT:    u8 = CLS_JMP | JMP_EXIT | SRC_IMM; // 0x95

// ── ExecutionError (mirrors Agave/rbpf fault kinds) ───────────────────────────
// sig/src/vm/executable.zig:ExecutionError / fd_vm_private.h error labels
pub const ExecutionError = error{
    /// Instruction pointer overran text segment
    ExecutionOverrun,
    /// Instruction limit (compute budget) exceeded
    ExceededMaxInstructions,
    /// Divide-by-zero or mod-by-zero
    DivisionByZero,
    /// Memory access outside mapped regions
    AccessViolation,
    /// Stack region access violation (r10 frame pointer abuse)
    StackAccessViolation,
    /// Call to invalid address / unresolved function
    UnsupportedInstruction,
    /// call_reg target outside text segment
    CallOutsideTextSegment,
    /// Syscall returned an error
    SyscallError,
    /// Program called exit at depth 0 normally (not an error per se)
    Exit,
    /// Out-of-memory inside VM (shouldn't propagate but kept for safety)
    OutOfMemory,
    /// Invalid region for a memory operation
    InvalidMemoryRegion,
};

// ── Compute budget defaults ───────────────────────────────────────────────────
pub const ComputeBudget = struct {
    pub const DEFAULT_UNITS:          u64 = 200_000;
    pub const MAX_UNITS:              u64 = 1_400_000;
    pub const SHA256_BASE_COST:       u64 = 85;
    pub const SHA256_BYTE_COST:       u64 = 1;
    pub const KECCAK256_BASE_COST:    u64 = 36;
    pub const KECCAK256_BYTE_COST:    u64 = 1;
    pub const SECP256K1_COST:         u64 = 25_000;
    pub const SYSCALL_BASE_COST:      u64 = 100;
    pub const LOG_PUBKEY_COST:        u64 = 100;
    pub const CPI_BASE_COST:          u64 = 1_000;
    pub const MEM_OP_BASE_COST:       u64 = 10;
    pub const SYSVAR_BASE_COST:       u64 = 100;
    pub const CURVE25519_VALIDATE:    u64 = 159;
    pub const CURVE25519_GROUP_OP:    u64 = 2_242;
    pub const LOG_64_COST:            u64 = 100;
    pub const CPI_BYTES_PER_UNIT:     u64 = 250;
};
