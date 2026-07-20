//! Vexor sBPF bytecode verifier — spec-for-spec rebuild
//!
//! Canonical reference (locked):
//!   solana-sbpf v0.14.4 — solana-sbpf-v0.14.4/src/verifier.rs (~422 LoC)
//!   solana-sbpf v0.14.4 — src/program.rs:11-104 (SBPFVersion + version predicates)
//!   solana-sbpf v0.14.4 — src/ebpf.rs:26-540   (opcodes, INSN_SIZE, get_insn, FRAME_PTR_REG=10)
//!
//! Zig idiom reference (non-authoritative): sig — no `verifier*`
//! file present at `src/vm/verifier*` as of this snapshot; verifier logic
//! lives inline in sig's interpreter module. Therefore the canonical Rust
//! file is the only authoritative source for this rebuild.
//!
//! This module is the M3 deliverable of the parallel-directory rebuild. It
//! is self-contained except for one read-only import: `elf.zig` (M1) for
//! SbpfVersion + FunctionRegistry.
//!
//! ── Mirrored solana-sbpf-v0.14.4 verifier.rs ranges ─────────────────────────
//!   verifier.rs:18-78   VerifierError enum                  → VerifyError
//!   verifier.rs:94-102  check_prog_len                      → checkProgLen
//!   verifier.rs:104-109 check_imm_nonzero                   → checkImmNonzero
//!   verifier.rs:111-116 check_imm_endian                    → checkImmEndian
//!   verifier.rs:118-128 check_imm_aligned                   → checkImmAligned
//!   verifier.rs:130-140 check_load_dw                       → checkLoadDw
//!   verifier.rs:142-164 check_jmp_offset                    → checkJmpOffset
//!   verifier.rs:166-184 check_registers                     → checkRegisters
//!   verifier.rs:187-195 check_imm_shift                     → checkImmShift
//!   verifier.rs:197-214 check_callx_register                → checkCallxRegister
//!   verifier.rs:216-422 RequisiteVerifier::verify           → verify (public entry)
//!   ebpf.rs:670-684    get_insn_unchecked                  → getInsnUnchecked
//!   program.rs:32-93   SBPFVersion::* predicates           → free fns below
//!
//! ── Divergences from canonical (each justified) ─────────────────────────────
//! D1. VerifyError (per task spec) omits canonical's `ProgramTooLarge`,
//!     `NoProgram`, `DivisionByZero`, `InvalidSyscall`, `UnalignedImmediate`.
//!     Spec-for-spec SEMANTICS preserved by re-routing:
//!       NoProgram                → ProgramLengthNotMultipleOfInsnSize
//!         (empty .text is malformed; re-use the closest spec variant.)
//!       DivisionByZero(insn)     → UnknownOpcode
//!         (DIV/MOD with imm=0 is a malformed-instruction equivalent under
//!          our shorter taxonomy. checkImmNonzero CALLS still run — losing
//!          the call would silently let through DIV-by-zero bytecode.)
//!       UnalignedImmediate(insn) → InvalidRegister
//!         (Only fires for `ADD64 r10, imm` where imm % 8 != 0 in V1/V2
//!          manual-stack-frame-bump mode. Closest spec fit is "bad operand
//!          on a register-targeted insn" — InvalidRegister.)
//!       InvalidSyscall(u32)      → not reachable
//!         (verifier.rs never emits InvalidSyscall — that variant is owned
//!          by the syscall-resolution layer. Omitting is parity, not a
//!          divergence.)
//!     Spec-listed extras NOT in canonical:
//!       InfiniteLoop  → DEFINED but NEVER EMITTED. canonical does not
//!         detect self-jumps, and adding a Vexor-only check would risk a
//!         consensus split. Locked-in: keep variant declared (spec contract)
//!         but never emit it. Documented in verifier_test.zig.
//!
//! D2. `VerifyConfig.enabled_sbpf_versions` is `std.StaticBitSet(4)` per
//!     spec, NOT M1 `Config`'s u8 bitmask. Different layers; user threads
//!     the live FeatureSet → both. A version that's loaded but disabled
//!     here returns `UnsupportedSbpfVersion` BEFORE the per-insn loop runs.
//!
//! D3. SBPFVersion predicates (manual_stack_frame_bump, enable_pqr,
//!     disable_lddw, disable_le, disable_neg, callx_uses_src_reg,
//!     callx_uses_dst_reg, move_memory_instruction_classes, enable_jmp32)
//!     are defined as FREE FUNCTIONS here mirroring program.rs:32-93
//!     verbatim. M1's elf.zig only exposes the three predicates the loader
//!     consults; we cannot modify M1.
//!
//! D4. Opcode dispatch uses RAW HEX BYTES instead of named constants.
//!     Reason: 26 opcode bytes COLLIDE between version-mutually-exclusive
//!     sets (e.g. 0x27 = ST_1B_IMM in V2, MUL64_IMM otherwise; 0x36 =
//!     UHMUL64_IMM in V2, JGE32_IMM in V3+; 0x46 = UDIV32_IMM vs JSET32_IMM;
//!     etc.). Rust's match-with-guards falls through; Zig switch demands
//!     unique case constants. By matching on raw bytes and version-gating
//!     inside each arm, we keep canonical semantics exact. The full
//!     collision map is reproduced in /tmp/opcheck.py from this build's
//!     research; pasted into the comment block at the dispatch site.
//!
//! ── SIMD inventory affecting verification ───────────────────────────────────
//! All feature pubkeys cross-referenced from solana-improvement-documents/.
//! Live activation status NOT queried inline — that's the SIMD sweep agent's
//! job. Listed here for cross-reference only:
//!
//!   SIMD-0166  dynamic stack frames (V1)                 — manual_stack_frame_bump
//!     pubkey: JE86WkYvTrzW8HgNmrHY7dFYpCmSptUpKupbo2AdQ9cG
//!   SIMD-0173  sBPF instruction encoding improvements (V2)
//!     pubkey: F6UVKh1ujTEFK3en2SyAL3cdVnqko1FVEXWhmdLRu6WP
//!     affects: callx_uses_src_reg, disable_lddw, disable_le,
//!              move_memory_instruction_classes
//!   SIMD-0174  sBPF arithmetics improvements (V2 — same gate as 0173)
//!     pubkey: F6UVKh1ujTEFK3en2SyAL3cdVnqko1FVEXWhmdLRu6WP
//!     affects: enable_pqr, disable_neg, explicit_sign_extension_of_results,
//!              swap_sub_reg_imm_operands
//!   SIMD-0178  static syscalls (V3)
//!     pubkey: BUwGLeF3Lxyfv1J1wY8biFHBB2hrk2QhbNftQf3VV3cC
//!     verifier impact: CALL_IMM points to a local fn (registry-resolved).
//!     Verifier accepts CALL_IMM; the loader's relocation step + the
//!     runtime registry handle resolution.
//!   SIMD-0189  sBPF stricter ELF headers (V3)
//!     pubkey: GJav1vwg2etvSWraPT96QvYuQJswJTJwtcyARrvkhuV9
//!     verifier impact: defense-in-depth. The loader rejects malformed ELFs
//!     first; the verifier still does its own per-instruction sanity pass.
//!   SIMD-0377  jmp32 + callx_uses_dst_reg (V3+)
//!     pubkey: not yet activated on testnet as of 2026-04-25
//!     verifier impact: enables JMP32 family + CALL_REG dst-reg sourcing.
//!
//! ── fix_ledger anchors honored ──────────────────────────────────────────────
//!   vex-079 (BPF_ALIGN_OF_U128 = 8) — serializer invariant, not verifier's.
//!     Verifier never inspects per-account alignment padding. Recorded so a
//!     future reader doesn't accidentally weave 16-byte alignment in here.
//!   vex-152n (program_region_vaddr = text_vaddr + base_vaddr) — loader
//!     invariant. Verifier operates on text bytes post-loader; vaddrs unused.
//!   vex-152o (single .text enforcement) — loader invariant. Verifier sees
//!     only the bytes of that one section.
//!   No prior fix_ledger entries lock verifier-specific invariants; this
//!     file establishes the first.

const std = @import("std");
const elf = @import("elf.zig");

/// Re-export so callers can `verifier.SbpfVersion`.
pub const SbpfVersion = elf.SbpfVersion;
/// Re-export.
pub const FunctionRegistry = elf.FunctionRegistry;

// ═══════════════════════════════════════════════════════════════════════════
//                       SBPFVersion predicates (program.rs:32-93)
// ═══════════════════════════════════════════════════════════════════════════
// Verbatim mirror of solana-sbpf-0.14.4 program.rs SBPFVersion methods.
// Defined as free fns because M1's SbpfVersion enum only exposes the three
// predicates the loader consults. Adding methods would mutate M1 (read-only).

/// SIMD-0166. program.rs:32-34. Allows `add64 r10, imm` (manual frame bump).
pub fn manualStackFrameBump(v: SbpfVersion) bool {
    return v == .v1 or v == .v2;
}
/// SIMD-0166. program.rs:36-38. V0 leaves a register-spill gap.
pub fn stackFrameGaps(v: SbpfVersion) bool {
    return v == .v0;
}
/// SIMD-0174. program.rs:41-43. PQR class.
pub fn enablePqr(v: SbpfVersion) bool {
    return v == .v2;
}
/// SIMD-0173. program.rs:58-60. CALL_REG reads target from src reg.
pub fn callxUsesSrcReg(v: SbpfVersion) bool {
    return v == .v2;
}
/// SIMD-0173. program.rs:62-64. lddw retired in V2.
pub fn disableLddw(v: SbpfVersion) bool {
    return v == .v2;
}
/// SIMD-0173. program.rs:66-68. LE retired in V2.
pub fn disableLe(v: SbpfVersion) bool {
    return v == .v2;
}
/// SIMD-0173. program.rs:70-72. LDX/STX classes get new opcodes in V2.
pub fn moveMemoryInstructionClasses(v: SbpfVersion) bool {
    return v == .v2;
}
/// SIMD-0174. program.rs:53-55. NEG retired in V2.
pub fn disableNeg(v: SbpfVersion) bool {
    return v == .v2;
}
/// SIMD-0377. program.rs:87-89. jmp32 family available in V3+.
pub fn enableJmp32(v: SbpfVersion) bool {
    return @intFromEnum(v) >= @intFromEnum(SbpfVersion.v3);
}
/// SIMD-0377. program.rs:91-93. CALL_REG reads target from dst reg in V3+.
pub fn callxUsesDstReg(v: SbpfVersion) bool {
    return @intFromEnum(v) >= @intFromEnum(SbpfVersion.v3);
}

// ═══════════════════════════════════════════════════════════════════════════
//                         Public surface
// ═══════════════════════════════════════════════════════════════════════════

/// Errors emitted by `verify`. Spec-locked subset of canonical
/// `VerifierError`; see module-level D1.
pub const VerifyError = error{
    InstructionPlusOpcodeOutOfBounds,
    UnknownOpcode,
    InvalidSourceRegister,
    InvalidDestinationRegister,
    CannotWriteToR10,
    InfiniteLoop,
    JumpOutOfCode,
    JumpToMiddleOfLddw,
    UnsupportedLEBEArgument,
    LDDWCannotBeLast,
    IncompleteLDDW,
    InvalidRegister,
    ShiftWithOverflow,
    ProgramLengthNotMultipleOfInsnSize,
    InvalidFunction,
    UnsupportedSbpfVersion,
};

/// Verifier-local config. NOT to be confused with M1's `elf.Config`.
pub const VerifyConfig = struct {
    /// Bit i set ⇒ Vi accepted. Default = V0..V3 enabled.
    enabled_sbpf_versions: std.StaticBitSet(4) = blk: {
        var b = std.StaticBitSet(4).initEmpty();
        b.set(0);
        b.set(1);
        b.set(2);
        b.set(3);
        break :blk b;
    },

    /// Reject `callx r10` / variants targeting r10. Defaults true (matches
    /// canonical RequisiteVerifier behavior — r10 is frame-pointer, never a
    /// valid call target).
    reject_callx_r10: bool = true,

    pub const DEFAULT: VerifyConfig = .{};

    pub fn versionEnabled(self: VerifyConfig, v: SbpfVersion) bool {
        return self.enabled_sbpf_versions.isSet(@intFromEnum(v));
    }
};

// ═══════════════════════════════════════════════════════════════════════════
//                         Internal: instruction decode
// ═══════════════════════════════════════════════════════════════════════════

/// ebpf.rs:541. Pre-decoded instruction.
const Insn = struct {
    ptr: usize,
    opc: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i64,
};

const INSN_SIZE: usize = 8;
const FRAME_PTR_REG: u8 = 10;

/// ebpf.rs:675-684 get_insn_unchecked. Caller ensures pc is in range.
inline fn getInsnUnchecked(prog: []const u8, pc: usize) Insn {
    const base = INSN_SIZE * pc;
    const reg_byte = prog[base + 1];
    const off = std.mem.readInt(i16, prog[base + 2 ..][0..2], .little);
    const imm32 = std.mem.readInt(i32, prog[base + 4 ..][0..4], .little);
    return Insn{
        .ptr = pc,
        .opc = prog[base],
        .dst = reg_byte & 0x0f,
        .src = (reg_byte & 0xf0) >> 4,
        .off = off,
        .imm = @as(i64, imm32),
    };
}

// ═══════════════════════════════════════════════════════════════════════════
//                         Internal helpers (verifier.rs:94-214)
// ═══════════════════════════════════════════════════════════════════════════

fn checkProgLen(prog: []const u8) VerifyError!void {
    if (prog.len % INSN_SIZE != 0) return VerifyError.ProgramLengthNotMultipleOfInsnSize;
    // canonical NoProgram → re-routed per D1.
    if (prog.len == 0) return VerifyError.ProgramLengthNotMultipleOfInsnSize;
}

fn checkImmNonzero(insn: Insn) VerifyError!void {
    // canonical DivisionByZero(insn.ptr) — re-routed to UnknownOpcode per D1.
    if (insn.imm == 0) return VerifyError.UnknownOpcode;
}

fn checkImmEndian(insn: Insn) VerifyError!void {
    switch (insn.imm) {
        16, 32, 64 => return,
        else => return VerifyError.UnsupportedLEBEArgument,
    }
}

fn checkImmAligned(insn: Insn, alignment: i64) VerifyError!void {
    // canonical UnalignedImmediate — re-routed to InvalidRegister per D1.
    if ((insn.imm & (alignment - 1)) != 0) return VerifyError.InvalidRegister;
}

fn checkLoadDw(prog: []const u8, insn_ptr: usize) VerifyError!void {
    if ((insn_ptr + 1) * INSN_SIZE >= prog.len) return VerifyError.LDDWCannotBeLast;
    const next = getInsnUnchecked(prog, insn_ptr + 1);
    if (next.opc != 0) return VerifyError.IncompleteLDDW;
}

fn checkJmpOffset(prog: []const u8, insn_ptr: usize, insn_count: usize) VerifyError!void {
    const insn = getInsnUnchecked(prog, insn_ptr);
    const dst_signed: i64 = @as(i64, @intCast(insn_ptr)) + 1 + @as(i64, insn.off);
    if (dst_signed < 0 or dst_signed >= @as(i64, @intCast(insn_count))) {
        return VerifyError.JumpOutOfCode;
    }
    const dst_pc: usize = @intCast(dst_signed);
    const dst_insn = getInsnUnchecked(prog, dst_pc);
    if (dst_insn.opc == 0) return VerifyError.JumpToMiddleOfLddw;
}

fn checkRegisters(insn: Insn, store: bool, version: SbpfVersion) VerifyError!void {
    if (insn.src > 10) return VerifyError.InvalidSourceRegister;
    if (insn.dst <= 9) return;
    if (insn.dst == FRAME_PTR_REG) {
        if (store) return; // STX targeting r10 is OK (write to stack pointer slot)
        // V1/V2 manual_stack_frame_bump permits ADD64_IMM r10, imm.
        if (manualStackFrameBump(version) and insn.opc == 0x07) return;
        return VerifyError.CannotWriteToR10;
    }
    return VerifyError.InvalidDestinationRegister;
}

fn checkImmShift(insn: Insn, imm_bits: u64) VerifyError!void {
    if (insn.imm < 0) return VerifyError.ShiftWithOverflow;
    const by: u64 = @intCast(insn.imm);
    if (by >= imm_bits) return VerifyError.ShiftWithOverflow;
}

fn checkCallxRegister(insn: Insn, version: SbpfVersion, cfg: VerifyConfig) VerifyError!void {
    const reg_i64: i64 = blk: {
        if (callxUsesSrcReg(version)) break :blk @as(i64, insn.src);
        if (callxUsesDstReg(version)) break :blk @as(i64, insn.dst);
        break :blk insn.imm;
    };
    if (reg_i64 == 10) {
        if (cfg.reject_callx_r10) return VerifyError.InvalidRegister;
        return;
    }
    if (reg_i64 < 0 or reg_i64 >= 10) return VerifyError.InvalidRegister;
}

// ═══════════════════════════════════════════════════════════════════════════
//                         Public entry: verify (verifier.rs:222-422)
// ═══════════════════════════════════════════════════════════════════════════
//
// Opcode collision matrix (computed; preserved in /tmp/opcheck.py during
// development). 26 colliding bytes; canonical verifier.rs disambiguates via
// `if !sbpf_version.X()` guards on each match arm. Zig requires unique
// switch cases, so we match on the RAW BYTE and dispatch on version inside
// each arm. Mapping (byte → V0/V1 meaning | V2 meaning | V3+ meaning):
//
//   0x27 — MUL64_IMM       | ST_1B_IMM       | MUL64_IMM (default)
//   0x2c — MUL32_REG       | LD_1B_REG       | MUL32_REG
//   0x2f — MUL64_REG       | ST_1B_REG       | MUL64_REG
//   0x36 — UHMUL64_IMM(no) | UHMUL64_IMM     | JGE32_IMM
//   0x37 — DIV64_IMM       | ST_2B_IMM       | DIV64_IMM
//   0x3c — DIV32_REG       | LD_2B_REG       | DIV32_REG
//   0x3e — UHMUL64_REG(no) | UHMUL64_REG     | JGE32_REG
//   0x3f — DIV64_REG       | ST_2B_REG       | DIV64_REG
//   0x46 — (unused V0/V1)  | UDIV32_IMM      | JSET32_IMM
//   0x4e — (unused V0/V1)  | UDIV32_REG      | JSET32_REG
//   0x56 — (unused V0/V1)  | UDIV64_IMM      | JNE32_IMM
//   0x5e — (unused V0/V1)  | UDIV64_REG      | JNE32_REG
//   0x66 — (unused V0/V1)  | UREM32_IMM      | JSGT32_IMM
//   0x6e — (unused V0/V1)  | UREM32_REG      | JSGT32_REG
//   0x76 — (unused V0/V1)  | UREM64_IMM      | JSGE32_IMM
//   0x7e — (unused V0/V1)  | UREM64_REG      | JSGE32_REG
//   0x87 — NEG64           | ST_4B_IMM       | NEG64? actually NEG64 is gated!
//          canonical: NEG64 if !disable_neg (V0/V1/V3+); else 0x87 only
//          remapped to ST_4B_IMM when move_memory_instruction_classes (V2).
//   0x97 — MOD64_IMM       | ST_8B_IMM       | MOD64_IMM
//   0x9c — MOD32_REG       | LD_8B_REG       | MOD32_REG
//   0x9f — MOD64_REG       | ST_8B_REG       | MOD64_REG
//   0xb6 — (unused V0/V1)  | SHMUL64_IMM     | JLE32_IMM
//   0xbe — (unused V0/V1)  | SHMUL64_REG     | JLE32_REG
//   0xc6 — (unused V0/V1)  | SDIV32_IMM      | JSLT32_IMM
//   0xce — (unused V0/V1)  | SDIV32_REG      | JSLT32_REG
//   0xd6 — (unused V0/V1)  | SDIV64_IMM      | JSLE32_IMM
//   0xde — (unused V0/V1)  | SDIV64_REG      | JSLE32_REG

/// Verifies that `text_bytes` is a well-formed sBPF program for `version`.
///
/// Returns void on success; otherwise the FIRST encountered violation as
/// a `VerifyError`.
///
/// `function_registry` is reserved for future SIMD-0178 enforcement
/// (call-target resolution). Canonical verifier.rs at v0.14.4 does NOT
/// consult the registry per-instruction — CALL_IMM acceptance is
/// unconditional. We keep the parameter to match the spec'd public API
/// and unblock evolution; today it is unused.
pub fn verify(
    text_bytes: []const u8,
    version: SbpfVersion,
    cfg: VerifyConfig,
    function_registry: *const FunctionRegistry,
) VerifyError!void {
    _ = function_registry; // accepted unconditionally; see doc above
    if (!cfg.versionEnabled(version)) return VerifyError.UnsupportedSbpfVersion;
    try checkProgLen(text_bytes);

    const insn_count = text_bytes.len / INSN_SIZE;

    var insn_ptr: usize = 0;
    while ((insn_ptr + 1) * INSN_SIZE <= text_bytes.len) {
        const insn = getInsnUnchecked(text_bytes, insn_ptr);
        var store = false;
        var lddw_consumed = false;

        switch (insn.opc) {
            // ─── BPF_LD class ──────────────────────────────────────────
            0x18 => { // LD_DW_IMM
                if (disableLddw(version)) return VerifyError.UnknownOpcode;
                try checkLoadDw(text_bytes, insn_ptr);
                lddw_consumed = true;
            },

            // ─── BPF_LDX class (V0/V1; retired in V2) ─────────────────
            0x71, 0x69, 0x61, 0x79 => { // LD_B_REG, LD_H_REG, LD_W_REG, LD_DW_REG
                if (moveMemoryInstructionClasses(version)) return VerifyError.UnknownOpcode;
            },

            // ─── BPF_ST class (V0/V1; retired in V2) ──────────────────
            0x72, 0x6a, 0x62, 0x7a, 0x73, 0x6b, 0x63, 0x7b => {
                if (moveMemoryInstructionClasses(version)) return VerifyError.UnknownOpcode;
                store = true;
            },

            // ─── BPF_ALU32 class (no collisions) ──────────────────────
            0x04, 0x0c, 0x14, 0x1c => {}, // ADD32/SUB32 IMM/REG
            0x44, 0x4c, 0x54, 0x5c => {}, // OR32/AND32 IMM/REG
            0x6c => {}, // LSH32_REG
            0x74 => try checkImmShift(insn, 32), // RSH32_IMM
            0x7c => {}, // RSH32_REG
            0x64 => try checkImmShift(insn, 32), // LSH32_IMM
            0x84 => { // NEG32
                if (disableNeg(version)) return VerifyError.UnknownOpcode;
            },
            0xa4, 0xac, 0xb4, 0xbc => {}, // XOR32/MOV32 IMM/REG
            0xc4 => try checkImmShift(insn, 32), // ARSH32_IMM
            0xcc => {}, // ARSH32_REG
            0xd4 => { // LE
                if (disableLe(version)) return VerifyError.UnknownOpcode;
                try checkImmEndian(insn);
            },
            0xdc => try checkImmEndian(insn), // BE

            // ─── MUL32_IMM (0x24) — no collision; gated by enable_pqr ─
            0x24 => {
                if (enablePqr(version)) return VerifyError.UnknownOpcode;
            },
            // 0x34 = DIV32_IMM (no collision). Gated.
            0x34 => {
                if (enablePqr(version)) return VerifyError.UnknownOpcode;
                try checkImmNonzero(insn);
            },
            // 0x94 = MOD32_IMM (no collision). Gated.
            0x94 => {
                if (enablePqr(version)) return VerifyError.UnknownOpcode;
                try checkImmNonzero(insn);
            },

            // ─── ALU64 (no collision arms) ────────────────────────────
            0x07 => { // ADD64_IMM
                // r10 + V1/V2 manual_stack_frame_bump: imm must be 64-aligned.
                if (insn.dst == FRAME_PTR_REG and manualStackFrameBump(version)) {
                    try checkImmAligned(insn, 64);
                }
            },
            0x0f, 0x17, 0x1f => {}, // ADD64_REG, SUB64_IMM, SUB64_REG
            0x47, 0x4f, 0x57, 0x5f => {}, // OR64/AND64 IMM/REG
            0x67 => try checkImmShift(insn, 64), // LSH64_IMM
            0x6f => {}, // LSH64_REG
            0x77 => try checkImmShift(insn, 64), // RSH64_IMM
            0x7f => {}, // RSH64_REG
            0xa7, 0xaf, 0xb7, 0xbf => {}, // XOR64/MOV64 IMM/REG
            0xc7 => try checkImmShift(insn, 64), // ARSH64_IMM
            0xcf => {}, // ARSH64_REG
            0xf7 => { // HOR64_IMM — only valid when lddw is disabled (V2)
                if (!disableLddw(version)) return VerifyError.UnknownOpcode;
            },

            // ─── COLLISION 0x27 — ST_1B_IMM (V2) | MUL64_IMM (else) ───
            0x27 => {
                if (moveMemoryInstructionClasses(version)) {
                    store = true;
                } else if (enablePqr(version)) {
                    // V2 has both PQR and the move-mem-classes gate; PQR
                    // alone covers both. (PQR=true ⇒ move=true here.)
                    return VerifyError.UnknownOpcode; // unreachable in canon
                } else {
                    // MUL64_IMM
                }
            },
            // 0x2c — MUL32_REG (else) | LD_1B_REG (V2) — note: ALU32 MUL
            // is rejected in V2 (enable_pqr). canonical: arm MUL32_REG only
            // matches when !enable_pqr; else V2 routes to LD_1B_REG.
            0x2c => {
                if (moveMemoryInstructionClasses(version)) {
                    // LD_1B_REG — V2 load. Accept.
                } else if (enablePqr(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    // MUL32_REG — V0/V1
                }
            },
            // 0x2f — MUL64_REG (else) | ST_1B_REG (V2)
            0x2f => {
                if (moveMemoryInstructionClasses(version)) {
                    store = true;
                } else if (enablePqr(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    // MUL64_REG
                }
            },
            // 0x37 — DIV64_IMM (else) | ST_2B_IMM (V2)
            0x37 => {
                if (moveMemoryInstructionClasses(version)) {
                    store = true;
                } else if (enablePqr(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    try checkImmNonzero(insn); // DIV64_IMM
                }
            },
            // 0x3c — DIV32_REG (else) | LD_2B_REG (V2)
            0x3c => {
                if (moveMemoryInstructionClasses(version)) {
                    // LD_2B_REG accept.
                } else if (enablePqr(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    // DIV32_REG
                }
            },
            // 0x3f — DIV64_REG (else) | ST_2B_REG (V2)
            0x3f => {
                if (moveMemoryInstructionClasses(version)) {
                    store = true;
                } else if (enablePqr(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    // DIV64_REG
                }
            },
            // 0x87 — NEG64 (V0/V1/V3+) | ST_4B_IMM (V2)
            0x87 => {
                if (moveMemoryInstructionClasses(version)) {
                    store = true;
                } else if (disableNeg(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    // NEG64
                }
            },
            // 0x8c — LD_4B_REG (V2 move-memory class). No non-V2 instruction at
            // this opcode (0x8c = NEG32|BPF_X, not a real classic op) → reject when
            // move-memory-classes is off. Canonical anza-sbpf v0.21.0 verifier.rs:275
            // `LD_4B_REG if move_memory_instruction_classes() => {}`. (Carrier
            // 2026-06-19 slot 416377907: this arm + 0x8f were the only missing
            // opcodes — C8ZDjy82 ArchiveProperty used LD_4B_REG; verifier rejected
            // → program never ran → dropped writes → bank_hash divergence.)
            0x8c => {
                if (!moveMemoryInstructionClasses(version)) return VerifyError.UnknownOpcode;
                // LD_4B_REG — accept (interpreter.zig:1063 executes it).
            },
            // 0x8f — ST_4B_REG (V2 move-memory class). No non-V2 instruction at this
            // opcode. Canonical verifier.rs:388 `ST_4B_REG if move_memory_...() => store = true`.
            0x8f => {
                if (!moveMemoryInstructionClasses(version)) return VerifyError.UnknownOpcode;
                store = true; // ST_4B_REG — interpreter.zig:1068 executes it.
            },

            // 0x97 — MOD64_IMM (else) | ST_8B_IMM (V2)
            0x97 => {
                if (moveMemoryInstructionClasses(version)) {
                    store = true;
                } else if (enablePqr(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    try checkImmNonzero(insn); // MOD64_IMM
                }
            },
            // 0x9c — MOD32_REG (else) | LD_8B_REG (V2)
            0x9c => {
                if (moveMemoryInstructionClasses(version)) {
                    // LD_8B_REG accept.
                } else if (enablePqr(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    // MOD32_REG
                }
            },
            // 0x9f — MOD64_REG (else) | ST_8B_REG (V2)
            0x9f => {
                if (moveMemoryInstructionClasses(version)) {
                    store = true;
                } else if (enablePqr(version)) {
                    return VerifyError.UnknownOpcode;
                } else {
                    // MOD64_REG
                }
            },

            // ─── COLLISION 0x36 — UHMUL64_IMM (V2) | JGE32_IMM (V3+) ──
            0x36 => {
                if (enablePqr(version)) {
                    // UHMUL64_IMM accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x3e — UHMUL64_REG (V2) | JGE32_REG (V3+)
            0x3e => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x46 — UDIV32_IMM (V2) | JSET32_IMM (V3+)
            0x46 => {
                if (enablePqr(version)) {
                    try checkImmNonzero(insn);
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x4e — UDIV32_REG (V2) | JSET32_REG (V3+)
            0x4e => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x56 — UDIV64_IMM (V2) | JNE32_IMM (V3+)
            0x56 => {
                if (enablePqr(version)) {
                    try checkImmNonzero(insn);
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x5e — UDIV64_REG (V2) | JNE32_REG (V3+)
            0x5e => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x66 — UREM32_IMM (V2) | JSGT32_IMM (V3+)
            0x66 => {
                if (enablePqr(version)) {
                    try checkImmNonzero(insn);
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x6e — UREM32_REG (V2) | JSGT32_REG (V3+)
            0x6e => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x76 — UREM64_IMM (V2) | JSGE32_IMM (V3+)
            0x76 => {
                if (enablePqr(version)) {
                    try checkImmNonzero(insn);
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0x7e — UREM64_REG (V2) | JSGE32_REG (V3+)
            0x7e => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0xb6 — SHMUL64_IMM (V2) | JLE32_IMM (V3+)
            0xb6 => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0xbe — SHMUL64_REG (V2) | JLE32_REG (V3+)
            0xbe => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0xc6 — SDIV32_IMM (V2) | JSLT32_IMM (V3+)
            0xc6 => {
                if (enablePqr(version)) {
                    try checkImmNonzero(insn);
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0xce — SDIV32_REG (V2) | JSLT32_REG (V3+)
            0xce => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0xd6 — SDIV64_IMM (V2) | JSLE32_IMM (V3+)
            0xd6 => {
                if (enablePqr(version)) {
                    try checkImmNonzero(insn);
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },
            // 0xde — SDIV64_REG (V2) | JSLE32_REG (V3+)
            0xde => {
                if (enablePqr(version)) {
                    // accept
                } else if (enableJmp32(version)) {
                    try checkJmpOffset(text_bytes, insn_ptr, insn_count);
                } else {
                    return VerifyError.UnknownOpcode;
                }
            },

            // ─── PQR-only opcodes (no JMP32 collision; V2 only) ──────
            0x86, 0x8e, 0x96, 0x9e => { // LMUL32/64 IMM/REG
                if (!enablePqr(version)) return VerifyError.UnknownOpcode;
            },
            0xe6 => { // SREM32_IMM
                if (!enablePqr(version)) return VerifyError.UnknownOpcode;
                try checkImmNonzero(insn);
            },
            0xee => { // SREM32_REG
                if (!enablePqr(version)) return VerifyError.UnknownOpcode;
            },
            0xf6 => { // SREM64_IMM
                if (!enablePqr(version)) return VerifyError.UnknownOpcode;
                try checkImmNonzero(insn);
            },
            0xfe => { // SREM64_REG
                if (!enablePqr(version)) return VerifyError.UnknownOpcode;
            },

            // ─── JMP32-only opcodes (no PQR collision; V3+ only) ─────
            0x16, 0x1e, 0x26, 0x2e, 0xa6, 0xae => { // JEQ/JGT IMM+REG, JLT IMM+REG
                if (!enableJmp32(version)) return VerifyError.UnknownOpcode;
                try checkJmpOffset(text_bytes, insn_ptr, insn_count);
            },

            // ─── BPF_JMP64 class (no version gate; JA family always on) ─
            0x05, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d,
            0xa5, 0xad, 0xb5, 0xbd, 0x45, 0x4d,
            0x55, 0x5d, 0x65, 0x6d, 0x75, 0x7d,
            0xc5, 0xcd, 0xd5, 0xdd => {
                try checkJmpOffset(text_bytes, insn_ptr, insn_count);
            },

            0x85 => {
                // CALL_IMM. canonical accepts unconditionally.
                // function_registry resolution is the loader's job.
            },
            0x8d => try checkCallxRegister(insn, version, cfg), // CALL_REG
            0x95 => {}, // EXIT

            else => return VerifyError.UnknownOpcode,
        }

        try checkRegisters(insn, store, version);

        insn_ptr += 1;
        if (lddw_consumed) insn_ptr += 1;
    }

    // verifier.rs:416-418 tail check.
    if (insn_ptr != insn_count) return VerifyError.JumpOutOfCode;
}

// ═══════════════════════════════════════════════════════════════════════════
//                         Inline smoke tests
// ═══════════════════════════════════════════════════════════════════════════

test "verify: empty program → ProgramLengthNotMultipleOfInsnSize" {
    var registry = FunctionRegistry{};
    defer registry.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.ProgramLengthNotMultipleOfInsnSize,
        verify(&[_]u8{}, .v0, VerifyConfig.DEFAULT, &registry),
    );
}

test "verify: tiny EXIT-only program → OK on V0..V3" {
    const exit_only = [_]u8{ 0x95, 0, 0, 0, 0, 0, 0, 0 };
    var registry = FunctionRegistry{};
    defer registry.deinit(std.testing.allocator);
    inline for ([_]SbpfVersion{ .v0, .v1, .v2, .v3 }) |v| {
        try verify(&exit_only, v, VerifyConfig.DEFAULT, &registry);
    }
}

test "verify: disabled version → UnsupportedSbpfVersion" {
    const exit_only = [_]u8{ 0x95, 0, 0, 0, 0, 0, 0, 0 };
    var cfg = VerifyConfig.DEFAULT;
    cfg.enabled_sbpf_versions = std.StaticBitSet(4).initEmpty();
    var registry = FunctionRegistry{};
    defer registry.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.UnsupportedSbpfVersion,
        verify(&exit_only, .v0, cfg, &registry),
    );
}

test "predicates parity: program.rs 32-93" {
    try std.testing.expect(manualStackFrameBump(.v1));
    try std.testing.expect(manualStackFrameBump(.v2));
    try std.testing.expect(!manualStackFrameBump(.v0));
    try std.testing.expect(!manualStackFrameBump(.v3));
    try std.testing.expect(stackFrameGaps(.v0));
    try std.testing.expect(!stackFrameGaps(.v3));
    try std.testing.expect(enablePqr(.v2));
    try std.testing.expect(!enablePqr(.v3));
    try std.testing.expect(disableLddw(.v2));
    try std.testing.expect(!disableLddw(.v3));
    try std.testing.expect(callxUsesSrcReg(.v2));
    try std.testing.expect(callxUsesDstReg(.v3));
    try std.testing.expect(!callxUsesDstReg(.v2));
    try std.testing.expect(enableJmp32(.v3));
    try std.testing.expect(!enableJmp32(.v2));
    try std.testing.expect(moveMemoryInstructionClasses(.v2));
    try std.testing.expect(disableLe(.v2));
    try std.testing.expect(disableNeg(.v2));
}
