//! Stage-A verifier test surface.
//!
//! Exercises every spec-listed VerifyError variant with a hand-built
//! bytecode plus happy-path V0/V1/V2/V3 programs. Mirrors the per-variant
//! discipline of solana-sbpf-0.14.4's `verifier.rs::tests` but at the
//! Vexor-native error taxonomy.
//!
//! Variant coverage (spec list — 16 errors):
//!   InstructionPlusOpcodeOutOfBounds  → tested via 7-byte program (sub-INSN)
//!   UnknownOpcode                     → 0x00 (BPF_LD_ABS class) — never valid
//!   InvalidSourceRegister             → src=11 in MOV64_REG
//!   InvalidDestinationRegister        → dst=11 in MOV64_REG
//!   CannotWriteToR10                  → MOV64_REG dst=10 (V0)
//!   InfiniteLoop                      → DOCUMENTED non-emit (canonical parity)
//!   JumpOutOfCode                     → JA off=+100 in 2-insn program
//!   JumpToMiddleOfLddw                → JA landing on LDDW pseudo-slot
//!   UnsupportedLEBEArgument           → BE imm=17
//!   LDDWCannotBeLast                  → LDDW as final insn
//!   IncompleteLDDW                    → LDDW second slot opc != 0
//!   InvalidRegister                   → CALL_REG imm=15 (V0); also imm=10 with reject_callx_r10
//!   ShiftWithOverflow                 → LSH64_IMM imm=64
//!   ProgramLengthNotMultipleOfInsnSize→ 5-byte program
//!   InvalidFunction                   → reserved-only; not emitted today (D1 doc)
//!   UnsupportedSbpfVersion            → cfg with bitset cleared

const std = @import("std");
const verifier = @import("verifier.zig");
const elf = @import("elf.zig");

const VerifyError = verifier.VerifyError;
const SbpfVersion = elf.SbpfVersion;
const FunctionRegistry = elf.FunctionRegistry;

/// Helper: write a single 8-byte sBPF instruction.
fn buildInsn(opc: u8, dst: u4, src: u4, off: i16, imm: i32) [8]u8 {
    var out: [8]u8 = undefined;
    out[0] = opc;
    out[1] = (@as(u8, src) << 4) | @as(u8, dst);
    std.mem.writeInt(i16, out[2..4], off, .little);
    std.mem.writeInt(i32, out[4..8], imm, .little);
    return out;
}

fn cfgDefault() verifier.VerifyConfig {
    return verifier.VerifyConfig.DEFAULT;
}

fn newRegistry() FunctionRegistry {
    return FunctionRegistry{};
}

// ─── Variant: ProgramLengthNotMultipleOfInsnSize ─────────────────────────────

test "ProgramLengthNotMultipleOfInsnSize: 5-byte program" {
    const bad = [_]u8{ 0x95, 0, 0, 0, 0 }; // 5 bytes — not multiple of 8
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.ProgramLengthNotMultipleOfInsnSize,
        verifier.verify(&bad, .v0, cfgDefault(), &reg),
    );
}

test "ProgramLengthNotMultipleOfInsnSize: empty program (NoProgram re-route per D1)" {
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.ProgramLengthNotMultipleOfInsnSize,
        verifier.verify(&[_]u8{}, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: UnsupportedSbpfVersion ─────────────────────────────────────────

test "UnsupportedSbpfVersion: V2 disabled in bitset" {
    const exit_only = buildInsn(0x95, 0, 0, 0, 0);
    var cfg = cfgDefault();
    cfg.enabled_sbpf_versions.unset(2);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.UnsupportedSbpfVersion,
        verifier.verify(&exit_only, .v2, cfg, &reg),
    );
}

// ─── Variant: UnknownOpcode ──────────────────────────────────────────────────

test "UnknownOpcode: 0x00 (BPF_LD_ABS — never valid) in V0" {
    const insn0 = buildInsn(0x00, 0, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &insn0);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.UnknownOpcode,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "UnknownOpcode: HOR64_IMM (0xf7) rejected in V0 (lddw enabled)" {
    // canonical: HOR64_IMM only valid when disable_lddw → V2.
    const hor = buildInsn(0xf7, 1, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &hor);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.UnknownOpcode,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "UnknownOpcode: NEG32 (0x84) rejected in V2 (disable_neg)" {
    const neg = buildInsn(0x84, 1, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &neg);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.UnknownOpcode,
        verifier.verify(&prog, .v2, cfgDefault(), &reg),
    );
}

test "UnknownOpcode: divide-by-zero (DIV64_IMM imm=0) re-routed per D1" {
    // canonical DivisionByZero → UnknownOpcode in our taxonomy.
    const div = buildInsn(0x37, 1, 0, 0, 0); // DIV64_IMM r1, 0
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &div);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.UnknownOpcode,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: InvalidSourceRegister ──────────────────────────────────────────

test "InvalidSourceRegister: src=11 in MOV64_REG" {
    // Hand-build because buildInsn restricts src to u4. Assemble manually.
    var mov: [8]u8 = .{ 0xbf, (11 << 4) | 1, 0, 0, 0, 0, 0, 0 };
    _ = &mov;
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &mov);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.InvalidSourceRegister,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: InvalidDestinationRegister ─────────────────────────────────────

test "InvalidDestinationRegister: dst=11 in MOV64_REG" {
    var mov: [8]u8 = .{ 0xbf, (1 << 4) | 11, 0, 0, 0, 0, 0, 0 };
    _ = &mov;
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &mov);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.InvalidDestinationRegister,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: CannotWriteToR10 ───────────────────────────────────────────────

test "CannotWriteToR10: MOV64_REG dst=r10 in V0" {
    const mov = buildInsn(0xbf, 10, 1, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &mov);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.CannotWriteToR10,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "CannotWriteToR10: ADD64 r10 imm permitted in V1 (manual_stack_frame_bump)" {
    const add = buildInsn(0x07, 10, 0, 0, -64);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &add);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v1, cfgDefault(), &reg);
}

test "CannotWriteToR10: ADD64 r10 imm rejected in V0 (no manual frame bump)" {
    const add = buildInsn(0x07, 10, 0, 0, -64);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &add);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.CannotWriteToR10,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: JumpOutOfCode ──────────────────────────────────────────────────

test "JumpOutOfCode: JA off=+100 in 2-insn program" {
    const ja = buildInsn(0x05, 0, 0, 100, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &ja);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.JumpOutOfCode,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "JumpOutOfCode: JA off=-10 (negative) before pc=0" {
    const ja = buildInsn(0x05, 0, 0, -10, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &ja);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.JumpOutOfCode,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: JumpToMiddleOfLddw ─────────────────────────────────────────────

test "JumpToMiddleOfLddw: JA targets LDDW pseudo-slot (V0)" {
    // pc=0: JA off=+1 → lands on pc=2 (the LDDW second slot).
    // pc=1: LDDW r1, 0x1234
    // pc=2: pseudo-slot (opc=0, imm=high32)
    // pc=3: EXIT
    // Wait: with off=+1 from pc=0, target = 0+1+1 = 2 (the lddw pseudo).
    const ja = buildInsn(0x05, 0, 0, 1, 0);
    const lddw_lo = buildInsn(0x18, 1, 0, 0, 0x1234);
    const lddw_hi: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [32]u8 = undefined;
    @memcpy(prog[0..8], &ja);
    @memcpy(prog[8..16], &lddw_lo);
    @memcpy(prog[16..24], &lddw_hi);
    @memcpy(prog[24..32], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.JumpToMiddleOfLddw,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: UnsupportedLEBEArgument ────────────────────────────────────────

test "UnsupportedLEBEArgument: BE imm=17" {
    const be = buildInsn(0xdc, 1, 0, 0, 17);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &be);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.UnsupportedLEBEArgument,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "UnsupportedLEBEArgument: BE imm=64 OK" {
    const be = buildInsn(0xdc, 1, 0, 0, 64);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &be);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v0, cfgDefault(), &reg);
}

// ─── Variant: LDDWCannotBeLast ───────────────────────────────────────────────

test "LDDWCannotBeLast: LDDW as last insn" {
    const lddw_lo = buildInsn(0x18, 1, 0, 0, 0x1234);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.LDDWCannotBeLast,
        verifier.verify(&lddw_lo, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: IncompleteLDDW ─────────────────────────────────────────────────

test "IncompleteLDDW: second slot opc != 0" {
    const lddw_lo = buildInsn(0x18, 1, 0, 0, 0x1234);
    const bad_pseudo = buildInsn(0x07, 0, 0, 0, 0); // ADD64 — not 0
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [24]u8 = undefined;
    @memcpy(prog[0..8], &lddw_lo);
    @memcpy(prog[8..16], &bad_pseudo);
    @memcpy(prog[16..24], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.IncompleteLDDW,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Variant: InvalidRegister (callx) ────────────────────────────────────────

test "InvalidRegister: CALL_REG with imm=15 in V0 (callx_uses_imm)" {
    // V0/V1: callx target = imm. imm=15 ⇒ out of [0,10).
    const callr = buildInsn(0x8d, 0, 0, 0, 15);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &callr);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.InvalidRegister,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "InvalidRegister: CALL_REG with target=r10 (reject_callx_r10=true)" {
    // V3+: callx target = dst reg.
    const callr = buildInsn(0x8d, 10, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &callr);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.InvalidRegister,
        verifier.verify(&prog, .v3, cfgDefault(), &reg),
    );
}

test "InvalidRegister: ADD64 r10, imm=7 (unaligned) in V1 — re-routed per D1" {
    // canonical UnalignedImmediate → InvalidRegister.
    const add = buildInsn(0x07, 10, 0, 0, 7); // 7 % 8 != 0
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &add);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.InvalidRegister,
        verifier.verify(&prog, .v1, cfgDefault(), &reg),
    );
}

// ─── Variant: ShiftWithOverflow ──────────────────────────────────────────────

test "ShiftWithOverflow: LSH64_IMM imm=64 (>= 64-bit width)" {
    const lsh = buildInsn(0x67, 1, 0, 0, 64);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &lsh);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.ShiftWithOverflow,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "ShiftWithOverflow: LSH32_IMM imm=32 (>= 32-bit width)" {
    const lsh = buildInsn(0x64, 1, 0, 0, 32);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &lsh);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.ShiftWithOverflow,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "ShiftWithOverflow: LSH64_IMM imm=-1 (negative)" {
    const lsh = buildInsn(0x67, 1, 0, 0, -1);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &lsh);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.ShiftWithOverflow,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Documented non-emit: InfiniteLoop ───────────────────────────────────────

test "InfiniteLoop NOT emitted: self-jump (JA off=-1) is accepted (canonical parity)" {
    // canonical verifier.rs does NOT detect self-jumps. We mirror.
    // pc=0: JA off=-1 → target = 0+1-1 = 0 (self). Accepted.
    // pc=1: EXIT
    const ja = buildInsn(0x05, 0, 0, -1, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &ja);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v0, cfgDefault(), &reg);
}

// ─── InstructionPlusOpcodeOutOfBounds — emitted only on pure mid-stream
// ─── truncation. Our checkProgLen catches multiples-of-8 first; the
// ─── only path to this variant is a partial last instruction, which the
// ─── ProgramLengthNotMultipleOfInsnSize check pre-empts. Documented:
// ─── this variant is RESERVED for future granular reporting; not emitted
// ─── today. (Spec parity: declared, not exercised — same status as
// ─── canonical InvalidSyscall.) ───────────────────────────────────────────

test "InstructionPlusOpcodeOutOfBounds variant DECLARED but pre-empted by length check" {
    // Comp-time verify the variant is declared on the error set so callers
    // can match exhaustively even when not emitted.
    const Catcher = struct {
        fn fire() VerifyError!void {
            return VerifyError.InstructionPlusOpcodeOutOfBounds;
        }
    };
    try std.testing.expectError(VerifyError.InstructionPlusOpcodeOutOfBounds, Catcher.fire());
}

// ─── InvalidFunction — same status; reserved for future SIMD-0178 path ───────

test "InvalidFunction variant DECLARED (reserved for future SIMD-0178)" {
    const Catcher = struct {
        fn fire() VerifyError!void {
            return VerifyError.InvalidFunction;
        }
    };
    try std.testing.expectError(VerifyError.InvalidFunction, Catcher.fire());
}

// ─── Happy paths: synthesized minimal programs across V0..V3 ─────────────────

test "happy V0: MOV64_IMM r0, 42; EXIT" {
    const mov = buildInsn(0xb7, 0, 0, 0, 42); // MOV64_IMM r0, 42
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &mov);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v0, cfgDefault(), &reg);
}

test "happy V1: ADD64 r10, -64; EXIT (manual_stack_frame_bump)" {
    const add = buildInsn(0x07, 10, 0, 0, -64);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &add);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v1, cfgDefault(), &reg);
}

test "happy V2: PQR LMUL64_REG; EXIT" {
    // 0x9e LMUL64_REG (PQR-only, V2-only).
    const lmul = buildInsn(0x9e, 1, 2, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &lmul);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v2, cfgDefault(), &reg);
}

test "happy V3: JEQ32_IMM jumps forward 1; EXIT" {
    // 0x16 JEQ32_IMM, off=+0 (skip nothing — lands on next insn = EXIT).
    const jeq = buildInsn(0x16, 1, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &jeq);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v3, cfgDefault(), &reg);
}

test "happy V2: HOR64_IMM (replaces lddw — V2-only per disable_lddw gate)" {
    // 0xf7 HOR64_IMM. canonical verifier.rs:325:
    //   `HOR64_IMM if sbpf_version.disable_lddw() => {}`
    // program.rs:62-64: disable_lddw == (v == V2). So HOR64_IMM is V2-only.
    // (Naming the test "V2" not "V3" — the canonical accept-version is V2;
    //  V3 has lddw re-enabled and HOR64 is rejected as unknown there.)
    const hor = buildInsn(0xf7, 1, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &hor);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v2, cfgDefault(), &reg);
}

// ─── Spec-listed known-bad fixtures ──────────────────────────────────────────

test "known-bad: callx r10 in V3 (reject_callx_r10 default true)" {
    const callr = buildInsn(0x8d, 10, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &callr);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.InvalidRegister,
        verifier.verify(&prog, .v3, cfgDefault(), &reg),
    );
}

test "known-bad: jump out of code" {
    const ja = buildInsn(0x05, 0, 0, 1000, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &ja);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.JumpOutOfCode,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "known-bad: lddw as last instruction" {
    const lddw = buildInsn(0x18, 1, 0, 0, 0x1234);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.LDDWCannotBeLast,
        verifier.verify(&lddw, .v0, cfgDefault(), &reg),
    );
}

test "known-bad: jump into middle of lddw" {
    // pc=0: JA off=+1 → target=2 (LDDW pseudo-slot)
    // pc=1: LDDW lo
    // pc=2: LDDW hi (pseudo)
    // pc=3: EXIT
    const ja = buildInsn(0x05, 0, 0, 1, 0);
    const lddw_lo = buildInsn(0x18, 1, 0, 0, 0);
    const lddw_hi: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [32]u8 = undefined;
    @memcpy(prog[0..8], &ja);
    @memcpy(prog[8..16], &lddw_lo);
    @memcpy(prog[16..24], &lddw_hi);
    @memcpy(prog[24..32], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.JumpToMiddleOfLddw,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

// ─── Cross-version opcode-collision regression tests ─────────────────────────

test "collision 0x36: UHMUL64_IMM accepted in V2 (PQR)" {
    const uhmul = buildInsn(0x36, 1, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &uhmul);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v2, cfgDefault(), &reg);
}

test "collision 0x36: JGE32_IMM treated as jump in V3 (offset must be valid)" {
    const jge = buildInsn(0x36, 1, 0, 0, 0); // off=0 → next insn
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &jge);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v3, cfgDefault(), &reg);
}

test "collision 0x36: rejected in V0/V1 (neither PQR nor JMP32)" {
    const op36 = buildInsn(0x36, 1, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &op36);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try std.testing.expectError(
        VerifyError.UnknownOpcode,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
}

test "collision 0x27: ST_1B_IMM in V2 vs MUL64_IMM in V0" {
    const op27 = buildInsn(0x27, 1, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &op27);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    try verifier.verify(&prog, .v0, cfgDefault(), &reg); // MUL64_IMM ok
    try verifier.verify(&prog, .v2, cfgDefault(), &reg); // ST_1B_IMM ok
}

test "collision 0x37 div-zero: DIV64_IMM rejected with imm=0 in V0; ST_2B_IMM ok in V2" {
    const op37 = buildInsn(0x37, 1, 0, 0, 0);
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &op37);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    // V0: DIV64_IMM with imm=0 → re-routed to UnknownOpcode (D1)
    try std.testing.expectError(
        VerifyError.UnknownOpcode,
        verifier.verify(&prog, .v0, cfgDefault(), &reg),
    );
    // V2: ST_2B_IMM — accept.
    try verifier.verify(&prog, .v2, cfgDefault(), &reg);
}

// ─── Carrier regression: 0x8c/0x8f V2 move-memory opcodes (commit 1f21c14) ───
// These two arms were MISSING from the verifier — the 4-byte LD_4B_REG (0x8c) and
// ST_4B_REG (0x8f) move-memory variants. On 2026-06-19 slot 416377907, program
// C8ZDjy82wEAkpWkAUmXWhP73LmGnvdWLodYfRUxkyo67 (SBPF v2, redeployed with new
// bytecode) hit LD_4B_REG → verifier returned UnknownOpcode → M3_VerifyFailed →
// program never ran → 6 account-data writes DROPPED → bank_hash divergence →
// emitted 518→1 → TWO delinquencies. moveMemoryInstructionClasses(v) == (v==.v2),
// so both opcodes accept ONLY in V2 and reject as UnknownOpcode in V0/V1/V3
// (0x8c = NEG32|BPF_X, 0x8f = ST_REG with no classic counterpart — neither is a
// real non-V2 op). Byte-faithful to anza-sbpf v0.21.0 verifier.rs:275/:388.

test "carrier 0x8c LD_4B_REG: accepted in V2, rejected V0/V1/V3" {
    const ld4 = buildInsn(0x8c, 1, 2, 0, 0); // load 4B [r2+0] → r1
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &ld4);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    // V2: LD_4B_REG accepted (the carrier fix).
    try verifier.verify(&prog, .v2, cfgDefault(), &reg);
    // V0/V1/V3: no valid op at 0x8c (NEG32 has no reg-form) → UnknownOpcode.
    try std.testing.expectError(VerifyError.UnknownOpcode, verifier.verify(&prog, .v0, cfgDefault(), &reg));
    try std.testing.expectError(VerifyError.UnknownOpcode, verifier.verify(&prog, .v1, cfgDefault(), &reg));
    try std.testing.expectError(VerifyError.UnknownOpcode, verifier.verify(&prog, .v3, cfgDefault(), &reg));
}

test "carrier 0x8f ST_4B_REG: accepted in V2, rejected V0/V1/V3" {
    const st4 = buildInsn(0x8f, 1, 2, 0, 0); // store 4B r2 → [r1+0]
    const exit = buildInsn(0x95, 0, 0, 0, 0);
    var prog: [16]u8 = undefined;
    @memcpy(prog[0..8], &st4);
    @memcpy(prog[8..16], &exit);
    var reg = newRegistry();
    defer reg.deinit(std.testing.allocator);
    // V2: ST_4B_REG accepted (the carrier fix).
    try verifier.verify(&prog, .v2, cfgDefault(), &reg);
    // V0/V1/V3: no valid op at 0x8f → UnknownOpcode.
    try std.testing.expectError(VerifyError.UnknownOpcode, verifier.verify(&prog, .v0, cfgDefault(), &reg));
    try std.testing.expectError(VerifyError.UnknownOpcode, verifier.verify(&prog, .v1, cfgDefault(), &reg));
    try std.testing.expectError(VerifyError.UnknownOpcode, verifier.verify(&prog, .v3, cfgDefault(), &reg));
}
