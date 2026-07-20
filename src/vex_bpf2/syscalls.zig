//! Vexor BPF2 — Syscall Registry (M6, Wave 3)
//!
//! Spec-for-spec rebuild of Agave's syscall registration block plus
//! per-syscall handlers. @prov:syscall.module-map — full per-syscall
//! upstream line-map, SIMD inventory, crypto sourcing, and fix_ledger
//! anchors in PROVENANCE.md.
//!
//! ── Public API ──────────────────────────────────────────────────────────────
//!
//!   pub const SyscallError = error{...};
//!   pub const SyscallFn = *const fn(ctx: *InvokeContext, r1..r5) SyscallError!u64;
//!   pub const SyscallEntry = struct{ name, hash, fn_, cu_cost, sbpf_versions };
//!   pub const SyscallRegistry = struct{ init, deinit, invoke, lookup, count, selfTest };
//!
//! M4's interpreter expects an opaque `SyscallRegistry` (interpreter.zig:168)
//! returning `InterpreterError!u64`. M6 owns a concrete `Registry`, plus an
//! `asTrait()` adapter that maps `SyscallError → InterpreterError`.
//!
//! ── Tracing ─────────────────────────────────────────────────────────────────
//!
//! `[VBPF2-TRACE]` emission is gated on `TRACE_SYSCALLS` (build option;
//! defaults false). Format:
//!   [VBPF2-TRACE] tx=<sig-hex> M6.<syscall_name>(r1,r2,r3,r4,r5) -> <result>
//! `tx_signature` is read from `InvokeContext.tx_signature` (per
//! `RFC-invoke-ctx-syscall-bindings.md`); placeholder zeros until Wave 3.5.

const std = @import("std");
const memory = @import("memory.zig");
const invoke_ctx_mod = @import("invoke_ctx.zig");
const sysvar_cache_mod = @import("sysvar_cache.zig");
const interpreter = @import("interpreter.zig");
const trace = @import("trace.zig");
const vex_crypto = @import("vex_crypto");
const bn254 = vex_crypto.bn254;
const bls12_381 = vex_crypto.bls12_381_syscall;
const cpi = @import("cpi.zig");
const elf_mod = @import("elf.zig");
const crypto_helpers = @import("crypto_helpers.zig");
// vex_crypto.secp256k1 is not currently importable from a standalone test
// module (test-vex-bpf2-syscalls is a single-root build step). Until the
// build wiring exposes vex_crypto as a named module to vex_bpf2, the
// secp256k1_recover handler is a placeholder that consumes CU and returns
// `M6_Secp256k1RecoverError` with the path forward to
// `src/vex_crypto/secp256k1.zig:recoverPublicKey` (already pure-Zig). Wave
// 3.5 wires the import via build module graph and the body becomes a
// 3-line call.

pub const InvokeContext = invoke_ctx_mod.InvokeContext;
pub const Pubkey32 = sysvar_cache_mod.Pubkey32;
const AlignedMemoryMap = memory.AlignedMemoryMap;
const Region = memory.Region;
const MemoryRegionAccess = memory.MemoryRegionAccess;
const AccessError = memory.AccessError;

// ──────────────────────────────────────────────────────────────────────────────
// Wave 3.5 trace integration (supersedes the original build-constant gate).
//
// The shim *bodies* now route into `trace.zig`'s global level filter. Call
// sites (`traceEmit` / `traceEntry` / `traceExit`) are unchanged so the
// `[VBPF2-TRACE]` log format is preserved byte-for-byte. The `TRACE_SYSCALLS`
// constant is kept for backward source-compatibility but no longer gates
// emission — the runtime CLI flag `--bpf-stack-trace` controls it instead.
// ──────────────────────────────────────────────────────────────────────────────

/// Deprecated: kept for backward source-compatibility. Wave 3.5 uses the
/// runtime `trace.Level` instead. Reads of this value are no-ops.
pub const TRACE_SYSCALLS: bool = false;

inline fn traceEmit(comptime fmt: []const u8, args: anytype) void {
    trace.emitRaw(fmt, args);
}

inline fn traceEntry(name: []const u8, ic: *const InvokeContext, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) void {
    if (trace.level() == .off) return;
    var hex_buf: [128]u8 = undefined;
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < ic.tx_signature.len and i * 2 + 1 < hex_buf.len) : (i += 1) {
        hex_buf[i * 2] = hex[(ic.tx_signature[i] >> 4) & 0xf];
        hex_buf[i * 2 + 1] = hex[ic.tx_signature[i] & 0xf];
    }
    const tx_hex_len = i * 2;
    trace.emitRaw(
        "[VBPF2-TRACE] tx={s} M6.{s}(r1=0x{x},r2=0x{x},r3=0x{x},r4=0x{x},r5=0x{x})",
        .{ hex_buf[0..tx_hex_len], name, r1, r2, r3, r4, r5 },
    );
}

inline fn traceExit(name: []const u8, result: u64) void {
    trace.emitRaw("[VBPF2-TRACE] M6.{s} -> 0x{x}", .{ name, result });
}

// ──────────────────────────────────────────────────────────────────────────────
// Errors (exhaustive, module-prefixed; no bare error.Exit).
// ──────────────────────────────────────────────────────────────────────────────

pub const SyscallError = error{
    /// Unknown syscall hash; shouldn't happen at runtime if registry is consistent.
    M6_NotRegistered,
    /// Memory translation failed — VM pointer outside any region or RO violation.
    M6_AccessViolation,
    /// Argument shape rejected before translation.
    M6_InvalidArgument,
    /// Feature gate is off; agave returns NotSupported for the same case.
    M6_FeatureGated,
    /// Compute-meter exhausted by `consumeCompute`.
    M6_ConsumeOverflow,
    /// Agave SyscallError::TooManySlices — hash-family slice-count cap
    /// (sha256_max_slices = 20_000) exceeded, checked BEFORE any CU consume.
    M6_TooManySlices,
    /// vex-058: SysvarCache lacks the requested sysvar.
    M6_SysvarNotPopulated,
    /// AccountInfo / Instruction layout (CPI) ABI mismatch.
    M6_AbiMismatch,
    /// CPI handler not yet wired by sister M7 (the two `dispatchCpi` early
    /// returns for `ic.mm == null` / `ic.cpi_syscalls == null` — a genuine
    /// V2-infrastructure gap, e.g. a pre-Wave-6A caller that never stamped
    /// the hooks). Distinct from `M6_CpiBuiltinFailed` below — see that
    /// variant's doc for the masking bug this split fixes.
    M6_CpiHandlerNotReady,
    /// The CPI's TARGET builtin program ran (M9 dispatch reached it, hooks
    /// were fully wired) and returned a genuine typed `BuiltinError`
    /// (`CpiError.M7_BuiltinFailed`) — e.g. a nested System transfer inside
    /// a CPI hitting InsufficientFunds. This is a NORMAL tx-failure outcome,
    /// not an infrastructure gap. Hygiene fix (2026-07-03): `dispatchCpi`'s
    /// catch-switch previously folded this into `M6_CpiHandlerNotReady` via
    /// its `else` arm, so any downstream site that only logs the FINAL
    /// error name (e.g. `traitInvoke`'s `[V2-SYSCALL-FAIL] err=...`) could
    /// not tell "a builtin genuinely failed" from "the CPI handler was
    /// never wired" — a real infra regression would read identically to a
    /// benign builtin failure. Both still fold to the SAME
    /// `InterpreterError.SyscallError` (agave's "Exit") at the M4 boundary —
    /// this split is a LABEL/LOG fidelity fix only, no consensus-outcome or
    /// success-path change.
    M6_CpiBuiltinFailed,
    /// Hash family failure (currently unused; future-proof).
    M6_HashError,
    /// Curve25519/Ristretto syscall placeholder (port sig ecc.zig).
    /// RETAINED for unsupported curve_id values on still-stubbed flows.
    M6_CurveNotImplemented,
    /// curve_id supplied is not a known CurveId enum value.
    M6_CurveInvalidId,
    /// curve_id is recognised but this VEXOR build does not support it for
    /// this op (e.g. BLS12-381 inputs where only Edwards/Ristretto are wired).
    M6_CurveUnsupportedId,
    /// GroupOp byte does not decode to one of {add, sub, mul}.
    M6_CurveInvalidGroupOp,
    /// Bytes failed Edwards25519/Ristretto255 decoding (fromBytes).
    M6_CurveInvalidPoint,
    /// Scalar failed `Edwards25519.scalar.rejectNonCanonical`.
    M6_CurveInvalidScalar,
    /// Multiscalar mul rejected (count > 512 — agave SyscallError::InvalidLength).
    M6_CurveMsmTooManyPoints,
    /// BLS12-381 G1/G2 decompress is implemented (`solCurveDecompress` below
    /// calls `bls12_381.g1Decompress`/`g2Decompress`) and never returns this
    /// variant — RETAINED but currently dead/unreachable. Kept for
    /// defensive-completeness parity with the enum shape only.
    M6_CurveDecompressRequiresBls12_381ImplPort,
    /// BLS12-381 pairing is implemented (`solCurvePairingMap` below calls
    /// `bls12_381.pairingMap`) and never returns this variant — RETAINED but
    /// currently dead/unreachable. Kept for defensive-completeness parity
    /// with the enum shape only.
    M6_CurvePairingRequiresBls12_381ImplPort,
    /// Declared for defensive completeness; not currently returned anywhere
    /// (alt_bn128 group-op is a real, live implementation — see below).
    M6_AltBn128NotImplemented,
    /// Alt_bn128 group-op (add/mul/pairing) is a real, pure-Zig, KAT-verified
    /// implementation (`bn254.g1Add`/`g1Mul`/`g2Add`/`g2Mul`/`pairing`,
    /// `vex_crypto/bn254.zig`). This variant is only returned when
    /// `bn254.active_backend == .unported`, which is permanently false
    /// (`bn254.zig:39`: `active_backend: Backend = .pure_zig`, not gated by
    /// any build option) — the branch that returns this error is dead code,
    /// retained as a defensive guard in case a future backend variant is
    /// added.
    M6_AltBn128RequiresBn254ImplPort,
    /// Returned when a `sol_poseidon` call passes an unsupported parameter
    /// id (only Bn254X5 is defined) — this IS live, current behavior, not a
    /// stale placeholder (see `solPoseidon` below).
    M6_PoseidonNotImplemented,
    /// `sol_poseidon`'s BN254 hash is a real, pure-Zig, KAT-verified
    /// implementation (`bn254.poseidonHash`, `vex_crypto/bn254/poseidon.zig`).
    /// Like `M6_AltBn128RequiresBn254ImplPort` above, this variant is only
    /// returned when `bn254.active_backend == .unported`, which is
    /// permanently false — the branch that returns this error is dead code,
    /// retained as a defensive guard.
    M6_PoseidonRequiresBn254ImplPort,
    /// secp256k1_recover failure (signature/recovery_id/message bad).
    M6_Secp256k1RecoverError,
    /// big_mod_exp placeholder. RETAINED for downstream rejection paths.
    M6_BigModExpNotImplemented,
    /// `sol_big_mod_exp` invalid input (length > 512, etc.).
    M6_BigModExpInvalidLength,
    /// `sol_big_mod_exp` modulus is zero — undefined operation.
    M6_BigModExpModulusZero,
    /// Generic OOM.
    M6_OutOfMemory,
    /// PDA not derivable: bump exhausted (try_find_program_address).
    M6_PdaNotDerivable,
    /// MAX seeds / seed length / nonce exceeded.
    M6_PdaInputTooLarge,
    /// Set-return-data oversized (>1024 bytes per agave MAX_RETURN_DATA).
    M6_ReturnDataTooLarge,
    /// Memcpy/memmove src and dst overlap (agave SyscallError::CopyOverlapping).
    M6_CopyOverlapping,
    /// sol_log_'d bytes are not valid UTF-8 (agave SyscallError::InvalidString).
    M6_InvalidUtf8,
    /// Aborted by program (sol_panic_, abort).
    M6_ProgramAbort,
    /// `sol_alloc_free_` called after deactivation feature gate flips on.
    M6_AllocFreeDeprecated,
    /// CallDepthExceeded — bubbled up from CPI.
    M6_CallDepthExceeded,
    /// Underlying SyscallError families that bubble up from helpers.
    M6_InternalError,
};

pub const SyscallFn = *const fn (
    ctx: *InvokeContext,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r5: u64,
) SyscallError!u64;

pub const SbpfVersionMask = packed struct(u8) {
    v0: bool = true,
    v1: bool = true,
    v2: bool = true,
    v3: bool = true,
    _pad: u4 = 0,

    pub const ALL: SbpfVersionMask = .{};
    pub const V0_TO_V2: SbpfVersionMask = .{ .v0 = true, .v1 = true, .v2 = true, .v3 = false };
    pub const V3_ONLY: SbpfVersionMask = .{ .v0 = false, .v1 = false, .v2 = false, .v3 = true };
};

pub const SyscallEntry = struct {
    name: []const u8,
    hash: u32,
    fn_: SyscallFn,
    /// Base CU cost (handlers may consume more for variable-length args).
    /// Cited per family below; final per-call cost computed at invoke time.
    cu_cost: u64,
    sbpf_versions: SbpfVersionMask,
};

// ──────────────────────────────────────────────────────────────────────────────
// Murmur3-32 hash for syscall name → ID (agave/sig/Vexor V1 unanimous).
// V1 fix_ledger asserts these IDs (vm_syscalls.zig:1046 test). M6 reuses the
// trivial `std.hash.Murmur3_32.hashWithSeed(name, 0)` — a one-liner; copying
// it here is byte-for-byte equivalent to V1's `vm_executable.zig:851` body.
// ──────────────────────────────────────────────────────────────────────────────

pub fn nameHash(name: []const u8) u32 {
    return std.hash.Murmur3_32.hashWithSeed(name, 0);
}

// ──────────────────────────────────────────────────────────────────────────────
// CU cost constants. @prov:syscall.cu-cost-table — full per-constant
// execution_budget.rs line map in PROVENANCE.md.
// ──────────────────────────────────────────────────────────────────────────────

pub const CuCost = struct {
    pub const log_64_units: u64 = 100;
    pub const create_program_address_units: u64 = 1500;
    pub const sha256_base_cost: u64 = 85;
    pub const sha256_byte_cost: u64 = 1;
    pub const sha256_max_slices: u64 = 20_000; // budget, not cost
    pub const log_pubkey_units: u64 = 100;
    pub const cpi_bytes_per_unit: u64 = 250;
    pub const sysvar_base_cost: u64 = 100;
    pub const secp256k1_recover_cost: u64 = 25_000;
    pub const syscall_base_cost: u64 = 100;
    pub const curve25519_edwards_validate_point_cost: u64 = 159;
    // curve25519 per-op costs. Task #8 2026-06-19: group_op/msm previously
    // charged the flat validate cost (159) for EVERY op — a consensus CU
    // divergence. These are byte-exact to rc.1 560e317.
    pub const curve25519_edwards_add_cost: u64 = 473;
    pub const curve25519_edwards_subtract_cost: u64 = 475;
    pub const curve25519_edwards_multiply_cost: u64 = 2177;
    pub const curve25519_edwards_msm_base_cost: u64 = 2273;
    pub const curve25519_edwards_msm_incremental_cost: u64 = 758;
    pub const curve25519_ristretto_validate_point_cost: u64 = 169;
    pub const curve25519_ristretto_add_cost: u64 = 521;
    pub const curve25519_ristretto_subtract_cost: u64 = 519;
    pub const curve25519_ristretto_multiply_cost: u64 = 2208;
    pub const curve25519_ristretto_msm_base_cost: u64 = 2303;
    pub const curve25519_ristretto_msm_incremental_cost: u64 = 788;
    pub const heap_cost: u64 = 8; // DEFAULT_HEAP_COST
    pub const mem_op_base_cost: u64 = 10;
    pub const alt_bn128_g1_addition_cost: u64 = 334;
    // Phase 2 (2026-06-19): per-op BN254 costs (the prior stub charged 334
    // for ALL ops — wrong on every row).
    pub const alt_bn128_g2_addition_cost: u64 = 535;
    pub const alt_bn128_g1_multiplication_cost: u64 = 3_840;
    pub const alt_bn128_g2_multiplication_cost: u64 = 15_670;
    pub const alt_bn128_pairing_one_pair_cost_first: u64 = 36_364;
    pub const alt_bn128_pairing_one_pair_cost_other: u64 = 12_121;
    // Compression per-op costs. Syscall ADDS syscall_base_cost(100) on top of
    // these (group_op does NOT). So G1 compress total = 100+30 = 130, etc.
    pub const alt_bn128_g1_compress: u64 = 30;
    pub const alt_bn128_g1_decompress: u64 = 398;
    pub const alt_bn128_g2_compress: u64 = 86;
    pub const alt_bn128_g2_decompress: u64 = 13_610;
    pub const big_modular_exponentiation_base_cost: u64 = 190;
    pub const big_modular_exponentiation_cost_divisor: u64 = 2;
    pub const poseidon_cost_coefficient_a: u64 = 61;
    pub const poseidon_cost_coefficient_c: u64 = 542;
    pub const get_remaining_compute_units_cost: u64 = 100;
    // SIMD-0388 BLS12-381 per-op costs.
    pub const bls12_381_g1_add_cost: u64 = 128;
    pub const bls12_381_g2_add_cost: u64 = 203;
    pub const bls12_381_g1_subtract_cost: u64 = 129;
    pub const bls12_381_g2_subtract_cost: u64 = 204;
    pub const bls12_381_g1_multiply_cost: u64 = 4_627;
    pub const bls12_381_g2_multiply_cost: u64 = 8_255;
    pub const bls12_381_g1_decompress_cost: u64 = 2_100;
    pub const bls12_381_g2_decompress_cost: u64 = 3_050;
    pub const bls12_381_g1_validate_cost: u64 = 1_565;
    pub const bls12_381_g2_validate_cost: u64 = 1_968;
    pub const bls12_381_one_pair_cost: u64 = 25_445;
    pub const bls12_381_additional_pair_cost: u64 = 13_023;
};

// ──────────────────────────────────────────────────────────────────────────────
// Memory translation helpers — thin wrappers around M2's AlignedMemoryMap.
//
// Every syscall that takes a VM pointer goes through these; M6 NEVER speaks
// directly to `memory.Region` so the M2 invariants (vex-152n2 underflow
// guard, AccessError plumbing) hold uniformly.
// ──────────────────────────────────────────────────────────────────────────────

inline fn currentMm(ic: *InvokeContext) SyscallError!*AlignedMemoryMap {
    const opaque_mm = ic.mm orelse return error.M6_AccessViolation;
    return @ptrCast(@alignCast(opaque_mm));
}

inline fn translateSlice(
    ic: *InvokeContext,
    vm_addr: u64,
    len: u64,
    acc: MemoryRegionAccess,
) SyscallError![]u8 {
    if (len == 0) return &.{}; // agave allows zero-length translations.
    const mm = try currentMm(ic);
    return mm.vmap(acc, vm_addr, len) catch return error.M6_AccessViolation;
}

inline fn translateConstSlice(ic: *InvokeContext, vm_addr: u64, len: u64) SyscallError![]const u8 {
    return @as([]const u8, try translateSlice(ic, vm_addr, len, .load));
}

inline fn translateMutSlice(ic: *InvokeContext, vm_addr: u64, len: u64) SyscallError![]u8 {
    return translateSlice(ic, vm_addr, len, .store);
}

inline fn translateType(ic: *InvokeContext, comptime T: type, vm_addr: u64) SyscallError!*const T {
    const sz: u64 = @intCast(@sizeOf(T));
    const slice = try translateConstSlice(ic, vm_addr, sz);
    if (slice.len < @sizeOf(T)) return error.M6_AccessViolation;
    return @ptrCast(@alignCast(slice.ptr));
}

inline fn translateMutType(ic: *InvokeContext, comptime T: type, vm_addr: u64) SyscallError!*T {
    const sz: u64 = @intCast(@sizeOf(T));
    const slice = try translateMutSlice(ic, vm_addr, sz);
    if (slice.len < @sizeOf(T)) return error.M6_AccessViolation;
    return @ptrCast(@alignCast(slice.ptr));
}

// is_nonoverlapping. @prov:syscall.memops
fn isNonoverlapping(src: u64, src_len: u64, dst: u64, dst_len: u64) bool {
    if (src > dst) {
        return (src - dst) >= dst_len;
    } else {
        return (dst - src) >= src_len;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Logging family. @prov:syscall.logging
// ──────────────────────────────────────────────────────────────────────────────

/// carrier #17 one-shot probe: armed by replay_stage around HistoryJT ix
/// dispatch; program logs surface at warn (capped). Remove when closed.
pub var c17_probe: bool = false;
var c17_lines: u32 = 0;

fn solLog(ic: *InvokeContext, addr: u64, len: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_log_", ic, addr, len, 0, 0, 0);
    // @prov:syscall.logging — cost = max(syscall_base_cost, len)
    const cost: u64 = @max(CuCost.syscall_base_cost, len);
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;
    const bytes = try translateConstSlice(ic, addr, len);
    // G3 fix (conformance grind, sol_log_ UTF-8 validation): Agave's real
    // SyscallLog (agave-4.2.0-beta.1-src/syscalls/src/lib.rs) validates the
    // logged bytes are valid UTF-8 (`str::from_utf8`) and hard-fails
    // `SyscallError::InvalidString` (declaration-order discriminant 0 ->
    // proto code 1) on invalid input. Vexor previously logged raw bytes
    // unconditionally and always returned success — silently accepting
    // malformed UTF-8 (e.g. an overlong 3-byte encoding like `e0 80 80`)
    // where Agave rejects it.
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.M6_InvalidUtf8;
    if (c17_probe and c17_lines < 400) {
        // skip the high-volume succeeding crank; capture everything else
        if (!std.mem.eql(u8, bytes, "Instruction: CopyVoteAccount")) {
            c17_lines += 1;
            std.log.warn("[C17-PLOG] {s}", .{bytes});
        }
    }
    // 2026-06-04: program-log now respects the trace gate (emitRaw, not the
    // carrier-hunt emitRawForce) — silent in production (level=on_error),
    // visible only when trace is raised. CU was already charged above; logs
    // are not hashed into consensus, so this is observability-only.
    trace.emitRaw("[VBPF2-PROGRAM-LOG] {s}", .{bytes});
    traceExit("sol_log_", 0);
    return 0;
}

fn solLog64(ic: *InvokeContext, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) SyscallError!u64 {
    traceEntry("sol_log_64_", ic, a1, a2, a3, a4, a5);
    ic.consumeCompute(CuCost.log_64_units) catch return error.M6_ConsumeOverflow;
    // Wave 5: program-log forced (see solLog comment).
    trace.emitRaw("[VBPF2-PROGRAM-LOG] 0x{x}, 0x{x}, 0x{x}, 0x{x}, 0x{x}", .{ a1, a2, a3, a4, a5 });
    traceExit("sol_log_64_", 0);
    return 0;
}

fn solLogPubkey(ic: *InvokeContext, addr: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_log_pubkey", ic, addr, 0, 0, 0, 0);
    ic.consumeCompute(CuCost.log_pubkey_units) catch return error.M6_ConsumeOverflow;
    const pk = try translateType(ic, [32]u8, addr);
    // Wave 5: program-log forced. Hand-rolled hex (fmtSliceHexLower removed
    // in Zig 0.15.2 — see WAVE4-FINAL latent issues).
    var pk_hex: [64]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    inline for (0..32) |i| {
        pk_hex[i * 2 + 0] = hex_chars[(pk[i] >> 4) & 0xF];
        pk_hex[i * 2 + 1] = hex_chars[pk[i] & 0xF];
    }
    trace.emitRaw("[VBPF2-PROGRAM-LOG] pubkey={s}", .{pk_hex[0..]});
    traceExit("sol_log_pubkey", 0);
    return 0;
}

fn solLogComputeUnits(ic: *InvokeContext, _: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_log_compute_units_", ic, 0, 0, 0, 0, 0);
    ic.consumeCompute(CuCost.syscall_base_cost) catch return error.M6_ConsumeOverflow;
    // Wave 5: program-log forced.
    trace.emitRaw("[VBPF2-PROGRAM-LOG] CU remaining: {d}", .{ic.computeRemaining()});
    traceExit("sol_log_compute_units_", 0);
    return 0;
}

fn solLogData(ic: *InvokeContext, addr: u64, len: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_log_data", ic, addr, len, 0, 0, 0);
    // @prov:syscall.logging — base + per-vmslice + sum of slice lengths.
    ic.consumeCompute(CuCost.syscall_base_cost) catch return error.M6_ConsumeOverflow;
    // VmSlice<u8> is 16 bytes (u64 ptr + u64 len) — agave SBPF ABI.
    const slice_size: u64 = 16;
    const total_bytes: u64 = std.math.mul(u64, len, slice_size) catch return error.M6_InvalidArgument;
    const raw = try translateConstSlice(ic, addr, total_bytes);
    ic.consumeCompute(CuCost.syscall_base_cost *| len) catch return error.M6_ConsumeOverflow;

    // Sum the individual lengths and burn one CU per byte (saturating).
    var sum_len: u64 = 0;
    var i: usize = 0;
    while (i < raw.len) : (i += @intCast(slice_size)) {
        const sl_len: u64 = std.mem.readInt(u64, raw[i + 8 ..][0..8], .little);
        sum_len = std.math.add(u64, sum_len, sl_len) catch return error.M6_InvalidArgument;
    }
    ic.consumeCompute(sum_len) catch return error.M6_ConsumeOverflow;

    // Optionally emit each field to log. Wave 3.5 wires real collector.
    traceExit("sol_log_data", 0);
    return 0;
}

fn solPanic(ic: *InvokeContext, addr: u64, len: u64, line: u64, col: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_panic_", ic, addr, len, line, col, 0);
    ic.consumeCompute(@max(CuCost.syscall_base_cost, len)) catch return error.M6_ConsumeOverflow;
    // vex-V2-PANIC-DIAG: log the panic message for triage. Read-only side-effect
    // — instrumentation only, doesn't change the abort outcome.
    const safe_len = @min(len, 240);
    if (translateConstSlice(ic, addr, safe_len)) |bytes| {
        std.log.err("[V2-PANIC-MSG] line={d} col={d} len={d} msg={s}", .{ line, col, len, bytes });
    } else |_| {
        std.log.err("[V2-PANIC-MSG] line={d} col={d} len={d} msg=<UNTRANSLATABLE addr=0x{x}>", .{ line, col, len, addr });
    }
    return error.M6_ProgramAbort;
}

fn abort_(ic: *InvokeContext, _: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("abort", ic, 0, 0, 0, 0, 0);
    // vex-V2-PANIC-DIAG: abort takes no args, but some programs sol_log_ the
    // panic message immediately before calling abort. The preceding [VBPF2-
    // PROGRAM-LOG] line in the log will hold the message in those cases.
    std.log.err("[V2-ABORT-NOARG] (panic message logged via prior sol_log_, if any)", .{});
    return error.M6_ProgramAbort;
}

// ──────────────────────────────────────────────────────────────────────────────
// Memory ops family. @prov:syscall.memops
// ──────────────────────────────────────────────────────────────────────────────

inline fn memOpConsume(ic: *InvokeContext, n: u64) SyscallError!void {
    // @prov:syscall.memops
    const div = if (CuCost.cpi_bytes_per_unit == 0) std.math.maxInt(u64) else n / CuCost.cpi_bytes_per_unit;
    const cost = @max(CuCost.mem_op_base_cost, div);
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;
}

fn solMemcpy(ic: *InvokeContext, dst: u64, src: u64, n: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_memcpy_", ic, dst, src, n, 0, 0);
    try memOpConsume(ic, n);
    if (n == 0) return 0;
    if (!isNonoverlapping(src, n, dst, n)) return error.M6_CopyOverlapping;
    const src_slice = try translateConstSlice(ic, src, n);
    const dst_slice = try translateMutSlice(ic, dst, n);
    @memcpy(dst_slice[0..n], src_slice[0..n]);
    traceExit("sol_memcpy_", 0);
    return 0;
}

fn solMemmove(ic: *InvokeContext, dst: u64, src: u64, n: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_memmove_", ic, dst, src, n, 0, 0);
    try memOpConsume(ic, n);
    if (n == 0) return 0;
    const src_slice = try translateConstSlice(ic, src, n);
    const dst_slice = try translateMutSlice(ic, dst, n);
    // copyForwards/Backwards based on overlap direction (mirror std.mem.copyBackwards semantics).
    if (@intFromPtr(dst_slice.ptr) > @intFromPtr(src_slice.ptr) and
        @intFromPtr(dst_slice.ptr) < @intFromPtr(src_slice.ptr) + n)
    {
        std.mem.copyBackwards(u8, dst_slice[0..n], src_slice[0..n]);
    } else {
        std.mem.copyForwards(u8, dst_slice[0..n], src_slice[0..n]);
    }
    traceExit("sol_memmove_", 0);
    return 0;
}

fn solMemcmp(ic: *InvokeContext, s1: u64, s2: u64, n: u64, cmp_addr: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_memcmp_", ic, s1, s2, n, cmp_addr, 0);
    try memOpConsume(ic, n);
    const a = try translateConstSlice(ic, s1, n);
    const b = try translateConstSlice(ic, s2, n);
    var result: i32 = 0;
    var i: usize = 0;
    while (i < @as(usize, @intCast(n))) : (i += 1) {
        if (a[i] != b[i]) {
            result = @as(i32, @intCast(a[i])) - @as(i32, @intCast(b[i]));
            break;
        }
    }
    const out_ptr = try translateMutType(ic, i32, cmp_addr);
    out_ptr.* = result;
    traceExit("sol_memcmp_", 0);
    return 0;
}

fn solMemset(ic: *InvokeContext, dst: u64, c: u64, n: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_memset_", ic, dst, c, n, 0, 0);
    try memOpConsume(ic, n);
    if (n == 0) return 0;
    const slice = try translateMutSlice(ic, dst, n);
    @memset(slice[0..n], @truncate(c));
    traceExit("sol_memset_", 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────────────
// Hash family. @prov:syscall.hash-cost
//
// FIX 1 (2026-07-12, cpi-invoke-units-cu-parity): the previous cost model
// here summed all slice lengths then charged ONCE via
// `max(mem_op_base_cost, sum/cpi_bytes_per_unit)` — wrong constant (250
// divisor) AND wrong aggregation (sum-then-once instead of per-slice), and
// had NO max-slices gate at all. Mirrors the already-correct `solSha512`
// below (SIMD-0512), which was the reference pattern for this fix.
// ──────────────────────────────────────────────────────────────────────────────

// ABI: SBPF VmSlice<u8> = { u64 ptr, u64 len } = 16 bytes.
const VM_SLICE_SIZE: u64 = 16;

fn hashSlicesGeneric(
    ic: *InvokeContext,
    comptime Hasher: type,
    vals_addr: u64,
    vals_len: u64,
    out_addr: u64,
    base_cost: u64,
    byte_cost: u64,
    max_slices: u64,
) SyscallError!u64 {
    // @prov:syscall.hash-cost — max-slices gate BEFORE any CU consumption.
    if (max_slices < vals_len) return error.M6_TooManySlices;

    // base cost.
    ic.consumeCompute(base_cost) catch return error.M6_ConsumeOverflow;

    // translate the output buffer before touching input.
    const dst = try translateMutSlice(ic, out_addr, 32);

    var hasher = Hasher.init(.{});
    if (vals_len > 0) {
        const total_bytes: u64 = std.math.mul(u64, vals_len, VM_SLICE_SIZE) catch return error.M6_InvalidArgument;
        const raw = try translateConstSlice(ic, vals_addr, total_bytes);
        var i: usize = 0;
        while (i < raw.len) : (i += @intCast(VM_SLICE_SIZE)) {
            const sl_addr = std.mem.readInt(u64, raw[i .. i + 8][0..8], .little);
            const sl_len = std.mem.readInt(u64, raw[i + 8 .. i + 16][0..8], .little);
            const seg = try translateConstSlice(ic, sl_addr, sl_len);
            // @prov:syscall.hash-cost — per-slice: max(mem_op_base, byte_cost*(len/2)).
            const cost = @max(CuCost.mem_op_base_cost, byte_cost *| (sl_len / 2));
            ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;
            hasher.update(seg);
        }
    }
    var h: [32]u8 = undefined;
    hasher.final(&h);
    @memcpy(dst[0..32], &h);
    return 0;
}

fn solSha256(ic: *InvokeContext, vals: u64, vlen: u64, out: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_sha256", ic, vals, vlen, out, 0, 0);
    const r = try hashSlicesGeneric(ic, std.crypto.hash.sha2.Sha256, vals, vlen, out, CuCost.sha256_base_cost, CuCost.sha256_byte_cost, CuCost.sha256_max_slices);
    traceExit("sol_sha256", r);
    return r;
}

fn solKeccak256(ic: *InvokeContext, vals: u64, vlen: u64, out: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_keccak256", ic, vals, vlen, out, 0, 0);
    const r = try hashSlicesGeneric(ic, std.crypto.hash.sha3.Keccak256, vals, vlen, out, CuCost.sha256_base_cost, CuCost.sha256_byte_cost, CuCost.sha256_max_slices);
    traceExit("sol_keccak256", r);
    return r;
}

fn solBlake3(ic: *InvokeContext, vals: u64, vlen: u64, out: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_blake3", ic, vals, vlen, out, 0, 0);
    const r = try hashSlicesGeneric(ic, std.crypto.hash.Blake3, vals, vlen, out, CuCost.sha256_base_cost, CuCost.sha256_byte_cost, CuCost.sha256_max_slices);
    traceExit("sol_blake3", r);
    return r;
}

// SIMD-0512: sol_sha512. @prov:syscall.hash-cost — shares the sha256
// cost family (base 85 / byte 1 / max_slices 20_000 — there are NO
// sha512-specific constants, deliberately); 64-byte digest.
//
// Cost model is the CANONICAL per-slice formula — NOT hashSlicesGeneric's
// (which charges once-total via cpi_bytes_per_unit and skips the slice cap;
// that latent divergence on sha256/keccak/blake3 is tracked separately):
//   per slice: max(mem_op_base_cost, sha256_byte_cost * (len / 2))
//
// Feature gate enable_sha512_syscall (s512oDwg…, pending epoch 973 testnet):
// Agave never REGISTERS the syscall pre-activation, so a call fails the tx
// with zero CU consumed. Vexor registers unconditionally and gates here,
// before any CU consumption — same failed-tx outcome (fee-only rollback ⇒
// hash parity). A pre-activation program merely CONTAINING the symbol can't
// exist on-chain: deployment rejects unresolved symbols.
fn solSha512(ic: *InvokeContext, vals: u64, vlen: u64, out: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_sha512", ic, vals, vlen, out, 0, 0);
    if (!ic.sha512_syscall_active) return error.M6_FeatureGated;

    // @prov:syscall.hash-cost — slice cap BEFORE base-cost consumption.
    if (CuCost.sha256_max_slices < vlen) return error.M6_TooManySlices;
    ic.consumeCompute(CuCost.sha256_base_cost) catch return error.M6_ConsumeOverflow;

    // translate the 64-byte result BEFORE reading slices.
    const dst = try translateMutSlice(ic, out, 64);

    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    if (vlen > 0) {
        const total_bytes: u64 = std.math.mul(u64, vlen, VM_SLICE_SIZE) catch return error.M6_InvalidArgument;
        const raw = try translateConstSlice(ic, vals, total_bytes);
        var i: usize = 0;
        while (i < raw.len) : (i += @intCast(VM_SLICE_SIZE)) {
            const sl_addr = std.mem.readInt(u64, raw[i .. i + 8][0..8], .little);
            const sl_len = std.mem.readInt(u64, raw[i + 8 .. i + 16][0..8], .little);
            const seg = try translateConstSlice(ic, sl_addr, sl_len);
            // @prov:syscall.hash-cost — per-slice: max(mem_op_base, byte_cost*(len/2)).
            const cost = @max(CuCost.mem_op_base_cost, CuCost.sha256_byte_cost *| (sl_len / 2));
            ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;
            hasher.update(seg);
        }
    }
    var h: [64]u8 = undefined;
    hasher.final(&h);
    @memcpy(dst[0..64], &h);
    traceExit("sol_sha512", 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────────────
// secp256k1_recover (agave declare_builtin in lib.rs; uses
// libsecp256k1::recover under the hood). vex_crypto/secp256k1.zig has a
// pure-Zig recover via std.crypto.sign.ecdsa.
// ──────────────────────────────────────────────────────────────────────────────

fn solSecp256k1Recover(
    ic: *InvokeContext,
    hash_addr: u64,
    recovery_id: u64,
    sig_addr: u64,
    result_addr: u64,
    _: u64,
) SyscallError!u64 {
    traceEntry("sol_secp256k1_recover", ic, hash_addr, recovery_id, sig_addr, result_addr, 0);
    ic.consumeCompute(CuCost.secp256k1_recover_cost) catch return error.M6_ConsumeOverflow;
    if (recovery_id > 1) return error.M6_Secp256k1RecoverError;
    const hash_ptr = try translateType(ic, [32]u8, hash_addr);
    const sig_ptr = try translateType(ic, [64]u8, sig_addr);
    const out = try translateMutSlice(ic, result_addr, 64);
    // Wave 3.5 wireup: vex_crypto.secp256k1.recoverPublicKey is now imported
    // as a build module dependency. Implementation is at
    // src/vex_crypto/secp256k1.zig:242 (recoverPublicKey).
    const rec_id: u2 = @intCast(recovery_id);
    const pk = vex_crypto.secp256k1.recoverPublicKey(hash_ptr, sig_ptr, rec_id) catch {
        return error.M6_Secp256k1RecoverError;
    };
    // Serialise the recovered public key into the agave-compatible 64-byte
    // form: X || Y, big-endian (drop the 0x04 prefix from SEC1 uncompressed).
    const uncompressed = pk.toUncompressedSec1();
    @memcpy(out[0..64], uncompressed[1..65]);
    traceExit("sol_secp256k1_recover", 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────────────
// Curve25519 / BLS12-381 / alt_bn128 / poseidon / big_mod_exp.
//
// Wave 6C-2 lands real implementations for everything Zig 0.15.2 stdlib can
// support:
//   • Edwards25519 / Ristretto255 validate / group_op / multiscalar_mul
//     → std.crypto.ecc.{Edwards25519, Ristretto255}
//   • big_mod_exp → std.math.big.int.Managed (square-and-multiply)
//
// The remaining handlers require external crypto libraries that aren't yet
// vendored into Vexor (sig pulls Rexicon226/zig-poseidon, supranational/blst,
// and 3800+ LoC of bn254). Those handlers consume the documented CU, validate
// every pointer arg (so AccessViolation tests still work), then return a
// specific `*RequiresBn254ImplPort` / `*RequiresBls12_381ImplPort` named
// error so callers see exactly what's missing — never a silent 0 or 1.
//
// Curve / op references. @prov:syscall.curve-ops (validate/group_op/msm/decompress/pairing_map);
// @prov:syscall.big-mod-exp; @prov:syscall.poseidon — full sig+agave line map in PROVENANCE.md.
// ──────────────────────────────────────────────────────────────────────────────

fn solCurveValidatePoint(ic: *InvokeContext, curve_id_raw: u64, point_addr: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_curve_validate_point", ic, curve_id_raw, point_addr, 0, 0, 0);

    const curve_id = crypto_helpers.CurveId.wrap(curve_id_raw) orelse {
        traceExit("sol_curve_validate_point", 1);
        return error.M6_CurveInvalidId;
    };

    // @prov:syscall.curve-ops — SIMD-0388 feature gate FIRST: BLS curve_ids with
    // the feature inactive → InvalidAttribute abort, BEFORE any CU charge.
    if (!ic.enable_bls12_381_syscall and curve_id.isBls()) {
        return error.M6_FeatureGated;
    }

    switch (curve_id) {
        .edwards => {
            ic.consumeCompute(CuCost.curve25519_edwards_validate_point_cost) catch return error.M6_ConsumeOverflow;
            const buffer = try translateType(ic, [32]u8, point_addr);
            const result: u64 = if (std.meta.isError(crypto_helpers.Edwards25519.fromBytes(buffer.*))) 1 else 0;
            traceExit("sol_curve_validate_point", result);
            return result;
        },
        .ristretto => {
            ic.consumeCompute(CuCost.curve25519_ristretto_validate_point_cost) catch return error.M6_ConsumeOverflow;
            const buffer = try translateType(ic, [32]u8, point_addr);
            const result: u64 = if (std.meta.isError(crypto_helpers.Ristretto255.fromBytes(buffer.*))) 1 else 0;
            traceExit("sol_curve_validate_point", result);
            return result;
        },
        // BLS12-381 G1 (curve_id 5/133). @prov:syscall.curve-ops
        // = to_affine().is_some() (field + on-curve + subgroup). r0=0 valid, 1 not.
        .bls12_381_g1_be, .bls12_381_g1_le => {
            ic.consumeCompute(CuCost.bls12_381_g1_validate_cost) catch return error.M6_ConsumeOverflow;
            const point = try translateType(ic, [96]u8, point_addr);
            const endianness: bls12_381.Endianness = if (curve_id == .bls12_381_g1_le) .le else .be;
            const result: u64 = if (bls12_381.g1Validate(point, endianness)) 0 else 1;
            traceExit("sol_curve_validate_point", result);
            return result;
        },
        // BLS12-381 G2 (curve_id 6/134). @prov:syscall.curve-ops
        .bls12_381_g2_be, .bls12_381_g2_le => {
            ic.consumeCompute(CuCost.bls12_381_g2_validate_cost) catch return error.M6_ConsumeOverflow;
            const point = try translateType(ic, [192]u8, point_addr);
            const endianness: bls12_381.Endianness = if (curve_id == .bls12_381_g2_le) .le else .be;
            const result: u64 = if (bls12_381.g2Validate(point, endianness)) 0 else 1;
            traceExit("sol_curve_validate_point", result);
            return result;
        },
        // curve_id 4/132 (plain BLS12-381, pairing-only) is not valid for
        // validate — agave's match has no arm → InvalidAttribute abort.
        else => return error.M6_CurveUnsupportedId,
    }
}

fn solCurveGroupOp(ic: *InvokeContext, curve_id_raw: u64, op_raw: u64, left_addr: u64, right_addr: u64, out_addr: u64) SyscallError!u64 {
    traceEntry("sol_curve_group_op", ic, curve_id_raw, op_raw, left_addr, right_addr, out_addr);

    const curve_id = crypto_helpers.CurveId.wrap(curve_id_raw) orelse return error.M6_CurveInvalidId;
    const op = crypto_helpers.GroupOp.wrap(op_raw) orelse return error.M6_CurveInvalidGroupOp;

    // @prov:syscall.curve-ops — SIMD-0388 feature gate FIRST: BLS curve_ids with
    // the feature inactive → InvalidAttribute abort, before any CU charge.
    if (!ic.enable_bls12_381_syscall and curve_id.isBls()) return error.M6_FeatureGated;

    switch (curve_id) {
        inline .edwards, .ristretto => |id| {
            const T = comptime switch (id) {
                .edwards => crypto_helpers.Edwards25519,
                .ristretto => crypto_helpers.Ristretto255,
                else => unreachable,
            };
            // Per-op CU. @prov:syscall.curve-ops — charged BEFORE decode, so a
            // soft-fail (bad point / non-canonical scalar) still consumes it — matches
            // canonical (cost consumed, then None → Ok(1)).
            const cost: u64 = switch (op) {
                .add => if (id == .edwards) CuCost.curve25519_edwards_add_cost else CuCost.curve25519_ristretto_add_cost,
                .sub => if (id == .edwards) CuCost.curve25519_edwards_subtract_cost else CuCost.curve25519_ristretto_subtract_cost,
                .mul => if (id == .edwards) CuCost.curve25519_edwards_multiply_cost else CuCost.curve25519_ristretto_multiply_cost,
            };
            ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;
            const left_buf = try translateType(ic, [32]u8, left_addr);
            const right_buf = try translateType(ic, [32]u8, right_addr);
            const result_bytes = crypto_helpers.edwardsGroupOp(T, op, left_buf.*, right_buf.*) catch {
                // decode-fail / non-canonical scalar → canonical None → SOFT r0=1.
                // (Identity/low-order/scalar-zero are NOT errors — edwardsGroupOp
                // computes them, so they fall through to the write+r0=0 path below.)
                traceExit("sol_curve_group_op", 1);
                return 1;
            };
            // Translate the output pointer ONLY on success — canonical translate_mut
            // lives inside the `Some` branch, so a soft-fail never validates out_addr.
            const out_slice = try translateMutSlice(ic, out_addr, 32);
            @memcpy(out_slice[0..32], &result_bytes);
            traceExit("sol_curve_group_op", 0);
            return 0;
        },
        // BLS12-381 G1. @prov:syscall.curve-ops — ADD/SUB read two 96-byte G1
        // points from left/right; MUL reads scalar@left, point@right (NOTE the
        // operand order). On success: 96-byte out + r0=0; soft fail → 1.
        .bls12_381_g1_be, .bls12_381_g1_le => {
            const endianness: bls12_381.Endianness = if (curve_id == .bls12_381_g1_le) .le else .be;
            const out_slice = try translateMutSlice(ic, out_addr, 96);
            var out: [96]u8 = undefined;
            const ok = switch (op) {
                .add => blk: {
                    ic.consumeCompute(CuCost.bls12_381_g1_add_cost) catch return error.M6_ConsumeOverflow;
                    const l = try translateType(ic, [96]u8, left_addr);
                    const r = try translateType(ic, [96]u8, right_addr);
                    break :blk bls12_381.g1Add(l, r, endianness, &out);
                },
                .sub => blk: {
                    ic.consumeCompute(CuCost.bls12_381_g1_subtract_cost) catch return error.M6_ConsumeOverflow;
                    const l = try translateType(ic, [96]u8, left_addr);
                    const r = try translateType(ic, [96]u8, right_addr);
                    break :blk bls12_381.g1Sub(l, r, endianness, &out);
                },
                .mul => blk: {
                    ic.consumeCompute(CuCost.bls12_381_g1_multiply_cost) catch return error.M6_ConsumeOverflow;
                    const scalar = try translateType(ic, [32]u8, left_addr);
                    const point = try translateType(ic, [96]u8, right_addr);
                    break :blk bls12_381.g1Mul(point, scalar, endianness, &out);
                },
            };
            if (!ok) {
                traceExit("sol_curve_group_op", 1);
                return 1;
            }
            @memcpy(out_slice[0..96], &out);
            traceExit("sol_curve_group_op", 0);
            return 0;
        },
        // BLS12-381 G2. @prov:syscall.curve-ops — same shape, 192-byte points.
        .bls12_381_g2_be, .bls12_381_g2_le => {
            const endianness: bls12_381.Endianness = if (curve_id == .bls12_381_g2_le) .le else .be;
            const out_slice = try translateMutSlice(ic, out_addr, 192);
            var out: [192]u8 = undefined;
            const ok = switch (op) {
                .add => blk: {
                    ic.consumeCompute(CuCost.bls12_381_g2_add_cost) catch return error.M6_ConsumeOverflow;
                    const l = try translateType(ic, [192]u8, left_addr);
                    const r = try translateType(ic, [192]u8, right_addr);
                    break :blk bls12_381.g2Add(l, r, endianness, &out);
                },
                .sub => blk: {
                    ic.consumeCompute(CuCost.bls12_381_g2_subtract_cost) catch return error.M6_ConsumeOverflow;
                    const l = try translateType(ic, [192]u8, left_addr);
                    const r = try translateType(ic, [192]u8, right_addr);
                    break :blk bls12_381.g2Sub(l, r, endianness, &out);
                },
                .mul => blk: {
                    ic.consumeCompute(CuCost.bls12_381_g2_multiply_cost) catch return error.M6_ConsumeOverflow;
                    const scalar = try translateType(ic, [32]u8, left_addr);
                    const point = try translateType(ic, [192]u8, right_addr);
                    break :blk bls12_381.g2Mul(point, scalar, endianness, &out);
                },
            };
            if (!ok) {
                traceExit("sol_curve_group_op", 1);
                return 1;
            }
            @memcpy(out_slice[0..192], &out);
            traceExit("sol_curve_group_op", 0);
            return 0;
        },
        // curve_id 4 (plain) has no group_op arm → InvalidAttribute abort.
        else => return error.M6_CurveUnsupportedId,
    }
}

fn solCurveMsm(ic: *InvokeContext, curve_id_raw: u64, scalars_addr: u64, points_addr: u64, n: u64, out_addr: u64) SyscallError!u64 {
    traceEntry("sol_curve_multiscalar_mul", ic, curve_id_raw, scalars_addr, points_addr, n, out_addr);

    // n>512 → abort BEFORE any CU charge. @prov:syscall.curve-ops — n==0 is
    // NOT an error: canonical msm([],[]) → Some(identity), r0=0 (translate_slice len 0 is
    // a no-op; edwardsMsm returns the identity encoding).
    if (n > 512) return error.M6_CurveMsmTooManyPoints;

    const curve_id = crypto_helpers.CurveId.wrap(curve_id_raw) orelse return error.M6_CurveInvalidId;

    switch (curve_id) {
        inline .edwards, .ristretto => |id| {
            const T = comptime switch (id) {
                .edwards => crypto_helpers.Edwards25519,
                .ristretto => crypto_helpers.Ristretto255,
                else => unreachable,
            };
            // Per-curve CU = base + incr*(n-1), charged INSIDE the curve arm before decode.
            // @prov:syscall.curve-ops — saturating; n==0 → n-|1=0 → base.
            const base = if (id == .edwards) CuCost.curve25519_edwards_msm_base_cost else CuCost.curve25519_ristretto_msm_base_cost;
            const incr = if (id == .edwards) CuCost.curve25519_edwards_msm_incremental_cost else CuCost.curve25519_ristretto_msm_incremental_cost;
            const cost: u64 = base +| (incr *| (n -| 1));
            ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

            const scalars_bytes_total = std.math.mul(u64, n, 32) catch return error.M6_InvalidArgument;
            const scalars_raw = try translateConstSlice(ic, scalars_addr, scalars_bytes_total);
            const points_raw = try translateConstSlice(ic, points_addr, scalars_bytes_total);
            // Re-cast contiguous bytes as []const [32]u8, then take the first n elements.
            const scalars: []const [32]u8 = @ptrCast(@alignCast(scalars_raw[0..@intCast(scalars_bytes_total)]));
            const points: []const [32]u8 = @ptrCast(@alignCast(points_raw[0..@intCast(scalars_bytes_total)]));

            const result_bytes = crypto_helpers.edwardsMsm(T, scalars[0..@intCast(n)], points[0..@intCast(n)]) catch {
                // non-canonical scalar / undecodable point → canonical None → SOFT r0=1.
                // (Per-term identity / identity sum are NOT errors — computed above.)
                traceExit("sol_curve_multiscalar_mul", 1);
                return 1;
            };
            // Translate output ONLY on success — canonical translate_mut is in the `Some` branch.
            const out_slice = try translateMutSlice(ic, out_addr, 32);
            @memcpy(out_slice[0..32], &result_bytes);
            traceExit("sol_curve_multiscalar_mul", 0);
            return 0;
        },
        else => return error.M6_CurveUnsupportedId,
    }
}

// ABI: r1=curve_id, r2=point_addr, r3=result_addr. r4/r5 unused.
// @prov:syscall.curve-ops (The prior stub read result from r5 — a latent
// bug masked by the always-error stub; corrected here.)
fn solCurveDecompress(ic: *InvokeContext, curve_id_raw: u64, point_addr: u64, out_addr: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_curve_decompress", ic, curve_id_raw, point_addr, out_addr, 0, 0);

    const curve_id = crypto_helpers.CurveId.wrap(curve_id_raw) orelse return error.M6_CurveInvalidId;
    // Decompress has NO feature-gate-inline check in agave (it's gated at
    // registration). @prov:syscall.curve-ops — mirrors that observable behavior with an
    // inline gate: pre-activation, the BLS curve_ids abort (InvalidAttribute).
    if (!ic.enable_bls12_381_syscall and curve_id.isBls()) return error.M6_FeatureGated;

    switch (curve_id) {
        // @prov:syscall.curve-ops — decompression.rs: uncompress (field+on-curve)
        // + is_torsion_free (subgroup). r0=0 + 96-byte out on success, 1 else.
        .bls12_381_g1_be, .bls12_381_g1_le => {
            ic.consumeCompute(CuCost.bls12_381_g1_decompress_cost) catch return error.M6_ConsumeOverflow;
            const compressed = try translateType(ic, [48]u8, point_addr);
            const out_slice = try translateMutSlice(ic, out_addr, 96);
            const endianness: bls12_381.Endianness = if (curve_id == .bls12_381_g1_le) .le else .be;
            var out: [96]u8 = undefined;
            if (!bls12_381.g1Decompress(compressed, endianness, &out)) {
                traceExit("sol_curve_decompress", 1);
                return 1;
            }
            @memcpy(out_slice[0..96], &out);
            traceExit("sol_curve_decompress", 0);
            return 0;
        },
        // @prov:syscall.curve-ops
        .bls12_381_g2_be, .bls12_381_g2_le => {
            ic.consumeCompute(CuCost.bls12_381_g2_decompress_cost) catch return error.M6_ConsumeOverflow;
            const compressed = try translateType(ic, [96]u8, point_addr);
            const out_slice = try translateMutSlice(ic, out_addr, 192);
            const endianness: bls12_381.Endianness = if (curve_id == .bls12_381_g2_le) .le else .be;
            var out: [192]u8 = undefined;
            if (!bls12_381.g2Decompress(compressed, endianness, &out)) {
                traceExit("sol_curve_decompress", 1);
                return 1;
            }
            @memcpy(out_slice[0..192], &out);
            traceExit("sol_curve_decompress", 0);
            return 0;
        },
        // curve_id 4 (plain) / edwards / ristretto have no decompress arm →
        // agave `_ => InvalidAttribute` abort.
        else => return error.M6_CurveUnsupportedId,
    }
}

// ABI: r1=curve_id, r2=num_pairs, r3=g1_points_addr, r4=g2_points_addr,
// r5=result_addr. @prov:syscall.curve-ops (The prior stub used the wrong ABI — corrected here.)
fn solCurvePairingMap(ic: *InvokeContext, curve_id_raw: u64, num_pairs: u64, g1_addr: u64, g2_addr: u64, out_addr: u64) SyscallError!u64 {
    traceEntry("sol_curve_pairing_map", ic, curve_id_raw, num_pairs, g1_addr, g2_addr, out_addr);

    const curve_id = crypto_helpers.CurveId.wrap(curve_id_raw) orelse return error.M6_CurveInvalidId;
    // No inline feature check in agave (gated at registration). Mirror with an
    // inline gate so pre-activation the BLS curve_ids abort.
    if (!ic.enable_bls12_381_syscall and curve_id.isBls()) return error.M6_FeatureGated;

    // Only plain BLS12-381 (curve_id 4/132) — no G1/G2 suffix. agave's match
    // arm; anything else → InvalidAttribute abort.
    const endianness: bls12_381.Endianness = switch (curve_id) {
        .bls12_381_be => .be,
        .bls12_381_le => .le,
        else => return error.M6_CurveUnsupportedId,
    };

    // CU = one_pair_cost + additional_pair_cost*(num_pairs-1), saturating.
    // @prov:syscall.curve-ops — charged BEFORE translate. num_pairs==0 → -1
    // saturates to 0 multiplier → just one_pair_cost (matches saturating_sub).
    var cost = CuCost.bls12_381_one_pair_cost;
    cost +|= CuCost.bls12_381_additional_pair_cost *| (num_pairs -| 1);
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    // translate_slice::<PodG1Point>(addr, num_pairs) — 96 bytes each.
    // num_pairs==0 → zero-length translation (allowed).
    const g1_bytes = try translateConstSlice(ic, g1_addr, num_pairs *| 96);
    const g2_bytes = try translateConstSlice(ic, g2_addr, num_pairs *| 192);
    const out_slice = try translateMutSlice(ic, out_addr, bls12_381.GT_SIZE);

    var out: [bls12_381.GT_SIZE]u8 = undefined;
    // pairing.rs: num_pairs>8 OR any decode failure → None → Ok(1); n==0 →
    // identity Gt → Ok(0). pairingMap handles all of these internally.
    if (!bls12_381.pairingMap(g1_bytes, g2_bytes, @intCast(num_pairs), endianness, &out)) {
        traceExit("sol_curve_pairing_map", 1);
        return 1;
    }
    @memcpy(out_slice[0..bls12_381.GT_SIZE], &out);
    traceExit("sol_curve_pairing_map", 0);
    return 0;
}

// ── alt_bn128 group op id table (solana-bn254 v3.2.1; LE_FLAG = 0x80) ──────────
// G1 add  BE=0   LE=0x80 | G1 mul BE=2 LE=0x82 | pairing BE=3 LE=0x83
// G2 add  BE=4   LE=0x84 | G2 mul BE=6 LE=0x86
const ALT_BN128_G1_ADD_BE: u64 = 0;
const ALT_BN128_G1_ADD_LE: u64 = 0x80;
const ALT_BN128_G1_MUL_BE: u64 = 2;
const ALT_BN128_G1_MUL_LE: u64 = 0x82;
const ALT_BN128_PAIRING_BE: u64 = 3;
const ALT_BN128_PAIRING_LE: u64 = 0x83;
const ALT_BN128_G2_ADD_BE: u64 = 4;
const ALT_BN128_G2_ADD_LE: u64 = 0x84;
const ALT_BN128_G2_MUL_BE: u64 = 6;
const ALT_BN128_G2_MUL_LE: u64 = 0x86;
const ALT_BN128_PAIRING_ELEMENT_SIZE: u64 = 192;
const ALT_BN128_PAIRING_OUTPUT_SIZE: u64 = 32;

// op kind after stripping the LE bit; drives cost + output size + FD call.
const Bn128GroupKind = enum { g1_add, g1_mul, pairing, g2_add, g2_mul };

fn solAltBn128GroupOp(ic: *InvokeContext, op: u64, in_addr: u64, in_len: u64, out_addr: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_alt_bn128_group_op", ic, op, in_addr, in_len, out_addr, 0);
    // @prov:syscall.altbn128-group-op — big_endian = no LE bit.
    //
    // ERROR MAPPING (consensus-critical):
    //   gate violation (LE w/o SIMD-0284, G2 w/o SIMD-0302) OR unknown op-id
    //       → Zig error → ABORT (agave SyscallError::InvalidAttribute, tx fails)
    //   math failure (not-on-curve / subgroup / bad-len-V1, FD returns -1)
    //       → return value 1 (agave Ok(1) soft — tx CONTINUES)
    //   success → write out + return 0 (agave Ok(SUCCESS))
    const big_endian: bool = (op & 0x80) == 0;

    // (1) SIMD-0284: block LE ops if feature inactive — BEFORE cost.
    // @prov:syscall.altbn128-group-op — the 3 LE ops listed by agave are G1 add/mul +
    // pairing LE; G2 LE ops are caught by the G2 gate below.
    if (!ic.alt_bn128_little_endian_active) {
        switch (op) {
            ALT_BN128_G1_ADD_LE, ALT_BN128_G1_MUL_LE, ALT_BN128_PAIRING_LE => return error.M6_FeatureGated,
            else => {},
        }
    }
    // (2) SIMD-0302: block ALL G2 ops if feature inactive.
    if (!ic.alt_bn128_g2_active) {
        switch (op) {
            ALT_BN128_G2_ADD_BE, ALT_BN128_G2_ADD_LE, ALT_BN128_G2_MUL_BE, ALT_BN128_G2_MUL_LE => return error.M6_FeatureGated,
            else => {},
        }
    }

    // (3) Resolve kind/cost/output via the op-id (unknown id → abort) — matches
    //     agave's `match group_op { … _ => Err(InvalidAttribute) }` at :2169.
    const kind: Bn128GroupKind, const out_size: u64, const cost: u64 = switch (op) {
        ALT_BN128_G1_ADD_BE, ALT_BN128_G1_ADD_LE => .{ .g1_add, 64, CuCost.alt_bn128_g1_addition_cost },
        ALT_BN128_G2_ADD_BE, ALT_BN128_G2_ADD_LE => .{ .g2_add, 128, CuCost.alt_bn128_g2_addition_cost },
        ALT_BN128_G1_MUL_BE, ALT_BN128_G1_MUL_LE => .{ .g1_mul, 64, CuCost.alt_bn128_g1_multiplication_cost },
        ALT_BN128_G2_MUL_BE, ALT_BN128_G2_MUL_LE => .{ .g2_mul, 128, CuCost.alt_bn128_g2_multiplication_cost },
        ALT_BN128_PAIRING_BE, ALT_BN128_PAIRING_LE => blk: {
            // Pairing cost = first + other*(k-1) + sha256_base + in_len + out_size,
            // all saturating. k = in_len/192 (FD/agave reject non-%192 later as a
            // soft Ok(1); cost still uses integer div). @prov:syscall.altbn128-group-op
            const k = in_len / ALT_BN128_PAIRING_ELEMENT_SIZE;
            var c = CuCost.alt_bn128_pairing_one_pair_cost_first;
            c +|= CuCost.alt_bn128_pairing_one_pair_cost_other *| (k -| 1);
            c +|= CuCost.sha256_base_cost;
            c +|= in_len;
            c +|= ALT_BN128_PAIRING_OUTPUT_SIZE;
            break :blk .{ .pairing, ALT_BN128_PAIRING_OUTPUT_SIZE, c };
        },
        else => return error.M6_FeatureGated, // unknown op-id → InvalidAttribute abort
    };

    // (4) Consume CU BEFORE translate + op (agave :2207).
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    // (5) Translate OUT (exact out_size) then IN (agave :2210-2221).
    const out = try translateMutSlice(ic, out_addr, out_size);
    const in = try translateConstSlice(ic, in_addr, in_len);

    if (bn254.active_backend == .unported) return error.M6_AltBn128RequiresBn254ImplPort;

    // (6) Run the op. FD validates input length internally (e.g. g1 add: >128→-1,
    //     LE requires exact len; g1 mul V1 = 96B; pairing strict %192). FD -1 →
    //     soft return 1; success → out written, return 0.
    const ok = switch (kind) {
        .g1_add => bn254.g1Add(out, in, big_endian),
        .g1_mul => bn254.g1Mul(out, in, big_endian),
        .g2_add => bn254.g2Add(out, in, big_endian),
        .g2_mul => bn254.g2Mul(out, in, big_endian),
        .pairing => bn254.pairing(out, in, big_endian),
    };
    if (!ok) {
        traceExit("sol_alt_bn128_group_op", 1);
        return 1; // soft failure — tx continues with r0=1
    }
    traceExit("sol_alt_bn128_group_op", 0);
    return 0;
}

// ── alt_bn128 compression op id table (solana-bn254 v3.2.1) ───────────────────
// G1 compress 0 | G1 decompress 1 | G2 compress 2 | G2 decompress 3 (+0x80 = LE)
const ALT_BN128_G1_COMPRESS_BE: u64 = 0;
const ALT_BN128_G1_DECOMPRESS_BE: u64 = 1;
const ALT_BN128_G2_COMPRESS_BE: u64 = 2;
const ALT_BN128_G2_DECOMPRESS_BE: u64 = 3;
const ALT_BN128_G1_COMPRESS_LE: u64 = 0x80;
const ALT_BN128_G1_DECOMPRESS_LE: u64 = 0x81;
const ALT_BN128_G2_COMPRESS_LE: u64 = 0x82;
const ALT_BN128_G2_DECOMPRESS_LE: u64 = 0x83;

const Bn128CompressKind = enum { g1_compress, g1_decompress, g2_compress, g2_decompress };

fn solAltBn128Compress(ic: *InvokeContext, op: u64, in_addr: u64, in_len: u64, out_addr: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_alt_bn128_compression", ic, op, in_addr, in_len, out_addr, 0);
    // @prov:syscall.altbn128-compress
    // Cost = syscall_base_cost(100) + per_op (group_op does NOT add the base).
    // ERROR MAPPING: LE w/o SIMD-0284 OR unknown op-id → abort (InvalidAttribute);
    // input_size mismatch OR FD NULL (bad point) → return 1 (soft); else out+0.
    const big_endian: bool = (op & 0x80) == 0;

    // (1) SIMD-0284: block ALL LE compress ops if inactive.
    if (!ic.alt_bn128_little_endian_active) {
        switch (op) {
            ALT_BN128_G1_COMPRESS_LE, ALT_BN128_G2_COMPRESS_LE, ALT_BN128_G1_DECOMPRESS_LE, ALT_BN128_G2_DECOMPRESS_LE => return error.M6_FeatureGated,
            else => {},
        }
    }

    // (2) Resolve kind/output/cost + the EXACT expected input size. agave's
    //     match only sets cost+output; the in-size check is implicit in the
    //     fixed-size compress fns (wrong len → Err → Ok(1)). FD's compress fns
    //     take fixed buffers (no in_sz arg), so we size-check HERE and map a
    //     mismatch to the same soft return 1.
    const kind: Bn128CompressKind, const out_size: u64, const in_size: u64, const per_op: u64 = switch (op) {
        ALT_BN128_G1_COMPRESS_BE, ALT_BN128_G1_COMPRESS_LE => .{ .g1_compress, 32, 64, CuCost.alt_bn128_g1_compress },
        ALT_BN128_G1_DECOMPRESS_BE, ALT_BN128_G1_DECOMPRESS_LE => .{ .g1_decompress, 64, 32, CuCost.alt_bn128_g1_decompress },
        ALT_BN128_G2_COMPRESS_BE, ALT_BN128_G2_COMPRESS_LE => .{ .g2_compress, 64, 128, CuCost.alt_bn128_g2_compress },
        ALT_BN128_G2_DECOMPRESS_BE, ALT_BN128_G2_DECOMPRESS_LE => .{ .g2_decompress, 128, 64, CuCost.alt_bn128_g2_decompress },
        else => return error.M6_FeatureGated, // unknown op-id → InvalidAttribute abort
    };

    // (3) Consume CU = base + per_op BEFORE translate (agave :2486,:2507).
    const cost = CuCost.syscall_base_cost +| per_op;
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    // (4) Translate OUT (exact out_size) then IN (in_len, the raw arg — agave
    //     :2510-2521). Pointer validity is checked against the actual in_len.
    const out = try translateMutSlice(ic, out_addr, out_size);
    const in = try translateConstSlice(ic, in_addr, in_len);

    if (bn254.active_backend == .unported) return error.M6_AltBn128RequiresBn254ImplPort;

    // (5) Wrong input length → soft return 1 (agave: the fixed-size compress fn
    //     errors on a short/long slice → Ok(1)). FD takes a fixed in[N], so we
    //     must reject mismatches before the call rather than read OOB.
    if (in_len != in_size) {
        traceExit("sol_alt_bn128_compression", 1);
        return 1;
    }

    // (5b) FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #2, zbpf 64c9e56
    // stageIfAliasing/freeStaged): G1/G2 compress() in bn254/curve.zig do a
    // bare @memcpy(out, input[0..N]) internally, which PANICS (safety-checked
    // ReleaseSafe build -- @memcpy requires disjoint src/dst) the instant
    // `in`/`out` alias at all, including exact aliasing (in_addr==out_addr),
    // a legitimate in-place-compress calling pattern. Real Agave never
    // crashes the validator process on this input shape. Stage `in` through
    // a scratch allocator copy whenever it overlaps `out`, using the
    // pre-existing isNonoverlapping() helper (:371, previously unused on
    // this path) so the crypto leaf never receives aliasing pointers.
    // compress()/decompress() are pure functions of the input bytes, so
    // staging changes crash behavior only, never the result.
    const staged_in = if (isNonoverlapping(in_addr, in_len, out_addr, out_size))
        in
    else
        ic.allocator.dupe(u8, in) catch return error.M6_ConsumeOverflow;
    defer if (staged_in.ptr != in.ptr) ic.allocator.free(@constCast(staged_in));

    const ok = switch (kind) {
        .g1_compress => bn254.g1Compress(out, staged_in, big_endian),
        .g1_decompress => bn254.g1Decompress(out, staged_in, big_endian),
        .g2_compress => bn254.g2Compress(out, staged_in, big_endian),
        .g2_decompress => bn254.g2Decompress(out, staged_in, big_endian),
    };
    if (!ok) {
        traceExit("sol_alt_bn128_compression", 1);
        return 1; // bad point → soft, tx continues with r0=1
    }
    traceExit("sol_alt_bn128_compression", 0);
    return 0;
}

const BigModExpParamsAbi = extern struct {
    base: u64,
    base_len: u64,
    exponent: u64,
    exponent_len: u64,
    modulus: u64,
    modulus_len: u64,
};
const BIG_MOD_EXP_MAX_LEN: u64 = 512;

// FIX 2 (cpi-invoke-units-cu-parity, 2026-07-12). @prov:syscall.big-mod-exp
// Agave's stub is UNCONDITIONAL — no CU consumed, always returns 1. The
// previous real square-and-multiply modpow implementation (an older Agave
// pin that DID have a real quadratic-cost implementation) is preserved below
// as `solBigModExpRealUnused`, dead-code-eliminated by Zig's lazy analysis
// (never referenced), for the day SIMD-529 lands with a real, checkable
// feature ID — do not wire it up before then.
fn solBigModExp(ic: *InvokeContext, params_addr: u64, arg2: u64, arg3: u64, arg4: u64, out_addr: u64) SyscallError!u64 {
    traceEntry("sol_big_mod_exp", ic, params_addr, arg2, arg3, arg4, out_addr);
    // Agave never reads _params/_return_value and never touches the compute
    // meter or VM memory — mirror that exactly: no translate, no consume.
    traceExit("sol_big_mod_exp", 1);
    return 1;
}

// DEAD CODE (never referenced — Zig's lazy top-level analysis will not
// compile this into the binary). Retained verbatim as the pre-SIMD-529
// "rc.1"-era real modpow implementation, for when SIMD-529 lands with a
// real checkable feature ID. DO NOT call this from solBigModExp above
// until that happens — doing so unconditionally would diverge from the
// current, pinned agave-4.2.0-beta.0 stub behavior audited above.
fn solBigModExpRealUnused(ic: *InvokeContext, params_addr: u64, _: u64, _: u64, _: u64, out_addr: u64) SyscallError!u64 {
    traceEntry("sol_big_mod_exp", ic, params_addr, 0, 0, 0, out_addr);

    // @prov:syscall.big-mod-exp — CU + ORDER (pre-SIMD-529 "rc.1"-era real implementation):
    //   (1) translate the params struct
    //   (2) if any of base_len/exponent_len/modulus_len > 512 → InvalidLength ABORT
    //       (BEFORE any CU consume — over-length txs do NOT pay the syscall cost)
    //   (3) input_len = max(base_len, exponent_len, modulus_len)
    //   (4) cost = syscall_base_cost + (input_len^2 / divisor(2)) + base_cost(190)
    //   (5) consume → (6) translate slices → (7) compute.
    const params_ptr = try translateType(ic, BigModExpParamsAbi, params_addr);
    const p = params_ptr.*;
    if (p.base_len > BIG_MOD_EXP_MAX_LEN or p.exponent_len > BIG_MOD_EXP_MAX_LEN or p.modulus_len > BIG_MOD_EXP_MAX_LEN) {
        return error.M6_BigModExpInvalidLength;
    }

    const input_len = @max(p.base_len, @max(p.exponent_len, p.modulus_len));
    // input_len ≤ 512 (checked above) so input_len^2 ≤ 262144 — no overflow; the
    // saturating ops mirror agave's saturating_mul / checked_div(unwrap_or MAX).
    const quad = (std.math.mul(u64, input_len, input_len) catch std.math.maxInt(u64)) /
        CuCost.big_modular_exponentiation_cost_divisor;
    const cost = CuCost.syscall_base_cost +| quad +| CuCost.big_modular_exponentiation_base_cost;
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    const base = try translateConstSlice(ic, p.base, p.base_len);
    const exponent = try translateConstSlice(ic, p.exponent, p.exponent_len);
    const modulus = try translateConstSlice(ic, p.modulus, p.modulus_len);
    const out = try translateMutSlice(ic, out_addr, p.modulus_len);

    crypto_helpers.bigModExp(ic.allocator, base, exponent, modulus, out) catch |e| switch (e) {
        error.InvalidModulusZero => return error.M6_BigModExpModulusZero,
        error.OutOfMemory => return error.M6_OutOfMemory,
    };

    traceExit("sol_big_mod_exp", 0);
    return 0;
}

const POSEIDON_MAX_VALS: u64 = 12; // @prov:syscall.poseidon — vals_len>12 → InvalidLength abort

fn solPoseidon(ic: *InvokeContext, params: u64, endian: u64, vals_addr: u64, vals_len: u64, out_addr: u64) SyscallError!u64 {
    traceEntry("sol_poseidon", ic, params, endian, vals_addr, vals_len, out_addr);
    // @prov:syscall.poseidon — ORDER (each abort is
    // a Zig error → tx fails; hash failure is a soft return 1):
    //   (1) parse params: 0 = Bn254X5, else InvalidParams ABORT
    //   (2) parse endian: 0 = BE, 1 = LE, else InvalidEndianness ABORT
    //   (3) vals_len > 12 → InvalidLength ABORT
    //   (4) cost = 61*n^2 + 542 (consume; overflow → ArithmeticOverflow ABORT)
    //   (5) translate OUT(32) then the VmSlice array + each slice (bad ptr ABORT)
    //   (6) enforce_padding = featureActive(SIMD-0359); hash fail → return 1 soft
    //   (7) success → 32B out + return 0
    // vals_len==0 is NOT special-cased: it flows through to fd_poseidon_fini
    // (cnt==0 → NULL → return 1), matching agave hashv([]) → Ok(1).

    // (1) params: only Bn254X5 (=0) is defined (agave poseidon::Parameters).
    if (params != 0) return error.M6_PoseidonNotImplemented; // InvalidParams abort

    // (2) endian: agave 0=BE, 1=LE. FD convention is inverted (1=BE,0=LE), so
    //     FD big_endian = (endian == 0).
    const fd_big_endian: bool = switch (endian) {
        0 => true, // agave BE
        1 => false, // agave LE
        else => return error.M6_InvalidArgument, // InvalidEndianness abort
    };

    // (3) vals_len > 12 → abort (BEFORE cost). @prov:syscall.poseidon
    if (vals_len > POSEIDON_MAX_VALS) return error.M6_BigModExpInvalidLength; // InvalidLength abort

    // (4) cost = 61*n^2 + 542 (agave execution_budget.rs poseidon_cost).
    const n_sq = std.math.mul(u64, vals_len, vals_len) catch return error.M6_InvalidArgument;
    const cost = std.math.add(
        u64,
        std.math.mul(u64, CuCost.poseidon_cost_coefficient_a, n_sq) catch return error.M6_InvalidArgument,
        CuCost.poseidon_cost_coefficient_c,
    ) catch return error.M6_InvalidArgument;
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    // (5) translate OUT(32) then the VmSlice array, then each referenced slice
    //     (agave :2400-2411). Translate-failures ABORT (Zig error).
    const out = try translateMutSlice(ic, out_addr, 32);

    if (bn254.active_backend == .unported) return error.M6_PoseidonRequiresBn254ImplPort;

    // vals_len is ≤12 here; collect the host slices into a fixed buffer.
    var segs: [POSEIDON_MAX_VALS][]const u8 = undefined;
    const n: usize = @intCast(vals_len);
    if (vals_len > 0) {
        const total = std.math.mul(u64, vals_len, VM_SLICE_SIZE) catch return error.M6_InvalidArgument;
        const raw = try translateConstSlice(ic, vals_addr, total);
        var i: usize = 0;
        var idx: usize = 0;
        while (i < raw.len) : (i += @intCast(VM_SLICE_SIZE)) {
            const sl_addr = std.mem.readInt(u64, raw[i .. i + 8][0..8], .little);
            const sl_len = std.mem.readInt(u64, raw[i + 8 .. i + 16][0..8], .little);
            segs[idx] = try translateConstSlice(ic, sl_addr, sl_len);
            idx += 1;
        }
    }

    // (6) enforce_padding from SIMD-0359 gate. Hash failure (data≥modulus,
    //     enforce && sz!=32, empty slice, or vals_len==0 via fini cnt==0) →
    //     soft return 1 (agave :2418-2420).
    const ok = bn254.poseidonHash(out, segs[0..n], fd_big_endian, ic.poseidon_enforce_padding_active);
    if (!ok) {
        traceExit("sol_poseidon", 1);
        return 1;
    }
    traceExit("sol_poseidon", 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────────────
// PDA family — pure crypto via SHA-256 (no external dependency beyond std).
//
// Reference: solana-program-sdk pubkey.rs `create_program_address` /
//            agave SyscallCreateProgramAddress in syscalls/src/lib.rs.
// ──────────────────────────────────────────────────────────────────────────────

const PDA_MARKER: []const u8 = "ProgramDerivedAddress";
const MAX_SEEDS: usize = 16;
const MAX_SEED_LEN: usize = 32;

/// Hex character lookup for diagnostic logging (env-gated, infallible
/// alternative to bufPrint("{x:0>2}") that avoids `catch {}` shapes per
/// the no-bandaid rule). 16 entries; index always in 0..16.
const HEX_LUT: [16]u8 = "0123456789abcdef".*;

fn createProgramAddressInner(
    seeds: []const []const u8,
    program_id: *const [32]u8,
    out: *[32]u8,
) SyscallError!void {
    if (seeds.len > MAX_SEEDS) return error.M6_PdaInputTooLarge;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (seeds) |s| {
        if (s.len > MAX_SEED_LEN) return error.M6_PdaInputTooLarge;
        hasher.update(s);
    }
    hasher.update(program_id);
    hasher.update(PDA_MARKER);
    var h: [32]u8 = undefined;
    hasher.final(&h);
    // Reject on-curve points: any successful Edwards25519 decompression means
    // this is a real public key, not a PDA. Use std.crypto.ecc Ed25519.
    if (std.crypto.ecc.Edwards25519.fromBytes(h)) |_| {
        return error.M6_PdaNotDerivable;
    } else |_| {}
    @memcpy(out, &h);
}

fn readSeedTable(
    ic: *InvokeContext,
    seeds_addr: u64,
    seeds_len: u64,
    storage: *[MAX_SEEDS][]const u8,
) SyscallError![]const []const u8 {
    if (seeds_len == 0) return storage[0..0];
    if (seeds_len > MAX_SEEDS) return error.M6_PdaInputTooLarge;
    const raw = try translateConstSlice(ic, seeds_addr, std.math.mul(u64, seeds_len, VM_SLICE_SIZE) catch
        return error.M6_PdaInputTooLarge);
    var i: usize = 0;
    var idx: usize = 0;
    while (i < raw.len) : (i += @intCast(VM_SLICE_SIZE)) {
        const a = std.mem.readInt(u64, raw[i .. i + 8][0..8], .little);
        const l = std.mem.readInt(u64, raw[i + 8 .. i + 16][0..8], .little);
        if (l > MAX_SEED_LEN) return error.M6_PdaInputTooLarge;
        const seed = try translateConstSlice(ic, a, l);
        storage[idx] = seed;
        idx += 1;
    }
    return storage[0..idx];
}

fn solCreatePda(
    ic: *InvokeContext,
    seeds_addr: u64,
    seeds_len: u64,
    program_id_addr: u64,
    out_addr: u64,
    _: u64,
) SyscallError!u64 {
    traceEntry("sol_create_program_address", ic, seeds_addr, seeds_len, program_id_addr, out_addr, 0);
    ic.consumeCompute(CuCost.create_program_address_units) catch return error.M6_ConsumeOverflow;
    var seed_storage: [MAX_SEEDS][]const u8 = undefined;
    const seeds = try readSeedTable(ic, seeds_addr, seeds_len, &seed_storage);
    const pid = try translateType(ic, [32]u8, program_id_addr);
    const out = try translateMutType(ic, [32]u8, out_addr);
    createProgramAddressInner(seeds, pid, out) catch |e| switch (e) {
        error.M6_PdaNotDerivable => {
            return 1; // SUCCESS=0, "not derivable" is non-zero return per agave.
        },
        else => return e,
    };
    traceExit("sol_create_program_address", 0);
    return 0;
}

fn solTryFindPda(
    ic: *InvokeContext,
    seeds_addr: u64,
    seeds_len: u64,
    program_id_addr: u64,
    addr_out: u64,
    bump_out: u64,
) SyscallError!u64 {
    traceEntry("sol_try_find_program_address", ic, seeds_addr, seeds_len, program_id_addr, addr_out, bump_out);
    var seed_storage: [MAX_SEEDS][]const u8 = undefined;
    // G2 fix (conformance grind, try_find_program_address MAX_SEEDS
    // off-by-one): the redundant `seeds.len + 1 > MAX_SEEDS` pre-check that
    // used to live here double-counted the bump seed against the 16-seed
    // limit Agave applies to USER seeds only (agave-4.2.0-beta.1-src/
    // syscalls/src/lib.rs `translate_and_check_program_address_inputs`:
    // `if untranslated_seeds.len() > MAX_SEEDS { return Err(...) }`, checked
    // on the USER-supplied seeds BEFORE appending the bump byte).
    // `readSeedTable` above already enforces this correct bound, so no
    // separate check is needed here.
    const seeds = try readSeedTable(ic, seeds_addr, seeds_len, &seed_storage);
    const pid = try translateType(ic, [32]u8, program_id_addr);

    // G2 fix, part 2 (2026-07-18, re-derived from reading Agave's real
    // `SyscallTryFindProgramAddress::rust` directly, agave-4.2.0-beta.1-src/
    // syscalls/src/lib.rs:882-931 -- the naive fix (delete the old guard +
    // resize `local_seeds`) was NOT sufficient on its own: it still
    // hard-errored/access-violated on the empirically confirmed 16-user-seed
    // corpus fixtures. Reading the primary source revealed the REAL
    // structure, replicated below:
    //   1. `Pubkey::create_program_address(&seeds_with_bump, program_id)` is
    //      called with the FULL 17-element set (16 user + 1 bump) when
    //      seeds.len()==MAX_SEEDS -- Agave's own `create_program_address`
    //      re-checks `seeds.len() > MAX_SEEDS` on that combined count and
    //      returns `Err(MaxSeedLengthExceeded)` EVERY attempt. The caller
    //      only does `if let Ok(new_address) = ...` -- ANY `Err` (not just
    //      "not derivable") is silently treated as "this bump didn't work,
    //      try the next one," so 16 user seeds structurally can NEVER find
    //      a PDA and always exhausts to the not-derivable path.
    //   2. `address_addr`/`bump_seed_addr` are translated LAZILY via
    //      `translate_mut!` INSIDE the `if let Ok(new_address) = ...` arm --
    //      i.e. ONLY when a candidate is actually about to be written --
    //      not eagerly before the search loop. A garbage/unmapped
    //      `addr_out`/`bump_out` is never dereferenced on the (structurally
    //      guaranteed, for 16 seeds) not-derivable path, matching the
    //      corpus's `expected error=0 r0=1` (soft "not derivable") instead
    //      of an access-violation.
    //   3. Exhausting the loop returns `Ok(1)` (soft "not derivable"), NOT
    //      an error -- same convention `sol_create_program_address` already
    //      uses just above.
    // `local_seeds` stays sized [MAX_SEEDS+1] (16 user + 1 bump) so building
    // that 17-element slice for `createProgramAddressInner` never overflows
    // the array itself; `createProgramAddressInner`'s OWN `seeds.len >
    // MAX_SEEDS` check (unchanged) is what correctly rejects it per-attempt.
    var local_seeds: [MAX_SEEDS + 1][]const u8 = undefined;
    @memcpy(local_seeds[0..seeds.len], seeds);
    var bump_byte: [1]u8 = .{0xff};
    var bump: u8 = 255;
    while (true) : (bump -%= 1) {
        // Each attempt costs create_program_address_units (agave matches this).
        ic.consumeCompute(CuCost.create_program_address_units) catch return error.M6_ConsumeOverflow;
        bump_byte[0] = bump;
        local_seeds[seeds.len] = &bump_byte;
        var out: [32]u8 = undefined;
        if (createProgramAddressInner(local_seeds[0 .. seeds.len + 1], pid, &out)) |_| {
            // Lazy translate — only reached once a candidate PDA is found.
            const addr_slot = try translateMutType(ic, [32]u8, addr_out);
            const bump_slot = try translateMutType(ic, u8, bump_out);
            // G1 fix (conformance grind, sol_try_find_program_address
            // output-overlap check): Agave's real `translate_mut!` call
            // translates `bump_seed_ref`/`address` TOGETHER into the same
            // mutable-region-overlap-checked arena and rejects two
            // overlapping mutable output regions with
            // `SyscallError::CopyOverlapping` (declaration-order
            // discriminant 11 -> proto code 12). Vexor previously
            // translated these two host slices independently with NO
            // overlap check, silently corrupting the aliased byte when
            // `addr_out == bump_out` (or otherwise overlaps). Reuses the
            // same `isNonoverlapping` helper `sol_memcpy_`/`sol_memmove_`
            // already use against the two translated hosts' own
            // addresses/lengths.
            if (!isNonoverlapping(@intFromPtr(addr_slot), 32, @intFromPtr(bump_slot), 1)) {
                return error.M6_CopyOverlapping;
            }
            @memcpy(addr_slot, &out);
            bump_slot.* = bump;
            return 0;
        } else |e| switch (e) {
            // Agave's `if let Ok(new_address) = ...` swallows ANY `Err` from
            // `Pubkey::create_program_address` as "try the next bump" --
            // both the genuine "on-curve, not derivable" case
            // (`M6_PdaNotDerivable`) AND the "seeds_with_bump exceeds
            // MAX_SEEDS" case (`M6_PdaInputTooLarge`, structurally always
            // hit once seeds.len==MAX_SEEDS — see part 2 above).
            error.M6_PdaNotDerivable, error.M6_PdaInputTooLarge => {},
            else => return e,
        }
        if (bump == 0) break;
    }
    return 1; // SUCCESS=0, "not derivable" is non-zero return per agave (matches solCreatePda above).
}

// ──────────────────────────────────────────────────────────────────────────────
// Sysvar getters. @prov:syscall.sysvar-getters
// ──────────────────────────────────────────────────────────────────────────────

fn sysvarGetGeneric(
    ic: *InvokeContext,
    bytes_result: error{SysvarNotPopulated}![]const u8,
    var_addr: u64,
    type_size: u64,
) SyscallError!u64 {
    // @prov:syscall.sysvar-getters — cost = sysvar_base_cost + size_of::<T>()
    const cost = std.math.add(u64, CuCost.sysvar_base_cost, type_size) catch return error.M6_InvalidArgument;
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    // SIMD-0459: var_addr in MM_INPUT region rejected when feature active.
    // @prov:syscall.sysvar-getters — honoured preemptively to match upcoming activation.
    if (var_addr >= memory.MM_INPUT_START) return error.M6_AccessViolation;

    const dst = try translateMutSlice(ic, var_addr, type_size);
    const bytes = bytes_result catch return error.M6_SysvarNotPopulated;
    if (bytes.len < type_size) return error.M6_SysvarNotPopulated;
    @memcpy(dst[0..type_size], bytes[0..type_size]);
    return 0;
}

fn solGetClock(ic: *InvokeContext, addr: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_get_clock_sysvar", ic, addr, 0, 0, 0, 0);
    return sysvarGetGeneric(ic, ic.sysvar_cache.getClockBytes(), addr, sysvar_cache_mod.CLOCK_SIZE);
}

// PR-5an (2026-05-20): EpochSchedule wire-form vs in-memory layout fix
// (Carrier I closer).
//
// Bug: Vexor's sysvar cache stores the 33-byte bincode wire form of
// EpochSchedule (declaration-order: u64 + u64 + bool(1) + u64 + u64).
// @prov:syscall.sysvar-epoch-schedule-layout — Agave's
// `sol_get_epoch_schedule_sysvar` writes the in-memory `#[repr(C)]` padded
// 40-byte layout via `*var = T::clone(sysvar.as_ref())` — preserving the
// 7-byte alignment gap after `warmup` so `first_normal_epoch` lands at
// offset 24 and `first_normal_slot` at offset 32.
//
// HJT-6009 (`HistoryJTGbKQD2mRgLZ3XhqHnN811Qpez8X9kCcGHoa`) — Jito StakeNet
// `confirmed_blocks_in_epoch` — calls Anchor's `EpochSchedule::get()` which
// allocates a 40-byte `Self::default()` on the BPF stack, hands it to the
// syscall, then reads `self.first_normal_epoch` at offset 24. With Vexor's
// flat 33-byte memcpy, offsets 24-31 contain shifted wire-form bytes
// (no padding skip), so `first_normal_epoch` reads as garbage and the
// downstream `start_slot.checked_add(BITVEC_BLOCK_SIZE - ...)` in
// `copy_cluster_info.rs:90-96` overflows → `AnchorError::ArithmeticError=6009`
// stored at HJT-6009 pc=9658/9849, surfacing as r0=6009 at TX exit pc=34650.
//
// Evidence: PR5AG-INTERP probe trace (`d7da483`) captured 3500 BPF
// instruction rows this boot. r2 transitions to `0xffffffffffffffff` at
// pc=9443 (`ldxdw r2, [r10-248]`); the source value comes from the get-first-
// slot-in-epoch path entered at pc=44843 which loads `[r6+24]` and compares
// against `r2=epoch=960`. Trace + Agave struct layout converge: the wire
// vs padded mismatch is the carrier. (Static analysis history:
// `project_carrier_i_static_analysis_2026_05_20.md`.)
//
// Fix: reshape the cache's 33 wire bytes into the 40-byte padded layout
// before writing to the BPF destination. ~20 LoC inline. Other typed
// sysvar getters (Clock, EpochRewards, LastRestartSlot) have no
// wire-vs-padded mismatch; Rent has the same bug class (17 wire vs 24
// padded) — separate PR.
fn solGetEpochSchedule(ic: *InvokeContext, addr: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_get_epoch_schedule_sysvar", ic, addr, 0, 0, 0, 0);

    const PADDED_SIZE: u64 = 40;
    const cost = std.math.add(u64, CuCost.sysvar_base_cost, PADDED_SIZE) catch return error.M6_InvalidArgument;
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    if (addr >= memory.MM_INPUT_START) return error.M6_AccessViolation;

    const dst = try translateMutSlice(ic, addr, PADDED_SIZE);
    const wire = ic.sysvar_cache.getEpochScheduleBytes() catch return error.M6_SysvarNotPopulated;
    if (wire.len < sysvar_cache_mod.EPOCH_SCHEDULE_SIZE) return error.M6_SysvarNotPopulated;

    // Wire (bincode, 33 bytes, declaration order):
    //   [0..8]   slots_per_epoch
    //   [8..16]  leader_schedule_slot_offset
    //   [16]     warmup (1 byte)
    //   [17..25] first_normal_epoch
    //   [25..33] first_normal_slot
    //
    // Padded (#[repr(C)], 40 bytes, struct memory layout per Agave's
    // `*var = T::clone(...)`):
    //   [0..8]   slots_per_epoch
    //   [8..16]  leader_schedule_slot_offset
    //   [16]     warmup (1 byte)
    //   [17..24] padding (7 bytes, zero — alignment fill for next u64)
    //   [24..32] first_normal_epoch
    //   [32..40] first_normal_slot
    @memcpy(dst[0..16], wire[0..16]);
    dst[16] = wire[16];
    @memset(dst[17..24], 0);
    @memcpy(dst[24..32], wire[17..25]);
    @memcpy(dst[32..40], wire[25..33]);

    return 0;
}

fn solGetRent(ic: *InvokeContext, addr: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_get_rent_sysvar", ic, addr, 0, 0, 0, 0);
    return sysvarGetGeneric(ic, ic.sysvar_cache.getRentBytes(), addr, sysvar_cache_mod.RENT_SIZE);
}

fn solGetEpochRewards(ic: *InvokeContext, addr: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_get_epoch_rewards_sysvar", ic, addr, 0, 0, 0, 0);
    return sysvarGetGeneric(ic, ic.sysvar_cache.getEpochRewardsBytes(), addr, sysvar_cache_mod.EPOCH_REWARDS_SIZE);
}

fn solGetLastRestartSlot(ic: *InvokeContext, addr: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_get_last_restart_slot", ic, addr, 0, 0, 0, 0);
    return sysvarGetGeneric(ic, ic.sysvar_cache.getLastRestartSlotBytes(), addr, sysvar_cache_mod.LAST_RESTART_SLOT_SIZE);
}

fn solGetFees(ic: *InvokeContext, addr: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    // SIMD-0089: disable_fees_sysvar — gate is "active" in production
    // (the syscall is feature-gated OFF). On testnet today the gate has
    // long since flipped; we surface a FeatureGated error.
    traceEntry("sol_get_fees_sysvar", ic, addr, 0, 0, 0, 0);
    ic.consumeCompute(CuCost.sysvar_base_cost) catch return error.M6_ConsumeOverflow;
    return error.M6_FeatureGated;
}

// SIMD-0127 generic getter. @prov:syscall.sysvar-getters
fn solGetSysvar(
    ic: *InvokeContext,
    sysvar_id_addr: u64,
    var_addr: u64,
    offset: u64,
    length: u64,
    _: u64,
) SyscallError!u64 {
    traceEntry("sol_get_sysvar", ic, sysvar_id_addr, var_addr, offset, length, 0);
    // Cost: sysvar_base + (32/cpi_bytes_per_unit) + max(length/cpi_bytes_per_unit, mem_op_base).
    const id_cost = if (CuCost.cpi_bytes_per_unit == 0) 0 else 32 / CuCost.cpi_bytes_per_unit;
    const buf_cost_div = if (CuCost.cpi_bytes_per_unit == 0) std.math.maxInt(u64) else length / CuCost.cpi_bytes_per_unit;
    const buf_cost = @max(buf_cost_div, CuCost.mem_op_base_cost);
    const cost = std.math.add(u64, std.math.add(u64, CuCost.sysvar_base_cost, id_cost) catch
        return error.M6_InvalidArgument, buf_cost) catch return error.M6_InvalidArgument;
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    if (var_addr >= memory.MM_INPUT_START) return error.M6_AccessViolation;

    const var_dst = try translateMutSlice(ic, var_addr, length);
    const id_ptr = try translateType(ic, [32]u8, sysvar_id_addr);

    const offset_length = std.math.add(u64, offset, length) catch return error.M6_InvalidArgument;
    _ = std.math.add(u64, var_addr, length) catch return error.M6_InvalidArgument;

    const bytes = ic.sysvar_cache.getBytesByPubkey(id_ptr.*) catch return 2; // SYSVAR_NOT_FOUND
    if (offset_length > bytes.len) return 1; // OFFSET_LENGTH_EXCEEDS_SYSVAR
    @memcpy(var_dst[0..length], bytes[@intCast(offset)..@intCast(offset_length)]);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────────────
// alloc/free (deprecated; gate `disable_deploy_of_alloc_free_syscall` is
// active in production. Per agave register block: registered
// only when the gate is OFF. We register unconditionally and surface a
// deprecation error so a deployment-time check elsewhere can short-circuit).
// ──────────────────────────────────────────────────────────────────────────────

fn solAllocFree(ic: *InvokeContext, size: u64, free_addr: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_alloc_free_", ic, size, free_addr, 0, 0, 0);
    ic.consumeCompute(CuCost.syscall_base_cost) catch return error.M6_ConsumeOverflow;

    // sol_alloc_free_ semantics (per agave's BumpAllocator + Solana SDK
    // entrypoint heap layout):
    //
    //   - free_addr != 0: free is a no-op; bump allocator never reclaims.
    //     Return 0 (NULL).
    //   - free_addr == 0: allocate `size` bytes, downward-bump from the top
    //     of the heap region. The 8-byte position counter lives at
    //     heap[0..8] (vm_addr MM_HEAP_START). When the counter is zero
    //     (unused/initialized state), interpret as heap_start + heap_len.
    //     Subtract size, align down to 8 bytes, write back, return the
    //     aligned address.
    //   - On exhaustion (would overlap the position counter), return 0.
    //
    // Without this real implementation, programs deployed before
    // `disable_deploy_of_alloc_free_syscall` activated (most Anchor 0.x +
    // Jito tip-payment) panic at instruction 57 with "Error: memory
    // allocation failed, out of memory" — the message Rust's allocator
    // error handler emits when alloc returns NULL.
    if (free_addr != 0) {
        traceExit("sol_alloc_free_", 0);
        return 0; // free is a no-op
    }

    const HEAP_START: u64 = memory.MM_HEAP_START;
    const HEAP_LEN: u64 = 32 * 1024; // matches v2_dispatch.zig:688 heap allocation
    const POS_PTR_SIZE: u64 = 8;
    const ALIGN: u64 = 8;

    // Read the 8-byte position counter at heap[0..8].
    const pos_ptr = translateMutType(ic, u64, HEAP_START) catch {
        std.log.err("[V2-ALLOC-DIAG] size={d} TRANSLATE_FAIL ret=0", .{size});
        traceExit("sol_alloc_free_", 0);
        return 0; // can't access heap → return NULL (panic-equivalent)
    };
    var pos = pos_ptr.*;
    const pos_initial = pos;
    if (pos == 0) pos = HEAP_START + HEAP_LEN;

    // Saturating subtract size + align down.
    if (pos < size) {
        std.log.err("[V2-ALLOC-DIAG] size={d} pos=0x{x} OOM_underflow ret=0", .{ size, pos });
        traceExit("sol_alloc_free_", 0);
        return 0;
    }
    var new_pos = pos - size;
    new_pos &= ~(ALIGN - 1);

    // Reserve the first POS_PTR_SIZE bytes for the counter itself.
    if (new_pos < HEAP_START + POS_PTR_SIZE) {
        std.log.err("[V2-ALLOC-DIAG] size={d} pos=0x{x} OOM_overlap ret=0", .{ size, pos });
        traceExit("sol_alloc_free_", 0);
        return 0; // OOM
    }

    pos_ptr.* = new_pos;
    std.log.err("[V2-ALLOC-DIAG] size={d} pos_initial=0x{x} pos=0x{x} new_pos=0x{x} OK", .{ size, pos_initial, pos, new_pos });
    traceExit("sol_alloc_free_", new_pos);
    return new_pos;
}

// ──────────────────────────────────────────────────────────────────────────────
// Return data (agave lib.rs SyscallSetReturnData / SyscallGetReturnData).
// ──────────────────────────────────────────────────────────────────────────────

const MAX_RETURN_DATA: u64 = 1024; // agave constant

fn solSetReturnData(ic: *InvokeContext, addr: u64, len: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_set_return_data", ic, addr, len, 0, 0, 0);
    if (len > MAX_RETURN_DATA) return error.M6_ReturnDataTooLarge;
    const div = if (CuCost.cpi_bytes_per_unit == 0) std.math.maxInt(u64) else len / CuCost.cpi_bytes_per_unit;
    const cost = std.math.add(u64, CuCost.syscall_base_cost, div) catch return error.M6_InvalidArgument;
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;

    const pid: Pubkey32 = ic.currentProgramId() orelse [_]u8{0} ** 32;

    const bytes = if (len == 0) &[_]u8{} else try translateConstSlice(ic, addr, len);
    ic.tx.return_data.set(ic.allocator, pid, bytes) catch return error.M6_OutOfMemory;
    traceExit("sol_set_return_data", 0);
    return 0;
}

fn solGetReturnData(ic: *InvokeContext, addr: u64, len: u64, program_id_addr: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_get_return_data", ic, addr, len, program_id_addr, 0, 0);
    ic.consumeCompute(CuCost.syscall_base_cost) catch return error.M6_ConsumeOverflow;
    const stored = ic.tx.return_data.data.items;
    const total: u64 = @intCast(stored.len);
    if (len == 0) return total;
    const copy_len = @min(len, total);
    if (copy_len > 0) {
        // FIX 3 (cpi-invoke-units-cu-parity, 2026-07-12). @prov:syscall.return-data-cost
        // The prior formula omitted the `+ size_of::<Pubkey>()` (32) term
        // entirely (`copy_len / 250`).
        const numerator = std.math.add(u64, copy_len, @sizeOf([32]u8)) catch std.math.maxInt(u64);
        const div = if (CuCost.cpi_bytes_per_unit == 0) std.math.maxInt(u64) else numerator / CuCost.cpi_bytes_per_unit;
        ic.consumeCompute(div) catch return error.M6_ConsumeOverflow;
        const dst = try translateMutSlice(ic, addr, copy_len);
        @memcpy(dst[0..@intCast(copy_len)], stored[0..@intCast(copy_len)]);
        const pid_dst = try translateMutType(ic, [32]u8, program_id_addr);
        @memcpy(pid_dst, &ic.tx.return_data.program_id);
    }
    return total;
}

// ──────────────────────────────────────────────────────────────────────────────
// Stack-related syscalls
// ──────────────────────────────────────────────────────────────────────────────

fn solGetStackHeight(ic: *InvokeContext, _: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_get_stack_height", ic, 0, 0, 0, 0, 0);
    ic.consumeCompute(CuCost.syscall_base_cost) catch return error.M6_ConsumeOverflow;
    // R2 fix: return tx instruction-stack length (matches sig). Min = 1
    // (top-level instr is depth 1, agave/sig agree). Agave returns
    // self.transaction_context.get_instruction_context_stack_height().
    const d: u64 = ic.currentDepth();
    const result = if (d == 0) 1 else d;
    traceExit("sol_get_stack_height", result);
    return result;
}

fn solGetSibling(
    ic: *InvokeContext,
    index: u64,
    meta_addr: u64,
    pid_addr: u64,
    data_addr: u64,
    accs_addr: u64,
) SyscallError!u64 {
    traceEntry("sol_get_processed_sibling_instruction", ic, index, meta_addr, pid_addr, data_addr, accs_addr);
    ic.consumeCompute(CuCost.syscall_base_cost) catch return error.M6_ConsumeOverflow;
    // Wave 4 will hook into the real instruction-trace. For now, M6 honestly
    // reports "no sibling at this index" which is the spec-correct answer
    // for an empty trace — return 0 (= NotFound). @prov:syscall.misc-getters
    return 0;
}

fn solRemainingComputeUnits(ic: *InvokeContext, _: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_remaining_compute_units", ic, 0, 0, 0, 0, 0);
    ic.consumeCompute(CuCost.get_remaining_compute_units_cost) catch return error.M6_ConsumeOverflow;
    return ic.computeRemaining();
}

fn solGetEpochStake(ic: *InvokeContext, vote_pk_addr: u64, _: u64, _: u64, _: u64, _: u64) SyscallError!u64 {
    traceEntry("sol_get_epoch_stake", ic, vote_pk_addr, 0, 0, 0, 0);
    // FIX 4 (cpi-invoke-units-cu-parity, 2026-07-12). @prov:syscall.epoch-stake-cost
    // Charges DIFFERENT costs on the null vs non-null `var_addr` branch — the
    // prior code charged a single flat `sysvar_base_cost` for both.
    //   var_addr == 0:  cost = syscall_base_cost
    //   var_addr != 0:  cost = syscall_base_cost
    //                        + floor(PUBKEY_BYTES(32) / cpi_bytes_per_unit(250))  (=0)
    //                        + mem_op_base_cost(10)
    //                  = 100 + 0 + 10 = 110.
    if (vote_pk_addr == 0) {
        ic.consumeCompute(CuCost.syscall_base_cost) catch return error.M6_ConsumeOverflow;
        // agave: addr=0 → return total active stake. Wave 4 hooks bank.
        return 0;
    }
    const pubkey_component = if (CuCost.cpi_bytes_per_unit == 0)
        std.math.maxInt(u64)
    else
        @as(u64, @sizeOf([32]u8)) / CuCost.cpi_bytes_per_unit;
    const cost = CuCost.syscall_base_cost +| pubkey_component +| CuCost.mem_op_base_cost;
    ic.consumeCompute(cost) catch return error.M6_ConsumeOverflow;
    _ = try translateType(ic, [32]u8, vote_pk_addr);
    // No epoch-stake source wired yet; honestly return 0.
    return 0;
}

// ──────────────────────────────────────────────────────────────────────────────
// CPI — sister M7 owns the body. M6 stubs to a named error so the registry
// is wholly populated; the executor will see this error and short-circuit.
// ──────────────────────────────────────────────────────────────────────────────

// ── CPI dispatch (Wave 6A) ────────────────────────────────────────────────────
//
// `solInvokeSignedC/Rust` reach into `InvokeContext.cpi_*` opaque hooks the
// V2 dispatcher stamps on before `vm.run`. The hooks carry the M6 syscall
// registry and the program resolver — neither fits in the 6-tuple SyscallFn
// ABI — so we type-erase through `*anyopaque` and reconstitute here.
//
// Lifetime: the V2 dispatcher owns the registry + resolver on its stack frame
// for the entire `vm.run`; the pointers are valid for the duration of the
// syscall.
//
// Null-hook fallback: pre-Wave-6A callers (and the M6 syscall test suite)
// never set the hooks — those paths still get `M6_CpiHandlerNotReady`, which
// preserves every existing test.

fn dispatchCpi(
    ic: *InvokeContext,
    abi: cpi.Abi,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
) SyscallError!u64 {
    // RULE #17 (2026-06-01, SESSION-6): distinguish the early null-hook return
    // from the masked handleSolInvokeSigned error below. The live PR-5p capture
    // showed the ATA `Create` CPI returning M6_CpiHandlerNotReady — but we can't
    // tell WHICH source without this. Logging-only, error-path-only, rate-limited.
    const mm_opaque = ic.mm orelse {
        const P = struct {
            var n: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
        };
        const cn = P.n.fetchAdd(1, .monotonic);
        if (cn < 32) std.log.warn("[V2-CPI-NULLHOOK n={d}] ic.mm is NULL (abi={s}) -> M6 early-return", .{ cn, @tagName(abi) });
        return error.M6_CpiHandlerNotReady;
    };
    const reg_opaque = ic.cpi_syscalls orelse {
        const P = struct {
            var n: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
        };
        const cn = P.n.fetchAdd(1, .monotonic);
        if (cn < 32) std.log.warn("[V2-CPI-NULLHOOK n={d}] ic.cpi_syscalls is NULL (abi={s}) -> M6 early-return", .{ cn, @tagName(abi) });
        return error.M6_CpiHandlerNotReady;
    };

    const mm: *memory.AlignedMemoryMap = @ptrCast(@alignCast(mm_opaque));
    const reg: *SyscallRegistry = @ptrCast(@alignCast(reg_opaque));

    // Optional resolver — null is legal when the CPI target is a builtin.
    const resolver: ?cpi.ProgramResolver = blk: {
        const ctx_opaque = ic.cpi_resolver_ctx orelse break :blk null;
        const resolve_opaque = ic.cpi_resolver_resolve orelse break :blk null;
        // `cpi.ProgramResolver.VTable.resolve` matches this typed shape;
        // the cast goes through `*const anyopaque` to keep invoke_ctx.zig
        // free of any cpi.zig import.
        const ResolveFn = *const fn (ctx: *anyopaque, pid: sysvar_cache_mod.Pubkey32) ?*const elf_mod.Executable;
        const resolve_fn: ResolveFn = @ptrCast(@alignCast(resolve_opaque));
        // Build a temporary VTable on the stack — its lifetime spans this
        // call only, which is fine: cpi.handleSolInvokeSigned does not
        // retain the VTable past return.
        const tmp_vtable = struct {
            // SAFETY: this static is module-private and only read through the
            // `*const VTable` pointer we hand below.
            var v: cpi.ProgramResolver.VTable = undefined;
        };
        tmp_vtable.v = .{ .resolve = resolve_fn };
        break :blk cpi.ProgramResolver{ .ctx = ctx_opaque, .vtable = &tmp_vtable.v };
    };

    return cpi.handleSolInvokeSigned(
        ic,
        abi,
        instruction_addr,
        account_infos_addr,
        account_infos_len,
        signers_seeds_addr,
        signers_seeds_len,
        mm,
        resolver,
        reg.asTrait(),
    ) catch |e| {
        // RULE #17 (2026-05-31): surface the REAL CpiError BEFORE the `else`
        // arm below masks it to M6_CpiHandlerNotReady. That masking hid the
        // CPI carrier (real ATA create via Rust-ABI sol_invoke_signed →
        // M4_RunFailed → dropped account, funder under-debited, tx err=0).
        // Rate-limited so live CPI errors never flood the log.
        const CpiErrProbe = struct {
            var n: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
        };
        const cn = CpiErrProbe.n.fetchAdd(1, .monotonic);
        if (cn < 64) std.log.warn(
            "[V2-CPI-DISPATCH-ERR n={d}] handleSolInvokeSigned(abi={s}) -> {s}",
            .{ cn, @tagName(abi), @errorName(e) },
        );
        return switch (e) {
            // CpiError variants → narrow SyscallError. The interpreter
            // trait-adapter folds SyscallError → InterpreterError.SyscallError,
            // so the distinct CPI sub-failure (M7_*) is observable in
            // [VBPF2-TRACE] while still mapping to agave's "Exit" at the VM
            // boundary.
            error.M7_OutOfMemory => error.M6_OutOfMemory,
            error.M7_OutOfCompute => error.M6_ConsumeOverflow,
            error.M7_TranslateFailed => error.M6_AccessViolation,
            error.M7_AbiMismatch => error.M6_AbiMismatch,
            // Hygiene fix (2026-07-03): a genuine M9 builtin-handler failure
            // (the CPI reached its target and the target itself failed) is
            // NOT the same condition as "the CPI handler was never wired" —
            // un-mask it to its own label so the two are distinguishable
            // wherever only the FINAL error name is logged downstream (e.g.
            // traitInvoke's [V2-SYSCALL-FAIL]). Same fold target
            // (InterpreterError.SyscallError) either way — no behavior or
            // consensus-outcome change, log/label fidelity only. See
            // M6_CpiBuiltinFailed's doc comment.
            error.M7_BuiltinFailed => error.M6_CpiBuiltinFailed,
            // Every OTHER CpiError (depth/PDA/account-shape/recursive-load
            // etc.) still folds to the pre-existing catch-all. Out of scope
            // for this hygiene pass — only the builtin-failure-vs-unwired
            // confusion the task named was addressed here.
            else => error.M6_CpiHandlerNotReady,
        };
    };
}

fn solInvokeSignedC(
    ic: *InvokeContext,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
) SyscallError!u64 {
    traceEntry("sol_invoke_signed_c", ic, instruction_addr, account_infos_addr, account_infos_len, signers_seeds_addr, signers_seeds_len);
    return dispatchCpi(ic, .c, instruction_addr, account_infos_addr, account_infos_len, signers_seeds_addr, signers_seeds_len);
}

fn solInvokeSignedRust(
    ic: *InvokeContext,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
) SyscallError!u64 {
    traceEntry("sol_invoke_signed_rust", ic, instruction_addr, account_infos_addr, account_infos_len, signers_seeds_addr, signers_seeds_len);
    return dispatchCpi(ic, .rust, instruction_addr, account_infos_addr, account_infos_len, signers_seeds_addr, signers_seeds_len);
}

// ──────────────────────────────────────────────────────────────────────────────
// Registry — concrete table + M4 trait adapter.
// ──────────────────────────────────────────────────────────────────────────────

pub const SyscallRegistry = struct {
    entries: []SyscallEntry,
    allocator: std.mem.Allocator,

    pub fn init(
        alloc: std.mem.Allocator,
        sbpf_version: anytype,
        feature_set: anytype,
    ) !SyscallRegistry {
        _ = sbpf_version; // version-gating dormant until SBPFv3 (see SIMD-STATUS-SWEEP).
        _ = feature_set; // feature-gated registration is a Wave 4 concern.

        // Build the canonical 43-entry list. @prov:syscall.module-map
        // (+sol_sha512 SIMD-0512, registered unconditionally / gated at invoke).
        const tbl = [_]struct { name: []const u8, f: SyscallFn, cu: u64 }{
            .{ .name = "abort",                           .f = abort_,                  .cu = 0 },
            .{ .name = "sol_panic_",                      .f = solPanic,                .cu = CuCost.syscall_base_cost },
            .{ .name = "sol_log_",                        .f = solLog,                  .cu = CuCost.syscall_base_cost },
            .{ .name = "sol_log_64_",                     .f = solLog64,                .cu = CuCost.log_64_units },
            .{ .name = "sol_log_pubkey",                  .f = solLogPubkey,            .cu = CuCost.log_pubkey_units },
            .{ .name = "sol_log_compute_units_",          .f = solLogComputeUnits,      .cu = CuCost.syscall_base_cost },
            .{ .name = "sol_create_program_address",      .f = solCreatePda,            .cu = CuCost.create_program_address_units },
            .{ .name = "sol_try_find_program_address",    .f = solTryFindPda,           .cu = CuCost.create_program_address_units },
            .{ .name = "sol_sha256",                      .f = solSha256,               .cu = CuCost.sha256_base_cost },
            .{ .name = "sol_keccak256",                   .f = solKeccak256,            .cu = CuCost.sha256_base_cost },
            .{ .name = "sol_secp256k1_recover",           .f = solSecp256k1Recover,     .cu = CuCost.secp256k1_recover_cost },
            .{ .name = "sol_blake3",                      .f = solBlake3,               .cu = CuCost.sha256_base_cost },
            .{ .name = "sol_sha512",                      .f = solSha512,               .cu = CuCost.sha256_base_cost }, // SIMD-0512 (gated at invoke)
            .{ .name = "sol_curve_validate_point",        .f = solCurveValidatePoint,   .cu = CuCost.curve25519_edwards_validate_point_cost },
            .{ .name = "sol_curve_group_op",              .f = solCurveGroupOp,         .cu = CuCost.curve25519_edwards_validate_point_cost },
            .{ .name = "sol_curve_multiscalar_mul",       .f = solCurveMsm,             .cu = CuCost.curve25519_edwards_validate_point_cost },
            .{ .name = "sol_curve_decompress",            .f = solCurveDecompress,      .cu = CuCost.curve25519_edwards_validate_point_cost },
            .{ .name = "sol_curve_pairing_map",           .f = solCurvePairingMap,      .cu = CuCost.curve25519_edwards_validate_point_cost },
            .{ .name = "sol_get_clock_sysvar",            .f = solGetClock,             .cu = CuCost.sysvar_base_cost },
            .{ .name = "sol_get_epoch_schedule_sysvar",   .f = solGetEpochSchedule,     .cu = CuCost.sysvar_base_cost },
            .{ .name = "sol_get_fees_sysvar",             .f = solGetFees,              .cu = CuCost.sysvar_base_cost },
            .{ .name = "sol_get_rent_sysvar",             .f = solGetRent,              .cu = CuCost.sysvar_base_cost },
            .{ .name = "sol_get_last_restart_slot",       .f = solGetLastRestartSlot,   .cu = CuCost.sysvar_base_cost },
            .{ .name = "sol_get_epoch_rewards_sysvar",    .f = solGetEpochRewards,      .cu = CuCost.sysvar_base_cost },
            .{ .name = "sol_memcpy_",                     .f = solMemcpy,               .cu = CuCost.mem_op_base_cost },
            .{ .name = "sol_memmove_",                    .f = solMemmove,              .cu = CuCost.mem_op_base_cost },
            .{ .name = "sol_memset_",                     .f = solMemset,               .cu = CuCost.mem_op_base_cost },
            .{ .name = "sol_memcmp_",                     .f = solMemcmp,               .cu = CuCost.mem_op_base_cost },
            .{ .name = "sol_get_processed_sibling_instruction", .f = solGetSibling,     .cu = CuCost.syscall_base_cost },
            .{ .name = "sol_get_stack_height",            .f = solGetStackHeight,       .cu = CuCost.syscall_base_cost },
            .{ .name = "sol_set_return_data",             .f = solSetReturnData,        .cu = CuCost.syscall_base_cost },
            .{ .name = "sol_get_return_data",             .f = solGetReturnData,        .cu = CuCost.syscall_base_cost },
            .{ .name = "sol_invoke_signed_c",             .f = solInvokeSignedC,        .cu = 0 },
            .{ .name = "sol_invoke_signed_rust",          .f = solInvokeSignedRust,     .cu = 0 },
            .{ .name = "sol_alloc_free_",                 .f = solAllocFree,            .cu = CuCost.syscall_base_cost },
            .{ .name = "sol_alt_bn128_group_op",          .f = solAltBn128GroupOp,      .cu = CuCost.alt_bn128_g1_addition_cost },
            .{ .name = "sol_big_mod_exp",                 .f = solBigModExp,            .cu = 0 }, // @prov:syscall.big-mod-exp
            .{ .name = "sol_poseidon",                    .f = solPoseidon,             .cu = CuCost.poseidon_cost_coefficient_c },
            .{ .name = "sol_remaining_compute_units",     .f = solRemainingComputeUnits, .cu = CuCost.get_remaining_compute_units_cost },
            .{ .name = "sol_alt_bn128_compression",       .f = solAltBn128Compress,     .cu = CuCost.alt_bn128_g1_addition_cost },
            .{ .name = "sol_get_sysvar",                  .f = solGetSysvar,            .cu = CuCost.sysvar_base_cost },
            .{ .name = "sol_get_epoch_stake",             .f = solGetEpochStake,        .cu = CuCost.sysvar_base_cost },
            .{ .name = "sol_log_data",                    .f = solLogData,              .cu = CuCost.syscall_base_cost },
        };

        var entries = try alloc.alloc(SyscallEntry, tbl.len);
        for (tbl, 0..) |t, i| {
            entries[i] = .{
                .name = t.name,
                .hash = nameHash(t.name),
                .fn_ = t.f,
                .cu_cost = t.cu,
                .sbpf_versions = SbpfVersionMask.ALL,
            };
        }
        return .{ .entries = entries, .allocator = alloc };
    }

    pub fn deinit(self: *SyscallRegistry) void {
        self.allocator.free(self.entries);
        self.entries = &.{};
    }

    pub fn count(self: *const SyscallRegistry) usize {
        return self.entries.len;
    }

    pub fn lookup(self: *const SyscallRegistry, hash: u32) ?*const SyscallEntry {
        for (self.entries) |*e| {
            if (e.hash == hash) return e;
        }
        return null;
    }

    pub fn invoke(
        self: *const SyscallRegistry,
        ctx: *InvokeContext,
        hash: u32,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
    ) SyscallError!u64 {
        const entry = self.lookup(hash) orelse return error.M6_NotRegistered;
        return entry.fn_(ctx, r1, r2, r3, r4, r5);
    }

    /// Self-test: check every entry's hash matches Murmur3(name) and no
    /// duplicates. Used at registry construction time and in tests.
    pub fn selfTest(self: *const SyscallRegistry) struct { registered: usize, missing: []const []const u8 } {
        // We don't dynamically allocate "missing" for Stage A.
        for (self.entries) |e| {
            std.debug.assert(e.hash == nameHash(e.name));
        }
        return .{ .registered = self.entries.len, .missing = &.{} };
    }

    // ── M4 trait adapter ────────────────────────────────────────────────
    //
    // Returns a `interpreter.SyscallRegistry` (the vtable trait) backed by
    // this concrete registry. The vtable's `lookup` returns the entry index
    // as `Slot`, and `invoke` dispatches by index. SyscallError is mapped
    // to InterpreterError via `mapErr` (any structured failure becomes
    // `InterpreterError.SyscallError` — agave's "Exit" — preserving the
    // error.M6_ProgramAbort → InterpreterError.SyscallError chain).
    pub fn asTrait(self: *SyscallRegistry) interpreter.SyscallRegistry {
        return .{
            .ctx = @ptrCast(self),
            .vtable = &trait_vtable,
        };
    }
};

const trait_vtable: interpreter.SyscallRegistry.VTable = .{
    .lookup = traitLookup,
    .invoke = traitInvoke,
    .consume = traitConsume,
    .remaining = traitRemaining,
};

/// CU-METER unification (2026-07-05, carrier 419786142): rbpf
/// ContextObject::consume — saturating settle of owed VM insns into the
/// shared InvokeContext CU meter (the same meter every syscall's
/// consumeCompute draws from). Exhaustion is NOT an error here; it surfaces
/// at the interpreter's next `due >= meter` check, matching canonical order.
fn traitConsume(invoke_ctx_opaque: *anyopaque, n: u64) void {
    const ic: *InvokeContext = @ptrCast(@alignCast(invoke_ctx_opaque));
    ic.consumeCompute(n) catch {};
}

/// rbpf ContextObject::get_remaining.
fn traitRemaining(invoke_ctx_opaque: *anyopaque) u64 {
    const ic: *InvokeContext = @ptrCast(@alignCast(invoke_ctx_opaque));
    return ic.computeRemaining();
}

fn traitLookup(ctx: *anyopaque, hash: u32) ?interpreter.SyscallRegistry.Slot {
    const reg: *SyscallRegistry = @ptrCast(@alignCast(ctx));
    for (reg.entries, 0..) |e, i| {
        if (e.hash == hash) return @intCast(i);
    }
    return null;
}

fn traitInvoke(
    ctx: *anyopaque,
    invoke_ctx_opaque: *anyopaque,
    slot: interpreter.SyscallRegistry.Slot,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r5: u64,
) interpreter.InterpreterError!u64 {
    const reg: *SyscallRegistry = @ptrCast(@alignCast(ctx));
    if (slot >= reg.entries.len) return error.SyscallError;
    const ic: *InvokeContext = @ptrCast(@alignCast(invoke_ctx_opaque));
    const entry = &reg.entries[slot];
    const result: u64 = entry.fn_(ic, r1, r2, r3, r4, r5) catch |e| {
        return switch (e) {
            // Compute-meter exhaustion has its own InterpreterError variant if
            // present; otherwise fold into SyscallError. We log the originating
            // syscall name + concrete error before folding so live shadow
            // and fixture replay both surface enough info to localize the bug
            // (V2's port can fail differently than agave's syscall — e.g.
            // sol_log_pubkey could AccessError, or sol_invoke_signed_c could
            // miss a feature gate). Without this log line every failure
            // collapses to opaque InterpreterError.SyscallError.
            error.M6_ConsumeOverflow => error.ExceededMaxInstructions,
            else => blk: {
                std.log.err(
                    "[V2-SYSCALL-FAIL] name={s} err={s} r1=0x{x} r2=0x{x} r3=0x{x} r4=0x{x} r5=0x{x}",
                    .{ entry.name, @errorName(e), r1, r2, r3, r4, r5 },
                );
                break :blk error.SyscallError;
            },
        };
    };
    return result;
}

// Tests live in syscalls_test.zig.
