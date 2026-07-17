//! BN254 (alt_bn128) group ops + compression + Poseidon — pure-Zig leaf.
//!
//! Backend dispatch (comptime):
//!   • `.pure_zig` → routes the alt_bn128/poseidon leaf through Vexor's own
//!                   pure-Zig implementation (bn254/root.zig + bn254/poseidon.zig).
//!                   Gated byte-for-byte vs the published solana-bn254 v3.2.1 /
//!                   go-ethereum / py_ecc vectors by src/vex_crypto/bn254/kat.zig.
//!   • `.unported`→ no implementation linked. The syscall layer checks
//!                  `active_backend == .unported` ITSELF and surfaces the
//!                  tx-aborting RequiresBn254ImplPort error BEFORE calling any
//!                  wrapper here (instant in-binary revert, RULE #13). The
//!                  comptime-known check elides the wrapper bodies so nothing is
//!                  referenced when unported.
//!
//! The 3 syscall bodies (`solAltBn128GroupOp`, `solAltBn128Compress`,
//! `solPoseidon` in `src/vex_bpf2/syscalls.zig`) own ALL the Vexor-side glue
//! (CU consume, memory translation, SIMD-0284/0302/0359 feature gates, the
//! abort-vs-`return 1` error mapping). This module is ONLY the crypto leaf:
//! it takes already-translated host slices and returns the verdict.
//!
//! Input-length validation is done INSIDE the pure-Zig leaf (e.g. g1_add: in_sz>128
//! → soft-fail). Group ops forward the raw input + len. Compression funcs take
//! FIXED-size buffers (no in_sz arg), so the syscall layer size-checks BEFORE calling.
//!
//! @prov:crypto.bn254

const std = @import("std");

// Pure-Zig BN254 leaf. Gated byte-for-byte vs published EIP-197 / solana-bn254
// vectors by src/vex_crypto/bn254/kat.zig (`zig build test-vex-bn254`).
const pure = @import("bn254/root.zig");
const pure_poseidon = @import("bn254/poseidon.zig");

// `.unported` is retained in the enum because the syscall layer branches on it
// (`bn254.active_backend == .unported`), but the alt_bn128/poseidon leaf is now
// routed unconditionally through the pure-Zig implementation.
pub const Backend = enum { unported, pure_zig };

pub const active_backend: Backend = .pure_zig;

// The syscall layer (vex_bpf2/syscalls.zig) checks `active_backend == .unported`
// itself and returns the tx-aborting `M6_AltBn128RequiresBn254ImplPort` /
// `M6_PoseidonRequiresBn254ImplPort` error BEFORE calling any wrapper here — so
// these wrappers are only ever reached with `.pure_zig`, and return a plain
// `bool` (true = out written; false = soft-failure → caller `return 1`).

// ── Group ops ─────────────────────────────────────────────────────────────────
// out/in are already-translated host slices. `big_endian` is the FD convention
// (1=BE, 0=LE); the syscall layer derives it from `(op & 0x80) == 0`.
// Returns `true` on success (out written), `false` on soft-failure
// (not-on-curve / subgroup / bad length) → syscall maps to `return 1`.

pub fn g1Add(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.g1Add(out, in, big_endian);
    unreachable; // .unported is guarded by the syscall layer before reaching here
}

pub fn g1Mul(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.g1Mul(out, in, big_endian);
    unreachable;
}

pub fn g2Add(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.g2Add(out, in, big_endian);
    unreachable;
}

pub fn g2Mul(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.g2Mul(out, in, big_endian);
    unreachable;
}

pub fn pairing(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.pairingIsOne(out, in, big_endian);
    unreachable;
}

// ── Compression ─────────────────────────────────────────────────────────────
// Fixed-size buffers. The syscall layer MUST have already validated
// `in.len`/`out.len` to the exact sizes below.
// Returns true (out written) / false (soft `return 1`).

pub fn g1Compress(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.g1Compress(out, in, big_endian);
    unreachable;
}

pub fn g1Decompress(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.g1Decompress(out, in, big_endian);
    unreachable;
}

pub fn g2Compress(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.g2Compress(out, in, big_endian);
    unreachable;
}

pub fn g2Decompress(out: []u8, in: []const u8, big_endian: bool) bool {
    if (active_backend == .pure_zig) return pure.g2Decompress(out, in, big_endian);
    unreachable;
}

// ── Poseidon ─────────────────────────────────────────────────────────────────
// `inputs` are already-translated host slices (one per VmSlice). `big_endian`
// is FD convention (1=BE, 0=LE) — the syscall layer inverts Agave's
// (0=BE, 1=LE) endian arg. `enforce_padding` from SIMD-0359 feature gate.
//
// Returns true (32-byte `out` written) / false (soft `return 1`) when:
//   - a slice fails append (data ≥ modulus; sz>32; enforce && sz!=32; empty slice)
//   - fini fails (cnt==0, i.e. vals_len==0 → matches Agave hashv([])→Ok(1))
pub fn poseidonHash(
    out: []u8,
    inputs: []const []const u8,
    big_endian: bool,
    enforce_padding: bool,
) bool {
    if (active_backend == .pure_zig) return pure_poseidon.poseidonHash(out, inputs, big_endian, enforce_padding);
    unreachable;
}
