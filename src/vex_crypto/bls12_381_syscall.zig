//! BLS12-381 elliptic-curve syscall ops (SIMD-0388) — `sol_curve_*` BLS arms.
//!
//! CANONICAL SOURCE: `solana-bls12-381-syscall` v0.1.0 (Agave 4.1.0-rc.1's pin,
//! Cargo.toml:370 `solana-bls12-381-syscall = "0.1.0"`). That crate wraps
//! `blstrs` 0.7 (→ `blst` 0.3.x C). Vexor links the SAME vendored blst C
//! (vendor/blst, attached to the `bls_pop` module + the KAT target), so the
//! same C arithmetic computes both verdicts → byte-parity guarantee.
//!
//! This file is the leaf-crypto layer: it takes already-translated host byte
//! buffers + an endianness flag and returns the canonical verdict/bytes. The
//! four syscall bodies (`solCurveValidatePoint`, `solCurveGroupOp`,
//! `solCurveDecompress`, `solCurvePairingMap` in vex_bpf2/syscalls.zig) own ALL
//! the Vexor-side glue: CU consume, memory translation, the
//! `enable_bls12_381_syscall` feature gate (threaded onto InvokeContext like
//! `alt_bn128_g2_active`), and the abort-vs-`return 1` error mapping.
//!
//! ── blstrs → blst MAPPING (the crate's exact check sequence) ───────────────
//!   PodG1Point.to_affine_subgroup_unchecked (encoding.rs:50-64):
//!     LE → swap_fq_endianness; reject `bytes[0] & 0xa0 != 0`;
//!     G1Affine::from_uncompressed_unchecked = field + on-curve (NO subgroup)
//!       ≡ blst_p1_deserialize (validates canonical field + on-curve).
//!   PodG1Point.to_affine adds is_torsion_free ≡ blst_p1_affine_in_g1.
//!   to_uncompressed (Zcash BE, 96 bytes) ≡ blst_p1_affine_serialize.
//!   G2 mirrors with the extra swap_g2_c0_c1 (c0/c1 ordering) for LE.
//!   PodScalar.to_scalar: BE/LE bytes, None if >= r ≡ blst_scalar_fr_check.
//!   add/sub: G?Projective::from(affine) +/- affine (to_affine_subgroup_unchecked).
//!   mul: full to_affine (incl subgroup) then projective * scalar.
//!   pairing: to_affine (full) both sides, multi_miller_loop + final_exp,
//!     serialize_gt (transmute fp12 → blst_lendian_from_fp per coeff; BE reverses).
//!
//! Refs:
//!   - Agave rc.1 syscalls/src/lib.rs:978-1206 (validate/decompress),
//!     :1209-1679 (group_op), :1828-1901 (pairing_map); curve ids :290-301.
//!   - solana-bls12-381-syscall-0.1.0 src/{encoding,validation,decompression,
//!     addition,subtraction,multiplication,pairing}.rs.
//!   - vendor/blst/bindings/blst.h.

const std = @import("std");

// ─────────────────────────────────────────────────────────────────────────────
// blst extern ABI (vendor/blst/bindings/blst.h). Structs mirror bls12_381.zig
// (the bls_pop module) byte-for-byte; the C is linked once via that module in
// the final exe, and attached directly to the standalone KAT target.
// ─────────────────────────────────────────────────────────────────────────────

const limb_t = u64; // x86_64: 6 limbs per fp

pub const blst_fp = extern struct { l: [6]limb_t };
pub const blst_fp2 = extern struct { fp: [2]blst_fp };
pub const blst_fp6 = extern struct { fp2: [3]blst_fp2 };
pub const blst_fp12 = extern struct { fp6: [2]blst_fp6 };
pub const blst_p1 = extern struct { x: blst_fp, y: blst_fp, z: blst_fp };
pub const blst_p1_affine = extern struct { x: blst_fp, y: blst_fp };
pub const blst_p2 = extern struct { x: blst_fp2, y: blst_fp2, z: blst_fp2 };
pub const blst_p2_affine = extern struct { x: blst_fp2, y: blst_fp2 };
pub const blst_scalar = extern struct { b: [32]u8 };

const BLST_SUCCESS: c_int = 0;

// G1
extern fn blst_p1_deserialize(out: *blst_p1_affine, in: *const [96]u8) c_int;
extern fn blst_p1_affine_serialize(out: *[96]u8, in: *const blst_p1_affine) void;
extern fn blst_p1_affine_in_g1(p: *const blst_p1_affine) bool;
extern fn blst_p1_affine_is_inf(p: *const blst_p1_affine) bool;
extern fn blst_p1_from_affine(out: *blst_p1, in: *const blst_p1_affine) void;
extern fn blst_p1_to_affine(out: *blst_p1_affine, in: *const blst_p1) void;
extern fn blst_p1_add_or_double(out: *blst_p1, a: *const blst_p1, b: *const blst_p1) void;
extern fn blst_p1_cneg(p: *blst_p1, cbit: bool) void;
extern fn blst_p1_mult(out: *blst_p1, p: *const blst_p1, scalar: [*]const u8, nbits: usize) void;

// G2
extern fn blst_p2_deserialize(out: *blst_p2_affine, in: *const [192]u8) c_int;
extern fn blst_p2_affine_serialize(out: *[192]u8, in: *const blst_p2_affine) void;
extern fn blst_p2_affine_in_g2(p: *const blst_p2_affine) bool;
extern fn blst_p2_affine_is_inf(p: *const blst_p2_affine) bool;
extern fn blst_p2_from_affine(out: *blst_p2, in: *const blst_p2_affine) void;
extern fn blst_p2_to_affine(out: *blst_p2_affine, in: *const blst_p2) void;
extern fn blst_p2_add_or_double(out: *blst_p2, a: *const blst_p2, b: *const blst_p2) void;
extern fn blst_p2_cneg(p: *blst_p2, cbit: bool) void;
extern fn blst_p2_mult(out: *blst_p2, p: *const blst_p2, scalar: [*]const u8, nbits: usize) void;

// Scalar. NOTE: blst_scalar_from_{be,le}_bytes reject all-zero input (return
// false), which does NOT match blstrs Scalar::from_bytes_*: 0 is a CANONICAL
// scalar (0 < r). So we load the raw 32-byte representation via
// blst_scalar_from_{bendian,lendian} (no rejection) and validate canonicality
// with blst_scalar_fr_check (< r, accepts 0) — the exact blstrs check sequence.
extern fn blst_scalar_from_bendian(out: *blst_scalar, in: *const [32]u8) void;
extern fn blst_scalar_from_lendian(out: *blst_scalar, in: *const [32]u8) void;
extern fn blst_scalar_fr_check(a: *const blst_scalar) bool;

// Pairing
extern fn blst_miller_loop_n(
    ret: *blst_fp12,
    Qs: [*]const *const blst_p2_affine,
    Ps: [*]const *const blst_p1_affine,
    n: usize,
) void;
extern fn blst_final_exp(ret: *blst_fp12, f: *const blst_fp12) void;
extern fn blst_lendian_from_fp(ret: *[48]u8, a: *const blst_fp) void;
extern fn blst_fp12_one() *const blst_fp12;

// ─────────────────────────────────────────────────────────────────────────────
// Encoding constants + endianness helpers (encoding.rs)
// ─────────────────────────────────────────────────────────────────────────────

const FQ_SIZE: usize = 48;
const FQ2_SIZE: usize = 2 * FQ_SIZE; // 96
pub const GT_SIZE: usize = 12 * FQ_SIZE; // 576
pub const G1_UNCOMPRESSED_SIZE: usize = 2 * FQ_SIZE; // 96
pub const G1_COMPRESSED_SIZE: usize = FQ_SIZE; // 48
pub const G2_UNCOMPRESSED_SIZE: usize = 2 * FQ2_SIZE; // 192
pub const G2_COMPRESSED_SIZE: usize = FQ2_SIZE; // 96
pub const SCALAR_SIZE: usize = 32;

pub const Endianness = enum { be, le };

/// encoding.rs:164 — reverse each 48-byte Fq chunk in place.
fn swapFqEndianness(bytes: []u8) void {
    var i: usize = 0;
    while (i + FQ_SIZE <= bytes.len) : (i += FQ_SIZE) {
        std.mem.reverse(u8, bytes[i .. i + FQ_SIZE]);
    }
}

/// encoding.rs:178 — swap the two 48-byte halves of each 96-byte Fq2 chunk.
fn swapG2C0C1(bytes: []u8) void {
    var i: usize = 0;
    while (i + FQ2_SIZE <= bytes.len) : (i += FQ2_SIZE) {
        var tmp: [FQ_SIZE]u8 = undefined;
        @memcpy(&tmp, bytes[i .. i + FQ_SIZE]);
        @memcpy(bytes[i .. i + FQ_SIZE], bytes[i + FQ_SIZE .. i + FQ2_SIZE]);
        @memcpy(bytes[i + FQ_SIZE .. i + FQ2_SIZE], &tmp);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Affine decode (the blstrs `to_affine*` equivalents)
// ─────────────────────────────────────────────────────────────────────────────

/// PodG1Point::to_affine_subgroup_unchecked (encoding.rs:50-64): field +
/// on-curve, NO subgroup. `input` is the raw 96-byte uncompressed point in the
/// caller's endianness; we copy + normalize to Zcash BE for blst.
fn g1ToAffineUnchecked(input: *const [96]u8, endianness: Endianness) ?blst_p1_affine {
    var bytes: [96]u8 = input.*;
    if (endianness == .le) swapFqEndianness(&bytes);
    // reject if the compressed (0x80) or sort/parity (0x20) flag bit is set
    if (bytes[0] & 0xa0 != 0) return null;
    var p: blst_p1_affine = undefined;
    if (blst_p1_deserialize(&p, &bytes) != BLST_SUCCESS) return null;
    return p;
}

/// PodG1Point::to_affine — adds the subgroup (is_torsion_free) check.
fn g1ToAffine(input: *const [96]u8, endianness: Endianness) ?blst_p1_affine {
    const p = g1ToAffineUnchecked(input, endianness) orelse return null;
    if (!blst_p1_affine_in_g1(&p)) return null;
    return p;
}

/// PodG2Point::to_affine_subgroup_unchecked (encoding.rs:95-110).
fn g2ToAffineUnchecked(input: *const [192]u8, endianness: Endianness) ?blst_p2_affine {
    var bytes: [192]u8 = input.*;
    if (endianness == .le) {
        swapFqEndianness(&bytes);
        swapG2C0C1(&bytes);
    }
    if (bytes[0] & 0xa0 != 0) return null;
    var p: blst_p2_affine = undefined;
    if (blst_p2_deserialize(&p, &bytes) != BLST_SUCCESS) return null;
    return p;
}

fn g2ToAffine(input: *const [192]u8, endianness: Endianness) ?blst_p2_affine {
    const p = g2ToAffineUnchecked(input, endianness) orelse return null;
    if (!blst_p2_affine_in_g2(&p)) return null;
    return p;
}

/// PodScalar::to_scalar (encoding.rs:130-137) — None if >= r (no reduction).
fn toScalar(input: *const [32]u8, endianness: Endianness) ?blst_scalar {
    var s: blst_scalar = undefined;
    switch (endianness) {
        .be => blst_scalar_from_bendian(&s, input),
        .le => blst_scalar_from_lendian(&s, input),
    }
    if (!blst_scalar_fr_check(&s)) return null; // reject non-canonical (>= r); 0 OK
    return s;
}

// ── affine → output bytes (to_uncompressed = Zcash BE; then re-apply LE) ──────

fn g1Serialize(p: *const blst_p1_affine, endianness: Endianness, out: *[96]u8) void {
    blst_p1_affine_serialize(out, p); // Zcash BE
    if (endianness == .le) swapFqEndianness(out);
}

fn g2Serialize(p: *const blst_p2_affine, endianness: Endianness, out: *[192]u8) void {
    blst_p2_affine_serialize(out, p); // Zcash BE (c1, c0 order)
    if (endianness == .le) {
        swapG2C0C1(out);
        swapFqEndianness(out);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public crypto ops — verdicts/bytes only. Caller owns CU + memory + gating.
// ─────────────────────────────────────────────────────────────────────────────

/// validation.rs — `to_affine(...).is_some()`. true=on-curve+in-subgroup.
pub fn g1Validate(input: *const [96]u8, endianness: Endianness) bool {
    return g1ToAffine(input, endianness) != null;
}

pub fn g2Validate(input: *const [192]u8, endianness: Endianness) bool {
    return g2ToAffine(input, endianness) != null;
}

/// decompression.rs:13-43. `compressed` is 48 bytes; on success writes 96-byte
/// uncompressed point to `out` and returns true. Field+on-curve via blst's
/// compressed deserialize, then subgroup (is_torsion_free).
pub fn g1Decompress(compressed: *const [48]u8, endianness: Endianness, out: *[96]u8) bool {
    var bytes: [48]u8 = compressed.*;
    if (endianness == .le) swapFqEndianness(&bytes);
    var p: blst_p1_affine = undefined;
    if (blst_p1_uncompress(&p, &bytes) != BLST_SUCCESS) return false; // field + on-curve
    if (!blst_p1_affine_in_g1(&p)) return false; // subgroup
    g1Serialize(&p, endianness, out);
    return true;
}

pub fn g2Decompress(compressed: *const [96]u8, endianness: Endianness, out: *[192]u8) bool {
    var bytes: [96]u8 = compressed.*;
    if (endianness == .le) {
        swapFqEndianness(&bytes);
        swapG2C0C1(&bytes);
    }
    var p: blst_p2_affine = undefined;
    if (blst_p2_uncompress(&p, &bytes) != BLST_SUCCESS) return false;
    if (!blst_p2_affine_in_g2(&p)) return false;
    g2Serialize(&p, endianness, out);
    return true;
}

extern fn blst_p1_uncompress(out: *blst_p1_affine, in: *const [48]u8) c_int;
extern fn blst_p2_uncompress(out: *blst_p2_affine, in: *const [96]u8) c_int;

/// addition.rs:11-33. add/sub use the *unchecked* affine decode (no subgroup).
pub fn g1Add(left: *const [96]u8, right: *const [96]u8, endianness: Endianness, out: *[96]u8) bool {
    const a = g1ToAffineUnchecked(left, endianness) orelse return false;
    const b = g1ToAffineUnchecked(right, endianness) orelse return false;
    var ap: blst_p1 = undefined;
    blst_p1_from_affine(&ap, &a);
    var bp: blst_p1 = undefined;
    blst_p1_from_affine(&bp, &b);
    var sum: blst_p1 = undefined;
    blst_p1_add_or_double(&sum, &ap, &bp);
    var res_aff: blst_p1_affine = undefined;
    blst_p1_to_affine(&res_aff, &sum);
    g1Serialize(&res_aff, endianness, out);
    return true;
}

/// subtraction.rs — `P1 + (-P2)`.
pub fn g1Sub(left: *const [96]u8, right: *const [96]u8, endianness: Endianness, out: *[96]u8) bool {
    const a = g1ToAffineUnchecked(left, endianness) orelse return false;
    const b = g1ToAffineUnchecked(right, endianness) orelse return false;
    var ap: blst_p1 = undefined;
    blst_p1_from_affine(&ap, &a);
    var bp: blst_p1 = undefined;
    blst_p1_from_affine(&bp, &b);
    blst_p1_cneg(&bp, true); // negate
    var sum: blst_p1 = undefined;
    blst_p1_add_or_double(&sum, &ap, &bp);
    var res_aff: blst_p1_affine = undefined;
    blst_p1_to_affine(&res_aff, &sum);
    g1Serialize(&res_aff, endianness, out);
    return true;
}

/// multiplication.rs:11-31 — full to_affine (incl subgroup), then * scalar.
pub fn g1Mul(point: *const [96]u8, scalar: *const [32]u8, endianness: Endianness, out: *[96]u8) bool {
    const p = g1ToAffine(point, endianness) orelse return false;
    const s = toScalar(scalar, endianness) orelse return false;
    var pp: blst_p1 = undefined;
    blst_p1_from_affine(&pp, &p);
    var res: blst_p1 = undefined;
    blst_p1_mult(&res, &pp, &s.b, 255); // r < 2^255
    var res_aff: blst_p1_affine = undefined;
    blst_p1_to_affine(&res_aff, &res);
    g1Serialize(&res_aff, endianness, out);
    return true;
}

pub fn g2Add(left: *const [192]u8, right: *const [192]u8, endianness: Endianness, out: *[192]u8) bool {
    const a = g2ToAffineUnchecked(left, endianness) orelse return false;
    const b = g2ToAffineUnchecked(right, endianness) orelse return false;
    var ap: blst_p2 = undefined;
    blst_p2_from_affine(&ap, &a);
    var bp: blst_p2 = undefined;
    blst_p2_from_affine(&bp, &b);
    var sum: blst_p2 = undefined;
    blst_p2_add_or_double(&sum, &ap, &bp);
    var res_aff: blst_p2_affine = undefined;
    blst_p2_to_affine(&res_aff, &sum);
    g2Serialize(&res_aff, endianness, out);
    return true;
}

pub fn g2Sub(left: *const [192]u8, right: *const [192]u8, endianness: Endianness, out: *[192]u8) bool {
    const a = g2ToAffineUnchecked(left, endianness) orelse return false;
    const b = g2ToAffineUnchecked(right, endianness) orelse return false;
    var ap: blst_p2 = undefined;
    blst_p2_from_affine(&ap, &a);
    var bp: blst_p2 = undefined;
    blst_p2_from_affine(&bp, &b);
    blst_p2_cneg(&bp, true);
    var sum: blst_p2 = undefined;
    blst_p2_add_or_double(&sum, &ap, &bp);
    var res_aff: blst_p2_affine = undefined;
    blst_p2_to_affine(&res_aff, &sum);
    g2Serialize(&res_aff, endianness, out);
    return true;
}

pub fn g2Mul(point: *const [192]u8, scalar: *const [32]u8, endianness: Endianness, out: *[192]u8) bool {
    const p = g2ToAffine(point, endianness) orelse return false;
    const s = toScalar(scalar, endianness) orelse return false;
    var pp: blst_p2 = undefined;
    blst_p2_from_affine(&pp, &p);
    var res: blst_p2 = undefined;
    blst_p2_mult(&res, &pp, &s.b, 255);
    var res_aff: blst_p2_affine = undefined;
    blst_p2_to_affine(&res_aff, &res);
    g2Serialize(&res_aff, endianness, out);
    return true;
}

pub const MAX_PAIRING_LENGTH: usize = 8; // pairing.rs:14

/// pairing.rs:20-56. `g1_bytes`/`g2_bytes` are num_pairs contiguous 96/192-byte
/// points; writes the 576-byte Gt to `out`. num_pairs==0 → identity Gt.
/// Returns false on any decode failure or length>8 (caller → `return 1`).
pub fn pairingMap(
    g1_bytes: []const u8,
    g2_bytes: []const u8,
    num_pairs: usize,
    endianness: Endianness,
    out: *[GT_SIZE]u8,
) bool {
    if (num_pairs > MAX_PAIRING_LENGTH) return false;
    if (g1_bytes.len != num_pairs * G1_UNCOMPRESSED_SIZE) return false;
    if (g2_bytes.len != num_pairs * G2_UNCOMPRESSED_SIZE) return false;

    if (num_pairs == 0) {
        serializeGt(blst_fp12_one(), endianness, out);
        return true;
    }

    var g1_affines: [MAX_PAIRING_LENGTH]blst_p1_affine = undefined;
    var g2_affines: [MAX_PAIRING_LENGTH]blst_p2_affine = undefined;
    var ps: [MAX_PAIRING_LENGTH]*const blst_p1_affine = undefined;
    var qs: [MAX_PAIRING_LENGTH]*const blst_p2_affine = undefined;

    // n_eff/ps/qs below only include pairs where BOTH operands decoded (any
    // decode failure on either side still aborts the whole call, matching
    // pairing.rs's `.ok_or(...)?` per-point — decode success/failure is
    // unrelated to infinity-filtering, checked in this same pass).
    var n_eff: usize = 0;
    var i: usize = 0;
    while (i < num_pairs) : (i += 1) {
        const g1_pt: *const [96]u8 = @ptrCast(g1_bytes[i * 96 .. i * 96 + 96].ptr);
        const g2_pt: *const [192]u8 = @ptrCast(g2_bytes[i * 192 .. i * 192 + 192].ptr);
        const g1_aff = g1ToAffine(g1_pt, endianness) orelse return false;
        const g2_aff = g2ToAffine(g2_pt, endianness) orelse return false;

        // blst_miller_loop_n (unlike the single-pair blst_miller_loop, which
        // wraps an internal helper that special-cases an all-zero affine
        // operand) does NOT special-case the point at infinity -- its affine
        // (0,0) sentinel isn't a real curve point, so feeding it straight
        // into the Miller loop's line-evaluation arithmetic propagates zeros
        // through the accumulated product and yields the ZERO fp12 element
        // (not the multiplicative identity `1`) after final exponentiation.
        // Mathematically, e(P, O) = e(O, Q) = 1 (the pairing of any point
        // with the identity is the Gt identity) -- so a pair with either
        // operand at infinity contributes NOTHING to the product and is
        // correctly dropped before the Miller loop, exactly like Agave's own
        // blstrs-backed pairing (pairing.rs's `multi_miller_loop` receives
        // blstrs `G1Affine`/`G2Affine`, whose `MillerLoopResult` combinator
        // is defined via the same "identity contributes nothing" group law).
        if (blst_p1_affine_is_inf(&g1_aff) or blst_p2_affine_is_inf(&g2_aff)) continue;

        g1_affines[n_eff] = g1_aff;
        g2_affines[n_eff] = g2_aff;
        ps[n_eff] = &g1_affines[n_eff];
        qs[n_eff] = &g2_affines[n_eff];
        n_eff += 1;
    }

    if (n_eff == 0) {
        serializeGt(blst_fp12_one(), endianness, out);
        return true;
    }

    var miller: blst_fp12 = undefined;
    blst_miller_loop_n(&miller, &qs, &ps, n_eff);
    var gt: blst_fp12 = undefined;
    blst_final_exp(&gt, &miller);
    serializeGt(&gt, endianness, out);
    return true;
}

/// encoding.rs:198-233 serialize_gt. Iterate the fp12 = [fp6;2], each fp6 =
/// [fp2;3], each fp2 = [fp;2] (c0 then c1), emit blst_lendian_from_fp per coeff
/// (LE memory order). For BE, reverse the whole 576-byte array (flips coeff
/// order c0..c11 → c11..c0 AND flips each coeff's bytes LE→BE simultaneously).
fn serializeGt(gt: *const blst_fp12, endianness: Endianness, out: *[GT_SIZE]u8) void {
    var off: usize = 0;
    for (gt.fp6) |fp6| {
        for (fp6.fp2) |fp2| {
            const c0_chunk: *[48]u8 = @ptrCast(out[off .. off + 48].ptr);
            blst_lendian_from_fp(c0_chunk, &fp2.fp[0]);
            off += FQ_SIZE;
            const c1_chunk: *[48]u8 = @ptrCast(out[off .. off + 48].ptr);
            blst_lendian_from_fp(c1_chunk, &fp2.fp[1]);
            off += FQ_SIZE;
        }
    }
    if (endianness == .be) std.mem.reverse(u8, out);
}
