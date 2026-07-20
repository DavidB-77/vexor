//! Pure-Zig port of the ARM optimized-routines double-double pow(f64,f64)
//! algorithm, FMA variant (__FP_FAST_FMA branches — the path taken on any
//! CPU with usable FMA+AVX2, true for znver4, the build target here).
//! @prov:math.pow
//!
//! PROVENANCE (re-sourced 2026-07-15, see PROVENANCE.md + POW-RESOURCE-
//! PROGRESS.log for the full verification record): this is the ARM Limited
//! algorithm from ARM-software/optimized-routines, `math/pow.c` +
//! `math/pow_log_data.c` + `math/exp_data.c`, commit
//! a6230320c149a8e1ae790433fe0828e6060c53fa ("Improve pow implementation",
//! 2018-06-21, author Szabolcs Nagy <szabolcs.nagy@arm.com>) — file headers
//! there read "Copyright (c) 2018, Arm Limited. SPDX-License-Identifier:
//! Apache-2.0". The same author separately contributed the identical
//! algorithm+tables to glibc (glibc commit 424c4f60, 2018-06-13,
//! sysdeps/ieee754/dbl-64/{e_pow.c, e_pow_log_data.c, e_exp_data.c}, shipped
//! in glibc 2.29 under LGPL 2.1+/FSF) — glibc redistributes ARM's own
//! Apache-2.0 work, it does not originate it. Verified programmatically:
//! every table/polynomial constant in zpow_tables.zig (all 396 hex-float
//! values incl. LOG_TAB's 128 invc/logc/logctail entries and the scaled A[]
//! poly, plus all 256 EXP_TAB u64 words) is byte-identical to ARM's a6230320
//! source, and byte-identical to glibc 2.29's copy. ARM's current `master`
//! has since diverged (parameterized table sizes/poly orders) — a6230320 is
//! the frozen, matching commit, not master.
//!
//! TOINT_INTRINSICS=0, WANT_ROUNDING=1, HIGH_ORDER_BIT_IS_SET_FOR_SNAN=0
//! (generic, non-MIPS/x86_64 config) apply, matching both ARM's and glibc's
//! non-x86_64-override build of this algorithm.
//!
//! math_err.c-equivalent error-case return values (mathUflow/mathOflow/
//! mathDivzero/mathInvalid below) are ported the same way from the
//! byte-identical ARM/glibc source.
//!
//! CRITICAL — this is NOT just a transliteration of e_pow.c's C operator
//! structure. glibc's own Makefiles do not pass -ffp-contract=off for
//! e_pow.c/e_pow_log_data.c/e_exp_data.c (only branred.c/e_sqrt.c get that,
//! via config-cflags-nofma), so the actual compiled glibc binary is built
//! under GCC's *default* -ffp-contract=fast. That auto-fuses every a*b term
//! that feeds directly into a following +/- within the same C statement —
//! including OUTSIDE the source's explicit __FP_FAST_FMA #ifdef branches —
//! wherever the product has no other use forcing it to be materialized
//! separately (if a product is reused, GCC keeps it as one materialized
//! plain multiply and does NOT fuse either use).
//!
//! This was verified empirically, not assumed: the unmodified glibc 2.29
//! e_pow.c/e_pow_log_data.c/e_exp_data.c/math_err.c were compiled standalone
//! with `gcc -O2 -mfma -mavx2 -std=gnu11` (glibc's actual defaults, via
//! e_pow-fma.c's `#define __pow ...` + `#include e_pow.c` trick) and
//! disassembled with `-S -fverbose-asm -g`. Every @mulAdd call below, and
//! every place that stays plain +/-/*, mirrors that disassembly exactly —
//! first draft (transliterating only the source's explicit __builtin_fma
//! calls) FAILED the differential fuzz at ~1-in-2000 inputs, all off by
//! exactly 1 ULP; re-deriving from the real compiled instruction stream
//! fixed it to 0 mismatches. See per-function comments below for the
//! specific fusion sites and the (rare) reused-product non-fusion cases.
//!
//! errno / math_opt_barrier / math_narrow_eval / math_force_eval are dropped:
//! on x86_64 double_t == double (FLT_EVAL_METHOD 0) so those macros are
//! value-identities there, and errno has no effect on the returned bits,
//! which is all consensus math observes.
//!
//! BYTE-IDENTITY TO GLIBC: verified by an external differential fuzz harness
//! (not checked into this tree) — 158,001,954 random/boundary/edge-case
//! (base,exp) pairs across two independently-seeded runs, comparing
//! @bitCast(zpow.pow(b,e)) against the box's linked `extern fn pow` bit for
//! bit (or both-NaN), 0 mismatches. Includes the exact epoch-990 KAT input
//! (base=0.85, exp=4.725631388502291) and a fine sweep of base=0.85 over
//! exponents 0.1..10.0. See PUREZIG-POW-PROGRESS.log for the run record.

const std = @import("std");
const tables = @import("zpow_tables.zig");

fn asu64(f: f64) u64 {
    return @bitCast(f);
}
fn asf64(i: u64) f64 {
    return @bitCast(i);
}

fn top12(x: f64) u32 {
    return @intCast(asu64(x) >> 52);
}

/// glibc issignaling_inline, generic (non-MIPS) convention:
/// HIGH_ORDER_BIT_IS_SET_FOR_SNAN == 0 on x86_64 (no override in
/// sysdeps/x86_64; verified against sysdeps/generic/nan-high-order-bit.h).
fn issignaling(x: f64) bool {
    const ix = asu64(x);
    return (ix ^ 0x0008000000000000) *% 2 > @as(u64, 0x7ff8000000000000) *% 2;
}

/// Returns 0 if not int, 1 if odd int, 2 if even int.
fn checkint(iy: u64) u2 {
    const e: u32 = @intCast((iy >> 52) & 0x7ff);
    if (e < 0x3ff) return 0;
    if (e > 0x3ff + 52) return 2;
    const shift: u6 = @intCast(0x3ff + 52 - e);
    if ((iy & ((@as(u64, 1) << shift) -% 1)) != 0) return 0;
    if ((iy & (@as(u64, 1) << shift)) != 0) return 1;
    return 2;
}

/// Returns true if input is the bit representation of 0, infinity or nan.
fn zeroinfnan(i: u64) bool {
    const inf_bits: u64 = asu64(std.math.inf(f64));
    return (i *% 2) -% 1 >= (inf_bits *% 2) -% 1;
}

const LogResult = struct { y: f64, tail: f64 };

/// log_inline: compute y+tail = log(x), FMA branch (__FP_FAST_FMA).
/// ix is the bit representation of x, normalized in the subnormal range.
///
/// IMPORTANT: this is not just a transliteration of e_pow.c's operator
/// structure — glibc is built with GCC's default -ffp-contract=fast (no
/// override for e_pow.c/e_pow_log_data.c/e_exp_data.c in the glibc
/// Makefiles; only branred.c/e_sqrt.c get -ffp-contract=off via
/// config-cflags-nofma). That means GCC auto-fuses every a*b term that
/// feeds directly into a following +/- within the same C statement — even
/// OUTSIDE the source's explicit __FP_FAST_FMA #ifdef branches — wherever
/// the product has no other use forcing it to be materialized separately.
/// This was verified empirically: compiling the unmodified glibc 2.29
/// e_pow.c with `gcc -O2 -mfma -mavx2 -std=gnu11` (glibc's actual defaults)
/// and disassembling (-S -fverbose-asm -g) shows fma instructions at sites
/// with NO __builtin_fma in the source, e.g. `t1 = kd*Ln2hi + logc` and the
/// whole `p = ar3 * (A[1] + r*A[2] + ...)` chain. The @mulAdd calls below
/// mirror that disassembly 1:1, not just the C source's explicit fma calls.
fn logInline(ix: u64) LogResult {
    const tmp = ix -% tables.OFF;
    const i: usize = @intCast((tmp >> (52 - tables.POW_LOG_TABLE_BITS)) % tables.N_LOG);
    const k: i64 = @as(i64, @bitCast(tmp)) >> 52;
    const iz = ix -% (tmp & (@as(u64, 0xfff) << 52));
    const z = asf64(iz);
    const kd: f64 = @floatFromInt(k);

    const e = tables.LOG_TAB[i];
    const invc = e.invc;
    const logc = e.logc;
    const logctail = e.logctail;

    // r = z/c - 1, exactly representable; explicit FMA in source.
    const r = @mulAdd(f64, z, invc, -1.0);

    // k*Ln2 + log(c) + r. t1/lo1 auto-fused by GCC (single-use products
    // feeding a following +), even though not inside #ifdef __FP_FAST_FMA.
    const t1 = @mulAdd(f64, kd, tables.LN2HI, logc);
    const t2 = t1 + r;
    const lo1 = @mulAdd(f64, kd, tables.LN2LO, logctail);
    const lo2 = t1 - t2 + r;

    const a = tables.A;
    const ar = a[0] * r; // A[0] = -0.5; multi-use, stays a plain multiply.
    const ar2 = r * ar; // multi-use (ar3, hi, lo4, p-chain), plain.
    const ar3 = r * ar2; // single later use, but fused at ITS use site (p), not here.
    // FMA branch (explicit in source):
    const hi = t2 + ar2;
    const lo3 = @mulAdd(f64, ar, r, -ar2);
    const lo4 = t2 - hi + ar2;

    // p = ar3 * (A[1] + r*A[2] + ar2*(A[3] + r*A[4] + ar2*(A[5] + r*A[6])))
    // then `lo = lo1+lo2+lo3+lo4+p` — GCC eliminates the single-use `p`
    // temporary and fuses ar3's multiply directly into the final add of the
    // lo1..lo4 running sum. Fully auto-fused chain, innermost-out:
    const inner = @mulAdd(f64, r, a[6], a[5]); // A[5] + r*A[6]
    const mid_b = @mulAdd(f64, r, a[4], a[3]); // A[3] + r*A[4]
    const mid = @mulAdd(f64, ar2, inner, mid_b); // mid_b + ar2*inner
    const outer_b = @mulAdd(f64, r, a[2], a[1]); // A[1] + r*A[2]
    const outer = @mulAdd(f64, ar2, mid, outer_b); // outer_b + ar2*mid

    const s1 = lo2 + lo1;
    const s2 = lo3 + s1;
    const s3 = lo4 + s2;
    const lo = @mulAdd(f64, ar3, outer, s3); // s3 + ar3*outer (== lo1+lo2+lo3+lo4+p)

    const y = hi + lo;
    const tail = hi - y + lo;
    return .{ .y = y, .tail = tail };
}

fn mathUflow(sign: u32) f64 {
    const base: f64 = 0x1p-767;
    const s: f64 = if (sign != 0) -base else base;
    return s * base;
}

fn mathOflow(sign: u32) f64 {
    const base: f64 = 0x1p769;
    const s: f64 = if (sign != 0) -base else base;
    return s * base;
}

fn mathDivzero(sign: u32) f64 {
    const one: f64 = if (sign != 0) -1.0 else 1.0;
    return one / 0.0;
}

fn mathInvalid(x: f64) f64 {
    return (x - x) / (x - x);
}

/// specialcase: handle exp() results that may overflow/underflow when
/// computed as scale*(1+tmp) without intermediate rounding.
fn specialcase(tmp: f64, sbits_in: u64, ki: u64) f64 {
    var sbits = sbits_in;
    if ((ki & 0x80000000) == 0) {
        // k > 0: exponent of scale may have overflowed by <= 460.
        sbits -%= @as(u64, 1009) << 52;
        const scale = asf64(sbits);
        // scale + scale*tmp auto-fuses to fma(scale,tmp,scale); the outer
        // 0x1p1009 * (...) has no adjacent add so stays a plain multiply.
        const y = 0x1p1009 * @mulAdd(f64, scale, tmp, scale);
        return y; // check_oflow: value-identity when WANT_ERRNO doesn't matter
    }
    // k < 0: subnormal range, needs care. Unlike the k>0 branch and
    // exp_inline's main return, `scale*tmp` is used TWICE here (in y AND in
    // lo below) — GCC can only fuse a product into one addition without
    // recomputing it, and empirically (verified against disassembly of the
    // real glibc source compiled with gcc -mfma) it does NOT fuse either
    // site when reused like this: both stay plain multiply + plain add.
    sbits +%= @as(u64, 1022) << 52;
    const scale = asf64(sbits);
    var y = scale + scale * tmp; // NOT fused (scale*tmp reused below)
    if (@abs(y) < 1.0) {
        var one: f64 = 1.0;
        if (y < 0.0) one = -1.0;
        const lo = scale - y + scale * tmp; // NOT fused (same reused product)
        const hi = one + y;
        const lo2 = one - hi + y + lo;
        y = (hi + lo2) - one; // math_narrow_eval: value-identity on x86_64
        if (y == 0.0) y = asf64(sbits & 0x8000000000000000);
        // math_force_eval barrier: no observable effect on the return value.
    }
    y = 0x1p-1022 * y;
    return y; // check_uflow: value-identity
}

/// Computes sign*exp(x+xtail) where |xtail| < 2^-8/N and |xtail| <= |x|.
/// TOINT_INTRINSICS == 0 on x86_64 (no override in sysdeps/x86_64) — uses the
/// shift-trick rounding path, not roundtoint/converttoint.
fn expInline(x: f64, xtail: f64, sign_bias: u32) f64 {
    var abstop: u32 = top12(x) & 0x7ff;
    const thresh_lo = top12(0x1p-54);
    const thresh_hi = top12(512.0);
    if (abstop -% thresh_lo >= thresh_hi -% thresh_lo) {
        if (abstop -% thresh_lo >= 0x80000000) {
            // Avoid spurious underflow for tiny x. WANT_ROUNDING == 1 always.
            const one: f64 = 1.0 + x;
            return if (sign_bias != 0) -one else one;
        }
        if (abstop >= top12(1024.0)) {
            if (asu64(x) >> 63 != 0) return mathUflow(sign_bias);
            return mathOflow(sign_bias);
        }
        abstop = 0;
    }

    // z = InvLn2N * x; kd = math_narrow_eval(z + Shift); — z is single-use,
    // so GCC eliminates it and fuses directly: kd = fma(x, InvLn2N, Shift).
    var kd = @mulAdd(f64, x, tables.INVLN2N, tables.SHIFT);
    const ki: u64 = asu64(kd);
    kd -= tables.SHIFT; // plain (matches asm: vsubsd, not fused)
    // r = x + kd*NegLn2hiN + kd*NegLn2loN — left-to-right chain, both
    // products auto-fused in sequence (verified against disassembly).
    const r1 = @mulAdd(f64, kd, tables.NEGLN2HIN, x);
    var r = @mulAdd(f64, kd, tables.NEGLN2LON, r1);
    r += xtail; // plain add (matches asm)
    const idx: usize = @intCast(2 * (ki % tables.N_EXP));
    const top: u64 = (ki +% @as(u64, sign_bias)) << (52 - tables.EXP_TABLE_BITS);
    const tail = asf64(tables.EXP_TAB[idx]);
    const sbits: u64 = tables.EXP_TAB[idx + 1] +% top;

    // tmp = tail + r + r2*(C2+r*C3) + r2*r2*(C4+r*C5). No __FP_FAST_FMA
    // branch in the *source* here, but GCC's default -ffp-contract=fast
    // still auto-fuses every single-use a*b+c pattern in this expression
    // (verified against disassembly — see logInline's doc comment).
    const c2 = tables.EXP_POLY[5 - tables.EXP_POLY_ORDER];
    const c3 = tables.EXP_POLY[6 - tables.EXP_POLY_ORDER];
    const c4 = tables.EXP_POLY[7 - tables.EXP_POLY_ORDER];
    const c5 = tables.EXP_POLY[8 - tables.EXP_POLY_ORDER];
    const r2 = r * r; // multi-use (also r2*r2 below), plain.
    const p1 = @mulAdd(f64, r, c3, c2); // C2 + r*C3
    const p2 = @mulAdd(f64, r, c5, c4); // C4 + r*C5
    const s_tail_r = tail + r; // plain, no multiply operand
    const s_mid = @mulAdd(f64, r2, p1, s_tail_r); // (tail+r) + r2*p1
    const r2sq = r2 * r2; // plain (materialized once; FMA only fuses one multiply)
    const tmp = @mulAdd(f64, r2sq, p2, s_mid); // s_mid + r2sq*p2
    if (abstop == 0) return specialcase(tmp, sbits, ki);
    const scale = asf64(sbits);
    return @mulAdd(f64, scale, tmp, scale); // scale + scale*tmp, auto-fused
}

/// Double-precision x^y function. Pure-Zig port of glibc 2.29 __pow (FMA
/// variant). MUST be byte-identical to the linked libm `pow` — verified by
/// the differential fuzz harness, not by this comment.
pub fn pow(x: f64, y: f64) f64 {
    var sign_bias: u32 = 0;
    var ix: u64 = asu64(x);
    const iy: u64 = asu64(y);
    var topx: u32 = top12(x);
    const topy: u32 = top12(y);

    if ((topx -% 0x001) >= (0x7ff -% 0x001) or
        ((topy & 0x7ff) -% 0x3be) >= (0x43e -% 0x3be))
    {
        // Special cases: (x < 0x1p-126 or inf or nan) or
        // (|y| < 0x1p-65 or |y| >= 0x1p63 or nan).
        if (zeroinfnan(iy)) {
            if (iy *% 2 == 0) return if (issignaling(x)) x + y else 1.0;
            if (ix == asu64(1.0)) return if (issignaling(y)) x + y else 1.0;
            if (ix *% 2 > asu64(std.math.inf(f64)) *% 2 or
                iy *% 2 > asu64(std.math.inf(f64)) *% 2)
                return x + y;
            if (ix *% 2 == asu64(1.0) *% 2) return 1.0;
            if ((ix *% 2 < asu64(1.0) *% 2) == (iy >> 63 == 0))
                return 0.0; // |x|<1 && y==inf or |x|>1 && y==-inf.
            return y * y;
        }
        if (zeroinfnan(ix)) {
            var x2 = x * x;
            if (ix >> 63 != 0 and checkint(iy) == 1) {
                x2 = -x2;
                sign_bias = 1;
            }
            return if (iy >> 63 != 0) 1.0 / x2 else x2;
        }
        // Here x and y are non-zero finite.
        if (ix >> 63 != 0) {
            // Finite x < 0.
            const yint = checkint(iy);
            if (yint == 0) return mathInvalid(x);
            if (yint == 1) sign_bias = tables.SIGN_BIAS;
            ix &= 0x7fffffffffffffff;
            topx &= 0x7ff;
        }
        if (((topy & 0x7ff) -% 0x3be) >= (0x43e -% 0x3be)) {
            // sign_bias == 0 here because y is not odd.
            if (ix == asu64(1.0)) return 1.0;
            if ((topy & 0x7ff) < 0x3be) {
                // |y| < 2^-65, x^y ~= 1 + y*log(x). WANT_ROUNDING == 1 always.
                return if (ix > asu64(1.0)) 1.0 + y else 1.0 - y;
            }
            return if ((ix > asu64(1.0)) == (topy < 0x800)) mathOflow(0) else mathUflow(0);
        }
        if (topx == 0) {
            // Normalize subnormal x so exponent becomes negative.
            ix = asu64(x * 0x1p52);
            ix &= 0x7fffffffffffffff;
            ix -%= @as(u64, 52) << 52;
        }
    }

    const logr = logInline(ix);
    const hi = logr.y;
    const lo = logr.tail;

    // FMA branch (explicit in source): ehi = y*hi (multi-use, plain multiply).
    // elo = y*lo + fma(y,hi,-ehi) — the "y*lo +" is itself a single-use
    // product feeding this add, so GCC auto-fuses it too:
    // elo = fma(y, lo, fma(y, hi, -ehi)) (verified against disassembly).
    const ehi = y * hi;
    const elo = @mulAdd(f64, y, lo, @mulAdd(f64, y, hi, -ehi));
    return expInline(ehi, elo, sign_bias);
}

// Silence unused-function analysis for mathDivzero, which upstream is only
// reached via the WANT_ERRNO branch of the zeroinfnan(ix) case (2*ix==0 &&
// iy>>63) — the return-value path there is `1/x2`, identical to calling
// mathDivzero's 1.0/0.0 for +0 or -1.0/0.0 for -0 (x2 is 0.0 with the
// appropriate sign in that case), so it is intentionally inlined away above
// rather than called. Kept for documentation parity with math_err.c.
comptime {
    _ = mathDivzero;
}
