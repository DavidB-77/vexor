//! Vexor BN254 optimal-ate pairing — Miller loop + hard/easy final exponentiation.
//!
//! Vexor's own implementation, following the standard BN254 optimal-ate pairing
//! (line functions in homogeneous projective G2 coords, ia.cr/2013/722 §4.3 for
//! doubling and ia.cr/2012/408 §4.2 for add/sub; final exp per gnark-crypto's
//! addition chain) and gated byte-for-byte against Firedancer Ballet. Only used
//! by `alt_bn128_pairing`, whose 32-byte 0/1 output is forgiving of internal
//! representation — but we still match Ballet exactly.

const std = @import("std");
const f = @import("field.zig");
const curve = @import("curve.zig");

const Fp2 = f.Fp2;
const Fp12 = f.Fp12;
const G1 = curve.G1;
const G2 = curve.G2;

pub const BATCH_MAX = 16;

/// NAF-like signed digits of the ate loop count (6x+2 recoding), LSB→MSB, as in
/// the reference Miller loop.
const loop_naf = [_]i2{
    0,  0,  0,  1,  0,  1,  0,  -1,
    0,  0,  -1, 0,  0,  0,  1,  0,
    0,  -1, 0,  -1, 0,  0,  0,  1,
    0,  -1, 0,  0,  0,  0,  -1, 0,
    0,  1,  0,  -1, 0,  0,  1,  0,
    0,  0,  0,  0,  -1, 0,  0,  -1,
    0,  1,  0,  -1, 0,  0,  0,  -1,
    0,  -1, 0,  0,  0,  1,  0,  -1,
};

/// Miller loop over parallel batches of (P∈G1 affine, Q∈G2 affine).
pub fn millerLoop(ps: []const G1, qs: []const G2) Fp12 {
    std.debug.assert(ps.len == qs.len);
    const n = ps.len;

    var t: [BATCH_MAX]G2 = undefined;
    var line: Fp12 = undefined;
    var acc: Fp12 = .one;
    for (0..n) |i| t[i] = qs[i];

    for (0..n) |i| {
        projDouble(&line, &t[i], ps[i]);
        acc = acc.mul(line);
    }
    acc = acc.sq();

    for (0..n) |i| {
        // FIX (bn254 Miller-loop T-update order, backported from zolcrypt
        // c2762b7, 2026-07-18): the two preprocessing line evaluations must be
        // subtract-then-add with the T-update on the ADD call (leaving T=3Q for
        // the main NAF loop). The prior add-then-subtract with update-on-subtract
        // left T=Q, silently corrupting every subsequent doubling/add. Both
        // orderings multiply the same pair of lines into acc (mul is
        // commutative), so only T changes. Ref: Firedancer Ballet
        // fd_bn254_pairing.c:169-176. Verified by bilinearity (e(P,Q1)*e(P,Q2)
        // == e(P,Q1+Q2)) + py_ecc cross-check.
        projAddSub(&line, &t[i], ps[i], qs[i], false, false);
        acc = acc.mul(line);
        projAddSub(&line, &t[i], ps[i], qs[i], true, true);
        acc = acc.mul(line);
    }

    var fwd: usize = 63;
    while (fwd > 0) {
        fwd -= 1;
        const bit = loop_naf[fwd];
        acc = acc.sq();
        for (0..n) |j| {
            projDouble(&line, &t[j], ps[j]);
            acc = acc.mul(line);
        }
        if (bit != 0) {
            for (0..n) |j| {
                projAddSub(&line, &t[j], ps[j], qs[j], bit > 0, true);
                acc = acc.mul(line);
            }
        }
    }

    // Final two line evaluations against the Frobenius-mapped Q (the "+p, -p²"
    // terms of the optimal-ate loop).
    for (0..n) |i| {
        const q_frob = qs[i].frob();
        projAddSub(&line, &t[i], ps[i], q_frob, true, true);
        acc = acc.mul(line);

        const q_frob2 = qs[i].frob2().negate();
        projAddSub(&line, &t[i], ps[i], q_frob2, true, false);
        acc = acc.mul(line);
    }

    return acc;
}

/// Full final exponentiation: f^((p¹²−1)/r) = easy part · hard part.
pub fn finalExp(x: Fp12) Fp12 {
    // Easy part: f^(p⁶−1)(p²+1).
    var t1 = x.inverse();
    var t0 = x.conj().mul(t1);
    var t2 = t0.frob2();
    const s = t0.mul(t2);

    // Hard part (Fuentes-Castañeda-style chain over the seed power).
    t0 = s.powBySeed().conj().cyclotomicSq();
    t1 = t0.cyclotomicSq().mul(t0);
    t2 = t1.powBySeed().conj();
    t1 = t1.conj().mul(t2);
    var t3 = t2.cyclotomicSq();
    var t4 = t3.powBySeed().mul(t1);
    t3 = t4.mul(t0);
    t0 = t4.mul(t2).mul(s);
    t2 = t3.frob();
    t0 = t0.mul(t2);
    t2 = t4.frob2();
    t0 = t0.mul(t2);
    // frob³ = frob² ∘ frob
    t2 = s.conj().mul(t3).frob2().frob();
    return t0.mul(t2);
}

/// Point doubling of the homogeneous-projective accumulator T plus the tangent
/// line evaluated at P (ia.cr/2013/722 §4.3). Updates T, writes the line to `r`.
fn projDouble(r: *Fp12, t: *G2, p: G1) void {
    const a = t.x.mul(t.y).halve(); // A = X·Y/2
    const b = t.y.sq(); // B = Y²
    const c = t.z.sq(); // C = Z²
    const d = c.triple(); // D = 3C
    const e = d.mul(Fp2.constants.twist_b_mont); // E = b'·D
    const ee = e.triple(); // F = 3E
    const g = b.add(ee).halve(); // G = (B+F)/2
    const h = t.y.add(t.z).sq().sub(b.add(c)); // H = (Y+Z)² − (B+C)

    r.* = .{
        .c0 = .{ .c0 = h.negate().mulByFp(p.y), .c1 = .zero, .c2 = .zero },
        .c1 = .{ .c0 = t.x.sq().mulByFp(p.x.triple()), .c1 = e.sub(b), .c2 = .zero },
    };

    t.* = .{
        .x = b.sub(ee).mul(a),
        .y = g.sq().sub(e.sq().triple()),
        .z = b.mul(h),
    };
}

/// Mixed add (or sub) of affine Q into the projective accumulator T plus the
/// line at P (ia.cr/2012/408 §4.2). When `update` is false, only the line is
/// produced (used for the two loop-tail evaluations that must not advance T).
fn projAddSub(r: *Fp12, t: *G2, p: G1, q: G2, is_add: bool, update: bool) void {
    const y2 = if (is_add) q.y else q.y.negate();
    const a = y2.mul(t.z);
    const b = q.x.mul(t.z);
    const theta = t.y.sub(a);
    const lambda = t.x.sub(b);
    const j = theta.mul(q.x);
    const k = lambda.mul(y2);

    r.* = .{
        .c0 = .{ .c0 = lambda.mulByFp(p.y), .c1 = .zero, .c2 = .zero },
        .c1 = .{ .c0 = theta.negate().mulByFp(p.x), .c1 = j.sub(k), .c2 = .zero },
    };

    if (update) {
        const c = theta.sq();
        const d = lambda.sq();
        const e = d.mul(lambda);
        const ff = t.z.mul(c);
        const g = t.x.mul(d);
        const h = e.add(ff).sub(g).sub(g);
        const i = t.y.mul(e);
        t.* = .{
            .x = lambda.mul(h),
            .y = g.sub(h).mul(theta).sub(i),
            .z = t.z.mul(e),
        };
    }
}
