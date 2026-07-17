//! Vexor BN254 groups — G1 (over Fp) and G2 (over Fp2) — with the exact
//! deserialization / subgroup semantics of the Solana alt_bn128 syscalls.
//!
//! Vexor's own implementation of the group law and point (de)serialization,
//! written against the standard Jacobian formulas and cross-checked byte-for-byte
//! against Firedancer Ballet by `kat.zig`. Points are held in Jacobian (X,Y,Z);
//! the affine add path uses the projective-free λ formula because that is what
//! the syscall reference does (byte-identical intermediate rounding matters).
//!
//! ── Subgroup-check semantics (SIMD-locked; getting this wrong forks the chain)
//! Extracted from solana-bn254 v3.2.1 (the crate Agave wraps) and mirrored by
//! Ballet:
//!   • G1 add / G1 mul / pairing-G1 : on-curve check only (G1 has cofactor 1, so
//!     on-curve ⇒ in-subgroup).
//!   • G2 ADD                       : on-curve check ONLY — NO subgroup check
//!     (ark `into_affine_unchecked`; the crate has an explicit security note).
//!   • G2 MUL / pairing-G2          : on-curve check AND subgroup membership
//!     (ark `Validate::Yes`).
//! So G2 has two decode entry points, and using the wrong one is a divergence.

const std = @import("std");
const f = @import("field.zig");
const Fp = f.Fp;
const Fp2 = f.Fp2;
const Flags = f.Flags;

const Endian = std.builtin.Endian;

pub const Error = error{ NotOnCurve, NotInSubgroup, BadEncoding };

/// The BN seed x = 0x44e992b44a6909f1 (little-endian bit iteration source for
/// the fast G2 subgroup check).
const x_seed: u256 = Fp.constants.x_seed;

fn bitOf(v: u256, i: u32) bool {
    return (v >> @intCast(i)) & 1 != 0;
}

// ── G1 over Fp ──────────────────────────────────────────────────────────────
pub const G1 = struct {
    x: Fp,
    y: Fp,
    z: Fp,

    pub const zero: G1 = .{ .x = .zero, .y = .zero, .z = .zero };

    pub fn isZero(p: G1) bool {
        return p.z.isZero();
    }

    /// Decode raw coordinates (NON-Montgomery), no curve check. All-zero input
    /// (or infinity flag on Y) → point at infinity. Used by compress.
    fn fromBytesRaw(input: *const [64]u8, endian: Endian) !G1 {
        if (std.mem.allEqual(u8, input, 0)) return zero;
        var flags: Flags = undefined;
        const x = try Fp.fromBytes(input[0..32], endian, null);
        const y = try Fp.fromBytes(input[32..64], endian, &flags);
        return .{ .x = x, .y = y, .z = if (flags.is_inf) .zero else .one };
    }

    /// Decode for arithmetic: Montgomery form + on-curve check (y² = x³ + b).
    /// For G1 the on-curve check is also the subgroup check (cofactor 1).
    pub fn fromBytes(input: *const [64]u8, endian: Endian) !G1 {
        var p = try fromBytesRaw(input, endian);
        if (p.isZero()) return p;
        p.x.toMont();
        p.y.toMont();
        p.z = .one;
        const y2 = p.y.sq();
        const x3b = p.x.sq().mul(p.x).add(Fp.constants.b_mont);
        if (!y2.eql(x3b)) return Error.NotOnCurve;
        return p;
    }

    pub fn toBytes(p: G1, out: *[64]u8, endian: Endian) void {
        if (p.isZero()) {
            @memset(out, 0);
            return;
        }
        var a = toAffine(p);
        a.x.fromMont();
        a.y.fromMont();
        a.x.toBytes(out[0..32], endian);
        a.y.toBytes(out[32..64], endian);
    }

    pub fn compress(out: *[32]u8, input: *const [64]u8, endian: Endian) !void {
        const p = try fromBytesRaw(input, endian);
        const inf_byte = input[if (endian == .big) 32 else 63] & Flags.INF;
        if (p.isZero()) {
            @memset(out, 0);
            out[if (endian == .big) 0 else 31] |= inf_byte;
            return;
        }
        @memcpy(out, input[0..32]);
        if (p.y.isNegative()) out[if (endian == .big) 0 else 31] |= Flags.NEG;
    }

    pub fn decompress(out: *[64]u8, input: *const [32]u8, endian: Endian) !void {
        if (std.mem.allEqual(u8, input, 0)) return @memset(out, 0);
        var flags: Flags = undefined;
        const x = try Fp.fromBytes(input, endian, &flags);
        if (flags.is_inf) return @memset(out, 0);
        var xm = x;
        xm.toMont();
        const x3b = xm.sq().mul(xm).add(Fp.constants.b_mont);
        var y = try x3b.sqrt();
        y.fromMont();
        if (flags.is_neg != y.isNegative()) y = y.negateNm();
        x.toBytes(out[0..32], endian);
        y.toBytes(out[32..64], endian);
    }
};

// ── G2 over Fp2 ─────────────────────────────────────────────────────────────
pub const G2 = struct {
    x: Fp2,
    y: Fp2,
    z: Fp2,

    pub const zero: G2 = .{ .x = .zero, .y = .zero, .z = .zero };

    pub fn isZero(p: G2) bool {
        return p.z.isZero();
    }

    fn fromBytesRaw(input: *const [128]u8, endian: Endian) !G2 {
        if (std.mem.allEqual(u8, input, 0)) return zero;
        var flags: Flags = undefined;
        const x = try Fp2.fromBytes(input[0..64], endian, null);
        const y = try Fp2.fromBytes(input[64..128], endian, &flags);
        return .{ .x = x, .y = y, .z = if (flags.is_inf) .zero else .one };
    }

    /// on-curve check only (G2 ADD path).
    pub fn fromBytesCheckCurve(input: *const [128]u8, endian: Endian) !G2 {
        var p = try fromBytesRaw(input, endian);
        if (p.isZero()) return p;
        p.x.toMont();
        p.y.toMont();
        p.z = .one;
        try p.assertOnCurve();
        return p;
    }

    /// on-curve check AND subgroup membership (G2 MUL / pairing path).
    pub fn fromBytesCheckSubgroup(input: *const [128]u8, endian: Endian) !G2 {
        const p = try fromBytesCheckCurve(input, endian);
        if (p.isZero()) return p;
        if (!p.inSubgroup()) return Error.NotInSubgroup;
        return p;
    }

    fn assertOnCurve(p: G2) !void {
        const y2 = p.y.sq();
        const x3b = p.x.sq().mul(p.x).add(Fp2.constants.twist_b_mont);
        if (!y2.eql(x3b)) return Error.NotOnCurve;
    }

    /// Fast G2 subgroup test (ia.cr/2022/348 §3.1):
    ///   [x+1]P + ψ([x]P) + ψ²([x]P) == ψ³([2x]P)
    /// where ψ is the untwist-Frobenius-twist endomorphism (frob) and x is the
    /// BN seed. Assumes P is on-curve and non-zero.
    fn inSubgroup(p: G2) bool {
        const xp = mulScalar(G2, p, x_seed); // [x]P  (p affine)
        const psi = xp.frob(); // ψ([x]P)   (not affine)
        const psi2 = xp.frob2(); // ψ²([x]P) (not affine)
        // [x+1]P + ψ([x]P) + ψ²([x]P):  first term mixes affine p into Jacobian xp,
        // the ψ terms are full Jacobian additions.
        const lhs = addJacobian(G2, addJacobian(G2, addMixed(G2, xp, p), psi), psi2);
        const rhs = dbl(G2, psi2.frob()); // ψ³([2x]P)
        return lhs.eql(rhs);
    }

    pub fn frob(p: G2) G2 {
        const g1 = Fp2.constants.gamma1_mont;
        return .{
            .x = p.x.conj().mul(g1[1]),
            .y = p.y.conj().mul(g1[2]),
            .z = p.z.conj(),
        };
    }

    pub fn frob2(p: G2) G2 {
        const g2 = Fp.constants.gamma2_mont;
        return .{
            .x = p.x.mulByFp(g2[1]),
            .y = p.y.mulByFp(g2[2]),
            .z = p.z,
        };
    }

    pub fn negate(p: G2) G2 {
        return .{ .x = p.x, .y = p.y.negate(), .z = p.z };
    }

    fn eql(a: G2, b: G2) bool {
        if (a.isZero()) return b.isZero();
        if (b.isZero()) return false;
        const za2 = a.z.sq();
        const zb2 = b.z.sq();
        if (!a.x.mul(zb2).eql(b.x.mul(za2))) return false;
        return a.y.mul(zb2).mul(b.z).eql(b.y.mul(za2).mul(a.z));
    }

    pub fn toBytes(p: G2, out: *[128]u8, endian: Endian) void {
        if (p.isZero()) {
            @memset(out, 0);
            return;
        }
        var a = toAffine(p);
        a.x.fromMont();
        a.y.fromMont();
        a.x.toBytes(out[0..64], endian);
        a.y.toBytes(out[64..128], endian);
    }

    pub fn compress(out: *[64]u8, input: *const [128]u8, endian: Endian) !void {
        const p = try fromBytesRaw(input, endian);
        const inf_byte = input[if (endian == .big) 64 else 127] & Flags.INF;
        if (p.isZero()) {
            @memset(out, 0);
            out[if (endian == .big) 0 else 63] |= inf_byte;
            return;
        }
        @memcpy(out, input[0..64]);
        if (p.y.isNegative()) out[if (endian == .big) 0 else 63] |= Flags.NEG;
    }

    pub fn decompress(out: *[128]u8, input: *const [64]u8, endian: Endian) !void {
        if (std.mem.allEqual(u8, input, 0)) return @memset(out, 0);
        var flags: Flags = undefined;
        const x = try Fp2.fromBytes(input, endian, &flags);
        if (flags.is_inf) return @memset(out, 0);
        var xm = x;
        xm.toMont();
        const x3b = xm.sq().mul(xm).add(Fp2.constants.twist_b_mont);
        var y = try x3b.sqrt();
        y.fromMont();
        if (flags.is_neg != y.isNegative()) y = y.negateNm();
        x.toBytes(out[0..64], endian);
        y.toBytes(out[64..128], endian);
    }
};

// ── Shared Jacobian group law (generic over G1/G2 via duck-typed field ops) ──

fn toAffine(p: anytype) @TypeOf(p) {
    if (p.z.isZero() or p.z.isOne()) return p;
    const iz = p.z.inverse();
    const iz2 = iz.sq();
    return .{ .x = p.x.mul(iz2), .y = p.y.mul(iz2).mul(iz), .z = .one };
}

/// Point doubling in Jacobian coords (dbl-2007-bl).
fn dbl(comptime T: type, p: T) T {
    if (p.isZero()) return T.zero;
    const xx = p.x.sq();
    const yy = p.y.sq();
    const zz = p.z.sq();
    const yyyy = yy.sq();
    const s = p.x.add(yy).sq().sub(xx).sub(yyyy).dbl();
    const m = xx.triple();
    const t = m.sq().sub(s).sub(s);
    return .{
        .x = t,
        .y = s.sub(t).mul(m).sub(yyyy.dbl().dbl().dbl()),
        .z = p.y.add(p.z).sq().sub(yy).sub(zz),
    };
}

/// Mixed addition: `a` Jacobian, `b` affine (z=1) (madd-2007-bl).
fn addMixed(comptime T: type, a: T, b: T) T {
    if (a.isZero()) return b;
    const z1z1 = a.z.sq();
    const uu2 = b.x.mul(z1z1);
    const s2 = b.y.mul(a.z).mul(z1z1);
    if (uu2.eql(a.x) and s2.eql(a.y)) return dbl(T, a);
    const h = uu2.sub(a.x);
    const hh = h.sq();
    const i = hh.dbl().dbl();
    const j = h.mul(i);
    const r = s2.sub(a.y).dbl();
    const v = a.x.mul(i);
    const x3 = r.sq().sub(j).sub(v).sub(v);
    return .{
        .x = x3,
        .y = v.sub(x3).mul(r).sub(a.y.mul(j).dbl()),
        .z = a.z.add(h).sq().sub(z1z1).sub(hh),
    };
}

/// Full Jacobian + Jacobian addition (add-2007-bl). Neither operand need be
/// affine. Used by the G2 subgroup check where the ψ-endomorphism outputs are
/// projective. (Only its accept/reject verdict is consensus-relevant, not its
/// internal representation.)
fn addJacobian(comptime T: type, a: T, b: T) T {
    if (a.isZero()) return b;
    if (b.isZero()) return a;
    const z1z1 = a.z.sq();
    const z2z2 = b.z.sq();
    const uu1 = a.x.mul(z2z2);
    const uu2 = b.x.mul(z1z1);
    const s1 = a.y.mul(b.z).mul(z2z2);
    const s2 = b.y.mul(a.z).mul(z1z1);
    if (uu1.eql(uu2) and s1.eql(s2)) return dbl(T, a);
    const h = uu2.sub(uu1);
    const i = h.dbl().sq();
    const j = h.mul(i);
    const r = s2.sub(s1).dbl();
    const v = uu1.mul(i);
    const x3 = r.sq().sub(j).sub(v.dbl());
    return .{
        .x = x3,
        .y = v.sub(x3).mul(r).sub(s1.mul(j).dbl()),
        .z = a.z.add(b.z).sq().sub(z1z1).sub(z2z2).mul(h),
    };
}

/// Affine + affine via the λ chord/tangent formula (both z=1). This is the
/// exact syscall-add reference path; result is affine (z=1).
fn affineAdd(comptime T: type, a: T, b: T) T {
    if (a.isZero()) return b;
    if (b.isZero()) return a;
    const lambda = if (a.x.eql(b.x)) blk: {
        if (!a.y.eql(b.y)) return T.zero; // a == -b
        // tangent: λ = 3x² / 2y
        break :blk a.y.dbl().inverse().mul(a.x.sq().triple());
    } else blk: {
        // chord: λ = (y1 - y2)/(x1 - x2)
        break :blk a.x.sub(b.x).inverse().mul(a.y.sub(b.y));
    };
    const x3 = lambda.sq().sub(a.x).sub(b.x);
    const y3 = a.x.sub(x3).mul(lambda).sub(a.y);
    return .{ .x = x3, .y = y3, .z = .one };
}

/// Double-and-add scalar multiply; `a` assumed affine. Iterates scalar bits MSB
/// to LSB.
fn mulScalar(comptime T: type, a: T, scalar: u256) T {
    if (scalar == 0) return T.zero;
    var i: u32 = 255 - @clz(scalar);
    var r = a;
    while (i > 0) {
        i -= 1;
        r = dbl(T, r);
        if (bitOf(scalar, i)) r = addMixed(T, r, a);
    }
    return r;
}

// Re-exported so the syscall layer / pairing can reach the shared law.
pub const ops = struct {
    pub const affineAddG1 = struct {
        fn call(a: G1, b: G1) G1 {
            return affineAdd(G1, a, b);
        }
    }.call;
    pub const affineAddG2 = struct {
        fn call(a: G2, b: G2) G2 {
            return affineAdd(G2, a, b);
        }
    }.call;
    pub const mulScalarG1 = struct {
        fn call(a: G1, s: u256) G1 {
            return mulScalar(G1, a, s);
        }
    }.call;
    pub const mulScalarG2 = struct {
        fn call(a: G2, s: u256) G2 {
            return mulScalar(G2, a, s);
        }
    }.call;
};
