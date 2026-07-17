//! Vexor BN254 field tower — Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12.
//!
//! Vexor's own implementation of the BN254 extension-field arithmetic used by the
//! alt_bn128 group ops and the optimal-ate pairing. The base field Fp delegates
//! its modular reduction to the fiat-crypto Montgomery artifact (`fiat_fp.zig`,
//! the one bit-identical-mandatory layer); everything here — the Fp wrapper and
//! the Fp2/Fp6/Fp12 tower — is written fresh, following the standard published
//! algorithms and cross-checked byte-for-byte against Firedancer Ballet by the
//! differential gate (`kat.zig`). Algorithm references are cited inline; the
//! curve constants are mathematical facts (their derivation is documented where
//! they appear).
//!
//! Tower layout (BN254, the arkworks/Ballet convention):
//!   Fp2  = Fp[u]  / (u² + 1)                      (i.e. u = √-1)
//!   Fp6  = Fp2[v] / (v³ − ξ),   ξ = 9 + u         (the "mulByXi" non-residue)
//!   Fp12 = Fp6[w] / (w²  − v)                      ("mulByGamma" = ·v)
//!
//! Montgomery domain: all arithmetic runs in the Montgomery domain except the
//! byte (de)serialization boundary and the sign test, which are explicitly in
//! the non-Montgomery ("nm") domain — matching Ballet's fd_bn254_fp_*_nm.

const std = @import("std");
const fiat = @import("fiat_fp.zig");

/// Serialization flag byte (arkworks short-Weierstrass convention). Lives in the
/// top two bits of the most-significant coordinate byte: bit7 = "y is negative"
/// (point-compression sign), bit6 = "point at infinity". The low 6 bits are part
/// of the field element and are masked off before decoding.
pub const Flags = packed struct(u8) {
    _low: u6,
    is_inf: bool,
    is_neg: bool,

    pub const NEG: u8 = 1 << 7;
    pub const INF: u8 = 1 << 6;
    pub const MASK: u8 = 0b0011_1111;
};

/// Big-endian byte-swap of a 256-bit little-endian limb array. Kept as four
/// per-limb @byteSwap so the limbs also reverse order (full 32-byte reversal).
fn bswap32(a: [32]u8) [32]u8 {
    const limbs: [4]u64 = @bitCast(a);
    return @bitCast([4]u64{
        @byteSwap(limbs[3]),
        @byteSwap(limbs[2]),
        @byteSwap(limbs[1]),
        @byteSwap(limbs[0]),
    });
}

// ── Fp: the BN254 base field ────────────────────────────────────────────────
pub const Fp = struct {
    limbs: [4]u64,

    pub const zero: Fp = .{ .limbs = @splat(0) };
    pub const one: Fp = blk: {
        var f: Fp = undefined;
        fiat.setOne(&f.limbs);
        break :blk f;
    };

    pub const p: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    const p_limbs: [4]u64 = @bitCast(p);
    const p_minus_1_half: u256 = (p - 1) / 2;
    const p_minus_2: u256 = p - 2;
    // p ≡ 3 (mod 4), so a square root is a^((p+1)/4); the Atkin test exponent is
    // (p-3)/4 (see sqrt).
    const sqrt_exp: u256 = (p - 3) / 4;

    /// Comptime constructor: integer → Montgomery-domain Fp. Test/const use only.
    pub fn fromInt(comptime v: u256) Fp {
        var le: [32]u8 = undefined;
        std.mem.writeInt(u256, &le, v, .little);
        var nm: [4]u64 = undefined;
        fiat.fromBytes(&nm, le);
        var m: [4]u64 = undefined;
        fiat.toMontgomery(&m, nm);
        return .{ .limbs = m };
    }

    pub const constants = struct {
        /// b = 3 in the short-Weierstrass equation y² = x³ + b (Montgomery form).
        pub const b_mont: Fp = fromInt(3);
        /// −1 (Montgomery), used as the "not a square" sentinel in sqrt.
        pub const minus_one_mont: Fp = fromInt(p - 1);
        /// The BN generator parameter x (the curve's design seed).
        pub const x_seed: u256 = 0x44e992b44a6909f1;

        /// Frobenius γ₂ constants (Fp, for the p²-power Frobenius). Derived as
        /// (ξ)^{(i·(p²−1))/6}; carried verbatim as field constants.
        pub const gamma2_mont: [5]Fp = .{
            .{ .limbs = .{ 0xca8d800500fa1bf2, 0xf0c5d61468b39769, 0x0e201271ad0d4418, 0x04290f65bad856e6 } },
            .{ .limbs = .{ 0x3350c88e13e80b9c, 0x7dce557cdb5e56b9, 0x6001b4b8b615564a, 0x2682e617020217e0 } },
            .{ .limbs = .{ 0x68c3488912edefaa, 0x8d087f6872aabf4f, 0x51e1a24709081231, 0x2259d6b14729c0fa } },
            .{ .limbs = .{ 0x71930c11d782e155, 0xa6bb947cffbe3323, 0xaa303344d4741444, 0x2c3b3f0d26594943 } },
            .{ .limbs = .{ 0x08cfc388c494f1ab, 0x19b315148d1373d4, 0x584e90fdcb6c0213, 0x09e1685bdf2f8849 } },
        };
    };

    /// Decode a 32-byte field element. `endian` selects wire byte order.
    /// When `maybe_flags` is non-null this is the flag-bearing coordinate:
    /// the flag bits are captured then masked off, and both-flags-set is
    /// rejected (arkworks serialization_flags rule). Rejects value ≥ p.
    pub fn fromBytes(input: *const [32]u8, endian: std.builtin.Endian, maybe_flags: ?*Flags) !Fp {
        if (maybe_flags) |flags| {
            const flag_byte = input[if (endian == .big) 0 else 31];
            flags.* = @bitCast(flag_byte);
            if (flags.is_inf and flags.is_neg) return error.BothFlags;
        }
        var le: [32]u8 = if (endian == .big) bswap32(input.*) else input.*;
        if (maybe_flags != null) le[31] &= Flags.MASK;
        if (@as(u256, @bitCast(le)) >= p) return error.NotReduced;
        return .{ .limbs = @bitCast(le) };
    }

    pub fn toBytes(f: Fp, out: *[32]u8, endian: std.builtin.Endian) void {
        out.* = if (endian == .big) bswap32(@bitCast(f.limbs)) else @bitCast(f.limbs);
    }

    pub fn eql(a: Fp, b: Fp) bool {
        const va: @Vector(4, u64) = a.limbs;
        const vb: @Vector(4, u64) = b.limbs;
        return @reduce(.And, va == vb);
    }
    pub fn isZero(f: Fp) bool {
        return f.eql(zero);
    }
    pub fn isOne(f: Fp) bool {
        return f.eql(one);
    }

    /// "Negative" per arkworks compression: the raw (non-Montgomery) integer is
    /// in the upper half (> (p-1)/2). Caller must pass an nm-domain element.
    pub fn isNegative(f: Fp) bool {
        return @as(u256, @bitCast(f.limbs)) > p_minus_1_half;
    }

    pub fn add(a: Fp, b: Fp) Fp {
        var r: Fp = undefined;
        fiat.add(&r.limbs, a.limbs, b.limbs);
        return r;
    }
    pub fn sub(a: Fp, b: Fp) Fp {
        var r: Fp = undefined;
        fiat.sub(&r.limbs, a.limbs, b.limbs);
        return r;
    }
    pub fn mul(a: Fp, b: Fp) Fp {
        var r: Fp = undefined;
        fiat.mul(&r.limbs, a.limbs, b.limbs);
        return r;
    }
    pub fn sq(a: Fp) Fp {
        var r: Fp = undefined;
        fiat.square(&r.limbs, a.limbs);
        return r;
    }
    pub fn dbl(a: Fp) Fp {
        return a.add(a);
    }
    pub fn triple(a: Fp) Fp {
        return a.add(a).add(a);
    }
    pub fn negate(a: Fp) Fp {
        var r: Fp = undefined;
        fiat.opp(&r.limbs, a.limbs);
        return r;
    }

    /// p - a in the non-Montgomery domain (0 maps to 0). Constant-time borrow
    /// chain; used to fix a decompressed y to the requested sign.
    pub fn negateNm(a: Fp) Fp {
        if (a.isZero()) return zero;
        var r: Fp = undefined;
        var borrow: u64 = 0;
        inline for (0..4) |i| {
            var b = a.limbs[i];
            b +%= borrow;
            borrow = @intFromBool(b < borrow) + @intFromBool(p_limbs[i] < b);
            r.limbs[i] = p_limbs[i] -% b;
        }
        return r;
    }

    /// a / 2 (Montgomery domain): if odd, add p first, then shift right 1.
    pub fn halve(a: Fp) Fp {
        const odd = (a.limbs[0] & 1) != 0;
        const wide: u256 = @as(u256, @bitCast(a.limbs)) + (if (odd) p else 0);
        var l: [4]u64 = @bitCast(wide);
        l[0] = (l[0] >> 1) | (l[1] << 63);
        l[1] = (l[1] >> 1) | (l[2] << 63);
        l[2] = (l[2] >> 1) | (l[3] << 63);
        l[3] >>= 1;
        return .{ .limbs = @bitCast(l) };
    }

    pub fn toMont(f: *Fp) void {
        fiat.toMontgomery(&f.limbs, f.limbs);
    }
    pub fn fromMont(f: *Fp) void {
        fiat.fromMontgomery(&f.limbs, f.limbs);
    }

    fn bitSet(v: u256, i: u32) bool {
        return (v >> @intCast(i)) & 1 != 0;
    }

    pub fn pow(a: Fp, comptime e: u256) Fp {
        var r = one;
        var i: u32 = 255 - @clz(e);
        while (true) {
            r = r.sq();
            if (bitSet(e, i)) r = r.mul(a);
            if (i == 0) break;
            i -= 1;
        }
        return r;
    }

    pub fn inverse(a: Fp) Fp {
        return a.pow(p_minus_2);
    }

    /// Square root via the Atkin/Shanks shortcut for p ≡ 3 (mod 4)
    /// (Adj–Rodríguez-Henríquez, ia.cr/2012/685 Alg. 2). Returns error if `a`
    /// is a non-residue.
    pub fn sqrt(a: Fp) !Fp {
        const c1 = a.pow(sqrt_exp);
        const c0 = c1.sq().mul(a);
        if (c0.eql(constants.minus_one_mont)) return error.NotSquare;
        return c1.mul(a);
    }
};

// ── Fp2 = Fp[u]/(u²+1) ──────────────────────────────────────────────────────
pub const Fp2 = struct {
    c0: Fp,
    c1: Fp,

    pub const zero: Fp2 = .{ .c0 = .zero, .c1 = .zero };
    pub const one: Fp2 = .{ .c0 = .one, .c1 = .zero };

    pub const constants = struct {
        /// Twist coefficient b' = 3 / (9 + u) (Montgomery), for the sextic twist
        /// equation y² = x³ + b'.
        pub const twist_b_mont: Fp2 = .{
            .c0 = .{ .limbs = .{ 0x3bf938e377b802a8, 0x020b1b273633535d, 0x26b7edf049755260, 0x2514c6324384a86d } },
            .c1 = .{ .limbs = .{ 0x38e7ecccd1dcff67, 0x65f0b37d93ce0d3e, 0xd749d0dd22ac00aa, 0x0141b9ce4a688d4d } },
        };

        /// Frobenius γ₁ constants (Fp2, for the p-power Frobenius): ξ^{(i·(p−1))/6}.
        pub const gamma1_mont: [5]Fp2 = .{
            .{ .c0 = .{ .limbs = .{ 0xaf9ba69633144907, 0xca6b1d7387afb78a, 0x11bded5ef08a2087, 0x02f34d751a1f3a7c } }, .c1 = .{ .limbs = .{ 0xa222ae234c492d72, 0xd00f02a4565de15b, 0xdc2ff3a253dfc926, 0x10a75716b3899551 } } },
            .{ .c0 = .{ .limbs = .{ 0xb5773b104563ab30, 0x347f91c8a9aa6454, 0x7a007127242e0991, 0x1956bcd8118214ec } }, .c1 = .{ .limbs = .{ 0x6e849f1ea0aa4757, 0xaa1c7b6d89f89141, 0xb6e713cdfae0ca3a, 0x26694fbb4e82ebc3 } } },
            .{ .c0 = .{ .limbs = .{ 0xe4bbdd0c2936b629, 0xbb30f162e133bacb, 0x31a9d1b6f9645366, 0x253570bea500f8dd } }, .c1 = .{ .limbs = .{ 0xa1d77ce45ffe77c7, 0x07affd117826d1db, 0x6d16bd27bb7edc6b, 0x2c87200285defecc } } },
            .{ .c0 = .{ .limbs = .{ 0x7361d77f843abe92, 0xa5bb2bd3273411fb, 0x9c941f314b3e2399, 0x15df9cddbb9fd3ec } }, .c1 = .{ .limbs = .{ 0x5dddfd154bd8c949, 0x62cb29a5a4445b60, 0x37bc870a0c7dd2b9, 0x24830a9d3171f0fd } } },
            .{ .c0 = .{ .limbs = .{ 0xc970692f41690fe7, 0xe240342127694b0b, 0x32bee66b83c459e8, 0x12aabced0ab08841 } }, .c1 = .{ .limbs = .{ 0x0d485d2340aebfa9, 0x05193418ab2fcc57, 0xd3b0a40b8a4910f5, 0x2f21ebb535d2925a } } },
        };
    };

    /// c0 is the low coordinate; the flag-bearing coordinate is c1. On the wire
    /// the two Fp elements are ordered [c1, c0] for big-endian (EIP-197) and
    /// [c0, c1] for little-endian.
    pub fn fromBytes(input: *const [64]u8, endian: std.builtin.Endian, maybe_flags: ?*Flags) !Fp2 {
        const off0: usize, const off1: usize = if (endian == .big) .{ 32, 0 } else .{ 0, 32 };
        return .{
            .c0 = try Fp.fromBytes(input[off0..][0..32], endian, null),
            .c1 = try Fp.fromBytes(input[off1..][0..32], endian, maybe_flags),
        };
    }

    pub fn toBytes(f: Fp2, out: *[64]u8, endian: std.builtin.Endian) void {
        const off0: usize, const off1: usize = if (endian == .big) .{ 32, 0 } else .{ 0, 32 };
        f.c0.toBytes(out[off0..][0..32], endian);
        f.c1.toBytes(out[off1..][0..32], endian);
    }

    pub fn eql(a: Fp2, b: Fp2) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }
    pub fn isZero(f: Fp2) bool {
        return f.c0.isZero() and f.c1.isZero();
    }
    pub fn isOne(f: Fp2) bool {
        return f.c0.isOne() and f.c1.isZero();
    }
    fn isMinusOne(f: Fp2) bool {
        return f.c1.isZero() and f.c0.eql(Fp.constants.minus_one_mont);
    }

    /// Lexicographic sign of the Fp2 element (nm domain): sign of c1, or of c0
    /// when c1 is zero.
    pub fn isNegative(f: Fp2) bool {
        return if (f.c1.isZero()) f.c0.isNegative() else f.c1.isNegative();
    }

    pub fn add(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }
    pub fn sub(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }
    pub fn dbl(a: Fp2) Fp2 {
        return a.add(a);
    }
    pub fn triple(a: Fp2) Fp2 {
        return a.add(a).add(a);
    }
    pub fn negate(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.negate(), .c1 = a.c1.negate() };
    }
    pub fn negateNm(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.negateNm(), .c1 = a.c1.negateNm() };
    }
    pub fn halve(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.halve(), .c1 = a.c1.halve() };
    }
    pub fn conj(a: Fp2) Fp2 {
        return .{ .c0 = a.c0, .c1 = a.c1.negate() };
    }
    pub fn toMont(a: *Fp2) void {
        a.c0.toMont();
        a.c1.toMont();
    }
    pub fn fromMont(a: *Fp2) void {
        a.c0.fromMont();
        a.c1.fromMont();
    }
    pub fn mulByFp(a: Fp2, s: Fp) Fp2 {
        return .{ .c0 = a.c0.mul(s), .c1 = a.c1.mul(s) };
    }

    /// Karatsuba mul in Fp[u]/(u²+1): (a0+a1u)(b0+b1u).
    pub fn mul(a: Fp2, b: Fp2) Fp2 {
        const a0b0 = a.c0.mul(b.c0);
        const a1b1 = a.c1.mul(b.c1);
        const cross = a.c0.add(a.c1).mul(b.c0.add(b.c1));
        return .{
            .c0 = a0b0.sub(a1b1), // u² = −1
            .c1 = cross.sub(a0b0).sub(a1b1),
        };
    }

    /// Complex squaring: (c0+c1u)² = (c0−c1)(c0+c1) + 2·c0·c1·u.
    pub fn sq(a: Fp2) Fp2 {
        return .{
            .c0 = a.c0.add(a.c1).mul(a.c0.sub(a.c1)),
            .c1 = a.c0.mul(a.c1).dbl(),
        };
    }

    /// Multiply by the Fp6 non-residue ξ = 9 + u.
    fn mulByXi(a: Fp2) Fp2 {
        // (9+u)(c0+c1u) = (9c0 − c1) + (9c1 + c0)u
        return .{
            .c0 = a.c0.triple().triple().sub(a.c1), // 9c0 − c1
            .c1 = a.c1.triple().triple().add(a.c0), // 9c1 + c0
        };
    }

    /// Inverse via norm to Fp (ia.cr/2010/354 Alg. 8).
    pub fn inverse(a: Fp2) Fp2 {
        const norm = a.c0.sq().add(a.c1.sq()).inverse();
        return .{ .c0 = a.c0.mul(norm), .c1 = a.c1.mul(norm).negate() };
    }

    fn pow(a: Fp2, comptime e: u256) Fp2 {
        var r = one;
        var i: u32 = 255 - @clz(e);
        while (true) {
            r = r.sq();
            if ((e >> @intCast(i)) & 1 != 0) r = r.mul(a);
            if (i == 0) break;
            i -= 1;
        }
        return r;
    }

    /// Fp2 square root (ia.cr/2012/685 Alg. 9). May return r or −r (both valid);
    /// error on non-residue.
    pub fn sqrt(a: Fp2) !Fp2 {
        const a1 = a.pow(Fp.sqrt_exp);
        const alpha = a1.sq().mul(a);
        const a0 = alpha.conj().mul(alpha);
        if (a0.isMinusOne()) return error.NotSquare;
        const x0 = a1.mul(a);
        if (alpha.isMinusOne()) return x0.conj();
        const b = alpha.add(one).pow(Fp.p_minus_1_half);
        return b.mul(x0);
    }
};

// ── Fp6 = Fp2[v]/(v³−ξ) ─────────────────────────────────────────────────────
pub const Fp6 = struct {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,

    pub const zero: Fp6 = .{ .c0 = .zero, .c1 = .zero, .c2 = .zero };
    pub const one: Fp6 = .{ .c0 = .one, .c1 = .zero, .c2 = .zero };

    pub fn isZero(f: Fp6) bool {
        return f.c0.isZero() and f.c1.isZero() and f.c2.isZero();
    }
    pub fn isOne(f: Fp6) bool {
        return f.c0.isOne() and f.c1.isZero() and f.c2.isZero();
    }
    pub fn add(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1), .c2 = a.c2.add(b.c2) };
    }
    pub fn sub(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1), .c2 = a.c2.sub(b.c2) };
    }
    pub fn dbl(a: Fp6) Fp6 {
        return a.add(a);
    }
    pub fn negate(a: Fp6) Fp6 {
        return .{ .c0 = a.c0.negate(), .c1 = a.c1.negate(), .c2 = a.c2.negate() };
    }

    /// Karatsuba-style Fp6 mul (ia.cr/2010/354 Alg. 13).
    pub fn mul(a: Fp6, b: Fp6) Fp6 {
        const t0 = a.c0.mul(b.c0);
        const t1 = a.c1.mul(b.c1);
        const t2 = a.c2.mul(b.c2);
        return .{
            .c0 = a.c1.add(a.c2).mul(b.c1.add(b.c2)).sub(t1).sub(t2).mulByXi().add(t0),
            .c1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(t0).sub(t1).add(t2.mulByXi()),
            .c2 = a.c0.add(a.c2).mul(b.c0.add(b.c2)).sub(t0).sub(t2).add(t1),
        };
    }

    /// Multiply by v (the Fp12 "gamma" step): (c0,c1,c2)·v = (ξ·c2, c0, c1).
    pub fn mulByV(a: Fp6) Fp6 {
        return .{ .c0 = a.c2.mulByXi(), .c1 = a.c0, .c2 = a.c1 };
    }

    /// Fp6 squaring (CH-SQR3, ia.cr/2010/354 Alg. 16).
    pub fn sq(a: Fp6) Fp6 {
        const s0 = a.c0.sq();
        const s1 = a.c0.mul(a.c1).dbl();
        const s2 = a.c0.sub(a.c1).add(a.c2).sq();
        const s3 = a.c1.mul(a.c2).dbl();
        const s4 = a.c2.sq();
        return .{
            .c0 = s3.mulByXi().add(s0),
            .c1 = s4.mulByXi().add(s1),
            .c2 = s1.add(s2).add(s3).sub(s0).sub(s4),
        };
    }

    /// Fp6 inverse (ia.cr/2010/354 Alg. 17).
    pub fn inverse(a: Fp6) Fp6 {
        const t0 = a.c0.sq();
        const t1 = a.c1.sq();
        const t2 = a.c2.sq();
        const t3 = a.c0.mul(a.c1);
        const t4 = a.c0.mul(a.c2);
        const t5 = a.c1.mul(a.c2);
        const v0 = t0.sub(t5.mulByXi());
        const v1 = t2.mulByXi().sub(t3);
        const v2 = t1.sub(t4);
        var d = a.c0.mul(v0);
        d = d.add(a.c2.mulByXi().mul(v1));
        d = d.add(a.c1.mulByXi().mul(v2));
        d = d.inverse();
        return .{ .c0 = v0.mul(d), .c1 = v1.mul(d), .c2 = v2.mul(d) };
    }
};

// ── Fp12 = Fp6[w]/(w²−v) ────────────────────────────────────────────────────
pub const Fp12 = struct {
    c0: Fp6,
    c1: Fp6,

    pub const one: Fp12 = .{ .c0 = .one, .c1 = .zero };

    pub fn isOne(f: Fp12) bool {
        return f.c0.isOne() and f.c1.isZero();
    }

    /// Fp12 mul (ia.cr/2010/354 Alg. 20).
    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        const t0 = a.c0.mul(b.c0);
        const t1 = a.c1.mul(b.c1);
        return .{
            .c0 = t0.add(t1.mulByV()),
            .c1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(t0).sub(t1),
        };
    }

    /// Fp12 squaring (complex method, ia.cr/2010/354 Alg. 22).
    pub fn sq(a: Fp12) Fp12 {
        const t3 = a.c0.sub(a.c1.mulByV());
        const t2 = a.c0.mul(a.c1);
        const t0 = a.c0.sub(a.c1).mul(t3).add(t2);
        return .{ .c0 = t2.mulByV().add(t0), .c1 = t2.dbl() };
    }

    pub fn conj(a: Fp12) Fp12 {
        return .{ .c0 = a.c0, .c1 = a.c1.negate() };
    }

    /// Fp12 inverse (ia.cr/2010/354 Alg. 23).
    pub fn inverse(a: Fp12) Fp12 {
        const t = a.c0.sq().sub(a.c1.sq().mulByV()).inverse();
        return .{ .c0 = a.c0.mul(t), .c1 = a.c1.mul(t).negate() };
    }

    /// p-power Frobenius (ia.cr/2010/354 Alg. 28): conjugate each Fp2 and scale
    /// by the γ₁ constants.
    pub fn frob(a: Fp12) Fp12 {
        const g1 = Fp2.constants.gamma1_mont;
        return .{
            .c0 = .{
                .c0 = a.c0.c0.conj(),
                .c1 = a.c0.c1.conj().mul(g1[1]),
                .c2 = a.c0.c2.conj().mul(g1[3]),
            },
            .c1 = .{
                .c0 = a.c1.c0.conj().mul(g1[0]),
                .c1 = a.c1.c1.conj().mul(g1[2]),
                .c2 = a.c1.c2.conj().mul(g1[4]),
            },
        };
    }

    /// p²-power Frobenius (ia.cr/2010/354 Alg. 29): scale each Fp2 by an Fp γ₂.
    pub fn frob2(a: Fp12) Fp12 {
        const g2 = Fp.constants.gamma2_mont;
        return .{
            .c0 = .{
                .c0 = a.c0.c0,
                .c1 = a.c0.c1.mulByFp(g2[1]),
                .c2 = a.c0.c2.mulByFp(g2[3]),
            },
            .c1 = .{
                .c0 = a.c1.c0.mulByFp(g2[0]),
                .c1 = a.c1.c1.mulByFp(g2[2]),
                .c2 = a.c1.c2.mulByFp(g2[4]),
            },
        };
    }

    /// Cyclotomic squaring (Granger–Scott, ia.cr/2009/565 §3.2). Valid only for
    /// elements in the cyclotomic subgroup (post first two final-exp steps).
    pub fn cyclotomicSq(a: Fp12) Fp12 {
        const t0 = a.c1.c1.sq();
        const t1 = a.c0.c0.sq();
        const t6 = a.c1.c1.add(a.c0.c0).sq().sub(t0).sub(t1);
        const t2 = a.c0.c2.sq();
        const t3 = a.c1.c0.sq();
        const t7 = a.c0.c2.add(a.c1.c0).sq().sub(t2).sub(t3);
        const t4 = a.c1.c2.sq();
        const t5 = a.c0.c1.sq();
        const t8 = a.c1.c2.add(a.c0.c1).sq().sub(t4).sub(t5).mulByXi();
        const r0 = t0.mulByXi().add(t1);
        const r2 = t2.mulByXi().add(t3);
        const r4 = t4.mulByXi().add(t5);
        return .{
            .c0 = .{
                .c0 = r0.sub(a.c0.c0).dbl().add(r0),
                .c1 = r2.sub(a.c0.c1).dbl().add(r2),
                .c2 = r4.sub(a.c0.c2).dbl().add(r4),
            },
            .c1 = .{
                .c0 = t8.add(a.c1.c0).dbl().add(t8),
                .c1 = t6.add(a.c1.c1).dbl().add(t6),
                .c2 = t7.add(a.c1.c2).dbl().add(t7),
            },
        };
    }

    /// a^x where x = 0x44e992b44a6909f1 is the BN seed. Fixed addition chain
    /// (gnark-crypto e12_pairing) over cyclotomic squarings.
    pub fn powBySeed(a: Fp12) Fp12 {
        var t3 = a.cyclotomicSq();
        var t5 = t3.cyclotomicSq();
        const res0 = t5.cyclotomicSq();
        var t0 = res0.cyclotomicSq();
        var t2 = a.mul(t0);
        t0 = t3.mul(t2);
        var t1 = a.mul(t0);
        var t4 = res0.mul(t2);
        var t6 = t2.cyclotomicSq();
        t1 = t0.mul(t1);
        t0 = t3.mul(t1);
        for (0..6) |_| t6 = t6.cyclotomicSq();
        t5 = t5.mul(t6);
        t5 = t5.mul(t4);
        for (0..7) |_| t5 = t5.cyclotomicSq();
        t4 = t4.mul(t5);
        for (0..8) |_| t4 = t4.cyclotomicSq();
        t4 = t4.mul(t0);
        t3 = t3.mul(t4);
        for (0..6) |_| t3 = t3.cyclotomicSq();
        t2 = t2.mul(t3);
        for (0..8) |_| t2 = t2.cyclotomicSq();
        t2 = t2.mul(t0);
        for (0..6) |_| t2 = t2.cyclotomicSq();
        t2 = t2.mul(t0);
        for (0..10) |_| t2 = t2.cyclotomicSq();
        t1 = t1.mul(t2);
        for (0..6) |_| t1 = t1.cyclotomicSq();
        t0 = t0.mul(t1);
        return res0.mul(t0);
    }
};
