//! ed25519 MSM API for the ZK ElGamal proof port (task #11, 2026-06-19).
//!
//! Vexor-native reimplementation of the Sig `crypto/ed25519/{straus,pippenger}` MSM API,
//! built directly on `std.crypto.ecc.{Edwards25519,Ristretto255}` (the SAME primitives
//! vex_bpf2 already uses for the curve25519 syscalls — see crypto_helpers.zig).
//!
//! WHY a reimplementation instead of porting Sig's backend: Sig's straus/pippenger pull in
//! its entire custom ed25519 backend (generic.zig ExtendedPoint/CachedPoint/LookupTable +
//! avx512.zig asm + a vendored `std14`), ~2300 LoC of non-std machinery. The proofs only
//! ever call the high-level MSM API below — they never touch ExtendedPoint/LookupTable —
//! and an MSM result is a GROUP element: any correct implementation yields the byte-identical
//! compressed encoding (advisor: "group math is byte-exact for free"). So we expose Sig's
//! exact signatures over std.crypto.ecc and the proof modules compile unchanged.
//!
//! Consensus-sensitive behaviour PRESERVED:
//!   • non-rejecting scalar mult (identity / low-order / unreduced scalars never rejected),
//!     matching curve25519-dalek `&scalar * &point` and Sig straus (radix-16, no reject).
//!   • encoded-input decode goes through `fromBytes` (canonical / on-curve validation) and
//!     propagates the error — `mulMultiRuntime(encoded=true)` returns an error union exactly
//!     like Sig (NonCanonical / EncodingError).
//!
//! PERF NOTE (follow-up): scalar mult here is plain MSB-first double-and-add; the big
//! bulletproof U256 MSM is O(points·256) group ops. Correct but unwindowed. A radix-16
//! window (mirroring Sig's asRadix16/LookupTable) is a drop-in optimisation if replay timing
//! ever needs it — the RESULT is unchanged, so it can be added post-gate without re-validation.

const std = @import("std");

pub const Edwards25519 = std.crypto.ecc.Edwards25519;
pub const Ristretto255 = std.crypto.ecc.Ristretto255;
pub const CompressedScalar = Edwards25519.scalar.CompressedScalar; // [32]u8, little-endian

/// `ed25519.straus` / `ed25519.pippenger` resolve back to this same namespace: we do not
/// implement two distinct MSM algorithms (the result is identical), so both aliases point here.
pub const straus = @This();
pub const pippenger = @This();

pub fn PointType(comptime encoded: bool, comptime ristretto: bool) type {
    if (encoded) return [32]u8;
    return if (ristretto) Ristretto255 else Edwards25519;
}

pub fn ReturnType(comptime encoded: bool, comptime ristretto: bool) type {
    const Base = if (ristretto) Ristretto255 else Edwards25519;
    return if (encoded) (error{NonCanonical} || std.crypto.errors.EncodingError)!Base else Base;
}

/// Non-rejecting fixed-/variable-base scalar mult over the complete Edwards group law.
/// MSB-first double-and-add over all 256 bits of `s` (little-endian). Never rejects identity,
/// low-order, or unreduced scalars — equivalent to dalek `&s * &P`.
fn scalarMulPoint(p: Edwards25519, s: CompressedScalar) Edwards25519 {
    var q: Edwards25519 = Edwards25519.identityElement;
    var i: usize = 256;
    while (i > 0) {
        i -= 1;
        q = q.dbl();
        if ((s[i >> 3] >> @as(u3, @intCast(i & 7))) & 1 == 1) {
            q = q.add(p);
        }
    }
    return q;
}

/// Variable-time, variable-base scalar mult. `ristretto` selects the wire type.
pub fn mul(
    comptime ristretto: bool,
    point: PointType(false, ristretto),
    scalar: CompressedScalar,
) PointType(false, ristretto) {
    const ep: Edwards25519 = if (ristretto) point.p else point;
    const q = scalarMulPoint(ep, scalar);
    return if (ristretto) .{ .p = q } else q;
}

/// Variable-base multiplication of `scalar` by a comptime-known Ristretto point.
pub fn mulByKnown(comptime point: Ristretto255, scalar: CompressedScalar) Ristretto255 {
    return .{ .p = scalarMulPoint(point.p, scalar) };
}

/// MSM with a comptime-known count: Σ scalars[i]·points[i].
pub fn mulMulti(
    comptime N: comptime_int,
    points: [N]Ristretto255,
    scalars: [N]CompressedScalar,
) Ristretto255 {
    var acc: Edwards25519 = Edwards25519.identityElement;
    inline for (points, scalars) |p, s| {
        acc = acc.add(scalarMulPoint(p.p, s));
    }
    return .{ .p = acc };
}

/// Multiply many points by the SAME scalar (saves nothing here vs N muls, but matches the API).
pub fn mulManyWithSameScalar(
    comptime N: comptime_int,
    points: [N]Ristretto255,
    scalar: CompressedScalar,
) [N]Ristretto255 {
    var out: [N]Ristretto255 = undefined;
    inline for (points, &out) |p, *o| {
        o.* = .{ .p = scalarMulPoint(p.p, scalar) };
    }
    return out;
}

/// MSM with a runtime (comptime-bounded) count. `encoded` => points are [32]u8 wire bytes
/// decoded via fromBytes (return type becomes an error union; decode failure propagates).
pub fn mulMultiRuntime(
    comptime max_elements: comptime_int,
    comptime encoded: bool,
    comptime ristretto: bool,
    points: []const PointType(encoded, ristretto),
    scalars: []const CompressedScalar,
) ReturnType(encoded, ristretto) {
    _ = max_elements;
    std.debug.assert(points.len == scalars.len);
    var acc: Edwards25519 = Edwards25519.identityElement;
    for (points, scalars) |pt, s| {
        const ep: Edwards25519 = if (encoded) blk: {
            break :blk if (ristretto)
                (try Ristretto255.fromBytes(pt)).p
            else
                try Edwards25519.fromBytes(pt);
        } else (if (ristretto) pt.p else pt);
        acc = acc.add(scalarMulPoint(ep, s));
    }
    const Base = if (ristretto) Ristretto255 else Edwards25519;
    const result: Base = if (ristretto) .{ .p = acc } else acc;
    return result;
}

test "ed25519 shim: mulMulti([2,3],[G,G]) == mul(5)·G" {
    const G = Edwards25519.basePoint;
    const RG: Ristretto255 = .{ .p = G };
    const two: CompressedScalar = [_]u8{2} ++ [_]u8{0} ** 31;
    const three: CompressedScalar = [_]u8{3} ++ [_]u8{0} ** 31;
    const five: CompressedScalar = [_]u8{5} ++ [_]u8{0} ** 31;
    const viaMsm = mulMulti(2, .{ RG, RG }, .{ two, three });
    const viaMul = mul(true, RG, five);
    try std.testing.expectEqualSlices(u8, &viaMul.toBytes(), &viaMsm.toBytes());
}

test "ed25519 shim: scalar=0 -> identity (non-rejecting)" {
    const RG: Ristretto255 = .{ .p = Edwards25519.basePoint };
    const zero: CompressedScalar = [_]u8{0} ** 32;
    const out = mul(true, RG, zero);
    const id: Ristretto255 = .{ .p = Edwards25519.identityElement };
    try std.testing.expectEqualSlices(u8, &id.toBytes(), &out.toBytes());
}
