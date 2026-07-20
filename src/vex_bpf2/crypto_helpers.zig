//! Vexor BPF2 — Crypto syscall helpers.
//!
//! Shared primitives for the M6 curve syscall family. Edwards25519 and
//! Ristretto255 are first-class via Zig 0.15.2 stdlib (`std.crypto.ecc`) and
//! live entirely in this file. BLS12-381, BN254, and Poseidon are NOT
//! implemented in THIS file — they are real, pure-Zig, KAT-verified
//! implementations that live in their own modules (`vex_crypto.bn254` /
//! `vex_crypto.bn254.poseidonHash`, `vex_crypto.bls12_381_syscall`) and are
//! imported separately by the syscall handlers in `syscalls.zig` (see the
//! `bn254`/`bls12_381` imports there). The `M6_*RequiresBn254ImplPort` /
//! `M6_*RequiresBls12_381ImplPort` error variants still exist in
//! `syscalls.zig` for defensive completeness but their gating conditions are
//! permanently false now that both backends are live — see the doc comments
//! on those variants for the current wiring.
//!
//! @prov:syscall.curve-ops — cross-references (sig ecc.zig port, agave ABI)
//! and CurveId numbering trail live in PROVENANCE.md.
//!
//! ── CurveId encoding ───────────────────────────────────────────────────────
//! Values:
//!   0  → Edwards25519
//!   1  → Ristretto255
//!   4  → BLS12-381 little-endian   (BLS-only ops)
//!   5  → BLS12-381 G1 little-endian
//!   6  → BLS12-381 G2 little-endian
//!   132 (4|0x80) → BLS12-381 big-endian
//!   133 (5|0x80) → BLS12-381 G1 big-endian
//!   134 (6|0x80) → BLS12-381 G2 big-endian
//!
//! ── GroupOp encoding ───────────────────────────────────────────────────────
//! 0=add, 1=sub, 2=mul. Anything else is rejected with M6_CurveInvalidGroupOp.

const std = @import("std");

pub const Edwards25519 = std.crypto.ecc.Edwards25519;
pub const Ristretto255 = std.crypto.ecc.Ristretto255;

pub const CurveId = enum(u64) {
    edwards = 0,
    ristretto = 1,
    bls12_381_le = 4,
    bls12_381_g1_le = 5,
    bls12_381_g2_le = 6,
    bls12_381_be = 4 | 0x80,
    bls12_381_g1_be = 5 | 0x80,
    bls12_381_g2_be = 6 | 0x80,

    pub fn wrap(id: u64) ?CurveId {
        return std.meta.intToEnum(CurveId, id) catch null;
    }

    pub fn isBls(self: CurveId) bool {
        return switch (self) {
            .edwards, .ristretto => false,
            else => true,
        };
    }
};

pub const GroupOp = enum(u8) {
    add = 0,
    sub = 1,
    mul = 2,

    pub fn wrap(op: u64) ?GroupOp {
        return switch (op) {
            0 => .add,
            1 => .sub,
            2 => .mul,
            else => null,
        };
    }
};

/// Apply add/sub/mul to two Edwards25519/Ristretto255 points (32-byte little-
/// endian encoded). For `mul`, `left` is the scalar (must reject non-
/// canonical) and `right` is the point.
///
/// Returns the 32-byte encoded result, or an error tag for the caller to map
/// to the appropriate syscall error.
pub const EdwardsOpError = error{
    /// Point bytes failed to decode (off-curve / non-canonical Y encoding). Caller
    /// maps to the syscall SOFT failure r0=1 (canonical add/sub/mul → None → Ok(1)).
    InvalidPoint,
    /// Scalar was not canonical (s >= group order ℓ). Caller maps to SOFT r0=1.
    InvalidScalar,
    // ⚠ There is deliberately NO IdentityElement error. A scalar-mult whose result is
    // identity (scalar=0), or whose input is low-order/identity, is NOT a failure —
    // canonical curve25519-dalek `&scalar*&point → Some(...)` returns the (possibly
    // identity) point with r0=0 and WRITES it. Mapping such a case to r0=1 would
    // STILL diverge (wrong r0 AND no output written). std `Edwards25519.mul` rejects
    // these (rejectIdentity/rejectLowOrder) for signature safety, so we must NOT use
    // it here — see scalarMulNoReject. (@prov:syscall.curve-ops)
};

/// Identity-allowing scalar multiplication of an Edwards/Ristretto point — mirrors
/// curve25519-dalek `&scalar * &point`, which NEVER rejects. MSB-first double-and-add
/// over the *complete* Edwards addition law (std `add`/`dbl` return identity correctly
/// and never error). `scalar` must already be canonical (caller rejects non-canonical
/// first). Output encoding is curve-canonical, so the bytes match dalek regardless of
/// the mult algorithm. Returns the underlying Edwards25519 point; caller re-wraps for
/// Ristretto. NOTE: variable-time (not constant-time) — fine for a public-input syscall
/// where only the deterministic result matters for consensus.
fn scalarMulNoReject(comptime T: type, point: T, scalar: [32]u8) Edwards25519 {
    const ep: Edwards25519 = if (T == Edwards25519) point else point.p;
    var q: Edwards25519 = Edwards25519.identityElement;
    var i: usize = 256;
    while (i > 0) {
        i -= 1;
        q = q.dbl();
        if ((scalar[i >> 3] >> @as(u3, @intCast(i & 7))) & 1 == 1) {
            q = q.add(ep);
        }
    }
    return q;
}

pub fn edwardsGroupOp(
    comptime T: type,
    op: GroupOp,
    left: [32]u8,
    right: [32]u8,
) EdwardsOpError![32]u8 {
    if (T != Edwards25519 and T != Ristretto255) @compileError("edwardsGroupOp expects Edwards25519 or Ristretto255");
    switch (op) {
        .add, .sub => {
            const lp = T.fromBytes(left) catch return error.InvalidPoint;
            const rp = T.fromBytes(right) catch return error.InvalidPoint;
            const result = switch (op) {
                .add => lp.add(rp),
                .sub => switch (T) {
                    Edwards25519 => lp.sub(rp),
                    Ristretto255 => Ristretto255{ .p = lp.p.sub(rp.p) },
                    else => unreachable,
                },
                else => unreachable,
            };
            return result.toBytes();
        },
        .mul => {
            // For multiply, left = scalar (32 bytes), right = point.
            Edwards25519.scalar.rejectNonCanonical(left) catch return error.InvalidScalar;
            const point = T.fromBytes(right) catch return error.InvalidPoint;
            // Identity-allowing: scalar=0 / low-order / identity-result all COMPUTE
            // (never reject), matching canonical `&scalar*&point → Some(...)`.
            const q = scalarMulNoReject(T, point, left);
            return (if (T == Edwards25519) q else T{ .p = q }).toBytes();
        },
    }
}

/// Multiscalar multiplication for Edwards25519 / Ristretto255.
///
/// Computes Σ scalars[i] · points[i] over the chosen curve and returns the
/// 32-byte encoded result. Canonical (`multiscalar_multiply_edwards` over
/// `optional_multiscalar_mul`) returns `Some(identity)` for the EMPTY input and
/// for any zero/identity sum — these are NOT failures (caller r0=0, writes the
/// identity bytes). Only a non-canonical scalar or an undecodable point is a soft
/// failure (→ InvalidScalar/InvalidPoint → caller r0=1, matching canonical None).
pub fn edwardsMsm(
    comptime T: type,
    scalars: []const [32]u8,
    points_bytes: []const [32]u8,
) EdwardsOpError![32]u8 {
    if (T != Edwards25519 and T != Ristretto255) @compileError("edwardsMsm expects Edwards25519 or Ristretto255");
    std.debug.assert(scalars.len == points_bytes.len);

    // Reject all non-canonical scalars up front (matches agave/sig order → soft r0=1).
    for (scalars) |s| {
        Edwards25519.scalar.rejectNonCanonical(s) catch return error.InvalidScalar;
    }

    // Accumulate Σ sᵢ·Pᵢ with an identity-allowing per-term mult. Empty input → acc
    // stays identity → returns the identity encoding (canonical Some(identity), r0=0).
    // Naive O(n) double-and-add per term — correct for n ≤ 512; Tier-2 perf path is
    // a Pippenger multiscalar mult (@prov:syscall.curve-ops). Bytes are identical either way.
    var acc: Edwards25519 = Edwards25519.identityElement;
    for (scalars, points_bytes) |s, pb| {
        const p = T.fromBytes(pb) catch return error.InvalidPoint;
        acc = acc.add(scalarMulNoReject(T, p, s));
    }

    return (if (T == Edwards25519) acc else T{ .p = acc }).toBytes();
}

// ──────────────────────────────────────────────────────────────────────────────
// Big-int modular exponentiation backing `sol_big_mod_exp`.
// @prov:syscall.big-mod-exp — Vexor reproduces this with std.math.big.int —
// square-and-multiply over the bit-length of the exponent.
//
// Edge cases (@prov:syscall.big-mod-exp):
//   • modulus = 0  → InvalidModulusZero (caller maps to M6_BigModExpModulusZero).
//   • modulus = 1  → result = 0.
//   • exponent = 0 → result = 1 mod modulus.
//   • All inputs are big-endian byte strings (agave convention).
//   • Output is big-endian, exactly modulus_len bytes (left-zero-padded).
// ──────────────────────────────────────────────────────────────────────────────

pub const BigModExpError = error{
    InvalidModulusZero,
    OutOfMemory,
};

pub fn bigModExp(
    allocator: std.mem.Allocator,
    base_be: []const u8,
    exponent_be: []const u8,
    modulus_be: []const u8,
    out_be: []u8,
) BigModExpError!void {
    std.debug.assert(out_be.len == modulus_be.len);

    const Managed = std.math.big.int.Managed;

    // Helper: read big-endian bytes into a Managed big-int.
    const readBe = struct {
        fn f(alloc: std.mem.Allocator, bytes: []const u8) !Managed {
            var m = try Managed.init(alloc);
            errdefer m.deinit();
            // writeTwosComplement writes from a `Const` to bytes in given endian; we
            // need the inverse — readTwosComplement on a Mutable. We'll construct
            // limbs by interpreting bytes as a non-negative big-endian integer.
            // Use a temporary mutable that grows as needed.
            try m.set(0);
            if (bytes.len == 0) return m;
            // Manual: result = 0; for byte in bytes: result = result*256 + byte
            for (bytes) |b| {
                try m.shiftLeft(&m, 8);
                var byte_m = try Managed.initSet(alloc, @as(u64, b));
                defer byte_m.deinit();
                try m.add(&m, &byte_m);
            }
            return m;
        }
    }.f;

    var modulus = readBe(allocator, modulus_be) catch return error.OutOfMemory;
    defer modulus.deinit();

    if (modulus.eqlZero()) return error.InvalidModulusZero;

    // modulus == 1 → zero output.
    var one = Managed.initSet(allocator, @as(u64, 1)) catch return error.OutOfMemory;
    defer one.deinit();
    if (modulus.order(one) == .eq) {
        @memset(out_be, 0);
        return;
    }

    var base = readBe(allocator, base_be) catch return error.OutOfMemory;
    defer base.deinit();
    var exponent = readBe(allocator, exponent_be) catch return error.OutOfMemory;
    defer exponent.deinit();

    // base = base mod modulus
    {
        var q = Managed.init(allocator) catch return error.OutOfMemory;
        defer q.deinit();
        var r = Managed.init(allocator) catch return error.OutOfMemory;
        defer r.deinit();
        Managed.divFloor(&q, &r, &base, &modulus) catch return error.OutOfMemory;
        base.swap(&r);
    }

    // result = 1
    var result = Managed.initSet(allocator, @as(u64, 1)) catch return error.OutOfMemory;
    defer result.deinit();

    // Square-and-multiply over big-endian exponent bits, MSB first.
    // We iterate bytes left-to-right; for each byte, bits high-to-low.
    var saw_msb: bool = false;
    for (exponent_be) |byte| {
        var bit_idx: i32 = 7;
        while (bit_idx >= 0) : (bit_idx -= 1) {
            if (saw_msb) {
                // result = result^2 mod modulus
                var sq = Managed.init(allocator) catch return error.OutOfMemory;
                defer sq.deinit();
                Managed.sqr(&sq, &result) catch return error.OutOfMemory;
                var q = Managed.init(allocator) catch return error.OutOfMemory;
                defer q.deinit();
                var r = Managed.init(allocator) catch return error.OutOfMemory;
                defer r.deinit();
                Managed.divFloor(&q, &r, &sq, &modulus) catch return error.OutOfMemory;
                result.swap(&r);
            }
            const bit = (byte >> @intCast(bit_idx)) & 1;
            if (bit == 1) {
                saw_msb = true;
                // result = result * base mod modulus
                var prod = Managed.init(allocator) catch return error.OutOfMemory;
                defer prod.deinit();
                Managed.mul(&prod, &result, &base) catch return error.OutOfMemory;
                var q = Managed.init(allocator) catch return error.OutOfMemory;
                defer q.deinit();
                var r = Managed.init(allocator) catch return error.OutOfMemory;
                defer r.deinit();
                Managed.divFloor(&q, &r, &prod, &modulus) catch return error.OutOfMemory;
                result.swap(&r);
            }
        }
    }

    // exponent == 0 → result == 1 (we never entered the loop OR never saw a 1
    // bit). Fall through with result = 1 as initialised.

    // Serialise result as big-endian into out_be (left-zero-padded to len).
    // Use Const.writeTwosComplement which writes the big-int in the requested
    // endianness padded to buffer length. Non-negative magnitudes pad with 0.
    @memset(out_be, 0);
    const result_const = result.toConst();
    // writeTwosComplement requires buffer ≥ ceil(bits/8); when buffer is
    // shorter than the magnitude it would truncate. Caller guarantees
    // `out_be.len == modulus_be.len` and `result < modulus`, so the magnitude
    // fits.
    result_const.writeTwosComplement(out_be, .big);
}

test "bigModExp basic 2^10 mod 1000" {
    const a = std.testing.allocator;
    var out: [4]u8 = undefined;
    try bigModExp(a, &.{2}, &.{10}, &.{ 0, 0, 3, 0xe8 }, &out);
    // 2^10 = 1024. 1024 mod 1000 = 24 = 0x18.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0x18 }, &out);
}

test "bigModExp exponent zero → 1" {
    const a = std.testing.allocator;
    var out: [4]u8 = undefined;
    try bigModExp(a, &.{0xab}, &.{}, &.{ 0, 0, 0, 0xff }, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1 }, &out);
}

test "bigModExp modulus 1 → 0" {
    const a = std.testing.allocator;
    var out: [1]u8 = undefined;
    try bigModExp(a, &.{0xab}, &.{0x10}, &.{0x01}, &out);
    try std.testing.expectEqualSlices(u8, &.{0}, &out);
}

test "bigModExp modulus 0 → InvalidModulusZero" {
    const a = std.testing.allocator;
    var out: [1]u8 = undefined;
    try std.testing.expectError(
        error.InvalidModulusZero,
        bigModExp(a, &.{1}, &.{1}, &.{0}, &out),
    );
}

test "bigModExp Fermat — 3^4 mod 5 = 1" {
    // 3^4 = 81; 81 mod 5 = 1. Fermat's little: 3^(5-1) ≡ 1 (mod 5).
    const a = std.testing.allocator;
    var out: [1]u8 = undefined;
    try bigModExp(a, &.{3}, &.{4}, &.{5}, &out);
    try std.testing.expectEqualSlices(u8, &.{1}, &out);
}
