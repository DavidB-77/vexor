//! Vexor Ed25519 — pure-Zig field/point arithmetic core.
//!
//! This module is Vexor's OWN standalone ed25519 primitive layer: the fast
//! extended-coordinates point arithmetic (AVX-512 IFMA on capable x86_64,
//! portable @Vector fallback elsewhere) plus the double-base-scalar-multiply
//! verify primitive built on top of it. It has ZERO Ballet/Firedancer FFI
//! dependency and ZERO dependency on any external `sig`/`lib` namespace —
//! `std` only, so it compiles and tests standalone.
//!
//! PROVENANCE (see src/vex_crypto/NOTICE for full detail). Two layers:
//!   * OURS — the orchestration in THIS file: the double-base scalar-multiply
//!     (`doubleBaseMul`), the w-NAF machinery (`asNaf`) and NAF lookup tables,
//!     the three explicitly-named verify predicates + the strictness matrix,
//!     `signPureZig`, and `verifyBatchStrict`. Written as Vexor's own; the
//!     consensus `verify()` deliberately stays bare `std.crypto` (see below).
//!   * CREDITED FLOOR — the field-element + lane-packed point vector kernels
//!     (avx512.zig IFMA / generic.zig portable @Vector). These are the
//!     dalek-cryptography curve25519-dalek vectorized-IFMA algorithm at the
//!     bit level (the canonical RFC8032 curve25519 arithmetic; there is no
//!     cleaner byte-identical expression), reached here via Syndica's Sig
//!     (Apache-2.0). Carried as the verbatim numeric floor and credited, NOT
//!     claimed as from-scratch — the analogue of fiat-crypto for bn254.
//! We decoupled Sig's `sig.crypto.ed25519` / `lib.solana.*` namespace wiring
//! and reconciled the verify-strictness matrix against Vexor's already-live
//! consensus routing (see the doc comment on `verifyStrict` /
//! `verifyLenientCofactorless` below).
//!
//! ⚠️ SEMANTIC MATRIX — READ BEFORE WIRING A NEW CALL SITE ⚠️
//! Three genuinely different ed25519 "accept" predicates exist in the wild,
//! and conflating them is the proven fork mechanism (slot 415479361,
//! 2026-06-15, see ../ed25519.zig's verify() doc comment):
//!   1. `std.crypto.sign.Ed25519.Signature.verify` (Vexor consensus default,
//!      UNTOUCHED by this module) — cofactored equality (accepts R that
//!      differs from sB-hA by a low-order component) + rejects IDENTITY
//!      (order-1) A/R only. This is Agave/dalek's production tx-verify
//!      behavior and MUST stay the consensus path. This module never
//!      overrides it.
//!   2. `verifyLenientCofactorless` (this file) — Sig-derived: EXACT
//!      (cofactorless) equality, NO low-order rejection at all (not even
//!      identity). Ported faithfully from Sig for completeness + future
//!      audited comparison, but is NOT wired to the consensus `verify()`
//!      path — its accept set is provably different from #1 on identity
//!      A/R (see ed25519_kat.zig's 3-way divergence KAT). Do not route
//!      consensus traffic through this without a boundary-soaked A/B gate.
//!   3. `verifyStrict` (this file) — Sig-derived + Ballet-equivalent: EXACT
//!      (cofactorless) equality + full low-order (order ≤8) rejection on
//!      both A and R. This is the `verify_strict` family (matches
//!      fd_ed25519_verify / dalek verify_strict). SAFE for the drop-safe
//!      shred path (over-rejection just triggers repair, never a bank_hash
//!      divergence) — this is what `verifyShred` now uses.
const std = @import("std");
const builtin = @import("builtin");

// avx512 implementation relies on LLVM-specific intrinsics (vpmadd52
// IFMA). Verified on Zig 0.15.2 + -mcpu=znver4: builds clean, 11/11 KATs
// pass (Sig's own header warns this crashed LLVM on Zig 0.14.1 — that does
// NOT reproduce here). Gate strictly on feature bits + the LLVM backend so
// a non-LLVM or non-AVX512IFMA target silently and correctly falls back to
// the portable generic.zig backend — never a hard compile error.
const avx512 = @import("avx512.zig");
const generic = @import("generic.zig");

const has_avx512_ifma = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512ifma) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512vl);
pub const use_avx512_ifma = has_avx512_ifma and builtin.zig_backend == .stage2_llvm;

comptime {
    // generic.zig is portable @Vector code — always safe to force into the
    // test graph on any target. avx512.zig emits real vpmadd52 IFMA LLVM
    // intrinsics that DO NOT LEGALIZE on a target lacking the feature (this
    // is a genuine target-mismatch compile error, not the historical
    // 0.14.1 LLVM crash) — so, exactly like Sig's own guard, it is only
    // forced into the test tree when `use_avx512_ifma` is actually true
    // for the target being compiled. `zig build test-vex-ed25519` compiles
    // natively on this box (AMD EPYC 9374F / znver4: has avx512ifma+vl),
    // so both backends ARE exercised there; a non-AVX512 target build
    // still gets full generic.zig + wycheproof coverage.
    if (builtin.is_test) {
        _ = generic;
        if (use_avx512_ifma) _ = avx512;
        _ = @import("wycheproof.zig");
    }
}

const namespace = if (use_avx512_ifma) avx512 else generic;
pub const ExtendedPoint = namespace.ExtendedPoint;
pub const CachedPoint = namespace.CachedPoint;

// NOTE: general N-point multi-scalar-mul (Straus / Pippenger) is deliberately
// NOT provided here. The ed25519 signature verify hot path uses the 2-point
// `doubleBaseMul` below, not general MSM; the one in-tree MSM consumer (the
// zk-ElGamal proof program) carries its own std.crypto.ecc-based
// implementation in src/vex_bpf2/zksdk/ed25519.zig. We do not ship unused
// vendored MSM code.

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Sha512 = std.crypto.hash.sha2.Sha512;
const CompressedScalar = [32]u8;

const convention: std.builtin.CallingConvention = switch (builtin.mode) {
    .ReleaseFast => .@"inline",
    else => .auto,
};

/// Odd-multiple lookup table (1A,3A,...,15A) for the non-basepoint operand.
const NafLookupTable5 = struct {
    table: [8]CachedPoint,

    fn init(point: Edwards25519) callconv(convention) NafLookupTable5 {
        const A: ExtendedPoint = .fromPoint(point);
        var Ai: [8]CachedPoint = @splat(.fromExtended(A));
        const A2 = A.dbl();
        for (0..7) |i| Ai[i + 1] = .fromExtended(A2.addCached(Ai[i]));
        return .{ .table = Ai };
    }

    fn select(self: NafLookupTable5, index: u64) CachedPoint {
        std.debug.assert(index & 1 == 1);
        std.debug.assert(index < 16);
        return self.table[index / 2];
    }
};

/// Same as `NafLookupTable5` but radix 2^8, precomputed once at comptime for
/// the basepoint (used by both verify and our own sign()'s R = rB step).
const NafLookupTable8 = struct {
    table: [64]CachedPoint,

    fn init(point: Edwards25519) callconv(convention) NafLookupTable8 {
        const A: ExtendedPoint = .fromPoint(point);
        var Ai: [64]CachedPoint = @splat(.fromExtended(A));
        const A2 = A.dbl();
        for (0..63) |i| Ai[i + 1] = .fromExtended(A2.addCached(Ai[i]));
        return .{ .table = Ai };
    }

    fn select(self: NafLookupTable8, index: u64) CachedPoint {
        std.debug.assert(index & 1 == 1);
        std.debug.assert(index < 128);
        return self.table[index / 2];
    }
};

/// Ported from dalek-cryptography/curve25519-dalek scalar.rs `non_adjacent_form`.
fn asNaf(a: CompressedScalar, comptime w: comptime_int) [256]i8 {
    std.debug.assert(w >= 2);
    std.debug.assert(w <= 8);

    var naf: [256]i8 = @splat(0);

    var x: [5]u64 = @splat(0);
    @memcpy(std.mem.asBytes(x[0..4]), &a);

    const width = 1 << w;
    const window_mask = width - 1;

    var pos: u64 = 0;
    var carry: u64 = 0;
    while (pos < 256) {
        const idx = pos / 64;
        const bit_idx: std.math.Log2Int(u64) = @intCast(pos % 64);

        const bit_buf: u64 = switch (bit_idx) {
            0...63 - w => x[idx] >> bit_idx,
            else => x[idx] >> bit_idx | x[1 + idx] << @intCast(64 - @as(u7, bit_idx)),
        };

        const window = carry + (bit_buf & window_mask);

        if (window & 1 == 0) {
            pos += 1;
            continue;
        }

        if (window < width / 2) {
            carry = 0;
            naf[pos] = @intCast(window);
        } else {
            carry = 1;
            const signed: i64 = @bitCast(window);
            naf[pos] = @as(i8, @truncate(signed)) -% @as(i8, @truncate(width));
        }

        pos += w;
    }

    return naf;
}

/// Compute `aA + bB` in variable time, where `B` is the ed25519 basepoint.
/// The workhorse behind both verify variants below AND `signPureZig`'s
/// R = rB step (called there with a=0, A=identityElement).
pub fn doubleBaseMul(a: CompressedScalar, A: Edwards25519, b: CompressedScalar) Edwards25519 {
    const a_naf = asNaf(a, 5);
    const b_naf = asNaf(b, 8);

    var i: u64 = std.math.maxInt(u8);
    for (0..256) |rev| {
        i = 256 - rev - 1;
        if (a_naf[i] != 0 or b_naf[i] != 0) break;
    }

    const table_A: NafLookupTable5 = .init(A);

    @setEvalBranchQuota(100_000);
    const table_B: NafLookupTable8 = comptime .init(.basePoint);

    var Q: ExtendedPoint = .identityElement;
    while (true) {
        Q = Q.dbl();

        switch (std.math.order(a_naf[i], 0)) {
            .gt => Q = Q.addCached(table_A.select(@intCast(a_naf[i]))),
            .lt => Q = Q.subCached(table_A.select(@intCast(-a_naf[i]))),
            .eq => {},
        }

        switch (std.math.order(b_naf[i], 0)) {
            .gt => Q = Q.addCached(table_B.select(@intCast(b_naf[i]))),
            .lt => Q = Q.subCached(table_B.select(@intCast(-b_naf[i]))),
            .eq => {},
        }

        if (i == 0) break;
        i -= 1;
    }

    return Q.toPoint();
}

/// Equate two ed25519 points assuming b.z == 1 (true right after
/// deserializing a point off the wire).
fn affineEqual(a: Edwards25519, b: Edwards25519) bool {
    const x1 = b.x.mul(a.z);
    const y1 = b.y.mul(a.z);
    return x1.equivalent(a.x) and y1.equivalent(a.y);
}

/// True iff `a` (with a.z == 1) is one of the 8 points of order ≤ 8 in the
/// torsion subgroup E[8]. Ported verbatim (math unchanged) from Sig's
/// `affineLowOrder`; see that function's original doc-comment for the full
/// enumeration of the 8 low-order points this checks.
fn isLowOrder(a: Edwards25519) bool {
    const y0: Edwards25519.Fe = .{ .limbs = .{
        0x4d3d706a17c7, 0x1aec1679749fb, 0x14c80a83d9c40, 0x3a763661c967d, 0x7a03ac9277fdc,
    } };
    const y1: Edwards25519.Fe = .{ .limbs = .{
        0x7b2c28f95e826, 0x6513e9868b604, 0x6b37f57c263bf, 0x4589c99e36982, 0x5fc536d88023,
    } };
    return a.x.isZero() or a.y.isZero() or a.y.equivalent(y0) or a.y.equivalent(y1);
}

const Strictness = enum { lenient_cofactorless, strict };

/// Core verify: exact (cofactorless) sB-hA == R equality, with low-order
/// rejection on A/expected_r gated by `mode`. Byte-for-byte port of Sig's
/// `verifySignature` math, decoupled from `lib.solana.Signature/Pubkey` to
/// operate directly on raw wire bytes (Vexor's existing FFI-call-site shape).
fn verifyCore(sig: *const [64]u8, pubkey: *const [32]u8, message: []const u8, mode: Strictness) bool {
    const r: [32]u8 = sig[0..32].*;
    const s: [32]u8 = sig[32..64].*;

    Edwards25519.scalar.rejectNonCanonical(s) catch return false;

    const a = Edwards25519.fromBytes(pubkey.*) catch return false;
    const expected_r = Edwards25519.fromBytes(r) catch return false;

    if (mode == .strict) {
        if (isLowOrder(a) or isLowOrder(expected_r)) return false;
    }

    var h = Sha512.init(.{});
    h.update(&r);
    h.update(pubkey);
    h.update(message);
    var hram64: [Sha512.digest_length]u8 = undefined;
    h.final(&hram64);
    const hram = Edwards25519.scalar.reduce64(hram64);

    const computed = doubleBaseMul(hram, a.neg(), s);
    return affineEqual(computed, expected_r);
}

/// Sig-derived LENIENT verify: exact/cofactorless equality, NO low-order
/// rejection (not even identity). NOT wired to Vexor's consensus `verify()`
/// — see the module doc-comment's semantic matrix. Exposed + KAT'd for
/// future audited comparison only.
pub fn verifyLenientCofactorless(sig: *const [64]u8, pubkey: *const [32]u8, message: []const u8) bool {
    return verifyCore(sig, pubkey, message, .lenient_cofactorless);
}

/// Vexor-owned STRICT verify (Ballet/dalek verify_strict-equivalent): exact
/// equality + full low-order (order ≤8) rejection on A and R. This is the
/// AVX-512-accelerated replacement for the `fd_ed25519_verify` FFI on the
/// drop-safe shred path (see ../ed25519.zig `verifyShred`).
pub fn verifyStrict(sig: *const [64]u8, pubkey: *const [32]u8, message: []const u8) bool {
    return verifyCore(sig, pubkey, message, .strict);
}

/// Serial batch of `verifyStrict` calls — matches Ballet's own batch-verify
/// shape (a plain loop over the same fast double-base-mul primitive; there
/// is no exotic combined-MSM kernel to beat here, confirmed by the build
/// plan's adversarial perf pass). `results[i]` is set for every item;
/// returns true iff every item verified.
pub fn verifyBatchStrict(sigs: []const [64]u8, pubkeys: []const [32]u8, messages: []const []const u8, results: []bool) bool {
    std.debug.assert(sigs.len == pubkeys.len);
    std.debug.assert(sigs.len == messages.len);
    std.debug.assert(sigs.len == results.len);
    var all_ok = true;
    for (sigs, pubkeys, messages, results) |*sig, *pk, msg, *out| {
        const ok = verifyStrict(sig, pk, msg);
        out.* = ok;
        all_ok = all_ok and ok;
    }
    return all_ok;
}

/// Vexor-owned pure-Zig RFC 8032 sign, built on our own `doubleBaseMul` for
/// the R = rB step (a=0, A=identityElement contributes nothing — see
/// doubleBaseMul's doc comment). KAT-proven byte-identical to
/// `std.crypto.sign.Ed25519.KeyPair.sign(msg, null)` across many vectors
/// (ed25519_kat.zig) before being wired as the -Dpure_zig default.
pub fn signPureZig(secret_key: [64]u8, message: []const u8) [64]u8 {
    const seed: [32]u8 = secret_key[0..32].*;
    const pubkey: [32]u8 = secret_key[32..64].*;

    var az: [Sha512.digest_length]u8 = undefined;
    {
        var h = Sha512.init(.{});
        h.update(&seed);
        h.final(&az);
    }
    var scalar: [32]u8 = az[0..32].*;
    Edwards25519.scalar.clamp(&scalar);
    const prefix: [32]u8 = az[32..64].*;

    var nonce64: [Sha512.digest_length]u8 = undefined;
    {
        var h = Sha512.init(.{});
        h.update(&prefix);
        h.update(message);
        h.final(&nonce64);
    }
    const r = Edwards25519.scalar.reduce64(nonce64);

    // R = r*B via doubleBaseMul(0, identity, r): the `a`-side NAF is all
    // zero so this degrades to a pure basepoint scalar-mult, just routed
    // through the same AVX-512/generic fast path as verify.
    const zero_scalar: [32]u8 = @splat(0);
    const R_point = doubleBaseMul(zero_scalar, Edwards25519.identityElement, r);
    const R = R_point.toBytes();

    var hram64: [Sha512.digest_length]u8 = undefined;
    {
        var h = Sha512.init(.{});
        h.update(&R);
        h.update(&pubkey);
        h.update(message);
        h.final(&hram64);
    }
    const k = Edwards25519.scalar.reduce64(hram64);
    const s = Edwards25519.scalar.mulAdd(k, scalar, r);

    var sig: [64]u8 = undefined;
    sig[0..32].* = R;
    sig[32..64].* = s;
    return sig;
}

test "doubleBaseMul matches dalek reference vector" {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/c3a82a8a38a58aee500a20bde1664012fcfa83ba/curve25519-dalek/src/edwards.rs#L1812-L1835
    const A_TIMES_BASEPOINT: [32]u8 = .{
        0xea, 0x27, 0xe2, 0x60, 0x53, 0xdf, 0x1b, 0x59, 0x56, 0xf1, 0x4d, 0x5d, 0xec, 0x3c, 0x34,
        0xc3, 0x84, 0xa2, 0x69, 0xb7, 0x4c, 0xc3, 0x80, 0x3e, 0xa8, 0xe2, 0xe7, 0xc9, 0x42, 0x5e,
        0x40, 0xa5,
    };
    const A_SCALAR: [32]u8 = .{
        0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d, 0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8,
        0x26, 0x4d, 0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1, 0x58, 0x9e, 0x7b, 0x7f,
        0x23, 0x76, 0xef, 0x09,
    };
    const B_SCALAR: [32]u8 = .{
        0x91, 0x26, 0x7a, 0xcf, 0x25, 0xc2, 0x09, 0x1b, 0xa2, 0x17, 0x74, 0x7b, 0x66, 0xf0,
        0xb3, 0x2e, 0x9d, 0xf2, 0xa5, 0x67, 0x41, 0xcf, 0xda, 0xc4, 0x56, 0xa7, 0xd4, 0xaa,
        0xb8, 0x60, 0x8a, 0x05,
    };
    const DOUBLE_BASE_MUL_RESULT: [32]u8 = .{
        0x7d, 0xfd, 0x6c, 0x45, 0xaf, 0x6d, 0x6e, 0x0e, 0xba, 0x20, 0x37, 0x1a, 0x23, 0x64, 0x59,
        0xc4, 0xc0, 0x46, 0x83, 0x43, 0xde, 0x70, 0x4b, 0x85, 0x09, 0x6f, 0xfe, 0x35, 0x4f, 0x13,
        0x2b, 0x42,
    };

    const A: Edwards25519 = try .fromBytes(A_TIMES_BASEPOINT);
    const result = doubleBaseMul(A_SCALAR, A, B_SCALAR);
    try std.testing.expectEqualSlices(u8, &result.toBytes(), &DOUBLE_BASE_MUL_RESULT);
}

test "asNaf reconstruction round trip" {
    const Scalar = Edwards25519.scalar.Scalar;
    for (0..200) |_| {
        const scalar: Scalar = .random();
        inline for (.{ 5, 6, 7, 8 }) |w| {
            const naf = asNaf(scalar.toBytes(), w);
            var y: Scalar = .fromBytes(@splat(0));
            for (0..256) |rev| {
                const i = 256 - rev - 1;
                y = y.add(y);
                const n = @abs(naf[i]);
                var limbs: [32]u8 = @splat(0);
                std.mem.writeInt(u64, limbs[0..8], n, .little);
                const digit: Scalar = .fromBytes(if (naf[i] < 0) Edwards25519.scalar.neg(limbs) else limbs);
                y = y.add(digit);
            }
            try std.testing.expectEqual(y, scalar);
        }
    }
}

test "signPureZig matches std.crypto.sign.Ed25519 byte-for-byte" {
    var seed: [32]u8 = undefined;
    for (0..40) |i| {
        @memset(&seed, @intCast(i & 0xff));
        seed[0] = @intCast((i *% 37) & 0xff);
        seed[31] = @intCast((i *% 101) & 0xff);

        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch continue;
        var secret_key: [64]u8 = undefined;
        secret_key[0..32].* = seed;
        secret_key[32..64].* = kp.public_key.toBytes();

        var msg_buf: [50]u8 = undefined;
        const msg_len = (i % 47) + 1;
        for (0..msg_len) |j| msg_buf[j] = @intCast((i + j) & 0xff);
        const msg = msg_buf[0..msg_len];

        const our_sig = signPureZig(secret_key, msg);
        const std_sig = (kp.sign(msg, null) catch unreachable).toBytes();
        try std.testing.expectEqualSlices(u8, &std_sig, &our_sig);

        // And the signature must verify under both our strict and stdlib paths.
        try std.testing.expect(verifyStrict(&our_sig, &kp.public_key.toBytes(), msg));
        try std.crypto.sign.Ed25519.Signature.fromBytes(our_sig).verify(msg, kp.public_key);
    }
}

test "verifyStrict and verifyLenientCofactorless agree on canonical valid signatures" {
    var seed: [32]u8 = undefined;
    for (0..40) |i| {
        @memset(&seed, @intCast((i *% 53) & 0xff));
        seed[1] = @intCast((i *% 131) & 0xff);
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch continue;
        var msg_buf: [40]u8 = undefined;
        const msg_len = (i % 37) + 1;
        for (0..msg_len) |j| msg_buf[j] = @intCast((i + j * 3) & 0xff);
        const msg = msg_buf[0..msg_len];

        const sig = (kp.sign(msg, null) catch unreachable).toBytes();
        const pubkey = kp.public_key.toBytes();

        try std.testing.expect(verifyStrict(&sig, &pubkey, msg));
        try std.testing.expect(verifyLenientCofactorless(&sig, &pubkey, msg));

        var bad = sig;
        bad[0] ^= 1;
        try std.testing.expect(!verifyStrict(&bad, &pubkey, msg));
        try std.testing.expect(!verifyLenientCofactorless(&bad, &pubkey, msg));
    }
}
