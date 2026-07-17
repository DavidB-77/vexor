//! Curve25519 sol_curve_group_op / multiscalar_mul KAT — task #8 (2026-06-19).
//!
//! Guards the byte-for-byte fix of the latent abort-vs-soft / abort-vs-compute-identity
//! divergence found by the agave-behavior-extractor:
//!   • Class A — bad point / non-canonical scalar → canonical None → SOFT (helper returns
//!     InvalidPoint/InvalidScalar; the syscall maps to r0=1). Previously aborted.
//!   • Class B — scalar=0 / identity / low-order / identity-sum / msm n==0 → canonical
//!     Some(identity-or-result) → r0=0 + WRITE. Previously aborted (std Edwards25519.mul
//!     rejects identity/low-order). Now computed via scalarMulNoReject.
//!
//! These exercise crypto_helpers.edwardsGroupOp / edwardsMsm directly (pure std.crypto,
//! no InvokeContext/FFI). The double-and-add is validated ALGEBRAICALLY against the
//! (separately-canonical) group `add` — mul(2)·G == G+G — so no external hex vectors are
//! needed and the Edwards-Y compression is implicitly checked. @prov:syscall.curve-ops
//!
//! Run with: zig build test-curve25519

const std = @import("std");
const ch = @import("crypto_helpers.zig");

const E = ch.Edwards25519;
const R = ch.Ristretto255;

const IDENTITY_ED: [32]u8 = [_]u8{1} ++ [_]u8{0} ** 31; // dalek CompressedEdwardsY identity
fn scalar(n: u8) [32]u8 {
    return [_]u8{n} ++ [_]u8{0} ** 31; // little-endian small scalar
}
const ZERO: [32]u8 = [_]u8{0} ** 32;

// ── Class B (compute-identity): MUST return Ok(0) + identity bytes, NOT abort ──

test "ed mul scalar=0 · G → identity bytes (THE CRUX)" {
    const out = try ch.edwardsGroupOp(E, .mul, ZERO, E.basePoint.toBytes());
    try std.testing.expectEqualSlices(u8, &IDENTITY_ED, &out);
    // identity encoding is exactly dalek's 01 00..00
    try std.testing.expectEqualSlices(u8, &IDENTITY_ED, &E.identityElement.toBytes());
}

test "ed mul point=identity, scalar=7 → identity bytes" {
    const out = try ch.edwardsGroupOp(E, .mul, scalar(7), IDENTITY_ED);
    try std.testing.expectEqualSlices(u8, &IDENTITY_ED, &out);
}

test "ed msm n==0 → identity bytes (no abort)" {
    const out = try ch.edwardsMsm(E, &.{}, &.{});
    try std.testing.expectEqualSlices(u8, &IDENTITY_ED, &out);
}

test "ed msm [0,1]·[G,Q] → Q (per-term identity must not abort)" {
    const G = E.basePoint.toBytes();
    const Q = try ch.edwardsGroupOp(E, .mul, scalar(2), G); // Q = 2G
    const out = try ch.edwardsMsm(E, &.{ ZERO, scalar(1) }, &.{ G, Q });
    try std.testing.expectEqualSlices(u8, &Q, &out);
}

// ── Double-and-add correctness, validated against the canonical group add ──

test "ed mul(1)·G == G" {
    const G = E.basePoint.toBytes();
    const out = try ch.edwardsGroupOp(E, .mul, scalar(1), G);
    try std.testing.expectEqualSlices(u8, &G, &out);
}

test "ed mul(2)·G == add(G,G)" {
    const G = E.basePoint.toBytes();
    const viaMul = try ch.edwardsGroupOp(E, .mul, scalar(2), G);
    const viaAdd = try ch.edwardsGroupOp(E, .add, G, G);
    try std.testing.expectEqualSlices(u8, &viaAdd, &viaMul);
}

test "ed mul(3)·G == add(add(G,G),G)" {
    const G = E.basePoint.toBytes();
    const twoG = try ch.edwardsGroupOp(E, .add, G, G);
    const threeG = try ch.edwardsGroupOp(E, .add, twoG, G);
    const viaMul = try ch.edwardsGroupOp(E, .mul, scalar(3), G);
    try std.testing.expectEqualSlices(u8, &threeG, &viaMul);
}

test "ed msm [3,5]·[G,G] == mul(8)·G (linearity)" {
    const G = E.basePoint.toBytes();
    const viaMsm = try ch.edwardsMsm(E, &.{ scalar(3), scalar(5) }, &.{ G, G });
    const via8 = try ch.edwardsGroupOp(E, .mul, scalar(8), G);
    try std.testing.expectEqualSlices(u8, &via8, &viaMsm);
}

// ── Class A (soft-fail): helper returns InvalidPoint/InvalidScalar → syscall r0=1 ──

// Deterministically find a genuinely off-curve Y encoding (≈50% of Y values have no
// on-curve X). NOTE: 0xff*32 is NOT off-curve — its Y reduces to 18 mod p, a valid point
// (Zig std fromBytes reduces non-canonical Y just like dalek decompress).
fn offCurvePoint() [32]u8 {
    var p: [32]u8 = ZERO;
    var y: u8 = 2;
    while (y < 255) : (y += 1) {
        p[0] = y;
        if (std.meta.isError(E.fromBytes(p))) return p;
    }
    unreachable; // an off-curve Y always exists in [2,255)
}

test "ed add off-curve point → InvalidPoint (soft, not abort)" {
    try std.testing.expectError(error.InvalidPoint, ch.edwardsGroupOp(E, .add, offCurvePoint(), E.basePoint.toBytes()));
}

test "ed mul non-canonical scalar → InvalidScalar (soft)" {
    const nc: [32]u8 = [_]u8{0xff} ** 32; // s >= group order ℓ
    try std.testing.expectError(error.InvalidScalar, ch.edwardsGroupOp(E, .mul, nc, E.basePoint.toBytes()));
}

test "ed mul canonical scalar + off-curve point → InvalidPoint (soft)" {
    try std.testing.expectError(error.InvalidPoint, ch.edwardsGroupOp(E, .mul, scalar(1), offCurvePoint()));
}

test "ed low-order point (y=0, order-4): mul(4)·P → identity, NOT rejected" {
    // y=0 decodes to (±sqrt(-1), 0), an order-4 point. std Edwards25519.mul would
    // reject it (rejectLowOrder → WeakPublicKey); scalarMulNoReject must COMPUTE it.
    const lo: [32]u8 = ZERO; // Y=0, sign 0
    if (std.meta.isError(E.fromBytes(lo))) return; // skip if this build rejects Y=0 at decode
    const out = try ch.edwardsGroupOp(E, .mul, scalar(4), lo);
    try std.testing.expectEqualSlices(u8, &IDENTITY_ED, &out); // 4·(order-4) = identity
}

test "ed msm with one non-canonical scalar → InvalidScalar (soft)" {
    const G = E.basePoint.toBytes();
    const nc: [32]u8 = [_]u8{0xff} ** 32;
    try std.testing.expectError(error.InvalidScalar, ch.edwardsMsm(E, &.{ scalar(1), nc }, &.{ G, G }));
}

// ── Happy path (already matched pre-fix; guard against regression) ──

test "ed add(identity, G) == G" {
    const G = E.basePoint.toBytes();
    const out = try ch.edwardsGroupOp(E, .add, IDENTITY_ED, G);
    try std.testing.expectEqualSlices(u8, &G, &out);
}

test "ed sub(G,G) → identity" {
    const G = E.basePoint.toBytes();
    const out = try ch.edwardsGroupOp(E, .sub, G, G);
    try std.testing.expectEqualSlices(u8, &IDENTITY_ED, &out);
}

// ── Ristretto coverage (distinct encoding: identity = all-zero, NOT 01 00..00) ──

test "ristretto mul scalar=0 · basepoint → ristretto identity" {
    const RG = R.basePoint.toBytes();
    const ristretto_identity = (R{ .p = E.identityElement }).toBytes();
    const out = try ch.edwardsGroupOp(R, .mul, ZERO, RG);
    try std.testing.expectEqualSlices(u8, &ristretto_identity, &out);
}

test "ristretto mul(2)·B == add(B,B)" {
    const RG = R.basePoint.toBytes();
    const viaMul = try ch.edwardsGroupOp(R, .mul, scalar(2), RG);
    const viaAdd = try ch.edwardsGroupOp(R, .add, RG, RG);
    try std.testing.expectEqualSlices(u8, &viaAdd, &viaMul);
}

test "ristretto msm n==0 → ristretto identity" {
    const ristretto_identity = (R{ .p = E.identityElement }).toBytes();
    const out = try ch.edwardsMsm(R, &.{}, &.{});
    try std.testing.expectEqualSlices(u8, &ristretto_identity, &out);
}
