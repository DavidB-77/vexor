//! BLS12-381 syscall KAT (SIMD-0388) — drives the blstrs-faithful blst wrappers
//! in src/vex_crypto/bls12_381_syscall.zig against the OFFICIAL test vectors
//! lifted from `solana-bls12-381-syscall` v0.1.0 src/test_vectors/*.rs (Agave
//! 4.1.0-rc.1's pinned crate). Vectors are machine-extracted into
//! bls12_381_test_vectors.zig (NOT hand-typed) → identical-verdict cross-check.
//!
//! Run: zig build test-bls12-381   (links vendor/blst, no -D flags needed)
//!
//! Coverage mirrors the crate's own #[test]s: validate (random/infinity/
//! generator/not-on-curve/field-x=p), decompress (random/infinity/generator/
//! invalid-curve/field-too-large), add (random/doubling/p+inf/inf+inf), sub,
//! mul (random/scalar 0/1/-1/point-inf), pairing (identity/1/2/3 pairs/
//! bilinearity), all BE + LE. Plus the syscall-layer gate (active→executes,
//! inactive→abort) and unknown-curve-id→abort.

const std = @import("std");
const testing = std.testing;
const bls = @import("vex_crypto").bls12_381_syscall;
const v = @import("bls12_381_test_vectors.zig");

const E = bls.Endianness;

// ── validate ─────────────────────────────────────────────────────────────────

fn checkG1Validate(input: []const u8, e: E, expected: bool) !void {
    const pt: *const [96]u8 = @ptrCast(input.ptr);
    try testing.expectEqual(expected, bls.g1Validate(pt, e));
}
fn checkG2Validate(input: []const u8, e: E, expected: bool) !void {
    const pt: *const [192]u8 = @ptrCast(input.ptr);
    try testing.expectEqual(expected, bls.g2Validate(pt, e));
}

test "BLS G1 validate: random / infinity / generator (valid)" {
    try checkG1Validate(&v.INPUT_BE_G1_VALIDATE_RANDOM_VALID, .be, v.EXPECTED_G1_VALIDATE_RANDOM_VALID);
    try checkG1Validate(&v.INPUT_LE_G1_VALIDATE_RANDOM_VALID, .le, v.EXPECTED_G1_VALIDATE_RANDOM_VALID);
    try checkG1Validate(&v.INPUT_BE_G1_VALIDATE_INFINITY_VALID, .be, v.EXPECTED_G1_VALIDATE_INFINITY_VALID);
    try checkG1Validate(&v.INPUT_LE_G1_VALIDATE_INFINITY_VALID, .le, v.EXPECTED_G1_VALIDATE_INFINITY_VALID);
    try checkG1Validate(&v.INPUT_BE_G1_VALIDATE_GENERATOR_VALID, .be, v.EXPECTED_G1_VALIDATE_GENERATOR_VALID);
    try checkG1Validate(&v.INPUT_LE_G1_VALIDATE_GENERATOR_VALID, .le, v.EXPECTED_G1_VALIDATE_GENERATOR_VALID);
}

test "BLS G1 validate: not-on-curve / field-x=p (invalid)" {
    try checkG1Validate(&v.INPUT_BE_G1_VALIDATE_NOT_ON_CURVE_INVALID, .be, v.EXPECTED_G1_VALIDATE_NOT_ON_CURVE_INVALID);
    try checkG1Validate(&v.INPUT_LE_G1_VALIDATE_NOT_ON_CURVE_INVALID, .le, v.EXPECTED_G1_VALIDATE_NOT_ON_CURVE_INVALID);
    try checkG1Validate(&v.INPUT_BE_G1_VALIDATE_FIELD_X_EQ_P_INVALID, .be, v.EXPECTED_G1_VALIDATE_FIELD_X_EQ_P_INVALID);
    try checkG1Validate(&v.INPUT_LE_G1_VALIDATE_FIELD_X_EQ_P_INVALID, .le, v.EXPECTED_G1_VALIDATE_FIELD_X_EQ_P_INVALID);
}

test "BLS G2 validate: random / infinity (valid) + invalids" {
    try checkG2Validate(&v.INPUT_BE_G2_VALIDATE_RANDOM_VALID, .be, v.EXPECTED_G2_VALIDATE_RANDOM_VALID);
    try checkG2Validate(&v.INPUT_LE_G2_VALIDATE_RANDOM_VALID, .le, v.EXPECTED_G2_VALIDATE_RANDOM_VALID);
    try checkG2Validate(&v.INPUT_BE_G2_VALIDATE_INFINITY_VALID, .be, v.EXPECTED_G2_VALIDATE_INFINITY_VALID);
    try checkG2Validate(&v.INPUT_LE_G2_VALIDATE_INFINITY_VALID, .le, v.EXPECTED_G2_VALIDATE_INFINITY_VALID);
    try checkG2Validate(&v.INPUT_BE_G2_VALIDATE_NOT_ON_CURVE_INVALID, .be, v.EXPECTED_G2_VALIDATE_NOT_ON_CURVE_INVALID);
    try checkG2Validate(&v.INPUT_LE_G2_VALIDATE_NOT_ON_CURVE_INVALID, .le, v.EXPECTED_G2_VALIDATE_NOT_ON_CURVE_INVALID);
    try checkG2Validate(&v.INPUT_BE_G2_VALIDATE_FIELD_X_EQ_P_INVALID, .be, v.EXPECTED_G2_VALIDATE_FIELD_X_EQ_P_INVALID);
    try checkG2Validate(&v.INPUT_LE_G2_VALIDATE_FIELD_X_EQ_P_INVALID, .le, v.EXPECTED_G2_VALIDATE_FIELD_X_EQ_P_INVALID);
}

// ── decompress ───────────────────────────────────────────────────────────────

fn checkG1Decompress(input: []const u8, e: E, expected: ?[]const u8) !void {
    const c: *const [48]u8 = @ptrCast(input.ptr);
    var out: [96]u8 = undefined;
    const ok = bls.g1Decompress(c, e, &out);
    if (expected) |exp| {
        try testing.expect(ok);
        try testing.expectEqualSlices(u8, exp, &out);
    } else {
        try testing.expect(!ok);
    }
}
fn checkG2Decompress(input: []const u8, e: E, expected: ?[]const u8) !void {
    const c: *const [96]u8 = @ptrCast(input.ptr);
    var out: [192]u8 = undefined;
    const ok = bls.g2Decompress(c, e, &out);
    if (expected) |exp| {
        try testing.expect(ok);
        try testing.expectEqualSlices(u8, exp, &out);
    } else {
        try testing.expect(!ok);
    }
}

test "BLS G1 decompress: random / infinity / generator" {
    try checkG1Decompress(&v.INPUT_BE_G1_DECOMPRESS_RANDOM, .be, &v.OUTPUT_BE_G1_DECOMPRESS_RANDOM);
    try checkG1Decompress(&v.INPUT_LE_G1_DECOMPRESS_RANDOM, .le, &v.OUTPUT_LE_G1_DECOMPRESS_RANDOM);
    try checkG1Decompress(&v.INPUT_BE_G1_DECOMPRESS_INFINITY, .be, &v.OUTPUT_BE_G1_DECOMPRESS_INFINITY);
    try checkG1Decompress(&v.INPUT_LE_G1_DECOMPRESS_INFINITY, .le, &v.OUTPUT_LE_G1_DECOMPRESS_INFINITY);
    try checkG1Decompress(&v.INPUT_BE_G1_DECOMPRESS_GENERATOR, .be, &v.OUTPUT_BE_G1_DECOMPRESS_GENERATOR);
    try checkG1Decompress(&v.INPUT_LE_G1_DECOMPRESS_GENERATOR, .le, &v.OUTPUT_LE_G1_DECOMPRESS_GENERATOR);
}

test "BLS G1 decompress: invalid-curve / field-too-large → null" {
    try checkG1Decompress(&v.INPUT_BE_G1_DECOMPRESS_RANDOM_INVALID_CURVE, .be, null);
    try checkG1Decompress(&v.INPUT_LE_G1_DECOMPRESS_RANDOM_INVALID_CURVE, .le, null);
    try checkG1Decompress(&v.INPUT_BE_G1_DECOMPRESS_FIELD_TOO_LARGE_INVALID, .be, null);
    try checkG1Decompress(&v.INPUT_LE_G1_DECOMPRESS_FIELD_TOO_LARGE_INVALID, .le, null);
}

test "BLS G2 decompress: random / infinity / generator + invalids" {
    try checkG2Decompress(&v.INPUT_BE_G2_DECOMPRESS_RANDOM, .be, &v.OUTPUT_BE_G2_DECOMPRESS_RANDOM);
    try checkG2Decompress(&v.INPUT_LE_G2_DECOMPRESS_RANDOM, .le, &v.OUTPUT_LE_G2_DECOMPRESS_RANDOM);
    try checkG2Decompress(&v.INPUT_BE_G2_DECOMPRESS_INFINITY, .be, &v.OUTPUT_BE_G2_DECOMPRESS_INFINITY);
    try checkG2Decompress(&v.INPUT_LE_G2_DECOMPRESS_INFINITY, .le, &v.OUTPUT_LE_G2_DECOMPRESS_INFINITY);
    try checkG2Decompress(&v.INPUT_BE_G2_DECOMPRESS_GENERATOR, .be, &v.OUTPUT_BE_G2_DECOMPRESS_GENERATOR);
    try checkG2Decompress(&v.INPUT_LE_G2_DECOMPRESS_GENERATOR, .le, &v.OUTPUT_LE_G2_DECOMPRESS_GENERATOR);
    try checkG2Decompress(&v.INPUT_BE_G2_DECOMPRESS_RANDOM_INVALID_CURVE, .be, null);
    try checkG2Decompress(&v.INPUT_LE_G2_DECOMPRESS_RANDOM_INVALID_CURVE, .le, null);
    try checkG2Decompress(&v.INPUT_BE_G2_DECOMPRESS_FIELD_TOO_LARGE_INVALID, .be, null);
    try checkG2Decompress(&v.INPUT_LE_G2_DECOMPRESS_FIELD_TOO_LARGE_INVALID, .le, null);
}

// ── add / sub (input = [P1 | P2]) ────────────────────────────────────────────

fn checkG1Add(input: []const u8, e: E, expected: []const u8) !void {
    const l: *const [96]u8 = @ptrCast(input[0..96].ptr);
    const r: *const [96]u8 = @ptrCast(input[96..192].ptr);
    var out: [96]u8 = undefined;
    try testing.expect(bls.g1Add(l, r, e, &out));
    try testing.expectEqualSlices(u8, expected, &out);
}
fn checkG1Sub(input: []const u8, e: E, expected: []const u8) !void {
    const l: *const [96]u8 = @ptrCast(input[0..96].ptr);
    const r: *const [96]u8 = @ptrCast(input[96..192].ptr);
    var out: [96]u8 = undefined;
    try testing.expect(bls.g1Sub(l, r, e, &out));
    try testing.expectEqualSlices(u8, expected, &out);
}
fn checkG2Add(input: []const u8, e: E, expected: []const u8) !void {
    const l: *const [192]u8 = @ptrCast(input[0..192].ptr);
    const r: *const [192]u8 = @ptrCast(input[192..384].ptr);
    var out: [192]u8 = undefined;
    try testing.expect(bls.g2Add(l, r, e, &out));
    try testing.expectEqualSlices(u8, expected, &out);
}
fn checkG2Sub(input: []const u8, e: E, expected: []const u8) !void {
    const l: *const [192]u8 = @ptrCast(input[0..192].ptr);
    const r: *const [192]u8 = @ptrCast(input[192..384].ptr);
    var out: [192]u8 = undefined;
    try testing.expect(bls.g2Sub(l, r, e, &out));
    try testing.expectEqualSlices(u8, expected, &out);
}

test "BLS G1 add: random / doubling / p+inf / inf+inf" {
    try checkG1Add(&v.INPUT_BE_G1_ADD_RANDOM, .be, &v.OUTPUT_BE_G1_ADD_RANDOM);
    try checkG1Add(&v.INPUT_LE_G1_ADD_RANDOM, .le, &v.OUTPUT_LE_G1_ADD_RANDOM);
    try checkG1Add(&v.INPUT_BE_G1_ADD_DOUBLING, .be, &v.OUTPUT_BE_G1_ADD_DOUBLING);
    try checkG1Add(&v.INPUT_LE_G1_ADD_DOUBLING, .le, &v.OUTPUT_LE_G1_ADD_DOUBLING);
    try checkG1Add(&v.INPUT_BE_G1_ADD_P_PLUS_INF, .be, &v.OUTPUT_BE_G1_ADD_P_PLUS_INF);
    try checkG1Add(&v.INPUT_LE_G1_ADD_P_PLUS_INF, .le, &v.OUTPUT_LE_G1_ADD_P_PLUS_INF);
    try checkG1Add(&v.INPUT_BE_G1_ADD_INF_PLUS_INF, .be, &v.OUTPUT_BE_G1_ADD_INF_PLUS_INF);
    try checkG1Add(&v.INPUT_LE_G1_ADD_INF_PLUS_INF, .le, &v.OUTPUT_LE_G1_ADD_INF_PLUS_INF);
}

test "BLS G2 add: random / doubling / p+inf / inf+inf" {
    try checkG2Add(&v.INPUT_BE_G2_ADD_RANDOM, .be, &v.OUTPUT_BE_G2_ADD_RANDOM);
    try checkG2Add(&v.INPUT_LE_G2_ADD_RANDOM, .le, &v.OUTPUT_LE_G2_ADD_RANDOM);
    try checkG2Add(&v.INPUT_BE_G2_ADD_DOUBLING, .be, &v.OUTPUT_BE_G2_ADD_DOUBLING);
    try checkG2Add(&v.INPUT_LE_G2_ADD_DOUBLING, .le, &v.OUTPUT_LE_G2_ADD_DOUBLING);
    try checkG2Add(&v.INPUT_BE_G2_ADD_P_PLUS_INF, .be, &v.OUTPUT_BE_G2_ADD_P_PLUS_INF);
    try checkG2Add(&v.INPUT_LE_G2_ADD_P_PLUS_INF, .le, &v.OUTPUT_LE_G2_ADD_P_PLUS_INF);
    try checkG2Add(&v.INPUT_BE_G2_ADD_INF_PLUS_INF, .be, &v.OUTPUT_BE_G2_ADD_INF_PLUS_INF);
    try checkG2Add(&v.INPUT_LE_G2_ADD_INF_PLUS_INF, .le, &v.OUTPUT_LE_G2_ADD_INF_PLUS_INF);
}

test "BLS G1 sub: random / p-p / inf-p / p-inf" {
    try checkG1Sub(&v.INPUT_BE_G1_SUB_RANDOM, .be, &v.OUTPUT_BE_G1_SUB_RANDOM);
    try checkG1Sub(&v.INPUT_LE_G1_SUB_RANDOM, .le, &v.OUTPUT_LE_G1_SUB_RANDOM);
    try checkG1Sub(&v.INPUT_BE_G1_SUB_P_MINUS_P, .be, &v.OUTPUT_BE_G1_SUB_P_MINUS_P);
    try checkG1Sub(&v.INPUT_LE_G1_SUB_P_MINUS_P, .le, &v.OUTPUT_LE_G1_SUB_P_MINUS_P);
    try checkG1Sub(&v.INPUT_BE_G1_SUB_INF_MINUS_P, .be, &v.OUTPUT_BE_G1_SUB_INF_MINUS_P);
    try checkG1Sub(&v.INPUT_LE_G1_SUB_INF_MINUS_P, .le, &v.OUTPUT_LE_G1_SUB_INF_MINUS_P);
    try checkG1Sub(&v.INPUT_BE_G1_SUB_P_MINUS_INF, .be, &v.OUTPUT_BE_G1_SUB_P_MINUS_INF);
    try checkG1Sub(&v.INPUT_LE_G1_SUB_P_MINUS_INF, .le, &v.OUTPUT_LE_G1_SUB_P_MINUS_INF);
}

test "BLS G2 sub: random / p-p / inf-p / p-inf" {
    try checkG2Sub(&v.INPUT_BE_G2_SUB_RANDOM, .be, &v.OUTPUT_BE_G2_SUB_RANDOM);
    try checkG2Sub(&v.INPUT_LE_G2_SUB_RANDOM, .le, &v.OUTPUT_LE_G2_SUB_RANDOM);
    try checkG2Sub(&v.INPUT_BE_G2_SUB_P_MINUS_P, .be, &v.OUTPUT_BE_G2_SUB_P_MINUS_P);
    try checkG2Sub(&v.INPUT_LE_G2_SUB_P_MINUS_P, .le, &v.OUTPUT_LE_G2_SUB_P_MINUS_P);
    try checkG2Sub(&v.INPUT_BE_G2_SUB_INF_MINUS_P, .be, &v.OUTPUT_BE_G2_SUB_INF_MINUS_P);
    try checkG2Sub(&v.INPUT_LE_G2_SUB_INF_MINUS_P, .le, &v.OUTPUT_LE_G2_SUB_INF_MINUS_P);
    try checkG2Sub(&v.INPUT_BE_G2_SUB_P_MINUS_INF, .be, &v.OUTPUT_BE_G2_SUB_P_MINUS_INF);
    try checkG2Sub(&v.INPUT_LE_G2_SUB_P_MINUS_INF, .le, &v.OUTPUT_LE_G2_SUB_P_MINUS_INF);
}

// ── mul (input = [Point | Scalar(32)]) ───────────────────────────────────────

fn checkG1Mul(input: []const u8, e: E, expected: []const u8) !void {
    const point: *const [96]u8 = @ptrCast(input[0..96].ptr);
    const scalar: *const [32]u8 = @ptrCast(input[96..128].ptr);
    var out: [96]u8 = undefined;
    try testing.expect(bls.g1Mul(point, scalar, e, &out));
    try testing.expectEqualSlices(u8, expected, &out);
}
fn checkG2Mul(input: []const u8, e: E, expected: []const u8) !void {
    const point: *const [192]u8 = @ptrCast(input[0..192].ptr);
    const scalar: *const [32]u8 = @ptrCast(input[192..224].ptr);
    var out: [192]u8 = undefined;
    try testing.expect(bls.g2Mul(point, scalar, e, &out));
    try testing.expectEqualSlices(u8, expected, &out);
}

test "BLS G1 mul: random / scalar 0 / 1 / -1 / point-inf" {
    try checkG1Mul(&v.INPUT_BE_G1_MUL_RANDOM, .be, &v.OUTPUT_BE_G1_MUL_RANDOM);
    try checkG1Mul(&v.INPUT_LE_G1_MUL_RANDOM, .le, &v.OUTPUT_LE_G1_MUL_RANDOM);
    try checkG1Mul(&v.INPUT_BE_G1_MUL_SCALAR_ZERO, .be, &v.OUTPUT_BE_G1_MUL_SCALAR_ZERO);
    try checkG1Mul(&v.INPUT_LE_G1_MUL_SCALAR_ZERO, .le, &v.OUTPUT_LE_G1_MUL_SCALAR_ZERO);
    try checkG1Mul(&v.INPUT_BE_G1_MUL_SCALAR_ONE, .be, &v.OUTPUT_BE_G1_MUL_SCALAR_ONE);
    try checkG1Mul(&v.INPUT_LE_G1_MUL_SCALAR_ONE, .le, &v.OUTPUT_LE_G1_MUL_SCALAR_ONE);
    try checkG1Mul(&v.INPUT_BE_G1_MUL_SCALAR_MINUS_ONE, .be, &v.OUTPUT_BE_G1_MUL_SCALAR_MINUS_ONE);
    try checkG1Mul(&v.INPUT_LE_G1_MUL_SCALAR_MINUS_ONE, .le, &v.OUTPUT_LE_G1_MUL_SCALAR_MINUS_ONE);
    try checkG1Mul(&v.INPUT_BE_G1_MUL_POINT_INFINITY, .be, &v.OUTPUT_BE_G1_MUL_POINT_INFINITY);
    try checkG1Mul(&v.INPUT_LE_G1_MUL_POINT_INFINITY, .le, &v.OUTPUT_LE_G1_MUL_POINT_INFINITY);
}

test "BLS G2 mul: random / scalar 0 / 1 / -1 / point-inf" {
    try checkG2Mul(&v.INPUT_BE_G2_MUL_RANDOM, .be, &v.OUTPUT_BE_G2_MUL_RANDOM);
    try checkG2Mul(&v.INPUT_LE_G2_MUL_RANDOM, .le, &v.OUTPUT_LE_G2_MUL_RANDOM);
    try checkG2Mul(&v.INPUT_BE_G2_MUL_SCALAR_ZERO, .be, &v.OUTPUT_BE_G2_MUL_SCALAR_ZERO);
    try checkG2Mul(&v.INPUT_LE_G2_MUL_SCALAR_ZERO, .le, &v.OUTPUT_LE_G2_MUL_SCALAR_ZERO);
    try checkG2Mul(&v.INPUT_BE_G2_MUL_SCALAR_ONE, .be, &v.OUTPUT_BE_G2_MUL_SCALAR_ONE);
    try checkG2Mul(&v.INPUT_LE_G2_MUL_SCALAR_ONE, .le, &v.OUTPUT_LE_G2_MUL_SCALAR_ONE);
    try checkG2Mul(&v.INPUT_BE_G2_MUL_SCALAR_MINUS_ONE, .be, &v.OUTPUT_BE_G2_MUL_SCALAR_MINUS_ONE);
    try checkG2Mul(&v.INPUT_LE_G2_MUL_SCALAR_MINUS_ONE, .le, &v.OUTPUT_LE_G2_MUL_SCALAR_MINUS_ONE);
    try checkG2Mul(&v.INPUT_BE_G2_MUL_POINT_INFINITY, .be, &v.OUTPUT_BE_G2_MUL_POINT_INFINITY);
    try checkG2Mul(&v.INPUT_LE_G2_MUL_POINT_INFINITY, .le, &v.OUTPUT_LE_G2_MUL_POINT_INFINITY);
}

// ── pairing (input = [g1_points (n*96) | g2_points (n*192)]) ──────────────────

fn checkPairing(num_pairs: usize, input: []const u8, e: E, expected: []const u8) !void {
    const g1_len = num_pairs * 96;
    const g1_bytes = input[0..g1_len];
    const g2_bytes = input[g1_len .. g1_len + num_pairs * 192];
    var out: [bls.GT_SIZE]u8 = undefined;
    try testing.expect(bls.pairingMap(g1_bytes, g2_bytes, num_pairs, e, &out));
    try testing.expectEqualSlices(u8, expected, &out);
}

test "BLS pairing: identity (0 pairs) / 1 / 2 / 3 pairs / bilinearity" {
    try checkPairing(0, &v.INPUT_BE_PAIRING_IDENTITY, .be, &v.OUTPUT_BE_PAIRING_IDENTITY);
    try checkPairing(0, &v.INPUT_LE_PAIRING_IDENTITY, .le, &v.OUTPUT_LE_PAIRING_IDENTITY);
    try checkPairing(1, &v.INPUT_BE_PAIRING_ONE_PAIR, .be, &v.OUTPUT_BE_PAIRING_ONE_PAIR);
    try checkPairing(1, &v.INPUT_LE_PAIRING_ONE_PAIR, .le, &v.OUTPUT_LE_PAIRING_ONE_PAIR);
    try checkPairing(2, &v.INPUT_BE_PAIRING_TWO_PAIRS, .be, &v.OUTPUT_BE_PAIRING_TWO_PAIRS);
    try checkPairing(2, &v.INPUT_LE_PAIRING_TWO_PAIRS, .le, &v.OUTPUT_LE_PAIRING_TWO_PAIRS);
    try checkPairing(3, &v.INPUT_BE_PAIRING_THREE_PAIRS, .be, &v.OUTPUT_BE_PAIRING_THREE_PAIRS);
    try checkPairing(3, &v.INPUT_LE_PAIRING_THREE_PAIRS, .le, &v.OUTPUT_LE_PAIRING_THREE_PAIRS);
    try checkPairing(2, &v.INPUT_BE_PAIRING_BILINEARITY_IDENTITY, .be, &v.OUTPUT_BE_PAIRING_BILINEARITY_IDENTITY);
    try checkPairing(2, &v.INPUT_LE_PAIRING_BILINEARITY_IDENTITY, .le, &v.OUTPUT_LE_PAIRING_BILINEARITY_IDENTITY);
}

test "BLS pairing: >8 pairs and length-mismatch → false" {
    var dummy_g1: [9 * 96]u8 = undefined;
    var dummy_g2: [9 * 192]u8 = undefined;
    @memset(&dummy_g1, 0);
    @memset(&dummy_g2, 0);
    var out: [bls.GT_SIZE]u8 = undefined;
    try testing.expect(!bls.pairingMap(&dummy_g1, &dummy_g2, 9, .be, &out)); // >8
    try testing.expect(!bls.pairingMap(dummy_g1[0..96], dummy_g2[0..96], 1, .be, &out)); // g2 len mismatch
}
