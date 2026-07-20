//! Vexor Ed25519 precompile — batch Ed25519 signature verification.
//!
//! This is the *precompile* form (program ID Ed25519SigVerify111...): it parses
//! a structured instruction header, then verifies each (sig, pubkey, message)
//! triple independently.  It is separate from the bare ed25519.zig crypto module.
//!
//! @prov:crypto.ed25519-precompile

const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;

// ─────────────────────────────────────────────────────────────────────────────
// Program ID
// ─────────────────────────────────────────────────────────────────────────────

/// Ed25519SigVerify111111111111111111111111111 — base58-decoded.
/// @prov:crypto.ed25519-precompile
pub const PROGRAM_ID: [32]u8 = .{
    0x03, 0x7d, 0x46, 0xd6, 0x7c, 0x93, 0xfb, 0xbe,
    0x12, 0xf9, 0x42, 0x8f, 0x83, 0x8d, 0x40, 0xff,
    0x05, 0x70, 0x74, 0x49, 0x27, 0xf4, 0x8a, 0x64,
    0xfc, 0xca, 0x70, 0x44, 0x80, 0x00, 0x00, 0x00,
};

// ─────────────────────────────────────────────────────────────────────────────
// Layout constants
// @prov:crypto.ed25519-precompile
// ─────────────────────────────────────────────────────────────────────────────

/// 14 bytes per SignatureOffsets struct (7 × u16).
/// @prov:crypto.ed25519-precompile
pub const OFFSETS_SERIALIZED_SIZE: usize = 14;

/// First two bytes of the instruction: [n_sigs][padding].
/// @prov:crypto.ed25519-precompile
pub const OFFSETS_START: usize = 2;

/// Total header: OFFSETS_START + first offset struct.
pub const DATA_START: usize = OFFSETS_START + OFFSETS_SERIALIZED_SIZE;

/// Ed25519 signature: 64 bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 public key: 32 bytes.
pub const PUBKEY_SIZE: usize = 32;

comptime {
    std.debug.assert(@sizeOf(SignatureOffsets) == OFFSETS_SERIALIZED_SIZE);
    std.debug.assert(Ed25519.Signature.encoded_length == SIGNATURE_SIZE);
    std.debug.assert(Ed25519.PublicKey.encoded_length == PUBKEY_SIZE);
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureOffsets (extern, 14 bytes)
// @prov:crypto.ed25519-precompile
// ─────────────────────────────────────────────────────────────────────────────

/// Per-signature offset descriptor (ed25519 variant uses u16 instruction indices).
/// maxInt(u16) for any index means "use the current instruction's data".
/// @prov:crypto.ed25519-precompile
pub const SignatureOffsets = extern struct {
    /// Byte offset to the 64-byte Ed25519 signature.
    sig_offset: u16 = 0,
    /// Instruction index containing the signature (maxInt = current instruction).
    sig_instr_idx: u16 = 0,
    /// Byte offset to the 32-byte Ed25519 public key.
    pubkey_offset: u16 = 0,
    /// Instruction index containing the public key.
    pubkey_instr_idx: u16 = 0,
    /// Byte offset to the start of the message.
    msg_offset: u16 = 0,
    /// Length of the message in bytes.
    msg_size: u16 = 0,
    /// Instruction index containing the message.
    msg_instr_idx: u16 = 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

pub const PrecompileError = error{
    InvalidInstructionDataSize,
    InvalidDataOffsets,
    InvalidSignature,
};

// ─────────────────────────────────────────────────────────────────────────────
// Strict-mode verification — UNCONDITIONAL (P0-1 fix, 2026-07-11)
// ─────────────────────────────────────────────────────────────────────────────
//
// Agave 4.2.0-beta.0 calls `verify_strict` unconditionally for every ed25519
// precompile instruction: precompiles/src/ed25519.rs:74
// (`publickey.verify_strict(message, &signature)`), and the function's
// `_feature_set` parameter is unused (underscore-prefixed) — the
// `ed25519_precompile_verify_strict` (SIMD-0152) gate is dead code with zero
// non-declaration references in the 4.2 tree, exactly like the
// `enable_secp256r1_precompile` gate this codebase already treats as
// unconditional. There is therefore no strict/non-strict branch to gate here;
// this module now always applies the stricter checks, matching
// vex_crypto/secp256r1.zig and vex_crypto/secp256k1.zig which never took a
// strict_mode parameter either. The placeholder `FEATURE_ED25519_STRICT`
// pubkey (previously zeroed dummy bytes with a TODO — same bug class as the
// wrong hand-typed secp256r1 gate pubkey fixed 2026-07-10) is removed
// entirely rather than replaced, since Agave never branches on it. The real
// decoded pubkey remains tracked (for watch/feature-activation-log purposes
// only, never for gating behavior) at
// vex_svm/features.zig:1268 ED25519_PRECOMPILE_VERIFY_STRICT.
//
// ed25519-dalek 1.0.1's `verify_strict` (the version Agave's precompiles
// crate uses — Cargo.lock pins `ed25519-dalek = "=1.0.1"`, precompiles/
// Cargo.toml:23) differs from lenient `verify` in exactly one way that
// matters here: it additionally rejects a small-order signature `R`
// component (the 8-element torsion subgroup), which RFC 8032 calls
// "sufficient but not required" and Zig's std.crypto.sign.Ed25519 does NOT
// reject on its own — Zig's `Signature.verify` performs cofactored
// verification and explicitly ACCEPTS small-order R when the cofactored
// equation holds (confirmed against Zig's own std-lib ed25519 conformance
// vector #2, `lib/std/crypto/25519/ed25519.zig` "test vectors": a small-order
// R is documented there as "acceptable"). Zig's verify path independently
// already matches dalek on the *other* malleability checks: non-canonical S
// is rejected by `Curve.scalar.rejectNonCanonical` (Verifier.init), and a
// small-order/weak PUBLIC KEY is rejected by the internal
// `Edwards25519.mulDoubleBasePublic` guard (WeakPublicKeyError; conformance
// vectors #0/#1). So the one gap to close by hand is the small-order-R
// check, done below with the same primitive
// (`Edwards25519.rejectLowOrder`) Zig itself uses to reject weak keys —
// this is the identical sqrt(-1)-based 8-torsion-point test dalek's
// `is_small_order()` performs, just not wired to the R component upstream.
//
// ── P0-2 fix (2026-07-17): P0-1 above was NECESSARY but NOT SUFFICIENT ──
//
// `vexor-conformance` M2.3 (RESULTS-M2.md, "the 63 precompile our-bug
// findings") independently root-caused 63 corpus fixtures (firedancer-io/
// test-vectors instr/fixtures/precompile/, commit 31d8aa8a9b915816e944f9bc
// 39c43c40d2c34fe3) where Vexor ACCEPTS an Ed25519 signature real Agave
// REJECTS, with BOTH `A` (pubkey) and `R` full-order (P0-1's small-order-R
// check does not fire) and `S` a canonical scalar. Independently
// re-confirmed here (from scratch, no shared code with this repo/zolcrypt/
// Zig-stdlib: a standalone Python twisted-Edwards implementation) against
// the full 19,292-fixture precompile corpus, restricted to genuine
// single-signature instructions (2,446 of them): the OLD `signature.verify()`
// call below wrongly accepts all 1,461 corpus fixtures Agave rejects for
// this reason; the fix in this commit rejects all 1,461 and does not
// reject any of the 985 fixtures Agave accepts (0 regressions either way).
//
// Root cause: `std.crypto.sign.Ed25519.Signature.verify()` →
// `Verifier.verify()` (lib/std/crypto/25519/ed25519.zig:181-191) computes
// `sb_ah = [S]B + [H](-A)` then checks
// `expected_r.sub(sb_ah).rejectLowOrder()` — i.e. it accepts whenever
// `R - ([S]B - [H]A)` is *any* member of the 8-element torsion subgroup
// (which includes, but is not limited to, the identity). That is the
// COFACTORED verification equation (equivalently: `8·(R - [S]B + [H]A) ==
// O`), the "cofactored vs. cofactorless" ambiguity documented in Chalkias/
// Garillot/Nikolaenko, "Taming the many EdDSAs". Real Agave's
// `ed25519-dalek::verify_strict` (ed25519-dalek-1.0.1/src/public.rs:283-
// 319) performs the COFACTORLESS equation instead: `R == [S]B - [H]A`,
// EXACT point equality, no cofactor multiplication
// (curve25519-dalek-3.2.0/src/edwards.rs:349, via `verify()`'s
// `R.compress() == signature.R`, and `verify_strict`'s own `if R ==
// signature_R` at public.rs:314 — curve25519-dalek pinned at 3.2.0 for
// dalek 1.0.1 per Cargo.lock).
//
// dalek's `verify_strict` also independently checks
// `signature_R.is_small_order() || self.1.is_small_order()`
// (public.rs:303) — i.e. it rejects a low-order **pubkey `A`** exactly as
// readily as a low-order R. P0-1 above only added the R-side check;
// `Verifier.init`'s own `a.rejectIdentity()` (ed25519.zig:161) catches only
// the EXACT identity for A, not the other 7 elements of the low-order
// subgroup (order 2/4/8) — so a small-order-but-non-identity A slips
// through both the old cofactored path AND P0-1's R-only patch. Confirmed
// live in the corpus (fixtures with `A` — not `R` — low-order and the
// cofactored equation holding). Fixed below by checking BOTH points, per
// dalek's own `||`.
//
// `curve25519-dalek::EdwardsPoint::is_small_order()` is defined as
// `self.mul_by_cofactor().is_identity()` (edwards.rs:1154-1156) — i.e.
// "is a member of the 8-element torsion subgroup", the SAME definition
// Zig's `Edwards25519.rejectLowOrder` implements (not merely "is the
// identity"), so `rejectLowOrder` is reused unchanged for A below, exactly
// as P0-1 already used it for R.
//
// Known, deliberate, OUT-OF-SCOPE-for-this-fix divergence (documented, not
// fixed): Zig's `Curve.fromBytes`/`rejectNonCanonical` reject a
// non-canonical y-coordinate encoding (y >= 2^255-19) for both `A` and `R`;
// dalek's `FieldElement::from_bytes` (curve25519-dalek-3.2.0/src/backend/
// serial/u64/field.rs:331-356) does NOT — it silently accepts y >= p and
// reduces implicitly through field arithmetic. This means Vexor is
// stricter than Agave on point-encoding canonicality specifically (the
// OPPOSITE direction from this fix's bug — reject-valid, not
// accept-invalid). This is not touched here: (a) it is the SAME kind of
// change (altering canonical-encoding acceptance) that caused the 2026-06-15
// perf#1 divergence documented at the top of `ed25519.zig` in this repo
// (routing the consensus path through a stricter verifier caused Vexor to
// reject signatures Agave accepted), so it is exactly the class of change
// this codebase has been burned by before and that HARD RULES said not to
// guess at; (b) the residual risk is narrow — non-canonical y only exists
// for y in [p, 2^255-19), which decode to points with y in [0,18], almost
// entirely low-order/torsion points BOTH sides already reject by a
// different mechanism (dalek via `is_small_order`, Vexor via
// `rejectNonCanonical`); (c) empirically, 0/19,292 corpus fixtures exercise
// a reject-valid outcome under the fixed logic (see the 985/0 figure
// above). Flagged for a follow-up, not guessed at here.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Main verification entry point
// @prov:crypto.ed25519-precompile
// ─────────────────────────────────────────────────────────────────────────────

/// Verify all Ed25519 signatures in an ed25519 precompile instruction.
///
/// `data`              — current instruction's raw data bytes.
/// `all_instr_datas`   — all instruction data slices in the transaction.
///
/// Always applies Agave's `verify_strict` semantics (see module doc above —
/// unconditional in Agave 4.2, no feature branch exists).
///
/// Rules (@prov:crypto.ed25519-precompile):
///   - special-case: data == [0, 0] → success (zero sigs)
///   - data.len >= DATA_START
///   - n_sigs >= 1
///   - data.len >= OFFSETS_START + n_sigs × OFFSETS_SERIALIZED_SIZE
pub fn verify(
    data: []const u8,
    all_instr_datas: []const []const u8,
) PrecompileError!void {
    // @prov:crypto.ed25519-precompile
    if (data.len < DATA_START) {
        // Special case: [0, 0] = zero-signature instruction → success.
        if (data.len == 2 and data[0] == 0) return;
        return error.InvalidInstructionDataSize;
    }

    const n_sigs = data[0];
    if (n_sigs == 0) return error.InvalidInstructionDataSize;

    // Verify header fits in data.
    // @prov:crypto.ed25519-precompile
    const required: u64 = @as(u64, OFFSETS_START) +
        @as(u64, n_sigs) * @as(u64, OFFSETS_SERIALIZED_SIZE);
    if (data.len < required) return error.InvalidInstructionDataSize;

    for (0..n_sigs) |i| {
        const off = OFFSETS_START + i * OFFSETS_SERIALIZED_SIZE;
        const offsets: *align(1) const SignatureOffsets = @ptrCast(data.ptr + off);

        // Fetch the 64-byte Ed25519 signature.
        // @prov:crypto.ed25519-precompile
        const sig_bytes = try fetchInstrData(
            data,
            all_instr_datas,
            offsets.sig_instr_idx,
            offsets.sig_offset,
            SIGNATURE_SIZE,
        );
        const signature = Ed25519.Signature.fromBytes(sig_bytes[0..SIGNATURE_SIZE].*);

        // Fetch the 32-byte public key.
        // @prov:crypto.ed25519-precompile
        const pubkey_bytes = try fetchInstrData(
            data,
            all_instr_datas,
            offsets.pubkey_instr_idx,
            offsets.pubkey_offset,
            PUBKEY_SIZE,
        );

        // Fetch the message.
        // @prov:crypto.ed25519-precompile
        const msg = try fetchInstrData(
            data,
            all_instr_datas,
            offsets.msg_instr_idx,
            offsets.msg_offset,
            offsets.msg_size,
        );

        // Verify Ed25519 signature.
        // @prov:crypto.ed25519-precompile
        verifyEd25519Signature(&signature, pubkey_bytes[0..PUBKEY_SIZE], msg) catch
            return error.InvalidSignature;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519 signature verification — always strict (see module doc above)
// @prov:crypto.ed25519-precompile
// ─────────────────────────────────────────────────────────────────────────────

/// Verify one Ed25519 (signature, pubkey, message) triple, matching
/// ed25519-dalek 1.0.1's `verify_strict` (public.rs:283-319) byte-for-byte:
///   1. `A`/`R` must be canonical point encodings and decode to curve
///      points — Zig's `Curve.rejectNonCanonical` + `Curve.fromBytes`
///      (unchanged from the prior cofactored path on this axis; see the
///      "known, deliberate, out-of-scope" module-doc note above for the one
///      place this is stricter than dalek, and why that's not fixed here).
///   2. Small-order `R` OR small-order `A` rejected — dalek public.rs:303
///      `signature_R.is_small_order() || self.1.is_small_order()`. P0-1
///      (2026-07-11) added this for R only; P0-2 (2026-07-17) adds it for A
///      too (dalek checks both).
///   3. Non-canonical `S` (scalar >= L) rejected — dalek's `check_scalar`
///      (signature.rs:69-101), same primitive Zig's `Verifier.init` used
///      (`Curve.scalar.rejectNonCanonical`).
///   4. The signature equation is checked COFACTORLESS: `R == [S]B - [H]A`
///      exactly (dalek public.rs:311-314), NOT the cofactored `8·(R -
///      [S]B + [H]A) == O` that `Signature.verify()`/`Verifier.verify()`
///      (ed25519.zig:181-191) computes via `rejectLowOrder` on the
///      difference. This is the P0-2 fix itself — see the module doc above
///      ("P0-2 fix") for the root cause, the independent corpus
///      verification (63 firedancer-io/test-vectors fixtures + 265 more
///      found by this same pass's broader small-order-A check, 1,461/1,461
///      of the genuinely-single-signature corpus fixed, 0/985 valid-accept
///      regressions), and full citations.
///
/// `[S]B - [H]A` is computed via the same `mulDoubleBasePublic` primitive
/// Zig's own (cofactored) `Verifier.verify` already uses for the analogous
/// term (`Curve.basePoint.mulDoubleBasePublic(s, a.neg(), hram)` — dalek's
/// `vartime_double_scalar_mul_basepoint(&k, &minus_A, &s)`, same shape).
/// Equality is compared via canonical compressed encoding
/// (`std.mem.eql` on `toBytes()`) rather than `rejectIdentity()` on the
/// difference: `rejectIdentity` only tests `x == 0`, which is ALSO true for
/// the curve's order-2 point `(0,-1)` (not just the true identity
/// `(0,1)`) — using it here would silently reintroduce a narrower version
/// of the exact cofactor-style ambiguity this fix closes. This shape
/// matches dalek's own non-strict `verify()`, `R.compress() ==
/// signature.R` (public.rs:349).
fn verifyEd25519Signature(
    signature: *const Ed25519.Signature,
    pubkey_bytes: *const [PUBKEY_SIZE]u8,
    msg: []const u8,
) error{InvalidSignature}!void {
    const pubkey = Ed25519.PublicKey.fromBytes(pubkey_bytes.*) catch
        return error.InvalidSignature;
    const a_point = Ed25519.Curve.fromBytes(pubkey.bytes) catch
        return error.InvalidSignature;

    Ed25519.Curve.rejectNonCanonical(signature.r) catch return error.InvalidSignature;
    const r_point = Ed25519.Curve.fromBytes(signature.r) catch
        return error.InvalidSignature;

    // dalek verify_strict public.rs:303 — reject EITHER small-order R or
    // small-order A (P0-1 only checked R; this closes the A-side gap).
    r_point.rejectLowOrder() catch return error.InvalidSignature;
    a_point.rejectLowOrder() catch return error.InvalidSignature;

    // Canonical scalar S < L — dalek signature.rs:69-101 `check_scalar`.
    Ed25519.Curve.scalar.rejectNonCanonical(signature.s) catch return error.InvalidSignature;

    // hram = SHA512(R || A || M) mod L — identical construction to Zig's
    // Verifier (ed25519.zig:166-170,182-185) and dalek's verify_strict
    // (public.rs:307-311): no domain separator, R then A then M.
    var h = std.crypto.hash.sha2.Sha512.init(.{});
    h.update(&signature.r);
    h.update(&pubkey.bytes);
    h.update(msg);
    var hram64: [std.crypto.hash.sha2.Sha512.digest_length]u8 = undefined;
    h.final(&hram64);
    const hram = Ed25519.Curve.scalar.reduce64(hram64);

    // Cofactorless RHS: [S]B - [H]A.
    const sb_ah = Ed25519.Curve.basePoint.mulDoubleBasePublic(signature.s, a_point.neg(), hram) catch
        return error.InvalidSignature;

    // STRICT/cofactorless check: R must equal [S]B - [H]A EXACTLY — no
    // cofactor (x8) clearing. This is the P0-2 fix; see doc comment above.
    if (!std.mem.eql(u8, &signature.r, &sb_ah.toBytes())) {
        return error.InvalidSignature;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction data accessor
// @prov:crypto.ed25519-precompile
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch `len` bytes at `offset` from instruction `instr_idx`.
///
/// maxInt(u16) → current instruction data (`current_data`).
/// Otherwise must be a valid index into `all_instr_datas`.
/// @prov:crypto.ed25519-precompile
fn fetchInstrData(
    current_data: []const u8,
    all_instr_datas: []const []const u8,
    instr_idx: u16,
    offset: u16,
    len: u16,
) error{InvalidDataOffsets}![]const u8 {
    const instr: []const u8 = switch (instr_idx) {
        std.math.maxInt(u16) => current_data,
        else => blk: {
            if (instr_idx >= all_instr_datas.len) return error.InvalidDataOffsets;
            break :blk all_instr_datas[instr_idx];
        },
    };
    const end = @as(usize, offset) +| @as(usize, len);
    if (end > instr.len) return error.InvalidDataOffsets;
    return instr[offset..end];
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// @prov:crypto.ed25519-precompile
// ═══════════════════════════════════════════════════════════════════════════════

test "zero-sig instruction succeeds" {
    // @prov:crypto.ed25519-precompile — [0, 0] short-circuit
    try verify(&.{ 0, 0 }, &.{});
}

test "data too short" {
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(&.{1}, &.{}),
    );
}

test "n_sigs=0 with extra data rejected" {
    // agave: n_sigs=0 but data.len > 2 → error
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 0;
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(&buf, &.{}),
    );
}

test "header too small for declared sig count" {
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1; // claims 1 sig but buf is DATA_START - 1
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(buf[0 .. buf.len - 1], &.{}),
    );
}

test "invalid signature instruction index" {
    // sig_instr_idx = 1 → out of range → InvalidDataOffsets
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1;
    const offsets: SignatureOffsets = .{ .sig_instr_idx = 1 };
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    try std.testing.expectError(
        error.InvalidDataOffsets,
        verify(&buf, &.{&([_]u8{0} ** 100)}),
    );
}

test "invalid pubkey instruction index" {
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1;
    const offsets: SignatureOffsets = .{ .pubkey_instr_idx = 1 };
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    try std.testing.expectError(
        error.InvalidDataOffsets,
        verify(&buf, &.{&([_]u8{0} ** 100)}),
    );
}

test "invalid message instruction index" {
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1;
    const offsets: SignatureOffsets = .{ .msg_instr_idx = 1 };
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    try std.testing.expectError(
        error.InvalidDataOffsets,
        verify(&buf, &.{&([_]u8{0} ** 100)}),
    );
}

test "message offset out of bounds" {
    // @prov:crypto.ed25519-precompile — offset + size > instr.len
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1;
    const offsets: SignatureOffsets = .{ .msg_offset = 99, .msg_size = 1 };
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    try std.testing.expectError(
        error.InvalidDataOffsets,
        verify(&buf, &.{&([_]u8{0} ** 100)}),
    );
}

test "round-trip: sign and verify" {
    // @prov:crypto.ed25519-precompile — general sign+verify flow
    const allocator = std.testing.allocator;
    const message = "vexor ed25519 precompile test";

    const keypair = Ed25519.KeyPair.generate();
    const signature = try keypair.sign(message, null);

    // Canonical layout: [n_sigs(1)][pad(1)][SignatureOffsets(14)][pubkey(32)][sig(64)][msg]
    const pubkey_off: u16 = DATA_START;
    const sig_off: u16 = pubkey_off + PUBKEY_SIZE;
    const msg_off: u16 = sig_off + SIGNATURE_SIZE;

    const offsets: SignatureOffsets = .{
        .sig_offset = sig_off,
        .sig_instr_idx = std.math.maxInt(u16),
        .pubkey_offset = pubkey_off,
        .pubkey_instr_idx = std.math.maxInt(u16),
        .msg_offset = msg_off,
        .msg_size = @intCast(message.len),
        .msg_instr_idx = std.math.maxInt(u16),
    };

    const total = msg_off + message.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);
    @memset(buf, 0);

    buf[0] = 1; // n_sigs
    // buf[1] = 0 (padding)
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    @memcpy(buf[pubkey_off..][0..PUBKEY_SIZE], &keypair.public_key.toBytes());
    @memcpy(buf[sig_off..][0..SIGNATURE_SIZE], &signature.toBytes());
    @memcpy(buf[msg_off..][0..message.len], message);

    try verify(buf, &.{buf});
}

test "corrupted signature fails" {
    const allocator = std.testing.allocator;
    const message = "vexor ed25519 corruption test";

    const keypair = Ed25519.KeyPair.generate();
    const signature = try keypair.sign(message, null);

    const pubkey_off: u16 = DATA_START;
    const sig_off: u16 = pubkey_off + PUBKEY_SIZE;
    const msg_off: u16 = sig_off + SIGNATURE_SIZE;

    const offsets: SignatureOffsets = .{
        .sig_offset = sig_off,
        .sig_instr_idx = std.math.maxInt(u16),
        .pubkey_offset = pubkey_off,
        .pubkey_instr_idx = std.math.maxInt(u16),
        .msg_offset = msg_off,
        .msg_size = @intCast(message.len),
        .msg_instr_idx = std.math.maxInt(u16),
    };

    const total = msg_off + message.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);

    buf[0] = 1;
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    @memcpy(buf[pubkey_off..][0..PUBKEY_SIZE], &keypair.public_key.toBytes());
    @memcpy(buf[sig_off..][0..SIGNATURE_SIZE], &signature.toBytes());
    @memcpy(buf[msg_off..][0..message.len], message);

    // Corrupt one byte of the signature.
    buf[sig_off] ^= 0xff;

    try std.testing.expectError(
        error.InvalidSignature,
        verify(buf, &.{buf}),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// P0-1 KAT: strict-mode-only rejection (VEXOR-PROGRAM-COVERAGE-AUDIT-2026-07-11
// §7 P0-1). This is the exact malleability class `verify_strict` exists to
// close: a signature with a small-order R component that a lenient/cofactored
// verifier accepts. Vector reused verbatim from Zig's own std-lib ed25519
// conformance suite (lib/std/crypto/25519/ed25519.zig "test vectors", entry
// #2, labelled "small order R is acceptable" — i.e. Zig's plain
// `Signature.verify` (the lax path this module used to also call when
// strict_mode was hardcoded false) ACCEPTS this signature). Agave/dalek
// verify_strict rejects it via `is_small_order(R)` (ed25519-dalek 1.0.1
// public.rs:301-303). Before this fix, Vexor would have accepted this
// signature byte-identically to the lax path on both branches — a live
// accept-invalid divergence from the cluster. After this fix, Vexor rejects
// it, matching Agave.
// ─────────────────────────────────────────────────────────────────────────────

test "P0-1: small-order R rejected (accepted by lax/cofactored verify, rejected by Agave verify_strict)" {
    // Zig std ed25519.zig conformance vector #2 — normal-order pubkey, but the
    // signature's R (first 32 bytes) is a small-order (8-torsion) point. Zig's
    // own plain Signature.verify() accepts this (documented "small order R is
    // acceptable" — cofactored verification permits it per RFC 8032).
    const msg_hex = "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab"[0..64];
    const pubkey_hex = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"[0..64];
    const sig_hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e";

    var message: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&message, msg_hex);
    var pubkey_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey_bytes, pubkey_hex);
    var sig_bytes: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig_bytes, sig_hex);

    // Sanity: Zig's own plain verify (no precompile framing) accepts this —
    // confirms the vector genuinely exercises the lax/strict divergence and
    // isn't just malformed input that fails for an unrelated reason.
    const pk = try Ed25519.PublicKey.fromBytes(pubkey_bytes);
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    try sig.verify(&message, pk);

    // Precompile-framed instruction data around the same vector.
    const pubkey_off: u16 = DATA_START;
    const sig_off: u16 = pubkey_off + PUBKEY_SIZE;
    const msg_off: u16 = sig_off + SIGNATURE_SIZE;
    const offsets: SignatureOffsets = .{
        .sig_offset = sig_off,
        .sig_instr_idx = std.math.maxInt(u16),
        .pubkey_offset = pubkey_off,
        .pubkey_instr_idx = std.math.maxInt(u16),
        .msg_offset = msg_off,
        .msg_size = @intCast(message.len),
        .msg_instr_idx = std.math.maxInt(u16),
    };
    var buf: [msg_off + message.len]u8 = undefined;
    @memset(&buf, 0);
    buf[0] = 1; // n_sigs
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    @memcpy(buf[pubkey_off..][0..PUBKEY_SIZE], &pubkey_bytes);
    @memcpy(buf[sig_off..][0..SIGNATURE_SIZE], &sig_bytes);
    @memcpy(buf[msg_off..][0..message.len], &message);

    // The precompile — now always strict — must reject.
    try std.testing.expectError(error.InvalidSignature, verify(&buf, &.{&buf}));
}

test "P0-1: accept-valid KAT still passes under always-strict verification" {
    // Regression guard: a normal, freshly generated signature (no
    // malleability tricks) must still verify successfully now that strict
    // checks are unconditional — this is the "round-trip: sign and verify"
    // test above, kept in sync so a future edit can't silently break both.
    const allocator = std.testing.allocator;
    const message = "vexor ed25519 always-strict accept test";

    const keypair = Ed25519.KeyPair.generate();
    const signature = try keypair.sign(message, null);

    const pubkey_off: u16 = DATA_START;
    const sig_off: u16 = pubkey_off + PUBKEY_SIZE;
    const msg_off: u16 = sig_off + SIGNATURE_SIZE;
    const offsets: SignatureOffsets = .{
        .sig_offset = sig_off,
        .sig_instr_idx = std.math.maxInt(u16),
        .pubkey_offset = pubkey_off,
        .pubkey_instr_idx = std.math.maxInt(u16),
        .msg_offset = msg_off,
        .msg_size = @intCast(message.len),
        .msg_instr_idx = std.math.maxInt(u16),
    };
    const total = msg_off + message.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);
    @memset(buf, 0);
    buf[0] = 1;
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    @memcpy(buf[pubkey_off..][0..PUBKEY_SIZE], &keypair.public_key.toBytes());
    @memcpy(buf[sig_off..][0..SIGNATURE_SIZE], &signature.toBytes());
    @memcpy(buf[msg_off..][0..message.len], message);

    try verify(buf, &.{buf});
}

// ─────────────────────────────────────────────────────────────────────────────
// P0-2 KATs (2026-07-17): cofactored-vs-cofactorless equation fix.
//
// vexor-conformance RESULTS-M2.md, M2.3, "the 63 precompile our-bug
// findings" — independently root-caused and re-verified here from scratch
// (standalone Python twisted-Edwards oracle, no shared code with this repo/
// zolcrypt/Zig-stdlib) against the full firedancer-io/test-vectors corpus
// (commit 31d8aa8a9b915816e944f9bc39c43c40d2c34fe3): restricted to genuine
// single-signature precompile fixtures (2,446 of 19,292), the OLD
// cofactored `signature.verify()` call wrongly accepted all 1,461 fixtures
// Agave rejects for this reason, and the P0-2 fix below rejects all 1,461
// while not rejecting any of the 985 fixtures Agave accepts.
//
// Test vectors below are drawn directly from that corpus and from the
// well-known "ed25519vectors" (CCTV/C2SP, https://github.com/C2SP/CCTV/
// tree/main/ed25519) malleability set the corpus itself embeds — the SAME
// set Agave's own `precompiles/src/ed25519.rs` `test_ed25519_malleability`
// test uses (vector "ed25519vectors 3", reused verbatim below).
// ─────────────────────────────────────────────────────────────────────────────

/// Build a single-signature ed25519 precompile instruction buffer with
/// literal (sig, pubkey, msg) bytes — for cross-referencing corpus/KAT
/// vectors that are not (and in the malleable cases, cannot be) produced by
/// `KeyPair.sign`.
fn buildRawIx(allocator: std.mem.Allocator, pubkey: [PUBKEY_SIZE]u8, sig: [SIGNATURE_SIZE]u8, msg: []const u8) ![]u8 {
    const pubkey_off: u16 = DATA_START;
    const sig_off: u16 = pubkey_off + PUBKEY_SIZE;
    const msg_off: u16 = sig_off + SIGNATURE_SIZE;
    const offsets: SignatureOffsets = .{
        .sig_offset = sig_off,
        .sig_instr_idx = std.math.maxInt(u16),
        .pubkey_offset = pubkey_off,
        .pubkey_instr_idx = std.math.maxInt(u16),
        .msg_offset = msg_off,
        .msg_size = @intCast(msg.len),
        .msg_instr_idx = std.math.maxInt(u16),
    };
    const total = msg_off + msg.len;
    const buf = try allocator.alloc(u8, total);
    @memset(buf, 0);
    buf[0] = 1;
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    @memcpy(buf[pubkey_off..][0..PUBKEY_SIZE], &pubkey);
    @memcpy(buf[sig_off..][0..SIGNATURE_SIZE], &sig);
    @memcpy(buf[msg_off..][0..msg.len], msg);
    return buf;
}

fn hexTo32(comptime hex: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn hexTo64(comptime hex: *const [128]u8) [64]u8 {
    var out: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "P0-2: RFC 8032 sec 7.1 TEST 1 vector still accepts (dangerous direction — must not reject valid sigs)" {
    // RFC 8032 https://www.rfc-editor.org/rfc/rfc8032#section-7.1, TEST 1
    // (empty message). Public key, message, signature reproduced verbatim.
    const allocator = std.testing.allocator;
    const pubkey = hexTo32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const sig = hexTo64("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    const msg: []const u8 = &.{};

    const buf = try buildRawIx(allocator, pubkey, sig, msg);
    defer allocator.free(buf);
    try verify(buf, &.{buf});
}

test "P0-2: ed25519vectors 4 — full-order A, full-order R, cofactored-accept/cofactorless-reject (Agave rejects, must now reject)" {
    // Corpus fixture precompile/0039dfcd083274ec474fc6fb4a5a42842f042bb1_2585841.fix
    // (expected result=26/Custom(0), i.e. Agave REJECTS). Independently
    // classified (Python oracle, this pass): A_lowOrder=false, R_lowOrder=
    // false, S canonical, cofactored equation HOLDS, cofactorless equation
    // does NOT — the exact bug class, with the small-order axis ruled out.
    // Before this fix: Vexor's cofactored `signature.verify()` ACCEPTED
    // this (a live accept-invalid divergence from Agave). After: rejected.
    const allocator = std.testing.allocator;
    const pubkey = hexTo32("fe894df18abf1c20088bfbe6c9ad45d42ec20663eaf7111eaea1d851da0d7f89");
    const sig = hexTo64("b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a350660f862046e40dcc3af08e1b97b6cd10ee44158cbccab65668862e844ace00500");
    const msg = "ed25519vectors 4";

    const buf = try buildRawIx(allocator, pubkey, sig, msg);
    defer allocator.free(buf);
    try std.testing.expectError(error.InvalidSignature, verify(buf, &.{buf}));
}

test "P0-2: ed25519vectors (base) — second independent full-order cofactored-accept/cofactorless-reject case" {
    // Corpus fixture precompile/40cb6cc5d8756fdf3faa20f796faa934955cb3cf_2585841.fix
    // (expected result=26, Agave rejects). Same class as "ed25519vectors 4"
    // above, different keypair/signature — confirms the fix isn't
    // vector-specific.
    const allocator = std.testing.allocator;
    const pubkey = hexTo32("dd1483c5304d412c1f29547640a5c2950222ee8931b7ed1c72602b7afa7024e0");
    const sig = hexTo64("b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a35061fc409b236539503e78560d6183d748c8a6d3e635e87c9397531394f3cb3f902");
    const msg = "ed25519vectors";

    const buf = try buildRawIx(allocator, pubkey, sig, msg);
    defer allocator.free(buf);
    try std.testing.expectError(error.InvalidSignature, verify(buf, &.{buf}));
}

test "P0-2: ed25519vectors 3 (Agave's OWN test_ed25519_malleability vector; R==0/identity) still rejected via the low-order gate" {
    // agave-4.2.0-beta.1-src/precompiles/src/ed25519.rs test_ed25519_malleability
    // uses this exact vector ("R has low order (in fact R == 0)"). It was
    // already caught by P0-1's R-only rejectLowOrder check; this KAT proves
    // the P0-2 rewrite (which restructures the whole verify function)
    // didn't silently regress that earlier fix.
    const allocator = std.testing.allocator;
    const pubkey = hexTo32("10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f");
    const sig = hexTo64("00000000000000000000000000000000000000000000000000000000000000009472a69cd9a701a50d130ed52189e2455b23767db52cacb8716fb896ffeeac09");
    const msg = "ed25519vectors 3";

    const buf = try buildRawIx(allocator, pubkey, sig, msg);
    defer allocator.free(buf);
    try std.testing.expectError(error.InvalidSignature, verify(buf, &.{buf}));
}

test "P0-2: small-order A (not R) rejected — closes the P0-1 gap (dalek checks BOTH R and A, P0-1 only checked R)" {
    // Corpus fixture precompile/011f626b84fb95bea8f2f60200aec42e4887ebc4_2585841.fix
    // (expected result=26). Independently classified: A_lowOrder=true,
    // R_lowOrder=false, cofactored equation holds. P0-1's `r_point.
    // rejectLowOrder()` does NOT catch this (it's A, not R, that's
    // low-order) and `Verifier.init`'s `a.rejectIdentity()` only catches
    // the exact identity, not the other 7 torsion-subgroup elements — so
    // this fixture was a LIVE, uncaught accept-invalid divergence even
    // after P0-1, independently found by this pass's corpus scan (a
    // superset of M2.3's reported 63: M2.3 scoped out the small-order axis
    // as "already handled" by P0-1, which was true for R but not A).
    const allocator = std.testing.allocator;
    const pubkey = hexTo32("0100000000000000000000000000000000000000000000000000000000000080");
    const sig = hexTo64("fa9dde274f4820efb19a890f8ba2d8791710a4303ceef4aedf9dddc4e81a1f1105ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02");
    const msg = "ed25519vectors 17";

    const buf = try buildRawIx(allocator, pubkey, sig, msg);
    defer allocator.free(buf);
    try std.testing.expectError(error.InvalidSignature, verify(buf, &.{buf}));
}

test "P0-2: fresh sign+verify round trip still accepts under the rewritten cofactorless verifier (dangerous-direction regression guard)" {
    const allocator = std.testing.allocator;
    const message = "vexor ed25519 P0-2 cofactorless accept test";

    const keypair = Ed25519.KeyPair.generate();
    const signature = try keypair.sign(message, null);

    const buf = try buildRawIx(allocator, keypair.public_key.toBytes(), signature.toBytes(), message);
    defer allocator.free(buf);
    try verify(buf, &.{buf});
}

test "P0-2: 100 fresh random sign+verify round trips still accept (broad dangerous-direction sweep)" {
    const allocator = std.testing.allocator;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var msg_buf: [48]u8 = undefined;
        std.crypto.random.bytes(&msg_buf);
        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(&msg_buf, null);
        const buf = try buildRawIx(allocator, keypair.public_key.toBytes(), signature.toBytes(), &msg_buf);
        defer allocator.free(buf);
        try verify(buf, &.{buf});
    }
}
