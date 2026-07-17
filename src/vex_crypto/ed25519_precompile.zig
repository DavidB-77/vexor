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
// crate uses — Cargo.lock) differs from lenient `verify` in exactly one way
// that matters here: it additionally rejects a small-order signature `R`
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
/// ed25519-dalek's `verify_strict` byte-for-byte:
///   1. Non-canonical S (scalar malleability) rejected — Zig's
///      `Curve.scalar.rejectNonCanonical` inside `Signature.verify`.
///   2. Small-order/weak public key rejected — Zig's internal
///      `Edwards25519.mulDoubleBasePublic` guard inside `Signature.verify`.
///   3. Small-order signature `R` rejected — NOT covered by Zig's cofactored
///      `Signature.verify` (RFC 8032 permits it), so checked explicitly here
///      with the same `rejectLowOrder` primitive Zig uses for #2, applied to
///      the decompressed R point. This is dalek verify_strict's
///      `signature_R.is_small_order()` check (public.rs:301-303).
fn verifyEd25519Signature(
    signature: *const Ed25519.Signature,
    pubkey_bytes: *const [PUBKEY_SIZE]u8,
    msg: []const u8,
) error{InvalidSignature}!void {
    const pubkey = Ed25519.PublicKey.fromBytes(pubkey_bytes.*) catch
        return error.InvalidSignature;

    // dalek verify_strict rejects a small-order R (any of the 8-element
    // torsion subgroup) even when the cofactored equation would otherwise
    // hold. Decompress R and run the identical low-order test Zig's own
    // Edwards25519.mul* helpers use to reject weak public keys.
    const r_point = Ed25519.Curve.fromBytes(signature.r) catch
        return error.InvalidSignature;
    r_point.rejectLowOrder() catch return error.InvalidSignature;

    signature.verify(msg, pubkey) catch return error.InvalidSignature;
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
