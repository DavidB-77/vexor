//! Vexor secp256r1 (NIST P-256) precompile — ECDSA-SHA256 batch signature verification.
//!
//! SIMD-0075: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0075-precompile-for-secp256r1-sigverify.md
//!
//! Algorithm: for each signature entry, verify the P-256/SHA-256 signature over
//! the message using the compressed public key, with low-S enforcement to prevent
//! signature malleability.  Maximum 8 signatures per instruction.
//!
//! @prov:crypto.secp256r1

const std = @import("std");

const P256 = std.crypto.ecc.P256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Scalar = P256.scalar.Scalar;

// ─────────────────────────────────────────────────────────────────────────────
// Program ID
// ─────────────────────────────────────────────────────────────────────────────

/// Secp256r1SigVerify1111111111111111111111111 — base58-decoded.
/// @prov:crypto.secp256r1
pub const PROGRAM_ID: [32]u8 = .{
    0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5,
    0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9, 0x03,
    0x1c, 0x83, 0xe7, 0x5f, 0xdb, 0x79, 0x5d, 0x56,
    0x8e, 0x75, 0x47, 0x80, 0x20, 0x00, 0x00, 0x00,
};

// ─────────────────────────────────────────────────────────────────────────────
// Layout constants
// @prov:crypto.secp256r1
// ─────────────────────────────────────────────────────────────────────────────

/// Byte size of one serialized SignatureOffsets entry (7 × u16 = 14 bytes).
/// @prov:crypto.secp256r1
pub const OFFSETS_SERIALIZED_SIZE: usize = 14;

/// Byte offset where the first SignatureOffsets struct begins (after count byte + padding).
/// @prov:crypto.secp256r1
pub const OFFSETS_START: usize = 2;

/// Total header size: count byte + padding byte + first offset struct.
pub const DATA_START: usize = OFFSETS_START + OFFSETS_SERIALIZED_SIZE;

/// Compact P-256 signature: 64 bytes (r=32, s=32), big-endian scalars.
/// @prov:crypto.secp256r1
pub const SIGNATURE_SIZE: usize = 64;

/// Compressed SEC1 public key: 33 bytes (0x02/0x03 prefix + 32-byte X coordinate).
/// @prov:crypto.secp256r1
pub const PUBKEY_SIZE: usize = 33;

/// Maximum signatures per instruction (SIMD-0075 constraint).
/// @prov:crypto.secp256r1
pub const MAX_SIGNATURES: usize = 8;

/// secp256r1 curve order n.
/// Used to enforce low-S: s must be ≤ (n-1)/2.
/// @prov:crypto.secp256r1
const ORDER: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
const HALF_ORDER: u256 = (ORDER - 1) / 2;

comptime {
    std.debug.assert(@sizeOf(SignatureOffsets) == OFFSETS_SERIALIZED_SIZE);
    std.debug.assert(EcdsaP256.Signature.encoded_length == SIGNATURE_SIZE);
    std.debug.assert(EcdsaP256.PublicKey.compressed_sec1_encoded_length == PUBKEY_SIZE);
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureOffsets (extern, 14 bytes)
// @prov:crypto.secp256r1
// ─────────────────────────────────────────────────────────────────────────────

/// Per-signature offset descriptor.  All fields are u16 (unlike secp256k1 which uses u8 indices).
/// A field value of std.math.maxInt(u16) means "use the current instruction's data".
/// @prov:crypto.secp256r1
pub const SignatureOffsets = extern struct {
    /// Byte offset to the compact 64-byte P-256 signature (r || s).
    sig_offset: u16 = 0,
    /// Instruction index containing the signature (maxInt(u16) = current instruction).
    sig_instr_idx: u16 = 0,
    /// Byte offset to the compressed 33-byte public key.
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
// Main verification entry point
// @prov:crypto.secp256r1
// ─────────────────────────────────────────────────────────────────────────────

/// Verify all P-256/SHA-256 signatures in a secp256r1 precompile instruction.
///
/// `data`              — current instruction's raw data bytes.
/// `all_instr_datas`   — all instruction data slices in the transaction.
///
/// Rules (@prov:crypto.secp256r1):
///   - data.len >= DATA_START
///   - 1 ≤ n_sigs ≤ 8
///   - data.len >= OFFSETS_START + n_sigs × OFFSETS_SERIALIZED_SIZE
///   - Each signature's S value must be in the low half of the curve order.
pub fn verify(
    data: []const u8,
    all_instr_datas: []const []const u8,
) PrecompileError!void {
    // @prov:crypto.secp256r1
    if (data.len < OFFSETS_START) return error.InvalidInstructionDataSize;

    const n_sigs = data[0];

    // @prov:crypto.secp256r1 — 0 sigs and >8 sigs both rejected
    if (n_sigs == 0 or n_sigs > MAX_SIGNATURES) return error.InvalidInstructionDataSize;

    const required = @as(usize, n_sigs) * OFFSETS_SERIALIZED_SIZE + OFFSETS_START;
    if (data.len < required) return error.InvalidInstructionDataSize;

    for (0..n_sigs) |i| {
        const start = OFFSETS_START + i * OFFSETS_SERIALIZED_SIZE;
        const offsets: *align(1) const SignatureOffsets = @ptrCast(data[start..].ptr);

        // Fetch the 64-byte compact P-256 signature.
        // @prov:crypto.secp256r1
        const sig_bytes = try fetchInstrData(
            data,
            all_instr_datas,
            offsets.sig_instr_idx,
            offsets.sig_offset,
            SIGNATURE_SIZE,
        );
        const signature: EcdsaP256.Signature = .fromBytes(sig_bytes[0..SIGNATURE_SIZE].*);

        // Enforce low-S to prevent signature malleability.
        // @prov:crypto.secp256r1
        const s_big: u256 = @byteSwap(@as(u256, @bitCast(signature.s)));
        if (s_big > HALF_ORDER) return error.InvalidSignature;

        // Fetch the 33-byte compressed public key.
        // @prov:crypto.secp256r1
        const pubkey_bytes = try fetchInstrData(
            data,
            all_instr_datas,
            offsets.pubkey_instr_idx,
            offsets.pubkey_offset,
            PUBKEY_SIZE,
        );
        const pubkey = EcdsaP256.PublicKey.fromSec1(pubkey_bytes) catch
            return error.InvalidSignature;

        // Fetch the message bytes.
        // @prov:crypto.secp256r1
        const msg = try fetchInstrData(
            data,
            all_instr_datas,
            offsets.msg_instr_idx,
            offsets.msg_offset,
            offsets.msg_size,
        );

        // Verify P-256/SHA-256 signature.
        // @prov:crypto.secp256r1
        signature.verify(msg, pubkey) catch return error.InvalidSignature;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction data accessor
// @prov:crypto.secp256r1
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch `len` bytes at `offset` from instruction `instr_idx`.
///
/// When `instr_idx == maxInt(u16)`, the current instruction's data (`data`) is used.
/// This is the secp256r1/ed25519 self-reference convention introduced in SIMD-0075.
/// @prov:crypto.secp256r1
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
// @prov:crypto.secp256r1
// ═══════════════════════════════════════════════════════════════════════════════

test "data too short" {
    const small: [OFFSETS_START - 1]u8 = @splat(0);
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(&small, &.{}),
    );
}

test "zero signatures rejected" {
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 0;
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(&buf, &.{}),
    );
}

test "too many signatures rejected" {
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = @intCast(MAX_SIGNATURES + 1);
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(&buf, &.{}),
    );
}

test "invalid instruction data size for offset count" {
    // 1 sig declared but buffer too small to hold the offset struct.
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1;
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(buf[0 .. buf.len - 1], &.{}),
    );
}

test "invalid signature instruction index" {
    // sig_instr_idx = 1 but only 1 instruction (index 0) in the list.
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

test "message offset out of range" {
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1;
    // msg at offset 99, size 1 — fits within 100-byte instruction
    const offsets_ok: SignatureOffsets = .{ .msg_offset = 99, .msg_size = 1 };
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets_ok));
    try std.testing.expectError(
        error.InvalidDataOffsets,
        verify(&buf, &.{&([_]u8{0} ** 100)}),
    );
}

test "round-trip: sign and verify" {
    const allocator = std.testing.allocator;
    const message = "vexor secp256r1 round-trip";

    const keypair = EcdsaP256.KeyPair.generate();
    const raw_sig = try keypair.sign(message, null);

    // Enforce low-S (SIMD-0075)
    var s = try Scalar.fromBytes(raw_sig.s, .big);
    const s_big: u256 = @byteSwap(@as(u256, @bitCast(raw_sig.s)));
    if (s_big > HALF_ORDER) s = s.neg();
    const signature: EcdsaP256.Signature = .{ .r = raw_sig.r, .s = s.toBytes(.big) };

    // Build canonical instruction layout:
    // [n_sigs(1)][pad(1)][SignatureOffsets(14)][pubkey(33)][sig(64)][message]
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
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    @memcpy(buf[pubkey_off..][0..PUBKEY_SIZE], &keypair.public_key.toCompressedSec1());
    @memcpy(buf[sig_off..][0..SIGNATURE_SIZE], &signature.toBytes());
    @memcpy(buf[msg_off..][0..message.len], message);

    try verify(buf, &.{buf});
}

test "high-S signature rejected" {
    // @prov:crypto.secp256r1 — malleability test
    const allocator = std.testing.allocator;
    const message = "vexor high-s test";

    const keypair = EcdsaP256.KeyPair.generate();
    const raw_sig = try keypair.sign(message, null);

    // Force high-S by negating — if already high, negate to make low then negate again.
    var s = try Scalar.fromBytes(raw_sig.s, .big);
    const s_big: u256 = @byteSwap(@as(u256, @bitCast(raw_sig.s)));
    // If S was low, we negate it to produce a high-S signature.
    if (s_big <= HALF_ORDER) s = s.neg();
    const bad_sig: EcdsaP256.Signature = .{ .r = raw_sig.r, .s = s.toBytes(.big) };

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
    @memcpy(buf[pubkey_off..][0..PUBKEY_SIZE], &keypair.public_key.toCompressedSec1());
    @memcpy(buf[sig_off..][0..SIGNATURE_SIZE], &bad_sig.toBytes());
    @memcpy(buf[msg_off..][0..message.len], message);

    try std.testing.expectError(
        error.InvalidSignature,
        verify(buf, &.{buf}),
    );
}
