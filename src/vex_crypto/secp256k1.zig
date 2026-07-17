//! Vexor secp256k1 precompile — ECDSA-Keccak256 recovery + Ethereum address verification.
//!
//! Algorithm: recover secp256k1 public key from (sig, recovery_id, message_hash),
//! derive Ethereum address (last 20 bytes of Keccak256(uncompressed_pubkey[1..])),
//! compare against expected address in instruction data.
//!
//! @prov:crypto.secp256k1

const std = @import("std");

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, Keccak256);

// ─────────────────────────────────────────────────────────────────────────────
// Program ID
// ─────────────────────────────────────────────────────────────────────────────

/// KeccakSecp256k11111111111111111111111111111 — base58-decoded.
/// @prov:crypto.secp256k1
pub const PROGRAM_ID: [32]u8 = .{
    0x04, 0xc6, 0xfc, 0x20, 0xf0, 0x50, 0xcc, 0xf0,
    0x55, 0x84, 0xd7, 0x21, 0x1c, 0x9f, 0x8c, 0xf5,
    0x9e, 0xc1, 0x47, 0x85, 0xbb, 0x16, 0x6a, 0x1e,
    0x28, 0x30, 0xe8, 0x12, 0x20, 0x00, 0x00, 0x00,
};

// ─────────────────────────────────────────────────────────────────────────────
// Layout constants
// @prov:crypto.secp256k1
// ─────────────────────────────────────────────────────────────────────────────

/// Byte size of a serialized SignatureOffsets struct.
/// @prov:crypto.secp256k1
pub const OFFSETS_SERIALIZED_SIZE: usize = 11;

/// Byte offset in instruction data where the first SignatureOffsets begins.
/// @prov:crypto.secp256k1
pub const OFFSETS_START: usize = 1;

/// Offset to the first non-header data byte (after count + all offset structs).
/// @prov:crypto.secp256k1
pub const DATA_START: usize = OFFSETS_START + OFFSETS_SERIALIZED_SIZE;

/// Compact ECDSA signature: 64 bytes (r=32, s=32).
/// @prov:crypto.secp256k1
pub const SIGNATURE_SIZE: usize = 64;

/// Ethereum address: last 20 bytes of Keccak256(uncompressed pubkey[1..]).
/// @prov:crypto.secp256k1
pub const ETH_ADDRESS_SIZE: usize = 20;

comptime {
    // SignatureOffsets wire format: u16+u8+u16+u8+u16+u16+u8 = 11 bytes = 88 bits.
    // In Zig 0.15.2 packed structs round up to the next power-of-2 byte size,
    // so @sizeOf == 16, but @bitSizeOf == 88. We assert bit-width correctness.
    // Fields are accessed through *align(1) pointer cast which reads at correct bit offsets.
    std.debug.assert(@bitSizeOf(SignatureOffsets) == OFFSETS_SERIALIZED_SIZE * 8);
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureOffsets (packed, 11 bytes)
// @prov:crypto.secp256k1
// ─────────────────────────────────────────────────────────────────────────────

/// Per-signature offset descriptor embedded in instruction data.
/// secp256k1 uniquely uses 1-byte instruction indices (u8), not u16.
/// @prov:crypto.secp256k1
pub const SignatureOffsets = packed struct {
    /// Byte offset within instruction to the 65-byte blob (sig[64] || recovery_id[1]).
    sig_offset: u16 = 0,
    /// Index of instruction whose data contains the signature blob.
    sig_instr_idx: u8 = 0,
    /// Byte offset within instruction to the 20-byte Ethereum address.
    eth_addr_offset: u16 = 0,
    /// Index of instruction whose data contains the eth address.
    eth_addr_instr_idx: u8 = 0,
    /// Byte offset within instruction to the start of the message.
    msg_offset: u16 = 0,
    /// Length of the message in bytes.
    msg_size: u16 = 0,
    /// Index of instruction whose data contains the message.
    msg_instr_idx: u8 = 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

pub const PrecompileError = error{
    InvalidInstructionDataSize,
    InvalidDataOffsets,
    InvalidRecoveryId,
    InvalidSignature,
};

// ─────────────────────────────────────────────────────────────────────────────
// Main verification entry point
// @prov:crypto.secp256k1
// ─────────────────────────────────────────────────────────────────────────────

/// Verify all secp256k1 signatures in a precompile instruction.
///
/// `data`              — the current instruction's raw data bytes.
/// `all_instr_datas`   — slice of all instruction data slices in the transaction
///                       (index 0 = instruction 0, etc.).
///
/// Returns void on success, or PrecompileError on any validation failure.
pub fn verify(
    data: []const u8,
    all_instr_datas: []const []const u8,
) PrecompileError!void {
    // @prov:crypto.secp256k1
    if (data.len < DATA_START) {
        // Special case: a single byte [0] means "zero signatures" → success.
        if (data.len == 1 and data[0] == 0) return;
        return error.InvalidInstructionDataSize;
    }

    const n_sigs = data[0];
    // agave: zero count with extra data is an error
    if (n_sigs == 0 and data.len > 1) return error.InvalidInstructionDataSize;

    // Verify there is enough room for all offset structs.
    // Use saturating arithmetic to avoid wrapping on adversarial inputs.
    const required: usize = OFFSETS_START +| (@as(usize, n_sigs) *| OFFSETS_SERIALIZED_SIZE);
    if (data.len < required) return error.InvalidInstructionDataSize;

    for (0..n_sigs) |i| {
        const off = OFFSETS_START + i * OFFSETS_SERIALIZED_SIZE;
        // Safety: @sizeOf(SignatureOffsets) == 16 in Zig 0.15.2 (packed struct rounds up to
        // next power-of-2), but only OFFSETS_SERIALIZED_SIZE (11) bytes are validated above.
        // Ensure 16 bytes are available before the ptrCast to avoid an out-of-bounds read.
        if (off + @sizeOf(SignatureOffsets) > data.len) return error.InvalidInstructionDataSize;
        const offsets: *align(1) const SignatureOffsets = @ptrCast(data.ptr + off);

        // @prov:crypto.secp256k1 — validate sig_instr_idx early
        if (offsets.sig_instr_idx >= all_instr_datas.len) {
            return error.InvalidInstructionDataSize;
        }

        // Fetch 65-byte signature blob: sig[64] || recovery_id[1]
        // @prov:crypto.secp256k1
        const sig_blob = try fetchInstrData(
            SIGNATURE_SIZE + 1,
            all_instr_datas,
            offsets.sig_instr_idx,
            offsets.sig_offset,
        );

        const recovery_id: u2 = blk: {
            const raw = sig_blob[SIGNATURE_SIZE];
            if (raw > 3) return error.InvalidRecoveryId;
            break :blk @intCast(raw);
        };
        const sig_bytes: *const [SIGNATURE_SIZE]u8 = sig_blob[0..SIGNATURE_SIZE];

        // Fetch 20-byte Ethereum address.
        // @prov:crypto.secp256k1
        const eth_addr = try fetchInstrData(
            ETH_ADDRESS_SIZE,
            all_instr_datas,
            offsets.eth_addr_instr_idx,
            offsets.eth_addr_offset,
        );

        // Fetch message bytes.
        // @prov:crypto.secp256k1
        const msg = try fetchInstrData(
            offsets.msg_size,
            all_instr_datas,
            offsets.msg_instr_idx,
            offsets.msg_offset,
        );

        // Hash the message with Keccak256.
        // @prov:crypto.secp256k1
        var msg_hash: [Keccak256.digest_length]u8 = undefined;
        Keccak256.hash(msg, &msg_hash, .{});

        // Recover public key from (signature, recovery_id, message_hash).
        // @prov:crypto.secp256k1
        const pubkey = try recoverPublicKey(&msg_hash, sig_bytes, recovery_id);

        // Derive Ethereum address and compare.
        // @prov:crypto.secp256k1
        const recovered_addr = ethereumAddress(&pubkey);
        if (!std.mem.eql(u8, eth_addr, &recovered_addr)) {
            return error.InvalidSignature;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public key recovery — pure Zig ECDSA recovery over secp256k1
// @prov:crypto.secp256k1
//
// Algorithm (bitcoin/secp256k1 recovery_impl.h equivalent):
//   Given: compact sig (r, s), recovery_id, message hash z
//   1. Reconstruct curve point R from x-coordinate r and parity (recovery_id & 1).
//      If recovery_id & 2: add curve order n to r before recovering R.
//   2. Compute public key: Q = r^-1 * (s*R - z*G)
//      i.e. Q = r^-1*s*R + r^-1*(-z)*G  via mulDoubleBasePublic
//   3. Reject identity point.
// ─────────────────────────────────────────────────────────────────────────────

/// secp256k1 curve order n (big-endian).
/// Used for recovery_id & 2 path: add n to r to get a second candidate x.
/// @prov:crypto.secp256k1
const SECP256K1_N: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

/// secp256k1 field prime p.
/// @prov:crypto.secp256k1 — p_minus_n comparison: if rs >= p-n, reject for recovery_id & 2
const SECP256K1_P: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
};

/// Recover an uncompressed secp256k1 public key from a compact signature.
///
/// `msg_hash`    — 32-byte Keccak256 digest of the signed message.
/// `sig_bytes`   — 64-byte compact signature (r[32] || s[32]), big-endian.
/// `recovery_id` — 0–3: bit 0 = Y parity, bit 1 = use r + n as x-coordinate.
///
/// Pure Zig implementation; no external C library required.
/// Algorithm mirrors bitcoin-core secp256k1 recovery. @prov:crypto.secp256k1
pub fn recoverPublicKey(
    msg_hash: *const [32]u8,
    sig_bytes: *const [SIGNATURE_SIZE]u8,
    recovery_id: u2,
) error{InvalidSignature}!Ecdsa.PublicKey {
    const scalar = Secp256k1.scalar;

    // Validate r and s are non-zero canonical scalars.
    // @prov:crypto.secp256k1
    const r_bytes: [32]u8 = sig_bytes[0..32].*;
    const s_bytes: [32]u8 = sig_bytes[32..64].*;
    scalar.rejectNonCanonical(r_bytes, .big) catch return error.InvalidSignature;
    scalar.rejectNonCanonical(s_bytes, .big) catch return error.InvalidSignature;

    // Reconstruct x-coordinate from r.
    // If recovery_id & 2: x = r + n; validate x < p first.
    // @prov:crypto.secp256k1
    var x_bytes = r_bytes;
    if (recovery_id & 2 != 0) {
        // Check r + n < p to ensure valid x-coordinate.
        // We do big-integer addition: x = r + n (mod p field — just add and check).
        var carry: u16 = 0;
        var i: usize = 31;
        while (true) : (i -= 1) {
            const sum = @as(u16, r_bytes[i]) + @as(u16, SECP256K1_N[i]) + carry;
            x_bytes[i] = @truncate(sum);
            carry = sum >> 8;
            if (i == 0) break;
        }
        // If carry != 0 or x_bytes >= p, the x-coordinate is invalid.
        if (carry != 0) return error.InvalidSignature;
        if (cmpBytes(&x_bytes, &SECP256K1_P) >= 0) return error.InvalidSignature;
    }

    // Recover the curve point R = (x, y) where y has parity (recovery_id & 1).
    // @prov:crypto.secp256k1
    const x_fe = Secp256k1.Fe.fromBytes(x_bytes, .big) catch return error.InvalidSignature;
    const is_odd = (recovery_id & 1) != 0;
    const y_fe = Secp256k1.recoverY(x_fe, is_odd) catch return error.InvalidSignature;
    const R = Secp256k1.fromAffineCoordinates(.{ .x = x_fe, .y = y_fe }) catch
        return error.InvalidSignature;

    // Reduce message hash modulo curve order.
    // @prov:crypto.secp256k1 — message scalar is unconditionally reduced
    // Use reduce64: pass hash in the low 32 bytes of a 64-byte big-endian integer (high 32 = 0).
    var z_pad: [64]u8 = @splat(0);
    @memcpy(z_pad[32..64], msg_hash);
    const z = scalar.reduce64(z_pad, .big);

    // Compute r^-1 in the scalar field.
    // @prov:crypto.secp256k1
    const r_scalar = scalar.Scalar.fromBytes(r_bytes, .big) catch return error.InvalidSignature;
    const r_inv = r_scalar.invert();
    if (r_inv.isZero()) return error.InvalidSignature;
    const r_inv_bytes = r_inv.toBytes(.big);

    // u1 = r^-1 * (-z)  — multiplier for the base point G
    // u2 = r^-1 * s     — multiplier for the recovered point R
    // @prov:crypto.secp256k1
    const neg_z = scalar.neg(z, .big) catch return error.InvalidSignature;
    const scalar_u1 = scalar.mul(r_inv_bytes, neg_z, .big) catch return error.InvalidSignature;
    const scalar_u2 = scalar.mul(r_inv_bytes, s_bytes, .big) catch return error.InvalidSignature;

    // Q = u1*G + u2*R — Shamir's trick double-base scalar multiplication.
    // @prov:crypto.secp256k1
    const Q = Secp256k1.mulDoubleBasePublic(Secp256k1.basePoint, scalar_u1, R, scalar_u2, .big) catch
        return error.InvalidSignature;

    // Reject identity (point at infinity).
    // @prov:crypto.secp256k1
    Q.rejectIdentity() catch return error.InvalidSignature;

    // Serialize Q as uncompressed SEC1 (0x04 || X || Y) and wrap as PublicKey.
    // @prov:crypto.secp256k1
    const uncompressed = Q.toUncompressedSec1();
    return Ecdsa.PublicKey.fromSec1(&uncompressed) catch return error.InvalidSignature;
}

/// Compare two 32-byte big-endian integers.
/// Returns a negative value if a < b, 0 if equal, positive if a > b.
fn cmpBytes(a: *const [32]u8, b: *const [32]u8) i8 {
    for (a, b) |ab, bb| {
        if (ab < bb) return -1;
        if (ab > bb) return 1;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Ethereum address derivation
// @prov:crypto.secp256k1
// ─────────────────────────────────────────────────────────────────────────────

/// Derive the Ethereum address from an uncompressed secp256k1 public key.
///
/// Address = last 20 bytes of Keccak256(uncompressed_pubkey[1..]).
/// The leading 0x04 prefix byte is stripped before hashing.
pub fn ethereumAddress(pubkey: *const Ecdsa.PublicKey) [ETH_ADDRESS_SIZE]u8 {
    const uncompressed = pubkey.toUncompressedSec1(); // 65 bytes: 0x04 || X || Y
    var digest: [Keccak256.digest_length]u8 = undefined;
    Keccak256.hash(uncompressed[1..], &digest, .{}); // skip the 0x04 tag byte
    return digest[12..32].*; // last 20 bytes
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction data accessor
// @prov:crypto.secp256k1
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch `len` bytes starting at `offset` from instruction `idx`.
///
/// For secp256k1, instruction indices are raw u8 values (no maxInt sentinel).
/// @prov:crypto.secp256k1 — secp256k1 does NOT support the self-reference trick;
/// invalid index → InvalidDataOffsets (distinct from the sig validation path).
fn fetchInstrData(
    len: usize,
    all_instr_datas: []const []const u8,
    instr_idx: u8,
    offset: u16,
) error{ InvalidDataOffsets, InvalidSignature }![]const u8 {
    if (instr_idx >= all_instr_datas.len) return error.InvalidDataOffsets;
    const instr = all_instr_datas[instr_idx];
    const end = @as(usize, offset) +| len;
    if (end > instr.len) return error.InvalidSignature;
    return instr[offset..end];
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

test "empty instruction — zero sig byte succeeds" {
    // @prov:crypto.secp256k1
    try verify(&.{0}, &.{});
}

test "too-short instruction data" {
    // @prov:crypto.secp256k1
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(&.{}, &.{&([_]u8{0} ** 100)}),
    );
    // n_sigs=1 but no room for offset struct
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(&.{1}, &.{&([_]u8{0} ** 100)}),
    );
}

test "zero sigs with trailing data" {
    // @prov:crypto.secp256k1 — zero count but data.len > 1 → error
    var buf: [DATA_START]u8 = undefined;
    buf[0] = 0; // n_sigs = 0
    @memset(buf[1..], 0);
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(buf[0 .. buf.len - 1], &.{&([_]u8{0} ** 100)}),
    );
}

test "invalid sig instruction index" {
    // @prov:crypto.secp256k1
    // sig_instr_idx points beyond the transaction's instruction list.
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1; // n_sigs = 1
    // SignatureOffsets at offset 1; sig_instr_idx is the 3rd byte (offset 3).
    const offsets: SignatureOffsets = .{ .sig_instr_idx = 1 }; // instr 1 does not exist
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    try std.testing.expectError(
        error.InvalidInstructionDataSize,
        verify(&buf, &.{&([_]u8{0} ** 100)}),
    );
}

test "invalid eth address instruction index" {
    // eth_addr_instr_idx = 1 → InvalidDataOffsets (only 1 instruction in list)
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1;
    const offsets: SignatureOffsets = .{ .eth_addr_instr_idx = 1 };
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    try std.testing.expectError(
        error.InvalidDataOffsets,
        verify(&buf, &.{&([_]u8{0} ** 100)}),
    );
}

test "invalid message instruction index" {
    // msg_instr_idx = 1 → InvalidDataOffsets
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
    // @prov:crypto.secp256k1
    var buf: [DATA_START]u8 = @splat(0);
    buf[0] = 1;
    const offsets: SignatureOffsets = .{ .msg_offset = 99, .msg_size = 1 };
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    try std.testing.expectError(
        error.InvalidSignature,
        verify(&buf, &.{&([_]u8{0} ** 100)}),
    );
}

test "full round-trip: sign, encode, verify" {
    // @prov:crypto.secp256k1
    const allocator = std.testing.allocator;

    const keypair = Ecdsa.KeyPair.generate();
    const message = "vexor secp256k1 test";

    var msg_hash: [Keccak256.digest_length]u8 = undefined;
    Keccak256.hash(message, &msg_hash, .{});

    const eth_addr = ethereumAddress(&keypair.public_key);

    // Build instruction data in the canonical layout.
    // Layout: [n_sigs(1)] [SignatureOffsets(11)] [eth_addr(20)] [sig(64)] [rec_id(1)] [msg]
    const eth_off: u16 = DATA_START;
    const sig_off: u16 = eth_off + ETH_ADDRESS_SIZE;
    const msg_off: u16 = sig_off + SIGNATURE_SIZE + 1;

    const offsets: SignatureOffsets = .{
        .sig_offset = sig_off,
        .sig_instr_idx = 0,
        .eth_addr_offset = eth_off,
        .eth_addr_instr_idx = 0,
        .msg_offset = msg_off,
        .msg_size = @intCast(message.len),
        .msg_instr_idx = 0,
    };

    const total = msg_off + message.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);
    @memset(buf, 0);

    buf[0] = 1; // n_sigs
    @memcpy(buf[OFFSETS_START..][0..OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    @memcpy(buf[eth_off..][0..ETH_ADDRESS_SIZE], &eth_addr);

    // Sign the pre-hashed message (msg_hash was already computed above).
    // Use signPrehashed so we don't double-hash.
    const signature = try keypair.signPrehashed(msg_hash, null);
    const sig_bytes = signature.toBytes();
    @memcpy(buf[sig_off..][0..SIGNATURE_SIZE], &sig_bytes);

    // Recover the signature to determine the correct recovery_id.
    var rec_id: u2 = 0;
    for (0..4) |candidate| {
        const r: u2 = @intCast(candidate);
        if (recoverPublicKey(&msg_hash, &sig_bytes, r)) |recovered| {
            if (std.mem.eql(u8, &recovered.toUncompressedSec1(), &keypair.public_key.toUncompressedSec1())) {
                rec_id = r;
                break;
            }
        } else |_| {}
    }
    buf[sig_off + SIGNATURE_SIZE] = rec_id;
    @memcpy(buf[msg_off..][0..message.len], message);

    try verify(buf, &.{buf});
}
