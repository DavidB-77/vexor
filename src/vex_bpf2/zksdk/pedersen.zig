//! Pedersen commitments over Ristretto255.
//!
//! A commitment is `commit(m, r) = m·G + r·H` for message scalar `m` and opening
//! (blinding) scalar `r`, where `G` and `H` are fixed, independent generators —
//! nobody knows `log_G(H)`, which is what makes the scheme both binding (can't
//! open a commitment to two different messages) and hiding (the commitment
//! alone reveals nothing about `m`). Twisted ElGamal (elgamal.zig) builds on
//! this: a ciphertext is a commitment plus a "decrypt handle" that binds the
//! same opening to a specific public key.
//!
//! CONSENSUS-CRITICAL: `G`/`H` are fixed wire constants and every combination
//! here is Ristretto255 group arithmetic — any correct implementation of that
//! arithmetic produces the byte-identical compressed encoding as Agave's
//! curve25519-dalek, so there is no room for behavioral drift as long as the
//! scalar/point math itself is correct. Allocation-free: everything here is
//! value math over fixed-size types.
//!
//! https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/zk-sdk/src/encryption/pedersen.rs

const std = @import("std");
const ed25519 = @import("ed25519.zig");
const elgamal = @import("elgamal.zig");

const Ristretto255 = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;

/// Pedersen base generator — the standard Ristretto255 basepoint, fixed by the wire protocol.
pub const G = b: {
    @setEvalBranchQuota(10_000);
    break :b Ristretto255.fromBytes(.{
        0xe2, 0xf2, 0xae, 0xa,  0x6a, 0xbc, 0x4e, 0x71,
        0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x0,  0x51, 0x5f,
        0x58, 0xe3, 0xb,  0x6a, 0xa5, 0x82, 0xdd, 0x8d,
        0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
    }) catch unreachable;
};

/// Second generator, independent of G with unknown discrete log: hash-to-ristretto
/// of SHA3-512(compressed G). Pinned as a constant rather than derived at comptime —
/// hash-to-group is far too slow to run through the compile-time evaluator.
pub const H = b: {
    @setEvalBranchQuota(10_000);
    break :b Ristretto255.fromBytes(.{
        0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
        0x65, 0xc3, 0x77, 0xa1, 0x4,  0x8d, 0x74, 0x5f,
        0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
        0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
    }) catch unreachable;
};

/// A commitment's blinding factor. Also doubles as the shared secret between a
/// commitment and every decrypt handle bound to it (same opening, different pubkey).
pub const Opening = struct {
    scalar: Scalar,

    /// Decodes a canonical (fully-reduced) scalar. Non-canonical encodings are rejected
    /// rather than silently reduced — an opening must round-trip exactly.
    pub fn fromBytes(bytes: [32]u8) !Opening {
        const scalar = Scalar.fromBytes(bytes);
        try Edwards25519.scalar.rejectNonCanonical(bytes);
        return .{ .scalar = scalar };
    }

    pub fn random() Opening {
        return .{ .scalar = .random() };
    }
};

/// `m·G + r·H` compressed to its 32-byte Ristretto255 encoding.
pub const Commitment = struct {
    point: Ristretto255,

    pub fn fromBytes(bytes: [32]u8) !Commitment {
        return .{ .point = try Ristretto255.fromBytes(bytes) };
    }

    pub fn toBytes(self: Commitment) [32]u8 {
        return self.point.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Commitment {
        const base64 = std.base64.standard;
        var buffer: [32]u8 = .{0} ** 32;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }

    pub fn rejectIdentity(self: *const Commitment) error{IdentityElement}!void {
        try self.point.rejectIdentity();
    }
};

/// Binds a commitment's opening to a specific ElGamal public key: `r·pubkey`.
/// Whoever holds the matching secret key can combine this with the commitment
/// to recover (and decrypt) the message; nobody else can, without the opening.
pub const DecryptHandle = struct {
    point: Ristretto255,

    pub fn init(pubkey: *const elgamal.Pubkey, opening: *const Opening) DecryptHandle {
        const point = ed25519.mul(true, pubkey.point, opening.scalar.toBytes());
        return .{ .point = point };
    }

    pub fn fromBytes(bytes: [32]u8) !DecryptHandle {
        return .{ .point = try Ristretto255.fromBytes(bytes) };
    }

    pub fn fromBase64(string: []const u8) !DecryptHandle {
        const base64 = std.base64.standard;
        var buffer: [32]u8 = .{0} ** 32;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }
};

/// Commits to an already-reduced scalar with a caller-supplied opening.
/// G and H are non-identity and `opening.scalar` is never required to be nonzero
/// for the MSM itself, so this can't fail — no error union needed.
pub fn init(s: Scalar, opening: *const Opening) Commitment {
    const point = ed25519.mulMulti(
        2,
        .{ G, H },
        .{ s.toBytes(), opening.scalar.toBytes() },
    );
    return .{ .point = point };
}

/// Commits to a scalar with a freshly-generated random opening.
pub fn initScalar(s: Scalar) struct { Commitment, Opening } {
    const opening = Opening.random();
    return .{ init(s, &opening), opening };
}

/// Commits to an integer value (encoded as a scalar) with a freshly-generated opening.
pub fn initValue(comptime T: type, value: T) struct { Commitment, Opening } {
    const opening = Opening.random();
    return .{ initOpening(T, value, &opening), opening };
}

/// Commits to an integer value with a caller-supplied opening.
pub fn initOpening(comptime T: type, value: T, opening: *const Opening) Commitment {
    const scalar = scalarFromInt(T, value);
    return init(scalar, opening);
}

/// Encodes an unsigned integer as a little-endian scalar, zero-extended to 32 bytes.
pub fn scalarFromInt(comptime T: type, value: T) Scalar {
    var buffer: [32]u8 = .{0} ** 32;
    std.mem.writeInt(T, buffer[0..@sizeOf(T)], value, .little);
    return Scalar.fromBytes(buffer);
}
