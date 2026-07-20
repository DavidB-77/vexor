//! Twisted ElGamal encryption.
//!
//! A twisted ElGamal ciphertext is a Pedersen commitment to the plaintext plus
//! a decrypt handle binding that commitment's opening to the recipient's public
//! key: `{commitment: m·G + r·H, handle: r·pubkey}`. The plaintext is encoded as
//! a scalar, so recovering it from a decrypted point means solving discrete log
//! — practical here because the amounts this protects (token balances) fit a
//! bounded search space, unlike general ElGamal.
//!
//! CONSENSUS-CRITICAL: every value here is Ristretto255/Edwards25519 group math
//! or scalar arithmetic — correct group-law implementations are byte-identical
//! by construction, so parity with Agave's curve25519-dalek reduces entirely to
//! getting the underlying MSM right (see ed25519.zig). Allocation-free.
//!
//! https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/zk-sdk/src/encryption/elgamal.rs
//! https://spl.solana.com/assets/files/twisted_elgamal-2115c6b1e6c62a2bb4516891b8ae9ee0.pdf

const std = @import("std");
const ed25519 = @import("ed25519.zig");
const pedersen = @import("pedersen.zig");

const Ristretto255 = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;

pub const Pubkey = struct {
    point: Ristretto255,

    /// Derives the public key matching a secret scalar `s` as `s⁻¹·H`. Inverting
    /// (rather than multiplying) is what lets `DecryptHandle.init` and decryption
    /// both land on `r·s⁻¹·H` from either side without needing the secret to be public.
    pub fn fromSecret(secret: Keypair.Secret) Pubkey {
        const scalar = secret.scalar;
        std.debug.assert(!scalar.isZero());
        return .{ .point = ed25519.mul(
            true,
            pedersen.H,
            scalar.invert().toBytes(),
        ) };
    }

    pub fn fromBytes(bytes: [32]u8) !Pubkey {
        return .{ .point = try Ristretto255.fromBytes(bytes) };
    }

    pub fn toBytes(self: Pubkey) [32]u8 {
        return self.point.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Pubkey {
        const base64 = std.base64.standard;
        var buffer: [32]u8 = .{0} ** 32;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }

    pub fn rejectIdentity(self: *const Pubkey) error{IdentityElement}!void {
        try self.point.rejectIdentity();
    }
};

pub const Keypair = struct {
    secret: Secret,
    public: Pubkey,

    pub const Secret = struct {
        scalar: Scalar,

        pub fn random() Secret {
            return .{ .scalar = Scalar.random() };
        }
    };

    pub fn fromScalar(s: Scalar) Keypair {
        const secret: Secret = .{ .scalar = s };
        const public = Pubkey.fromSecret(secret);
        return .{ .secret = secret, .public = public };
    }

    /// Generates a cryptographically secure random keypair.
    pub fn random() Keypair {
        var scalar = Scalar.random();
        defer std.crypto.secureZero(u64, &scalar.limbs);
        return Keypair.fromScalar(scalar);
    }
};

pub const Ciphertext = struct {
    commitment: pedersen.Commitment,
    handle: pedersen.DecryptHandle,

    pub fn fromBytes(bytes: [64]u8) !Ciphertext {
        return .{
            .commitment = .{ .point = try Ristretto255.fromBytes(bytes[0..32].*) },
            .handle = .{ .point = try Ristretto255.fromBytes(bytes[32..64].*) },
        };
    }

    pub fn toBytes(self: Ciphertext) [64]u8 {
        return self.commitment.point.toBytes() ++ self.handle.point.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Ciphertext {
        const base64 = std.base64.standard;
        var buffer: [64]u8 = .{0} ** 64;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }

    pub fn rejectIdentity(self: *const Ciphertext) error{IdentityElement}!void {
        try self.commitment.point.rejectIdentity();
        try self.handle.point.rejectIdentity();
    }
};

/// Encrypts `value` under `pubkey` with a freshly-generated opening.
pub fn encrypt(comptime T: type, value: T, pubkey: *const Pubkey) Ciphertext {
    const commitment, const opening = pedersen.initValue(T, value);
    const handle = pedersen.DecryptHandle.init(pubkey, &opening);
    return .{
        .commitment = commitment,
        .handle = handle,
    };
}

/// Encrypts `value` under `pubkey` with a caller-supplied opening (e.g. to produce
/// a ciphertext whose commitment matches one already committed to elsewhere).
pub fn encryptWithOpening(
    comptime T: type,
    value: T,
    pubkey: *const Pubkey,
    opening: *const pedersen.Opening,
) Ciphertext {
    const commitment = pedersen.initOpening(T, value, opening);
    const handle = pedersen.DecryptHandle.init(pubkey, opening);
    return .{
        .commitment = commitment,
        .handle = handle,
    };
}

/// A single commitment shared by `N` decrypt handles — one ciphertext, readable by
/// N different keyholders (e.g. sender + recipient + auditor) without revealing the
/// amount to anyone else, since every handle binds the SAME opening to the SAME commitment.
pub fn GroupedElGamalCiphertext(comptime N: u64) type {
    return struct {
        commitment: pedersen.Commitment,
        handles: [N]pedersen.DecryptHandle,

        const Self = @This();
        pub const BYTE_LEN = (N * 32) + 32;

        pub fn encryptWithOpening(
            pubkeys: [N]Pubkey,
            amount: u64,
            opening: *const pedersen.Opening,
        ) Self {
            const commitment = pedersen.initOpening(u64, amount, opening);
            var handles: [N]pedersen.DecryptHandle = undefined;
            for (&handles, pubkeys) |*handle, public| {
                handle.* = pedersen.DecryptHandle.init(&public, opening);
            }
            return .{
                .commitment = commitment,
                .handles = handles,
            };
        }

        pub fn fromBytes(bytes: [BYTE_LEN]u8) !Self {
            var handles: [N]pedersen.DecryptHandle = undefined;
            for (&handles, 0..) |*handle, i| {
                const position = 32 + (i * 32);
                handle.* = try pedersen.DecryptHandle.fromBytes(bytes[position..][0..32].*);
            }
            return .{
                .commitment = try pedersen.Commitment.fromBytes(bytes[0..32].*),
                .handles = handles,
            };
        }

        pub fn fromBase64(string: []const u8) !Self {
            const base64 = std.base64.standard;
            var buffer: [BYTE_LEN]u8 = @splat(0);
            const decoded_length = try base64.Decoder.calcSizeForSlice(string);
            try std.base64.standard.Decoder.decode(
                buffer[0..decoded_length],
                string,
            );
            return fromBytes(buffer);
        }

        pub fn toBytes(self: Self) [BYTE_LEN]u8 {
            var handles: [N * 32]u8 = undefined;
            for (self.handles, 0..) |handle, i| {
                handles[i * 32 ..][0..32].* = handle.point.toBytes();
            }
            return self.commitment.point.toBytes() ++ handles;
        }

        pub fn rejectIdentity(self: *const Self) error{IdentityElement}!void {
            try self.commitment.rejectIdentity();
        }
    };
}
