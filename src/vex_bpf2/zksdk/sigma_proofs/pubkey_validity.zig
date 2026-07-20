//! Pubkey-validity sigma proof: proves that an ElGamal public key is
//! well-formed — i.e. that the prover knows the secret scalar `s` for which
//! `pubkey = s⁻¹·H` — without revealing `s`. This is a Schnorr-style proof of
//! knowledge of a discrete log, specialized to the inverted-secret form
//! `Pubkey.fromSecret` uses (see elgamal.zig).
//!
//! Protocol: the prover picks a random nonce `y`, commits to it as
//! `Y = y·H`, and the transcript (Fiat-Shamir) turns `y`'s random challenge
//! into a deterministic scalar `c` derived from everything committed so far
//! (the pubkey, the domain separator, and `Y` itself) — binding the proof to
//! exactly this pubkey and no other. The response `z = c·s⁻¹ + y` lets a
//! verifier, who does NOT know `s` or `y`, check the single MSM relation
//! `z·H - c·pubkey == Y` (rearranged from `z·H == Y + c·pubkey`): only someone
//! who knew `s⁻¹` could have produced a `z` satisfying this for the `c` that
//! the transcript deterministically produces, since `c` cannot be predicted
//! before `Y` is fixed.
//!
//! CONSENSUS-CRITICAL: transcript append order/domain separator and the final
//! MSM check must match Agave's `zk-sdk` bit-for-bit — see merlin.zig's file
//! header for why this can't be established by "any correct implementation
//! converges" reasoning alone.
//!
//! [fd] https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_pubkey_validity.c
//! [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/pubkey_validity.rs

const std = @import("std");
const ed25519 = @import("../ed25519.zig");
const elgamal = @import("../elgamal.zig");
const pedersen = @import("../pedersen.zig");
const merlin = @import("../merlin.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const ElGamalKeypair = elgamal.Keypair;
const ElGamalPubkey = elgamal.Pubkey;
const ProofType = @import("../zk_elgamal_types.zig").ProofType;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = merlin.Transcript;
const DomainSeperator = Transcript.DomainSeperator;

pub const Proof = struct {
    Y: Ristretto255,
    z: Scalar,

    const contract: Transcript.Contract = &.{
        .{ .label = "pubkey", .type = .validate_pubkey },
        .domain(.@"pubkey-proof"),

        .{ .label = "Y", .type = .validate_point },
        .{ .label = "c", .type = .challenge },
    };

    pub fn init(
        kp: *const ElGamalKeypair,
        transcript: *Transcript,
    ) Proof {
        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        transcript.appendNoValidate(&session, .pubkey, "pubkey", kp.public);
        transcript.appendDomSep(&session, .@"pubkey-proof");

        const s = kp.secret.scalar;
        std.debug.assert(!s.isZero());
        var s_inv = s.invert();
        defer std.crypto.secureZero(u64, &s_inv.limbs);

        var y = Scalar.random();
        defer std.crypto.secureZero(u64, &y.limbs);

        const Y = ed25519.straus.mulByKnown(pedersen.H, y.toBytes());

        transcript.appendNoValidate(&session, .point, "Y", Y);
        const c = transcript.challengeScalar(&session, "c");

        // Compute the masked secret key.
        const z = c.mul(s_inv).add(y);

        return .{
            .Y = Y,
            .z = z,
        };
    }

    pub fn verify(
        self: Proof,
        pubkey: *const ElGamalPubkey,
        transcript: *Transcript,
    ) !void {
        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        // Setup.
        // [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/pubkey_validity.rs#L102-L104
        try transcript.append(&session, .validate_pubkey, "pubkey", pubkey.*);
        transcript.appendDomSep(&session, .@"pubkey-proof");

        // Retrieve the challenge scalar.
        try transcript.append(&session, .validate_point, "Y", self.Y);
        const c = transcript.challengeScalar(&session, "c");

        //     points  scalars
        // 0   H        z
        // 1   P       -c
        // ----------------------- MSM
        //     Y

        // zig fmt: off
        const check = ed25519.mulMulti(2, .{
            pedersen.H,
            pubkey.point,
        }, .{
            self.z.toBytes(),                     //  z
            Edwards25519.scalar.neg(c.toBytes()), // -c
        });
        // zig fmt: on

        if (!self.Y.equivalent(check)) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [64]u8) !Proof {
        const Y = try Ristretto255.fromBytes(bytes[0..32].*);
        const z = Scalar.fromBytes(bytes[32..64].*);
        try Edwards25519.scalar.rejectNonCanonical(z.toBytes());
        return .{
            .Y = Y,
            .z = z,
        };
    }

    pub fn fromBase64(string: []const u8) !Proof {
        const base64 = std.base64.standard;
        var buffer: [64]u8 = .{0} ** 64;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }

    pub fn toBytes(self: Proof) [64]u8 {
        return self.Y.toBytes() ++ self.z.toBytes();
    }
};

pub const Data = struct {
    context: Context,
    proof: Proof,

    pub const TYPE: ProofType = .pubkey_validity;
    pub const BYTE_LEN = 96;
    const DOMAIN: DomainSeperator = .@"pubkey-validity-instruction";

    pub const Context = struct {
        pubkey: ElGamalPubkey,

        pub const BYTE_LEN = 32;

        pub fn fromBytes(bytes: [32]u8) !Context {
            return .{ .pubkey = try ElGamalPubkey.fromBytes(bytes[0..32].*) };
        }

        pub fn toBytes(self: Context) [32]u8 {
            return self.pubkey.toBytes();
        }
    };

    pub fn init(kp: *const ElGamalKeypair) Data {
        const context: Context = .{ .pubkey = kp.public };
        var transcript = Transcript.init(DOMAIN);
        const proof = Proof.init(kp, &transcript);
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !Data {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..32].*),
            .proof = try Proof.fromBytes(data[32..][0..64].*),
        };
    }

    pub fn toBytes(self: Data) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: Data) !void {
        var transcript = Transcript.init(DOMAIN);
        try self.proof.verify(&self.context.pubkey, &transcript);
    }

    test "correctness" {
        const kp = ElGamalKeypair.random();
        const pubkey_validity_data = Data.init(&kp);
        try pubkey_validity_data.verify();
    }
};

test "correctness" {
    const kp = ElGamalKeypair.random();

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(&kp, &prover_transcript);
    try proof.verify(&kp.public, &verifier_transcript);
}

test "incorrect pubkey" {
    const kp = ElGamalKeypair.random();
    const incorrect_kp = ElGamalKeypair.random();

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(&kp, &prover_transcript);

    try std.testing.expectError(
        error.AlgebraicRelation,
        proof.verify(&incorrect_kp.public, &verifier_transcript),
    );
}

test "proof string" {
    const pubkey_string = "lhKgvZ+xRsKTR7wfKNlpltvPZk0Pc5MfpyVlqRmDcAk=";
    const pubkey = try ElGamalPubkey.fromBase64(pubkey_string);

    // zig fmt: off
    const proof_string = "utgoLBANuVRtvN7YyZrUwz0dZL+ObsDlRpJdb6erXiQZWCtkvRbSJ8mSBKPvkahHunah80JooQWqhFQXkOCWBw==";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.initTest("test");
    try proof.verify(&pubkey, &verifier_transcript);
}
