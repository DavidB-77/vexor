//! BLS12-381 proof-of-possession verification (SIMD-0387) — task #49.
//!
//! CANONICAL SOURCE CHAIN (see docs/BLS-POP-BEHAVIOR-TABLE-2026-06-10.md):
//!   Agave 4.1.0-beta.3 programs/vote/src/vote_state/mod.rs:1047-1063
//!     `verify_bls_proof_of_possession`
//!   → solana-bls-signatures 3.3.0 pubkey/verify.rs:24-46 (VerifyPop) +
//!     hash.rs:86-95 (`hash_bound_pop_to_projective`)
//!   → blstrs 0.7.1 g1.rs:337-340 / g2.rs (from_compressed = uncompress +
//!     on_curve + subgroup) + verify.rs:142-176 (multi-miller-loop equation)
//!   → blst 0.3.16 C (vendor/blst — byte-copied from the cargo-cached source
//!     Agave's own build links, so the SAME C code computes both verdicts).
//!
//! Co-implementation reference: Firedancer src/ballet/bls/fd_bls12_381.c
//! (`fd_bls12_381_core_verify` + `fd_bls12_381_proof_of_possession_verify`) —
//! identical blst recipe (miller_loop_n + fp12_finalverify). NOTE: FD
//! deliberately deviates from Agave by rejecting bound messages < 48 bytes;
//! Vexor follows AGAVE (the vote program's payload is always 41 bytes anyway).
//!
//! Scheme: min-pk. Pubkey = G1, 48-byte compressed. PoP signature = G2,
//! 96-byte compressed. Verification equation (verify.rs:147-176):
//!   pk != identity  AND  e(pk, H(payload || pk_bytes)) * e(-g1, proof) == 1
//! with H = hash-to-curve into G2 under POP_DST, aug = [].
//!
//! This file has NO imports beyond std so it can be the root of the shared
//! `bls_pop` named module (consumed by vex_crypto, vex_svm's legacy vote path,
//! and the sigvote transplant). The blst C objects are attached to that module
//! in build.zig and propagate to every consuming compilation.

const std = @import("std");

// ─────────────────────────────────────────────────────────────────────────────
// blst 0.3.16 extern ABI (vendor/blst/bindings/blst.h)
// ─────────────────────────────────────────────────────────────────────────────

const limb_t = u64; // x86_64: 384/8/sizeof(u64) = 6 limbs

pub const blst_fp = extern struct { l: [6]limb_t };
pub const blst_fp2 = extern struct { fp: [2]blst_fp };
pub const blst_fp6 = extern struct { fp2: [3]blst_fp2 };
pub const blst_fp12 = extern struct { fp6: [2]blst_fp6 };
pub const blst_p1 = extern struct { x: blst_fp, y: blst_fp, z: blst_fp };
pub const blst_p1_affine = extern struct { x: blst_fp, y: blst_fp };
pub const blst_p2 = extern struct { x: blst_fp2, y: blst_fp2, z: blst_fp2 };
pub const blst_p2_affine = extern struct { x: blst_fp2, y: blst_fp2 };
pub const blst_scalar = extern struct { b: [32]u8 };

/// blst.h BLST_ERROR — only SUCCESS(0) is consumed here.
const BLST_SUCCESS: c_int = 0;

extern fn blst_p1_uncompress(out: *blst_p1_affine, in: *const [48]u8) c_int;
extern fn blst_p2_uncompress(out: *blst_p2_affine, in: *const [96]u8) c_int;
extern fn blst_p1_affine_on_curve(p: *const blst_p1_affine) bool;
extern fn blst_p2_affine_on_curve(p: *const blst_p2_affine) bool;
extern fn blst_p1_affine_in_g1(p: *const blst_p1_affine) bool;
extern fn blst_p2_affine_in_g2(p: *const blst_p2_affine) bool;
extern fn blst_p1_affine_is_inf(p: *const blst_p1_affine) bool;
extern fn blst_hash_to_g2(
    out: *blst_p2,
    msg: [*]const u8,
    msg_len: usize,
    dst: [*]const u8,
    dst_len: usize,
    aug: ?[*]const u8,
    aug_len: usize,
) void;
extern fn blst_p2_to_affine(out: *blst_p2_affine, in: *const blst_p2) void;
extern fn blst_p1_to_affine(out: *blst_p1_affine, in: *const blst_p1) void;
extern fn blst_p1_generator() *const blst_p1;
extern fn blst_p1_cneg(p: *blst_p1, cbit: bool) void;
extern fn blst_miller_loop_n(
    ret: *blst_fp12,
    Qs: [*]const *const blst_p2_affine,
    Ps: [*]const *const blst_p1_affine,
    n: usize,
) void;
extern fn blst_fp12_finalverify(gt1: *const blst_fp12, gt2: *const blst_fp12) bool;
extern fn blst_fp12_one() *const blst_fp12;

// Test-vector generation helpers (synthetic positives/negatives in KATs).
extern fn blst_keygen(
    out_sk: *blst_scalar,
    ikm: [*]const u8,
    ikm_len: usize,
    info: ?[*]const u8,
    info_len: usize,
) void;
extern fn blst_sk_to_pk_in_g1(out_pk: *blst_p1, sk: *const blst_scalar) void;
extern fn blst_sign_pk_in_g1(out_sig: *blst_p2, hash: *const blst_p2, sk: *const blst_scalar) void;
extern fn blst_p1_compress(out: *[48]u8, in: *const blst_p1) void;
extern fn blst_p2_compress(out: *[96]u8, in: *const blst_p2) void;

// ─────────────────────────────────────────────────────────────────────────────
// Constants (solana-bls-signatures 3.3.0)
// ─────────────────────────────────────────────────────────────────────────────

/// proof_of_possession/mod.rs:22 — PoP hash-to-curve domain separation tag
/// (draft-irtf-cfrg-bls-signature-05 §4.2.3). Identical string in Firedancer
/// fd_bls12_381.c:437 FD_BLS_SIG_DOMAIN_POP.
pub const POP_DST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Agave mod.rs:1041 — fixed PoP payload prefix for vote-account BLS pubkeys.
pub const ALPENGLOW_LABEL = "ALPENGLOW";

pub const BLS_PUBLIC_KEY_COMPRESSED_SIZE = 48;
pub const BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE = 96;

/// Agave mod.rs:1024 POP_MESSAGE_SIZE = 9 + 32.
pub const POP_PAYLOAD_SIZE = ALPENGLOW_LABEL.len + 32;
/// payload || bls_pubkey_compressed (hash.rs:90-95 hash_bound_pop_to_projective).
pub const POP_BOUND_MESSAGE_SIZE = POP_PAYLOAD_SIZE + BLS_PUBLIC_KEY_COMPRESSED_SIZE;

// ─────────────────────────────────────────────────────────────────────────────
// Verification
// ─────────────────────────────────────────────────────────────────────────────

/// blstrs `from_compressed` for G1 (g1.rs:337-340): uncompress (validates
/// canonical field element + flag bits + on-curve) AND on_curve AND subgroup.
fn pubkeyFromCompressed(bytes: *const [48]u8) ?blst_p1_affine {
    var p: blst_p1_affine = undefined;
    if (blst_p1_uncompress(&p, bytes) != BLST_SUCCESS) return null;
    if (!blst_p1_affine_on_curve(&p)) return null;
    if (!blst_p1_affine_in_g1(&p)) return null;
    return p;
}

/// blstrs `from_compressed` for G2 (g2.rs, same shape as g1.rs:337-340).
fn proofFromCompressed(bytes: *const [96]u8) ?blst_p2_affine {
    var p: blst_p2_affine = undefined;
    if (blst_p2_uncompress(&p, bytes) != BLST_SUCCESS) return null;
    if (!blst_p2_affine_on_curve(&p)) return null;
    if (!blst_p2_affine_in_g2(&p)) return null;
    return p;
}

/// Hash-to-curve of the BOUND message (payload || pubkey_bytes) into G2 under
/// POP_DST, aug = [] — solana-bls-signatures hash.rs:86-95.
fn hashBoundPopToG2Affine(payload: []const u8, pubkey_bytes: *const [48]u8, out: *blst_p2_affine) void {
    // The crate concatenates payload||pk into one buffer; blst's `aug`
    // parameter is PREPENDED (aug||msg), so it cannot express a suffix —
    // build the concatenation explicitly. Payload here is at most
    // POP_PAYLOAD_SIZE in the vote program; allow any length via two-step
    // hashing is NOT possible (XMD is not streaming across msg), so use a
    // stack buffer for the program-sized case and a bounded buffer otherwise.
    var stack_buf: [256]u8 = undefined;
    std.debug.assert(payload.len + 48 <= stack_buf.len); // vote program: 41+48=89
    @memcpy(stack_buf[0..payload.len], payload);
    @memcpy(stack_buf[payload.len .. payload.len + 48], pubkey_bytes);
    var proj: blst_p2 = undefined;
    blst_hash_to_g2(&proj, &stack_buf, payload.len + 48, POP_DST.ptr, POP_DST.len, null, 0);
    blst_p2_to_affine(out, &proj);
}

/// Core PoP verify — EXACT mirror of solana-bls-signatures
/// pubkey/verify.rs:24-46 + :142-176 (the path Agave's
/// `verify_bls_proof_of_possession` takes for compressed byte inputs):
///   1. pubkey from_compressed (uncompress + on_curve + in_g1) else fail
///   2. proof from_compressed (uncompress + on_curve + in_g2) else fail
///   3. pubkey identity → fail
///   4. H = hash_to_g2(payload || pubkey_bytes, POP_DST, aug=[])
///   5. e(pk, H) * e(-g1, proof) final-exp == 1
/// Returns true iff the proof verifies. ANY failure mode (decode/subgroup/
/// identity/pairing) is the same single verdict, exactly like the crate's
/// BlsError → Agave's blanket `InstructionError::InvalidArgument`.
///
/// `payload` is the message WITHOUT the pubkey suffix (the crate appends the
/// pubkey bytes internally; so do we). For vote accounts use
/// `verifyVoteProofOfPossession`.
pub fn verifyProofOfPossession(
    payload: []const u8,
    bls_pubkey_compressed: *const [48]u8,
    proof_of_possession_compressed: *const [96]u8,
) bool {
    if (payload.len + 48 > 256) return false; // bound the stack buffer; vote path is 89
    const pk = pubkeyFromCompressed(bls_pubkey_compressed) orelse return false;
    const proof = proofFromCompressed(proof_of_possession_compressed) orelse return false;
    // verify.rs:147-149 — identity pubkey always fails.
    if (blst_p1_affine_is_inf(&pk)) return false;

    var hashed: blst_p2_affine = undefined;
    // NOTE: the crate appends `to_bytes_compressed()` of the DECODED point
    // (verify.rs:29-30); blst compressed encodings round-trip byte-identically
    // for every encoding `from_compressed` accepts, so appending the raw input
    // bytes is verdict-identical.
    hashBoundPopToG2Affine(payload, bls_pubkey_compressed, &hashed);

    // e(pk, H) * e(-g1, proof) — multi-miller-loop + final verify against 1.
    // Same recipe as blstrs verify.rs:162-176 and FD fd_bls12_381.c:496-505.
    var neg_g1_proj: blst_p1 = blst_p1_generator().*;
    blst_p1_cneg(&neg_g1_proj, true);
    var neg_g1: blst_p1_affine = undefined;
    blst_p1_to_affine(&neg_g1, &neg_g1_proj);

    const qs = [2]*const blst_p2_affine{ &hashed, &proof };
    const ps = [2]*const blst_p1_affine{ &pk, &neg_g1 };
    var acc: blst_fp12 = undefined;
    blst_miller_loop_n(&acc, &qs, &ps, 2);
    return blst_fp12_finalverify(&acc, blst_fp12_one());
}

/// Agave mod.rs:1026-1063 `generate_pop_message` + `verify_bls_proof_of_possession`:
/// payload = "ALPENGLOW" || vote_account_pubkey (41 bytes). CU consumption is
/// the CALLER's job (it happens before this, mod.rs:1056-1057), as is mapping
/// `false` → InstructionError.InvalidArgument (mod.rs:1058-1062).
pub fn verifyVoteProofOfPossession(
    vote_account_pubkey: *const [32]u8,
    bls_pubkey_compressed: *const [48]u8,
    proof_of_possession_compressed: *const [96]u8,
) bool {
    var payload: [POP_PAYLOAD_SIZE]u8 = undefined;
    @memcpy(payload[0..ALPENGLOW_LABEL.len], ALPENGLOW_LABEL);
    @memcpy(payload[ALPENGLOW_LABEL.len..], vote_account_pubkey);
    return verifyProofOfPossession(&payload, bls_pubkey_compressed, proof_of_possession_compressed);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT-only helpers: deterministic keygen + PoP signing (the prover side),
// used to manufacture synthetic positive/negative vectors. NOT used by the
// validator runtime.
// ─────────────────────────────────────────────────────────────────────────────

pub const TestKeypair = struct {
    sk: blst_scalar,
    pubkey_compressed: [48]u8,

    /// Deterministic keypair from an IKM seed (blst_keygen, IKM >= 32 bytes).
    pub fn fromIkm(ikm: *const [32]u8) TestKeypair {
        var kp: TestKeypair = undefined;
        blst_keygen(&kp.sk, ikm, 32, null, 0);
        var pk_proj: blst_p1 = undefined;
        blst_sk_to_pk_in_g1(&pk_proj, &kp.sk);
        blst_p1_compress(&kp.pubkey_compressed, &pk_proj);
        return kp;
    }

    /// Produce a PoP over payload||pk under POP_DST — the prover dual of
    /// `verifyProofOfPossession` (solana-bls-signatures keypair
    /// proof_of_possession with Some(payload)).
    pub fn signPop(self: *const TestKeypair, payload: []const u8) [96]u8 {
        var msg_buf: [256]u8 = undefined;
        std.debug.assert(payload.len + 48 <= msg_buf.len);
        @memcpy(msg_buf[0..payload.len], payload);
        @memcpy(msg_buf[payload.len .. payload.len + 48], &self.pubkey_compressed);
        var hashed: blst_p2 = undefined;
        blst_hash_to_g2(&hashed, &msg_buf, payload.len + 48, POP_DST.ptr, POP_DST.len, null, 0);
        var sig: blst_p2 = undefined;
        blst_sign_pk_in_g1(&sig, &hashed, &self.sk);
        var out: [96]u8 = undefined;
        blst_p2_compress(&out, &sig);
        return out;
    }
};
