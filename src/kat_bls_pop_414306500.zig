//! KAT: SIMD-0387 BLS12-381 proof-of-possession verification (task #49).
//! Run with: zig build test-bls-pop-414306500
//!
//! Gates the bls_pop module (src/vex_crypto/bls12_381.zig + vendored blst
//! 0.3.16) against:
//!   1. BOTH real on-chain VoterWithBLS proof-of-possessions (testnet,
//!      fetched via api.testnet.solana.com getTransaction, base64-decoded;
//!      data = [07000000][02000000][bls_pk:48][pop:96], CU 36,600):
//!        - tx 2QDtb7Dw… @414306532, vote acct BfXryoEG8XEsdi4YBpSA7iWgs2BZfVxBM6xXCnreDC8n
//!        - tx 3qqdwjWe… @414304896 (second testnet vote account)
//!   2. Firedancer cross-implementation vectors (src/ballet/bls/
//!      test_bls12_381.c:1106-1176) under AGAVE semantics — including the
//!      empty-payload vector FD itself rejects by POLICY (bound msg < 48)
//!      but Agave/solana-bls-signatures ACCEPTS (FD's comment concedes it).
//!   3. Synthetic negatives derived from the real vectors: bit-flipped pop,
//!      bit-flipped bls pubkey, wrong vote-account pubkey, identity pubkey,
//!      garbage encodings, swapped proofs between the two real accounts.
//!   4. Prover-side self-consistency: blst keygen + sign over the exact
//!      ALPENGLOW payload must verify, and must FAIL for a different vote
//!      account (domain binding) or a different keypair's pubkey.
//!
//! The instruction-level error mapping (verify-false → InstructionError.
//! InvalidArgument at the exact Agave call site) is gated separately by
//! voteforge's authorize-with-BLS KATs in
//! src/vex_svm/voteforge/kat_vote_instructions.zig (test-vote-instructions).

const std = @import("std");
const bls = @import("bls_pop");

fn unhex(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(20_000);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ── Vector 1: BfX vote account, tx 2QDtb7Dw… @414306532 ─────────────────────
const BFX_VOTE_PUBKEY = unhex("9e73d5e07cfdb3948e136e991d41b2a4cbdfac655b6bb36093d626f3f71707df"); // BfXryoEG8XEsdi4YBpSA7iWgs2BZfVxBM6xXCnreDC8n
const BFX_BLS_PUBKEY = unhex("9798349f91f0fbb947e64bd205cdf31f8fe7b6decc3a2534b22c311ab34edded4e6a860dbe0cc0450fe4296ff3884b2b");
const BFX_POP = unhex("85b8d8cbcba98565c7abad2fd889912f7fcdb6f5a308fa0858686a73ec2c4743175333564afac59943ecfd4490e9021b15b285b90685a5d6da53866caad4ab438c8aaa9fbac8376e72fa0910625c311b9d8137ef7b1e8d147fa2350805e256ff");

// ── Vector 2: second testnet vote account, tx 3qqdwjWe… @414304896 ──────────
const ACCT2_VOTE_PUBKEY = unhex("79ad56c64a9aad9cfeef71421d82eacb43217b7383970fd059657d44d6ef6924");
const ACCT2_BLS_PUBKEY = unhex("99a7703f8504ef64e2e5412242aa4f1b095e18ce81e3ed4ca38a0e27138c28a9ea20a773d70e4146a77383e8991abdb1");
const ACCT2_POP = unhex("961088f568999317a39fd0ad9a739b104cb5bf9adcfc36965f39e361aad2d1b2949e2b087b2e0dec8e0e766d3ac1fea905c65c9971e401e996cef670c704b7991ad68239c8550d26369ac50002a29308777dd9c0a1800b94a711fc4d7f10de00");

// ── Firedancer cross-vectors (test_bls12_381.c:1106-1176) ───────────────────
// FD positive test 1: bound msg = "ALPENGLOW" || 0x0123456789abcdef×4 || pk.
const FD_VOTE_PUBKEY = unhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
const FD_BLS_PUBKEY = unhex("b8778284f744f6ae2791145183ef8fcb66dcd6602da8ca1add3e6828904db482708fb1d9bd2cbeb72320cdef56d173bc");
const FD_POP = unhex("b21b2bc4933e1d2cd32e9b976cc89a98d14f45c89356bb67afab0bc48a6ff9c2d3c4d2394d68706077e5dd7596459da70227c70f2f14adbfbcf6b46ae34f970f88b49dd8185f705333f682eb27674e8abbdf21519dd01424f6993713c9e4632d");
// FD positive test 0: payload EMPTY (bound msg = the pubkey alone) — the
// classic RFC PoP. Valid under Agave semantics (FD rejects it by policy only).
const FD_EMPTY_BLS_PUBKEY = unhex("a8cf3d21aea94391b844264ca99cadd22388406ab492e1625328d7b045ce31d36d0ba7753b8821c34f8af888c16d88ab");
const FD_EMPTY_POP = unhex("913e00764fcc3e44d2f0f6bcefb7c946ad4deb3ec93adf143bd7fb111b9f57cc01b0c09b9f3934249be8ca5be6a3251c099f11709387a1877d4c270c39ee25c30951e5a6b2da9db5688244e474d6d60684195b2df361200608115ac14e74b04c");

test "REAL on-chain positive: BfX VoterWithBLS PoP @414306532 verifies" {
    try std.testing.expect(bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &BFX_BLS_PUBKEY, &BFX_POP));
}

test "REAL on-chain positive: second vote account PoP @414304896 verifies" {
    try std.testing.expect(bls.verifyVoteProofOfPossession(&ACCT2_VOTE_PUBKEY, &ACCT2_BLS_PUBKEY, &ACCT2_POP));
}

test "FD cross-vector positive: ALPENGLOW-bound PoP verifies" {
    try std.testing.expect(bls.verifyVoteProofOfPossession(&FD_VOTE_PUBKEY, &FD_BLS_PUBKEY, &FD_POP));
}

test "FD cross-vector: empty payload (RFC PoP) — Agave semantics ACCEPT" {
    // FD rejects this (bound msg < 48 policy, fd_bls12_381.c:512-524); Agave
    // accepts. Vexor must follow AGAVE. Unreachable from the vote program
    // (payload is always 41 bytes) but locks the library-level semantics.
    try std.testing.expect(bls.verifyProofOfPossession(&.{}, &FD_EMPTY_BLS_PUBKEY, &FD_EMPTY_POP));
}

test "FD cross-vector negatives: flipped payload / zeroed proof / zeroed pubkey" {
    // FD negative test 2: first payload byte flipped ("¾LPENGLOW...").
    var payload: [bls.POP_PAYLOAD_SIZE]u8 = undefined;
    @memcpy(payload[0..9], "ALPENGLOW");
    @memcpy(payload[9..41], &FD_VOTE_PUBKEY);
    payload[0] = 0xbe;
    try std.testing.expect(!bls.verifyProofOfPossession(&payload, &FD_BLS_PUBKEY, &FD_POP));
    // FD negative test 3: proof first byte zeroed (00 clears the compression
    // flag → uncompress MUST reject).
    var bad_pop = FD_POP;
    bad_pop[0] = 0x00;
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&FD_VOTE_PUBKEY, &FD_BLS_PUBKEY, &bad_pop));
    // FD negative test 4: pubkey first byte zeroed.
    var bad_pk = FD_BLS_PUBKEY;
    bad_pk[0] = 0x00;
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&FD_VOTE_PUBKEY, &bad_pk, &FD_POP));
}

test "negative: bit-flipped PoP (real vector) must fail" {
    var pop = BFX_POP;
    pop[40] ^= 0x01; // flip a bit in the middle of the x-coordinate
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &BFX_BLS_PUBKEY, &pop));
}

test "negative: bit-flipped BLS pubkey (real vector) must fail" {
    var pk = BFX_BLS_PUBKEY;
    pk[20] ^= 0x01;
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &pk, &BFX_POP));
}

test "negative: wrong vote-account pubkey (wrong-message PoP) must fail" {
    // The REAL BfX PoP presented for a DIFFERENT vote account — exactly the
    // replay-an-existing-PoP attack the ALPENGLOW||vote_pubkey binding kills.
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&ACCT2_VOTE_PUBKEY, &BFX_BLS_PUBKEY, &BFX_POP));
}

test "negative: swapped proofs between the two real accounts must fail" {
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &BFX_BLS_PUBKEY, &ACCT2_POP));
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&ACCT2_VOTE_PUBKEY, &ACCT2_BLS_PUBKEY, &BFX_POP));
}

test "negative: identity (infinity) pubkey must fail even with its canonical encoding" {
    // Compressed G1 infinity = 0xc0 || 47 zero bytes — decodes fine, then the
    // explicit identity check (solana-bls-signatures verify.rs:147-149) fires.
    var inf_pk = [_]u8{0} ** 48;
    inf_pk[0] = 0xc0;
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &inf_pk, &BFX_POP));
}

test "negative: garbage encodings must fail (uncompress reject)" {
    const ff_pk = [_]u8{0xff} ** 48;
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &ff_pk, &BFX_POP));
    const ff_pop = [_]u8{0xff} ** 96;
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &BFX_BLS_PUBKEY, &ff_pop));
    // Compression flag CLEAR on otherwise-valid bytes → reject.
    var uncomp_pk = BFX_BLS_PUBKEY;
    uncomp_pk[0] &= 0x7f;
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &uncomp_pk, &BFX_POP));
}

test "prover/verifier self-consistency + domain binding (synthetic keypair)" {
    const ikm = [_]u8{0x42} ** 32;
    const kp = bls.TestKeypair.fromIkm(&ikm);

    var payload: [bls.POP_PAYLOAD_SIZE]u8 = undefined;
    @memcpy(payload[0..9], "ALPENGLOW");
    @memcpy(payload[9..41], &BFX_VOTE_PUBKEY);
    const pop = kp.signPop(&payload);
    // Fresh PoP over the exact program payload verifies...
    try std.testing.expect(bls.verifyProofOfPossession(&payload, &kp.pubkey_compressed, &pop));
    try std.testing.expect(bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &kp.pubkey_compressed, &pop));
    // ...but NOT for a different vote account (message binding)...
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&ACCT2_VOTE_PUBKEY, &kp.pubkey_compressed, &pop));
    // ...and NOT for a different keypair's pubkey (key binding — the bound
    // message includes the pubkey, so even the same payload re-hashes).
    const kp2 = bls.TestKeypair.fromIkm(&([_]u8{0x43} ** 32));
    try std.testing.expect(!bls.verifyVoteProofOfPossession(&BFX_VOTE_PUBKEY, &kp2.pubkey_compressed, &pop));
}
