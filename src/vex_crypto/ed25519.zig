//! Vexor Ed25519 Implementation
//! @prov:crypto.ed25519
//!
//! SIMD-optimized Ed25519 signature verification.
//! Targets AVX2/AVX-512 on x86_64 and NEON on ARM.

const std = @import("std");

const builtin = @import("builtin");

/// Vexor's OWN pure-Zig ed25519 core (vendored from Sig + decoupled; see
/// ed25519/root.zig and src/vex_crypto/NOTICE). Under `-Dpure_zig` this
/// drives the drop-safe shred verify path and the sign path — a fully
/// FFI-free ed25519. The consensus verify() path below is UNCHANGED (it was
/// always std.crypto pure-Zig, never FFI).
const pure = @import("ed25519/root.zig");

/// Verify a single Ed25519 signature — CONSENSUS-PATH default (Zig stdlib, Agave/dalek-equivalent
/// acceptance criteria). Used by transaction sigverify (tx_ingest), gossip/CRDS, keypair, precompile.
///
/// 2026-07-26 CORRECTION — this comment previously said "DO NOT route this to a verify_strict
/// implementation … Agave/dalek (the cluster) ACCEPTS [what strict rejects]". **That was FACTUALLY
/// WRONG and it made us non-compliant with Agave for six weeks.** Verified from the actual crate
/// source Agave compiles against:
///     agave perf/src/sigverify.rs:51      signature.verify(pubkey.as_ref(), message)
///     solana-signature-3.4.0 lib.rs:78    publickey.verify_strict(message_bytes, &signature)
///     solana-signature-2.3.0 lib.rs:70    publickey.verify_strict(message_bytes, &signature)
/// Agave's `Signature::verify()` IS dalek `verify_strict`. Cofactored stdlib verify ACCEPTS
/// small-order-R signatures that Agave REJECTS ⇒ we executed transactions Agave invalidates ⇒
/// attacker-constructible bank_hash divergence.
///
/// On the 2026-06-15 wedge (slot 415479361) that the old comment cited: it was real, but the cause
/// was **Firedancer's `fd_ed25519_verify` C/AVX-512 FFI** (wired globally by bd3d2cd, scoped back out
/// by e484d98) — a deviation in that specific library, NOT strictness as a policy. The reductio is
/// decisive: Agave is strict and does not wedge, so every transaction in a finalized block was
/// accepted by real dalek verify_strict. `pure.verifyStrict` below is a DIFFERENT implementation
/// (pure-Zig, dalek-derived IFMA floor), differential-KAT-pinned in ed25519/kat.zig.
///
/// Note SIMD-0376 would legitimise cofactored verification (it exists because strict blocks
/// *aggregated* batch verification). It is status Review and NOT active — so strict is correct today.
/// Lane-parallel SIMD verification and per-key precomputed tables are unaffected by strictness.
pub fn verify(sig: *const [64]u8, pubkey: *const [32]u8, message: []const u8) bool {
    return pure.verifyStrict(sig, pubkey, message);
}

/// SHRED-PATH verify (perf#1, scoped 2026-06-15). Under `-Dpure_zig` this uses Vexor's own pure-Zig
/// verify_strict (AVX-512 IFMA on znver4, generic @Vector fallback) — the high-volume 8-worker shred
/// sigverify hot path. SAFE to use verify_strict here (unlike the consensus path): shred signatures are
/// leader-signed and canonical, and a rejected shred is DROP-SAFE — it just triggers FEC recovery /
/// repair and can NEVER cause a bank_hash divergence (a shred is data availability, not consensus
/// state). Falls back to stdlib otherwise.
pub fn verifyShred(sig: *const [64]u8, pubkey: *const [32]u8, message: []const u8) bool {
    switch (active_backend) {
        // Vexor's own pure-Zig verify_strict (AVX-512 IFMA on znver4, generic
        // @Vector fallback). Differential-KAT-proven byte-identical to the
        // canonical verify_strict on canonical vectors (ed25519/kat.zig).
        .pure_zig => return pure.verifyStrict(sig, pubkey, message),
        .stdlib => return verifyStdlib(sig, pubkey, message),
    }
}

/// Zig stdlib verify (Agave/dalek-equivalent). The consensus-path verifier.
fn verifyStdlib(sig: *const [64]u8, pubkey: *const [32]u8, message: []const u8) bool {
    const Ed25519 = std.crypto.sign.Ed25519;

    const signature = Ed25519.Signature.fromBytes(sig.*);
    const public_key = Ed25519.PublicKey.fromBytes(pubkey.*) catch return false;

    signature.verify(message, public_key) catch return false;
    return true;
}

// Backend selector — comptime, so the unused path is dead-stripped. The
// shred-strict-verify + sign paths route unconditionally through Vexor's OWN
// pure-Zig ed25519 core (FFI-free). `.stdlib` is retained in the enum as a
// portable fallback but is not selected. The consensus verify() path above is
// std.crypto pure-Zig directly, independent of this selector.
const Backend = enum { stdlib, pure_zig };
const active_backend: Backend = .pure_zig;

/// Sign a message.
/// secret_key is Solana format: [32-byte seed][32-byte public key]
///
/// Build-time dispatch:
/// - `-Dpure_zig`: Vexor's own pure-Zig RFC 8032 sign.
/// - default: Zig stdlib (portable, ~154µs/sign on Zen4).
pub fn sign(secret_key: [64]u8, message: []const u8) [64]u8 {
    switch (active_backend) {
        // Vexor's own pure-Zig RFC 8032 sign (KAT-proven byte-identical to
        // std.crypto sign, ed25519/root.zig test).
        .pure_zig => return pure.signPureZig(secret_key, message),
        .stdlib => return signStdlib(secret_key, message),
    }
}

/// Stdlib Zig fallback path. Used when -Dpure_zig is absent.
fn signStdlib(secret_key: [64]u8, message: []const u8) [64]u8 {
    const Ed25519 = std.crypto.sign.Ed25519;
    const seed: [32]u8 = secret_key[0..32].*;
    const key_pair = Ed25519.KeyPair.generateDeterministic(seed) catch {
        return [_]u8{0} ** 64;
    };
    const sig = key_pair.sign(message, null) catch {
        return [_]u8{0} ** 64;
    };
    return sig.toBytes();
}

/// Generate a new keypair
pub fn generateKeypair() struct { public: [32]u8, secret: [64]u8 } {
    const Ed25519 = std.crypto.sign.Ed25519;
    const key_pair = Ed25519.KeyPair.generate();
    return .{
        .public = key_pair.public_key.toBytes(),
        .secret = key_pair.secret_key.toBytes(),
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "ed25519 sign and verify" {
    const keypair = generateKeypair();
    const message = "Hello, Vexor!";

    const signature = sign(keypair.secret, message);
    const valid = verify(&signature, &keypair.public, message);

    try std.testing.expect(valid);
}

test "ed25519 verify invalid" {
    const keypair = generateKeypair();
    const message = "Hello, Vexor!";
    const wrong_message = "Wrong message";

    const signature = sign(keypair.secret, message);
    const valid = verify(&signature, &keypair.public, wrong_message);

    try std.testing.expect(!valid);
}
