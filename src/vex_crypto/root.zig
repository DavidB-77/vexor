pub const hash_mod = @import("hash.zig");
pub const lthash_mod = @import("lthash.zig");
pub const ed25519 = @import("ed25519.zig");
pub const ed25519_precompile = @import("ed25519_precompile.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const secp256r1 = @import("secp256r1.zig");
// ITEM K: BLAKE3 wrapper with comptime stdlib/Ballet AVX-512 dispatch.
// Used by bank.zig:accountLtHash (the ~3.7pp hot path).
pub const blake3 = @import("blake3.zig");
// Phase 2 (2026-06-19): BN254 (alt_bn128) group ops + compression + Poseidon
// via Firedancer ballet leaf-crypto FFI under `-Dballet_bn254`. Default
// `.unported` (no archive linked → RequiresBalletBn254 error → instant revert).
pub const bn254 = @import("bn254.zig");
// BLS12-381 syscall ops (SIMD-0388) via the vendored blst C (same as bls_pop).
// blstrs-faithful wrappers for sol_curve_* BLS arms. blst C is linked once via
// the bls_pop module in the final exe; externs here resolve at final link.
pub const bls12_381_syscall = @import("bls12_381_syscall.zig");

pub const Hash = hash_mod.Hash;
pub const Pubkey = hash_mod.Pubkey;
pub const Signature = hash_mod.Signature;
pub const LtHash = lthash_mod.LtHash;
pub const verify = ed25519.verify;
/// Shred-path AVX-512-accelerated verify (perf#1, scoped). Drop-safe; NOT for consensus tx/gossip.
pub const verifyShred = ed25519.verifyShred;
