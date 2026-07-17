//! vex_crypto/core.zig — minimal hash + lthash exports
//!
//! A subset of vex_crypto/root.zig that excludes secp256k1/ed25519/secp256r1.
//! Used by the diagnostics/conformance/health test steps to avoid pulling in
//! the secp256k1 module which has a pre-existing Zig 0.15.2 compile issue.

pub const hash_mod = @import("hash.zig");
pub const lthash_mod = @import("lthash.zig");

pub const Hash = hash_mod.Hash;
pub const Pubkey = hash_mod.Pubkey;
pub const LtHash = lthash_mod.LtHash;
