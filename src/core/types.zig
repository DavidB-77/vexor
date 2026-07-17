//! Vexor Core Types
//!
//! Re-exports fundamental types from vex_crypto to ensure a single canonical
//! definition of Pubkey, Hash, and Signature across the entire codebase.
//! This eliminates type mismatches between modules (the core.Pubkey vs
//! types.Pubkey vs vex_crypto.Pubkey problem).

const vex_crypto = @import("vex_crypto");

// ── Canonical type re-exports (from vex_crypto) ─────────────────────────────
// ALL modules should ultimately resolve to these same types.

pub const Pubkey = vex_crypto.Pubkey;
pub const Hash = vex_crypto.Hash;
pub const Signature = vex_crypto.Signature;

// ── Solana scalar types ─────────────────────────────────────────────────────

/// Slot number (monotonically increasing)
pub const Slot = u64;

/// Epoch number
pub const Epoch = u64;

/// Lamports (1 SOL = 1_000_000_000 lamports)
pub const Lamports = u64;
