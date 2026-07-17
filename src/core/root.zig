const core_types = @import("types.zig");

// core module root: re-exports the canonical scalar/key types (types.zig) plus
// the keypair/config/base58/restart_gate leaves.
// (Rebuild hygiene 2026-07-06: dropped the dangling AccountMeta re-export —
// types.zig defines no AccountMeta, the alias was never analyzable.)

pub const Pubkey = core_types.Pubkey;
pub const Hash = core_types.Hash;
pub const Epoch = core_types.Epoch;
pub const Slot = core_types.Slot;
pub const Signature = core_types.Signature;
pub const Keypair = @import("keypair.zig").Keypair;
pub const Config = @import("config.zig").Config;
pub const envFlagValueArmed = @import("config.zig").envFlagValueArmed;
pub const base58 = @import("base58.zig");
pub const restart_gate = @import("restart_gate.zig");
// Client identity single-source (2026-07-10): honest gossip client id + semver
// shared by the gossip self-advertisement and the metrics reporter.
pub const version = @import("version.zig");
