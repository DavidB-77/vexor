// REBUILD-CLEAN (2026-07-07, module 49): origin-tree's 3 dead re-exports dropped
// from this barrel — `vote` (@import("vote.zig")), `bpf_loader`
// (@import("bpf_loader.zig")), `vote_codec` (@import("vote_codec.zig")).
// All 3 are manifest-disposed DEAD | DELETE | NONE (manifest lines
// 674/655/675) and this file is each one's SOLE importer, independently
// re-confirmed by a fresh repo-wide grep this module (not just the
// manifest's own text):
//   - vote.zig (native/, 54 LoC — NOT the unrelated vex_consensus/vote.zig,
//     a different file, CLEAN, already migrated): superseded by
//     vote_program.zig + vote_state_serde.zig; its own PROGRAM_ID is even
//     computed wrong (hash of base58 text, not the decoded id).
//   - bpf_loader.zig (native/, 614 LoC): superseded by bpf_loader_program.zig
//     (the live loader-v3 handler, still blocked on the frozen vex_bpf2
//     umbrella — see REBUILD-LEDGER module-47 row) + the vex_bpf2 executor.
//   - vote_codec.zig (1,005 LoC): superseded by vote_state_serde.zig (the
//     live Agave-shaped round-trip codec).
// No replacement re-export is added for any of the 3 — nothing live
// consumes them by that name. Zero other lines changed.
pub const system = @import("system.zig");
pub const stake_program = @import("stake_program.zig");
pub const system_v2 = @import("system_v2.zig");
pub const vote_v2 = @import("vote_v2.zig");
pub const precompiles = @import("precompiles.zig");
pub const compute_budget = @import("compute_budget"); // task #13: dedicated shared module (build.zig)
pub const nonce = @import("nonce.zig");
pub const address_lookup_table = @import("address_lookup_table.zig");
// Re-exported so the canonical top_votes chokepoint (AccountsDb.refreshTopVoteForWrite
// in vex_store/accounts.zig) can reach the vote program id + state deserializer
// through the vex_svm module without a cross-module relative @import.
pub const vote_program = @import("vote_program.zig");
pub const vote_state_serde = @import("vote_state_serde.zig");
