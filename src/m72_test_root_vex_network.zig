//! REBUILD-NATIVE force-compile gate — module 72 (§J/§K vex_network hub +
//! §E3 replay_stage full-type-surface validation).
//!
//! Rooted at src/ (top level) so it relatively OWNS no `vex_svm/*.zig` or
//! `vex_network/*.zig` file: every cross-package reference goes through the
//! NAMED module boundary (`@import("vex_network")` / `@import("vex_svm")`),
//! giving zero "file exists in multiple modules" collision against the real
//! `vex_network` (rooted at tvu.zig) and `vex_svm` (rooted at root.zig) module
//! instances that build.zig mints for this target.
//!
//! PURPOSE: the module-71 §E4 umbrella minted the `vex_svm` cycle but OMITTED
//! the `vex_network`/`vex_topo` reciprocal edges (tvu.zig was unmigrated), so
//! `replay_stage.zig` (15,547-LoC whole-file KEEP, module 71) sat migrated but
//! NEVER force-compiled — reached only lazily via the umbrella. This gate mints
//! the missing edges (tvu now present) and FORCES full type-surface analysis of:
//!   * `vex_network.TvuService`     — the tvu.zig monolith hub; @sizeOf pulls the
//!                                     full struct layout incl. its verify_tile /
//!                                     turbine_relay value/pointer fields + the
//!                                     gossip/repair/shred/replay_stage closure.
//!   * the QUIC + RPC re-exports    — tvu.zig's `pub const` seams, forced so their
//!                                     closures (quic.zig / tpu_client.zig /
//!                                     rpc_methods.zig / verify_tile.zig) type-check.
//!   * `vex_svm.replay_stage.ReplayStage` — @sizeOf forces the full field layout of
//!                                     the §E3 whole-file KEEP, so the entire
//!                                     migrated replay_stage type closure (v2_dispatch/
//!                                     executor/tx_dispatcher/block_produce/…) must
//!                                     type-check together — the real validation of
//!                                     the 15.5k-LoC §E3 migration.
//!
//! NOTE (scope of the validation): @sizeOf forces struct FIELD-LAYOUT resolution
//! (every field type's full closure), not method BODIES — those are analyzed only
//! when CALLED, which requires the replay driver (main.zig, §3.7, not yet migrated).
//! So this gate proves the type surface of the whole vex_network hub + replay_stage
//! compiles and links as one module graph; full method-body codegen arms with the
//! exe-wiring phase (§3.8).
const std = @import("std");
const vex_network = @import("vex_network");
const vex_svm = @import("vex_svm");

test "force-compile: tvu hub + replay_stage type surface" {
    // tvu.zig hub — full TvuService layout (turbine_relay value field + verify_tile
    // instance + the ?*ReplayStage tendril + gossip/repair/shred closure).
    _ = @sizeOf(vex_network.TvuService);
    // tvu.zig's `pub const` QUIC/RPC seams — force their transitive closures.
    _ = vex_network.solana_quic; // → quic.zig, tpu_client.zig
    _ = vex_network.quic_ingest_adapter; // → banking_stage / tx_ingest / compute_budget
    _ = vex_network.rpc; // → rpc_methods.zig
    _ = vex_network.rpc_methods;
    _ = vex_network.verify_tile;
    // §E3 whole-file KEEP — full struct layout forces the entire replay_stage
    // type closure to type-check.
    _ = @sizeOf(vex_svm.replay_stage.ReplayStage);
    try std.testing.expect(@sizeOf(vex_svm.replay_stage.ReplayStage) > 0);
}
