//! module 69/70 (§E1+E2) test root for the replay_stage.zig LEAF + SECOND-TIER
//! sibling batch. Lives at src/vex_svm/ (module-root dir = src/vex_svm/) so every
//! sibling's RELATIVE imports (`types.zig`, `features.zig`, `bank.zig`,
//! `hashes.zig`, `gossip_votes.zig`, `native/vote_program.zig`,
//! `native/vote_state_serde.zig`, `native/epoch_schedule.zig`,
//! `native/system_v2.zig`, …) resolve WITHIN the subtree, exactly as they do
//! inside fix105's `vex_svm` module (rooted at src/vex_svm/root.zig). Rooting a
//! test at any single leaf would either escape `../` imports or miss the batch.
//! Rebuild-native discovery shim — module-63 m9_test_root / module-68
//! m68_test_root precedent — NATIVE class in drift-baseline (no upstream).
//!
//! These 15 files sit DEAD (uncalled) in the tree until replay_stage.zig (§E3)
//! and the vex_svm umbrella (§E4) land — none has a standalone fix105 build.zig
//! target (their real gates — test-core-bpf-stake-poc / test-vex-bpf2-v2-dispatch
//! / test-cpi-carrier-dispatch — all `@import("vex_svm")`, the §E umbrella, and
//! stay blocked until E4). So this ad-hoc discovery gate is their proof-of-
//! compile + inline-test run, both Debug and ReleaseSafe (module-35/53 device).
//! `_ = @import`ing each file makes Zig test-discovery pull that file's own
//! inline `test` blocks (86 total across the batch); bank.zig/features.zig etc.
//! are decl-referenced for COMPILE (proving the closure type-checks) but their
//! test blocks are not discovery-included (Zig walks test decls only for the
//! root + `_ = @import`-referenced files), so bank.zig's 3 known pre-existing
//! fix105 failures (module-46) do NOT run here — the gate is GREEN and still
//! proves the full closure compiles.
//!
//! v2_dispatch.zig is the FIRST in-tree consumer of the named `vex_bpf` V1
//! module (module 67 landed the files but wired no createModule — create-at-
//! consumer, m66/m68 precedent); its createModule is minted at this gate in
//! build.zig, anchored as its committed consumer.

// This gate FORCES test-discovery (thus full analysis + inline tests) only for the
// CLEANLY-COMPILABLE live leaves. The 4 partially-dead / dormant-carry siblings —
// executor.zig (dead DISPATCH half: manifest SPLIT→rent_state LIVE half / DELETE
// dead half; consumeComputeUnits@811 carries a latent `InstrError!void` type-rot
// fix105 never compiles), hashes.zig + runtime.zig (manifest DEAD/DELETE, latent
// std-Blake3/switch rot in dead decls), block_producer.zig (DELETE→KEEP, 0 tests)
// — are migrated byte-identical VERBATIM-CARRY and are NOT force-tested here,
// exactly as module 67 did NOT root a gate at the dormant vex_bpf chain and m62/
// m66 carried heap_trace/loader without a standalone gate. fix105 never fully
// compiles these files either (they analyze lazily via replay_stage's LIVE uses,
// §E3); their call-site strip / SPLIT is the deferred post-migration refactor.
// Their correctness anchor is md5 src==dst; the LIVE halves compile-gate under
// replay_stage.zig at E3.
comptime {
    // §E1 — clean live leaves
    _ = @import("shadow_capture.zig");
    _ = @import("tx_dispatcher.zig");
    _ = @import("feature_watch.zig");
    _ = @import("gossip_votes.zig");
    _ = @import("gossip_retarget.zig");
    _ = @import("fork_choice_feed.zig");
    _ = @import("snapshot_service.zig");
    _ = @import("bank_sysvar_adapter.zig");
    _ = @import("v2_dispatch.zig");
    _ = @import("wave_pool.zig");
    // §E2 — second tier (clean)
    _ = @import("gossip_precompute.zig"); // needs gossip_votes.zig
}
