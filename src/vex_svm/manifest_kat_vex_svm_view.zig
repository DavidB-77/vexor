// Thin REAL vex_svm-shaped module root used ONLY by `test-manifest-lthash-verify`.
//
// snapshot_manifest.zig (src/vex_store/) resolves its FeeRateGovernor type via
// `@import("vex_svm").blockhash_queue.FeeRateGovernor`. origin-tree's OWN vex_svm
// module is rooted at src/vex_svm/root.zig, which transitively re-exports
// bank.zig / replay_stage.zig (the two consensus-frozen god-files this
// rebuild has not migrated and must not pull in). This file is NOT that
// module — it is a narrow, single-purpose re-export of the one real,
// byte-identical migrated sibling (blockhash_queue.zig) that snapshot_
// manifest.zig actually needs, wired as a substitute "vex_svm" module for
// this ONE test target only (mirrors origin-tree's own precedent device for the
// exact same module-boundary problem: src/vex_store/accounts_test_vex_svm_
// stub.zig, used by test-accounts / test-snapshot-len-provenance). Unlike
// that stub, EVERYTHING referenced here is real, unmodified production code
// — no sentinel/fabricated values, because FeeRateGovernor is a live
// consensus type and snapshot_manifest.zig's KAT actually exercises it.
//
// Session-13 rebuild note: empirically verified in a /tmp scratch build
// (never origin-tree, never this tree) BEFORE wiring — confirmed this resolves
// snapshot_manifest.zig + kat_manifest_lthash_verify.zig without reaching
// bank.zig / replay_stage.zig / vex_store/accounts.zig. See REBUILD-LEDGER.md
// module-13 row for the full empirical trail.
pub const blockhash_queue = @import("blockhash_queue.zig");
