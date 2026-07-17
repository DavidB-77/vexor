//! module-73 test root for native/stake_program.zig. Lives at src/vex_svm/
//! (NOT at native/) so the test binary's module-root directory is
//! src/vex_svm/ — this is what lets native/stake_program.zig's RELATIVE
//! imports `../bank.zig` (m46) + `../overlay_lookup.zig` resolve WITHIN the
//! module subtree, exactly as they do inside the real `vex_svm` module
//! (rooted at src/vex_svm/root.zig). Rooting a test directly at
//! native/stake_program.zig would set the module path to native/ and those
//! `../` imports would escape it ("import of file outside module path").
//! Module-68 m68_test_root_bpf_loader_program.zig precedent (same shape,
//! same reason) — created because native/stake_program.zig had NO test
//! target at all before the P0-2 fix (2026-07-11,
//! VEXOR-PROGRAM-COVERAGE-AUDIT-2026-07-11 §7): its pre-existing
//! `parseInstruction`/offset unit tests were never wired into any build step
//! (only imported by production code — replay_stage.zig / instruction_dispatch.zig
//! — neither of which is a test root), so they never ran. This root makes
//! both the pre-existing tests and the new P0-2 AuthorizeWithSeed /
//! AuthorizeCheckedWithSeed KATs live + gate-checkable.
comptime {
    _ = @import("native/stake_program.zig");
}
