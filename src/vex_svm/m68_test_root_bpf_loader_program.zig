//! module-68 test root for bpf_loader_program. Lives at src/vex_svm/ (NOT at
//! native/) so the test binary's module-root directory is src/vex_svm/ — this
//! is what lets native/bpf_loader_program.zig's RELATIVE imports `../bank.zig`
//! (m46) + `../features.zig` (m30) resolve WITHIN the module subtree, exactly
//! as they do inside fix105's `vex_svm` module (rooted at src/vex_svm/root.zig).
//! Rooting a test directly at native/bpf_loader_program.zig would set the module
//! path to native/ and those `../` imports would escape it ("import of file
//! outside module path"). Rebuild-native discovery shim, module-63
//! m9_test_root_*.zig precedent — NATIVE class in drift-baseline (no upstream).
//!
//! `_ = @import`ing ONLY native/bpf_loader_program.zig means Zig test-discovery
//! pulls ONLY that file's 2 inline tests. bank.zig / features.zig are pulled into
//! the module for COMPILATION (decl-referenced by bpf_loader_program) but their
//! `test` blocks are NOT discovery-included (Zig walks test decls only for the
//! root file + `_ = @import`-referenced files), so bank.zig's known pre-existing
//! fix105 failures (module-46) do NOT run here — the gate is GREEN 2/2 and still
//! proves the full closure compiles. The file's real behavioral KATs
//! (test-bpf-loader-extend / test-bpf-loader-setauth) `@import("vex_svm")` and
//! stay blocked on the §E umbrella.

comptime {
    _ = @import("native/bpf_loader_program.zig");
}
