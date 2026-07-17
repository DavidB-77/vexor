//! Test-only root module for `native/precompiles.zig`.
//!
//! Exists because `precompiles.zig` imports `../features.zig` directly, which
//! escapes the module prefix when `precompiles.zig` is itself the
//! root_source_file of a `zig build test` module. Setting this file (sitting
//! one directory up, in `src/vex_svm/`) as the root widens the prefix to
//! `src/vex_svm/` so `../features.zig` resolves. Same shape as the sibling
//! `vote_program_test_root.zig` (identical `../features.zig` escape, via
//! vote_state_serde.zig there vs. directly here).
//!
//! This file does nothing except re-import the target for its test blocks.

comptime {
    _ = @import("native/precompiles.zig");
}

test {
    _ = @import("native/precompiles.zig");
}
