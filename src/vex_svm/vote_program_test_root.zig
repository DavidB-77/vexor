//! Test-only root module for `vote_program.zig`.
//!
//! Exists because `vote_program.zig` transitively imports `../features.zig`
//! via `vote_state_serde.zig`, which escapes the module prefix when
//! `vote_program.zig` is itself the root_source_file of a `zig build test`
//! module. Setting this file (sitting one directory up) as the root widens
//! the prefix to `src/vex_svm/` so `../features.zig` resolves.
//!
//! This file does nothing except re-import the target for its test blocks.

comptime {
    _ = @import("native/vote_program.zig");
}

test {
    _ = @import("native/vote_program.zig");
}
