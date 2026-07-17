//! Test root for the create_with_seed carrier (#12 @414674115). Fires every
//! `test {}` in native/system_v2.zig — including the golden create_with_seed
//! vector — by importing it for compilation (same idiom as the M9 test roots).
//! Rooted here (src/vex_svm/) so the relative import path matches system_v2's
//! own `@import("types.zig")` / `@import("native/...")` expectations.

comptime {
    _ = @import("native/system_v2.zig");
}
