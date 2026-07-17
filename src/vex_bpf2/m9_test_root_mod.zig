//! M9 test root for mod.zig. Lives at src/vex_bpf2/ so the test's module
//! path includes the M8 deps + the builtins/ subtree.

comptime {
    _ = @import("builtins/mod.zig");
}
