//! M9 test root for vote program. Lives at src/vex_bpf2/ so the test's
//! module path includes invoke_ctx.zig + sysvar_cache.zig. Auto-generated
//! shim.

comptime {
    _ = @import("builtins/vote_program.zig");
}
