//! vex_bpf2.stake_bpf_flag — Phase-1 Core-BPF Stake dual-path switch (env gate).
//!
//! Holds the process-global `VEX_STAKE_BPF` flag that, together with the
//! fork-aware `migrate_stake_program_to_core_bpf` feature gate, selects whether
//! a Stake-program instruction routes through Vexor's SBPF VM (the canonical
//! on-chain v5 `.so`) instead of the Zig native stake handlers.
//!
//! ## Design (mirrors `dispatch_mode.zig`)
//!
//!   • Read ONCE at boot from `std.posix.getenv("VEX_STAKE_BPF")` — `init()`
//!     called from `main.zig` after CLI parse, before replay threads spawn.
//!   • Read-only thereafter via `enabled()`; no atomics needed.
//!   • DEFAULT = FALSE (unset or "0"): the native stake path is taken,
//!     byte-identical to current behavior. The BPF route is DORMANT.
//!
//! The flag lives in `vex_bpf2` (the low-level package) so that BOTH
//! `vex_bpf2/cpi.zig` (sibling import) AND `vex_svm/replay_stage.zig`
//! (via `vex_bpf2.stake_bpf_flag`) can read it without an import cycle —
//! `vex_svm` imports `vex_bpf2`, never the reverse.

const std = @import("std");

/// Internal storage. Do not read directly outside this module — go through
/// `enabled()`. Set once by `init()`.
var _enabled: bool = false;

/// Initialize from the environment. Idempotent-safe to call once at boot.
/// Treats unset / "0" / "false" / "" as OFF; "1" / anything else nonzero as ON.
pub fn init() void {
    if (std.posix.getenv("VEX_STAKE_BPF")) |v| {
        _enabled = !(v.len == 0 or
            std.mem.eql(u8, v, "0") or
            std.mem.eql(u8, v, "false") or
            std.mem.eql(u8, v, "FALSE"));
    } else {
        _enabled = false;
    }
}

/// True only when VEX_STAKE_BPF is set to an enabling value. DEFAULT = false.
/// This is the FIRST operand of every dual-path gate so that, when OFF, the
/// fork-aware feature check is never even evaluated and the native path is
/// byte-identical to current behavior.
pub fn enabled() bool {
    return _enabled;
}

// ── Tests ──────────────────────────────────────────────────────────────────

test "stake_bpf_flag: default is OFF before init" {
    // Fresh process: static-init value is false.
    try std.testing.expect(!enabled());
}
