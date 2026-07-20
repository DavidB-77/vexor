//! vex_bpf2.dispatch_mode — Wave 4 runtime dispatch flag.
//!
//! Holds the global mode that selects which BPF stack `replay_stage`
//! consults when it encounters a non-native program: V1 (the legacy
//! `src/vex_bpf/sbpf_executor` path), V2 (this rebuild), or shadow (V1
//! commits, V2 runs in parallel for diagnostic comparison).
//!
//! ## Design
//!
//!   • Set ONCE at boot from `main.zig` after CLI parsing, before any
//!     replay thread spawns.
//!   • Read-only thereafter; no atomics needed.
//!   • A debug-only `set_after_lock` invariant guard catches accidental
//!     late writes if the bootstrap order ever changes.
//!
//! ## Default
//!
//! `.v1` — i.e. running this binary with no `--bpf-stack` flag is
//! byte-identical to today's behavior. The new V2 path is dormant.

const std = @import("std");

pub const BpfStackMode = enum {
    /// Legacy path (`src/vex_bpf/sbpf_executor`). Default.
    v1,
    /// V2 owns BPF execution end-to-end (`src/vex_bpf2`).
    v2,
    /// V1 commits; V2 runs in parallel for diagnostic comparison.
    shadow,
};

/// Internal storage. Do not read directly outside this module — go through
/// `current()`. Do not write outside `setMode()`.
var _mode: BpfStackMode = .v1;

/// Once true, `setMode()` will assert. Flipped by `lockForReadOnly()` once
/// boot wiring completes (called from main.zig before threads spawn).
var _locked: bool = false;

/// Optional override path for the shadow log. Default is
/// `vex-fd-shadow.log`. Set via `--bpf-stack-shadow-log=<path>`.
var _shadow_log_path: []const u8 = "/home/davidb/vex-fd-shadow.log";

pub fn current() BpfStackMode {
    return _mode;
}

pub fn isV1() bool {
    return _mode == .v1;
}

pub fn isV2() bool {
    return _mode == .v2;
}

pub fn isShadow() bool {
    return _mode == .shadow;
}

/// Set the global mode. Must be called before `lockForReadOnly()`.
pub fn setMode(m: BpfStackMode) void {
    if (_locked) {
        @panic("vex_bpf2.dispatch_mode.setMode called after lockForReadOnly()");
    }
    _mode = m;
}

/// Set the shadow log path. No-op when path is empty. Must be called
/// before `lockForReadOnly()`.
pub fn setShadowLogPath(path: []const u8) void {
    if (_locked) {
        @panic("vex_bpf2.dispatch_mode.setShadowLogPath called after lockForReadOnly()");
    }
    if (path.len == 0) return;
    _shadow_log_path = path;
}

pub fn shadowLogPath() []const u8 {
    return _shadow_log_path;
}

/// Lock the global mode against further writes. Called once from main.zig
/// after CLI parsing + smoke-gate succeed and before replay threads spawn.
/// Subsequent calls to `setMode`/`setShadowLogPath` will @panic.
pub fn lockForReadOnly() void {
    _locked = true;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "dispatch_mode: default is v1" {
    // Note: this test runs in a fresh process; in real usage `_mode` may be
    // mutated by main.zig long before tests run. The test asserts the
    // default value of an internal global, which is the static-init value.
    try std.testing.expectEqual(BpfStackMode.v1, current());
}

test "dispatch_mode: setMode toggles current()" {
    setMode(.shadow);
    try std.testing.expectEqual(BpfStackMode.shadow, current());
    try std.testing.expect(isShadow());
    setMode(.v2);
    try std.testing.expect(isV2());
    setMode(.v1);
    try std.testing.expect(isV1());
}

test "dispatch_mode: setShadowLogPath updates path" {
    setShadowLogPath("/tmp/test-shadow.log");
    try std.testing.expectEqualStrings("/tmp/test-shadow.log", shadowLogPath());
    // Restore default for any later tests.
    setShadowLogPath("/home/davidb/vex-fd-shadow.log");
}
