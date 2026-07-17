//! Per-instruction breadcrumb state for V2 interpreter panic localization.
//!
//! This module is intentionally libc-free so it can be imported by
//! `interpreter.zig` without dragging libc into standalone test compilations
//! (e.g. test-vex-bpf2-interpreter) that don't link libc.
//!
//! `shadow_panic_safety.zig` exposes the public accessors (`lastPc`,
//! `lastOpcode`, `lastRegs`) and calls `recordStep` on behalf of callers that
//! already hold a `shadow_panic_safety.isProtected()` guard.
//!
//! `interpreter.zig` calls `recordStep` directly (gated by `g_breadcrumb_active`)
//! without needing to import `shadow_panic_safety.zig`.

// ── Threadlocal state ────────────────────────────────────────────────────────

/// When true, recordStep stores breadcrumbs.  Set/cleared by
/// shadow_panic_safety.runProtected — NOT by this module directly.
pub threadlocal var g_breadcrumb_active: bool = false;

/// PC of the last fetched instruction on this thread (updated by recordStep).
pub threadlocal var g_last_pc: u64 = 0;

/// Opcode byte of the last fetched instruction (updated by recordStep).
pub threadlocal var g_last_opcode: u8 = 0;

/// Register snapshot r0..r10 at last recordStep call (updated by recordStep).
pub threadlocal var g_last_regs: [11]u64 = [_]u64{0} ** 11;

// ── API ──────────────────────────────────────────────────────────────────────

/// Record the PC, opcode, and r0..r10 registers just after fetching an
/// instruction.  No-op when breadcrumbs are not active (i.e. when the
/// current thread is NOT inside a runProtected scope).
///
/// Call site in interpreter.zig:
///
///   if (interp_breadcrumb.g_breadcrumb_active)
///       interp_breadcrumb.recordStep(self.reg[11], insn.opc, self.reg[0..11].*);
///
/// Performance: ~20 ns per call (5–6 TLS stores on x86-64).
pub inline fn recordStep(pc: u64, opcode: u8, regs: [11]u64) void {
    g_last_pc = pc;
    g_last_opcode = opcode;
    g_last_regs = regs;
}

/// Reset all breadcrumb state to zero.  Called by shadow_panic_safety on
/// runProtected entry so stale values from a prior scope are never visible.
pub inline fn reset() void {
    g_last_pc = 0;
    g_last_opcode = 0;
    g_last_regs = [_]u64{0} ** 11;
}
