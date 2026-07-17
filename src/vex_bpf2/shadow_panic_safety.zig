//! Shadow-mode panic safety harness.
//!
//! The V2 BPF stack runs in shadow mode beside V1 (which is the source
//! of truth). When V2 has a bug it can @panic (integer overflow,
//! unreachable, slice OOB) or trigger a hardware signal (SIGSEGV from a
//! bad pointer, SIGFPE from div-by-zero, etc.) — and any of those would
//! normally take the validator process down with it.
//!
//! This module lets the V2 path execute under a per-thread protective
//! scope. Inside the scope, panics and the four "safe" signals are
//! intercepted, the protected scope unwinds with `error.ShadowPanicked`,
//! and the validator continues. Stable's V1 path is never disturbed.
//!
//! ── Mechanism ─────────────────────────────────────────────────────────
//!
//!   1. `runProtected` calls libc `__sigsetjmp` on entry and clears the
//!      thread-local guard on exit. The guard says "this thread is in a
//!      shadow scope right now."
//!   2. The validator's signal handler checks the guard FIRST. If set,
//!      it `siglongjmp`s back to the checkpoint (returns from the
//!      `__sigsetjmp` call site with a non-zero return code, which
//!      `runProtected` maps to `error.ShadowPanicked`).
//!   3. The Zig panic hook (installed via `pub const panic` in main.zig)
//!      does the same for compiler-emitted panics.
//!
//! ── Hard requirements ─────────────────────────────────────────────────
//!
//!   • The protected scope MUST own its allocator (a per-dispatch arena
//!     in shadowDispatch). Recovery is `arena.deinit()` on the way out;
//!     the global heap is never touched.
//!   • The protected scope MUST NOT acquire a mutex / lock. Shadow code
//!     today is pure compute on snapshots and holds nothing — verify this
//!     stays true if shadow ever needs shared state.
//!   • Re-entry is unsupported. `runProtected` from inside a protected
//!     scope returns `error.ShadowPanicked` immediately.
//!
//! ── Caveats ───────────────────────────────────────────────────────────
//!
//!   • SIGABRT from libc internals (e.g. malloc corruption) is caught
//!     too — this is correct because it likely means the V2 path
//!     corrupted the heap. We log and unwind; the validator stays up.
//!     If the corruption is severe, the next allocation in V1 will trip
//!     the same handler outside a protected scope and we'll fall through
//!     to the fatal exit. This is a safety floor, not a guarantee that
//!     V2 cannot harm V1 — but per-dispatch arenas + no-locks make that
//!     highly unlikely in practice.
//!   • Thread cancellation / pthread state is not touched.

const std = @import("std");
const interp_breadcrumb = @import("interp_breadcrumb.zig");

/// Opaque storage for libc's `sigjmp_buf`. glibc's `sigjmp_buf` is
/// declared as `__jmp_buf[8] + saved_mask + flag` ≈ 200 bytes on x86-64.
/// 256 bytes with 16-byte align gives generous headroom and matches the
/// alignment libc expects.
pub const JmpBuf = extern struct {
    storage: [256]u8 align(16) = undefined,
};

extern "c" fn __sigsetjmp(env: *JmpBuf, savemask: c_int) c_int;
extern "c" fn siglongjmp(env: *JmpBuf, val: c_int) noreturn;

pub const ShadowPanicReason = enum(c_int) {
    none = 0,
    sigsegv = 1,
    sigbus = 2,
    sigfpe = 3,
    sigill = 4,
    sigabrt = 5,
    zig_panic = 6,
};

threadlocal var g_protected: bool = false;
threadlocal var g_env: JmpBuf = .{};
threadlocal var g_reason: ShadowPanicReason = .none;
threadlocal var g_panic_msg: [128]u8 = [_]u8{0} ** 128;
threadlocal var g_panic_msg_len: usize = 0;

/// True iff the current thread is executing inside a `runProtected` scope.
/// Async-signal-safe (no allocations, no locks).
pub fn isProtected() bool {
    return g_protected;
}

pub fn lastReason() ShadowPanicReason {
    return g_reason;
}

pub fn lastPanicMessage() []const u8 {
    return g_panic_msg[0..g_panic_msg_len];
}

// Phase-3: breadcrumb accessors — state lives in interp_breadcrumb.zig
// (libc-free) so interpreter.zig can import it without dragging libc into
// standalone test compilations.

/// Return the PC captured at the last `recordStep` call on this thread.
pub fn lastPc() u64 {
    return interp_breadcrumb.g_last_pc;
}

/// Return the opcode byte captured at the last `recordStep` call on this thread.
pub fn lastOpcode() u8 {
    return interp_breadcrumb.g_last_opcode;
}

/// Return a copy of r0..r10 captured at the last `recordStep` call on this thread.
pub fn lastRegs() [11]u64 {
    return interp_breadcrumb.g_last_regs;
}

/// Record the current interpreter state just after fetching an instruction.
///
/// Callers in `stepOnce` gate via `interp_breadcrumb.g_breadcrumb_active`
/// (set/cleared by runProtected) so this is never called outside a protected
/// scope. Performance budget: ~20 ns per call (5–6 TLS stores on x86-64).
pub fn recordStep(pc: u64, opcode: u8, regs: [11]u64) void {
    interp_breadcrumb.recordStep(pc, opcode, regs);
}

/// Async-signal-safe handler hook. Called from main.zig's `signalHandler`
/// FIRST (before the fatal-exit path). Returns true if the signal was
/// consumed via `siglongjmp` (does not actually return — the longjmp
/// throws to the protected-scope checkpoint).
pub fn signalHandlerHook(sig: c_int) bool {
    if (!g_protected) return false;
    g_reason = switch (sig) {
        std.posix.SIG.SEGV => ShadowPanicReason.sigsegv,
        std.posix.SIG.BUS => ShadowPanicReason.sigbus,
        std.posix.SIG.FPE => ShadowPanicReason.sigfpe,
        std.posix.SIG.ILL => ShadowPanicReason.sigill,
        std.posix.SIG.ABRT => ShadowPanicReason.sigabrt,
        else => ShadowPanicReason.none,
    };
    g_protected = false;
    interp_breadcrumb.g_breadcrumb_active = false;
    siglongjmp(&g_env, 1);
}

/// Called by the Zig panic override in main.zig. Records the message,
/// clears the guard, and longjumps. If not protected, returns false so
/// the caller falls through to default panic behavior.
pub fn zigPanicHook(msg: []const u8) bool {
    if (!g_protected) return false;
    g_reason = .zig_panic;
    const n = @min(msg.len, g_panic_msg.len);
    @memcpy(g_panic_msg[0..n], msg[0..n]);
    g_panic_msg_len = n;
    g_protected = false;
    interp_breadcrumb.g_breadcrumb_active = false;
    siglongjmp(&g_env, 1);
}

pub const ProtectedError = error{ShadowPanicked};

/// Run `f(ctx)` inside a protective scope. If `f` returns normally, the
/// result is forwarded. If `f` panics or hits SIGSEGV/SIGBUS/SIGFPE/
/// SIGILL/SIGABRT, the scope unwinds with `error.ShadowPanicked` and the
/// caller can inspect `lastReason()` + `lastPanicMessage()`.
///
/// Re-entrancy: not supported. A second `runProtected` from inside a
/// protected scope returns `error.ShadowPanicked` immediately.
pub fn runProtected(
    comptime ResultT: type,
    ctx: anytype,
    comptime f: fn (@TypeOf(ctx)) ResultT,
) ProtectedError!ResultT {
    if (g_protected) return error.ShadowPanicked;
    g_reason = .none;
    g_panic_msg_len = 0;
    // Phase-3: reset breadcrumbs (live in interp_breadcrumb) so stale values
    // from a prior scope are never visible after ShadowPanicked.
    interp_breadcrumb.reset();
    // savemask=1 → save current signal mask on entry, restore on longjmp.
    // This matters because the signal handler runs with SIGSEGV (etc.)
    // masked by default; restoring the prior mask lets future signals
    // fire normally after we unwind.
    const rc = __sigsetjmp(&g_env, 1);
    if (rc != 0) {
        // Returned from a longjmp — protected work failed.
        return error.ShadowPanicked;
    }
    g_protected = true;
    interp_breadcrumb.g_breadcrumb_active = true;
    defer {
        g_protected = false;
        interp_breadcrumb.g_breadcrumb_active = false;
    }
    return f(ctx);
}

test "runProtected returns normal value" {
    const result = try runProtected(u32, @as(u32, 42), struct {
        fn f(x: u32) u32 {
            return x + 1;
        }
    }.f);
    try std.testing.expectEqual(@as(u32, 43), result);
    try std.testing.expectEqual(ShadowPanicReason.none, lastReason());
}

test "runProtected catches Zig panic via hook" {
    // Direct hook test — exercises the same code the panic override calls
    // without actually invoking @panic (which would terminate the test).
    const Ctx = struct {
        fn f(_: void) u32 {
            // Simulate a panic by invoking the hook directly.
            _ = zigPanicHook("simulated overflow");
            return 0; // unreachable
        }
    };
    const result = runProtected(u32, {}, Ctx.f);
    try std.testing.expectError(error.ShadowPanicked, result);
    try std.testing.expectEqual(ShadowPanicReason.zig_panic, lastReason());
    try std.testing.expectEqualStrings("simulated overflow", lastPanicMessage());
}

test "runProtected: re-entry returns error" {
    // Mark a "protected" scope manually then attempt re-entry.
    g_protected = true;
    defer g_protected = false;
    const result = runProtected(u32, {}, struct {
        fn f(_: void) u32 {
            return 1;
        }
    }.f);
    try std.testing.expectError(error.ShadowPanicked, result);
}

test "recordStep breadcrumbs survive ShadowPanic" {
    // Inside a protected scope, record a step, then trigger a panic via the
    // hook.  After unwinding, lastPc/lastOpcode/lastRegs must reflect the
    // recorded values rather than zero.
    const Ctx = struct {
        fn f(_: void) u32 {
            // Simulate stepping at pc=0xDEAD, opcode=0x07 (add64 imm).
            const test_regs: [11]u64 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
            recordStep(0xDEAD, 0x07, test_regs);
            // Simulate panic immediately after.
            _ = zigPanicHook("test panic after recordStep");
            return 0;
        }
    };
    const result = runProtected(u32, {}, Ctx.f);
    try std.testing.expectError(error.ShadowPanicked, result);
    try std.testing.expectEqual(ShadowPanicReason.zig_panic, lastReason());
    try std.testing.expectEqual(@as(u64, 0xDEAD), lastPc());
    try std.testing.expectEqual(@as(u8, 0x07), lastOpcode());
    const regs = lastRegs();
    try std.testing.expectEqual(@as(u64, 1), regs[0]);
    try std.testing.expectEqual(@as(u64, 11), regs[10]);
}

test "runProtected resets breadcrumbs on entry" {
    // Verify that a fresh runProtected scope resets pc/opcode/regs to zero
    // even if a previous scope left stale values.
    interp_breadcrumb.g_last_pc = 0xBEEF;
    interp_breadcrumb.g_last_opcode = 0xFF;
    interp_breadcrumb.g_last_regs = [_]u64{0xAA} ** 11;
    const result = try runProtected(u32, @as(u32, 5), struct {
        fn f(x: u32) u32 {
            return x;
        }
    }.f);
    try std.testing.expectEqual(@as(u32, 5), result);
    // Breadcrumbs were reset on entry; after a clean run they stay at zero.
    try std.testing.expectEqual(@as(u64, 0), lastPc());
    try std.testing.expectEqual(@as(u8, 0), lastOpcode());
}
