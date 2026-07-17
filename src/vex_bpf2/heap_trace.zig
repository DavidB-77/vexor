//! V2 heap-trace instrumentation (Stage-4 [V2-HEAP-WRITE/READ] hooks).
//!
//! Per-dispatch tagged trace of every read/write landing in the BPF heap
//! region [MM_HEAP_START, MM_HEAP_START + 32 KiB). Used to discriminate
//! the four-way verdict A/B/C/D defined in
//!   memory/project_v2_heap_trace_design_2026_04_26.md
//!
//! Read-only — no behavior change. Logs only when `g_active` is set;
//! `v2_dispatch.v2DispatchBpfProgram` flips it on/off around `vm.run`.
//!
//! Rate limit: 128 op log lines per dispatch (writes + reads combined).
//! After the cap, ops still execute but are not logged.
//!
//! Pc plumbing: read from `interp_breadcrumb.g_last_pc` which the
//! interpreter updates per step (active inside V2's panic-safety harness).

const std = @import("std");
const interp_breadcrumb = @import("interp_breadcrumb.zig");

pub const OP_LOG_LIMIT: u32 = 128;
pub const CALL_LOG_LIMIT: u32 = 8192;

pub threadlocal var g_active: bool = false;
pub threadlocal var g_dispatch_id: u64 = 0;
pub threadlocal var g_op_count: u32 = 0;
pub threadlocal var g_call_count: u32 = 0;

pub var g_dispatch_id_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

pub fn enable() u64 {
    // R18 (Helm SEQ:55-helm Step 1): production build leaves g_active = false
    // so every record/dump function below returns at its `if (!g_active) return`
    // guard. No log emission, no /tmp file writes, no PROGRAM_FILTER work.
    // F-track invariants (F3 bank_prune, F4 vm.reg[1] = MM_INPUT_START,
    // F5 vm.reg[2] = instruction_data_offset) live elsewhere and are unaffected.
    // To re-enable diag for a future R-iteration: restore the original body
    // (set g_active = true + bump g_dispatch_id from g_dispatch_id_seq).
    return 0;
}

pub fn disable() void {
    g_active = false;
}

inline fn shouldLog() bool {
    if (!g_active) return false;
    if (g_op_count >= OP_LOG_LIMIT) return false;
    g_op_count += 1;
    return true;
}

/// Hook for store ops that translate into the heap region.
/// Branch-(a) shape: intent-only, no byte peek. We log the access
/// attempt + accepted flag; the byte content is unavailable to the M2
/// translation path (the interpreter writes the new value AFTER vmap
/// returns the host slice). Branch B / C verdict still mechanical from
/// counts; Branch A / D discrimination requires byte equality which a
/// future round adds via interpreter-loop hooks (option (b)).
pub fn recordWriteIntent(vm_addr: u64, len: u64, accepted: bool) void {
    if (!shouldLog()) return;
    std.log.err(
        "[V2-HEAP-WRITE] disp={d} vm_addr=0x{x} sz={d} pc={d} accepted={any}",
        .{ g_dispatch_id, vm_addr, len, interp_breadcrumb.g_last_pc, accepted },
    );
}

/// Hook for load ops that translate into the heap region.
pub fn recordReadIntent(vm_addr: u64, len: u64) void {
    if (!shouldLog()) return;
    std.log.err(
        "[V2-HEAP-READ] disp={d} vm_addr=0x{x} sz={d} pc={d}",
        .{ g_dispatch_id, vm_addr, len, interp_breadcrumb.g_last_pc },
    );
}

/// One-shot dump of 80 bytes (10 BPF instructions) at a target pc, used to
/// give Helm the AUTHORITATIVE bytes Vexor reads in fn 43636's first 10 insns.
/// Helm SEQ:33 — R9 path-2 byte verification; r6=0x3479 set by some non-CALL
/// non-SYSCALL instruction in Vexor's runtime view of pcs 43636-43645.
///
/// Hardcoded to fn 43636 entry (HistoryJT). Logs the full 80 bytes as 10
/// little-endian u64 hex words — same format Helm decodes from V2-CALL insn=
/// field. Fires ONCE per dispatch (gated by g_fn43636_dumped threadlocal),
/// reset by enable() on each dispatch.
pub threadlocal var g_fn43636_dumped: bool = false;

pub fn dumpFn43636Bytes(program: []const u8) void {
    if (!g_active) return;
    if (g_fn43636_dumped) return;
    g_fn43636_dumped = true;
    const start: usize = 43636 * 8;
    if (start + 80 > program.len) return;
    var w: [10]u64 = undefined;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        w[i] = std.mem.readInt(u64, program[start + i * 8 ..][0..8], .little);
    }
    std.log.err(
        "[V2-FN43636-DUMP] disp={d} pc=43636..43645 bytes={x:0>16} {x:0>16} {x:0>16} {x:0>16} {x:0>16} {x:0>16} {x:0>16} {x:0>16} {x:0>16} {x:0>16}",
        .{ g_dispatch_id, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9] },
    );
}

/// One-shot dump of V2's serialize2 input region — first 256 bytes hex + total
/// length. Throttled to first INPUT_DUMP_LIMIT dispatches globally to keep log
/// volume sane. Helm SEQ:45 — F7 direction needs the bytes Vexor packs at
/// MM_INPUT_START so Helm can byte-diff against Agave's expected layout.
pub const INPUT_DUMP_LIMIT: u32 = 5;
pub var g_input_dump_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// One-shot full-buffer dump to /tmp/v2_input_disp{N}_prog{P}.bin —
/// throttled to FILE_DUMP_LIMIT dispatches globally. Helm SEQ:48 F8:
/// Helm runs `python3 scripts/agave_serialize_expected.py | diff` against
/// these to find any byte divergence beyond the first 256 already verified.
pub const FILE_DUMP_LIMIT: u32 = 5;
pub var g_file_dump_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// R17 (Helm SEQ:50): per-program guard for HistoryJT / validator-history
/// (program_id_short = f8755962, dominant V2 fail at 88% in SEQ:48). Filter
/// gates BEFORE the global counter so other programs don't exhaust the
/// 5-slot budget. Empty string disables filter (revert to global throttle).
pub const PROGRAM_FILTER: []const u8 = "f8755962";

pub fn dumpInputToFile(disp_id: u64, program_short: []const u8, bytes: []const u8) void {
    if (!g_active) return;
    if (PROGRAM_FILTER.len > 0 and !std.mem.eql(u8, program_short, PROGRAM_FILTER)) return;
    const n = g_file_dump_count.fetchAdd(1, .monotonic);
    if (n >= FILE_DUMP_LIMIT) return;
    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(
        &path_buf,
        "/tmp/v2_input_disp{d}_prog{s}.bin",
        .{ disp_id, program_short },
    ) catch return;
    const f = std.fs.cwd().createFile(path, .{}) catch return;
    defer f.close();
    f.writeAll(bytes) catch return;
    std.log.err(
        "[V2-INPUT-FILE] disp={d} program={s} bytes_len={d} path={s}",
        .{ disp_id, program_short, bytes.len, path },
    );
}

/// One-shot dump of 64 bytes (8 u64 LE) at a vm_addr — used at
/// CALL_REG/CallOutsideTextSegment to capture the &Arguments struct
/// the panic was given (Helm SEQ:48 F7-or-F8).
pub fn dumpStructAtVaddr(tag: []const u8, caller_pc: u64, vm_addr: u64, slice: []const u8) void {
    if (!g_active) return;
    if (g_call_count >= CALL_LOG_LIMIT) return;
    g_call_count += 1;
    const len = @min(slice.len, 64);
    var buf: [256]u8 = undefined;
    var fb: std.io.FixedBufferStream([]u8) = .{ .buffer = &buf, .pos = 0 };
    const writer = fb.writer();
    var i: usize = 0;
    while (i + 8 <= len) : (i += 8) {
        const v = std.mem.readInt(u64, slice[i..][0..8], .little);
        if (i > 0) writer.writeByte(' ') catch return;
        writer.print("{x:0>16}", .{v}) catch return;
    }
    std.log.err(
        "[V2-STRUCT-DUMP] tag={s} disp={d} caller_pc={d} vm_addr=0x{x} bytes={s}",
        .{ tag, g_dispatch_id, caller_pc, vm_addr, buf[0..fb.pos] },
    );
}

pub fn dumpInputRegion(program_short: []const u8, bytes: []const u8) void {
    if (!g_active) return;
    const n = g_input_dump_count.fetchAdd(1, .monotonic);
    if (n >= INPUT_DUMP_LIMIT) return;
    // Header line — confirms the function reached std.log.err at all.
    std.log.err(
        "[V2-INPUT-DUMP-HDR] disp={d} program={s} bytes_len={d}",
        .{ g_dispatch_id, program_short, bytes.len },
    );
    // Body: dump 32 u64 words (256 bytes) as space-separated hex on one line.
    // 32 * 16-char hex + 31 spaces + tag overhead < 600 chars; well within
    // any plausible log-line cap. Read 8 bytes at a time as u64 LE.
    var line_buf: [800]u8 = undefined;
    const word_count: usize = @min(@divFloor(bytes.len, 8), 32);
    var w: std.io.FixedBufferStream([]u8) = .{ .buffer = &line_buf, .pos = 0 };
    const writer = w.writer();
    for (0..word_count) |i| {
        const v = std.mem.readInt(u64, bytes[i * 8 ..][0..8], .little);
        if (i > 0) writer.writeByte(' ') catch return;
        writer.print("{x:0>16}", .{v}) catch return;
    }
    std.log.err(
        "[V2-INPUT-DUMP] disp={d} words={d} first32u64={s}",
        .{ g_dispatch_id, word_count, line_buf[0..w.pos] },
    );
}

/// Hook for CALL_REG (callx) when target is OUTSIDE program text segment.
/// Helm SEQ:43 — F6 round, both Jito (pc=44475) and ATokenG (pc=9117)
/// CallOutsideTextSegment failures originate from CALL_REG paths where the
/// target register holds a .rodata vaddr instead of a .text vaddr.
/// Capture caller_pc, target value, source reg, r1, r10 for upstream trace.
pub fn recordCallxFail(caller_pc: u64, target: u64, source_reg: u8, r1: u64, r10: u64) void {
    if (!g_active) return;
    if (g_call_count >= CALL_LOG_LIMIT) return;
    g_call_count += 1;
    std.log.err(
        "[V2-CALLX-FAIL] disp={d} caller_pc={d} target=0x{x} source_reg=r{d} r1=0x{x} r10=0x{x}",
        .{ g_dispatch_id, caller_pc, target, source_reg, r1, r10 },
    );
}

/// Hook for CALL_REG when target IS in text — successful resolution.
/// Useful for verifying CALL_REG paths fire at all (sanity).
pub fn recordCallxOk(caller_pc: u64, target: u64, source_reg: u8) void {
    if (!g_active) return;
    if (g_call_count >= CALL_LOG_LIMIT) return;
    g_call_count += 1;
    std.log.err(
        "[V2-CALLX-OK] disp={d} caller_pc={d} target=0x{x} source_reg=r{d}",
        .{ g_dispatch_id, caller_pc, target, source_reg },
    );
}

/// Hook for SYSCALL CALL_IMM dispatch — fires AT entry (r6_before) and AT exit
/// (r6_after) of every syscall. Used to confirm/refute the hypothesis that a
/// syscall at HistoryJT pc=43643 is the source of r6=0x3479 corruption.
/// Helm SEQ:31 — r8 instrument round.
pub fn recordSyscallEntry(caller_pc: u64, hash: u32, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64, r6_before: u64) void {
    if (!g_active) return;
    if (g_call_count >= CALL_LOG_LIMIT) return;
    g_call_count += 1;
    std.log.err(
        "[V2-SYSCALL] disp={d} caller_pc={d} hash=0x{x:0>8} r1=0x{x} r2=0x{x} r3=0x{x} r4=0x{x} r5=0x{x} r6_before=0x{x}",
        .{ g_dispatch_id, caller_pc, hash, r1, r2, r3, r4, r5, r6_before },
    );
}

pub fn recordSyscallExit(caller_pc: u64, hash: u32, r0: u64, r6_after: u64) void {
    if (!g_active) return;
    if (g_call_count >= CALL_LOG_LIMIT) return;
    g_call_count += 1;
    std.log.err(
        "[V2-SYSCALL-RET] disp={d} caller_pc={d} hash=0x{x:0>8} r0=0x{x} r6_after=0x{x}",
        .{ g_dispatch_id, caller_pc, hash, r0, r6_after },
    );
}

/// Hook for internal CALL_IMM dispatch (V3 static + legacy paths).
/// Captures caller pc, target pc, the callee-saved register r6 and
/// frame ptr r10 at the moment the frame is pushed, plus the raw 8
/// bytes of the CALL instruction at caller_pc. r6 is preserved across
/// calls, so r6 here equals r6 at callee entry.
///
/// `insn_bytes` lets static-disasm verify Vexor's pc convention against
/// the ELF byte layout — Helm SEQ:29 needs this to resolve the
/// 49134-vs-58630 target_pc mismatch.
///
/// Used to identify the caller that loads r6 with a read-only program-
/// region vm_addr (e.g. 0x3479 for HistoryJTGbKQD2mRgLZ3XhqHnN811Qpez8X9k
/// CcGHoa), which then AVs on the first stxdw [r6+N] inside the callee.
/// project_v2_pc16005_r6_correction_2026_04_26.md.
pub fn recordCall(caller_pc: u64, target_pc: u64, r6: u64, r10: u64, insn_bytes: u64) void {
    if (!g_active) return;
    if (g_call_count >= CALL_LOG_LIMIT) return;
    g_call_count += 1;
    std.log.err(
        "[V2-CALL] disp={d} caller_pc={d} target_pc={d} r6=0x{x} r10=0x{x} insn=0x{x:0>16}",
        .{ g_dispatch_id, caller_pc, target_pc, r6, r10, insn_bytes },
    );
}
