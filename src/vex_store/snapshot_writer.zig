//! Vexor Snapshot Writer — OUTPUT-FROZEN AppendVec byte writer.
//!
//! SPLIT from snapshot.zig (module 27, 2026-07-06): the byte-format-critical
//! writer primitives used by SnapshotManager's save/create paths (in
//! snapshot_boot.zig): a buffering wrapper that is byte-transparent to the
//! AppendVec wire format (BufferedAvWriter), a fork-BGSAVE child-side
//! trickle-fsync shim over it (SyncingAvWriter), and the fork-safe raw
//! helpers the BGSAVE child uses (alloc-free / lock-free / log-free by
//! design — see the prohibitions comment below). OUTPUT FROZEN: these change
//! HOW bytes are written (buffering, sync cadence), never WHAT bytes are
//! written — the produced AppendVec file is bit-for-bit unchanged.
//!
//! Every declaration below is copied byte-identical from the original
//! snapshot.zig (fix105 726287b, lines 19-259) except 6 documented
//! visibility promotions (`pub` added, zero behavior change) required
//! because snapshot_boot.zig now reaches these across a file boundary:
//! DEFAULT_BUF_BYTES, SyncingAvWriter, bgsaveRawErr, bgsaveChildSetup,
//! bgsaveDeleteTree, readPrivateDirtyKb.

const std = @import("std");
const fs = std.fs;

/// PERF (liveness): transparent big-chunk buffer over a snapshot AppendVec file.
///
/// The snapshot writers (`writeSnapshotAppendVec` / `writeSnapshotAppendVecLocked`)
/// emit ~10 tiny `writeAll`/`writeByte` calls PER ACCOUNT. Over 86.7M accounts on
/// an UNbuffered `File.deprecatedWriter()` that is ~870M raw `write(2)` syscalls,
/// each of which costs hundreds of ns of kernel-crossing overhead — and the entire
/// multi-minute walk runs while `storage.lock` is held SHARED, so every replay
/// `writeAccount` (which needs it EXCLUSIVE) STALLS for the whole duration
/// (a vote-landing/delinquency hazard).
///
/// This wrapper accumulates into one large reusable heap buffer and flushes in
/// `buf.len`-sized chunks, collapsing ~870M syscalls into ~`ceil(total_bytes/buf)`
/// (a few thousand). It is BYTE-TRANSPARENT: it exposes exactly the `writeAll` /
/// `writeByte` surface the writers use and forwards the identical byte stream, so
/// the produced AppendVec file is bit-for-bit unchanged (OUTPUT FROZEN — we change
/// HOW it writes, never WHAT). Removing the syscalls also shrinks the lock-hold
/// ~10x (the syscall overhead was the dominant component of the walk).
///
/// SAFETY NOTE on why the lock is NOT dropped: the walk reads BORROWED mmap views
/// (`AppendVec.getAccount` returns `self.data[..]`), and `reapRetired`/`shrinkSlot`/
/// `evictOldest` free+unmap stores under the EXCLUSIVE `storage.lock` while
/// `getOrCreateStore` mutates the `stores` hashmap — so a lock-free read would be a
/// use-after-free + a hashmap data race that a single round-trip cannot prove
/// absent. We keep the shared lock and win via buffering instead.
///
/// CALLER CONTRACT: call `flush()` (or `deinit()`, which flushes) BEFORE the file
/// is closed or re-stat'd for the manifest — a buffered tail not flushed before
/// close would silently truncate the file AND record a wrong manifest size.
pub const BufferedAvWriter = struct {
    file: std.fs.File,
    buf: []u8,
    len: usize = 0,
    allocator: std.mem.Allocator,
    // Telemetry for the perf gate: number of real write(2) flushes + bytes emitted.
    flushes: u64 = 0,
    bytes_total: u64 = 0,

    pub const DEFAULT_BUF_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

    pub fn init(allocator: std.mem.Allocator, file: std.fs.File) !BufferedAvWriter {
        return .{
            .file = file,
            .buf = try allocator.alloc(u8, DEFAULT_BUF_BYTES),
            .allocator = allocator,
        };
    }

    /// Frees the buffer ONLY. Does NOT flush — the caller MUST call `flush()`
    /// explicitly (with `try`, so a failed final write surfaces as an error and is
    /// never silently dropped) BEFORE the file is closed / re-stat'd. Safe to
    /// `defer` for buffer cleanup on any (incl. error) path.
    pub fn deinit(self: *BufferedAvWriter) void {
        self.allocator.free(self.buf);
        self.buf = &[_]u8{};
    }

    pub fn flush(self: *BufferedAvWriter) !void {
        if (self.len == 0) return;
        try self.file.writeAll(self.buf[0..self.len]);
        self.flushes += 1;
        self.len = 0;
    }

    /// Byte-transparent forward of the writer's `writeAll` — identical bytes, fewer
    /// syscalls. Buffers; flushes a full buffer. Inputs larger than the buffer are
    /// split across flushes (the byte order is preserved exactly).
    pub fn writeAll(self: *BufferedAvWriter, bytes: []const u8) !void {
        self.bytes_total += bytes.len;
        var rem = bytes;
        while (rem.len > 0) {
            if (self.len == self.buf.len) try self.flush();
            const n = @min(self.buf.len - self.len, rem.len);
            @memcpy(self.buf[self.len..][0..n], rem[0..n]);
            self.len += n;
            rem = rem[n..];
        }
    }

    /// Byte-transparent forward of the writer's `writeByte`.
    pub fn writeByte(self: *BufferedAvWriter, b: u8) !void {
        self.bytes_total += 1;
        if (self.len == self.buf.len) try self.flush();
        self.buf[self.len] = b;
        self.len += 1;
    }
};

/// fork-BGSAVE (task #26, 2026-07-01) child-side writer shim: forwards
/// byte-transparently to the pre-staged `BufferedAvWriter` and fdatasync(2)s the
/// AppendVec fd every ~256 MiB so dirty pages TRICKLE to disk at the child's
/// IDLE io priority instead of bursting at close (Redis rioSetAutoSync analog;
/// the sync cost lands on the idle isolated-core child, never the parent).
/// Fork-safe subset: alloc-free, lock-free, log-free — memcpy + raw
/// write(2)/fdatasync(2) only. Design: FORK-BGSAVE-SNAPSHOT-DESIGN-2026-07-01 §2.
pub const SyncingAvWriter = struct {
    inner: *BufferedAvWriter,
    fd: std.posix.fd_t,
    since_sync: u64 = 0,

    const SYNC_EVERY_BYTES: u64 = 256 * 1024 * 1024;

    pub fn writeAll(self: *SyncingAvWriter, bytes: []const u8) !void {
        try self.inner.writeAll(bytes);
        self.maybeSync(bytes.len);
    }

    pub fn writeByte(self: *SyncingAvWriter, b: u8) !void {
        try self.inner.writeByte(b);
        self.maybeSync(1);
    }

    fn maybeSync(self: *SyncingAvWriter, n: u64) void {
        self.since_sync += n;
        if (self.since_sync >= SYNC_EVERY_BYTES) {
            std.posix.fdatasync(self.fd) catch {}; // best-effort trickle
            self.since_sync = 0;
        }
    }
};

// ── fork-BGSAVE child raw helpers (fork-safe subset — design §2). HARD
//    PROHIBITIONS inside the child, each traced to a concrete deadlock or
//    corruption in FORK-BGSAVE-FORK-SAFETY-AUDIT-2026-07-01: NO heap allocation
//    (jemalloc atfork prefork makes it survivable — treat as safety net, not
//    license), NO std.log / std.debug.print (std.Progress.stderr_mutex may be
//    frozen-held by a logging thread), NO Zig Mutex/RwLock acquisition of ANY
//    kind (inherited locks can be frozen-held), NO std.process.Child (mallocs +
//    double-fork; tar belongs to the parent), NO AF_XDP/io_uring/VexLedger/
//    socket fd contact (MAP_SHARED rings would corrupt the LIVE parent), NO
//    banks/cache/overlay structures (torn state + frozen locks in the image),
//    NO recorder contact — recorder.emitFreezeAccount / recorder.files_mutex
//    (b51e280 moved the freeze-dump onto the hot collectWrite path, so at fork
//    instant a replay worker may hold files_mutex → frozen-held in the child
//    image; re-audit 2026-07-02), NO std.posix.exit / normal return (libc
//    atexit + stdio flush over
//    possibly-frozen locks; Zig defers over copied state) — exit_group(2) only.
//    Everything below is raw syscalls + stack buffers. ──────────────────────

/// Raw, alloc-free, lock-free stderr line for the CHILD only ([vex-bgsave] tag).
pub fn bgsaveRawErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "[vex-bgsave] " ++ fmt ++ "\n", args) catch return;
    _ = std.posix.write(2, line) catch {};
}

/// CHILD-ONLY post-fork setup, in the mandated order (design §2 steps 1-2):
/// signal hygiene FIRST (the inherited SIGSEGV handler calls
/// dumpCurrentStackTrace = allocates + takes debug state — unsafe over a forked
/// image), then setsid (terminal/pgrp signal isolation), then PDEATHSIG + the
/// fork↔prctl orphan-race re-check, then comm rename (deploy.sh
/// `pkill '^vex-fd'` must never match the child), then self-demotion: isolated
/// core (operator requirement, 2026-07-02) + SCHED_IDLE, nice 19, ioprio IDLE,
/// oom_score_adj 1000 (MAXIMUM OOM preference — the child dies first, always;
/// re-audit F1, stricter than the Redis-BGSAVE 800).
pub fn bgsaveChildSetup(child_core: i64, parent_pid_before_fork: std.posix.pid_t) void {
    // 1. SIG_DFL for the eight parent-installed handlers (main.zig installSignalHandlers).
    const parent_handled_sigs = [_]u8{ 1, 2, 4, 6, 7, 8, 11, 15 };
    for (parent_handled_sigs) |sig| {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.DFL },
            .mask = @as(std.posix.sigset_t, @bitCast([_]u8{0} ** @sizeOf(std.posix.sigset_t))),
            .flags = 0,
        };
        std.posix.sigaction(sig, &act, null);
    }
    // 1b. New session (re-audit F3): detach from the parent's controlling
    //     terminal + process group so pgrp-directed signals (SIGINT/SIGHUP to
    //     the parent's group from a terminal or `kill -- -PGID`) can never kill
    //     the child spuriously. PDEATHSIG below is per-process and SURVIVES
    //     setsid — deliberate intent-kill via parent death still works.
    _ = std.os.linux.syscall0(.setsid); // best-effort (fails only if already leader)
    // 2. Parent death (watchdog VEX_WATCHDOG_RESTART posix.exit(1), crash,
    //    deploy kill) ⇒ SIGKILL us. Then close the race where the parent died
    //    BEFORE this prctl registered (PDEATHSIG would never fire).
    _ = std.posix.prctl(.SET_PDEATHSIG, .{@as(usize, std.posix.SIG.KILL)}) catch {};
    if (std.os.linux.getppid() != parent_pid_before_fork) std.os.linux.exit_group(4);
    // 3. comm = "vex-bgsave" (15-char comm limit): ps-visible, pkill '^vex-fd'-immune.
    const comm: [*:0]const u8 = "vex-bgsave";
    _ = std.posix.prctl(.SET_NAME, .{@intFromPtr(comm)}) catch {};
    // 4. Isolated core (raw sched_setaffinity — same pattern as main.zig
    //    pinToCore). Operator core-isolation directive (2026-07-02): the
    //    failure is CHECKED (re-audit F2) — an unpinned child roams the
    //    floater mask, so log it loudly (still proceed: SCHED_IDLE + nice 19 +
    //    ioprio IDLE below keep even an unpinned child preemptible-by-anyone).
    if (child_core >= 0) {
        var cpu_set = [_]usize{0} ** 16;
        const cid: u32 = @intCast(child_core);
        cpu_set[cid / @bitSizeOf(usize)] = @as(usize, 1) << @intCast(cid % @bitSizeOf(usize));
        const aff_rc = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
        if (@as(isize, @bitCast(aff_rc)) < 0) {
            bgsaveRawErr("sched_setaffinity(core {d}) FAILED rc={d} — child UNPINNED (SCHED_IDLE still applies)", .{ child_core, @as(isize, @bitCast(aff_rc)) });
        }
    }
    // 4b. SCHED_IDLE (policy 5, static priority must be 0): even a thread that
    //     SHARES the isolated core (e.g. the in-binary watchdog on core 31)
    //     ALWAYS preempts the child (re-audit F2 recommendation).
    const SchedParam = extern struct { priority: c_int };
    const sched_param = SchedParam{ .priority = 0 };
    _ = std.os.linux.syscall3(.sched_setscheduler, 0, 5, @intFromPtr(&sched_param));
    // 5. nice 19 (setpriority(PRIO_PROCESS=0, who=0=self, 19)) — moot under
    //    SCHED_IDLE but kept as belt-and-braces if 4b ever fails.
    _ = std.os.linux.syscall3(.setpriority, 0, 0, 19);
    // 6. ioprio IDLE: ioprio_set(IOPRIO_WHO_PROCESS=1, 0=self,
    //    IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE=3, data=0) = 3<<13).
    _ = std.os.linux.syscall3(.ioprio_set, 1, 0, @as(usize, 3) << 13);
    // 7. MAXIMUM OOM preference (re-audit F1 + operator directive: the child
    //    must NEVER cost the validator memory): oom_score_adj=1000 ⇒ under any
    //    memory pressure the kernel kills the CoW child first, always.
    //    posix.open null-terminates on the stack.
    if (std.posix.open("/proc/self/oom_score_adj", .{ .ACCMODE = .WRONLY }, 0)) |fd| {
        _ = std.posix.write(fd, "1000") catch {};
        std.posix.close(fd);
    } else |_| {}
}

/// PARENT-side best-effort staging cleanup (never throws — the failure policy
/// is LOG LOUD + SKIP, and even a leftover staging dir is invisible to every
/// consumer: pruneOld and vex-base-ring.sh glob only `snapshot-*.tar.zst`).
pub fn bgsaveDeleteTree(p: []const u8) void {
    if (p.len > 0 and p[0] == '/')
        std.fs.deleteTreeAbsolute(p) catch {}
    else
        std.fs.cwd().deleteTree(p) catch {};
}

/// PARENT-side CoW telemetry: this process's current Private_Dirty in KiB from
/// /proc/self/smaps_rollup. The delta across the child's lifetime ≈ the
/// realized CoW bill (Redis-style reporting, design §4 — the budget is
/// continuously validated, never assumed). Stack buffer only; 0 on any error.
pub fn readPrivateDirtyKb() u64 {
    const f = fs.cwd().openFile("/proc/self/smaps_rollup", .{}) catch return 0;
    defer f.close();
    var buf: [4096]u8 = undefined;
    const n = f.readAll(&buf) catch return 0;
    const key = "Private_Dirty:";
    const at = std.mem.indexOf(u8, buf[0..n], key) orelse return 0;
    var rest = buf[at + key.len .. n];
    if (std.mem.indexOfScalar(u8, rest, '\n')) |nl| rest = rest[0..nl];
    const trimmed = std.mem.trim(u8, rest, " \tkB");
    return std.fmt.parseInt(u64, trimmed, 10) catch 0;
}
