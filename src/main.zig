//! Vex-FD Validator Entry Point
//!
//! Migrated from Vexor 0.14.1 → Zig 0.15.2 for vex-fd.
//! Changes applied:
//!   - Removed Vexor-specific module imports (runtime, diagnostics, optimizer, installer)
//!     that don't exist in vex-fd yet (marked TODO)
//!   - ThreadSafeAllocator wrapping GPA retained (prevents concurrent alloc races)
//!   - Signal handler logic retained verbatim
//!   - build_options wired through vex-fd build.zig
//!
//! Module dependencies:
//!   - core:         vex-fd/src/core/root.zig (Pubkey, Hash, Keypair, Config)
//!   - vex_svm:      vex-fd/src/vex_svm/root.zig (Bank, executor)
//!   - vex_network:  vex-fd/src/vex_network/tvu.zig (TVU, TpuClient)
//!   - vex_store:    vex-fd/src/vex_store/root.zig (AccountsDb, LedgerDb)
//!   - vex_consensus: vex-fd/src/vex_consensus/root.zig (Tower, ConsensusEngine)

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

// Production log-level filter (2026-05-02 stderr-saturation root fix).
// Codebase had ~975 std.log.debug + 550 std.log.info sites firing per slot,
// per shred, per repair across multiple worker threads. Cumulative stderr
// volume saturated the buffered Writer after 3-10h, triggering Writer.zig:639
// unreachable panic + multi-thread SIGABRT. Five gating-pass fixes (ed7f03aa,
// 8bafb5fe, 1a0c204d, c6d7cccd, 66e354fc) reduced but never eliminated it.
//
// Setting log_level=.warn here, combined with sed-replace of std.log.debug →
// std.log.debug across src/, makes saturation mathematically impossible: only
// .warn and .err calls reach stderr. .debug and .info are runtime-filtered to
// no-ops (one integer comparison + early return — not even format-arg eval).
//
// To re-enable diagnostic output: change to .info / .debug and rebuild, OR
// build -Doptimize=Debug (slow). std.log.warn / .err calls are unaffected.
//
// FIX B3 (2026-06-14, AF_XDP catch-up wedge diagnostics — RUNTIME OVERRIDE, NO
// DEFAULT CHANGE): the comptime log_level is raised .warn → .info ONLY so that
// std.log.info call sites are COMPILED IN (the ~975 std.log.debug sites stay
// COMPILED OUT — no saturation regression there). A custom logFn (vexLogFn)
// then enforces the SAME default runtime behavior as before — only .warn/.err
// reach stderr — UNLESS the env var VEX_LOG_INFO=1 is set at launch, in which
// case .info also passes. This surfaces the EXISTING .info diagnostics during a
// wedge WITHOUT a rebuild — notably fec_resolver.zig:1536 "[FEC] #61 Recovered
// ... root gate PASS" and the "[FEC] SIMD engine" line. The only added cost vs
// the old .warn comptime filter is that .info format args are evaluated before
// vexLogFn decides to drop them; formatting (the expensive part) is still
// deferred into logFn and skipped when suppressed, so steady-state stderr
// volume is unchanged when VEX_LOG_INFO is unset. NOTE: shred.zig:1321
// "[FEC-DIAG]" is std.log.DEBUG, so this .info override does NOT surface it
// (would require .debug, which reintroduces the saturation risk — out of scope).
pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = vexLogFn,
};

// Runtime info-gate cache: 0 = uninitialized, 1 = suppress info, 2 = allow info.
// Set once on first log call from std.posix.getenv("VEX_LOG_INFO") (works under
// AT_SECURE — file caps only hide LD_*/MALLOC_CONF-style vars via secure_getenv,
// not plain getenv; same pattern as VEX_DEBUG_ALLOC below).
var vex_info_gate: std.atomic.Value(u8) = std.atomic.Value(u8).init(0);

fn vexInfoAllowed() bool {
    const cached = vex_info_gate.load(.acquire);
    if (cached != 0) return cached == 2;
    const allow = if (std.posix.getenv("VEX_LOG_INFO")) |v|
        (std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true"))
    else
        false;
    vex_info_gate.store(if (allow) 2 else 1, .release);
    return allow;
}

fn vexLogFn(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    // .warn and .err always pass (default behavior, unchanged). .info passes
    // ONLY when VEX_LOG_INFO=1. .debug is already compiled out by log_level.
    if (message_level == .info and !vexInfoAllowed()) return;
    std.log.defaultLog(message_level, scope, format, args);
}

// jemalloc runtime config via the `malloc_conf` global symbol (2026-06-10).
// jemalloc reads this symbol from the main program UNCONDITIONALLY — unlike
// the MALLOC_CONF env var, which secure_getenv() hides under AT_SECURE (this
// binary carries AF_XDP file caps, so ALL env-based allocator config is dead).
//
// TUNING (always on): the 2026-06-10 heap-profile forensic proved the
// remaining at-tip RSS growth (~23-26 GB/hr) is NOT a live-byte leak (live
// delta +367MB across ~96GiB of churn) but jemalloc DIRTY-PAGE RETENTION:
// with background_thread:false (default), decay/purge only runs piggybacked
// on per-arena allocator activity, and under Vexor's highly multi-threaded
// churn the dirty backlog outruns opportunistic purging.
//   background_thread:true → dedicated purger threads; decay honored on time.
//   dirty_decay_ms:1000    → dirty pages returned to the OS after ~1s.
//   muzzy_decay_ms:0       → no muzzy second-stage retention.
//
// PROFILING (-Djeprof diagnostic builds): adds the sampling heap profiler;
// lg_prof_interval:33 dumps every 8 GiB cumulative allocation to
// /tmp/vexjeprof.<pid>.*.heap (symbolize with llvm-symbolizer vs this binary).
comptime {
    @export(&jemalloc_conf, .{ .name = "malloc_conf" });
}
const jemalloc_conf: [*:0]const u8 = if (build_options.jeprof)
    "background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0,prof:true,prof_active:true,lg_prof_interval:33,prof_prefix:/tmp/vexjeprof"
else
    "background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0";

// vex-fd modules
const vex_svm = @import("vex_svm");
const vex_crypto = @import("vex_crypto");
const vex_store = @import("vex_store");
const vex_network = @import("vex_network");
const vex_consensus = @import("vex_consensus");
const core = @import("core");
const vex_bpf2 = @import("vex_bpf2");
const vex_topo = @import("vex_topo"); // Phase 9: declarative tile→core topology table

// vex_svm sub-exports (accessed via module import, not raw file paths)
const bootstrap_mod = vex_svm.bootstrap;
const replay_mod = vex_svm.replay_stage;

// ── CPU pinning helper ───────────────────────────────────────────────────────

fn pinToCore(core_id: u32) void {
    var cpu_set = [_]usize{0} ** 16;
    const idx = core_id / @bitSizeOf(usize);
    const bit: u6 = @intCast(core_id % @bitSizeOf(usize));
    cpu_set[idx] = @as(usize, 1) << bit;
    _ = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
    std.log.debug("[PIN] Thread pinned to core {d}\n", .{core_id});
}

// ── Global signal handler ─────────────────────────────────────────────────────

var signal_received: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

fn signalHandler(sig: c_int) callconv(.c) void {
    // Stage-D follow-up: shadow panic safety. If the current thread is
    // executing inside a `runProtected` scope, the hook calls siglongjmp
    // and never returns — the validator stays up and shadowDispatch
    // unwinds with error.ShadowPanicked.
    if (vex_bpf2.shadow_panic_safety.signalHandlerHook(sig)) {
        unreachable; // siglongjmp doesn't return
    }

    const sig_u: u32 = @intCast(sig);
    const prev = signal_received.swap(sig_u, .seq_cst);
    if (prev != 0) {
        // Already handling a signal — force exit
        std.posix.exit(128 + @as(u8, @intCast(sig)));
    }

    const msg = switch (sig) {
        2 => "[SIGNAL] Received SIGINT (2)\n",
        15 => "[SIGNAL] Received SIGTERM (15)\n",
        1 => "[SIGNAL] Received SIGHUP (1)\n",
        6 => "[SIGNAL] Received SIGABRT (6)\n",
        7 => "[SIGNAL] Received SIGBUS (7)\n",
        8 => "[SIGNAL] Received SIGFPE (8)\n",
        4 => "[SIGNAL] Received SIGILL (4)\n",
        11 => "[SIGNAL] Received SIGSEGV (11) - SEGFAULT!\n",
        else => "[SIGNAL] Received unknown signal\n",
    };
    _ = std.posix.write(2, msg) catch {};

    if (sig == 11) {
        std.debug.dumpCurrentStackTrace(null);
    }

    std.posix.exit(128 + @as(u8, @intCast(sig)));
}

fn installSignalHandlers() void {
    // SIGHUP, SIGINT, SIGILL, SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGTERM.
    // SIGILL/SIGBUS/SIGFPE added so shadow_panic_safety can intercept the
    // full set of crash signals a misbehaving V2 program can produce.
    const signals = [_]u6{ 1, 2, 4, 6, 7, 8, 11, 15 };
    for (signals) |sig| {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = signalHandler },
            .mask = @as(std.posix.sigset_t, @bitCast([_]u8{0} ** @sizeOf(std.posix.sigset_t))),
            .flags = 0,
        };
        std.posix.sigaction(sig, &act, null);
    }
    std.log.debug("[SIGNAL] Signal handlers installed for SIGHUP, SIGINT, SIGILL, SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGTERM\n", .{});
}

// ── Zig panic override (Stage-D follow-up) ─────────────────────────────────────
//
// The compiler emits panics for integer overflow, unreachable, slice
// out-of-bounds, etc. The default panic prints + aborts. We wrap it so
// that if the panic fires inside a shadow-protected scope, the hook
// siglongjmps out and the validator stays up. Outside protected scope,
// behaviour is unchanged.
fn shadowAwarePanic(msg: []const u8, ra: ?usize) noreturn {
    _ = vex_bpf2.shadow_panic_safety.zigPanicHook(msg);
    // Hook didn't consume → fall through to default panic.
    std.debug.defaultPanic(msg, ra);
}

pub const panic = std.debug.FullPanic(shadowAwarePanic);

// ── Main entry point ──────────────────────────────────────────────────────────

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

/// Config bake-in (Phase E, env leg, 2026-07-08): default the ALWAYS-ON production
/// feature envs at boot so the deploy/start script no longer has to set them — a
/// dropped env can no longer silently disable a proven feature (the class of bug the
/// -Dvex_ledger/-Dsig_vote drops were on the build side). `setenv(...,0)` only fills
/// UNSET vars, so an explicit `VEX_X=0` from the operator or an offline gate still
/// overrides. The binary links libc, so std.posix.getenv delegates to libc getenv and
/// sees these (verified). Each value is EXACTLY what the proven deploy sets, so a run
/// with these baked (envs absent) is behaviorally identical to the deploy setting them.
/// NOT baked (machine/boot/hardware/diagnostic — must stay external, see
/// VEXOR-CANONICAL-FLAGS.md §1b): VEX_BINARY, VEX_FRESH_SNAPSHOT, VEX_PARALLEL_EXEC_CORES,
/// VEX_TASKSET_CORES, VEX_UMEM_RESERVE, VEX_ENABLE_AFXDP, VEX_FORENSIC_SNAPSHOT_EVERY/FORK.
fn bakeProdEnvDefaults() void {
    // PROD-ONLY: skip entirely in offline-replay / golden-gate mode. Those runs
    // deliberately keep VEX_LEDGER / VEX_WATCHDOG_RESTART / VEX_LEADER_BROADCAST /
    // repair off (and must NOT persist a VexLedger into the read-only replay feed).
    // The bake is exclusively for a live prod deploy launched with a bare command.
    if (std.posix.getenv("VEX_LEDGER_REPLAY") != null or std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null) {
        std.log.warn("[CONFIG-BAKE] offline-replay mode — prod env bake SKIPPED (offline stays lean)", .{});
        return;
    }
    const Pair = struct { k: [*:0]const u8, v: [*:0]const u8 };
    const defaults = [_]Pair{
        .{ .k = "VEX_LEDGER", .v = "1" },
        .{ .k = "VEX_DAG_DISPATCH", .v = "1" },
        .{ .k = "VEX_PARALLEL_EXEC", .v = "1" },
        .{ .k = "VEXOR_ED25519_FEC_DEDUP", .v = "1" },
        .{ .k = "VEX_DISABLE_NETHASH", .v = "1" },
        .{ .k = "VEX_LEADER_BROADCAST", .v = "1" },
        .{ .k = "VEX_TURBINE_REAL_STAKES", .v = "1" },
        .{ .k = "VEX_STAKE_BPF", .v = "1" },
        .{ .k = "VEX_FORK_ISOLATION", .v = "1" },
        .{ .k = "VEX_REPAIR_INFLIGHT", .v = "1" },
        .{ .k = "VEX_CATCHUP_ADAPTIVE_REFIRE", .v = "1" },
        .{ .k = "VEX_VOTE_REFRESH", .v = "1" },
        .{ .k = "VEX_SWITCH_PROOF", .v = "1" },
        .{ .k = "VEX_PROP_GATE", .v = "1" },
        .{ .k = "VEX_PROP_LATCH", .v = "1" },
        // canonical vote-selection (Task-#3, Agave select_vote_and_reset_forks); REQUIRES VEX_SWITCH_PROOF (above).
        // Was proven-good in the 07-04 deploy but OMITTED from the rebuild bake → recurring switch-proof/orphan
        // wedge (2026-07-11). Baked here so supervisor/manual restarts inherit it (not just the recipe env).
        .{ .k = "VEX_CANONICAL_VOTE", .v = "1" },
        .{ .k = "VEX_VOTE_PREWARM", .v = "1" },
        .{ .k = "VEX_DISABLE_CURL_VOTES", .v = "1" },
        .{ .k = "VEX_REPAIR_SKIP_ABANDONED", .v = "1" },
        .{ .k = "VEX_WATCHDOG_RESTART", .v = "0" },
        // tuning defaults (exact proven-deploy values)
        .{ .k = "VEX_LEDGER_MAX_BYTES", .v = "107374182400" },
        .{ .k = "VEX_LEDGER_KEEP_SLOTS", .v = "216000" },
        .{ .k = "VEX_VOTE_FANOUT_ROTATIONS", .v = "3" },
    };
    var baked: usize = 0;
    for (defaults) |d| {
        if (std.posix.getenv(std.mem.span(d.k)) == null) {
            _ = setenv(d.k, d.v, 0);
            baked += 1;
        }
    }
    std.log.warn("[CONFIG-BAKE] production env defaults applied: {d}/{d} filled (unset), {d} already set by launcher", .{ baked, defaults.len, defaults.len - baked });
}

/// Value-parsed boolean env gate: armed iff the var is SET and not an explicit off ("0"/"false").
/// The pure parse (core.envFlagValueArmed, KAT'd in core/config.zig) is what the bakeProdEnvDefaults
/// override contract above ("an explicit VEX_X=0 ... still overrides") requires of every baked
/// flag's consumer — existence-only checks (`getenv(..) != null`) make `VEX_X=0` indistinguishable
/// from `VEX_X=1` (the VEX_PARALLEL_EXEC=0 offline-gate defect, fixed 2026-07-10).
fn envFlagArmed(name: []const u8) bool {
    return core.envFlagValueArmed(std.posix.getenv(name));
}

pub fn main() !void {
    // Install signal handlers FIRST to catch any crashes
    installSignalHandlers();

    // Config bake-in (Phase E): default the always-on production feature envs before
    // ANY subsystem reads them (single-threaded here). See bakeProdEnvDefaults above.
    bakeProdEnvDefaults();

    // Client identity (2026-07-10, core/version.zig): stamp the build's git hash
    // into the shared version singleton BEFORE gossip init — the gossip
    // ContactInfo self-advertisement (bincode.zig initSelf) and the metrics
    // reporter both read it. Single-threaded here; read-only afterwards.
    core.version.setGitHash(build_options.git_hash);

    // ITEM K: Ballet AVX-512 BLAKE3 boot-time KAT cross-validation.
    // Compares stdlib vs Ballet on 11 sizes × (32B + 2048B XOF) + the
    // streaming-multi-update shape used by accountLtHash. PANICS on any
    // mismatch — refuses to start rather than risk a wrong vote on bad FFI.
    // (Historical note: this ran against a Ballet AVX-512 FFI backend that was
    // removed 2026-07-12; the comparison is stdlib-vs-stdlib today and always passes.)
    @import("vex_crypto").blake3.runBalletSelfTest();

    // Initialize allocator.
    // Use c_allocator (wraps libc malloc/free via posix_memalign) instead of GPA.
    // GPA holds freed pages in an internal freelist and never calls munmap, causing
    // RSS to grow ~0.33 GB/min. c_allocator delegates all allocation to libc, which
    // allows jemalloc (via LD_PRELOAD) to handle page lifecycle including munmap.
    // ThreadSafeAllocator is not needed: CAllocator has zero mutable Zig-side state;
    // libc malloc is already thread-safe. See: council ruling 2026-04-15-rss-fix.
    //
    // DEBUG ESCAPE HATCH (2026-06-14): VEX_DEBUG_ALLOC=1 swaps in Zig's
    // DebugAllocator (page-allocator-backed, jemalloc OUT of the picture) with
    // safety on. It catches double-free / invalid-free at the offending call
    // with a real app stack, and turns use-after-free into a clean page-fault
    // (app frames, not "libjemalloc ???"). Used to localize the stochastic
    // jemalloc SIGSEGV during AF_XDP catch-up. SLOW + higher RSS — boot ONLY to
    // hunt the crash, NEVER production. thread_safe is mandatory (recv/verify/
    // replay threads all allocate).
    var dbg_alloc_inst = std.heap.DebugAllocator(.{ .thread_safe = true, .safety = true }){};
    const allocator = if (std.posix.getenv("VEX_DEBUG_ALLOC") != null)
        dbg_alloc_inst.allocator()
    else
        std.heap.c_allocator;

    printBanner();

    // PERF #3 boot self-test: exercise the std.compress.zstd decode path in THIS production binary on a
    // hardcoded real zstd frame (logs PASS/WARN). Non-fatal — the decoder is an unwired utility, not on
    // the snapshot/accounts/consensus path, so a failure must never block voting.
    // warn-level on BOTH paths: this binary suppresses info-level logs (matches the BLAKE3 boot KAT).
    if (vex_store.streaming_decompress.zstdSelfTest(allocator)) {
        std.log.warn("[ZSTD-SELFTEST] PASS — std.compress.zstd decode verified (1480B frame byte-exact)", .{});
    } else {
        std.log.warn("[ZSTD-SELFTEST] WARN — zstd decode self-test mismatch (unwired utility; not fatal)", .{});
    }

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    // --help / -h / help must print usage and exit — NEVER fall through to launching the
    // validator. Applies whether help is the command itself (`vex-fd help`, `vex-fd --help`)
    // or a flag passed to a subcommand (`vex-fd run --help`, `vex-fd validator -h`).
    if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or
        std.mem.eql(u8, command, "-h") or hasHelpFlag(args[2..]))
    {
        printUsage();
        return;
    }

    if (std.mem.eql(u8, command, "run") or std.mem.eql(u8, command, "validator")) {
        runValidator(allocator, args[2..]) catch |err| {
            const sig = signal_received.load(.seq_cst);
            std.log.debug("\n[FATAL] Validator exited with error: {any}\n", .{err});
            std.log.debug("[FATAL] Signal received: {d}\n", .{sig});
            std.log.debug("[FATAL] Timestamp: {d}\n", .{std.time.timestamp()});
            return err;
        };
        const sig = signal_received.load(.seq_cst);
        std.log.debug("\n[EXIT] Validator returned normally - signal={d}\n", .{sig});
    } else if (std.mem.eql(u8, command, "rpc")) {
        // RPC mode: a dedicated RPC node does NOT vote and serves the FULL API. Inject both
        // --no-voting and --full-rpc-api (canonical: an RPC node is `agave-validator --no-voting
        // --full-rpc-api`). The voting node, by contrast, runs the default minimal 12-method API.
        var rpc_args = try allocator.alloc([]const u8, args.len);
        defer allocator.free(rpc_args);
        rpc_args[0] = "--no-voting";
        rpc_args[1] = "--full-rpc-api";
        for (args[2..], 0..) |arg, i| {
            rpc_args[i + 2] = arg;
        }
        try runValidator(allocator, rpc_args[0..args.len]);
    } else if (std.mem.eql(u8, command, "version")) {
        printVersion();
    } else if (std.mem.eql(u8, command, "help")) {
        printUsage();
    } else if (std.mem.eql(u8, command, "xdp-selftest")) {
        cmdXdpSelfTest(allocator, args[2..]) catch |err| {
            std.log.err("[XDP-SELFTEST] failed: {any}", .{err});
            return err;
        };
    } else {
        std.log.debug("Unknown command: {s}\n", .{command});
        printUsage();
    }
}

/// Diagnostic: drive the REAL AF_XDP receive path (SharedXdpManager.registerSocket
/// + AcceleratedIO) on one interface/queue for N seconds, reporting packets
/// delivered. For validating the AF_XDP pipeline + XSKMAP keying on a veth (default
/// SKB mode) or a dedicated NIC port (--driver). Run setup-xdp-vexor.sh <iface>
/// first. NOT part of the validator `run` path.
fn cmdXdpSelfTest(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var interface: []const u8 = "";
    var queue_id: u32 = 0;
    var port: u16 = 8003;
    var duration_s: u64 = 5;
    var use_driver: bool = false;
    var zero_copy: bool = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--interface") and i + 1 < args.len) {
            i += 1;
            interface = args[i];
        } else if (std.mem.eql(u8, a, "--queue") and i + 1 < args.len) {
            i += 1;
            queue_id = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, a, "--port") and i + 1 < args.len) {
            i += 1;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, a, "--duration") and i + 1 < args.len) {
            i += 1;
            duration_s = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, a, "--driver")) {
            use_driver = true;
        } else if (std.mem.eql(u8, a, "--skb")) {
            use_driver = false;
        } else if (std.mem.eql(u8, a, "--zero-copy")) {
            zero_copy = true;
        } else if (std.mem.eql(u8, a, "--copy")) {
            zero_copy = false;
        }
    }
    if (interface.len == 0) {
        std.log.err("[XDP-SELFTEST] --interface <name> is required", .{});
        return error.MissingInterface;
    }
    try vex_network.runXdpSelfTest(allocator, interface, queue_id, port, duration_s, use_driver, zero_copy);
}

// ── Feature-gate conformance canary — force-activate override (M1) ──────────────

/// `VEX_FEATURE_FORCE_ACTIVATE=<pubkey>[,<pubkey>...]` — OFFLINE-REPLAY-ONLY.
///
/// Productizes differentiator #4 (independent second-opinion feature-gate / SIMD
/// conformance auditing): force one or more PENDING feature gates ON during an
/// offline replay so Vexor can be diffed against Agave *ahead* of the network's
/// real activation. Design: FEATURE-GATE-CONFORMANCE-CANARY-DESIGN-2026-07-12.md
/// (item (a)#1); runbook: CANARY-RUNBOOK-M1.md.
///
/// SAFETY MODEL (mirrors VEX_REPLAY_FORCE_ROOT_DEPTH, main.zig:2665, but HARD-FATAL
/// rather than ignore-and-continue — forcing a gate ON *changes execution*, so a
/// live node must never honor it, even silently): if the env is set without
/// `VEX_LEDGER_REPLAY` / `VEX_SNAPSHOT_OFFLINE`, this refuses loudly and returns an
/// error that aborts boot. Any malformed / unknown pubkey is likewise fatal.
///
/// EFFECT: flips only the in-memory `FeatureSet` gate (the same map
/// `applyNewFeatureActivations`, replay_stage.zig:9377, flips in place) — it does
/// NOT rewrite the on-chain feature account bytes and carries NO LtHash delta.
/// It therefore validates "does the feature's logic behave identically once ON,"
/// NOT "does the activation TRANSITION behave identically" (that only happens at a
/// real epoch boundary — design risk (e)). Activation slot for every forced gate =
/// the replay start slot (`root_slot + 1`, the first bank the replay evaluates), so
/// `isActive` holds across the whole window and `activationSlot()` reads back a
/// real in-window slot rather than 0 (which would falsely imply genesis activation).
///
/// NO-OP GUARANTEE: a feature already active at a slot ≤ the window start is left
/// untouched (its real activation slot is preserved) — forcing an already-on
/// feature cannot perturb the bank_hash. This is the M1 safety property the gate
/// exercises.
fn applyFeatureForceActivate(
    fs: *vex_svm.features.FeatureSet,
    allocator: std.mem.Allocator,
    root_slot: u64,
) !void {
    const feats = vex_svm.features;
    const spec = std.posix.getenv("VEX_FEATURE_FORCE_ACTIVATE") orelse return;

    const offline = std.posix.getenv("VEX_LEDGER_REPLAY") != null or
        std.posix.getenv("VEX_SNAPSHOT_OFFLINE") != null;
    if (!offline) {
        std.log.err("[FEATURE-FORCE] REFUSED — VEX_FEATURE_FORCE_ACTIVATE set without VEX_LEDGER_REPLAY / VEX_SNAPSHOT_OFFLINE (live mode). This env is OFFLINE-REPLAY-ONLY. Refusing to boot.", .{});
        return error.FeatureForceActivateLiveMode;
    }

    // First bank the replay actually evaluates (root is already frozen from snapshot).
    const target_slot = root_slot + 1;

    var it = std.mem.tokenizeAny(u8, spec, ", \t\r\n");
    var forced: usize = 0;
    var noop: usize = 0;
    while (it.next()) |tok| {
        var pk: [32]u8 = undefined;
        core.base58.decodeToBuf(tok, &pk) catch {
            std.log.err("[FEATURE-FORCE] REFUSED — '{s}' is not a valid base58 pubkey. VEX_FEATURE_FORCE_ACTIVATE takes comma-separated feature pubkeys.", .{tok});
            return error.FeatureForceActivateBadPubkey;
        };

        var kf_name: ?[]const u8 = null;
        for (feats.KNOWN_FEATURES) |kf| {
            if (std.mem.eql(u8, &kf.pubkey, &pk)) {
                kf_name = kf.name;
                break;
            }
        }
        if (kf_name == null) {
            std.log.err("[FEATURE-FORCE] REFUSED — pubkey '{s}' is not in KNOWN_FEATURES ({d} entries). Valid feature names follow:", .{ tok, feats.KNOWN_FEATURES.len });
            var b: [64]u8 = undefined;
            for (feats.KNOWN_FEATURES) |kf| {
                const pkb = core.base58.encodeToBuf(&kf.pubkey, &b) catch kf.name;
                std.log.err("[FEATURE-FORCE]   {s} = {s}", .{ kf.name, pkb });
            }
            return error.FeatureForceActivateUnknownFeature;
        }
        const name = kf_name.?;

        // In-place flip on the pre-seeded map slot (no alloc / rehash — the same
        // mechanic applyNewFeatureActivations uses, replay_stage.zig:9377).
        if (fs.slots.getPtr(pk)) |v| {
            if (v.* != feats.FEATURE_DISABLED and v.* <= target_slot) {
                noop += 1;
                std.log.warn("[FEATURE-FORCE] already-active (no-op) name={s} pubkey={s} activation_slot={d}", .{ name, tok, v.* });
            } else {
                const was = v.*;
                v.* = target_slot;
                forced += 1;
                std.log.warn("[FEATURE-FORCE] *** FORCED-ACTIVE name={s} pubkey={s} activation_slot={d} (was {s}) — OFFLINE REPLAY", .{ name, tok, target_slot, if (was == feats.FEATURE_DISABLED) @as([]const u8, "pending") else "future-activation" });
            }
        } else {
            // Defensive: unreachable for KNOWN_FEATURES (all pre-seeded at boot).
            try fs.activate(allocator, pk, target_slot);
            forced += 1;
            std.log.warn("[FEATURE-FORCE] *** FORCED-ACTIVE name={s} pubkey={s} activation_slot={d} (seeded) — OFFLINE REPLAY", .{ name, tok, target_slot });
        }
    }

    std.log.warn("[FEATURE-FORCE] summary forced={d} noop={d} target_slot={d} — in-memory gate only (account bytes NOT rewritten, no LtHash delta; validates feature LOGIC parity, not the activation transition)", .{ forced, noop, target_slot });
}

// ── Validator runtime ─────────────────────────────────────────────────────────

fn runValidator(allocator: std.mem.Allocator, args: []const []const u8) !void {
    std.log.debug("\nStarting Vex-FD Validator...\n\n", .{});

    // Feature-gate conformance canary (M1): fail-fast interlock. VEX_FEATURE_FORCE_
    // ACTIVATE is OFFLINE-REPLAY-ONLY and force-activating a gate CHANGES execution,
    // so a live node must refuse BEFORE doing any boot/network work (not merely at
    // the later FeatureSet-construction check, which applyFeatureForceActivate also
    // enforces as defense-in-depth). Mirror of VEX_REPLAY_FORCE_ROOT_DEPTH's shape,
    // but hard-fatal rather than ignore-and-continue.
    if (std.posix.getenv("VEX_FEATURE_FORCE_ACTIVATE") != null and
        std.posix.getenv("VEX_LEDGER_REPLAY") == null and
        std.posix.getenv("VEX_SNAPSHOT_OFFLINE") == null)
    {
        std.log.err("[FEATURE-FORCE] REFUSED — VEX_FEATURE_FORCE_ACTIVATE set without VEX_LEDGER_REPLAY / VEX_SNAPSHOT_OFFLINE (live mode). This env is OFFLINE-REPLAY-ONLY. Refusing to boot.", .{});
        return error.FeatureForceActivateLiveMode;
    }

    var use_bootstrap = false;
    var debug_mode = false;
    // Wave 3.5: BPF2 trace level. Default = on_error (errors only, low cost).
    var bpf_trace_level: vex_bpf2.trace.Level = .on_error;
    var bpf_self_test_requested = false;
    // Wave 4: BPF stack mode. Default = .v1 (current behavior, byte-identical
    // to today's binary). `.v2` and `.shadow` require selfTest.smoke to pass
    // before they engage; otherwise the validator refuses to start.
    var bpf_stack_mode: vex_bpf2.dispatch_mode.BpfStackMode = .v1;
    var bpf_shadow_log_override: ?[]const u8 = null;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--bootstrap") or
            std.mem.eql(u8, arg, "--production") or
            std.mem.eql(u8, arg, "--full-start"))
        {
            use_bootstrap = true;
        }
        if (std.mem.eql(u8, arg, "--debug") or
            std.mem.eql(u8, arg, "--verbose") or
            std.mem.eql(u8, arg, "-v"))
        {
            debug_mode = true;
        }
        // --bpf-stack-trace={off,on-error,verbose}
        if (std.mem.startsWith(u8, arg, "--bpf-stack-trace=")) {
            const val = arg["--bpf-stack-trace=".len..];
            if (std.mem.eql(u8, val, "off")) {
                bpf_trace_level = .off;
            } else if (std.mem.eql(u8, val, "on-error")) {
                bpf_trace_level = .on_error;
            } else if (std.mem.eql(u8, val, "verbose")) {
                bpf_trace_level = .verbose;
                bpf_self_test_requested = true;
            } else {
                std.log.debug("[MAIN] WARNING: unknown --bpf-stack-trace value '{s}'; using on-error\n", .{val});
            }
        }
        // Wave 4: --bpf-stack={v1,v2,shadow}
        if (std.mem.startsWith(u8, arg, "--bpf-stack=")) {
            const val = arg["--bpf-stack=".len..];
            if (std.mem.eql(u8, val, "v1")) {
                bpf_stack_mode = .v1;
            } else if (std.mem.eql(u8, val, "v2")) {
                bpf_stack_mode = .v2;
                bpf_self_test_requested = true;
            } else if (std.mem.eql(u8, val, "shadow")) {
                bpf_stack_mode = .shadow;
                bpf_self_test_requested = true;
            } else {
                std.log.debug("[MAIN] WARNING: unknown --bpf-stack value '{s}'; using v1\n", .{val});
            }
        }
        // Wave 4: --bpf-stack-shadow-log=<path>
        if (std.mem.startsWith(u8, arg, "--bpf-stack-shadow-log=")) {
            bpf_shadow_log_override = arg["--bpf-stack-shadow-log=".len..];
        }
        // Stage-D: --bpf-stack-shadow-log-rate=auto|1|10|100|1000
        // Controls shadow-mode steady-state line rate. `auto` (default)
        // is the adaptive ramp: every line for first 1k, 1/10 for next 9k,
        // 1/100 thereafter. Errors are NEVER rate-limited.
        if (std.mem.startsWith(u8, arg, "--bpf-stack-shadow-log-rate=")) {
            const val = arg["--bpf-stack-shadow-log-rate=".len..];
            const safety = vex_bpf2.shadow_safety;
            if (std.mem.eql(u8, val, "auto")) {
                safety.setRateOverride(.auto);
            } else if (std.mem.eql(u8, val, "1")) {
                safety.setRateOverride(.every_1);
            } else if (std.mem.eql(u8, val, "10")) {
                safety.setRateOverride(.every_10);
            } else if (std.mem.eql(u8, val, "100")) {
                safety.setRateOverride(.every_100);
            } else if (std.mem.eql(u8, val, "1000")) {
                safety.setRateOverride(.every_1000);
            } else {
                std.log.debug("[MAIN] WARNING: unknown --bpf-stack-shadow-log-rate value '{s}'; using auto\n", .{val});
            }
        }
    }
    // Honour the env var override too: VBPF2_SELFTEST=1 forces the dashboard
    // even when the CLI flag is off/on-error.
    if (std.posix.getenv("VBPF2_SELFTEST")) |sv| {
        if (std.mem.eql(u8, sv, "1") or std.mem.eql(u8, sv, "true")) {
            bpf_self_test_requested = true;
        }
    }
    // Apply trace level globally before any vex_bpf2 call site emits.
    vex_bpf2.trace.setLevel(bpf_trace_level);
    if (bpf_self_test_requested) {
        // Print the wireup dashboard to stderr. Do NOT exit on failure —
        // this is informational; Wave 4 gates --bpf-stack=v2 on smoke result.
        const stderr_w = vex_bpf2.self_test.fileWriter(std.fs.File.stderr());
        const report = vex_bpf2.self_test.run(stderr_w) catch |err| blk: {
            std.log.debug("[VBPF2-WIRE] self_test FAILED to run: {s}\n", .{@errorName(err)});
            break :blk vex_bpf2.self_test.Report{
                .modules = &.{},
                .aggregate_ok = false,
                .smoke_test_passed = false,
                .total_tests = 0,
            };
        };
        if (!report.aggregate_ok) {
            std.log.debug("[VBPF2-WIRE] aggregate NOT GREEN — Wave 4 gating will block --bpf-stack=v2\n", .{});
        }

        // Wave 4 gate: --bpf-stack=v2 / shadow refuse to engage when the
        // smoke pipeline failed. We log the reason and demote to .v1 so
        // the validator continues to boot in the legacy code path. This
        // is the "smoke gate" — V2 cannot run unless the boot smoke is OK.
        if (bpf_stack_mode != .v1 and !report.smoke_test_passed) {
            std.log.debug(
                "[VBPF2-WIRE] REFUSING --bpf-stack={s}: smoke_test_passed=false. " ++
                    "Demoting to --bpf-stack=v1 and continuing boot.\n",
                .{@tagName(bpf_stack_mode)},
            );
            bpf_stack_mode = .v1;
        }
    } else if (bpf_stack_mode != .v1) {
        // Belt-and-braces: v2 / shadow always require a passing self_test
        // run, even if --bpf-stack-trace was not set. Force the smoke now.
        const stderr_w = vex_bpf2.self_test.fileWriter(std.fs.File.stderr());
        const r = vex_bpf2.self_test.run(stderr_w) catch |err| blk: {
            std.log.debug("[VBPF2-WIRE] self_test FAILED to run: {s}\n", .{@errorName(err)});
            break :blk vex_bpf2.self_test.Report{
                .modules = &.{},
                .aggregate_ok = false,
                .smoke_test_passed = false,
                .total_tests = 0,
            };
        };
        if (!r.smoke_test_passed) {
            std.log.debug(
                "[VBPF2-WIRE] REFUSING --bpf-stack={s}: smoke_test_passed=false. " ++
                    "Demoting to --bpf-stack=v1 and continuing boot.\n",
                .{@tagName(bpf_stack_mode)},
            );
            bpf_stack_mode = .v1;
        }
    }

    // Wave 4: publish the resolved mode + shadow-log path globally, then
    // lock so no replay-thread can race a setMode().
    vex_bpf2.dispatch_mode.setMode(bpf_stack_mode);
    if (bpf_shadow_log_override) |p| vex_bpf2.dispatch_mode.setShadowLogPath(p);
    vex_bpf2.dispatch_mode.lockForReadOnly();

    // Phase-1 Core-BPF Stake dual-path env gate. Read VEX_STAKE_BPF ONCE here
    // (like other VEX_ flags), before any replay thread spawns. DEFAULT OFF →
    // stake instructions take the native handler path, byte-identical to today.
    vex_bpf2.stake_bpf_flag.init();
    if (vex_bpf2.stake_bpf_flag.enabled()) {
        std.log.warn("[CBPF-STAKE] VEX_STAKE_BPF=1 — stake instructions route through the SBPF VM when migrate_stake_program_to_core_bpf is active (Phase-1 dual-path ON)", .{});
    }

    if (bpf_stack_mode != .v1) {
        std.log.debug(
            "[VBPF2-WIRE] BPF stack mode = {s} (shadow log = {s})\n",
            .{ @tagName(bpf_stack_mode), vex_bpf2.dispatch_mode.shadowLogPath() },
        );
    }

    if (debug_mode) {
        std.log.debug("DEBUG MODE ENABLED\n", .{});
        std.log.debug("  OS: {s}\n", .{@tagName(@import("builtin").os.tag)});
        std.log.debug("  Arch: {s}\n", .{@tagName(@import("builtin").cpu.arch)});
    }

    // Load configuration
    // Zig 0.15.2: Config.load uses ArrayListUnmanaged internally
    const config = try core.Config.load(allocator, args);
    defer config.deinit();

    // Print execution environment
    {
        const is_x86_64 = @import("builtin").cpu.arch == .x86_64;
        const cpufiles = @import("builtin").cpu.features;
        const has_avx512 = if (is_x86_64) std.Target.x86.featureSetHas(cpufiles, .avx512f) else false;
        const has_avx2 = if (is_x86_64) std.Target.x86.featureSetHas(cpufiles, .avx2) else false;
        const has_gfni = if (is_x86_64) std.Target.x86.featureSetHas(cpufiles, .gfni) else false;

        std.log.debug("\nExecution Environment:\n", .{});
        std.log.debug("  CPU Architecture: {s}\n", .{@tagName(@import("builtin").cpu.arch)});
        std.log.debug("  AVX-512:  {s}\n", .{if (has_avx512) "ENABLED" else "disabled"});
        std.log.debug("  AVX2:     {s}\n", .{if (has_avx2) "ACTIVE" else "MISSING"});
        std.log.debug("  GFNI:     {s}\n", .{if (has_gfni) "ACTIVE" else "MISSING"});
        std.log.debug("  Shred version: {d}\n", .{config.expected_shred_version orelse 0});
        std.log.debug("\n", .{});
    }

    // ── Halt-restart safety parameter visibility ──────────────────────────────
    // Per Solana testnet restart docs (linked in core/config.zig): join-late
    // nodes must have --expected-shred-version + --expected-bank-hash +
    // --wait-for-supermajority configured correctly. Vexor previously silently
    // dropped --expected-bank-hash and --wait-for-supermajority — fixed
    // 2026-05-05 to parse + log them. Snapshot-bootstrap from slots well past
    // wait-for-supermajority slot inherits the post-restart state from the
    // snapshot's FeatureSet, so these are visibility-only for join-late nodes.
    std.log.warn("[CONFIG] Halt-restart safety params:", .{});
    std.log.warn("[CONFIG]   --expected-shred-version = {d}", .{config.expected_shred_version orelse 0});
    if (config.expected_genesis_hash) |gh| {
        std.log.warn("[CONFIG]   --expected-genesis-hash  = {s}", .{gh});
    } else {
        std.log.warn("[CONFIG]   --expected-genesis-hash  = (not set)", .{});
    }
    if (config.expected_bank_hash) |bh| {
        std.log.warn("[CONFIG]   --expected-bank-hash     = {s}", .{bh});
    } else {
        std.log.warn("[CONFIG]   --expected-bank-hash     = (not set — halt-restart safety check INACTIVE)", .{});
    }
    if (config.wait_for_supermajority) |s| {
        std.log.warn("[CONFIG]   --wait-for-supermajority = slot {d}", .{s});
    } else {
        std.log.warn("[CONFIG]   --wait-for-supermajority = (not set)", .{});
    }

    if (use_bootstrap) {
        // Production mode: Full bootstrap with snapshot download, tower loading, voting
        std.log.debug("Starting PRODUCTION MODE (with snapshot bootstrap)...\n\n", .{});

        if (config.identity_path == null) {
            std.log.debug("[ERROR] --identity is required for production mode\n", .{});
            return error.IdentityRequired;
        }

        const bootstrap_config = bootstrap_mod.BootstrapConfig{
            .identity_path = config.identity_path.?,
            .vote_account_path = config.vote_account_path,
            .ledger_dir = config.ledger_path,
            .accounts_dir = config.accounts_path,
            .snapshots_dir = config.snapshots_path,
            .rpc_url_override = config.rpc_url_override,
            .cluster = @tagName(config.cluster),
            .enable_voting = config.enable_voting,
            .enable_parallel_snapshot = config.enable_parallel_snapshot,
            .parallel_snapshot_threads = @intCast(config.parallel_snapshot_threads),
            .force_fresh_snapshot = config.force_fresh_snapshot,
            // Genesis mode: skip snapshot, create empty slot-0 bank for localnet
            .genesis_mode = (config.cluster == .localnet),
        };

        var bootstrap = try bootstrap_mod.ValidatorBootstrap.init(allocator, bootstrap_config);
        defer bootstrap.deinit();

        const result = try bootstrap.bootstrap();

        // ── TASK 1: --expected-bank-hash halt-restart safety gate (2026-06-15) ──
        // Mirrors Agave's halt-on-bank-hash-mismatch boot check. ADDITIVE: only
        // runs when --expected-bank-hash is set; otherwise this block is a no-op
        // and boot is byte-for-byte unchanged. On mismatch we refuse to start so
        // the node never joins consensus on a divergent snapshot.
        if (config.expected_bank_hash) |expected_b58| {
            const loaded_hash = result.root_bank.bank_hash.data; // [32]u8 from snapshot
            const loaded_b58 = try core.base58.encode(allocator, &loaded_hash);
            defer allocator.free(loaded_b58);
            switch (core.restart_gate.checkExpectedBankHash(allocator, expected_b58, loaded_hash)) {
                .match => std.log.warn(
                    "[RESTART-GATE] expected bank hash CONFIRMED: snapshot bank at slot {d} has hash {s} == --expected-bank-hash",
                    .{ result.root_bank.slot, loaded_b58 },
                ),
                .mismatch => {
                    std.log.err(
                        "[RESTART-GATE] expected bank hash {s} but loaded snapshot bank at slot {d} has hash {s} — refusing to start",
                        .{ expected_b58, result.root_bank.slot, loaded_b58 },
                    );
                    return error.ExpectedBankHashMismatch;
                },
                .invalid_expected => {
                    std.log.err(
                        "[RESTART-GATE] --expected-bank-hash {s} is not a valid 32-byte base58 hash — refusing to start (loaded slot {d} hash {s})",
                        .{ expected_b58, result.root_bank.slot, loaded_b58 },
                    );
                    return error.ExpectedBankHashInvalid;
                },
            }
        }

        // Set the root bank on the replay stage so it can create child banks
        result.replay_stage.root_bank.store(result.root_bank, .release);
        std.log.debug("[MAIN] Replay stage root_bank set to slot {d}\n", .{result.root_bank.slot});

        // Connect AccountsDb for account loading during tx execution
        result.replay_stage.setAccountsDb(result.accounts_db);

        // ANCHOR-ROOT (2026-06-06): a snapshot is taken at a ROOTED slot, so the
        // accounts-db consensus root MUST start AT the snapshot slot. Without this,
        // db.rooted_slot stays 0 until the first advanceRoot — but consensus_root
        // (= db.rooted_slot) is read by the chain-gap / orphan-repair logic, which
        // b2b7b42 re-keyed onto the consensus root. With consensus_root=0 at fresh
        // boot, that logic chases orphan slots BELOW the snapshot (parents that can
        // never be replayed) instead of replaying the handful of slots forward to
        // the tip → catch-up wedges on EVERY fresh-snapshot boot, never voting.
        // Canonical (Agave/Sig): the loaded snapshot slot IS the initial root.
        result.accounts_db.rooted_slot = result.root_bank.slot;
        std.log.warn("[ANCHOR-ROOT] db.rooted_slot initialized to snapshot slot {d}", .{result.root_bank.slot});

        // Phase D: boot recorder EARLY (right after AccountsDb wiring) so
        // catchup is captured. Previously boot()'d after TVU spawn; that
        // missed the entire catchup window where Phase 1D/1E's regression
        // mechanism fires (bounded ancestors[] false-flags canonical writes).
        // Recorder is gated by VEX_RECORD_READS/WRITES env vars — invisible
        // by default. FeatureSet load reads (~10-20) below will be captured
        // but tagged with current_slot=0 → dropped by emitRead's boundCheck.
        vex_store.recorder.boot();

        // Build the live FeatureSet from on-chain feature accounts.
        // Lifetime matches the validator process — declared here, wired to
        // the replay stage, never destroyed before exit.
        var live_feature_set = vex_svm.features.FeatureSet.init();
        defer live_feature_set.deinit(allocator);
        {
            const stats = live_feature_set.loadFromAccountsDb(allocator, result.accounts_db) catch |err| blk: {
                std.debug.print("[FEATURES] loadFromAccountsDb error: {any} — FeatureSet will be empty\n", .{err});
                break :blk vex_svm.features.FeatureSet.LoadStats{
                    .total_known = 0,
                    .found = 0,
                    .activated = 0,
                    .pending = 0,
                    .skipped_bad_owner = 0,
                    .skipped_bad_size = 0,
                    .skipped_parse_error = 0,
                };
            };
            const current_slot: u64 = result.root_bank.slot;
            std.debug.print(
                "[FEATURES] Loaded {d} activated / {d} total known features (current slot {d}; {d} pending, {d} accounts not found, owner-skip {d}, size-skip {d}, parse-skip {d})\n",
                .{
                    stats.activated,        stats.total_known,               current_slot,
                    stats.pending,          stats.total_known - stats.found, stats.skipped_bad_owner,
                    stats.skipped_bad_size, stats.skipped_parse_error,
                },
            );
        }

        // Feature-gate conformance canary (M1): offline-replay-only force-activate
        // override. Refuses loudly (hard-fatal) if set in live mode. See
        // applyFeatureForceActivate + CANARY-RUNBOOK-M1.md.
        try applyFeatureForceActivate(&live_feature_set, allocator, result.root_bank.slot);

        result.replay_stage.setLiveFeatureSet(&live_feature_set);

        // d28ff (2026-05-12): leader schedule computed natively from snapshot's
        // per-epoch vote_account_stakes (no RPC dependency). Agave-canonical
        // port — see src/vex_consensus/leader_schedule_agave.zig (passes 4
        // Agave test_case vectors byte-for-byte). RPC fallback retained for
        // historical/diagnostic only; not on the hot path.
        var leader_cache = vex_consensus.leader_schedule.LeaderScheduleCache.init(allocator);
        const rpc_url = config.rpc_url_override orelse config.getRpcUrl();
        std.log.warn("[MAIN] Computing leader schedule natively from epoch_stakes (epoch={d})...", .{
            leader_cache.generator.getEpoch(result.start_slot),
        });
        leader_cache.populateAgaveCanonical(result.accounts_db, result.start_slot) catch |err| {
            std.log.warn("[MAIN] Native leader-schedule compute failed: {any} — falling back to RPC fetch", .{err});
            leader_cache.fetchFromRpc(rpc_url, result.start_slot) catch |rpc_err| {
                std.log.warn("[MAIN] RPC leader-schedule fallback also failed: {any} (fees WILL be burned, parity WILL diverge)", .{rpc_err});
            };
        };
        // carrier #16 final gate blocker (2026-06-12): ALSO populate the NEXT
        // epoch's schedule. A boot whose snapshot sits at the last slot of an
        // epoch (close-boot gate: 414812255) replays the boundary slot in the
        // NEXT epoch — with only the start-slot epoch cached, getSlotLeader
        // misses -> collector_id stays zero -> freeze BURNS the leader's 50%
        // fee share (canonical credits it) -> bank_hash diverges by exactly
        // the fee (@414812256: 1,367,500 lamports to the leader). Canonical
        // Agave always has the leader_schedule_epoch (+1) schedule;
        // epoch_stakes(next) is in the snapshot manifest, so the native
        // generator can always serve it.
        {
            const cur_epoch = leader_cache.generator.getEpoch(result.start_slot);
            const next_first = leader_cache.generator.getFirstSlotInEpoch(cur_epoch + 1);
            leader_cache.populateAgaveCanonical(result.accounts_db, next_first) catch |err| {
                std.log.warn("[MAIN] Native leader-schedule for NEXT epoch {d} failed: {any} (boundary-slot fees would burn)", .{ cur_epoch + 1, err });
            };
        }
        // Wire leader lookup function to replay stage
        const LeaderLookup = struct {
            var cache: *vex_consensus.leader_schedule.LeaderScheduleCache = undefined;
            var rpc: []const u8 = undefined;
            fn lookup(slot_val: u64) ?core.Pubkey {
                // Update current slot estimate for vote leader targeting
                if (slot_val > cache.current_slot_estimate) {
                    cache.current_slot_estimate = slot_val;
                }
                const leader = cache.getSlotLeader(slot_val);
                if (leader == null) {
                    // Leader not found — likely crossed an epoch boundary.
                    // Trigger a background re-fetch at most once per 1000 slots to avoid
                    // hammering RPC. lookup() is called from replay, not the hot-path inner loop.
                    const S = struct {
                        var last_fetch_slot: u64 = 0;
                    };
                    if (slot_val > S.last_fetch_slot + 1000) {
                        S.last_fetch_slot = slot_val;
                        std.log.debug("[LeaderLookup] Epoch boundary detected at slot {d}, refreshing schedule...\n", .{slot_val});
                        cache.fetchFromRpc(rpc, slot_val) catch |err| {
                            std.log.debug("[LeaderLookup] Schedule refresh failed: {any}\n", .{err});
                        };
                    }
                }
                return leader;
            }
        };
        LeaderLookup.cache = &leader_cache;
        LeaderLookup.rpc = rpc_url;
        result.replay_stage.getSlotLeader = &LeaderLookup.lookup;

        // PHASE-2 (2026-05-26): bootstrap-time seed of fork_choice's latest_votes
        // was REMOVED here after advisor review — the cold-start BootstrapBhCtx
        // could only resolve root_bank.slot, so every other voter's lastVote
        // landed as `no_bank_hash` and the call emitted ~0 votes. Placeholder
        // code on the bootstrap path hides whether the future replacement wires
        // up correctly; the per-bank delta hook at replay_stage.zig:~2535
        // populates `latest_votes` incrementally as banks freeze (convergence
        // within seconds at cluster pace) so the seed is not a correctness
        // requirement to reach steady-state.
        //
        // Phase 2.5 will re-introduce a real bootstrap seed using
        // SlotHashes-sysvar-based bank_hash resolution (capable of returning
        // a hash for the full ~512-slot ring, not just the snapshot anchor).
        // `vex_svm.fork_choice_feed.buildSeedBatch` and its 23 unit tests
        // remain available in the worktree for that future call.

        // Wire vote submission config (identity keypair + vote account)
        // The identity_kp is loaded later for gossip, so we load it here too
        if (config.identity_path) |id_path| {
            const vote_identity_kp = bootstrap_mod.loadKeypairFromFile(allocator, id_path) catch null;
            if (vote_identity_kp) |kp| {
                result.replay_stage.setVoteConfig(kp.secret, core.Pubkey{ .data = kp.public.data });
                // If vote account path provided, use that pubkey instead
                if (config.vote_account_path) |va_path| {
                    const vote_kp = bootstrap_mod.loadKeypairFromFile(allocator, va_path) catch null;
                    if (vote_kp) |vkp| {
                        result.replay_stage.vote_account = core.Pubkey{ .data = vkp.public.data };
                        std.log.debug("[MAIN] Vote account set to {x:0>2}{x:0>2}..{x:0>2}{x:0>2}\n", .{
                            vkp.public.data[0], vkp.public.data[1], vkp.public.data[30], vkp.public.data[31],
                        });
                    }
                }
            }
        }

        // d27k (2026-05-11): RPC-based catchup REMOVED.
        //
        // The bootstrap-to-tip gap is now closed via the canonical Agave +
        // Firedancer pattern: turbine-seeded repair burst. On the first
        // turbine shred received in `TvuService.processShred`, the TVU
        // captures `turbine_slot0` and fires `RepairHighestWindowIndex`
        // requests at every slot in `(snapshot_root, turbine_slot0]`,
        // round-robin across gossip peers. Repair responses flow back
        // through the existing shred-assembler + replay pipeline.
        //
        // The snapshot_root is communicated to TVU via `setCatchupRoot`
        // right before tvu_svc.start() (see below). The seed burst is
        // gated by an atomic so it fires exactly once.
        //
        // Why this replaces the sequential `catchUpReplay` loop:
        //  - Sequential RPC is ~1-2 slots/sec end-to-end (HTTP round-trip
        //    bound by public-RPC rate limits). Gap grew pass-over-pass
        //    in empirical testing (360 → 731 → 1766 → 4646 slots).
        //  - Repair is UDP, parallel across peers, runs at
        //    hundreds-to-thousands of slots/sec.
        //  - No `RpcClient` or `getBlock` in Agave `core/src/` (verified
        //    2026-05-11 by parallel agent investigation).
        //  - Firedancer commit `090e2f8de` (PR #9314) "repair: construct
        //    startup repair requests from root to turbine_slot0" landed
        //    exactly this pattern as their canonical bootstrap catchup.
        std.log.warn("[CATCHUP] RPC catchup disabled per d27k — repair will burst on first turbine shred (snapshot_root={d})", .{result.start_slot});

        std.log.debug("Bootstrap complete!\n", .{});
        std.log.debug("  Start slot:      {d}\n", .{result.start_slot});
        std.log.debug("  Accounts loaded: {d}\n", .{result.accounts_loaded});
        std.log.debug("  Total lamports:  {d}\n", .{result.total_lamports});
        const idx_count = result.accounts_db.index.totalCount();
        std.log.debug("  Index entries:   {d}\n", .{idx_count});
        // Verify index works by looking up System program (all-zeros pubkey)
        const sys_pk = core.Pubkey{ .data = [_]u8{0} ** 32 };
        const sys_result = result.accounts_db._getRooted(&sys_pk);
        std.log.debug("  System program:  {s}\n\n", .{if (sys_result != null) "FOUND" else "NOT FOUND"});

        // Start gossip service (must come before TVU so peers discover us)
        const identity_kp = bootstrap_mod.loadKeypairFromFile(allocator, config.identity_path.?) catch |err| {
            std.log.debug("[MAIN] Failed to load identity for gossip: {any}\n", .{err});
            return err;
        };
        const identity_pubkey = identity_kp.public;
        var gossip_svc = vex_network.gossip.GossipService.init(allocator, identity_pubkey, .{
            .gossip_port = config.gossip_port, // must match ContactInfo advertisement
            .gossip_bind_addr = config.gossip_bind_addr, // dual-NIC source-IP fix (2026-07-06)
            .tvu_port = config.tvu_port,
            .repair_port = config.repair_port,
            .tpu_port = config.tpu_port,
            .rpc_port = config.rpc_port,
        });
        defer gossip_svc.deinit();
        gossip_svc.shred_version = config.expected_shred_version orelse 0;
        // A3b snapshot-trust: point gossip at the trusted --known-validator set so the
        // gated tag-10 ingest accepts only their SnapshotHashes. Empty ⇒ inert.
        gossip_svc.setKnownValidators(config.known_validators);

        // Add testnet entrypoints
        for (config.entrypoints) |ep| {
            // Parse "host:port" format
            if (std.mem.lastIndexOfScalar(u8, ep, ':')) |colon| {
                const host = ep[0..colon];
                const port = std.fmt.parseInt(u16, ep[colon + 1 ..], 10) catch 8001;
                gossip_svc.addEntrypoint(host, port) catch |err| {
                    std.log.debug("[MAIN] Failed to add entrypoint {s}: {any}\n", .{ ep, err });
                };
            }
        }

        // Set our ContactInfo (public IP + ports) so peers know where to send shreds
        if (config.public_ip) |ip| {
            gossip_svc.setSelfInfo(
                ip,
                config.gossip_port, // 8000
                config.tpu_port, // 8004
                config.tvu_port, // 8003
                config.repair_port, // 8002
                config.rpc_port, // 8899
            );
            std.log.debug("[MAIN] Gossip ContactInfo set: {d}.{d}.{d}.{d}\n", .{ ip[0], ip[1], ip[2], ip[3] });
        } else {
            std.log.debug("[MAIN] WARNING: No --public-ip set! Peers cannot send us shreds!\n", .{});
        }

        // Set keypair for signing gossip messages
        gossip_svc.keypair = &identity_kp;

        // GOSSIP-FED PROP_RETARGET wiring: inject the vote-tx length parser (P2 CRDS
        // Vote delimiting) + the vote sink → ReplayStage.latest_gossip_votes. Both
        // are byte-inert to consensus unless VEX_GOSSIP_PROP is set; the parser fix
        // is a pure correctness improvement to multi-value CRDS packet walking.
        gossip_svc.setParseVoteTx(&vex_svm.gossip_votes.parseTxConsumed);
        gossip_svc.setGossipVoteSink(.{
            .ctx = @ptrCast(result.replay_stage),
            .func = &vex_svm.replay_stage.ReplayStage.onGossipVoteThunk,
        });

        gossip_svc.start() catch |err| {
            std.log.debug("[MAIN] Gossip start failed: {any}\n", .{err});
        };
        std.log.debug("[MAIN] Gossip service started (shred_version={d})\n", .{gossip_svc.shred_version});

        // Spawn gossip run loop in background thread (pinned to its OWN core).
        const gossip_thread = std.Thread.spawn(.{}, struct {
            fn run(svc: *vex_network.gossip.GossipService) void {
                // Pin gossip to core 24 (own CCX6, isolated from the main/control
                // thread which defaults to core 5, from replay on 16, and repair on
                // 30). 2026-06-16: gossip was pinned to core 5 and COLLIDED with the
                // unpinned main thread — post-restart EpochSlots gossip volume
                // saturated core 5 and starved replay dispatch → delinquent.
                // Phase 9: default = vex_topo table (.gossip == core 24, byte-identical);
                // VEX_LEGACY_PINS / -Dlegacy_pins reverts to the inline pinToCore(24).
                if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) {
                    pinToCore(24);
                } else {
                    _ = vex_topo.pinTile(vex_topo.LIVE, .gossip, 0);
                }
                svc.run() catch |err| {
                    std.log.debug("[MAIN] Gossip run loop exited: {any}\n", .{err});
                };
            }
        }.run, .{&gossip_svc}) catch |err| {
            std.log.debug("[MAIN] Failed to spawn gossip thread: {any}\n", .{err});
            return err;
        };
        _ = gossip_thread; // detach — runs until shutdown

        // Start TVU networking (shred reception, repair, verify)
        var tvu_config = vex_network.TvuService.Config{};
        tvu_config.shred_version = config.expected_shred_version orelse 0;
        tvu_config.keypair = &identity_kp;
        tvu_config.tvu_port = config.tvu_port; // 8003
        tvu_config.repair_port = config.repair_port; // 8002
        // d27i (2026-05-11): wire the global --repair-interface / --interface flags
        // into the TVU config. Without this, tvu_config.repair_interface stayed ""
        // (default), the condition at tvu.zig:549 `repair_interface.len > 0` was
        // false, and the AF_XDP repair init block was silently skipped — explaining
        // the "no AF_XDP log lines, no XDP program attached" symptoms with
        // --enable-af-xdp on the cmdline. Mellanox-retry session 2026-05-11.
        tvu_config.repair_interface = config.repair_interface;
        tvu_config.interface = config.repair_interface; // primary iface for AF_XDP RX
        tvu_config.repair_bind_addr = config.repair_bind_addr;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--enable-af-xdp")) tvu_config.enable_af_xdp = true;
            if (std.mem.eql(u8, arg, "--xdp-zero-copy")) tvu_config.xdp_zero_copy = true;
        }

        var tvu_svc = try vex_network.TvuService.init(allocator, tvu_config);
        defer tvu_svc.deinit();
        // #66 fix (2026-06-25): wire leader_cache + catchup_root BEFORE setGossipService, because
        // setGossipService triggers the FIRST updateTurbineTree() (tvu.zig:605). Without the cache + a
        // non-zero catchup_root, that first build falls back to a uniform (NON-canonical) broadcast tree
        // for ~30s until the periodic rebuild — the boot "epoch_stakes EMPTY → uniform-1000" warning.
        // SAFETY: both setters only set their own fields, and leader_cache is still set AFTER
        // TvuService.init (line 926), so verify_tile's init-captured leader_cache copy stays null (the
        // shred-sig invariant — repair/turbine read self.leader_cache directly). Real epoch stakes were
        // already populated at populateAgaveCanonical above, so the FIRST broadcast tree is now canonical.
        // (setLeaderCache also feeds the gated repair stake-weighting getRepairPeers→fillStakesForSlot.)
        tvu_svc.setLeaderCache(&leader_cache);
        tvu_svc.setCatchupRoot(result.start_slot); // snapshot root → turbine-seeded catchup-repair burst (processShred)
        tvu_svc.setGossipService(&gossip_svc);
        tvu_svc.setSlotSink(result.replay_stage.slotSink());
        // leader_mode: wire the produce→broadcast callback. Replay produces empty-block bytes on our
        // leader slots and hands them here; TVU shreds (KAT-green block_broadcast) + transmits to the
        // turbine roots. comptime-gated → zero footprint when -Dleader_mode is off.
        if (comptime build_options.leader_mode) {
            const BcWrap = struct {
                fn f(ctx: *anyopaque, slot: u64, parent_slot: u64, entry_bytes: []const u8, chained_root: [32]u8, secret: [64]u8, shred_version: u16) void {
                    const t: *vex_network.TvuService = @ptrCast(@alignCast(ctx));
                    t.broadcastProducedBlock(slot, parent_slot, entry_bytes, chained_root, secret, shred_version);
                }
            };
            result.replay_stage.setProduceBroadcast(tvu_svc, BcWrap.f, tvu_config.shred_version);
            // Multi-slot leader-window chaining (2026-06-19): wire the compute-block_id callback so a
            // produced slot's last-FEC merkle root is fed forward as the next slot's chained_root
            // (reuses the produce_broadcast_ctx set above). Without this, slots 2..N of our leader
            // window skip ("parent block_id null") even with broadcast on.
            const BidWrap = struct {
                fn f(ctx: *anyopaque, entry_bytes: []const u8, slot: u64, parent_slot: u64, chained_root: [32]u8, secret: [64]u8, shred_version: u16, out: *[32]u8) bool {
                    const t: *vex_network.TvuService = @ptrCast(@alignCast(ctx));
                    return t.computeProducedBlockId(entry_bytes, slot, parent_slot, chained_root, secret, shred_version, out);
                }
            };
            result.replay_stage.setProduceBlockId(BidWrap.f);
            std.log.warn("[LEADER-MODE] block production WIRED (produce→broadcast→loopback, no self-vote) shred_version={d}", .{tvu_config.shred_version});
        }
        // (d27k 2026-05-11: setCatchupRoot — the snapshot root slot the turbine-seeded
        // catchup-repair burst in processShred uses — was MOVED UP to line 938, before
        // setGossipService, by the #66 fix so the first updateTurbineTree() sees it. Same
        // value (result.start_slot); the original call here is removed to avoid a redundant
        // idempotent re-set.)

        std.log.debug("[MAIN] TVU service initialized after bootstrap\n", .{});
        try tvu_svc.start();

        // ── A3b snapshot-trust: post-load / PRE-VOTE gate ──────────────────────────
        // Gated by VEX_SNAPSHOT_TRUST (off=byte-identical: this whole block is skipped).
        // Validates the LOADED snapshot's ARCHIVE (slot,hash) against a known-validator
        // gossip agreement (Agave validator/src/bootstrap.rs build_known_snapshot_hashes,
        // keep-first/conflict-drop) — applied POST-load/PRE-vote (we can't un-load; abort
        // before the first vote). absent≠abort (a known-validator that hasn't advertised
        // OUR exact slot ⇒ proceed); only a PRESENT-AND-MISMATCHED vouch logs (log mode)
        // or aborts (reject mode). The bounded wait gives the gate teeth (an empty table ⇒
        // all-absent ⇒ pass would be theater). Coverage: catches a poisoned snapshot AT a
        // known-validator-advertised slot; broader "any poisoned snapshot" = deferred A4.
        snaptrust_gate: {
            const st_mode = vex_network.gossip.GossipService.SnapTrust.mode();
            if (st_mode == .off) break :snaptrust_gate;
            if (config.known_validators.len == 0) {
                std.log.warn("[SNAPSHOT-TRUST] no --known-validator set — skipping gate", .{});
                break :snaptrust_gate;
            }
            const archive_hash = result.base_archive_hash orelse {
                std.log.warn("[SNAPSHOT-TRUST] no base archive hash (genesis/no-manifest) — skipping gate", .{});
                break :snaptrust_gate;
            };
            const loaded_slot = result.start_slot;
            // BOUNDED WAIT: poll until all known-validators advertise, or timeout (absent
            // never aborts — timeout just proceeds with whatever arrived).
            const WAIT_SECS: u64 = 30;
            var waited: u64 = 0;
            while (waited < WAIT_SECS) : (waited += 1) {
                var present: usize = 0;
                for (config.known_validators) |kv| {
                    if (gossip_svc.getSnapshotHashes(kv) != null) present += 1;
                }
                if (present == config.known_validators.len) break;
                std.log.info("[SNAPSHOT-TRUST] waiting for known-validator SnapshotHashes {d}/{d} ({d}s)", .{ present, config.known_validators.len, waited });
                std.Thread.sleep(1 * std.time.ns_per_s);
            }
            // Build the keep-first/conflict-drop agreement from whatever arrived.
            const fulls = try allocator.alloc(?vex_network.snapshot_trust.SlotHash, config.known_validators.len);
            defer allocator.free(fulls);
            for (config.known_validators, 0..) |kv, idx| {
                fulls[idx] = if (gossip_svc.getSnapshotHashes(kv)) |sh|
                    .{ .slot = sh.slot, .hash = sh.hash }
                else
                    null;
            }
            var agreement = try vex_network.snapshot_trust.build(allocator, fulls);
            defer agreement.deinit();
            if (agreement.conflicts > 0)
                std.log.warn("[SNAPSHOT-TRUST] ⚠️ {d} known-validator (slot,hash) CONFLICT(s) — trusted validators disagree on a slot", .{agreement.conflicts});
            // Distinguish absent vs present-mismatch vs present-match for OUR loaded slot.
            if (agreement.map.get(loaded_slot)) |vouched_hash| {
                if (std.mem.eql(u8, &vouched_hash, &archive_hash)) {
                    std.log.warn("[SNAPSHOT-TRUST] ✅ loaded snapshot slot={d} VOUCHED by known-validators", .{loaded_slot});
                } else if (st_mode == .reject) {
                    std.log.err("[SNAPSHOT-TRUST] ❌ loaded snapshot slot={d} MISMATCH vs known-validator agreement — REFUSING to vote (reject mode)", .{loaded_slot});
                    return error.SnapshotNotVouched;
                } else {
                    std.log.warn("[SNAPSHOT-TRUST] ⚠️ loaded snapshot slot={d} MISMATCH vs known-validator agreement (log mode — proceeding; would ABORT in reject)", .{loaded_slot});
                }
            } else {
                std.log.warn("[SNAPSHOT-TRUST] loaded snapshot slot={d} not advertised by any known-validator (absent) — proceeding", .{loaded_slot});
            }
        }

        // ── Phase-1 tile→core topology banner (2026-06-22, observability) ──────────
        // One-time WARN logging the FINAL tile→core map the BINARY controls, so the
        // live pinning is confirmable from the log. Static hot tiles are UNMOVED
        // (conservative/additive rework). The dynamic-relief pool (CCX0 1-3) is set
        // by tools/vex-fd-pin.sh, which the binary cannot observe — noted as such.
        std.log.warn(
            "[TOPO] static: recv={d} quic-pump={d} verify={d}-{d} replay={d} produce={d} gossip={d} txsend={d} sysvar={d} repair={d} | floaters: rpc={d} quic_poller={d}(==txsend) afxdp_workers=cold1[dormant] fetch_workers=cold1[dormant] | dynamic-relief: CCX0 {d},{d},{d} (vex-fd-pin.sh) | reserved: {s}",
            .{
                vex_topo.LIVE.recv,
                vex_topo.LIVE.quic,
                vex_topo.LIVE.verify_base,
                vex_topo.LIVE.verify_base + vex_topo.NUM_VERIFY_WORKERS - 1,
                vex_topo.LIVE.replay,
                vex_topo.LIVE.produce,
                vex_topo.LIVE.gossip,
                vex_topo.LIVE.txsend,
                vex_topo.LIVE.sysvar,
                vex_topo.LIVE.repair,
                vex_topo.LIVE.rpc,
                vex_topo.LIVE.txsend,
                vex_topo.COLD_CCX0_RELIEF[0],
                vex_topo.COLD_CCX0_RELIEF[1],
                vex_topo.COLD_CCX0_RELIEF[2],
                vex_topo.COLD_CCX0_RESERVED_PHASE2,
            },
        );

        // ── task #13 LOOPBACK: QUIC TPU ingest → mempool → real (non-empty) block production ──
        // GATE: VEX_TPU_INGEST (env, default OFF), INDEPENDENT of VEX_LEADER_BROADCAST. When unset,
        // this whole block is skipped: no QUIC server is bound, no mempool exists, replay's
        // banking_stage stays null → produceAndBroadcastEmptySlot takes the byte-identical empty path.
        // Broadcast stays separately OFF (VEX_LEADER_BROADCAST untouched) → tx-bearing blocks only
        // loop back to our own bank, never reaching the cluster.
        // Hoisted so the RPC server (created below) can reuse the SAME mempool for sendTransaction.
        // null when VEX_TPU_INGEST is off → sendTransaction returns a JSON-RPC error (RULE #0).
        var banking_handle: ?*vex_svm.banking_stage.BankingStage = null;
        if (std.posix.getenv("VEX_TPU_INGEST") != null) {
            // The mempool must outlive the QUIC pump thread AND replay; heap-allocate so the pointer
            // handed to both the adapter and replay is stable. Process-lifetime (freed at exit).
            const banking = try allocator.create(vex_svm.banking_stage.BankingStage);
            banking.* = vex_svm.banking_stage.BankingStage.init(allocator, .{});
            banking_handle = banking;

            // Bind the advertised tpu_quic port = tpu_port + 6 (constant aligned in commit b6ae490).
            const tpu_quic_port: u16 = config.tpu_port + 6;
            const quic_server = try vex_network.solana_quic.SolanaTpuQuic.init(allocator, .{
                .is_server = true,
                .bind_port = tpu_quic_port,
            });
            try quic_server.listen(tpu_quic_port);

            // The adapter bridges raw QUIC bytes → parse-validate → mempool. Heap-allocate so its
            // address (the callback ctx) stays stable for the server's lifetime.
            const adapter = try allocator.create(vex_network.quic_ingest_adapter.QuicIngestAdapter);
            adapter.* = vex_network.quic_ingest_adapter.QuicIngestAdapter.init(banking);
            quic_server.setTransactionCallback(adapter, vex_network.quic_ingest_adapter.QuicIngestAdapter.onTransaction);

            // Wire the mempool into replay so produced leader blocks pack drained txs (loopback-only).
            result.replay_stage.setBankingStage(banking);

            // Spawn a pinned detached pump thread: poll() drains QUIC streams → adapter → mempool.
            // Mirrors the gossip thread spawn (main.zig:875) + the KAT's loopbackServerPump.
            const quic_pump_thread = std.Thread.spawn(.{}, struct {
                fn run(srv: *vex_network.solana_quic.SolanaTpuQuic) void {
                    // Phase 9: default = vex_topo table (.quic == core 6, byte-identical);
                    // VEX_LEGACY_PINS / -Dlegacy_pins reverts to the inline pinToCore(6).
                    if (build_options.legacy_pins or std.posix.getenv("VEX_LEGACY_PINS") != null) {
                        pinToCore(6);
                    } else {
                        _ = vex_topo.pinTile(vex_topo.LIVE, .quic, 0);
                    }
                    while (srv.running.load(.acquire)) {
                        srv.poll() catch {};
                        std.Thread.sleep(200 * std.time.ns_per_us);
                    }
                }
            }.run, .{quic_server}) catch |err| {
                std.log.warn("[TPU-INGEST] failed to spawn QUIC pump thread: {any}", .{err});
                return err;
            };
            _ = quic_pump_thread; // detach — runs until process exit
            std.log.warn("[TPU-INGEST] QUIC TPU ingest WIRED (port={d} → mempool → loopback block production, NO broadcast)", .{tpu_quic_port});

            // 2026-06-16 BLOCK-PRODUCTION TILE ISOLATION (Firedancer replay→pack→poh→replay).
            // Move block production OFF the replay tile (core 16) onto a dedicated PRODUCE tile
            // (core 20) so QUIC-TPU drain+pack+PoH+shred+broadcast NEVER steal replay cycles (the
            // delinquency cause). Replay now only EMITS a become-leader frag (Ring A) at the
            // isLeader detection and CONSUMES a slot-done frag (Ring B) for the loopback — the block
            // is built entirely on the produce tile. comptime-gated on -Dleader_mode (this build),
            // runtime-gated by enableProduceTile() so it's only ever active under VEX_TPU_INGEST.
            // Block bytes come from the same block_produce.zig → no consensus-byte change.
            // task #26: VEX_FORCE_INLINE_PRODUCE skips the produce tile so block production runs on the
            // INLINE replay path — the one carrying the task #25/26 SEQUENTIAL inclusion gate (the tile's
            // snapshot gate is a later flip-blocker). Used to EXERCISE/test the gate in loopback. When
            // unset (default), the isolated tile is spawned exactly as before (byte-identical).
            if (comptime build_options.leader_mode) {
                if (std.posix.getenv("VEX_FORCE_INLINE_PRODUCE") != null) {
                    std.log.warn("[PRODUCE-TILE] DISABLED via VEX_FORCE_INLINE_PRODUCE — block production on the INLINE replay path (sequential inclusion gate active)", .{});
                } else {
                    try result.replay_stage.enableProduceTile();
                    const produce_tile_thread = std.Thread.spawn(.{}, struct {
                        fn run(rs: *vex_svm.replay_stage.ReplayStage) void {
                            rs.produceTileLoop();
                        }
                    }.run, .{result.replay_stage}) catch |err| {
                        std.log.warn("[PRODUCE-TILE] failed to spawn produce tile thread: {any}", .{err});
                        return err;
                    };
                    _ = produce_tile_thread; // detach — runs until process exit
                    std.log.warn("[PRODUCE-TILE] block production isolated onto core 20 (off replay core 16)", .{});
                }
            }
        }

        // task #32: liveness WATCHDOG (gated -Dwatchdog; default build comptime-excludes it ⇒ byte-
        // identical). Read-only observer of ReplayStats liveness atomics; alerts on a wedge, and
        // restarts (exit 1) only when VEX_WATCHDOG_RESTART is set.
        if (comptime build_options.watchdog) {
            const watchdog_thread = std.Thread.spawn(.{}, struct {
                fn run(rs: *vex_svm.replay_stage.ReplayStage) void {
                    // Watchdog pin 1→31 (2026-06-23 cores-0-4 wall-off): CCX0 cores 0-4 are now
                    // OS/kernel-only, enforced by a cgroup-v2 cpuset (cpus=5-31) at deploy time.
                    // pinToCore(1) would EINVAL inside the cpuset. Core 31 is the free tail of CCX7
                    // (txsend=28/sysvar=29/repair=30) — a low-duty home for this low-duty poll loop,
                    // off the hot pipeline, inside the cpuset.
                    pinToCore(31);
                    rs.watchdogLoop();
                }
            }.run, .{result.replay_stage}) catch |err| {
                std.log.warn("[WATCHDOG] failed to spawn: {any}", .{err});
                return err;
            };
            _ = watchdog_thread; // detach — runs until process exit
            std.log.warn("[WATCHDOG] liveness watchdog spawned (-Dwatchdog)", .{});
        }

        // ── FORENSIC DENSE SNAPSHOTS (env-gated, default OFF) ───────────────────────────────────
        // Periodic background full-snapshot CREATION for forensic offline replay. The minimal-tier
        // voting node otherwise emits only 88-byte .marker files (snapshot_service) and full creation
        // is reachable only via the full-API saveAccountsSnapshot RPC the voting node rejects — so a
        // carrier can sit >10k slots from the nearest durable base. This wires the EXISTING, proven
        // SnapshotManager.saveFullSnapshot (the same writer that RPC uses) onto a timer so the running
        // node emits dense, durable, extractable bases.
        //
        // DORMANCY CONTRACT: when VEX_FORENSIC_SNAPSHOT_EVERY is UNSET (or 0) this is a COMPLETE no-op
        // — no thread is spawned, nothing is allocated, and the consensus/replay/vote path is byte-
        // identical. Everything below is reached ONLY when the operator opts in.
        // SECOND GATE (MUST-FIX #1, 2026-07-02): even with EVERY>0 the tool stays DISARMED unless
        // VEX_FORENSIC_SNAPSHOT_FORK is ALSO set (=1 fork-BGSAVE / =0 explicit legacy) — see the
        // arming resolve below. Two explicit envs are required before ANY snapshot path can run.
        //
        // CONSENSUS-SAFE: the worker reads the FROZEN, ROOTED tip bank (replay_stage.root_bank, the
        // rooted+flushed canonical state — strictly more correct than the RPC's possibly-unrooted
        // ctx.bank) and emits an artifact; it never mutates bank_hash. bank_fields are taken from ONE
        // root_bank read immediately before the writer call (RULE: no latch-then-walk skew).
        //
        // LIVENESS NOTE (HUMAN deploy call, RULE #10): writeSnapshotAppendVec holds
        // accounts_db.storage.lock SHARED for the whole index walk; replay's account WRITES need it
        // EXCLUSIVE, so replay-writes BLOCK for the walk duration regardless of which thread runs it
        // (off-thread only moves the tar/zstd CPU off the critical path AFTER the lock releases). Keep
        // the cadence COARSE. Default OFF; the operator decides cadence/deploy.
        arming: {
            const fs_every_str = std.posix.getenv("VEX_FORENSIC_SNAPSHOT_EVERY");
            const fs_interval: u64 = if (fs_every_str) |s|
                (std.fmt.parseInt(u64, std.mem.trim(u8, s, " \t\r\n"), 10) catch 0)
            else
                0;
            if (fs_interval > 0) {
                // ── MUST-FIX #1 (critic 2026-07-01) + operator directive
                // 2026-07-02 ("the tool CANNOT affect the validator — it must
                // be armed explicitly"): DEFAULT-OFF three-state arming gate.
                // VEX_FORENSIC_SNAPSHOT_FORK unset/unrecognized ⇒ DISARMED:
                // NOTHING below runs — no worker thread, no fs_dir mkdir, and
                // in particular the legacy ~41 s storage.lock staller (the
                // 2026-07-01 live-delinquency incident) is UNREACHABLE even
                // with EVERY>0. FORK=1 arms the fork-BGSAVE path; FORK=0 is
                // the EXPLICIT opt-in to the legacy in-thread saver (rollback
                // sibling). Resolver unit-KAT'd in tests/kat_bgsave_fork.zig;
                // integration half = offline gate leg D (off-means-off).
                const fs_arming = vex_store.SnapshotManager.resolveForkArming(std.posix.getenv("VEX_FORENSIC_SNAPSHOT_FORK"));
                if (fs_arming == .disarmed) {
                    std.log.warn("[FORENSIC-SNAP] VEX_FORENSIC_SNAPSHOT_EVERY={d} is set but VEX_FORENSIC_SNAPSHOT_FORK is unset/unrecognized — snapshot tool stays DISARMED (default-OFF, MUST-FIX #1). Set VEX_FORENSIC_SNAPSHOT_FORK=1 (fork-BGSAVE, isolated child) or =0 (legacy in-thread saver: holds storage.lock SHARED ~41 s — replay-writes block).", .{fs_interval});
                    break :arming;
                }
                const fs_dir_default = "/mnt/snapshots/vex-forensic-ring";
                const fs_dir = try allocator.dupe(u8, std.posix.getenv("VEX_FORENSIC_SNAPSHOT_DIR") orelse fs_dir_default);
                if (std.fs.path.isAbsolute(fs_dir))
                    std.fs.makeDirAbsolute(fs_dir) catch {}
                else
                    std.fs.cwd().makePath(fs_dir) catch {};
                const fs_keep: u32 = if (std.posix.getenv("VEX_FORENSIC_SNAPSHOT_KEEP")) |s|
                    (std.fmt.parseInt(u32, std.mem.trim(u8, s, " \t\r\n"), 10) catch 4)
                else
                    4;
                const fs_poll_secs: u64 = if (std.posix.getenv("VEX_FORENSIC_SNAPSHOT_POLL")) |s|
                    (std.fmt.parseInt(u64, std.mem.trim(u8, s, " \t\r\n"), 10) catch 15)
                else
                    15;
                const fs_pin_core: i64 = if (std.posix.getenv("VEX_FORENSIC_SNAPSHOT_CORE")) |s|
                    (std.fmt.parseInt(i64, std.mem.trim(u8, s, " \t\r\n"), 10) catch -1)
                else
                    -1;

                // ── fork()-BGSAVE (task #26, 2026-07-01) ─────────────────────
                // Design: vexor-designs/FORK-BGSAVE-SNAPSHOT-DESIGN-2026-07-01.md
                // Mode comes from the three-state arming gate above (default-
                // OFF; we only get here armed). fork mode: the legacy in-thread
                // path's ~41 s storage.lock hold (replay writeAccount blocked →
                // the recurring ~13-min transient delinquency) collapses to
                // captureTip + bin sweep + fork() (~100-500 ms budget).
                // Rollback is VEX_FORENSIC_SNAPSHOT_FORK=0 — an env flip, no
                // rebuild; legacy saveFullSnapshotAtTip stays byte-frozen.
                // NOTE: with fork mode ON, VEX_FORENSIC_SNAPSHOT_CORE pins the
                // CHILD (isolated core, operator requirement), not this worker.
                const fs_fork: bool = (fs_arming == .fork);
                const fs_timeout_secs: u64 = if (std.posix.getenv("VEX_FORENSIC_SNAPSHOT_TIMEOUT")) |s|
                    (std.fmt.parseInt(u64, std.mem.trim(u8, s, " \t\r\n"), 10) catch 1800)
                else
                    1800;
                const fs_verify: bool = if (std.posix.getenv("VEX_FORENSIC_SNAPSHOT_VERIFY")) |s|
                    !std.mem.eql(u8, std.mem.trim(u8, s, " \t\r\n"), "0")
                else
                    true;
                const fs_fork_fallback: bool = if (std.posix.getenv("VEX_FORENSIC_SNAPSHOT_FORK_FALLBACK")) |s|
                    std.mem.eql(u8, std.mem.trim(u8, s, " \t\r\n"), "1")
                else
                    false;

                const Forensic = struct {
                    allocator: std.mem.Allocator,
                    rs: *vex_svm.replay_stage.ReplayStage,
                    adb: *vex_store.accounts.AccountsDb,
                    manager: vex_store.SnapshotManager,
                    dir: []const u8,
                    interval: u64,
                    keep: u32,
                    poll_secs: u64,
                    pin_core: i64,
                    fork_enabled: bool,
                    timeout_secs: u64,
                    verify: bool,
                    fork_fallback: bool,

                    fn run(self: *@This()) void {
                        // fork-BGSAVE pinning split (design §3): in fork mode
                        // VEX_FORENSIC_SNAPSHOT_CORE pins the CHILD process; this
                        // worker becomes a lightweight unpinned poll loop (nice 19
                        // kept below). Legacy mode keeps the old worker pinning.
                        if (self.pin_core >= 0 and !self.fork_enabled) pinToCore(@intCast(self.pin_core));
                        // Lowest scheduling priority for this thread AND any tar/zstd child it forks
                        // (children inherit the caller-thread nice at fork). Best-effort; ignore errs.
                        _ = std.os.linux.syscall3(.setpriority, 0, 0, 19);
                        // fork-BGSAVE: kill any orphaned vex-bgsave child left by a
                        // PREVIOUS incarnation (pid-file + comm check; PDEATHSIG covers
                        // the common case — this is the restart-sweep belt-and-braces).
                        if (self.fork_enabled) {
                            vex_store.SnapshotManager.sweepStaleBgsave(self.dir);
                            // Crash-orphan sweep: a parent death mid-cycle strands
                            // local-snapshot-<slot>/ staging dirs (tens of GB) and
                            // snapshot-*.tar.zst.tmp partials that pruneOld skips by
                            // design — without this they leak the ring toward ENOSPC.
                            vex_store.SnapshotManager.sweepOrphanedStaging(self.dir);
                        }
                        // DIAGNOSTIC: confirm whether the snapshot index-walk drops accounts before
                        // committing to a fix. Fast (no 32G write). Set VEX_FORENSIC_SNAPSHOT_DIAG=1.
                        if (std.posix.getenv("VEX_FORENSIC_SNAPSHOT_DIAG") != null) {
                            std.Thread.sleep(2 * std.time.ns_per_s); // let boot settle
                            const d = self.adb.snapshotWalkDiag();
                            std.log.warn("[FORENSIC-DIAG] index_entries={d} storage_null={d} (store_id_missing={d} getaccount_null={d}) null_resolved_by_bulk={d} null_resolved_by_cache={d} rooted_slot={d}", .{
                                d.entries, d.storage_null, d.store_id_missing, d.getaccount_null, d.null_resolved_by_bulk, d.null_resolved_by_cache, self.adb.rooted_slot,
                            });
                            return; // diagnostic only — no snapshot
                        }
                        // Cadence is driven by the CONSENSUS ROOT (db.rooted_slot), the slot the
                        // snapshot is actually taken at — NOT the frozen tip. Seed at the boot root so
                        // we don't immediately snapshot the boot slot, and so we never fire while
                        // rooted_slot is still the snapshot-loaded base (whose bank is not in
                        // self.banks). VEX_FORENSIC_SNAPSHOT_AT_BOOT seeds below the boot root so the
                        // FIRST poll snapshots the current rooted slot immediately (capture a base at
                        // boot; also the offline-gate hook since the offline harness never roots).
                        var last: u64 = if (std.posix.getenv("VEX_FORENSIC_SNAPSHOT_AT_BOOT") != null)
                            (self.adb.rooted_slot -| self.interval)
                        else
                            self.adb.rooted_slot;
                        while (true) {
                            std.Thread.sleep(self.poll_secs * std.time.ns_per_s);
                            const rooted: u64 = self.adb.rooted_slot;
                            if (rooted < last +| self.interval) continue;
                            // Fire: saveFullSnapshotAtTip re-reads db.rooted_slot via captureTip
                            // UNDER the storage lock (replay-writes blocked) so the manifest slot
                            // and the walked accounts are the SAME slot — no latch-then-walk skew.
                            const t0 = std.time.milliTimestamp();
                            // fork-BGSAVE (task #26): default path. The parent
                            // returns from the lock window in ms (fork_ms); this
                            // worker then blocks HERE on the WNOHANG reap loop —
                            // which also implements the single-child latch: the
                            // next interval cannot fire while a child runs.
                            var fr = blk: {
                                if (self.fork_enabled) {
                                    const opts = vex_store.SnapshotManager.BgsaveOptions{
                                        // Operator core-isolation directive (2026-07-02)
                                        // + re-audit F2: the child ALWAYS gets a
                                        // dedicated core in fork mode. Default 31:
                                        // inside the deploy cgroup cpuset 5-31 (0-4
                                        // would EINVAL), off replay/recv/verify/wave
                                        // CCXs, off external-forensics cores 28-30;
                                        // shares 31 only with the in-binary watchdog
                                        // (15 s two-atomic poll), which always
                                        // preempts the SCHED_IDLE child.
                                        .child_core = if (self.pin_core >= 0) self.pin_core else 31,
                                        .timeout_secs = self.timeout_secs,
                                        .verify = self.verify,
                                    };
                                    if (self.manager.saveFullSnapshotForked(self.adb, @ptrCast(self.rs), captureTip, opts)) |r| {
                                        break :blk r;
                                    } else |err| {
                                        // Per-cycle degradation (design §3): ONLY a
                                        // failed fork(2) may fall back to one legacy
                                        // in-thread save (accepting one ~41 s stall),
                                        // and only when the operator opted in.
                                        if (err == error.BgsaveForkFailed and self.fork_fallback) {
                                            std.log.warn("[FORENSIC-SNAP] fork() failed — FALLBACK to legacy in-thread save this cycle (VEX_FORENSIC_SNAPSHOT_FORK_FALLBACK=1)", .{});
                                            break :blk self.manager.saveFullSnapshotAtTip(self.adb, @ptrCast(self.rs), captureTip) catch |err2| {
                                                std.log.warn("[FORENSIC-SNAP] rooted~{d} legacy fallback FAILED: {s}", .{ rooted, @errorName(err2) });
                                                last = rooted; // don't hammer on a persistent failure
                                                continue;
                                            };
                                        }
                                        // Child/arming failures log the marker at their
                                        // site, but parent-side classes (tar, manifest,
                                        // status-cache, fsync/rename) reach ONLY this
                                        // catch-all — it must carry the marker too: the
                                        // guardian and offline gate grep for it. Staging
                                        // and .tmp are cleaned by errdefers inside.
                                        std.log.warn("[FORENSIC-SNAP-FORK-FAIL] rooted~{d} saveFullSnapshotForked FAILED: {s} — skipping cycle", .{ rooted, @errorName(err) });
                                        last = rooted; // don't hammer on a persistent failure
                                        continue;
                                    }
                                }
                                break :blk self.manager.saveFullSnapshotAtTip(self.adb, @ptrCast(self.rs), captureTip) catch |err| {
                                    std.log.warn("[FORENSIC-SNAP] rooted~{d} saveFullSnapshotAtTip FAILED: {s}", .{ rooted, @errorName(err) });
                                    last = rooted; // don't hammer on a persistent failure
                                    continue;
                                };
                            };
                            const ms = std.time.milliTimestamp() - t0;
                            std.log.warn(
                                "[FORENSIC-SNAP] wrote slot={d} accounts={d} lamports={d} manifest_bytes={d} ms={d} tar={s}",
                                .{ fr.slot, fr.accounts_written, fr.lamports_total, fr.manifest_bytes, ms, fr.tar_path },
                            );
                            // Reclaim the uncompressed staging dir (local-snapshot-<slot>/) — the
                            // durable artifact is the tar.zst; the staging tree is redundant.
                            deleteTreePath(fr.output_dir);
                            last = fr.slot; // the ACTUAL captured (under-lock) slot
                            fr.deinit(self.allocator);
                            self.pruneOld();
                        }
                    }

                    // Invoked ONCE by saveFullSnapshotAtTip while the accounts storage lock is held
                    // shared. CRITICAL: snapshot the CONSENSUS ROOT (db.rooted_slot), NOT the frozen
                    // tip (root_bank). The account index/storage that the walk reads reflects state
                    // promoted up to db.rooted_slot ONLY — frozen-but-unrooted slots' writes live in
                    // the two-tier ring / unflushed_cache and are NOT in the walked storage. The
                    // frozen tip leads the rooted slot by the consensus-root gap (~32 slots offline),
                    // so tagging the manifest with the tip over rooted-state accounts diverges on
                    // reload. Under the held storage.lock-shared, advanceRoot (which needs the lock
                    // EXCLUSIVE) is blocked, so db.rooted_slot is STABLE and its ring-promotion into
                    // storage already completed (it runs before db.advanceRoot) — so (rooted_slot,
                    // storage state, rooted bank fields) are mutually consistent. ctx is the
                    // *ReplayStage. Fields mirror rpc_methods.zig saveAccountsSnapshot (2158-2172).
                    fn captureTip(ctx_ptr: *anyopaque) vex_store.SnapshotManager.CapturedTip {
                        const rs: *vex_svm.replay_stage.ReplayStage = @ptrCast(@alignCast(ctx_ptr));
                        const db = rs.accounts_db orelse return .{
                            .slot = 0,
                            .fields = std.mem.zeroes(vex_store.SnapshotManager.FullSnapshotBankFields),
                        };
                        const rooted: u64 = db.rooted_slot;
                        // The rooted bank carries the bank_hash / accounts_lthash for `rooted`.
                        rs.banks_lock.lockShared();
                        const maybe_bank = rs.banks.get(rooted);
                        rs.banks_lock.unlockShared();
                        const rb = maybe_bank orelse blk: {
                            // The snapshot-LOADED base bank is not in self.banks but IS root_bank at
                            // boot; when root_bank.slot == rooted the tip-pointer IS the rooted bank
                            // (storage fully reflects it) — exact, not skewed. Otherwise (tip leads the
                            // rooted slot, or no tip) we'd produce a TIP-SKEWED snapshot tagged at the
                            // rooted slot — a silently-wrong forensic base that's worse than none. ABORT
                            // (slot=0 sentinel → saveFullSnapshotAtTip skips); the worker retries next
                            // cycle once the rooted bank is in bank_forks.
                            const tip = rs.root_bank.load(.acquire) orelse return .{
                                .slot = 0,
                                .fields = std.mem.zeroes(vex_store.SnapshotManager.FullSnapshotBankFields),
                            };
                            if (tip.slot != rooted) {
                                std.log.warn("[FORENSIC-SNAP] rooted bank {d} not in bank_forks (tip={d}) — SKIPPING this cycle (refusing a tip-skewed snapshot)", .{ rooted, tip.slot });
                                return .{
                                    .slot = 0,
                                    .fields = std.mem.zeroes(vex_store.SnapshotManager.FullSnapshotBankFields),
                                };
                            }
                            break :blk tip;
                        };
                        const lt_ptr: *const [2048]u8 = rb.accounts_lthash.asBytes();
                        return .{
                            .slot = rb.slot,
                            .fields = .{
                                .parent_slot = rb.parent_slot orelse 0,
                                .bank_hash = rb.bank_hash.data,
                                .parent_hash = rb.parent_hash.data,
                                .last_blockhash = rb.poh_hash.data,
                                .capitalization = rb.capitalization,
                                .block_height = rb.block_height,
                                .hashes_per_tick = if (rb.hashes_per_tick == 0) null else rb.hashes_per_tick,
                                .ticks_per_slot = rb.ticks_per_slot,
                                .epoch = rb.epoch_schedule.getEpoch(rb.slot),
                                .block_id = rb.block_id,
                                .accounts_lt_hash = lt_ptr.*,
                                // CONSENSUS-CRITICAL for round-trip: carry the governor +
                                // signature_count that seed the reloaded root bank's per-slot
                                // RecentBlockhashes lamports_per_signature (see FullSnapshotBankFields).
                                .fee_rate_governor = rb.fee_rate_governor,
                                .signature_count = rb.signature_count,
                            },
                        };
                    }

                    fn deleteTreePath(p: []const u8) void {
                        if (p.len > 0 and p[0] == '/')
                            std.fs.deleteTreeAbsolute(p) catch {}
                        else
                            std.fs.cwd().deleteTree(p) catch {};
                    }

                    // Keep the newest `keep` forensic `snapshot-<slot>-<hash>.tar.zst` archives by slot;
                    // delete older ones. ONLY touches the `snapshot-*.tar.zst` prefix — never the
                    // `extracted-*` bases the forensic ring preserver may co-locate in this dir.
                    fn pruneOld(self: *@This()) void {
                        var dir = (if (std.fs.path.isAbsolute(self.dir))
                            std.fs.openDirAbsolute(self.dir, .{ .iterate = true })
                        else
                            std.fs.cwd().openDir(self.dir, .{ .iterate = true })) catch return;
                        defer dir.close();

                        var slots: [256]u64 = undefined;
                        var n: usize = 0;
                        var it = dir.iterate();
                        while (it.next() catch null) |e| {
                            if (e.kind != .file) continue;
                            if (!std.mem.startsWith(u8, e.name, "snapshot-")) continue;
                            if (!std.mem.endsWith(u8, e.name, ".tar.zst")) continue;
                            // snapshot-<slot>-<hash>.tar.zst
                            const rest = e.name["snapshot-".len..];
                            const dash = std.mem.indexOfScalar(u8, rest, '-') orelse continue;
                            const sl = std.fmt.parseInt(u64, rest[0..dash], 10) catch continue;
                            if (n < slots.len) {
                                slots[n] = sl;
                                n += 1;
                            }
                        }
                        if (n <= self.keep) return;
                        std.mem.sort(u64, slots[0..n], {}, std.sort.asc(u64));
                        const cutoff = slots[n - self.keep]; // keep slots >= cutoff
                        var it2 = dir.iterate();
                        while (it2.next() catch null) |e| {
                            if (e.kind != .file) continue;
                            if (!std.mem.startsWith(u8, e.name, "snapshot-")) continue;
                            if (!std.mem.endsWith(u8, e.name, ".tar.zst")) continue;
                            const rest = e.name["snapshot-".len..];
                            const dash = std.mem.indexOfScalar(u8, rest, '-') orelse continue;
                            const sl = std.fmt.parseInt(u64, rest[0..dash], 10) catch continue;
                            if (sl < cutoff) dir.deleteFile(e.name) catch {};
                        }
                    }
                };

                const fctx = allocator.create(Forensic) catch |err| {
                    std.log.warn("[FORENSIC-SNAP] alloc failed: {any} — forensic snapshots DISABLED", .{err});
                    return err;
                };
                fctx.* = .{
                    .allocator = allocator,
                    .rs = result.replay_stage,
                    .adb = result.accounts_db,
                    .manager = vex_store.SnapshotManager.init(allocator, fs_dir),
                    .dir = fs_dir,
                    .interval = fs_interval,
                    .keep = fs_keep,
                    .poll_secs = fs_poll_secs,
                    .pin_core = fs_pin_core,
                    .fork_enabled = fs_fork,
                    .timeout_secs = fs_timeout_secs,
                    .verify = fs_verify,
                    .fork_fallback = fs_fork_fallback,
                };
                const fthread = std.Thread.spawn(.{}, Forensic.run, .{fctx}) catch |err| {
                    std.log.warn("[FORENSIC-SNAP] failed to spawn: {any} — forensic snapshots DISABLED", .{err});
                    return err;
                };
                _ = fthread; // detach — runs until process exit
                std.log.warn(
                    "[FORENSIC-SNAP] ARMED ({s}): full snapshot every {d} rooted slots -> {s} (keep {d}, poll {d}s, pin_core {d} [fork child_core defaults 31 when unset], timeout {d}s, verify={}, fork_fallback={})",
                    .{ @tagName(fs_arming), fs_interval, fs_dir, fs_keep, fs_poll_secs, fs_pin_core, fs_timeout_secs, fs_verify, fs_fork_fallback },
                );
            }
        }

        // ── SB-2 RPC block/transaction-history stores (2026-06-17) ──────────────────────────────
        // Standalone (NOT on LedgerDb, which is never instantiated live). Created ONLY when the
        // -Drpc_store comptime flag AND the VEX_RPC_STORE env are BOTH on, so the DEFAULT build leaves
        // them null AND the replay-path population call sites are comptime-dead (consensus path
        // byte-identical). The RPC *reads* are always wired and null-check these (Agave-correct
        // empty/null when absent). Process-lifetime (freed at exit).
        var rpc_block_store: ?*vex_store.BlockStore = null;
        var rpc_tx_status_store: ?*vex_store.TxStatusStore = null;
        if (comptime build_options.rpc_store) {
            if (std.posix.getenv("VEX_RPC_STORE") != null) {
                const bs = try allocator.create(vex_store.BlockStore);
                bs.* = vex_store.BlockStore.init(allocator);
                const ts = try allocator.create(vex_store.TxStatusStore);
                ts.* = vex_store.TxStatusStore.init(allocator);
                rpc_block_store = bs;
                rpc_tx_status_store = ts;
                result.replay_stage.setRpcStores(bs, ts);
                std.log.warn("[RPC-STORE] block/tx-history population ENABLED (-Drpc_store + VEX_RPC_STORE) — replay populates BlockStore/TxStatusStore", .{});
            }
        }

        // Hoisted nullable VexLedger handle for the RPC server's safe-subset reads
        // (getFirstAvailableBlock/getBlocks*). Assigned inside the -Dvex_ledger +
        // VEX_LEDGER block below; stays null otherwise ⇒ RPC keeps its legacy
        // fallback (so this is byte-identical when the feature is off). main.zig (exe)
        // imports vex_ledger unconditionally (build.zig), so the type resolves regardless.
        var vl_for_rpc: ?*@import("vex_ledger").VexLedger = null;

        // VexLedger persistent blockstore (2026-06-24). Flag-gated shadow-write of
        // completed slots (raw data shreds + SlotMeta) into the --ledger dir, so a
        // restart / offline replay can source shreds FROM VexLedger (the empty-ledger
        // gap that blocks offline carrier reproduction). Built only with -Dvex_ledger
        // AND the VEX_LEDGER env set ⇒ DEFAULT build is comptime-dead/byte-identical.
        // The persist tap (tvu.dispatchCompletedSlot) runs on the verify-worker threads
        // + repair, so the handle gets a THREAD-SAFE allocator (process-lifetime).
        if (comptime build_options.vex_ledger) {
            if (envFlagArmed("VEX_LEDGER")) {
                const vex_ledger_mod = @import("vex_ledger");
                const tsa = try allocator.create(std.heap.ThreadSafeAllocator);
                tsa.* = .{ .child_allocator = allocator };
                const vl = try vex_ledger_mod.VexLedger.init(tsa.allocator(), config.ledger_path);
                tvu_svc.setVexLedger(vl);
                vl_for_rpc = vl; // expose the same handle to the RPC server (safe-subset reads)
                result.replay_stage.setVexLedgerFlight(vl); // P5#1 flight recorder freeze-tap (dormant unless VEX_LEDGER_FLIGHT)

                // P5 MOAT #2 (M2): the LIVE divergence-alarm. Armed only when VEX_DIVERGE_ALARM=1
                // AND VEX_LEDGER_FLIGHT=1 (the alarm reads the FlightRecord for the 4 bank_hash
                // inputs). If VEX_DIVERGE_ALARM is set but the flight recorder is not, we log a
                // warning and stay dormant (no silent half-on state — design §5.2). The alarm owns
                // an off-consensus thread; the freeze-tap is a single non-blocking ring push.
                if (envFlagArmed("VEX_DIVERGE_ALARM")) {
                    if (!envFlagArmed("VEX_LEDGER_FLIGHT")) {
                        std.log.warn("[DIVERGENCE-ALARM] VEX_DIVERGE_ALARM set but VEX_LEDGER_FLIGHT is not — alarm stays DORMANT (it needs the FlightRecord)", .{});
                    } else {
                        const da_rt = vex_ledger_mod.divergence_alarm_rt;
                        // FlightRecord → FlightInputs adapter (ctx = *VexLedger). lthash_digest is
                        // blake3(2048B accounts_lt_hash) for the bundle; classify() never compares it.
                        const Adapter = struct {
                            fn read(ctx: ?*anyopaque, slot: u64) ?da_rt.FlightInputs {
                                const vlp: *vex_ledger_mod.VexLedger = @ptrCast(@alignCast(ctx.?));
                                const rec = vlp.getFlightRecord(slot) orelse return null;
                                var digest: [32]u8 = undefined;
                                std.crypto.hash.Blake3.hash(&rec.accounts_lt_hash, &digest, .{});
                                return .{
                                    .slot = slot,
                                    .bank_hash = rec.bank_hash,
                                    .parent_hash = rec.parent_hash,
                                    .signature_count = rec.signature_count,
                                    .poh_hash = rec.poh_hash,
                                    .lthash_digest = digest,
                                };
                            }
                        };
                        const oracle = try tsa.allocator().create(da_rt.CurlOracle);
                        oracle.* = .{ .allocator = tsa.allocator() };
                        const alarm = try da_rt.DivergeAlarm.init(
                            tsa.allocator(),
                            da_rt.AlarmConfig.fromEnv(),
                            vl,
                            &Adapter.read,
                            oracle,
                            &da_rt.CurlOracle.fetch,
                        );
                        try alarm.start();
                        result.replay_stage.setDivergeAlarm(alarm);
                        std.log.warn("[DIVERGENCE-ALARM] M2 LIVE alarm ENABLED (-Dvex_ledger + VEX_DIVERGE_ALARM + VEX_LEDGER_FLIGHT)", .{});
                    }
                }
                // Spawn the dedicated ledger tile on a COLD core (4; cores 0-4 are
                // walled off from the consensus tile set) so putShred/finishSlot+fsync
                // run OFF the completion threads. tsa is thread-safe (the tile decodes/
                // allocs on its consumer thread). Q4 graceful shutdown (stop+join) is
                // tvu_svc.stopLedgerTile(), to be called after producers quiesce.
                tvu_svc.startLedgerTile(tsa.allocator(), vl, 4) catch |e| {
                    std.log.warn("[LEDGER-TILE] spawn failed ({any}) — inline persist fallback (correct, just on-thread fsync)", .{e});
                };
                std.log.warn("[VEX-LEDGER] persistent blockstore ENABLED (-Dvex_ledger + VEX_LEDGER) path={s}", .{config.ledger_path});
            }
        }

        // Parallel-exec Stage A (2026-06-22): enable the EXISTING single-threaded conflict-DAG
        // dispatcher (tx_dispatcher.zig, fd_rdisp port) on the replay path for offline/live
        // re-validation. Default OFF (dag_dispatch_enabled=false) ⇒ serial path = byte-identical. The
        // 408211451 duplicate-dispatch bug is structurally fixed (getNextReady removes+marks DISPATCHED;
        // completeTxn enqueues only on the 1→0 transition) + bank-exact KAT green; this env lets us
        // empirically confirm bank-exactness on real slots before any threading (Stage B).
        if (envFlagArmed("VEX_DAG_DISPATCH")) {
            result.replay_stage.dag_dispatch_enabled = true;
            std.log.warn("[DAG] conflict-DAG dispatch ENABLED (VEX_DAG_DISPATCH) — single-threaded reorder; watch [BANK-FROZEN] parity", .{});
        }

        // Parallel-exec Stage B B2c (2026-06-22): arm the WAVE-BARRIER parallel execution path.
        // comptime-dead unless built with -Dparallel_exec (default OFF ⇒ byte-identical to serial-DAG).
        // Runtime gate: VEX_PARALLEL_EXEC env. The wave path lives INSIDE the DAG drain, so it also
        // requires VEX_DAG_DISPATCH (warn + stay serial if armed without it). Worker cores come from
        // VEX_PARALLEL_EXEC_CORES (comma-separated; CCX0 0-3 is OS-reserved — never list it; re-verify
        // each core is free at deploy). CONSENSUS-CRITICAL: even armed-OFF this build refactored the live
        // DAG drain, so the deploy MUST pass the at-tip parity gate (RULE #13).
        // 2026-07-10 VALUE-PARSE FIX: this was an existence-only check (`!= null`), so an explicit
        // `VEX_PARALLEL_EXEC=0` — the offline gates' documented way to force a SERIAL control run,
        // and the override contract bakeProdEnvDefaults promises ("an explicit VEX_X=0 still
        // overrides") — silently ARMED the wave path whenever VEX_DAG_DISPATCH was on. Every prior
        // "serial" repro987 gate actually ran parallel. Now "0" (and "false") disarm; any other
        // set value arms (the proven deploy sets "1" — behavior there unchanged).
        if (comptime build_options.parallel_exec) {
            if (envFlagArmed("VEX_PARALLEL_EXEC")) {
                if (!result.replay_stage.dag_dispatch_enabled) {
                    std.log.warn("[PARALLEL-EXEC] VEX_PARALLEL_EXEC set but VEX_DAG_DISPATCH is OFF — wave path lives in the DAG drain; staying SERIAL (set VEX_DAG_DISPATCH=1 to arm)", .{});
                } else {
                    // Parse worker cores (default {25,26} = CCX6, off the hot replay pipeline).
                    var n_cores: u8 = 0;
                    if (std.posix.getenv("VEX_PARALLEL_EXEC_CORES")) |spec| {
                        var it = std.mem.tokenizeScalar(u8, spec, ',');
                        while (it.next()) |tok| {
                            if (n_cores >= result.replay_stage.wave_cores_buf.len) break;
                            const c = std.fmt.parseInt(u32, std.mem.trim(u8, tok, " \t"), 10) catch continue;
                            if (c < 4) {
                                std.log.warn("[PARALLEL-EXEC] ignoring core {d}: CCX0 (0-3) is OS-reserved", .{c});
                                continue;
                            }
                            result.replay_stage.wave_cores_buf[n_cores] = c;
                            n_cores += 1;
                        }
                    }
                    if (n_cores == 0) {
                        result.replay_stage.wave_cores_buf[0] = 25;
                        result.replay_stage.wave_cores_buf[1] = 26;
                        n_cores = 2;
                    }
                    result.replay_stage.wave_cores_len = n_cores;
                    result.replay_stage.parallel_exec_armed = true;
                    std.log.warn("[PARALLEL-EXEC] wave-barrier parallel execution ARMED (VEX_PARALLEL_EXEC) — {d} worker cores {any}; watch [BANK-FROZEN] parity vs cluster", .{ n_cores, result.replay_stage.wave_cores_buf[0..n_cores] });
                }
            }
        }

        // Geyser streaming sink (2026-06-22): comptime-gated -Dgeyser + VEX_GEYSER env. Default OFF =
        // comptime-dead (consensus byte-identical, rpc_store pattern). Creates the cold-core consumer
        // thread + wires the wait-free slot-status callback into replay_stage. Non-consensus.
        if (comptime build_options.geyser) {
            if (std.posix.getenv("VEX_GEYSER") != null) {
                const sock_path = std.posix.getenv("VEX_GEYSER_SOCKET") orelse vex_network.geyser.GeyserService.DEFAULT_SOCKET;
                if (vex_network.geyser.GeyserService.init(allocator, sock_path)) |gsvc| {
                    gsvc.start() catch |e| std.log.warn("[GEYSER] start failed: {any}", .{e});
                    const W = struct {
                        fn slot(ctx: *anyopaque, s: u64, parent: u64, has_parent: bool, status: u8) void {
                            const svc: *vex_network.geyser.GeyserService = @ptrCast(@alignCast(ctx));
                            svc.onSlotStatus(s, if (has_parent) parent else null, @enumFromInt(status));
                        }
                    };
                    result.replay_stage.geyser_ctx = gsvc;
                    result.replay_stage.geyser_slot_fn = W.slot;
                    std.log.warn("[GEYSER] streaming ENABLED (-Dgeyser + VEX_GEYSER) — slot-status → {s}", .{sock_path});
                } else |e| std.log.warn("[GEYSER] init failed: {any}", .{e});
            }
        }

        // Start RPC server
        var rpc_server = try vex_network.rpc.RpcServer.init(allocator, config.rpc_port);
        defer rpc_server.deinit();
        rpc_server.accounts_db = result.replay_stage.accounts_db;
        rpc_server.leader_cache = &leader_cache; // warmup-aware epoch + real slot leaders in getEpochInfo/getSlotLeaders/getLeaderSchedule
        rpc_server.block_store = rpc_block_store; // SB-2 reads (null unless gate on)
        rpc_server.vex_ledger = vl_for_rpc; // SAFE-SUBSET VexLedger reads (getFirstAvailableBlock/getBlocks*); null ⇒ legacy fallback
        rpc_server.tx_status_store = rpc_tx_status_store;
        rpc_server.banking = banking_handle; // SB-1 sendTransaction mempool (null unless VEX_TPU_INGEST)
        // Config-driven operational RPC values (non-consensus convenience: getClusterNodes/
        // getGenesisHash/cluster). Replaces hardcoded host:port/genesis/cluster literals.
        rpc_server.public_ip = config.public_ip;
        rpc_server.gossip_port = config.gossip_port;
        rpc_server.tpu_port = config.tpu_port;
        rpc_server.rpc_port = config.rpc_port;
        rpc_server.shred_version = config.expected_shred_version orelse 0;
        rpc_server.genesis_hash = config.expected_genesis_hash;
        rpc_server.cluster_name = @tagName(config.cluster);
        rpc_server.full_rpc_api = config.full_rpc_api; // canonical tier: false ⇒ Minimal-12 only (voting node), true ⇒ full API (`vex-fd rpc` / --full-rpc-api)
        std.log.warn("[RPC] mode={s}{s}\n", .{
            if (config.full_rpc_api) "FULL-API" else "MINIMAL (12 methods)",
            if (config.full_rpc_api) "" else " — Full/BankData/AccountsScan return -32601; run `vex-fd rpc` or pass --full-rpc-api for the complete API",
        });
        try rpc_server.start();
        std.log.debug("[MAIN] RPC server started on port {d}\n", .{config.rpc_port});

        // Wire vote sending — UDP to current slot leader's TPU vote port.
        // Resolves leader identity from leader schedule, then looks up their
        // TPU vote address from gossip ContactInfo.
        const VoteSender = struct {
            var gossip_ref: *vex_network.gossip.GossipService = undefined;
            var leader_ref: *vex_consensus.leader_schedule.LeaderScheduleCache = undefined;
            var tvu_ref: ?*vex_network.TvuService = null;
            var udp_sock: ?std.posix.socket_t = null;
            var send_count: u64 = 0;
            var alloc: std.mem.Allocator = undefined;
            var rpc_endpoint: []const u8 = "https://api.testnet.solana.com";
            // Stage-0 observability: curl-spawn failures (posix_spawn errno or
            // curl transport exit!=0). On-chain lastVote is the only throttle
            // signal now (-o /dev/null drops HTTP-200 throttle JSON); this still
            // catches spawn/DNS/TLS/timeout failures (e.g. curl exit 28).
            var rpc_fail_count: u64 = 0;
            // Native QUIC TPU vote client (step 1, 2026-06-18). Set only when the validator was
            // built with -Duse_native_quic_votes; null otherwise → vote path byte-identical to today.
            var tpu_client: ?*vex_network.tpu_client.TpuClient = null;
            // FD-style vote fanout width: send each vote to the next N distinct upcoming leaders over
            // UDP+QUIC. 7 rotations matches Firedancer; tunable live via VEX_VOTE_FANOUT_ROTATIONS.
            var fanout_rotations: u32 = 7;
            // 2026-07-06 dual-NIC vote-client source-IP fix (incident 21:48Z-ongoing, sibling of
            // fc85545's gossip_bind_addr fix): from config.quic_bind_addr (--quic-bind-addr).
            // udp_sock below is created via plain std.posix.socket() with NO bind() at all, so the
            // kernel picks the egress source by route on first sendto() — on this host that's the
            // DEFAULT route's IP (.155), while gossip advertises a DIFFERENT IP (.154). Leaders'
            // stake-weighted QUIC/UDP QoS can't match our vote packets' source to our staked
            // ContactInfo → treated as unstaked → starved under load → votes die at leader ingest.
            var bind_addr: []const u8 = "";

            fn send(tx_bytes: []const u8) void {
                if (udp_sock == null) {
                    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch null;
                    if (fd) |sock_fd| {
                        // 2026-07-06 dual-NIC source-IP fix: bind BEFORE any sendto() so the OS
                        // can't pick the wrong-NIC ephemeral source (see `bind_addr` doc above).
                        // Port 0 = ephemeral (unchanged); only the IP is pinned. Bind failure (bad
                        // config / address not on this host) is loud but never fatal — the socket
                        // still works, just with the old kernel-routed (possibly wrong) source.
                        if (bind_addr.len > 0) {
                            if (std.net.Address.parseIp4(bind_addr, 0)) |addr| {
                                if (std.posix.bind(sock_fd, &addr.any, addr.getOsSockLen())) |_| {
                                    std.log.warn("[VOTE-BIND] addr={s} vote UDP fanout socket bound (dual-NIC source-IP fix) ✓\n", .{bind_addr});
                                } else |err| {
                                    std.log.warn("[VOTE-BIND] addr={s} bind failed: {} — vote UDP socket falls back to kernel-routed source\n", .{ bind_addr, err });
                                }
                            } else |err| {
                                std.log.warn("[VOTE-BIND] invalid bind_addr '{s}': {} — vote UDP socket unbound (kernel-routed source)\n", .{ bind_addr, err });
                            }
                        }
                    }
                    udp_sock = fd;
                }

                send_count += 1;
                // FD-STYLE VOTE FANOUT (2026-06-28): send every vote to the next `fanout_rotations`
                // DISTINCT upcoming leaders over BOTH transports — UDP→tpu_vote (tag-9) AND QUIC→
                // tpu_quic — matching Firedancer send_vote_to_leader (fd_txsend_tile.c: 7 rotations,
                // dual UDP+QUIC). Replaces the old 5-consecutive-slot (~1-2 distinct leader) UDP leg +
                // 12-RANDOM gossip spray (wasted — non-leaders drop votes) + 3-slot QUIC enqueue.
                // Transport-only (identical signed vote bytes) → NOT consensus; a duplicate landing is
                // a signature no-op. Tunable live via VEX_VOTE_FANOUT_ROTATIONS (default 7); each
                // rotation = 4 slots (NUM_CONSECUTIVE_LEADER_SLOTS).
                const MAX_FANOUT_LEADERS = 16;
                var ldr_slot: [MAX_FANOUT_LEADERS]u64 = undefined; // representative slot per distinct leader (QUIC)
                var ldr_udp: [MAX_FANOUT_LEADERS]std.net.Address = undefined; // tpu_vote (tag-9) per leader (UDP)
                var ldr_udp_ok: [MAX_FANOUT_LEADERS]bool = undefined; // leader advertises a UDP vote port
                var seen: [MAX_FANOUT_LEADERS]core.Pubkey = undefined; // distinct-leader dedup set
                var n: usize = 0;

                // Scan base = replay frontier clamped UP to the shred tip (the real network position),
                // capped at +200 to stop corrupted shreds from poisoning the target. Same base the
                // proven UDP leg used.
                const scan_base = blk: {
                    const replay_slot = leader_ref.current_slot_estimate;
                    if (tvu_ref) |tvu| {
                        const shred_tip = tvu.stats.max_slot_seen.load(.monotonic);
                        if (shred_tip > replay_slot) break :blk @min(shred_tip, replay_slot + 200);
                    }
                    break :blk replay_slot;
                };

                if (scan_base > 0) {
                    const window: u64 = @as(u64, fanout_rotations) * 4; // rotations → slots
                    gossip_ref.table.contacts_rw.lockShared();
                    defer gossip_ref.table.contacts_rw.unlockShared();
                    var off: u64 = 0;
                    while (off < window and n < MAX_FANOUT_LEADERS) : (off += 1) {
                        const ls = scan_base + off;
                        const leader = leader_ref.getSlotLeader(ls) orelse continue;
                        // dedup: a leader owns 4 consecutive slots, so the same leader repeats — only
                        // the first occurrence (its earliest upcoming slot) is recorded.
                        var dup = false;
                        for (seen[0..n]) |s| {
                            if (std.meta.eql(s, leader)) {
                                dup = true;
                                break;
                            }
                        }
                        if (dup) continue;
                        const ci = gossip_ref.table.contacts.get(leader) orelse continue;
                        seen[n] = leader;
                        ldr_slot[n] = ls;
                        if (ci.tpu_vote_addr.port() != 0) {
                            ldr_udp[n] = ci.tpu_vote_addr.toStd();
                            ldr_udp_ok[n] = true;
                        } else {
                            ldr_udp_ok[n] = false;
                        }
                        n += 1;
                    }
                }

                // UDP leg (no lock held): fire the vote to each distinct leader's tpu_vote (tag-9).
                var udp_sent: u32 = 0;
                if (udp_sock) |sock| {
                    var i: usize = 0;
                    while (i < n) : (i += 1) {
                        if (!ldr_udp_ok[i]) continue;
                        const addr = ldr_udp[i];
                        _ = std.posix.sendto(sock, tx_bytes, 0, &addr.any, addr.getOsSockLen()) catch continue;
                        udp_sent += 1;
                    }
                }

                // QUIC leg: enqueue one slot per distinct leader (drained + prewarmed by the poller).
                // Enqueue only (thread-safe) — the dedicated QUIC thread owns the endpoint and drains
                // via processPending()+poll(); send() may run on >1 thread so it must never touch the
                // endpoint directly. NOT consensus — identical vote bytes, transport only.
                // PRE-FILTER (2026-07-10 vote-fanout hygiene): resolve-then-enqueue. enqueueVote resolves
                // the leader's QUIC endpoint AT ENQUEUE TIME and enqueues ONLY resolvable, non-dead-cached
                // leaders — the old code enqueued EVERY distinct leader (up to 16) unconditionally, so
                // leaders with no gossip QUIC endpoint (or a recently dead handshake) filled the 256-deep
                // ring with never-sendable entries that aged out as 'dropped', delaying/starving QUIC sends
                // to leaders that DO resolve. Skipped leaders are still covered by the UDP leg above.
                var quic_enq: u32 = 0;
                if (comptime build_options.use_native_quic_votes) {
                    if (tpu_client) |tc| {
                        var i: usize = 0;
                        while (i < n) : (i += 1) {
                            if (tc.enqueueVote(tx_bytes, ldr_slot[i]) == .enqueued) quic_enq += 1;
                        }
                    }
                }

                // Path 3: RPC fallback every 5th vote — now DEFAULT-OFF (2026-06-29 fix).
                // ROOT CAUSE of a recurring vote-LANDING delinquency: sendViaRpc does a BLOCKING
                // waitpid(pid,0) on a curl(-m 5) to the shared-IP public RPC, stalling the
                // vote-sender worker (core 28) up to 5s/5th-vote. When that RPC is rate-limited,
                // the worker starves → vote_send_queue backs up → UDP+QUIC sends fall behind →
                // votes go stale before their leader → stop landing while replay stays at-tip.
                // UDP(tag-9)+QUIC carry the votes (Agave/FD don't curl votes at all), so the curl
                // relay is redundant insurance and not worth a blocking call on the hot path.
                // Opt back IN with VEX_ENABLE_CURL_VOTES=1 (e.g. before QUIC/UDP are proven on a
                // new cluster). VEX_DISABLE_CURL_VOTES=1 still forces off (backward-compat).
                if (send_count % 5 == 0) {
                    const force_off = if (std.posix.getenv("VEX_DISABLE_CURL_VOTES")) |v| std.mem.eql(u8, v, "1") else false;
                    const opt_in = if (std.posix.getenv("VEX_ENABLE_CURL_VOTES")) |v| std.mem.eql(u8, v, "1") else false;
                    if (opt_in and !force_off) sendViaRpc(tx_bytes);
                }

                if (send_count <= 3 or send_count % 100 == 0) {
                    std.log.debug("[VOTE-SEND] leaders={d} udp={d} quic={d} RPC={s} [#{d}]\n", .{
                        n,
                        udp_sent,
                        quic_enq,
                        if (send_count % 5 == 0) "YES" else "skip",
                        send_count,
                    });
                }
            }

            // posix_spawn extern: Zig 0.15.2 stdlib binds posix_spawn only for
            // darwin; declare for Linux glibc (libc IS linked). Used by sendViaRpc
            // to spawn curl WITHOUT fork()'s 36GB page-table copy (Stage 0, 2026-06-17).
            extern "c" fn posix_spawn(
                pid_out: *std.c.pid_t,
                path: [*:0]const u8,
                file_actions: ?*const anyopaque,
                attrp: ?*const anyopaque,
                argv_p: [*:null]const ?[*:0]const u8,
                envp_p: [*:null]const ?[*:0]const u8,
            ) c_int;

            fn sendViaRpc(tx_bytes: []const u8) void {
                // Base64-encode the transaction for RPC sendTransaction
                const std_lib = @import("std");
                const b64 = std_lib.base64.standard;
                const encoded_len = b64.Encoder.calcSize(tx_bytes.len);
                const b64_buf = alloc.alloc(u8, encoded_len) catch return;
                defer alloc.free(b64_buf);
                const b64_tx = b64.Encoder.encode(b64_buf, tx_bytes);

                // Build JSON-RPC body
                const prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendTransaction\",\"params\":[\"";
                const suffix = "\",{\"encoding\":\"base64\",\"skipPreflight\":true}]}";
                const body_len = prefix.len + b64_tx.len + suffix.len;
                const body = alloc.alloc(u8, body_len) catch return;
                defer alloc.free(body);
                @memcpy(body[0..prefix.len], prefix);
                @memcpy(body[prefix.len..][0..b64_tx.len], b64_tx);
                @memcpy(body[prefix.len + b64_tx.len ..][0..suffix.len], suffix);

                // Send via curl subprocess (simple, reliable, handles TLS).
                // throughput-fix (2026-06-11): prepend `taskset -c 28-31` so the
                // curl/TLS work runs on the OPS LANE, never on a replay core
                // (validator owns 4-27). This holds whether sendViaRpc is invoked
                // from the core-28 vote-sender worker OR from the inline fallback
                // path on the replay thread (submitVote → sendFn when the SPSC
                // queue overflows during a catch-up vote burst). Self-affinity to
                // 28-31 is permitted (no cpuset cgroup confinement — confirmed by
                // the worker's own pinToCore(28) taking effect).
                const argv = [_][]const u8{
                    "/usr/bin/taskset",               "-c",   "28-31",
                    "/usr/bin/curl",                  "-s",   "-o",
                    "/dev/null",                      "-m",   "5",
                    "-X",                             "POST", "-H",
                    "Content-Type: application/json", "-d",   body,
                    rpc_endpoint,
                };
                // Stage 0 (2026-06-17): spawn curl WITHOUT copying the validator's
                // ~36GB page table. Zig's Child.spawn uses fork()+execve → the
                // copy_page_range that perf showed as ~30% of CPU (forking a huge-RSS
                // process every 5th vote). posix_spawn uses glibc clone(CLONE_VM|
                // CLONE_VFORK): the child shares the address space until exec → NO
                // page-table copy. curl writes to /dev/null (-o), so no pipe is needed
                // (vote landing is verified on-chain, not via the curl body). Legacy
                // fork path kept under VEX_VOTE_LEGACY_FORK for instant runtime revert.
                if (std_lib.posix.getenv("VEX_VOTE_LEGACY_FORK") != null) {
                    var child = std_lib.process.Child.init(&argv, alloc);
                    child.stdout_behavior = .Ignore;
                    child.stderr_behavior = .Ignore;
                    child.spawn() catch return;
                    _ = child.wait() catch {};
                    return;
                }
                var c_argv: [argv.len + 1]?[*:0]const u8 = undefined;
                var dupes: [argv.len][:0]u8 = undefined;
                var ndup: usize = 0;
                defer {
                    for (dupes[0..ndup]) |s| alloc.free(s);
                }
                for (argv, 0..) |a, i| {
                    const z = alloc.dupeZ(u8, a) catch return;
                    dupes[ndup] = z;
                    ndup += 1;
                    c_argv[i] = z.ptr;
                }
                c_argv[argv.len] = null;
                var empty_env = [_]?[*:0]const u8{null};
                var pid: std.c.pid_t = 0;
                const rc = posix_spawn(&pid, "/usr/bin/taskset", null, null, @ptrCast(&c_argv), @ptrCast(&empty_env));
                if (rc != 0) {
                    rpc_fail_count += 1;
                    if (rpc_fail_count <= 3 or rpc_fail_count % 50 == 0) {
                        std.log.warn("[RPC-VOTE] posix_spawn failed errno={d} (vote-RPC submit dropped; fails={d}) — watch on-chain lastVote\n", .{ rc, rpc_fail_count });
                    }
                    return;
                }
                const wr = std_lib.posix.waitpid(pid, 0);
                if (std_lib.posix.W.IFEXITED(wr.status)) {
                    const code = std_lib.posix.W.EXITSTATUS(wr.status);
                    if (code != 0) {
                        rpc_fail_count += 1;
                        if (rpc_fail_count <= 3 or rpc_fail_count % 50 == 0) {
                            std.log.warn("[RPC-VOTE] curl exit={d} (vote-RPC transport fail; fails={d}) — watch on-chain lastVote\n", .{ code, rpc_fail_count });
                        }
                    }
                }
            }
        };
        VoteSender.gossip_ref = &gossip_svc;
        VoteSender.leader_ref = &leader_cache;
        VoteSender.tvu_ref = tvu_svc;
        VoteSender.alloc = allocator;
        VoteSender.rpc_endpoint = rpc_url;
        VoteSender.bind_addr = config.quic_bind_addr; // dual-NIC source-IP fix (2026-07-06)
        result.replay_stage.sendVoteFn = &VoteSender.send;
        // FD-style fanout width (next N distinct leaders per vote, UDP+QUIC). Default 7 (Firedancer).
        // Live-tunable: VEX_VOTE_FANOUT_ROTATIONS=<1..16>. Clamped to [1, MAX_FANOUT_LEADERS=16].
        if (std.posix.getenv("VEX_VOTE_FANOUT_ROTATIONS")) |v| {
            const parsed = std.fmt.parseInt(u32, v, 10) catch 7;
            VoteSender.fanout_rotations = std.math.clamp(parsed, 1, 16);
        }
        std.log.warn("[MAIN] Vote sending ENABLED — FD-style fanout: {d} rotations (UDP tpu_vote + QUIC), RPC fallback\n", .{VoteSender.fanout_rotations});

        // ── Native QUIC TPU vote client (step 1, 2026-06-18; -Duse_native_quic_votes) ──────────
        // Build the identity-mTLS QUIC client + TpuClient, wire leader discovery (gossip + leader
        // schedule + RPC fallback), and spawn a DEDICATED QUIC thread that OWNS the endpoint and
        // drains queued votes via processPending()+poll() single-threaded. VoteSender.send only
        // ENQUEUES (Path 4). Comptime-gated → byte-identical to today when built OFF (the default).
        if (comptime build_options.use_native_quic_votes) {
            quic_votes: {
                var id_seed: [32]u8 = undefined;
                @memcpy(&id_seed, identity_kp.secret[0..32]);
                const qc = vex_network.solana_quic.SolanaTpuQuic.init(allocator, .{
                    .is_server = false,
                    .bind_port = 0,
                    .identity_seed = id_seed,
                    .allow_insecure = false,
                    .bind_addr = config.quic_bind_addr, // dual-NIC source-IP fix (2026-07-06)
                }) catch |err| {
                    std.log.warn("[QUIC-VOTE] SolanaTpuQuic client init failed: {} — QUIC votes OFF\n", .{err});
                    break :quic_votes;
                };
                const tc = vex_network.tpu_client.TpuClient.init(allocator, true, false, false, true, 0, false, 0) catch |err| {
                    std.log.warn("[QUIC-VOTE] TpuClient init failed: {} — QUIC votes OFF\n", .{err});
                    break :quic_votes;
                };
                tc.setQuicClient(qc);
                tc.setGossipService(&gossip_svc);
                tc.setLeaderSchedule(&leader_cache);
                tc.rpc_url = rpc_url;
                VoteSender.tpu_client = tc;

                const QuicVotePoller = struct {
                    fn run(poll_qc: *vex_network.solana_quic.SolanaTpuQuic, poll_tc: *vex_network.tpu_client.TpuClient, poll_tvu: ?*vex_network.TvuService, prewarm_enabled: bool) void {
                        // This thread drains PRODUCED votes (processPending) + drives QUIC I/O (poll), and
                        // — when VEX_VOTE_PREWARM is set AND we are caught up — pre-opens connections to OUR
                        // upcoming vote leaders (the gated block below).
                        //
                        // PREWARM HISTORY + SAFETY INVARIANT (read before touching the gate): the OLD
                        // prewarmUpcoming(...)/100ms was REMOVED 2026-06-18 because it was FREE-RUNNING (no
                        // caught-up gate) — during catch-up it kept opening/churning QUIC connections and
                        // starved the repair REQUEST path → catch-up stall (flag-ON/OFF A/B proven: OFF
                        // caught up, ON stalled, gap 1360). The 2026-06-28 RE-ADD fixes that three ways:
                        // (a) default-OFF; (b) the shouldPrewarmCaughtUp gate only fires when frontier≈tip;
                        // (c) it targets OUR REPLAY FRONTIER. CANONICAL: Agave WarmQuicCacheService warms
                        // the tpu_vote cache ~100 slots ahead off PoH; FD fd_txsend warms ~7 rotations off
                        // voted_slot — both off their OWN position, never the cluster tip.
                        //   ⚠️ INVARIANT THE GATE DEPENDS ON: `leader_schedule.current_slot_estimate` is the
                        //   REPLAY FRONTIER — its ONLY writer is replay_stage.getSlotLeader (main.zig:730-731,
                        //   wired at :752), so it is ≤ replayed_slot+1 and LAGS the shred tip during catch-up.
                        //   That lag is exactly what makes the gate (`tip <= frontier+slack`) return false
                        //   during catch-up. If current_slot_estimate is EVER rewired to track the received-
                        //   shred tip (e.g. updated from the TVU/shred path), the gate silently defeats and
                        //   the 2026-06-18 catch-up stall returns. DO NOT do that without revisiting this gate.
                        //
                        // QuicVotePoller → DEDICATED core 7 (2026-06-23 TIER-B2): vote landing is
                        // delinquency-critical, so give it its own core instead of sharing txsend's 28.
                        // Core 7 is the free tail of CCX1 {4=OS/NIC-IRQ, 5=recv, 6=quic, 7=vote-poller},
                        // inside the cpuset (5-31). Was pinTile(.txsend) (core 28); before that, UNPINNED
                        // (floated onto consensus cores — the original tiling gap).
                        pinToCore(7);
                        var tick: u32 = 0;
                        while (true) {
                            poll_tc.processPending(); // drain PRODUCED votes (QUIC-send queued); no-op when none
                            poll_qc.poll() catch {}; // drive handshakes / ACKs / keepalive on live connections
                            // ~every 2s: prune never-completing (dead-handshake) connections to leaders
                            // that don't run QUIC — bounds the conn pool + poll() cost over long uptime
                            // (Agave ConnectionCache model). Same thread as poll/connect → race-free.
                            if (tick % 2000 == 0) poll_qc.pruneDeadConnections();
                            // TARGETED CONNECT-AHEAD (2026-06-28, gated VEX_VOTE_PREWARM, default OFF):
                            // ~every 500ms, when CAUGHT UP, pre-open QUIC connections to the next few leaders
                            // OUR replay frontier is about to vote to, so their handshakes finish BEFORE we
                            // send the vote (votes land at slot-start, not after a cold-handshake delay →
                            // targets the measured ~17% timely-vote-credit gap). The caught-up gate is the
                            // guard the OLD removed prewarm lacked: it warms OUR-frontier leaders, and ONLY
                            // when frontier≈tip, so it never churns the cluster's current leaders / starves
                            // repair during catch-up (the 2026-06-18 stall cause). prewarmUpcoming is a no-op
                            // for already-pooled leaders, so re-firing is cheap.
                            if (prewarm_enabled and tick % 500 == 0) {
                                const frontier: u64 = if (poll_tc.leader_schedule) |ls| ls.current_slot_estimate else 0;
                                const tip: u64 = if (poll_tvu) |tv| tv.stats.max_slot_seen.load(.monotonic) else 0;
                                if (vex_network.solana_quic.SolanaTpuQuic.shouldPrewarmCaughtUp(frontier, tip, 8)) {
                                    // Warm from `frontier` across the SAME window sendVote fans out to:
                                    // fanout_rotations × 4 slots (= the next ~N distinct leaders). Matches
                                    // FD's connect-ahead so every leader QUIC reaches is warm by vote time.
                                    // count is u8; fanout_rotations is clamped to ≤16 so ×4 ≤ 64.
                                    const pw_slots: u8 = @intCast(VoteSender.fanout_rotations * 4);
                                    poll_tc.prewarmUpcoming(frontier, pw_slots);
                                }
                            }
                            // Observability: ~every 10s emit QUIC vote send stats so we can PROVE
                            // votes actually connect + send over QUIC (txs_sent_quic>0 ⟹ a handshake
                            // completed, since a stream can't open without it) vs falling back to UDP.
                            if (tick % 10000 == 0) {
                                const s = poll_tc.stats;
                                // qc_real = solana_quic's own transactions_sent (the authoritative count
                                // of QUIC streams actually written) — cross-check vs txs_sent_quic.
                                const qstats = poll_qc.getStats();
                                const qc_real = qstats.transactions_sent;
                                // pool/evicted = the 2026-06-23 wedge-fix signal: pool MUST stay <=128 and
                                // (under leader rotation) evicted climbs — proves the bounded pool recycles
                                // and can never saturate (the old refuse-on-full delinquency cause).
                                // pruned_dead (2026-06-28) = connections that NEVER completed a handshake:
                                // high vs pool ⟹ a dead-handshake leader tail (votes to them can't land);
                                // low + healthy pool ⟹ connections complete, so any landing gap is warmth
                                // (prewarm-addressable). The [QUIC-VOTE-PENDING] line classifies the current
                                // backlog — unresolved (gossip/schedule gap) vs not_ready (waiting on a
                                // handshake) vs ready (drains next round) — so we know WHY votes lag.
                                std.log.warn("[QUIC-VOTE-STATS] quic={d} qc_real={d} udp={d} batches={d} batched={d} dropped={d} failed={d} pool={d} evicted={d} pruned_dead={d} skipped_unresolvable={d} dead_cache_hits={d} prewarm={s} cache_hit={d} cache_miss={d} retries={d}\n", .{ s.txs_sent_quic, qc_real, s.txs_sent_udp, s.txs_sent_quic_batches, s.txs_sent_quic_batched, s.txs_dropped, s.txs_failed, qstats.conn_pool_size, qstats.connections_evicted, qstats.handshakes_pruned_dead, s.skipped_unresolvable, s.dead_cache_hits, if (prewarm_enabled) "on" else "off", s.cache_hits, s.cache_misses, s.quic_retries });
                                const pd = poll_tc.pendingDiag();
                                std.log.warn("[QUIC-VOTE-PENDING] depth={d} unresolved={d} not_ready={d} ready={d}\n", .{ pd.depth, pd.unresolved, pd.not_ready, pd.ready });
                            }
                            std.Thread.sleep(1 * std.time.ns_per_ms);
                            tick +%= 1;
                        }
                    }
                };
                // VEX_VOTE_PREWARM (default OFF) arms the targeted caught-up connect-ahead in the poller
                // loop. Default-off keeps the baseline byte-identical to the proven no-prewarm vote path;
                // arm only after the offline gate + a live credit-rate A/B confirms it helps and is safe.
                const vote_prewarm_enabled = envFlagArmed("VEX_VOTE_PREWARM");
                const quic_thread = std.Thread.spawn(.{}, QuicVotePoller.run, .{ qc, tc, tvu_svc, vote_prewarm_enabled }) catch |err| {
                    std.log.warn("[QUIC-VOTE] poll thread spawn failed: {} — QUIC votes OFF\n", .{err});
                    VoteSender.tpu_client = null;
                    break :quic_votes;
                };
                _ = quic_thread;
                std.log.warn("[QUIC-VOTE] native QUIC TPU vote submission ENABLED (identity mTLS, ALPN solana-tpu) — targeted prewarm: {s}\n", .{if (vote_prewarm_enabled) "ON (VEX_VOTE_PREWARM)" else "off (default)"});
            }
        }

        // Create vote send queue and spawn sender thread (heap-allocated -- must outlive both threads)
        vote_wiring: {
            const vote_send_queue = try allocator.create(replay_mod.VoteSendQueue);
            vote_send_queue.* = replay_mod.VoteSendQueue.init(allocator);
            const vote_sender_shutdown = try allocator.create(std.atomic.Value(bool));
            vote_sender_shutdown.* = std.atomic.Value(bool).init(false);

            result.replay_stage.vote_send_queue = vote_send_queue;

            const vote_sender_thread = std.Thread.spawn(.{}, replay_mod.voteSenderWorker, .{
                vote_send_queue,
                &VoteSender.send,
                vote_sender_shutdown,
            }) catch |err| {
                std.log.debug("[MAIN] Failed to spawn vote sender thread: {any}\n", .{err});
                // Non-fatal: submitVote() falls back to inline send
                result.replay_stage.vote_send_queue = null;
                break :vote_wiring;
            };
            _ = vote_sender_thread;

            std.log.debug("[MAIN] Vote sender thread spawned (core 17)\n", .{});
        }

        // ── TASK 2: --wait-for-supermajority gossip-stake gate (2026-06-15) ─────
        // Mirrors Agave's coordinated-restart behavior: after a halt, hold the
        // node from receiving shreds / voting / producing until ≥80% of the
        // epoch's activated stake is observed back online in gossip. ADDITIVE:
        // only engages when --wait-for-supermajority is SET AND equals the loaded
        // root/boot slot (Agave only waits when the configured slot IS the slot
        // we are bootstrapping at). Otherwise this block is a pure no-op and boot
        // is byte-for-byte unchanged. Placed BEFORE the TVU recv thread spawns
        // and before the replay loop's first vote / any block production, so the
        // gate gates all consensus participation. Gossip itself was started above
        // (separate thread) and keeps populating contacts while we wait.
        //
        // STAKE SOURCE: result.accounts_db.epoch_stakes — the snapshot's frozen
        // per-epoch vote-account stake table (the SAME source the leader-schedule
        // generator uses). For the boot epoch we sum stake[i] over the matching
        // entry as the denominator (total activated stake), and build a
        // node_pubkey → stake map (epoch_stakes carries the parallel node_pubkeys
        // slice). GOSSIP SOURCE: gossip_svc.table.contacts — node-identity-keyed
        // ContactInfo. The observed numerator sums the stake of every node
        // identity currently present in the gossip table that maps to a staked
        // node. This is a stake-weighted gossip-PARTICIPATION gate.
        //
        // LIMITATION (documented in commit): observation is keyed on node
        // identity presence in the gossip CRDS contacts table, not on a fresh
        // restart-attestation message (Agave's wen-restart uses a dedicated
        // LastVotedForkSlots/Heaviest gossip protocol). A node that is in gossip
        // but has not yet re-attested still counts. This is the conservative,
        // correct-on-the-common-path version; it cannot release EARLY relative to
        // true 80% online (a node must actually be in gossip to count) but could
        // in principle release once 80% are merely reachable rather than
        // re-voting. If epoch_stakes is empty, the gate logs and does NOT silently
        // pass (it would block); see supermajorityMet(total==0)==false.
        if (config.wait_for_supermajority) |wfs_slot| {
            const boot_slot = result.root_bank.slot;
            if (wfs_slot != boot_slot) {
                std.log.warn(
                    "[RESTART-GATE] --wait-for-supermajority slot {d} != boot/root slot {d} — gate INACTIVE (snapshot already past the supermajority slot; post-restart state inherited)",
                    .{ wfs_slot, boot_slot },
                );
            } else {
                const boot_epoch = result.root_bank.epoch_schedule.getEpoch(boot_slot);

                // Build node_pubkey → stake map + total activated stake for the
                // boot epoch from the snapshot's frozen epoch_stakes table.
                var node_stake = std.AutoHashMap([32]u8, u128).init(allocator);
                defer node_stake.deinit();
                var total_stake: u128 = 0;
                for (result.accounts_db.epoch_stakes) |entry| {
                    if (entry.epoch != boot_epoch) continue;
                    for (entry.vote_account_stakes, 0..) |vstake, i| {
                        total_stake += vstake.stake;
                        // node_pubkeys is a parallel slice; may be shorter / all-zero
                        // for short-data parses — fall back to keying by the vote
                        // pubkey so the stake still contributes to the denominator
                        // (it just won't be matchable in gossip, which is correct:
                        // an unidentifiable node cannot be observed present).
                        if (i < entry.node_pubkeys.len) {
                            const nid = entry.node_pubkeys[i];
                            if (!std.mem.allEqual(u8, &nid, 0)) {
                                const gop = node_stake.getOrPut(nid) catch continue;
                                if (!gop.found_existing) gop.value_ptr.* = 0;
                                gop.value_ptr.* += vstake.stake;
                            }
                        }
                    }
                    break; // one entry per epoch
                }

                if (total_stake == 0) {
                    std.log.err(
                        "[RESTART-GATE] --wait-for-supermajority set for slot {d} (epoch {d}) but snapshot epoch_stakes is empty — cannot compute activated stake; refusing to start rather than silently bypassing the gate",
                        .{ boot_slot, boot_epoch },
                    );
                    return error.WaitForSupermajorityNoStake;
                }

                std.log.warn(
                    "[RESTART-GATE] wait-for-supermajority ENGAGED at slot {d} (epoch {d}): waiting for {d}% of {d} activated stake across {d} staked nodes to appear in gossip",
                    .{ boot_slot, boot_epoch, core.restart_gate.SUPERMAJORITY_THRESHOLD_PERCENT, total_stake, node_stake.count() },
                );

                var last_log_time: i64 = 0;
                while (signal_received.load(.seq_cst) == 0) {
                    // Sum the stake of every staked node identity currently in gossip.
                    var observed: u128 = 0;
                    gossip_svc.table.contacts_rw.lockShared();
                    var it = gossip_svc.table.contacts.iterator();
                    while (it.next()) |kv| {
                        if (node_stake.get(kv.key_ptr.data)) |s| observed += s;
                    }
                    gossip_svc.table.contacts_rw.unlockShared();

                    if (core.restart_gate.supermajorityMet(observed, total_stake)) {
                        const pct = core.restart_gate.observedPercent(observed, total_stake);
                        std.log.warn(
                            "[RESTART-GATE] supermajority reached ({d}%), resuming at slot {d}",
                            .{ pct, boot_slot },
                        );
                        break;
                    }

                    const now = std.time.timestamp();
                    if (now - last_log_time >= 3) {
                        const pct = core.restart_gate.observedPercent(observed, total_stake);
                        std.log.warn(
                            "[RESTART-GATE] Waiting for {d}% of activated stake at slot {d} to be in gossip (currently {d}%)",
                            .{ core.restart_gate.SUPERMAJORITY_THRESHOLD_PERCENT, boot_slot, pct },
                        );
                        last_log_time = now;
                    }
                    std.Thread.sleep(1 * std.time.ns_per_s);
                }
                if (signal_received.load(.seq_cst) != 0) {
                    std.log.warn("[RESTART-GATE] shutdown signal during wait-for-supermajority — exiting before consensus join", .{});
                    return;
                }
            }
        }

        // ── Metrics reporter (2026-07-10): Agave-schema InfluxDB telemetry ─────────
        // ONE background thread (nice 19, unpinned) samples EXISTING atomics + /proc
        // every 10 s and POSTs to metrics.solana.com over a persistent curl handle.
        // ZERO hot-path cost: nothing below adds instrumentation — the sampler is
        // monotonic loads on counters that already exist. Master switch =
        // SOLANA_METRICS_CONFIG; start() itself refuses under VEX_LEDGER_REPLAY /
        // VEX_SNAPSHOT_OFFLINE (offline/golden-gate guard) and on any parse failure.
        // Placed BEFORE the Phase-3 offline driver so the guard line is visible in
        // gate logs (Phase 3 exits the process without reaching runMainLoop).
        {
            const mr = @import("core/metrics_reporter.zig");
            const MetricsWiring = struct {
                const mrep = @import("core/metrics_reporter.zig");
                var rs_ptr: ?*vex_svm.replay_stage.ReplayStage = null;
                var tvu_ptr: ?*vex_network.TvuService = null;
                fn get(v: *const std.atomic.Value(u64)) u64 {
                    return v.load(.monotonic);
                }
                fn sample(_: ?*anyopaque, out: *mrep.ValidatorSample) void {
                    if (rs_ptr) |rs| {
                        out.replay_valid = true;
                        out.shreds_received = get(&rs.stats.shreds_received);
                        out.invalid_shreds = get(&rs.stats.invalid_shreds);
                        out.slots_replayed = get(&rs.stats.slots_replayed);
                        out.successful_txs = get(&rs.stats.successful_txs);
                        out.failed_txs = get(&rs.stats.failed_txs);
                        out.votes_sent = get(&rs.stats.votes_sent);
                        out.blocks_produced = get(&rs.stats.blocks_produced);
                        out.slot_queue_drops = get(&rs.stats.slot_queue_drops);
                        out.root_slot = if (rs.root_bank.load(.acquire)) |rb| rb.slot else 0;
                        const c = vex_svm.replay_stage.getVoteCensusSnapshot();
                        out.census_valid = true;
                        out.census_eligible = c.eligible;
                        out.census_cast = c.cast;
                        out.census_fallback_decided = c.fallback_decided;
                        out.census_fallback_cast = c.fallback_cast;
                        out.census_silent_withhold = c.silent_withhold;
                    }
                    if (tvu_ptr) |t| {
                        out.tvu_valid = true;
                        out.tvu_shreds_received = get(&t.stats.shreds_received);
                        out.tvu_shreds_inserted = get(&t.stats.shreds_inserted);
                        out.tvu_shreds_duplicate = get(&t.stats.shreds_duplicate);
                        out.tvu_shreds_invalid = get(&t.stats.shreds_invalid);
                        out.tvu_zc_version_rejects = get(&t.stats.zc_version_rejects);
                        out.tvu_repairs_sent = get(&t.stats.repairs_sent);
                        out.tvu_repairs_received = get(&t.stats.repairs_received);
                        out.tvu_repairs_served = get(&t.stats.repairs_served);
                        out.tvu_repair_requests_received = get(&t.stats.repair_requests_received);
                        out.tvu_slots_completed = get(&t.stats.slots_completed);
                        out.tvu_max_slot_seen = get(&t.stats.max_slot_seen);
                        out.tvu_shreds_retransmitted = get(&t.stats.shreds_retransmitted);
                        out.tvu_repairs_dropped_ratelimit = get(&t.stats.repairs_dropped_ratelimit);
                        out.tvu_rx_shed = get(&t.stats.rx_shed);
                        // AF_XDP kernel counters: hand only the fd over; the reporter
                        // does its own read-only getsockopt (no Vexor state touched —
                        // XdpSocket.getStats() would racily write xdp.stats cross-thread).
                        if (t.shred_io) |io| {
                            if (io.getXdpSocket()) |x| out.afxdp_fd = x.fd;
                        }
                    }
                }
            };
            MetricsWiring.rs_ptr = result.replay_stage;
            MetricsWiring.tvu_ptr = tvu_svc;
            var host_id_buf: [64]u8 = undefined;
            const host_id: []const u8 = core.base58.encodeToBuf(&identity_pubkey.data, &host_id_buf) catch "invalid";
            var ver_buf: [128]u8 = undefined;
            const ver = core.version.buildVersionString(&ver_buf);
            std.debug.print("[MR-CK] PRE-CALL\n", .{});
            mr.start(allocator, .{
                .host_id = host_id, // agave set_host_id(identity pubkey b58)
                .version = ver,
                .cluster_type = 0, // agave ClusterType::Testnet = 0
                .shred_version = @intCast(config.expected_shred_version orelse 0),
                .waited_for_supermajority = config.wait_for_supermajority != null,
                .ledger_path = config.ledger_path,
                .accounts_path = config.accounts_path,
                .snapshots_path = config.snapshots_path,
                .sample_fn = &MetricsWiring.sample,
            });
            std.debug.print("[MR-CK] POST-CALL\n", .{});
        }

        // ── Phase 3: VexLedger READ DRIVER (offline replay FROM VexLedger) ──────────
        // Flag-gated (-Dvex_ledger) + env-gated (VEX_LEDGER_REPLAY=<S>:<K>). When set,
        // this runs INSTEAD OF the live network: the validator booted offline from a
        // local snapshot @S-1 (via VEX_SNAPSHOT_OFFLINE + --snapshots <dir-with-
        // extracted-(S-1)>), and the driver feeds slots S..S+K's shreds FROM VexLedger
        // into the SAME shred-assembler + replay path the network/repair uses — NO
        // cluster, NO AF_XDP, NO repair, NO gossip recv loop. Each slot freezes and
        // emits its [BANK-FROZEN] bank_hash line, which a harness compares to the
        // canonical per-slot bank_hash (bank-exact gate). Then the process exits
        // cleanly WITHOUT spawning the TVU recv loop (svc.run()) below.
        //
        // Replay model (researched): replay is THREADED — replay_stage.init spawns
        // `replayWorker` (replay_stage.zig:1106) which drains slot_queue and freezes
        // banks asynchronously. So the driver only inserts shreds + dispatches; the
        // already-running worker thread does the execute+freeze. dispatchCompletedSlot
        // (tvu.zig:630) assembles the slot's data + boundaries and pushes onto
        // slot_queue via pushSlotForReplayWithBoundaries — exactly the network path.
        //
        // Per-slot feed-then-wait (NOT dump-all): feed all shreds for slot N, dispatch,
        // then poll replay_stage.slotFrozen(N) until N freezes, before feeding N+1. This
        // guarantees every slot's parent is already frozen when fed (root_bank @S-1 for
        // S, then N-1 for N), so NO slot ever defers (FAR_AHEAD_THRESHOLD / pending-
        // chain), chain-wake never fires, and the driver thread is the sole slot_queue
        // producer. (slot_queue.push is mutex-guarded MPSC, so even overlap would be
        // memory-safe, but per-slot ordering keeps the path simple + clean to audit.)
        if (comptime build_options.vex_ledger) {
            if (std.posix.getenv("VEX_LEDGER_REPLAY")) |spec| {
                // Parse "S:K" → start_slot, count. K is INCLUSIVE (replays S..=S+K).
                const colon = std.mem.indexOfScalar(u8, spec, ':') orelse {
                    std.log.err("[VEX-LEDGER-REPLAY] bad spec '{s}' — expected <S>:<K>", .{spec});
                    return error.InvalidVexLedgerReplaySpec;
                };
                const start_slot = std.fmt.parseInt(u64, std.mem.trim(u8, spec[0..colon], " \t"), 10) catch {
                    std.log.err("[VEX-LEDGER-REPLAY] bad start slot in '{s}'", .{spec});
                    return error.InvalidVexLedgerReplaySpec;
                };
                const count = std.fmt.parseInt(u64, std.mem.trim(u8, spec[colon + 1 ..], " \t"), 10) catch {
                    std.log.err("[VEX-LEDGER-REPLAY] bad count in '{s}'", .{spec});
                    return error.InvalidVexLedgerReplaySpec;
                };
                const end_slot = start_slot + count; // inclusive upper bound

                // Linchpin check: the snapshot must be @S-1 so slot S finds a frozen
                // parent (root_bank @S-1). If not, every slot defers forever.
                const root_slot = result.root_bank.slot;
                if (root_slot + 1 != start_slot) {
                    std.log.err("[VEX-LEDGER-REPLAY] snapshot root slot={d} but VEX_LEDGER_REPLAY start S={d} — need a snapshot @S-1 (={d}). Boot with VEX_SNAPSHOT_OFFLINE + --snapshots <dir-with-extracted-{d}>.", .{ root_slot, start_slot, start_slot - 1, start_slot - 1 });
                    return error.VexLedgerReplaySnapshotSlotMismatch;
                }

                // Open our OWN read-only handle. Do NOT setVexLedger() on tvu — that
                // would make dispatchCompletedSlot re-putShred the shreds we just read.
                // Leaving tvu.vex_ledger null keeps the persist branch dead.
                const vex_ledger_mod = @import("vex_ledger");
                const vl_read = try vex_ledger_mod.VexLedger.init(allocator, config.ledger_path);
                defer vl_read.deinit();

                const shred_mod = vex_network.shred_pub; // re-exported @import("shred.zig")

                // Per-slot freeze-wait timeout (forensic harness only). Default 60s; bump via
                // VEX_LEDGER_REPLAY_FREEZE_TIMEOUT_S when a CONCURRENT background snapshot
                // (VEX_FORENSIC_SNAPSHOT_EVERY) deliberately stalls replay-writes for the duration
                // of writeSnapshotAppendVec's storage.lock-shared walk — that legitimate stall would
                // otherwise trip this guard and abort the replay. Non-consensus; offline driver only.
                const freeze_timeout_s: u64 = if (std.posix.getenv("VEX_LEDGER_REPLAY_FREEZE_TIMEOUT_S")) |s|
                    (std.fmt.parseInt(u64, std.mem.trim(u8, s, " \t\r\n"), 10) catch 60)
                else
                    60;

                // #27 (2026-07-02) VEX_REPLAY_FORCE_ROOT_DEPTH=N: after freezing
                // slot K, advance the accounts-db root to the newest FROZEN slot
                // ≤ K−N via the SAME shared root-advance the live vote path uses
                // (replay_stage.forceAdvanceRootTo → doRootAdvance: ancestry
                // guard + partition promote/purge + advanceRoot + purgeRootedSlot —
                // never bare advanceRoot). Without this a no-vote replay never
                // roots → unrooted_ring grows unboundedly → account reads go
                // O(slots²) (the 2026-07-01 21.7k-slot wall: 63% CPU in
                // getWithModifiedSlotPlusSelf). 0/unset = OFF (prior behavior).
                // OFFLINE-ONLY by construction: parsed + wired only inside this
                // VEX_LEDGER_REPLAY branch (live mode refuses loudly below).
                // Candidate = newest FROZEN slot ≤ K−N (not K−N itself, which
                // may be a cluster-skipped slot that never froze).
                const force_root_depth: u64 = if (std.posix.getenv("VEX_REPLAY_FORCE_ROOT_DEPTH")) |s|
                    (std.fmt.parseInt(u64, std.mem.trim(u8, s, " \t\r\n"), 10) catch 0)
                else
                    0;
                var frozen_slots: std.ArrayListUnmanaged(u64) = .{};
                defer frozen_slots.deinit(allocator);
                var force_root_idx: usize = 0;
                if (force_root_depth > 0)
                    std.log.warn("[FORCE-ROOT] armed depth={d} (offline replay only)", .{force_root_depth});

                // #25 (2026-07-06) VEX_LEDGER_REPLAY_CANON=<file>: canonical-chain filter.
                // Without it the driver feeds EVERY shred-bearing slot — including cluster-
                // ORPHANED blocks (shreds recorded, block NOT in the canonical chain), which
                // the live node only avoided via fork choice; feeding one wedges the replay
                // (blocked carrier 418999361's window). The file holds one canonical slot
                // number per line (vex-carrier-isolate.sh fetches it from cluster getBlocks);
                // a shred-bearing slot NOT in the set is skipped exactly like a zero-shred
                // cluster skip, logged as [ORPHAN-SKIP]. Set-but-unreadable = hard error:
                // an ambiguous half-armed filter must never produce a silently-wrong replay.
                var canon_set: std.AutoHashMapUnmanaged(u64, void) = .{};
                defer canon_set.deinit(allocator);
                var canon_armed = false;
                if (std.posix.getenv("VEX_LEDGER_REPLAY_CANON")) |cf| {
                    const f = std.fs.cwd().openFile(cf, .{}) catch |err| {
                        std.log.err("[VEX-LEDGER-REPLAY] VEX_LEDGER_REPLAY_CANON='{s}' unreadable ({any}) — refusing ambiguous replay", .{ cf, err });
                        return error.VexLedgerReplayCanonUnreadable;
                    };
                    defer f.close();
                    const body = try f.readToEndAlloc(allocator, 64 << 20);
                    defer allocator.free(body);
                    var canon_toks = std.mem.tokenizeAny(u8, body, "\r\n \t,");
                    while (canon_toks.next()) |tok| {
                        const cslot = std.fmt.parseInt(u64, tok, 10) catch continue;
                        try canon_set.put(allocator, cslot, {});
                    }
                    if (canon_set.count() == 0) {
                        std.log.err("[VEX-LEDGER-REPLAY] VEX_LEDGER_REPLAY_CANON='{s}' parsed to ZERO slots — refusing (would skip the whole window)", .{cf});
                        return error.VexLedgerReplayCanonEmpty;
                    }
                    canon_armed = true;
                    std.log.warn("[VEX-LEDGER-REPLAY] CANON filter armed: {d} canonical slots from {s}", .{ canon_set.count(), cf });
                }

                std.log.warn("[VEX-LEDGER-REPLAY] START offline replay slots {d}..={d} (K={d}) FROM VexLedger path={s} (parent @S-1={d} frozen); NO network", .{ start_slot, end_slot, count, config.ledger_path, root_slot });

                var slot: u64 = start_slot;
                while (slot <= end_slot) : (slot += 1) {
                    // Ascending data-shred indices for this slot (caller frees).
                    const idxs = vl_read.getSlotShredIndices(allocator, slot) catch |err| {
                        std.log.err("[VEX-LEDGER-REPLAY] slot={d} getSlotShredIndices err={any}", .{ slot, err });
                        return err;
                    };
                    defer allocator.free(idxs);
                    if (idxs.len == 0) {
                        // Cluster-SKIPPED slot (no block produced) → legitimately no shreds in
                        // VexLedger. The live network/repair replay path simply advances past
                        // skipped slots; mirror that here instead of aborting. The next PRODUCED
                        // slot references its true parent (the last frozen slot) via parent_slot
                        // in its own shreds, so the bank chain stays correct across the gap.
                        // (Without this, any replay window spanning a leader skip aborts — which
                        // is exactly what blocked carrier 417758552's offline reproduction.)
                        std.log.warn("[VEX-LEDGER-REPLAY] slot={d} SKIPPED (no shreds = cluster skip); advancing without freeze", .{slot});
                        continue;
                    }

                    // #25: shreds exist but the cluster never adopted this block → orphan.
                    // Skip it exactly like a zero-shred cluster skip; the next canonical
                    // slot's shreds carry the true parent_slot, so the chain stays correct.
                    if (canon_armed and !canon_set.contains(slot)) {
                        std.log.warn("[ORPHAN-SKIP] slot={d} has {d} shreds but is NOT in the canonical chain (getBlocks) — skipping like a cluster skip", .{ slot, idxs.len });
                        continue;
                    }

                    var completed = false;
                    for (idxs) |idx| {
                        const wire = (vl_read.getShred(slot, idx) catch |err| {
                            std.log.err("[VEX-LEDGER-REPLAY] slot={d} idx={d} getShred err={any}", .{ slot, idx, err });
                            return err;
                        }) orelse {
                            std.log.err("[VEX-LEDGER-REPLAY] slot={d} idx={d} getShred returned null (index/log mismatch)", .{ slot, idx });
                            return error.VexLedgerReplayShredMissing;
                        };
                        defer allocator.free(wire);

                        // Parse the verbatim wire bytes into a Shred (same parser the
                        // network recv path uses) and insert into the SAME assembler.
                        const s = shred_mod.Shred.fromPayload(wire) catch |err| {
                            std.log.err("[VEX-LEDGER-REPLAY] slot={d} idx={d} Shred.fromPayload err={any}", .{ slot, idx, err });
                            return error.VexLedgerReplayBadShred;
                        };
                        const ins = tvu_svc.shred_assembler.insert(s) catch |err| {
                            std.log.err("[VEX-LEDGER-REPLAY] slot={d} idx={d} assembler.insert err={any}", .{ slot, idx, err });
                            return err;
                        };
                        if (ins == .completed_slot) completed = true;
                    }

                    if (!completed) {
                        std.log.err("[VEX-LEDGER-REPLAY] slot={d} did NOT complete after feeding all {d} shreds (missing DATA_COMPLETE / gap) — aborting", .{ slot, idxs.len });
                        return error.VexLedgerReplayIncompleteSlot;
                    }

                    // Assemble + push onto slot_queue → replay worker executes + freezes.
                    // (Mirrors tvu's network/repair handling of .completed_slot.)
                    tvu_svc.dispatchCompletedSlot(slot);

                    // Wait for the replay worker to freeze this slot before feeding the
                    // next (so the next slot's parent is frozen ⇒ never defers). Bounded
                    // timeout so we never hang on an incomplete slot / unfrozen parent.
                    const POLL_NS: u64 = 2 * std.time.ns_per_ms;
                    const TIMEOUT_NS: u64 = freeze_timeout_s * std.time.ns_per_s;
                    var waited: u64 = 0;
                    while (!result.replay_stage.slotFrozen(slot)) {
                        if (waited >= TIMEOUT_NS) {
                            std.log.err("[VEX-LEDGER-REPLAY] slot={d} did NOT freeze within {d}s — aborting (incomplete shreds or unfrozen parent?)", .{ slot, TIMEOUT_NS / std.time.ns_per_s });
                            return error.VexLedgerReplayFreezeTimeout;
                        }
                        std.Thread.sleep(POLL_NS);
                        waited += POLL_NS;
                    }
                    std.log.warn("[VEX-LEDGER-REPLAY] slot={d} FROZEN ({d}/{d})", .{ slot, slot - start_slot + 1, count + 1 });

                    // #27: force-root the newest frozen slot ≤ slot−depth (see
                    // env parse above). Idempotent: forceAdvanceRootTo no-ops
                    // when the candidate ≤ current db.rooted_slot.
                    if (force_root_depth > 0) {
                        try frozen_slots.append(allocator, slot);
                        if (slot >= start_slot + force_root_depth) {
                            const cutoff = slot - force_root_depth;
                            while (force_root_idx + 1 < frozen_slots.items.len and
                                frozen_slots.items[force_root_idx + 1] <= cutoff) force_root_idx += 1;
                            const cand = frozen_slots.items[force_root_idx];
                            if (cand <= cutoff) {
                                result.replay_stage.forceAdvanceRootTo(cand, slot);
                            }
                        }
                    }
                }

                std.log.warn("[VEX-LEDGER-REPLAY] DONE {d}..={d} — {d} slots replayed + frozen from VexLedger. Compare each [BANK-FROZEN] bank_hash to canonical.", .{ start_slot, end_slot, count + 1 });

                // Flush buffered stderr before process.exit (which skips defers /
                // buffered flushes). The [BANK-FROZEN] lines are the deliverable; give
                // the logging thread a beat to drain, then exit WITHOUT spawning the
                // live network recv loop below.
                std.Thread.sleep(200 * std.time.ns_per_ms);
                std.process.exit(0);
            } else if (std.posix.getenv("VEX_REPLAY_FORCE_ROOT_DEPTH") != null) {
                // #27 offline-only interlock: a LIVE node must never root from
                // replay-position math instead of tower consensus. Refuse loudly
                // and continue with the env ignored (design: REPLAY-FORCE-ROOT-
                // DESIGN-2026-07-02.md §2.1).
                std.log.err("[FORCE-ROOT] REFUSED — VEX_REPLAY_FORCE_ROOT_DEPTH set without VEX_LEDGER_REPLAY (live mode). Env IGNORED.", .{});
            }
        }

        // Spawn TVU receive loop in background thread
        const tvu_thread = std.Thread.spawn(.{}, struct {
            fn run(svc: *vex_network.TvuService) void {
                svc.run();
            }
        }.run, .{tvu_svc}) catch |err| {
            std.log.debug("[MAIN] Failed to spawn TVU recv thread: {any}\n", .{err});
            return err;
        };
        _ = tvu_thread;
        std.log.debug("[MAIN] TVU receive loop spawned\n", .{});

        // Run until shutdown signal
        try runMainLoop(result.replay_stage);
    } else {
        // Quick mode: networking only (for testing / development)
        std.log.debug("Starting QUICK MODE (networking only)...\n\n", .{});

        var tvu_config = vex_network.TvuService.Config{};
        tvu_config.shred_version = config.expected_shred_version orelse 0;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--enable-af-xdp")) tvu_config.enable_af_xdp = true;
            if (std.mem.eql(u8, arg, "--xdp-zero-copy")) tvu_config.xdp_zero_copy = true;
        }

        var tvu_svc = try vex_network.TvuService.init(allocator, tvu_config);
        defer tvu_svc.deinit();

        std.log.debug("TVU service initialized. Entering main loop...\n", .{});
        try tvu_svc.start();

        // Spin until signal
        while (signal_received.load(.seq_cst) == 0) {
            std.Thread.sleep(1 * std.time.ns_per_s);
        }
    }
}

/// Main event loop — spins until a shutdown signal is received.
fn runMainLoop(replay_stage: *replay_mod.ReplayStage) !void {
    std.log.debug("[MAIN] Entering main event loop. Signal to stop.\n", .{});

    var last_stats_time = std.time.timestamp();

    while (signal_received.load(.seq_cst) == 0) {
        std.Thread.sleep(1 * std.time.ns_per_s);

        // Print stats every 60 seconds
        const now = std.time.timestamp();
        if (now - last_stats_time >= 60) {
            replay_stage.printStats();
            last_stats_time = now;
        }
    }

    const sig = signal_received.load(.seq_cst);
    std.log.debug("[MAIN] Shutting down (signal={d})\n", .{sig});
}

// ── Output helpers ────────────────────────────────────────────────────────────

fn printBanner() void {
    std.log.debug(
        \\
        \\  VEX-FD Solana Validator
        \\  Native Zig SVM port — Zig 0.15.2
        \\  ===================================
        \\
    , .{});
}

fn printVersion() void {
    std.log.debug("Vex-FD\n", .{});
    std.log.debug("Zig: {any}\n", .{builtin.zig_version});
}

fn hasHelpFlag(extra: []const []const u8) bool {
    for (extra) |a| {
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) return true;
    }
    return false;
}

fn printUsage() void {
    const usage =
        \\
        \\Usage: vex-fd <command> [options]
        \\
        \\Commands:
        \\  run, validator    Start the validator (consensus mode)
        \\  rpc               Start as RPC node (non-voting)
        \\  version           Show version information
        \\  help              Show this help message
        \\
        \\Network Selection:
        \\  --mainnet-beta         Connect to Mainnet Beta
        \\  --testnet              Connect to Testnet (default)
        \\  --devnet               Connect to Devnet
        \\  --localnet             Local test cluster
        \\
        \\Validator Options:
        \\  --identity <KEYPAIR>           Path to validator identity keypair
        \\  --vote-account <KEYPAIR>       Path to vote account keypair
        \\  --ledger <DIR>                 Ledger directory
        \\  --accounts <DIR>               Accounts directory
        \\  --snapshots <DIR>              Snapshots directory
        \\  --bootstrap, --production      Enable full production bootstrap
        \\  --public-ip <IP>               Public IP for gossip advertisement
        \\  --entrypoint <HOST:PORT>       Cluster entrypoint (repeatable)
        \\  --expected-shred-version <VER> Expected shred version
        \\  --rpc-url <URL>                Override RPC URL
        \\
        \\Performance:
        \\  --enable-af-xdp         Enable AF_XDP kernel-bypass networking
        \\  --xdp-zero-copy         Enable AF_XDP zero-copy mode
        \\  --enable-parallel-snapshot  Parallel snapshot loading
        \\  --no-voting             Run as non-voting node
        \\
        \\BPF Stack (Wave 4):
        \\  --bpf-stack=v1          Use legacy BPF executor (default)
        \\  --bpf-stack=v2          Use vex_bpf2 stack (requires smoke pass)
        \\  --bpf-stack=shadow      V1 commits, V2 logs Stage-D diff lines
        \\  --bpf-stack-shadow-log=<path>  Override shadow log path
        \\                          (default: /tmp/vex-fd-shadow.log)
        \\  --bpf-stack-trace={off,on-error,verbose}
        \\                          BPF2 trace verbosity (default: on-error)
        \\
        \\Examples:
        \\  vex-fd validator --testnet \
        \\    --identity ~/keypair.json \
        \\    --vote-account ~/vote.json \
        \\    --ledger /mnt/ledger \
        \\    --bootstrap
        \\
        \\  vex-fd rpc --testnet --ledger /mnt/ledger
        \\
    ;
    // Write directly to stdout — NOT std.log.debug, which is suppressed at normal log
    // levels (the reason `vex-fd help` / `--help` previously appeared to print nothing).
    std.debug.print("{s}", .{usage});
}
