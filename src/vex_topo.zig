//! vex_topo.zig — Declarative tile→core topology table (the Firedancer `fd_topob`
//! analogue). Phase 9 of the Track-B tiling port (2026-06-17).
//!
//! PURPOSE: centralize the FOUR previously-duplicated affinity-pinning sites
//! (three byte-identical `pinToCore` copies in main.zig / replay_stage.zig /
//! tvu.zig, plus the open-coded `8 + worker_id` block in verify_tile.zig) and
//! every magic core-number literal into ONE comptime table. The table emits
//! BIT-IDENTICAL `sched_setaffinity` arguments to today's inline literals — this
//! is a pure data refactor, NOT a tile split. No work moves between threads; no
//! compute path, bank_hash, lt-hash, PoH, or vote-state byte changes. The
//! "change" is purely *where the core number lives* (one table vs four scattered
//! literals), never *what runs on which core*.
//!
//! ESCAPE HATCH (see build.zig `legacy_pins` + env `VEX_LEGACY_PINS`): each call
//! site branches `legacy_pins ? <old inline literal> : pinTile(LIVE, .<tile>, id)`.
//! Because `LIVE` holds the SAME literals read off the live call sites, the two
//! branches are observationally identical (same cpu_set → same syscall). The flag
//! exists only to give an instant in-binary revert if the table is ever doubted;
//! the DEFAULT path (flag OFF) is the table path, byte-identical to the literals.
//!
//! This module is intentionally `std`-ONLY (no `build_options`, no other Vexor
//! module) so its KATs run as a tiny standalone test graph (`zig build test-topo`),
//! exactly like spsc_ring.zig / produce_ring.zig. The `legacy_pins` comptime
//! branch lives at each *call site* (which already imports `build_options`), not
//! here — so this file never needs the build-options module.

const std = @import("std");

/// The fixed-core dedicated tiles. Each maps to exactly one core via `CoreMap`,
/// except `verify_base` which is the BASE of a contiguous range of
/// `NUM_VERIFY_WORKERS` cores (`verify_base .. verify_base + NUM_VERIFY_WORKERS-1`).
///
/// NOTE: the dead `svm_pool` self-pin path (replay_stage.zig parallelWorkerFn,
/// dynamic core 20-23) is deliberately NOT a tile here — it computes its core at
/// runtime and is dead code (zero spawn calls); it is outside this table's scope.
pub const Tile = enum {
    recv, // TVU recv / net front
    repair, // repair / control tile
    verify_base, // base core of the 8-worker verify pool
    replay, // replay (consensus heart)
    sysvar, // sysvar refresh
    txsend, // vote sender (txsend)
    gossip, // gossip
    produce, // produce tile (pack+poh), leader-gated
    quic, // QUIC TPU pump, ingest-gated
    rpc, // RPC HTTP listen loop — diagnostic/bursty, not on the hot pipeline (Phase-1 topo rework 2026-06-22)
};

/// ── Phase-1 tile→core topology rework (2026-06-22) ───────────────────────────
/// COLD reserve = CCX0 (cores 0-3), which historically sat OUTSIDE the validator
/// taskset (deploy.sh widened to include it in this same rework). Core 0 stays for
/// the OS/main thread. Cores 1-3 are the dynamic-relief pool (vex-fd-pin.sh
/// HOT_CORES, moved off the hot pipeline 16/20/24). The binary itself pins NO
/// thread onto CCX0 today — the cold block is RESERVED for future Phase-2
/// parallel-exec worker tiles (when wired: shrink relief to {1}, dedicate {2,3}+
/// to the exec pool). These constants document that reservation; they are NOT a
/// Tile (no thread self-pins to them yet) — just named landmarks for Phase-2 and
/// for the dormant-revival pins below.
pub const COLD_CCX0_OS: u32 = 0; // OS / main thread (never pinned by us)
pub const COLD_CCX0_RELIEF: [3]u32 = .{ 1, 2, 3 }; // dynamic pinner relief pool (vex-fd-pin.sh)
pub const COLD_CCX0_RESERVED_PHASE2 = "CCX0 cores 1-3 (relief now); Phase-2 exec workers later";

/// Number of verify workers. SOURCE OF TRUTH for the verify range here; coupled
/// to `verify_tile.DEFAULT_NUM_WORKERS` by a `comptime assert` at the verify call
/// site (verify_tile.zig imports this module for `pinTile`). Keeping it here lets
/// the standalone KAT below check range-disjointness without dragging verify_tile
/// into the test graph; the assert at the call site is the anti-drift tripwire.
pub const NUM_VERIFY_WORKERS: u32 = 8;

/// A complete tile→core assignment. Single-core tiles hold their core directly;
/// `verify_base` holds the base of the verify range.
pub const CoreMap = struct {
    recv: u32,
    repair: u32,
    verify_base: u32,
    replay: u32,
    sysvar: u32,
    txsend: u32,
    gossip: u32,
    produce: u32,
    quic: u32,
    rpc: u32,

    /// The core for a single-core tile. For `verify_base`, returns the base
    /// (callers add `worker_id`; see `pinTile`).
    pub fn coreOf(self: CoreMap, comptime t: Tile) u32 {
        return switch (t) {
            .recv => self.recv,
            .repair => self.repair,
            .verify_base => self.verify_base,
            .replay => self.replay,
            .sysvar => self.sysvar,
            .txsend => self.txsend,
            .gossip => self.gossip,
            .produce => self.produce,
            .quic => self.quic,
            .rpc => self.rpc,
        };
    }
};

/// THE one authoritative map — these are the EXACT live literals (plan §1.1),
/// bit-for-bit, read off the live call sites on f17cb19 (2026-06-17):
///   recv 4 (tvu.zig:3253) · repair 30 (tvu.zig:3143) · verify_base 8
///   (verify_tile.zig:440, `8 + worker_id`) · replay 16 (replay_stage.zig:5959) ·
///   sysvar 29 (replay_stage.zig:1517) · txsend 28 (replay_stage.zig:361) ·
///   gossip 24 (main.zig:882) · produce 20 (replay_stage.zig:3603) ·
///   quic 6 (main.zig:971).
pub const LIVE: CoreMap = .{
    // recv 4→5 (2026-06-23 cores-0-4 wall-off): cores 0-4 are now OS/kernel-only,
    // enforced by a cgroup-v2 cpuset (cpus=5-31) at deploy time. recv must live in
    // the cpuset → moved 4→5 (still CCX1 {5,6,7}, adjacent to quic=6). pinToCore(4)
    // would EINVAL inside the cpuset. The deploy floater mask excludes 5 so recv
    // owns its core (mirrors the old core-4 reservation).
    .recv = 5,
    .repair = 30,
    .verify_base = 8,
    .replay = 16,
    .sysvar = 29,
    .txsend = 28,
    .gossip = 24,
    .produce = 20,
    .quic = 6,
    // rpc 27 (NEW, Phase-1 topo rework 2026-06-22): the RPC HTTP listen loop was
    // the ONLY genuinely-unpinned LIVE floater (rpc.zig:110). Core 27 is the tail
    // of CCX6 (24-27), FREE in the static map (gossip=24 is the only CCX6 tile),
    // inside the widened taskset (≤27), diagnostic/bursty so co-residency with the
    // gossip CCX6's spare cores is fine and never touches the hot pipeline.
    .rpc = 27,
};

// ── Comptime invariants on LIVE ──────────────────────────────────────────────
// Any future accidental edit of a core number becomes a BUILD ERROR, not a
// silent mis-pin (plan Risk #1 mitigation). The frozen 06-17 values:
comptime {
    std.debug.assert(LIVE.recv == 5); // 4→5: cores-0-4 wall-off (2026-06-23)
    std.debug.assert(LIVE.repair == 30);
    std.debug.assert(LIVE.verify_base == 8);
    std.debug.assert(LIVE.replay == 16);
    std.debug.assert(LIVE.sysvar == 29);
    std.debug.assert(LIVE.txsend == 28);
    std.debug.assert(LIVE.gossip == 24);
    std.debug.assert(LIVE.produce == 20);
    std.debug.assert(LIVE.quic == 6);
    std.debug.assert(LIVE.rpc == 27); // Phase-1 topo rework 2026-06-22
    // No two single-core tiles collide, and none falls inside the verify range.
    assertNoCollision(LIVE);
}

/// Comptime check that all single-core tiles are pairwise distinct AND that none
/// of them lands inside the verify range `[verify_base, verify_base+N)`. Used by
/// the `comptime` block above (over LIVE) and by the collision KAT.
pub fn assertNoCollision(map: CoreMap) void {
    const singles = [_]u32{
        map.recv,   map.repair, map.replay,  map.sysvar,
        map.txsend, map.gossip, map.produce, map.quic,
        map.rpc,
    };
    // Pairwise-distinct among single-core tiles.
    for (singles, 0..) |a, i| {
        for (singles[i + 1 ..]) |b| {
            std.debug.assert(a != b);
        }
        // Not inside the verify range.
        std.debug.assert(a < map.verify_base or a >= map.verify_base + NUM_VERIFY_WORKERS);
    }
}

/// Pin the calling thread to the core assigned to tile `t`. For `verify_base`,
/// the actual core is `verify_base + worker_id`; for every single-core tile,
/// `worker_id` MUST be 0 (asserted) and is ignored.
///
/// Returns the raw `sched_setaffinity` return code so the ONE call site that
/// checks it (verify_tile's worker loop, which logs info/warn on rc) keeps that
/// behavior; the other 8 sites discard the return. The cpu_set construction is
/// byte-identical to the legacy `pinToCore` (main.zig:128-132) and the
/// open-coded verify block (verify_tile.zig:441-443): a 16-word usize array,
/// single bit set at `core/64 : 1<<(core%64)`.
pub fn pinTile(map: CoreMap, comptime t: Tile, worker_id: u32) usize {
    const core_id: u32 = if (t == .verify_base)
        map.verify_base + worker_id
    else blk: {
        std.debug.assert(worker_id == 0);
        break :blk map.coreOf(t);
    };
    return pinCore(core_id);
}

/// The byte-identical core-pin primitive (matches legacy `pinToCore`). Exposed
/// so the equivalence KAT can call it directly. Returns the syscall rc.
pub fn pinCore(core_id: u32) usize {
    var cpu_set = [_]usize{0} ** 16;
    const idx = core_id / @bitSizeOf(usize);
    const bit: u6 = @intCast(core_id % @bitSizeOf(usize));
    cpu_set[idx] = @as(usize, 1) << bit;
    return std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
}

/// Construct the 16-word cpu_set bitmask that `pinCore` would pass to the kernel,
/// WITHOUT issuing the syscall. Used by the equivalence KAT to byte-compare the
/// table path against the legacy open-coded math.
pub fn cpuSetFor(core_id: u32) [16]usize {
    var cpu_set = [_]usize{0} ** 16;
    const idx = core_id / @bitSizeOf(usize);
    const bit: u6 = @intCast(core_id % @bitSizeOf(usize));
    cpu_set[idx] = @as(usize, 1) << bit;
    return cpu_set;
}

// ── KATs ─────────────────────────────────────────────────────────────────────
// Run off-core: `taskset -c 0-3 zig build test-topo --prefix /tmp/topo-test`

const testing = std.testing;

test "vex_topo: LIVE map matches the frozen 06-17 live literals" {
    // Regression tripwire (plan §3.5 KAT #1). Any future core re-map must
    // CONSCIOUSLY edit these exact values — this is what proves the refactor is
    // non-behavioral vs the pre-refactor inline literals (plan §1.1).
    try testing.expectEqual(@as(u32, 5), LIVE.recv); // 4→5 cores-0-4 wall-off (was tvu.zig pinToCore(4))
    try testing.expectEqual(@as(u32, 30), LIVE.repair); // tvu.zig:3143  pinToCore(30)
    try testing.expectEqual(@as(u32, 8), LIVE.verify_base); // verify_tile.zig:440  8 + worker_id
    try testing.expectEqual(@as(u32, 16), LIVE.replay); // replay_stage.zig:5959  pinToCore(16)
    try testing.expectEqual(@as(u32, 29), LIVE.sysvar); // replay_stage.zig:1517 pinToCore(29)
    try testing.expectEqual(@as(u32, 28), LIVE.txsend); // replay_stage.zig:361  pinToCore(28)
    try testing.expectEqual(@as(u32, 24), LIVE.gossip); // main.zig:882   pinToCore(24)
    try testing.expectEqual(@as(u32, 20), LIVE.produce); // replay_stage.zig:3603 pinToCore(20)
    try testing.expectEqual(@as(u32, 6), LIVE.quic); // main.zig:971   pinToCore(6)
    try testing.expectEqual(@as(u32, 27), LIVE.rpc); // rpc.zig:110  Phase-1 topo rework 2026-06-22
    try testing.expectEqual(@as(u32, 8), NUM_VERIFY_WORKERS);
}

test "vex_topo: no two tiles collide; verify range is contiguous and disjoint" {
    // plan §3.5 KAT #2. Comptime-checked over LIVE already; here we also walk the
    // explicit derived assignment list and assert the verify range
    // [8..16) is exactly cores 8,9,10,11,12,13,14,15 and overlaps no single tile.
    assertNoCollision(LIVE); // will @panic at comptime/test if violated

    // Build the full per-thread core list the way each site emits it.
    var seen = [_]bool{false} ** 64;
    const singles = [_]u32{
        LIVE.recv, LIVE.repair, LIVE.replay, LIVE.sysvar,
        LIVE.txsend, LIVE.gossip, LIVE.produce, LIVE.quic,
    };
    for (singles) |c| {
        try testing.expect(c < 64);
        try testing.expect(!seen[c]); // no duplicate single-core assignment
        seen[c] = true;
    }
    // Verify range: contiguous, in-bounds, and disjoint from every single tile.
    var w: u32 = 0;
    while (w < NUM_VERIFY_WORKERS) : (w += 1) {
        const core = LIVE.verify_base + w;
        try testing.expectEqual(LIVE.verify_base + w, core); // contiguous by construction
        try testing.expect(core < 64);
        try testing.expect(!seen[core]); // disjoint from single tiles
        seen[core] = true;
    }
    // Concretely: the verify pool is cores 8..15 inclusive.
    try testing.expectEqual(@as(u32, 8), LIVE.verify_base + 0);
    try testing.expectEqual(@as(u32, 15), LIVE.verify_base + (NUM_VERIFY_WORKERS - 1));
}

test "vex_topo: pinTile emits the same cpu_set bit as the legacy open-coded math" {
    // plan §3.5 KAT #3. Prove the table path and the legacy `pinToCore` /
    // verify_tile bit math construct a BYTE-IDENTICAL cpu_set, so the escape
    // hatch and the table are observationally identical (same syscall arg).
    //
    // Legacy verify_tile.zig math (lines 441-442):
    //   var cpu_set = [_]usize{0} ** 16;
    //   cpu_set[target_core / 64] = 1 << (target_core % 64);
    // Legacy pinToCore math (main.zig:128-131): identical, with @bitSizeOf(usize)
    // == 64 on this target, so `/ @bitSizeOf(usize)` == `/ 64`.

    // Check every tile's emitted core, including all 8 verify workers.
    const single_cases = [_]struct { t: Tile, expect_core: u32 }{
        .{ .t = .recv, .expect_core = 5 },
        .{ .t = .repair, .expect_core = 30 },
        .{ .t = .replay, .expect_core = 16 },
        .{ .t = .sysvar, .expect_core = 29 },
        .{ .t = .txsend, .expect_core = 28 },
        .{ .t = .gossip, .expect_core = 24 },
        .{ .t = .produce, .expect_core = 20 },
        .{ .t = .quic, .expect_core = 6 },
        .{ .t = .rpc, .expect_core = 27 },
    };
    inline for (single_cases) |c| {
        // The cpu_set the table would build for this tile's core.
        const table_set = cpuSetFor(LIVE.coreOf(c.t));
        // The legacy open-coded equivalent (verify_tile.zig:441-442 shape).
        var legacy_set = [_]usize{0} ** 16;
        legacy_set[c.expect_core / 64] = @as(usize, 1) << @intCast(c.expect_core % 64);
        try testing.expectEqualSlices(usize, &legacy_set, &table_set);
    }

    // All 8 verify workers: pinTile core == 8 + worker_id, byte-identical cpu_set.
    var worker_id: u32 = 0;
    while (worker_id < NUM_VERIFY_WORKERS) : (worker_id += 1) {
        const want_core: u32 = 8 + worker_id; // verify_tile.zig:440 exact formula
        const table_set = cpuSetFor(LIVE.verify_base + worker_id);
        var legacy_set = [_]usize{0} ** 16;
        legacy_set[want_core / 64] = @as(usize, 1) << @intCast(want_core % 64);
        try testing.expectEqualSlices(usize, &legacy_set, &table_set);
    }
}
