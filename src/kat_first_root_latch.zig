//! G0 first-root positive-attestation latch — live-path regression gate
//! (incident 423083743, boot 18:45 2026-07-19).
//!
//! src/vex_svm/root_guards.zig KATs (zig build test-root-guards) prove the PURE
//! G0/G1/G2 decision logic in isolation. This file proves the REAL glue in
//! replay_stage.zig around it — `rootGuardDecisionForAdvance` driving the actual
//! rootGuardInputs collection (fork-choice key resolution + scanCachedSlotHash),
//! the actual `probeClusterProduced` → `fetchProducedSlots` VEX_SKIP_CANON_FILE
//! offline-injection path, the per-candidate probe cache, and the
//! `first_root_attested` latch field transition — against a REAL ReplayStage
//! instance. Mirrors kat_revive_would_fire.zig's established pattern for this
//! struct (arena allocator; auto-spawned worker + sysvar-refresh threads stopped
//! AND JOINED before any manual state manipulation — see `stopAndJoinWorkers`).
//!
//! Incident shape being gated (live testnet divergence, boot 2026-07-19):
//! fresh snapshot at 423083741; the FIRST replayed slot 423083742 was produced
//! but cluster-SKIPPED (0 attestations, never in cluster SlotHashes) → the old
//! G2 fail-open branch allowed rooting it → irreversible dead-fork root; G2 then
//! fired one slot too late at 423083743 (fires=1). With the latch: the 742-shape
//! advance is REFUSED pre-latch (hash-silent + not-produced-confirmed).
//!
//! Build/run: zig build test-first-root-latch

const std = @import("std");
const vex_svm = @import("vex_svm");
const vex_consensus = @import("vex_consensus");
const core = @import("core");

const ReplayStage = vex_svm.replay_stage.ReplayStage;
const root_guards = vex_svm.root_guards;
const fc_mod = vex_consensus.fork_choice;
const Pubkey = core.Pubkey;
const Hash = core.Hash;

/// Same rationale as kat_revive_would_fire.zig's stopAndJoinWorkers (see its
/// 2026-07-17 CI-SIGSEGV FIX header): ReplayStage.init unconditionally spawns
/// worker_thread + sysvar_refresh_thread, and both can race this test's manual
/// cached_slot_hashes field writes (installSlotHashes frees+reassigns with no
/// lock). Stop + JOIN both before touching any state.
fn stopAndJoinWorkers(stage: *ReplayStage) void {
    stage.is_running.store(false, .release);
    if (stage.worker_thread) |t| {
        t.join();
        stage.worker_thread = null;
    }
    if (stage.sysvar_refresh_thread) |t| {
        t.join();
        stage.sysvar_refresh_thread = null;
    }
}

fn mkHash(b: u8) Hash {
    return .{ .data = [_]u8{b} ** 32 };
}

/// Builds a `cached_slot_hashes`-shaped blob (8-byte LE count + count*(8-byte
/// LE slot, 32-byte hash) — the SysvarS1otHashes111... on-chain layout, same
/// shape installSlotHashes produces) for direct field injection.
fn makeSlotHashBlob(allocator: std.mem.Allocator, entries: []const struct { slot: u64, hash: Hash }) ![]u8 {
    const out = try allocator.alloc(u8, 8 + entries.len * 40);
    std.mem.writeInt(u64, out[0..8], entries.len, .little);
    for (entries, 0..) |e, i| {
        const off = 8 + i * 40;
        std.mem.writeInt(u64, out[off..][0..8], e.slot, .little);
        @memcpy(out[off + 8 ..][0..32], &e.hash.data);
    }
    return out;
}

/// Writes `contents` to a temp file and setenv's VEX_SKIP_CANON_FILE at it —
/// the offline injection seam fetchProducedSlots documents (static file replaces
/// the getBlocks curl; filtered to [lo,hi] by the callee).
fn setCanonFile(tmp: *std.testing.TmpDir, name: []const u8, contents: []const u8) !void {
    {
        const f = try tmp.dir.createFile(name, .{});
        defer f.close();
        try f.writeAll(contents);
    }
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &pathbuf);
    var file_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try std.fmt.bufPrintZ(&file_path_buf, "{s}/{s}", .{ dir, name });
    _ = setenv("VEX_SKIP_CANON_FILE", file_path.ptr, 1);
}

test "incident 423083743 sequence: skipped-742 REFUSED pre-latch; divergent-743 G2; positive match latches; post-latch hash-silent allowed" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    // Real incident slot numbers. 741 = the fresh-snapshot boot root (canonical,
    // parent-hash-proven byte-correct); 742 = produced-but-cluster-SKIPPED (the
    // slot the 18:45 boot irreversibly rooted); 743 = first slot where the
    // cluster held a KNOWN-DIFFERENT hash (the too-late G2 fires=1).
    const S741: u64 = 423_083_741;
    const S742: u64 = 423_083_742;
    const S743: u64 = 423_083_743;
    const S744: u64 = 423_083_744;
    const S745: u64 = 423_083_745;
    const h741 = mkHash(0x41);
    const h742 = mkHash(0x42); // OUR minority-fork version
    const h743 = mkHash(0x43); // OUR version
    const h744 = mkHash(0x44);
    const h745 = mkHash(0x45);
    const cluster_h743 = mkHash(0xC3); // cluster's canonical 743 — DIFFERENT

    // Our replayed fork in the REAL fork-choice tree (seeds root at 741).
    if (stage.fork_choice) |*fc| {
        try fc_mod.addForkCompat(fc, S742, S741, h742, h741);
        try fc_mod.addForkCompat(fc, S743, S742, h743, h742);
        try fc_mod.addForkCompat(fc, S744, S743, h744, h743);
        try fc_mod.addForkCompat(fc, S745, S744, h745, h744);
    } else return error.TestNoForkChoice;

    // Cluster SlotHashes view: 742 ABSENT (skipped slots never appear — the G2
    // structural blind spot), 743 present with a DIFFERENT hash, 744 present and
    // MATCHING ours, 745 absent (beyond the cached window).
    stage.cached_slot_hashes = try makeSlotHashBlob(allocator, &.{
        .{ .slot = S743, .hash = cluster_h743 },
        .{ .slot = S744, .hash = h744 },
    });

    // Historical produced-slot oracle (getBlocks analog): 742 and 745 absent.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try setCanonFile(&tmp, "canon.txt", "423083741\n423083743\n423083744\n");
    defer _ = unsetenv("VEX_SKIP_CANON_FILE");

    try std.testing.expect(!stage.first_root_attested);

    // 1) The 742 shape: hash-silent + cluster-NOT-produced ⇒ G0 REFUSE, no latch.
    {
        const dec = stage.rootGuardDecisionForAdvance(S742, S743) orelse return error.TestNoDecision;
        switch (dec) {
            .refuse_g0 => |why| try std.testing.expectEqual(root_guards.G0Why.not_produced, why),
            else => return error.TestExpectedG0Refuse,
        }
        try std.testing.expect(!stage.first_root_attested);
    }

    // 2) 743: cluster holds a KNOWN-DIFFERENT hash ⇒ G2 refuse (unchanged,
    //    pre- and post-latch — the incident's fires=1, now no longer too late).
    {
        const dec = stage.rootGuardDecisionForAdvance(S743, S744) orelse return error.TestNoDecision;
        try std.testing.expect(dec == .refuse_g2);
        try std.testing.expect(!stage.first_root_attested);
    }

    // 3) 744: positive cluster-attested hash MATCH ⇒ allow + latch SET.
    {
        const dec = stage.rootGuardDecisionForAdvance(S744, S745) orelse return error.TestNoDecision;
        try std.testing.expect(dec == .allow_attested);
        try std.testing.expect(stage.first_root_attested);
    }

    // 4) Post-latch: hash-silent AND absent from the canon file ⇒ allow (today's
    //    fail-open behavior verbatim; the produced probe is no longer consulted —
    //    if it were, the canon file would refuse this slot).
    {
        const dec = stage.rootGuardDecisionForAdvance(S745, S745) orelse return error.TestNoDecision;
        try std.testing.expect(dec == .allow);
        try std.testing.expect(stage.first_root_attested);
    }
}

test "pre-latch hash-silent + produced-CONFIRMED (deep catch-up outside SlotHashes window) => allowed, latch NOT set" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    const PARENT: u64 = 423_080_000;
    const CAND: u64 = 423_080_001; // candidate root, > 512 slots behind the tip
    if (stage.fork_choice) |*fc| {
        try fc_mod.addForkCompat(fc, CAND, PARENT, mkHash(0x11), mkHash(0x10));
    } else return error.TestNoForkChoice;
    // cached_slot_hashes stays null — the whole range is outside the cluster's
    // ~512-slot SlotHashes window (hash-silent).

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try setCanonFile(&tmp, "canon.txt", "423080000\n423080001\n423080002\n");
    defer _ = unsetenv("VEX_SKIP_CANON_FILE");

    const dec = stage.rootGuardDecisionForAdvance(CAND, CAND) orelse return error.TestNoDecision;
    try std.testing.expect(dec == .allow);
    // Chain-level attestation only — NOT a positive hash match — so no latch:
    // the first in-window candidate must still positively match before the G0
    // gate stands down.
    try std.testing.expect(!stage.first_root_attested);
}

test "pre-latch hash-silent + oracle UNREACHABLE => G0 REFUSE (fail-closed only pre-latch)" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    const PARENT: u64 = 423_090_000;
    const CAND: u64 = 423_090_001;
    if (stage.fork_choice) |*fc| {
        try fc_mod.addForkCompat(fc, CAND, PARENT, mkHash(0x21), mkHash(0x20));
    } else return error.TestNoForkChoice;

    // Unreadable canon file = fetchProducedSlots returns null (a failed curl's
    // exact degradation), with NO live-RPC fallback attempted under the env.
    _ = setenv("VEX_SKIP_CANON_FILE", "/nonexistent/kat-first-root-latch-canon", 1);
    defer _ = unsetenv("VEX_SKIP_CANON_FILE");

    const dec = stage.rootGuardDecisionForAdvance(CAND, CAND) orelse return error.TestNoDecision;
    switch (dec) {
        .refuse_g0 => |why| try std.testing.expectEqual(root_guards.G0Why.oracle_unreachable, why),
        else => return error.TestExpectedG0Refuse,
    }
    try std.testing.expect(!stage.first_root_attested);
}

// Test-only libc externs (mirrors main.zig:210's identical setenv declaration —
// std.posix has no portable setenv/unsetenv on this target).
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;
