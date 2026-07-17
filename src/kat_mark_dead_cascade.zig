//! Regression KAT — `markSlotDead` orphan-cascade must NOT recurse to a depth
//! proportional to the pending_chain length (stack-overflow SIGSEGV).
//!
//! ROOT CAUSE (feat/verify-ticks-canonical-zig-2026-06-19 zerohash crash,
//! slot ~416277365): the verify_ticks `zerohash` build is the FIRST mark-dead
//! caller that kills an UNFROZEN slot from DEEP inside `replayEntriesInternal`
//! (replay_stage.zig:5345/6238 → verifyTicksKill → markSlotDead). Every OTHER
//! mark-dead caller fires from a shallow base frame (a sweep or onSlotCompleted
//! directly). markSlotDead's orphan cascade (replay_stage.zig:2182-2191,
//! pre-fix) was a GENUINE recursive `self.markSlotDead(child)` — on a long
//! linear orphan chain in pending_chain (normal during catchup) it recursed to
//! depth == chain-length, each level carrying markSlotDead's full frame
//! (orphans ArrayList + locks) ON TOP of the giant replayEntriesInternal frame.
//! That overflows the replay-worker thread stack → SIGSEGV with the smashed,
//! frame-less backtrace `start_thread→clone3→??? 0x0` (the unwinder can't walk
//! a corrupted stack — a use-after-free would instead show the full deep chain
//! below the bad PC). The `off` build never crashes because it never drives the
//! Verifier, so it never kills an unfrozen slot mid-replay → no cascade on the
//! deep frame.
//!
//! THE FIX (replay_stage.zig markSlotDead): the cascade is now an ITERATIVE
//! worklist (explicit queue drained in a loop, O(1) stack depth) instead of
//! recursion — closer to Agave's `mark_dead_slot` shape and depth-independent
//! of the orphan chain length. The per-slot side-effects (dead_slots insert,
//! purgeUnrootedSlot, fork_choice mark-invalid, pending_chain removal, recorder)
//! are unchanged and still fire once per dead slot, in the same order.
//!
//! This KAT drives the REAL `ReplayStage.markSlotDead` (not a copy) against a
//! deliberately DEEP linear pending_chain. PRE-FIX it SIGSEGVs (stack overflow);
//! POST-FIX it completes and every chain slot lands in dead_slots. Run on a
//! freshly-spawned thread with a MODEST stack so the overflow reproduces fast
//! and deterministically (a 8/16 MB main-thread stack would need a much longer
//! chain to blow; the production replay-worker frame is already near-full when
//! the cascade starts, which the small test stack faithfully emulates).
//!
//! Build/run:  zig build test-mark-dead-cascade

const std = @import("std");
const vex_svm = @import("vex_svm");
const vex_crypto = @import("vex_crypto");
const core = @import("core");

const ReplayStage = vex_svm.replay_stage.ReplayStage;
const Bank = vex_svm.Bank;
const Hash = vex_svm.Hash;
const LtHash = vex_crypto.LtHash;
const Pubkey = core.Pubkey;

/// Depth of the linear orphan chain. Each slot k (1..=N) defers with
/// target_parent = k-1, so killing slot 0 must cascade through all N. With the
/// pre-fix recursion this needs ~N stack frames; on the 512 KiB worker stack
/// (set below) markSlotDead's heavy frame overflows at depth ~900 (empirically
/// observed pre-fix), so 20_000 reliably overflows the pre-fix build with margin
/// while staying fast. The iterative fix handles it at O(1) stack depth.
const CHAIN_DEPTH: u64 = 20_000;

/// Worker that builds the deep chain and drives the real markSlotDead. Runs on a
/// spawned thread with a bounded stack (see `runOnSmallStack`) so the pre-fix
/// recursion overflows quickly. Sets `ok.*` true only if markSlotDead returns
/// (post-fix). On the pre-fix build the process SIGSEGVs here and never returns.
fn cascadeWorker(stage: *ReplayStage, ok: *bool) void {
    // Stop the background replay worker thread so it can't race our manual
    // pending_chain/dead_slots manipulation — this is a single-threaded
    // logic-bug repro, not a concurrency test.
    stage.is_running.store(false, .release);

    // Build a LINEAR orphan chain entirely in pending_chain:
    //   slot 1  -> target_parent 0
    //   slot 2  -> target_parent 1
    //   ...
    //   slot N  -> target_parent N-1
    // markSlotDead(0) collects {1} (target_parent==0), kills 1 → collects {2}
    // → ... a single unbroken cascade of length N.
    var k: u64 = 1;
    while (k <= CHAIN_DEPTH) : (k += 1) {
        stage.pending_chain.put(k, .{
            .data = &.{}, // no owned bytes → no frees needed
            .target_parent = k - 1,
            .added_ms = 0,
            .boundaries = &.{},
        }) catch return;
    }

    // banks is empty → markSlotDead's fork_choice block takes the "never frozen"
    // skip branch (no real Bank needed). accounts_db is null → purge is a no-op.
    // recorder is disabled by default → emitDeadSlot is a no-op. So the ONLY
    // work that scales with CHAIN_DEPTH is the cascade traversal itself — which
    // is exactly the code under test.
    stage.markSlotDead(0, "kat_deep_orphan_cascade");

    ok.* = true; // reached only if the cascade did NOT overflow the stack
}

test "markSlotDead deep orphan cascade does not overflow the stack (verify_ticks zerohash SIGSEGV regression)" {
    // Arena: ReplayStage.init pre-warms 1024 banks + a heap queue and is not
    // designed for a leak-checked per-alloc deinit (it spawns/owns threads). The
    // arena frees everything in one shot and avoids testing.allocator's
    // leak-panic, matching the established pattern (kat_failed_tx_rollback.zig).
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    // No stage.deinit(): the worker thread is stopped inside cascadeWorker and
    // the arena reclaims all of stage's memory on test exit.

    var ok = false;
    // 512 KiB stack: large enough for the iterative fix's O(1) depth, far too
    // small for the pre-fix per-slot recursion at CHAIN_DEPTH. Matches the
    // production reality that the cascade begins atop an already-deep frame.
    var thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, cascadeWorker, .{ stage, &ok });
    thread.join();

    try std.testing.expect(ok);

    // Every slot in the chain (0..=N) must now be marked dead.
    try std.testing.expect(stage.dead_slots.contains(0));
    try std.testing.expect(stage.dead_slots.contains(CHAIN_DEPTH));
    try std.testing.expect(stage.dead_slots.contains(CHAIN_DEPTH / 2));
    try std.testing.expectEqual(@as(u32, @intCast(CHAIN_DEPTH + 1)), stage.dead_slots.count());

    // And the cascade must have drained the pending_chain (each dead slot's own
    // pending_chain entry is removed).
    try std.testing.expectEqual(@as(u32, 0), stage.pending_chain.count());
}

// ─────────────────────────────────────────────────────────────────────────────
// LIVE-PATH GATE (task step 4): force a dead verdict through the REAL replay
// driving path — verifyTicksKill → markSlotDead → cascade — on an UNFROZEN slot,
// NOT just the pure Verifier (which is pointer-free and can't segfault). This is
// the exact path the live zerohash kill takes (replay_stage.zig:5345/6238 →
// verifyTicksKill). It guarantees a driving-path crash can never slip to deploy
// again behind a green pure-Verifier KAT.
// ─────────────────────────────────────────────────────────────────────────────

const LIVE_CHAIN_DEPTH: u64 = 20_000;
const KILL_SLOT: u64 = 1_000_000;

fn livePathWorker(stage: *ReplayStage, bank: *Bank, ok: *bool) void {
    stage.is_running.store(false, .release);

    // Insert the UNFROZEN bank for KILL_SLOT into self.banks: present but
    // is_frozen=false, bank_hash all-zeros — exactly the state a verify_ticks
    // kill sees (it fires mid-replay, before freeze). This exercises the
    // unfrozen fork_choice guard (is_frozen=false → skip, no fork_info).
    stage.banks.put(KILL_SLOT, bank) catch return;

    // Deep linear orphan chain hanging off KILL_SLOT:
    //   KILL_SLOT+1 -> target_parent KILL_SLOT, +2 -> +1, ...
    var k: u64 = 1;
    while (k <= LIVE_CHAIN_DEPTH) : (k += 1) {
        stage.pending_chain.put(KILL_SLOT + k, .{
            .data = &.{},
            .target_parent = KILL_SLOT + k - 1,
            .added_ms = 0,
            .boundaries = &.{},
        }) catch return;
    }

    // THE REAL KILL ENTRYPOINT — same call the live replay loop makes when the
    // Verifier returns a dead verdict (a zero-hash tick). Must NOT overflow.
    stage.verifyTicksKill(bank, "invalid_tick_hash_count_zero");

    ok.* = true;
}

test "live-path: verifyTicksKill on UNFROZEN slot with deep orphan chain does not crash" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });

    // Real unfrozen Bank for KILL_SLOT (is_frozen=false, bank_hash=0 by init).
    const bank = try Bank.init(
        allocator,
        KILL_SLOT,
        KILL_SLOT - 1, // parent_slot
        Hash.ZERO, // parent_hash
        LtHash.init(), // parent_lthash
        Hash.ZERO, // parent_poh_hash
    );
    try std.testing.expect(!bank.is_frozen);

    var ok = false;
    var thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, livePathWorker, .{ stage, bank, &ok });
    thread.join();

    try std.testing.expect(ok);
    // KILL_SLOT + its entire orphan chain are dead.
    try std.testing.expect(stage.dead_slots.contains(KILL_SLOT));
    try std.testing.expect(stage.dead_slots.contains(KILL_SLOT + LIVE_CHAIN_DEPTH));
    try std.testing.expectEqual(@as(u32, @intCast(LIVE_CHAIN_DEPTH + 1)), stage.dead_slots.count());
}
