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

/// 2026-07-17 CI-SIGSEGV FIX — ReplayStage.init unconditionally spawns TWO
/// real background threads (worker_thread=replayWorker, sysvar_refresh_thread
/// =sysvarRefreshWorker), both of which allocate/free through `self.allocator`
/// from their own thread context. This file passes an ArenaAllocator (chosen
/// to dodge std.testing.allocator's leak-panic — ReplayStage.init isn't
/// designed for a leak-checked per-alloc deinit, see the arena comment below)
/// as that allocator — but std.heap.ArenaAllocator has ZERO internal
/// synchronization, unlike production's std.heap.c_allocator (thread-safe
/// libc malloc, see main.zig's allocator-selection comment: "recv/verify/
/// replay threads all allocate").
///
/// This file's PREVIOUS fix attempt was a bare `is_running.store(false,
/// .release)` at the top of cascadeWorker/livePathWorker, on the theory that
/// it "never exercises the sysvar-refresh chain" (see the — now corrected —
/// claim in kat_revive_would_fire.zig's header, which added the real fix,
/// `stopAndJoinWorkers`, only for ITS OWN direct sysvar_refresh_thread
/// exposure). That theory was WRONG: replayWorker (worker_thread) has its
/// OWN independent periodic call into the exact same fetchSlotHashesRemote
/// -> installSlotHashes chain (the "PR-5aq proactive cluster SlotHashes
/// refresh" block, replay_stage.zig ~:9683-9694) — completely unrelated to
/// sysvar_refresh_thread. A bare is_running.store(false) is only a hint the
/// worker checks between loop iterations; it does NOT stop a worker already
/// mid-iteration, and fetchSlotHashesRemote posix_spawns a real `curl -m 3`
/// child and blocks in waitpid() for up to 3s — a wide, genuine window in
/// which the still-live worker_thread calls self.allocator.dupeZ/.free on
/// the SAME ArenaAllocator this test's own thread is concurrently mutating
/// (building the 20k-entry pending_chain / running markSlotDead's cascade).
///
/// CONFIRMED BY REPRODUCTION (2026-07-17, gdb on 15 captured core dumps under
/// deliberate CPU starvation): the crash is `self.allocator.free(s)` at
/// replay_stage.zig:2336 inside fetchSlotHashesRemote, called from
/// replayWorker at :9693 — on a thread whose `self` pointer belonged to a
/// DIFFERENT, already-torn-down ReplayStage from an earlier test in the same
/// process (that test function returned — and its arena's backing STACK
/// frame was reused — while its worker_thread was still leaked and running,
/// having never been joined). A textbook orphaned-thread use-after-free of a
/// non-thread-safe arena, NOT a bug in markSlotDead/verifyTicksKill
/// themselves (neither appears anywhere in the crashing thread's backtrace).
/// Production is never exposed: main.zig always constructs the allocator as
/// std.heap.c_allocator (thread-safe) and ReplayStage.deinit() always stops
/// AND JOINS both threads before freeing anything.
///
/// FIX: mirror kat_revive_would_fire.zig's `stopAndJoinWorkers` exactly, and
/// call it on the MAIN test thread immediately after ReplayStage.init()
/// returns — before spawning cascadeWorker/livePathWorker, before any
/// pending_chain/dead_slots manipulation, before any further arena use. This
/// closes the window entirely: init() performs no allocator use on the main
/// thread after spawning worker_thread (verified: the only code between the
/// spawn and `return stage` is the sysvar_refresh_thread spawn itself), so
/// by the time stopAndJoinWorkers returns, no other thread can still be
/// touching this stage's arena.
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
    // Background worker_thread/sysvar_refresh_thread are already stopped AND
    // JOINED by the caller (stopAndJoinWorkers, called right after
    // ReplayStage.init returns — see the 2026-07-17 CI-SIGSEGV FIX comment
    // above) before this thread was even spawned. This is a single-threaded
    // logic-bug repro, not a concurrency test.

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
    stopAndJoinWorkers(stage); // eliminate the race BEFORE any manual state manipulation
    // No full stage.deinit(): that would free dead_slots/pending_chain before
    // this test's own assertions read them. The arena reclaims all of
    // stage's memory on test exit; stopAndJoinWorkers already guarantees no
    // other thread is touching it by then.

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
    // Background worker_thread/sysvar_refresh_thread are already stopped AND
    // JOINED by the caller (stopAndJoinWorkers) before this thread was even
    // spawned — see the 2026-07-17 CI-SIGSEGV FIX comment at the top of this
    // file. This is the exact fix `is_running.store(false, .release)` here
    // (pre-fix) failed to provide: it's only a hint checked between
    // replayWorker loop iterations, not a stop — a worker already inside
    // fetchSlotHashesRemote's `waitpid` (up to curl's -m 3 = 3s) keeps
    // running, unsynchronized, against the SAME arena this thread is about
    // to mutate.

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
    stopAndJoinWorkers(stage); // eliminate the race BEFORE any manual state manipulation

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
