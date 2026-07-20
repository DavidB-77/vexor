//! Switch-proof gossip-arming fix (2026-07-17, d2c2f59) — live-path regression
//! gate for `ReplayStage.ancestorChainComplete`'s CALLER-side buffer sizing.
//!
//! `ancestorChainComplete` (vex_svm/replay_stage.zig, made `pub` for this
//! file) is itself UNCHANGED by d2c2f59 — it always walked `out.len` entries
//! or to root, whichever came first. THE BUG was entirely in the call site
//! (replay_stage.zig ~6337-6420, the tower-lockout ancestor-set builder): it
//! passed a FIXED `[4096]Slot` stack buffer. Once unrooted depth
//! (candidate.parent_slot - db.rooted_slot) exceeds ~4096, the walk silently
//! truncates BEFORE reaching a `last_voted_slot` sitting close to root —
//! `tower.zig`'s `isLockedOut` (129-163) cannot distinguish "walked to root,
//! confirmed absent" from "buffer exhausted first"; either way
//! `ancestors.containsSlot(last_voted_slot)` is false, and a false
//! `containsSlot` unconditionally returns locked-out=true, so the vote
//! function returns before switch-proof is ever reached (replay_stage.zig
//! [SWITCH-PROOF] lines stop for good at slot 422525389, unrooted depth 4187,
//! while [TOWER-LOCKOUT] refusals keep climbing for 10,800+ more slots — the
//! ACTUAL blocker behind the live wedge, per d2c2f59's commit message).
//!
//! This file drives the REAL `ancestorChainComplete` against a REAL
//! `ReplayStage.banks` map (populated with a genuine parent-linked chain, no
//! mock/stand-in), using the EXACT captured incident numbers
//! (root=422521202, last_voted_slot=422521275, candidate.parent_slot at the
//! walk's freeze point=422525388, matching the log's "unrooted depth 4187" at
//! candidate slot 422525389) plus the EXACT two buffer shapes the fix
//! changes between (fixed `[4096]Slot` pre-fix vs. heap-sized-to-need
//! post-fix — the identical `need = parent - rooted_slot` computation
//! d2c2f59 added at the call site). Mirrors kat_revive_would_fire.zig's
//! established pattern for this struct (arena allocator; auto-spawned worker
//! + sysvar-refresh threads stopped AND JOINED before manual state
//! manipulation).
//!
//! Design: fix/switchproof-gossip-arming-2026-07-17, commit d2c2f59.
//!
//! Build/run: zig build test-ancestor-walk-depth

const std = @import("std");
const vex_svm = @import("vex_svm");
const core = @import("core");
const vex_crypto = @import("vex_crypto");

const ReplayStage = vex_svm.replay_stage.ReplayStage;
const Bank = vex_svm.Bank;
const Slot = vex_svm.replay_stage.Slot;
const Pubkey = core.Pubkey;
const Hash = core.Hash;
const LtHash = vex_crypto.LtHash;

/// Same rationale/shape as kat_revive_would_fire.zig's stopAndJoinWorkers:
/// ReplayStage.init unconditionally spawns worker_thread + sysvar_refresh_thread;
/// this test never exercises them and manipulates `banks`/`banks_lock` directly
/// on the main thread, so stop+join eliminates any race before manual writes.
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

/// Populate `stage.banks` with a genuine linear parent chain covering
/// (root, tip] — i.e. slots root+1..=tip, each bank's `.parent_slot` pointing
/// at the true preceding slot. This is exactly the "LIVE banks map —
/// authoritative in-memory parent links" ancestorChainComplete's own doc
/// comment describes as its primary source (no slot_parents/accounts_db
/// fallback exercised — `.accounts_db` stays null throughout, matching
/// ReplayStage.init's own default). root's own Bank entry is NOT inserted:
/// the walk's condition is `p > root`, so it never needs to resolve root.
fn buildLinearChain(stage: *ReplayStage, allocator: std.mem.Allocator, root: Slot, tip: Slot) !void {
    var slot: Slot = root + 1;
    while (slot <= tip) : (slot += 1) {
        const parent: ?Slot = slot - 1;
        const b = try Bank.init(allocator, slot, parent, Hash.default(), LtHash.init(), Hash.default());
        try stage.banks.put(slot, b);
    }
}

test "PRE-FIX shape: fixed [4096]Slot buffer truncates before reaching last_voted_slot at the live wedge's exact unrooted depth" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    // Exact captured incident numbers (forensics/incident-lockout-422521275-20260717-0757/,
    // d2c2f59's commit message): root=422521202 (tower root, frozen for the
    // whole wedge), last_voted_slot=422521275 (73 slots above root — inside
    // the unrooted region by construction), candidate.parent_slot=422525388
    // (one below the log's "unrooted depth 4187 at slot 422525389" freeze
    // point where [SWITCH-PROOF] lines stop for good).
    const root: Slot = 422_521_202;
    const last_voted_slot: Slot = 422_521_275;
    const parent: Slot = 422_525_388;
    try buildLinearChain(stage, allocator, root, parent);

    var fixed_buf: [4096]Slot = undefined;
    const out = stage.ancestorChainComplete(parent, root, &fixed_buf);

    // The walk fills exactly `out.len` == buffer capacity (need=4186 > 4096,
    // so it truncates, never reaching root).
    try std.testing.expectEqual(@as(usize, 4096), out.len);

    // THE BUG, reproduced against the REAL function: last_voted_slot sits
    // just 73 slots above root, well inside the true unrooted chain, but the
    // fixed buffer's nearest-4096-slots window (down to parent-4095=422521293)
    // never reaches it.
    var found = false;
    for (out) |s| {
        if (s == last_voted_slot) {
            found = true;
            break;
        }
    }
    try std.testing.expect(!found); // FALSE containsSlot -> tower.zig would misclassify this as non-ancestor -> false lockout

    // Exact truncation boundary: out[out.len-1] == parent - (4096-1).
    try std.testing.expectEqual(@as(Slot, 422_521_293), out[out.len - 1]);
}

test "POST-FIX shape: buffer sized to actual unrooted depth (d2c2f59's exact call-site formula) reaches last_voted_slot and walks all the way to root" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    const root: Slot = 422_521_202;
    const last_voted_slot: Slot = 422_521_275;
    const parent: Slot = 422_525_388;
    try buildLinearChain(stage, allocator, root, parent);

    // d2c2f59's EXACT call-site formula (replay_stage.zig ~6398-6420):
    //   const need: usize = if (parent > db.rooted_slot) parent - db.rooted_slot else 0;
    //   anc_buf_dyn = try self.allocator.alloc(Slot, need);
    const need: usize = if (parent > root) parent - root else 0;
    try std.testing.expectEqual(@as(usize, 4186), need); // sanity: > the old 4096 bound
    const dyn_buf = try allocator.alloc(Slot, need);
    const out = stage.ancestorChainComplete(parent, root, dyn_buf);

    // THE FIX: walk is no longer capped — it consumes the FULL unrooted
    // chain and reaches root.
    try std.testing.expectEqual(need, out.len);
    try std.testing.expectEqual(@as(Slot, root + 1), out[out.len - 1]); // walked all the way down to root+1

    var found = false;
    for (out) |s| {
        if (s == last_voted_slot) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found); // last_voted_slot now correctly found -> isLockedOut's containsSlot is TRUE -> no false lockout -> switch-proof block is reached

    // ancestorChainComplete itself is UNCHANGED by d2c2f59 (only the
    // caller's buffer sizing changed) — this confirms the SAME function,
    // given a correctly-sized buffer, was ALWAYS capable of full coverage;
    // the bug was purely the fixed-4096 call-site allocation, never the walk.
}

test "both-directions safety: below the old 4096 bound, fixed and dynamically-sized buffers agree byte-for-byte (fix is strictly additive, never changes existing-good behavior)" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stage = try ReplayStage.init(allocator, Pubkey{ .data = [_]u8{0} ** 32 });
    stopAndJoinWorkers(stage);

    // Synthetic small-depth wedge (300 unrooted slots — comfortably under the
    // old 4096 cap), same shape as the live incident but shallow.
    const root: Slot = 200_000;
    const last_voted_slot: Slot = 200_050;
    const parent: Slot = 200_300;
    try buildLinearChain(stage, allocator, root, parent);

    var fixed_buf: [4096]Slot = undefined;
    const out_fixed = stage.ancestorChainComplete(parent, root, &fixed_buf);

    const need: usize = parent - root;
    const dyn_buf = try allocator.alloc(Slot, need);
    const out_dyn = stage.ancestorChainComplete(parent, root, dyn_buf);

    try std.testing.expectEqual(out_fixed.len, out_dyn.len);
    try std.testing.expectEqualSlices(Slot, out_fixed, out_dyn);

    // Both correctly find last_voted_slot — the fix changes nothing here.
    for ([_][]const Slot{ out_fixed, out_dyn }) |slice| {
        var found = false;
        for (slice) |s| {
            if (s == last_voted_slot) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}
