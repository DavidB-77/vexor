//! vote_arming — the SINGLE source of the vote-program feature gates, shared by the replay seam and
//! the produce executor (vote-arming prerequisite P1, 2026-07-27).
//!
//! WHY THIS FILE EXISTS. `voteforge`'s `ExecContext.features` is a 9-gate open/closed struct that
//! decides, among other things, whether a vote account is serialized in the V4 layout. Replay derives
//! it from `instruction_dispatch.g_vote_live_features` — the `FeatureSet` `ReplayStage.setLiveFeatureSet`
//! publishes at bootstrap. If the produce path ever derived the same struct from a second place (a
//! produce-local literal, a re-read of the snapshot, a "current testnet" constant), the two could
//! disagree WITHOUT ANY ERROR: the vote would execute on both sides, both would commit, and the
//! account bytes would differ → bank_hash fork. `block_executor.VoteExecContext`'s own doc names this
//! as the first thing to resolve before arming.
//!
//! Duplicating the 9-line translation into the produce path would have made that class of bug
//! unprovable — a KAT comparing produce's flags to replay's would have been comparing a mirror to
//! itself. So the translation is EXTRACTED here and BOTH sides call it. That is a pure refactor:
//! `instruction_dispatch.executeVoteViaVoteforge`'s inline block moved verbatim, same expressions,
//! same order, gated by `test-replay-stage` + the golden replay.
//!
//! DELIBERATELY MIRRORED, NOT FIXED: `activationSlot(X) != null` asks "is this feature SCHEDULED at
//! all", not "is it active at THIS slot". That is what replay does today, so it is what produce must
//! do today; a slot-relative reading would be a behaviour change to the live vote path wearing the
//! costume of a produce-path fix, and it belongs in its own change with its own proof.
//!
//! WHAT IS NOT HERE: the bank-shaped glue (reading the parent bank's SlotHashes pending-write,
//! checking `is_frozen`). That lives at the arming call site. This file stays free of `bank.zig` so it
//! can be a standalone test root — run `zig build test-vote-arming`.

const std = @import("std");
const features_mod = @import("features.zig");
const vi = @import("voteforge/vote_instructions.zig");
const block_executor = @import("block_executor.zig");

pub const FeatureFlags = vi.FeatureFlags;
pub const EpochSchedule = block_executor.EpochSchedule;
pub const VoteExecContext = block_executor.VoteExecContext;

/// The 9 live vote gates as activation-slot-PRESENCE booleans (voteforge's `ExecContext.features` is
/// gate-open/closed only, never slot-relative). `null` ⇒ voteforge's conservative default (every new
/// gate closed), which is what an early-bootstrap or KAT-harness call site gets.
///
/// [moved verbatim from `instruction_dispatch.executeVoteViaVoteforge`, 2026-07-27 — same nine
/// expressions in the same order, including `custom_commission_collector`'s `orelse` over the V1/V2
/// feature ids. Any gate added to voteforge must be added HERE, once, not twice.]
pub fn voteFeatureFlags(live: ?*const features_mod.FeatureSet) FeatureFlags {
    const lfs = live orelse return .{};
    return .{
        .vote_state_v4 = lfs.activationSlot(features_mod.VOTE_STATE_LAYOUT_V4) != null,
        .enable_tower_sync_ix = lfs.activationSlot(features_mod.ENABLE_TOWER_SYNC_IX) != null,
        .deprecate_legacy_vote_ixs = lfs.activationSlot(features_mod.REJECT_LEGACY_VOTE_INSTRUCTIONS) != null,
        .custom_commission_collector = (lfs.activationSlot(features_mod.CUSTOM_COMMISSION_COLLECTOR) orelse
            lfs.activationSlot(features_mod.CUSTOM_COMMISSION_COLLECTOR_V2)) != null,
        .delay_commission_updates = lfs.activationSlot(features_mod.DELAY_COMMISSION_UPDATES) != null,
        .bls_pubkey_management_in_vote_account = lfs.activationSlot(features_mod.BLS_PUBKEY_MANAGEMENT_IN_VOTE_ACCOUNT) != null,
        .commission_rate_in_basis_points = lfs.activationSlot(features_mod.COMMISSION_RATE_IN_BASIS_POINTS) != null,
        .block_revenue_sharing = lfs.activationSlot(features_mod.BLOCK_REVENUE_SHARING) != null,
        .vote_account_initialize_v2 = lfs.activationSlot(features_mod.VOTE_ACCOUNT_INITIALIZE_V2) != null,
    };
}

/// Assemble the produce-side `VoteExecContext` from the same three sources replay reads, or return
/// null — meaning LEAVE `vote_ctx` UNARMED — when any of them is unavailable.
///
/// The null cases are the point of this function, not an afterthought:
///   * `parent_frozen == false` ⇒ the parent's `bank_hash` is still `Hash.default()`, so the
///     SlotHashes entry we would prepend carries a zero hash. That turns the tip-slot
///     `SlotHashMismatch` into a DIFFERENT, quieter mismatch instead of fixing anything.
///   * `parent_slot_hashes_blob == null` ⇒ `getSysvarFromPendingWrites` found no SlotHashes write on
///     the parent bank: a snapshot-loaded or sentinel parent on which no replay ever ran. The
///     tempting fallback — read SlotHashes from accounts_db — is the fork-BLIND
///     `_getRooted → unflushed_cache` path (see bank.zig's rooted-read helper), which can hand back a
///     SIBLING FORK's SlotHashes. Not arming for one slot costs one slot of vote throughput; arming on
///     a sibling fork's SlotHashes costs the chain.
///   * `childSlotHashes` returns null on a malformed blob — same treatment.
///
/// `live_features == null` is NOT a refusal: it maps to voteforge's all-gates-closed default, which is
/// precisely what replay would use at the same moment, and matching replay is the whole contract.
///
/// FOURTH REFUSAL — `bls_pubkey_management_in_vote_account` (SIMD-0387). Replay threads a real
/// `ExecContext.pop_cu_meter` (the shared per-tx compute meter that already took the flat 2,100 entry
/// charge); the produce executor passes null, because it runs no compute meter at all. With the gate
/// CLOSED that difference is unobservable: `consumePopComputeUnits` is only reached from
/// `verify_bls_proof_of_possession`, which no TowerSync path touches, so no committed byte differs.
/// With the gate OPEN it becomes a live divergence — replay can fail the instruction with
/// `ComputationalBudgetExceeded` after drawing 34,500 CU while produce, unmetered, succeeds and
/// commits. The gate is false on testnet today, so this refusal is inert; it exists because the flip
/// arrives on the cluster's schedule, not ours, and the failure mode is silent. Wiring a real meter
/// into the produce executor is the correct eventual fix and is NOT attempted here.
pub fn voteExecContextFor(
    producing_slot: u64,
    parent_slot: u64,
    parent_bank_hash: [32]u8,
    parent_frozen: bool,
    parent_slot_hashes_blob: ?[]const u8,
    sched: EpochSchedule,
    live_features: ?*const features_mod.FeatureSet,
) ?VoteExecContext {
    // ⚠️ SUPERSEDED 2026-07-27: this constructor has NO production callers. replay_stage's produce
    // path is now the PRODUCE ORACLE, which executes votes through the same golden-proven ladder
    // replay uses (executeDagTx) against a scratch child bank, so the child-bank vote context is
    // built by the ordinary replay machinery rather than reconstructed here.
    //
    // Its four refusals live on, restated as the oracle's ARM-TIME refusals in
    // replay_stage.buildProduceOracle (unfrozen parent; missing parent SlotHashes blob; and, via
    // produce_admit.SlotPreconditions, the rest) — the refuse-rather-than-guess discipline this file
    // established was kept deliberately, not dropped.
    //
    // voteFeatureFlags single-sourcing also became automatic: the oracle and replay now read the SAME
    // FeatureSet on the SAME code path, so the two can no longer disagree.
    if (!parent_frozen) return null;
    const features = voteFeatureFlags(live_features);
    // SIMD-0387 refusal — RETIRED for the produce path (still correct for any caller of THIS
    // function). It existed only because block_executor threaded pop_cu_meter=null, so a vote could
    // not be metered. The oracle inherits executeDagTx's REAL CU meter (seeded from
    // compute_budget.executionLimit and threaded into executeVoteInstruction), so the condition this
    // refusal guarded cannot arise there. Do not port this refusal onto the oracle.
    if (features.bls_pubkey_management_in_vote_account) return null; // SIMD-0387: no CU meter here
    const blob = parent_slot_hashes_blob orelse return null;
    const sh = block_executor.childSlotHashes(blob, parent_slot, parent_bank_hash) orelse return null;
    return block_executor.voteExecContextForProducingSlot(producing_slot, sched, features, sh);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// KATs — run: zig build test-vote-arming
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

/// Every gate, its feature id, and the `FeatureFlags` field it drives — the table the KAT below walks
/// so that a gate wired to the WRONG feature id (the failure mode a hand-written duplicate produces)
/// is caught per-gate rather than only in aggregate.
const GATE_TABLE = [_]struct { id: [32]u8, name: []const u8 }{
    .{ .id = features_mod.VOTE_STATE_LAYOUT_V4, .name = "vote_state_v4" },
    .{ .id = features_mod.ENABLE_TOWER_SYNC_IX, .name = "enable_tower_sync_ix" },
    .{ .id = features_mod.REJECT_LEGACY_VOTE_INSTRUCTIONS, .name = "deprecate_legacy_vote_ixs" },
    .{ .id = features_mod.CUSTOM_COMMISSION_COLLECTOR, .name = "custom_commission_collector" },
    .{ .id = features_mod.DELAY_COMMISSION_UPDATES, .name = "delay_commission_updates" },
    .{ .id = features_mod.BLS_PUBKEY_MANAGEMENT_IN_VOTE_ACCOUNT, .name = "bls_pubkey_management_in_vote_account" },
    .{ .id = features_mod.COMMISSION_RATE_IN_BASIS_POINTS, .name = "commission_rate_in_basis_points" },
    .{ .id = features_mod.BLOCK_REVENUE_SHARING, .name = "block_revenue_sharing" },
    .{ .id = features_mod.VOTE_ACCOUNT_INITIALIZE_V2, .name = "vote_account_initialize_v2" },
};

fn flagByName(f: FeatureFlags, name: []const u8) bool {
    inline for (@typeInfo(FeatureFlags).@"struct".fields) |fld| {
        if (std.mem.eql(u8, fld.name, name)) return @field(f, fld.name);
    }
    unreachable;
}

test "P1: the produce path and the replay seam read the SAME function, not two copies" {
    // The structural half of P1. `instruction_dispatch.executeVoteViaVoteforge` no longer contains a
    // FeatureFlags literal — it calls `vote_arming.voteFeatureFlags`, and so does every produce-side
    // context built through `voteExecContextFor`. A behavioural KAT cannot prove single-sourcing (two
    // identical copies pass it); this assertion is that `voteExecContextFor` routes through the shared
    // function rather than assembling its own struct.
    var fs = features_mod.FeatureSet.init();
    defer fs.deinit(testing.allocator);
    try fs.activate(testing.allocator, features_mod.VOTE_STATE_LAYOUT_V4, 1);

    var blob: [8 + 40]u8 = undefined;
    std.mem.writeInt(u64, blob[0..8], 1, .little);
    std.mem.writeInt(u64, blob[8..16], 100, .little);
    @memset(blob[16..48], 0xAA);

    const ctx = voteExecContextFor(102, 101, [_]u8{0xBB} ** 32, true, &blob, EpochSchedule.DEFAULT, &fs).?;
    try testing.expectEqual(voteFeatureFlags(&fs), ctx.features);
}

test "P1: each of the 9 gates maps to its own feature id (one-hot activation table)" {
    for (GATE_TABLE, 0..) |gate, gi| {
        var fs = features_mod.FeatureSet.init();
        defer fs.deinit(testing.allocator);
        try fs.activate(testing.allocator, gate.id, 1);
        const f = voteFeatureFlags(&fs);

        for (GATE_TABLE, 0..) |other, oi| {
            const expect_on = oi == gi;
            testing.expectEqual(expect_on, flagByName(f, other.name)) catch |e| {
                std.debug.print("gate {s} activated: flag {s} = {any}, expected {any}\n", .{ gate.name, other.name, flagByName(f, other.name), expect_on });
                return e;
            };
        }
    }
}

test "P1: custom_commission_collector opens on EITHER the V1 or the V2 feature id" {
    // The one gate whose translation is not 1:1 — `orelse` over two ids. A hand-copied duplicate that
    // dropped the V2 arm would still pass a naive "all gates off / all gates on" test.
    var fs2 = features_mod.FeatureSet.init();
    defer fs2.deinit(testing.allocator);
    try fs2.activate(testing.allocator, features_mod.CUSTOM_COMMISSION_COLLECTOR_V2, 7);
    try testing.expect(voteFeatureFlags(&fs2).custom_commission_collector);

    var fs1 = features_mod.FeatureSet.init();
    defer fs1.deinit(testing.allocator);
    try fs1.activate(testing.allocator, features_mod.CUSTOM_COMMISSION_COLLECTOR, 7);
    try testing.expect(voteFeatureFlags(&fs1).custom_commission_collector);
}

test "P1: a null FeatureSet is all-gates-closed, matching voteforge's own conservative default" {
    try testing.expectEqual(FeatureFlags{}, voteFeatureFlags(null));
}

test "P1: a DISABLED feature reads as closed, not as scheduled" {
    var fs = features_mod.FeatureSet.init();
    defer fs.deinit(testing.allocator);
    try fs.disable(testing.allocator, features_mod.VOTE_STATE_LAYOUT_V4);
    try testing.expect(!voteFeatureFlags(&fs).vote_state_v4);
}

test "P2 (arming refusals): unfrozen parent, absent SlotHashes write, or malformed blob ⇒ NO context" {
    const SCHED = EpochSchedule.DEFAULT;
    var blob: [8 + 40]u8 = undefined;
    std.mem.writeInt(u64, blob[0..8], 1, .little);
    std.mem.writeInt(u64, blob[8..16], 100, .little);
    @memset(blob[16..48], 0x01);

    // Unfrozen parent ⇒ its bank_hash is still Hash.default(); refuse.
    try testing.expect(voteExecContextFor(102, 101, [_]u8{0xBB} ** 32, false, &blob, SCHED, null) == null);
    // No SlotHashes pending-write on the parent (snapshot-loaded / sentinel bank). Refuse rather than
    // fall back to the fork-blind accounts_db read, which can return a sibling fork's SlotHashes.
    try testing.expect(voteExecContextFor(102, 101, [_]u8{0xBB} ** 32, true, null, SCHED, null) == null);
    // Header claims 2 entries, blob holds 1.
    var bad: [8 + 40]u8 = blob;
    std.mem.writeInt(u64, bad[0..8], 2, .little);
    try testing.expect(voteExecContextFor(102, 101, [_]u8{0xBB} ** 32, true, &bad, SCHED, null) == null);
    // All three satisfied ⇒ armed.
    try testing.expect(voteExecContextFor(102, 101, [_]u8{0xBB} ** 32, true, &blob, SCHED, null) != null);
}

test "P6: SIMD-0387 BLS-PoP gate open ⇒ REFUSE to arm (produce has no CU meter, replay does)" {
    // Inert today (the gate is false on testnet) and that is the point: the flip arrives on the
    // cluster's schedule. Once open, `verify_bls_proof_of_possession` draws 34,500 CU from replay's
    // shared per-tx meter and can fail the instruction with `ComputationalBudgetExceeded`, while the
    // produce executor — which threads `pop_cu_meter = null` and runs no meter at all — succeeds and
    // commits. Different committed bytes, no error on either side. Refusing turns that into "votes
    // stay dropped", which is exactly today's behaviour and is safe.
    const SCHED = EpochSchedule.DEFAULT;
    var blob: [8 + 40]u8 = undefined;
    std.mem.writeInt(u64, blob[0..8], 1, .little);
    std.mem.writeInt(u64, blob[8..16], 100, .little);
    @memset(blob[16..48], 0x03);

    var fs = features_mod.FeatureSet.init();
    defer fs.deinit(testing.allocator);
    try fs.activate(testing.allocator, features_mod.VOTE_STATE_LAYOUT_V4, 1);
    // Every other prerequisite satisfied ⇒ armed, so the refusal below is attributable to this gate
    // alone rather than to some other missing input.
    try testing.expect(voteExecContextFor(102, 101, [_]u8{0xBB} ** 32, true, &blob, SCHED, &fs) != null);

    try fs.activate(testing.allocator, features_mod.BLS_PUBKEY_MANAGEMENT_IN_VOTE_ACCOUNT, 1);
    try testing.expect(voteFeatureFlags(&fs).bls_pubkey_management_in_vote_account);
    try testing.expect(voteExecContextFor(102, 101, [_]u8{0xBB} ** 32, true, &blob, SCHED, &fs) == null);
}

test "P4: epoch + leader_schedule_epoch derive from the PRODUCING slot, not the parent's" {
    // The prerequisite the earlier `vote_ctx` note did not name. At an epoch boundary the parent and
    // the produced slot fall in DIFFERENT epochs; `get_and_update_authorized_voter(epoch)` and
    // `purge_authorized_voters(epoch-1)` resolve against it, so the wrong source writes different
    // vote-account bytes than replay does — a fork with no error anywhere.
    const SCHED = EpochSchedule.DEFAULT;
    const boundary = SCHED.getFirstSlotInEpoch(1000); // first slot of epoch 1000
    const parent = boundary - 1; // last slot of epoch 999

    // The two candidate sources genuinely differ here — without this the choice would be moot and the
    // assertion below vacuous.
    try testing.expect(SCHED.getEpoch(parent) != SCHED.getEpoch(boundary));

    var blob: [8 + 40]u8 = undefined;
    std.mem.writeInt(u64, blob[0..8], 1, .little);
    std.mem.writeInt(u64, blob[8..16], parent - 1, .little);
    @memset(blob[16..48], 0x02);

    const ctx = voteExecContextFor(boundary, parent, [_]u8{0xCC} ** 32, true, &blob, SCHED, null).?;
    // Replay's formula is `bank.epoch_schedule.getEpoch(bank.slot)` where bank.slot is the slot BEING
    // EXECUTED (instruction_dispatch.zig:2969-2970) — i.e. the produced slot.
    try testing.expectEqual(SCHED.getEpoch(boundary), ctx.epoch);
    try testing.expectEqual(SCHED.getLeaderScheduleEpoch(boundary), ctx.leader_schedule_epoch);
    try testing.expect(ctx.epoch != SCHED.getEpoch(parent)); // the parent-sourced value is NOT what we produced
    // The schedule parameters themselves are passed through unchanged (no second epoch math).
    try testing.expectEqual(SCHED.slots_per_epoch, ctx.epoch_schedule.slots_per_epoch);
    try testing.expectEqual(SCHED.first_normal_slot, ctx.epoch_schedule.first_normal_slot);
}
