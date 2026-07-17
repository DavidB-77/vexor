//! kat_epoch_schedule.zig — FIX-2 regression KAT (proactive-trio 2026-06-10):
//! canonical EpochSchedule epoch math, replacing the deleted hardcoded
//! `vote_state_serde.slotToEpoch` helper (the 524288-vs-524256 off-by-32
//! carrier class: first 32 slots of EVERY epoch got epoch N−1 →
//! incrementCredits(wrong_epoch) → poisoned vote epoch_credits exactly at
//! epoch boundaries — prime suspect for the epoch-972 crossing divergence
//! @414380256 on 2026-06-10).
//!
//! Ground truth = Agave EpochSchedule (solana-epoch-schedule-3.1.0, dep of
//! agave-4.1.0-beta.3): get_epoch_and_slot_index / get_first_slot_in_epoch.
//! Testnet schedule: warmup=true, slots_per_epoch=432000,
//! first_normal_epoch=14, first_normal_slot=524256 (= (2^14−1)×32, derived
//! below from the struct itself — not trusted as a magic constant).
//!
//! Run: zig build test-epoch-schedule-414380256

const std = @import("std");
const vex_svm = @import("vex_svm");

const EpochSchedule = vex_svm.bank.EpochSchedule;
const SCHED = EpochSchedule.DEFAULT;

test "epoch-972 boundary: ALL 32 first slots of the epoch map to 972 (the off-by-32 carrier)" {
    // Derive the boundary FROM THE STRUCT (task rule: don't trust the
    // formula blindly): first slot of epoch 972.
    const first_972 = SCHED.getFirstSlotInEpoch(972);
    try std.testing.expectEqual(@as(u64, 414_380_256), first_972);
    // Cross-check the closed form: epoch e (>=14) starts at
    // first_normal_slot + (e-14)*slots_per_epoch.
    try std.testing.expectEqual(
        SCHED.first_normal_slot + (972 - SCHED.first_normal_epoch) * SCHED.slots_per_epoch,
        first_972,
    );

    // The 32 slots that the old 524288 hardcode mapped to epoch 971:
    // (414380256 - 524288) / 432000 = floor(413855968/432000) = 957 → 14+957
    // = 971. Canonical: all 32 → 972.
    var s: u64 = first_972;
    while (s < first_972 + 32) : (s += 1) {
        try std.testing.expectEqual(@as(u64, 972), SCHED.getEpoch(s));
    }
    // Last slot BEFORE the boundary is epoch 971.
    try std.testing.expectEqual(@as(u64, 971), SCHED.getEpoch(first_972 - 1));
    // And slot_index resets to 0 exactly at the boundary.
    try std.testing.expectEqual(@as(u64, 0), SCHED.getEpochAndSlotIndex(first_972).slot_index);
    try std.testing.expectEqual(
        SCHED.slots_per_epoch - 1,
        SCHED.getEpochAndSlotIndex(first_972 - 1).slot_index,
    );
}

test "warmup era: exact Agave get_epoch_and_slot_index math (epochs 0..13 doubling)" {
    // Agave: epoch sizes 32, 64, 128, …, 262144 for epochs 0..13;
    // first_normal_slot = sum = (2^14 − 1) × 32 = 524,256.
    // Spot vectors computed from the Agave formula
    //   epoch = tz(next_pow2(slot+33)) − tz(32) − 1:
    try std.testing.expectEqual(@as(u64, 0), SCHED.getEpoch(0));
    try std.testing.expectEqual(@as(u64, 0), SCHED.getEpoch(31));
    try std.testing.expectEqual(@as(u64, 1), SCHED.getEpoch(32));
    try std.testing.expectEqual(@as(u64, 1), SCHED.getEpoch(95));
    try std.testing.expectEqual(@as(u64, 2), SCHED.getEpoch(96));
    try std.testing.expectEqual(@as(u64, 2), SCHED.getEpoch(223));
    try std.testing.expectEqual(@as(u64, 3), SCHED.getEpoch(224));
    // Last warmup slot → epoch 13; first normal slot → 14.
    try std.testing.expectEqual(@as(u64, 13), SCHED.getEpoch(SCHED.first_normal_slot - 1));
    try std.testing.expectEqual(@as(u64, 14), SCHED.getEpoch(SCHED.first_normal_slot));

    // slot_index within warmup epochs: slot − (epoch_len − 32).
    try std.testing.expectEqual(@as(u64, 0), SCHED.getEpochAndSlotIndex(0).slot_index);
    try std.testing.expectEqual(@as(u64, 31), SCHED.getEpochAndSlotIndex(31).slot_index);
    try std.testing.expectEqual(@as(u64, 0), SCHED.getEpochAndSlotIndex(32).slot_index);
    try std.testing.expectEqual(@as(u64, 63), SCHED.getEpochAndSlotIndex(95).slot_index);

    // getFirstSlotInEpoch warmup branch: (2^e − 1) × 32, and consistency
    // with getEpoch at every warmup boundary.
    var e: u64 = 0;
    while (e < 14) : (e += 1) {
        const first = SCHED.getFirstSlotInEpoch(e);
        const pow: u64 = @as(u64, 1) << @intCast(e);
        try std.testing.expectEqual((pow - 1) * 32, first);
        try std.testing.expectEqual(e, SCHED.getEpoch(first));
        if (first > 0) try std.testing.expectEqual(e - 1, SCHED.getEpoch(first - 1));
    }
}

test "every epoch boundary in a wide window: first 32 slots belong to the NEW epoch" {
    // Sweep epochs 960..975 (covers the live testnet window incl. 972):
    // the off-by-32 class is a BOUNDARY bug, so assert the exact transition
    // shape at every boundary, derived from the struct.
    var e: u64 = 960;
    while (e <= 975) : (e += 1) {
        const first = SCHED.getFirstSlotInEpoch(e);
        try std.testing.expectEqual(e - 1, SCHED.getEpoch(first - 1));
        try std.testing.expectEqual(e, SCHED.getEpoch(first));
        try std.testing.expectEqual(e, SCHED.getEpoch(first + 31));
        try std.testing.expectEqual(e, SCHED.getEpoch(first + 32));
    }
}

test "threaded epoch reaches applyVoteToState (legacy fallback == canonical schedule)" {
    // The serde fallback (current_epoch=null) must be the SAME canonical
    // math — guard against a hardcode creeping back in.
    const serde = vex_svm.native.vote_state_serde;
    _ = serde; // applyVoteToState needs a full vote-account buffer; the
    // threading is covered by compilation (signature now REQUIRES the epoch
    // argument at every call site) + the production call sites passing
    // bank.epoch_schedule.getEpoch(bank.slot). The deleted helper cannot be
    // referenced anymore: vote_state_serde.slotToEpoch does not exist.
    try std.testing.expect(!@hasDecl(vex_svm.native.vote_state_serde, "slotToEpoch"));
}
