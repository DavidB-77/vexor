//! Stage-A unit tests for sysvar_cache.zig.
//!
//! Locks the vex-058 invariant: every getter on a fresh cache returns
//! `error.SysvarNotPopulated`; every getter on a populated cache returns
//! the populated value byte-for-byte.

const std = @import("std");
const sc = @import("sysvar_cache.zig");

/// Mock bank that hands out canonical bytes for all 8 sysvars.
const MockBank = struct {
    clock: [sc.CLOCK_SIZE]u8,
    rent: [sc.RENT_SIZE]u8,
    epoch_schedule: [sc.EPOCH_SCHEDULE_SIZE]u8,
    slot_hashes: []const u8,
    slot_history: []const u8,
    stake_history: []const u8,
    epoch_rewards: [sc.EPOCH_REWARDS_SIZE]u8,
    last_restart_slot: [sc.LAST_RESTART_SLOT_SIZE]u8,

    pub fn getClockBytes(self: *const MockBank) ?[]const u8 {
        return self.clock[0..];
    }
    pub fn getRentBytes(self: *const MockBank) ?[]const u8 {
        return self.rent[0..];
    }
    pub fn getEpochScheduleBytes(self: *const MockBank) ?[]const u8 {
        return self.epoch_schedule[0..];
    }
    pub fn getSlotHashesBytes(self: *const MockBank) ?[]const u8 {
        return self.slot_hashes;
    }
    pub fn getSlotHistoryBytes(self: *const MockBank) ?[]const u8 {
        return self.slot_history;
    }
    pub fn getStakeHistoryBytes(self: *const MockBank) ?[]const u8 {
        return self.stake_history;
    }
    pub fn getEpochRewardsBytes(self: *const MockBank) ?[]const u8 {
        return self.epoch_rewards[0..];
    }
    pub fn getLastRestartSlotBytes(self: *const MockBank) ?[]const u8 {
        return self.last_restart_slot[0..];
    }
};

fn buildBank(alloc: std.mem.Allocator) !MockBank {
    var b: MockBank = undefined;

    // Clock: slot=42, epoch=7, leader=8, ts1=1700000000, ts2=1700001000
    std.mem.writeInt(u64, b.clock[0..8], 42, .little);
    std.mem.writeInt(i64, b.clock[8..16], 1700000000, .little);
    std.mem.writeInt(u64, b.clock[16..24], 7, .little);
    std.mem.writeInt(u64, b.clock[24..32], 8, .little);
    std.mem.writeInt(i64, b.clock[32..40], 1700001000, .little);

    // Rent: lpb=3480, et=2.0, burn=50
    std.mem.writeInt(u64, b.rent[0..8], 3480, .little);
    const et: f64 = 2.0;
    std.mem.writeInt(u64, b.rent[8..16], @bitCast(et), .little);
    b.rent[16] = 50;

    // EpochSchedule: slots=432000, leader_off=432000, first_normal_epoch=14,
    // first_normal_slot=524256, warmup=true. Canonical declaration-order bincode
    // layout (547b2e1): warmup@[16], first_normal_epoch@[17..25],
    // first_normal_slot@[25..33].
    std.mem.writeInt(u64, b.epoch_schedule[0..8], 432000, .little);
    std.mem.writeInt(u64, b.epoch_schedule[8..16], 432000, .little);
    b.epoch_schedule[16] = 1; // warmup
    std.mem.writeInt(u64, b.epoch_schedule[17..25], 14, .little);
    std.mem.writeInt(u64, b.epoch_schedule[25..33], 524256, .little);

    // SlotHashes: 2 entries.
    const sh = try alloc.alloc(u8, 8 + 2 * 40);
    std.mem.writeInt(u64, sh[0..8], 2, .little);
    std.mem.writeInt(u64, sh[8..16], 100, .little);
    @memset(sh[16..48], 0xAA);
    std.mem.writeInt(u64, sh[48..56], 99, .little);
    @memset(sh[56..88], 0xBB);
    b.slot_hashes = sh;

    // SlotHistory: 2048 blocks of zeros + next_slot=42.
    const sh2 = try alloc.alloc(u8, 8 + 2048 * 8 + 8);
    std.mem.writeInt(u64, sh2[0..8], 2048, .little);
    @memset(sh2[8 .. 8 + 2048 * 8], 0);
    std.mem.writeInt(u64, sh2[8 + 2048 * 8 ..][0..8], 42, .little);
    b.slot_history = sh2;

    // StakeHistory: 1 entry.
    const sk = try alloc.alloc(u8, 8 + 1 * 32);
    std.mem.writeInt(u64, sk[0..8], 1, .little);
    std.mem.writeInt(u64, sk[8..16], 7, .little);
    std.mem.writeInt(u64, sk[16..24], 1_000_000, .little);
    std.mem.writeInt(u64, sk[24..32], 100, .little);
    std.mem.writeInt(u64, sk[32..40], 50, .little);
    b.stake_history = sk;

    // EpochRewards: zeros + active=false.
    @memset(&b.epoch_rewards, 0);
    b.epoch_rewards[80] = 0;

    // LastRestartSlot.
    std.mem.writeInt(u64, b.last_restart_slot[0..8], 0, .little);
    return b;
}

fn freeBank(alloc: std.mem.Allocator, b: MockBank) void {
    alloc.free(b.slot_hashes);
    alloc.free(b.slot_history);
    alloc.free(b.stake_history);
}

test "vex-058 invariant: empty cache returns SysvarNotPopulated for every getter" {
    var cache = sc.SysvarCache.init(std.testing.allocator);
    defer cache.deinit();

    try std.testing.expectError(error.SysvarNotPopulated, cache.getClock());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getClockBytes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getRent());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getRentBytes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getEpochSchedule());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getEpochScheduleBytes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getSlotHashes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getSlotHashesBytes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getSlotHistory());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getSlotHistoryBytes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getStakeHistory());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getStakeHistoryBytes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getEpochRewards());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getEpochRewardsBytes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getLastRestartSlot());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getLastRestartSlotBytes());
    try std.testing.expectError(error.SysvarNotPopulated, cache.getBytesByPubkey(sc.SYSVAR_CLOCK_ID));
}

test "populated cache returns canonical bytes + decoded views (Clock)" {
    const alloc = std.testing.allocator;
    var bank = try buildBank(alloc);
    defer freeBank(alloc, bank);

    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    try cache.populateFromBank(&bank);

    const clk = try cache.getClock();
    try std.testing.expectEqual(@as(u64, 42), clk.slot);
    try std.testing.expectEqual(@as(u64, 7), clk.epoch);
    try std.testing.expectEqual(@as(i64, 1700001000), clk.unix_timestamp);

    const clk_bytes = try cache.getClockBytes();
    try std.testing.expectEqual(@as(usize, sc.CLOCK_SIZE), clk_bytes.len);
}

test "populated EpochSchedule respects warmup=true (vex-058 fix shape)" {
    const alloc = std.testing.allocator;
    var bank = try buildBank(alloc);
    defer freeBank(alloc, bank);

    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    try cache.populateFromBank(&bank);

    const es = try cache.getEpochSchedule();
    try std.testing.expectEqual(true, es.warmup);
    try std.testing.expectEqual(@as(u64, 14), es.first_normal_epoch);
    try std.testing.expectEqual(@as(u64, 524256), es.first_normal_slot);

    // toBytes round-trip.
    const round = es.toBytes();
    const back = try sc.EpochSchedule.fromBytes(&round);
    try std.testing.expectEqual(es.warmup, back.warmup);
    try std.testing.expectEqual(es.first_normal_epoch, back.first_normal_epoch);
}

test "EpochSchedule.toBytes/fromBytes canonical declaration-order byte layout (547b2e1)" {
    const es = sc.EpochSchedule{
        .slots_per_epoch = 432000,
        .leader_schedule_slot_offset = 432000,
        .warmup = true,
        .first_normal_epoch = 14,
        .first_normal_slot = 524256,
    };
    const bytes = es.toBytes();
    // warmup is byte [16], NOT the final byte [32]; first_normal_* follow it.
    try std.testing.expectEqual(@as(u64, 432000), std.mem.readInt(u64, bytes[0..8], .little));
    try std.testing.expectEqual(@as(u64, 432000), std.mem.readInt(u64, bytes[8..16], .little));
    try std.testing.expectEqual(@as(u8, 1), bytes[16]);
    try std.testing.expectEqual(@as(u64, 14), std.mem.readInt(u64, bytes[17..25], .little));
    try std.testing.expectEqual(@as(u64, 524256), std.mem.readInt(u64, bytes[25..33], .little));

    const back = try sc.EpochSchedule.fromBytes(&bytes);
    try std.testing.expectEqual(es.slots_per_epoch, back.slots_per_epoch);
    try std.testing.expectEqual(es.leader_schedule_slot_offset, back.leader_schedule_slot_offset);
    try std.testing.expectEqual(es.warmup, back.warmup);
    try std.testing.expectEqual(es.first_normal_epoch, back.first_normal_epoch);
    try std.testing.expectEqual(es.first_normal_slot, back.first_normal_slot);
}

test "populated SlotHashes decodes both entries" {
    const alloc = std.testing.allocator;
    var bank = try buildBank(alloc);
    defer freeBank(alloc, bank);

    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    try cache.populateFromBank(&bank);

    const sh = try cache.getSlotHashes();
    try std.testing.expectEqual(@as(usize, 2), sh.entries.len);
    try std.testing.expectEqual(@as(u64, 100), sh.entries[0].slot);
    try std.testing.expectEqual(@as(u8, 0xAA), sh.entries[0].hash[0]);
    try std.testing.expectEqual(@as(u64, 99), sh.entries[1].slot);
    try std.testing.expectEqual(@as(u8, 0xBB), sh.entries[1].hash[0]);
}

test "populated SlotHistory decodes blocks + next_slot" {
    const alloc = std.testing.allocator;
    var bank = try buildBank(alloc);
    defer freeBank(alloc, bank);

    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    try cache.populateFromBank(&bank);

    const hist = try cache.getSlotHistory();
    try std.testing.expectEqual(@as(usize, 2048), hist.bits.len);
    try std.testing.expectEqual(@as(u64, 42), hist.next_slot);
}

test "populated StakeHistory decodes one entry" {
    const alloc = std.testing.allocator;
    var bank = try buildBank(alloc);
    defer freeBank(alloc, bank);

    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    try cache.populateFromBank(&bank);

    const sh = try cache.getStakeHistory();
    try std.testing.expectEqual(@as(usize, 1), sh.entries.len);
    try std.testing.expectEqual(@as(u64, 7), sh.entries[0].epoch);
    try std.testing.expectEqual(@as(u64, 1_000_000), sh.entries[0].effective);
}

test "populated Rent + LastRestartSlot + EpochRewards decode" {
    const alloc = std.testing.allocator;
    var bank = try buildBank(alloc);
    defer freeBank(alloc, bank);

    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    try cache.populateFromBank(&bank);

    const r = try cache.getRent();
    try std.testing.expectEqual(@as(u64, 3480), r.lamports_per_byte_year);
    try std.testing.expectEqual(@as(u8, 50), r.burn_percent);

    const lrs = try cache.getLastRestartSlot();
    try std.testing.expectEqual(@as(u64, 0), lrs.last_restart_slot);

    const er = try cache.getEpochRewards();
    try std.testing.expectEqual(false, er.active);
}

test "SIMD-0127 generic getBytesByPubkey covers all 7 sysvars (SlotHistory excluded, matches Agave's sysvar_id_to_buffer)" {
    const alloc = std.testing.allocator;
    var bank = try buildBank(alloc);
    defer freeBank(alloc, bank);

    var cache = sc.SysvarCache.init(alloc);
    defer cache.deinit();
    try cache.populateFromBank(&bank);

    const pks = [_]sc.Pubkey32{
        sc.SYSVAR_CLOCK_ID,
        sc.SYSVAR_RENT_ID,
        sc.SYSVAR_EPOCH_SCHEDULE_ID,
        sc.SYSVAR_SLOT_HASHES_ID,
        sc.SYSVAR_STAKE_HISTORY_ID,
        sc.SYSVAR_EPOCH_REWARDS_ID,
        sc.SYSVAR_LAST_RESTART_SLOT_ID,
    };
    for (pks) |pk| {
        const bytes = try cache.getBytesByPubkey(pk);
        try std.testing.expect(bytes.len > 0);
    }

    // conformance RC7 (2026-07-18): SlotHistory is NOT resolved through the
    // generic by-pubkey path — Agave's sysvar_id_to_buffer has no SlotHistory
    // arm (program-runtime/src/sysvar_cache.rs:109-127), so sol_get_sysvar on
    // this pubkey always falls through to SYSVAR_NOT_FOUND, even though the
    // typed getSlotHistoryBytes() getter still resolves it fine.
    try std.testing.expectError(error.SysvarNotPopulated, cache.getBytesByPubkey(sc.SYSVAR_SLOT_HISTORY_ID));
    _ = try cache.getSlotHistoryBytes();
}
