//! Vexor Stake State Types and Bincode Serialization
//!
//! Ported from Firedancer:
//!   firedancer/src/flamenco/stakes/fd_stake_types.h
//!   firedancer/src/flamenco/stakes/fd_stake_types.c
//!
//! Stake account data layout (bincode, all little-endian):
//!   [u32 discriminant]  0=Uninitialized, 1=Initialized, 2=Stake, 3=RewardsPool
//!   [Meta]              120 bytes (rent_exempt_reserve + authorized + lockup)
//!   [Stake]             72 bytes (delegation + credits_observed) — only if type==2
//!   [u8 flags]          1 byte — only if type==2

const std = @import("std");

pub const STAKE_STATE_SZ: usize = 200;

// ---------------------------------------------------------------------------
// Byte offsets into stake account data (bincode layout, all little-endian)
// ---------------------------------------------------------------------------
// The stake account data is bincode-serialized StakeStateV2:
//   [u32 discriminant at 0]  0=Uninit, 1=Init, 2=Stake, 3=RewardsPool
//   [StakeMeta at 4]         120 bytes: rent_exempt_reserve + authorized + lockup
//   [StakeData at 124]       72 bytes: delegation + credits_observed  (disc==2 only)
//   [StakeFlags at 196]      1 byte                                   (disc==2 only)
//
// These offsets are ABSOLUTE from the start of account data.
// Use the helper functions below instead of ptrCast to avoid the alignment/padding
// bug in the StakeState extern struct (which has a stray 4-byte pad after stake_type).
// ---------------------------------------------------------------------------
pub const Offsets = struct {
    // Discriminant (u32, 4 bytes)
    pub const discriminant = 0;

    // Meta fields (absolute offsets from start of account data; meta starts at 4)
    pub const rent_exempt_reserve = 4; // u64, 8 bytes  (meta+0)
    pub const staker = 12; // [32]u8          (meta+8)
    pub const withdrawer = 44; // [32]u8       (meta+40)
    pub const lockup_unix_timestamp = 76; // i64, 8 bytes (meta+72)
    pub const lockup_epoch = 84; // u64, 8 bytes          (meta+80)
    pub const lockup_custodian = 92; // [32]u8             (meta+88)

    // Stake/Delegation fields — only valid when discriminant == 2
    // Stake data begins at 124 (= 4 disc + 120 meta)
    pub const voter_pubkey = 124; // [32]u8               (stake+0)
    pub const delegation_stake = 156; // u64              (stake+32)
    pub const activation_epoch = 164; // u64              (stake+40)
    pub const deactivation_epoch = 172; // u64            (stake+48)
    pub const warmup_cooldown_rate = 180; // u64 (f64 as bits, stake+56)
    pub const credits_observed = 188; // u64              (stake+64)
    pub const stake_flags = 196; // u8                    (stake+72)
};

// ---------------------------------------------------------------------------
// Byte-level reader/writer helpers — use these, not ptrCast
// ---------------------------------------------------------------------------

/// Read a u64 at the given byte offset (little-endian). Returns null if out of bounds.
pub fn readU64(data: []const u8, offset: usize) ?u64 {
    if (data.len < offset + 8) return null;
    return std.mem.readInt(u64, data[offset..][0..8], .little);
}

/// Write a u64 at the given byte offset (little-endian).
pub fn writeU64(data: []u8, offset: usize, value: u64) void {
    std.mem.writeInt(u64, data[offset..][0..8], value, .little);
}

/// Read an i64 at the given byte offset (little-endian). Returns null if out of bounds.
pub fn readI64(data: []const u8, offset: usize) ?i64 {
    if (data.len < offset + 8) return null;
    return std.mem.readInt(i64, data[offset..][0..8], .little);
}

/// Write an i64 at the given byte offset (little-endian).
pub fn writeI64(data: []u8, offset: usize, value: i64) void {
    std.mem.writeInt(i64, data[offset..][0..8], value, .little);
}

/// Read a u32 at the given byte offset (little-endian). Returns null if out of bounds.
pub fn readU32(data: []const u8, offset: usize) ?u32 {
    if (data.len < offset + 4) return null;
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

/// Write a u32 at the given byte offset (little-endian).
pub fn writeU32(data: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, data[offset..][0..4], value, .little);
}

/// Read a 32-byte pubkey at the given offset. Returns null if out of bounds.
pub fn readPubkey(data: []const u8, offset: usize) ?[32]u8 {
    if (data.len < offset + 32) return null;
    return data[offset..][0..32].*;
}

/// Write a 32-byte pubkey at the given offset.
pub fn writePubkey(data: []u8, offset: usize, pubkey: [32]u8) void {
    @memcpy(data[offset..][0..32], &pubkey);
}

/// Convenience: read the stake account discriminant (4-byte little-endian u32).
pub fn readStakeStateDiscriminant(data: []const u8) ?u32 {
    return readU32(data, Offsets.discriminant);
}

/// Partitioned-rewards distribution store: apply the per-account byte mutations
/// Agave makes when storing a rewarded stake account at its distribution slot
/// (runtime/src/bank/partitioned_epoch_rewards/distribution.rs:212-225 stores the
/// calc-time compounded `StakeStateV2::Stake(meta, stake, flags)`; the stake was
/// compounded at calc via `stake.delegation.stake += staker_rewards`,
/// programs/stake `inflation_rewards/mod.rs:114`; FD fd_rewards.c:778 sat-adds
/// the reward into stake.delegation.stake).
///
/// Mutates EXACTLY two fields, everything else verbatim:
///   - delegation.stake   @ Offsets.delegation_stake (156..164) = new_delegation_stake
///   - credits_observed   @ Offsets.credits_observed (188..196) = new_credits_observed
/// stake_flags @ 196 and all other bytes are untouched.
///
/// Returns false (no mutation) unless data is a Stake-typed account of at least
/// STAKE_STATE_SZ bytes. Callers verify Agave's distribution.rs:218 invariant
/// (current stake + reward == new_delegation_stake) BEFORE calling.
pub fn applyRewardStoreBytes(data: []u8, new_delegation_stake: u64, new_credits_observed: u64) bool {
    if (data.len < STAKE_STATE_SZ) return false;
    const disc = readStakeStateDiscriminant(data) orelse return false;
    if (disc != @intFromEnum(StakeStateType.stake)) return false;
    writeU64(data, Offsets.delegation_stake, new_delegation_stake);
    writeU64(data, Offsets.credits_observed, new_credits_observed);
    return true;
}

pub const StakeStateType = enum(u32) {
    uninitialized = 0,
    initialized = 1,
    stake = 2,
    rewards_pool = 3,
    _,
};

/// Stake metadata — always present in Initialized and Stake states.
/// Firedancer: fd_stake_meta_t (120 bytes packed)
pub const StakeMeta = extern struct {
    rent_exempt_reserve: u64,
    // Authorized
    staker: [32]u8,
    withdrawer: [32]u8,
    // Lockup
    unix_timestamp: i64,
    epoch: u64,
    custodian: [32]u8,
};

/// Delegation info — present only in Stake state.
/// Firedancer: fd_delegation_t
pub const Delegation = extern struct {
    voter_pubkey: [32]u8,
    stake: u64,
    activation_epoch: u64,
    deactivation_epoch: u64,
    warmup_cooldown_rate_bits: u64, // f64 as bits
};

/// Stake data (Delegation + credits) — present only in Stake state.
/// Firedancer: fd_stake_t
pub const Stake = extern struct {
    delegation: Delegation,
    credits_observed: u64,
};

/// Full stake state — reinterpret_cast of account data.
/// Firedancer: fd_stake_state_t
///
/// ⚠ FOOTGUN: the `_pad: [4]u8` below 8-aligns `meta` (align=8), but the
/// on-the-wire bincode layout has NO such padding — every field after the u32
/// discriminant is +4 bytes off when read through this struct. DO NOT @ptrCast
/// account data through StakeState to read delegation fields; use the `Offsets`
/// byte-readers above. carrier #16 secondary (2026-06-12): the epoch 972→973
/// boundary loop ptrCast'd here and read deactivation_epoch=0 /
/// activation_epoch=garbage for all 558,759 type-2 stakes → zero delegations →
/// the whole rewards + EpochRewards-sysvar path silently returned → boundary
/// bank_hash divergence.
pub const StakeState = extern struct {
    stake_type: u32,
    // Padding to align the union — match Firedancer's packed layout
    _pad: [4]u8 = [_]u8{0} ** 4,
    meta: StakeMeta,
    stake: Stake,
    stake_flags: u8,
};

/// Attempt to view serialized stake state data as a StakeState.
/// Returns null if data is too small or discriminant is invalid.
/// Equivalent to Firedancer's fd_stake_state_view().
pub fn viewStakeState(data: []const u8) ?*const StakeState {
    if (data.len < 4) return null;
    const disc = std.mem.readInt(u32, data[0..4], .little);
    return switch (disc) {
        0 => null, // Uninitialized — no useful data
        1 => { // Initialized — need Meta (120 bytes)
            if (data.len < 4 + @sizeOf(StakeMeta)) return null;
            return @ptrCast(@alignCast(data.ptr));
        },
        2 => { // Stake — need Meta + Stake + flags
            if (data.len < STAKE_STATE_SZ) return null;
            return @ptrCast(@alignCast(data.ptr));
        },
        3 => null, // RewardsPool — not used in normal operations
        else => null,
    };
}

/// Read the discriminant from stake account data.
pub fn getStakeType(data: []const u8) ?StakeStateType {
    if (data.len < 4) return null;
    const disc = std.mem.readInt(u32, data[0..4], .little);
    return std.meta.intToEnum(StakeStateType, disc) catch null;
}

/// Stake instruction discriminants (from Firedancer fd_stake_program.c)
pub const StakeInstructionType = enum(u32) {
    initialize = 0,
    authorize = 1,
    delegate_stake = 2,
    split = 3,
    withdraw = 4,
    deactivate = 5,
    set_lockup = 6,
    merge = 7,
    authorize_with_seed = 8,
    initialize_checked = 9,
    authorize_checked = 10,
    authorize_checked_with_seed = 11,
    set_lockup_checked = 12,
    get_minimum_delegation = 13,
    deactivate_delinquent = 14,
    redelegate = 15,
    move_stake = 16,
    move_lamports = 17,
    _,
};

// ---------------------------------------------------------------------------
// KATs — structural offset guard + reward-store byte mutation golden
// (RCA VEXOR-E1-BOUNDARY-DIVERGENCE-RCA-2026-07-02.md §4.5: bind the store
// path to Offsets against golden Agave-bincode layout so no @sizeOf/ptrCast
// arithmetic can ever drift them again — the exact trap Defect B fell into.)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "Offsets match Agave bincode StakeStateV2 layout (structural guard)" {
    // Agave bincode StakeStateV2::Stake layout: 4-byte u32 enum discriminant
    // (bincode, NOT 8), then Meta{rent_exempt_reserve u64, Authorized{staker,
    // withdrawer 32+32}, Lockup{i64,u64,32}} = 120, then Stake{Delegation{
    // voter 32, stake u64, activation u64, deactivation u64, warmup f64} = 64,
    // credits_observed u64} = 72, then StakeFlags u8 @196. Total 200.
    try testing.expectEqual(@as(usize, 4 + 120 + 32), Offsets.delegation_stake); // 156
    try testing.expectEqual(@as(usize, 4 + 120 + 64), Offsets.credits_observed); // 188
    try testing.expectEqual(@as(usize, 4 + 120 + 64 + 8), Offsets.stake_flags); // 196
    try testing.expectEqual(@as(usize, 200), STAKE_STATE_SZ);
    // The Defect-B trap, pinned forever: 8 + @sizeOf(StakeMeta) + @sizeOf(Delegation)
    // is 192 — NOT credits_observed. Any "recomputed" offset must fail here.
    try testing.expect(8 + @sizeOf(StakeMeta) + @sizeOf(Delegation) != Offsets.credits_observed);
}

test "applyRewardStoreBytes mutates exactly stake@156 + credits_observed@188, all else verbatim" {
    // Golden 200-byte Stake-typed account: every byte = (i*7+3)&0xFF so any
    // unintended write is caught positionally; then discriminant forced to 2.
    var data: [STAKE_STATE_SZ]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
    writeU32(&data, Offsets.discriminant, 2);
    var expected = data;

    const new_stake: u64 = 0x1122334455667788;
    const new_co: u64 = 0x99AABBCCDDEEFF00;
    try testing.expect(applyRewardStoreBytes(&data, new_stake, new_co));

    // Expected = golden with ONLY the two 8-byte LE fields swapped in.
    writeU64(&expected, Offsets.delegation_stake, new_stake);
    writeU64(&expected, Offsets.credits_observed, new_co);
    try testing.expectEqualSlices(u8, &expected, &data);

    // stake_flags byte @196 verbatim (Defect B clobbered it via a u64 at 192).
    try testing.expectEqual(@as(u8, @truncate(196 * 7 + 3)), data[Offsets.stake_flags]);
    // Bytes 189..196 hold ONLY the CO write (i.e. 192..196 are CO's high half,
    // not a misplaced low half): read CO back as one LE u64 at 188.
    try testing.expectEqual(new_co, readU64(&data, Offsets.credits_observed).?);
    try testing.expectEqual(new_stake, readU64(&data, Offsets.delegation_stake).?);
}

test "applyRewardStoreBytes refuses non-Stake and short accounts" {
    var short: [100]u8 = [_]u8{0} ** 100;
    try testing.expect(!applyRewardStoreBytes(&short, 1, 2));

    var init_acct: [STAKE_STATE_SZ]u8 = [_]u8{0} ** STAKE_STATE_SZ;
    writeU32(&init_acct, Offsets.discriminant, 1); // Initialized, no Stake section
    const before = init_acct;
    try testing.expect(!applyRewardStoreBytes(&init_acct, 1, 2));
    try testing.expectEqualSlices(u8, &before, &init_acct); // untouched
}

test "applyRewardStoreBytes zero-reward entry: stake unchanged value, CO updated (E2 semantics)" {
    // Agave distribution.rs:245-247 — zero-reward stakes are still stored
    // because credits_observed changed; delegation.stake value is unchanged
    // (reward=0 ⇒ new_delegation_stake == current).
    var data: [STAKE_STATE_SZ]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 3 + 11);
    writeU32(&data, Offsets.discriminant, 2);
    const cur_stake = readU64(&data, Offsets.delegation_stake).?;

    try testing.expect(applyRewardStoreBytes(&data, cur_stake, 424242));
    try testing.expectEqual(cur_stake, readU64(&data, Offsets.delegation_stake).?);
    try testing.expectEqual(@as(u64, 424242), readU64(&data, Offsets.credits_observed).?);
}

test "applyRewardStoreBytes on REAL testnet StakeStateV2 bytes (RCA Gate-3 real-bytes golden)" {
    // Real 200-byte stake account fetched 2026-07-02 via read-only public RPC
    // (api.testnet.solana.com getProgramAccounts, dataSize=200, voter-filtered):
    // pubkey 3ULPpfjz417Nj8q9h3kGy7EEHhZL1KH482XNWX6E42WZ, delegated to vote
    // account BnwAiWfj1Rf2t1vV1VUY9B4FYWvALpMxaX1mECi35s6m. Layout triple-
    // attested from the LIVE bytes themselves: disc@0 == 2; voter@124 base58
    // == the vote account the RPC filter matched on; and account lamports
    // (3871229720) == stake@156 (3868946840) + rent_exempt_reserve@4
    // (2282880) exactly — the offsets are provably the cluster's, not ours.
    var data = [_]u8{
        0x02, 0x00, 0x00, 0x00, 0x80, 0xd5, 0x22, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xe1, 0x6d, 0x27, 0x9f, 0xe0, 0x04, 0x67, 0x70,
        0xe3, 0x70, 0xd0, 0x30, 0xc6, 0xe7, 0x11, 0x3d, 0xeb, 0x28,
        0xf3, 0xd9, 0x37, 0x01, 0xf3, 0x2a, 0xe6, 0xcf, 0x2d, 0x80,
        0x1e, 0x35, 0x19, 0x46, 0xe1, 0x6d, 0x27, 0x9f, 0xe0, 0x04,
        0x67, 0x70, 0xe3, 0x70, 0xd0, 0x30, 0xc6, 0xe7, 0x11, 0x3d,
        0xeb, 0x28, 0xf3, 0xd9, 0x37, 0x01, 0xf3, 0x2a, 0xe6, 0xcf,
        0x2d, 0x80, 0x1e, 0x35, 0x19, 0x46, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xe1, 0x6d, 0x27, 0x9f, 0xe0, 0x04, 0x67, 0x70,
        0xe3, 0x70, 0xd0, 0x30, 0xc6, 0xe7, 0x11, 0x3d, 0xeb, 0x28,
        0xf3, 0xd9, 0x37, 0x01, 0xf3, 0x2a, 0xe6, 0xcf, 0x2d, 0x80,
        0x1e, 0x35, 0x19, 0x46, 0xa0, 0x59, 0x40, 0xc9, 0x6a, 0x7a,
        0x87, 0xac, 0x00, 0x2c, 0x6d, 0xea, 0x9b, 0xb1, 0x51, 0xb4,
        0xb4, 0x81, 0x58, 0x1f, 0xcf, 0x6d, 0x88, 0x8e, 0xd4, 0x96,
        0xe8, 0x14, 0x47, 0x8d, 0xf4, 0xf6, 0x98, 0x71, 0x9b, 0xe6,
        0x00, 0x00, 0x00, 0x00, 0xa2, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xbd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x3f, 0xc6, 0x0b,
        0x83, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try testing.expectEqual(@as(u32, 2), readStakeStateDiscriminant(&data).?);
    const real_stake: u64 = 3_868_946_840;
    const real_co: u64 = 126_028_742;
    try testing.expectEqual(real_stake, readU64(&data, Offsets.delegation_stake).?);
    try testing.expectEqual(real_co, readU64(&data, Offsets.credits_observed).?);
    try testing.expectEqual(@as(u64, 2_282_880), readU64(&data, Offsets.rent_exempt_reserve).?);
    try testing.expectEqual(@as(u8, 0), data[Offsets.stake_flags]);

    // Simulate a distribution store on the REAL bytes: reward 12345 lamports,
    // CO advanced. Expect EXACTLY fields 156..164 and 188..196 to change.
    var expected = data;
    const reward: u64 = 12_345;
    const new_co: u64 = real_co + 999;
    writeU64(&expected, Offsets.delegation_stake, real_stake + reward);
    writeU64(&expected, Offsets.credits_observed, new_co);

    try testing.expect(applyRewardStoreBytes(&data, real_stake + reward, new_co));
    try testing.expectEqualSlices(u8, &expected, &data);
    // The Defect-B clobber cannot recur: real stake_flags byte verbatim.
    try testing.expectEqual(@as(u8, 0), data[Offsets.stake_flags]);
}
