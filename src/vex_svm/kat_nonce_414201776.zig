//! KAT — durable-nonce AdvanceNonceAccount, PROVEN carrier @414201776.
//!
//! Ground truth (cluster canonical, slot 414201776, nonce acct
//! Fiz4USe1brrSCavyKWut…): post-advance state
//!   version=1 (current) state=1 (initialized)
//!   authority      = b5157277f272cd5be8026fe92aa6a8ef1054782e459a4292799e1dc65fb1de18
//!   durable_nonce  = f68e14e1e9ee3a354ff11d50692de5ede981d0cf3d3446d18a4c042f763f0638
//!   lamports_per_signature = 5000
//! where durable_nonce == sha256("DURABLE_NONCE" ‖ 37fc9863…6a2f) and
//! 37fc9863… is the PARENT bank (414201775) last_blockhash (final PoH hash,
//! newest blockhash-queue entry) — NOT the executing bank's in-progress poh.
//!
//! Locks: (1) durableNonceFromHash derivation, (2) the 80-byte
//! NonceStateVersions wire layout [ver u32=1][state u32=1][authority 32]
//! [durable_nonce 32][lps u64] LE, (3) the system_v2 dispatch wiring
//! (disc=4 → execAdvanceNonce with NonceEnv + sysvar-account + signer +
//! writable checks), (4) the NonceNoAdvance (same-blockhash) negative.
//!
//! Run: zig build test-nonce-414201776
//! (regression guard for the @414201776 bank_hash carrier — the pre-fix
//! Unimplemented stubs silently committed STALE nonce bytes.)

const std = @import("std");
const nonce = @import("native/nonce.zig");
const system_v2 = @import("native/system_v2.zig");
const types = @import("types.zig");

// ── Proven vectors ───────────────────────────────────────────────────────────

/// Parent bank 414201775 last_blockhash (= executing bank's last_blockhash).
const PARENT_LAST_BLOCKHASH: [32]u8 = .{
    0x37, 0xfc, 0x98, 0x63, 0x9c, 0x18, 0x15, 0x52,
    0x0b, 0xfc, 0x72, 0xee, 0x23, 0x0d, 0x08, 0x6c,
    0xe1, 0x8d, 0x12, 0x12, 0x6e, 0x2c, 0xfd, 0x1f,
    0xf3, 0x4c, 0x94, 0x1b, 0x9a, 0xff, 0x6a, 0x2f,
};

/// Cluster-canonical post-advance durable_nonce.
const EXPECTED_DURABLE_NONCE: [32]u8 = .{
    0xf6, 0x8e, 0x14, 0xe1, 0xe9, 0xee, 0x3a, 0x35,
    0x4f, 0xf1, 0x1d, 0x50, 0x69, 0x2d, 0xe5, 0xed,
    0xe9, 0x81, 0xd0, 0xcf, 0x3d, 0x34, 0x46, 0xd1,
    0x8a, 0x4c, 0x04, 0x2f, 0x76, 0x3f, 0x06, 0x38,
};

/// Nonce authority (cluster-canonical, unchanged by advance).
const AUTHORITY: [32]u8 = .{
    0xb5, 0x15, 0x72, 0x77, 0xf2, 0x72, 0xcd, 0x5b,
    0xe8, 0x02, 0x6f, 0xe9, 0x2a, 0xa6, 0xa8, 0xef,
    0x10, 0x54, 0x78, 0x2e, 0x45, 0x9a, 0x42, 0x92,
    0x79, 0x9e, 0x1d, 0xc6, 0x5f, 0xb1, 0xde, 0x18,
};

const LPS: u64 = 5000;

/// SysvarRecentB1ockHashes11111111111111111111
const RBH_ID: [32]u8 = .{
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
    0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
    0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
    0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
};

/// Build the proven 80-byte cluster-canonical POST state.
fn expectedPostBytes() [80]u8 {
    var out: [80]u8 = .{0} ** 80;
    std.mem.writeInt(u32, out[0..4], 1, .little); // version = current
    std.mem.writeInt(u32, out[4..8], 1, .little); // state = initialized
    @memcpy(out[8..40], &AUTHORITY);
    @memcpy(out[40..72], &EXPECTED_DURABLE_NONCE);
    std.mem.writeInt(u64, out[72..80], LPS, .little);
    return out;
}

/// Build a plausible PRE state: same authority/lps, durable_nonce derived
/// from a DIFFERENT (older) blockhash so the advance is legal.
fn preBytes() [80]u8 {
    const older_blockhash: [32]u8 = .{0x42} ** 32;
    const old_dn = nonce.durableNonceFromHash(&older_blockhash);
    var out: [80]u8 = .{0} ** 80;
    std.mem.writeInt(u32, out[0..4], 1, .little);
    std.mem.writeInt(u32, out[4..8], 1, .little);
    @memcpy(out[8..40], &AUTHORITY);
    @memcpy(out[40..72], &old_dn);
    std.mem.writeInt(u64, out[72..80], LPS, .little);
    return out;
}

const ENV = system_v2.NonceEnv{
    .recent_blockhash = PARENT_LAST_BLOCKHASH,
    .lamports_per_signature = LPS,
    .recent_blockhashes_empty = false,
    .rent_minimum_balance_fn = null,
};

/// Accounts for AdvanceNonceAccount: [0]=nonce(writable), [1]=RBH sysvar,
/// [2]=authority(signer). ix data = [u32 disc=4].
fn buildAccounts(nonce_data: []u8) [3]types.AccountMeta {
    return .{
        .{
            .pubkey = .{ .data = .{0xF1} ** 32 }, // Fiz4USe1… stand-in (pubkey not hashed here)
            .lamports = 1_447_680, // rent-exempt min for 80B
            .owner = .{ .data = system_v2.PROGRAM_ID },
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
            .data = nonce_data,
        },
        .{
            .pubkey = .{ .data = RBH_ID },
            .lamports = 42_706_560,
            .owner = .{ .data = .{0} ** 32 },
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
            .data = &[_]u8{},
        },
        .{
            .pubkey = .{ .data = AUTHORITY },
            .lamports = 1_000_000_000,
            .owner = .{ .data = system_v2.PROGRAM_ID },
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
            .data = &[_]u8{},
        },
    };
}

const ADVANCE_IX: [4]u8 = .{ 4, 0, 0, 0 };

test "KAT @414201776: durableNonceFromHash(parent last_blockhash) == cluster durable_nonce" {
    const dn = nonce.durableNonceFromHash(&PARENT_LAST_BLOCKHASH);
    try std.testing.expectEqualSlices(u8, &EXPECTED_DURABLE_NONCE, &dn);
}

test "KAT @414201776: AdvanceNonceAccount via system_v2.execute → exact cluster post bytes" {
    var data = preBytes();
    var accounts = buildAccounts(&data);
    var ctx = system_v2.InstrCtx{
        .accounts = &accounts,
        .signer_mask = 0b100, // authority (idx 2) signed
        .allocator = std.testing.allocator,
        .writable_mask = 0b001, // nonce acct writable
        .nonce_env = ENV,
    };
    try system_v2.execute(&ctx, &ADVANCE_IX);

    const expected = expectedPostBytes();
    try std.testing.expectEqualSlices(u8, &expected, &data); // FULL 80 bytes
    // Lamports untouched by advance.
    try std.testing.expectEqual(@as(u64, 1_447_680), accounts[0].lamports);
}

test "KAT @414201776 negative: same blockhash → NonceNoAdvance (BlockhashNotExpired)" {
    // Start from the POST state (durable_nonce already == derived from the
    // env blockhash) — a second advance in the same bank must fail.
    var data = expectedPostBytes();
    var accounts = buildAccounts(&data);
    var ctx = system_v2.InstrCtx{
        .accounts = &accounts,
        .signer_mask = 0b100,
        .allocator = std.testing.allocator,
        .writable_mask = 0b001,
        .nonce_env = ENV,
    };
    const snapshot = data;
    try std.testing.expectError(
        system_v2.InstrError.CustomError, // SystemError::NonceBlockhashNotExpired
        system_v2.execute(&ctx, &ADVANCE_IX),
    );
    // No bytes may change on the failure path.
    try std.testing.expectEqualSlices(u8, &snapshot, &data);
}

test "KAT @414201776 negative: authority did not sign → MissingRequiredSignature" {
    var data = preBytes();
    var accounts = buildAccounts(&data);
    var ctx = system_v2.InstrCtx{
        .accounts = &accounts,
        .signer_mask = 0, // nobody signed
        .allocator = std.testing.allocator,
        .writable_mask = 0b001,
        .nonce_env = ENV,
    };
    try std.testing.expectError(
        system_v2.InstrError.MissingRequiredSignature,
        system_v2.execute(&ctx, &ADVANCE_IX),
    );
}

test "KAT @414201776 negative: account[1] is not the RecentBlockhashes sysvar → InvalidArgument" {
    var data = preBytes();
    var accounts = buildAccounts(&data);
    accounts[1].pubkey = .{ .data = .{0x99} ** 32 };
    var ctx = system_v2.InstrCtx{
        .accounts = &accounts,
        .signer_mask = 0b100,
        .allocator = std.testing.allocator,
        .writable_mask = 0b001,
        .nonce_env = ENV,
    };
    try std.testing.expectError(
        system_v2.InstrError.InvalidArgument,
        system_v2.execute(&ctx, &ADVANCE_IX),
    );
}

test "KAT @414201776 negative: nonce account not writable → InvalidArgument" {
    var data = preBytes();
    var accounts = buildAccounts(&data);
    var ctx = system_v2.InstrCtx{
        .accounts = &accounts,
        .signer_mask = 0b100,
        .allocator = std.testing.allocator,
        .writable_mask = 0, // nonce acct NOT writable
        .nonce_env = ENV,
    };
    try std.testing.expectError(
        system_v2.InstrError.InvalidArgument,
        system_v2.execute(&ctx, &ADVANCE_IX),
    );
}

test "nonce wiring: InitializeNonceAccount sets lps + durable_nonce from env" {
    var data: [80]u8 = .{0} ** 80; // uninitialized (all zero = ver 0/legacy, state 0)
    var accounts = buildAccounts(&data);
    // Initialize layout: [0]=nonce, [1]=RBH, [2]=Rent — replace authority slot
    // with the Rent sysvar and make the nonce account self-signed funder.
    accounts[2].pubkey = .{ .data = .{
        0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x5c, 0x51,
        0x21, 0x8c, 0xc9, 0x4c, 0x3d, 0x4a, 0xf1, 0x7f,
        0x58, 0xda, 0xee, 0x08, 0x9b, 0xa1, 0xfd, 0x44,
        0xe3, 0xdb, 0xd9, 0x8a, 0x00, 0x00, 0x00, 0x00,
    } };
    var env = ENV;
    env.rent_minimum_balance_fn = &testRentMin;
    var ctx = system_v2.InstrCtx{
        .accounts = &accounts,
        .signer_mask = 0b001,
        .allocator = std.testing.allocator,
        .writable_mask = 0b001,
        .nonce_env = env,
    };
    // ix: disc=6 + authorized pubkey
    var ix: [36]u8 = undefined;
    std.mem.writeInt(u32, ix[0..4], 6, .little);
    @memcpy(ix[4..36], &AUTHORITY);
    try system_v2.execute(&ctx, &ix);

    const expected = expectedPostBytes();
    try std.testing.expectEqualSlices(u8, &expected, &data);
}

fn testRentMin(data_len: u64) u64 {
    return (data_len + 128) * 3480 * 2;
}

// Pull in nonce.zig's own unit tests (encode/decode round-trips etc.).
test {
    std.testing.refAllDecls(nonce);
}
