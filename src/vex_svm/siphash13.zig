//! Canonical SipHash1-3 (1 compression round, 3 finalization rounds).
//! @prov:svm.siphash13-port
//!
//! Byte-exact port of Firedancer `src/ballet/siphash13/fd_siphash13.c`
//! (v0.1004.40101) which is itself the antirez/Aumasson reference SipHash.
//! Agave uses the identical algorithm via the `siphasher` crate's
//! `SipHasher13` inside `EpochRewardsHasher`.
//!
//! This module is intentionally SELF-CONTAINED (only `std`) so it unit-tests
//! without the bank dependency graph. It provides:
//!   - `hash`: one-shot SipHash1-3 over a byte slice with 128-bit key (k0,k1).
//!   - `assignPartitionIndex`: the partitioned-epoch-rewards partition hash
//!     (SipHash1-3 keyed 0,0 over parent_blockhash ‖ stake_pubkey, then the
//!     multiply-shift bucketing), matching FD `fd_stake_rewards.c:271-277`.
//!
//! SipHash1-3 == SipHash-c-d with c=1 compression rounds, d=3 finalization.

const std = @import("std");

/// SipHash1-3 round function (fd_siphash13.h FD_SIPHASH_ROUND).
inline fn round(v: *[4]u64) void {
    v[0] +%= v[1];
    v[1] = std.math.rotl(u64, v[1], 13);
    v[1] ^= v[0];
    v[0] = std.math.rotl(u64, v[0], 32);
    v[2] +%= v[3];
    v[3] = std.math.rotl(u64, v[3], 16);
    v[3] ^= v[2];
    v[0] +%= v[3];
    v[3] = std.math.rotl(u64, v[3], 21);
    v[3] ^= v[0];
    v[2] +%= v[1];
    v[1] = std.math.rotl(u64, v[1], 17);
    v[1] ^= v[2];
    v[2] = std.math.rotl(u64, v[2], 32);
}

/// One-shot SipHash1-3. Mirrors `fd_siphash13_hash` exactly:
///   - initial vector XOR'd with the 128-bit key (k0,k1),
///   - 8-byte blocks read little-endian (native LE on x86 in FD),
///   - final block packs `len<<56 | trailing bytes`,
///   - v[2] ^= 0xff, three finalization rounds, fold to u64.
pub fn hash(data: []const u8, k0: u64, k1: u64) u64 {
    var v = [4]u64{
        0x736f6d6570736575,
        0x646f72616e646f6d,
        0x6c7967656e657261,
        0x7465646279746573,
    };
    v[3] ^= k1;
    v[2] ^= k0;
    v[1] ^= k1;
    v[0] ^= k0;

    const nblocks = data.len / 8;
    var i: usize = 0;
    while (i < nblocks) : (i += 1) {
        const m = std.mem.readInt(u64, data[i * 8 ..][0..8], .little);
        v[3] ^= m;
        round(&v);
        v[0] ^= m;
    }

    // Final block: high byte = length mod 256, low bytes = the <8 trailing bytes.
    var b: u64 = @as(u64, @intCast(data.len)) << 56;
    const rem = data[nblocks * 8 ..];
    var j: usize = 0;
    while (j < rem.len) : (j += 1) {
        b |= @as(u64, rem[j]) << @intCast(8 * j);
    }
    v[3] ^= b;
    round(&v);
    v[0] ^= b;

    v[2] ^= 0xff;
    round(&v);
    round(&v);
    round(&v);
    return v[0] ^ v[1] ^ v[2] ^ v[3];
}

/// Raw partition hash64: SipHash1-3 keyed (0,0) over
/// parent_blockhash (32B, FIRST) ‖ stake_pubkey (32B, SECOND).
/// Matches FD `fd_stake_rewards.c:271-275`.
pub fn partitionHash64(parent_blockhash: [32]u8, stake_pubkey: [32]u8) u64 {
    var concat: [64]u8 = undefined;
    @memcpy(concat[0..32], &parent_blockhash);
    @memcpy(concat[32..64], &stake_pubkey);
    return hash(&concat, 0, 0);
}

/// Partition index for a stake account: multiply-shift bucketing of the
/// partition hash64. Matches FD `fd_stake_rewards.c:277`:
///   partition_index = (u128)num_partitions * (u128)hash64 / (2^64)
/// i.e. the high 64 bits of the 128-bit product. Result is < num_partitions.
pub fn assignPartitionIndex(parent_blockhash: [32]u8, stake_pubkey: [32]u8, num_partitions: u32) u32 {
    const h64 = partitionHash64(parent_blockhash, stake_pubkey);
    return @intCast((@as(u128, num_partitions) * @as(u128, h64)) >> 64);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests / KATs
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical SipHash1-3 test vectors (from FD `test_siphash13.c`, which are the
/// antirez/Aumasson reference vectors). vector[i] = SipHash13(msg, i) where
/// msg[k] = k for k in 0..i, with k0=0x0706050403020100, k1=0x0f0e0d0c0b0a0908.
/// These exercise ALL trailing-byte lengths 0..63 → the leftover-byte
/// finalization path (which the always-64-byte partition path never hits).
const siphash13_test_vector = [64]u64{
    0xabac0158050fc4dc, 0xc9f49bf37d57ca93, 0x82cb9b024dc7d44d, 0x8bf80ab8e7ddf7fb,
    0xcf75576088d38328, 0xdef9d52f49533b67, 0xc50d2b50c59f22a7, 0xd3927d989bb11140,
    0x369095118d299a8e, 0x25a48eb36c063de4, 0x79de85ee92ff097f, 0x70c118c1f94dc352,
    0x78a384b157b4d9a2, 0x306f760c1229ffa7, 0x605aa111c0f95d34, 0xd320d86d2a519956,
    0xcc4fdd1a7d908b66, 0x9cf2689063dbd80c, 0x8ffc389cb473e63e, 0xf21f9de58d297d1c,
    0xc0dc2f46a6cce040, 0xb992abfe2b45f844, 0x7ffe7b9ba320872e, 0x525a0e7fdae6c123,
    0xf464aeb267349c8c, 0x45cd5928705b0979, 0x3a3e35e3ca9913a5, 0xa91dc74e4ade3b35,
    0xfb0bed02ef6cd00d, 0x88d93cb44ab1e1f4, 0x540f11d643c5e663, 0x2370dd1f8c21d1bc,
    0x81157b6c16a7b60d, 0x4d54b9e57a8ff9bf, 0x759f12781f2a753e, 0xcea1a3bebf186b91,
    0x2cf508d3ada26206, 0xb6101c2da3c33057, 0xb3f47496ae3a36a1, 0x626b57547b108392,
    0xc1d2363299e41531, 0x667cc1923f1ad944, 0x65704ffec8138825, 0x24f280d1c28949a6,
    0xc2ca1cedfaf8876b, 0xc2164bfc9f042196, 0xa16e9c9368b1d623, 0x49fb169c8b5114fd,
    0x9f3143f8df074c46, 0xc6fdaf2412cc86b3, 0x7eaf49d10a52098f, 0x1cf313559d292f9a,
    0xc44a30dda2f41f12, 0x36fae98943a71ed0, 0x318fb34c73f0bce6, 0xa27abf3670a7e980,
    0xb4bcc0db243c6d75, 0x23f8d852fdb71513, 0x8f035f4da67d8a08, 0xd89cd0e5b7e8f148,
    0xf6f4e6bcf7a644ee, 0xaec59ad80f1837f2, 0xc3b2f6154b6694e0, 0x9d199062b7bbb3a8,
};

test "SipHash1-3 canonical 64-vector KAT (all trailing-byte lengths)" {
    const k0: u64 = 0x0706050403020100;
    const k1: u64 = 0x0f0e0d0c0b0a0908;
    var buf: [64]u8 = undefined;
    for (0..64) |i| {
        const h = hash(buf[0..i], k0, k1);
        try std.testing.expectEqual(siphash13_test_vector[i], h);
        buf[i] = @intCast(i);
    }
}

test "partition hash64 golden vectors (k0=k1=0, blockhash-first)" {
    // Goldens generated from a faithful reimplementation of fd_siphash13.c,
    // anchored by the 64-vector KAT above (byte-exact match to FD's table).
    // GOLDEN A: blockhash = 0..31, pubkey = 0x80..0x9f.
    var bh_a: [32]u8 = undefined;
    var pk_a: [32]u8 = undefined;
    for (0..32) |i| {
        bh_a[i] = @intCast(i);
        pk_a[i] = @intCast(0x80 + i);
    }
    try std.testing.expectEqual(@as(u64, 0x50037bca30f3ad09), partitionHash64(bh_a, pk_a));
    try std.testing.expectEqual(@as(u32, 0), assignPartitionIndex(bh_a, pk_a, 1));
    try std.testing.expectEqual(@as(u32, 2), assignPartitionIndex(bh_a, pk_a, 7));
    try std.testing.expectEqual(@as(u32, 15), assignPartitionIndex(bh_a, pk_a, 49));

    // GOLDEN B: blockhash all-zero, pubkey = 0x11 x32.
    const bh_b = [_]u8{0} ** 32;
    const pk_b = [_]u8{0x11} ** 32;
    try std.testing.expectEqual(@as(u64, 0x842e368ff876d12b), partitionHash64(bh_b, pk_b));
    try std.testing.expectEqual(@as(u32, 65), assignPartitionIndex(bh_b, pk_b, 126));
    try std.testing.expectEqual(@as(u32, 4229), assignPartitionIndex(bh_b, pk_b, 8192));

    // GOLDEN C: blockhash = 0xAA x32, pubkey = 0..31.
    const bh_c = [_]u8{0xAA} ** 32;
    var pk_c: [32]u8 = undefined;
    for (0..32) |i| pk_c[i] = @intCast(i);
    try std.testing.expectEqual(@as(u64, 0x3cfcce1676141fc6), partitionHash64(bh_c, pk_c));
    try std.testing.expectEqual(@as(u32, 30), assignPartitionIndex(bh_c, pk_c, 126));
}

test "multiply-shift bucketing (independent of SipHash)" {
    // Directly exercise the (u128)N*hash>>64 step with hand-computed values.
    // max hash, 126 partitions → 125 (top bucket).
    try std.testing.expectEqual(
        @as(u32, 125),
        @as(u32, @intCast((@as(u128, 126) * @as(u128, 0xFFFFFFFFFFFFFFFF)) >> 64)),
    );
    // hash = 2^63, 2 partitions → 1.
    try std.testing.expectEqual(
        @as(u32, 1),
        @as(u32, @intCast((@as(u128, 2) * @as(u128, 0x8000000000000000)) >> 64)),
    );
    // hash = 0 → always bucket 0.
    try std.testing.expectEqual(
        @as(u32, 0),
        @as(u32, @intCast((@as(u128, 126) * @as(u128, 0)) >> 64)),
    );
}
